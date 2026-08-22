"""The deployment-mode vocabulary, and the silent failure it is capable of.

WHAT MAKES THIS WORTH A FILE
A deployment mode is not a label. Four call sites decide whether a system is
governed by SAP's Enterprise Cloud Services rules by asking whether its mode name
starts with "rise", and that single question changes which findings are raised,
who is recorded as able to fix them, and which absent sources are excused rather
than reported as gaps.

So a mode named `ecc_rise` instead of `rise_ecc` would disable every ECS rule for
a system contractually bound by them. It would do so silently: no exception, no
empty report, just a quieter one. That is decision D7 in docs/DECISIONS.md, and
`test_every_mode_lands_on_the_intended_side_of_the_rise_test` is what makes the
next such mode fail loudly instead.

The vocabulary is declared in four places that cannot import each other — Python,
two SQL statements, and TypeScript. `modules/deployment_modes.py` is the source
of truth for the one language that can be imported; the tests here are the only
thing holding the other three to it.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.deployment_modes import (                                # noqa: E402
    DEFAULT_DEPLOYMENT_MODE, DEPLOYMENT_MODES, is_rise, normalise)

SCHEMA = (ROOT / "server" / "schema.sql").read_text(encoding="utf-8")
TYPES = (ROOT / "frontend" / "src" / "api" / "types.ts").read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
#  The predicate that decides ECS governance                                  #
# --------------------------------------------------------------------------- #

#: Every mode, and whether it is operated by SAP under ECS. Written out by hand
#: rather than derived with a startswith, because deriving it from the same rule
#: the code uses would assert nothing at all — the test would agree with the
#: implementation by construction, including when both are wrong.
EXPECTED_RISE = {
    "on_prem": False,
    "rise_pce": True,
    "rise_tailored": True,
    "rise_ecc": True,          # ECC running INSIDE RISE. Bound by ECS rules.
}


def test_every_mode_lands_on_the_intended_side_of_the_rise_test():
    """The one that would have caught `ecc_rise`.

    A mode added to the tuple and left out of EXPECTED_RISE fails here rather
    than shipping with whatever answer `startswith` happens to give it.
    """
    assert set(EXPECTED_RISE) == set(DEPLOYMENT_MODES), (
        "a deployment mode was added or removed without deciding whether it is "
        "ECS-governed; that decision cannot be left to string prefixes")
    for mode, expected in EXPECTED_RISE.items():
        assert is_rise(mode) is expected, (
            f"{mode!r} is {'not ' if expected else ''}treated as RISE. Four call "
            f"sites branch on this, and none of them would fail if it were wrong.")


def test_the_ecc_in_rise_mode_is_named_rise_first():
    """Naming, asserted directly, because the hazard IS the name.

    `ecc_rise` reads just as naturally in English and is silently wrong.
    """
    assert "rise_ecc" in DEPLOYMENT_MODES
    assert "ecc_rise" not in DEPLOYMENT_MODES
    assert is_rise("rise_ecc") is True


def test_an_unknown_or_empty_mode_falls_back_to_on_premise():
    """Never to a RISE mode. The RISE rules are the stricter set, so defaulting
    into them would invent contractual obligations a customer does not have and
    report the absence of SAP-only sources as coverage gaps on a system SAP does
    not operate."""
    for junk in ("", None, "   ", "nonsense", "RISE_TYPO"):
        assert normalise(junk) == DEFAULT_DEPLOYMENT_MODE
        assert is_rise(junk) is False
    assert DEFAULT_DEPLOYMENT_MODE == "on_prem"


def test_modes_are_normalised_for_case_and_whitespace():
    """Three modules carried their own `str(mode).strip().lower()`; the behaviour
    they had must survive being spelled once."""
    assert normalise("  RISE_PCE  ") == "rise_pce"
    assert is_rise("  Rise_Ecc ") is True


# --------------------------------------------------------------------------- #
#  The three declarations that cannot import the source of truth              #
# --------------------------------------------------------------------------- #

def _sql_modes(statement: str):
    """The value list of a deployment_mode CHECK, as a set."""
    m = re.search(r"deployment_mode IN \(([^)]*)\)", statement)
    assert m, f"no deployment_mode CHECK found in:\n{statement[:200]}"
    return {v.strip().strip("'") for v in m.group(1).split(",")}


def test_the_schema_create_and_migration_agree_with_python_and_each_other():
    """Three-way, for the reason the schema-upgrade job is three-way.

    `CREATE TABLE IF NOT EXISTS` is a no-op on an existing table, so the CREATE
    constraint governs fresh installs and the migration block governs upgrades.
    Widening one and not the other is a change that works on exactly half of the
    world's databases — and it is invisible to any test that builds its schema
    from empty, which is all of them.
    """
    create = re.search(r"CREATE TABLE IF NOT EXISTS landscape.*?\n\);", SCHEMA, re.S)
    assert create, "the landscape CREATE TABLE has moved; this test must follow it"
    migration = re.search(
        r"ALTER TABLE landscape ADD CONSTRAINT landscape_deployment_mode_check.*?;",
        SCHEMA, re.S)
    assert migration, (
        "the deployment_mode migration block is gone. Editing the CREATE alone "
        "changes nothing on any database that already exists.")

    from_create = _sql_modes(create.group(0))
    from_migration = _sql_modes(migration.group(0))
    expected = set(DEPLOYMENT_MODES)

    assert from_create == expected, f"CREATE TABLE: {from_create ^ expected}"
    assert from_migration == expected, f"migration block: {from_migration ^ expected}"


def test_the_typescript_union_agrees_with_python():
    """The console offers these in a picker. A mode the backend accepts and the
    console cannot name is a mode no customer can select; the reverse is a value
    the API rejects with a 422 the user cannot explain."""
    m = re.search(r"export type DeploymentMode\s*=\s*([^\n]+)", TYPES)
    assert m, "the DeploymentMode union has moved or been renamed"
    declared = {v.strip().strip("'") for v in m.group(1).split("|")}
    assert declared == set(DEPLOYMENT_MODES), \
        f"types.ts and deployment_modes.py disagree: {declared ^ set(DEPLOYMENT_MODES)}"


def test_both_command_line_choice_lists_read_the_tuple():
    """Rather than repeating it. Two CLIs accept a --mode/--deployment-mode, and a
    hardcoded choices= list rejects a newly added mode with an argparse error that
    names every OTHER mode as valid — which reads as the feature not existing."""
    for path in ("sap_scanner.py", "server/cli.py"):
        src = (ROOT / path).read_text(encoding="utf-8")
        assert "DEPLOYMENT_MODES" in src, f"{path} no longer reads the tuple"
        assert '"rise_pce"' not in src.replace(
            'from modules.deployment_modes', ''), \
            f"{path} has re-hardcoded the vocabulary"


def test_no_call_site_still_asks_the_question_itself():
    """The four `startswith("rise")` branches are why the name matters. Spelled
    once they can be tested once; spelled four times, a fifth appears.

    Parsed with ast rather than grepped, because the docstrings that RECORD this
    history quote `startswith("rise")` in prose, and a textual search cannot tell
    a call from a sentence about a call. A test that forced those explanations to
    be deleted in order to pass would be trading the documentation for the check.
    """
    import ast

    offenders = []
    for path in list((ROOT / "modules").glob("*.py")) + \
                list((ROOT / "server").glob("*.py")) + [ROOT / "sap_scanner.py"]:
        if path.name == "deployment_modes.py":
            continue                      # the one place it is allowed to live
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "startswith"
                    and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)
                    and node.args[0].value.startswith("rise")):
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    assert not offenders, (
        "these ask the RISE question directly instead of calling is_rise(): "
        + ", ".join(offenders))
