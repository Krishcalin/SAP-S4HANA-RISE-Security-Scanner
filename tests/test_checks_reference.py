"""The generated check reference, and the properties that make it worth trusting.

The CI gate (`--check` in the purity job) catches drift. These catch the ways the
GENERATOR itself could quietly produce a wrong document — which is the failure the
hand-written version had, and the one a machine would commit with more authority.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import build_checks_reference as gen        # noqa: E402

TARGET = ROOT / "docs" / "CHECKS_REFERENCE.md"


# ── the document is current ──────────────────────────────────────────────────

def test_the_committed_document_matches_the_code():
    """The same assertion CI makes, so a stale file fails locally first."""
    assert TARGET.exists(), "docs/CHECKS_REFERENCE.md has not been generated"
    current = TARGET.read_text(encoding="utf-8").replace("\r\n", "\n")
    assert current == gen.render(), (
        "docs/CHECKS_REFERENCE.md is stale. "
        "Run: python -m tools.build_checks_reference")


def test_the_document_says_it_is_generated():
    """A generated file that does not say so gets hand-edited, and the edit is
    then silently reverted by the next build."""
    head = TARGET.read_text(encoding="utf-8")[:600]
    assert "GENERATED FILE" in head
    assert "build_checks_reference" in head


# ── nothing is silently lost ─────────────────────────────────────────────────

def test_every_runtime_family_resolves_to_a_non_empty_table():
    """THE BUG THIS EXISTS FOR.

    The first version wrapped these imports in `except Exception: pass`, guessed
    two class names wrong, and produced a reference missing 37 ids — the whole ARA
    ruleset and every ATC family — while printing a success line. A generated
    document that quietly omits a family is worse than the hand-written one it
    replaced, because nobody re-reads a generated file.
    """
    families = gen.collect_dynamic_families()
    assert families
    for family in families:
        assert family["count"] > 0, family["pattern"]
        assert family["source"], family["pattern"]


def test_the_abap_family_covers_every_rule_table():
    """ABAP/UI5, JavaScript, BTP descriptors and the cross-artefact checks all
    emit into the `ABAP-` namespace. Reading only ALL_ABAP_SAST_RULES
    undercounted by 15, and 118 is a plausible enough number that nobody would
    have noticed.

    CROSS_ARTIFACT_RULES was the fourth, and it arrived by a different route —
    its ids live in `modules/cds_authorization_index.py`, which has no
    `BaseAuditor` and is therefore skipped by `module_check_ids`. An id there is
    invisible to every denominator until the day it first fails, which is the
    defect the runtime-family machinery exists to end. The assertion is written
    against the tables rather than a number so a fifth table cannot be added
    without this failing."""
    from modules.abap_sast import (ALL_ABAP_SAST_RULES, ALL_BTP_CONFIG_RULES,
                                   ALL_JS_RULES, CROSS_ARTIFACT_RULES)
    expected = (len(ALL_ABAP_SAST_RULES) + len(ALL_JS_RULES)
                + len(ALL_BTP_CONFIG_RULES) + len(CROSS_ARTIFACT_RULES))
    abap = [f for f in gen.collect_dynamic_families()
            if f["pattern"].startswith("ABAP-")][0]
    assert abap["count"] == expected


def test_a_cross_artefact_rule_reaches_the_denominator():
    """The specific regression: these two ids are not literals in an auditor and
    not patterns in a scanned table, so every automatic route to the denominator
    misses them unless the family registration names their table."""
    from modules.coverage import all_check_ids, check_catalogue
    ids = {c for v in all_check_ids().values() for c in v}
    for check in ("ABAP-CDS-003", "ABAP-RAP-005"):
        assert check in ids, "%s is invisible to the denominator" % check
        assert check_catalogue().get(check), "%s carries no category" % check


def test_every_module_that_emits_a_check_appears():
    """Twelve of thirty modules were missing from the hand-written version."""
    checks = gen.collect_literal_checks()
    modules = {c.module for c in checks}
    assert len(modules) >= 28, sorted(modules)
    body = TARGET.read_text(encoding="utf-8")
    for module in modules:
        assert f"`{module}`" in body, module


def test_the_id_set_matches_an_independent_walk():
    """A second reading of the same source, deliberately naive, must agree on the
    id set. If the generator's extraction ever narrows, this notices."""
    import ast
    independent = set()
    for path in (ROOT / "modules").glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call):
                continue
            fn = getattr(node.func, "attr", getattr(node.func, "id", ""))
            if fn not in gen.EMITTERS:
                continue
            kw = {k.arg: k.value for k in node.keywords if k.arg}
            node_id = kw.get("check_id") or (node.args[0] if node.args else None)
            if isinstance(node_id, ast.Constant) and isinstance(node_id.value, str):
                if node_id.value[:1].isupper():
                    independent.add(node_id.value)
    assert {c.check_id for c in gen.collect_literal_checks()} == independent


# ── nothing is invented ──────────────────────────────────────────────────────

def test_a_dynamic_title_is_never_resolved_to_one_example():
    """USR-001's title is f"Default user {uname} is unlocked". Rendering it as
    any single user's name would be the precise failure that left the old
    document carrying eleven wrong titles."""
    checks = {c.check_id: c for c in gen.collect_literal_checks()}
    usr1 = checks["USR-001"]
    assert usr1.title is None, "an f-string title was resolved to a literal"
    assert usr1.title_template and "…" in usr1.title_template


def test_a_conditional_severity_reports_both_branches():
    checks = {c.check_id: c for c in gen.collect_literal_checks()}
    usr1 = checks["USR-001"]
    assert usr1.severity is None
    assert usr1.severity_template
    assert "CRITICAL" in usr1.severity_template and "HIGH" in usr1.severity_template


def test_the_severity_constants_are_resolved_not_left_as_attributes():
    """self.SEVERITY_HIGH must read as HIGH; leaving it unresolved would mark
    hundreds of perfectly knowable severities as varying."""
    checks = {c.check_id: c for c in gen.collect_literal_checks()}
    assert checks["USR-004"].severity == "HIGH"
    resolved = sum(1 for c in gen.collect_literal_checks() if c.severity)
    assert resolved > 300, f"only {resolved} severities resolved"


def test_positional_wrapper_arguments_are_read():
    """abap_authorizations calls _emit positionally. A keyword-only reader
    rendered all sixteen of its checks as varies/varies, which is noise dressed
    as documentation."""
    checks = {c.check_id: c for c in gen.collect_literal_checks()}
    auth = checks["AUTH-001"]
    assert auth.severity == "CRITICAL"
    assert auth.title and "Debug & Replace" in auth.title


def test_wrapper_signatures_are_read_from_the_code_not_hardcoded():
    """A hardcoded argument order is a second copy of the signature, and the day
    somebody inserts a parameter the table starts reporting the description as
    the title."""
    sigs = gen.wrapper_signatures()
    assert sigs["finding"][:3] == ["check_id", "title", "severity"]
    assert sigs["_emit"][:3] == ["check_id", "title", "severity"]
    assert sigs["_flag"][:3] == ["check_id", "title", "severity"]


def test_most_rows_carry_real_information():
    """A table of 'varies / varies' is not documentation. If a refactor pushes
    this below the threshold, the document has stopped being useful even though
    it is still 'current'."""
    rows = [l for l in TARGET.read_text(encoding="utf-8").splitlines()
            if l.startswith("| `")]
    unknown = sum(1 for l in rows if l.count(gen.VARIES) == 2)
    assert rows
    assert unknown / len(rows) < 0.10, (
        f"{unknown} of {len(rows)} rows carry no title and no severity")


# ── the --check gate ─────────────────────────────────────────────────────────

def test_the_gate_passes_on_a_current_document():
    assert gen.main(["--check"]) == 0


def test_the_gate_fails_on_a_stale_document(monkeypatch, tmp_path):
    """A gate that cannot fail is not a gate."""
    stale = tmp_path / "CHECKS_REFERENCE.md"
    stale.write_text("# Check reference\n\nsomething else entirely\n", encoding="utf-8")
    monkeypatch.setattr(gen, "TARGET", stale)
    assert gen.main(["--check"]) == 1


def test_the_gate_fails_when_the_document_is_absent(monkeypatch, tmp_path):
    monkeypatch.setattr(gen, "TARGET", tmp_path / "nothing.md")
    assert gen.main(["--check"]) == 1


def test_generating_twice_produces_the_same_bytes():
    """Otherwise the gate would fail on an unchanged tree and everyone would
    learn to ignore it."""
    assert gen.render() == gen.render()
