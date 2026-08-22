"""`module_sources()` is published to customers, so a wrong answer is worse than
a missing one.

WHERE IT SURFACES. `/checks/{id}` renders it under "Exports the module reads",
and `build_manifest` uses it to decide whether a module was supplied with what it
needs. Both are statements to a customer about their own scan.

WHAT WAS WRONG. The analysis found methods that read `self.data.get(<param>)` and
then collected the string LITERALS passed to them. Two shapes escaped it, and
`ecs_config_items` used both:

  * a source named by a CONSTANT — `TABLE_AUTH_GROUPS = "table_auth_groups"`,
    then `self._rows(TABLE_AUTH_GROUPS)`. An `ast.Name` is not an `ast.Constant`.
  * an accessor that FORWARDS — `_rows(key)` reads `self.data.get(key)` and was
    detected; `_filter_rows(key)` calls `self._rows(key)` and was not, so every
    literal passed to it was lost as well.

The module therefore published `client_settings` — its single written literal —
as the whole of what it reads, while actually reading four sources. The module's
own docstring named `table_auth_groups` in its first paragraph, which is how the
two could disagree for so long: the prose was right and nobody compared it to the
derived answer.

THIS FILE COMPARES THEM. Not for one module — for every module that names its
sources in prose, which is the general form of the bug.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.coverage import all_logical_sources, module_sources  # noqa: E402

MODULES = ROOT / "modules"


def test_a_source_named_by_a_constant_is_found():
    """The exact shape that was missed. Kept as its own test so a regression
    names the cause rather than only the symptom."""
    reads = set(module_sources()["ecs_config_items"])
    assert "table_auth_groups" in reads, (
        "ecs_config_items declares TABLE_AUTH_GROUPS = \"table_auth_groups\" and "
        "reads it through that constant; the analysis has stopped resolving "
        "constants")


def test_a_source_reached_through_a_forwarding_accessor_is_found():
    """`_filter_rows` forwards to `_rows`. Both are accessors, and only the
    fixed-point analysis sees the second one."""
    reads = set(module_sources()["ecs_config_items"])
    assert {"security_audit_log", "audit_config"} <= reads


def test_no_module_declares_a_source_the_loader_cannot_supply():
    """Over-reporting is the more dangerous direction: it manufactures coverage
    gaps that are not real, and a manifest that cries wolf gets ignored."""
    known = set(all_logical_sources())
    for module, sources in module_sources().items():
        unknown = sorted(set(sources) - known - {"abap_source_dir",
                                                 "cap_project_dir"})
        assert not unknown, "%s declares sources DataLoader has never heard of: %s" % (
            module, unknown)


#: Modules whose docstring names a source they legitimately do NOT read. Every
#: entry is a DECISION with the reason beside it, not a suppression — the whole
#: value of this test is that it forces the question, so an entry added without
#: reading the docstring would throw that away.
_PROSE_ONLY = {
    # webdisp_security names `security_params` to explain why it does NOT use it:
    # that is the ABAP instance profile, a Web Dispatcher is a separate instance
    # with its own, and merging them would give one finding for two components
    # with no way to tell which was exposed. SAP draws the same line (2ADISCL
    # reads ABAP_INSTANCE_PAHI, 2ODISCL reads Parameters).
    ("webdisp_security", "security_params"),
    # cap_xsuaa says outright that `btp_users` "is not collected at all" — it is
    # named as a boundary of what the module can see, not as an input.
    ("cap_xsuaa", "btp_users"),
}


def _docstring_sources(src: str, known: set) -> set:
    """Logical source names that appear in the module's own leading docstring."""
    match = re.match(r'\s*(?:#[^\n]*\n)*\s*(?:"""|\'\'\')(.*?)(?:"""|\'\'\')',
                     src, re.S)
    if not match:
        return set()
    prose = match.group(1)
    # Backticked names only. A bare word matching a source name is far too easy
    # to hit by accident ("clients", "findings"), and a false failure here would
    # teach people to add suppressions rather than to fix the analysis.
    return {name for name in re.findall(r"`([a-z0-9_]+)`", prose)
            if name in known}


def _auditor_modules():
    """The auditor source files, decided ONCE at collection time.

    PARAMETRISED OVER AUDITORS, NOT OVER `modules/*.py`. The first version
    parametrised over every file and skipped the two thirds that are not
    auditors, which produced 34 skips — and the CI job caps DB-backed skips at
    one, precisely because "a suite that silently skips is worse than one that
    does not exist, because it LOOKS verified". Thirty-four decorative skips
    would have blinded that guard to a real one. Deciding here means every case
    that runs is a case worth running.
    """
    from modules.coverage import _NOT_AN_AUDITOR

    out = []
    for path in sorted(MODULES.glob("*.py")):
        if path.stem in _NOT_AN_AUDITOR:
            continue
        try:
            if "BaseAuditor" in path.read_text(encoding="utf-8"):
                out.append(path)
        except OSError:                                  # pragma: no cover
            continue
    return out


@pytest.mark.parametrize("path", _auditor_modules(), ids=lambda p: p.stem)
def test_the_derived_answer_agrees_with_the_module_s_own_prose(path):
    """The comparison nobody had made.

    A module whose docstring says it reads a source, and whose derived answer does
    not list it, is publishing one of the two to a customer. This test does not
    decide which is right — it requires them to agree, which is what forces the
    question to be asked at all.
    """
    src = path.read_text(encoding="utf-8")
    declared = set(module_sources().get(path.stem, []))
    known = set(all_logical_sources())
    in_prose = _docstring_sources(src, known)
    missing = sorted(name for name in in_prose - declared
                     if (path.stem, name) not in _PROSE_ONLY)
    assert not missing, (
        "%s's docstring names %s as inputs and module_sources() does not report "
        "them. Either the analysis cannot see how they are read — which is the "
        "bug this file exists for — or the docstring is stale. They cannot both "
        "stand: one of them is on /checks/{id}." % (path.stem, missing))
