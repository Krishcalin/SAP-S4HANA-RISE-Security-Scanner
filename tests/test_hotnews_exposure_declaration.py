"""HOTNEWS-017 — the stack/exposure applicability declaration.

A catalogue note for a non-ABAP stack (Visual Composer on AS Java, BI, BTP…) is
normally an INFO disclosure (HOTNEWS-005): an ABAP SNOTE export cannot prove it
patched. When the customer DECLARES that stack present in landscape_profile, the
note stops being "can't assess" and becomes a real, elevated item to verify — and
an actively-exploited one on an internet-facing landscape is CRITICAL.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.sap_hotnews import SapHotNewsAuditor  # noqa: E402

# An applied_notes export with nothing useful, so the java catalogue notes are not
# "applied" and fall into the out-of-scope disclosure.
_APPLIED = {"applied_notes": [{"NOTE": "1", "STATUS": "E"}]}


def _ids(data):
    return {f["check_id"] for f in SapHotNewsAuditor(dict(data)).run_all_checks()}


def _find(data, cid):
    return next(f for f in SapHotNewsAuditor(dict(data)).run_all_checks()
               if f["check_id"] == cid)


def test_without_a_declaration_java_notes_stay_info_005():
    ids = _ids(_APPLIED)
    assert "HOTNEWS-005" in ids and "HOTNEWS-017" not in ids


def test_declaring_the_java_stack_elevates_to_017():
    data = dict(_APPLIED, landscape_profile={"stacks_present": ["java"]})
    f = _find(data, "HOTNEWS-017")
    # exploited java notes present (CVE-2025-31324/42999) -> CRITICAL even without
    # the internet-facing flag.
    assert f["severity"] == "CRITICAL"
    assert "3594142" in f["details"]["notes"]        # CVE-2025-31324
    assert f["details"]["exploited_among_them"] >= 1


def test_internet_facing_is_recorded_and_forces_critical():
    data = dict(_APPLIED, landscape_profile={"stacks_present": ["bi"],
                                             "internet_facing": True})
    f = _find(data, "HOTNEWS-017")
    assert f["details"]["internet_facing"] is True and f["severity"] == "CRITICAL"


def test_boolean_flag_form_is_accepted():
    data = dict(_APPLIED, landscape_profile={"java_stack": True})
    assert "HOTNEWS-017" in _ids(data)


def test_only_the_declared_stack_elevates_the_rest_stay_info():
    # Declare only 'bi'. The bi notes elevate to 017; the java notes (undeclared)
    # stay in the INFO 005 disclosure and must NOT appear in 017.
    data = dict(_APPLIED, landscape_profile={"stacks_present": ["bi"]})
    findings = SapHotNewsAuditor(dict(data)).run_all_checks()
    ids = {f["check_id"] for f in findings}
    assert "HOTNEWS-017" in ids and "HOTNEWS-005" in ids
    f17 = next(f for f in findings if f["check_id"] == "HOTNEWS-017")
    assert "3594142" not in f17["details"]["notes"]      # java, undeclared, not here


def test_abap_in_the_declaration_is_ignored_not_elevated():
    # ABAP is always implied and assessed normally; declaring it elevates nothing.
    data = dict(_APPLIED, landscape_profile={"stacks_present": ["abap"]})
    assert "HOTNEWS-017" not in _ids(data)


def test_017_routes_to_basis_and_carries_the_hotnews_requirement():
    from modules import rise_ownership
    from server import sapcontent
    assert rise_ownership.team_for("HOTNEWS-017") == "basis"
    # Inherits the HotNews family requirement (security update), like HOTNEWS-001.
    assert sapcontent.requirement_for("HOTNEWS-017") == "SECUPD-A"
