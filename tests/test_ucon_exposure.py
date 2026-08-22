"""UCON — the only view of remote-callable exposure a RISE customer still has.

WHY THIS MODULE EXISTS. `secinfo` and `reginfo` are filesystem files on the
application server and a RISE customer contractually never gets OS access, so the
product's whole view of remote-callable exposure was unreachable there.
`docs/RISE_SECURITY_MODEL.md` section 7.1 ranks UCON state first among the checks
to add; section 3 carried "Gap in our ingest" against it; `docs/EXPORT_GUIDE.md`
repeated that it was an ingest gap and not a translation problem.

WHAT THESE TESTS ARE FOR. The three places a UCON check could say more than the
export supports: reading a missing call-count column as "never called", reading a
missing assembly column as "not exposed", and letting a recording phase read as an
enforced allowlist.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.ucon_exposure import UconExposureAuditor     # noqa: E402


def _run(**data):
    return UconExposureAuditor(data, {}, {}).run_all_checks()


def _ids(findings):
    return {f["check_id"] for f in findings}


def _one(findings, check_id):
    hits = [f for f in findings if f["check_id"] == check_id]
    assert hits, f"{check_id} not raised; got {sorted(_ids(findings))}"
    return hits[0]


# ═════════════════════════════════════════════════════════════════════════════
#  Absent data is not a clean bill of health
# ═════════════════════════════════════════════════════════════════════════════

def test_no_ucon_export_degrades_coverage_rather_than_passing_silently():
    """In RISE the gateway ACLs are unreachable too, so with neither the product
    can say nothing whatsoever about remote-callable exposure. A report that omits
    the topic reads as though it was examined and found clean."""
    f = _one(_run(), "UCON-COV-001")
    assert f["details"]["degrades_coverage"] is True


def test_the_coverage_note_says_whether_the_gateway_acls_were_there_either():
    """The two are different questions — registration and start of external
    programs versus which function a caller may invoke once connected — and the
    RISE customer usually has neither. Which of the two situations they are in
    changes what they should go and get."""
    without = _one(_run(), "UCON-COV-001")["description"]
    with_gw = _one(_run(gw_secinfo=[{"LINE": "P TP=x"}]), "UCON-COV-001")["description"]
    assert "only available view" in without
    assert "different question" in with_gw


def test_supplying_ucon_data_retires_the_coverage_finding():
    findings = _run(ucon_rfc_state=[{"FUNCNAME": "Z_X", "PHASE": "FINAL",
                                     "DEFAULT_CA": "X", "CALLS": "9"}])
    assert "UCON-COV-001" not in _ids(findings)


# ═════════════════════════════════════════════════════════════════════════════
#  Recording is not enforcing
# ═════════════════════════════════════════════════════════════════════════════

def test_a_scenario_left_in_the_logging_phase_is_reported():
    """An allowlist that records and blocks nothing is worse than none, because
    somebody believes the control is live."""
    f = _one(_run(ucon_rfc_state=[{"FUNCNAME": "Z_A", "PHASE": "LOGGING"},
                                  {"FUNCNAME": "Z_B", "PHASE": "LOGGING"}]),
             "UCON-001")
    assert f["severity"] == "HIGH"
    assert f["details"]["recording"] == 2 and f["details"]["enforcing"] == 0


def test_a_partly_migrated_scenario_is_reported_less_severely():
    """Some enforcement is meaningfully better than none, and a HIGH on a customer
    who is halfway through the migration is a finding they cannot act on faster."""
    f = _one(_run(ucon_rfc_state=[{"FUNCNAME": "Z_A", "PHASE": "LOGGING"},
                                  {"FUNCNAME": "Z_B", "PHASE": "FINAL"}]),
             "UCON-001")
    assert f["severity"] == "MEDIUM"


def test_a_fully_enforcing_scenario_raises_nothing():
    findings = _run(ucon_rfc_state=[{"FUNCNAME": "Z_A", "PHASE": "FINAL"},
                                    {"FUNCNAME": "Z_B", "PHASE": "FINAL"}])
    assert "UCON-001" not in _ids(findings)


def test_an_export_with_no_phase_column_makes_no_phase_claim():
    """Silence about the phase is not evidence of the logging phase."""
    findings = _run(ucon_rfc_state=[{"FUNCNAME": "Z_A", "DEFAULT_CA": "X"}])
    assert "UCON-001" not in _ids(findings)


# ═════════════════════════════════════════════════════════════════════════════
#  Exposed but never called — the check this module exists for
# ═════════════════════════════════════════════════════════════════════════════

def test_a_function_exposed_and_never_called_is_reported():
    """Remote attack surface with no observed use behind it, which is the
    cheapest reduction available in an ABAP system."""
    f = _one(_run(ucon_rfc_state=[
        {"FUNCNAME": "Z_UNUSED", "DEFAULT_CA": "X", "CALLS": "0"},
        {"FUNCNAME": "Z_BUSY", "DEFAULT_CA": "X", "CALLS": "4211"}]), "UCON-002")
    assert f["affected_items"] == ["Z_UNUSED"]
    assert f["details"]["never_called"] == 1


def test_an_export_without_a_call_count_makes_no_usage_claim():
    """THE ONE THAT MATTERS MOST. An absent column is not evidence of silence.
    Treating it as zero would report every remote-callable function in the system
    as unused, off an export that never said so."""
    findings = _run(ucon_rfc_state=[{"FUNCNAME": "Z_A", "DEFAULT_CA": "X"},
                                    {"FUNCNAME": "Z_B", "DEFAULT_CA": "X"}])
    assert "UCON-002" not in _ids(findings)


def test_an_unparseable_call_count_is_not_read_as_zero():
    findings = _run(ucon_rfc_state=[{"FUNCNAME": "Z_A", "DEFAULT_CA": "X",
                                     "CALLS": "n/a"}])
    assert "UCON-002" not in _ids(findings)


def test_a_function_outside_the_default_assembly_is_not_exposed():
    """It is already unreachable from outside, so its call count is irrelevant —
    reporting it would send the customer to remove something already removed."""
    findings = _run(ucon_rfc_state=[{"FUNCNAME": "Z_A", "DEFAULT_CA": "",
                                     "CALLS": "0"}])
    assert "UCON-002" not in _ids(findings)


def test_the_finding_states_the_window_caveat_rather_than_hiding_it():
    """A function used only at period end looks unused in a two-week recording.
    The fix for that is a longer window, not a shorter conclusion, and a customer
    who removes on this evidence alone will break their period-end."""
    f = _one(_run(ucon_rfc_state=[{"FUNCNAME": "Z_A", "DEFAULT_CA": "X",
                                  "CALLS": "0"}]), "UCON-002")
    assert "period end" in f["description"]
    assert f["details"]["window_caveat"]
    assert "extend it" in f["remediation"]


def test_the_named_functions_become_graph_objects():
    """Typed objects, not prose — so a function module joins the graph the same
    way every other named object does."""
    f = _one(_run(ucon_rfc_state=[{"FUNCNAME": "Z_A", "DEFAULT_CA": "X",
                                  "CALLS": "0"}]), "UCON-002")
    assert f["affected_objects"] == [{"type": "function_module", "name": "Z_A"}]


# ═════════════════════════════════════════════════════════════════════════════
#  The two this repository already names as powerful
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("name", ["RFC_READ_TABLE", "SXPG_COMMAND_EXECUTE"])
def test_a_powerful_function_module_exposed_externally_is_reported(name):
    f = _one(_run(ucon_rfc_state=[{"FUNCNAME": name, "DEFAULT_CA": "X"}]),
             "UCON-003")
    assert f["severity"] == "HIGH"
    assert name in f["title"]


def test_a_powerful_function_module_outside_the_assembly_is_not_reported():
    findings = _run(ucon_rfc_state=[{"FUNCNAME": "RFC_READ_TABLE",
                                     "IN_DEFAULT_CA": "NO"}])
    assert "UCON-003" not in _ids(findings)


def test_the_powerful_list_is_short_and_sourced():
    """A long list assembled from memory is exactly the invention this project's
    conventions forbid. Both entries appear in this repository's own vetted
    content under AUTH-003 and AUTH-006."""
    from modules.ucon_exposure import POWERFUL_FUNCTION_MODULES
    assert set(POWERFUL_FUNCTION_MODULES) == {"RFC_READ_TABLE",
                                              "SXPG_COMMAND_EXECUTE"}
    for reason in POWERFUL_FUNCTION_MODULES.values():
        assert len(reason) > 40


# ═════════════════════════════════════════════════════════════════════════════
#  Column aliases, and the HTTP half
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("col", ["FUNCNAME", "FUNCTION", "FUNCTION_MODULE",
                                 "RFM", "FMODULE"])
def test_the_function_column_is_matched_through_its_aliases(col):
    """UCONCOCKPIT's list view varies by release and language. Declaring one true
    header would be a claim about SAP's UI no primary source here supports."""
    f = _one(_run(ucon_rfc_state=[{col: "Z_A", "DEFAULT_CA": "X", "CALLS": "0"}]),
             "UCON-002")
    assert f["affected_items"] == ["Z_A"]


def test_headers_match_case_insensitively():
    f = _one(_run(ucon_rfc_state=[{"funcname": "Z_A", "default_ca": "X",
                                   "calls": "0"}]), "UCON-002")
    assert f["affected_items"] == ["Z_A"]


def test_an_empty_http_allowlist_that_was_supplied_is_a_finding():
    f = _one(_run(ucon_rfc_state=[{"FUNCNAME": "Z", "PHASE": "FINAL"}],
                  ucon_http_allowlist=[]), "UCON-004")
    assert "2573569" in " ".join(f["references"])


def test_an_absent_http_allowlist_export_is_not_an_empty_one():
    """Not supplying the file says nothing about whether the allowlist has
    entries, and reporting it as empty would invent a finding out of an upload
    choice."""
    findings = _run(ucon_rfc_state=[{"FUNCNAME": "Z", "PHASE": "FINAL"}])
    assert "UCON-004" not in _ids(findings)


def test_a_populated_http_allowlist_raises_nothing():
    findings = _run(ucon_rfc_state=[{"FUNCNAME": "Z", "PHASE": "FINAL"}],
                    ucon_http_allowlist=[{"PATH": "/sap/opu/odata"}])
    assert "UCON-004" not in _ids(findings)


# ═════════════════════════════════════════════════════════════════════════════
#  It does not restate what TRUST-007 already says
# ═════════════════════════════════════════════════════════════════════════════

def test_the_profile_parameter_check_is_not_duplicated():
    """`system_trust.check_ucon_allowlist` owns `ucon/rfc/active` as TRUST-007.
    Two modules reporting the same parameter is how one estate produces two
    findings for one defect."""
    src = (ROOT / "modules" / "ucon_exposure.py").read_text(encoding="utf-8")
    assert "ucon/rfc/active" not in src.split('"""', 2)[2]


def test_malformed_rows_do_not_abort_the_module():
    findings = _run(ucon_rfc_state=["junk", None,
                                    {"FUNCNAME": "Z_A", "DEFAULT_CA": "X",
                                     "CALLS": "0"}])
    assert "UCON-002" in _ids(findings)
