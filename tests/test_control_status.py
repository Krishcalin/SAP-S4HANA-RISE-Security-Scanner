"""Per-control audit evidence — status + the findings that prove it.

modules/control_status.py generalises the CSF status recipe to every framework in
ComplianceMapper.FRAMEWORKS: a control with findings is a GAP; one whose feeding
checks RAN and found nothing is CLEAR; one whose checks did NOT run is NOT_TESTED;
one nothing maps to is NOT_MAPPED. What must hold: the four states are produced
correctly, the evidence rides along, CLEAR is never claimed when coverage is
unknown, NOT_TESTED is claimed only when feeders demonstrably did not run, and NO
percentage is ever computed (the standing compliance-honesty rule).
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import control_status as cs  # noqa: E402

# An AUTH finding maps (via the access-control / privileged-access / sod themes)
# onto SOX/ITGC's "Access to Programs and Data" (APD) control.
_AUTH_GAP = {"id": 1, "check_id": "AUTH-015",
             "category": "ABAP Authorization & Critical Access", "severity": "HIGH",
             "title": "SAP_ALL assigned to a dialog user", "sid": "PRD",
             "state": "open", "priority_tier": "P2",
             "affected_items": ["user ADMIN1 (PRD/100)"]}


def _control(result, cid):
    return next(c for c in result["controls"] if c["id"] == cid)


def test_frameworks_lists_every_mapper_framework():
    ids = {f["id"] for f in cs.frameworks()}
    assert {"soxitgc", "cisv8", "nist80053", "gdpr", "dora"} <= ids
    assert all(f["name"] for f in cs.frameworks())


def test_unknown_framework_is_none():
    assert cs.assess_framework("not-a-framework", [_AUTH_GAP]) is None


def test_a_mapped_finding_makes_its_control_a_gap_with_evidence():
    r = cs.assess_framework("soxitgc", [_AUTH_GAP], coverage={"modules": {}})
    apd = _control(r, "APD")
    assert apd["status"] == cs.GAP
    assert apd["total"] == 1
    assert apd["counts"]["HIGH"] == 1
    ev = apd["findings"][0]
    assert ev["check_id"] == "AUTH-015" and ev["id"] == 1
    assert ev["title"] and ev["affected_items"] == ["user ADMIN1 (PRD/100)"]


def test_no_findings_with_coverage_unknown_is_clear_never_not_tested():
    # coverage omitted => we cannot prove an export was missing, so a quiet
    # control is CLEAR (we looked), never NOT_TESTED.
    r = cs.assess_framework("soxitgc", [], coverage=None)
    assert {c["status"] for c in r["controls"]} == {cs.CLEAR}


def test_no_findings_with_nothing_run_is_not_tested():
    # A manifest that says zero modules ran: a quiet control was NOT tested, and
    # must not read as a pass.
    r = cs.assess_framework("soxitgc", [], coverage={"modules": {}})
    assert {c["status"] for c in r["controls"]} == {cs.NOT_TESTED}


def test_every_control_has_one_of_the_four_states_and_totals_reconcile():
    r = cs.assess_framework("cisv8", [_AUTH_GAP], coverage={"modules": {}})
    valid = {cs.GAP, cs.CLEAR, cs.NOT_TESTED, cs.NOT_MAPPED}
    assert all(c["status"] in valid for c in r["controls"])
    tally = r["totals"]["by_status"]
    assert sum(tally.values()) == len(r["controls"]) == r["totals"]["controls"]
    assert r["totals"]["findings"] == sum(c["total"] for c in r["controls"])


def test_no_percentage_is_ever_reported():
    r = cs.assess_framework("soxitgc", [_AUTH_GAP], coverage={"modules": {}})
    blob = repr(r).lower()
    assert "percent" not in blob and "pct" not in blob
    # keys, recursively, carry no percentage/coverage-ratio field
    for c in r["controls"]:
        assert not any(k for k in c if "percent" in k or "pct" in k)


def test_gaps_sort_before_clear_and_worst_first():
    r = cs.assess_framework("soxitgc", [_AUTH_GAP], coverage={"modules": {}})
    statuses = [c["status"] for c in r["controls"]]
    # the GAP control (APD) comes before any non-gap one
    assert statuses.index(cs.GAP) < min(
        (i for i, s in enumerate(statuses) if s != cs.GAP), default=len(statuses))


# ── drift ────────────────────────────────────────────────────────────────────

def _apd(r):
    return next(c for c in r["controls"] if c["id"] == "APD")


def test_drift_remediated_when_a_gap_clears():
    # before: APD had the AUTH gap; now: it is gone and the checks looked.
    r = cs.drift("soxitgc", [], None, [_AUTH_GAP], None)
    apd = _apd(r)
    assert apd["was"] == cs.GAP and apd["status"] == cs.CLEAR
    assert apd["change"] == cs.REMEDIATED
    assert r["has_baseline"] is True


def test_drift_newly_failing_when_a_clear_control_gains_a_finding():
    r = cs.drift("soxitgc", [_AUTH_GAP], None, [], None)
    assert _apd(r)["change"] == cs.NEWLY_FAILING


def test_drift_stopped_testing_when_coverage_drops():
    # before: clear (coverage unknown -> looked); now: nothing ran -> not tested.
    r = cs.drift("soxitgc", [], {"modules": {}}, [], None)
    assert _apd(r)["change"] == cs.STOPPED_TESTING


def test_drift_reports_no_baseline_when_there_is_no_previous_scan():
    r = cs.drift("soxitgc", [_AUTH_GAP], None, None, None)
    assert r["has_baseline"] is False
    assert all(c["change"] == cs.NO_BASELINE for c in r["controls"])
    assert r["totals"]["by_change"][cs.NO_BASELINE] == r["totals"]["controls"]


def test_drift_unknown_framework_is_none():
    assert cs.drift("not-a-framework", [], None, [], None) is None


def test_drift_orders_actionable_changes_first():
    # one newly-failing (APD gains a gap), everything else unchanged.
    r = cs.drift("soxitgc", [_AUTH_GAP], None, [], None)
    assert r["controls"][0]["change"] == cs.NEWLY_FAILING
