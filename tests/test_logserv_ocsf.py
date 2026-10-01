"""
The SAP LogServ (OCSF) → Security-Audit-Log adapter, and its integration with the
retrospective log review.

The adapter must: normalise OCSF into the row shape log_review classifies, map the
Authentication class to logon success/failure, read the epoch-ms `time`, read SAP
fields from `unmapped`, tolerate wrappers and garbage, and — end to end — let a
LogServ event fire an existing `LREV-PAT-*` pattern unchanged (LogServ as a fresher
source for the exported-window review, not a live feed).
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import logserv_ocsf                       # noqa: E402
from modules.log_review import LogReviewAuditor        # noqa: E402

BASE_MS = 1768471200000  # 2026-01-15T10:00:00Z, epoch milliseconds


def _auth(user, ok=True, host="WS-01", ms=BASE_MS, **extra):
    ev = {"class_uid": 3002, "class_name": "Authentication", "activity_id": 1,
          "time": ms, "status_id": 1 if ok else 2,
          "status": "Success" if ok else "Failure",
          "actor": {"user": {"name": user}}, "src_endpoint": {"hostname": host}}
    ev.update(extra)
    return ev


# ── field normalisation ───────────────────────────────────────────────────────
def test_authentication_success_maps_to_dialog_logon():
    row = logserv_ocsf.to_audit_events([_auth("ALICE")])[0]
    assert row["EVENT_CLASS"] == "dialog_logon"
    assert row["USER"] == "ALICE" and row["TERMINAL"] == "WS-01"


def test_authentication_failure_maps_to_dialog_logon_failure():
    assert logserv_ocsf.to_audit_events([_auth("BOB", ok=False)])[0]["EVENT_CLASS"] \
        == "dialog_logon_failure"


def test_rfc_logon_is_recognised():
    row = logserv_ocsf.to_audit_events([_auth("SVC", auth_protocol="RFC")])[0]
    assert row["EVENT_CLASS"] == "rfc_logon"


def test_epoch_ms_becomes_date_and_time_strings():
    row = logserv_ocsf.to_audit_events([_auth("ALICE", ms=BASE_MS)])[0]
    assert row["DATE"] == "2026-01-15" and row["TIME"] == "10:00:00"


def test_sap_fields_read_from_unmapped():
    ev = _auth("ALICE")
    ev["unmapped"] = {"client": "100", "tcode": "SM49"}
    row = logserv_ocsf.to_audit_events([ev])[0]
    assert row["CLIENT"] == "100" and row["TCODE"] == "SM49"


def test_non_auth_class_defers_to_message_and_tcode():
    # A non-Authentication event carries no mapped class; its message/tcode are
    # preserved so log_review's own heuristics still classify it.
    ev = {"class_uid": 1007, "class_name": "Process Activity", "time": BASE_MS,
          "message": "External command executed", "actor": {"user": {"name": "OPS"}},
          "unmapped": {"tcode": "SM69"}}
    row = logserv_ocsf.to_audit_events([ev])[0]
    assert row["EVENT_CLASS"] == ""        # not mapped here
    assert row["TCODE"] == "SM69" and "External command" in row["TEXT"]


# ── shape tolerance ───────────────────────────────────────────────────────────
def test_accepts_events_wrapper_and_bare_list():
    assert len(logserv_ocsf.to_audit_events({"events": [_auth("A"), _auth("B")]})) == 2
    assert len(logserv_ocsf.to_audit_events([_auth("A")])) == 1


def test_garbage_and_empty_are_skipped_not_raised():
    assert logserv_ocsf.to_audit_events(None) == []
    assert logserv_ocsf.to_audit_events("nonsense") == []
    assert logserv_ocsf.to_audit_events([1, "x", {}, {"time": "bad"}]) == []


def test_event_with_no_usable_time_is_still_returned_undated():
    row = logserv_ocsf.to_audit_events([_auth("ALICE", ms="not-a-number")])[0]
    assert "DATE" not in row and row["USER"] == "ALICE"


# ── end to end: a LogServ batch fires an existing pattern ─────────────────────
def test_a_logserv_spray_batch_fires_pattern_010_through_log_review():
    batch = {"events": [_auth("USER%d" % i, ok=False, host="attacker",
                              ms=BASE_MS + i * 60000) for i in range(6)]}
    ids = {f["check_id"] for f in LogReviewAuditor({"logserv_events": batch}, {}).run_all_checks()}
    assert "LREV-PAT-010" in ids


def test_no_logserv_export_leaves_the_review_unchanged():
    # Absent source: the LogServ path contributes nothing and raises nothing.
    ids = {f["check_id"] for f in LogReviewAuditor({}, {}).run_all_checks()}
    assert not any(c.startswith("LREV-PAT") for c in ids)


# ── system-log (non-SAL) extraction for the broader log-class detectors ───────
def _gw(program="ZEVILTP", host="attacker-1", gw="sapprd01", ms=BASE_MS,
        denied=False, message=None, **extra):
    """A gateway registered-program OCSF event as LogServ would forward it."""
    ev = {"class_name": "SAP Gateway", "activity_name": "Register Program",
          "time": ms,
          "status_id": 2 if denied else 1,
          "status": "Denied" if denied else "Success",
          "message": message or "External program %s registered via reginfo" % program,
          "src_endpoint": {"hostname": host},
          "dst_endpoint": {"hostname": gw},
          "unmapped": {"program": program}}
    ev.update(extra)
    return ev


def test_gateway_event_is_extracted_as_a_system_event():
    row = logserv_ocsf.to_system_events([_gw()])[0]
    assert row["CLASS"] == "gateway" and row["ACTION"] == "register"
    assert row["PROGRAM"] == "ZEVILTP" and row["GATEWAY_HOST"] == "sapprd01"
    assert row["SRC_HOST"] == "attacker-1" and row["DECISION"] == "allowed"
    assert row["DATE"] == "2026-01-15" and row["TIME"] == "10:00:00"


def test_gateway_denial_reads_the_acl_verdict():
    row = logserv_ocsf.to_system_events([_gw(denied=True)])[0]
    assert row["DECISION"] == "denied" and row["ACTION"] == "deny"


def test_gateway_monitor_mode_is_recognised():
    ev = _gw(message="Program ZX would be denied by secinfo (monitor mode), allowed")
    assert logserv_ocsf.to_system_events([ev])[0]["DECISION"] == "monitored"


def test_gateway_events_do_not_leak_into_the_sal_rows():
    # The whole point of the split: a gateway event must not become an audit-log
    # row and inflate the window log_review reviews.
    assert logserv_ocsf.to_audit_events([_gw()]) == []


def test_sal_events_are_not_claimed_as_system_events():
    assert logserv_ocsf.to_system_events([_auth("ALICE")]) == []


def test_a_tcode_event_stays_sal_even_with_gateway_words():
    # A SAP transaction code is the strongest SAL signal; an event carrying one is
    # classified by log_review's heuristics, not pulled out as a system event.
    ev = {"class_name": "SAP Gateway", "time": BASE_MS, "message": "reginfo check",
          "actor": {"user": {"name": "OPS"}}, "unmapped": {"tcode": "SMGW"}}
    assert logserv_ocsf.to_system_events([ev]) == []
    assert logserv_ocsf.to_audit_events([ev])[0]["TCODE"] == "SMGW"


def test_gateway_batch_does_not_fire_any_sal_pattern_through_log_review():
    batch = {"events": [_gw(program="ZTP%d" % i, ms=BASE_MS + i * 60000)
                        for i in range(8)]}
    ids = {f["check_id"] for f in LogReviewAuditor({"logserv_events": batch}, {}).run_all_checks()}
    assert not any(c.startswith("LREV-PAT") for c in ids)
