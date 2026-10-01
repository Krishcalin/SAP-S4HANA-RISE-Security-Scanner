"""The SAP LogServ gateway-log review (modules/logserv_review.py).

A retrospective review over the exported gateway log — the same discipline as
log_review, applied to the RFC gateway class LogServ forwards. Three things are
defended: the three patterns fire on a window built to contain them; a gateway
event never reaches this module as a Security-Audit-Log row (that split lives in
logserv_ocsf); and the findings name gateway/program objects so CORR-GW-* can
join them to the configuration findings.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.logserv_review import LogServReviewAuditor   # noqa: E402

BASE_MS = 1768471200000  # 2026-01-15T10:00:00Z


def _gw(program="ZEVILTP", host="attacker-1", gw="sapprd01", ms=BASE_MS,
        action="register", denied=False, monitored=False, message=None):
    status_id = 2 if denied else 1
    if monitored:
        msg = message or "Program %s would be denied by secinfo (simulation mode)" % program
    elif denied:
        msg = message or "Registration of %s denied by reginfo" % program
    else:
        msg = message or "External program %s %sed via reginfo" % (program, action)
    return {"class_name": "SAP Gateway", "activity_name": "%s Program" % action.title(),
            "time": ms, "status_id": status_id,
            "status": "Denied" if denied else "Success",
            "message": msg,
            "src_endpoint": {"hostname": host},
            "dst_endpoint": {"hostname": gw},
            "unmapped": {"program": program}}


def _run(events):
    return LogServReviewAuditor({"logserv_events": {"events": events}}).run_all_checks()


def _ids(findings):
    return {f["check_id"] for f in findings}


def _by_id(findings, cid):
    return [f for f in findings if f["check_id"] == cid][0]


# ── the three patterns fire ──────────────────────────────────────────────────
def test_external_program_registration_fires_gwlog_001():
    f = _by_id(_run([_gw(program="ZBADTP")]), "GWLOG-001")
    assert f["severity"] == "HIGH" and f["scope"] == "aggregate"
    types = {o["type"] for o in f["affected_objects"]}
    assert types == {"program", "gateway"}
    assert any(o["name"] == "ZBADTP" and o["type"] == "program"
               for o in f["affected_objects"])


def test_acl_denials_fire_gwlog_002():
    events = [_gw(host="prober", denied=True, ms=BASE_MS + i * 1000) for i in range(4)]
    f = _by_id(_run(events), "GWLOG-002")
    assert f["severity"] == "MEDIUM"
    assert f["details"]["blocked_attempts"] == 4


def test_permissive_gateway_used_fires_gwlog_003():
    f = _by_id(_run([_gw(monitored=True)]), "GWLOG-003")
    assert f["severity"] == "HIGH"
    assert f["details"]["connections"] == 1


def test_the_window_is_stated_retrospectively():
    f = _by_id(_run([_gw()]), "GWLOG-001")
    assert "Reviewed window: 2026-01-15" in f["description"]


# ── silence ──────────────────────────────────────────────────────────────────
def test_no_gateway_log_is_silent():
    assert LogServReviewAuditor({}).run_all_checks() == []


def test_a_pure_sal_event_is_not_a_gateway_event():
    auth = {"class_uid": 3002, "class_name": "Authentication", "time": BASE_MS,
            "status_id": 1, "actor": {"user": {"name": "ALICE"}}}
    assert LogServReviewAuditor({"logserv_events": {"events": [auth]}}).run_all_checks() == []


def test_an_allowed_registration_is_not_a_denial_or_permissive():
    ids = _ids(_run([_gw()]))
    assert "GWLOG-001" in ids
    assert "GWLOG-002" not in ids and "GWLOG-003" not in ids
