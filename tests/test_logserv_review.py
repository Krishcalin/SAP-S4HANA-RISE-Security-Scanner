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


# ── HANA / ICM / network detectors ────────────────────────────────────────────
def _hana(user="SYSTEM", action="GRANT", obj="", policy="", ok=True, ms=BASE_MS, message=None):
    um = {"db_user": user}
    if obj:
        um["db_object"] = obj
    if policy:
        um["audit_policy"] = policy
    return {"class_name": "SAP HANA Audit", "activity_name": action, "time": ms,
            "status_id": 1 if ok else 2,
            "message": message or "%s %s" % (user, action), "unmapped": um}


def _icm(path="/x", status=200, src="10.0.0.1", method="GET", ms=BASE_MS):
    return {"class_name": "ICM HTTP", "time": ms,
            "http_request": {"url": {"path": path}, "http_method": method},
            "http_response": {"code": status}, "src_endpoint": {"ip": src},
            "message": "%s %s" % (method, path)}


def _net(src="10.0.0.2", dst="sapprd01", port=3300, disp="Allowed", ms=BASE_MS):
    return {"class_name": "Firewall", "activity_name": "Connect", "time": ms,
            "src_endpoint": {"ip": src}, "dst_endpoint": {"hostname": dst, "port": port},
            "connection_info": {"protocol_name": "TCP"}, "disposition": disp,
            "message": "conn %s:%s" % (dst, port)}


def test_hana_audit_change_fires_hanalog_001():
    f = _by_id(_run([_hana(action="ALTER", policy="GLOBAL",
                           message="audit policy GLOBAL altered")]), "HANALOG-001")
    assert f["severity"] == "HIGH" and "GLOBAL" in f["details"]["policies"]


def test_hana_privileged_activity_fires_hanalog_002():
    f = _by_id(_run([_hana(user="SYSTEM", action="SELECT", obj="SYS.USERS")]), "HANALOG-002")
    assert f["severity"] == "HIGH"
    assert any(o["type"] == "hana_user" and o["name"] == "SYSTEM" for o in f["affected_objects"])


def test_hana_grant_by_ordinary_user_still_fires_hanalog_002():
    ids = _ids(_run([_hana(user="APPADMIN", action="GRANT")]))
    assert "HANALOG-002" in ids


def test_hana_failed_logon_fires_hanalog_003():
    f = _by_id(_run([_hana(user="APP", action="CONNECT", ok=False,
                           message="logon failed")]), "HANALOG-003")
    assert f["severity"] == "MEDIUM"


def test_ordinary_hana_read_by_normal_user_is_silent():
    assert "HANALOG-002" not in _ids(_run([_hana(user="APPUSER", action="SELECT")]))


def test_icm_admin_path_fires_icmlog_001():
    f = _by_id(_run([_icm(path="/sap/bc/webdynpro/sap/wd_analyze/admin", status=200)]),
               "ICMLOG-001")
    assert f["severity"] == "HIGH"


def test_icm_scanning_fires_icmlog_002():
    events = [_icm(path="/probe%d" % i, status=404, src="203.0.113.5") for i in range(6)]
    f = _by_id(_run(events), "ICMLOG-002")
    assert f["severity"] == "MEDIUM"


def test_icm_remote_execution_fires_icmlog_003():
    assert "ICMLOG-003" in _ids(_run([_icm(path="/sap/bc/soap/rfc", status=200)]))


def test_icm_ordinary_request_is_silent():
    assert not (_ids(_run([_icm(path="/sap/public/bc/ur", status=200)]))
                & {"ICMLOG-001", "ICMLOG-003"})


def test_network_sensitive_port_fires_netlog_001():
    assert "NETLOG-001" in _ids(_run([_net(port=3300, disp="Allowed")]))


def test_network_blocked_fires_netlog_002():
    assert "NETLOG-002" in _ids(_run([_net(disp="Denied")]))


def test_network_public_source_fires_netlog_003():
    f = _by_id(_run([_net(src="8.8.8.8", port=3600, disp="Allowed")]), "NETLOG-003")
    assert f["severity"] == "HIGH"


def test_private_source_on_sap_port_is_not_public():
    assert "NETLOG-003" not in _ids(_run([_net(src="10.1.1.1", port=3300)]))


def test_window_note_spans_all_classes():
    f = _by_id(_run([_hana()]), "HANALOG-002")
    assert "Reviewed window: 2026-01-15" in f["description"]
