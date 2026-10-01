"""Config-vs-log correlation (modules/correlation.py, CORR-*).

The correlation reads the OTHER auditors' findings and raises a higher-severity
finding where a configuration weakness and a log observation of it being used
coincide. What is defended here: it fires only when BOTH halves are present, a
denial (the ACL working) is not treated as exploitation, and the correlated
finding carries the gateway object so it joins the graph.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.correlation import CorrelationAuditor   # noqa: E402


def _run(peers):
    return CorrelationAuditor({}, None, {"peer_findings": peers}).run_all_checks()


def _config(check_id="BASELINE-007"):
    return {"check_id": check_id,
            "affected_objects": [{"type": "parameter_name", "name": "gw/acl_mode"}]}


def _log(check_id="GWLOG-001", host="SAPPRD01", program="ZBADTP"):
    return {"check_id": check_id,
            "affected_objects": [{"type": "gateway", "name": host},
                                 {"type": "program", "name": program}]}


def test_config_weakness_plus_log_use_fires_corr_gw_001():
    f = [x for x in _run([_config(), _log()]) if x["check_id"] == "CORR-GW-001"][0]
    assert f["severity"] == "CRITICAL"
    assert f["details"]["config_findings"] == ["BASELINE-007"]
    assert f["details"]["log_findings"] == ["GWLOG-001"]
    assert {"type": "gateway", "name": "SAPPRD01"} in f["affected_objects"]


def test_intg_gw_and_param_gw_are_also_config_weaknesses():
    for cid in ("INTG-GW-003", "PARAM-gw/sim_mode"):
        ids = {x["check_id"] for x in _run([_config(cid), _log("GWLOG-003")])}
        assert "CORR-GW-001" in ids, cid


def test_config_weakness_alone_does_not_correlate():
    assert "CORR-GW-001" not in {x["check_id"] for x in _run([_config()])}


def test_log_signal_alone_does_not_correlate():
    assert "CORR-GW-001" not in {x["check_id"] for x in _run([_log()])}


def test_a_denial_is_not_an_exploitation_signal():
    # GWLOG-002 is the ACL WORKING, so a config weakness plus denials is NOT an
    # active-exploitation indicator.
    peers = [_config(), {"check_id": "GWLOG-002", "affected_objects": []}]
    assert "CORR-GW-001" not in {x["check_id"] for x in _run(peers)}


def test_no_peers_is_silent():
    assert CorrelationAuditor({}, None, {}).run_all_checks() == []


def test_findings_in_a_different_system_do_not_cross_correlate():
    peers = [dict(_config(), system="PRD"), dict(_log(), system="QAS")]
    assert "CORR-GW-001" not in {x["check_id"] for x in _run(peers)}
