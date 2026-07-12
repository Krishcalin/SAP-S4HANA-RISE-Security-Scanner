"""Focused tests for the GRC Access Control module + the adversarial-review fixes:
RISK_TYPE must not be read as criticality, ARM blank-risk gating, CLOSED requests
are not provisioned, and expired mitigations leave a SoD violation open.
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.grc_access_control import GrcAccessControlAuditor  # noqa: E402


def _run(data):
    a = GrcAccessControlAuditor(data)
    a.run_all_checks()
    return {f["check_id"]: f for f in a.findings}


def test_empty_input_no_crash():
    assert GrcAccessControlAuditor({}).run_all_checks() == []


# ── RISK_TYPE vs criticality (review fix #1/#3) ────────────────────────────────

def test_risk_type_not_treated_as_criticality():
    # RISK_TYPE-only export (1=SoD, 2=Critical Action, 3=Critical Permission) is a
    # classification, NOT a severity — a disabled type-1/2 must NOT be reported as a
    # disabled CRITICAL/HIGH risk (was a false positive).
    rows = [{"RISK_ID": "S1", "RISK_TYPE": "1", "STATUS": "DISABLED", "OWNER": "RO"},
            {"RISK_ID": "S2", "RISK_TYPE": "2", "STATUS": "DISABLED", "OWNER": "RO"},
            {"RISK_ID": "S3", "RISK_TYPE": "3", "STATUS": "DISABLED", "OWNER": "RO"}]
    got = _run({"grac_sod_risks": rows})
    assert "GRC-RS-001" not in got


def test_real_risk_level_still_flags_disabled_critical():
    rows = [{"RISK_ID": "C1", "RISK_LEVEL": "Critical", "STATUS": "DISABLED", "OWNER": "RO"},
            {"RISK_ID": "H1", "RISK_LEVEL": "High", "STATUS": "DISABLED", "OWNER": "RO"},
            {"RISK_ID": "L1", "RISK_LEVEL": "Low", "STATUS": "DISABLED", "OWNER": "RO"}]
    got = _run({"grac_sod_risks": rows})
    assert "GRC-RS-001" in got and got["GRC-RS-001"]["details"]["count"] == 2   # Low not counted


# ── ARM blank-risk gating (review fix #4) ──────────────────────────────────────

def test_arm_blank_risk_flagged_when_column_present():
    rows = [{"REQ_ID": "R1", "REQUESTOR": "A", "PROVISIONED_USER": "B", "APPROVER": "MGR",
             "PROVISIONED": "YES", "RISK_ANALYSIS": "YES"},
            {"REQ_ID": "R2", "REQUESTOR": "A", "PROVISIONED_USER": "C", "APPROVER": "MGR",
             "PROVISIONED": "YES", "RISK_ANALYSIS": ""}]   # blank on a provisioned request
    got = _run({"grac_access_requests": rows})
    assert "GRC-ARM-002" in got and any("R2" in i for i in got["GRC-ARM-002"]["affected_items"])


def test_arm_no_false_positive_when_risk_column_absent():
    # export with NO risk-analysis column at all -> must not flag every request
    rows = [{"REQ_ID": "R1", "REQUESTOR": "A", "PROVISIONED_USER": "B", "APPROVER": "MGR", "PROVISIONED": "YES"}]
    got = _run({"grac_access_requests": rows})
    assert "GRC-ARM-002" not in got


# ── CLOSED request is not "provisioned" (review fix #5) ────────────────────────

def test_closed_request_not_treated_as_provisioned():
    rows = [{"REQ_ID": "R9", "REQUESTOR": "U", "PROVISIONED_USER": "U", "APPROVER": "",
             "PROVISIONED": "CLOSED", "RISK_ANALYSIS": "NO"}]
    got = _run({"grac_access_requests": rows})
    # a closed/rejected request with no approver + self-target must NOT raise ARM findings
    assert "GRC-ARM-001" not in got and "GRC-ARM-001B" not in got and "GRC-ARM-002" not in got


# ── expired mitigation leaves the SoD violation open ───────────────────────────

def test_expired_mitigation_leaves_violation_open():
    rows = [{"USERID": "U1", "RISK_ID": "P2P_01", "MITIGATION_ID": "M1", "VALID_TO": "20200101"},
            {"USERID": "U2", "RISK_ID": "O2C_02", "MITIGATION_ID": "M2", "VALID_TO": "20991231"}]
    got = _run({"grac_sod_violations": rows})
    assert "GRC-ARA-001" in got
    items = " ".join(got["GRC-ARA-001"]["affected_items"])
    assert "U1" in items and "U2" not in items       # expired counts as open; active does not
