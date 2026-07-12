"""Focused tests for role_governance + the adversarial-review fixes:
SU24 indicator precedence is order-independent, derived-role drift detects value-level
changes (not just object/field presence) while ignoring org-value differences, MANDT
is not an org level, and the ungenerated-profile wording is honest about assignment.
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.role_governance import RoleGovernanceAuditor  # noqa: E402


def _su24(rows):
    a = RoleGovernanceAuditor({"su24_proposals": rows})
    a.check_su24_proposal_hygiene()
    return {f["check_id"] for f in a.findings}


def _drv(auth, details):
    a = RoleGovernanceAuditor({"role_details": details, "role_auth_values": auth})
    a.check_derived_role_drift()
    return {f["check_id"] for f in a.findings}


def test_empty_input_no_crash():
    assert RoleGovernanceAuditor({}).run_all_checks() == []


# ── SU24 precedence is order-independent (review fix #1/#3) ─────────────────────

def test_su24_mixed_indicators_order_independent():
    rows = [{"TCODE": "ZFOO", "OBJECT": "O1", "CHECK_INDICATOR": "U"},
            {"TCODE": "ZFOO", "OBJECT": "O2", "CHECK_INDICATOR": "N"}]
    # same data, both orders -> same verdict (N gives the tcode a maintained decision)
    assert _su24(rows) == _su24(list(reversed(rows)))


def test_su24_all_unmaintained_flagged_and_maintained_not():
    assert "RG-SU24-001" in _su24([{"TCODE": "ZALLU", "OBJECT": "O1", "CHECK_INDICATOR": "U"},
                                   {"TCODE": "ZALLU", "OBJECT": "O2", "CHECK_INDICATOR": ""}])
    assert "RG-SU24-001" not in _su24([{"TCODE": "ZMAINT", "OBJECT": "O1", "CHECK_INDICATOR": "U"},
                                       {"TCODE": "ZMAINT", "OBJECT": "O2", "CHECK_INDICATOR": "CM"}])
    # standard (non Z/Y) tcodes are never flagged
    assert "RG-SU24-001" not in _su24([{"TCODE": "FB01", "OBJECT": "O1", "CHECK_INDICATOR": "U"}])


# ── derived-role drift detects VALUE changes, ignores org values (fix #2/#5) ────

_DET = [{"AGR_NAME": "Z_P"}, {"AGR_NAME": "Z_C", "PARENT_AGR": "Z_P"}]
_PARENT = [{"AGR_NAME": "Z_P", "OBJECT": "S_TCODE", "FIELD": "TCD", "LOW": "FB01", "HIGH": ""},
           {"AGR_NAME": "Z_P", "OBJECT": "F_BKPF_BUK", "FIELD": "ACTVT", "LOW": "03", "HIGH": ""},
           {"AGR_NAME": "Z_P", "OBJECT": "F_BKPF_BUK", "FIELD": "BUKRS", "LOW": "1000", "HIGH": ""}]


def test_derived_value_drift_detected():
    child = _PARENT + [{"AGR_NAME": "Z_C", "OBJECT": "S_TCODE", "FIELD": "TCD", "LOW": "FB01", "HIGH": ""},
                       {"AGR_NAME": "Z_C", "OBJECT": "F_BKPF_BUK", "FIELD": "ACTVT", "LOW": "01", "HIGH": "03"},
                       {"AGR_NAME": "Z_C", "OBJECT": "F_BKPF_BUK", "FIELD": "BUKRS", "LOW": "2000", "HIGH": ""}]
    assert "RG-DRV-001" in _drv(child, _DET)     # broadened ACTVT (03 -> 01-03) is drift


def test_derived_clean_when_only_org_value_differs():
    child = _PARENT + [{"AGR_NAME": "Z_C", "OBJECT": "S_TCODE", "FIELD": "TCD", "LOW": "FB01", "HIGH": ""},
                       {"AGR_NAME": "Z_C", "OBJECT": "F_BKPF_BUK", "FIELD": "ACTVT", "LOW": "03", "HIGH": ""},
                       {"AGR_NAME": "Z_C", "OBJECT": "F_BKPF_BUK", "FIELD": "BUKRS", "LOW": "2000", "HIGH": ""}]
    assert "RG-DRV-001" not in _drv(child, _DET)  # only org-level BUKRS value differs -> OK


def test_mandt_is_not_org_level():
    assert "MANDT" not in RoleGovernanceAuditor._ORG_FIELDS


# ── ungenerated-profile wording honest about assignment (fix #6) ───────────────

def test_ungenerated_wording_without_user_roles():
    a = RoleGovernanceAuditor({"role_profiles": [{"AGR_NAME": "ZR", "PROFILE": "", "GENERATED": "NO"}]})
    a.check_ungenerated_profiles()
    assert a.findings and "assigned to users" not in a.findings[0]["title"]


def test_ungenerated_flagged_when_assigned():
    a = RoleGovernanceAuditor({
        "role_profiles": [{"AGR_NAME": "ZR", "PROFILE": "", "GENERATED": "NO"},
                          {"AGR_NAME": "ZOK", "PROFILE": "T_X", "GENERATED": "YES"}],
        "user_roles": [{"UNAME": "U1", "AGR_NAME": "ZR"}]})
    a.check_ungenerated_profiles()
    got = {f["check_id"]: f for f in a.findings}
    assert "RG-GEN-001" in got and got["RG-GEN-001"]["details"]["count"] == 1  # ZOK generated, excluded
    assert "assigned to users" in got["RG-GEN-001"]["title"]
