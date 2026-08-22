"""Regression tests for the Phase-5 adversarial-review fixes.

Each test pins a specific confirmed defect so it cannot silently regress:
  HANADB-PARAM-005  strict section scoping (no cross-section 'enabled' leak) + targets_for_
  CRYPTO-HANA-004   valid backup-encryption SQL (ALTER SYSTEM BACKUP ENCRYPTION ON)
  CRYPTO-HANA-005   layer-precedence: effective (highest-layer) value is evaluated
  BTP-IAS-004       absent-lockout not a finding; minLength=0 is HIGH; 'standard' tier alone is not a finding
  BTP-CC-008        CVE only for the 2.15.0-2.16.1 regression range; CWE-295 / CVSS 7.4 wording
  AUTH-016          ICF_VALUE = SM59 authorization-group value (not destination name); no fabricated note subtitle
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.hana_db_security import HanaDbSecurityAuditor as HANA          # noqa: E402
from modules.crypto_posture import CryptoPostureAuditor as CRYPTO          # noqa: E402
from modules.btp_cloud_surface import BtpCloudSurfaceAuditor as BTP        # noqa: E402
from modules.abap_authorizations import AbapAuthorizationAuditor as AUTHZ  # noqa: E402


def _run(cls, data):
    a = cls(dict(data), {})
    a.run_all_checks()
    return {f["check_id"]: f for f in a.findings}


# ── HANADB-PARAM-005 : section scoping + parameter name ───────────────────────

def test_cross_db_does_not_leak_from_other_section():
    got = _run(HANA, {"hana_parameters": [
        {"FILE_NAME": "global.ini", "SECTION": "expensive_statement", "KEY": "enabled", "VALUE": "true"},
    ]})
    assert "HANADB-PARAM-005" not in got   # 'enabled' belongs to another section


def test_cross_db_fires_on_real_section_and_names_targets_for():
    got = _run(HANA, {"hana_parameters": [
        {"FILE_NAME": "global.ini", "SECTION": "cross_database_access", "KEY": "enabled", "VALUE": "true"},
    ]})
    assert "HANADB-PARAM-005" in got
    blob = got["HANADB-PARAM-005"]["description"] + got["HANADB-PARAM-005"]["remediation"]
    assert "targets_for_" in blob and "targets_<db>" not in blob


# ── CRYPTO-HANA-004 : valid backup-encryption SQL ─────────────────────────────

def test_backup_encryption_remediation_is_valid_sql():
    got = _run(CRYPTO, {"hana_encryption": {"backupEncryption": False}})
    rem = got["CRYPTO-HANA-004"]["remediation"]
    assert "ALTER SYSTEM BACKUP ENCRYPTION ON" in rem
    assert "ENCRYPTION CONFIGURATION SET" not in rem   # the invalid form must be gone


# ── CRYPTO-HANA-005 : layer precedence ────────────────────────────────────────

def test_replication_tls_uses_effective_layer_value():
    # DEFAULT off but SYSTEM on -> effective ON -> no finding
    on = _run(CRYPTO, {"hana_parameters": [
        {"SECTION": "system_replication_communication", "KEY": "enable_ssl", "VALUE": "false", "LAYER_NAME": "DEFAULT"},
        {"SECTION": "system_replication_communication", "KEY": "enable_ssl", "VALUE": "true", "LAYER_NAME": "SYSTEM"},
    ]})
    assert "CRYPTO-HANA-005" not in on
    # highest layer off -> finding
    off = _run(CRYPTO, {"hana_parameters": [
        {"SECTION": "system_replication_communication", "KEY": "enable_ssl", "VALUE": "true", "LAYER_NAME": "DEFAULT"},
        {"SECTION": "system_replication_communication", "KEY": "enable_ssl", "VALUE": "false", "LAYER_NAME": "SYSTEM"},
    ]})
    assert "CRYPTO-HANA-005" in off


# ── BTP-IAS-004 : absence vs explicit values, tier handling ───────────────────

def _ias(policy):
    return _run(BTP, {"ias_config": {"passwordPolicy": policy}})


def test_ias_absent_lockout_is_not_a_finding():
    assert "BTP-IAS-004" not in _ias({"minLength": 10, "requireComplexity": True})


def test_ias_minlength_zero_is_high():
    got = _ias({"minLength": 0})
    assert "BTP-IAS-004" in got and got["BTP-IAS-004"]["severity"] == "HIGH"


def test_ias_standard_tier_alone_is_not_a_finding():
    # SAP 'Standard' policy already enforces length 8 / complexity / lockout
    assert "BTP-IAS-004" not in _ias({"policyType": "standard", "minLength": 8, "requireComplexity": True})


def test_ias_explicit_zero_lockout_still_flagged():
    got = _ias({"maxFailedAttempts": 0})
    assert "BTP-IAS-004" in got


# ── BTP-CC-008 : CVE regression range + accuracy ──────────────────────────────

def _cc(version):
    return _run(BTP, {"cloud_connector": {"version": version}})


def test_cc_cve_range_only():
    inrange = _cc("2.15.2")
    assert "BTP-CC-008" in inrange
    f = inrange["BTP-CC-008"]
    assert f["severity"] == "HIGH" and "CVE-2024-25642" in f["title"]
    # accuracy: CWE-295 / 7.4, not deserialization / 9.1
    blob = f["description"] + " ".join(f["references"])
    assert "CWE-295" in blob and "7.4" in blob
    assert "deserialization" not in blob.lower() and "9.1" not in blob


def test_cc_below_regression_is_not_cve():
    old = _cc("2.9.0")
    assert "BTP-CC-008" in old                    # still flagged (old/EOL)
    f = old["BTP-CC-008"]
    assert f["severity"] == "MEDIUM"              # but MEDIUM currency, not the CVE
    assert "CVE-2024-25642" not in f["title"]


def test_cc_fixed_version_clean():
    assert "BTP-CC-008" not in _cc("2.16.2")


# ── AUTH-016 : ICF_VALUE semantics + reference accuracy ───────────────────────

def test_auth016_semantics_and_reference():
    data = {"role_auth_values": [
        {"AGR_NAME": "Z_BAD", "OBJECT": "S_ICF", "AUTH": "I1", "FIELD": "ICF_FIELD", "LOW": "DEST", "HIGH": ""},
        {"AGR_NAME": "Z_BAD", "OBJECT": "S_ICF", "AUTH": "I1", "FIELD": "ICF_VALUE", "LOW": "*", "HIGH": ""},
    ]}
    got = _run(AUTHZ, data)
    assert "AUTH-016" in got
    f = got["AUTH-016"]
    # description explains ICF_VALUE is the SM59 authorization-group value, not the destination name
    assert "authorization-group" in f["description"] or "Authorization for Destination" in f["description"]
    # the fabricated note subtitle must be gone
    refs = " ".join(f["references"])
    assert "RFC / destination authorization risks" not in refs
