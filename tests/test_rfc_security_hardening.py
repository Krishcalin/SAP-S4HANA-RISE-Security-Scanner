"""RFC hardening checks adopted from SAP's "Securing Remote Function Call" whitepaper.

Each check is written in the one direction the rest of the product is: it reports what
it positively found, names the exact SAP artifact, and stays silent where the export
gives no evidence. The tests below pin both directions — the finding fires on the
insecure shape and stays silent on the secure one — because a check that cannot stay
silent is as useless as one that cannot fire.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.abap_authorizations import AbapAuthorizationAuditor   # noqa: E402
from modules.system_trust import SystemTrustAuditor               # noqa: E402
from modules.security_params import SecurityParamAuditor          # noqa: E402
from modules.log_monitoring import LogMonitoringAuditor           # noqa: E402


def _fired(auditor):
    out = {}
    for f in auditor.run_all_checks() or []:
        out.setdefault(f["check_id"], []).append(f)
    return out


def _auth(role, obj, auth, field, low, high=""):
    return {"AGR_NAME": role, "OBJECT": obj, "AUTH": auth,
            "FIELD": field, "LOW": low, "HIGH": high}


# ═════════════════════════════════════════════════════════════════════════════
#  AUTH-018 — S_DEVELOP ACTVT=16 test execution of function modules (SE37)
# ═════════════════════════════════════════════════════════════════════════════

def test_s_develop_test_execution_on_function_modules_is_reported():
    rows = [_auth("Z_SUP", "S_DEVELOP", "A1", "OBJTYPE", "FUGR"),
            _auth("Z_SUP", "S_DEVELOP", "A1", "ACTVT", "16")]
    fired = _fired(AbapAuthorizationAuditor({"role_auth_values": rows}))
    assert "AUTH-018" in fired
    assert fired["AUTH-018"][0]["severity"] == "MEDIUM"


def test_s_develop_create_change_is_not_the_test_execution_finding():
    """ACTVT 01/02 is AUTH-014's create/change vector, not AUTH-018's test execution."""
    rows = [_auth("Z_DEV", "S_DEVELOP", "A1", "OBJTYPE", "FUGR"),
            _auth("Z_DEV", "S_DEVELOP", "A1", "ACTVT", "02")]
    assert "AUTH-018" not in _fired(AbapAuthorizationAuditor({"role_auth_values": rows}))


def test_s_develop_test_execution_on_a_non_function_object_is_not_reported():
    """The SE37 vector is object type FUGR; ACTVT=16 on PROG is not it."""
    rows = [_auth("Z_X", "S_DEVELOP", "A1", "OBJTYPE", "PROG"),
            _auth("Z_X", "S_DEVELOP", "A1", "ACTVT", "16")]
    assert "AUTH-018" not in _fired(AbapAuthorizationAuditor({"role_auth_values": rows}))


# ═════════════════════════════════════════════════════════════════════════════
#  AUTH-019 / AUTH-020 — S_RFC_ADM (SM59) and S_RFC_TT (SMT1) maintenance
# ═════════════════════════════════════════════════════════════════════════════

def test_rfc_admin_maintenance_is_reported():
    rows = [_auth("Z_ADM", "S_RFC_ADM", "A1", "ACTVT", "02")]
    assert "AUTH-019" in _fired(AbapAuthorizationAuditor({"role_auth_values": rows}))


def test_rfc_admin_display_only_is_not_reported():
    """Display (03) is not the who-can-change-destinations question the check asks."""
    rows = [_auth("Z_DIS", "S_RFC_ADM", "A1", "ACTVT", "03")]
    assert "AUTH-019" not in _fired(AbapAuthorizationAuditor({"role_auth_values": rows}))


def test_trust_maintenance_object_is_reported():
    rows = [_auth("Z_TT", "S_RFC_TT", "A1", "ACTVT", "01")]
    fired = _fired(AbapAuthorizationAuditor({"role_auth_values": rows}))
    assert "AUTH-020" in fired
    assert fired["AUTH-020"][0]["severity"] == "MEDIUM"


# ═════════════════════════════════════════════════════════════════════════════
#  AUTH-013 — STRUST is now a critical transaction (PSE / crypto key store)
# ═════════════════════════════════════════════════════════════════════════════

def test_strust_is_treated_as_a_critical_transaction():
    rows = [_auth("Z_ANY", "S_TCODE", "A1", "TCD", "STRUST")]
    fired = _fired(AbapAuthorizationAuditor({"role_auth_values": rows}))
    assert "AUTH-013" in fired
    assert any("STRUST" in i for i in fired["AUTH-013"][0]["affected_items"])


# ═════════════════════════════════════════════════════════════════════════════
#  TRUST-009 — privileged user stored in an RFC destination (RFC hopping)
# ═════════════════════════════════════════════════════════════════════════════

def _hop(dest_user, holder=None, profile="SAP_ALL", ustyp="B", rfcauth="STORED"):
    data = {"rfc_destinations": [{"RFCDEST": "D1", "RFCTYPE": "3",
                                  "RFCUSER": dest_user, "RFCAUTH": rfcauth}]}
    if holder:
        data["profiles"] = [{"BNAME": holder, "PROFILE": profile}]
        data["users"] = [{"BNAME": holder, "USTYP": ustyp}]
    return data


def test_privileged_stored_destination_user_is_reported():
    fired = _fired(SystemTrustAuditor(_hop("RFC_ADMIN", "RFC_ADMIN")))
    assert "TRUST-009" in fired
    assert fired["TRUST-009"][0]["severity"] == "HIGH"
    assert "RFC_ADMIN" in fired["TRUST-009"][0]["affected_items"][0]


def test_non_privileged_stored_user_is_not_rfc_hopping():
    assert "TRUST-009" not in _fired(
        SystemTrustAuditor(_hop("SVC01", "SVC01", profile="Z_CUSTOM")))


def test_a_stored_user_that_is_not_a_local_user_is_not_guessed_at():
    """The privilege join is sound only for users of THIS system; an unknown name is
    a user of the target system this scan cannot see, so nothing is claimed."""
    data = {"rfc_destinations": [{"RFCDEST": "D1", "RFCTYPE": "3",
                                  "RFCUSER": "REMOTE_ADMIN", "RFCAUTH": "STORED"}]}
    assert "TRUST-009" not in _fired(SystemTrustAuditor(data))


def test_a_trusted_destination_is_not_double_reported_as_hopping():
    """A trusted destination is TRUST-004's domain (current-user vs fixed-user), so the
    stored-credential hopping check steps aside for it."""
    assert "TRUST-009" not in _fired(
        SystemTrustAuditor(_hop("RFC_ADMIN", "RFC_ADMIN", rfcauth="TRUSTED")))


# ═════════════════════════════════════════════════════════════════════════════
#  TRUST-012 — RFCSYSACL behind table authorization group TTRL
# ═════════════════════════════════════════════════════════════════════════════

def test_rfcsysacl_without_ttrl_is_reported():
    data = {"table_auth_groups": [{"TABNAME": "RFCSYSACL", "CCLASS": "SS"}]}
    fired = _fired(SystemTrustAuditor(data))
    assert "TRUST-012" in fired
    assert fired["TRUST-012"][0]["severity"] == "HIGH"


def test_rfcsysacl_behind_ttrl_is_not_reported():
    data = {"table_auth_groups": [{"TABNAME": "RFCSYSACL", "CCLASS": "TTRL"}]}
    assert "TRUST-012" not in _fired(SystemTrustAuditor(data))


def test_rfcsysacl_absent_from_the_extract_makes_no_claim():
    """A TDDAT extract that omits RFCSYSACL is filtered/partial, not evidence the
    table has no group, so the check stays silent rather than guessing."""
    data = {"table_auth_groups": [{"TABNAME": "USR02", "CCLASS": "SPWD"}]}
    assert "TRUST-012" not in _fired(SystemTrustAuditor(data))


# ═════════════════════════════════════════════════════════════════════════════
#  PARAM-gw/sim_mode — RFC gateway ACL simulation mode left active
# ═════════════════════════════════════════════════════════════════════════════

def test_gw_sim_mode_active_is_reported():
    data = {"security_params": [{"NAME": "gw/sim_mode", "VALUE": "1"}]}
    assert "PARAM-gw/sim_mode" in _fired(SecurityParamAuditor(data))


def test_gw_sim_mode_off_is_not_reported():
    data = {"security_params": [{"NAME": "gw/sim_mode", "VALUE": "0"}]}
    assert "PARAM-gw/sim_mode" not in _fired(SecurityParamAuditor(data))


# ═════════════════════════════════════════════════════════════════════════════
#  LOG-AUD-003 — RFC callback (DUI/DUJ/DUK) and switchable-auth (DUO/DUP/DUQ)
# ═════════════════════════════════════════════════════════════════════════════

_TEN = ("dialog_logon_failure", "rfc_logon", "transaction_start", "user_master_change",
        "authority_check_fail", "report_start", "rfc_function_call", "table_access",
        "system_event", "audit_config_change")


def test_rfc_callback_and_switchable_auth_events_are_required():
    """The ten pre-existing classes are all active; the RFC callback and switchable-
    authorization classes are still reported as uncovered."""
    audit = [{"CONFIG_NAME": c, "EVENT_CLASS": c, "ACTIVE": "ACTIVE"} for c in _TEN]
    fired = _fired(LogMonitoringAuditor({"security_audit_log": audit}))
    assert "LOG-AUD-003" in fired
    items = " ".join(fired["LOG-AUD-003"][0]["affected_items"])
    assert "rfc_callback" in items and "switchable_authorization" in items


def test_an_all_classes_filter_covers_the_rfc_events():
    """An 'All audit classes' filter satisfies every required class, the new ones
    included — the same escape the other ten events already honour."""
    audit = [{"CONFIG_NAME": "All", "EVENT_CLASS": "ALL", "ACTIVE": "ACTIVE"}]
    assert "LOG-AUD-003" not in _fired(LogMonitoringAuditor({"security_audit_log": audit}))
