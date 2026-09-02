"""Checks that had never been seen to fire — anywhere, by anything.

`docs/CHECK_FIRING.md` counts every check id that fires somewhere in this suite
or against the bundled corpus. 87 of 804 appeared in neither. A check nobody has
ever watched work is a claim, not a control: if its parameter name, column name
or threshold is wrong it fires for no customer, and the report reads clean.

The 87 sorted into four groups, and only the last one is covered here:

  57  ARA-* and ABAP-* ids generated at run time from the duty-separation and
      custom-code rulesets. Each needs an estate that actually exhibits that
      risk or that code pattern; the corpus exhibits some and not others. A
      breadth question about the corpus, not a defect.
   6  blocked by a source the corpus has no file for at all.
   4  WDISP-* and ATC-* ids generated at run time from their own rulesets.
  21  reachable from data the corpus already carries, or from one small file,
      and simply never exercised — thresholds nobody crossed and branches
      nobody took.

Each test below constructs the smallest input that reaches one such branch. Two
of them turned up defects rather than gaps, and those live in
`test_certificate_posture.py` and `test_time_relative_checks.py`.

The value here is not the assertion. It is that the trigger for each check is
now written down: the next person to change one of these modules can see, in
one place, what the check was built to catch.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.btp_cloud_surface import BtpCloudSurfaceAuditor         # noqa: E402
from modules.code_transport import CodeTransportAuditor              # noqa: E402
from modules.crypto_posture import CryptoPostureAuditor              # noqa: E402
from modules.data_protection import DataProtectionAuditor            # noqa: E402
from modules.financial_controls import FinancialControlsAuditor      # noqa: E402
from modules.fiori_ui import FioriUiAuditor                          # noqa: E402
from modules.hana_db_security import HanaDbSecurityAuditor           # noqa: E402
from modules.iam_advanced import AdvancedIamAuditor                  # noqa: E402
from modules.integration_layer import IntegrationLayerAuditor        # noqa: E402
from modules.network_services import NetworkServiceAuditor           # noqa: E402
from modules.user_auth_audit import UserAuthAuditor                  # noqa: E402


def fired(auditor_cls, data):
    for args in ((data,), (data, None), (data, None, {})):
        try:
            auditor = auditor_cls(*args)
            break
        except TypeError:
            continue
    else:                                                   # pragma: no cover
        raise AssertionError("could not construct %s" % auditor_cls.__name__)
    return {f["check_id"] for f in (auditor.run_all_checks() or [])}


# ── identity and access ────────────────────────────────────────────────────

def test_iam_ref_001_a_dialog_user_serving_as_a_reference_user():
    """A reference user donates its authorizations to whoever names it. When
    that user is a Dialog account, somebody can also log in as the template."""
    assert "IAM-REF-001" in fired(AdvancedIamAuditor, {"users": [
        {"BNAME": "REF_TEMPLATE", "USTYP": "A"},
        {"BNAME": "JSMITH", "USTYP": "A", "REF_USER": "REF_TEMPLATE"},
    ]})


def test_iam_ff_000_firefighter_accounts_with_no_usage_log():
    """The absence of the log is the finding: emergency access exists and
    nothing evidences how it was used."""
    assert "IAM-FF-000" in fired(AdvancedIamAuditor, {
        "users": [{"BNAME": "FF_EMERGENCY_01", "USTYP": "A"}]})


def test_iam_xid_002_locked_in_s4_but_live_in_btp():
    """Locking the ABAP account is the offboarding step people remember. The
    BTP identity is the one that keeps working."""
    assert "IAM-XID-002" in fired(AdvancedIamAuditor, {
        "users": [{"BNAME": "JSMITH", "USTYP": "A", "UFLAG": "64",
                   "SMTP_ADDR": "j.smith@corp.example"}],
        "btp_users": [{"userName": "JSMITH", "roleCollections": []}],
    })


def test_usr_005_a_user_past_the_role_count_threshold():
    assert "USR-005" in fired(UserAuthAuditor, {"user_roles": [
        {"UNAME": "POWERUSER", "AGR_NAME": "Z_ROLE_%02d" % i} for i in range(35)]})


def test_usr_006_unrestricted_table_display_authority():
    assert "USR-006" in fired(UserAuthAuditor, {"auth_objects": [
        {"UNAME": "JSMITH", "OBJECT": "S_TABU_DIS", "FIELD": "DICBERCLS",
         "VALUE": "*"}]})


def test_iam_priv_001_two_halves_of_a_self_service_escalation():
    """S_USER_AGR=* edits any role; S_USER_GRP=* assigns any user to it. One
    reason is an administrator; two is somebody who can grant themselves
    anything without asking. The check needs at least two."""
    assert "IAM-PRIV-001" in fired(AdvancedIamAuditor, {"auth_objects": [
        {"UNAME": "LWANG", "OBJECT": "S_USER_AGR", "FIELD": "ACTVT", "VALUE": "*"},
        {"UNAME": "LWANG", "OBJECT": "S_USER_GRP", "FIELD": "ACTVT", "VALUE": "*"},
    ]})


def test_iam_priv_001_one_reason_alone_is_an_administrator_not_an_escalation():
    assert "IAM-PRIV-001" not in fired(AdvancedIamAuditor, {"auth_objects": [
        {"UNAME": "LWANG", "OBJECT": "S_USER_AGR", "FIELD": "ACTVT", "VALUE": "*"},
    ]})


# ── transports and custom code ─────────────────────────────────────────────

def test_net_006_a_modifiable_transport_request():
    """TRSTATUS D or L, not R. An open request in production is a change that
    has not been through the transport path."""
    assert "NET-006" in fired(NetworkServiceAuditor, {"transports": [
        {"TRKORR": "DEVK900001", "TRSTATUS": "D", "AS4USER": "DEVELOPER1",
         "AS4TEXT": "open request"}]})


def test_net_007_a_transport_whose_description_admits_what_it_is():
    assert "NET-007" in fired(NetworkServiceAuditor, {"transports": [
        {"TRKORR": "DEVK900002", "TRSTATUS": "R", "AS4USER": "DEVELOPER1",
         "AS4TEXT": "debug breakpoint left in ZFI_POST"}]})


def test_code_syschg_002_the_global_switch_is_closed_but_a_namespace_is_open():
    """The `elif` branch. While the global setting is Modifiable the module
    reports CODE-SYSCHG-001 and this one cannot be reached — which is the state
    the corpus has always been in."""
    got = fired(CodeTransportAuditor, {"system_change": [
        {"SCOPE": "GLOBAL", "MODIFIABLE": "Not modifiable"},
        {"SCOPE": "/CUST/", "MODIFIABLE": "Modifiable"},
    ]})
    assert "CODE-SYSCHG-002" in got
    assert "CODE-SYSCHG-001" not in got


def test_code_dead_001_dead_code_past_the_alerting_threshold():
    """Above 50 unreferenced objects this is the finding; below it the module
    reports CODE-DEAD-002 instead, so one row proves the wrong branch."""
    got = fired(CodeTransportAuditor, {"code_inventory": [
        {"OBJECT_NAME": "Z_OLD_%03d" % i, "OBJECT_TYPE": "PROG",
         "LAST_USED": "", "OWNER": "AGARCIA", "REFERENCED": "NO",
         "CREATED": "20180101"} for i in range(60)]})
    assert "CODE-DEAD-001" in got


# ── cryptography ───────────────────────────────────────────────────────────

def test_crypto_snc_002_snc_enabled_but_authentication_only():
    """Unreachable while SNC is off, which is how the corpus ships it. With
    SNC on and quality of protection at 1, traffic is authenticated and then
    sent in clear — the configuration that looks done and is not."""
    assert "CRYPTO-SNC-002" in fired(CryptoPostureAuditor, {"security_params": [
        {"PARAMETER": "snc/enable", "VALUE": "1"},
        {"PARAMETER": "snc/data_protection/min", "VALUE": "1"},
        {"PARAMETER": "snc/data_protection/max", "VALUE": "1"},
        {"PARAMETER": "snc/data_protection/use", "VALUE": "1"},
    ]})


# ── HANA ───────────────────────────────────────────────────────────────────

def test_hanadb_audit_003_policies_defined_and_none_of_them_active():
    """Auditing can be on globally and record nothing at all."""
    assert "HANADB-AUDIT-003" in fired(HanaDbSecurityAuditor, {
        "hana_audit_policies": [{"POLICY_NAME": "P_GRANTS",
                                 "IS_AUDIT_POLICY_ACTIVE": "FALSE",
                                 "AUDIT_ACTION_NAME": "GRANT PRIVILEGE"}]})


# ── Fiori ──────────────────────────────────────────────────────────────────

def test_fiori_cat_002_a_catalog_spread_across_too_many_roles():
    assert "FIORI-CAT-002" in fired(FioriUiAuditor, {"fiori_catalogs": [
        {"CATALOG_ID": "Z_CAT_WIDE", "SCOPE": "ROLE", "ROLE": "Z_ROLE_%02d" % i}
        for i in range(30)]})


def test_fiori_tile_001_a_tile_whose_role_lacks_the_service_authorization():
    """The tile launches; the OData call behind it is authorised by something
    other than what the service requires."""
    assert "FIORI-TILE-001" in fired(FioriUiAuditor, {
        "fiori_tiles": [{"TILE_ID": "Z_TILE_1", "ODATA_SERVICE": "Z_SRV",
                         "ROLE": "Z_ROLE", "AUTH_OBJECT_IN_ROLE": "S_SERVICE"}],
        "odata_auth": [{"SERVICE": "Z_SRV", "REQUIRED_AUTH_OBJECT": "S_TABU_DIS"}],
    })


# ── integration and BTP ────────────────────────────────────────────────────

def test_intg_ws_002_more_active_web_services_than_the_threshold():
    assert "INTG-WS-002" in fired(IntegrationLayerAuditor, {"ws_endpoints": [
        {"ENDPOINT_NAME": "Z_WS_%03d" % i, "SERVICE_NAME": "Z_SRV_%03d" % i,
         "ACTIVE": "X", "AUTH_METHOD": "BASIC"} for i in range(60)]})


def test_intg_topo_002_one_system_carrying_most_of_the_topology():
    """A hub is a single point whose compromise reaches everything wired to it,
    however well each individual connection is encrypted."""
    assert "INTG-TOPO-002" in fired(IntegrationLayerAuditor, {
        "integration_topology": [
            {"SOURCE_SYSTEM": "HUB", "TARGET_SYSTEM": "SYS%02d" % i,
             "PROTOCOL": "HTTPS", "ENCRYPTION": "TLS1.2"} for i in range(40)]})


def test_btp_cc_003_more_cloud_connector_backends_than_the_threshold():
    assert "BTP-CC-003" in fired(BtpCloudSurfaceAuditor, {"cloud_connector": [
        {"BACKEND_HOST": "sap%02d.corp" % i, "VIRTUAL_HOST": "v%02d" % i,
         "PROTOCOL": "HTTPS", "RESOURCE": "/sap/opu/odata"} for i in range(30)]})


@pytest.mark.parametrize("check_id", ["BTP-NET-001", "BTP-NET-002"])
def test_btp_net_a_public_endpoint_on_a_critical_service(check_id):
    """`btp_network` has no file in the corpus at all, so neither of these has
    ever run. The export is camelCase JSON, not the upper-case CSV columns the
    rest of the product reads — which is the sort of difference a check can be
    wrong about for years without anybody finding out."""
    assert check_id in fired(BtpCloudSurfaceAuditor, {"btp_network": [
        {"service": "hana-cloud", "endpointType": "PUBLIC", "privateLink": False,
         "url": "https://hana.example.hana.ondemand.com"}]})


# ── data protection ────────────────────────────────────────────────────────

@pytest.mark.parametrize("check_id", ["DPP-FIELD-001", "DPP-FIELD-002"])
def test_dpp_field_a_classified_field_without_logging_or_masking(check_id):
    """Both branches walk `personal_data_inventory`, NOT `sensitive_fields` —
    the two are declared sources of the same checks and only the first drives
    them. The corpus supplies the second and not the first, so these have never
    run even though the data looked present."""
    assert check_id in fired(DataProtectionAuditor, {
        "personal_data_inventory": [
            {"TABLE_NAME": "PA0002", "FIELD_NAME": "GBDAT",
             "CLASSIFICATION": "HIGH", "RAL_ENABLED": "NO",
             "MASKED_IN_NONPROD": "NO"}]})


# ── financial controls ─────────────────────────────────────────────────────

def test_fin_tol_002_an_export_that_was_supplied_and_came_back_empty():
    """The distinction this product is built on, done right in the source: an
    absent `tolerance_groups` returns silently because nothing was asked, while
    a SUPPLIED and empty one is an answer — no posting limits are defined."""
    assert "FIN-TOL-002" in fired(FinancialControlsAuditor,
                                  {"tolerance_groups": []})


def test_an_absent_tolerance_export_stays_silent():
    assert "FIN-TOL-002" not in fired(FinancialControlsAuditor, {})


# CODE-DEV-001 HAS TWO PATHS AND THEY FILTER DIFFERENTLY, which is easy to
# cross by accident — a first draft of these tests supplied both sources and
# proved the wrong one. `dev_access_prod` is the dedicated export and every row
# in it is reported, because `docs/EXPORT_GUIDE.md` defines that file as
# ALREADY filtered to the development authorizations by whoever took it. The
# fallback over `auth_objects` is the unfiltered general extract, so it applies
# the activity filter itself. Both paths are exercised below, separately.

def test_code_dev_001_from_the_dedicated_export():
    """`dev_access_prod` has no file in the corpus, so this path has never
    run."""
    assert "CODE-DEV-001" in fired(CodeTransportAuditor, {
        "dev_access_prod": [{"USERNAME": "DEVELOPER1", "TCODE": "SE38",
                             "AUTH_OBJECT": "S_DEVELOP", "ACTIVITY": "02"}]})


def test_code_dev_001_falls_back_to_the_general_authorization_extract():
    """S_DEVELOP with ACTVT 01 or 02 is the ability to write code directly in
    production — the change-management gap every transport control exists to
    close."""
    assert "CODE-DEV-001" in fired(CodeTransportAuditor, {
        "auth_objects": [{"UNAME": "DEVELOPER1", "OBJECT": "S_DEVELOP",
                          "FIELD": "ACTVT", "VALUE": "02"}]})


def test_code_dev_001_display_only_access_is_not_the_finding_on_the_fallback():
    """Reading code in production is not changing it."""
    assert "CODE-DEV-001" not in fired(CodeTransportAuditor, {
        "auth_objects": [{"UNAME": "DEVELOPER1", "OBJECT": "S_DEVELOP",
                          "FIELD": "ACTVT", "VALUE": "03"}]})
