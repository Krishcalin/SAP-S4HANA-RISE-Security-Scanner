"""The BTP settings fields that were ingested and never read.

`modules/btp_import.py` has normalised `accessTokenValidity`,
`refreshTokenValidity`, `iframeDomains`, `customEmailDomains` and
`treatUsersWithSameEmailAsSameUser` onto their subaccounts since it was written,
and built a per-tenant summary of the audit-log export. Nothing read any of it.

An ingested field with no consumer is a specific kind of dishonesty, not merely
dead code: the export guide asks a customer to run a command and send a file, the
coverage manifest confirms the file arrived, and the report then says nothing
about it. The reader concludes the setting was examined and found acceptable.

These tests cover the four checks that now read those fields, and one defect the
work exposed: BTP-GOV-001 reported a subaccount as having no audit logging on the
strength of a field its export never carried.
"""
from __future__ import annotations

import contextlib
import io
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.btp_cloud_surface import (BtpCloudSurfaceAuditor,      # noqa: E402
                                       _ACCESS_TOKEN_DEFAULT,
                                       _REFRESH_TOKEN_DEFAULT,
                                       _TOKEN_VALIDITY_FLOOR)

FIXTURES = ROOT / "tests" / "fixtures" / "btp_cli"


def _run(**data):
    """Findings from one hand-built data dict, keyed by check id."""
    out = {}
    for finding in BtpCloudSurfaceAuditor(dict(data), {}).run_all_checks():
        out.setdefault(finding["check_id"], []).append(finding)
    return out


def _subaccounts(*records):
    return {"btp_subaccounts": {"subaccounts": list(records)}}


def _sa(sa_id="sa-1", name="Production", **settings):
    record = {"id": sa_id, "name": name, "region": "eu10"}
    record.update(settings)
    return record


# ═════════════════════════════════════════════════════════════════════════════
#  The thresholds are SAP's, not ours
# ═════════════════════════════════════════════════════════════════════════════

def test_the_token_thresholds_are_the_numbers_sap_publishes():
    """A token lifetime has no natural right answer, so a threshold this product
    invented would be an opinion presented as a measurement. These three are
    quoted from SAP's "Setting Token Policy" section, and pinning them here means
    changing one has to be a deliberate act rather than a tuning tweak."""
    assert _ACCESS_TOKEN_DEFAULT == 43200        # "Default: 43200 seconds (12 hours)"
    assert _REFRESH_TOKEN_DEFAULT == 604800      # "Default: 604800 seconds (7 days)"
    assert _TOKEN_VALIDITY_FLOOR == 1800         # "not less than 30 minutes"


# ═════════════════════════════════════════════════════════════════════════════
#  BTP-TOK-*: token policy
# ═════════════════════════════════════════════════════════════════════════════

def test_a_lifetime_longer_than_the_sap_default_is_reported():
    fired = _run(**_subaccounts(_sa(accessTokenValidity=86400,
                                    refreshTokenValidity=604800)))
    assert "BTP-TOK-001" in fired
    finding = fired["BTP-TOK-001"][0]
    assert finding["severity"] == "HIGH"
    assert "86400" in finding["affected_items"][0]
    # The refresh token is exactly at the default, so it must not be named as
    # relaxed alongside the access token that genuinely was.
    assert "refresh token" not in finding["affected_items"][0]


def test_a_relaxed_subaccount_is_not_also_in_the_backlog_finding():
    """A subaccount that lengthened one token and left the other at the default
    belongs in the finding about the change, not the one about inaction — or the
    same subaccount is reported twice for one decision."""
    fired = _run(**_subaccounts(_sa(accessTokenValidity=86400,
                                    refreshTokenValidity=-1)))
    assert "BTP-TOK-001" in fired
    assert "BTP-TOK-002" not in fired


def test_the_unset_sentinel_reads_as_the_sap_default_not_as_zero():
    """`-1` is what the exports carry where nothing has been set. Read as a
    number of seconds it would be a lifetime in the past."""
    fired = _run(**_subaccounts(_sa(accessTokenValidity=-1,
                                    refreshTokenValidity=-1)))
    assert "BTP-TOK-002" in fired
    assert "BTP-TOK-003" not in fired, "-1 was read as a lifetime below the floor"
    assert fired["BTP-TOK-002"][0]["severity"] == "LOW"


def test_each_unset_token_names_only_its_own_default():
    """A subaccount that set a 30-minute access token and left the refresh token
    alone must not be told it is running on SAP's 12-hour access token."""
    item = _run(**_subaccounts(_sa(accessTokenValidity=1800,
                                   refreshTokenValidity=-1)))["BTP-TOK-002"][0]
    assert item["affected_items"] == [
        "Production (sa-1) — left at the SAP default: "
        "refresh token at 604800 s (7 days)"]


def test_a_lifetime_below_the_sap_floor_is_reported_separately():
    fired = _run(**_subaccounts(_sa(accessTokenValidity=300,
                                    refreshTokenValidity=43200)))
    assert "BTP-TOK-003" in fired
    assert "BTP-TOK-001" not in fired
    assert "300" in fired["BTP-TOK-003"][0]["affected_items"][0]


def test_a_field_that_was_never_exported_is_not_reported_as_defaulted():
    """A settings export trimmed to one of the two fields must not produce a
    claim about the other. Saying "refresh token left at the SAP default" of a
    field that was never in the file is the same fabrication as reading an
    absent auditLogEnabled as "logging is off", at a lower severity."""
    fired = _run(**_subaccounts(_sa(accessTokenValidity=1800)))
    assert not [k for k in fired if k.startswith("BTP-TOK-")], fired


def test_a_subaccount_that_exported_no_token_fields_is_silent():
    """THE RULE THIS FILE EXISTS FOR. A settings export carrying only iframe
    domains says nothing about token policy, and a check that reported it as
    "left at the default" would be describing an absent field."""
    fired = _run(**_subaccounts(_sa(iframeDomains="")))
    assert "BTP-TOK-001" not in fired
    assert "BTP-TOK-002" not in fired
    assert "BTP-TOK-003" not in fired


def test_no_settings_anywhere_produces_no_token_finding():
    fired = _run(**_subaccounts({"id": "sa-1", "name": "Production"}))
    assert not [k for k in fired if k.startswith("BTP-TOK-")]


def test_every_token_finding_discloses_the_override_it_cannot_see():
    """The subaccount value applies only to instances that set nothing in their
    own xs-security.json. A finding that did not say so would be claiming to
    have measured every token the subaccount issues."""
    fired = _run(**_subaccounts(
        _sa("sa-1", "Prod", accessTokenValidity=86400),
        _sa("sa-2", "QA", accessTokenValidity=-1, refreshTokenValidity=-1),
        _sa("sa-3", "Dev", accessTokenValidity=300)))
    for cid in ("BTP-TOK-001", "BTP-TOK-002", "BTP-TOK-003"):
        assert cid in fired, cid
        assert "xs-security.json" in fired[cid][0]["description"], cid


def test_the_duration_is_rendered_with_a_human_reading():
    render = BtpCloudSurfaceAuditor._duration
    assert render(43200) == "43200 s (12 hours)"
    assert render(604800) == "604800 s (7 days)"
    assert render(1800) == "1800 s (30 minutes)"
    assert render(3600) == "3600 s (1 hour)"
    assert render(45) == "45 s"


# ═════════════════════════════════════════════════════════════════════════════
#  BTP-FRM-*: iframe embedding
# ═════════════════════════════════════════════════════════════════════════════

def test_the_string_form_holds_several_domains_separated_by_spaces():
    """SAP's own Terraform provider: "Enter as string. To provide multiple
    domains, separate them by spaces." Reading it as one origin would treat a
    two-domain list as a single unresolvable hostname and report nothing."""
    origins = BtpCloudSurfaceAuditor._iframe_origins(
        {"iframeDomains": "https://a.example.com https://b.example.com"})
    assert origins == ["https://a.example.com", "https://b.example.com"]


def test_both_spellings_are_read_and_the_union_is_deduplicated():
    origins = BtpCloudSurfaceAuditor._iframe_origins({
        "iframeDomains": "https://a.example.com https://b.example.com",
        "iframeDomainsList": ["https://b.example.com", "https://c.example.com"]})
    assert origins == ["https://a.example.com", "https://b.example.com",
                       "https://c.example.com"]


@pytest.mark.parametrize("origin", ["*", "https://*", "*.com", "https://*.com",
                                    "http://portal.example.com"])
def test_an_unrestricted_or_plaintext_origin_is_high(origin):
    fired = _run(**_subaccounts(_sa(iframeDomainsList=[origin])))
    assert "BTP-FRM-001" in fired, origin
    assert fired["BTP-FRM-001"][0]["severity"] == "HIGH"
    assert "BTP-FRM-002" not in fired, "the same subaccount was reported twice"


def test_a_subdomain_wildcard_inside_an_owned_domain_is_not_flagged_as_broad():
    """SAP documents `https://*.example.com` as a legitimate entry. Flagging it
    as "any origin" would make the high finding unusable in exactly the estates
    that configured this correctly."""
    fired = _run(**_subaccounts(_sa(iframeDomains="https://*.example.com")))
    assert "BTP-FRM-001" not in fired
    assert "BTP-FRM-002" in fired
    assert fired["BTP-FRM-002"][0]["severity"] == "MEDIUM"


def test_framing_switched_off_is_a_pass_not_a_finding():
    """Empty is the SAP default and the secure state."""
    fired = _run(**_subaccounts(_sa(iframeDomains="", iframeDomainsList=[])))
    assert not [k for k in fired if k.startswith("BTP-FRM-")]


def test_a_subaccount_that_exported_no_iframe_field_is_silent():
    fired = _run(**_subaccounts(_sa(accessTokenValidity=-1)))
    assert not [k for k in fired if k.startswith("BTP-FRM-")]


# ═════════════════════════════════════════════════════════════════════════════
#  BTP-IDL-001: email as a cross-provider join key
# ═════════════════════════════════════════════════════════════════════════════

TWO_TRUSTS = {"btp_trust": {"trusts": [
    {"identityProvider": "SAP ID Service", "originKey": "sap.default",
     "status": True},
    {"identityProvider": "Corporate Azure AD", "originKey": "corp-aad",
     "status": True}]}}


def test_email_linking_with_two_active_providers_is_reported():
    data = dict(TWO_TRUSTS)
    data.update(_subaccounts(_sa(treatUsersWithSameEmailAsSameUser=True,
                                 customEmailDomains=[])))
    fired = _run(**data)
    assert "BTP-IDL-001" in fired
    finding = fired["BTP-IDL-001"][0]
    assert finding["severity"] == "MEDIUM"
    assert "unbounded" in finding["affected_items"][0]
    assert "SAP ID Service" in finding["description"]


def test_a_populated_email_domain_list_is_reported_as_bounding_the_linking():
    """`customEmailDomains` is SAP's "set of domains that are allowed to be used
    for user authentication". Populated and empty are different situations with
    different remediations, so the finding must not read the same for both."""
    data = dict(TWO_TRUSTS)
    data.update(_subaccounts(_sa(treatUsersWithSameEmailAsSameUser=True,
                                 customEmailDomains=["acme.example"])))
    item = _run(**data)["BTP-IDL-001"][0]["affected_items"][0]
    assert "bounded to acme.example" in item
    assert "unbounded" not in item


def test_one_identity_provider_is_not_a_join_key():
    data = {"btp_trust": {"trusts": [{"identityProvider": "Corporate Azure AD",
                                      "originKey": "corp-aad", "status": True}]}}
    data.update(_subaccounts(_sa(treatUsersWithSameEmailAsSameUser=True)))
    assert "BTP-IDL-001" not in _run(**data)


def test_an_inactive_second_trust_does_not_count():
    data = {"btp_trust": {"trusts": [
        {"identityProvider": "Corporate Azure AD", "originKey": "corp-aad",
         "status": True},
        {"identityProvider": "SAP ID Service", "originKey": "sap.default",
         "status": False}]}}
    data.update(_subaccounts(_sa(treatUsersWithSameEmailAsSameUser=True)))
    assert "BTP-IDL-001" not in _run(**data)


def test_no_trust_export_makes_no_claim_either_way():
    """There is no way to tell a single-provider subaccount from one whose trust
    configuration was never exported, so neither is reported."""
    fired = _run(**_subaccounts(_sa(treatUsersWithSameEmailAsSameUser=True)))
    assert "BTP-IDL-001" not in fired


def test_linking_switched_off_is_not_reported():
    data = dict(TWO_TRUSTS)
    data.update(_subaccounts(_sa(treatUsersWithSameEmailAsSameUser=False)))
    assert "BTP-IDL-001" not in _run(**data)


# ═════════════════════════════════════════════════════════════════════════════
#  BTP-AUD-001, and the BTP-GOV-001 defect it exposed
# ═════════════════════════════════════════════════════════════════════════════

def test_a_missing_audit_field_is_not_a_claim_that_logging_is_off():
    """THE DEFECT.

    `check_subaccount_governance` read `sa.get("auditLogEnabled",
    sa.get("hasAuditLog", False))`, so a subaccount whose export never carried
    the field was reported at HIGH as "does not have the audit log service
    enabled" — a finding manufactured out of a default argument. `btp list
    accounts/subaccount` does not carry audit enablement at all, so every
    subaccount from a CLI export was one merge away from this.
    """
    fired = _run(**_subaccounts({"id": "sa-1", "name": "Production"}))
    assert "BTP-GOV-001" not in fired, "audit logging reported off from an absent field"
    assert "BTP-AUD-001" in fired
    assert fired["BTP-AUD-001"][0]["severity"] == "INFO"


@pytest.mark.parametrize("value", ["unknown", "", None])
def test_the_unknown_sentinel_and_its_neighbours_read_as_unassessed(value):
    fired = _run(**_subaccounts({"id": "sa-1", "name": "Prod",
                                 "auditLogEnabled": value}))
    assert "BTP-GOV-001" not in fired
    assert "BTP-AUD-001" in fired


def test_an_explicit_false_still_reaches_the_high_finding():
    """The fix must not go the other way and lose the real ones."""
    fired = _run(**_subaccounts({"id": "sa-1", "name": "Prod",
                                 "auditLogEnabled": False}))
    assert "BTP-GOV-001" in fired
    assert fired["BTP-GOV-001"][0]["severity"] == "HIGH"
    assert "BTP-AUD-001" not in fired, "a settled subaccount was also reported unassessed"


@pytest.mark.parametrize("value", [True, "true", "Yes", "enabled"])
def test_an_evidenced_subaccount_is_in_neither_finding(value):
    fired = _run(**_subaccounts({"id": "sa-1", "name": "Prod",
                                 "auditLogEnabled": value}))
    assert "BTP-GOV-001" not in fired
    assert "BTP-AUD-001" not in fired


def test_the_unassessed_finding_arms_the_release_gate():
    """`--gate` must not return a clean build on the strength of subaccounts that
    were never assessed."""
    finding = _run(**_subaccounts({"id": "sa-1"}))["BTP-AUD-001"][0]
    assert finding["details"]["degrades_coverage"] is True


def test_it_states_what_the_audit_export_did_prove():
    data = _subaccounts({"id": "sa-1", "auditLogEnabled": True},
                        {"id": "sa-2"})
    data["btp_audit_log"] = {
        "source": "auditlog-management /auditlog/v2/auditlogrecords",
        "record_count": 12,
        "tenants": [{"tenant": "sa-1", "records": 12, "earliest": "2026-07-30",
                     "latest": "2026-08-02", "categories": ["audit.security-events"]}],
        "categories": [{"category": "audit.security-events", "records": 12}]}
    finding = _run(**data)["BTP-AUD-001"][0]
    assert "sa-1" in finding["description"] and "12 records" in finding["description"]
    assert finding["affected_items"] == ["unnamed (sa-2)"]
    assert finding["details"]["subaccounts_evidenced"] == 1
    assert finding["details"]["subaccounts_unassessed"] == 1


def test_no_audit_export_at_all_says_so_rather_than_naming_a_window():
    finding = _run(**_subaccounts({"id": "sa-1"}))["BTP-AUD-001"][0]
    assert "No audit-log export was supplied" in finding["description"]


def test_retention_is_never_inferred_from_the_export_window():
    """The span of an export is chosen by whoever ran the query. Reading a
    retention period out of it would measure the operator, not the tenant."""
    data = _subaccounts({"id": "sa-1", "auditLogEnabled": True}, {"id": "sa-2"})
    data["btp_audit_log"] = {"record_count": 5, "tenants": [
        {"tenant": "sa-1", "records": 5, "earliest": "2026-05-04",
         "latest": "2026-08-02"}]}
    finding = _run(**data)["BTP-AUD-001"][0]
    text = (finding["description"] + finding["remediation"]).lower()
    assert "retention" not in text
    assert finding["details"]["retention_not_inferred"] is True


def test_without_a_subaccount_list_nothing_is_claimed():
    assert "BTP-AUD-001" not in _run(btp_audit_log={"record_count": 0, "tenants": []})


# ═════════════════════════════════════════════════════════════════════════════
#  One measurement, one finding
# ═════════════════════════════════════════════════════════════════════════════

def test_a_settings_record_merged_onto_a_subaccount_is_not_read_twice():
    """`btp_import` folds the settings onto the subaccount AND leaves the raw
    list in place. Reading both would report one subaccount's token policy
    twice, and the second copy would carry a guid instead of a name."""
    data = _subaccounts(_sa("sa-1", "Production", accessTokenValidity=-1,
                            refreshTokenValidity=-1))
    data["btp_security_settings"] = [{"subaccount": "sa-1",
                                      "accessTokenValidity": -1,
                                      "refreshTokenValidity": -1}]
    finding = _run(**data)["BTP-TOK-002"][0]
    assert len(finding["affected_items"]) == 1, finding["affected_items"]
    assert "Production" in finding["affected_items"][0]


def test_a_settings_record_that_matches_no_subaccount_is_still_read():
    """It is a real measurement of a real subaccount. Dropping it would be the
    same silence this whole file is about."""
    data = _subaccounts(_sa("sa-1", "Production"), _sa("sa-2", "Quality"))
    data["btp_security_settings"] = [{"subaccount": "sa-9",
                                      "accessTokenValidity": 999999}]
    finding = _run(**data)["BTP-TOK-001"][0]
    assert len(finding["affected_items"]) == 1
    assert "sa-9" in finding["affected_items"][0]


def test_an_unattributed_record_names_no_subaccount_object():
    """An id nothing in the export corresponds to is not a graph node, and
    "unattributed" as a name would merge every such record in the estate into
    one."""
    data = _subaccounts(_sa("sa-1", "Production"), _sa("sa-2", "Quality"))
    data["btp_security_settings"] = [{"subaccount": "", "accessTokenValidity": 999999}]
    finding = _run(**data)["BTP-TOK-001"][0]
    assert finding.get("affected_objects", []) == []
    assert "name no subaccount" in finding["affected_items"][0]


# ═════════════════════════════════════════════════════════════════════════════
#  End to end, on raw tooling output
# ═════════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def cli_findings():
    from modules.data_loader import DataLoader
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(FIXTURES).load_all()
        findings = BtpCloudSurfaceAuditor(data, {}).run_all_checks()
    out = {}
    for finding in findings:
        out.setdefault(finding["check_id"], []).append(finding)
    return out


def test_the_new_checks_fire_on_unmodified_btp_cli_output(cli_findings):
    """Not one file in tests/fixtures/btp_cli is in this product's own shape.
    These checks read what `btp --format json list security/settings` and the
    audit-log API actually return, after `btp_import` translates them."""
    assert "BTP-TOK-002" in cli_findings          # both subaccounts at -1
    assert "BTP-FRM-001" in cli_findings          # iframeDomains "*" on Quality
    assert "BTP-AUD-001" in cli_findings          # records for one of three


def test_the_wildcard_finding_names_only_the_subaccount_that_set_it(cli_findings):
    names = {o["name"] for o in cli_findings["BTP-FRM-001"][0]["affected_objects"]}
    assert names == {"a1b2c3d4-1111-4aaa-8bbb-000000000002"}


def test_the_unassessed_finding_names_the_two_the_audit_export_missed(cli_findings):
    names = {o["name"] for o in cli_findings["BTP-AUD-001"][0]["affected_objects"]}
    assert names == {"a1b2c3d4-1111-4aaa-8bbb-000000000002",
                     "a1b2c3d4-1111-4aaa-8bbb-000000000003"}


def test_no_audit_logging_is_still_never_claimed_on_this_fixture(cli_findings):
    """The claim `tests/test_btp_import.py` already guards, re-checked from the
    other side: the subaccounts that used to be at risk of a fabricated
    BTP-GOV-001 are now explicitly reported as unassessed instead."""
    assert "BTP-GOV-001" not in cli_findings
