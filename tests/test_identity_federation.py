# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
Identity federation and SCIM provisioning — modules/iam_advanced.py IAM-FED-*.

WHY THESE CHECKS ARE UNUSUALLY EASY TO GET WRONG, AND SO ARE THESE TESTS
------------------------------------------------------------------------
Three of the four checks read fields we have NOT observed in any real tenant
export — only in the shape `docs/EXPORT_GUIDE.md` documents. A check reading an
absent field is one careless truth-test away from firing on every customer in the
estate: `if not row.get("allowedUsers")` is True for "the field says nobody may log
on", for "the field says everybody may", AND for "there is no such field". Only the
middle one is a finding. Several tests below exist for nothing but that distinction.

The other trap is the opposite direction. `status` arrives as a JSON boolean in one
export and as the string "inactive" in another, and "inactive" is truthy, so the
naive test reports a decommissioned trust as a live logon path. There is a test for
that too.

Every check here ships a negative control, and `test_a_correctly_federated_tenant_
is_silent` is the one that matters most: a rule that also fires on a correctly
federated tenant is worse than no rule, because the first thing a customer does
with a federation report is check it against the one subaccount they know is right.

The fixtures are built inline rather than as files because the shape is the thing
under test — a reader has to see the exact row that does and does not fire, next to
the assertion. `sample_data/btp_trust.json` is the repository's real export fixture
and is exercised at the end, so these tests cannot drift away from the shipped data.
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.iam_advanced import AdvancedIamAuditor  # noqa: E402
from modules.rise_btp_checks import RiseBtpAuditor   # noqa: E402
from server.enrich import team_for                   # noqa: E402

FED_CHECKS = ("IAM-FED-001", "IAM-FED-002", "IAM-FED-003", "IAM-FED-004")


# --------------------------------------------------------------------------- #
#  Fixtures, built inline so the row under test sits next to the assertion     #
# --------------------------------------------------------------------------- #

def trust(**overrides):
    """One trust row. The defaults are a well-behaved corporate trust: active,
    explicitly provisioned rather than auto-creating, admitting a named group."""
    row = {
        "identityProvider": "Corporate Azure AD",
        "originKey": "corp-aad-tenant",
        "status": True,
        "createShadowUsers": False,
    }
    row.update(overrides)
    return row


def fed(**data):
    """Every IAM-FED-* finding for `data`, raised through the real entry point.

    Deliberately runs `run_all_checks()` rather than the individual methods: a check
    that works but was never added to the runner is a check the product does not
    have, and that has happened before in this repository.

    Filtered to IAM-FED-* because the module raises IAM-SOD-000 whenever no SoD data
    is supplied, which is pre-existing behaviour and none of this feature's business.
    """
    return [f for f in AdvancedIamAuditor(dict(data), {}).run_all_checks()
            if f["check_id"].startswith("IAM-FED-")]


def ids(findings):
    return sorted(f["check_id"] for f in findings)


def in_days(n):
    """A date `n` days from now, in the SAP export format, so the tests do not rot."""
    return (datetime.now() + timedelta(days=n)).strftime("%Y-%m-%d")


# --------------------------------------------------------------------------- #
#  IAM-FED-001 — how many independent ways in exist                           #
# --------------------------------------------------------------------------- #

def test_two_live_trusts_are_reported_as_two_logon_paths():
    """A subaccount's assurance is the WEAKEST of its logon paths. If a second trust
    is never named, an unMFA'd partner or legacy IdP silently sets the security level
    of the whole subaccount and no report ever mentions it."""
    findings = fed(btp_trust={"trusts": [
        trust(),
        trust(identityProvider="Legacy SAML", originKey="legacy-saml"),
    ]})
    assert ids(findings) == ["IAM-FED-001"]
    items = " ".join(findings[0]["affected_items"])
    assert "corp-aad-tenant" in items and "legacy-saml" in items


def test_a_single_identity_provider_is_not_a_finding():
    """NEGATIVE CONTROL. One corporate IdP is the target state. Reporting it would
    make the check fire on every correctly federated tenant in the estate."""
    assert fed(btp_trust={"trusts": [trust()]}) == []


def test_a_trust_switched_off_is_not_a_second_logon_path():
    """NEGATIVE CONTROL, and the specific bug this guards: BTP writes trust status as
    the STRING "inactive" in some exports, and "inactive" is truthy in Python. A naive
    `if row["status"]` reports a decommissioned trust as live, and the customer is
    sent to remove something that is already gone."""
    findings = fed(btp_trust={"trusts": [
        trust(),
        trust(originKey="legacy-saml", status="inactive"),
    ]})
    assert findings == []


@pytest.mark.parametrize("false_value", [False, "false", "0", "no", "disabled"])
def test_every_spelling_of_off_is_understood(false_value):
    """Exports disagree on how to spell a disabled flag. Missing one spelling means a
    dead trust is reported as a live authentication path."""
    assert fed(btp_trust={"trusts": [
        trust(), trust(originKey="legacy", status=false_value)]}) == []


def test_a_trust_not_offered_for_interactive_logon_is_not_counted():
    """A trust used only for technical/API authentication is not a way for a person
    to log in, so counting it inflates the logon-path count and turns a correct
    configuration into a finding."""
    assert fed(btp_trust={"trusts": [
        trust(),
        trust(originKey="api-only", availableForUserLogon=False),
    ]}) == []


def test_a_trust_with_no_name_at_all_is_not_invented():
    """An export row carrying neither an originKey nor an IdP name names no trust.
    Emitting it would put a nameless node in the attack-path graph, and every other
    nameless row in the estate would then share that one identity."""
    findings = fed(btp_trust={"trusts": [
        trust(),
        trust(originKey="legacy-saml", identityProvider="Legacy SAML"),
        trust(originKey="", identityProvider="", name=""),
    ]})
    assert ids(findings) == ["IAM-FED-001"]
    assert len(findings[0]["affected_items"]) == 2, "a nameless row was counted"
    assert {o["name"] for o in findings[0]["affected_objects"]} == {
        "corp-aad-tenant", "legacy-saml"}


def test_the_same_trust_listed_twice_is_still_one_logon_path():
    """NEGATIVE CONTROL. Trust exports get concatenated and hand-merged, and a row
    repeated is still ONE way in. Counting it twice made the text say "2 trust
    configuration(s)" while the structured objects de-duplicated to one — a finding
    contradicting itself, and an owner sent to hunt for a second IdP that is not
    there."""
    assert fed(btp_trust={"trusts": [trust(), trust()]}) == []


@pytest.mark.parametrize("wrapper", [
    lambda rows: rows,                              # bare list
    lambda rows: {"trusts": rows},                  # documented envelope
    lambda rows: {"trust_configurations": rows},    # alternative envelope
])
def test_every_export_envelope_is_unwrapped(wrapper):
    """`rise_btp_checks` accepts all three shapes. If this module accepted fewer, the
    same export would produce trust findings from one module and silence from the
    other, which reads as "federation was checked" when half of it was not."""
    rows = [trust(), trust(originKey="legacy-saml")]
    assert ids(fed(btp_trust=wrapper(rows))) == ["IAM-FED-001"]


# --------------------------------------------------------------------------- #
#  IAM-FED-002 — a trust that admits everybody the IdP will authenticate       #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("unrestricted", ["*", "any", "ALL", "", "  "])
def test_a_wildcard_or_empty_user_restriction_fires(unrestricted):
    """A corporate directory holds contractors, B2B guests and service identities that
    were never meant to reach production SAP. An unrestricted trust admits all of
    them, and authorization becomes the only thing standing in the way."""
    findings = fed(btp_trust={"trusts": [trust(userRestriction=unrestricted)]})
    assert ids(findings) == ["IAM-FED-002"]
    assert findings[0]["scope"] == "object", (
        "restricting one trust is its own change; collapsing several would hide all "
        "but one of them")


def test_a_restricted_trust_produces_no_finding():
    """NEGATIVE CONTROL. A trust scoped to a named group is the target state."""
    assert fed(btp_trust={"trusts": [trust(userRestriction="SAP_PROD_Users")]}) == []


def test_a_restriction_given_as_a_list_of_domains_is_read():
    """NEGATIVE CONTROL. Exports carry this as an array as often as a string; reading
    only strings would report a properly restricted trust as wide open."""
    assert fed(btp_trust={"trusts": [
        trust(allowedUserDomains=["company.com", "company.co.uk"])]}) == []


def test_an_empty_list_restriction_is_a_finding_but_an_absent_field_is_not():
    """THE distinction this check turns on. "The field is present and admits nobody in
    particular" and "the export does not carry the field" look identical to a truth
    test, and conflating them fires IAM-FED-002 on every customer whose BTP CLI
    version does not emit the attribute — which is all of them we have seen."""
    assert ids(fed(btp_trust={"trusts": [trust(allowedUsers=[])]})) == ["IAM-FED-002"]
    assert fed(btp_trust={"trusts": [trust()]}) == [], (
        "an absent restriction field was read as an unrestricted trust")


def test_an_inactive_trust_is_not_reported_as_unrestricted():
    """A decommissioned trust admits nobody regardless of what its stale restriction
    field says. Reporting it sends the customer to fix something switched off."""
    assert fed(btp_trust={"trusts": [
        trust(status="inactive", userRestriction="*")]}) == []


def test_each_unrestricted_trust_is_its_own_finding():
    """Two unrestricted trusts are two separate conversations with two separate IdP
    owners. Sharing one identity would make one of them disappear from the report."""
    findings = fed(btp_trust={"trusts": [
        trust(userRestriction="*"),
        trust(originKey="partner-idp", userRestriction="*"),
    ]})
    fed_002 = [f for f in findings if f["check_id"] == "IAM-FED-002"]
    assert len(fed_002) == 2
    named = {o["name"] for f in fed_002 for o in f["affected_objects"]}
    assert named == {"corp-aad-tenant", "partner-idp"}


# --------------------------------------------------------------------------- #
#  IAM-FED-003 — the certificate holding the federation up                     #
# --------------------------------------------------------------------------- #

def test_an_expired_federation_certificate_is_high():
    """When it lapses, SSO fails for everyone at once and the field workaround is to
    re-enable the default IdP "just until it is renewed" — turning a certificate
    lapse into an authentication bypass, under outage pressure, unreviewed."""
    findings = fed(btp_trust={"trusts": [
        trust(certificateExpiryDate=in_days(-3))]})
    assert ids(findings) == ["IAM-FED-003"]
    assert findings[0]["severity"] == "HIGH"


def test_a_certificate_expiring_inside_the_window_is_medium():
    """Renewal needs the IdP owner and the BTP owner together, so it is scheduled
    work. Warning on the day it expires is warning too late to schedule anything."""
    findings = fed(btp_trust={"trusts": [trust(certificateValidTo=in_days(10))]})
    assert ids(findings) == ["IAM-FED-003"]
    assert findings[0]["severity"] == "MEDIUM"


def test_a_certificate_valid_for_a_year_produces_no_finding():
    """NEGATIVE CONTROL. A healthy certificate is the normal case and must be silent,
    or every trust in the estate carries a permanent finding."""
    assert fed(btp_trust={"trusts": [trust(certificateExpiryDate=in_days(365))]}) == []


def test_an_iso_timestamp_is_parsed_rather_than_ignored():
    """Cloud APIs return `2026-06-30T23:59:59Z`. Failing to parse it means a genuinely
    expired certificate is silently skipped — the failure nobody notices, because it
    looks exactly like a clean result."""
    findings = fed(btp_trust={"trusts": [
        trust(certificateExpiryDate=in_days(-1) + "T23:59:59Z")]})
    assert ids(findings) == ["IAM-FED-003"]


def test_an_unparseable_expiry_date_is_not_guessed():
    """NEGATIVE CONTROL. Told "soon" or "n/a", the honest answer is silence. Guessing
    a date either invents an expiry that has not happened or hides one that has."""
    assert fed(btp_trust={"trusts": [trust(certificateExpiryDate="n/a")]}) == []


def test_a_certificate_valid_until_tonight_is_not_reported_as_already_expired():
    """A certificate whose validity ends TODAY has not lapsed yet. Subtracting a
    mid-afternoon `now` from a midnight-parsed date floors an extra day off and made
    this read "expired 1 day(s) ago" at HIGH severity — the report asserting an outage
    that has not happened, on a check whose whole value is being believed."""
    findings = fed(btp_trust={"trusts": [
        trust(certificateExpiryDate=in_days(0) + "T23:59:59Z")]})
    assert ids(findings) == ["IAM-FED-003"]
    assert findings[0]["severity"] == "MEDIUM", "a live certificate was called expired"
    assert "expired" not in findings[0]["title"]
    assert "expires today" in findings[0]["title"]


def test_the_days_remaining_are_counted_in_whole_calendar_days():
    """Told a certificate is good for five more days, the report must not say four.
    The number is what a change manager schedules the renewal against."""
    findings = fed(btp_trust={"trusts": [trust(certificateValidTo=in_days(5))]})
    assert "expires in 5 day(s)" in findings[0]["title"]


def test_a_baseline_window_typed_as_a_string_does_not_take_down_the_scan():
    """Baseline overrides are hand-written JSON and `"90"` is what a human types. An
    int-vs-str comparison raises inside run_all_checks(), so one mistyped baseline
    entry would cost the customer every other IAM finding in the run, not just this
    one."""
    data = {"btp_trust": {"trusts": [trust(certificateExpiryDate=in_days(60))]}}
    assert [f["check_id"] for f
            in AdvancedIamAuditor(dict(data), {"trust_cert_warning_days": "90"}
                                  ).run_all_checks()
            if f["check_id"] == "IAM-FED-003"] == ["IAM-FED-003"]
    # Unreadable overrides fall back to the shipped default rather than disabling the
    # check silently, which would look identical to a clean result.
    assert [f["check_id"] for f
            in AdvancedIamAuditor(dict(data), {"trust_cert_warning_days": "ninety"}
                                  ).run_all_checks()
            if f["check_id"] == "IAM-FED-003"] == []


def test_the_warning_window_is_configurable_from_the_baseline():
    """A customer whose change process needs 90 days' notice must be able to say so;
    a hard-coded window makes the check useless to them rather than merely noisy."""
    data = {"btp_trust": {"trusts": [trust(certificateExpiryDate=in_days(60))]}}

    def run(overrides):
        return [f["check_id"]
                for f in AdvancedIamAuditor(dict(data), overrides).run_all_checks()
                if f["check_id"] == "IAM-FED-003"]

    assert run({}) == [], "60 days out is outside the 30-day default window"
    assert run({"trust_cert_warning_days": 90}) == ["IAM-FED-003"]


# --------------------------------------------------------------------------- #
#  IAM-FED-004 — identities appear automatically; does anything remove them?   #
# --------------------------------------------------------------------------- #

def test_auto_created_identities_with_no_provisioning_evidence_fires():
    """The classic federation failure: HR disables the leaver's directory account, the
    BTP shadow user it created keeps its role collections and its tokens, and nobody
    reviewing the corporate directory can see it any more."""
    findings = fed(btp_trust={"trusts": [trust(createShadowUsers=True)]})
    assert ids(findings) == ["IAM-FED-004"]
    assert findings[0]["scope"] == "aggregate", (
        "one provisioning integration closes the gap for every trust at once")


def test_explicit_provisioning_means_the_lifecycle_is_somebody_s_job():
    """NEGATIVE CONTROL. Without auto-creation an administrator creates each identity
    deliberately and owns it. Firing here would report the more-controlled
    configuration as the defect."""
    assert fed(btp_trust={"trusts": [trust(createShadowUsers=False)]}) == []


def test_a_scim_communication_arrangement_is_accepted_as_evidence():
    """NEGATIVE CONTROL. A tenant that HAS wired provisioning must not be told it has
    not — the first false positive on a control the customer knows they built is the
    one that gets the whole report dismissed."""
    assert fed(
        btp_trust={"trusts": [trust(createShadowUsers=True)]},
        comm_arrangements={"arrangements": [
            {"name": "IDENTITY_PROVISIONING_IPS", "scenario_id": "SAP_COM_XXXX"}]},
    ) == []


def test_hr_master_data_replication_is_not_mistaken_for_identity_provisioning():
    """`SF_EMPLOYEE_SYNC` in the shipped sample moves employee RECORDS, not shadow
    users. Accepting it as evidence would silence the finding on exactly the estate
    that has the problem — a false negative bought with a sloppy substring match."""
    findings = fed(
        btp_trust={"trusts": [trust(createShadowUsers=True)]},
        comm_arrangements={"arrangements": [
            {"name": "SF_EMPLOYEE_SYNC", "scenario_id": "SAP_COM_0008"},
            {"name": "SHIPS_AND_TIPS", "scenario_id": "SAP_COM_0100"}]},
    )
    assert ids(findings) == ["IAM-FED-004"], (
        "a business integration was read as identity provisioning")


def test_an_ias_provisioning_block_counts_as_evidence():
    """NEGATIVE CONTROL. Provisioning is as often evidenced by the IAS export as by a
    communication arrangement; reading only one source fires on half the tenants that
    are configured correctly."""
    assert fed(
        btp_trust={"trusts": [trust(createShadowUsers=True)]},
        ias_config={"provisioning": {"enabled": True}},
    ) == []


@pytest.mark.parametrize("empty_block", [None, {}, [], ""])
def test_an_empty_provisioning_block_is_not_evidence(empty_block):
    """A key present but carrying nothing describes no integration. Accepting its mere
    presence silences the finding — and a silenced IAM-FED-004 is indistinguishable
    from a tenant that genuinely closed its identity lifecycle."""
    assert ids(fed(
        btp_trust={"trusts": [trust(createShadowUsers=True)]},
        ias_config={"provisioning": empty_block},
    )) == ["IAM-FED-004"]


def test_a_provisioning_block_that_is_switched_off_is_not_evidence():
    """A configuration explicitly disabled is the OPPOSITE of evidence. Accepting its
    mere presence would let a tenant silence the finding by having once configured —
    and then turned off — the control."""
    assert ids(fed(
        btp_trust={"trusts": [trust(createShadowUsers=True)]},
        ias_config={"provisioning": {"enabled": False}},
    )) == ["IAM-FED-004"]


# --------------------------------------------------------------------------- #
#  The master negative control, and absent data                                #
# --------------------------------------------------------------------------- #

def test_a_correctly_federated_tenant_is_silent():
    """THE test. A single enforced corporate trust, restricted to a named group, with
    identities provisioned rather than auto-created and a certificate a year out, must
    produce ZERO federation findings. A rule that also fires on correct configuration
    is worse than no rule — the customer checks the report against the subaccount they
    know is right, and everything after that is noise to them."""
    assert fed(
        btp_trust={"trusts": [trust(
            status=True,
            availableForUserLogon=True,
            createShadowUsers=False,
            userRestriction="SAP_PROD_Users",
            certificateExpiryDate=in_days(365),
        )]},
        comm_arrangements={"arrangements": [
            {"name": "IDENTITY_PROVISIONING", "scenario_id": "SAP_COM_XXXX"}]},
    ) == []


def test_the_default_sap_idp_alone_is_left_to_the_rise_module():
    """`rise_btp_checks` already reports the default SAP IdP being active (RISE-001)
    and shadow-user creation per trust (RISE-002). Restating either here would double
    every such finding in the report and split one defect across two owners."""
    assert fed(btp_trust={"trusts": [
        {"identityProvider": "SAP ID Service", "originKey": "sap.default",
         "status": True, "createShadowUsers": False}]}) == []


@pytest.mark.parametrize("absent", [None, {}, [], "", {"trusts": []}])
def test_an_absent_trust_export_produces_no_federation_findings(absent):
    """Every export is optional. A customer who cannot get the BTP trust JSON must get
    a scan, not a crash and not a fabricated federation verdict."""
    assert fed(btp_trust=absent) == []


def test_empty_data_runs_every_check_without_raising():
    """A module that raises on a missing export takes the whole scan down with it, and
    the exports it needs are precisely the ones a first-time customer cannot produce."""
    findings = AdvancedIamAuditor({}, {}).run_all_checks()
    assert isinstance(findings, list)
    assert not [f for f in findings if f["check_id"].startswith("IAM-FED-")]


def test_malformed_trust_rows_do_not_abort_the_check():
    """One hand-edited or half-truncated row must not cost the customer the other
    trusts in the same file."""
    findings = fed(btp_trust={"trusts": [
        "not-a-dict", None, 42, trust(), trust(originKey="legacy-saml")]})
    assert ids(findings) == ["IAM-FED-001"]


# --------------------------------------------------------------------------- #
#  Contract: routing, node naming, and the real shipped export                 #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("check_id", FED_CHECKS)
def test_every_federation_check_routes_to_a_team(check_id):
    """An unrouted check_id lands in nobody's queue and is never worked."""
    assert team_for(check_id) != "unassigned"


def test_trust_findings_name_the_same_graph_node_as_the_rise_module():
    """RISE-001/002 and IAM-FED-* must resolve to ONE `idp_trust` node per trust. If
    this module keyed on the editable display name instead of the originKey, a single
    trust would appear twice in the attack-path graph and renaming the IdP in the BTP
    cockpit would orphan half its finding history."""
    rows = [{"identityProvider": "SAP ID Service", "originKey": "sap.default",
             "status": True, "createShadowUsers": True}]
    export = {"btp_trust": {"trusts": rows}}

    rise_names = {o["name"]
                  for f in RiseBtpAuditor(dict(export), {}).run_all_checks()
                  for o in f.get("affected_objects", [])
                  if o["type"] == "idp_trust"}
    iam_names = {o["name"] for f in fed(**export)
                 for o in f.get("affected_objects", [])
                 if o["type"] == "idp_trust"}
    assert rise_names, "the RISE module stopped naming trusts; re-derive this test"
    assert iam_names == rise_names == {"sap.default"}


def test_findings_honour_the_finding_contract():
    """A malformed finding — a tuple where a string belongs — renders as garbage in the
    PDF and breaks the ingest, and it is invisible until a customer sees the report."""
    findings = fed(btp_trust={"trusts": [
        trust(createShadowUsers=True, userRestriction="*",
              certificateExpiryDate=in_days(-1)),
        trust(originKey="legacy-saml"),
    ]})
    assert ids(findings) == ["IAM-FED-001", "IAM-FED-002", "IAM-FED-003", "IAM-FED-004"]
    for f in findings:
        for key in ("check_id", "title", "severity", "category",
                    "description", "remediation"):
            assert isinstance(f[key], str) and f[key].strip()
        assert f["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        assert f["affected_items"] and all(isinstance(i, str) for i in f["affected_items"])
        assert f["affected_count"] == len(f["affected_items"])
        assert f["references"] and all(isinstance(r, str) for r in f["references"])
        assert f["scope"] in ("object", "aggregate")
        assert all(o["type"] and o["name"] for o in f["affected_objects"])


@pytest.mark.skipif(not (ROOT / "sample_data" / "btp_trust.json").is_file(),
                    reason="sample_data not present")
def test_the_shipped_sample_export_exercises_the_feature():
    """The bundled export is what every demo and every screenshot runs on. If it stops
    triggering these checks, the tests above are proving the feature works on fixtures
    nobody ships — which is how a feature ends up green in CI and absent in the
    product."""
    import contextlib
    import io

    from modules.data_loader import DataLoader
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(ROOT / "sample_data").load_all()

    findings = [f for f in AdvancedIamAuditor(dict(data), {}).run_all_checks()
                if f["check_id"].startswith("IAM-FED-")]
    raised = ids(findings)
    # Two active trusts, both auto-creating shadow users, and no provisioning
    # arrangement anywhere in the bundle.
    assert raised == ["IAM-FED-001", "IAM-FED-004"]
    # The two field-dependent checks stay silent, which is the documented behaviour:
    # the shipped export carries neither a user restriction nor a certificate expiry,
    # and absence must never be read as a defect.
    assert "IAM-FED-002" not in raised and "IAM-FED-003" not in raised
