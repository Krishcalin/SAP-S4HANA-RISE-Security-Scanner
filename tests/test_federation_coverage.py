# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
"Nothing to find" and "could not look" must not look the same — IAM-FEDCOV-*.

WHAT WENT WRONG, SO THE TESTS ARE READ AGAINST THE RIGHT PROBLEM
-----------------------------------------------------------------
IAM-FED-002 (which users a trust admits) and IAM-FED-003 (when its certificate
expires) key on attributes nobody has confirmed appear in a real `btp_trust` export.
They were therefore DORMANT: on every export this product can currently load they
contributed nothing and, worse, said nothing. A reader saw a federation section with
no admission finding and no certificate finding in it, which reads as two clean
results. It was two questions nobody asked.

The fix is NOT to make absence fire. `tests/test_identity_federation.py` holds that
line and it is the right line — reading "the export did not say" as "the trust is
unrestricted" is how a federation report becomes something nobody trusts. The fix is
to disclose the gap separately, as `snc_posture.check_family_not_assessable` does.

SO THESE TESTS COME IN PAIRS, AND THE SECOND OF EACH PAIR IS THE POINT
  * the gap is disclosed when the attribute is missing            (it speaks)
  * NOTHING is emitted when the attribute is there and healthy    (it shuts up)

`test_a_correctly_federated_tenant_is_silent_including_coverage` is the one that
matters most. A coverage finding that also fires on an export which genuinely
carried the evidence is a permanent piece of noise on the customer's best-configured
subaccount, and it discredits the disclosure everywhere else.

The two boundary rules have tests of their own because both are easy to lose:
an ABSENT `btp_trust` export says nothing here (that is the coverage manifest's
subject, `server/coverage.py`), and the coverage ids stay OUT of the `IAM-FED-*`
family so a gap in our evidence is never counted as a defect in the customer's.
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
from server.enrich import team_for                   # noqa: E402

COVERAGE_CHECKS = ("IAM-FEDCOV-002", "IAM-FEDCOV-003")


# --------------------------------------------------------------------------- #
#  Fixtures, inline so the row under test sits next to the assertion           #
# --------------------------------------------------------------------------- #

def trust(**overrides):
    """One trust row in the ONLY shape observed in a real export: five fields, and
    neither the admission attribute nor the certificate one. This is what the product
    actually receives, which is why it is the default here."""
    row = {
        "identityProvider": "Corporate Azure AD",
        "originKey": "corp-aad-tenant",
        "status": True,
        "createShadowUsers": False,
        "description": "Corporate IDP",
    }
    row.update(overrides)
    return row


def run(**data):
    """Every federation finding for `data` — defect AND coverage — through the real
    entry point.

    `run_all_checks()` rather than the check methods directly: a check that works but
    was never wired into the runner is a check the product does not have.

    The `IAM-FED` prefix catches both families deliberately, so a negative control can
    assert that a well-configured tenant produces NOTHING rather than merely no defect.
    Everything else the module emits is filtered out — it raises IAM-SOD-000 whenever
    no SoD data is supplied, which is pre-existing behaviour and none of this
    feature's business.
    """
    return [f for f in AdvancedIamAuditor(dict(data), {}).run_all_checks()
            if f["check_id"].startswith("IAM-FED")]


def cov(**data):
    """Only the coverage findings."""
    return [f for f in run(**data) if f["check_id"].startswith("IAM-FEDCOV-")]


def ids(findings):
    return sorted(f["check_id"] for f in findings)


def in_days(n):
    """A date `n` days out, in an export format, so these tests do not rot."""
    return (datetime.now() + timedelta(days=n)).strftime("%Y-%m-%d")


# --------------------------------------------------------------------------- #
#  IAM-FEDCOV-002 — the admission question that was never asked                #
# --------------------------------------------------------------------------- #

def test_a_trust_carrying_no_admission_attribute_is_disclosed():
    """THE defect. This export is the shape every real tenant has produced so far, so
    before this finding existed IAM-FED-002 was silent on 100% of real scans and the
    report showed a federation section with no admission finding in it."""
    findings = cov(btp_trust={"trusts": [trust()]})
    assert "IAM-FEDCOV-002" in ids(findings)


def test_the_disclosure_says_what_it_looked_for_and_what_it_could_not_conclude():
    """A coverage finding that only says "could not assess" is an apology. The reader
    has to be able to act on it: which attribute is missing, what is therefore unknown,
    and what to do instead."""
    f = next(f for f in cov(btp_trust={"trusts": [trust()]})
             if f["check_id"] == "IAM-FEDCOV-002")
    text = f["description"] + " " + f["remediation"]
    for name in AdvancedIamAuditor.FED_RESTRICTION_FIELDS:
        assert name in f["description"], (
            "the finding must quote the attribute names the code actually reads, or "
            "the customer cannot tell us their export names it differently")
    assert "IAM-FED-002" in f["description"], "the check it stands in for is not named"
    assert "not a verdict" in f["description"], (
        "a gap in the evidence stated without that caveat will be read as a verdict")
    assert "docs/EXPORT_GUIDE.md" in text, "no route to an export that would answer it"
    assert "corp-aad-tenant" in " ".join(f["affected_items"]), (
        "the owner has to know WHICH trust was not assessed")


def test_a_restricted_trust_produces_nothing_at_all():
    """THE NEGATIVE CONTROL for this check. A trust that carries the attribute AND is
    restricted is the target state: no IAM-FED-002, because it is restricted, and no
    coverage finding either, because we looked and we saw. Firing here would put a
    permanent INFO on the one subaccount the customer knows is right.

    The certificate attribute is supplied too, because the two disclosures are
    independent: an export that answers one question and not the other must produce
    exactly one of them, and this test would otherwise be asserting that from the
    wrong end."""
    assert run(btp_trust={"trusts": [
        trust(userRestriction="SAP_PROD_Users",
              certificateExpiryDate=in_days(365))]}) == []


def test_an_unrestricted_trust_is_reported_as_a_defect_not_as_a_gap():
    """When the evidence IS there, the defect finding must fire and the coverage
    finding must not. A gap disclosure alongside a real answer would double-report and
    devalue both."""
    assert ids(run(btp_trust={"trusts": [
        trust(userRestriction="*",
              certificateExpiryDate=in_days(365))]})) == ["IAM-FED-002"]


def test_a_trust_that_admits_nobody_is_not_a_coverage_gap():
    """NEGATIVE CONTROL. An inactive trust needs no admission restriction, so there is
    genuinely nothing to assess — not something we failed to assess. Disclosing it
    would manufacture a gap out of a decommissioned configuration."""
    assert [f for f in cov(btp_trust={"trusts": [trust(status="inactive")]})
            if f["check_id"] == "IAM-FEDCOV-002"] == []


def test_only_the_trusts_that_were_not_assessed_are_named():
    """A mixed export must not be summarised as if it were uniform. Naming the trust
    that DID carry the attribute would tell its owner to go and re-export something
    that is already correct, and the disclosure stops being believed."""
    f = next(f for f in cov(btp_trust={"trusts": [
        trust(originKey="answered", userRestriction="SAP_PROD_Users"),
        trust(originKey="silent"),
    ]}) if f["check_id"] == "IAM-FEDCOV-002")
    items = " ".join(f["affected_items"])
    assert "silent" in items and "answered" not in items
    assert f["details"]["trusts_not_assessed"] == ["silent"]


def test_a_trust_with_no_name_is_not_reported_as_an_unassessed_trust():
    """We cannot tell an owner "this trust was not assessed" about a trust we cannot
    name. A placeholder would send them looking for something that does not exist, and
    every nameless row in the estate would carry the same invented label."""
    assert [f for f in cov(btp_trust={"trusts": [{"status": True}]})
            if f["check_id"] == "IAM-FEDCOV-002"] == []


def test_a_row_we_could_not_name_is_never_counted_as_one_we_assessed():
    """The failure mode this whole finding exists to prevent, turned on itself. A row
    naming no trust is rightly skipped — but it used to stay in the denominator, so the
    finding said "1 other trust configuration in this export did carry the attribute and
    was assessed" about a row that carried nothing and was assessed not at all. A
    coverage statement that overstates coverage is worse than no coverage statement."""
    f = next(f for f in cov(btp_trust={"trusts": [{"status": True}, trust()]})
             if f["check_id"] == "IAM-FEDCOV-002")
    assert "were assessed" not in f["description"]
    assert f["details"]["trusts_admitting_users"] == 1


def test_one_trust_listed_twice_is_counted_once():
    """Exports get concatenated and hand-merged; IAM-FED-001 de-duplicates for exactly
    that reason. A coverage finding that says "2 trust configurations" about one trust,
    and names it twice, sends the owner hunting for a second logon path that is not
    there — and contradicts the very report it appears in."""
    dup = {"trusts": [trust(originKey="same"), trust(originKey="SAME")]}
    two = next(f for f in cov(btp_trust=dup) if f["check_id"] == "IAM-FEDCOV-002")
    three = next(f for f in cov(btp_trust=dup) if f["check_id"] == "IAM-FEDCOV-003")
    assert two["details"]["trusts_not_assessed"] == ["same"]
    assert two["details"]["trusts_admitting_users"] == 1
    assert two["affected_count"] == 1
    assert three["details"]["trusts_without_the_attribute"] == ["same"]
    assert three["details"]["trusts_in_export"] == 1
    assert three["affected_count"] == 1


def test_the_assessed_tally_counts_only_trusts_that_answered():
    """The reassuring half of the sentence has to be true too. When it says N others
    carried the attribute, N must be trusts that really did — otherwise the finding
    quietly credits itself with coverage it did not have."""
    f = next(f for f in cov(btp_trust={"trusts": [
        trust(originKey="answered", userRestriction="SAP_PROD_Users"),
        trust(originKey="also-answered", userRestriction="SAP_PROD_Users"),
        trust(originKey="silent"),
    ]}) if f["check_id"] == "IAM-FEDCOV-002")
    assert "2 other trust configuration(s)" in f["description"]
    assert f["details"]["trusts_admitting_users"] == 3


# --------------------------------------------------------------------------- #
#  IAM-FEDCOV-003 — the certificate nobody was watching                        #
# --------------------------------------------------------------------------- #

def test_a_trust_carrying_no_certificate_attribute_is_disclosed():
    """Certificate expiry is the check a reader is most likely to assume is running:
    it is exactly the kind of thing a scanner is expected to watch. Silence about it
    is read as "nothing is expiring"."""
    assert "IAM-FEDCOV-003" in ids(cov(btp_trust={"trusts": [trust()]}))


def test_a_healthy_certificate_produces_nothing_at_all():
    """THE NEGATIVE CONTROL for this check. A certificate a year out is the normal,
    correct case and must be completely silent — no defect, and no gap either."""
    assert run(btp_trust={"trusts": [
        trust(userRestriction="SAP_PROD_Users",
              certificateExpiryDate=in_days(365))]}) == []


def test_an_expiring_certificate_is_reported_as_a_defect_not_as_a_gap():
    """The evidence was present and was read; a coverage finding on top of the real
    answer would say the opposite of what just happened."""
    assert ids(run(btp_trust={"trusts": [
        trust(userRestriction="SAP_PROD_Users",
              certificateValidTo=in_days(10))]})) == ["IAM-FED-003"]


def test_a_date_that_cannot_be_read_is_disclosed_rather_than_guessed():
    """The half that is easy to forget. Declining to guess a date from "n/a" is right;
    declining to MENTION that we declined leaves a customer who tried to answer the
    question believing it was answered."""
    f = next(f for f in cov(btp_trust={"trusts": [
        trust(certificateExpiryDate="n/a")]}) if f["check_id"] == "IAM-FEDCOV-003")
    items = " ".join(f["affected_items"])
    assert "n/a" in items and "certificateExpiryDate" in items, (
        "the reader must see the value we could not parse, not just that we failed")
    assert f["details"]["trusts_with_an_unreadable_value"]


def test_an_attribute_present_but_empty_is_a_gap_not_a_clean_result():
    """An export that declares the attribute and leaves it blank told us nothing. It
    used to be indistinguishable from a certificate with years left on it."""
    assert "IAM-FEDCOV-003" in ids(cov(btp_trust={"trusts": [
        trust(certificateValidTo="")]}))


def test_a_populated_alias_wins_over_an_empty_one():
    """NEGATIVE CONTROL, and the regression it guards is a false NEGATIVE: a row
    carrying an empty `certificateExpiryDate` beside a populated `certificateValidTo`
    does say when the certificate lapses. Preferring the empty name would silence
    IAM-FED-003 about a real expiry and replace it with a coverage finding — a
    downgrade dressed up as diligence."""
    findings = run(btp_trust={"trusts": [
        trust(userRestriction="SAP_PROD_Users",
              certificateExpiryDate="", certificateValidTo=in_days(-2))]})
    assert ids(findings) == ["IAM-FED-003"]


def test_both_kinds_of_certificate_gap_are_counted_in_one_finding():
    """Two ways to be unassessable, one export, one conversation with one owner —
    and the finding has to distinguish them, because "add the attribute" and "fix the
    value" are different work."""
    f = next(f for f in cov(btp_trust={"trusts": [
        trust(originKey="no-field"),
        trust(originKey="bad-date", certificateValidTo="soon"),
    ]}) if f["check_id"] == "IAM-FEDCOV-003")
    assert f["details"]["trusts_without_the_attribute"] == ["no-field"]
    assert len(f["details"]["trusts_with_an_unreadable_value"]) == 1
    assert len(f["affected_items"]) == 2


def test_the_certificate_gap_covers_every_row_the_check_itself_reads():
    """The coverage statement must describe the SAME population as the check it stands
    in for. IAM-FED-003 examines every row, including inactive ones, so a coverage
    finding that quietly skipped inactive rows would claim assessment of a trust the
    check would have reported on."""
    assert "IAM-FEDCOV-003" in ids(cov(btp_trust={"trusts": [
        trust(status="inactive")]}))


# --------------------------------------------------------------------------- #
#  The master negative control, and the two boundaries                         #
# --------------------------------------------------------------------------- #

def test_a_correctly_federated_tenant_is_silent_including_coverage():
    """THE test. One enforced corporate trust, restricted to a named group, identities
    provisioned rather than auto-created, certificate a year out — and an export that
    carries all of it. ZERO findings, coverage included.

    A coverage finding here would be permanent noise on the best-configured subaccount
    in the estate, which is the first one a customer checks the report against."""
    assert run(
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


@pytest.mark.parametrize("absent", [None, {}, [], "", {"trusts": []}])
def test_an_absent_trust_export_discloses_nothing_here(absent):
    """BOUNDARY. A missing export is the coverage manifest's subject — it reports the
    41-of-117 sources story once, for the whole scan. Restating it per check would bury
    the manifest under duplicates of something it already says better."""
    assert cov(btp_trust=absent) == []


def test_empty_data_runs_every_check_without_raising():
    """A module that raises on a missing export takes the whole scan down, and these
    exports are precisely the ones a first-time customer cannot produce."""
    findings = AdvancedIamAuditor({}, {}).run_all_checks()
    assert isinstance(findings, list)
    assert not [f for f in findings if f["check_id"].startswith("IAM-FEDCOV-")]


@pytest.mark.parametrize("junk", [
    {"trusts": ["not-a-dict", None, 42]},
    {"trusts": [{"originKey": None, "status": None}]},
    "a bare string",
])
def test_malformed_trust_data_neither_raises_nor_invents_a_gap(junk):
    """Hand-edited and half-truncated exports are the normal input here. A row that
    names no trust cannot be disclosed as an unassessed trust."""
    assert cov(btp_trust=junk) == []


def test_the_coverage_ids_are_not_part_of_the_defect_family():
    """BOUNDARY, and load-bearing. `IAM-FED-*` means "a defect was found in this
    customer's federation" and is filtered on as such — by the report and by
    `tests/test_identity_federation.py`. A gap in OUR evidence counted under that
    prefix would inflate the number a reader trusts most, and would silently change
    what every existing IAM-FED-* assertion means."""
    for check_id in COVERAGE_CHECKS:
        assert not check_id.startswith("IAM-FED-")


# --------------------------------------------------------------------------- #
#  Contract: routing, shape, and the real shipped export                       #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("check_id", COVERAGE_CHECKS)
def test_every_coverage_check_routes_to_a_team(check_id):
    """An unrouted check_id lands in nobody's queue and is never worked — which for a
    disclosure means the gap is stated and then ignored, twice over."""
    assert team_for(check_id) != "unassigned"


def test_the_coverage_findings_honour_the_finding_contract():
    """A malformed finding renders as garbage in the PDF and breaks the ingest, and it
    is invisible until a customer sees the report."""
    findings = cov(btp_trust={"trusts": [trust()]})
    assert ids(findings) == list(COVERAGE_CHECKS)
    for f in findings:
        for key in ("check_id", "title", "severity", "category",
                    "description", "remediation"):
            assert isinstance(f[key], str) and f[key].strip()
        assert f["severity"] == "INFO", (
            "a gap in our evidence is not a defect in their landscape; rating it "
            "higher spends the reader's attention on our export guide")
        assert f["scope"] == "aggregate", (
            "supplying the attribute closes this for every trust at once; per-trust "
            "identity would retire and re-raise it as trusts come and go")
        assert "affected_objects" not in f, (
            "the gap is in the export, not in the trust — hanging an 'unassessed' "
            "node off the trust asserts what this finding declines to assert")
        assert f["affected_items"] and all(isinstance(i, str)
                                           for i in f["affected_items"])
        assert f["affected_count"] == len(f["affected_items"])
        assert f["references"] and all(isinstance(r, str) for r in f["references"])
        assert f["details"]["unassessable_check"].startswith("IAM-FED-")


@pytest.mark.skipif(not (ROOT / "sample_data" / "btp_trust.json").is_file(),
                    reason="sample_data not present")
def test_the_shipped_sample_export_shows_the_gap():
    """The bundled export is what every demo and every screenshot runs on, and it is
    the exact shape a real tenant produces: five fields, neither of the two this
    feature needs. If these findings stop appearing on it, the disclosure is being
    proved against fixtures nobody ships while the shipped report goes back to looking
    clean."""
    import contextlib
    import io

    from modules.data_loader import DataLoader
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(ROOT / "sample_data").load_all()

    findings = [f for f in AdvancedIamAuditor(dict(data), {}).run_all_checks()
                if f["check_id"].startswith("IAM-FEDCOV-")]
    assert ids(findings) == list(COVERAGE_CHECKS)
    # Both shipped trusts are active and neither carries either attribute, so both
    # are named — the report says which trusts were not assessed, not merely that
    # something was not.
    named = " ".join(i for f in findings for i in f["affected_items"])
    assert "sap.default" in named and "corp-aad-tenant" in named
