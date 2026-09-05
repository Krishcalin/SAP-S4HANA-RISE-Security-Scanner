"""The integration and cryptography half of `platform_pack`.

WHY THESE TWO FAMILIES WERE CHECKED CHECK BY CHECK. The family counts said INTG
300 and CRYPTO 170, and neither number survives reading the checks — the same
trap the IAM family set. CRYPTO carries almost no qualifiers at all, and several
INTG checks are the SAME design decision already declined on the BTP side:
"an insecure mechanism is in use" is fixed by choosing what to move to, which is
a decision about the integration.

WHAT IS WRITABLE IS WHERE THE ACTION NEEDS NO VALUE:

    INTG-IDOC-003     narrow `message type *`          qualifier IS the defect
    INTG-OAUTH-001    remove `scope ADMIN, MANAGE_ALL` qualifier IS the defect
    INTG-OAUTH-003    delete an unused client          object only
    INTG-WH-004       delete a stale registration      object only
    CRYPTO-CERT-001   remove an expired certificate    object only
    CRYPTO-CERT-002   renew an expiring certificate    object only

THE FOUR OBJECT-ONLY ONES are why `_NO_QUALIFIER` exists. `platform_pack`
otherwise declines a finding that records no setting — correctly, because
"narrow  to the specific paths" is a blank where a value goes. But for these the
NAME is the whole coordinate: an expired certificate is removed, not adjusted,
and there is nothing further to say. Without the set they would all decline and
the honest reading would be lost.

CRYPTO-CERT-002 IS THE ONE PACK WITH NO ROLLBACK, and it says so rather than
inventing one. A renewal replaces an expiring certificate; restoring the old one
is not an undo, it is reintroducing the finding.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server import remediation  # noqa: E402


def finding(check_id, subject, **over):
    row = {"check_id": check_id, "sid": "PRD",
           "remediation_owner": "customer_fixable", "subject": subject}
    row.update(over)
    return row


def obj(name, kind="thing", qualifier=None):
    out = {"name": name, "type": kind}
    if qualifier:
        out["qualifier"] = qualifier
    return out


# --------------------------------------------------------------------------- #
#  Where the qualifier is the defect                                           #
# --------------------------------------------------------------------------- #

def test_a_wildcard_message_type_becomes_a_step_to_narrow_it():
    pack = remediation.platform_pack(finding(
        "INTG-IDOC-003",
        [obj("SF_EC", "idoc_partner", "message type *")]))
    assert pack["applicable"] is True
    assert "WE20" in pack["where"]
    assert "SF_EC" in pack["apply"][0] and "message type *" in pack["apply"][0]
    assert "restore message type *" in pack["rollback"][0]


def test_admin_scopes_are_removed_by_name():
    pack = remediation.platform_pack(finding(
        "INTG-OAUTH-001",
        [obj("sb-apim-admin", "oauth_client", "scope ADMIN, MANAGE_ALL")]))
    assert "SOAUTH2" in pack["where"]
    assert "remove scope ADMIN, MANAGE_ALL" in pack["apply"][0]
    assert "leaving only the scopes it calls" in pack["apply"][0]


# --------------------------------------------------------------------------- #
#  Where the object's name is the whole coordinate                             #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("check_id,kind,expect", [
    ("INTG-OAUTH-003", "oauth_client", "delete this OAuth client"),
    ("INTG-WH-004", "endpoint", "delete this webhook registration"),
    ("CRYPTO-CERT-001", "certificate", "remove this expired certificate"),
    ("CRYPTO-CERT-002", "certificate", "renew this certificate"),
])
def test_an_action_needing_no_value_works_without_a_qualifier(check_id, kind, expect):
    """These findings record no setting, and none is needed: an expired
    certificate is removed, not adjusted. Without `_NO_QUALIFIER` they would all
    decline as "records no setting", which is true and beside the point."""
    pack = remediation.platform_pack(finding(check_id, [obj("THE_THING", kind)]))
    assert pack["applicable"] is True, pack.get("why")
    assert "THE_THING" in pack["apply"][0]
    assert expect in pack["apply"][0]


def test_a_renewal_says_it_has_no_rollback_rather_than_inventing_one():
    """Restoring an expiring certificate is not an undo — it is reintroducing the
    finding. Every other pack carries a real rollback; this one says why it
    cannot."""
    pack = remediation.platform_pack(finding(
        "CRYPTO-CERT-002", [obj("WebDisp_Public_Cert", "certificate")]))
    assert "no rollback" in pack["rollback"][0]
    assert "should not be restored" in pack["rollback"][0]


def test_the_same_object_twice_produces_one_deletion_step():
    """Two subject entries for one certificate must not become two identical
    'remove' steps — a step list with duplicates reads as more work than exists."""
    pack = remediation.platform_pack(finding(
        "CRYPTO-CERT-001",
        [obj("SSL_Server_Cert", "certificate"),
         obj("SSL_Server_Cert", "certificate")]))
    assert len(pack["apply"]) == 1


def test_a_qualifier_check_still_requires_its_qualifier():
    """The set is an allowlist, not a general loosening: a check whose action
    names `%(qual)s` must still decline when the finding records none."""
    pack = remediation.platform_pack(finding(
        "INTG-IDOC-003", [obj("SF_EC", "idoc_partner")]))
    assert pack["applicable"] is False
    assert "nothing precise to change" in pack["why"]


# --------------------------------------------------------------------------- #
#  What it refuses                                                             #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("check_id", ["INTG-WS-001", "INTG-WS-003",
                                      "INTG-OAUTH-002"])
def test_choosing_a_replacement_mechanism_is_declined(check_id):
    """The same shape declined on the BTP side, in the integration layer: the
    finding is that an insecure mechanism is in use, and the fix is choosing
    which one replaces it."""
    pack = remediation.platform_pack(finding(check_id, [obj("x")]))
    assert pack["applicable"] is False
    assert len(pack["why"]) > 40


@pytest.mark.parametrize("check_id", ["CRYPTO-HANA-001", "CRYPTO-TLS-001",
                                      "INTG-MON-001", "CRYPTO-KEY-001"])
def test_an_unexamined_check_is_not_covered_rather_than_declined(check_id):
    """None, not a decline. These have been neither written nor examined, and the
    plan counts them under `not_covered` — claiming a considered refusal for a
    check nobody looked at would be the more flattering lie."""
    assert remediation.platform_pack(finding(check_id, [obj("x")])) is None


def test_a_finding_sap_owns_is_refused_with_the_other_route():
    pack = remediation.platform_pack(finding(
        "CRYPTO-CERT-001", [obj("c", "certificate")],
        remediation_owner="ticket_to_sap"))
    assert pack["applicable"] is False
    assert "service request" in pack["why"]


# --------------------------------------------------------------------------- #
#  Kind and wiring                                                             #
# --------------------------------------------------------------------------- #

def test_these_report_a_different_kind_from_btp():
    """The plan groups blocks by kind, and one block mixing STRUST with the BTP
    cockpit would be a single 'where' covering two consoles."""
    btp = remediation.platform_pack(finding(
        "BTP-CC-001", [obj("b", "cc_backend", "path=/")]))
    crypto = remediation.platform_pack(finding(
        "CRYPTO-CERT-001", [obj("c", "certificate")]))
    assert btp["kind"] == "btp_setting"
    assert crypto["kind"] == "platform_setting"
    assert btp["kind"] != crypto["kind"]


@pytest.mark.parametrize("check_id,kind,expected", [
    ("INTG-IDOC-003", "idoc_partner", "WE20"),
    ("INTG-OAUTH-003", "oauth_client", "SOAUTH2"),
    ("CRYPTO-CERT-001", "certificate", "STRUST"),
])
def test_it_names_the_transaction_not_just_the_system(check_id, kind, expected):
    subject = [obj("x", kind, "message type *" if "IDOC" in check_id else None)]
    pack = remediation.platform_pack(finding(check_id, subject))
    assert expected in pack["where"], pack["where"]


def test_the_dispatcher_reaches_them():
    assert remediation.pack(finding(
        "CRYPTO-CERT-001", [obj("c", "certificate")]))["kind"] == "platform_setting"


def test_they_need_no_graph():
    assert remediation.platform_pack(
        finding("CRYPTO-CERT-001", [obj("c", "certificate")]), None
    )["applicable"] is True
