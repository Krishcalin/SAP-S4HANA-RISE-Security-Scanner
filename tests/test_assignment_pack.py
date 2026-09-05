"""SU01 coordinates for a role-assignment finding.

THE OTHER HALF OF `role_pack`. That one fixes what a role GRANTS; this fixes WHO
HOLDS IT and for how long. They read the same graph from opposite ends —
`grants_authorization` (role -> auth object) there, `holds_role` (user -> role)
here — and between them they are the two ends of an authorization remediation.

WHAT THE FAMILY ACTUALLY HOLDS, because the headline count was misleading and I
had recommended this on it. `IAM-*` is 22 checks and 220 open findings, but the
bulk is process rather than configuration: firefighter session review, access
review campaigns, federation trust, a deferral notice. No tool writes a change
for "sessions not reviewed by a controller".

The writable core is the three assignment checks, and only two of them:

    IAM-EXP-001  no expiry date        -> add one          WRITABLE
    IAM-EXP-002  expired, still there  -> remove it        WRITABLE
    IAM-EXP-003  validity too long     -> shorten it       DECLINED

`IAM-EXP-003` is declined because stating the change needs two numbers the
export carries neither of — what the validity is now, and what the policy
allows. "Reduce it" with no from and no to is the sentence-where-a-value-goes
failure `parameter_pack` already refuses, and the rollback could not restore a
date nobody recorded.

`IAM-EXP-001` is deliberately NOT declined on the same grounds, and the
distinction is the point: the change is to ADD an end date to an empty field,
which is unambiguous in kind. Only the date is the customer's, and that is said
in a caveat rather than guessed at.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server import remediation  # noqa: E402


def edge(user="AGARCIA", role="Z_MM_BUYER", edge_type="holds_role"):
    return {"edge_type": edge_type, "provenance": "configured",
            "from": user, "from_type": "user", "to": role, "to_type": "role"}


def finding(check_id="IAM-EXP-001", **over):
    row = {"check_id": check_id, "sid": "PRD",
           "remediation_owner": "customer_fixable",
           "subject": [{"name": "AGARCIA", "type": "user"},
                       {"name": "Z_MM_BUYER", "type": "role"}]}
    row.update(over)
    return row


def hood(within=None):
    return {"within": within if within is not None else [edge()],
            "held_by": [], "grants": []}


# --------------------------------------------------------------------------- #
#  The coordinates                                                             #
# --------------------------------------------------------------------------- #

def test_a_missing_expiry_becomes_a_step_to_add_one():
    pack = remediation.assignment_pack(finding("IAM-EXP-001"), hood())
    assert pack["applicable"] is True
    assert pack["where"].startswith("SU01")
    step = pack["apply"][0]
    assert "AGARCIA" in step and "Z_MM_BUYER" in step
    assert "validity end date" in step


def test_an_expired_assignment_becomes_a_step_to_remove_it():
    pack = remediation.assignment_pack(finding("IAM-EXP-002"), hood())
    assert "remove the expired assignment" in pack["apply"][0]
    assert "re-assign" in pack["rollback"][0]


def test_the_rollback_undoes_the_change_it_named():
    pack = remediation.assignment_pack(finding("IAM-EXP-001"), hood())
    assert len(pack["rollback"]) == len(pack["apply"])
    assert "clear the validity end date" in pack["rollback"][0]


def test_one_step_per_assignment():
    """A user holding four roles is four rows to maintain, not one."""
    roles = ["Z_A", "Z_B", "Z_C"]
    pack = remediation.assignment_pack(
        finding(), hood([edge(role=r) for r in roles]))
    assert len(pack["apply"]) == 3
    assert {s.split(" > ")[3].split(" ")[0] for s in pack["apply"]} == set(roles)


def test_it_is_not_executable():
    """SU01 is a dialog transaction. There is nothing to paste."""
    assert remediation.assignment_pack(finding(), hood())["executable"] is False


def test_only_user_to_role_edges_are_used():
    """`grants_authorization` is role -> auth object. Reading it here would put an
    authorization object where SU01 expects a role name."""
    other = {"edge_type": "grants_authorization", "from": "Z_MM_BUYER",
             "from_type": "role", "to": "S_TCODE", "to_type": "auth_object"}
    pack = remediation.assignment_pack(finding(), hood([edge(), other]))
    assert len(pack["apply"]) == 1
    assert "S_TCODE" not in " ".join(pack["apply"])


# --------------------------------------------------------------------------- #
#  What it refuses                                                             #
# --------------------------------------------------------------------------- #

def test_an_excessive_validity_is_declined_with_both_unknowns_named():
    pack = remediation.assignment_pack(finding("IAM-EXP-003"), hood())
    assert pack["applicable"] is False
    assert pack["apply"] == [] and pack["rollback"] == []
    assert "current period" in pack["why"] and "policy maximum" in pack["why"]


def test_a_finding_sap_owns_is_refused_with_the_other_route():
    pack = remediation.assignment_pack(
        finding(remediation_owner="ticket_to_sap"), hood())
    assert pack["applicable"] is False
    assert "service request" in pack["why"]


@pytest.mark.parametrize("check_id", ["AUTH-002", "PARAM-LOGIN/MIN_PASSWORD_LNG",
                                      "HANADB-PRIV-002", "IAM-FF-001"])
def test_it_answers_none_for_a_check_it_does_not_handle(check_id):
    """Including `IAM-FF-001` — same family, and a process finding no tool writes
    a configuration change for."""
    assert remediation.assignment_pack(finding(check_id), hood()) is None


def test_it_answers_none_without_a_graph():
    assert remediation.assignment_pack(finding(), None) is None


def test_it_answers_none_when_nothing_pairs_a_user_to_a_role():
    assert remediation.assignment_pack(finding(), hood([])) is None


# --------------------------------------------------------------------------- #
#  The caveats                                                                 #
# --------------------------------------------------------------------------- #

def test_it_says_nothing_has_been_applied():
    caveats = " ".join(remediation.assignment_pack(finding(), hood())["caveats"])
    assert "has changed nothing" in caveats


def test_it_warns_that_a_pfcg_edit_needs_the_user_comparison():
    """The assignment equivalent of role_pack's profile-regeneration warning, and
    the same class of SAP gotcha: an assignment maintained from PFCG's User tab
    does not reach the user master until the comparison runs, so it reads as
    fixed on the next scan and is not."""
    caveats = " ".join(remediation.assignment_pack(finding(), hood())["caveats"])
    assert "user comparison" in caveats
    assert "PFCG" in caveats and "SU01" in caveats


def test_the_expiry_date_is_named_as_the_customers_decision():
    """The finding is that the field is empty. What goes in it is a policy call,
    and saying so is what keeps this a coordinate rather than a guess."""
    caveats = " ".join(
        remediation.assignment_pack(finding("IAM-EXP-001"), hood())["caveats"])
    assert "your policy" in caveats


def test_removing_an_expired_assignment_says_what_it_cannot_restore():
    caveats = " ".join(
        remediation.assignment_pack(finding("IAM-EXP-002"), hood())["caveats"])
    assert "cannot restore the validity dates" in caveats
    assert "AGR_USERS" in caveats


def test_a_very_wide_finding_is_capped_and_says_so():
    edges = [edge(user="USER%03d" % i) for i in range(80)]
    pack = remediation.assignment_pack(finding(), hood(edges))
    assert len(pack["apply"]) == remediation._MAX_STATEMENTS
    assert any("of 80 assignments shown" in c for c in pack["caveats"])


# --------------------------------------------------------------------------- #
#  Wiring                                                                      #
# --------------------------------------------------------------------------- #

def test_the_dispatcher_reaches_it():
    assert remediation.pack(finding(), hood())["kind"] == "user_role_assignment"


def test_it_does_not_shadow_the_role_pack():
    """Both read the same neighbourhood; the check id is what separates them."""
    auth = {"check_id": "AUTH-002", "sid": "PRD",
            "remediation_owner": "customer_fixable",
            "subject": [{"name": "Z_BASIS_SUPER", "type": "role"},
                        {"name": "S_RFCACL", "type": "auth_object",
                         "qualifier": "RFC_USER=*"}]}
    grants = {"edge_type": "grants_authorization", "from": "Z_BASIS_SUPER",
              "from_type": "role", "to": "S_RFCACL", "to_type": "auth_object"}
    assert remediation.pack(auth, hood([grants]))["kind"] == "role_authorization"
