"""The change itself, for a finding the customer is able to make.

The product finds a problem, ranks it, explains the ranking and names the export
that would find more — then hands over prose. For a profile parameter it already
knows the name, the current value, the required value and the Note that mandates
it: everything an operator retypes by hand into RZ10 from a screen that could
have written it.

    apply    : login/min_password_lng = 15
    rollback : login/min_password_lng = 6

WHAT IT MUST NEVER DO, and what these tests are mostly about.

It must never emit a change the customer cannot apply. Under a RISE contract the
profile parameters are SAP's, and an RZ10 line is worse than nothing there —
`server/servicerequest.py` already drafts the right artefact, so this defers to
it and says so.

It must never emit a rule where a value goes. `expected_value` on a real finding
reads "15 (SAP standard) or one of: >=15"; `ecs_standard` reads "15". Pasting
the first into a profile puts a sentence where a number belongs, and this text
is meant to be APPLIED rather than read, so the bar is higher than for prose.

It must never claim anything was done. This product holds no connection to SAP.

TWO BUGS THESE TESTS EXIST BECAUSE OF, both found by running real findings
through the first draft rather than by reading it. The owner constant is
`customer_fixable` and I had guessed "customer", so every pack came back
inapplicable and looked like correct RISE behaviour. And `expected_value` is
prose, which would have produced an unusable apply line on any finding where
`ecs_standard` happened to be absent.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server import remediation  # noqa: E402


def finding(check_id="PARAM-LOGIN/MIN_PASSWORD_LNG",
            owner="customer_fixable", sid="OPD", **detail):
    base = {"parameter": "login/min_password_lng", "current_value": "6",
            "ecs_standard": "15",
            "expected_value": "15 (SAP standard) or one of: >=15",
            "baseline_source": "SAP Note 3250501"}
    base.update(detail)
    return {"check_id": check_id, "remediation_owner": owner, "sid": sid,
            "latest_details": base}


# --------------------------------------------------------------------------- #
#  The change                                                                  #
# --------------------------------------------------------------------------- #

def test_it_writes_the_line_an_operator_would_type():
    pack = remediation.pack(finding())
    assert pack["applicable"] is True
    assert pack["apply"] == ["login/min_password_lng = 15"]
    assert "RZ10" in pack["where"] and "OPD" in pack["where"]


def test_the_rollback_is_the_value_that_was_observed():
    """Not a guess at the SAP default: restoring what SAP ships is a different
    change from undoing this one."""
    pack = remediation.pack(finding(current_value="6"))
    assert pack["rollback"] == ["login/min_password_lng = 6"]


def test_an_unset_parameter_rolls_back_to_something_readable():
    """An empty value IS a value — `gw/sec_info` unset is the finding — and a
    blank in a change request reads as a broken tool."""
    pack = remediation.pack(finding(parameter="gw/sec_info", current_value="",
                                    ecs_standard="/usr/sap/PRD/secinfo"))
    assert pack["rollback"] == ["gw/sec_info = (not set)"]


def test_it_says_how_to_confirm_the_fix_worked():
    pack = remediation.pack(finding())
    assert "Re-run the scan" in pack["verify"]
    assert "PARAM-LOGIN/MIN_PASSWORD_LNG" in pack["verify"]


def test_it_never_claims_to_have_changed_anything():
    """This product holds no connection to SAP and never will."""
    pack = remediation.pack(finding())
    text = " ".join(pack["caveats"]).lower()
    assert "has changed nothing" in text
    assert "change control" in text


def test_it_carries_the_authority_for_the_value():
    pack = remediation.pack(finding())
    assert pack["source"] == "SAP Note 3250501"


# --------------------------------------------------------------------------- #
#  What it refuses                                                             #
# --------------------------------------------------------------------------- #

def test_a_parameter_sap_operates_is_deferred_not_drafted():
    """THE FIRST BUG THIS FILE EXISTS FOR, from the other direction. Under RISE
    the parameters are SAP's, and `servicerequest` already drafts the right
    artefact — an RZ10 line the customer cannot apply is worse than none."""
    pack = remediation.pack(finding(owner="ticket_to_sap"))
    assert pack["applicable"] is False
    assert pack["apply"] == [] and pack["rollback"] == []
    assert "service request" in pack["why"]


def test_the_customer_owner_value_is_the_one_the_product_actually_uses():
    """The first draft guessed "customer". The real value is `customer_fixable`,
    every pack came back inapplicable, and it looked exactly like correct RISE
    behaviour until real findings went through it."""
    assert remediation.pack(finding(owner="customer_fixable"))["applicable"]
    assert remediation._CUSTOMER_FIXABLE == "customer_fixable"


def test_a_rule_is_not_written_as_a_value():
    """`expected_value` reads "15 (SAP standard) or one of: >=15". Pasted into a
    profile that is a sentence where a number goes — and this text is meant to
    be applied, not read."""
    pack = remediation.pack(finding(ecs_standard=None))
    assert pack["applicable"] is False
    assert pack["apply"] == []
    assert "rather than a single value" in pack["why"]


def test_what_counts_as_a_value():
    assert remediation._is_a_value("15")
    assert remediation._is_a_value("/usr/sap/PRD/secinfo")
    assert remediation._is_a_value("X")
    assert not remediation._is_a_value(">=15")
    assert not remediation._is_a_value("15 (SAP standard) or one of: >=15")
    assert not remediation._is_a_value("A, B")
    assert not remediation._is_a_value("")


def test_a_finding_with_no_required_value_produces_nothing():
    """None, never a half-filled template: a change request with a blank where
    the number goes gets sent anyway."""
    assert remediation.pack(
        finding(ecs_standard=None, expected_value=None)) is None


# --------------------------------------------------------------------------- #
#  HANA grants: the statements come from the graph, not from a cross product   #
# --------------------------------------------------------------------------- #

def hana(check_id="HANADB-PRIV-002", owner="customer_fixable",
         pairs=(("J_SMITH", "DATA ADMIN"),), edge="holds_hana_privilege",
         subject=None):
    return (
        {"check_id": check_id, "remediation_owner": owner, "sid": "PRD",
         "subject": subject or [], "latest_details": {}},
        {"within": [{"from": u, "to": p, "edge_type": edge,
                     "provenance": "configured", "check_id": check_id}
                    for u, p in pairs],
         "held_by": [], "grants": [], "objects": 2, "edges_available": 40},
    )


def test_the_statements_pair_the_user_with_the_privilege_they_hold():
    """A finding lists grantees and privileges FLAT, and "REVOKE DATA ADMIN
    FROM one of these four users" is not a statement. The holds_hana_privilege
    edges are the pairing, which is why the graph work had to come first."""
    row, nb = hana(pairs=(("J_SMITH", "DATA ADMIN"),
                          ("SVC_INT", "USER ADMIN")))
    pack = remediation.pack(row, nb)
    assert pack["apply"] == ["REVOKE DATA ADMIN FROM J_SMITH;",
                             "REVOKE USER ADMIN FROM SVC_INT;"]


def test_the_rollback_regrants_exactly_what_was_revoked():
    row, nb = hana()
    assert remediation.pack(row, nb)["rollback"] == \
        ["GRANT DATA ADMIN TO J_SMITH;"]


def test_a_role_grant_uses_the_same_statement_shape():
    row, nb = hana(check_id="HANADB-ROLE-001", edge="holds_hana_role",
                   pairs=(("CONTRACTOR1", "SAP_INTERNAL_HANA_SUPPORT"),))
    assert remediation.pack(row, nb)["apply"] == \
        ["REVOKE SAP_INTERNAL_HANA_SUPPORT FROM CONTRACTOR1;"]


def test_a_scoped_privilege_is_refused_rather_than_guessed():
    """THE BUG THIS TEST EXISTS FOR. The qualifier lives on the OBJECT, not in
    the edge, so a first version checked the edge text, found nothing, and would
    have written `REVOKE DEBUG FROM CONTRACTOR1;` for a grant that was `DEBUG ON
    ZFI_PAYMENT_RUN`. That revokes the SYSTEM privilege instead of the object
    one — a different statement, run against a production database.

    The module's own comment says why it cannot be written: the export gives a
    bare OBJECT_NAME that may be a procedure or a user and no field says which,
    and a REVOKE has to name the object's kind."""
    row, nb = hana(check_id="HANADB-PRIV-006",
                   pairs=(("CONTRACTOR1", "DEBUG"),),
                   subject=[{"type": "hana_privilege", "name": "DEBUG",
                             "qualifier": "on=ZFI_PAYMENT_RUN"}])
    pack = remediation.pack(row, nb)
    assert pack["applicable"] is False
    assert pack["apply"] == []
    assert "guess whether it is a schema" in pack["why"]


def test_the_unscoped_grants_survive_when_only_some_are_scoped():
    row, nb = hana(pairs=(("A", "DEBUG"), ("B", "DATA ADMIN")),
                   subject=[{"type": "hana_privilege", "name": "DEBUG",
                             "qualifier": "on=ZFI"}])
    pack = remediation.pack(row, nb)
    assert pack["apply"] == ["REVOKE DATA ADMIN FROM B;"]
    assert any("not written here" in c for c in pack["caveats"]), pack["caveats"]


def test_it_warns_that_a_revoke_cascades():
    """Revoking a privilege held WITH ADMIN OPTION takes away everything the
    grantee granted onward. An operator running this from a console needs to
    know that before, not after."""
    row, nb = hana()
    assert any("cascades" in c for c in remediation.pack(row, nb)["caveats"])


def test_grants_the_customer_does_not_own_are_deferred():
    row, nb = hana(owner="ticket_to_sap")
    pack = remediation.pack(row, nb)
    assert pack["applicable"] is False and pack["apply"] == []


def test_a_long_list_is_capped_and_says_so():
    """Sixty statements is a script somebody runs, and the same [:50] cap the
    modules put on their display lists applies for the same reason."""
    row, nb = hana(pairs=tuple((f"U{i:04d}", "DATA ADMIN") for i in range(60)))
    pack = remediation.pack(row, nb)
    assert len(pack["apply"]) == 50
    assert any("50 of 60" in c for c in pack["caveats"])


def test_without_the_graph_no_hana_pack_is_written():
    """The pairing is the graph's, and a pack built from the flat object list
    would be the cross product the edge rules exist to refuse."""
    row, _ = hana()
    assert remediation.pack(row, None) is None
    assert remediation.pack(row, {"within": [], "held_by": [], "grants": []}) is None


def test_a_check_this_cannot_write_a_change_for_returns_nothing():
    """Most of the catalogue, honestly. A role change needs the authorisation
    object, field and value to be safe; a REVOKE needs the grantee-privilege
    pairing. Neither is guessed at."""
    assert remediation.pack(finding(check_id="AUTH-002")) is None
    assert remediation.pack(finding(check_id="HANADB-PRIV-002")) is None
