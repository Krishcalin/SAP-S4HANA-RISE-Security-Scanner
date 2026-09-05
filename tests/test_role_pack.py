"""PFCG coordinates for an authorization finding.

WHY THIS FAMILY NEXT. Measured on the drive database, change artefacts existed
for two shapes out of about fourteen finding families — roughly 2% of open
findings on a real system. Most families carry only aggregate counts in their
details (`total_unused`, `total_deprecated`), so no change can be written from
them at all. `AUTH-*` is the exception and by some distance the best one: 160 of
160 open AUTH findings carry object identity, and what they carry is exactly what
a PFCG change needs.

    AUTH-002  role Z_BASIS_SUPER · auth_object S_RFCACL · RFC_USER=*,RFC_SYSID=*

IT IS NOT EXECUTABLE, AND THAT IS NOT A SHORTCOMING. PFCG is a dialog
transaction: there is no statement to paste, and generating one would be a
fiction. `executable` is False and the console renders steps differently from
statements, so nobody pastes these into a terminal.

THE PAIRS COME FROM THE GRAPH, for the reason `hana_pack` already documents: a
finding names roles and objects as two flat lists, and "restrict one of these six
objects in one of these four roles" is not a change. What it does NOT do is join
user→role→object into user→object; `data/graph_edges.json` says AUTH-002
evidences the two hops and not the closure, and the pack stays on the hop it has.

THE QUALIFIER LESSON, INVERTED. In `hana_pack` a qualifier made a grant
unwritable — the export gave a bare object name that might be a procedure or a
user. Here the qualifier is the whole change: removing S_RFCACL from a role and
restricting RFC_USER within it are different acts with different blast radii, so
a pair with no field values is counted and not written.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server import remediation  # noqa: E402


def edge(role="Z_BASIS_SUPER", obj="S_RFCACL"):
    return {"edge_type": "grants_authorization", "provenance": "configured",
            "check_id": "AUTH-002", "from": role, "from_type": "role",
            "to": obj, "to_type": "auth_object"}


def finding(**over):
    row = {"check_id": "AUTH-002", "sid": "PRD",
           "remediation_owner": "customer_fixable",
           "subject": [{"name": "Z_BASIS_SUPER", "type": "role"},
                       {"name": "S_RFCACL", "type": "auth_object",
                        "qualifier": "RFC_USER=*,RFC_SYSID=*"}]}
    row.update(over)
    return row


def hood(within=None, held_by=None):
    return {"within": within if within is not None else [edge()],
            "held_by": held_by or [], "grants": []}


# --------------------------------------------------------------------------- #
#  The coordinates                                                             #
# --------------------------------------------------------------------------- #

def test_it_names_the_role_the_object_and_the_field_values():
    pack = remediation.role_pack(finding(), hood())
    assert pack["applicable"] is True
    assert pack["where"].startswith("PFCG")
    step = pack["apply"][0]
    for token in ("Z_BASIS_SUPER", "S_RFCACL", "RFC_USER=*", "RFC_SYSID=*"):
        assert token in step, step


def test_it_is_not_executable():
    """PFCG is a dialog transaction. There is nothing to paste, and a step that
    renders as a statement invites somebody to try."""
    assert remediation.role_pack(finding(), hood())["executable"] is False


def test_the_rollback_restores_the_values_it_named():
    pack = remediation.role_pack(finding(), hood())
    assert len(pack["rollback"]) == len(pack["apply"])
    assert "restore" in pack["rollback"][0]
    assert "RFC_USER=*" in pack["rollback"][0]


def test_one_step_per_role_that_grants_it():
    """Four roles granting the same object is four PFCG edits, not one."""
    roles = ["Z_A", "Z_B", "Z_C"]
    pack = remediation.role_pack(
        finding(), hood([edge(role=r) for r in roles]))
    assert len(pack["apply"]) == 3
    assert {s.split(" > ")[1] for s in pack["apply"]} == set(roles)


def test_only_role_to_object_edges_are_used():
    """`holds_role` is a user→role edge. Reading it here would put a user name
    where PFCG expects a role and a role where it expects an object, and
    asserting user→object is the transitive closure `data/graph_edges.json`
    refuses to evidence.

    THE ROLE IS GIVEN A QUALIFIER ON PURPOSE. Without one the edge is dropped by
    the field-values check instead, and this test passed with the type filter
    deleted — the wrong guard doing the work, which a mutation found."""
    row = finding(subject=[
        {"name": "Z_BASIS_SUPER", "type": "role", "qualifier": "ACTVT=02"},
        {"name": "S_RFCACL", "type": "auth_object",
         "qualifier": "RFC_USER=*,RFC_SYSID=*"}])
    user_edge = {"edge_type": "holds_role", "from": "JSMITH",
                 "from_type": "user", "to": "Z_BASIS_SUPER", "to_type": "role"}
    pack = remediation.role_pack(row, hood([edge(), user_edge]))
    assert len(pack["apply"]) == 1, pack["apply"]
    assert "JSMITH" not in " ".join(pack["apply"])


# --------------------------------------------------------------------------- #
#  What it refuses                                                             #
# --------------------------------------------------------------------------- #

def test_a_pair_with_no_field_values_is_declined_not_guessed():
    """Without the values the only statable change is "remove the object", which
    is a much larger act than restricting it."""
    row = finding(subject=[{"name": "Z_BASIS_SUPER", "type": "role"},
                           {"name": "S_RFCACL", "type": "auth_object"}])
    pack = remediation.role_pack(row, hood())
    assert pack["applicable"] is False
    assert pack["apply"] == [] and pack["rollback"] == []
    assert "field values" in pack["why"]


def test_a_qualifier_that_is_not_field_values_is_declined():
    """A qualifier is free text. Most AUTH checks write FIELD=VALUE pairs; one
    that writes a sentence is not coordinates."""
    row = finding(subject=[{"name": "Z_BASIS_SUPER", "type": "role"},
                           {"name": "S_RFCACL", "type": "auth_object",
                            "qualifier": "granted far too widely"}])
    assert remediation.role_pack(row, hood())["applicable"] is False


def test_a_finding_sap_owns_is_refused_with_the_other_route():
    pack = remediation.role_pack(
        finding(remediation_owner="ticket_to_sap"), hood())
    assert pack["applicable"] is False
    assert "service request" in pack["why"]


def test_pairs_without_values_are_counted_beside_the_ones_with():
    """Silently dropping them would make the plan read as complete."""
    row = finding(subject=[
        {"name": "Z_A", "type": "role"},
        {"name": "S_RFCACL", "type": "auth_object", "qualifier": "RFC_USER=*"},
        {"name": "S_DEVELOP", "type": "auth_object"}])
    pack = remediation.role_pack(
        row, hood([edge(role="Z_A", obj="S_RFCACL"),
                   edge(role="Z_A", obj="S_DEVELOP")]))
    assert len(pack["apply"]) == 1
    assert any("1 further authorization" in c for c in pack["caveats"])


@pytest.mark.parametrize("check_id", ["PARAM-LOGIN/MIN_PASSWORD_LNG",
                                      "HANADB-PRIV-002", "BTP-CC-001"])
def test_it_answers_none_for_another_family(check_id):
    assert remediation.role_pack(finding(check_id=check_id), hood()) is None


def test_it_answers_none_without_a_graph():
    assert remediation.role_pack(finding(), None) is None


def test_it_answers_none_when_no_role_grants_the_object():
    assert remediation.role_pack(finding(), hood([])) is None


# --------------------------------------------------------------------------- #
#  The caveats, which are most of the value                                    #
# --------------------------------------------------------------------------- #

def test_it_says_nothing_has_been_applied():
    caveats = " ".join(remediation.role_pack(finding(), hood())["caveats"])
    assert "has changed nothing" in caveats


def test_it_warns_that_an_ungenerated_role_is_not_a_changed_role():
    """The SAP gotcha that makes this artefact credible: PFCG does not apply an
    authorization change until the profile is regenerated, and a user does not
    receive it until their next logon. A role edited and not generated reads as
    fixed on the next scan and is not."""
    caveats = " ".join(remediation.role_pack(finding(), hood())["caveats"])
    assert "regenerated" in caveats and "logon" in caveats


def test_it_names_who_holds_the_role_when_the_export_says():
    """Who this breaks is why these changes stall in review."""
    holders = [{"edge_type": "holds_role", "name": "JSMITH"},
               {"edge_type": "holds_role", "name": "LWANG"}]
    caveats = " ".join(
        remediation.role_pack(finding(), hood(held_by=holders))["caveats"])
    assert "JSMITH" in caveats and "LWANG" in caveats
    assert "2 account(s)" in caveats


def test_an_absent_assignment_export_is_unknown_and_not_nobody():
    """The three-state rule this codebase runs on. A missing user-role export is
    not an unassigned role, and reading it as one would make a change look free
    of consequence."""
    caveats = " ".join(remediation.role_pack(finding(), hood())["caveats"])
    assert "unknown rather than nobody" in caveats
    assert "no account" not in caveats.lower()


def test_it_says_to_capture_the_role_before_editing():
    """The rollback restores the values named here and cannot restore anything
    this tool never saw."""
    caveats = " ".join(remediation.role_pack(finding(), hood())["caveats"])
    assert "transport request" in caveats or "download" in caveats


def test_a_very_wide_finding_is_capped_and_says_so():
    edges = [edge(role="Z_ROLE%03d" % i) for i in range(80)]
    pack = remediation.role_pack(finding(), hood(edges))
    assert len(pack["apply"]) == remediation._MAX_STATEMENTS
    assert any("of 80 steps shown" in c for c in pack["caveats"])


# --------------------------------------------------------------------------- #
#  Wiring                                                                      #
# --------------------------------------------------------------------------- #

def test_the_dispatcher_reaches_it():
    """`pack()` is what every caller uses; a family the dispatcher never tries
    is a family with no remediation however good its builder is."""
    assert remediation.pack(finding(), hood())["kind"] == "role_authorization"


def test_it_does_not_shadow_the_other_builders():
    param = {"check_id": "PARAM-LOGIN/MIN_PASSWORD_LNG", "sid": "PRD",
             "remediation_owner": "customer_fixable",
             "details": {"parameter": "login/min_password_lng",
                         "ecs_standard": "15", "current_value": "6"}}
    assert remediation.pack(param, hood())["kind"] == "profile_parameter"
