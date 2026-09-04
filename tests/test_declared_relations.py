"""A finding that knows which objects relate is now allowed to say so.

WHY THIS EXISTS, measured rather than supposed. On a 404-finding estate the
graph held 939 nodes and 15 edges, and 2.1% of nodes touched an edge at all.
The cause was not the pairing rule, which is careful and correct: it declines
only when BOTH sides are plural, because a finding naming three users and three
profiles evidences THAT they relate without evidencing WHICH, and guessing would
write nine edges where three are true. 42 of the 76 findings naming two object
types were declined that way.

The pairing was rarely unknown to the module. `check_critical_profiles` builds a
list it literally calls `object_pairs`, one (user, profile) at a time, and
flattens it one line later because `affected_objects` is flat and there was
nowhere else to put it. `check_role_expiry` builds `(("user", u), ("role", r))`
per row and comments that a role assignment has no name of its own while the two
ends of it do. Both knew. Neither could say.

`relations` is that place. A module declares WHICH objects relate; what the
relationship is CALLED stays in `data/graph_edges.json`, so declaring a pair
cannot invent edge vocabulary.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server import identity                       # noqa: E402
from server.edges import extract_edges, load_rules  # noqa: E402


def rel(from_type, from_name, to_type, to_name):
    return {"from": {"type": from_type, "name": from_name},
            "to": {"type": to_type, "name": to_name}}


def obj(t, n):
    return {"type": t, "name": n}


def finding(check_id, objects, relations=None, **extra):
    f = {"check_id": check_id, "severity": "CRITICAL", "scope": "aggregate",
         "affected_objects": objects}
    if relations:
        f["relations"] = relations
    f.update(extra)
    return f


THREE_USERS = [obj("user", "SAP*"), obj("user", "DDIC"), obj("user", "JSMITH")]
THREE_PROFILES = [obj("profile", "SAP_ALL"), obj("profile", "SAP_NEW"),
                  obj("profile", "S_A.SYSTEM")]


# --------------------------------------------------------------------------- #
#  The behaviour the ambiguity rule used to force                             #
# --------------------------------------------------------------------------- #

def test_without_relations_a_plural_finding_is_still_declined():
    """The existing rule is right and stays. Nine edges where three are true is
    a worse answer than none."""
    edges, stats = extract_edges(
        [finding("USR-002", THREE_USERS + THREE_PROFILES)], default_system="PRD")
    assert edges == []
    assert stats["declined_ambiguous"] == 1


def test_with_relations_the_declared_pairs_become_edges():
    edges, stats = extract_edges([finding(
        "USR-002", THREE_USERS + THREE_PROFILES,
        relations=[rel("user", "SAP*", "profile", "SAP_ALL"),
                   rel("user", "JSMITH", "profile", "SAP_NEW")])],
        default_system="PRD")
    assert stats["declined_ambiguous"] == 0, "a declared pairing is not ambiguous"
    pairs = {(e["from_key"], e["to_key"], e["type"]) for e in edges}
    assert len(pairs) == 2, pairs
    assert all(t == "holds_profile" for _f, _t, t in pairs)


def test_it_writes_only_the_pairs_declared_not_the_cross_product():
    """THE WHOLE POINT. Three users and three profiles with three declared pairs
    are three edges, never nine."""
    edges, _ = extract_edges([finding(
        "USR-002", THREE_USERS + THREE_PROFILES,
        relations=[rel("user", "SAP*", "profile", "SAP_ALL"),
                   rel("user", "DDIC", "profile", "SAP_NEW"),
                   rel("user", "JSMITH", "profile", "S_A.SYSTEM")])],
        default_system="PRD")
    assert len(edges) == 3
    got = {(e["from_key"].split(":")[1].split("@")[0],
            e["to_key"].split(":")[1].split("@")[0]) for e in edges}
    assert ("SAP*", "SAP_ALL") in got
    assert ("SAP*", "SAP_NEW") not in got, "the cross product was written"


# --------------------------------------------------------------------------- #
#  It must not become a way round the rest of the contract                     #
# --------------------------------------------------------------------------- #

def test_a_relation_with_no_rule_produces_no_edge():
    """A module says which objects relate; the rules file says what the
    relationship is called. Without a rule there is no edge, so a module cannot
    introduce an edge kind by writing one here."""
    edges, _ = extract_edges([finding(
        "USR-002", [obj("user", "A"), obj("table", "T000")],
        relations=[rel("user", "A", "table", "T000")])], default_system="PRD")
    assert edges == []


def test_a_relation_on_the_wrong_check_produces_no_edge():
    """Rules are keyed by check prefix, and declaring a pair does not bypass
    that: the check must be one the rule is about."""
    edges, _ = extract_edges([finding(
        "DPP-ILM-001", THREE_USERS + THREE_PROFILES,
        relations=[rel("user", "SAP*", "profile", "SAP_ALL")])],
        default_system="PRD")
    assert edges == []


def test_a_malformed_relation_does_not_cost_the_other_edges():
    edges, _ = extract_edges([finding(
        "USR-002", THREE_USERS + THREE_PROFILES,
        relations=["nonsense", {"from": None, "to": None},
                   rel("user", "SAP*", "profile", "SAP_ALL")])],
        default_system="PRD")
    assert len(edges) == 1


def test_declaring_relations_does_not_change_finding_identity():
    """It must be safe to convert a module: a declared pairing that changes no
    verdict must not retire the finding and raise a fresh one."""
    before = finding("USR-002", THREE_USERS + THREE_PROFILES)
    after = finding("USR-002", THREE_USERS + THREE_PROFILES,
                    relations=[rel("user", "SAP*", "profile", "SAP_ALL")])
    assert (identity.fingerprint_finding(before, system="PRD", client="100")
            == identity.fingerprint_finding(after, system="PRD", client="100"))


# --------------------------------------------------------------------------- #
#  The modules converted in this change                                        #
# --------------------------------------------------------------------------- #

def test_critical_profiles_declares_who_holds_what():
    from modules.user_auth_audit import UserAuthAuditor
    data = {"profiles": [{"BNAME": "JSMITH", "PROFILE": "SAP_ALL"},
                         {"BNAME": "MWILSON", "PROFILE": "SAP_NEW"}]}
    got = [f for f in UserAuthAuditor(data, {}, {}).run_all_checks()
           if f["check_id"] == "USR-002"]
    assert got, "USR-002 did not fire on two critical profile assignments"
    pairs = {(r["from"]["name"], r["to"]["name"]) for r in got[0]["relations"]}
    assert pairs == {("JSMITH", "SAP_ALL"), ("MWILSON", "SAP_NEW")}


def test_role_expiry_declares_the_assignment_it_is_about():
    from modules.iam_advanced import AdvancedIamAuditor
    data = {"role_expiry": [
        {"UNAME": "JSMITH", "AGR_NAME": "Z_FIN", "TO_DAT": "99991231"},
        {"UNAME": "MWILSON", "AGR_NAME": "Z_BASIS", "TO_DAT": "99991231"}]}
    got = [f for f in AdvancedIamAuditor(data, {}, {}).run_all_checks()
           if f["check_id"] == "IAM-EXP-001"]
    assert got, "IAM-EXP-001 did not fire on two open-ended assignments"
    pairs = {(r["from"]["name"], r["to"]["name"]) for r in got[0]["relations"]}
    assert pairs == {("JSMITH", "Z_FIN"), ("MWILSON", "Z_BASIS")}


def test_holds_role_can_now_actually_be_produced():
    """`holds_role` has existed as a rule since the rules file landed and had
    never produced a single edge on a real estate: the AUTH- family names no
    user objects at all, and the IAM-EXP- findings were all plural on both
    sides."""
    edges, _ = extract_edges([finding(
        "IAM-EXP-001",
        [obj("user", "JSMITH"), obj("user", "MWILSON"),
         obj("role", "Z_FIN"), obj("role", "Z_BASIS")],
        relations=[rel("user", "JSMITH", "role", "Z_FIN"),
                   rel("user", "MWILSON", "role", "Z_BASIS")])],
        default_system="PRD")
    assert {e["type"] for e in edges} == {"holds_role"}
    assert len(edges) == 2


# --------------------------------------------------------------------------- #
#  The rules file                                                              #
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
#  The database half of the estate                                             #
# --------------------------------------------------------------------------- #

def hana(rows_key, rows):
    from modules.hana_db_security import HanaDbSecurityAuditor
    return {f["check_id"]: f
            for f in HanaDbSecurityAuditor({rows_key: rows}, {}, {}
                                           ).run_all_checks()}


def test_hana_privilege_grants_declare_who_holds_what():
    """`check_system_privileges` already said in a comment that a grant is an
    edge and that both ends become graph nodes. Both ends did; which end went
    with which did not, so the entire database estate produced no privilege
    edges."""
    got = hana("hana_granted_privileges", [
        {"GRANTEE": "J_SMITH", "GRANTEE_TYPE": "USER",
         "PRIVILEGE": "DATA ADMIN", "IS_GRANTABLE": "FALSE"},
        {"GRANTEE": "CONTRACTOR1", "GRANTEE_TYPE": "USER",
         "PRIVILEGE": "USER ADMIN", "IS_GRANTABLE": "FALSE"},
    ])
    fired = [f for cid, f in got.items() if cid.startswith("HANADB-PRIV-")
             and f.get("relations")]
    assert fired, "no HANA privilege finding declared its grants"
    pairs = {(r["from"]["name"], r["to"]["name"])
             for f in fired for r in f["relations"]}
    assert ("J_SMITH", "DATA ADMIN") in pairs, pairs


def test_hana_role_grants_declare_who_holds_what():
    got = hana("hana_granted_roles", [
        {"GRANTEE": "J_SMITH", "ROLE_NAME": "SAP_INTERNAL_HANA_SUPPORT"},
        {"GRANTEE": "CONTRACTOR1", "ROLE_NAME": "CONTENT_ADMIN"},
    ])
    assert "HANADB-ROLE-001" in got
    pairs = {(r["from"]["name"], r["to"]["name"])
             for r in got["HANADB-ROLE-001"]["relations"]}
    assert pairs == {("J_SMITH", "SAP_INTERNAL_HANA_SUPPORT"),
                     ("CONTRACTOR1", "CONTENT_ADMIN")}


def test_hana_grants_become_edges():
    edges, _ = extract_edges([finding(
        "HANADB-ROLE-001",
        [obj("hana_user", "J_SMITH"), obj("hana_user", "CONTRACTOR1"),
         obj("hana_role", "CONTENT_ADMIN"), obj("hana_role", "MODELING")],
        relations=[rel("hana_user", "J_SMITH", "hana_role", "CONTENT_ADMIN"),
                   rel("hana_user", "CONTRACTOR1", "hana_role", "MODELING")])],
        default_system="PRD")
    assert {e["type"] for e in edges} == {"holds_hana_role"}
    assert len(edges) == 2


def test_an_incomplete_grant_is_skipped_rather_than_half_recorded():
    """Half a relationship is not a relationship, and inventing the other half
    would put a grant into the graph that nobody made."""
    from modules.hana_db_security import HanaDbSecurityAuditor
    out = []
    HanaDbSecurityAuditor._add_grant(out, "", "hana_role", "CONTENT_ADMIN")
    HanaDbSecurityAuditor._add_grant(out, "J_SMITH", "hana_role", None)
    assert out == []
    HanaDbSecurityAuditor._add_grant(out, "J_SMITH", "hana_role", "CONTENT_ADMIN")
    HanaDbSecurityAuditor._add_grant(out, "J_SMITH", "hana_role", "CONTENT_ADMIN")
    assert len(out) == 1, "duplicate grants must collapse"


def test_a_hana_role_and_a_hana_privilege_are_not_the_same_edge():
    """They are separate objects in HANA, and one edge type spanning both would
    lose which of the two was actually granted."""
    rules = {(r["from_type"], r["to_type"]): r["edge_type"] for r in load_rules()}
    assert rules[("hana_user", "hana_role")] == "holds_hana_role"
    assert rules[("hana_user", "hana_privilege")] == "holds_hana_privilege"


def test_every_rule_still_explains_itself():
    """`why` is what stops the rules file becoming a pile of type pairs nobody
    can audit."""
    for rule in load_rules():
        assert rule.get("why"), rule
        for field in ("check_prefix", "from_type", "to_type", "edge_type"):
            assert rule.get(field), (field, rule)


def test_a_profile_is_not_filed_as_a_role():
    """In SAP a role GENERATES a profile; they are separate objects, and one
    edge type spanning both would claim an equivalence that does not hold."""
    rules = {(r["from_type"], r["to_type"]): r["edge_type"] for r in load_rules()}
    assert rules[("user", "profile")] == "holds_profile"
    assert rules[("user", "role")] == "holds_role"
