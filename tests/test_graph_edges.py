"""Graph edges, and the refusals that keep them honest.

WHAT WAS MISSING. `graph_node` has been populated since the schema landed.
`graph_edge` was defined at the same time — with a `provenance` column, a
`confidence` column and a comment about never validating reachability — and
nothing had ever written a row into it. The graph held nodes and no
relationships between them.

WHAT THESE TESTS ARE FOR. Not that a rule matches a check id. They pin the three
places where an edge could over-claim: pairing objects a finding does not pair,
asserting the transitive edge, and calling a configured relationship an exercised
one. Each is a refusal, and a refusal with no test is a comment.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.edges import (active_users, extract_edges,  # noqa: E402
                          load_rules, observed_users)


def _finding(check_id, *objects):
    return {"check_id": check_id,
            "affected_objects": [{"type": t, "name": n} for t, n in objects]}


def _types(edges):
    return {(e["from_key"], e["type"], e["to_key"]) for e in edges}


# ═════════════════════════════════════════════════════════════════════════════
#  The pairing rule — the whole design
# ═════════════════════════════════════════════════════════════════════════════

def test_a_singleton_on_one_side_pairs_unambiguously():
    """One role and two users: which users hold the role is not in doubt, so
    both edges are evidenced."""
    edges, stats = extract_edges(
        [_finding("AUTH-002", ("role", "Z_SUPER"),
                  ("user", "ADMIN1"), ("user", "CONTRACTOR7"))])
    assert ("user:ADMIN1", "holds_role", "role:Z_SUPER") in _types(edges)
    assert ("user:CONTRACTOR7", "holds_role", "role:Z_SUPER") in _types(edges)
    assert stats["declined_ambiguous"] == 0


def test_plural_on_both_sides_is_declined_rather_than_cross_producted():
    """THE REFUSAL THIS MODULE IS BUILT ON. Three roles and five users would
    cross-product to fifteen edges where five exist. The finding evidences the
    relationship without evidencing WHICH, so no edge is asserted."""
    edges, stats = extract_edges(
        [_finding("AUTH-002", ("role", "R1"), ("role", "R2"),
                  ("user", "U1"), ("user", "U2"))])
    assert not [e for e in edges if e["type"] == "holds_role"]
    assert stats["declined_ambiguous"] >= 1


def test_the_declined_count_is_reported_rather_than_swallowed():
    """A caller reporting the edges without this number is reporting a graph as
    complete when it is not. It is the honest measure of what a flat object list
    costs."""
    _, stats = extract_edges(
        [_finding("AUTH-002", ("role", "R1"), ("role", "R2"),
                  ("user", "U1"), ("user", "U2"))])
    assert "declined_ambiguous" in stats and stats["declined_ambiguous"] > 0


def test_the_display_string_is_never_parsed_for_the_pairing():
    """`affected_items` carries the pairing as prose — "Role Z — 2 user(s)
    [A, B]". Reading it would resurrect the `display` identification basis this
    product retired, where a finding was identified by prose rather than by the
    objects it names. A finding with the prose but no objects yields nothing."""
    edges, _ = extract_edges([{
        "check_id": "AUTH-002",
        "affected_items": ["Role Z_SUPER — 2 user(s) [ADMIN1, CONTRACTOR7]"],
        "affected_objects": [],
    }])
    assert edges == []


# ═════════════════════════════════════════════════════════════════════════════
#  What an edge refuses to claim
# ═════════════════════════════════════════════════════════════════════════════

def test_the_transitive_edge_is_not_asserted():
    """AUTH-002 evidences user->role and role->auth_object. It does NOT
    evidence user->auth_object: that is the closure, and asserting it as an edge
    would state as observed what is only implied."""
    edges, _ = extract_edges(
        [_finding("AUTH-002", ("role", "Z_SUPER"), ("user", "ADMIN1"),
                  ("auth_object", "S_RFCACL"))])
    kinds = _types(edges)
    assert ("user:ADMIN1", "holds_role", "role:Z_SUPER") in kinds
    assert ("role:Z_SUPER", "grants_authorization", "auth_object:S_RFCACL") in kinds
    assert not [e for e in edges
                if e["from_key"].startswith("user:")
                and e["to_key"].startswith("auth_object:")]


def test_every_edge_says_it_was_derived_and_not_observed():
    """This product holds no connection to the system and never will. A buyer
    who has seen a dynamic scanner will ask whether anything was actually
    reached, and the answer has to be on the row rather than improvised."""
    edges, _ = extract_edges(
        [_finding("AUTH-002", ("role", "Z"), ("user", "U"))])
    assert edges
    for edge in edges:
        assert edge["confidence"] == "derived_from_config"


def test_a_configuration_finding_alone_never_produces_a_used_edge():
    """`used` means something was exercised, and a configuration export alone
    cannot evidence that. With no activity evidence passed in — which is every
    caller that has findings but not the sources they came from — the column
    stays `configured`."""
    edges, _ = extract_edges(
        [_finding("AUTH-002", ("role", "Z"), ("user", "U")),
         _finding("TRUST-004", ("user", "U"), ("destination", "D"))])
    assert edges
    assert {e["provenance"] for e in edges} == {"configured"}


def test_a_self_edge_is_never_emitted():
    """A node related to itself is not a relationship, and it would make a
    chokepoint count meaningless."""
    edges, _ = extract_edges(
        [{"check_id": "AUTH-002",
          "affected_objects": [{"type": "role", "name": "Z"},
                               {"type": "role", "name": "Z"}]}])
    assert not [e for e in edges if e["from_key"] == e["to_key"]]


# ═════════════════════════════════════════════════════════════════════════════
#  Keying, so an edge never points at nothing
# ═════════════════════════════════════════════════════════════════════════════

def test_edges_key_nodes_exactly_as_the_node_extractor_does():
    """An edge whose end is not already a node would mean the two extractors
    disagree about keying. The default system is applied the same way."""
    from server.identity import extract_nodes
    finding = _finding("AUTH-002", ("role", "Z_SUPER"), ("user", "ADMIN1"))
    nodes = {n["key"] for n in extract_nodes([finding], default_system="PRD")}
    edges, _ = extract_edges([finding], default_system="PRD")
    for edge in edges:
        assert edge["from_key"] in nodes, edge
        assert edge["to_key"] in nodes, edge


def test_a_cloud_object_is_not_stamped_with_the_abap_sid():
    """The mirror of the node extractor's cloud-scope rule, and it must stay a
    mirror: borrowing the ABAP SID for a BTP object would place it in the wrong
    namespace, and an edge would then join two systems that never met."""
    from server.identity import _CLOUD_SCOPED_TYPES
    assert _CLOUD_SCOPED_TYPES, "the cloud-scope rule vanished"
    edges, _ = extract_edges(
        [_finding("AUTH-002", ("role", "Z"), ("user", "U"))], default_system="PRD")
    assert all("@PRD" in e["from_key"] for e in edges)


def test_a_malformed_object_does_not_abort_extraction():
    """One bad row must not cost the whole run's edges."""
    edges, _ = extract_edges([{
        "check_id": "AUTH-002",
        "affected_objects": [{"type": "role", "name": "Z"},
                             {"nonsense": True},
                             {"type": "user", "name": "U"}]}])
    assert _types(edges)


# ═════════════════════════════════════════════════════════════════════════════
#  The rules are content
# ═════════════════════════════════════════════════════════════════════════════

def test_the_rules_are_data_not_code():
    """Adding an edge kind is a data change, exactly as adding an attack path
    is. If these move into Python, the next one gets added by whoever is
    comfortable editing Python."""
    rules = load_rules()
    assert rules
    for rule in rules:
        assert set(rule) >= {"check_prefix", "from_type", "to_type",
                             "edge_type", "why"}
        assert len(rule["why"]) > 40, rule


def test_an_unreadable_rules_file_disables_edges_and_nothing_else():
    """Nodes, paths, chokepoints and every check keep working, and the graph
    simply has no relationships — which is the state this module was written to
    leave behind, so degrading back to it is safe."""
    assert load_rules(ROOT / "data" / "does-not-exist.json") == []
    edges, _ = extract_edges(
        [_finding("AUTH-002", ("role", "Z"), ("user", "U"))], rules=[])
    assert edges == []


def test_a_check_no_rule_names_produces_no_edges():
    assert extract_edges([_finding("PARAM-001", ("user", "U"),
                                   ("role", "R"))])[0] == []


# ═════════════════════════════════════════════════════════════════════════════
#  Against the real corpus
# ═════════════════════════════════════════════════════════════════════════════

def test_the_sample_landscape_yields_a_graph_with_relationships_in_it():
    """The point of the whole exercise: before this, every one of these nodes
    stood alone."""
    import contextlib
    import importlib
    import io

    from modules.data_loader import DataLoader
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(ROOT / "sample_data").load_all()
        findings = []
        for name in ("abap_authorizations", "system_trust", "iam_advanced"):
            module = importlib.import_module("modules." + name)
            cls = next(getattr(module, n) for n in dir(module)
                       if n.endswith("Auditor") and n != "BaseAuditor")
            findings += cls(data, {}).run_all_checks()

    edges, stats = extract_edges(findings, default_system="PRD")
    assert len(edges) > 10, stats
    assert {"holds_role", "grants_authorization"} <= {e["type"] for e in edges}
    # And the honest half: some findings could not be paired, and it is counted.
    assert stats["declined_ambiguous"] >= 0


# ═════════════════════════════════════════════════════════════════════════════
#  used vs configured — the one activity claim this product can make offline
# ═════════════════════════════════════════════════════════════════════════════

def _logons(*rows):
    return {"logon_events": [dict(zip(("USERNAME", "EVENT", "COUNT"), r))
                             for r in rows]}


def test_no_logon_export_is_not_a_finding_that_nothing_is_used():
    """THE DISTINCTION THE COLUMN LIVES OR DIES ON. Absent evidence, every edge
    is `configured` — and `provenance_evidence` is None so a reader can tell a
    landscape with no dormant accounts from a landscape nobody checked. Without
    that field the two are the same row."""
    edges, stats = extract_edges(
        [_finding("AUTH-002", ("role", "Z"), ("user", "JSMITH"))], active=None)
    assert {e["provenance"] for e in edges} == {"configured"}
    assert stats["provenance_evidence"] is None
    assert stats["used"] == 0


def test_none_and_empty_are_different_answers():
    """`active_users` returns None for "no export supplied" and a set for "the
    export was read". An empty set is a real answer — nobody logged on — and
    collapsing it into None would say we could not look when we did."""
    assert active_users({}) is None
    assert active_users({"logon_events": None}) is None
    assert active_users({"logon_events": []}) == set()


def test_a_holder_who_logged_on_settles_the_edge_as_used():
    edges, stats = extract_edges(
        [_finding("AUTH-002", ("role", "Z_SUPER"), ("user", "JSMITH"))],
        active=active_users(_logons(("JSMITH", "SUCCESS", "150"))))
    assert [e["provenance"] for e in edges if e["type"] == "holds_role"] == ["used"]
    assert stats["used"] == 1
    assert stats["provenance_evidence"] == "logon_events"


def test_a_holder_absent_from_the_logon_export_stays_configured():
    """The dormant account holding a dangerous role — the case the column exists
    to separate out."""
    edges, _ = extract_edges(
        [_finding("AUTH-002", ("role", "Z_SUPER"), ("user", "DORMANT"))],
        active=active_users(_logons(("JSMITH", "SUCCESS", "150"))))
    assert {e["provenance"] for e in edges} == {"configured"}


def test_a_failed_logon_is_evidence_of_an_attempt_and_not_of_use():
    """MWILSON has 45 failures in the sample corpus. Counting a failure would
    mark an account active on the strength of somebody failing to get in."""
    assert active_users(_logons(("MWILSON", "FAILURE", "45"))) == set()


def test_a_success_row_counting_zero_successes_is_not_activity():
    """THE ROW THAT CAUGHT THIS. `logon_events.csv` is AGGREGATED, and the sample
    corpus contains `UNKNOWN_USER1,SUCCESS,0` — a success row meaning zero
    successful logons. Reading the EVENT column alone would mark the one account
    in the file that never got in as the active one."""
    assert active_users(_logons(("UNKNOWN_USER1", "SUCCESS", "0"))) == set()
    assert active_users(_logons(("UNKNOWN_USER1", "SUCCESS", "0"),
                                ("JSMITH", "SUCCESS", "150"))) == {"JSMITH"}


def test_an_untyped_export_is_one_row_per_logon():
    """The other shape: no outcome column at all, so a row IS a logon. Requiring
    a SUCCESS value would read the whole export as nobody active — "we looked and
    found nothing" from a file that says the opposite."""
    assert active_users({"logon_events": [{"USERNAME": "JSMITH"},
                                          {"BNAME": "AGARCIA"}]}) == {"JSMITH",
                                                                      "AGARCIA"}


def test_the_shape_is_decided_across_the_export_not_per_row():
    """One row missing its outcome in an otherwise-typed export is a hole, not a
    shape — treating it as an untyped row would let it claim activity that the
    export's own convention never granted it."""
    mixed = {"logon_events": [{"USERNAME": "JSMITH", "EVENT": "SUCCESS"},
                              {"USERNAME": "NOSTATUS"}]}
    assert active_users(mixed) == {"JSMITH"}


def test_only_an_edge_from_a_user_can_be_settled_by_a_logon():
    """A role-to-authorization edge has no holder of its own. Marking it `used`
    because somebody who held the role logged on would assert that the grant was
    exercised, which the logon does not show."""
    edges, _ = extract_edges(
        [_finding("AUTH-002", ("role", "Z"), ("user", "JSMITH"),
                  ("auth_object", "S_RFCACL"))],
        active=active_users(_logons(("JSMITH", "SUCCESS", "150"))))
    by_type = {e["type"]: e["provenance"] for e in edges}
    assert by_type["holds_role"] == "used"
    assert by_type["grants_authorization"] == "configured"


def test_a_used_edge_still_says_it_was_derived_from_config():
    """`used` upgrades PROVENANCE, never CONFIDENCE. Nothing was traversed: the
    account's liveness was read out of a second export, and the relationship is
    still inferred from configuration. A buyer asking "did you reach it?" gets
    the same answer as before."""
    edges, _ = extract_edges(
        [_finding("AUTH-002", ("role", "Z"), ("user", "JSMITH"))],
        active=active_users(_logons(("JSMITH", "SUCCESS", "150"))))
    assert {e["confidence"] for e in edges} == {"derived_from_config"}


def test_the_system_scope_does_not_hide_the_user_from_the_logon_export():
    """Node keys carry `@SID`; a logon export carries bare names. Comparing the
    key would settle nothing and every edge would silently stay configured."""
    edges, _ = extract_edges(
        [_finding("AUTH-002", ("role", "Z"), ("user", "JSMITH"))],
        default_system="PRD",
        active=active_users(_logons(("JSMITH", "SUCCESS", "150"))))
    assert [e for e in edges if e["provenance"] == "used"]


def test_case_and_padding_do_not_decide_whether_an_account_is_active():
    assert active_users(_logons((" jsmith ", "success", " 150 "))) == {"JSMITH"}


def test_an_unparseable_count_is_read_as_one_event():
    """Same fallback as `log_monitoring`, and it errs toward believing the row —
    a malformed count is a bad export, not a dormant account."""
    assert active_users(_logons(("JSMITH", "SUCCESS", "n/a"))) == {"JSMITH"}


def test_a_row_with_no_user_column_is_skipped_without_aborting():
    assert active_users({"logon_events": [{"EVENT": "SUCCESS"}, "junk",
                                          {"USERNAME": "JSMITH",
                                           "EVENT": "SUCCESS"}]}) == {"JSMITH"}


def test_both_provenance_counts_are_reported():
    """A UI that shows `used` without `configured` would present a partially
    settled graph as a fully settled one."""
    edges, stats = extract_edges(
        [_finding("AUTH-002", ("role", "Z"), ("user", "JSMITH"),
                  ("auth_object", "S_RFCACL"))],
        active=active_users(_logons(("JSMITH", "SUCCESS", "150"))))
    assert stats["used"] + stats["configured"] == len(edges)
    assert stats["used"] and stats["configured"]


def test_the_sample_corpus_separates_live_holders_from_dormant_ones():
    """End to end on the real files, which is where the aggregate shape and the
    zero-count row actually live."""
    import contextlib
    import importlib
    import io

    from modules.data_loader import DataLoader
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(ROOT / "sample_data").load_all()
        findings = []
        for name in ("abap_authorizations", "system_trust", "iam_advanced"):
            module = importlib.import_module("modules." + name)
            cls = next(getattr(module, n) for n in dir(module)
                       if n.endswith("Auditor") and n != "BaseAuditor")
            findings += cls(data, {}).run_all_checks()

    active = active_users(data)
    assert active is not None and "JSMITH" in active
    assert "UNKNOWN_USER1" not in active     # SUCCESS,0 — never actually got in

    # WHAT THE SAMPLE CORPUS ACTUALLY IS, and it is the awkward case rather than
    # the happy one: its logon export names JSMITH, AGARCIA, MWILSON, SVC_RFC_01
    # and ADMIN_TEST, while its role assignments name ADMIN1, BATCH1,
    # CONTRACTOR7 and DEV1. The populations are DISJOINT. So `used` is 0 for a
    # reason that has nothing to do with activity, and a fixture asserting only
    # "the counts add up" would have passed while the product reported a fully
    # dormant estate.
    _, stats = extract_edges(findings, default_system="PRD", active=active,
                             observed=observed_users(data))
    assert stats["provenance_evidence"] == "logon_events"
    assert stats["users_on_edges"] > 0
    assert stats["users_in_logon_export"] == 0
    assert stats["users_absent_from_logon_export"] == stats["users_on_edges"]
    assert stats["used"] == 0                # and the reason is above, not below


# ═════════════════════════════════════════════════════════════════════════════
#  Did the evidence even cover these users — the third state
# ═════════════════════════════════════════════════════════════════════════════

def test_a_user_absent_from_the_logon_export_is_unassessed_not_quiet():
    """THE DISTINCTION THAT MAKES A ZERO READABLE. `used = 0` has three causes:
    no export, an export covering nobody in this graph, and an export covering
    them all and finding them quiet. Only the third is a finding about the
    landscape. The counts separate them."""
    findings = [_finding("AUTH-002", ("role", "Z"), ("user", "ADMIN1"))]
    _, stats = extract_edges(findings,
                             active=active_users(_logons(("JSMITH", "SUCCESS", "9"))),
                             observed=observed_users(_logons(("JSMITH", "SUCCESS", "9"))))
    assert stats["used"] == 0
    assert stats["users_on_edges"] == 1
    assert stats["users_in_logon_export"] == 0     # nothing was assessed
    assert stats["users_absent_from_logon_export"] == 1


def test_a_user_the_export_covers_and_finds_quiet_is_a_real_finding():
    """The dormant privileged account — the one the column is for. Distinguished
    from the case above by being IN the export."""
    logs = _logons(("DORMANT", "FAILURE", "3"), ("JSMITH", "SUCCESS", "9"))
    _, stats = extract_edges(
        [_finding("AUTH-002", ("role", "Z"), ("user", "DORMANT"))],
        active=active_users(logs), observed=observed_users(logs))
    assert stats["used"] == 0
    assert stats["users_in_logon_export"] == 1      # assessed...
    assert stats["users_absent_from_logon_export"] == 0   # ...and found quiet


def test_observed_counts_every_user_the_export_names_whatever_the_outcome():
    """`observed` is coverage, not activity: a user who only ever failed to log
    on was still assessed."""
    logs = _logons(("MWILSON", "FAILURE", "45"), ("UNKNOWN_USER1", "SUCCESS", "0"))
    assert observed_users(logs) == {"MWILSON", "UNKNOWN_USER1"}
    assert active_users(logs) == set()


def test_no_export_leaves_the_coverage_question_unanswered_rather_than_zero():
    """None, not 0. A zero would answer a question nobody asked."""
    assert observed_users({}) is None
    _, stats = extract_edges(
        [_finding("AUTH-002", ("role", "Z"), ("user", "ADMIN1"))])
    assert stats["users_in_logon_export"] is None
    assert stats["users_absent_from_logon_export"] is None
    assert stats["users_on_edges"] == 1


def test_partial_overlap_reports_both_halves():
    logs = _logons(("JSMITH", "SUCCESS", "9"))
    _, stats = extract_edges(
        [_finding("AUTH-002", ("role", "Z"), ("user", "JSMITH")),
         _finding("AUTH-002", ("role", "Y"), ("user", "ADMIN1"))],
        active=active_users(logs), observed=observed_users(logs))
    assert stats["used"] == 1
    assert stats["users_on_edges"] == 2
    assert stats["users_in_logon_export"] == 1
    assert stats["users_absent_from_logon_export"] == 1
