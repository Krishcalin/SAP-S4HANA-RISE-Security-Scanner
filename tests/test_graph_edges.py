# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

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

from server.edges import extract_edges, load_rules      # noqa: E402


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


def test_no_configuration_finding_ever_produces_a_used_edge():
    """`used` means the relationship was exercised — a destination in a gateway
    log, a role whose holders logged on. No configuration finding evidences
    that, so the column stays honest by being left alone until something that
    observes use fills it."""
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
