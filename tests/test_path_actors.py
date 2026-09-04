"""Who is standing on this attack path.

THE FIRST THING IN THE PRODUCT THAT READS THE GRAPH. Before this, `graph_node`
and `graph_edge` were written by every ingest and selected by nothing.

A path is a chain of hops, and each hop names the CHECKS that evidence it --
"Caller can arrive as any user (AUTH-002)". A check is not an account, so the
templates structurally cannot say who is able to take the route they describe.
The graph can, since it holds `user -holds_role-> role`, `user -holds_profile->
profile` and `user -can_use_destination-> destination`: take the objects the
path's findings name, walk one actor edge backwards, and the accounts fall out.

WHAT IT CLAIMS, in the terms `data/graph_edges.json` sets for every edge: the
configuration GRANTS these accounts the privileges the path depends on. Not that
any of them walked it. `provenance` rides through unchanged rather than being
summarised into a verdict, because `used` means the account logged on in the
exported window -- evidence the ACCOUNT is live, never that it invoked this
role.

AND ABSENCE IS REPORTED AS ABSENCE. An empty actor list is two different things:
a path whose objects no edge reaches, and a landscape whose graph holds no edges
at all. Only one of them says anything about the estate, so the counts that tell
them apart are returned beside the list.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

pg = pytest.mark.skipif(not os.getenv("DB_DSN"),
                        reason="set DB_DSN to a PostgreSQL 16 instance")


# --------------------------------------------------------------------------- #
#  Which edge kinds put an ACCOUNT on a path                                  #
# --------------------------------------------------------------------------- #

def test_actor_edges_are_the_ones_whose_source_is_an_account():
    from server import graph
    from server.edges import load_rules

    rules = {r["edge_type"]: r for r in load_rules()}
    for edge_type in graph._ACTOR_EDGES:
        assert edge_type in rules, "%s is not an edge any rule produces" % edge_type
        assert rules[edge_type]["from_type"] in ("user", "btp_user"), (
            "%s does not start at an account, so walking it backwards does not "
            "answer 'who is standing here'" % edge_type)


def test_grants_authorization_is_deliberately_not_an_actor_edge():
    """It runs role -> auth_object. Its source is a role, and a role is not
    somebody who can log on. Including it would answer the question with the
    wrong kind of thing."""
    from server import graph
    assert "grants_authorization" not in graph._ACTOR_EDGES


# --------------------------------------------------------------------------- #
#  Against a real ingested estate                                             #
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def database():
    from server import db
    db.init_schema()
    yield db
    db.close_pool()


@pytest.fixture()
def a_path(database):
    row = database.one("SELECT id FROM attack_path ORDER BY id LIMIT 1")
    if row is None:
        pytest.skip("no attack paths in this database")
    return row["id"]


@pg
def test_it_returns_the_counts_that_make_an_empty_answer_readable(a_path):
    from server import graph
    got = graph.path_actors(a_path, None)
    for key in ("actors", "edges_available", "reachable_objects",
                "objects_on_path"):
        assert key in got, key
    assert isinstance(got["actors"], list)


@pg
def test_an_unknown_path_is_empty_rather_than_an_exception(database):
    from server import graph
    got = graph.path_actors(999999999, None)
    assert got["actors"] == []
    # None, not 0: nothing was looked up, which is not the same as looking and
    # finding no edges.
    assert got["edges_available"] is None


@pg
def test_a_path_outside_the_callers_scope_yields_nothing(a_path, database):
    """Scope is enforced by reading the path through `get_path` first. A caller
    who cannot see the path must not learn who stands on it."""
    from server import graph
    other = database.one(
        "INSERT INTO landscape (name, deployment_mode) "
        "VALUES (%s,'rise_pce') RETURNING id",
        ("actors-%s" % os.urandom(6).hex(),))["id"]
    system = database.one(
        "INSERT INTO sap_system (landscape_id, sid, client, tier) "
        "VALUES (%s,'ZZZ','000','sandbox') RETURNING id", (other,))["id"]
    try:
        got = graph.path_actors(a_path, [system])
        assert got["actors"] == []
        assert got["edges_available"] is None
    finally:
        database.execute("DELETE FROM landscape WHERE id = %s", (other,))


@pg
def test_every_actor_carries_the_evidence_for_why_it_is_named(database):
    """An account named without the edge that put it there is an accusation
    without a reason."""
    from server import graph
    for row in database.query("SELECT id FROM attack_path ORDER BY id LIMIT 8"):
        got = graph.path_actors(row["id"], None)
        for actor in got["actors"]:
            assert actor["actor"], actor
            assert actor["via"], "%s named with no edge behind it" % actor
            for via in actor["via"]:
                assert via["object"], via
                assert via["edge_type"] in graph._ACTOR_EDGES, via
                # Provenance is carried, never collapsed into a boolean verdict.
                assert "provenance" in via, via


@pg
def test_it_names_no_account_the_graph_does_not_connect(database):
    """The answer must come from edges, not from the findings' object lists. A
    path naming fifty users would otherwise report all fifty as actors, which is
    the ambiguity the edge rules exist to refuse."""
    from server import graph
    for row in database.query("SELECT id FROM attack_path ORDER BY id LIMIT 8"):
        got = graph.path_actors(row["id"], None)
        for actor in got["actors"]:
            n = database.one(
                "SELECT count(*) AS n FROM graph_edge e "
                "JOIN graph_node s ON s.id = e.from_node "
                "WHERE s.name = %s AND e.type = ANY(%s)",
                (actor["actor"], list(graph._ACTOR_EDGES)))["n"]
            assert n > 0, "%s is named but holds no actor edge" % actor["actor"]


@pg
def test_the_api_exposes_it_on_the_single_path_route(a_path):
    from fastapi.testclient import TestClient
    from server import app as appmod, auth, db

    name = "actors_%s" % os.urandom(4).hex()
    auth.create_user(name, "actors-test-password", "admin")
    client = TestClient(appmod.app)
    try:
        assert client.post("/api/auth/login",
                           json={"username": name,
                                 "password": "actors-test-password"}
                           ).status_code == 200
        body = client.get("/api/paths/%s" % a_path).json()
        assert "actors" in body, "the path route does not carry its actors"
        assert "edges_available" in body["actors"]
    finally:
        db.execute("DELETE FROM app_user WHERE username = %s", (name,))
