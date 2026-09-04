"""What the graph joins to the objects a finding names.

THE SECOND CONSUMER, and the one that finally reads `grants_authorization`.
`path_actors` walks only edges that START at an account, so the 14
role -> auth_object edges — the largest single kind in the graph — were still
read by nothing after it landed. A finding about a role is where they belong:
the reader is looking at Z_BASIS_SUPER and wants to know who holds it and what
it grants.

THE SEPARATION IS THE FEATURE. `data/graph_edges.json` states it plainly:
AUTH-002 evidences user -> role and role -> auth_object, and does NOT evidence
user -> auth_object, because that is the transitive closure and asserting it
would state as observed what is only implied. So this returns two one-hop lists
that are never joined, and the page renders them as separate lines with a
sentence saying why.

AND A THIRD LIST NOBODY WOULD PREDICT. An aggregate finding like USR-002 names
the users AND the profiles, so its own grants have both ends inside the finding.
The first version filed every one of those under BOTH "held by" and "grants" —
each edge listed twice, and a finding that was only describing itself looked
surrounded. `within` is that case, told apart.
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


@pytest.fixture(scope="module")
def database():
    from server import db
    db.init_schema()
    yield db
    db.close_pool()


@pg
def test_an_unknown_finding_is_empty_rather_than_an_exception(database):
    from server import graph
    got = graph.finding_neighbourhood(999999999, None)
    assert got["held_by"] == [] and got["grants"] == [] and got["within"] == []
    # None, not 0: nothing was looked up, which differs from looking and finding
    # no edges.
    assert got["edges_available"] is None


@pg
def test_a_finding_outside_the_callers_scope_reveals_no_neighbourhood(database):
    """Scope is checked by reading the finding first. A caller who cannot see a
    finding must not learn what it is connected to."""
    from server import graph
    fid = database.one("SELECT id FROM finding ORDER BY id LIMIT 1")
    if fid is None:
        pytest.skip("no findings in this database")
    other = database.one(
        "INSERT INTO landscape (name, deployment_mode) "
        "VALUES (%s,'rise_pce') RETURNING id",
        ("nbr-%s" % os.urandom(6).hex(),))["id"]
    system = database.one(
        "INSERT INTO sap_system (landscape_id, sid, client, tier) "
        "VALUES (%s,'ZZZ','000','sandbox') RETURNING id", (other,))["id"]
    try:
        got = graph.finding_neighbourhood(fid["id"], [system])
        assert got["held_by"] == [] and got["grants"] == []
        assert got["edges_available"] is None
    finally:
        database.execute("DELETE FROM landscape WHERE id = %s", (other,))


@pg
def test_an_edge_is_never_listed_in_two_places(database):
    """The bug the third list exists to fix: an edge whose both ends the finding
    names appeared as a neighbour twice, once in each direction."""
    from server import graph
    for row in database.query("SELECT id FROM finding ORDER BY id LIMIT 60"):
        got = graph.finding_neighbourhood(row["id"], None)
        seen = set()
        for entry in got["held_by"] + got["grants"]:
            key = (entry["name"], entry["object"], entry["edge_type"])
            assert key not in seen, "%s listed twice on finding %s" % (
                key, row["id"])
            seen.add(key)


@pg
def test_within_edges_have_both_ends_among_the_findings_own_objects(database):
    """That is what makes them internal structure rather than a neighbour."""
    from server import graph
    from server import identity, queries
    import json as _json

    for row in database.query("SELECT id FROM finding ORDER BY id LIMIT 40"):
        got = graph.finding_neighbourhood(row["id"], None)
        if not got["within"]:
            continue
        finding = queries.get_finding(row["id"], None)
        subject = finding.get("subject")
        if isinstance(subject, str):
            subject = _json.loads(subject)
        names = {n["name"] for n in identity.extract_nodes(
            [{"affected_objects": subject or []}],
            default_system=finding.get("sid"))}
        for edge in got["within"]:
            assert edge["from"] in names and edge["to"] in names, edge


@pg
def test_grants_authorization_is_finally_reachable(database):
    """It is the largest single edge kind in the graph and `path_actors` cannot
    read it, because its source is a role rather than an account. If this ever
    returns nothing on an estate that HAS such edges, the second consumer has
    stopped consuming the thing it was built for."""
    from server import graph
    n = database.one(
        "SELECT count(*) AS n FROM graph_edge WHERE type = 'grants_authorization'"
    )["n"]
    if not n:
        pytest.skip("no grants_authorization edges in this database")
    seen = False
    for row in database.query("SELECT id FROM finding ORDER BY id"):
        got = graph.finding_neighbourhood(row["id"], None)
        kinds = {e["edge_type"] for e in got["held_by"] + got["grants"]}
        kinds |= {e["edge_type"] for e in got["within"]}
        if "grants_authorization" in kinds:
            seen = True
            break
    assert seen, ("%d grants_authorization edges exist and no finding surfaces "
                  "one" % n)


@pg
def test_the_api_carries_it_on_the_finding_route(database):
    from fastapi.testclient import TestClient
    from server import app as appmod, auth, db

    fid = database.one("SELECT id FROM finding ORDER BY id LIMIT 1")
    if fid is None:
        pytest.skip("no findings in this database")
    name = "nbr_%s" % os.urandom(4).hex()
    auth.create_user(name, "neighbourhood-test-password", "admin")
    client = TestClient(appmod.app)
    try:
        assert client.post("/api/auth/login",
                           json={"username": name,
                                 "password": "neighbourhood-test-password"}
                           ).status_code == 200
        body = client.get("/api/findings/%s" % fid["id"]).json()
        assert "graph" in body, "the finding route does not carry its graph"
        for key in ("held_by", "grants", "within", "objects"):
            assert key in body["graph"], key
    finally:
        db.execute("DELETE FROM app_user WHERE username = %s", (name,))
