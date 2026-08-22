"""Filtering the triage queue by security domain.

TWO READINGS OF ONE RULE, AND THE TEST THAT MAKES THEM ONE
A domain tile counts findings in Python (`modules/domains.domain_for`); the queue
behind it selects rows in SQL. Those are two readings of the same membership
rules, and the reader who notices them disagreeing is the one holding both — the
tile that says 44 and the queue that pages through 51.

So the rules are emitted once by `domains.match_terms` and compiled mechanically
by `server/queries._domain_clause`, and the test below compares the two ends
against each other for EVERY domain rather than spot-checking one: it asks the
roll-up what it counted and the queue how many it can page through, and requires
the same number.

`tests/test_domains.py` covers the routing itself with no database. This file
exists for the part that only a database can answer — that the compiled predicate
selects the rows the router would have chosen, `starts_with()` prefixes included.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import domains                                       # noqa: E402

pg = pytest.mark.skipif(not os.getenv("DB_DSN"),
                        reason="set DB_DSN to a PostgreSQL 16 instance")


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient
    from server import app as appmod, auth, db
    db.init_schema()
    name = f"dom_{os.urandom(4).hex()}"
    auth.create_user(name, "domain-test-password", "admin")
    c = TestClient(appmod.app)
    assert c.post("/api/auth/login",
                  json={"username": name, "password": "domain-test-password"}
                  ).status_code == 200
    yield c
    db.execute("DELETE FROM app_user WHERE username = %s", (name,))


@pg
def test_the_queue_and_the_tile_report_the_same_number_for_every_domain(client):
    """THE INVARIANT. One rule, two engines, one answer."""
    rolled = client.get("/api/domains").json()
    for entry in rolled["domains"]:
        if entry["reach"] == domains.NONE:
            continue
        page = client.get("/api/findings", params={"domain": entry["id"]})
        assert page.status_code == 200, entry["id"]
        assert page.json()["total"] == entry["total"], entry["id"]


@pg
def test_every_row_the_filter_returns_really_belongs_to_that_domain(client):
    """Equal totals could in principle be equal by coincidence. Read the rows."""
    rolled = client.get("/api/domains").json()
    for entry in rolled["domains"]:
        if entry["reach"] == domains.NONE or not entry["total"]:
            continue
        rows = client.get("/api/findings",
                          params={"domain": entry["id"]}).json()["findings"]
        for row in rows:
            assert domains.domain_for(row["check_id"], row["category"]) == entry["id"], (
                f"{row['check_id']} ({row['category']}) was returned for "
                f"{entry['id']}")


@pg
def test_a_split_category_is_divided_by_the_queue_the_way_the_router_divides_it(client):
    """The prefix splits are where a hand-written WHERE clause would drift first:
    "Security Audit Log Review" feeds two domains and only the check id separates
    them."""
    events = client.get("/api/findings",
                        params={"domain": "event_monitoring"}).json()["findings"]
    behaviour = client.get("/api/findings",
                           params={"domain": "user_behaviour"}).json()["findings"]
    assert not ({f["id"] for f in events} & {f["id"] for f in behaviour})
    for f in behaviour:
        assert f["check_id"].startswith("LREV-PAT")
    for f in events:
        assert not f["check_id"].startswith("LREV-PAT")


@pg
def test_the_domain_we_do_not_assess_is_refused_rather_than_answered_emptily(client):
    """An empty queue reads as "nothing wrong here", which is the single claim
    this taxonomy exists to prevent us making about Exploit and 0-Day
    Protection. The request is refused with the reason instead."""
    r = client.get("/api/findings", params={"domain": "exploit"})
    assert r.status_code == 400
    assert "not assessed by this product" in r.json()["detail"]


@pg
def test_an_unknown_domain_is_refused_rather_than_ignored(client):
    """Silently dropping the filter answers a narrow question with the whole
    queue, and the caller has no way to tell."""
    r = client.get("/api/findings", params={"domain": "interface-traffic"})
    assert r.status_code == 400
    assert r.json()["detail"] == "no such domain"


@pg
def test_the_domain_filter_composes_with_the_others(client):
    """It is one predicate among several, not a mode. A domain plus a severity
    must narrow further rather than replace."""
    everything = client.get("/api/findings",
                            params={"domain": "identity"}).json()["total"]
    critical = client.get("/api/findings",
                          params={"domain": "identity",
                                  "severity": "CRITICAL"}).json()["total"]
    assert critical <= everything


@pg
def test_the_domain_view_reads_the_stored_coverage_manifest(client):
    """THE DEFECT THIS FILE MISSED THE FIRST TIME.

    `roll_up` grew a `coverage=` parameter, `modules/domains.py` was tested with
    it, the console grew a chip for the state it produces, the offline deck
    passed it — and the two server routes did not. So NOT_SUPPLIED was
    unreachable through the API, and a domain whose feeding module never ran
    rendered as "assessed, and nothing found": the exact sentence this taxonomy
    exists to stop the product saying, on the screen built to enforce it.

    Every unit test still passed, because they all called `roll_up` directly. The
    assertion that would have caught it is this one — the ROUTE reads the
    manifest — so it is made at the route.
    """
    from unittest.mock import patch

    from server import queries

    # A manifest in which nothing ran. Whatever the corpus holds, no assessable
    # domain may claim to have looked at it.
    nothing_ran = {"modules": {"log_review": {"status": "skipped"},
                               "user_auth_audit": {"status": "skipped"}}}
    with patch.object(queries, "latest_coverage", return_value=nothing_ran):
        rolled = client.get("/api/domains").json()
    states = {d["id"]: d["state"] for d in rolled["domains"]}
    assessable = [d for d in rolled["domains"] if d["reach"] != domains.NONE]
    assert assessable, "no assessable domains to check"
    for d in assessable:
        if d["total"] == 0:
            assert d["state"] == domains.NOT_SUPPLIED, (
                f"{d['id']} reported {d['state']} for a run in which no module ran")
    assert states["exploit"] == domains.NOT_ASSESSED


@pg
def test_a_domain_page_agrees_with_its_tile_about_being_assessed(client):
    """A tile and the page behind it disagreeing is worse than either being
    wrong alone — the reader who clicks through is the one who notices."""
    rolled = client.get("/api/domains").json()
    for entry in rolled["domains"]:
        page = client.get(f"/api/domains/{entry['id']}").json()
        assert page["state"] == entry["state"], entry["id"]
        assert page["total"] == entry["total"], entry["id"]


@pg
def test_the_manifest_is_absent_rather_than_invented_when_no_run_completed(client):
    """Claiming an export was missing without having checked is the same class of
    error as claiming it was clean. With no complete run in scope there is
    nothing to read, and the roll-up must not report NOT_SUPPLIED."""
    from unittest.mock import patch

    from server import queries

    with patch.object(queries, "latest_coverage", return_value=None):
        rolled = client.get("/api/domains").json()
    assert not any(d["state"] == domains.NOT_SUPPLIED for d in rolled["domains"])


@pg
def test_a_saved_view_keeps_its_domain_filter(client):
    """Dropped from the allowlist, a saved one-domain link silently replayed as
    the whole queue — a view showing far more than the person who saved it
    intended, which is precisely what the allowlist is for."""
    slug = f"dom-{os.urandom(3).hex()}"
    # FORM DATA, NOT JSON, and the filters come off the Referer rather than the
    # body — "save this view" means "save what I am looking at". The first
    # version of this test posted JSON and 422'd, and it skipped locally for
    # want of a database, so it asserted nothing until the suite was run against
    # one.
    saved = client.post("/api/views",
                        data={"name": "One domain", "slug": slug,
                              "kind": "findings", "description": ""},
                        headers={"Referer": "http://testserver/findings?domain=identity"})
    assert saved.status_code in (200, 201), saved.text
    view = client.get(f"/api/views/{slug}").json()
    assert view["filters"].get("domain") == "identity", view["filters"]
    client.delete(f"/api/views/{slug}")


def test_the_ran_statuses_have_one_definition():
    """modules/domains.py used to carry its own copy of the three statuses that
    mean a module ran, and this test pinned the import that fixed it.

    THE IMPORT HAS SINCE MOVED — `look_verdict` owns the question now, and
    domains.py asks it rather than answering it — so the assertion is written
    against the property instead: exactly one function reads the tuple, and the
    tuple says what it always said.
    """
    import ast

    from modules import coverage

    assert coverage.RAN_STATUSES == ("complete", "degraded", "no_file_inputs")

    readers = set()
    for path in sorted((ROOT / "modules").glob("*.py")) + \
            sorted((ROOT / "server").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) and node.id == "RAN_STATUSES":
                readers.add(path.name)
    assert readers == {"coverage.py"}, (
        f"the ran-status tuple is read outside the one function that owns it: "
        f"{sorted(readers)}")


def test_merging_manifests_takes_the_best_status_per_module():
    """A union across systems: a module counts as having run if it ran for ANY
    system in scope, because a finding from any of them can land in the domain.
    The opposite rule tells a customer they forgot an export they did send."""
    from modules.coverage import merge_manifests

    merged = merge_manifests([
        {"modules": {"log_review": {"status": "skipped"},
                     "user_auth_audit": {"status": "complete"}}},
        {"modules": {"log_review": {"status": "degraded"}}},
    ])
    assert merged["modules"]["log_review"]["status"] == "degraded"
    assert merged["modules"]["user_auth_audit"]["status"] == "complete"


def test_merging_nothing_returns_nothing_rather_than_an_empty_manifest():
    """An empty manifest says "no module ran", which over an empty sequence is a
    claim nobody checked. None says "we do not know", and the roll-up declines to
    report NOT_SUPPLIED on it."""
    from modules.coverage import merge_manifests

    assert merge_manifests([]) is None
    assert merge_manifests([{}, {"modules": "not a dict"}]) is None


def test_the_compiled_clause_has_one_parameter_per_placeholder():
    """No database needed, and it catches the classic composition bug: a clause
    whose params drift out of step with its placeholders does not fail loudly —
    it silently filters by the WRONG VALUES, because every later predicate in the
    statement reads one slot along."""
    from server.queries import _domain_clause
    for domain in domains.DOMAINS:
        where: list = []
        params: list = []
        _domain_clause(where, params, domain["id"])
        assert len(where) == 1, domain["id"]
        assert where[0].count("%s") == len(params), domain["id"]


def test_a_domain_with_no_terms_selects_nothing_rather_than_everything():
    """A filter that cannot be expressed must not quietly become no filter."""
    from server.queries import _domain_clause
    where: list = []
    params: list = []
    _domain_clause(where, params, "exploit")
    assert where == ["false"]
    assert params == []


@pg
def test_a_manifest_never_spans_a_landscape_its_findings_do_not(client):
    """A CALLER THAT NARROWS ONE SIDE MUST NARROW BOTH.

    /api/crq/fair-cam pairs `findings_for_crq(scope, landscape_id)` — one
    landscape — with `latest_coverage`. Without the landscape the manifest was a
    union over every landscape the reader could see, so a module that ran in
    landscape B counted as having looked at landscape A: a control function fed
    only by an export A never supplied reported CLEAR on the strength of a scan
    of a different estate.
    """
    from server import db, queries

    landscapes = db.query("SELECT id FROM landscape ORDER BY id")
    if len(landscapes) < 2:
        pytest.skip("needs two landscapes to tell the union from the narrowing")
    everything = queries.latest_coverage(None)
    first = queries.latest_coverage(None, landscapes[0]["id"])
    if everything is None:
        pytest.skip("no complete run to narrow")
    # Narrowing can only ever see the same modules or fewer, never more.
    assert first is None or set(first["modules"]) <= set(everything["modules"])


def test_the_fair_cam_route_narrows_both_sides_by_the_same_landscape():
    """The wiring, not the query. A landscape-aware helper nobody passes a
    landscape to is the shape of the defect it replaces."""
    source = (ROOT / "server" / "app.py").read_text(encoding="utf-8")
    block = source[source.index("def api_crq_controls("):]
    block = block[:block.index("@app.get", 10)]
    assert "findings_for_crq(scope, landscape_id)" in block
    assert "latest_coverage(scope, landscape_id)" in block


@pg
def test_an_unknown_state_is_refused_rather_than_hiding_the_corpus(client):
    """`?state=OPEN` — the obvious guess, and what a shell script produces from
    an uppercase constant — used to return HTTP 200 with the ENTIRE corpus
    hidden. The `state` filter replaces the default resolved/false-positive
    guard, so a value matching nothing hides everything, and an empty list is
    indistinguishable from a clean estate."""
    r = client.get("/api/findings", params={"state": "OPEN"})
    assert r.status_code == 400
    assert "no such state" in r.json()["detail"]
    # And the real one still works, in the spelling the schema uses.
    assert client.get("/api/findings", params={"state": "open"}).status_code == 200


def test_the_legal_states_match_the_schemas_own_constraint():
    """One spelling of the state vocabulary. A list here that drifts from
    schema.sql would refuse a state the database happily stores."""
    import re

    from server.queries import FINDING_STATES

    schema = (ROOT / "server" / "schema.sql").read_text(encoding="utf-8")
    block = schema[schema.index("CHECK (state IN ("):]
    block = block[:block.index("))") + 2]
    assert set(re.findall(r"'([a-z_]+)'", block)) == set(FINDING_STATES)
