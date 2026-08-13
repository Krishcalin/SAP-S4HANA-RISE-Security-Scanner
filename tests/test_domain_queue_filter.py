# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

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
