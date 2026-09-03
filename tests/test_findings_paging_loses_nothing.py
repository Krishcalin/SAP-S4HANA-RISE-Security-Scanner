"""Paging must serve every finding exactly once.

FOUND BY LOOKING, NOT BY TESTING. Driving the console against a real 397-finding
estate, the findings list reported `total: 397` across 8 pages and served 397
rows -- of which 27 were duplicates. 27 findings, one of them a HIGH
(`PARAM-LOGIN/MIN_PASSWORD_LNG`), appeared on no page at all. Both numbers on the
screen were correct and the list was still wrong, which is why `total` is not
evidence that paging works.

THE CAUSE was `ORDER BY tier, severity, first_seen_at LIMIT/OFFSET`. Every
finding an ingest creates carries the same `first_seen_at`, so those three keys
tie across essentially the whole estate, and SQL leaves the order of tied rows
unspecified -- Postgres may answer page 2 in a different order than it answered
page 1. A row then lands on both pages and another lands on neither.

`rank_key` had the unique tiebreak all along, and its comment claimed it was
"the same tiebreak list_findings uses". That belief is what let this sit: the
top-risks path was ordered and the paginated path only looked like it was.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

pg = pytest.mark.skipif(not os.getenv("DB_DSN"),
                        reason="set DB_DSN to a PostgreSQL 16 instance")


# --------------------------------------------------------------------------- #
#  Structural: the ORDER BY has to end somewhere unique                       #
# --------------------------------------------------------------------------- #

def test_the_paginated_order_by_ends_in_a_unique_column():
    """The one assertion that cannot be satisfied by luck.

    A behavioural paging test only fails when the planner actually reorders the
    tied rows, and whether it does depends on volume and on the plan it picks
    per OFFSET. This says the thing that has to be true regardless: LIMIT/OFFSET
    over a total order needs that order to be total.
    """
    src = (ROOT / "server" / "queries.py").read_text(encoding="utf-8")
    body = src[src.index("def list_findings"):]
    body = body[:body.index("LIMIT %s OFFSET %s")]
    # Strip SQL comments FIRST. The comment explaining this very clause says the
    # words "ORDER BY", so locating the clause before removing the prose finds
    # the sentence about it instead of the clause itself.
    body = "\n".join(re.sub(r"--.*$", "", line) for line in body.splitlines())
    last = [k.strip() for k in body[body.rindex("ORDER BY"):].split(",")
            if k.strip()][-1]
    assert last == "f.id", (
        "list_findings pages with LIMIT/OFFSET, so its ORDER BY must end in a "
        "unique column or tied rows are served twice and skipped once. "
        "Last key is %r." % last)


# --------------------------------------------------------------------------- #
#  Behavioural: page through rows that tie on every other key                 #
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def database():
    from server import db
    db.init_schema()
    yield db
    db.close_pool()


@pytest.fixture()
def tied_estate(database):
    """More than two pages of findings identical on every pre-id sort key.

    Same tier, same severity, same `first_seen_at` -- which is not contrived:
    it is what one ingest produces, and it was the real shape of the estate
    where this was found.
    """
    from server import queries

    landscape = database.one(
        "INSERT INTO landscape (name, deployment_mode) "
        "VALUES (%s,'rise_pce') RETURNING id",
        ("paging-%s" % os.urandom(6).hex(),))["id"]
    system = database.one(
        "INSERT INTO sap_system (landscape_id, sid, client, tier) "
        "VALUES (%s,'PRD','100','prod') RETURNING id", (landscape,))["id"]

    check = database.one("SELECT check_id FROM check_definition LIMIT 1")
    if check is None:
        pytest.skip("no check_definition rows: run an ingest first")

    count = queries.PAGE_SIZE * 2 + 7          # three pages, last one partial
    ids = set()
    for _ in range(count):
        ids.add(database.one(
            "INSERT INTO finding (landscape_id, system_id, fingerprint, "
            "                     check_id, severity, priority_tier, state, "
            "                     first_seen_at) "
            "VALUES (%s,%s,%s,%s,'HIGH','P1','open', "
            "        TIMESTAMPTZ '2026-01-01 00:00:00+00') RETURNING id",
            (landscape, system, os.urandom(16).hex(), check["check_id"]))["id"])
    assert len(ids) == count

    yield {"landscape": landscape, "ids": ids, "count": count}
    database.execute("DELETE FROM landscape WHERE id = %s", (landscape,))


@pg
def test_every_finding_is_served_exactly_once_across_the_pages(tied_estate):
    from server import queries

    scope = None
    seen: list = []
    first = queries.list_findings(scope, domain=None, page=1)
    # Restrict to the estate this test made; other rows may share the database.
    mine = tied_estate["ids"]

    pages = max(1, (first["total"] + queries.PAGE_SIZE - 1) // queries.PAGE_SIZE)
    for page in range(1, pages + 1):
        body = queries.list_findings(scope, page=page)
        seen.extend(f["id"] for f in body["findings"] if f["id"] in mine)

    duplicates = len(seen) - len(set(seen))
    missing = mine - set(seen)
    assert duplicates == 0, (
        "%d finding(s) were served on more than one page -- tied rows reordering "
        "between LIMIT/OFFSET queries" % duplicates)
    assert not missing, (
        "%d finding(s) appear on no page at all and are unreachable through the "
        "list, though `total` counts them" % len(missing))


@pg
def test_the_total_counts_what_the_pages_can_actually_reach(tied_estate):
    """`total` and the pages have to agree about the same rows.

    The defect version satisfied this for the count and failed it for the set,
    which is exactly why the count was not enough to notice.
    """
    from server import queries

    reachable = set()
    body = queries.list_findings(None, page=1)
    pages = max(1, (body["total"] + queries.PAGE_SIZE - 1) // queries.PAGE_SIZE)
    for page in range(1, pages + 1):
        reachable.update(f["id"] for f in
                         queries.list_findings(None, page=page)["findings"])
    assert tied_estate["ids"] <= reachable, (
        "%d of the %d findings this test created are counted by `total` but "
        "cannot be reached by paging"
        % (len(tied_estate["ids"] - reachable), tied_estate["count"]))


@pg
def test_paging_is_repeatable(tied_estate):
    """The same page twice is the same page.

    A reader who sorts, reads page 2, then comes back to page 2 must not be
    shown a different set of rows.
    """
    from server import queries
    a = [f["id"] for f in queries.list_findings(None, page=2)["findings"]]
    b = [f["id"] for f in queries.list_findings(None, page=2)["findings"]]
    assert a == b, "page 2 answered differently when asked twice"
