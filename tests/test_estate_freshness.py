"""
When was this answer measured?

THE DEFECT. The dashboard's systems table listed every registered system with
its platform, tier, criticality, exposure, mode and owner — and nothing about
when any of them was last looked at. Measured on the live sample estate, seven
systems rendered identically:

    PRD/100   assessed that morning
    D01/300   assessed 20 days earlier
    P01/100   assessed 20 days earlier
    T01/200   assessed 20 days earlier
    DEV/300   NEVER ASSESSED — no complete run, ever
    QAS/200   NEVER ASSESSED — no complete run, ever

and the panel above them read "Open findings across 7 systems", which is a
claim about two systems nothing has ever looked at. `coverage_for_scope` took
`DISTINCT ON (system_id) ... ORDER BY started_at DESC` and discarded the date,
so a control reported CLEAR on the strength of an export of any age.

This is the failure this codebase keeps finding, in a new place: an absence
rendering as a measurement. These tests hold the distinction that fixes it —
never assessed is not zero days old, and a date the reader cannot see is a date
that cannot be judged.

Run with:
    DB_DSN=postgresql://sapsec:sapsec@localhost:55433/sapsec \
    SESSION_SECRET=$(python -c "import secrets;print(secrets.token_urlsafe(48))") \
    python -m pytest tests/test_estate_freshness.py -q
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server import queries                                        # noqa: E402

pytestmark = pytest.mark.skipif(
    not os.getenv("DB_DSN"),
    reason="set DB_DSN to a PostgreSQL 16 instance (see this module's docstring)")


@pytest.fixture(scope="module")
def database():
    from server import db
    db.init_schema()
    yield db
    db.close_pool()


@pytest.fixture()
def landscape(database):
    row = database.one(
        "INSERT INTO landscape (name, deployment_mode) VALUES (%s,'on_prem') RETURNING id",
        (f"fresh-{os.urandom(6).hex()}",))
    yield row["id"]
    database.execute("DELETE FROM landscape WHERE id = %s", (row["id"],))


def _system(database, landscape, sid, client="100"):
    return database.one(
        "INSERT INTO sap_system (landscape_id, sid, client, tier) "
        "VALUES (%s,%s,%s,'prod') RETURNING id", (landscape, sid, client))["id"]


def _run(database, landscape, system_id, days_ago, status="complete"):
    """A run that finished `days_ago` days ago.

    `started_at` is written explicitly rather than defaulted, because the whole
    subject of this file is a date, and a fixture that could only produce
    "now" could not tell a fresh estate from a stale one.
    """
    return database.one(
        "INSERT INTO scan_run (landscape_id, system_id, status, started_at) "
        "VALUES (%s,%s,%s, now() - make_interval(days => %s)) RETURNING id",
        (landscape, system_id, status, days_ago))["id"]


def _by_label(rows):
    return {r["label"]: r for r in rows}


# ── the substrate ────────────────────────────────────────────────────────────

def test_a_system_carries_the_date_it_was_last_assessed(database, landscape):
    sid = _system(database, landscape, "PRD")
    _run(database, landscape, sid, days_ago=20)
    _run(database, landscape, sid, days_ago=3)

    row = _by_label(queries.list_systems([sid]))["PRD/100"]
    assert row["days_since_assessed"] == 3, "not the most recent assessment"
    assert row["assessed_runs"] == 2
    assert row["last_assessed"] is not None


def test_a_system_nothing_has_ever_scanned_says_so_rather_than_nothing(
        database, landscape):
    """The case the whole feature exists for.

    `None` must survive to the reader. Rendering it as 0, or as an empty cell
    beside six populated ones, puts a system nobody has ever looked at in the
    same visual class as one assessed this morning.
    """
    sid = _system(database, landscape, "DEV", "300")
    row = _by_label(queries.list_systems([sid]))["DEV/300"]
    assert row["last_assessed"] is None
    assert row["days_since_assessed"] is None, \
        "never assessed is being reported as an age, which reads as recent"
    assert row["assessed_runs"] == 0


def test_a_run_that_did_not_finish_is_not_an_assessment(database, landscape):
    """A failed run tells you the scanner stopped. It tells you nothing about
    the system, so it must not refresh the date."""
    sid = _system(database, landscape, "QAS", "200")
    _run(database, landscape, sid, days_ago=40, status="complete")
    # Every non-complete state the schema allows, so a status added later
    # cannot quietly start counting as an assessment.
    for status in ("pending", "parsing", "scanning", "deriving", "failed",
                   "cancelled"):
        _run(database, landscape, sid, days_ago=0, status=status)

    row = _by_label(queries.list_systems([sid]))["QAS/200"]
    assert row["days_since_assessed"] == 40, \
        "an unfinished run refreshed the assessment date"
    assert row["assessed_runs"] == 1


def test_the_age_is_computed_by_the_database_not_the_caller(database, landscape):
    """Two readers in different time zones must not disagree about whether the
    same system is stale, so the arithmetic happens once, server-side."""
    sid = _system(database, landscape, "T01", "200")
    _run(database, landscape, sid, days_ago=10)
    row = _by_label(queries.list_systems([sid]))["T01/200"]
    assert isinstance(row["days_since_assessed"], int)


# ── the summary the dashboard states in words ────────────────────────────────

def test_the_estate_summary_counts_current_stale_and_never(database, landscape):
    fresh = _system(database, landscape, "PRD", "100")
    stale = _system(database, landscape, "D01", "300")
    never = _system(database, landscape, "DEV", "300")
    _run(database, landscape, fresh, days_ago=2)
    _run(database, landscape, stale, days_ago=90)

    view = queries.estate_freshness([fresh, stale, never])
    assert view["systems"] == 3
    assert view["current"] == 1
    assert view["stale"] == 1
    assert view["never_assessed"] == 1
    # Named, not just counted: which system is the question the reader asks next.
    assert view["never_assessed_labels"] == ["DEV/300"]
    assert view["stale_labels"] == ["D01/300"]


def test_the_summary_names_how_old_the_oldest_answer_is(database, landscape):
    """A count of stale systems says something is old. This says how old, which
    is what decides whether it matters."""
    a = _system(database, landscape, "PRD", "100")
    b = _system(database, landscape, "D01", "300")
    _run(database, landscape, a, days_ago=5)
    _run(database, landscape, b, days_ago=200)
    assert queries.estate_freshness([a, b])["oldest_days"] == 200


def test_a_system_never_assessed_is_not_counted_as_the_oldest(
        database, landscape):
    """It has no age. Folding it into `oldest_days` as a very large number would
    be inventing a measurement, and as zero would be worse."""
    a = _system(database, landscape, "PRD", "100")
    never = _system(database, landscape, "DEV", "300")
    _run(database, landscape, a, days_ago=6)

    view = queries.estate_freshness([a, never])
    assert view["oldest_days"] == 6
    assert view["never_assessed"] == 1


def test_an_estate_nothing_has_ever_scanned_reports_no_oldest_at_all(
        database, landscape):
    never = _system(database, landscape, "DEV", "300")
    view = queries.estate_freshness([never])
    assert view["oldest_days"] is None, \
        "an estate with no measurements at all reported an age"
    assert view["current"] == 0


def test_the_threshold_moves_the_line_and_nothing_else(database, landscape):
    """It governs emphasis. The measured date is returned whatever it is set to,
    so no threshold can hide how old an answer is."""
    sid = _system(database, landscape, "PRD", "100")
    _run(database, landscape, sid, days_ago=40)

    assert queries.estate_freshness([sid], stale_after=35)["stale"] == 1
    assert queries.estate_freshness([sid], stale_after=90)["stale"] == 0
    for after in (35, 90):
        assert queries.estate_freshness([sid], stale_after=after)["oldest_days"] == 40


def test_a_system_exactly_at_the_threshold_is_not_yet_stale(database, landscape):
    """Off-by-one on a boundary that decides what a customer is told. 35 days is
    one patch cycle; the answer goes stale when it has been overtaken, not when
    it reaches the same age."""
    sid = _system(database, landscape, "PRD", "100")
    _run(database, landscape, sid, days_ago=queries.STALE_AFTER_DAYS)
    assert queries.estate_freshness([sid])["stale"] == 0
    assert queries.estate_freshness([sid])["current"] == 1


def test_the_summary_and_the_table_can_never_disagree(database, landscape):
    """The headline is built from the same rows it summarises. A headline from a
    second query is a headline that drifts from the table under it."""
    a = _system(database, landscape, "PRD", "100")
    b = _system(database, landscape, "DEV", "300")
    _run(database, landscape, a, days_ago=1)

    view = queries.estate_freshness([a, b])
    rows = queries.list_systems([a, b])
    assert view["systems"] == len(rows)
    assert view["never_assessed"] == sum(
        1 for r in rows if r["last_assessed"] is None)


def test_a_system_never_assessed_is_not_counted_as_stale_either(
        database, landscape):
    """It is neither fresh nor stale — it is unmeasured, and that is a third
    state. The obvious `days or 0` idiom files it as the freshest thing in the
    estate; the equally obvious `days > threshold` on a None crashes. Both are
    reachable from a one-word edit, so the rule is asserted rather than left to
    whichever falsy default happens to be in the expression."""
    never = _system(database, landscape, "DEV", "300")
    view = queries.estate_freshness([never], stale_after=1)
    assert view["stale"] == 0
    assert view["current"] == 0
    assert view["never_assessed"] == 1


# ── the wiring, not just the rule ────────────────────────────────────────────
#
# A query that answers correctly and reaches no screen is the shape of the
# defect this replaces: `scan_run.started_at` was recorded on every upload from
# Phase 1 and read by nothing that the dashboard rendered.

def test_the_dashboard_endpoint_serves_the_freshness_view(database):
    from fastapi.testclient import TestClient
    from server import app as appmod, auth

    username = f"freshtest_{os.urandom(4).hex()}"
    auth.create_user(username, "fresh-test-password", "admin")
    try:
        client = TestClient(appmod.app)
        assert client.post("/api/auth/login",
                           json={"username": username,
                                 "password": "fresh-test-password"}
                           ).status_code == 200
        body = client.get("/api/dashboard").json()

        assert "freshness" in body, \
            "the dashboard cannot say how current its own numbers are"
        for key in ("systems", "current", "stale", "never_assessed",
                    "stale_after_days", "oldest_days",
                    "never_assessed_labels", "stale_labels"):
            assert key in body["freshness"], key

        # And every system row carries its own date, because the summary is a
        # headline and the table under it is where a reader looks next.
        for row in body["systems"]:
            assert "last_assessed" in row
            assert "days_since_assessed" in row
            assert "assessed_runs" in row
    finally:
        database.execute("DELETE FROM app_user WHERE username = %s", (username,))
