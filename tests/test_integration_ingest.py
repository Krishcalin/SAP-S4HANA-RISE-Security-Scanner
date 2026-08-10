# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
End-to-end ingest tests against a real PostgreSQL.

WHY THESE MUST HIT A REAL DATABASE
-----------------------------------
The mitigation journey is implemented in SQL — upserts, a state machine, and the
"resolved means absent from the latest run" rule. A mocked database proves the
Python is self-consistent and proves nothing about whether the journey works.
Every claim in docs/PIVOT_PLAN.md Phase 1 is a claim about stored state.

Run with:
    DB_DSN=postgresql://sapsec:sapsec@localhost:55433/sapsec \
    SESSION_SECRET=$(python -c "import secrets;print(secrets.token_urlsafe(48))") \
    python -m pytest tests/test_integration_ingest.py -q

Without DB_DSN these SKIP. That is acceptable here and almost nowhere else,
because CI supplies the database — a suite that silently skips its only real
verification is worse than one that does not exist.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

pytestmark = pytest.mark.skipif(
    not os.getenv("DB_DSN"),
    reason="set DB_DSN to a PostgreSQL 16 instance (see this module's docstring)")

SAMPLE = ROOT / "sample_data"


@pytest.fixture(scope="module")
def database():
    from server import db
    db.init_schema()
    yield db
    db.close_pool()


@pytest.fixture()
def landscape(database):
    """A clean landscape per test. Cascades wipe every dependent row, so tests
    cannot leak state into each other through the finding table."""
    row = database.one(
        "INSERT INTO landscape (name, deployment_mode) VALUES (%s,'on_prem') RETURNING id",
        (f"test-{os.urandom(6).hex()}",))
    yield row["id"]
    database.execute("DELETE FROM landscape WHERE id = %s", (row["id"],))


@pytest.fixture()
def system(database, landscape):
    row = database.one(
        "INSERT INTO sap_system (landscape_id, sid, client, tier) "
        "VALUES (%s,'PRD','100','prod') RETURNING id", (landscape,))
    return row["id"]


def _scan(database, landscape, system_id, data_dir=SAMPLE):
    from server import ingest
    run = database.one(
        "INSERT INTO scan_run (landscape_id, system_id, status) "
        "VALUES (%s,%s,'pending') RETURNING id", (landscape, system_id))
    return ingest.scan_directory(Path(data_dir), landscape, system_id, run["id"],
                                 default_sid="PRD", default_client="100")


# --------------------------------------------------------------------------- #

@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_first_scan_stores_findings_and_coverage(database, landscape, system):
    result = _scan(database, landscape, system)

    assert result["findings"] > 0
    assert result["diff"]["new"] > 0
    assert result["diff"]["persisting"] == 0
    assert result["diff"]["resolved"] == 0

    stored = database.one(
        "SELECT count(*) AS n FROM finding WHERE landscape_id = %s", (landscape,))["n"]
    assert stored == result["diff"]["new"]

    # Coverage is recorded, not implied. A partial upload must be visibly partial.
    cov = database.one("SELECT coverage FROM scan_run WHERE id = %s",
                       (result["run_id"],))["coverage"]
    assert cov["counts"]["sources_known"] > 100
    assert cov["counts"]["sources_supplied"] > 0
    assert cov["summary"]

    # Every check_id got a catalogue row: check_id is a foreign key now, not an
    # identity, which is what resolves the within-run collisions.
    defs = database.one("SELECT count(*) AS n FROM check_definition")["n"]
    assert defs > 0


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_rescanning_the_same_bundle_reports_nothing_new(database, landscape, system):
    """THE PHASE 1 EXIT CRITERION.

    Upload the same bundle twice; every finding matches itself. If this fails,
    the mitigation journey is not merely inaccurate — it is unusable, because
    every re-upload would report the entire estate as newly broken.
    """
    first = _scan(database, landscape, system)
    second = _scan(database, landscape, system)

    assert second["diff"]["new"] == 0, (
        f"a re-upload of identical data invented {second['diff']['new']} new findings")
    assert second["diff"]["resolved"] == 0, (
        f"a re-upload of identical data resolved {second['diff']['resolved']} findings "
        "that are still present")
    assert second["diff"]["persisting"] == first["diff"]["new"]

    total = database.one(
        "SELECT count(*) AS n FROM finding WHERE landscape_id = %s", (landscape,))["n"]
    assert total == first["diff"]["new"], "the second run duplicated finding rows"

    # Two observations per finding, one per run: the durable defect and the
    # per-run sighting are separate, which is what makes the journey computable.
    obs = database.one(
        "SELECT count(*) AS n FROM finding_observation o JOIN finding f ON f.id = o.finding_id "
        "WHERE f.landscape_id = %s", (landscape,))["n"]
    assert obs == total * 2


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_a_finding_that_disappears_is_resolved_not_deleted(database, landscape, system,
                                                           tmp_path):
    """Resolution is the ABSENCE of an observation, never a row deletion — that is
    what lets a regression re-open the same row with its history intact."""
    _scan(database, landscape, system)
    before = database.one(
        "SELECT count(*) AS n FROM finding WHERE landscape_id = %s", (landscape,))["n"]

    # Scan a bundle with one export removed: its findings should resolve.
    partial = tmp_path / "partial"
    shutil.copytree(SAMPLE, partial)
    (partial / "users.csv").unlink()
    result = _scan(database, landscape, system, partial)

    assert result["diff"]["resolved"] > 0
    after = database.one(
        "SELECT count(*) AS n FROM finding WHERE landscape_id = %s", (landscape,))["n"]
    assert after >= before, "findings were DELETED rather than resolved; history is lost"

    resolved = database.one(
        "SELECT count(*) AS n FROM finding WHERE landscape_id = %s AND state = 'resolved'",
        (landscape,))["n"]
    assert resolved == result["diff"]["resolved"]


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_a_returning_finding_regresses_rather_than_duplicating(database, landscape,
                                                               system, tmp_path):
    """The row must be re-opened, its age preserved and its regression counted —
    not raised as a brand-new finding with a fresh age."""
    _scan(database, landscape, system)

    partial = tmp_path / "partial"
    shutil.copytree(SAMPLE, partial)
    (partial / "users.csv").unlink()
    _scan(database, landscape, system, partial)          # findings resolve

    third = _scan(database, landscape, system)           # the data comes back

    assert third["diff"]["regressed"] > 0, "returning findings were not detected"
    assert third["diff"]["new"] == 0, (
        "a returning finding was raised as NEW — its history and age were lost")

    row = database.one(
        "SELECT regression_count, first_seen_at, resolved_at FROM finding "
        "WHERE landscape_id = %s AND regression_count > 0 LIMIT 1", (landscape,))
    assert row["regression_count"] >= 1
    assert row["resolved_at"] is None, "a re-opened finding still looks resolved"

    trans = database.one(
        "SELECT count(*) AS n FROM finding_transition t JOIN finding f ON f.id = t.finding_id "
        "WHERE f.landscape_id = %s AND t.to_state = 'open' AND t.from_state = 'resolved'",
        (landscape,))["n"]
    assert trans > 0, "the regression left no audit trail"


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_graph_nodes_are_materialised(database, landscape, system):
    result = _scan(database, landscape, system)
    nodes = database.one(
        "SELECT count(*) AS n FROM graph_node WHERE landscape_id = %s", (landscape,))["n"]
    assert nodes == result["nodes"]
    # Nodes only exist where a module emits structured objects; assert the plumbing
    # rather than a count that changes as modules are converted.
    assert nodes >= 0


def test_a_module_that_raises_does_not_lose_the_other_modules(database, landscape,
                                                              system, monkeypatch):
    """Degrade, never drop. Losing 22 modules because the 23rd hit a bad row would
    be a far worse outcome than an incomplete run that says it is incomplete."""
    from server import ingest

    real_import = ingest.importlib.import_module

    def exploding(name, *a, **k):
        if name.endswith("user_auth_audit"):
            raise RuntimeError("simulated module failure")
        return real_import(name, *a, **k)

    monkeypatch.setattr(ingest.importlib, "import_module", exploding)
    result = _scan(database, landscape, system)

    assert result["findings"] > 0, "one failing module emptied the whole run"
    status = result["module_status"]["user_auth_audit"]
    assert status["status"] == "failed"
    assert "simulated module failure" in status["error"]
    # The detail must be recoverable: "a failing asset yields no error detail in the
    # console or the backend log" is a documented complaint about the incumbent.
    assert status["traceback"]


def test_converting_a_module_preserves_finding_history(database, landscape, system):
    """Regression test for a defect caught in a live run.

    A module was converted from display-string identity to structured-object
    identity between two scans of a BYTE-IDENTICAL bundle, and its finding churned
    new+resolved. In production that would mean a customer tracking a defect for
    six months loses its age, assignee, risk acceptance and history the day we ship
    an improvement to that check.
    """
    from server import ingest

    database.execute("INSERT INTO check_definition (check_id, title) VALUES ('REB-1','t') "
                     "ON CONFLICT (check_id) DO NOTHING")
    run1 = database.one("INSERT INTO scan_run (landscape_id, system_id, status) "
                        "VALUES (%s,%s,'complete') RETURNING id", (landscape, system))["id"]
    run2 = database.one("INSERT INTO scan_run (landscape_id, system_id, status) "
                        "VALUES (%s,%s,'complete') RETURNING id", (landscape, system))["id"]

    # Run 1: unconverted module — identity from the display string.
    legacy = {"check_id": "REB-1", "severity": "HIGH",
              "affected_items": ["DEST_A -> BASIC_AUTH"]}
    with database.connection() as conn:
        d1 = ingest.store_run(conn, run1, landscape, system, [legacy], "PRD", "100")
        conn.commit()
    assert d1.as_counts()["new"] == 1
    before = database.one(
        "SELECT id, first_seen_at, fingerprint_basis FROM finding "
        "WHERE landscape_id = %s AND check_id = 'REB-1'", (landscape,))
    assert before["fingerprint_basis"] == "display"

    # A human works the finding: this is the history that must survive.
    database.execute("UPDATE finding SET assignee = 'basis-team' WHERE id = %s",
                     (before["id"],))

    # Run 2: the SAME defect from the converted module — structured identity.
    converted = {"check_id": "REB-1", "severity": "HIGH",
                 "affected_items": ["DEST_A -> BASIC_AUTH"],
                 "affected_objects": [{"type": "destination", "name": "DEST_A",
                                       "qualifier": "auth=BASIC"}],
                 "scope": "object"}
    with database.connection() as conn:
        d2 = ingest.store_run(conn, run2, landscape, system, [converted], "PRD", "100")
        conn.commit()

    counts = d2.as_counts()
    assert counts["new"] == 0, "the converted finding was raised as new; history lost"
    assert counts["resolved"] == 0, "the pre-conversion row was resolved; history lost"
    assert counts["persisting"] == 1

    after = database.one("SELECT * FROM finding WHERE id = %s", (before["id"],))
    assert after is not None, "the original row was deleted"
    assert after["fingerprint_basis"] == "objects", "the identity did not rebase"
    assert after["assignee"] == "basis-team", "human-entered state was lost"
    assert after["first_seen_at"] == before["first_seen_at"], "the finding's age reset"

    trail = database.query(
        "SELECT reason FROM finding_transition WHERE finding_id = %s", (before["id"],))
    assert any("rebased" in (t["reason"] or "") for t in trail), \
        "an identity rebase must leave an audit trail"


def test_rebasing_refuses_when_it_would_have_to_guess(database, landscape, system):
    """If several open findings for a check could be the match, attaching one
    defect's history to another is worse than losing it. Do nothing instead."""
    from server import ingest

    database.execute("INSERT INTO check_definition (check_id, title) VALUES ('REB-2','t') "
                     "ON CONFLICT (check_id) DO NOTHING")
    r1 = database.one("INSERT INTO scan_run (landscape_id, system_id, status) "
                      "VALUES (%s,%s,'complete') RETURNING id", (landscape, system))["id"]
    r2 = database.one("INSERT INTO scan_run (landscape_id, system_id, status) "
                      "VALUES (%s,%s,'complete') RETURNING id", (landscape, system))["id"]

    legacy = [{"check_id": "REB-2", "severity": "HIGH", "affected_items": [f"D{i}"]}
              for i in (1, 2)]
    with database.connection() as conn:
        ingest.store_run(conn, r1, landscape, system, legacy, "PRD", "100")
        conn.commit()

    converted = [{"check_id": "REB-2", "severity": "HIGH", "affected_items": [f"D{i}"],
                  "affected_objects": [{"type": "destination", "name": f"D{i}"}],
                  "scope": "object"} for i in (1, 2)]
    with database.connection() as conn:
        d = ingest.store_run(conn, r2, landscape, system, converted, "PRD", "100")
        conn.commit()

    # Ambiguous: two candidates, so both are reported honestly as new rather than
    # silently mis-attributed.
    assert d.as_counts()["new"] == 2
    assert d.as_counts()["resolved"] == 2


def test_row_scoping_denies_by_default_on_an_empty_scope(database):
    """An empty explicit scope means NOTHING, not everything. Returning TRUE here
    would hand a deliberately-restricted user the entire estate."""
    from server import db
    assert db.scope_clause(None)[0] == "TRUE"
    assert db.scope_clause([])[0] == "FALSE"
    clause, params = db.scope_clause([1, 2])
    assert "= ANY(" in clause and params == [[1, 2]]
    with pytest.raises(ValueError):
        db.scope_clause([1], column="f.id; DROP TABLE finding--")


def test_transitions_require_a_reason_where_it_matters(database, landscape, system):
    """A dispute without a reason is noise; with one it is tuning data."""
    from server import queries
    fid = database.one(
        "INSERT INTO check_definition (check_id, title) VALUES ('T-1','t') "
        "ON CONFLICT DO NOTHING RETURNING check_id")
    database.execute("INSERT INTO check_definition (check_id, title) VALUES ('T-1','t') "
                     "ON CONFLICT (check_id) DO NOTHING")
    row = database.one(
        "INSERT INTO finding (landscape_id, system_id, fingerprint, check_id) "
        "VALUES (%s,%s,%s,'T-1') RETURNING id",
        (landscape, system, os.urandom(16).hex()))

    with pytest.raises(queries.TransitionError, match="reason is required"):
        queries.transition_finding(row["id"], "false_positive", "tester", reason="")

    with pytest.raises(queries.TransitionError, match="ticket reference is required"):
        queries.transition_finding(row["id"], "submitted_to_provider", "tester")

    with pytest.raises(queries.TransitionError, match="cannot move"):
        queries.transition_finding(row["id"], "resolved", "tester")

    out = queries.transition_finding(row["id"], "accepted", "tester",
                                     reason="compensating control in place")
    assert out["to"] == "accepted"
