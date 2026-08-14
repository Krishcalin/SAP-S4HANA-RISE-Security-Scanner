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

    # Scan a bundle with the profile-parameter export removed. It is the ONLY
    # input of baseline_params, security_params and snc_posture, so all three
    # come back `skipped` — the module could not look at all, which is the case
    # this test is about. (Removing an export that a module shares with others
    # leaves it `degraded`; see the note on the assertion below.)
    partial = tmp_path / "partial"
    shutil.copytree(SAMPLE, partial)
    for name in ("security_params.csv", "rsparam.csv", "profile_params.csv"):
        target = partial / name
        if target.exists():
            target.unlink()
    result = _scan(database, landscape, system, partial)

    # THIS ASSERTION WAS INVERTED, AND IT ENCODED THE DEFECT.
    #
    # It used to require `resolved > 0` for a bundle with users.csv REMOVED. But
    # deleting an export does not remediate anything: `user_auth_audit` had no
    # input, did not run, and the findings it can no longer see are unobserved
    # rather than fixed. Marking them resolved wrote a remediation that never
    # happened into MTTR, the burndown and the attack-path closure counts.
    #
    # A run may only resolve what it could have observed. Those findings now stay
    # open and are counted separately, and the row count still proves nothing was
    # deleted — which is what this test was always really about.
    assert result["diff"]["unexamined"] > 0, (
        "removing an export resolved its findings; that is a remediation that "
        "never happened")
    after = database.one(
        "SELECT count(*) AS n FROM finding WHERE landscape_id = %s", (landscape,))["n"]
    assert after >= before, "findings were DELETED rather than resolved; history is lost"

    still_open = database.one(
        "SELECT count(*) AS n FROM finding f JOIN check_definition cd "
        "ON cd.check_id = f.check_id WHERE f.landscape_id = %s "
        "AND cd.category = %s AND f.state NOT IN ('resolved','false_positive')",
        (landscape, "Security Baseline Parameters"))["n"]
    assert still_open > 0, "findings from the module that could not run were closed"


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_the_rule_is_not_a_blanket_freeze(database, landscape, system, tmp_path):
    """WITHHOLDING MUST STAY NARROW.

    A rule that withheld every resolution would freeze the backlog open for ever
    and quietly delete the mitigation journey the product is sold on — a worse
    defect than the one it fixes, and a much quieter one. Removing one module's
    only input must leave every OTHER module's resolutions working.
    """
    _scan(database, landscape, system)
    partial = tmp_path / "partial2"
    shutil.copytree(SAMPLE, partial)
    for name in ("security_params.csv", "rsparam.csv", "profile_params.csv",
                 "client_settings.csv"):
        target = partial / name
        if target.exists():
            target.unlink()
    result = _scan(database, landscape, system, partial)
    assert result["diff"]["resolved"] > 0, (
        "no finding resolved at all; the withholding rule has become a freeze")


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_a_finding_a_running_module_stops_seeing_is_still_resolved(database, landscape,
                                                                   system):
    """The other half, and the half that must not regress.

    Withholding resolution when a module did not run must not become withholding
    it always — that would freeze every finding open for ever and quietly delete
    the mitigation journey the product is sold on. With a manifest saying the
    module DID run, a finding it no longer reports is resolved exactly as before.
    """
    from server import db, ingest
    finding = {"check_id": "USR-001", "title": "t", "severity": "HIGH",
               "category": "User & Authorization", "description": "d",
               "affected_items": [], "subject": [{"type": "user", "name": "BOB"}]}
    ran = {"modules": {"user_auth_audit": {"status": "complete"}}}
    with db.connection() as conn:
        r1 = conn.execute(
            "INSERT INTO scan_run (landscape_id, system_id, status) "
            "VALUES (%s,%s,'complete') RETURNING id", (landscape, system)).fetchone()["id"]
        ingest.store_run(conn, r1, landscape, system, [finding], "PRD", "100",
                         coverage=ran)
        r2 = conn.execute(
            "INSERT INTO scan_run (landscape_id, system_id, status) "
            "VALUES (%s,%s,'complete') RETURNING id", (landscape, system)).fetchone()["id"]
        d2 = ingest.store_run(conn, r2, landscape, system, [], "PRD", "100",
                              coverage=ran)
        conn.commit()
    assert len(d2.resolved) == 1
    assert d2.unexamined == []


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_without_a_manifest_resolution_behaves_exactly_as_before(database, landscape,
                                                                 system):
    """We do not withhold a resolution on a suspicion. No manifest means nobody
    checked which modules ran, and a caller that passes none keeps the old
    behaviour rather than acquiring a new claim."""
    from server import db, ingest
    finding = {"check_id": "USR-002", "title": "t", "severity": "HIGH",
               "category": "User & Authorization", "description": "d",
               "affected_items": [], "subject": [{"type": "user", "name": "ANN"}]}
    with db.connection() as conn:
        r1 = conn.execute(
            "INSERT INTO scan_run (landscape_id, system_id, status) "
            "VALUES (%s,%s,'complete') RETURNING id", (landscape, system)).fetchone()["id"]
        ingest.store_run(conn, r1, landscape, system, [finding], "PRD", "100")
        r2 = conn.execute(
            "INSERT INTO scan_run (landscape_id, system_id, status) "
            "VALUES (%s,%s,'complete') RETURNING id", (landscape, system)).fetchone()["id"]
        d2 = ingest.store_run(conn, r2, landscape, system, [], "PRD", "100")
        conn.commit()
    assert len(d2.resolved) == 1
    assert d2.unexamined == []


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


# --------------------------------------------------------------------------- #
#  An upload with no system attached                                          #
# --------------------------------------------------------------------------- #

def _store(database, landscape, findings, system_id=None):
    """One run through store_run, bypassing the scanner so the findings are
    exactly what the test says they are."""
    from server import ingest
    run = database.one(
        "INSERT INTO scan_run (landscape_id, system_id, status) "
        "VALUES (%s,%s,'complete') RETURNING id", (landscape, system_id))
    with database.connection() as conn:
        diff = ingest.store_run(conn, run["id"], landscape, system_id, findings)
        conn.commit()
    return diff


CALM_FINDING = [{"check_id": "CALM-001", "severity": "HIGH", "title": "t",
                 "scope": "object",
                 "affected_objects": [{"type": "config_store",
                                       "name": "ABAP_INSTANCE_PAHI"}]}]
BTP_FINDING = [{"check_id": "BTP-DST-001", "severity": "HIGH", "title": "t",
                "scope": "object",
                "affected_objects": [{"type": "btp_user", "name": "a@b.com"}]}]


def test_an_unscoped_upload_cannot_resolve_another_platforms_findings(
        database, landscape):
    """The defect: `system_id IS NOT DISTINCT FROM NULL` matches EVERY system-less
    finding in the landscape, whatever produced it.

    Before the guard, this exact sequence produced a remediation that never
    happened followed by a re-breakage that never happened: the BTP upload marked
    the Cloud ALM finding resolved, and the next Cloud ALM upload reported it as a
    regression. Both are written into the mitigation journey the product is sold
    on, and both are fiction.

    `system_id` is optional on /api/upload, so this is reachable without doing
    anything unusual.
    """
    first = _store(database, landscape, CALM_FINDING)
    assert len(first.new) == 1
    assert first.resolution_skipped, "an unscoped run must say it resolved nothing"

    other_platform = _store(database, landscape, BTP_FINDING)
    assert len(other_platform.new) == 1
    assert other_platform.resolved == [], \
        "a BTP upload resolved another platform's findings"

    again = _store(database, landscape, CALM_FINDING)
    assert len(again.persisting) == 1
    assert again.resolved == []
    assert again.regressed == [], "a finding regressed that was never resolved"

    states = {r["check_id"]: r for r in database.query(
        "SELECT check_id, state, regression_count FROM finding "
        "WHERE landscape_id = %s", (landscape,))}
    assert states["CALM-001"]["state"] == "open"
    assert states["BTP-DST-001"]["state"] == "open"
    assert states["CALM-001"]["regression_count"] == 0


def test_a_scoped_upload_still_resolves_normally(database, landscape, system):
    """The guard must not cost the behaviour it protects. With a system attached,
    a finding that stops being observed is still resolved — that is the whole
    definition of resolved in this product."""
    first = _store(database, landscape, CALM_FINDING, system_id=system)
    assert len(first.new) == 1
    assert first.resolution_skipped is None

    gone = _store(database, landscape, [], system_id=system)
    assert len(gone.resolved) == 1, "a scoped run stopped resolving"

    row = database.one("SELECT state FROM finding WHERE landscape_id = %s",
                       (landscape,))
    assert row["state"] == "resolved"


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_the_run_records_what_it_declined_to_resolve(database, landscape, system):
    """WHAT THE RUN CONCLUDED, WHICH THE FINDING ROWS CANNOT SAY.

    A finding left open because no module could observe it looks, row by row,
    exactly like one that persisted. The difference is a property of the RUN, and
    nothing recorded it — so `unexamined` reached the CLI and stopped there, and
    the console could show the corrected backlog without being able to answer
    "why did nothing close this week?".
    """
    from server import db, ingest, queries

    finding = {"check_id": "LREV-PAT-003", "title": "t", "severity": "HIGH",
               "category": "Security Audit Log Review", "description": "d",
               "affected_items": [], "subject": [{"type": "user", "name": "IVY"}]}
    ran = {"modules": {"log_review": {"status": "complete", "sources_missing": []}}}
    starved = {"modules": {"log_review": {"status": "skipped"}}}

    with db.connection() as conn:
        r1 = conn.execute(
            "INSERT INTO scan_run (landscape_id, system_id, status) "
            "VALUES (%s,%s,'complete') RETURNING id", (landscape, system)).fetchone()["id"]
        ingest.store_run(conn, r1, landscape, system, [finding], "PRD", "100",
                         coverage=ran)
        r2 = conn.execute(
            "INSERT INTO scan_run (landscape_id, system_id, status) "
            "VALUES (%s,%s,'complete') RETURNING id", (landscape, system)).fetchone()["id"]
        d2 = ingest.store_run(conn, r2, landscape, system, [], "PRD", "100",
                              coverage=starved)
        # scan_directory persists this; store_run is called directly here, so
        # write it the same way the pipeline does.
        from psycopg.types.json import Jsonb
        conn.execute("UPDATE scan_run SET diff = %s WHERE id = %s",
                     (Jsonb(d2.as_counts()), r2))
        conn.commit()

    assert len(d2.unexamined) == 1
    assert d2.as_counts()["unexamined"] == 1
    assert queries.run_diff(r2, None)["unexamined"] == 1


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_a_run_that_never_measured_it_reports_null_not_nought(database, landscape,
                                                              system):
    """A scan stored before scan_run.diff existed did not withhold nothing — it
    did not measure. Zero would tell a reader the run examined everything, which
    is the same false reassurance in a new place, so the column defaults to '{}'
    and this returns None."""
    from server import db, queries

    run = db.one("INSERT INTO scan_run (landscape_id, system_id, status) "
                 "VALUES (%s,%s,'complete') RETURNING id", (landscape, system))["id"]
    assert queries.run_diff(run, None)["unexamined"] is None


def test_the_pipeline_persists_the_diff_it_computes():
    """The wiring. A count computed, returned and never stored is the shape of
    the defect this replaces — it is what `unexamined` was for a day."""
    source = (ROOT / "server" / "ingest.py").read_text(encoding="utf-8")
    assert "diff = %s" in source
    assert "Jsonb(diff.as_counts())" in source


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_an_unscoped_run_does_not_rewrite_another_findings_identity(database,
                                                                    landscape):
    """THE IRREVERSIBLE HALF OF A GUARD THAT ONLY REFUSED THE RECOVERABLE ONE.

    `system_id` is optional on /api/upload, and every query here scopes with
    `system_id IS NOT DISTINCT FROM %s` — which, for NULL, matches every OTHER
    system-less finding in the landscape. The resolution sweep has always refused
    to act on that basis. `_rebase` did not: it ran 130 lines earlier and
    rewrote finding IDENTITY over the same over-broad pool, so an unscoped upload
    could adopt an unrelated finding's row — same landscape, same check id, same
    basis, no system to tell them apart.

    A resolution is undone by the next scan observing the finding again. A
    rewritten fingerprint is not: the row now claims to be a different finding
    and nothing records what it was.
    """
    from server import db, ingest

    first = {"check_id": "USR-090", "title": "t", "severity": "HIGH",
             "category": "User & Authorization", "description": "d",
             "affected_items": [], "subject": [{"type": "user", "name": "ALPHA"}]}
    second = dict(first, subject=[{"type": "user", "name": "BETA"}])

    with db.connection() as conn:
        r1 = conn.execute(
            "INSERT INTO scan_run (landscape_id, status) "
            "VALUES (%s,'complete') RETURNING id", (landscape,)).fetchone()["id"]
        ingest.store_run(conn, r1, landscape, None, [first], "PRD", "100")
        r2 = conn.execute(
            "INSERT INTO scan_run (landscape_id, status) "
            "VALUES (%s,'complete') RETURNING id", (landscape,)).fetchone()["id"]
        diff = ingest.store_run(conn, r2, landscape, None, [second], "PRD", "100")
        conn.commit()

    # BETA is a new finding, not ALPHA wearing its name.
    assert len(diff.new) == 1, "the second finding adopted the first one's row"
    rows = database.query(
        "SELECT f.id, f.subject FROM finding f WHERE f.landscape_id = %s "
        "AND f.check_id = 'USR-090' ORDER BY f.id", (landscape,))
    assert len(rows) == 2, "one row means an identity was overwritten"
    # And the guard it was always paired with still holds.
    assert diff.resolution_skipped
    assert diff.resolved == []


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_a_scoped_run_still_rebases(database, landscape, system):
    """The control. Rebasing exists because a reworded check would otherwise
    orphan a finding's age and assignee; disabling it everywhere would be a
    worse defect than the one being fixed."""
    from server import db, ingest

    legacy = {"check_id": "USR-091", "title": "t", "severity": "HIGH",
              "category": "User & Authorization", "description": "d",
              "affected_items": [], "subject": [{"type": "user", "name": "GAMMA"}]}
    with db.connection() as conn:
        r1 = conn.execute(
            "INSERT INTO scan_run (landscape_id, system_id, status) "
            "VALUES (%s,%s,'complete') RETURNING id",
            (landscape, system)).fetchone()["id"]
        ingest.store_run(conn, r1, landscape, system, [legacy], "PRD", "100")
        conn.commit()
    before = database.one(
        "SELECT count(*) AS n FROM finding WHERE landscape_id = %s "
        "AND check_id = 'USR-091'", (landscape,))["n"]
    assert before == 1


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_a_run_that_resolved_nothing_reports_nothing_resolved(database, landscape,
                                                              system):
    """IT REPORTED THE SUM OF EVERYTHING EVER RESOLVED BEFORE IT.

    `run_diff` asked for `state='resolved' AND last_seen_run < run_id`, and the
    resolution UPDATE never touches `last_seen_run` — so every past resolution
    satisfied it for every later run. The "Resolved" tile grew monotonically for
    the life of the landscape and had nothing to do with the run on screen.
    """
    from server import db, ingest, queries

    finding = {"check_id": "USR-092", "title": "t", "severity": "HIGH",
               "category": "User & Authorization", "description": "d",
               "affected_items": [], "subject": [{"type": "user", "name": "DELTA"}]}
    ran = {"modules": {"user_auth_audit": {"status": "complete",
                                           "sources_missing": []}}}
    runs = []
    with db.connection() as conn:
        for payload in ([finding], [], []):
            run = conn.execute(
                "INSERT INTO scan_run (landscape_id, system_id, status) "
                "VALUES (%s,%s,'complete') RETURNING id",
                (landscape, system)).fetchone()["id"]
            ingest.store_run(conn, run, landscape, system, payload, "PRD", "100",
                             coverage=ran)
            runs.append(run)
        conn.commit()

    _first, resolving, quiet = runs
    assert queries.run_diff(resolving, None)["resolved"] == 1
    assert queries.run_diff(quiet, None)["resolved"] == 0, \
        "a run that resolved nothing inherited the previous run's resolution"
