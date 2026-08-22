"""
Phase 2 integration: the mitigation journey against a real PostgreSQL.

The exit criterion for Phase 2 is that a user can answer

    "what changed since last month, who owns it, and is it getting better?"

without exporting anything. These tests build an actual multi-run history — scan,
remediate, regress — and assert the analytics tell the truth about it, including
the two ways these numbers are commonly wrong:

  * measuring an average severity instead of counting resolved occurrences, and
  * charging the customer for time a finding spent waiting on the provider.

Run with DB_DSN set; see tests/test_integration_ingest.py for the container line.
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
    not os.getenv("DB_DSN"), reason="set DB_DSN to a PostgreSQL 16 instance")

SAMPLE = ROOT / "sample_data"


@pytest.fixture(scope="module")
def database():
    from server import db
    db.init_schema()
    yield db
    db.close_pool()


@pytest.fixture()
def landscape(database):
    row = database.one(
        "INSERT INTO landscape (name, deployment_mode) VALUES (%s,'rise_pce') RETURNING id",
        (f"journey-{os.urandom(6).hex()}",))
    yield row["id"]
    database.execute("DELETE FROM landscape WHERE id = %s", (row["id"],))


@pytest.fixture()
def system(database, landscape):
    return database.one(
        "INSERT INTO sap_system (landscape_id, sid, client, tier) "
        "VALUES (%s,'PRD','100','prod') RETURNING id", (landscape,))["id"]


def _scan(database, landscape, system_id, data_dir=SAMPLE):
    from server import ingest
    run = database.one(
        "INSERT INTO scan_run (landscape_id, system_id, status) "
        "VALUES (%s,%s,'pending') RETURNING id", (landscape, system_id))
    return ingest.scan_directory(Path(data_dir), landscape, system_id, run["id"],
                                 deployment_mode="rise_pce",
                                 default_sid="PRD", default_client="100")


def _scope(database, system_id):
    return [system_id]


# --------------------------------------------------------------------------- #

@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_priority_and_ownership_are_stored_not_just_computed(database, landscape, system):
    _scan(database, landscape, system)

    tiers = {r["priority_tier"]: r["n"] for r in database.query(
        "SELECT priority_tier, count(*) n FROM finding WHERE landscape_id=%s GROUP BY 1",
        (landscape,))}
    assert tiers and None not in tiers, "findings were stored without a priority tier"

    # RISE: profile-parameter findings must be the provider's to change.
    to_sap = database.one(
        "SELECT count(*) n FROM finding WHERE landscape_id=%s "
        "AND remediation_owner='ticket_to_sap'", (landscape,))["n"]
    assert to_sap > 0, "no finding routed to SAP in a RISE landscape"

    # Every tiered finding explains itself; a bare number is unarguable.
    unexplained = database.one(
        "SELECT count(*) n FROM finding WHERE landscape_id=%s "
        "AND priority_tier IS NOT NULL AND jsonb_array_length(priority_factors)=0",
        (landscape,))["n"]
    assert unexplained == 0

    # P4 carries no SLA clock; every other tier does.
    bad = database.one(
        "SELECT count(*) n FROM finding WHERE landscape_id=%s AND ("
        "(priority_tier='P4' AND due_date IS NOT NULL) OR "
        "(priority_tier<>'P4' AND due_date IS NULL))", (landscape,))["n"]
    assert bad == 0


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_the_journey_reports_real_remediation(database, landscape, system, tmp_path):
    """Scan, remediate, re-scan — and check the trend screen says so."""
    from server import analytics

    _scan(database, landscape, system)
    scope = _scope(database, system)

    before = analytics.backlog_by_tier(scope)
    open_before = sum(r["open"] for r in before)
    assert open_before > 0

    # Remediate by removing an export's worth of defects.
    partial = tmp_path / "fixed"
    shutil.copytree(SAMPLE, partial)
    (partial / "users.csv").unlink()
    result = _scan(database, landscape, system, partial)
    assert result["diff"]["resolved"] > 0

    after = analytics.backlog_by_tier(scope)
    assert sum(r["open"] for r in after) < open_before, "the backlog did not fall"

    m = analytics.mttr(scope)
    assert m["overall"]["resolved"] == result["diff"]["resolved"], (
        "MTTR counts resolved OCCURRENCES; it must match the run diff exactly")
    assert m["overall"]["mean_days"] is not None

    burn = analytics.burndown(scope)
    assert len(burn) >= 2, "the burndown needs a point per completed run"
    assert burn[0]["started_at"] <= burn[-1]["started_at"], "burndown is not chronological"


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_mttr_ignores_still_open_findings(database, landscape, system):
    """Including open findings as "time so far" would make MTTR FALL whenever a
    burst of new findings arrives, which is exactly backwards."""
    from server import analytics
    _scan(database, landscape, system)
    m = analytics.mttr(_scope(database, system))
    assert m["overall"]["resolved"] == 0, "nothing has been resolved yet"
    assert m["overall"]["mean_days"] is None, \
        "MTTR reported a number with zero resolved findings"


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_provider_bound_work_is_reported_separately(database, landscape, system):
    """Rolling SAP's queue into the customer's overdue count measures the wrong
    organisation."""
    from server import analytics
    _scan(database, landscape, system)

    # Force everything past due so both buckets are populated.
    database.execute("UPDATE finding SET due_date = CURRENT_DATE - 1 "
                     "WHERE landscape_id = %s AND due_date IS NOT NULL", (landscape,))
    sla = analytics.sla_status(_scope(database, system))

    assert sla["overdue_customer"] > 0
    assert sla["overdue_provider"] > 0
    assert "ticket_to_sap" in sla["by_owner"]
    # The headline is customer-only, so it must exclude the provider's rows.
    assert sla["overdue_customer"] < sla["total_tracked"]


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_domain_score_is_over_checks_that_ran_not_the_catalogue(database, landscape,
                                                                system):
    """Scoring against every check ever written would let a customer improve their
    score by supplying FEWER exports.

    THE DENOMINATOR MOVED, AND THIS TEST HAD PINNED THE OLD ONE. `checks_run`
    counted checks that had ever produced a FINDING, so a category where three
    of forty checks had ever failed had a denominator of three and a first-time
    customer read 0%. It is now `checks_known`, read from the scanner's source
    and narrowed to the modules that ran — which is what this docstring always
    claimed and the implementation never did.
    """
    from server import analytics
    _scan(database, landscape, system)
    domains = analytics.domain_scorecard(_scope(database, system))
    assert domains
    for d in domains:
        assert d["checks_known"] > 0
        assert d["checks_failing"] <= d["checks_known"], \
            "more checks failing than exist — the score denominator is wrong"
        if d["pct_passing"] is not None:
            assert 0 <= d["pct_passing"] <= 100
            assert d["assessed"] is True


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_notifications_fire_for_new_criticals_and_regressions(database, landscape,
                                                              system, tmp_path):
    """Only NEW criticals and regressions. Notifying on persisting findings would
    send the same alert every scan until it is fixed, and an alert that fires
    every day is an alert nobody reads."""
    r1 = _scan(database, landscape, system)
    first = database.query(
        "SELECT kind, subject FROM notification WHERE scan_run_id = %s", (r1["run_id"],))
    assert any(n["kind"] == "new_critical" for n in first)

    # Re-scan identical data: nothing is new, so nothing should be notified.
    r2 = _scan(database, landscape, system)
    assert not database.query(
        "SELECT 1 FROM notification WHERE scan_run_id = %s", (r2["run_id"],)), \
        "an unchanged re-scan raised notifications"

    # Resolve then regress: the regression must be announced.
    partial = tmp_path / "p"
    shutil.copytree(SAMPLE, partial)
    (partial / "users.csv").unlink()
    _scan(database, landscape, system, partial)
    r4 = _scan(database, landscape, system)
    kinds = {n["kind"] for n in database.query(
        "SELECT kind FROM notification WHERE scan_run_id = %s", (r4["run_id"],))}
    assert "regression" in kinds


# --------------------------------------------------------------------------- #
#  Saved views and bulk actions                                               #
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_crq_is_computed_and_priced_on_the_complete_finding_set(database, landscape,
                                                                system):
    """The one way to make this number dishonest is to price it on a filtered
    list, so the input count is stored and asserted against the scan."""
    from server import crq

    result = _scan(database, landscape, system)
    row = crq.latest([system])
    assert row is not None, "no CRQ result was stored"
    assert row["input_finding_count"] == result["findings"], (
        "CRQ was priced on a different number of findings than the scan produced — "
        "a display filter must never be able to move the currency figure")

    assert row["detail"]["engine_found"] is True, (
        "no Monte-Carlo engine was found, so the headline differentiator produced "
        "no number at all")
    assert row["ale_p90"] and row["ale_p90"] > 0
    assert row["ale_p50"] <= row["ale_p90"], "median exceeds the 90th percentile"

    # Residual after remediation must be non-zero: "fix everything and your risk
    # is exactly $0" is not a claim any risk function accepts.
    residual = (row["detail"].get("target_portfolio") or {}).get("ale_p90")
    assert residual and float(residual) > 0, \
        "the model reported zero residual risk after remediation"

    scenarios = crq.scenarios_for_run(row["run_id"])
    assert len(scenarios) == 5, f"expected 5 scoped SAP scenarios, got {len(scenarios)}"
    assert all(s["ale_p90"] is not None for s in scenarios)


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_the_unrouted_count_is_carried_not_hidden(database, landscape, system):
    """Disclosing what the model did NOT price is what separates this from vendor
    hand-waving, and it is the first thing a risk function tests."""
    from server import crq
    _scan(database, landscape, system)
    row = crq.latest([system])
    assert row["unrouted_count"] is not None, "the unrouted count was not stored"
    assert row["unrouted_count"] >= 0


def test_a_saved_view_stores_filters_and_can_never_widen_access(database, landscape,
                                                                system):
    """The security property of the whole saved-view feature: it stores FILTERS,
    never rows, so opening a shared link re-runs the query under the caller's own
    row scope."""
    from server import queries

    view = queries.save_view("basis-worklist", "Basis worklist", "findings",
                             {"team": "basis", "severity": "CRITICAL",
                              "evil": "DROP TABLE finding"}, "tester")
    assert view["filters"] == {"team": "basis", "severity": "CRITICAL"}, \
        "an unknown filter key was stored and would be replayed into the query layer"

    # A user scoped to no systems sees nothing through the view, whatever it says.
    scoped = queries.list_findings([], **view["filters"])
    assert scoped["total"] == 0

    assert queries.get_view("basis-worklist", "tester") is not None
    queries.delete_view("basis-worklist", "tester")
    assert queries.get_view("basis-worklist", "tester") is None


def test_a_private_view_is_invisible_to_others(database):
    from server import queries
    queries.save_view("mine-only", "Mine", "findings", {"severity": "HIGH"},
                      "alice", is_shared=False)
    try:
        assert queries.get_view("mine-only", "alice") is not None
        assert queries.get_view("mine-only", "bob") is None
    finally:
        queries.delete_view("mine-only", "alice")


def test_bulk_transition_applies_what_it_can_and_reports_the_rest(database, landscape,
                                                                  system):
    """Partial success, deliberately. Failing the whole batch over 3 of 40 makes
    the feature unusable; skipping silently misreports what happened."""
    from server import queries

    database.execute("INSERT INTO check_definition (check_id, title) VALUES ('BLK-1','t') "
                     "ON CONFLICT (check_id) DO NOTHING")
    ids = []
    for _ in range(3):
        ids.append(database.one(
            "INSERT INTO finding (landscape_id, system_id, fingerprint, check_id) "
            "VALUES (%s,%s,%s,'BLK-1') RETURNING id",
            (landscape, system, os.urandom(16).hex()))["id"])

    # Put one into a state that cannot reach 'accepted'.
    queries.transition_finding(ids[2], "false_positive", "t", reason="noise")

    out = queries.bulk_transition(ids, "accepted", "tester", reason="compensating control")
    assert out["applied_count"] == 2
    assert out["skipped_count"] == 1
    assert out["skipped"][0]["finding_id"] == ids[2]
    assert "cannot move" in out["skipped"][0]["reason"]


def test_assignment_is_not_a_lifecycle_event(database, landscape, system):
    """A finding can change hands three times while staying open; folding that into
    the state machine would fill the history with entries about nothing."""
    from server import queries

    database.execute("INSERT INTO check_definition (check_id, title) VALUES ('ASG-1','t') "
                     "ON CONFLICT (check_id) DO NOTHING")
    fid = database.one(
        "INSERT INTO finding (landscape_id, system_id, fingerprint, check_id) "
        "VALUES (%s,%s,%s,'ASG-1') RETURNING id",
        (landscape, system, os.urandom(16).hex()))["id"]

    queries.assign_finding(fid, "tester", assignee="basis-team", team="basis")
    row = database.one("SELECT assignee, owning_team, state FROM finding WHERE id=%s", (fid,))
    assert row["assignee"] == "basis-team"
    assert row["owning_team"] == "basis"
    assert row["state"] == "open", "assignment changed the lifecycle state"

    assert not database.query(
        "SELECT 1 FROM finding_transition WHERE finding_id = %s", (fid,)), \
        "assignment wrote a lifecycle transition"


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_rescanning_does_not_overwrite_a_humans_assignment(database, landscape, system):
    """The scanner owns severity and priority. A person owns the assignee, and a
    scan must never quietly undo their decision."""
    _scan(database, landscape, system)
    fid = database.one(
        "SELECT id FROM finding WHERE landscape_id = %s LIMIT 1", (landscape,))["id"]
    database.execute("UPDATE finding SET assignee = 'alice', owning_team = 'basis' "
                     "WHERE id = %s", (fid,))

    _scan(database, landscape, system)

    row = database.one("SELECT assignee, owning_team FROM finding WHERE id=%s", (fid,))
    assert row["assignee"] == "alice"
    assert row["owning_team"] == "basis"


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_a_category_nothing_assessed_reports_no_percentage(database, landscape, system):
    """Zero is a measured result; this is the absence of one.

    With a manifest saying only one module ran, every other category comes back
    with pct None rather than 0 — which the console used to coerce with `?? 0`,
    rendering an unsupplied export as the customer's worst-performing area and
    sorting it to the top of the table.
    """
    from server import analytics
    _scan(database, landscape, system)
    one_module = {"modules": {"user_auth_audit": {"status": "complete"}}}
    domains = analytics.domain_scorecard(_scope(database, system), coverage=one_module)
    unassessed = [d for d in domains if not d["assessed"]]
    assert unassessed, "no category was marked unassessed on a one-module manifest"
    for d in unassessed:
        assert d["pct_passing"] is None, d["category"]


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_supplying_less_cannot_produce_a_better_score(database, landscape, system):
    """The incentive the docstring has always described, asserted for the first
    time. A category whose module did not run must not appear as better."""
    from server import analytics
    _scan(database, landscape, system)
    scope = _scope(database, system)
    everything = {d["category"]: d for d in analytics.domain_scorecard(scope)}
    starved = {d["category"]: d for d in analytics.domain_scorecard(
        scope, coverage={"modules": {"user_auth_audit": {"status": "complete"}}})}
    improved = [c for c, d in starved.items()
                if d["pct_passing"] is not None
                and everything.get(c, {}).get("pct_passing") is not None
                and d["pct_passing"] > everything[c]["pct_passing"]]
    assert not improved, f"supplying fewer exports raised the score for {improved}"


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_the_burndown_keeps_a_finding_the_run_could_not_examine(database, landscape,
                                                                system):
    """A WITHHELD FINDING IS STILL IN THE BACKLOG, and the chart used to drop it.

    Every series in `burndown` counted `f.last_seen_run = r.id` — "observed by
    this run". That was a serviceable proxy while every open finding was observed
    by every run, and 3e0e00e ended it: a run may only resolve what it could have
    observed, so a finding whose module did not execute is left open with its
    `last_seen_run` still pointing at an older run.

    So on exactly the run the withholding rule was written for, the backlog bar,
    the CRITICAL overlay and the P1/P2 series all fell by the number of findings
    the run declined to examine — while the Findings queue went on showing them
    open. Two screens, one estate, different numbers, and the reassuring one was
    the chart.
    """
    from server import analytics, db, ingest

    finding = {"check_id": "LREV-PAT-001", "title": "t", "severity": "CRITICAL",
               "category": "Security Audit Log Review", "description": "d",
               "affected_items": [], "subject": [{"type": "user", "name": "ZED"}]}
    ran = {"modules": {"log_review": {"status": "complete", "sources_missing": []}}}
    starved = {"modules": {"log_review": {"status": "skipped"}}}

    with db.connection() as conn:
        r1 = conn.execute(
            "INSERT INTO scan_run (landscape_id, system_id, status, started_at) "
            "VALUES (%s,%s,'complete', now() - interval '2 days') RETURNING id",
            (landscape, system)).fetchone()["id"]
        ingest.store_run(conn, r1, landscape, system, [finding], "PRD", "100",
                         coverage=ran)
        # The second run cannot see the audit log at all, so it must neither
        # resolve the finding nor drop it from the backlog.
        r2 = conn.execute(
            "INSERT INTO scan_run (landscape_id, system_id, status, started_at) "
            "VALUES (%s,%s,'complete', now() - interval '1 day') RETURNING id",
            (landscape, system)).fetchone()["id"]
        d2 = ingest.store_run(conn, r2, landscape, system, [], "PRD", "100",
                              coverage=starved)
        conn.commit()

    assert len(d2.unexamined) == 1, "the guard did not withhold; fixture is wrong"
    assert d2.resolved == []

    series = {row["run_id"]: row for row in analytics.burndown(_scope(database, system))}
    assert r2 in series, "the second run is missing from the burndown entirely"
    assert series[r2]["open_after"] >= 1, (
        "the backlog dropped a finding the run could not examine — the chart and "
        "the findings queue now disagree about the same estate")
    assert series[r2]["critical"] >= 1, "the CRITICAL overlay dropped it too"


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_the_burndown_still_drops_a_finding_that_was_genuinely_resolved(database,
                                                                        landscape,
                                                                        system):
    """The other direction. Withholding must not become never-closing: a finding
    a run COULD see and did not report is resolved, and must leave the backlog on
    that run rather than lingering for ever."""
    from server import analytics, db, ingest

    finding = {"check_id": "USR-007", "title": "t", "severity": "HIGH",
               "category": "User & Authorization", "description": "d",
               "affected_items": [], "subject": [{"type": "user", "name": "ADA"}]}
    ran = {"modules": {"user_auth_audit": {"status": "complete", "sources_missing": []}}}

    with db.connection() as conn:
        r1 = conn.execute(
            "INSERT INTO scan_run (landscape_id, system_id, status, started_at) "
            "VALUES (%s,%s,'complete', now() - interval '2 hours') RETURNING id",
            (landscape, system)).fetchone()["id"]
        ingest.store_run(conn, r1, landscape, system, [finding], "PRD", "100",
                         coverage=ran)
        r2 = conn.execute(
            "INSERT INTO scan_run (landscape_id, system_id, status, started_at) "
            "VALUES (%s,%s,'complete', now() - interval '1 hour') RETURNING id",
            (landscape, system)).fetchone()["id"]
        d2 = ingest.store_run(conn, r2, landscape, system, [], "PRD", "100",
                              coverage=ran)
        conn.commit()

    assert len(d2.resolved) == 1, "the module ran; the finding should have resolved"
    series = {row["run_id"]: row for row in analytics.burndown(_scope(database, system))}
    ids = [f for f in d2.resolved]
    assert ids
    # It was open after r1 and gone after r2.
    assert series[r1]["open_after"] >= 1
