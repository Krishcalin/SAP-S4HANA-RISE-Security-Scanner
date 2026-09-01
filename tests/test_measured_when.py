"""When was this answer measured? — the two places that still could not say.

`tests/test_estate_freshness.py` gave every SYSTEM a date. Two things were
deliberately left, and this file closes them.

THE ROLL-UPS. `queries.latest_coverage` selects the newest complete run per
system, orders by `started_at`, and then threw the timestamp away. So the
Domains, CSF and Trend screens reported a category CLEAR on the strength of an
export of any age, and could not say which — a control function fed by a scan
from March reads exactly like one fed this morning.

THE OFFLINE REPORT, which is the copy that leaves the building and reaches an
auditor. Every export's timestamp was already recorded, in a `modified` column
inside a collapsed <details> that on a full bundle runs to a hundred and thirty
rows. Nobody was going to open it and scan the column, which is the failure
`report_generator` names twice in its own comments: a qualification nobody
reaches is not a qualification.

THE RULE THAT DECIDES THE OFFLINE HALF. A file's modification time is when it
was last WRITTEN on the machine that produced the bundle. Copying, unzipping or
exporting through a share resets it to the moment of the copy, so mtime can only
ever be LATER than the moment the data left SAP. The derived age is therefore a
FLOOR: "at least 240 days old" is sound and can be acted on; "0 days old" says
nothing at all. The report states the first and stays silent on the second,
because a reassuring sentence built on a number that cannot reassure is worse
than no sentence.
"""
from __future__ import annotations

import datetime as dt
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import coverage as cov                              # noqa: E402


# ── the offline half: how old is the evidence ────────────────────────────────

NOW = dt.datetime(2026, 9, 1, 12, 0, 0)


def _files(*stamps):
    return [{"file": "x%d.csv" % n, "modified": s}
            for n, s in enumerate(stamps)]


def test_the_age_is_taken_from_the_newest_file():
    """An export directory is written in one sitting. One stale leftover among
    a hundred current files does not make the assessment old."""
    age = cov.evidence_age(
        _files("2020-01-01 09:00:00", "2026-08-30 09:00:00"), NOW)
    assert age["at_least_days"] == 2
    assert age["newest"] == "2026-08-30"
    # The oldest is reported beside it, so a bundle assembled over years is
    # visible as one rather than averaged away.
    assert age["oldest"] == "2020-01-01"
    assert age["span_days"] > 2000


def test_old_evidence_is_reported_as_a_floor_and_said_out_loud():
    age = cov.evidence_age(_files("2026-01-05 10:00:00"), NOW)
    assert age["stale"] is True
    assert age["at_least_days"] == 239

    said = cov.evidence_age_sentence(age)
    assert "at least 239 days" in said
    # The asymmetry, stated where the reader is. Without it a floor reads as a
    # measurement, and somebody argues the data is fine because it says 239.
    assert "floor" in said
    assert "may be older still" in said


def test_a_fresh_looking_bundle_says_nothing_at_all():
    """THE ASYMMETRY THIS WHOLE FUNCTION EXISTS FOR. Copying resets mtime to
    now, so a small figure is not evidence of freshness — it is the absence of
    evidence of staleness, and those must not render the same."""
    age = cov.evidence_age(_files("2026-08-31 09:00:00"), NOW)
    assert age["at_least_days"] == 1
    assert age["stale"] is False
    assert cov.evidence_age_sentence(age) == "", \
        "a reassuring sentence was built on a number that cannot reassure"


def test_a_bundle_with_no_usable_timestamp_is_none_not_new():
    """None and "written today" are different claims, and only one of them is
    a measurement."""
    assert cov.evidence_age([{"file": "x.csv", "modified": ""}], NOW) is None
    assert cov.evidence_age([], NOW) is None
    assert cov.evidence_age(None, NOW) is None
    assert cov.evidence_age_sentence(None) == ""


def test_a_timestamp_the_parser_does_not_know_is_skipped_not_guessed():
    age = cov.evidence_age(
        _files("not a date", "2026-01-05 10:00:00"), NOW)
    assert age["files"] == 1, "an unparseable stamp was counted as a date"


@pytest.mark.parametrize("shape", ["2026-01-05 10:00:00", "2026-01-05T10:00:00",
                                   "2026-01-05"])
def test_the_shapes_a_manifest_can_carry(shape):
    assert cov.evidence_age(_files(shape), NOW)["newest"] == "2026-01-05"


def test_the_threshold_is_one_sap_patch_cycle():
    """Not an invented number: SAP publishes Security Notes on the second
    Tuesday of each month, and two of those fall 28 to 35 days apart."""
    assert cov.STALE_AFTER_DAYS == 35
    assert cov.evidence_age(_files("2026-07-28 12:00:00"), NOW)["stale"] is False
    assert cov.evidence_age(_files("2026-07-27 12:00:00"), NOW)["stale"] is True


def test_the_console_and_the_report_share_one_definition_of_old():
    """Two copies would drift the day somebody tuned one, leaving the console
    and the PDF a customer sends an auditor disagreeing about the same estate."""
    from server import queries
    assert queries.STALE_AFTER_DAYS is cov.STALE_AFTER_DAYS
    source = (ROOT / "server" / "queries.py").read_text(encoding="utf-8")
    assert "STALE_AFTER_DAYS = 35" not in source, \
        "the console has redefined the threshold instead of importing it"


def test_the_offline_report_states_it_before_the_finding_count():
    """`report_generator` already says twice that a qualification nobody
    reaches is not a qualification. This one must not land inside the collapsed
    manifest table it came from."""
    source = (ROOT / "modules" / "report_generator.py").read_text(encoding="utf-8")
    assert "_evidence_age_html" in source
    at_age = source.index("{self._evidence_age_html()}")
    at_manifest = source.index("{self._evidence_manifest_html()}")
    at_summary = source.index('<div class="summary-grid">')
    assert at_age < at_manifest < at_summary, \
        "the age is rendered after the numbers a reader anchors on"


# ── the console half: the roll-ups carry their date ──────────────────────────

def _manifest(measured=None):
    out = {"modules": {}}
    if measured is not None:
        out["measured"] = measured
    return out


def test_the_domain_rollup_carries_the_date_it_was_measured():
    from modules import domains
    rolled = domains.roll_up([], coverage=_manifest({"oldest_days": 90}))
    assert rolled["measured"] == {"oldest_days": 90}


def test_the_csf_rollup_carries_it_too():
    from modules import nist_csf
    rolled = nist_csf.roll_up([], coverage=_manifest({"oldest_days": 90}))
    assert rolled["measured"] == {"oldest_days": 90}


@pytest.mark.parametrize("module_name", ["domains", "nist_csf"])
def test_no_manifest_means_no_date_rather_than_today(module_name):
    """A roll-up with nothing to date itself by must say so. Defaulting to now
    would put today's date on an answer nobody measured today."""
    import importlib
    module = importlib.import_module("modules.%s" % module_name)
    assert module.roll_up([], coverage=None)["measured"] is None
    assert module.roll_up([], coverage=_manifest())["measured"] is None


def test_the_trend_screen_carries_it(monkeypatch):
    """"Is it getting better" is a question about a period, and a trend whose
    most recent point is eight months old is a statement about eight months ago
    rendered as the present."""
    from server import analytics
    for name in ("sla_status", "aging_buckets", "burndown", "backlog_by_tier",
                 "technical_debt", "team_scorecard"):
        monkeypatch.setattr(analytics, name, lambda *a, **k: {})
    monkeypatch.setattr(analytics, "mttr", lambda *a, **k: {})
    monkeypatch.setattr(analytics, "domain_scorecard", lambda *a, **k: {})

    got = analytics.journey_summary(None, coverage=_manifest({"oldest_days": 240}))
    assert got["measured"] == {"oldest_days": 240}


# ── the wiring, against a real database ──────────────────────────────────────

pg = pytest.mark.skipif(not os.getenv("DB_DSN"),
                        reason="set DB_DSN to a PostgreSQL 16 instance")


@pg
def test_latest_coverage_dates_its_own_manifest():
    """The query selected `started_at` to order by and then dropped it. A
    manifest nobody can date is what let a domain report CLEAR on an export of
    any age."""
    from server import db, queries
    db.init_schema()
    landscape = db.one(
        "INSERT INTO landscape (name, deployment_mode) VALUES (%s,'on_prem') "
        "RETURNING id", ("measured-%s" % os.urandom(5).hex(),))["id"]
    try:
        system = db.one(
            "INSERT INTO sap_system (landscape_id, sid, client, tier) "
            "VALUES (%s,'PRD','100','prod') RETURNING id", (landscape,))["id"]
        for days in (400, 120):
            db.execute(
                "INSERT INTO scan_run (landscape_id, system_id, status, "
                "started_at, coverage) VALUES (%s,%s,'complete', "
                "now() - make_interval(days => %s), %s)",
                (landscape, system, days, '{"modules": {}}'))

        manifest = queries.latest_coverage([system])
        assert manifest is not None
        measured = manifest["measured"]
        # The NEWEST run per system is what the open findings reflect, so that
        # is what dates this system.
        assert 119 <= measured["newest_days"] <= 121
        assert measured["stale"] is True
        assert measured["stale_after_days"] == queries.STALE_AFTER_DAYS
    finally:
        db.execute("DELETE FROM landscape WHERE id = %s", (landscape,))


@pg
def test_the_oldest_run_in_the_union_dates_the_rollup():
    """The manifest is a UNION across systems: a module counts as having run if
    it ran for ANY of them. So the weakest evidence behind a CLEAR verdict is
    the OLDEST run in that union, and dating the answer by the newest would
    describe it by its best input rather than its worst."""
    from server import db, queries
    db.init_schema()
    landscape = db.one(
        "INSERT INTO landscape (name, deployment_mode) VALUES (%s,'on_prem') "
        "RETURNING id", ("union-%s" % os.urandom(5).hex(),))["id"]
    try:
        systems = []
        for sid, days in (("PRD", 2), ("QAS", 300)):
            system = db.one(
                "INSERT INTO sap_system (landscape_id, sid, client, tier) "
                "VALUES (%s,%s,'100','prod') RETURNING id",
                (landscape, sid))["id"]
            systems.append(system)
            db.execute(
                "INSERT INTO scan_run (landscape_id, system_id, status, "
                "started_at, coverage) VALUES (%s,%s,'complete', "
                "now() - make_interval(days => %s), %s)",
                (landscape, system, days, '{"modules": {}}'))

        measured = queries.latest_coverage(systems)["measured"]
        assert measured["systems"] == 2
        assert 299 <= measured["oldest_days"] <= 301
        assert measured["newest_days"] <= 3
        assert measured["stale"] is True, \
            "one system scanned yesterday made a year-old estate look current"
    finally:
        db.execute("DELETE FROM landscape WHERE id = %s", (landscape,))
