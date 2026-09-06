"""Ranking the exports that would make the most open findings decidable.

WHAT THIS IS DEFENDING. Every module already records its own evidence gap, and
`modules/domains.py` already keeps `not_supplied` apart from `clear`. The fact was
therefore on every finding and nowhere in aggregate, so the question a customer
can actually act on -- *of everything we did not send, what is worth sending
first?* -- had no answer. `queries.evidence_gaps` is that sum, and the ways it can
lie are all arithmetic:

  * DOUBLE COUNTING. One finding may name several missing sources. Summing the
    per-source column would report more undecided findings than the estate holds,
    and the headline is the number a reader quotes.
  * STALE EVIDENCE. A gap closed by a later upload must stop being a gap. Reading
    any observation but the newest recommends a file the customer already sent.
  * COUNTING WHAT IS NO LONGER OPEN. A resolved finding's gap is nobody's work.

AND ONE WAY IT CAN MISLEAD WITHOUT BEING WRONG: five logical sources come from
the layer SAP operates under RISE. Ranking `ext_os_commands_sap` first for a RISE
customer is advice they cannot take, so the row is marked rather than dropped --
dropping it would misstate the total for the on-premise readers who CAN close it.

THE CLAIM IS DELIBERATELY WEAK. Supplying a source lets a check reach a verdict;
it does not say which. `test_it_does_not_predict_what_the_answers_would_be` pins
that, because the tempting next field -- "supplying this would fix N findings" --
is a number the product cannot know and has no connection to SAP to discover.
"""
from __future__ import annotations

import json
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


class Estate:
    """An isolated landscape whose findings no other test can see."""

    def __init__(self, db):
        self.db = db
        self.landscape = db.one(
            "INSERT INTO landscape (name, deployment_mode) "
            "VALUES (%s,'rise_pce') RETURNING id",
            ("gaps-%s" % os.urandom(6).hex(),))["id"]
        self.system = db.one(
            "INSERT INTO sap_system (landscape_id, sid, client, tier) "
            "VALUES (%s,'GAP','100','prod') RETURNING id",
            (self.landscape,))["id"]
        # Real check ids: finding.check_id is foreign-keyed to the catalogue.
        self.checks = [r["check_id"] for r in db.query(
            "SELECT check_id FROM check_definition ORDER BY check_id LIMIT 8")]
        self._n = 0

    def finding(self, check_id=None, state="open", missing=(), complete=False,
                runs=None):
        """One finding plus its observations, oldest first."""
        self._n += 1
        fid = self.db.one(
            "INSERT INTO finding (landscape_id, system_id, check_id, fingerprint,"
            " state, severity) VALUES (%s,%s,%s,%s,%s,'HIGH') RETURNING id",
            (self.landscape, self.system, check_id or self.checks[0],
             "gap-fp-%s-%d" % (os.urandom(4).hex(), self._n), state))["id"]
        for evidence in (runs if runs is not None else
                         [{"complete": complete, "missing_sources": list(missing),
                           "declared_sources": []}]):
            run = self.db.one(
                "INSERT INTO scan_run (landscape_id, system_id, status) "
                "VALUES (%s,%s,'complete') RETURNING id",
                (self.landscape, self.system))["id"]
            self.db.execute(
                "INSERT INTO finding_observation (finding_id, scan_run_id, "
                "evidence) VALUES (%s,%s,%s)",
                (fid, run, json.dumps(evidence)))
        return fid

    def gaps(self):
        from server import queries
        return queries.evidence_gaps([self.system])

    def drop(self):
        self.db.execute("DELETE FROM landscape WHERE id = %s", (self.landscape,))


@pytest.fixture
def estate(database):
    e = Estate(database)
    try:
        yield e
    finally:
        e.drop()


def by_source(result):
    return {g["source"]: g for g in result["gaps"]}


# --------------------------------------------------------------------------- #
#  The ranking                                                                 #
# --------------------------------------------------------------------------- #

@pg
def test_it_ranks_by_how_many_findings_a_source_would_decide(estate):
    """THE COUNT ORDERS THIS, NOT THE NAME. `user_groups` is deliberately the
    heavier source and the later one alphabetically: ordering by source name
    alone would put `auth_objects` first and produce the same list for the
    obvious wrong reason. Sorted the other way round this test cannot fail."""
    for _ in range(3):
        estate.finding(missing=["user_groups"])
    estate.finding(missing=["auth_objects"])
    got = estate.gaps()
    assert [g["source"] for g in got["gaps"]] == ["user_groups", "auth_objects"]
    assert got["gaps"][0]["findings_undecided"] == 3
    assert got["gaps"][1]["findings_undecided"] == 1


@pg
def test_the_total_counts_findings_not_source_mentions(estate):
    """THE HEADLINE NUMBER. One finding blocked on two sources is ONE undecided
    finding appearing in two rows. Summing the rows would report two, and the
    total is the figure a reader quotes back."""
    estate.finding(missing=["auth_objects", "user_groups"])
    got = estate.gaps()
    assert got["findings_undecided"] == 1
    assert sum(g["findings_undecided"] for g in got["gaps"]) == 2
    assert len(got["gaps"]) == 2


@pg
def test_a_finding_that_read_everything_is_not_a_gap(estate):
    estate.finding(complete=True, missing=[])
    assert estate.gaps() == {"gaps": [], "findings_undecided": 0,
                             "unknown_sources": []}


@pg
def test_a_resolved_finding_is_not_a_missing_export(estate):
    estate.finding(state="resolved", missing=["auth_objects"])
    estate.finding(state="false_positive", missing=["auth_objects"])
    estate.finding(state="open", missing=["auth_objects"])
    got = estate.gaps()
    assert got["findings_undecided"] == 1
    assert got["gaps"][0]["findings_undecided"] == 1


@pg
def test_only_the_newest_observation_decides(estate):
    """A gap closed by a later upload stops being a gap. Reading any observation
    but the newest recommends a file the customer has already sent."""
    estate.finding(runs=[
        {"complete": False, "missing_sources": ["auth_objects"]},
        {"complete": True, "missing_sources": []},
    ])
    got = estate.gaps()
    # BOTH HALVES, because they are separate queries over the same rule. Asserting
    # only the total left the ranked list free to read the oldest observation --
    # a mutation reversing exactly that survived this test until the second line
    # was added.
    assert got["findings_undecided"] == 0
    assert got["gaps"] == []


@pg
def test_a_gap_that_opened_on_the_latest_run_is_counted(estate):
    """The other direction, so the test above cannot pass by reading nothing."""
    estate.finding(runs=[
        {"complete": True, "missing_sources": []},
        {"complete": False, "missing_sources": ["auth_objects"]},
    ])
    got = estate.gaps()
    assert got["findings_undecided"] == 1
    assert got["gaps"][0]["source"] == "auth_objects"


@pg
def test_distinct_checks_and_systems_are_counted_not_rows(estate):
    estate.finding(check_id=estate.checks[0], missing=["auth_objects"])
    estate.finding(check_id=estate.checks[0], missing=["auth_objects"])
    estate.finding(check_id=estate.checks[1], missing=["auth_objects"])
    row = by_source(estate.gaps())["auth_objects"]
    assert row["findings_undecided"] == 3
    assert row["checks"] == 2
    assert row["systems"] == 1


# --------------------------------------------------------------------------- #
#  What the row says about the source                                          #
# --------------------------------------------------------------------------- #

@pg
def test_a_source_sap_operates_is_marked_rather_than_hidden(estate):
    """`ext_os_commands_sap` comes from the layer SAP runs under RISE. Telling
    that customer to produce it is advice they cannot act on; dropping the row
    would understate the estate's gap for on-premise readers who can."""
    from modules.coverage import RISE_UNREACHABLE_SOURCES
    assert "ext_os_commands_sap" in RISE_UNREACHABLE_SOURCES, (
        "this test is anchored on that source being one SAP operates")
    estate.finding(missing=["ext_os_commands_sap"])
    estate.finding(missing=["auth_objects"])
    got = estate.gaps()
    rows = by_source(got)
    assert rows["ext_os_commands_sap"]["obtainable_in_rise"] is False
    assert rows["auth_objects"]["obtainable_in_rise"] is True
    assert got["findings_undecided"] == 2, "still counted"


@pg
def test_it_names_the_files_the_loader_will_accept(estate):
    """So the row is actionable without a second document. Taken from the
    loader's own table, never written out here."""
    from modules.data_loader import DataLoader
    estate.finding(missing=["auth_objects"])
    row = by_source(estate.gaps())["auth_objects"]
    assert row["files_accepted"] == list(DataLoader.FILE_MAP["auth_objects"])
    assert row["files_accepted"], "a known source offers at least one filename"


@pg
def test_a_source_the_loader_does_not_know_is_surfaced_not_swallowed(estate):
    """A typo'd source name is a gap no export can ever close. Left unflagged it
    sits for ever looking like ordinary missing input."""
    estate.finding(missing=["auth_objekts"])
    got = estate.gaps()
    assert got["unknown_sources"] == ["auth_objekts"]
    row = by_source(got)["auth_objekts"]
    assert row["known_to_loader"] is False
    assert row["files_accepted"] == [], "nothing to offer for a name we lack"


@pg
def test_a_known_source_is_not_flagged_as_unknown(estate):
    estate.finding(missing=["auth_objects"])
    got = estate.gaps()
    assert got["unknown_sources"] == []
    assert by_source(got)["auth_objects"]["known_to_loader"] is True


# --------------------------------------------------------------------------- #
#  The claim it refuses to make                                                #
# --------------------------------------------------------------------------- #

@pg
def test_it_does_not_predict_what_the_answers_would_be(estate):
    """THE REFUSAL. The tempting next field is "supplying this would fix N" --
    a number reachable only from a verdict the scanner has not computed, about a
    system it is not connected to. `findings_undecided` is named for what it
    counts and nothing here promises an outcome."""
    estate.finding(missing=["auth_objects"])
    row = by_source(estate.gaps())["auth_objects"]
    banned = [k for k in row
              if any(w in k for w in ("fix", "resolve", "would_be", "predict",
                                      "estimate", "clear"))]
    assert not banned, "%s promises an outcome the product cannot know" % banned
    assert "findings_undecided" in row


@pg
def test_scope_is_respected(estate, database):
    """Another landscape's gaps are invisible, like every other query here."""
    estate.finding(missing=["auth_objects"])
    other = Estate(database)
    try:
        other.finding(missing=["sod_ruleset"])
        assert [g["source"] for g in estate.gaps()["gaps"]] == ["auth_objects"]
        assert [g["source"] for g in other.gaps()["gaps"]] == ["sod_ruleset"]
    finally:
        other.drop()


# --------------------------------------------------------------------------- #
#  Over HTTP                                                                   #
# --------------------------------------------------------------------------- #

@pytest.fixture()
def client():
    from fastapi.testclient import TestClient
    from server import app as appmod, auth, db
    db.init_schema()
    name = "gaps_%s" % os.urandom(4).hex()
    auth.create_user(name, "api-test-password", "admin")
    c = TestClient(appmod.app)
    assert c.post("/api/auth/login",
                  json={"username": name, "password": "api-test-password"}
                  ).status_code == 200
    yield c
    db.execute("DELETE FROM app_user WHERE username = %s", (name,))


@pg
def test_the_endpoint_refuses_an_anonymous_caller():
    """It reports what an estate has NOT sent, which is as much of a disclosure
    as the findings themselves."""
    from fastapi.testclient import TestClient
    from server import app as appmod
    assert TestClient(appmod.app).get(
        "/api/evidence-gaps").status_code in (401, 403)


@pg
def test_the_endpoint_returns_the_ranked_shape(client):
    got = client.get("/api/evidence-gaps")
    assert got.status_code == 200
    body = got.json()
    assert set(body) == {"gaps", "findings_undecided", "unknown_sources"}
    counts = [g["findings_undecided"] for g in body["gaps"]]
    assert counts == sorted(counts, reverse=True), "not ranked"
    for gap in body["gaps"]:
        assert set(gap) == {"source", "findings_undecided", "checks", "systems",
                            "files_accepted", "feeds", "known_to_loader",
                            "obtainable_in_rise"}


@pg
def test_no_source_a_module_asks_for_is_unknown_to_the_loader(client):
    """A LIVE DEFECT DETECTOR, not a shape assertion. A module naming a source
    the loader has no slot for creates a gap no customer can ever close, and the
    estate this runs against is the bundled demo — so this fails the day a typo
    ships rather than the day somebody reads the screen."""
    body = client.get("/api/evidence-gaps").json()
    assert body["unknown_sources"] == [], (
        "%s named in missing_sources but in no loader slot; no export closes it"
        % body["unknown_sources"])


@pg
def test_a_source_named_twice_by_one_finding_counts_once(estate):
    """The lateral expansion emits a row per (finding, named source), so a
    repeated name would count the finding twice and lift the source up the
    ranking on evidence that does not exist. Nothing enforces uniqueness in the
    array, and a duplicate inside the sibling `affected_items` array has already
    been seen in the reference database."""
    estate.finding(missing=["auth_objects", "auth_objects"])
    got = estate.gaps()
    assert got["gaps"][0]["findings_undecided"] == 1
    assert got["findings_undecided"] == 1


@pg
def test_the_latest_observation_is_the_latest_RUN_not_the_latest_row(estate,
                                                                    database):
    """AGREEMENT WITH THE FINDING ITSELF. `list_findings` picks `latest_evidence`
    with `ORDER BY o.scan_run_id DESC`, and FindingDetail prints that sentence on
    each finding; this screen is the sum of those sentences. Ordering by `o.id`
    instead gives the same answer whenever runs are observed in order and a
    different one the moment they are not -- re-importing an older run inserts a
    high row id against a low run id -- and a total that contradicts the findings
    it is summing is exactly the artefacts-disagreeing failure this codebase
    keeps warning about."""
    fid = estate.finding(runs=[{"complete": True, "missing_sources": []}])
    older = database.one(
        "INSERT INTO scan_run (landscape_id, system_id, status) "
        "VALUES (%s,%s,'complete') RETURNING id",
        (estate.landscape, estate.system))["id"]
    # The observation of an EARLIER run, inserted last: highest id, lowest run.
    database.execute(
        "UPDATE scan_run SET id = %s WHERE id = %s",
        (-older, older))
    database.execute(
        "INSERT INTO finding_observation (finding_id, scan_run_id, evidence) "
        "VALUES (%s,%s,%s)",
        (fid, -older, json.dumps({"complete": False,
                                  "missing_sources": ["auth_objects"]})))
    got = estate.gaps()
    assert got["findings_undecided"] == 0, (
        "an older run's evidence was read as current because it was inserted "
        "most recently")
    assert got["gaps"] == []
