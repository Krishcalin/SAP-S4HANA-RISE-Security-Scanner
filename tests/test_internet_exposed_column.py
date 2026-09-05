"""`internet_exposed` on the finding row, and the hop gate that reads it.

WHY A COLUMN. The exposure verdict has lived in `finding_observation.details`
since the endpoint join shipped, which makes it invisible to anything that reads
findings — the path graph, a query, a report — without a join per row. Lifting it
onto the finding puts it beside `taint_confidence` and `reachability`, which are
there for exactly the same reason and were added the same way.

ONLY `true` AND NULL ARE EVER WRITTEN, and that is the whole difficulty of using
it. `reachability.exposure` does not answer "not exposed": a class can be reached
through another class, through a dynamic call no graph resolves, or through an
endpoint whose HANDLER_CLASS the customer left blank. So NULL carries two
meanings the column cannot separate — "assessed, no route found" and "never
assessed" — and that is what stops the hop gate being shippable as a default.

THE GATE IS BUILT, CORRECT, AND APPLIED TO NOTHING. Written as `is not False` it
admits every finding, because nothing is ever False — a feature that does
nothing. Written as `is True` it drops every finding whose exposure is unknown,
which is most of them on most estates, so an estate that omitted one optional
column would lose its attack paths and read as having none. It gates on `is
True`, and no hop in `data/attack_paths.json` carries `requires_exposure` until
one can meet the condition that makes it safe.

That refusal is the point of this file. A gate nobody can use yet is worth
building only if the reason it is unused is written down and tested.
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

from server import graph, migrations  # noqa: E402

pg = pytest.mark.skipif(not os.getenv("DB_DSN"),
                        reason="set DB_DSN to a PostgreSQL 16 instance")


def finding(fid, check_id="ABAP-CMDI-001", exposed=None, confidence=None):
    return {"id": fid, "check_id": check_id, "severity": "HIGH", "system_id": 1,
            "subject": [], "priority_tier": "P2", "taint_confidence": confidence,
            "internet_exposed": exposed, "sid": "PRD", "client": "100",
            "tier": "prod"}


class _Conn:
    def __init__(self, rows):
        self._rows = rows

    def execute(self, _sql, _params):
        return self

    def fetchall(self):
        return self._rows


def instantiate(rows, hop):
    template = {"paths": [{
        "id": "T-1", "name": "test", "severity": "HIGH",
        "hops": [dict({"name": "the hop", "required": True, "cut": True}, **hop)],
    }]}
    return graph.instantiate(_Conn(rows), 1, template)


# --------------------------------------------------------------------------- #
#  The predicate                                                               #
# --------------------------------------------------------------------------- #

def test_a_hop_that_does_not_ask_is_unaffected():
    """Every hop in the shipped template is this one."""
    rows = [finding(1, exposed=None)]
    paths = instantiate(rows, {"checks": ["ABAP-CMDI-001"]})
    assert len(paths[0]["hops"][0]["findings"]) == 1
    assert paths[0]["hops"][0]["requires_exposure"] is False


def test_a_hop_that_asks_admits_only_a_proven_route():
    rows = [finding(1, exposed=True), finding(2, exposed=None)]
    paths = instantiate(rows, {"checks": ["ABAP-CMDI-001"],
                               "requires_exposure": True})
    assert [f["id"] for f in paths[0]["hops"][0]["findings"]] == [1]


def test_unknown_exposure_is_excluded_rather_than_assumed_safe():
    """The gate's dangerous half, asserted so it is a decision and not a
    surprise: `None` means the export did not say, and a hop asking for exposure
    drops it. This is why no shipped hop asks."""
    rows = [finding(1, exposed=None)]
    paths = instantiate(rows, {"checks": ["ABAP-CMDI-001"],
                               "requires_exposure": True})
    assert paths == []


def test_the_gate_is_not_a_no_op():
    """Written as `is not False` it would admit everything, since nothing is ever
    False. A gate that changes no outcome is a feature that does nothing."""
    rows = [finding(1, exposed=None), finding(2, exposed=True)]
    without = instantiate(rows, {"checks": ["ABAP-CMDI-001"]})
    with_gate = instantiate(rows, {"checks": ["ABAP-CMDI-001"],
                                   "requires_exposure": True})
    assert len(without[0]["hops"][0]["findings"]) == 2
    assert len(with_gate[0]["hops"][0]["findings"]) == 1


def test_it_composes_with_the_confidence_gate():
    """Both predicates apply; a finding must satisfy each."""
    rows = [finding(1, exposed=True, confidence="pattern-only"),
            finding(2, exposed=True, confidence="confirmed"),
            finding(3, exposed=None, confidence="confirmed")]
    paths = instantiate(rows, {"checks": ["ABAP-CMDI-001"],
                               "min_confidence": "tentative",
                               "requires_exposure": True})
    assert [f["id"] for f in paths[0]["hops"][0]["findings"]] == [2]


def test_no_shipped_hop_asks_for_exposure_yet():
    """The refusal, pinned. Applying this to a hop needs an estate-level fact the
    column cannot express — NULL means both "assessed, no route" and "never
    assessed" — so a hop that gains it would quietly drop every finding on every
    estate that has not supplied HANDLER_CLASS."""
    templates = graph.load_templates()
    asking = [(p["id"], h["name"]) for p in templates["paths"]
              for h in p.get("hops", []) if h.get("requires_exposure")]
    assert not asking, (
        "%s asks for exposure. Before shipping that, settle what happens on an "
        "estate with no HANDLER_CLASS column: today every finding there is "
        "unknown, and the hop would hold on none of them." % (asking,))


# --------------------------------------------------------------------------- #
#  The column and its backfill                                                 #
# --------------------------------------------------------------------------- #

@pg
def test_the_column_exists_and_is_nullable():
    from server import db
    db.init_schema()
    col = db.one("""SELECT data_type, is_nullable FROM information_schema.columns
                    WHERE table_name='finding' AND column_name='internet_exposed'""")
    assert col, "the column was not created"
    assert col["data_type"] == "boolean"
    assert col["is_nullable"] == "YES", (
        "a NOT NULL column would force a value for findings nobody assessed")


@pg
def test_the_backfill_copies_a_recorded_verdict_and_nothing_else():
    """Reads only observations that actually record the key. A finding scanned
    before the join existed has none, and stays NULL — `schema.sql` makes the
    same argument for crq_result.model_version: backfilling a value it was not
    computed from would be inventing provenance."""
    from server import db
    db.init_schema()
    with db.connection() as conn:
        row = conn.execute(
            "SELECT id FROM finding WHERE check_id LIKE 'ABAP-%' LIMIT 1").fetchone()
        if row is None:
            pytest.skip("no ABAP findings in this database")
        fid = row["id"]
        obs = conn.execute(
            "SELECT id FROM finding_observation WHERE finding_id=%s "
            "ORDER BY id DESC LIMIT 1", (fid,)).fetchone()
        if obs is None:
            pytest.skip("that finding has no observation")

        conn.execute(
            "UPDATE finding_observation SET details = "
            "COALESCE(details, '{}'::jsonb) || %s::jsonb WHERE id=%s",
            (json.dumps({"internet_exposed": True}), obs["id"]))
        conn.execute("DELETE FROM schema_version WHERE version=%s",
                     (migrations.INTERNET_EXPOSED_VERSION,))
        conn.execute("UPDATE finding SET internet_exposed = NULL")

        result = migrations.backfill_internet_exposed(conn)
        assert result["status"] == "applied"
        assert result["backfilled"] == 1, result

        assert conn.execute(
            "SELECT internet_exposed FROM finding WHERE id=%s",
            (fid,)).fetchone()["internet_exposed"] is True
        # Every other finding is untouched: no observation recorded the key.
        assert conn.execute(
            "SELECT count(*) n FROM finding WHERE internet_exposed IS NOT NULL "
            "AND id <> %s", (fid,)).fetchone()["n"] == 0
        conn.rollback()


@pg
def test_the_backfill_runs_once():
    """Guarded by its own `schema_version` row, like every migration here."""
    from server import db
    db.init_schema()
    with db.connection() as conn:
        conn.execute("INSERT INTO schema_version (version) VALUES (%s) "
                     "ON CONFLICT DO NOTHING",
                     (migrations.INTERNET_EXPOSED_VERSION,))
        assert migrations.backfill_internet_exposed(conn)["status"] == "already applied"
        conn.rollback()


@pg
def test_it_never_writes_false():
    """`exposure()` does not answer "not exposed", so a False on this column
    would be a claim the product does not make."""
    from server import db
    db.init_schema()
    assert db.one("SELECT count(*) n FROM finding "
                  "WHERE internet_exposed IS FALSE")["n"] == 0


def test_the_migration_takes_the_next_free_version():
    assert migrations.INTERNET_EXPOSED_VERSION == 5
    assert migrations.INTERNET_EXPOSED_VERSION != migrations.PARAMETER_TYPE_VERSION
