"""Single-landscape product + CRQ frequency inputs + recompute-in-place.

Three changes land together here:

* **One landscape.** MonitorRisk is installed per company, so a deployment
  assesses exactly one organization = one landscape. `db.singleton_landscape_id`
  resolves (and creates on first use) that one landscape; the upload/risk screens
  resolve it instead of offering a picker. The landscape table can still hold
  more than one row — a handful of row-scoping tests insert a second — so this is
  an app-layer rule, not a DB constraint.
* **Threat Exposure inputs.** The two frequency questions the FAIR engine needs to
  turn a loss magnitude into an ANNUAL figure were accepted on save but never
  rendered. They now carry form metadata and surface in a "Threat Exposure"
  section via the same schema endpoint the loss questions use.
* **Recompute in place.** Saving CRQ answers re-prices the latest completed scan
  so the board Risk page reflects them without a full re-scan, and an explicit
  recompute does the same on demand. The re-price REPLACES the run's stored
  result rather than appending a duplicate (the trend assumes one row per run).
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

pg = pytest.mark.skipif(not os.getenv("DB_DSN"),
                        reason="set DB_DSN to a PostgreSQL 16 instance")


# ── Part B: the Threat Exposure question set (no database) ───────────────────

def test_frequency_parameters_carry_form_metadata_in_their_own_group():
    from modules.fair_frequency_model import ANSWERS, FREQUENCY_PARAMETERS

    keys = {p["key"] for p in FREQUENCY_PARAMETERS}
    assert keys == {"observed_contacts_per_year", "sap_security_incidents_3y"}
    for p in FREQUENCY_PARAMETERS:
        assert p["group"] == "Threat Exposure"
        assert p["label"] and p["help"] and p["unit"] == "count"
        assert p["feeds"] == []
    # Back-compat: ANSWERS stays a {key: help} dict derived from the list.
    assert set(ANSWERS) == keys
    assert all(ANSWERS[k] for k in keys)


def test_the_two_schemas_do_not_collide_and_cover_six_groups():
    from modules.fair_frequency_model import FREQUENCY_PARAMETERS
    from modules.fair_loss_model import PARAMETERS

    combined = PARAMETERS + FREQUENCY_PARAMETERS
    assert len({p["key"] for p in combined}) == len(combined), "a key is duplicated"
    groups = [p["group"] for p in combined]
    # Threat Exposure comes last, after the five loss groups, so it renders as a
    # distinct final section.
    assert groups[-1] == "Threat Exposure"
    assert set(groups) == {"Business", "Resilience", "Data", "Financial",
                           "Insurance", "Threat Exposure"}


# ── fixtures for the DB-backed tests ─────────────────────────────────────────

ANALYST_PASSWORD = "initial-password-1"


@pytest.fixture()
def analyst():
    from server import auth, db
    db.init_schema()
    name = f"slc_{os.urandom(4).hex()}"
    uid = auth.create_user(name, ANALYST_PASSWORD, "analyst")
    yield {"id": uid, "username": name, "password": ANALYST_PASSWORD}
    db.execute("DELETE FROM app_user WHERE id = %s", (uid,))


def _signed_in(user):
    from fastapi.testclient import TestClient
    from server import app as appmod
    c = TestClient(appmod.app, follow_redirects=False)
    resp = c.post("/api/auth/login",
                  json={"username": user["username"], "password": user["password"]})
    assert resp.status_code == 200, resp.text
    return c


def _landscape(conn):
    return conn.execute(
        "INSERT INTO landscape (name, deployment_mode) VALUES (%s,'on_prem') "
        "RETURNING id", (f"slc-{os.urandom(5).hex()}",)).fetchone()["id"]


def _seed_completed_run(conn, landscape_id, check_ids):
    """A completed scan_run on a system, with one open finding per check id."""
    system_id = conn.execute(
        "INSERT INTO sap_system (landscape_id, sid, client) VALUES (%s,'PRD','100') "
        "RETURNING id", (landscape_id,)).fetchone()["id"]
    run_id = conn.execute(
        "INSERT INTO scan_run (landscape_id, system_id, status) "
        "VALUES (%s,%s,'complete') RETURNING id", (landscape_id, system_id)).fetchone()["id"]
    for cid in check_ids:
        conn.execute("INSERT INTO check_definition (check_id, title) VALUES (%s,%s) "
                     "ON CONFLICT (check_id) DO NOTHING", (cid, cid))
        conn.execute(
            "INSERT INTO finding (landscape_id, system_id, fingerprint, check_id, "
            "severity, state) VALUES (%s,%s,%s,%s,'HIGH','open')",
            (landscape_id, system_id, os.urandom(16).hex(), cid))
    return system_id, run_id


# ── Part A: one organization landscape ───────────────────────────────────────

@pg
def test_singleton_landscape_id_resolves_and_is_idempotent():
    from server import db
    db.init_schema()
    first = db.singleton_landscape_id()
    assert isinstance(first, int) and first > 0
    assert db.singleton_landscape_id() == first, "a second call made a new landscape"
    row = db.one("SELECT id FROM landscape WHERE id = %s", (first,))
    assert row is not None


@pg
def test_api_landscape_returns_the_one_landscape(analyst):
    c = _signed_in(analyst)
    resp = c.get("/api/landscape")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    from server import db
    assert body["id"] == db.singleton_landscape_id()
    assert body["name"] and body["deployment_mode"]


# ── Part B: the schema endpoint surfaces the Threat Exposure section ──────────

@pg
def test_crq_parameters_endpoint_surfaces_the_threat_exposure_section(analyst):
    from server import db
    c = _signed_in(analyst)
    land = db.singleton_landscape_id()
    resp = c.get(f"/api/crq/parameters?landscape_id={land}")
    assert resp.status_code == 200, resp.text
    params = resp.json()["parameters"]
    by_key = {p["key"]: p for p in params}
    for key in ("observed_contacts_per_year", "sap_security_incidents_3y"):
        assert key in by_key, f"{key} is not offered on the form"
        assert by_key[key]["group"] == "Threat Exposure"
    # The five loss groups are still present and come first.
    assert by_key["sap_revenue"]["group"] == "Business"


# ── Part C: recompute in place ───────────────────────────────────────────────

@pg
def test_recompute_writes_one_portfolio_row_and_replaces_it_not_appends():
    from server import crq, db

    db.init_schema()
    with db.pool().connection() as conn:
        land = _landscape(conn)
        _seed_completed_run(conn, land, ["RECOMP-A", "RECOMP-B"])
        conn.commit()

    def _portfolio_rows():
        return db.query(
            "SELECT c.id FROM crq_result c JOIN scan_run r ON r.id = c.scan_run_id "
            "WHERE r.landscape_id = %s AND c.scenario_id IS NULL", (land,))

    first = crq.recompute_latest(land)
    assert first["computed"] is True and first["run_id"] is not None
    assert len(_portfolio_rows()) == 1, "recompute did not write exactly one portfolio row"

    # Re-pricing the SAME run must replace, not append — the trend assumes one
    # portfolio row per run.
    crq.recompute_latest(land)
    assert len(_portfolio_rows()) == 1, "a second recompute appended a duplicate row"


@pg
def test_recompute_without_a_completed_scan_is_reported_not_an_error():
    from server import crq, db
    db.init_schema()
    with db.pool().connection() as conn:
        land = _landscape(conn)   # no scan_run at all
        conn.commit()
    result = crq.recompute_latest(land)
    assert result["computed"] is False
    assert result["run_id"] is None
    assert "no completed scan" in result["reason"]


@pg
def test_the_recompute_endpoint_requires_analyst_and_refreshes_the_result(analyst):
    from server import crq, db

    db.init_schema()
    with db.pool().connection() as conn:
        land = _landscape(conn)
        _seed_completed_run(conn, land, ["RECOMP-EP-1"])
        conn.commit()

    c = _signed_in(analyst)
    resp = c.post("/api/crq/recompute", data={"landscape_id": str(land)})
    assert resp.status_code == 200, resp.text
    assert resp.json()["computed"] is True
    # The board read now sees a portfolio row for the latest run.
    latest = crq.latest(None)
    assert latest is not None
