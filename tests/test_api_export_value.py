"""
GET /api/runs/{id}/export-value — which missing export to supply first.

WHY THE ROUTE EXISTS AT ALL. `modules/export_value.rank` has been in the tree
since the CLI grew a "next:" line, and the console — where anybody actually reads
a run — could not reach it. The run page listed each module's missing sources and
stopped, which is a list of filenames with no way to tell which is worth going
back to Basis for. On a partial upload missing five sources the ranking says
`users` alone would let 21 more checks run and `saprouttab` one; that ordering is
the whole product of the module and none of it was visible.

THE FAILURE THIS FILE IS REALLY GUARDING. `rank` takes a deployment mode, and
under RISE it moves the sources the customer has no contractual route to out of
the ranking and into `unobtainable`. Both the landscape row and the coverage
manifest carry that mode, and they agree — except on runs scanned before the
manifest had the key, where `coverage` is `{}` and reads as on_prem. On_prem is
the mode under which nothing is unobtainable, so a manifest-sourced mode turns
`gw_reginfo` and `saprouttab` into things to go and ask SAP for. The route reads
the landscape, and `test_the_mode_comes_from_the_landscape_not_the_manifest`
is that decision written down.
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

#: Real logical source keys, taken from `coverage.check_sources()`. The first
#: three are obtainable anywhere; the last two are in RISE_UNREACHABLE_SOURCES.
MISSING = ["users", "security_params", "user_roles", "gw_reginfo", "saprouttab"]


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient
    from server import app as appmod, auth, db
    db.init_schema()
    name = f"ev_{os.urandom(4).hex()}"
    auth.create_user(name, "api-test-password", "admin")
    c = TestClient(appmod.app)
    assert c.post("/api/auth/login",
                  json={"username": name, "password": "api-test-password"}
                  ).status_code == 200
    yield c
    db.execute("DELETE FROM app_user WHERE username = %s", (name,))


def _run_with(mode: str, coverage: dict) -> int:
    """A landscape in `mode` and one finished run carrying `coverage`."""
    from server import db
    land = db.one(
        "INSERT INTO landscape (name, deployment_mode) VALUES (%s, %s) "
        "RETURNING id", (f"ev_{os.urandom(3).hex()}", mode))
    import json
    run = db.one(
        "INSERT INTO scan_run (landscape_id, status, started_at, coverage) "
        "VALUES (%s, 'complete', now(), %s) RETURNING id",
        (land["id"], json.dumps(coverage)))
    return run["id"]


# --------------------------------------------------------------------------- #
#  The ranking                                                                 #
# --------------------------------------------------------------------------- #

@pg
def test_a_partial_upload_is_ranked_by_what_each_source_unlocks(client):
    run_id = _run_with("on_prem", {"missing": MISSING, "empty": []})
    body = client.get(f"/api/runs/{run_id}/export-value").json()

    assert body["missing"] == 5
    assert body["checks_blocked"] > 0
    unlocks = [r["unlocks_now"] for r in body["ranked"]]
    assert unlocks == sorted(unlocks, reverse=True), \
        f"the ranking is not ordered by what each source unlocks: {unlocks}"
    # The point of the endpoint: the biggest win is named first, not
    # alphabetised. `users` unlocks 21 on this manifest and `saprouttab` one, so
    # an alphabetical list would put the least useful export at the top.
    assert body["ranked"][0]["unlocks_now"] > body["ranked"][-1]["unlocks_now"]
    assert body["ranked"][0]["source"] != min(r["source"] for r in body["ranked"])


@pg
def test_the_two_counts_are_reported_apart(client):
    """`unlocks_now` and `also_needed_by` must not arrive pre-summed.

    Supplying one file makes `unlocks_now` checks run; the rest still wait on
    another source that is also missing. One combined number promises the whole
    of it for a single upload."""
    run_id = _run_with("on_prem", {"missing": MISSING, "empty": []})
    body = client.get(f"/api/runs/{run_id}/export-value").json()
    for row in body["ranked"]:
        assert "unlocks_now" in row and "also_needed_by" in row


@pg
def test_nothing_missing_answers_an_empty_ranking_not_a_404(client):
    """An upload with every source present is a result, not an absent one."""
    run_id = _run_with("on_prem", {"missing": [], "empty": []})
    resp = client.get(f"/api/runs/{run_id}/export-value")
    assert resp.status_code == 200
    assert resp.json()["ranked"] == []


@pg
def test_a_run_with_no_manifest_invents_nothing(client):
    """`coverage` defaults to {} and a run that failed early keeps it."""
    run_id = _run_with("on_prem", {})
    body = client.get(f"/api/runs/{run_id}/export-value").json()
    assert body["ranked"] == [] and body["missing"] == 0


# --------------------------------------------------------------------------- #
#  Deployment mode                                                             #
# --------------------------------------------------------------------------- #

@pg
def test_rise_moves_unreachable_sources_out_of_the_ranking(client):
    run_id = _run_with("rise_pce", {"missing": MISSING, "empty": []})
    body = client.get(f"/api/runs/{run_id}/export-value").json()

    ranked = {r["source"] for r in body["ranked"]}
    unobtainable = {r["source"] for r in body["unobtainable"]}
    assert {"gw_reginfo", "saprouttab"} <= unobtainable
    assert not ({"gw_reginfo", "saprouttab"} & ranked), \
        "a RISE customer cannot produce these; listing them is advice they " \
        "cannot act on"
    # Still reported, because they are the reason those checks did not run.
    assert unobtainable


@pg
def test_the_mode_comes_from_the_landscape_not_the_manifest(client):
    """A RISE landscape whose manifest predates the deployment_mode key.

    The manifest reads as on_prem, under which nothing is unobtainable. If the
    route trusted it, the two OS-level sources would be presented as the next
    thing to go and fetch."""
    run_id = _run_with("rise_pce", {"missing": MISSING, "empty": []})
    body = client.get(f"/api/runs/{run_id}/export-value").json()
    assert {r["source"] for r in body["unobtainable"]} == {"gw_reginfo", "saprouttab"}


# --------------------------------------------------------------------------- #
#  Access                                                                      #
# --------------------------------------------------------------------------- #

@pg
def test_an_unknown_run_is_404_not_500(client):
    assert client.get("/api/runs/999999999/export-value").status_code == 404


@pg
def test_an_anonymous_caller_gets_401(client):
    from fastapi.testclient import TestClient
    from server import app as appmod
    run_id = _run_with("on_prem", {"missing": MISSING, "empty": []})
    resp = TestClient(appmod.app).get(f"/api/runs/{run_id}/export-value")
    assert resp.status_code == 401


@pg
def test_a_run_outside_the_callers_scope_is_404(client):
    """Same answer as a run that does not exist. A distinguishable 403 turns run
    ids into a probe for which systems an estate has."""
    import json
    from fastapi.testclient import TestClient
    from server import app as appmod, auth, db

    land = db.one("INSERT INTO landscape (name, deployment_mode) VALUES (%s, %s)"
                  " RETURNING id", (f"ev_{os.urandom(3).hex()}", "on_prem"))
    # sid AND client, both non-empty: sap_system_shape_check refuses an ABAP row
    # without them, because an empty sid normalises to the same finding
    # fingerprint as every other empty one.
    mine = db.one("INSERT INTO sap_system (landscape_id, platform, sid, client) "
                  "VALUES (%s, 'abap', 'EVX', '100') RETURNING id", (land["id"],))
    other = db.one("INSERT INTO sap_system (landscape_id, platform, sid, client) "
                   "VALUES (%s, 'abap', 'EVY', '100') RETURNING id", (land["id"],))
    run = db.one(
        "INSERT INTO scan_run (landscape_id, system_id, status, started_at, "
        "coverage) VALUES (%s, %s, 'complete', now(), %s) RETURNING id",
        (land["id"], mine["id"], json.dumps({"missing": MISSING})))

    # A viewer scoped to the OTHER system. Scope is keyed on user id, and an
    # ABSENT scope row means unrestricted — so the row has to exist or this test
    # passes without ever restricting anything.
    name = f"ev_{os.urandom(4).hex()}"
    uid = auth.create_user(name, "api-test-password", "viewer")
    db.execute("INSERT INTO user_system_scope (user_id, system_id) "
               "VALUES (%s, %s)", (uid, other["id"]))

    c = TestClient(appmod.app)
    assert c.post("/api/auth/login",
                  json={"username": name, "password": "api-test-password"}
                  ).status_code == 200
    try:
        assert c.get(f"/api/runs/{run['id']}/export-value").status_code == 404
    finally:
        db.execute("DELETE FROM user_system_scope WHERE user_id = %s", (uid,))
        db.execute("DELETE FROM app_user WHERE id = %s", (uid,))
