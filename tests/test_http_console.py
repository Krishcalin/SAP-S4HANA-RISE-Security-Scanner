"""
HTTP-level tests for the console.

WHY THIS FILE EARNED ITS PLACE
-------------------------------
Every page in the console was broken and three other layers of testing said it was
fine. `TemplateResponse(name, context)` is the legacy Starlette signature; the
current one is `TemplateResponse(request, name, context)`, and the old form passes
the context dict where the template name belongs. Imports succeeded. Templates
parsed. The query layer was covered by integration tests. Not one page could
render, and only an actual HTTP request revealed it.

So: assert that every route returns 200 with a real database behind it. A console
whose pages 500 is not a console, however good the SQL underneath is.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

pytestmark = pytest.mark.skipif(
    not os.getenv("DB_DSN"), reason="set DB_DSN to a PostgreSQL 16 instance")


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient
    from server import app as appmod, auth, db

    db.init_schema()
    username = f"httptest_{os.urandom(4).hex()}"
    auth.create_user(username, "http-test-password", "admin")

    c = TestClient(appmod.app)
    resp = c.post("/login", data={"username": username,
                                  "password": "http-test-password", "next": "/"},
                  follow_redirects=False)
    assert resp.status_code == 303, f"login failed: {resp.text[:200]}"
    yield c
    db.execute("DELETE FROM app_user WHERE username = %s", (username,))


@pytest.fixture(scope="module")
def seeded(client):
    """A landscape with one scanned system, so the pages have something to render.

    Pages that render only the empty state would pass this suite while every
    populated page 500s on a column that does not exist.
    """
    from server import db, ingest
    from pathlib import Path as P

    sample = ROOT / "sample_data"
    if not sample.is_dir():
        pytest.skip("sample_data not present")

    land = db.one("INSERT INTO landscape (name, deployment_mode) VALUES (%s,'rise_pce') "
                  "RETURNING id", (f"http-{os.urandom(5).hex()}",))["id"]
    sysid = db.one("INSERT INTO sap_system (landscape_id, sid, client, tier) "
                   "VALUES (%s,'PRD','100','prod') RETURNING id", (land,))["id"]
    run = db.one("INSERT INTO scan_run (landscape_id, system_id, status) "
                 "VALUES (%s,%s,'pending') RETURNING id", (land, sysid))["id"]
    ingest.scan_directory(P(sample), land, sysid, run, deployment_mode="rise_pce",
                          default_sid="PRD", default_client="100")
    yield {"landscape": land, "system": sysid, "run": run}
    db.execute("DELETE FROM landscape WHERE id = %s", (land,))


@pytest.mark.parametrize("path", [
    "/", "/findings", "/trend", "/risk", "/paths", "/upload",
    "/api/risk", "/api/paths",
    "/findings?tier=P1",
    "/findings?owner=ticket_to_sap",
    "/findings?overdue=true",
    "/findings?team=basis",
    "/findings?state=resolved",
    "/findings?severity=CRITICAL&tier=P1&team=basis",   # filters combined
    "/trend?days=30",
    "/health", "/api/trend", "/api/findings",
])
def test_every_page_renders(client, seeded, path):
    resp = client.get(path)
    assert resp.status_code == 200, f"{path} -> {resp.status_code}: {resp.text[:400]}"
    assert resp.text, f"{path} rendered nothing"


def test_finding_and_run_detail_render(client, seeded):
    from server import db
    fid = db.one("SELECT id FROM finding WHERE landscape_id = %s LIMIT 1",
                 (seeded["landscape"],))["id"]
    assert client.get(f"/findings/{fid}").status_code == 200
    assert client.get(f"/runs/{seeded['run']}").status_code == 200


def test_unknown_ids_are_404_not_500(client, seeded):
    assert client.get("/findings/999999999").status_code == 404
    assert client.get("/runs/999999999").status_code == 404
    assert client.get("/v/no-such-view").status_code == 404


def test_an_anonymous_browser_is_sent_to_login_and_an_api_client_gets_json():
    from fastapi.testclient import TestClient
    from server import app as appmod

    anon = TestClient(appmod.app)
    page = anon.get("/findings", follow_redirects=False)
    assert page.status_code == 303 and "/login" in page.headers["location"]

    api = anon.get("/api/findings")
    assert api.status_code == 401
    assert api.json()["detail"] == "not authenticated"


def test_login_rejects_a_bad_password_without_leaking_which_part_was_wrong(client):
    from fastapi.testclient import TestClient
    from server import app as appmod

    anon = TestClient(appmod.app)
    resp = anon.post("/login", data={"username": "nobody", "password": "wrong",
                                     "next": "/"})
    assert resp.status_code == 401
    assert "Invalid credentials" in resp.text
    assert "nobody" not in resp.text.replace('name="username"', "")


def test_the_open_redirect_is_closed(client):
    """A phishing link must not be able to bounce a freshly-authenticated user
    off-site via ?next=."""
    from fastapi.testclient import TestClient
    from server import app as appmod, auth, db

    username = f"redir_{os.urandom(4).hex()}"
    auth.create_user(username, "redirect-test-pass", "viewer")
    try:
        anon = TestClient(appmod.app)
        for hostile in ("https://evil.example/", "//evil.example/"):
            resp = anon.post("/login", data={"username": username,
                                            "password": "redirect-test-pass",
                                            "next": hostile},
                             follow_redirects=False)
            assert resp.status_code == 303
            assert resp.headers["location"] == "/", \
                f"open redirect to {hostile!r} was allowed"
    finally:
        db.execute("DELETE FROM app_user WHERE username = %s", (username,))


def test_a_viewer_cannot_reach_analyst_routes(client, seeded):
    from fastapi.testclient import TestClient
    from server import app as appmod, auth, db

    username = f"viewer_{os.urandom(4).hex()}"
    auth.create_user(username, "viewer-test-password", "viewer")
    try:
        c = TestClient(appmod.app)
        c.post("/login", data={"username": username,
                               "password": "viewer-test-password", "next": "/"})
        assert c.get("/findings").status_code == 200      # reading is fine
        assert c.get("/upload").status_code == 403
        assert c.post("/api/views", data={"name": "x", "slug": "x"}).status_code == 403
        assert c.post("/api/findings/bulk-state",
                      data={"finding_ids": "1", "state": "open"}).status_code == 403
    finally:
        db.execute("DELETE FROM app_user WHERE username = %s", (username,))


def test_saving_and_opening_a_view_round_trips(client, seeded):
    from server import queries

    slug = f"rt-{os.urandom(4).hex()}"
    resp = client.post("/api/views",
                       data={"name": "Round trip", "slug": slug, "kind": "findings"},
                       headers={"referer": "http://x/findings?team=basis&severity=CRITICAL"})
    assert resp.status_code == 200
    body = resp.json()
    # Filters come from the referring page: "save this view" means "save what I am
    # looking at".
    assert body["filters"] == {"team": "basis", "severity": "CRITICAL"}

    follow = client.get(f"/v/{slug}", follow_redirects=False)
    assert follow.status_code == 303
    assert "team=basis" in follow.headers["location"]
    assert "severity=CRITICAL" in follow.headers["location"]

    queries.delete_view(slug, "test")


def test_health_reports_degradation_rather_than_hiding_it(client):
    body = client.get("/health").json()
    assert body["status"] in ("ok", "degraded")
    assert isinstance(body["degraded"], list)
