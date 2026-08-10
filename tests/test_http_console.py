# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

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

WHAT IT ASSERTS NOW THAT THE PAGES ARE GONE
The templates are deleted and the console is a compiled React bundle, so there is
no server-rendered page left to 500. The failure this file exists to catch did not
go away with them — it MOVED. A screen now renders from a JSON endpoint, and the
same class of bug is an endpoint that raises on a column that does not exist, or
returns 200 with a body missing the key the screen reads. Both look perfect from
the query layer and from the type checker, and both are a blank screen.

So: every endpoint a screen calls is requested over HTTP with a real database
behind it, and its RESPONSE SHAPE is checked — not merely its status. Asserting
only `200` on JSON is weaker than asserting `200` on HTML was, because an empty
body passes it.

WHAT DELIBERATELY IS NOT ASSERTED HERE
Anything about markup. The console composes its screens in the browser, so
"the finding's title is on the page" is a claim about the compiled bundle and
belongs in tests/test_spa_mount.py, which checks the artefact. Reaching for
`resp.text` here would only re-assert that index.html is index.html.
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
    """Signed in through the JSON surface, which is how the console signs in.

    The form POST to /login went with the templates: it answered with a 303 and a
    rendered page, which is exactly what a fetch-based client cannot use.
    """
    from fastapi.testclient import TestClient
    from server import app as appmod, auth, db

    db.init_schema()
    username = f"httptest_{os.urandom(4).hex()}"
    auth.create_user(username, "http-test-password", "admin")

    c = TestClient(appmod.app)
    resp = c.post("/api/auth/login",
                  json={"username": username, "password": "http-test-password"})
    assert resp.status_code == 200, f"login failed: {resp.text[:200]}"
    yield c
    db.execute("DELETE FROM app_user WHERE username = %s", (username,))


@pytest.fixture(scope="module")
def seeded(client):
    """A landscape with one scanned system, so the endpoints have something to say.

    Endpoints that only ever return the empty state would pass this suite while
    every populated one 500s on a column that does not exist.
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


# --------------------------------------------------------------------------- #
#  Every screen's data, over HTTP, with a shape                               #
# --------------------------------------------------------------------------- #
#: endpoint -> the keys the screen that calls it actually reads. One entry per
#: retired Jinja page, plus the filtered queues that were separate page requests.
#: The keys are the load-bearing half: a 200 with a body missing `summary` is a
#: dashboard with four blank panels and a green test.
_SCREEN_ENDPOINTS = [
    ("/api/dashboard", ("summary", "systems", "recent_runs", "crq",
                        "crq_scenarios")),                              # was "/"
    ("/api/findings", ("findings", "total", "page", "pages")),          # was /findings
    ("/api/trend", ("sla", "aging", "mttr", "burndown", "backlog_by_tier",
                    "technical_debt", "teams", "domains")),             # was /trend
    ("/api/risk", ("portfolio", "scenarios", "trend")),                 # was /risk
    ("/api/paths", ("summary", "paths", "chokepoints", "closed",
                    "template_count")),                                 # was /paths
    ("/api/coverage", ("requirements_published", "requirements_covered",
                       "covered", "not_covered", "beyond_baseline",
                       "meta", "our_checks")),                          # was /coverage
    ("/api/account", ("user", "forced", "sessions", "users")),          # was /account
    ("/api/landscapes", ("landscapes",)),                               # was /upload
    ("/api/systems", ("systems",)),                                     # the filter vocabulary
    ("/api/views", ("views",)),                                         # the saved-view list
    # The filter combinations the console puts in the address bar. Each one was a
    # page request before the cutover and is a query-string parse now, which is a
    # different way to get the same 500.
    ("/api/findings?tier=P1", ("findings",)),
    ("/api/findings?owner=ticket_to_sap", ("findings",)),
    ("/api/findings?overdue=true", ("findings",)),
    ("/api/findings?team=basis", ("findings",)),
    ("/api/findings?state=resolved", ("findings",)),
    ("/api/findings?severity=CRITICAL&tier=P1&team=basis", ("findings",)),
    ("/api/trend?days=30", ("sla", "mttr")),
]


@pytest.mark.parametrize("path,keys", _SCREEN_ENDPOINTS,
                         ids=[p for p, _ in _SCREEN_ENDPOINTS])
def test_every_screens_endpoint_answers_with_the_shape_it_promises(client, seeded,
                                                                   path, keys):
    resp = client.get(path)
    assert resp.status_code == 200, f"{path} -> {resp.status_code}: {resp.text[:400]}"
    body = resp.json()
    missing = [k for k in keys if k not in body]
    assert not missing, f"{path} answered 200 without {missing}; the screen renders blank"


def test_the_console_shell_is_served_at_every_screens_address(client, seeded):
    """The other half: the endpoint has data and the address serves the console.

    A 503 is accepted and means the bundle was never built — the routing is what
    is under test here, and requiring `npm run build` would make this skip on CI.
    404 is the failure that matters, and it is the one a missing route gives.
    """
    for screen in ("/", "/findings", "/trend", "/risk", "/paths", "/coverage",
                   "/upload", "/account", "/login"):
        resp = client.get(screen)
        assert resp.status_code in (200, 503), \
            f"{screen} -> {resp.status_code}; the console does not answer there"


def test_finding_and_run_detail_answer_over_the_api(client, seeded):
    """The two detail screens. `latest_details` is named explicitly because it is
    the only route by which a code finding's snippet and taint trace now reach a
    human — the page that used to render them server-side is deleted."""
    from server import db
    fid = db.one("SELECT id FROM finding WHERE landscape_id = %s LIMIT 1",
                 (seeded["landscape"],))["id"]

    finding = client.get(f"/api/findings/{fid}")
    assert finding.status_code == 200, finding.text[:400]
    body = finding.json()
    for key in ("id", "check_id", "title", "state", "remediation", "risk_narrative",
                "latest_details"):
        assert key in body, f"/api/findings/{fid} omits {key}"

    history = client.get(f"/api/findings/{fid}/history")
    assert history.status_code == 200
    assert {"history", "observations"} <= set(history.json())

    run = client.get(f"/api/runs/{seeded['run']}")
    assert run.status_code == 200 and "status" in run.json()
    diff = client.get(f"/api/runs/{seeded['run']}/diff")
    assert diff.status_code == 200


def test_unknown_ids_are_404_not_500(client, seeded):
    """Unchanged in substance, moved to where the answer is now produced.

    /findings/999999999 is answered by the static mount with the console, which
    then asks for the id and gets this 404 — so this is where "no such thing" is
    decided, and where confusing it with a 500 would surface as an error banner
    on a screen that should say the finding does not exist.
    """
    assert client.get("/api/findings/999999999").status_code == 404
    assert client.get("/api/runs/999999999").status_code == 404
    assert client.get("/api/views/no-such-view").status_code == 404
    assert client.get("/api/paths/999999999").status_code == 404


def test_an_anonymous_caller_is_refused_by_the_api_and_still_gets_the_console():
    """The 401 branch that used to redirect a browser to the Jinja sign-in page is
    gone, and it had to be: a fetch follows redirects silently, so answering a 303
    to an HTML page would hand a screen markup where it expected JSON — a 401 that
    presents as a parse error.

    The console is served to an anonymous visitor on purpose. It is a public
    static bundle; AuthGate reads the 401 below and renders the sign-in form. No
    DATA is served without a session, which is the line that matters and is
    asserted here and in tests/test_spa_mount.py.
    """
    from fastapi.testclient import TestClient
    from server import app as appmod

    anon = TestClient(appmod.app, follow_redirects=False)

    api = anon.get("/api/findings")
    assert api.status_code == 401
    assert api.json()["detail"] == "not authenticated"
    assert api.headers.get("location") is None, \
        "the API redirected instead of refusing; a fetch would follow it into HTML"

    screen = anon.get("/findings")
    assert screen.status_code in (200, 503)


def test_login_rejects_a_bad_password_without_leaking_which_part_was_wrong():
    """The JSON surface's rejection, which is now the only one.

    `auth.authenticate` hashes a dummy password for an unknown user so the two
    take the same time, and the message is identical for both. Echoing the
    submitted username back would rebuild the oracle in the response body.
    """
    from fastapi.testclient import TestClient
    from server import app as appmod

    anon = TestClient(appmod.app)
    resp = anon.post("/api/auth/login", json={"username": "nobody",
                                              "password": "wrong"})
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Invalid credentials"
    assert "nobody" not in resp.text


def test_the_open_redirect_is_closed():
    """The hole moved into the client, so this is where it is checked.

    ?next= is gone with the form login — there is no server-side redirect target
    left to poison. The console keeps the same behaviour: AuthGate hands Login the
    path it was heading for, and Login constrains it to a local path before
    navigating. Asserted against the source because it is a client-side decision
    now and nothing over HTTP can observe it.
    """
    login_tsx = (ROOT / "frontend" / "src" / "components" / "Login.tsx").read_text(
        encoding="utf-8")
    assert "startsWith('/')" in login_tsx and "startsWith('//')" in login_tsx, (
        "Login.tsx no longer constrains the post-sign-in destination to a local "
        "path; a crafted link could bounce a freshly-authenticated user off-site")

    from fastapi.testclient import TestClient
    from server import app as appmod

    paths = {r.path for r in appmod.app.routes if hasattr(r, "path")}
    assert "/login" not in paths, \
        "a server-side /login came back; it would need the ?next= guard again"
    # And the only redirect the server still issues goes somewhere local.
    resp = TestClient(appmod.app, follow_redirects=False).get("/ui/findings")
    assert resp.headers["location"].startswith("/") and \
        not resp.headers["location"].startswith("//")


def test_a_viewer_cannot_write(client, seeded):
    """Reading is fine, writing is not. Every write is an /api route now, so the
    /upload page check that used to stand in for "can this person upload" is
    replaced by the endpoint that actually enforces it."""
    from fastapi.testclient import TestClient
    from server import app as appmod, auth, db

    username = f"viewer_{os.urandom(4).hex()}"
    auth.create_user(username, "viewer-test-password", "viewer")
    try:
        c = TestClient(appmod.app)
        c.post("/api/auth/login", json={"username": username,
                                        "password": "viewer-test-password"})
        assert c.get("/api/findings").status_code == 200      # reading is fine
        assert c.post("/api/views", data={"name": "x", "slug": "x"}).status_code == 403
        assert c.post("/api/findings/bulk-state",
                      data={"finding_ids": "1", "state": "open"}).status_code == 403
        assert c.post("/api/upload").status_code == 403
        # The upload SCREEN is still served — it is a static bundle and cannot be
        # role-gated. The nav hides it and the endpoint above refuses, which is
        # where the control lives.
        assert c.get("/upload").status_code in (200, 503)
    finally:
        db.execute("DELETE FROM app_user WHERE username = %s", (username,))


def test_saving_and_opening_a_view_round_trips(client, seeded):
    """The saved view, end to end, through the endpoints the console uses.

    /v/{slug} used to be a server route answering 303 to /findings?…; it is a
    console route now, resolving through /api/views/{slug} and replacing its own
    address. The filters are what travels either way, so the round trip is
    asserted on them rather than on a Location header that no longer exists.
    """
    from server import queries

    slug = f"rt-{os.urandom(4).hex()}"
    resp = client.post("/api/views",
                       data={"name": "Round trip", "slug": slug, "kind": "findings"},
                       headers={"referer": "http://x/findings?team=basis&severity=CRITICAL"})
    assert resp.status_code == 200
    body = resp.json()
    # Filters come from the referring screen: "save this view" means "save what I
    # am looking at", and the console keeps its filters in the address bar so the
    # referer still carries them.
    assert body["filters"] == {"team": "basis", "severity": "CRITICAL"}
    assert body["url"] == f"/v/{slug}", \
        "the returned link is what gets pasted into a ticket"

    resolved = client.get(f"/api/views/{slug}")
    assert resolved.status_code == 200
    assert resolved.json()["filters"] == {"team": "basis", "severity": "CRITICAL"}
    assert resolved.json()["kind"] == "findings"

    # And the address in that link serves the console, which is what makes it a
    # link rather than a JSON endpoint somebody has to know about.
    assert client.get(f"/v/{slug}").status_code in (200, 503)

    queries.delete_view(slug, "test")


def test_health_reports_degradation_rather_than_hiding_it(client):
    """/health is not a console route and outlived the pages for that reason: a
    container healthcheck reads it, it takes no session, and it renders nothing.
    It is declared above the SPA mount, or every probe would be answered with
    index.html and go green over a dead database."""
    resp = client.get("/health")
    assert resp.headers["content-type"].startswith("application/json"), \
        "/health was answered with the console; the mount is above it in the table"
    body = resp.json()
    assert body["status"] in ("ok", "degraded")
    assert isinstance(body["degraded"], list)
