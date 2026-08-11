# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
The SPA mount, and the four ways this exact architecture is known to break.

WHY THIS FILE EARNED ITS PLACE
------------------------------
A sibling product with the same design — a React bundle compiled at build time
and served by the Python process that also serves the API — shipped the first
three of the following. None was caught by its test suite. The fourth arrived
with this repository's own cutover to the root.

1. THE HISTORY FALLBACK NEVER FIRED. Starlette's StaticFiles RAISES
   HTTPException(404); it does not return a 404 response. The fallback was
   written as `if response.status_code == 404`, so every deep link 404'd for
   months. It went unnoticed because "/" is served by the directory index, so
   only a shared URL or a reload on an inner screen ever hit it — and nobody
   tested one.

2. THE BUILD MODE WAS IMPLICIT. The client defaulted to a fixture-reading
   "sample" mode, nothing set the variable that turned it off, and the shipped
   bundle had the whole authentication feature tree-shaken out of it. It passed
   every test, because the tests ran against the source rather than the artefact.

3. A ROUTE WITH NO NAV ENTRY. Reachable only by typing the URL, so the feature
   looked unwired.

4. THE MOUNT AT "/" ATE THE APPLICATION. A Mount at the root matches every path
   there is and Starlette dispatches to the first match, so its POSITION in the
   route table became load-bearing the moment the console left /ui. Registered
   one line too early it answers /api, /health and /static with index.html — a
   200 with a page of HTML where JSON was expected, which surfaces as a parse
   error a long way from the cause.

Most of what follows needs neither a database nor a compiled bundle, on purpose:
a guard that skips on a fresh checkout is a guard that is not there.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest
from starlette.exceptions import HTTPException as StarletteHTTPException

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

FRONTEND = ROOT / "frontend"
INDEX_MARKER = "<!-- monitorrisk-spa-test-index -->"


def _all_paths(app) -> set:
    """Every route path in the app, INCLUDING the ones inside included routers.

    `app.routes` is not flat. FastAPI wraps `include_router` in an
    `_IncludedRouter` that has no `path` of its own and keeps the real routes on
    `original_router`, so the obvious one-line comprehension silently omits every
    /api/auth and /api/account route — and a test asserting "the replacement
    exists" fails on a replacement that is right there. Recursing is the
    difference between checking the route table and checking the top of it.

    Both `routes` and `original_router.routes` are followed because the wrapper is
    a FastAPI implementation detail: a version that flattens the router again, or
    exposes it under the ordinary attribute, must not turn this into a test that
    quietly stops looking.
    """
    found = set()

    def walk(routes):
        for route in routes:
            path = getattr(route, "path", None)
            if path is not None:
                found.add(path)
            walk(getattr(route, "routes", None) or [])
            inner = getattr(route, "original_router", None)
            if inner is not None:
                walk(getattr(inner, "routes", None) or [])

    walk(app.routes)
    return found


@pytest.fixture()
def spa_app(tmp_path):
    """A minimal app carrying the real SpaFiles over a synthetic bundle.

    Synthetic rather than the compiled one so this runs on a checkout where
    nobody has installed Node — the fallback logic is the thing under test, and
    it must not be excused by a missing build.

    Mounted at "/" like the real one. There is nothing else on this app, so the
    ordering hazard that comes with a root mount cannot show up here; it is
    tested against the REAL app further down, which is the only place it exists.
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from server.app import SpaFiles

    (tmp_path / "index.html").write_text(
        f"<!doctype html><html><body>{INDEX_MARKER}</body></html>", encoding="utf-8")
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "app.js").write_text("export const x = 1\n", encoding="utf-8")

    app = FastAPI()
    app.mount("/", SpaFiles(directory=str(tmp_path), html=True, check_dir=False),
              name="spa")
    return TestClient(app)


# --------------------------------------------------------------------------- #
#  Trap 1 — the raised 404                                                    #
# --------------------------------------------------------------------------- #

def test_staticfiles_RAISES_the_404_rather_than_returning_one(tmp_path):
    """The mechanism the fallback has to handle, asserted directly.

    If a future Starlette starts RETURNING the 404 instead, this test fails and
    tells the next reader that `SpaFiles.get_response`'s second branch — the one
    that looks redundant — is now the live one.
    """
    import anyio
    from starlette.staticfiles import StaticFiles

    files = StaticFiles(directory=str(tmp_path), html=True, check_dir=False)
    scope = {"type": "http", "method": "GET", "headers": []}

    with pytest.raises(StarletteHTTPException) as caught:
        anyio.run(lambda: files.get_response("no-such-path", scope))
    assert caught.value.status_code == 404


@pytest.mark.parametrize("deep_link", [
    "/findings/123",          # the canonical case: a shared link to one finding
    "/findings",
    "/paths/7",
    "/runs/42",
    "/v/quarterly-board-view",  # a saved view — the whole point of saved views
    "/login",
    "/account",
])
def test_a_deep_link_returns_index_html(spa_app, deep_link):
    """Every one of these is a URL somebody pastes into a message or reloads on.

    This is the test the sibling product did not have. Every path here was a
    server-rendered page until the cutover, so each one is also a URL that
    predates the SPA and has to keep working — see the paths test further down,
    which asserts the same list against the REAL app.
    """
    resp = spa_app.get(deep_link)
    assert resp.status_code == 200, f"{deep_link} did not resolve to the SPA"
    assert INDEX_MARKER in resp.text, f"{deep_link} served something other than index.html"
    assert resp.headers["content-type"].startswith("text/html")


def test_the_mount_root_serves_the_console(spa_app):
    resp = spa_app.get("/")
    assert resp.status_code == 200 and INDEX_MARKER in resp.text


def test_a_real_asset_is_served_as_itself(spa_app):
    """The fallback must not swallow the bundle it exists to deliver."""
    resp = spa_app.get("/assets/app.js")
    assert resp.status_code == 200
    assert "export const x" in resp.text
    assert "javascript" in resp.headers["content-type"]


@pytest.mark.parametrize("missing", [
    "/assets/index-deadbeef.js",
    "/assets/index-deadbeef.css",
    "/favicon.png",
])
def test_a_missing_ASSET_404s_instead_of_being_answered_with_html(spa_app, missing):
    """A missing hashed asset is a broken build, not a route.

    Answering it with index.html turns a clear 404 into a MIME-type error inside
    the module loader, which gets reported as "the app is blank" — a much longer
    walk to the same cause.
    """
    resp = spa_app.get(missing)
    assert resp.status_code == 404
    assert INDEX_MARKER not in resp.text


@pytest.mark.parametrize("api_path", [
    "/api/findigs",              # a typo — the shape this actually takes
    "/api/v2/findings",          # a version that does not exist
    "/api/",
])
def test_an_UNMATCHED_api_path_404s_instead_of_being_answered_with_html(spa_app, api_path):
    """New with the root mount, and the sharpest edge on it.

    At /ui the mount could never see an /api request. At "/" it is the last route
    in the table, so every /api path no real route claimed lands here — and
    answering an integrator's typo with 200 and a page of HTML breaks their JSON
    decoder somewhere with no relationship to the mistake. A 404 is the answer
    they can act on.
    """
    resp = spa_app.get(api_path)
    assert resp.status_code == 404, \
        f"{api_path} was answered with the console instead of a 404"
    assert INDEX_MARKER not in resp.text


def test_the_mount_does_not_serve_the_rest_of_the_disk(spa_app):
    for probe in ("/../app.py", "/..%2fapp.py", "/....//app.py",
                  "/../../requirements.txt"):
        resp = spa_app.get(probe)
        assert resp.status_code != 200 or INDEX_MARKER in resp.text, \
            f"{probe} escaped the SPA directory"
        assert b"SESSION_COOKIE" not in resp.content


def test_an_unbuilt_bundle_reports_itself_instead_of_404ing_quietly(tmp_path):
    """A fresh checkout with no `npm run build` is a normal state, and an image
    shipped without its frontend is a build failure. Both must be legible: a bare
    404 reads as a mistyped URL and would send someone hunting for a routing bug.

    It matters more now than it did at /ui. The console is the root, so an image
    missing its bundle answers EVERY screen with this — and the API answers
    normally right beside it, which is what turns "the product is down" into "the
    frontend did not build".
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from server.app import SpaFiles

    empty = tmp_path / "never-built"
    app = FastAPI()
    app.mount("/", SpaFiles(directory=str(empty), html=True, check_dir=False),
              name="spa")
    resp = TestClient(app).get("/findings")
    assert resp.status_code == 503
    assert "npm run build" in resp.json()["detail"]


# --------------------------------------------------------------------------- #
#  Trap 2 — the artefact must match the source                                #
# --------------------------------------------------------------------------- #

def _vite_base() -> str:
    text = (FRONTEND / "vite.config.ts").read_text(encoding="utf-8")
    match = re.search(r"^\s*base:\s*'([^']+)'", text, re.M)
    assert match, "vite.config.ts no longer declares a `base` — the mount cannot agree with it"
    return match.group(1)


def test_the_server_mount_and_vite_base_agree():
    """`base` is baked into every asset URL at build time, so it cannot be
    configuration. A bundle built for one prefix and mounted at another serves a
    blank page with four 404s in the console — and the two halves of that change
    live in different languages, in different directories, which is exactly how
    one of them gets made without the other.

    Both are now the ROOT. The comparison below normalises the trailing slash
    (vite wants '/ui/', the mount wants '/ui'), which at the root would let two
    empty strings agree with each other — so the value is also asserted outright,
    or a `base` of '' would pass while emitting relative asset URLs that break on
    every deep link.
    """
    from server.app import SPA_MOUNT_PATH

    assert _vite_base().rstrip("/") == SPA_MOUNT_PATH.rstrip("/"), (
        f"vite base {_vite_base()!r} does not match SPA_MOUNT_PATH "
        f"{SPA_MOUNT_PATH!r}; the built bundle will not load")
    assert SPA_MOUNT_PATH == "/" and _vite_base() == "/", (
        f"the console is meant to own the root; found mount {SPA_MOUNT_PATH!r} "
        f"and vite base {_vite_base()!r}")


def test_vite_builds_into_the_directory_the_server_serves():
    from server.app import SPA_DIR

    text = (FRONTEND / "vite.config.ts").read_text(encoding="utf-8")
    match = re.search(r"outDir:\s*'([^']+)'", text)
    assert match, "vite.config.ts no longer declares an outDir"
    resolved = (FRONTEND / match.group(1)).resolve()
    assert resolved == SPA_DIR.resolve(), (
        f"vite writes to {resolved}, the server serves {SPA_DIR.resolve()}")


def test_the_image_compiles_the_spa_rather_than_trusting_the_context():
    """The bundle must be produced BY the image. The sibling product's missing
    feature shipped because the build was a manual step, and the tests all ran
    against source that was fine."""
    docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "AS spa" in docker, "the Dockerfile has no SPA build stage"
    assert "npm ci" in docker, "the SPA stage must install from the lock file"
    assert "npm run build" in docker, "the SPA stage never builds the bundle"
    assert "COPY --from=spa" in docker, "the built bundle never reaches the runtime image"

    ignored = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    assert "server/spa/" in ignored, \
        "a host-built server/spa could be copied into the image ahead of the real one"
    # Vite loads frontend/.env at build time and INLINES what it finds — verified
    # by building with one present and finding the value in the emitted chunk. A
    # file left on a developer's disk would therefore rewrite the shipped bundle
    # with nothing in the image to show for it, which is trap 2's exact shape.
    assert "frontend/.env" in ignored, \
        "a stray frontend/.env would be copied into the build context and baked in"


def test_the_build_command_type_checks():
    """`npm run build` is what the image runs. If it does not type-check, a type
    error reaches the artefact and the only thing that would have caught it is a
    developer remembering to run tsc."""
    import json
    pkg = json.loads((FRONTEND / "package.json").read_text(encoding="utf-8"))
    build = pkg["scripts"]["build"]
    assert "tsc" in build, f"`npm run build` does not type-check: {build!r}"
    assert "vite build" in build


def test_the_type_check_command_actually_checks_something():
    """The documented command is `npx tsc --noEmit -p tsconfig.json`. A
    solution-style tsconfig (`"files": []` plus references) makes that exit 0
    without reading a line of src/ — a green check that cannot fail, which is
    how the sibling product's config is written.

    Matched with a regex rather than json.loads: tsconfig is JSONC and carries
    the comments that explain this decision, so parsing it as JSON would fail on
    the file being correct."""
    text = (FRONTEND / "tsconfig.json").read_text(encoding="utf-8")
    include = re.search(r'"include"\s*:\s*\[([^\]]*)\]', text)
    assert include, "tsconfig.json has no `include` — the type-check command is a no-op"
    assert '"src"' in include.group(1), \
        "tsconfig.json does not include src — the type-check command is a no-op"


@pytest.mark.parametrize("forbidden", ["VITE_DATA_SOURCE", "DATA_MODE", "/sample/"])
def test_the_console_has_no_offline_sample_mode(forbidden):
    """There is one mode and it talks to the API.

    MonitorRisk is an OFFLINE scanner whose entire value is that the numbers came
    from the customer's own exports. A console able to render plausible findings
    from a bundled fixture is a liability, and the sibling product proved it is
    also how a whole feature disappears from a shipped bundle.
    """
    offenders = [
        p.relative_to(ROOT).as_posix()
        for p in sorted((FRONTEND / "src").rglob("*.ts*"))
        if forbidden in p.read_text(encoding="utf-8")
    ]
    assert not offenders, f"{forbidden!r} appears in: {', '.join(offenders)}"


# --------------------------------------------------------------------------- #
#  Trap 3 — every route is reachable by clicking                              #
# --------------------------------------------------------------------------- #

def test_every_nav_destination_is_a_route_or_the_catch_all():
    """A nav entry pointing at nothing is a dead link; a route with no nav entry
    is a feature nobody finds. This checks the first half — the second cannot be
    checked statically for parameterised screens, which is why nav.ts names them
    and says how they are reached instead."""
    nav = (FRONTEND / "src" / "lib" / "nav.ts").read_text(encoding="utf-8")
    destinations = set(re.findall(r"to:\s*'([^']+)'", nav))
    assert destinations, "nav.ts declares no destinations at all"
    for dest in destinations:
        assert dest.startswith("/"), f"nav entry {dest!r} is not an absolute path"

    app_tsx = (FRONTEND / "src" / "App.tsx").read_text(encoding="utf-8")
    assert 'path="*"' in app_tsx, (
        "App.tsx has no catch-all, so an address with no route would render a "
        "blank layout that reads as a screen with no data")


#: Routes that are reachable by clicking but cannot appear in a static menu.
#: /login is not a destination — AuthGate sends people there and TopBar's sign-out
#: lands there — and a menu entry for it inside the signed-in console would be a
#: door back to a screen you are already past.
_ROUTES_WITHOUT_A_MENU_ENTRY = {"/login"}


def test_every_STATIC_route_has_a_nav_entry():
    """The other half, and the half that actually bit the sibling product.

    It shipped its two-factor enrolment screen as a <Route> nobody linked, so the
    whole feature looked unwired for a release. A parameterised route (/findings/:id,
    /paths/:id, /runs/:id, /v/:slug) genuinely cannot be in a menu — there is no
    single URL — and those are reached by clicking a row on the list above them.
    A route with a FIXED path has no such excuse, and this asserts it.
    """
    app_tsx = (FRONTEND / "src" / "App.tsx").read_text(encoding="utf-8")
    nav = (FRONTEND / "src" / "lib" / "nav.ts").read_text(encoding="utf-8")
    destinations = set(re.findall(r"to:\s*'([^']+)'", nav))

    routes = set(re.findall(r'<Route\s+path="([^"]+)"', app_tsx))
    static = {r for r in routes
              if ":" not in r and r != "*" and r not in _ROUTES_WITHOUT_A_MENU_ENTRY}
    assert static, "App.tsx declares no fixed-path routes at all"

    orphans = sorted(static - destinations)
    assert not orphans, (
        f"{orphans} are routes with a fixed URL and no nav entry — reachable only "
        f"by typing the address. Add them to src/lib/nav.ts, or link them from a "
        f"screen and record why here.")


def test_the_shell_lists_saved_views_because_their_urls_are_parameterised():
    """/v/:slug cannot appear in a static nav table, and a saved view nobody can
    click is the incumbent's problem (batch-exporting PDFs) with extra steps."""
    sidebar = (FRONTEND / "src" / "components" / "Sidebar.tsx").read_text(encoding="utf-8")
    assert "/v/${" in sidebar, "the sidebar does not link saved views"
    assert "views()" in sidebar, "the sidebar does not fetch the saved-view list"


def test_the_console_is_reached_by_going_to_the_product(spa_app):
    """Trap 3 at the scale of the whole migration, and the reason the mount moved.

    This used to assert that base.html carried a link into the React console: the
    SPA was mounted under a prefix no page linked, a signed-in user landed on the
    server-rendered dashboard, and nothing anywhere mentioned a second console
    existed. Reachable only by someone who had read server/app.py is the same
    failure as the sibling product's unlisted enrolment screen, with the whole
    deliverable behind it. Mounting it was not the same thing as shipping it.

    The fix was not a better link. It was giving the console the address people
    already type, which is what this now asserts — nobody has to be told where it
    is, and there is no longer a second console to be told about.
    """
    from server.app import SPA_MOUNT_PATH

    assert SPA_MOUNT_PATH == "/", \
        "the console is behind a prefix again; nothing links to it and nobody will find it"
    resp = spa_app.get("/")
    assert resp.status_code == 200 and INDEX_MARKER in resp.text


# --------------------------------------------------------------------------- #
#  Trap 4 — the root mount and everything it can eat                          #
# --------------------------------------------------------------------------- #

def test_the_spa_mount_is_the_LAST_route_in_the_table():
    """The whole application depends on one line's position.

    Starlette dispatches to the first route that matches and a Mount at "/"
    matches everything, so anything registered after it is dead. The failure is
    silent — the route still exists, it just never runs, and the caller gets 200
    and a page of HTML — which is why this is asserted structurally rather than
    left to whoever adds the next endpoint noticing the comment.
    """
    from starlette.routing import Mount
    from server import app as appmod

    routes = appmod.app.routes
    spa = [i for i, r in enumerate(routes)
           if isinstance(r, Mount) and getattr(r, "name", None) == "spa"]
    assert len(spa) == 1, f"expected exactly one SPA mount, found {len(spa)}"
    assert spa[0] == len(routes) - 1, (
        f"the SPA mount is at position {spa[0]} of {len(routes)}; every route "
        f"after it is unreachable: "
        f"{[getattr(r, 'path', r) for r in routes[spa[0] + 1:]]}")


def test_the_api_still_fails_closed_for_an_anonymous_caller():
    """Mounting a public directory at the ROOT must not have made anything else
    public. The API is the security boundary and this is it, unchanged.

    It matters more than it did at /ui: the mount now sits over every path, so a
    route that stopped matching for any reason would be answered by a public
    static directory rather than 404ing. A 200 with the console in it is not a
    leak of data, but it IS how one would first present.
    """
    from fastapi.testclient import TestClient
    from server import app as appmod

    anon = TestClient(appmod.app)
    for path in ("/api/findings", "/api/dashboard", "/api/paths", "/api/risk",
                 "/api/auth/me", "/api/account"):
        resp = anon.get(path)
        assert resp.status_code == 401, f"{path} answered {resp.status_code} to an anonymous caller"
        assert resp.json()["detail"] == "not authenticated"


def test_the_operational_and_asset_routes_survived_the_cutover():
    """Three routes that LOOK like part of the retired console and are not.

    Each one was checked against what it is for rather than where it sits in the
    file: /health is read by the container healthcheck and takes no session,
    /static carries the brand assets the compiled index.html names by absolute
    path, and both are declared above the mount or the mount would answer them.
    Deleting either is invisible in a test run and obvious in production.
    """
    from fastapi.testclient import TestClient
    from server import app as appmod

    paths = {r.path for r in appmod.app.routes if hasattr(r, "path")}
    assert "/health" in paths, "the operational probe was retired with the pages"
    assert "/static" in paths, "the brand assets the console loads are no longer served"

    anon = TestClient(appmod.app)
    # Unauthenticated on purpose: the sign-in screen carries the logo, and a gated
    # mount renders a broken image to exactly the people not signed in yet.
    assert anon.get("/static/monitorrisk-logo.png").status_code == 200


def test_the_jinja_page_routes_are_gone_and_the_spa_answers_their_paths():
    """The cutover, stated as one assertion.

    Every path below was a server-rendered page. None may still be a route in
    this application — a leftover would SHADOW the console at that address, since
    an explicit route always beats the mount, and the screen behind it would
    become unreachable while looking fine. All of them must still RESOLVE,
    because each one is a URL in somebody's bookmarks or in a ticket.

    Answered with the real app, so this is the paths as a browser meets them.
    """
    from fastapi.testclient import TestClient
    from server import app as appmod

    retired = ("/", "/findings", "/findings/{finding_id}", "/trend", "/paths",
               "/paths/{path_id}", "/risk", "/coverage", "/upload", "/account",
               "/runs/{run_id}", "/v/{slug}", "/login")
    paths = _all_paths(appmod.app)
    survivors = sorted(p for p in retired if p in paths)
    assert not survivors, (
        f"{survivors} are still server routes; they would shadow the console's own "
        f"screens at those addresses")

    # The POST targets of the retired forms, which the JSON API replaced. Named in
    # pairs on purpose: "the route is gone" on its own is satisfied by deleting a
    # feature, and what happened here is that it moved.
    for gone, replacement in (("/logout", "/api/auth/logout"),
                              ("/account/password", "/api/account/password"),
                              ("/account/reset/{user_id}", "/api/account/reset/{user_id}")):
        assert gone not in paths, f"{gone} outlived the form that posted to it"
        assert replacement in paths, f"{replacement} is missing, so {gone} had no successor"


@pytest.mark.parametrize("bookmarked", [
    "/", "/findings", "/findings/123", "/trend", "/paths", "/paths/7", "/risk",
    "/coverage", "/upload", "/account", "/runs/42", "/v/quarterly-board-view",
    "/login",
    "/findings?team=basis&severity=CRITICAL",   # a filtered queue somebody saved
])
def test_a_url_from_before_the_cutover_still_resolves(bookmarked):
    """Anything a person could have pasted into a ticket has to keep working.

    These need no redirect: the console declares every one of them at the SAME
    path the pages used, which is why the cutover added exactly one redirect
    (/ui) and not fourteen. That is a claim about App.tsx's route table, so it is
    checked rather than assumed.

    A 503 is a PASS here and is the unbuilt-bundle answer — the routing is what is
    under test, and requiring a compiled bundle would make this skip on the
    checkout where it is most useful. 404 and 401 are the failures worth naming.
    """
    from fastapi.testclient import TestClient
    from server import app as appmod

    resp = TestClient(appmod.app).get(bookmarked)
    assert resp.status_code in (200, 503), \
        f"{bookmarked} answered {resp.status_code} — a link in the world just broke"


@pytest.mark.parametrize("old,new", [
    ("/ui", "/"),
    ("/ui/", "/"),
    ("/ui/findings", "/findings"),
    ("/ui/findings/123", "/findings/123"),
    ("/ui/v/quarterly-board-view", "/v/quarterly-board-view"),
    ("/ui/account", "/account"),
])
def test_the_retired_ui_prefix_redirects_rather_than_rendering_the_wrong_screen(old, new):
    """The one redirect this cutover needed, and why it is not optional.

    /ui was a live console for the whole migration and its URLs were shared. It
    would "work" without this — the root mount answers everything with
    index.html — and react-router, whose basename is now "/", would match no
    route for "/ui/findings/123" and render the catch-all. A silent wrong screen
    is worse than a 404, and much worse than a redirect.
    """
    from fastapi.testclient import TestClient
    from server import app as appmod

    resp = TestClient(appmod.app, follow_redirects=False).get(old)
    assert resp.status_code == 301, \
        f"{old} answered {resp.status_code}; a bookmark from the migration is broken"
    assert resp.headers["location"] == new


def test_the_ui_redirect_answers_HEAD_as_well_as_GET():
    """FastAPI's `@app.get` registers GET only — Starlette's own Route quietly adds
    HEAD, FastAPI's APIRoute does not — so a bare decorator here leaves HEAD
    unmatched and the root mount answers it 200 with the console.

    That is not cosmetic. A link checker or a proxy probing with HEAD would be
    told the retired prefix is alive while every browser following it is
    redirected: two different answers about one URL, and the authoritative-looking
    one is wrong.
    """
    from fastapi.testclient import TestClient
    from server import app as appmod

    c = TestClient(appmod.app, follow_redirects=False)
    for path in ("/ui", "/ui/findings/123"):
        head = c.head(path)
        assert head.status_code == 301, \
            f"HEAD {path} answered {head.status_code}; only GET is redirected"
        assert head.headers["location"] == c.get(path).headers["location"], \
            f"HEAD and GET disagree about where {path} went"


def test_the_ui_redirect_carries_the_query_string():
    """Half of what makes these links worth keeping is in the query string: a
    saved triage queue that arrives without its filters shows the wrong list and
    says nothing about it."""
    from fastapi.testclient import TestClient
    from server import app as appmod

    resp = TestClient(appmod.app, follow_redirects=False).get(
        "/ui/findings?team=basis&severity=CRITICAL")
    assert resp.status_code == 301
    assert resp.headers["location"] == "/findings?team=basis&severity=CRITICAL"


@pytest.mark.parametrize("crafted", [
    "/ui//evil.example.com",           # the clean exploit: Location: //evil.example.com
    "/ui//evil.example.com/findings",  # with a plausible-looking tail on it
    "/ui////evil.example.com",         # more slashes, same idea
    "/ui/%2f%2fevil.example.com",      # Starlette decodes this before we see it
    "/ui/\\\\evil.example.com",        # browsers fold "\" to "/" parsing a Location
])
def test_the_retired_prefix_cannot_be_used_to_redirect_off_site(crafted):
    """The redirect this cutover added is the only user-controlled Location left,
    and it has to build a LOCAL path out of whatever follows /ui/.

    `/ui/{rest:path}` captures everything after the prefix, so a bare f"/{rest}"
    turns `/ui//evil.example.com` into `Location: //evil.example.com` — a
    protocol-relative URL that a browser resolves against the current scheme and
    follows straight off-site. Unauthenticated, on the one prefix the release
    notes tell people is still safe to click, and cached hard because it is a 301.

    It lives here rather than beside `test_the_open_redirect_is_closed` in
    tests/test_http_console.py deliberately: that file skips without DB_DSN, and a
    guard against a redirect hole must not be a guard that disappears on the
    checkout where somebody is editing the redirect.
    """
    from fastapi.testclient import TestClient
    from server import app as appmod

    resp = TestClient(appmod.app, follow_redirects=False).get(crafted)
    assert resp.status_code == 301
    location = resp.headers["location"]
    assert location.startswith("/") and not location.startswith("//"), (
        f"{crafted} redirects to {location!r} — a browser leaves the site")
    assert "\\" not in location, (
        f"{crafted} redirects to {location!r}; a browser reads \\ as / and the "
        f"leading-slash check above would not have seen it")
    # "/evil.example.com" is a perfectly good answer: it is a path on THIS host, it
    # names no screen, and the console renders its not-found page. The defect is
    # never the hostname in the string — it is the second slash in front of it.


def test_an_unknown_api_path_is_a_404_on_the_real_app():
    """Trap 4 as an integrator meets it. `_index_or_404` is the thing that stops
    a mistyped endpoint being answered with the console; this is that guard
    behind the real route table, where a real /api route must NOT be caught by
    it."""
    from fastapi.testclient import TestClient
    from server import app as appmod

    anon = TestClient(appmod.app)
    missing = anon.get("/api/findigs")
    assert missing.status_code == 404, \
        "a mistyped API path was answered with the console"
    assert "<div id=" not in missing.text

    # ...and a real one is still reached, refusing on authentication rather than
    # on routing. A 404 here would mean the guard had swallowed the API itself.
    assert anon.get("/api/findings").status_code == 401


def test_the_runtime_dependency_list_is_four_and_lost_jinja2():
    """React, Vite and TypeScript are BUILD-time dependencies. If one of them
    ever appears here, the deployment has quietly grown a second service.

    It was five. jinja2 left with server/templates/ — the console is compiled
    TypeScript now and nothing server-side renders HTML — which makes this the
    rare migration that REMOVED a runtime dependency instead of trading one for
    another. Asserted verbatim, in order, so neither an addition nor a quiet
    re-pin of jinja2 passes.
    """
    reqs = [line.split("[")[0].split(">")[0].split("=")[0].strip().lower()
            for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")]
    assert reqs == ["fastapi", "uvicorn", "psycopg", "python-multipart"], \
        f"the pinned runtime dependency list changed: {reqs}"


def test_nothing_in_the_server_imports_jinja2_any_more():
    """The other half of dropping it: an unpinned import is an ImportError in the
    image and a passing test on a developer's machine, where the package is still
    installed from an older requirements.txt.

    Includes `fastapi.templating`, which is the one that would be missed —
    importing it is what pulled jinja2 in, and it reads like part of FastAPI
    rather than like a dependency.
    """
    offenders = []
    for path in sorted((ROOT / "server").rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if not (stripped.startswith("import ") or stripped.startswith("from ")):
                continue
            if "jinja2" in stripped.lower() or "fastapi.templating" in stripped:
                offenders.append(f"{path.relative_to(ROOT).as_posix()}: {stripped}")
    assert not offenders, \
        "jinja2 is unpinned but still imported: " + "; ".join(offenders)


def test_the_templates_directory_is_gone():
    """A leftover template renders nothing and misleads everything: it reads as a
    live page to the next person and to every grep."""
    assert not (ROOT / "server" / "templates").exists(), \
        "server/templates/ survived the cutover"


# --------------------------------------------------------------------------- #
#  The compiled bundle, when one exists                                       #
# --------------------------------------------------------------------------- #

built = pytest.mark.skipif(
    not (ROOT / "server" / "spa" / "index.html").is_file(),
    reason="run `npm run build` in frontend/ to exercise the compiled bundle")


@built
def test_the_real_mount_serves_a_real_deep_link():
    from fastapi.testclient import TestClient
    from server import app as appmod

    resp = TestClient(appmod.app).get("/findings/123")
    assert resp.status_code == 200
    assert "<div id=\"root\">" in resp.text


@built
def test_the_shipped_bundle_contains_the_authentication_code():
    """Trap 2, checked against the ARTEFACT rather than the source. This is the
    assertion the sibling product's suite was missing: its login screen existed
    in src/ and had been tree-shaken out of the file it shipped."""
    js = "".join(p.read_text(encoding="utf-8", errors="ignore")
                 for p in (ROOT / "server" / "spa" / "assets").glob("*.js"))
    assert "/auth/login" in js, "the sign-in call is not in the compiled bundle"
    assert "/auth/me" in js, "the session check is not in the compiled bundle"


@built
def test_the_bundle_asks_for_assets_under_the_path_the_server_serves():
    """The stale-bundle check, and the one the move to the root could break
    silently: a server/spa built before the flip names /ui/assets/… , which the
    root mount answers with a 301 to /assets/… that no longer exists.

    SPA_MOUNT_PATH is "/" so the prefix test is trivially true — every absolute
    URL starts with it — which is precisely why the old /ui prefix is named
    explicitly as a thing that must NOT appear.
    """
    from server.app import SPA_MOUNT_PATH

    index = (ROOT / "server" / "spa" / "index.html").read_text(encoding="utf-8")
    urls = [m.group(1) for m in re.finditer(r'(?:src|href)="(/[^"]+)"', index)]
    assert urls, "index.html requests no assets at all — that is not a built bundle"
    for url in urls:
        if url.startswith("/static/"):
            continue                     # brand assets, served by the other mount
        assert url.startswith(SPA_MOUNT_PATH), \
            f"index.html requests {url}, which the SPA mount does not serve"
        assert not url.startswith("/ui/"), (
            f"index.html requests {url} — this bundle was built for the retired "
            f"/ui prefix; re-run `npm run build` in frontend/")


@built
@pytest.mark.skipif(bool(os.getenv("MONITORRISK_SKIP_BRAND")), reason="opt-out")
def test_the_console_carries_the_product_brand_not_the_sibling_product():
    """A rebrand — or, here, a port from another product's shell — is the kind of
    change that looks complete and is not."""
    index = (ROOT / "server" / "spa" / "index.html").read_text(encoding="utf-8")
    assert "MonitorRisk" in index
    assert "OverWatch" not in index

    src = "".join(p.read_text(encoding="utf-8")
                  for p in sorted((FRONTEND / "src").rglob("*.ts*")))
    assert "overwatch" not in src.lower(), "the sibling product's brand survived the port"


# --------------------------------------------------------------------------- #
#  Trap 5 — the frontend source, served to anyone who could reach the login   #
# --------------------------------------------------------------------------- #

def test_source_maps_are_never_served(spa_app, tmp_path):
    """A map beside a bundle must 404 even though the file is right there.

    HOW THIS WAS BELIEVED FIXED AND WAS NOT. vite's `sourcemap: 'hidden'` omits
    the //# sourceMappingURL comment, and the config comment recorded that as the
    remedy — the maps "are not advertised". But index.html advertises
    /assets/index-<hash>.js by name, the map is that name plus ".map", and this
    mount is unauthenticated because the sign-in screen has to load from it. The
    URL was derivable by anyone who could reach the login page, and it returned
    1,808,208 bytes of TypeScript with `sourcesContent` inlined.

    The map is WRITTEN into the synthetic bundle here on purpose. A test that only
    asserted the build no longer emits maps would pass on an empty directory and
    prove nothing about what the server does with one.
    """
    (tmp_path / "assets" / "app.js.map").write_text(
        '{"version":3,"sourcesContent":["const secret = 1"]}', encoding="utf-8")

    # The file is present and readable...
    assert (tmp_path / "assets" / "app.js.map").is_file()
    # ...the bundle beside it is served...
    assert spa_app.get("/assets/app.js").status_code == 200
    # ...and the map is not.
    r = spa_app.get("/assets/app.js.map")
    assert r.status_code == 404, \
        "the frontend source is being served to unauthenticated callers"
    assert "sourcesContent" not in r.text


def test_source_maps_are_refused_by_the_server_not_only_by_the_build(spa_app, tmp_path):
    """Case matters, and so does where the guard lives.

    The refusal is in server/app.py rather than in vite.config.ts because the build
    config is one line in another language in another directory, and the server is
    what actually hands bytes to the internet. A map that reappears — a vite
    default changing, a plugin emitting its own, someone flipping `true` while
    debugging — must be refused by the thing serving it.
    """
    (tmp_path / "assets" / "UPPER.JS.MAP").write_text("{}", encoding="utf-8")
    assert spa_app.get("/assets/UPPER.JS.MAP").status_code == 404

    src = (ROOT / "server" / "app.py").read_text(encoding="utf-8")
    assert '.map' in src and 'endswith(".map")' in src, \
        "the .map refusal has left server/app.py; the build config alone does not " \
        "close this, because it only governs what is written, not what is served"


@built
def test_the_compiled_bundle_does_not_expose_its_map(tmp_path):
    """The same claim against the REAL artefact and the REAL app.

    The synthetic test proves SpaFiles refuses a .map. This proves the map that
    actually exists, at the name actually derivable from the shipped index.html,
    is not reachable — which is the claim a reader cares about.
    """
    import re as _re
    from fastapi.testclient import TestClient
    from server.app import app

    index = (ROOT / "server" / "spa" / "index.html").read_text(encoding="utf-8")
    bundles = _re.findall(r'src="(/assets/[^"]+\.js)"', index)
    assert bundles, "index.html names no JS bundle — that is not a built bundle"

    client = TestClient(app)
    for bundle in bundles:
        # Derived exactly the way an attacker derives it: read the public
        # index.html, append four characters.
        r = client.get(bundle + ".map")
        assert r.status_code == 404, (
            f"{bundle}.map is served to unauthenticated callers "
            f"({len(r.content)} bytes)")
