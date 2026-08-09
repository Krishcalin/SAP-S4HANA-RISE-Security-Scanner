"""
The SPA mount, and the three ways this exact architecture is known to break.

WHY THIS FILE EARNED ITS PLACE
------------------------------
A sibling product with the same design — a React bundle compiled at build time
and served by the Python process that also serves the API — shipped all three of
the following. None was caught by its test suite.

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


@pytest.fixture()
def spa_app(tmp_path):
    """A minimal app carrying the real SpaFiles over a synthetic bundle.

    Synthetic rather than the compiled one so this runs on a checkout where
    nobody has installed Node — the fallback logic is the thing under test, and
    it must not be excused by a missing build.
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from server.app import SpaFiles

    (tmp_path / "index.html").write_text(
        f"<!doctype html><html><body>{INDEX_MARKER}</body></html>", encoding="utf-8")
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "app.js").write_text("export const x = 1\n", encoding="utf-8")

    app = FastAPI()
    app.mount("/ui", SpaFiles(directory=str(tmp_path), html=True, check_dir=False),
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
    "/ui/findings/123",          # the canonical case: a shared link to one finding
    "/ui/findings",
    "/ui/paths/7",
    "/ui/runs/42",
    "/ui/v/quarterly-board-view",  # a saved view — the whole point of saved views
    "/ui/login",
    "/ui/account",
])
def test_a_deep_link_returns_index_html(spa_app, deep_link):
    """Every one of these is a URL somebody pastes into a message or reloads on.

    This is the test the sibling product did not have.
    """
    resp = spa_app.get(deep_link)
    assert resp.status_code == 200, f"{deep_link} did not resolve to the SPA"
    assert INDEX_MARKER in resp.text, f"{deep_link} served something other than index.html"
    assert resp.headers["content-type"].startswith("text/html")


def test_the_mount_root_serves_the_console(spa_app):
    resp = spa_app.get("/ui/")
    assert resp.status_code == 200 and INDEX_MARKER in resp.text


def test_a_real_asset_is_served_as_itself(spa_app):
    """The fallback must not swallow the bundle it exists to deliver."""
    resp = spa_app.get("/ui/assets/app.js")
    assert resp.status_code == 200
    assert "export const x" in resp.text
    assert "javascript" in resp.headers["content-type"]


@pytest.mark.parametrize("missing", [
    "/ui/assets/index-deadbeef.js",
    "/ui/assets/index-deadbeef.css",
    "/ui/favicon.png",
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


def test_the_mount_does_not_serve_the_rest_of_the_disk(spa_app):
    for probe in ("/ui/../app.py", "/ui/..%2fapp.py", "/ui/....//app.py",
                  "/ui/../../requirements.txt"):
        resp = spa_app.get(probe)
        assert resp.status_code != 200 or INDEX_MARKER in resp.text, \
            f"{probe} escaped the SPA directory"
        assert b"SESSION_COOKIE" not in resp.content


def test_an_unbuilt_bundle_reports_itself_instead_of_404ing_quietly(tmp_path):
    """A fresh checkout with no `npm run build` is a normal state, and an image
    shipped without its frontend is a build failure. Both must be legible: a bare
    404 reads as a mistyped URL and would send someone hunting for a routing bug.
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from server.app import SpaFiles

    empty = tmp_path / "never-built"
    app = FastAPI()
    app.mount("/ui", SpaFiles(directory=str(empty), html=True, check_dir=False),
              name="spa")
    resp = TestClient(app).get("/ui/findings")
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
    one of them gets made without the other."""
    from server.app import SPA_MOUNT_PATH

    assert _vite_base().rstrip("/") == SPA_MOUNT_PATH.rstrip("/"), (
        f"vite base {_vite_base()!r} does not match SPA_MOUNT_PATH "
        f"{SPA_MOUNT_PATH!r}; the built bundle will not load")


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
        "App.tsx has no catch-all, so a nav entry for an unmigrated screen would "
        "render a blank page instead of saying it is not migrated yet")


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


def test_the_jinja_console_offers_a_door_into_the_spa():
    """Trap 3 at the scale of the whole migration.

    Every route INSIDE the SPA is reachable by clicking. The SPA itself was not:
    it is mounted under a prefix the Jinja console owns none of, a signed-in user
    lands on the server-rendered dashboard, and no page, README or compose file
    mentioned that a second console existed. Reachable only by someone who had
    read server/app.py is the same failure as the sibling product's unlisted
    enrolment screen, with the whole deliverable behind it.

    Asserted against base.html rather than a rendered page because the header
    only renders for a signed-in user and that needs a database — this guard has
    to hold on a bare checkout or it is not a guard.
    """
    from server.app import SPA_MOUNT_PATH, TEMPLATES

    assert TEMPLATES.env.globals.get("spa_mount") == SPA_MOUNT_PATH, (
        "base.html reads the SPA prefix from the `spa_mount` Jinja global; without "
        "it the link renders as an empty href and silently reloads the same page")

    base = (ROOT / "server" / "templates" / "base.html").read_text(encoding="utf-8")
    assert "{{ spa_mount }}/" in base, (
        "no Jinja page links to the React console, so nothing but a typed URL "
        "reaches it")
    assert f'href="{SPA_MOUNT_PATH}' not in base, (
        "base.html hardcodes the SPA prefix instead of reading `spa_mount`; the "
        "two definitions will drift the first time the mount moves")


# --------------------------------------------------------------------------- #
#  The mount must not disturb what is already there                           #
# --------------------------------------------------------------------------- #

def test_the_api_still_fails_closed_for_an_anonymous_caller():
    """Mounting a public directory at /ui must not have made anything else
    public. The API is the security boundary and this is it, unchanged."""
    from fastapi.testclient import TestClient
    from server import app as appmod

    anon = TestClient(appmod.app)
    for path in ("/api/findings", "/api/dashboard", "/api/paths", "/api/risk",
                 "/api/auth/me", "/api/account"):
        resp = anon.get(path)
        assert resp.status_code == 401, f"{path} answered {resp.status_code} to an anonymous caller"
        assert resp.json()["detail"] == "not authenticated"


def test_the_jinja_console_is_still_mounted_and_still_owns_its_paths():
    """The migration stays reversible until every screen is done. If a screen
    agent's work fails, these pages are what the product still has."""
    from fastapi.testclient import TestClient
    from server import app as appmod

    paths = {r.path for r in appmod.app.routes if hasattr(r, "path")}
    for jinja_route in ("/", "/findings", "/findings/{finding_id}", "/trend",
                        "/paths", "/paths/{path_id}", "/risk", "/coverage",
                        "/upload", "/account", "/runs/{run_id}", "/v/{slug}"):
        assert jinja_route in paths, f"{jinja_route} was removed from the console"

    # And one of them actually renders — the sign-in page needs no database.
    anon = TestClient(appmod.app)
    resp = anon.get("/login")
    assert resp.status_code == 200
    assert "/static/monitorrisk-logo.png" in resp.text


def test_the_runtime_dependency_count_did_not_move():
    """React, Vite and TypeScript are BUILD-time dependencies. If one of them
    ever appears here, the deployment has quietly grown a second service."""
    reqs = [line.split("[")[0].split(">")[0].split("=")[0].strip().lower()
            for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")]
    assert reqs == ["fastapi", "uvicorn", "jinja2", "psycopg", "python-multipart"], \
        f"the pinned runtime dependency list changed: {reqs}"


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

    resp = TestClient(appmod.app).get("/ui/findings/123")
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
    from server.app import SPA_MOUNT_PATH

    index = (ROOT / "server" / "spa" / "index.html").read_text(encoding="utf-8")
    for match in re.finditer(r'(?:src|href)="(/[^"]+)"', index):
        url = match.group(1)
        if url.startswith("/static/"):
            continue                     # brand assets, served by the other mount
        assert url.startswith(SPA_MOUNT_PATH + "/"), \
            f"index.html requests {url}, which the SPA mount does not serve"


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
