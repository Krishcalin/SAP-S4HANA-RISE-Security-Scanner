# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
FastAPI application.

ONE QUERY LAYER, ONE RENDERING
------------------------------
There used to be two: thirteen server-rendered Jinja pages and the JSON API, both
calling the same query helpers so they could not disagree. The React console has
replaced the pages, so this module is now the API plus the static mount that
serves the compiled bundle, and the invariant worth copying from the incumbent —
"everything the dashboard shows is available via the API" — has stopped being a
discipline and become the only way anything is rendered at all. There is no
second reading of the data left to drift from this one.

WHAT WENT, AND WHAT DELIBERATELY DID NOT
`server/templates/` and every route that rendered one are gone; jinja2 left
requirements.txt with them. Three things that LOOKED like part of the Jinja
console stayed, because none of them was:
  * `/static` — brand assets, referenced by the SPA's index.html by absolute path
    and by its sign-in screen. Unauthenticated by necessity.
  * `/health` — operational, read by a container healthcheck, never by a browser.
  * `/v/{slug}` — a shareable saved-view link that lives in bookmarks and tickets.
    It was a 303 to a Jinja page; the SPA declares the SAME path as a route and
    resolves it through `/api/views/{slug}`, so the URL survives the cutover
    without a redirect and the server route had to go rather than shadow it.

Reporting is READ ACCESS, not file production. Each audience gets a durable,
permission-scoped URL rather than a document somebody has to fetch and forward —
the workaround an incumbent's customers resorted to (batch scripts re-posting to
SharePoint) is a design smell we are deliberately not reproducing.
"""
from __future__ import annotations

import json
import asyncio
import logging
import shutil
import tempfile
import zipfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

from fastapi import Depends, FastAPI, Form, HTTPException, Request, UploadFile, File
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import Scope

from server import analytics, auth, crq, db, graph, ingest, queries, sapcontent
from modules import nist_csf, platforms
#: SESSION_COOKIE is imported but not USED here any more — the routes that set and
#: cleared it were the Jinja form's sign-in and sign-out, and the SPA uses
#: /api/auth/login and /api/auth/logout instead. It stays as a deliberate
#: re-export: one spelling of the cookie name, asserted by tests/test_api_auth.py,
#: because two modules holding two spellings presents as "signing in works but
#: nothing is signed in".
from server.api_auth import SESSION_COOKIE, current_user, require  # noqa: F401
from server.api_auth import router as api_auth_router
from server.config import settings

log = logging.getLogger(__name__)

app = FastAPI(title="MonitorRisk — SAP Threat, Vulnerabilities & GRC",
              docs_url="/api/docs")

#: Brand assets. Deliberately UNAUTHENTICATED: the sign-in screen carries the
#: logo, so gating this mount would render a broken image to everyone not yet
#: signed in. Nothing else is served from here, and nothing here is derived from
#: scan data. StaticFiles ships inside Starlette, which FastAPI already depends on
#: — the runtime dependency count stays at four.
#:
#: IT SURVIVED THE JINJA RETIREMENT ON PURPOSE. It reads like part of the
#: server-rendered console and is not: the compiled index.html names
#: /static/favicon.ico by ABSOLUTE path (base-relative would break the moment the
#: mount moved, which it just did), and the SPA's sign-in screen names
#: /static/monitorrisk-logo.png the same way. Removing this mount replaces the
#: brand with two broken images on the one screen every user sees first.
#:
#: DECLARED BEFORE THE SPA MOUNT and it must stay there — see the note on route
#: ordering at the foot of this file.
app.mount("/static",
          StaticFiles(directory=str(Path(__file__).with_name("static"))),
          name="static")


# --------------------------------------------------------------------------- #
#  The SPA                                                                    #
# --------------------------------------------------------------------------- #
#  The React console is compiled to static files at IMAGE-BUILD time and served
#  by this process. There is no Node at runtime and no second container: React,
#  Vite and TypeScript are build-time dependencies, and the pinned runtime list
#  went DOWN when this replaced the templates — jinja2 left with them.

#: Where `frontend/npm run build` puts its output. Beside the brand assets, so the
#: Dockerfile's existing `COPY server/` carries it and the path resolves off
#: __file__ rather than off a working directory.
SPA_DIR = Path(__file__).with_name("spa")

#: The URL prefix the bundle is built for. It is baked into every asset URL at
#: build time (vite.config.ts `base`), so it CANNOT be configuration — a bundle
#: built for one prefix and mounted at another loads a blank page with four
#: 404s in the console. tests/test_spa_mount.py asserts this string and vite's
#: `base` agree, so the pair cannot be half-changed.
#:
#: IT IS THE ROOT NOW. It was "/ui" for exactly as long as the Jinja console
#: owned "/", "/findings", "/paths" and the rest — the SPA could not be given
#: those paths while server-rendered pages were still the only working version of
#: those screens. Every screen is migrated, so the pages and their templates are
#: gone and the console has the address people actually type. vite's `base`
#: became "/" in the same commit, because a half-changed pair is a blank page.
#:
#: /ui DID NOT SIMPLY VANISH. It was a live console for the length of the
#: migration and its URLs are in bookmarks and tickets, so a redirect stands
#: where it was — see `_retired_ui_prefix` below.
SPA_MOUNT_PATH = "/"


class SpaFiles(StaticFiles):
    """StaticFiles with a history-API fallback that actually fires.

    THE BUG THIS EXISTS TO NOT HAVE. Starlette's StaticFiles does not *return* a
    404 response for a missing path — it RAISES HTTPException(404). A fallback
    written as `if response.status_code == 404: serve index.html` therefore never
    runs, and every deep link 404s. That shipped in a sibling product and went
    unnoticed for months, because "/" is served by the directory index and only
    a *shared* URL or a browser reload on an inner screen ever hits the bug.
    Both paths are handled below, and tests/test_spa_mount.py exercises the
    raised one specifically.

    A path whose last segment CONTAINS A DOT is refused honestly instead of being
    answered with index.html. `/assets/index-a1b2c3.js` going missing is a broken
    build, and answering it with HTML turns a clear 404 into a MIME-type error
    somewhere inside the module loader — the failure would be reported as "the app
    is blank", which is a much longer walk to the same cause. No SPA route
    contains a dot: saved-view slugs are stripped to alphanumerics, hyphen and
    underscore, and every other route segment is a numeric id.

    A path under `api/` is refused for the same reason and a sharper one. Now that
    this is mounted at the ROOT it is the last route in the table, so a mistyped or
    retired API path reaches it — and answering `GET /api/findigs` with 200 and a
    page of HTML is the worst possible reply to an integrator: their JSON parser
    fails somewhere unrelated and the actual cause (a typo) is invisible. See
    `_index_or_404`.
    """

    async def check_config(self) -> None:
        """Deliberately a no-op.

        StaticFiles re-checks its directory on the first request and raises
        RuntimeError — a 500 with a traceback — when it is absent. "Nobody has
        run `npm run build` yet" is a normal state of a fresh checkout and not a
        server fault. `_index_or_404` reports that state as a 503 that says what
        to do about it, and the API keeps answering throughout — which is what
        makes an unbuilt bundle diagnosable rather than a dead server.
        """
        return

    async def get_response(self, path: str, scope: Scope) -> Response:
        # SOURCE MAPS ARE NEVER SERVED, WHATEVER THE BUILD EMITS.
        #
        # vite's `sourcemap: 'hidden'` stops the browser FETCHING the map — it omits
        # the //# sourceMappingURL comment — and that was mistaken for the map being
        # unreachable. It is not: index.html publicly names /assets/index-<hash>.js,
        # the map sits at that exact name plus ".map", and this mount is
        # unauthenticated because the sign-in screen has to load from it. Anyone who
        # could reach the login page could read 1.8 MB of commented TypeScript with
        # `sourcesContent` inlined — the whole frontend, including every API shape
        # and client-side check, before presenting a credential.
        #
        # Refused HERE rather than by changing the build, because the build config
        # is one line in another language in another directory and this is the thing
        # that actually hands bytes to the internet. A map that reappears — a vite
        # default changing, a plugin emitting its own, someone setting `true` while
        # debugging and pushing it — is served by the build and refused by this.
        if path.lower().endswith(".map"):
            raise StarletteHTTPException(status_code=404)

        # StarletteHTTPException, not FastAPI's — FastAPI's subclasses it, so this
        # catches both, whereas catching only FastAPI's would miss the one
        # StaticFiles actually raises.
        try:
            response = await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if exc.status_code != 404:
                raise
            return await self._index_or_404(path, scope)
        # Belt and braces: a future Starlette that RETURNS the 404 rather than
        # raising it must not silently reintroduce the bug this class exists for.
        if response.status_code == 404:
            return await self._index_or_404(path, scope)
        # The mount root (html=True) serves index.html directly, bypassing
        # _index_or_404 — so the no-cache header has to be applied on this path too.
        if path in ("", ".", "index.html"):
            return self._no_cache(response)
        return response

    @staticmethod
    def _no_cache(response: Response) -> Response:
        """index.html must never be cached; every hashed asset may be cached forever.

        index.html NAMES the hashed bundles. Served with only ETag/Last-Modified, a
        browser applies heuristic freshness to it — so after an upgrade a returning
        client can keep an old index that references asset filenames the new image
        no longer contains, and the console fails to load with a 404 on a file the
        user cannot see and cannot clear without a hard refresh. The assets
        themselves are content-hashed and immutable, so nothing else needs this.
        """
        response.headers["Cache-Control"] = "no-cache, must-revalidate"
        return response

    async def _index_or_404(self, path: str, scope: Scope) -> Response:
        # Path().name rather than a manual rsplit: StaticFiles has already run the
        # incoming path through os.path.normpath, so the separator is the host's
        # and the mount root arrives as "." — which a naive "is there a dot in the
        # last segment" test reads as a file extension and refuses.
        if "." in Path(path).name:
            raise StarletteHTTPException(status_code=404)
        # An unmatched /api path is a 404, never the console. The mount is at the
        # root and therefore matches EVERYTHING that no real route claimed, so
        # without this an integrator's typo comes back as 200 text/html and their
        # JSON decoder blows up somewhere with no relationship to the mistake.
        # PurePosixPath, not Path: `path` has been normalised with the HOST's
        # separator, and on Windows `Path("api/x").parts` and `Path("api\\x").parts`
        # both start "api" while a plain `startswith("api/")` would miss the
        # backslash form and reopen the hole on exactly one platform.
        if PurePosixPath(path.replace("\\", "/")).parts[:1] == ("api",):
            raise StarletteHTTPException(status_code=404)
        try:
            return self._no_cache(await super().get_response("index.html", scope))
        except StarletteHTTPException:
            # The SPA was never built into this image. Say so loudly rather than
            # 404ing like a mistyped URL: an image shipped without its frontend
            # is a build failure, and the one thing that must not happen is for
            # it to look like an ordinary missing page.
            return JSONResponse(
                {"detail": f"the console bundle is missing from {SPA_DIR} — "
                           "run `npm run build` in frontend/, or rebuild the image"},
                status_code=503)


#  THE MOUNT ITSELF IS AT THE FOOT OF THIS FILE, NOT HERE. A Mount at "/" matches
#  every path there is, and Starlette dispatches to the FIRST route that matches,
#  so registering it at this point would swallow /api, /health and /static whole —
#  the entire API would answer with index.html and every test would fail at once.
#  It used to sit here safely only because "/ui" claimed a prefix nothing else
#  used. See the note above `app.mount(...)` at the end of the module.


#: Scans are CPU-bound Python; they must not run on the event loop or a single
#: upload would freeze every other user's console.
_scan_pool = ThreadPoolExecutor(max_workers=max(1, settings.max_concurrent_scans),
                                thread_name_prefix="scan")


@asynccontextmanager
async def _lifespan(_: FastAPI):
    settings.validate()
    db.init_schema()
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    log.info("ready")
    yield
    _scan_pool.shutdown(wait=False, cancel_futures=True)
    db.close_pool()


app.router.lifespan_context = _lifespan


# --------------------------------------------------------------------------- #
#  Auth plumbing                                                              #
# --------------------------------------------------------------------------- #
#  `current_user`, `require` and SESSION_COOKIE now live in server/api_auth.py
#  and are imported above. They moved so the JSON auth routes could use them
#  without importing this module back — one definition of "signed in", not two.

app.include_router(api_auth_router)


@app.exception_handler(401)
async def _unauth(request: Request, exc: HTTPException):
    """Always JSON now, for every caller.

    It used to branch: an API client got this body and a browser got a 303 to the
    Jinja sign-in page. There is nothing left to redirect. Every route that
    resolves a user is under /api, and a browser asking for a SCREEN never reaches
    an exception handler at all — it reaches the static mount, which hands back
    index.html unconditionally, and the console's own AuthGate reads a 401 from
    /api/auth/me and renders the sign-in form client-side.

    Keeping the redirect branch would be worse than dead code: it would answer a
    303 to `/login?next=…` from an endpoint the SPA calls with fetch, which
    follows redirects silently and would hand the screen a page of HTML where it
    expected JSON — a 401 that presents as a parse error.
    """
    return JSONResponse({"detail": "not authenticated"}, status_code=401)


@app.exception_handler(303)
async def _must_change(request: Request, exc: HTTPException):
    """A forced password change, reported to the caller rather than redirected.

    `change_at` KEPT ITS VALUE, and that is a decision rather than an oversight.
    It named the Jinja account page; it now names the SPA route at the identical
    path, because App.tsx declares `/account` and the console navigates there.
    The string did not have to move, so it did not — a shared client contract that
    changes for no observable reason is a change every integrator has to read and
    nobody benefits from. tests/test_account.py asserts the pointer is not
    dangling by checking it against the SPA's own route table, which is a stronger
    claim than the literal it replaced.

    It is a CONSOLE path, not an endpoint: a scripted client cannot POST to it.
    The call that actually clears the condition is POST /api/account/password,
    named here so a reader of the response is not left guessing.

    Like the 401 above this no longer branches on the path. `current_user` is the
    only thing that raises a 303 and it is now reached exclusively from /api.
    """
    return JSONResponse(
        {"detail": "password change required", "change_at": "/account"},
        status_code=403)


# --------------------------------------------------------------------------- #
#  Retired URLs that are still in the world                                   #
# --------------------------------------------------------------------------- #
#  The Jinja console's page paths — "/", "/findings/123", "/paths/7", "/v/{slug}"
#  and the rest — need nothing here: the SPA declares every one of them at the
#  SAME path, so the static mount answers them and react-router renders the right
#  screen. They were checked one by one against src/App.tsx rather than assumed.
#
#  "/ui" is the exception, and the only redirect this cutover needs. It was a
#  real, working console for the whole migration; its URLs were shared, bookmarked
#  and pasted into tickets, and the test suite named /ui/findings/123 as the
#  canonical case. Without this, /ui/findings/123 would resolve — the root mount
#  answers everything — and render the catch-all "page not found" screen, because
#  react-router's basename is "/" and no route matches "/ui/findings/123". A
#  silent wrong screen is worse than a 404, and much worse than a redirect.

#: GET and HEAD, spelled out. FastAPI's `@app.get` registers GET *only* — unlike
#: Starlette's own Route, which quietly adds HEAD alongside it — so a bare
#: `@app.get` here would leave `HEAD /ui/findings` unmatched, and the mount below
#: would answer it 200 with the console. A link checker or a proxy probing with
#: HEAD would then be told the retired prefix is alive while every browser
#: following it gets a 301: two different answers about the same URL, and the one
#: that reads as authoritative is the wrong one.
_UI_REDIRECT_METHODS = ["GET", "HEAD"]


@app.api_route("/ui", methods=_UI_REDIRECT_METHODS, include_in_schema=False)
@app.api_route("/ui/{rest:path}", methods=_UI_REDIRECT_METHODS,
               include_in_schema=False)
def _retired_ui_prefix(request: Request, rest: str = ""):
    """Send the migration-era console prefix to the address it now lives at.

    301 rather than 302: /ui is not coming back, and a permanent redirect lets a
    browser stop asking. The cost is that it is cached hard — which is the right
    trade for a prefix being retired in the same commit that gives the console the
    root, and the wrong one for anything that might return.

    THE QUERY STRING IS CARRIED. Half of what makes these links worth preserving
    is in it: /ui/findings?team=basis&severity=CRITICAL is somebody's saved triage
    queue, and dropping the filters would "work" while showing the wrong list.

    `rest` IS ATTACKER-CONTROLLED AND MUST BE NORMALISED TO EXACTLY ONE LEADING
    SLASH. Written as a bare f"/{rest}", `GET /ui//evil.example.com` gives
    rest="/evil.example.com" and a `Location: //evil.example.com` — a
    PROTOCOL-RELATIVE URL, which a browser resolves against the current scheme and
    follows off-site. That is an open redirect on an unauthenticated path, on the
    one prefix we are actively telling people is still safe to click, and the 301
    makes it worse: the browser caches the hop and keeps making it without asking
    us again. `%2f%2f` is the same attack pre-decoded by Starlette, and a backslash
    is the same attack again because browsers fold "\\" to "/" while parsing a
    Location — so both are collapsed before the slashes are stripped.

    The guard that already existed (tests/test_http_console.py's
    `test_the_open_redirect_is_closed`) covered the retired ?next= parameter and
    checked this route only with a well-formed path, which is why a redirect added
    in the same commit could reopen a hole the suite believed was shut.

    Declared BEFORE the mount at the foot of this file, or the mount would take it
    first and this would never run.
    """
    query = request.url.query
    target = "/" + rest.replace("\\", "/").lstrip("/")
    return RedirectResponse(f"{target}?{query}" if query else target,
                            status_code=301)


# --------------------------------------------------------------------------- #
#  JSON API                                                                   #
# --------------------------------------------------------------------------- #

@app.get("/api/risk")
def api_risk(user: Dict[str, Any] = Depends(current_user)):
    """Financial risk exposure — the board view.

    Neither incumbent produces a currency figure at all, which makes this the
    cleanest differentiated screen in the product.
    """
    scope = auth.scope_for(user)
    latest = crq.latest(scope)
    return {"portfolio": latest,
            "scenarios": crq.scenarios_for_run(latest["run_id"]) if latest else [],
            "trend": crq.trend(scope)}


@app.get("/api/paths")
def api_paths(user: Dict[str, Any] = Depends(current_user),
              include_closed: bool = False):
    """Everything the paths screen renders, in one call.

    The ranked path list plus choke points. The graph is NOT part of this — it
    renders inside one selected path (`/api/paths/{id}`), which is what keeps the
    screen legible at landscape scale.

    `closed` and `template_count` were on the retired HTML page and not here. The
    closed list is the mitigation journey's strongest unit — "this path was
    severed on 12 September" — and leaving it out of the API made the best
    evidence in the product reachable only by scraping a page.
    """
    scope = auth.scope_for(user)
    return {"summary": graph.path_summary(scope),
            "paths": graph.list_paths(scope, include_closed=include_closed),
            "chokepoints": graph.chokepoints(scope),
            "closed": graph.recently_closed(scope),
            "template_count": len(graph.load_templates().get("paths", []))}


@app.get("/api/coverage")
def api_coverage(user: Dict[str, Any] = Depends(current_user)):
    """The published check catalogue and its coverage of SAP's own Baseline.

    Coverage is computed from the check ids actually in the catalogue, so the
    screen cannot drift from what the scanner really does.

    `meta` and `our_checks` are additive — existing consumers keep the keys they
    already read. They are here because the screen renders the catalogue's
    provenance (which Baseline version, and the unit warning that comes with it)
    alongside the numbers, and a coverage percentage without its provenance is a
    claim an auditor cannot check.
    """
    check_ids = [r["check_id"] for r in db.query("SELECT check_id FROM check_definition")]
    cat = sapcontent.load_catalogue()
    return {**sapcontent.coverage(check_ids, cat),
            "meta": cat.get("_meta", {}),
            "our_checks": len(check_ids)}


@app.post("/api/views")
def api_save_view(name: str = Form(...), slug: str = Form(...),
                  kind: str = Form("findings"), shared: bool = Form(True),
                  description: str = Form(""), request: Request = None,
                  user: Dict[str, Any] = Depends(require("analyst"))):
    """Save the current filters as a durable URL.

    Filters come from the referring screen's query string rather than a body, so
    "save this view" is literally "save what I am looking at". The SPA keeps its
    filters in the address bar for exactly this reason, so the referer carries
    them unchanged and this did not need to move to a body when the pages went.

    The returned `url` is /v/{slug} — still a real address after the cutover,
    because the console declares that path as a route of its own. See the module
    docstring on why the server-side /v/{slug} redirect was retired rather than
    kept.
    """
    ref = urlparse(request.headers.get("referer", "")) if request else None
    filters = {k: v[0] for k, v in parse_qs(ref.query).items()} if ref else {}
    try:
        view = queries.save_view(slug, name, kind, filters, user["username"],
                                 description, shared)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"slug": view["slug"], "url": f"/v/{view['slug']}",
            "filters": view["filters"]}


@app.post("/api/findings/{finding_id}/assign")
def api_assign(finding_id: int, assignee: str = Form(None), team: str = Form(None),
               due_date: str = Form(None),
               user: Dict[str, Any] = Depends(require("analyst"))):
    try:
        return queries.assign_finding(finding_id, user["username"], assignee, team,
                                      due_date, auth.scope_for(user))
    except queries.TransitionError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/findings/bulk-state")
def api_bulk_state(finding_ids: str = Form(...), state: str = Form(...),
                   reason: str = Form(""), ticket: str = Form(""),
                   user: Dict[str, Any] = Depends(require("analyst"))):
    """Move several findings at once. Partial success is reported, not hidden."""
    ids = [int(x) for x in finding_ids.replace(",", " ").split() if x.strip().isdigit()]
    if not ids:
        raise HTTPException(400, "no finding ids supplied")
    return queries.bulk_transition(ids, state, user["username"], reason, ticket,
                                   auth.scope_for(user))


@app.get("/api/trend")
def api_trend(days: int = 180, user: Dict[str, Any] = Depends(current_user)):
    """The mitigation journey — answers "is it getting better" without an export."""
    return analytics.journey_summary(auth.scope_for(user), days)


# --------------------------------------------------------------------------- #
#  Upload and scan                                                            #
# --------------------------------------------------------------------------- #

def _extract(files: List[UploadFile], dest: Path) -> int:
    """Write uploads into `dest`, expanding a zip if one was sent.

    Every extracted path is checked to stay inside `dest`. A zip entry named
    ``../../etc/passwd`` is the oldest trick against an upload endpoint and
    `extractall` does not stop it.
    """
    dest.mkdir(parents=True, exist_ok=True)
    written = 0
    for up in files:
        name = Path(up.filename or "").name
        if not name:
            continue
        target = dest / name
        with target.open("wb") as fh:
            shutil.copyfileobj(up.file, fh, length=1024 * 1024)
        written += 1

        if name.lower().endswith(".zip"):
            with zipfile.ZipFile(target) as zf:
                for member in zf.namelist():
                    if member.endswith("/"):
                        continue
                    out = (dest / Path(member).name).resolve()
                    if not str(out).startswith(str(dest.resolve())):
                        raise HTTPException(400, f"unsafe path in archive: {member}")
                    with zf.open(member) as src, out.open("wb") as fh:
                        shutil.copyfileobj(src, fh)
                        written += 1
            target.unlink()
    return written


@app.post("/api/upload")
async def api_upload(request: Request,
                     files: List[UploadFile] = File(...),
                     landscape_id: int = Form(...),
                     system_id: Optional[int] = Form(None),
                     sid: Optional[str] = Form(None),
                     client: Optional[str] = Form(None),
                     user: Dict[str, Any] = Depends(require("analyst"))):
    if len(files) > settings.max_upload_files:
        raise HTTPException(413, f"too many files (max {settings.max_upload_files})")

    landscape = db.one("SELECT * FROM landscape WHERE id = %s", (landscape_id,))
    if landscape is None:
        raise HTTPException(404, "unknown landscape")

    run_dir = Path(tempfile.mkdtemp(prefix="run_", dir=str(settings.upload_dir)))
    try:
        count = _extract(files, run_dir)
        if not count:
            raise HTTPException(400, "no files uploaded")
        sha = ingest.bundle_sha(run_dir)
    except HTTPException:
        shutil.rmtree(run_dir, ignore_errors=True)
        raise

    # Duplicate detection INFORMS, it does not block: re-uploading an identical
    # bundle is a legitimate act that proves nothing changed.
    prior = db.one(
        "SELECT id, started_at FROM scan_run WHERE landscape_id = %s AND content_sha = %s "
        "ORDER BY started_at DESC LIMIT 1", (landscape_id, sha))

    with db.connection() as conn:
        run = conn.execute(
            "INSERT INTO scan_run (landscape_id, system_id, content_sha, uploaded_by, "
            "upload_name, status) VALUES (%s,%s,%s,%s,%s,'pending') RETURNING id",
            (landscape_id, system_id, sha, user["username"],
             f"{count} file(s)")).fetchone()
        db.audit(conn, user["username"], "scan.upload", "scan_run", str(run["id"]),
                 {"files": count, "sha": sha, "duplicate_of": prior["id"] if prior else None})
        conn.commit()
    run_id = run["id"]

    loop = asyncio.get_running_loop()
    loop.run_in_executor(
        _scan_pool, _run_scan_job, run_dir, landscape_id, system_id, run_id,
        landscape["deployment_mode"], sid, client)

    return {
        "run_id": run_id,
        "files": count,
        "content_sha": sha,
        "duplicate_of_run": prior["id"] if prior else None,
        "note": ("This bundle is byte-identical to an earlier upload; the scan will "
                 "run anyway and should report no changes.") if prior else None,
        "status_url": f"/api/runs/{run_id}",
    }


def _run_scan_job(run_dir: Path, landscape_id: int, system_id: Optional[int],
                  run_id: int, deployment_mode: str, sid: Optional[str],
                  client: Optional[str]) -> None:
    try:
        ingest.scan_directory(run_dir, landscape_id, system_id, run_id,
                              deployment_mode=deployment_mode,
                              default_sid=sid, default_client=client)
    except Exception:                                   # noqa: BLE001
        log.exception("scan job %s failed", run_id)     # already marked failed in DB
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)


@app.post("/api/runs/{run_id}/cancel")
def cancel_run(run_id: int, user: Dict[str, Any] = Depends(require("analyst"))):
    """Request cancellation. The worker checks between modules and stops cleanly.

    "You cannot stop a running scan" is a documented complaint about the
    incumbent; a long job with no stop button is a support ticket waiting to
    happen.
    """
    with db.connection() as conn:
        conn.execute("UPDATE scan_run SET cancel_requested = true WHERE id = %s "
                     "AND status IN ('pending','parsing','scanning','deriving')",
                     (run_id,))
        db.audit(conn, user["username"], "scan.cancel", "scan_run", str(run_id))
        conn.commit()
    return {"run_id": run_id, "cancel_requested": True}


# --------------------------------------------------------------------------- #
#  JSON API — findings and runs                                               #
# --------------------------------------------------------------------------- #

@app.get("/api/runs/{run_id}")
def api_run(run_id: int, user: Dict[str, Any] = Depends(current_user)):
    run = queries.get_run(run_id, auth.scope_for(user))
    if run is None:
        raise HTTPException(404, "not found")
    return run


@app.get("/api/findings")
def api_findings(user: Dict[str, Any] = Depends(current_user),
                 system_id: Optional[int] = None, state: Optional[str] = None,
                 severity: Optional[str] = None, team: Optional[str] = None,
                 owner: Optional[str] = None, tier: Optional[str] = None,
                 category: Optional[str] = None, assignee: Optional[str] = None,
                 overdue: bool = False, page: int = 1):
    """The triage queue.

    THE FILTER LIST IS THE CONSOLE'S, IN FULL. It was once a strict subset —
    system, state, severity and page — which quietly made this module's own
    invariant false: the server-rendered queue could filter by tier, team, owner,
    assignee and overdue, and an API client could not. The pages are gone and this
    is now the only reader of `list_findings`, so the subset could not come back
    by accident; the parameters stay because an integrator wants exactly the
    filters an analyst has.
    """
    return queries.list_findings(auth.scope_for(user), system_id=system_id,
                                 state=state, severity=severity, team=team,
                                 remediation_owner=owner, tier=tier,
                                 category=category, assignee=assignee,
                                 overdue=overdue, page=page)


@app.get("/api/findings/changes")
def api_changes(since_run: int, user: Dict[str, Any] = Depends(current_user)):
    """Findings that changed since a given run.

    Nearly free for us because the run-over-run diff already exists — and it is
    something the incumbent's integrators explicitly cannot get, since their sync
    is documented as full-only with no incremental filter.
    """
    return queries.changes_since(since_run, auth.scope_for(user))


# DECLARED AFTER /api/findings/changes ON PURPOSE. Starlette matches routes in
# declaration order, so a `{finding_id}` path registered above it would capture
# "changes" and fail int coercion with a 422 — the incremental-sync endpoint would
# break, and the failure would look like a client bug rather than a routing one.
@app.get("/api/findings/{finding_id}")
def api_finding(finding_id: int, user: Dict[str, Any] = Depends(current_user)):
    """One finding in full, including its risk narrative and remediation.

    Closes a gap against this module's own stated invariant: "everything the
    dashboard shows is available via the API". It was not — the list endpoints
    never select `cd.remediation` or `cd.risk_narrative`, and there was no
    single-finding route at all, so the two fields a consumer most wants when
    building a ticket were reachable only by scraping the server-rendered page.

    That scrape is no longer even possible, which is the migration's sharpest
    reminder of why this route had to exist before the pages could go: the code
    snippet, the source→sink taint trace and the reachability verdict now reach a
    human ONLY through `latest_details` in this response. `queries.get_finding`
    already selected all of it, plus the caller's system scope.
    """
    finding = queries.get_finding(finding_id, auth.scope_for(user))
    if finding is None:
        # 404 whether the finding does not exist OR is out of the caller's scope.
        # Distinguishing them would let a scoped user enumerate ids in landscapes
        # they cannot see.
        raise HTTPException(status_code=404, detail="not found")
    return finding


@app.post("/api/findings/{finding_id}/state")
def api_set_state(finding_id: int, state: str = Form(...), reason: str = Form(""),
                  ticket: str = Form(""),
                  user: Dict[str, Any] = Depends(require("analyst"))):
    try:
        return queries.transition_finding(finding_id, state, user["username"],
                                          reason=reason, ticket=ticket,
                                          scope=auth.scope_for(user))
    except queries.TransitionError as exc:
        raise HTTPException(400, str(exc)) from exc


# --------------------------------------------------------------------------- #
#  JSON API — the screens the SPA renders                                     #
# --------------------------------------------------------------------------- #
#  These were added so the React screens had something to read, each returning
#  the SAME context under the SAME keys as the Jinja page beside it — which is
#  what made the pages a working fallback for the length of the migration and
#  what makes retiring them now a deletion rather than a rewrite. Every key the
#  templates rendered is still produced here; nothing was dropped on the way out.
#
#  All of them are READS behind `current_user`, which applies the caller's row
#  scope through `auth.scope_for`. Nothing here widens what a user can see.

@app.get("/api/dashboard")
def api_dashboard(user: Dict[str, Any] = Depends(current_user)):
    """The landing screen's four panels, in one round trip."""
    scope = auth.scope_for(user)
    latest_crq = crq.latest(scope)
    return {
        "summary": queries.dashboard_summary(scope),
        "systems": queries.list_systems(scope),
        "recent_runs": queries.recent_runs(scope, limit=10),
        "crq": latest_crq,
        "crq_scenarios": crq.scenarios_for_run(latest_crq["run_id"]) if latest_crq else [],
    }


@app.get("/api/systems")
def api_systems(user: Dict[str, Any] = Depends(current_user)):
    """Systems in the caller's scope — the filter vocabulary for every screen."""
    return {"systems": queries.list_systems(auth.scope_for(user))}


@app.post("/api/systems")
def api_create_system(
    landscape_id: int = Form(...),
    platform: str = Form(platforms.ABAP),
    sid: str = Form(""),
    client: str = Form(""),
    external_key: str = Form(""),
    tier: str = Form("unknown"),
    criticality: str = Form("medium"),
    exposure_zone: str = Form("unknown"),
    owner: str = Form(""),
    user: Dict[str, Any] = Depends(require("admin")),
):
    """Register an ABAP system or a SaaS tenant. Decision D8.

    THERE WAS NO WRITE PATH HERE AT ALL. `/api/systems` was GET-only and the sole
    creator of a system row was `server/cli.py`, which meant a tenant could be
    stored by the schema and created by nobody using the product. A console that
    can filter by something it cannot create is a half-built feature.

    ADMIN, NOT ANALYST. Registering a system defines what the estate IS, and
    scoping is per-system: a non-admin's visible set is a list of system ids, so an
    analyst creating a system would create something they then could not see. The
    same reasoning that makes `scope_for` unrestricted for admins applies here.

    ONE ROUTE FOR BOTH SHAPES, unlike the CLI's two commands. The CLI takes its
    arguments positionally, where `add-system acme-sf-prod` would be ambiguous;
    a form field is named, so `platform` disambiguates without a second route, and
    the console's single "add system" dialog maps onto it directly.
    """
    if platform not in platforms.PLATFORMS:
        raise HTTPException(
            400, f"unknown platform {platform!r}. Known: "
                 f"{', '.join(platforms.PLATFORMS)}")
    if db.one("SELECT id FROM landscape WHERE id = %s", (landscape_id,)) is None:
        raise HTTPException(404, f"no landscape with id {landscape_id}")

    # Validate the SHAPE here as well as in the schema. sap_system_shape_check
    # refuses these too, but a 500 carrying a constraint name is a poor way to
    # tell somebody they left a field blank.
    if platforms.is_tenant(platform):
        if not external_key.strip():
            raise HTTPException(
                400, "a tenant needs an external key — it is what tells two "
                     "tenants of the same platform apart, and without it their "
                     "findings would collide into one")
        if sid.strip() or client.strip():
            raise HTTPException(
                400, f"a {platform} tenant has no SID or client; supply "
                     "external_key instead")
    else:
        if not sid.strip() or not client.strip():
            raise HTTPException(400, "an ABAP system needs both a SID and a client")
        if external_key.strip():
            raise HTTPException(
                400, "an ABAP system is identified by SID and client, not by an "
                     "external key")

    try:
        row = queries.create_system(
            landscape_id=landscape_id, platform=platform,
            sid=sid.strip().upper() or None, client=client.strip() or None,
            external_key=external_key.strip() or None, tier=tier,
            criticality=criticality, exposure_zone=exposure_zone,
            owner=owner.strip() or None, actor=user["username"])
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"system": row}


@app.get("/api/landscapes")
def api_landscapes(user: Dict[str, Any] = Depends(current_user)):
    """Landscapes, for the upload screen's required `landscape_id`.

    NOT scoped, matching the upload screen it serves: scoping is per SYSTEM, and a
    landscape carries no findings of its own. Restricting it would leave a scoped
    analyst with an empty dropdown and no way to upload at all.
    """
    return {"landscapes": queries.list_landscapes()}


@app.get("/api/paths/{path_id}")
def api_path(path_id: int, user: Dict[str, Any] = Depends(current_user)):
    """One path with its evidence, and which findings sit on a CUT hop.

    `cut_ids` drives the mitigate-vs-additional split the screen makes: a finding
    on a cut hop severs the path, one on a non-cut hop only reduces
    exploitability. Computed HERE rather than in the client, and it stays here
    now that the client is the only renderer: which findings actually end an
    attack is a claim about the graph, and it belongs beside the graph rather
    than re-derived in TypeScript from `hops`.
    """
    scope = auth.scope_for(user)
    path = graph.get_path(path_id, scope)
    if path is None:
        # 404 whether it does not exist OR is out of scope — distinguishing them
        # would let a scoped user enumerate ids in landscapes they cannot see.
        raise HTTPException(404, "not found")
    cut_ids = sorted({fid for hop in (path["detail"].get("hops") or [])
                      if hop.get("is_cut") for fid in hop.get("finding_ids", [])})
    return {"path": path, "findings": graph.path_findings(path_id),
            "cut_ids": cut_ids}


@app.get("/api/runs/{run_id}/diff")
def api_run_diff(run_id: int, user: Dict[str, Any] = Depends(current_user)):
    """New / persisting / resolved / regressed for one run.

    Separate from `/api/runs/{id}` on purpose: the run row is cheap and polled
    while a scan is in flight, and folding four aggregate queries into it would
    make a progress poll expensive.
    """
    scope = auth.scope_for(user)
    if queries.get_run(run_id, scope) is None:
        raise HTTPException(404, "not found")
    return queries.run_diff(run_id, scope)


@app.get("/api/findings/{finding_id}/history")
def api_finding_history(finding_id: int, user: Dict[str, Any] = Depends(current_user)):
    """The lifecycle trail and the per-run observations for one finding.

    Scope is checked against the FINDING before either is read — neither
    `finding_history` nor `finding_observations` filters by system, and querying
    them directly on an id would leak the transition history of a finding the
    caller cannot see.
    """
    if queries.get_finding(finding_id, auth.scope_for(user)) is None:
        raise HTTPException(404, "not found")
    return {"history": queries.finding_history(finding_id),
            "observations": queries.finding_observations(finding_id)}


@app.get("/api/views")
def api_views(user: Dict[str, Any] = Depends(current_user),
              kind: Optional[str] = None):
    """Saved views visible to this caller: their own, plus the shared ones."""
    return {"views": queries.list_views(user["username"], kind)}


@app.get("/api/views/{slug}")
def api_view(slug: str, user: Dict[str, Any] = Depends(current_user)):
    """Resolve a saved view to the filters a screen should apply.

    WHAT ANSWERS /v/{slug} NOW. There used to be a route of that name here which
    replied 303 to a Jinja page; the console declares `/v/:slug` as a route of its
    own, reads this, and replaces its own address with the destination. Keeping
    the server redirect would have shadowed that route — a Mount cannot outrank an
    explicit path — leaving a screen nobody could reach and a worse answer for a
    slug that does not exist: a bare 404 instead of a sentence explaining that a
    view is visible to its author and, when shared, to everyone.

    It returns the stored FILTERS rather than rows, which is the property that
    makes a shared link safe: the receiving screen re-runs the query under its own
    caller's row scope, so two people following the same URL each see only the
    systems they are entitled to. A saved view can never widen access, and it must
    not start returning data of its own or that stops being true.
    """
    view = queries.get_view(slug, user["username"])
    if view is None:
        raise HTTPException(404, "no such view")
    return {"view": view,
            "kind": view["kind"],
            "filters": view["filters"] or {}}


@app.get("/health")
def health():
    """Degraded components are reported, never hidden — a green light over a
    broken collector is worse than a red one.

    NOT a console route and never was, which is why it outlived the templates: it
    is read by a container healthcheck and by whatever watches the deployment, it
    takes no session, and it renders nothing. Declared above the SPA mount like
    every other real route, or it would be answered with index.html and every
    probe would go green forever.
    """
    degraded: List[str] = []
    try:
        db.one("SELECT 1 AS ok")
    except Exception as exc:                            # noqa: BLE001
        degraded.append(f"database: {type(exc).__name__}")
    stuck = db.query(
        "SELECT id FROM scan_run WHERE status IN ('parsing','scanning','deriving') "
        "AND started_at < now() - interval '2 hours'") if not degraded else []
    if stuck:
        degraded.append(f"{len(stuck)} scan run(s) appear stalled")
    return {"status": "degraded" if degraded else "ok", "degraded": degraded}


# --------------------------------------------------------------------------- #
#  The SPA mount — LAST, and it has to be                                     #
# --------------------------------------------------------------------------- #
#  A Mount at "/" matches every path there is and Starlette dispatches to the
#  FIRST route that matches, so this line has to come after every real route in
#  the module. Move it up — even one line, above /health — and that route stops
#  existing: the request is answered with index.html, 200, and the failure is
#  silent in exactly the way that takes a day to find. It sat safely near the top
#  of the file for the whole migration only because "/ui" claimed a prefix nothing
#  else used; giving the console the root turned its position into a load-bearing

# ── NIST Cybersecurity Framework (CSF) 2.0 ───────────────────────────────────
#  The literal path is declared BEFORE the parameterised one. FastAPI matches in
#  declaration order, so /api/csf/{function_id} declared first would swallow any
#  future literal sibling.


@app.get("/api/csf")
def api_csf(user: Dict[str, Any] = Depends(current_user)):
    """Open findings rolled up onto the CSF 2.0 Core.

    Returns the WHOLE Core — all 6 Functions and all 22 Categories — not only
    the ones carrying findings. A Category missing from the answer would be
    indistinguishable from a Category we cannot assess, and that ambiguity is
    the one thing modules/nist_csf.py exists to remove: every Category comes
    back labelled `assessed`, `clear` or `not_assessed`, and the last of those
    carries the reason no SAP export can answer it.

    No percentage is returned, here or anywhere below. compliance_mapping.py
    forbids one and the reason holds just as well for CSF: we see findings, not
    the control environment, so a "% compliant" would be a claim about evidence
    we do not hold.
    """
    findings = queries.findings_for_compliance(auth.scope_for(user))
    return nist_csf.roll_up(findings)


@app.get("/api/csf/{function_id}")
def api_csf_function(function_id: str,
                     user: Dict[str, Any] = Depends(current_user)):
    """One CSF Function in detail, with its Categories and their Subcategories.

    404 on anything that is not one of the six Function ids — an unknown id must
    not render as a Function with no findings, which is what returning an empty
    shell would look like on screen.
    """
    findings = queries.findings_for_compliance(auth.scope_for(user))
    detail = nist_csf.function_detail(findings, function_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="no such CSF Function")
    return detail



# ── Cyber Risk Quantification: the customer's own figures ────────────────────


@app.get("/api/crq/parameters")
def api_crq_parameters(landscape_id: int,
                       user: Dict[str, Any] = Depends(current_user)):
    """The question set, the latest answers, and the revision history.

    The QUESTIONS ship with the answers deliberately. The console must render the
    help text, the unit and which FAIR-MAM cost module each question prices, and
    duplicating that catalogue in TypeScript would let the two drift — at which
    point the screen would be explaining a model the server no longer runs.
    """
    from modules import fair_loss_model as loss_model
    latest = crq.latest_parameters(landscape_id)
    return {
        "parameters": loss_model.PARAMETERS,
        "mam_modules": {k: {"name": n, "kind": kind}
                        for k, (n, kind) in loss_model.MAM_MODULES.items()},
        "spread": dict(loss_model.SPREAD),
        "latest": latest,
        "history": crq.parameter_history(landscape_id),
    }


@app.post("/api/crq/parameters")
def api_crq_save_parameters(landscape_id: int = Form(...),
                            answers_json: str = Form(...),
                            currency: str = Form("USD"),
                            note: Optional[str] = Form(None),
                            user: Dict[str, Any] = Depends(require("analyst"))):
    """Record a revision. Analyst or above: these figures drive a board number."""
    try:
        answers = json.loads(answers_json)
    except ValueError:
        raise HTTPException(status_code=400, detail="answers_json is not valid JSON")
    if not isinstance(answers, dict):
        raise HTTPException(status_code=400, detail="answers_json must be an object")
    new_id = crq.save_parameters(landscape_id, answers, currency, note,
                                 created_by=user.get("username"))
    return {"id": new_id, "landscape_id": landscape_id}


@app.post("/api/crq/quantify")
def api_crq_quantify(landscape_id: int = Form(...),
                     answers_json: Optional[str] = Form(None),
                     simulations: int = Form(10000),
                     user: Dict[str, Any] = Depends(current_user)):
    """Quantify against a set of answers WITHOUT storing them.

    The input screen calls this on every recompute, so a CFO can try a different
    recovery time and see the effect immediately. Nothing is written: a draft
    assumption must never enter the history a trend chart is drawn from.

    `simulations` is clamped. The loop is pure Python and an unbounded value from
    the wire is a request that never returns.
    """
    answers: Dict[str, Any] = {}
    if answers_json:
        try:
            parsed = json.loads(answers_json)
        except ValueError:
            raise HTTPException(status_code=400, detail="answers_json is not valid JSON")
        if isinstance(parsed, dict):
            answers = parsed
    if not answers:
        stored = crq.latest_parameters(landscape_id)
        answers = (stored or {}).get("answers") or {}

    scope = auth.scope_for(user)
    findings = queries.findings_for_crq(scope, landscape_id)
    sims = max(1000, min(int(simulations or 10000), 50000))
    return crq.quantify_with_parameters(findings, answers, simulations=sims)



@app.get("/api/crq/controls")
def api_crq_controls(landscape_id: int,
                     user: Dict[str, Any] = Depends(current_user)):
    """Open findings attributed to the nine FAIR-CAM Loss Event Control functions.

    This is the answer to "which lever did those findings pull?". Each function
    names the FAIR factor it moves, so a reader can follow a finding to Contact
    Frequency, Probability of Action, Susceptibility or Loss Magnitude rather than
    taking a severity weight on trust.

    Two things it reports that a tidier version would hide: the confidence of each
    attribution (nine of sixteen themes map to more than one function, and saying
    so is the difference between a defensible split and a neat lie), and any
    function no check can reach — which is `not_assessed`, never a clean zero.
    """
    from modules import fair_cam
    scope = auth.scope_for(user)
    findings = queries.findings_for_crq(scope, landscape_id)
    return fair_cam.classify(findings)


@app.get("/api/crq/trend")
def api_crq_trend(user: Dict[str, Any] = Depends(current_user), limit: int = 12):
    """Portfolio ALE per run, with the fingerprint that says where it may be joined.

    The console must NOT draw one continuous polyline through these points. Risk
    moves for reasons other than remediation — a revised revenue figure, a changed
    simulation count, a dropped export that made checks self-skip — and a line
    drawn straight through such a change asserts the two ends are comparable.
    They are not. Break the line where `inputs_fingerprint` changes.
    """
    return {"points": crq.trend(auth.scope_for(user), limit=max(2, min(limit, 60)))}



# ── The twelve security domains ──────────────────────────────────────────────
#  Literal path before the parameterised one, as everywhere else in this file.


@app.get("/api/domains")
def api_domains(user: Dict[str, Any] = Depends(current_user)):
    """Open findings sorted into the twelve domains a buyer recognises.

    Returns all twelve ALWAYS, including the one this product does not do. A
    domain missing from the answer would be indistinguishable from a domain with
    nothing wrong in it, which is the ambiguity modules/domains.py exists to
    remove — each comes back with a REACH (what we can ever see) and a STATE
    (what this run found), and the two are not the same question.
    """
    from modules import domains
    scope = auth.scope_for(user)
    findings = queries.findings_for_domains(scope)
    return domains.roll_up(findings)


@app.get("/api/domains/{domain_id}")
def api_domain(domain_id: str,
               user: Dict[str, Any] = Depends(current_user)):
    """One domain, with the findings that landed in it.

    404 on an unknown id rather than an empty shell: an empty domain page is what
    a real domain with no findings looks like, and the two must not be confused.
    """
    from modules import domains
    definition = domains.by_id(domain_id)
    if definition is None:
        raise HTTPException(status_code=404, detail="no such domain")
    scope = auth.scope_for(user)
    findings = queries.findings_for_domains(scope)
    rolled = domains.roll_up(findings)
    entry = next(d for d in rolled["domains"] if d["id"] == domain_id)
    entry["findings"] = [
        f for f in findings
        if domains.domain_for(f.get("check_id"), f.get("category")) == domain_id
    ][:500]
    entry["categories_detail"] = sorted({
        f.get("category") for f in entry["findings"] if f.get("category")})
    return entry


#  detail.
#
#  ANYTHING ADDED BELOW THIS LINE IS UNREACHABLE. New routes go above it.
#
#  Three things depend on the ordering and are all declared above:
#    * /static      — brand assets, and a prefix the SPA's index.html hardcodes.
#    * /api/*       — including the router from server/api_auth.py. An /api path
#                     that matches NO route is refused by SpaFiles rather than
#                     answered with the console; see `_index_or_404`.
#    * /health, /ui — the operational probe and the retired-prefix redirect.
#
#  check_dir=False so the server still starts on a checkout where nobody has run
#  `npm run build`. The API is unaffected and every screen answers with the 503
#  from `_index_or_404`, which is the honest description of that state — and the
#  reason an unbuilt image is diagnosable over HTTP instead of a dead process.
app.mount(SPA_MOUNT_PATH,
          SpaFiles(directory=str(SPA_DIR), html=True, check_dir=False),
          name="spa")
