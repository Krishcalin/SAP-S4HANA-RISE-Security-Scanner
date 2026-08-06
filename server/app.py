"""
FastAPI application.

ONE QUERY LAYER, MANY RENDERINGS
--------------------------------
Every route below reads through the same helpers the JSON API uses. The invariant
worth copying from the incumbent — "everything the dashboard shows is available
via the API" — only holds if it is structural rather than remembered, so the HTML
pages and the JSON endpoints call the same functions and differ only in how they
render the result.

Reporting is READ ACCESS, not file production. Each audience gets a durable,
permission-scoped URL rather than a document somebody has to fetch and forward —
the workaround an incumbent's customers resorted to (batch scripts re-posting to
SharePoint) is a design smell we are deliberately not reproducing.
"""
from __future__ import annotations

import asyncio
import logging
import shutil
import tempfile
import zipfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, quote, urlencode, urlparse

from fastapi import Depends, FastAPI, Form, HTTPException, Request, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from server import analytics, auth, crq, db, graph, ingest, queries, sapcontent
from server.config import settings

log = logging.getLogger(__name__)

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).with_name("templates")))
SESSION_COOKIE = "sapsec_session"


def _money(value: Any) -> str:
    """Render a currency figure the way a board reads one.

    Loss exposure spans several orders of magnitude across scenarios, and
    "$1,240,000" next to "$8,300" is harder to compare at a glance than
    "$1.24M" next to "$8.3K". `None` renders as an em dash rather than "$0" —
    "not computed" and "zero risk" are very different claims.
    """
    if value is None:
        return "—"
    try:
        n = float(value)
    except (TypeError, ValueError):
        return "—"
    for limit, suffix in ((1e9, "B"), (1e6, "M"), (1e3, "K")):
        if abs(n) >= limit:
            return f"${n / limit:,.2f}{suffix}".replace(".00", "")
    return f"${n:,.0f}"


TEMPLATES.env.globals["money"] = _money

app = FastAPI(title="SAP Security Platform", docs_url="/api/docs")

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

#: Reachable while an account is still on a generated password. Everything else
#: redirects to /account until it is replaced — including the API, so a forced
#: account cannot simply be scripted around.
_ALLOWED_WHILE_FORCED = ("/account", "/logout", "/login", "/health")


def current_user(request: Request) -> Dict[str, Any]:
    user = auth.resolve_session(request.cookies.get(SESSION_COOKIE))
    if user is None:
        raise HTTPException(status_code=401, detail="not authenticated")
    if auth.must_change_password(user) and not request.url.path.startswith(
            _ALLOWED_WHILE_FORCED):
        # 303 rather than 403: the caller is authenticated and the fix is one
        # page away, so send them to it instead of refusing with no route out.
        raise HTTPException(status_code=303, detail="password change required")
    return user


def require(role: str):
    def dep(user: Dict[str, Any] = Depends(current_user)) -> Dict[str, Any]:
        if not auth.has_role(user, role):
            raise HTTPException(status_code=403, detail=f"requires {role}")
        return user
    return dep


@app.exception_handler(401)
async def _unauth(request: Request, exc: HTTPException):
    """Browsers get the login page; API clients get JSON."""
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": "not authenticated"}, status_code=401)
    return RedirectResponse(f"/login?next={request.url.path}", status_code=303)


@app.exception_handler(303)
async def _must_change(request: Request, exc: HTTPException):
    if request.url.path.startswith("/api/"):
        return JSONResponse(
            {"detail": "password change required", "change_at": "/account"},
            status_code=403)
    return RedirectResponse("/account", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request, next: str = "/"):
    return TEMPLATES.TemplateResponse(request, "login.html", {"next": next})


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...),
          next: str = Form("/")):
    user = auth.authenticate(username, password)
    if user is None:
        return TEMPLATES.TemplateResponse(
            request, "login.html",
            {"next": next, "error": "Invalid credentials"},
            status_code=401)
    token = auth.create_session(user["id"], request.headers.get("user-agent", ""))
    # Redirect target is constrained to a local path: an open redirect here would
    # let a phishing link bounce a freshly-authenticated user off-site.
    target = next if next.startswith("/") and not next.startswith("//") else "/"
    resp = RedirectResponse(target, status_code=303)
    resp.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax",
                    secure=request.url.scheme == "https",
                    max_age=settings.session_ttl_hours * 3600)
    return resp


@app.post("/logout")
def logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        auth.destroy_session(token)
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


# --------------------------------------------------------------------------- #
#  Console                                                                    #
# --------------------------------------------------------------------------- #

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, user: Dict[str, Any] = Depends(current_user)):
    scope = auth.scope_for(user)
    latest_crq = crq.latest(scope)
    return TEMPLATES.TemplateResponse(request, "dashboard.html", {
        "user": user,
        "summary": queries.dashboard_summary(scope),
        "systems": queries.list_systems(scope),
        "recent_runs": queries.recent_runs(scope, limit=10),
        "crq": latest_crq,
        "crq_scenarios": crq.scenarios_for_run(latest_crq["run_id"]) if latest_crq else [],
    })


@app.get("/findings", response_class=HTMLResponse)
def findings_page(request: Request, user: Dict[str, Any] = Depends(current_user),
                  system_id: Optional[int] = None, state: Optional[str] = None,
                  severity: Optional[str] = None, team: Optional[str] = None,
                  owner: Optional[str] = None, tier: Optional[str] = None,
                  assignee: Optional[str] = None, overdue: bool = False,
                  page: int = 1):
    scope = auth.scope_for(user)
    result = queries.list_findings(scope, system_id=system_id, state=state,
                                   severity=severity, team=team,
                                   remediation_owner=owner, tier=tier,
                                   assignee=assignee, overdue=overdue, page=page)
    return TEMPLATES.TemplateResponse(request, "findings.html", {
        "user": user, **result,
        "filters": {"system_id": system_id, "state": state, "severity": severity,
                    "team": team, "owner": owner, "tier": tier,
                    "assignee": assignee, "overdue": overdue},
        "systems": queries.list_systems(scope),
        "views": queries.list_views(user["username"], "findings"),
    })


@app.get("/trend", response_class=HTMLResponse)
def trend_page(request: Request, user: Dict[str, Any] = Depends(current_user),
               days: int = 180):
    """The mitigation journey — answers "is it getting better" without an export."""
    scope = auth.scope_for(user)
    return TEMPLATES.TemplateResponse(request, "trend.html", {
        "user": user, "days": days,
        "j": analytics.journey_summary(scope, days),
    })


@app.get("/risk", response_class=HTMLResponse)
def risk_page(request: Request, user: Dict[str, Any] = Depends(current_user)):
    """Financial risk exposure — the board view.

    Neither incumbent produces a currency figure at all, which makes this the
    cleanest differentiated screen in the product.
    """
    scope = auth.scope_for(user)
    latest = crq.latest(scope)
    return TEMPLATES.TemplateResponse(request, "risk.html", {
        "user": user,
        "crq": latest,
        "scenarios": crq.scenarios_for_run(latest["run_id"]) if latest else [],
        "trend": crq.trend(scope),
    })


@app.get("/api/risk")
def api_risk(user: Dict[str, Any] = Depends(current_user)):
    scope = auth.scope_for(user)
    latest = crq.latest(scope)
    return {"portfolio": latest,
            "scenarios": crq.scenarios_for_run(latest["run_id"]) if latest else [],
            "trend": crq.trend(scope)}


@app.get("/paths", response_class=HTMLResponse)
def paths_page(request: Request, user: Dict[str, Any] = Depends(current_user)):
    """Ranked path list plus choke points. The graph is NOT here — it renders inside
    one selected path, which is what keeps this legible at landscape scale."""
    scope = auth.scope_for(user)
    return TEMPLATES.TemplateResponse(request, "paths.html", {
        "user": user,
        "paths": graph.list_paths(scope),
        "chokes": graph.chokepoints(scope),
        "summary": graph.path_summary(scope),
        "closed": graph.recently_closed(scope),
        "template_count": len(graph.load_templates().get("paths", [])),
    })


@app.get("/paths/{path_id}", response_class=HTMLResponse)
def path_detail(path_id: int, request: Request,
                user: Dict[str, Any] = Depends(current_user)):
    scope = auth.scope_for(user)
    path = graph.get_path(path_id, scope)
    if path is None:
        raise HTTPException(404, "not found")
    findings = graph.path_findings(path_id)
    # Cut findings drive the mitigate-vs-additional split on the page.
    cut_ids = {fid for hop in (path["detail"].get("hops") or []) if hop.get("is_cut")
               for fid in hop.get("finding_ids", [])}
    return TEMPLATES.TemplateResponse(request, "path_detail.html", {
        "user": user, "path": path, "findings": findings, "cut_ids": cut_ids,
    })


@app.get("/api/paths")
def api_paths(user: Dict[str, Any] = Depends(current_user),
              include_closed: bool = False):
    scope = auth.scope_for(user)
    return {"summary": graph.path_summary(scope),
            "paths": graph.list_paths(scope, include_closed=include_closed),
            "chokepoints": graph.chokepoints(scope)}


@app.get("/coverage", response_class=HTMLResponse)
def coverage_page(request: Request, user: Dict[str, Any] = Depends(current_user)):
    """The published check catalogue and its coverage of SAP's own Baseline.

    Coverage is computed from the check ids actually in the catalogue, so the page
    cannot drift from what the scanner really does.
    """
    check_ids = [r["check_id"] for r in db.query("SELECT check_id FROM check_definition")]
    cat = sapcontent.load_catalogue()
    return TEMPLATES.TemplateResponse(request, "coverage.html", {
        "user": user,
        "cov": sapcontent.coverage(check_ids, cat),
        "meta": cat.get("_meta", {}),
        "our_checks": len(check_ids),
    })


@app.get("/api/coverage")
def api_coverage(user: Dict[str, Any] = Depends(current_user)):
    check_ids = [r["check_id"] for r in db.query("SELECT check_id FROM check_definition")]
    return sapcontent.coverage(check_ids)


@app.get("/account", response_class=HTMLResponse)
def account_page(request: Request, user: Dict[str, Any] = Depends(current_user),
                 changed: bool = False, error: str = None):
    return TEMPLATES.TemplateResponse(request, "account.html", {
        "user": user,
        "forced": auth.must_change_password(user),
        "changed": changed, "error": error,
        "sessions": db.one("SELECT count(*) n FROM session WHERE user_id = %s",
                           (user["id"],))["n"],
        "users": (db.query("SELECT * FROM app_user ORDER BY username")
                  if user["role"] == "admin" else []),
        # A generated password is rendered ONCE, on the response to the reset
        # that created it. It is never carried in a redirect or a query
        # string, where it would land in browser history, in a proxy log and
        # in the referer header.
        "generated": None,
    })


@app.post("/account/password")
def change_password(request: Request, current: str = Form(...),
                    new1: str = Form(...), new2: str = Form(...),
                    user: Dict[str, Any] = Depends(current_user)):
    """Change your own password.

    The CURRENT password is required even though the caller is already signed in:
    a stolen session should not be enough to take an account over permanently.
    """
    def back(msg):
        return RedirectResponse(f"/account?error={quote(msg)}", status_code=303)

    if not auth.verify_password(current, user["password_hash"]):
        return back("Current password is incorrect.")
    if new1 != new2:
        return back("The new passwords do not match.")
    if new1 == current:
        return back("The new password must differ from the current one.")
    try:
        auth.set_password(user["id"], new1, user["username"],
                          keep_token=request.cookies.get(SESSION_COOKIE))
    except auth.AuthError as exc:
        return back(str(exc))
    return RedirectResponse("/account?changed=true", status_code=303)


@app.post("/account/reset/{user_id}")
def reset_user_password(user_id: int, request: Request,
                        admin: Dict[str, Any] = Depends(require("admin"))):
    """Admin resets someone else's password by GENERATING one.

    Never by choosing it: an admin who can set a known password can impersonate a
    user and leave nothing that user could distinguish from their own activity.
    """
    target = db.one("SELECT username FROM app_user WHERE id = %s", (user_id,))
    if target is None:
        raise HTTPException(404, "no such user")
    if user_id == admin["id"]:
        raise HTTPException(400, "use the change-password form for your own account")
    new = auth.reset_password(user_id, admin["username"])
    return TEMPLATES.TemplateResponse(request, "account.html", {
        "user": admin, "forced": False, "changed": False, "error": None,
        "sessions": db.one("SELECT count(*) n FROM session WHERE user_id = %s",
                           (admin["id"],))["n"],
        "users": db.query("SELECT * FROM app_user ORDER BY username"),
        "generated": {"username": target["username"], "password": new},
    })


@app.get("/v/{slug}")
def open_view(slug: str, user: Dict[str, Any] = Depends(current_user)):
    """Open a saved view — the durable, permission-scoped URL per audience.

    The stored FILTERS are replayed as query parameters and the query re-runs under
    THIS caller's row scope, so a shared link can never widen access: two people
    following the same URL each see the systems they are entitled to.
    """
    view = queries.get_view(slug, user["username"])
    if view is None:
        raise HTTPException(404, "no such view")
    qs = urlencode({k: v for k, v in (view["filters"] or {}).items()
                    if v not in (None, "")})
    target = {"findings": "/findings", "trend": "/trend"}.get(view["kind"], "/findings")
    return RedirectResponse(f"{target}?{qs}" if qs else target, status_code=303)


@app.post("/api/views")
def api_save_view(name: str = Form(...), slug: str = Form(...),
                  kind: str = Form("findings"), shared: bool = Form(True),
                  description: str = Form(""), request: Request = None,
                  user: Dict[str, Any] = Depends(require("analyst"))):
    """Save the current filters as a durable URL.

    Filters come from the referring page's query string rather than a body, so
    "save this view" is literally "save what I am looking at".
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
    return analytics.journey_summary(auth.scope_for(user), days)


@app.get("/findings/{finding_id}", response_class=HTMLResponse)
def finding_detail(finding_id: int, request: Request,
                   user: Dict[str, Any] = Depends(current_user)):
    scope = auth.scope_for(user)
    finding = queries.get_finding(finding_id, scope)
    if finding is None:
        raise HTTPException(404, "not found")
    return TEMPLATES.TemplateResponse(request, "finding_detail.html", {
        "user": user, "finding": finding,
        "history": queries.finding_history(finding_id),
        "observations": queries.finding_observations(finding_id),
    })


@app.get("/runs/{run_id}", response_class=HTMLResponse)
def run_detail(run_id: int, request: Request,
               user: Dict[str, Any] = Depends(current_user)):
    scope = auth.scope_for(user)
    run = queries.get_run(run_id, scope)
    if run is None:
        raise HTTPException(404, "not found")
    return TEMPLATES.TemplateResponse(request, "run_detail.html", {
        "user": user, "run": run,
        "diff": queries.run_diff(run_id, scope),
    })


@app.get("/upload", response_class=HTMLResponse)
def upload_form(request: Request, user: Dict[str, Any] = Depends(require("analyst"))):
    return TEMPLATES.TemplateResponse(request, "upload.html", {
        "user": user,
        "systems": queries.list_systems(auth.scope_for(user)),
        "landscapes": queries.list_landscapes(),
    })


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
#  JSON API — the same query layer the pages use                              #
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
                 severity: Optional[str] = None, page: int = 1):
    return queries.list_findings(auth.scope_for(user), system_id=system_id,
                                 state=state, severity=severity, page=page)


@app.get("/api/findings/changes")
def api_changes(since_run: int, user: Dict[str, Any] = Depends(current_user)):
    """Findings that changed since a given run.

    Nearly free for us because the run-over-run diff already exists — and it is
    something the incumbent's integrators explicitly cannot get, since their sync
    is documented as full-only with no incremental filter.
    """
    return queries.changes_since(since_run, auth.scope_for(user))


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


@app.get("/health")
def health():
    """Degraded components are reported, never hidden — a green light over a
    broken collector is worse than a red one."""
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
