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
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Form, HTTPException, Request, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from server import auth, db, ingest, queries
from server.config import settings

log = logging.getLogger(__name__)

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).with_name("templates")))
SESSION_COOKIE = "sapsec_session"

app = FastAPI(title="SAP Security Platform", docs_url="/api/docs")

#: Scans are CPU-bound Python; they must not run on the event loop or a single
#: upload would freeze every other user's console.
_scan_pool = ThreadPoolExecutor(max_workers=max(1, settings.max_concurrent_scans),
                                thread_name_prefix="scan")


@app.on_event("startup")
def _startup() -> None:
    settings.validate()
    db.init_schema()
    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    log.info("ready")


@app.on_event("shutdown")
def _shutdown() -> None:
    _scan_pool.shutdown(wait=False, cancel_futures=True)
    db.close_pool()


# --------------------------------------------------------------------------- #
#  Auth plumbing                                                              #
# --------------------------------------------------------------------------- #

def current_user(request: Request) -> Dict[str, Any]:
    user = auth.resolve_session(request.cookies.get(SESSION_COOKIE))
    if user is None:
        raise HTTPException(status_code=401, detail="not authenticated")
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


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request, next: str = "/"):
    return TEMPLATES.TemplateResponse("login.html", {"request": request, "next": next})


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...),
          next: str = Form("/")):
    user = auth.authenticate(username, password)
    if user is None:
        return TEMPLATES.TemplateResponse(
            "login.html",
            {"request": request, "next": next, "error": "Invalid credentials"},
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
    return TEMPLATES.TemplateResponse("dashboard.html", {
        "request": request, "user": user,
        "summary": queries.dashboard_summary(scope),
        "systems": queries.list_systems(scope),
        "recent_runs": queries.recent_runs(scope, limit=10),
    })


@app.get("/findings", response_class=HTMLResponse)
def findings_page(request: Request, user: Dict[str, Any] = Depends(current_user),
                  system_id: Optional[int] = None, state: Optional[str] = None,
                  severity: Optional[str] = None, team: Optional[str] = None,
                  owner: Optional[str] = None, page: int = 1):
    scope = auth.scope_for(user)
    result = queries.list_findings(scope, system_id=system_id, state=state,
                                   severity=severity, team=team,
                                   remediation_owner=owner, page=page)
    return TEMPLATES.TemplateResponse("findings.html", {
        "request": request, "user": user, **result,
        "filters": {"system_id": system_id, "state": state, "severity": severity,
                    "team": team, "owner": owner},
        "systems": queries.list_systems(scope),
    })


@app.get("/findings/{finding_id}", response_class=HTMLResponse)
def finding_detail(finding_id: int, request: Request,
                   user: Dict[str, Any] = Depends(current_user)):
    scope = auth.scope_for(user)
    finding = queries.get_finding(finding_id, scope)
    if finding is None:
        raise HTTPException(404, "not found")
    return TEMPLATES.TemplateResponse("finding_detail.html", {
        "request": request, "user": user, "finding": finding,
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
    return TEMPLATES.TemplateResponse("run_detail.html", {
        "request": request, "user": user, "run": run,
        "diff": queries.run_diff(run_id, scope),
    })


@app.get("/upload", response_class=HTMLResponse)
def upload_form(request: Request, user: Dict[str, Any] = Depends(require("analyst"))):
    return TEMPLATES.TemplateResponse("upload.html", {
        "request": request, "user": user,
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
