"""
SAP LogServ OCSF batch puller (connected tier)
==============================================
Pulls a time-bounded window of OCSF events from SAP LogServ and writes them as
`logserv_events.json` — the file `modules/logserv_ocsf` normalises into the
retrospective log review (`modules/log_review.py`). Run on a short cron interval,
a batch pull gives near-real-time coverage WITHOUT a persistent consumer, which
keeps this inside the `collect/` contract:

  * **stdlib only** — `urllib`/`ssl`/`json` (no broker, no third-party client);
  * **read-only** — a single authenticated GET;
  * **one artefact** — it writes the same file a customer would upload, and a
    later scan reads it; the scanner never opens the connection itself.

Credentials never come from argv: `LOGSERV_URL` and `LOGSERV_TOKEN` are read from
the environment, the same discipline the ITSM webhook and the other connectors
use. The exact query parameters follow SAP's LogServ export API; `since`/`until`
(ISO-8601 UTC) are the time-window filter assumed here.

SHAPES. Whatever this writes is read by `modules/logserv_ocsf`, which accepts BOTH
the OCSF-converted event shape and the raw LogServ record shape (`_raw`/`_time`/
`source`/`host`) — LogServ delivers logs raw and OCSF conversion is a separate step,
so a tenant may forward either. A bare list or a `{"events": [...]}` wrapper is fine.

HARDENED FOR A CRON LOOP. A single pull is still one authenticated GET, but the
puller now: retries a transient failure with backoff; follows the response's own
"next" cursor so a window larger than one page is fetched whole; carries an
incremental HIGH-WATER-MARK in a small state file so each run fetches only events
newer than the last run saw (no gap, no re-pull); and writes a manifest naming the
window, the event count and how many pages it took. The `since`/`until` parameter
NAMES still follow SAP's LogServ export API and remain the one assumed part — per
tenant they are easy to override via `--since`/`--until` (or the API's own cursor,
which is followed verbatim once seen).

Per-CLASS coverage (did the gateway / HANA / ICM / network class appear?) is NOT
computed here on purpose: `collect/` is stdlib-only and self-contained, so it must
not import `modules/`. That coverage is the ingestion-health check's job, which runs
in the scanner where it can classify the events it reads.
"""
import json
import os
import ssl
import time as _time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, List, Optional

OUTPUT_FILE = "logserv_events.json"
STATE_FILE = ".logserv_state.json"
MANIFEST_FILE = "logserv_manifest.json"
TIMEOUT_DEFAULT = 60.0
RETRIES_DEFAULT = 3
MAX_PAGES = 1000
#: Response keys that carry the next-page cursor (a full URL or a token); the first
#: one present is followed. LogServ-variant spellings are accepted, as everywhere.
_NEXT_KEYS = ("next", "next_url", "nextLink", "@odata.nextLink", "next_page",
              "next_cursor", "cursor")
#: Event-time fields, newest-wins, for the high-water-mark. OCSF `time` is ms, the
#: raw LogServ `_time` is seconds; both are normalised to epoch seconds here.
_TIME_KEYS = ("time", "_time", "timestamp")


class LogServError(RuntimeError):
    """A connection or credential failure — not an estate with no logs."""


def _require_env(name: str) -> str:
    value = (os.getenv(name) or "").strip()
    if not value:
        raise LogServError(
            "%s is not set. SAP LogServ credentials are read from the environment, "
            "never the command line — export LOGSERV_URL and LOGSERV_TOKEN before "
            "collecting." % name)
    return value


def window_since(hours: float) -> str:
    """ISO-8601 UTC timestamp `hours` before now — the start of the pull window."""
    start = datetime.now(timezone.utc) - timedelta(hours=hours)
    return start.strftime("%Y-%m-%dT%H:%M:%SZ")


def _context(verify_tls: bool, ca_file: str = None) -> ssl.SSLContext:
    if not verify_tls:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()


def events_of(payload: Any) -> List[dict]:
    """The event list inside a payload — a bare list or a wrapper object. Mirrors
    `modules.logserv_ocsf._events_of`, kept here so `collect/` imports no `modules`."""
    if isinstance(payload, list):
        return [e for e in payload if isinstance(e, dict)]
    if isinstance(payload, dict):
        for key in ("events", "data", "results", "records", "logs"):
            if isinstance(payload.get(key), list):
                return [e for e in payload[key] if isinstance(e, dict)]
    return []


def _next_cursor(payload: Any) -> str:
    if isinstance(payload, dict):
        for key in _NEXT_KEYS:
            val = payload.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
    return ""


def _get(url: str, token: str, *, verify_tls: bool, ca_file: Optional[str],
         timeout: float, retries: int) -> Any:
    """One authenticated GET, parsed as JSON, retried with backoff on a transient
    failure (a 5xx, a timeout or a connection error). A 4xx is not retried — it will
    not fix itself — and is reported as a credential/request problem."""
    req = urllib.request.Request(url, headers={
        "Authorization": "Bearer " + token, "Accept": "application/json"})
    last = None
    for attempt in range(max(1, retries)):
        try:
            with urllib.request.urlopen(req, timeout=timeout,
                                        context=_context(verify_tls, ca_file)) as resp:
                body = resp.read().decode("utf-8")
            try:
                return json.loads(body)
            except ValueError as exc:
                raise LogServError("SAP LogServ response was not JSON: %s" % exc)
        except urllib.error.HTTPError as exc:
            if exc.code < 500:
                raise LogServError("SAP LogServ returned HTTP %s" % exc.code)
            last = exc                                   # 5xx: transient, retry
        except (urllib.error.URLError, TimeoutError, ssl.SSLError) as exc:
            last = exc
        if attempt + 1 < max(1, retries):
            _time.sleep(0.5 * (2 ** attempt))            # 0.5s, 1s, 2s, …
    raise LogServError("could not reach SAP LogServ after %d attempt(s): %s"
                       % (retries, last))


def fetch(since: str, until: str = None, *, verify_tls: bool = True,
          ca_file: str = None, timeout: float = TIMEOUT_DEFAULT,
          retries: int = RETRIES_DEFAULT, classes: str = None) -> Any:
    """GET the FIRST page of a window of events from SAP LogServ (retried). Returns
    the parsed payload; `fetch_all` follows pagination over this."""
    base = _require_env("LOGSERV_URL")
    token = _require_env("LOGSERV_TOKEN")
    params = {"since": since}
    if until:
        params["until"] = until
    if classes:
        params["classes"] = classes          # optional server-side class filter
    url = base + ("&" if "?" in base else "?") + urllib.parse.urlencode(params)
    return _get(url, token, verify_tls=verify_tls, ca_file=ca_file,
                timeout=timeout, retries=retries)


def fetch_all(since: str, until: str = None, *, verify_tls: bool = True,
              ca_file: str = None, timeout: float = TIMEOUT_DEFAULT,
              retries: int = RETRIES_DEFAULT, classes: str = None,
              max_pages: int = MAX_PAGES) -> dict:
    """Fetch a window WHOLE, following the response's own next-cursor across pages.

    Returns `{"events": [...], "pages": N}`. A cursor that is a full URL is followed
    verbatim; a bare token is passed back as a `cursor` parameter. Stops at the first
    page with no cursor, or at `max_pages` (a guard against a server that always
    returns one)."""
    token = _require_env("LOGSERV_TOKEN")
    base = _require_env("LOGSERV_URL")
    payload = fetch(since, until, verify_tls=verify_tls, ca_file=ca_file,
                    timeout=timeout, retries=retries, classes=classes)
    events = events_of(payload)
    pages = 1
    cursor = _next_cursor(payload)
    while cursor and pages < max_pages:
        if cursor.startswith("http://") or cursor.startswith("https://"):
            url = cursor
        else:
            url = base + ("&" if "?" in base else "?") + urllib.parse.urlencode(
                {"cursor": cursor})
        payload = _get(url, token, verify_tls=verify_tls, ca_file=ca_file,
                       timeout=timeout, retries=retries)
        events.extend(events_of(payload))
        pages += 1
        cursor = _next_cursor(payload)
    return {"events": events, "pages": pages}


def _event_epoch_seconds(event: dict) -> Optional[float]:
    for key in _TIME_KEYS:
        raw = event.get(key)
        if raw is None:
            continue
        try:
            v = float(raw)
        except (TypeError, ValueError):
            continue
        return v / 1000.0 if v > 10_000_000_000 else v   # ms vs s
    return None


def max_event_time(payload: Any) -> Optional[float]:
    """The newest event time in a payload, as epoch seconds, or None."""
    times = [t for t in (_event_epoch_seconds(e) for e in events_of(payload))
             if t is not None]
    return max(times) if times else None


def read_since(out_dir: Path) -> Optional[str]:
    """The high-water-mark from the last run (ISO-8601 UTC), or None. One second
    after the newest event seen, so the next pull resumes without re-fetching it."""
    try:
        state = json.loads((out_dir / STATE_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    hw = state.get("high_water_mark")
    return hw if isinstance(hw, str) and hw else None


def write_state(out_dir: Path, payload: Any) -> Optional[str]:
    """Record the new high-water-mark from this payload. Returns it, or None when
    the payload carried no readable times (then the mark is left unchanged)."""
    newest = max_event_time(payload)
    if newest is None:
        return None
    resume = datetime.fromtimestamp(newest + 1, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / STATE_FILE).write_text(
        json.dumps({"high_water_mark": resume,
                    "updated_at": datetime.now(timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%SZ")}, indent=2) + "\n", encoding="utf-8")
    return resume


def write_manifest(out_dir: Path, since: str, until: Optional[str],
                   count: int, pages: int) -> None:
    """A small record of what this pull covered, beside the events file. Per-class
    coverage is added by the ingestion-health check, which can classify events."""
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / MANIFEST_FILE).write_text(json.dumps({
        "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "since": since, "until": until, "events": count, "pages": pages,
    }, indent=2) + "\n", encoding="utf-8")


def write(out_dir: Path, payload: Any) -> int:
    """Write the payload as `logserv_events.json` in the export shape a scan reads.
    Returns the event count."""
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / OUTPUT_FILE).write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return len(events_of(payload))
