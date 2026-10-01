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
"""
import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, List

OUTPUT_FILE = "logserv_events.json"
TIMEOUT_DEFAULT = 60.0


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


def fetch(since: str, until: str = None, *, verify_tls: bool = True,
          ca_file: str = None, timeout: float = TIMEOUT_DEFAULT) -> Any:
    """GET a window of OCSF events from SAP LogServ. Returns the parsed payload
    (a list of events, or a `{"events": [...]}` wrapper — both are accepted
    downstream by `modules.logserv_ocsf`)."""
    base = _require_env("LOGSERV_URL")
    token = _require_env("LOGSERV_TOKEN")
    params = {"since": since}
    if until:
        params["until"] = until
    url = base + ("&" if "?" in base else "?") + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout,
                                    context=_context(verify_tls, ca_file)) as resp:
            body = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        raise LogServError("SAP LogServ returned HTTP %s for %s" % (exc.code, base))
    except (urllib.error.URLError, TimeoutError, ssl.SSLError) as exc:
        raise LogServError("could not reach SAP LogServ at %s: %s" % (base, exc))
    try:
        return json.loads(body)
    except ValueError as exc:
        raise LogServError("SAP LogServ response was not JSON: %s" % exc)


def _event_count(payload: Any) -> int:
    if isinstance(payload, list):
        return len(payload)
    if isinstance(payload, dict):
        for key in ("events", "data", "results", "records", "logs"):
            if isinstance(payload.get(key), list):
                return len(payload[key])
    return 0


def write(out_dir: Path, payload: Any) -> int:
    """Write the OCSF payload as `logserv_events.json` in the export shape a scan
    reads. Returns the event count."""
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / OUTPUT_FILE).write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return _event_count(payload)
