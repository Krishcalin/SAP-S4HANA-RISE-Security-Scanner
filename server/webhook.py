"""Outbound delivery of queued notifications to an ITSM endpoint.

WHAT WAS ALREADY THERE, AND WHAT WAS NOT. `ingest.queue_notifications` has
written rows for new CRITICALs and regressions since Phase 2, and the schema gave
`notification` a `delivered_at`, a `delivery_error` and an index on the
undelivered — everything except something that delivers. The queue filled up and
drained nowhere.

NOT A SERVICENOW APP, DELIBERATELY. The roadmap says so and it is the right call:
a per-vendor integration is a per-vendor maintenance burden and every ITSM in
this market accepts an inbound webhook. One POST of JSON reaches ServiceNow, Jira
Service Management, a Teams channel or a customer's own bus, and the shape is
theirs to map rather than ours to guess.

WHAT IT SENDS, AND WHAT IT REFUSES TO. The payload is the notification: kind,
severity, subject, body and the finding ids already in `payload`. It carries NO
finding detail beyond what `queue_notifications` composed — check id, title, and
how many times something regressed. That matters because a webhook leaves the
customer's boundary: audit-log records are personal data and never reach a
notification in the first place, and this must not become the place that changes.

CREDENTIALS COME FROM THE ENVIRONMENT, NEVER FROM argv. The same rule as every
other secret in this product — an argument is visible in `ps` and in shell
history, and `tests/test_cli_no_password_flag.py` enforces the absence of the
flag. `ITSM_WEBHOOK_URL` and `ITSM_WEBHOOK_TOKEN`.

PLAIN HTTP IS REFUSED UNLESS ASKED FOR. A webhook carrying check ids and finding
counts over an unencrypted hop is a real exposure, and an internal ITSM on http://
is a real deployment. So it is allowed, and only on purpose: `ITSM_WEBHOOK_INSECURE=1`.

DELIVERY IS AT-LEAST-ONCE AND SAYS SO. A row is marked delivered after the POST
returns 2xx. A crash between the POST and the UPDATE re-sends on the next drain,
which is why the payload carries a stable `notification_id` for the receiver to
deduplicate on. The alternative — marking delivered before the POST — loses
notifications silently, and a lost CRITICAL alert is worse than a repeated one.
"""
from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

#: How many attempts one drain makes before leaving the rest queued. A drain that
#: retried forever would hold the process open through an ITSM outage; the rows
#: stay undelivered and the next drain picks them up.
DEFAULT_LIMIT = 50

TIMEOUT_SECONDS = 15


class WebhookNotConfigured(RuntimeError):
    """No endpoint. Not an error — a deployment that does not use one."""


def endpoint() -> Optional[str]:
    return (os.getenv("ITSM_WEBHOOK_URL") or "").strip() or None


def _headers() -> Dict[str, str]:
    headers = {"Content-Type": "application/json",
               "User-Agent": "MonitorRisk-notify/1"}
    token = (os.getenv("ITSM_WEBHOOK_TOKEN") or "").strip()
    if token:
        # Bearer rather than a query parameter: a URL lands in access logs and
        # proxy history, and a token in one is a token to rotate.
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _check_scheme(url: str) -> None:
    if url.lower().startswith("https://"):
        return
    if url.lower().startswith("http://") and os.getenv("ITSM_WEBHOOK_INSECURE") == "1":
        log.warning("ITSM webhook is plain HTTP; findings cross the network in "
                    "clear text because ITSM_WEBHOOK_INSECURE=1 was set")
        return
    raise WebhookNotConfigured(
        "ITSM_WEBHOOK_URL must be https://. An internal ITSM on http:// is a real "
        "deployment, so it is allowed — deliberately, by setting "
        "ITSM_WEBHOOK_INSECURE=1. Findings crossing an unencrypted hop should be "
        "a decision somebody made rather than a default they inherited.")


def payload_for(row: Dict[str, Any]) -> Dict[str, Any]:
    """The JSON one notification becomes.

    `notification_id` is stable and is the receiver's deduplication key —
    delivery is at-least-once, so a receiver that ignores it will occasionally
    open two tickets for one alert.
    """
    return {
        "notification_id": row["id"],
        "scan_run_id": row.get("scan_run_id"),
        "kind": row.get("kind"),
        "severity": row.get("severity"),
        "subject": row.get("subject"),
        "body": row.get("body"),
        "detail": row.get("payload") or {},
        "source": "MonitorRisk",
    }


def post(url: str, body: Dict[str, Any], timeout: int = TIMEOUT_SECONDS) -> int:
    request = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers=_headers(), method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return int(response.status)


def deliver(conn: Any, limit: int = DEFAULT_LIMIT) -> Dict[str, Any]:
    """Drain the undelivered queue. Returns a summary, never raises on a bad POST.

    ONE FAILURE DOES NOT STOP THE DRAIN. An ITSM rejecting one malformed subject
    must not hold up the CRITICAL behind it, so each row is attempted and its
    error recorded on the row itself. `delivery_error` is what an operator reads
    when a ticket never appeared.
    """
    url = endpoint()
    if not url:
        return {"configured": False, "delivered": 0, "failed": 0, "pending": None,
                "note": "No ITSM_WEBHOOK_URL is set, so notifications stay queued. "
                        "That is a deployment choice, not a failure."}
    _check_scheme(url)

    rows = conn.execute(
        "SELECT id, scan_run_id, kind, severity, subject, body, payload "
        "FROM notification WHERE delivered_at IS NULL "
        "ORDER BY created_at LIMIT %s", (limit,)).fetchall()

    delivered = failed = 0
    for row in rows:
        record = dict(row)
        try:
            status = post(url, payload_for(record))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            failed += 1
            conn.execute("UPDATE notification SET delivery_error = %s WHERE id = %s",
                         (str(exc)[:500], record["id"]))
            continue
        if 200 <= status < 300:
            # AFTER the POST, never before: a crash here re-sends, and a repeated
            # alert is recoverable where a dropped CRITICAL is not.
            conn.execute("UPDATE notification SET delivered_at = now(), "
                         "delivery_error = NULL WHERE id = %s", (record["id"],))
            delivered += 1
        else:
            failed += 1
            conn.execute("UPDATE notification SET delivery_error = %s WHERE id = %s",
                         (f"HTTP {status}", record["id"]))

    pending = conn.execute(
        "SELECT count(*) AS n FROM notification WHERE delivered_at IS NULL"
    ).fetchone()
    remaining = (dict(pending).get("n") if pending else 0) or 0
    return {"configured": True, "delivered": delivered, "failed": failed,
            "pending": remaining,
            "note": ("%d delivered, %d failed, %d still queued. Delivery is "
                     "at-least-once: the receiver should deduplicate on "
                     "notification_id." % (delivered, failed, remaining))}
