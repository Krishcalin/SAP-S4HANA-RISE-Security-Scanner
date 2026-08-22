"""Outbound ITSM delivery, and the four ways it could quietly lose a CRITICAL.

WHAT WAS ALREADY THERE. `ingest.queue_notifications` has written rows for new
CRITICALs and regressions since Phase 2, and the schema gave `notification` a
`delivered_at`, a `delivery_error` and an index on the undelivered — everything
except something that delivers. The queue filled up and drained nowhere.

WHAT THESE TESTS PIN. Marking a row delivered before the POST returns, letting
one bad row block the queue behind it, sending over plain HTTP by default, and
putting the token somewhere it gets logged. Each of those is a silent failure
rather than a loud one, which is why they are tested rather than reviewed.
"""
from __future__ import annotations

import json
import sys
import urllib.error
from pathlib import Path
from typing import Any, Dict, List

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server import webhook                                     # noqa: E402


class FakeResult:
    def __init__(self, rows): self._rows = rows
    def fetchall(self): return self._rows
    def fetchone(self): return self._rows[0] if self._rows else None


class FakeConn:
    """Just enough connection to exercise the drain, and it records the UPDATEs
    so the order of POST-then-mark is checkable."""

    def __init__(self, rows: List[Dict[str, Any]]):
        self.rows = rows
        self.statements: List[str] = []
        self.params: List[Any] = []
        #: Set by the test's fake `post`. The ordering test compares against it
        #: rather than against statement indices, which shift whenever the drain
        #: gains a query.
        self.posted = False
        self.marked_after_post = None

    def execute(self, sql, params=None):
        flat = " ".join(sql.split())
        if "delivered_at = now()" in flat and self.marked_after_post is None:
            self.marked_after_post = self.posted
        self.statements.append(flat)
        self.params.append(params)
        if "FROM notification WHERE delivered_at IS NULL" in " ".join(sql.split()):
            return FakeResult(self.rows)
        if "count(*)" in sql:
            return FakeResult([{"n": len(self.rows)}])
        return FakeResult([])

    def commit(self): pass


def _row(nid=1, severity="CRITICAL", subject="s"):
    return {"id": nid, "scan_run_id": 7, "kind": "new_critical",
            "severity": severity, "subject": subject, "body": "b",
            "payload": {"finding_ids": [1, 2]}}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in ("ITSM_WEBHOOK_URL", "ITSM_WEBHOOK_TOKEN", "ITSM_WEBHOOK_INSECURE"):
        monkeypatch.delenv(name, raising=False)


# ═════════════════════════════════════════════════════════════════════════════
#  Not configured is not broken
# ═════════════════════════════════════════════════════════════════════════════

def test_no_endpoint_leaves_the_queue_alone_and_says_why():
    """A deployment without an ITSM is a deployment choice. Reporting it as a
    failure trains the operator to ignore the exit code."""
    conn = FakeConn([_row()])
    got = webhook.deliver(conn)
    assert got["configured"] is False and got["delivered"] == 0
    assert "deployment choice, not a failure" in got["note"]
    assert not any("UPDATE" in s for s in conn.statements)


# ═════════════════════════════════════════════════════════════════════════════
#  The transport
# ═════════════════════════════════════════════════════════════════════════════

def test_plain_http_is_refused_by_default(monkeypatch):
    """A webhook carrying check ids and finding counts over an unencrypted hop is
    a real exposure."""
    monkeypatch.setenv("ITSM_WEBHOOK_URL", "http://itsm.internal/hook")
    with pytest.raises(webhook.WebhookNotConfigured) as exc:
        webhook.deliver(FakeConn([_row()]))
    assert "ITSM_WEBHOOK_INSECURE" in str(exc.value)


def test_plain_http_is_allowed_when_asked_for(monkeypatch):
    """An internal ITSM on http:// is a real deployment. The point is that it is
    a decision somebody made rather than a default they inherited."""
    monkeypatch.setenv("ITSM_WEBHOOK_URL", "http://itsm.internal/hook")
    monkeypatch.setenv("ITSM_WEBHOOK_INSECURE", "1")
    monkeypatch.setattr(webhook, "post", lambda url, body, timeout=15: 200)
    assert webhook.deliver(FakeConn([_row()]))["delivered"] == 1


def test_the_token_travels_as_a_header_not_in_the_url(monkeypatch):
    """A URL lands in access logs and proxy history, and a token in one is a
    token to rotate."""
    monkeypatch.setenv("ITSM_WEBHOOK_TOKEN", "s3cret")
    headers = webhook._headers()
    assert headers["Authorization"] == "Bearer s3cret"


def test_no_token_sends_no_authorization_header(monkeypatch):
    assert "Authorization" not in webhook._headers()


def test_the_endpoint_is_configured_from_the_environment_not_argv():
    """Same rule as every other secret here: an argument is visible in ps and in
    shell history."""
    src = (ROOT / "server" / "cli.py").read_text(encoding="utf-8")
    assert "--webhook-url" not in src and "--token" not in src
    assert "ITSM_WEBHOOK_URL" in src


# ═════════════════════════════════════════════════════════════════════════════
#  Delivery semantics
# ═════════════════════════════════════════════════════════════════════════════

def test_a_row_is_marked_delivered_only_after_the_post_returns(monkeypatch):
    """THE ORDER THAT LOSES ALERTS. Marking first and posting second drops every
    notification in flight when the process dies; marking second repeats one,
    which is recoverable."""
    monkeypatch.setenv("ITSM_WEBHOOK_URL", "https://itsm/hook")
    seen: List[str] = []
    conn = FakeConn([_row()])

    def fake_post(url, body, timeout=15):
        seen.append("post")
        conn.posted = True
        return 200

    monkeypatch.setattr(webhook, "post", fake_post)
    webhook.deliver(conn)
    # THE ASSERTION THIS REPLACED COULD NOT FAIL EITHER: `update_at` was FOUND by
    # searching for "delivered_at = now()", so re-asserting that the statement at
    # that index contains it was a tautology. What matters is the ORDER, so the
    # POST is recorded with a marker and the two positions are compared.
    assert seen == ["post"], "the POST must happen"
    marks = [i for i, s in enumerate(conn.statements) if "delivered_at = now()" in s]
    assert len(marks) == 1, "exactly one row should be marked delivered"
    assert conn.marked_after_post is True,         "the row was marked delivered BEFORE the POST returned — every "        "notification in flight is lost if the process dies there"


def test_the_payload_carries_a_stable_deduplication_key(monkeypatch):
    """Delivery is at-least-once. A receiver that ignores this will occasionally
    open two tickets for one alert, so it has to be there and be stable."""
    body = webhook.payload_for(_row(nid=99))
    assert body["notification_id"] == 99
    assert body["source"] == "MonitorRisk"


def test_the_note_tells_the_operator_delivery_is_at_least_once(monkeypatch):
    monkeypatch.setenv("ITSM_WEBHOOK_URL", "https://itsm/hook")
    monkeypatch.setattr(webhook, "post", lambda url, body, timeout=15: 200)
    got = webhook.deliver(FakeConn([_row()]))
    assert "deduplicate on" in got["note"]


def test_one_failure_does_not_block_the_queue_behind_it(monkeypatch):
    """An ITSM rejecting one malformed subject must not hold up the CRITICAL
    behind it."""
    monkeypatch.setenv("ITSM_WEBHOOK_URL", "https://itsm/hook")

    def flaky(url, body, timeout=15):
        if body["notification_id"] == 1:
            raise urllib.error.URLError("refused")
        return 200

    monkeypatch.setattr(webhook, "post", flaky)
    got = webhook.deliver(FakeConn([_row(nid=1), _row(nid=2)]))
    assert got["delivered"] == 1 and got["failed"] == 1


def test_a_failure_is_recorded_on_the_row_an_operator_will_read(monkeypatch):
    """`delivery_error` is what somebody reads when a ticket never appeared."""
    monkeypatch.setenv("ITSM_WEBHOOK_URL", "https://itsm/hook")
    monkeypatch.setattr(webhook, "post",
                        lambda *a, **k: (_ for _ in ()).throw(urllib.error.URLError("nope")))
    conn = FakeConn([_row()])
    webhook.deliver(conn)
    assert any("delivery_error = %s" in s for s in conn.statements)
    assert any(p and "nope" in str(p[0]) for p in conn.params if p)


def test_a_non_2xx_response_is_a_failure_not_a_delivery(monkeypatch):
    """A 202 is success; a 400 is an ITSM saying no. Treating every response that
    did not raise as delivered would mark rejected alerts as sent."""
    monkeypatch.setenv("ITSM_WEBHOOK_URL", "https://itsm/hook")
    monkeypatch.setattr(webhook, "post", lambda url, body, timeout=15: 400)
    got = webhook.deliver(FakeConn([_row()]))
    assert got["delivered"] == 0 and got["failed"] == 1


def test_the_drain_is_bounded_so_an_outage_cannot_hold_the_process(monkeypatch):
    monkeypatch.setenv("ITSM_WEBHOOK_URL", "https://itsm/hook")
    calls = []
    monkeypatch.setattr(webhook, "post",
                        lambda url, body, timeout=15: calls.append(1) or 200)
    conn = FakeConn([_row(nid=i) for i in range(5)])
    webhook.deliver(conn, limit=2)
    assert conn.params[0] == (2,)


# ═════════════════════════════════════════════════════════════════════════════
#  What it must not carry
# ═════════════════════════════════════════════════════════════════════════════

def test_the_payload_carries_no_more_than_the_notification_composed():
    """A webhook leaves the customer's boundary. Audit-log records are personal
    data and never reach a notification in the first place; this must not become
    the place that changes."""
    body = webhook.payload_for(_row())
    assert set(body) == {"notification_id", "scan_run_id", "kind", "severity",
                         "subject", "body", "detail", "source"}


def test_the_module_says_it_is_not_a_per_vendor_integration():
    """Every ITSM in this market accepts an inbound webhook; a ServiceNow app is
    a per-vendor maintenance burden for a shape the customer should map."""
    src = (ROOT / "server" / "webhook.py").read_text(encoding="utf-8")
    assert "NOT A SERVICENOW APP" in src
