"""Security Monitor — the per-domain, per-check posture lens.

server/security_monitor.py regroups the findings a scan already produced into the
twelve security domains and, within each, the checks that fired — a strip + cards,
the way the market's monitors present posture, with MonitorRisk's honesty bolted
on. What must hold: a finding lands in the SAME domain domains.roll_up counts it
in (so the per-check totals SUM to the domain total — the two can never disagree);
every card carries a valid owner badge, decided by deployment mode; the domain
with no reach is always counted as not-assessed and never as clear; and the
summary tiles keep not-assessed separate from clear.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import domains                        # noqa: E402
from server import security_monitor as sm          # noqa: E402

pg = pytest.mark.skipif(not os.getenv("DB_DSN"),
                        reason="set DB_DSN to a PostgreSQL 16 instance")

_OWNERS = {"customer_fixable", "ticket_to_sap", "provider_owned", "not_assessable"}


def _f(fid, check_id, category, severity="HIGH"):
    return {"id": fid, "check_id": check_id, "severity": severity,
            "priority_tier": "P2", "title": f"{check_id} finding",
            "category": category, "sid": "PRD", "state": "open"}


# Real (check_id, category) pairs that the taxonomy places in a domain.
_AUTH = ("AUTH-015", "ABAP Authorization & Critical Access")
_PARAM = ("PARAM-login/min_password_length", "Security Baseline Parameters")
_HOTNEWS = ("HOTNEWS-001", "SAP Security Notes (HotNews)")


def _domains_by_id(view):
    return {d["id"]: d for d in view["domains"]}


# ── grouping + reconciliation ────────────────────────────────────────────────

def test_a_finding_lands_in_the_same_domain_the_strip_counts_it_in():
    findings = [_f(1, *_AUTH, "CRITICAL"), _f(2, *_AUTH, "HIGH"), _f(3, *_PARAM)]
    view = sm.roll_up(findings)
    by_id = _domains_by_id(view)

    for fid_cid_cat in (_AUTH, _PARAM):
        cid, cat = fid_cid_cat
        did = domains.domain_for(cid, cat)
        assert did is not None, cid
        cards = {c["check_id"]: c for c in by_id[did]["checks"]}
        assert cid in cards, f"{cid} missing from domain {did}"


def test_per_check_totals_sum_to_the_domain_total():
    """The load-bearing invariant: the cards in a tab add up to the tab's own
    count, because both come from domains.domain_for. If this drifts, the strip
    and the cards disagree about the same estate."""
    findings = [_f(1, *_AUTH, "CRITICAL"), _f(2, *_AUTH, "HIGH"),
                _f(3, *_PARAM), _f(4, *_HOTNEWS, "CRITICAL")]
    view = sm.roll_up(findings)
    for d in view["domains"]:
        assert sum(c["total"] for c in d["checks"]) == d["total"], d["id"]
        # and the severity breakdown reconciles too
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert sum(c["counts"][s] for c in d["checks"]) == d["counts"][s]


def test_worst_severity_and_card_order():
    findings = [_f(1, *_AUTH, "LOW"), _f(2, *_AUTH, "CRITICAL")]
    view = sm.roll_up(findings)
    did = domains.domain_for(*_AUTH)
    card = {c["check_id"]: c for c in _domains_by_id(view)[did]["checks"]}[_AUTH[0]]
    assert card["worst"] == "CRITICAL" and card["total"] == 2
    assert card["counts"]["CRITICAL"] == 1 and card["counts"]["LOW"] == 1


# ── owner badge ──────────────────────────────────────────────────────────────

def test_every_card_carries_a_valid_owner_and_on_prem_is_customer_fixable():
    findings = [_f(1, *_AUTH), _f(2, *_PARAM), _f(3, *_HOTNEWS)]
    view = sm.roll_up(findings, deployment_mode="on_prem")
    seen = 0
    for d in view["domains"]:
        for c in d["checks"]:
            seen += 1
            assert c["owner"] in _OWNERS
            assert c["owner"] == "customer_fixable"   # nothing is SAP's on-prem
    assert seen == 3


def test_rise_mode_can_route_a_check_to_sap():
    """The whole point of the badge: on a RISE estate at least one of these
    customer-visible-but-not-customer-fixable checks is a SAP service request."""
    findings = [_f(1, *_AUTH), _f(2, *_PARAM), _f(3, *_HOTNEWS)]
    view = sm.roll_up(findings, deployment_mode="rise_pce")
    owners = {c["owner"] for d in view["domains"] for c in d["checks"]}
    assert owners <= _OWNERS
    assert "ticket_to_sap" in owners


# ── the honest states ────────────────────────────────────────────────────────

def test_the_uncovered_domain_is_not_assessed_never_clear():
    view = sm.roll_up([_f(1, *_AUTH)])
    exploit = _domains_by_id(view)["exploit"]        # reach == none
    assert exploit["state"] == "not_assessed"
    assert exploit["total"] == 0 and exploit["checks"] == []
    assert view["totals"]["not_assessed"] >= 1


def test_summary_keeps_not_assessed_separate_from_clear():
    view = sm.roll_up([_f(1, *_AUTH)])
    t = view["totals"]
    # Exactly twelve domains, partitioned across the states with no overlap.
    assert t["domains"] == 12
    assert t["assessed"] >= 1               # the one with the AUTH finding
    assert t["not_assessed"] >= 1           # the exploit domain, at least
    assert t["assessed"] + t["clear"] + t["not_assessed"] <= t["domains"]
    assert t["findings"] == 1 and t["gaps"] == 1


def test_posture_is_none_without_a_manifest_to_divide_by():
    # No coverage -> no honest denominator -> the screen prints counts, not a band.
    view = sm.roll_up([_f(1, *_AUTH)])
    assert view["posture"] is None
    assert "posture" in view and "risk" in view


def test_empty_estate_still_lists_all_twelve_domains():
    view = sm.roll_up([])
    assert len(view["domains"]) == 12
    assert view["totals"]["findings"] == 0 and view["totals"]["gaps"] == 0
    assert view["risk"] is None


def test_risk_passes_through_untouched():
    risk = {"ale_p90": 3100000.0, "ale_mean": 900000.0, "currency": "USD",
            "priced": True, "unrouted": 2, "input_finding_count": 40}
    view = sm.roll_up([_f(1, *_AUTH)], risk=risk)
    assert view["risk"] == risk


# ── the endpoint ─────────────────────────────────────────────────────────────

@pytest.fixture()
def analyst():
    from server import auth, db
    db.init_schema()
    name = f"sm_{os.urandom(4).hex()}"
    uid = auth.create_user(name, "initial-password-1", "analyst")
    yield {"username": name, "password": "initial-password-1", "id": uid}
    db.execute("DELETE FROM app_user WHERE id = %s", (uid,))


def _signed_in(user):
    from fastapi.testclient import TestClient
    from server import app as appmod
    c = TestClient(appmod.app, follow_redirects=False)
    resp = c.post("/api/auth/login",
                  json={"username": user["username"], "password": user["password"]})
    assert resp.status_code == 200, resp.text
    return c


@pg
def test_the_endpoint_answers_with_the_shape_it_promises(analyst):
    c = _signed_in(analyst)
    resp = c.get("/api/security-monitor")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    for key in ("posture", "risk", "domains", "totals", "measured"):
        assert key in body, f"missing {key}"
    assert len(body["domains"]) == 12
    for key in ("findings", "counts", "gaps", "domains", "assessed", "clear",
                "not_assessed", "corpus", "unplaced"):
        assert key in body["totals"], f"totals missing {key}"


@pg
def test_an_unauthenticated_call_is_refused():
    from fastapi.testclient import TestClient
    from server import app as appmod
    c = TestClient(appmod.app, follow_redirects=False)
    assert c.get("/api/security-monitor").status_code == 401
