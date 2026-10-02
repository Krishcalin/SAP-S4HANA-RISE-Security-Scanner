"""Perceived Threats — the SAP LogServ observations roll-up and its endpoint.

The screen answers "what did the logs observe", distinct from the config queue.
server/perceived_threats.py groups the LogServ check families by log class (folding
each CORR-* into its subject) and keeps the pipeline-health families (LSRV-*, the
LREV capability families) in a separate section. What must hold: every LogServ
family lands in the right group, a config-posture or non-log finding is NOT pulled
in, and the health families are not mistaken for threats.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server import perceived_threats as pt  # noqa: E402

pg = pytest.mark.skipif(not os.getenv("DB_DSN"),
                        reason="set DB_DSN to a PostgreSQL 16 instance")


# ── group_for: every family in the right section/group ───────────────────────

def test_each_logserv_family_maps_to_its_group():
    cases = {
        "LREV-PAT-001": ("threat", "audit_behaviour"),
        "LVIO-FF-001": ("threat", "violations"),
        "LVIO-OFH-001": ("threat", "violations"),
        "GWLOG-002": ("threat", "gateway"),
        "CORR-GW-001": ("threat", "gateway"),
        "HANALOG-001": ("threat", "hana"),
        "CORR-HANA-001": ("threat", "hana"),
        "ICMLOG-003": ("threat", "icm_web"),
        "CORR-ICM-001": ("threat", "icm_web"),
        "NETLOG-001": ("threat", "network"),
        "CORR-NET-001": ("threat", "network"),
        "LSRV-COV-001": ("health", "ingestion"),
        "LSRV-WIN-001": ("health", "ingestion"),
        "LREV-SRC-001": ("health", "audit_coverage"),
        "LREV-FLT-002": ("health", "audit_coverage"),
        "LREV-WIN-001": ("health", "audit_coverage"),
    }
    for cid, expected in cases.items():
        assert pt.group_for(cid) == expected, cid


def test_lrev_pat_is_a_threat_not_audit_coverage():
    """The LREV-* namespace is split: PAT is an observation, SRC/FLT/WIN are
    capability. GROUPS is checked before HEALTH so PAT wins."""
    assert pt.group_for("LREV-PAT-010") == ("threat", "audit_behaviour")
    assert pt.group_for("LREV-SRC-001") == ("health", "audit_coverage")


def test_config_posture_and_non_log_findings_are_not_pulled_in():
    for cid in ("LOG-AUD-001", "LOG-SIEM-002", "AUTH-003", "HOTNEWS-001",
                "INTG-GW-001", ""):
        assert pt.group_for(cid) == (None, None), cid


# ── roll_up: grouping, counts, exclusion ─────────────────────────────────────

def _f(fid, check_id, severity="HIGH", tier="P2"):
    return {"id": fid, "check_id": check_id, "severity": severity,
            "priority_tier": tier, "title": f"{check_id} finding",
            "category": "x", "sid": "PRD", "state": "open"}


def test_roll_up_groups_threats_and_health_and_excludes_the_rest():
    findings = [
        _f(1, "LREV-PAT-001", "HIGH"),
        _f(2, "LREV-PAT-002", "CRITICAL", "P1"),
        _f(3, "CORR-GW-001", "CRITICAL", "P1"),
        _f(4, "GWLOG-001", "MEDIUM", "P3"),
        _f(5, "NETLOG-003", "HIGH"),
        _f(6, "LSRV-COV-001", "MEDIUM", "P3"),
        _f(7, "LREV-SRC-001", "LOW", "P4"),
        _f(8, "LOG-AUD-001", "HIGH"),      # config posture — excluded
        _f(9, "AUTH-003", "CRITICAL"),     # not a log finding — excluded
    ]
    out = pt.roll_up(findings, coverage={"measured": "2026-10-02"})

    by = {g["id"]: g for g in out["groups"]}
    assert by["audit_behaviour"]["total"] == 2
    assert by["audit_behaviour"]["counts"]["CRITICAL"] == 1
    assert by["audit_behaviour"]["counts"]["HIGH"] == 1
    assert by["gateway"]["total"] == 2            # GWLOG + CORR-GW folded together
    assert by["network"]["total"] == 1
    assert by["hana"]["total"] == 0 and by["icm_web"]["total"] == 0

    health = {h["id"]: h for h in out["health"]}
    assert health["ingestion"]["total"] == 1
    assert health["audit_coverage"]["total"] == 1

    # Totals count only the LogServ findings — the LOG-AUD and AUTH ones are gone.
    assert out["totals"]["threats"] == 5
    assert out["totals"]["health"] == 2
    assert out["measured"] == "2026-10-02"
    # Every group carries its label/blurb and a findings list.
    assert all(g["label"] and g["blurb"] for g in out["groups"] + out["health"])


def test_findings_within_a_group_are_ranked_tier_then_severity():
    findings = [
        _f(1, "LREV-PAT-001", "HIGH", "P3"),
        _f(2, "LREV-PAT-002", "CRITICAL", "P1"),
        _f(3, "LREV-PAT-003", "LOW", "P1"),
    ]
    out = pt.roll_up(findings)
    audit = next(g for g in out["groups"] if g["id"] == "audit_behaviour")
    # P1 rows first (ids 2,3), then P3 (id 1); within P1, CRITICAL before LOW.
    assert [r["id"] for r in audit["findings"]] == [2, 3, 1]


def test_empty_input_yields_all_groups_empty_not_missing():
    out = pt.roll_up([])
    assert [g["id"] for g in out["groups"]] == \
        ["audit_behaviour", "violations", "gateway", "hana", "icm_web", "network"]
    assert [h["id"] for h in out["health"]] == ["ingestion", "audit_coverage"]
    assert out["totals"]["threats"] == 0 and out["measured"] is None


# ── the endpoint ─────────────────────────────────────────────────────────────

@pytest.fixture()
def analyst():
    from server import auth, db
    db.init_schema()
    name = f"pt_{os.urandom(4).hex()}"
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
    resp = c.get("/api/perceived-threats")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    for key in ("groups", "health", "measured", "totals"):
        assert key in body, f"missing {key}"
    assert [g["id"] for g in body["groups"]] == \
        ["audit_behaviour", "violations", "gateway", "hana", "icm_web", "network"]
    assert {h["id"] for h in body["health"]} == {"ingestion", "audit_coverage"}


@pg
def test_an_unauthenticated_call_is_refused():
    from fastapi.testclient import TestClient
    from server import app as appmod
    c = TestClient(appmod.app, follow_redirects=False)
    assert c.get("/api/perceived-threats").status_code == 401
