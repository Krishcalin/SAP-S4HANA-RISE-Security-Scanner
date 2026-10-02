"""Vulnerabilities vs Mis-Configuration — the two posture lenses and their guard.

server/finding_classes.py partitions findings into "vulnerability" (missing SAP
Security Notes + exploitable custom-code weaknesses) and "misconfiguration"
(insecure settings/params/policy/authorizations), leaving SoD, compliance,
governance, log observations and evidence meta in NEITHER. What must hold: each
family lands in the right bucket, the vulnerability meta ids and the excluded
families are not pulled in, and — the load-bearing guard — EVERY category the
catalogue can emit is deliberately bucketed, so a new or renamed category can
never silently vanish from both screens.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server import finding_classes as fc  # noqa: E402

pg = pytest.mark.skipif(not os.getenv("DB_DSN"),
                        reason="set DB_DSN to a PostgreSQL 16 instance")


# ── classify: prefix + category → (kind, group) ──────────────────────────────

def test_vulnerability_families():
    cases = {
        ("HOTNEWS-001", "SAP Security Notes (HotNews)"): ("vulnerability", "patches"),
        ("HOTNEWS-003", "SAP Security Notes (HotNews)"): ("vulnerability", "patches"),
        ("HOTNEWS-006", "SAP Security Notes (HotNews)"): ("vulnerability", "patches"),
        ("ABAP-SQLI-001", "Code & Transport Security"): ("vulnerability", "native_code"),
        ("ABAP-CMDI-006", "Code & Transport Security"): ("vulnerability", "native_code"),
        ("ATC-SQLI", "Code & Transport Security"): ("vulnerability", "atc_code"),
        ("CODE-INJ-001", "Code & Transport Security"): ("vulnerability", "other_code"),
        ("CODE-STMT-002", "Code & Transport Security"): ("vulnerability", "other_code"),
    }
    for (cid, cat), expected in cases.items():
        assert fc.classify(cid, cat) == expected, cid


def test_misconfiguration_families_by_category():
    cases = {
        ("PARAM-0001", "Security Baseline Parameters"): "parameters",
        ("SECPOL-01", "Password Policy"): "parameters",
        ("AUTH-015", "ABAP Authorization & Critical Access"): "authorizations",
        ("TRUST-002", "System Trust & Standard Users"): "authorizations",
        ("NET-003", "Network & Service Exposure"): "network",
        ("WDISP-007", "Web Dispatcher Security"): "network",
        ("CRYPTO-001", "Cryptographic Posture"): "crypto",
        ("HANADB-002", "HANA Database Security"): "database",
        ("FIORI-001", "Fiori & UI Layer"): "app_ui",
        ("OSEC-001", "OS & Infrastructure Security"): "os_infra",
        ("BTP-010", "BTP Cloud Attack Surface"): "cloud_btp",
        ("CAPX-002", "CAP & XSUAA Application Security"): "cloud_btp",
        ("DPP-001", "Data Protection & Privacy"): "data_protection",
        ("LOG-AUD-001", "Logging, Monitoring & IR"): "logging",
        ("CODE-TMS-001", "Code & Transport Security"): "transport",
        ("TMS-x", "Transport Security"): "transport",
        ("CHG-x", "Change Management"): "transport",
        ("DEV-x", "Development Controls"): "transport",
    }
    for (cid, cat), gid in cases.items():
        assert fc.classify(cid, cat) == ("misconfiguration", gid), cid


def test_vulnerability_meta_ids_are_not_flaws():
    for cid in ("HOTNEWS-COVERAGE", "HOTNEWS-000", "HOTNEWS-005", "HOTNEWS-011",
                "ABAP-COV-001", "ABAP-LEX-001", "ABAP-NOSEC-001",
                "ATC-GOV-001", "ATC-GOV-002"):
        assert fc.classify(cid, "Code & Transport Security") == (None, None) \
            or fc.classify(cid, "SAP Security Notes (HotNews)") == (None, None), cid


def test_sod_compliance_governance_and_logs_are_excluded():
    for cid, cat in (("ARA-DIDDO-001", "Access Risk Analysis (SoD)"),
                     ("GRC-001", "GRC Access Control"),
                     ("FIN-001", "Financial Controls (SOX)"),
                     ("MDC-001", "Master Data Change Audit"),
                     ("RISE-001", "RISE / BTP Security"),
                     ("RES-001", "Resilience & Recovery Readiness"),
                     ("CSA-001", "SAP Cloud ALM CSA Results"),
                     ("LREV-PAT-001", "Security Audit Log Review"),
                     ("GWLOG-001", "Gateway Log Review"),
                     ("CODE-INV-001", "Code & Transport Security"),
                     ("EXPORT-001", "Export Integrity"),
                     ("SODCOV-001", "SoD Ruleset Coverage")):
        assert fc.classify(cid, cat) == (None, None), cid


# ── the load-bearing guard ───────────────────────────────────────────────────

def test_every_catalogue_category_is_deliberately_bucketed():
    """A category the catalogue can emit that is in NEITHER a mis-config group
    NOR the excluded/prefix-driven sets would vanish from both screens with no
    error. KNOWN_CATEGORIES is the union; this asserts the catalogue is covered,
    so a new/renamed category fails the build until it is placed."""
    from modules.coverage import check_catalogue
    cats = {c for c in check_catalogue().values() if c}
    missing = sorted(cats - fc.KNOWN_CATEGORIES)
    assert not missing, f"unbucketed catalogue categories: {missing}"


def test_misconfig_groups_and_excluded_do_not_overlap():
    misconfig_cats = {c for g in fc.MISCONFIG_GROUPS for c in g["categories"]}
    assert not (misconfig_cats & fc.EXCLUDED_CATEGORIES)
    assert not (misconfig_cats & fc._PREFIX_DRIVEN_CATEGORIES)


# ── roll_up ──────────────────────────────────────────────────────────────────

def _f(fid, check_id, category, severity="HIGH", tier="P2"):
    return {"id": fid, "check_id": check_id, "severity": severity,
            "priority_tier": tier, "title": f"{check_id} finding",
            "category": category, "sid": "PRD", "state": "open"}


def test_roll_up_vulnerability_groups_and_excludes_the_rest():
    findings = [
        _f(1, "HOTNEWS-001", "SAP Security Notes (HotNews)", "CRITICAL", "P1"),
        _f(2, "HOTNEWS-003", "SAP Security Notes (HotNews)", "CRITICAL", "P1"),
        _f(3, "ABAP-SQLI-001", "Code & Transport Security", "HIGH"),
        _f(4, "ATC-CMDI", "Code & Transport Security", "HIGH"),
        _f(5, "PARAM-1", "Security Parameters", "MEDIUM", "P3"),   # misconfig — out
        _f(6, "ARA-x", "Access Risk Analysis (SoD)", "HIGH"),      # excluded — out
        _f(7, "HOTNEWS-005", "SAP Security Notes (HotNews)", "INFO", "P4"),  # meta — out
    ]
    out = fc.roll_up(findings, "vulnerability", coverage={"measured": "2026-10-02"})
    by = {g["id"]: g for g in out["groups"]}
    assert by["patches"]["total"] == 2
    assert by["patches"]["counts"]["CRITICAL"] == 2
    assert by["native_code"]["total"] == 1 and by["atc_code"]["total"] == 1
    assert out["kind"] == "vulnerability"
    assert out["totals"]["findings"] == 4          # the misconfig/SoD/meta are gone
    assert out["measured"] == "2026-10-02"


def test_roll_up_misconfiguration_groups_by_subject():
    findings = [
        _f(1, "PARAM-1", "Security Baseline Parameters", "HIGH"),
        _f(2, "SECPOL-1", "Password Policy", "MEDIUM", "P3"),
        _f(3, "NET-1", "Gateway Security", "CRITICAL", "P1"),
        _f(4, "HOTNEWS-001", "SAP Security Notes (HotNews)", "CRITICAL", "P1"),  # vuln — out
    ]
    out = fc.roll_up(findings, "misconfiguration")
    by = {g["id"]: g for g in out["groups"]}
    assert by["parameters"]["total"] == 2
    assert by["network"]["total"] == 1
    assert out["totals"]["findings"] == 3          # HOTNEWS excluded from this lens
    assert out["kind"] == "misconfiguration"


def test_empty_input_yields_all_groups_present():
    v = fc.roll_up([], "vulnerability")
    assert [g["id"] for g in v["groups"]] == [g["id"] for g in fc.VULN_GROUPS]
    m = fc.roll_up([], "misconfiguration")
    assert [g["id"] for g in m["groups"]] == [g["id"] for g in fc.MISCONFIG_GROUPS]
    assert v["totals"]["findings"] == 0 and m["measured"] is None


# ── the endpoints ────────────────────────────────────────────────────────────

@pytest.fixture()
def analyst():
    from server import auth, db
    db.init_schema()
    name = f"fc_{os.urandom(4).hex()}"
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
@pytest.mark.parametrize("path,kind,groups_def", [
    ("/api/vulnerabilities", "vulnerability", fc.VULN_GROUPS),
    ("/api/misconfiguration", "misconfiguration", fc.MISCONFIG_GROUPS),
])
def test_the_endpoints_answer_with_the_shape_they_promise(analyst, path, kind, groups_def):
    c = _signed_in(analyst)
    resp = c.get(path)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    for key in ("kind", "groups", "measured", "totals"):
        assert key in body, f"missing {key}"
    assert body["kind"] == kind
    assert [g["id"] for g in body["groups"]] == [g["id"] for g in groups_def]


@pg
@pytest.mark.parametrize("path", ["/api/vulnerabilities", "/api/misconfiguration"])
def test_an_unauthenticated_call_is_refused(path):
    from fastapi.testclient import TestClient
    from server import app as appmod
    c = TestClient(appmod.app, follow_redirects=False)
    assert c.get(path).status_code == 401
