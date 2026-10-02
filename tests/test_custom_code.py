"""Custom Code — the ABAP/custom-code posture roll-up and its endpoint.

The screen answers "what is the state of the custom code", distinct from the
config queue. server/custom_code.py groups our native scanner families (ABAP-*)
and the imported SAP ATC/CVA families (ATC-*) by weakness (CWE family), with a
native-vs-ATC split, a worst-objects ranking, and a scan coverage & trust section
(COV/LEX/NOSEC + ATC governance). What must hold: every custom-code family lands
in a real group (never silently in the catch-all), a non-custom-code finding is
NOT pulled in, provenance and the object ranking are right, and the trust families
are not mistaken for weaknesses.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server import custom_code as cc  # noqa: E402

pg = pytest.mark.skipif(not os.getenv("DB_DSN"),
                        reason="set DB_DSN to a PostgreSQL 16 instance")


# ── group_for / provenance: every family in the right section/group ──────────

def test_each_family_maps_to_its_group():
    cases = {
        "ABAP-SQLI-001": ("weakness", "injection_sql"),
        "ABAP-NSQL-002": ("weakness", "injection_sql"),
        "ABAP-AMDP-001": ("weakness", "injection_sql"),
        "ATC-SQLI": ("weakness", "injection_sql"),
        "ABAP-CINJ-007": ("weakness", "injection_code"),
        "ABAP-DYNT-001": ("weakness", "injection_code"),
        "ATC-CINJ": ("weakness", "injection_code"),
        "ABAP-CMDI-001": ("weakness", "injection_os"),
        "ATC-CMDI": ("weakness", "injection_os"),
        "ABAP-PATH-001": ("weakness", "traversal"),
        "ATC-PATH": ("weakness", "traversal"),
        "ABAP-AUTH-003": ("weakness", "authorization"),
        "ABAP-CDS-003": ("weakness", "authorization"),
        "ABAP-RAP-005": ("weakness", "authorization"),
        "ATC-AUTHCHK": ("weakness", "authorization"),
        "ABAP-XSS-001": ("weakness", "web_output"),
        "ABAP-JS-004": ("weakness", "web_output"),
        "ATC-XSS": ("weakness", "web_output"),
        "ABAP-CRED-002": ("weakness", "secrets"),
        "ATC-CRED": ("weakness", "secrets"),
        "ABAP-BKDR-001": ("weakness", "backdoor"),
        "ABAP-CRYP-001": ("weakness", "crypto"),
        "ATC-CRYP": ("weakness", "crypto"),
        "ABAP-RFC-002": ("weakness", "interface"),
        "ATC-RFC": ("weakness", "interface"),
        "ABAP-SSRF-001": ("weakness", "ssrf_xxe"),
        "ABAP-XXE-001": ("weakness", "ssrf_xxe"),
        "ABAP-CONF-001": ("weakness", "config"),
        "ABAP-BTP-003": ("weakness", "config"),
        "ABAP-INFO-001": ("weakness", "info"),
        "ATC-INFO": ("weakness", "info"),
        "ABAP-COV-001": ("trust", "scan_coverage"),
        "ABAP-LEX-001": ("trust", "scan_coverage"),
        "ABAP-NOSEC-001": ("trust", "suppression"),
        "ATC-GOV-001": ("trust", "atc_evidence"),
        "ATC-GOV-002": ("trust", "atc_evidence"),
    }
    for cid, expected in cases.items():
        assert cc.group_for(cid) == expected, cid


def test_coverage_prefixes_do_not_collide_with_config_or_crypto():
    """ABAP-COV / ABAP-CONF / ABAP-CRYP share a stem; the trust prefixes must not
    swallow a weakness and vice-versa."""
    assert cc.group_for("ABAP-CONF-009") == ("weakness", "config")
    assert cc.group_for("ABAP-CRYP-006") == ("weakness", "crypto")
    assert cc.group_for("ABAP-COV-006") == ("trust", "scan_coverage")


def test_non_customcode_findings_are_not_pulled_in():
    for cid in ("LOG-AUD-001", "AUTH-003", "HOTNEWS-001", "INTG-GW-001",
                "CODE-001", ""):
        assert cc.group_for(cid) == (None, None), cid


def test_unmapped_customcode_family_lands_in_other_not_lost():
    assert cc.group_for("ABAP-NEWTHING-001") == ("weakness", "other")
    assert cc.group_for("ATC-NEWTHING") == ("weakness", "other")


def test_provenance_for():
    assert cc.provenance_for("ABAP-SQLI-001") == "native"
    assert cc.provenance_for("ATC-SQLI") == "atc"
    assert cc.provenance_for(None) == "native"


# ── live guard: no real custom-code family may fall into the catch-all ───────

def _native_family_stems():
    from modules import abap_sast_extra as X
    from modules import abap_sast_rules as R
    tables = []
    for mod in (R, X):
        for name in dir(mod):
            if name.isupper() and name.endswith("_RULES"):
                tbl = getattr(mod, name)
                if isinstance(tbl, (list, tuple)):
                    tables.append(tbl)
    try:
        from modules import cds_authorization_index as C
        tables.append(getattr(C, "CROSS_ARTIFACT_RULES", []))
    except Exception:
        pass
    stems = set()
    for tbl in tables:
        for rule in tbl:
            if isinstance(rule, dict) and rule.get("id"):
                stems.add(re.sub(r"-\d+$", "", str(rule["id"])))
    return stems


def test_every_native_rule_family_maps_to_a_weakness():
    stems = _native_family_stems()
    assert stems, "no native ABAP rule families discovered"
    for stem in stems:
        section, gid = cc.group_for(f"{stem}-001")
        assert (section, gid) != (None, None), f"{stem} unmapped"
        assert section == "weakness" and gid != "other", \
            f"{stem} fell into the catch-all — fold it into a GROUPS prefix"


def test_every_atc_family_maps_and_gov_is_trust():
    from modules.atc_import import AtcImportAuditor
    fams = getattr(AtcImportAuditor, "FAMILIES", [])
    assert fams, "no ATC families discovered"
    for fam in fams:
        section, gid = cc.group_for(f"ATC-{fam['family']}")
        assert section == "weakness" and gid != "other", fam["family"]
    assert cc.group_for("ATC-GOV-001") == ("trust", "atc_evidence")


# ── normalize: pull object / confidence / exposure out of the jsonb row ──────

def test_normalize_extracts_object_confidence_and_exposure():
    row = {"id": 1, "check_id": "ABAP-SQLI-001", "severity": "CRITICAL",
           "priority_tier": "P1", "title": "Dynamic WHERE — ZCL_FOO",
           "category": "Code & Transport Security", "sid": "PRD", "state": "open",
           "affected_objects": [{"type": "program", "name": "ZCL_FOO"}],
           "details": {"source": "abap_scan", "confidence": "confirmed",
                       "internet_exposed": True}}
    out = cc.normalize(row)
    assert out["object"] == "ZCL_FOO"
    assert out["confidence"] == "confirmed"
    assert out["internet_exposed"] is True


def test_normalize_is_idempotent_on_flat_rows():
    flat = {"id": 2, "check_id": "ATC-SQLI", "severity": "HIGH", "object": "ZREP",
            "confidence": None, "internet_exposed": None}
    out = cc.normalize(flat)
    assert out["object"] == "ZREP" and out["confidence"] is None


# ── roll_up: grouping, provenance, objects, counts, exclusion ────────────────

def _f(fid, check_id, severity="HIGH", tier="P2", obj=None,
       confidence=None, exposed=None):
    return {"id": fid, "check_id": check_id, "severity": severity,
            "priority_tier": tier, "title": f"{check_id} — {obj or 'ZX'}",
            "category": "Code & Transport Security", "sid": "PRD", "state": "open",
            "object": obj, "confidence": confidence, "internet_exposed": exposed}


def test_roll_up_groups_counts_provenance_and_excludes_the_rest():
    findings = [
        _f(1, "ABAP-SQLI-001", "CRITICAL", "P1", "ZCL_A", "confirmed", True),
        _f(2, "ABAP-SQLI-006", "HIGH", "P2", "ZCL_A", "tentative", False),
        _f(3, "ATC-SQLI", "CRITICAL", "P1", "ZCL_B"),
        _f(4, "ABAP-CMDI-001", "CRITICAL", "P1", "ZCL_B", "confirmed", None),
        _f(5, "ABAP-COV-001", "MEDIUM", "P3"),       # trust, not a weakness
        _f(6, "ATC-GOV-001", "HIGH", "P2"),          # trust
        _f(7, "LOG-AUD-001", "HIGH"),                # not custom code — excluded
    ]
    out = cc.roll_up(findings, coverage={"measured": "2026-10-02"})

    by = {g["id"]: g for g in out["groups"]}
    assert by["injection_sql"]["total"] == 3
    assert by["injection_sql"]["native"] == 2 and by["injection_sql"]["atc"] == 1
    assert by["injection_sql"]["counts"]["CRITICAL"] == 2
    assert by["injection_os"]["total"] == 1
    assert by["injection_sql"]["cwe"] == "CWE-89"

    trust = {h["id"]: h for h in out["health"]}
    assert trust["scan_coverage"]["total"] == 1
    assert trust["atc_evidence"]["total"] == 1

    # Totals count only the weakness findings — COV/GOV/LOG-AUD are not weaknesses.
    assert out["totals"]["findings"] == 4
    assert out["totals"]["trust"] == 2
    assert out["totals"]["provenance"] == {"native": 3, "atc": 1}
    assert out["measured"] == "2026-10-02"
    # "other" is absent when nothing was unmapped.
    assert "other" not in by


def test_roll_up_surfaces_unmapped_family_in_other():
    out = cc.roll_up([_f(1, "ABAP-MYSTERY-001", "HIGH", obj="ZX")])
    by = {g["id"]: g for g in out["groups"]}
    assert "other" in by and by["other"]["total"] == 1


def test_roll_up_ranks_worst_objects_by_severity():
    findings = [
        _f(1, "ABAP-SQLI-001", "CRITICAL", "P1", "ZBAD"),
        _f(2, "ABAP-CMDI-001", "HIGH", "P2", "ZBAD"),
        _f(3, "ABAP-XSS-001", "HIGH", "P2", "ZMEH"),
        _f(4, "ATC-CRED", "LOW", "P4", "ZMEH"),
    ]
    out = cc.roll_up(findings)
    names = [o["name"] for o in out["objects"]]
    assert names == ["ZBAD", "ZMEH"]           # a CRITICAL outranks two non-criticals
    zbad = out["objects"][0]
    assert zbad["total"] == 2 and zbad["worst"] == "CRITICAL"
    assert out["totals"]["objects"] == 2


def test_roll_up_counts_confidence_and_exposure():
    findings = [
        _f(1, "ABAP-SQLI-001", obj="ZA", confidence="confirmed", exposed=True),
        _f(2, "ABAP-SQLI-006", obj="ZB", confidence="tentative", exposed=False),
        _f(3, "ATC-SQLI", obj="ZC"),            # ATC carries no taint confidence
    ]
    out = cc.roll_up(findings)
    assert out["totals"]["confidence"] == {"confirmed": 1, "tentative": 1, "unknown": 1}
    assert out["totals"]["exposure"] == {"exposed": 1, "internal": 1, "unknown": 1}


def test_empty_input_yields_all_weakness_groups_without_other():
    out = cc.roll_up([])
    assert [g["id"] for g in out["groups"]] == [g["id"] for g in cc.GROUPS]
    assert [h["id"] for h in out["health"]] == [h["id"] for h in cc.HEALTH]
    assert out["objects"] == [] and out["totals"]["findings"] == 0
    assert out["measured"] is None


# ── the endpoint ─────────────────────────────────────────────────────────────

@pytest.fixture()
def analyst():
    from server import auth, db
    db.init_schema()
    name = f"cc_{os.urandom(4).hex()}"
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
    resp = c.get("/api/custom-code")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    for key in ("groups", "health", "objects", "measured", "totals"):
        assert key in body, f"missing {key}"
    assert [g["id"] for g in body["groups"]] == [g["id"] for g in cc.GROUPS]
    assert {h["id"] for h in body["health"]} == {h["id"] for h in cc.HEALTH}


@pg
def test_an_unauthenticated_call_is_refused():
    from fastapi.testclient import TestClient
    from server import app as appmod
    c = TestClient(appmod.app, follow_redirects=False)
    assert c.get("/api/custom-code").status_code == 401
