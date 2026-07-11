"""Tests for the P1-P4 risk-prioritization engine and its report rendering.

Covers the tier logic (severity x exploitability x exposure), the KEV-analog floor
(actively-exploited never below P2), score bounds, and that the HTML report renders
the tier cards + per-finding priority badges.
"""
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.risk_prioritizer import RiskPrioritizer, TIER_META, prioritize, by_finding  # noqa: E402
from modules.report_generator import ReportGenerator  # noqa: E402


def _f(check_id, severity, category="User & Authorization", title="", desc="", details=None):
    return {"check_id": check_id, "title": title or check_id, "severity": severity,
            "category": category, "description": desc, "affected_items": [], "affected_count": 0,
            "remediation": "", "references": [], "details": details or {}}


RP = RiskPrioritizer()


# ── tier logic ────────────────────────────────────────────────────────────────

def test_exploited_critical_is_p1():
    f = _f("HOTNEWS-003", "CRITICAL", "SAP Security Notes (HotNews)",
           "Missing notes for actively-exploited SAP vulnerabilities",
           "exploited in the wild / CISA KEV", {"cvss": 10.0})
    r = RP.assess(f)
    assert r.tier == "P1" and r.exploited and r.score >= 82


def test_plain_hotnews_critical_is_p2():
    # a missing HotNews P1 note that is NOT flagged actively-exploited -> P2
    f = _f("HOTNEWS-001", "CRITICAL", "SAP Security Notes (HotNews)",
           "Missing HotNews (Priority 1) SAP Security Notes", "top-severity notes")
    r = RP.assess(f)
    assert r.tier == "P2" and r.hotnews and not r.exploited


def test_default_credentials_critical_is_p1():
    f = _f("USR-001", "CRITICAL", "User & Authorization",
           "Standard user SAP* has default password", "default password for standard user SAP*")
    r = RP.assess(f)
    assert r.tier == "P1" and r.privileged


def test_open_gateway_exposure_is_p1():
    f = _f("NET-010", "CRITICAL", "Network & Service Exposure",
           "Gateway without reginfo/secinfo", "gateway reginfo missing, reachable from the network")
    r = RP.assess(f)
    assert r.tier == "P1" and r.exposed


def test_plain_high_is_p3():
    f = _f("PARAM-010", "HIGH", "Security Parameters", "login/min_password_length too low")
    assert RP.assess(f).tier == "P3"


def test_medium_on_exposed_surface_is_p3():
    f = _f("NET-020", "MEDIUM", "Network & Service Exposure", "Service exposed", "publicly reachable")
    assert RP.assess(f).tier == "P3"


def test_low_is_p4():
    assert RP.assess(_f("LOG-030", "LOW", "Audit Logging", "Short retention")).tier == "P4"


def test_kev_floor_holds_for_exploited_high():
    # an actively-exploited HIGH must not drop below P2 even though HIGH alone is P3
    f = _f("HOTNEWS-003", "HIGH", "SAP Security Notes (HotNews)",
           "actively-exploited note", "exploited in the wild")
    r = RP.assess(f)
    assert r.exploited and r.tier == "P2"


# ── scoring / API ───────────────────────────────────────────────────────────

def test_score_bounds():
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        r = RP.assess(_f("X-1", sev, "SAP Security Notes (HotNews)",
                         "actively-exploited", "exploited in the wild gateway internet", {"cvss": 10.0}))
        assert 0 <= r.score <= 100


def test_prioritize_sorts_p1_first_and_by_finding_maps():
    fs = [_f("LOG-1", "LOW"), _f("HN-3", "CRITICAL", "SAP Security Notes (HotNews)",
              "actively-exploited", "exploited in the wild")]
    results = prioritize(fs)
    assert results[0].tier == "P1"                       # sorted fix-first
    m = by_finding(results)
    assert all(id(r.finding) in m for r in results)


def test_every_result_has_valid_tier_and_rationale():
    fs = [_f(f"C-{i}", s) for i, s in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])]
    for r in prioritize(fs):
        assert r.tier in TIER_META
        assert TIER_META[r.tier]["label"] in r.rationale


# ── report rendering ──────────────────────────────────────────────────────────

def test_report_renders_priority_tiers(tmp_path):
    fs = [
        _f("HOTNEWS-003", "CRITICAL", "SAP Security Notes (HotNews)",
           "actively-exploited notes", "exploited in the wild", {"cvss": 10.0, "cve": "CVE-2020-6287"}),
        _f("USR-001", "CRITICAL", "User & Authorization", "SAP* default password", "default password SAP*"),
        _f("PARAM-010", "HIGH", "Security Parameters", "weak parameter"),
        _f("LOG-030", "LOW", "Audit Logging", "short retention"),
    ]
    results = prioritize(fs)
    out = tmp_path / "r.html"
    ReportGenerator(fs, {"scan_time": "2026-07-11T00:00:00"}, kb=None, priorities=results).generate(str(out))
    t = out.read_text(encoding="utf-8")
    assert "Risk-Prioritized Remediation Queue" in t
    for tier in ("P1", "P2", "P3", "P4"):
        assert f'class="tier-card {tier}"' in t
    assert 'class="p-badge P1"' in t                     # per-finding badge
    assert 'data-tier="P1"' in t                         # filterable
    assert "Top" in t and 'class="tr-row"' in t          # fix-first queue
    assert "Exploited" in t                              # exploitability tag


def test_report_without_priorities_still_renders(tmp_path):
    # ReportGenerator self-computes priorities when none are passed
    fs = [_f("PARAM-010", "HIGH", "Security Parameters", "weak parameter")]
    out = tmp_path / "r2.html"
    ReportGenerator(fs, {"scan_time": "2026-07-11T00:00:00"}).generate(str(out))
    t = out.read_text(encoding="utf-8")
    assert "Risk-Prioritized Remediation Queue" in t


# ── review regressions ─────────────────────────────────────────────────────────

def test_generic_phrase_does_not_flag_privileged():
    # "profile parameter" is a generic descriptive phrase (benign config hardening);
    # it must NOT be treated as a privileged attack path and escalate the tier.
    f = _f("AUTH-015", "MEDIUM", "ABAP Authorization & Critical Access",
           "Profile parameter auth/object_disabling_active", "Profile parameter set to Y")
    r = RP.assess(f)
    assert not r.privileged and r.tier == "P4"


def test_public_key_is_not_exposure():
    # "public key" must not trip the exposure signal (only 'publicly'/'public-facing' do)
    f = _f("CRYPTO-002", "MEDIUM", "Cryptographic Posture",
           "Weak public key length", "RSA public key is 1024-bit")
    assert not RP.assess(f).exposed


def test_no_tier_filter_buttons_when_prioritization_absent(tmp_path):
    # degraded path: priorities=[] -> no tier data -> no P1-P4 filter buttons (they would
    # otherwise be dead traps that hide every finding), but severity filters remain.
    fs = [_f("PARAM-010", "HIGH", "Security Parameters", "weak parameter")]
    out = tmp_path / "r3.html"
    ReportGenerator(fs, {"scan_time": "2026-07-11T00:00:00"}, kb=None, priorities=[]).generate(str(out))
    t = out.read_text(encoding="utf-8")
    assert "filterFindings('P1')" not in t and "Risk-Prioritized Remediation Queue" not in t
    assert "filterFindings('CRITICAL')" in t          # severity filters still present


def test_report_survives_nonstring_reference(tmp_path):
    f = _f("X-1", "HIGH", "Security Parameters", "weird refs")
    f["references"] = [1234, {"note": "x"}, "SAP Note 12345"]   # non-string entries
    out = tmp_path / "r4.html"
    ReportGenerator([f], {"scan_time": "2026-07-11T00:00:00"}).generate(str(out))  # must not raise
    assert out.read_text(encoding="utf-8")
