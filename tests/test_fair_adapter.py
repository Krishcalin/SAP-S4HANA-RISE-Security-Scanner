# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
Tests for the FAIR cyber-risk-quantification adapter (modules/fair_adapter.py).

Covers routing, range-SELECTION calibration (no ordinal arithmetic), the
detection-deficiency loss multiplier, the emitted CRQ scenario-JSON contract,
graceful degradation when the CRQ engine is absent, and - when the sibling CRQ
engine is locatable - a real end-to-end simulation.
"""
import pytest

from modules import fair_adapter as fa
from modules.risk_prioritizer import RiskPrioritizer


def _prio(findings):
    return RiskPrioritizer().prioritize(findings)


def _f(check_id, category, severity="HIGH", title="", desc="", details=None):
    return {
        "check_id": check_id, "category": category, "severity": severity,
        "title": title or check_id, "description": desc,
        "affected_items": [], "remediation": "", "references": [],
        "details": details or {},
    }


CATALOG = fa.load_catalog()


def test_catalog_shape():
    assert len(CATALOG["scenarios"]) == 5
    assert set(CATALOG["resistance_strength_bands"]) >= {"hardened", "MEDIUM", "HIGH", "CRITICAL"}
    assert CATALOG["detection"]["multiplier_by_worst_severity"]["CRITICAL"] > 1.0


@pytest.mark.parametrize("check_id,category,expect", [
    ("HOTNEWS-003", "SAP Security Notes (HotNews)", "SAP-RCE-01"),
    ("TRUST-005", "System Trust & Standard Users", "SAP-RCE-01"),
    ("NET-004", "Network & Service Exposure", "SAP-RCE-01"),
    ("ARA-P2P-01", "Access Risk Analysis (SoD)", "SAP-FRAUD-02"),
    ("GRC-FF-001", "GRC Access Control", "SAP-FRAUD-02"),
    ("FIN-PP-001", "Financial Controls (SOX)", "SAP-FRAUD-02"),
    ("STDUSR-002", "System Trust & Standard Users", "SAP-PRIV-03"),
    ("AUTH-002", "ABAP Authorization & Critical Access", "SAP-PRIV-03"),
    ("JOBCMD-CMD-001", "Basis Jobs & OS Commands", "SAP-PRIV-03"),
    ("HANADB-PRIV-001", "HANA Database Security", "SAP-DATA-04"),
    ("CRYPTO-HANA-001", "Cryptographic Posture", "SAP-DATA-04"),
    ("DPP-RAL-001", "Data Protection & Privacy", "SAP-DATA-04"),
    ("INTG-GW-001", "Network & Integration Layer", "SAP-INTF-05"),
    ("BTP-CC-001", "BTP Cloud Attack Surface", "SAP-INTF-05"),
    ("RISE-001", "RISE / BTP Security", "SAP-INTF-05"),
])
def test_routing(check_id, category, expect):
    # TRUST vs STDUSR share a category but split by prefix precedence
    assert fa._route(check_id, category, CATALOG["scenarios"]) == expect


def test_logging_is_detection_not_a_scenario():
    assert fa._is_detection("LOG-AUD-001", "Logging, Monitoring & IR", CATALOG)
    assert not fa._is_detection("AUTH-001", "ABAP Authorization & Critical Access", CATALOG)


def test_rs_band_selected_by_worst_severity():
    bands = CATALOG["resistance_strength_bands"]
    # a CRITICAL prevention finding -> the CRITICAL (lowest) RS band
    built = fa.build_inputs(_prio([_f("AUTH-001", "ABAP Authorization & Critical Access", "CRITICAL")]),
                            CATALOG, CATALOG["organization_default"])
    priv = next(s for s in built["asis"]["scenarios"] if s["id"] == "SAP-PRIV-03")
    assert priv["resistance_strength"] == bands["CRITICAL"]
    # a scenario with NO findings -> hardened band (best-case residual)
    data = next(s for s in built["asis"]["scenarios"] if s["id"] == "SAP-DATA-04")
    assert data["resistance_strength"] == bands["hardened"]
    # target set is always hardened
    priv_t = next(s for s in built["target"]["scenarios"] if s["id"] == "SAP-PRIV-03")
    assert priv_t["resistance_strength"] == bands["hardened"]


def test_exposed_and_exploited_select_bands():
    sc_def = next(s for s in CATALOG["scenarios"] if s["id"] == "SAP-RCE-01")
    # HOTNEWS-003 is exploited (KEV analog) + text says exposed
    findings = [_f("HOTNEWS-003", "SAP Security Notes (HotNews)", "CRITICAL",
                   desc="actively exploited in the wild; internet exposed")]
    built = fa.build_inputs(_prio(findings), CATALOG, CATALOG["organization_default"])
    rce = next(s for s in built["asis"]["scenarios"] if s["id"] == "SAP-RCE-01")
    assert rce["contact_frequency"] == sc_def["contact_frequency"]["exposed"]
    assert rce["probability_of_action"] == sc_def["probability_of_action"]["exploited"]


def test_detection_multiplier_scoped_and_exempt():
    org = CATALOG["organization_default"]
    withlog = fa.build_inputs(
        _prio([_f("HANADB-PRIV-001", "HANA Database Security", "HIGH"),
               _f("ARA-P2P-01", "Access Risk Analysis (SoD)", "CRITICAL"),
               _f("LOG-AUD-001", "Logging, Monitoring & IR", "CRITICAL")]), CATALOG, org)
    assert withlog["detection"]["multiplier"] == 1.35
    base = {s["id"]: s for s in CATALOG["scenarios"]}
    data = next(s for s in withlog["asis"]["scenarios"] if s["id"] == "SAP-DATA-04")
    fraud = next(s for s in withlog["asis"]["scenarios"] if s["id"] == "SAP-FRAUD-02")
    # dwell-sensitive components ARE scaled x1.35
    assert data["primary_loss"]["response"]["likely"] == pytest.approx(
        base["SAP-DATA-04"]["primary_loss"]["response"]["likely"] * 1.35)
    assert data["secondary_loss"]["reputation"]["likely"] == pytest.approx(
        base["SAP-DATA-04"]["secondary_loss"]["reputation"]["likely"] * 1.35)
    # replacement / competitive-advantage are NOT dwell-driven -> unscaled
    assert data["primary_loss"]["replacement"]["likely"] == \
        base["SAP-DATA-04"]["primary_loss"]["replacement"]["likely"]
    assert data["secondary_loss"]["competitive_advantage"]["likely"] == \
        base["SAP-DATA-04"]["secondary_loss"]["competitive_advantage"]["likely"]
    # fraud scenario is EXEMPT (its loss already assumes 12-month undetected dwell)
    assert fraud["primary_loss"]["response"]["likely"] == \
        base["SAP-FRAUD-02"]["primary_loss"]["response"]["likely"]


def test_low_severity_findings_use_hardened_band_and_label():
    # a scenario with only a LOW prevention finding -> hardened band, and the
    # meta label must match the band actually used (not "LOW").
    built = fa.build_inputs(_prio([_f("AUTH-014", "ABAP Authorization & Critical Access", "LOW")]),
                            CATALOG, CATALOG["organization_default"])
    priv = next(s for s in built["asis"]["scenarios"] if s["id"] == "SAP-PRIV-03")
    assert priv["resistance_strength"] == CATALOG["resistance_strength_bands"]["hardened"]
    meta = next(m for m in built["meta"] if m["id"] == "SAP-PRIV-03")
    assert meta["rs_band"] == "hardened"


def test_vulnerability_not_saturated_for_critical_band():
    # CRITICAL RS band vs the organized-crime TC likely must keep engine
    # Vulnerability = clamp((TC-RS+50)/100,0,1) in a discriminating range (<0.95),
    # not pinned at 1.0 (the recalibration guard).
    rs = CATALOG["resistance_strength_bands"]["CRITICAL"]["likely"]
    tc = next(s for s in CATALOG["scenarios"] if s["id"] == "SAP-RCE-01")["threat_capability"]["likely"]
    v = (tc - rs + 50) / 100.0
    assert 0.5 < v < 0.95


def test_emitted_scenarios_match_engine_contract():
    findings = [_f("HOTNEWS-003", "SAP Security Notes (HotNews)", "CRITICAL"),
                _f("ARA-P2P-01", "Access Risk Analysis (SoD)", "CRITICAL")]
    built = fa.build_inputs(_prio(findings), CATALOG, CATALOG["organization_default"])
    for sc in built["asis"]["scenarios"]:
        for key in ("id", "name", "contact_frequency", "probability_of_action",
                    "threat_capability", "resistance_strength", "primary_loss", "secondary_loss"):
            assert key in sc, "missing engine key: " + key
        for grp in ("contact_frequency", "probability_of_action", "threat_capability", "resistance_strength"):
            for k in ("min", "likely", "max"):
                assert isinstance(sc[grp][k], (int, float))
            assert sc[grp]["max"] >= sc[grp]["min"]
        for k in ("productivity", "response", "replacement"):
            assert k in sc["primary_loss"]
        for k in ("fines", "reputation", "competitive_advantage"):
            assert k in sc["secondary_loss"]


def test_run_without_engine_still_exports_json(monkeypatch):
    # Simulate "engine not installed" deterministically (the real sibling repo
    # is present in dev, so we force locate_engine to fail).
    monkeypatch.setattr(fa, "locate_engine", lambda explicit=None: None)
    findings = [_f("AUTH-001", "ABAP Authorization & Critical Access", "CRITICAL")]
    out = fa.run(findings, _prio(findings))
    assert out["engine_found"] is False
    assert out["summary"] is None
    assert out["crq_input"]["scenarios"] and "organization" in out["crq_input"]


def test_empty_findings_no_crash():
    out = fa.run([], _prio([]))
    assert out["crq_input"]["scenarios"]  # 5 scenarios at hardened/residual posture


def test_org_overrides_applied():
    findings = [_f("AUTH-001", "ABAP Authorization & Critical Access", "HIGH")]
    out = fa.run(findings, _prio(findings),
                 org_overrides={"revenue": 5_000_000_000, "industry": "financial_services",
                                "name": "Acme", "unused": None})
    assert out["organization"]["revenue"] == 5_000_000_000
    assert out["organization"]["industry"] == "financial_services"
    assert out["organization"]["name"] == "Acme"


@pytest.mark.skipif(fa.locate_engine() is None, reason="CRQ engine not locatable in this environment")
def test_end_to_end_when_engine_available():
    findings = [
        _f("HOTNEWS-003", "SAP Security Notes (HotNews)", "CRITICAL",
           desc="actively exploited; internet exposed"),
        _f("ARA-P2P-01", "Access Risk Analysis (SoD)", "CRITICAL"),
        _f("LOG-AUD-001", "Logging, Monitoring & IR", "CRITICAL"),
    ]
    out = fa.run(findings, _prio(findings), simulations=3000, seed=1)
    assert out["engine_found"] is True
    s = out["summary"]
    assert s["portfolio"]["ale_p90"] > 0
    # as-is loss exposure must be >= the fully-hardened target (remediation can only help)
    assert s["portfolio"]["ale_p90"] >= s["target_portfolio"]["ale_p90"]
    assert s["reducible_ale_p90"] >= 0
    assert len(s["portfolio"]["loss_exceedance"]) > 1
    # every scenario carries its finding diagnostics for the report
    assert all("finding_count" in sc for sc in s["scenarios"])
    # the summary discloses the fallback-routing count for report transparency
    assert "unrouted" in s


def test_unrouted_findings_counted_and_surfaced():
    # a finding matching no scenario prefix/category is conservatively folded into
    # SAP-PRIV-03, but the count must be surfaced (top level, and in the summary
    # when the engine is present) so the report can disclose the misattribution.
    findings = [_f("ZZZ-UNKNOWN-9", "Totally Unknown Category", "HIGH")]
    out = fa.run(findings, _prio(findings))
    assert out["unrouted"] >= 1
    if out["summary"] is not None:          # engine located in this environment
        assert out["summary"]["unrouted"] == out["unrouted"]


def test_change_management_and_hm_citation_removed():
    # regression: the dead 'Change Management' routing rule (shadowed by the NET-
    # prefix -> SAP-RCE-01) and the mis-typed H&M GDPR citation were removed.
    priv = next(s for s in CATALOG["scenarios"] if s["id"] == "SAP-PRIV-03")
    assert "Change Management" not in priv["routing"]["categories"]
    data = next(s for s in CATALOG["scenarios"] if s["id"] == "SAP-DATA-04")
    assert not any("H&M" in src for src in data["sources"])


def test_money_format_tier_boundaries_no_1000_prefix():
    # both report money formatters must promote a tier when the mantissa rounds
    # to 1000 (no "$1000K"/"$1000.0M"), and HTML/PDF must agree byte-for-byte.
    from modules.report_generator import ReportGenerator
    from modules.pdf_report import PDFReportGenerator
    cases = [
        (0, "$0"), (999, "$999"), (999499, "$999K"), (999500, "$1.0M"),
        (999999, "$1.0M"), (1_000_000, "$1.0M"), (1_500_000, "$1.5M"),
        (73_611_599, "$73.6M"), (999_949_999, "$999.9M"), (999_950_001, "$1.00B"),
        (1_000_000_000, "$1.00B"), (-73_611_599, "-$73.6M"),
    ]
    for v, expected in cases:
        html_s = ReportGenerator._fmt_money(v)
        pdf_s = PDFReportGenerator._money(v)
        assert html_s == expected, (v, html_s)
        assert pdf_s == expected, (v, pdf_s)
