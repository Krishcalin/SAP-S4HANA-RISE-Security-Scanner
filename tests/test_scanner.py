"""End-to-end and per-module tests for the SAP S/4HANA RISE Security Scanner.

Strategy: every audit module is run against the bundled ``sample_data`` (crafted
to trigger its checks). We assert each module fires, handles empty input without
crashing, and that every finding honours the ``finding()`` contract — plus that
the full report pipeline (all modules → ReportGenerator) renders, and that the
``sap_scanner.py`` CLI runs end-to-end. The finding-contract test in particular
catches a whole bug class (e.g. a stray trailing comma turning a description into
a tuple) that a plain "does it produce findings" check would miss.
"""
import contextlib
import io
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

from modules.user_auth_audit import UserAuthAuditor
from modules.security_params import SecurityParamAuditor
from modules.network_services import NetworkServiceAuditor
from modules.rise_btp_checks import RiseBtpAuditor
from modules.iam_advanced import AdvancedIamAuditor
from modules.btp_cloud_surface import BtpCloudSurfaceAuditor
from modules.integration_layer import IntegrationLayerAuditor
from modules.data_protection import DataProtectionAuditor
from modules.code_transport import CodeTransportAuditor
from modules.log_monitoring import LogMonitoringAuditor
from modules.fiori_ui import FioriUiAuditor
from modules.crypto_posture import CryptoPostureAuditor
from modules.hana_db_security import HanaDbSecurityAuditor
from modules.sap_hotnews import SapHotNewsAuditor
from modules.abap_authorizations import AbapAuthorizationAuditor
from modules.system_trust import SystemTrustAuditor
from modules.baseline_params import BaselineParamAuditor
from modules.s4_business_authz import S4BusinessAuthzAuditor
from modules.access_risk_analysis import AccessRiskAnalysisAuditor
from modules.basis_job_command import BasisJobCommandAuditor
from modules.grc_access_control import GrcAccessControlAuditor
from modules.role_governance import RoleGovernanceAuditor
from modules.financial_controls import FinancialControlsAuditor

# (module key, auditor class) — mirrors sap_scanner.py's module registry.
MODULES = [
    ("users", UserAuthAuditor), ("params", SecurityParamAuditor),
    ("network", NetworkServiceAuditor), ("rise", RiseBtpAuditor),
    ("iam", AdvancedIamAuditor), ("btpcloud", BtpCloudSurfaceAuditor),
    ("intglayer", IntegrationLayerAuditor), ("dataprot", DataProtectionAuditor),
    ("codetrans", CodeTransportAuditor), ("logmon", LogMonitoringAuditor),
    ("fiori", FioriUiAuditor), ("crypto", CryptoPostureAuditor),
    ("hanadb", HanaDbSecurityAuditor), ("hotnews", SapHotNewsAuditor),
    ("authz", AbapAuthorizationAuditor), ("systrust", SystemTrustAuditor),
    ("baseline", BaselineParamAuditor), ("s4authz", S4BusinessAuthzAuditor),
    ("ara", AccessRiskAnalysisAuditor), ("jobcmd", BasisJobCommandAuditor),
    ("grcac", GrcAccessControlAuditor), ("rolegov", RoleGovernanceAuditor),
    ("fincontrols", FinancialControlsAuditor),
]
_IDS = [m[0] for m in MODULES]

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

# Key check ids each module is expected to raise on sample_data (a robust
# regression guard for the modules authored with tightly-crafted samples).
EXPECTED_CHECKS = {
    "hanadb": {"HANADB-USER-001", "HANADB-PRIV-001", "HANADB-PRIV-005",
               "HANADB-AUDIT-001", "HANADB-PARAM-001", "HANADB-PARAM-004",
               "HANADB-PARAM-005", "HANADB-PRIV-006"},
    "crypto": {"CRYPTO-HANA-004", "CRYPTO-HANA-005"},
    "btpcloud": {"BTP-IAS-004", "BTP-IAS-005", "BTP-CC-008"},
    "hotnews": {"HOTNEWS-001", "HOTNEWS-002", "HOTNEWS-003", "HOTNEWS-004"},
    "authz": {"AUTH-001", "AUTH-002", "AUTH-003", "AUTH-004", "AUTH-005", "AUTH-013"},
    "systrust": {"STDUSR-001", "STDUSR-002", "STDUSR-003", "TRUST-001",
                 "TRUST-004", "TRUST-005", "TRUST-008", "TRUST-010"},
    "logmon": {"LOG-AUD-010", "LOG-AUD-011", "LOG-TBL-010"},
    "codetrans": {"CODE-SYSCHG-001"},
    "baseline": {"BASELINE-001", "BASELINE-002", "BASELINE-003", "BASELINE-004",
                 "BASELINE-005", "BASELINE-006", "BASELINE-007", "BASELINE-008",
                 "BASELINE-009", "BASELINE-010"},
    "s4authz": {"S4AUTHZ-001", "S4AUTHZ-002", "S4AUTHZ-003", "S4AUTHZ-004",
                "S4AUTHZ-005", "S4AUTHZ-006", "S4AUTHZ-007", "S4AUTHZ-008"},
    "ara": {"ARA-P2P-01", "ARA-R2R-01", "ARA-BASIS-01", "ARA-H2R-01", "ARA-SCORE-001"},
    "jobcmd": {"JOBCMD-CMD-001", "JOBCMD-CMD-002", "JOBCMD-CMD-003", "JOBCMD-JOB-001",
               "JOBCMD-JOB-002", "JOBCMD-JOB-003", "JOBCMD-JOB-005"},
    "grcac": {"GRC-FF-001", "GRC-FF-002", "GRC-FF-002B", "GRC-ARM-001", "GRC-ARM-001B",
              "GRC-ARA-001", "GRC-MIT-001", "GRC-RS-001", "GRC-RS-003"},
    "rolegov": {"RG-SU24-001", "RG-GEN-001", "RG-DRV-001"},
    "fincontrols": {"FIN-PP-001", "FIN-TOL-001", "FIN-SF-001", "FIN-DOC-001", "FIN-NR-001"},
}


def _run(cls, data):
    # shallow-copy so a module cannot leak state into another via the shared dict
    return cls(dict(data), {}).run_all_checks()


def _all_findings(data):
    out = []
    for _key, cls in MODULES:
        out.extend(_run(cls, data))
    return out


# ── per-module behaviour ─────────────────────────────────────────────────────
@pytest.mark.parametrize("key,cls", MODULES, ids=_IDS)
def test_module_fires_on_sample(key, cls, data):
    """Every module must produce at least one finding on the crafted sample."""
    findings = _run(cls, data)
    assert len(findings) >= 1, f"module '{key}' produced no findings on sample_data"


@pytest.mark.parametrize("key,cls", MODULES, ids=_IDS)
def test_module_handles_empty_input(key, cls):
    """Empty input must not crash; a module may emit a 'data not provided' finding."""
    findings = cls({}, {}).run_all_checks()
    assert isinstance(findings, list)
    for f in findings:  # any such finding must still be well-formed
        assert isinstance(f.get("check_id"), str) and f.get("severity") in VALID_SEVERITIES


@pytest.mark.parametrize(
    "key,cls",
    [(k, c) for k, c in MODULES if k in EXPECTED_CHECKS],
    ids=[k for k, _ in MODULES if k in EXPECTED_CHECKS],
)
def test_module_expected_checks_present(key, cls, data):
    """Key check ids for the newer modules must fire on sample_data."""
    ids = {f["check_id"] for f in _run(cls, data)}
    missing = EXPECTED_CHECKS[key] - ids
    assert not missing, f"module '{key}' missing expected checks: {sorted(missing)}"


# ── finding contract (catches the tuple-in-description bug class) ─────────────
def test_finding_contract(data):
    findings = _all_findings(data)
    assert len(findings) >= 150  # sanity floor on the shipped check coverage
    for f in findings:
        for key in ("check_id", "title", "severity", "category", "description", "remediation"):
            assert isinstance(f[key], str), (
                f"{f.get('check_id')}.{key} is {type(f[key]).__name__}, expected str")
        assert f["severity"] in VALID_SEVERITIES, f"{f['check_id']}: bad severity {f['severity']!r}"
        assert isinstance(f["affected_items"], list) and all(isinstance(x, str) for x in f["affected_items"])
        assert isinstance(f["references"], list) and all(isinstance(x, str) for x in f["references"])
        assert isinstance(f["details"], dict)
        assert f["affected_count"] == len(f["affected_items"])


def test_no_cross_module_check_id_collision(data):
    """A check_id must belong to exactly one module. (An original module may repeat
    its own id once per affected item, but two different modules must not share one.)"""
    from collections import defaultdict
    owners = defaultdict(set)
    for key, cls in MODULES:
        for f in _run(cls, data):
            owners[f["check_id"]].add(key)
    shared = {cid: sorted(m) for cid, m in owners.items() if len(m) > 1}
    assert not shared, f"check_ids emitted by multiple modules: {shared}"


# Modules that emit at most ONE finding per check_id (aggregated). Excludes modules
# that legitimately repeat an id once per affected item (e.g. codetrans CODE-STMT-001,
# users USR-*, rise RISE-*), which are covered by the cross-module-collision test only.
AGGREGATING_MODULES = {"hanadb", "hotnews", "authz", "systrust", "baseline", "s4authz",
                       "ara", "jobcmd", "grcac", "logmon", "rolegov", "fincontrols"}


@pytest.mark.parametrize(
    "key,cls", [(k, c) for k, c in MODULES if k in AGGREGATING_MODULES],
    ids=[k for k, _ in MODULES if k in AGGREGATING_MODULES])
def test_aggregating_module_ids_unique(key, cls, data):
    """The aggregating modules emit one finding per check_id — no repeats within a run."""
    ids = [f["check_id"] for f in _run(cls, data)]
    dupes = [c for c, n in Counter(ids).items() if n > 1]
    assert not dupes, f"module '{key}' emits duplicate check_ids: {dupes}"


def test_ara_permission_level_and_mitigation(data):
    """ARA's headline behaviours: permission-level false-positive suppression (a user with
    the maintain *transaction* but only display *activity* must not fire), an active
    mitigating control suppresses the risk, and an EXPIRED mitigation re-surfaces it."""
    findings = _run(AccessRiskAnalysisAuditor, data)
    by_id = {f["check_id"]: f for f in findings}
    p2p = by_id.get("ARA-P2P-01")
    assert p2p is not None, "ARA-P2P-01 should fire on the crafted vendor↔payment conflict"
    affected = " ".join(p2p["affected_items"])
    assert "ARAFRAUD1" in affected, "expired mitigation must re-surface the risk"
    assert "ARAMULTI" not in affected, "active mitigation must suppress the risk"
    assert p2p["details"]["mitigated"] >= 1
    # ARACLEAN holds the FK02 maintain transaction but only ACTVT 03 (display) → must not fire.
    leaked = " ".join(i for f in findings for i in f["affected_items"])
    assert "ARACLEAN" not in leaked, "display-only access must be suppressed at the permission level"


def test_check_id_shape(data):
    """Every check_id is an uppercase module prefix + hyphen + suffix. (The PARAM
    module names checks after the parameter, e.g. PARAM-login/min_password_lng.)"""
    import re
    pat = re.compile(r"^[A-Z][A-Z0-9]*-\S+$")
    bad = sorted({f["check_id"] for f in _all_findings(data) if not pat.match(f["check_id"])})
    assert not bad, f"malformed check_ids: {bad}"


# ── full report pipeline ─────────────────────────────────────────────────────
def test_report_renders(data, tmp_path):
    from modules.report_generator import ReportGenerator
    findings = _all_findings(data)
    out = tmp_path / "report.html"
    ReportGenerator(findings, {"scan_time": "2026-01-01T00:00:00",
                               "data_directory": "sample_data",
                               "modules_run": _IDS, "severity_filter": "ALL"}).generate(str(out))
    html = out.read_text(encoding="utf-8")
    assert html.lstrip().startswith("<!DOCTYPE html>")
    assert "</html>" in html
    # a couple of real findings should appear in the rendered output
    assert "Debug &amp; Replace" in html or "SAP*" in html


def test_report_handles_no_findings(tmp_path):
    from modules.report_generator import ReportGenerator
    out = tmp_path / "empty.html"
    ReportGenerator([], {"scan_time": "t", "modules_run": [], "severity_filter": "ALL"}).generate(str(out))
    assert out.read_text(encoding="utf-8").lstrip().startswith("<!DOCTYPE html>")


# ── PDF report + findings knowledge base ─────────────────────────────────────
_META = {"scan_time": "2026-01-01T00:00:00", "data_directory": "sample_data",
         "modules_run": _IDS, "severity_filter": "ALL"}


def test_pdf_writer_wraps_and_builds():
    from modules.pdf_writer import PDFWriter
    w = PDFWriter()
    w.add_page()
    w.text(50, 700, "Hello — world → SAP ≥ test", font="HB", size=12, color=(0.1, 0.1, 0.1))
    w.rect(40, 40, 100, 20, fill=(0.9, 0.9, 0.9), stroke=(0, 0, 0))
    lines = w.wrap("averylongword " * 60, "H", 10, 200)
    assert len(lines) > 1  # wrapped to multiple lines
    data = w.build()
    assert data.startswith(b"%PDF-1.4") and data.rstrip().endswith(b"%%EOF")


def test_pdf_report_generates(data, tmp_path):
    from modules.pdf_report import PDFReportGenerator
    from modules.finding_kb import FindingKB
    findings = _all_findings(data)
    out = tmp_path / "report.pdf"
    PDFReportGenerator(findings, _META, FindingKB()).generate(str(out))
    raw = out.read_bytes()
    assert raw.startswith(b"%PDF-1.4")
    assert raw.rstrip().endswith(b"%%EOF")
    assert raw.count(b" 0 obj") > 5              # cover + summary + finding pages
    assert b"/Type /Page" in raw and b"xref" in raw


def test_pdf_report_handles_no_findings(tmp_path):
    from modules.pdf_report import PDFReportGenerator
    out = tmp_path / "empty.pdf"
    PDFReportGenerator([], {"scan_time": "t", "modules_run": [], "severity_filter": "ALL"}).generate(str(out))
    assert out.read_bytes().startswith(b"%PDF")


def test_finding_kb_fallback_and_lookup(tmp_path):
    from modules.finding_kb import FindingKB
    # missing file → graceful fallback to the finding's own text
    kb = FindingKB(path=str(tmp_path / "does_not_exist.json"))
    risk, mit, detailed = kb.detail_for({"check_id": "X-1", "description": "d", "remediation": "r"})
    assert (risk, mit, detailed) == ("d", "r", False)
    # a real KB with a family entry resolves by prefix
    import json
    p = tmp_path / "kb.json"
    p.write_text(json.dumps({"BTP-CC": {"risk": "R", "mitigation": "M"}}), encoding="utf-8")
    kb2 = FindingKB(path=str(p))
    r2, m2, d2 = kb2.detail_for({"check_id": "BTP-CC-001", "description": "d", "remediation": "r"})
    assert (r2, m2, d2) == ("R", "M", True)


# ── CLI end-to-end ───────────────────────────────────────────────────────────
def test_cli_end_to_end(tmp_path):
    out = tmp_path / "cli_report.html"
    env = dict(os.environ, PYTHONIOENCODING="utf-8")  # banner uses box-drawing chars
    proc = subprocess.run(
        [sys.executable, "sap_scanner.py", "--data-dir", "sample_data", "--output", str(out)],
        cwd=str(ROOT), env=env, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=120)
    assert proc.returncode == 0, f"scanner exited {proc.returncode}\n{proc.stderr[-800:]}"
    assert out.exists() and out.stat().st_size > 0
    assert "SCAN COMPLETE" in proc.stdout
