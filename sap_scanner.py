#!/usr/bin/env python3
"""
SAP S/4HANA RISE Security Scanner
===================================
Offline configuration review tool for identifying vulnerabilities
and misconfigurations in SAP S/4HANA RISE environments.

Reads exported configuration data (CSV/JSON) and produces an
HTML dashboard with findings, risk ratings, and remediation guidance.

Usage:
    python sap_scanner.py --data-dir ./sample_data --output report.html
    python sap_scanner.py --data-dir ./exports --output report.html --severity HIGH
"""

import argparse
import json
import os
import sys
import datetime
from pathlib import Path

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
from modules.grc_access_control import GrcAccessControlAuditor
from modules.role_governance import RoleGovernanceAuditor
from modules.financial_controls import FinancialControlsAuditor
from modules.baseline_params import BaselineParamAuditor
from modules.s4_business_authz import S4BusinessAuthzAuditor
from modules.access_risk_analysis import AccessRiskAnalysisAuditor
from modules.basis_job_command import BasisJobCommandAuditor
from modules.report_generator import ReportGenerator
from modules.pdf_report import PDFReportGenerator
from modules.pptx_report import PPTXReportGenerator
from modules.finding_kb import FindingKB
from modules.risk_prioritizer import RiskPrioritizer
from modules.data_loader import DataLoader


def banner():
    print(r"""
  ╔═══════════════════════════════════════════════════════╗
  ║   SAP S/4HANA RISE Security Scanner v1.0             ║
  ║   Offline Configuration Review & Vulnerability Audit  ║
  ╚═══════════════════════════════════════════════════════╝
    """)


def main():
    banner()

    parser = argparse.ArgumentParser(
        description="SAP S/4HANA RISE Security Scanner - Offline Config Review"
    )
    parser.add_argument(
        "--data-dir", required=True,
        help="Directory containing exported SAP configuration files (CSV/JSON)"
    )
    parser.add_argument(
        "--output", default="sap_security_report.html",
        help="Output HTML report filename (default: sap_security_report.html)"
    )
    parser.add_argument(
        "--severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "ALL"],
        default="ALL",
        help="Minimum severity to include in report (default: ALL)"
    )
    parser.add_argument(
        "--modules", nargs="+",
        choices=["users", "params", "network", "rise", "iam", "btpcloud", "intglayer", "dataprot", "codetrans", "logmon", "fiori", "crypto", "hanadb", "hotnews", "authz", "systrust", "baseline", "s4authz", "ara", "jobcmd", "grcac", "rolegov", "fincontrols", "all"],
        default=["all"],
        help="Which audit modules to run (default: all)"
    )
    parser.add_argument(
        "--config", default=None,
        help="Path to custom baseline config JSON (optional)"
    )
    parser.add_argument(
        "--format", choices=["html", "pdf", "pptx", "both", "all"], default="html",
        help="Report format: html (default), pdf (detailed hand-over report), "
             "pptx (presentation deck), both (html+pdf), or all (html+pdf+pptx)"
    )
    parser.add_argument(
        "--pptx-mode", choices=["full", "summary"], default="full",
        help="PPTX deck scope: full (executive summary + compliance mapping + one slide "
             "per finding, 300+ slides; default) or summary (short executive deck only)"
    )

    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    if not data_dir.exists():
        print(f"[ERROR] Data directory not found: {data_dir}")
        sys.exit(1)

    # Load data
    print("[*] Loading exported configuration data...")
    loader = DataLoader(data_dir)
    data = loader.load_all()

    # Load custom baseline if provided
    baseline_overrides = {}
    if args.config:
        with open(args.config, "r") as f:
            baseline_overrides = json.load(f)
        print(f"[*] Loaded custom baseline from {args.config}")

    run_modules = args.modules if "all" not in args.modules else [
        "users", "params", "network", "rise", "iam", "btpcloud",
        "intglayer", "dataprot", "codetrans", "logmon", "fiori", "crypto", "hanadb", "hotnews", "authz", "systrust",
        "baseline", "s4authz", "ara", "jobcmd", "grcac", "rolegov", "fincontrols"
    ]

    all_findings = []
    scan_meta = {
        "scan_time": datetime.datetime.now().isoformat(),
        "data_directory": str(data_dir),
        "modules_run": run_modules,
        "severity_filter": args.severity,
    }

    # --- User & Authorization Audit ---
    if "users" in run_modules:
        print("[*] Running User & Authorization Audit...")
        auditor = UserAuthAuditor(data, baseline_overrides)
        findings = auditor.run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")

    # --- Security Parameters Baseline ---
    if "params" in run_modules:
        print("[*] Running Security Parameters Baseline Check...")
        auditor = SecurityParamAuditor(data, baseline_overrides)
        findings = auditor.run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")

    # --- Network & Service Exposure ---
    if "network" in run_modules:
        print("[*] Running Network & Service Exposure Audit...")
        auditor = NetworkServiceAuditor(data, baseline_overrides)
        findings = auditor.run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")

    # --- RISE/BTP-Specific Checks ---
    if "rise" in run_modules:
        print("[*] Running RISE/BTP-Specific Checks...")
        auditor = RiseBtpAuditor(data, baseline_overrides)
        findings = auditor.run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")

    # --- Advanced Identity & Access Management ---
    if "iam" in run_modules:
        print("[*] Running Advanced IAM Checks (SoD, Firefighter, Role Expiry, Cross-ID)...")
        auditor = AdvancedIamAuditor(data, baseline_overrides)
        findings = auditor.run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")

    # --- BTP Cloud Attack Surface ---
    if "btpcloud" in run_modules:
        print("[*] Running BTP Cloud Attack Surface Checks...")
        auditor = BtpCloudSurfaceAuditor(data, baseline_overrides)
        findings = auditor.run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")

    # --- Network & Integration Layer ---
    if "intglayer" in run_modules:
        print("[*] Running Network & Integration Layer Checks...")
        auditor = IntegrationLayerAuditor(data, baseline_overrides)
        findings = auditor.run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")

    # --- Data Protection & Privacy ---
    if "dataprot" in run_modules:
        print("[*] Running Data Protection & Privacy Checks...")
        auditor = DataProtectionAuditor(data, baseline_overrides)
        findings = auditor.run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")

    # --- Code & Transport Security ---
    if "codetrans" in run_modules:
        print("[*] Running Code & Transport Security Checks...")
        auditor = CodeTransportAuditor(data, baseline_overrides)
        findings = auditor.run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")

    # --- Logging, Monitoring & Incident Response ---
    if "logmon" in run_modules:
        print("[*] Running Logging, Monitoring & IR Checks...")
        auditor = LogMonitoringAuditor(data, baseline_overrides)
        findings = auditor.run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")

    # --- Fiori & UI Layer ---
    if "fiori" in run_modules:
        print("[*] Running Fiori & UI Layer Checks...")
        auditor = FioriUiAuditor(data, baseline_overrides)
        findings = auditor.run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")

    # --- Cryptographic Posture ---
    if "crypto" in run_modules:
        print("[*] Running Cryptographic Posture Checks...")
        auditor = CryptoPostureAuditor(data, baseline_overrides)
        findings = auditor.run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")

    # --- HANA Database Security ---
    if "hanadb" in run_modules:
        print("[*] Running HANA Database Security Checks (users, privileges, audit, params)...")
        auditor = HanaDbSecurityAuditor(data, baseline_overrides)
        findings = auditor.run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")

    # --- SAP Security Notes / HotNews ---
    if "hotnews" in run_modules:
        print("[*] Running SAP Security Notes / HotNews Checks (missing critical patches since 2020)...")
        auditor = SapHotNewsAuditor(data, baseline_overrides)
        findings = auditor.run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")

    # --- ABAP Authorization & Critical Access ---
    if "authz" in run_modules:
        print("[*] Running ABAP Authorization & Critical Access Checks (AGR_1251 role analysis)...")
        auditor = AbapAuthorizationAuditor(data, baseline_overrides)
        findings = auditor.run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")

    # --- System Trust & Standard Users ---
    if "systrust" in run_modules:
        print("[*] Running System Trust & Standard Users Checks (trusted RFC, SAP*, default passwords)...")
        auditor = SystemTrustAuditor(data, baseline_overrides)
        findings = auditor.run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")

    # --- Security Baseline Parameters ---
    if "baseline" in run_modules:
        print("[*] Running Security Baseline Parameter Checks (auth engine, SNC, GUI scripting, gateway)...")
        auditor = BaselineParamAuditor(data, baseline_overrides)
        findings = auditor.run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")

    # --- S/4HANA & Cloud Authorization ---
    if "s4authz" in run_modules:
        print("[*] Running S/4HANA & Cloud Authorization Checks (business roles, CDS, OData V4, CF, BTP)...")
        auditor = S4BusinessAuthzAuditor(data, baseline_overrides)
        findings = auditor.run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")

    # --- Access Risk Analysis (Segregation of Duties) ---
    if "ara" in run_modules:
        print("[*] Running Access Risk Analysis (permission-level SoD, critical access, mitigations)...")
        auditor = AccessRiskAnalysisAuditor(data, baseline_overrides)
        findings = auditor.run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")

    # --- Basis Jobs & External OS Commands ---
    if "jobcmd" in run_modules:
        print("[*] Running Basis Jobs & OS-Command Checks (external commands, background job step users)...")
        auditor = BasisJobCommandAuditor(data, baseline_overrides)
        findings = auditor.run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")

    # --- GRC Access Control (Firefighter/EAM, ARM, GRC-native SoD & mitigations) ---
    if "grcac" in run_modules:
        print("[*] Running GRC Access Control Checks (firefighter/EAM, access requests, SoD & mitigations)...")
        auditor = GrcAccessControlAuditor(data, baseline_overrides)
        findings = auditor.run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")

    # --- Role Design & Governance (SU24 hygiene, ungenerated profiles, derived drift) ---
    if "rolegov" in run_modules:
        print("[*] Running Role Design & Governance Checks (SU24 proposals, profile generation, derived drift)...")
        auditor = RoleGovernanceAuditor(data, baseline_overrides)
        findings = auditor.run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")

    # --- Financial Controls (SOX: posting periods, tolerances, dual control, doc change) ---
    if "fincontrols" in run_modules:
        print("[*] Running Financial Controls Checks (posting periods, tolerances, dual control, doc change rules)...")
        auditor = FinancialControlsAuditor(data, baseline_overrides)
        findings = auditor.run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")

    # Filter by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    if args.severity != "ALL":
        threshold = severity_order.get(args.severity, 4)
        all_findings = [
            f for f in all_findings
            if severity_order.get(f.get("severity", "INFO"), 4) <= threshold
        ]

    # Resolve output paths for the requested format(s) — a common base name, one
    # file per format, so `--format all` produces .html/.pdf/.pptx side by side.
    out = args.output
    low = out.lower()
    base = out
    for ext in (".pptx", ".pdf", ".html", ".htm"):
        if low.endswith(ext):
            base = out[: -len(ext)]
            break
    html_path = base + ".html"
    pdf_path = base + ".pdf"
    pptx_path = base + ".pptx"

    # Risk prioritization (P1-P4): score every finding on severity x exploitability
    # (HotNews / actively-exploited) x exposure, so the report leads with a fix-first
    # tier queue instead of an unranked wall of CRITICAL/HIGH findings.
    prio_results = RiskPrioritizer().prioritize(all_findings)
    tiers = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    for r in prio_results:
        tiers[r.tier] = tiers.get(r.tier, 0) + 1
    print(f"[*] Risk prioritization: P1 {tiers['P1']}  P2 {tiers['P2']}  "
          f"P3 {tiers['P3']}  P4 {tiers['P4']}")

    # Generate report(s) — the findings knowledge base supplies the detailed
    # risk narrative + step-by-step remediation for each finding (both formats).
    kb = FindingKB()
    detail = f"detailed knowledge base: {len(kb)} checks" if kb.loaded else "finding descriptions (no KB)"
    if args.format in ("html", "both", "all"):
        print(f"\n[*] Generating HTML report: {html_path}  ({detail})")
        ReportGenerator(all_findings, scan_meta, kb, priorities=prio_results).generate(html_path)
    if args.format in ("pdf", "both", "all"):
        print(f"[*] Generating PDF report: {pdf_path}  ({detail})")
        PDFReportGenerator(all_findings, scan_meta, kb, priorities=prio_results).generate(pdf_path)
    if args.format in ("pptx", "all"):
        full = args.pptx_mode == "full"
        kind = "full per-finding deck" if full else "summarised meeting deck"
        print(f"[*] Generating PPTX presentation: {pptx_path}  ({kind})")
        PPTXReportGenerator(all_findings, scan_meta, kb, priorities=prio_results).generate(
            pptx_path, full=full)

    # Summary
    crit = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in all_findings if f["severity"] == "HIGH")
    med = sum(1 for f in all_findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in all_findings if f["severity"] == "LOW")

    saved = []
    if args.format in ("html", "both", "all"):
        saved.append(html_path)
    if args.format in ("pdf", "both", "all"):
        saved.append(pdf_path)
    if args.format in ("pptx", "all"):
        saved.append(pptx_path)

    print(f"\n{'='*55}")
    print(f"  SCAN COMPLETE — Total Findings: {len(all_findings)}")
    print(f"  CRITICAL: {crit}  |  HIGH: {high}  |  MEDIUM: {med}  |  LOW: {low}")
    print(f"  Report(s) saved: {', '.join(saved)}")
    print(f"{'='*55}\n")


if __name__ == "__main__":
    main()
