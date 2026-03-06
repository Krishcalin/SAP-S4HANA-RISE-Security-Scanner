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
from modules.report_generator import ReportGenerator
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
        choices=["users", "params", "network", "rise", "iam", "btpcloud", "intglayer", "all"],
        default=["all"],
        help="Which audit modules to run (default: all)"
    )
    parser.add_argument(
        "--config", default=None,
        help="Path to custom baseline config JSON (optional)"
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
        "users", "params", "network", "rise", "iam", "btpcloud", "intglayer"
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

    # Filter by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    if args.severity != "ALL":
        threshold = severity_order.get(args.severity, 4)
        all_findings = [
            f for f in all_findings
            if severity_order.get(f.get("severity", "INFO"), 4) <= threshold
        ]

    # Generate report
    print(f"\n[*] Generating HTML report: {args.output}")
    generator = ReportGenerator(all_findings, scan_meta)
    generator.generate(args.output)

    # Summary
    crit = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
    high = sum(1 for f in all_findings if f["severity"] == "HIGH")
    med = sum(1 for f in all_findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in all_findings if f["severity"] == "LOW")

    print(f"\n{'='*55}")
    print(f"  SCAN COMPLETE — Total Findings: {len(all_findings)}")
    print(f"  CRITICAL: {crit}  |  HIGH: {high}  |  MEDIUM: {med}  |  LOW: {low}")
    print(f"  Report saved to: {args.output}")
    print(f"{'='*55}\n")


if __name__ == "__main__":
    main()
