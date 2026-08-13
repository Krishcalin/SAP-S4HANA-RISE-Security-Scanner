#!/usr/bin/env python3
# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

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

from modules import release_gate
from modules.snc_posture import SncPostureAuditor
from modules.ecs_config_items import EcsConfigAuditor
from modules.code_inventory_report import CodeInventoryAuditor
from modules.resilience_posture import ResiliencePostureAuditor
from modules.user_auth_audit import UserAuthAuditor
from modules.security_params import SecurityParamAuditor
from modules.network_services import NetworkServiceAuditor
from modules.rise_btp_checks import RiseBtpAuditor
from modules.iam_advanced import AdvancedIamAuditor
from modules.btp_cloud_surface import BtpCloudSurfaceAuditor
from modules.integration_layer import IntegrationLayerAuditor
from modules.data_protection import DataProtectionAuditor
from modules.code_transport import CodeTransportAuditor
from modules.atc_import import AtcImportAuditor
from modules.abap_sast import AbapSastAuditor
from modules.log_monitoring import LogMonitoringAuditor
from modules.log_review import LogReviewAuditor
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
from modules import fair_adapter
from modules.coverage import build_manifest
from modules.data_loader import DataLoader
from modules.deployment_modes import DEPLOYMENT_MODES, DEFAULT_DEPLOYMENT_MODE


def _make_output_encoding_safe() -> None:
    """Survive being redirected on Windows.

    An interactive Windows console negotiates UTF-8, but the moment stdout is a
    pipe or a file Python falls back to the ANSI code page (cp1252 here) and the
    banner's box-drawing characters raise UnicodeEncodeError before any work
    starts. The traceback names an encodings module, so it reads like a broken
    install rather than an unprintable character.

    This is load-bearing for the release gate specifically: a CI pipeline ALWAYS
    redirects stdout, so on a Windows agent the scanner would die before it
    reached the gate — and a control that cannot run under redirection is not a
    control. `errors="replace"` rather than a strict re-encode: a mangled dash in
    a log is a cosmetic problem, a crashed build step is not.
    """
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):        # detached or already closed
                pass


_make_output_encoding_safe()


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
        "--abap-src", default=None, metavar="DIR",
        help="Unpacked abapGit offline export to scan with the `cva` module. "
             "abapGit's offline ZIP is the one route by which ABAP source leaves a "
             "RISE system without OS access or an SAP ticket."
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
        choices=["users", "params", "network", "rise", "iam", "btpcloud", "intglayer", "dataprot", "codetrans", "atc", "cva", "logmon", "logreview", "fiori", "crypto", "hanadb", "hotnews", "authz", "systrust", "baseline", "s4authz", "ara", "jobcmd", "grcac", "rolegov", "fincontrols", "codeinv", "resilience", "snc", "ecsconfig", "all"],
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
    parser.add_argument(
        "--crq", action="store_true",
        help="Run FAIR cyber-risk quantification: map findings to SAP loss scenarios, "
             "write <output>.crq.json, and (if the CRQ engine is available) embed the "
             "annualized loss exposure (ALE) + loss-exceedance curve in the HTML/PDF report."
    )
    parser.add_argument("--crq-engine", default=None,
        help="Path to the CRQ engine (crq_engine.py). Defaults to the CRQ_ENGINE env var "
             "or an auto-detected sibling Cyber-Risk-Quantification repo.")
    parser.add_argument("--crq-revenue", type=float, default=None,
        help="Organization annual revenue (USD) for the FAIR analysis (default: illustrative $1B).")
    parser.add_argument("--crq-industry", default=None,
        help="Industry LABEL for the FAIR report. It is printed and scales nothing — there is no industry multiplier in the engine and there never has been. One of: financial_services, healthcare, "
             "technology, retail, manufacturing, government, energy, education).")
    parser.add_argument("--crq-org-name", default=None, help="Organization name for the FAIR report.")
    parser.add_argument("--crq-inputs", default=None, metavar="FILE",
        help="Path to the customer's financial figures (crq_parameters.json shape). "
             "Defaults to crq_parameters.json in the data directory if present. "
             "Without figures, no currency total is presented as this "
             "organisation's exposure.")
    parser.add_argument("--crq-sims", type=int, default=10000,
        help="Monte Carlo iterations per scenario (default: 10000).")

    # ── Release gate ─────────────────────────────────────────────────────────
    parser.add_argument(
        "--deployment-mode", choices=list(DEPLOYMENT_MODES),
        default=DEFAULT_DEPLOYMENT_MODE,
        help="Which estate this export came from. SAP Note 3250501 is the MANDATORY "
             "baseline for rise_* (SAP Enterprise Cloud Services) and changes what "
             "counts as compliant: snc/accept_insecure_gui=1 and "
             "rfc/callback_security_method=1 are SAP's own mandate there and are not "
             "findings, and DDIC is not required to be locked. Defaults to on_prem, "
             "because guessing ECS would silently relax genuine on-premise findings.")

    gate = parser.add_argument_group(
        "release gate",
        "Decide whether a change may ship, and exit non-zero when it may not. "
        "Exit codes: 0 pass, 1 policy violated, 2 could not assess.")
    gate.add_argument(
        "--gate", action="store_true",
        help="Evaluate the release gate and exit with its decision.")
    gate.add_argument(
        "--gate-policy", default=None, metavar="FILE",
        help="Gate policy JSON. Merged over the defaults, so a policy naming only "
             "one key cannot silently switch the others off.")
    gate.add_argument(
        "--gate-baseline", default=None, metavar="FILE",
        help="Accepted-state baseline. Without it EVERY in-scope finding counts as "
             "new, which is right for a first run and wrong for a pipeline.")
    gate.add_argument(
        "--gate-scope", default=None, metavar="FILE",
        help="Object names the transport touches, one per line. Only findings on "
             "these objects are judged — a developer cannot be asked to fix "
             "somebody else's object to ship their own.")
    gate.add_argument(
        "--gate-write-baseline", default=None, metavar="FILE",
        help="Write the current findings out as the accepted baseline and exit 0. "
             "This is step one of adopting the gate.")
    gate.add_argument(
        "--gate-json", default=None, metavar="FILE",
        help="Write the gate decision as JSON, for a pipeline to consume.")

    args = parser.parse_args()

    if args.crq and args.crq_sims < 1:
        parser.error("--crq-sims must be >= 1")

    data_dir = Path(args.data_dir)
    if not data_dir.exists():
        print(f"[ERROR] Data directory not found: {data_dir}")
        sys.exit(1)

    # Load data
    print("[*] Loading exported configuration data...")
    loader = DataLoader(data_dir)
    data = loader.load_all()
    # Source is a DIRECTORY, not one of the tabular exports, so it is handed to the
    # auditor through the same dict rather than through DataLoader's FILE_MAP.
    if getattr(args, "abap_src", None):
        data["abap_source_dir"] = args.abap_src

    # Load custom baseline if provided
    baseline_overrides = {}
    if args.config:
        with open(args.config, "r") as f:
            baseline_overrides = json.load(f)
        print(f"[*] Loaded custom baseline from {args.config}")

    run_modules = args.modules if "all" not in args.modules else [
        "users", "params", "network", "rise", "iam", "btpcloud",
        "intglayer", "dataprot", "codetrans", "atc", "cva", "logmon", "logreview", "fiori", "crypto", "hanadb", "hotnews", "authz", "systrust",
        "baseline", "s4authz", "ara", "jobcmd", "grcac", "rolegov", "fincontrols", "codeinv", "resilience", "snc", "ecsconfig"
    ]

    # Every ECS-aware check reads the mode from here. Built once so two auditors
    # cannot disagree about which estate they are looking at.
    run_ctx = {"deployment_mode": args.deployment_mode, "modules": set(run_modules)}

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
        auditor = UserAuthAuditor(data, baseline_overrides, run_ctx)
        findings = auditor.run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")

    # --- Security Parameters Baseline ---
    if "params" in run_modules:
        print("[*] Running Security Parameters Baseline Check...")
        auditor = SecurityParamAuditor(data, baseline_overrides, run_ctx)
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
        # run_context lets the module see whether the deeper permission-level SoD
        # module ('ara') is actually in this run. Without it, iam deferred whenever
        # role_auth_values was merely PRESENT — so `--modules iam` stood down in
        # favour of a module that was not running, and produced no SoD findings.
        auditor = AdvancedIamAuditor(data, baseline_overrides,
                                     run_context={"modules": set(run_modules)})
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

    # --- SNC posture (SAP Note 3250501, ECS mandatory) ---
    if "snc" in run_modules:
        print("[*] Running SNC Posture Assessment...")
        auditor = SncPostureAuditor(data, baseline_overrides, run_ctx)
        findings = auditor.run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")

    # --- ECS mandatory configuration items ---
    if "ecsconfig" in run_modules:
        print("[*] Running ECS Mandatory Configuration Checks...")
        auditor = EcsConfigAuditor(data, baseline_overrides, run_ctx)
        findings = auditor.run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")

    # --- Custom-code estate inventory ---
    if "codeinv" in run_modules:
        print("[*] Running Custom-Code Estate Inventory...")
        auditor = CodeInventoryAuditor(data, baseline_overrides)
        findings = auditor.run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")

    # --- Resilience & Recovery Readiness ---
    if "resilience" in run_modules:
        print("[*] Running Resilience & Recovery Readiness Checks...")
        auditor = ResiliencePostureAuditor(data, baseline_overrides)
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

    # --- ATC / Code Inspector / SAP CVA result import ---
    # Runs before our own scanner would: these findings are SAP's, produced inside
    # the customer's own system, so they carry no false positives of our making.
    if "atc" in run_modules:
        print("[*] Importing ABAP Test Cockpit / Code Inspector results...")
        auditor = AtcImportAuditor(data, baseline_overrides,
                                   run_context={"modules": set(run_modules)})
        findings = auditor.run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")

    # --- ABAP / UI5 source scanning (our own engine) ---
    # Only runs when --abap-src points at an unpacked abapGit export. Where the
    # customer has SAP's own CVA, prefer the `atc` module: those findings are SAP's.
    if "cva" in run_modules:
        print("[*] Running ABAP / UI5 source scan...")
        auditor = AbapSastAuditor(data, baseline_overrides,
                                  run_context={"modules": set(run_modules)})
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

    # --- Security Audit Log Retrospective Review ---
    # Retrospective review over the window the customer exported — NOT monitoring,
    # NOT detection, NOT real-time. Two halves: whether the audit log was capturing
    # what the customer believes it captures, and what the exported window contains.
    if "logreview" in run_modules:
        print("[*] Running Security Audit Log Retrospective Review (filter coverage + patterns over the exported window)...")
        auditor = LogReviewAuditor(data, baseline_overrides)
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
        auditor = CryptoPostureAuditor(data, baseline_overrides, run_ctx)
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
        auditor = BaselineParamAuditor(data, baseline_overrides, run_ctx)
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

    # THE CORPUS AS SCANNED. `--severity` is a DISPLAY option — it decides what
    # is listed, not what was found — so everything that makes a claim ABOUT THE
    # ESTATE reads this rather than the filtered list below.
    #
    # It was introduced for the FAIR figure alone, with the argument that a
    # display option "must not silently change the dollar figure". The argument
    # was right and its scope was too narrow: the CSF, FAIR-CAM, compliance and
    # domain roll-ups make exactly the same kind of claim, and on --severity HIGH
    # a Category with real MEDIUM findings rendered the green "no findings" chip.
    # The money was protected and the frameworks were not.
    fair_findings = list(all_findings)

    # Filter by severity (affects the displayed findings / tiers only)
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

    # FAIR cyber-risk quantification (optional): translate findings into a
    # dollar-denominated annual loss exposure (ALE) via the FAIR Monte Carlo
    # engine. Always exports the CRQ scenario JSON; embeds numbers in the
    # HTML/PDF report when the CRQ engine can be located.
    fair_summary = None
    if args.crq:
        print("[*] FAIR cyber-risk quantification (mapping findings to SAP loss scenarios)...")
        org_overrides = {"name": args.crq_org_name, "revenue": args.crq_revenue,
                         "industry": args.crq_industry}

        # THE CUSTOMER'S OWN FIGURES REACH THE OFFLINE REPORT HERE.
        #
        # Until this existed the offline path was structurally incapable of
        # printing them: fair_adapter.run gates all pricing on `loss_answers` and
        # nothing offline ever passed it. So the HTML and PDF a customer sends to
        # their auditor carried the catalogue's illustrative $1bn manufacturer,
        # while the console showed the customer's own — same product, same estate,
        # two different numbers, and neither artefact said why.
        #
        # Precedence: an explicit --crq-inputs beats crq_parameters.json in the
        # data directory, for the same reason --crq-engine beats the bundled
        # engine — somebody who types a path has said what they mean.
        crq_answers = None
        crq_source = None
        if getattr(args, "crq_inputs", None):
            with open(args.crq_inputs, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
            crq_answers = (payload or {}).get("answers") or None
            crq_source = args.crq_inputs
        else:
            sidecar = data.get(DataLoader.CRQ_PARAMETERS_KEY)
            if sidecar:
                crq_answers = sidecar.get("answers") or None
                crq_source = DataLoader.CRQ_PARAMETERS_FILE

        # --crq-revenue ALONE NOW MEANS SOMETHING.
        #
        # It was inert: it set org["revenue"], and crq_engine.simulate_scenario
        # never reads the organization dict at all. Measured before this change,
        # 42,000,000 and 4,200,000,000 produced the identical P90 — a documented
        # flag that promised to change the analysis and did nothing. Turning it
        # into the one answer it actually is lets the revenue ratio scale the
        # catalogue's bands, which is the whole of what a bare revenue figure can
        # honestly support.
        if crq_answers is None and args.crq_revenue:
            crq_answers = {"sap_revenue": float(args.crq_revenue)}
            crq_source = "--crq-revenue"

        # FAIR runs on the UNFILTERED finding set (see fair_findings above) so a
        # report severity filter never changes the quantified loss exposure.
        fair_prio = (prio_results if args.severity == "ALL"
                     else RiskPrioritizer().prioritize(fair_findings))
        crq_out = fair_adapter.run(
            fair_findings, fair_prio, org_overrides=org_overrides,
            engine_path=args.crq_engine, simulations=args.crq_sims,
            loss_answers=crq_answers)
        if crq_answers:
            print(f"    Loss figures: {len(crq_answers)} answer(s) from {crq_source}")
        else:
            print("    Loss figures: NONE SUPPLIED. The scenario catalogue's "
                  "illustrative company is used for the shape of the analysis, and "
                  "the report will NOT present a currency figure as this "
                  "organisation's exposure. Supply crq_parameters.json to price it.")
        crq_json_path = base + ".crq.json"
        with open(crq_json_path, "w", encoding="utf-8") as fh:
            json.dump(crq_out["crq_input"], fh, indent=2)
        print(f"    CRQ scenario input written: {crq_json_path}")
        if crq_out["unrouted"]:
            print(f"    (note: {crq_out['unrouted']} finding(s) had no explicit scenario route "
                  f"- assigned to the privileged-access scenario)")
        if crq_out["engine_found"] and crq_out["summary"]:
            fair_summary = crq_out["summary"]
            pf = fair_summary["portfolio"]
            # THE TERMINAL OBEYS THE SAME RULE AS THE REPORT. It said "will NOT
            # present a currency figure" and then printed one two lines later —
            # and a figure on a terminal is copied into a chat message exactly as
            # readily as one in a PDF.
            if (fair_summary.get("loss_model") or {}).get("applied"):
                print("    Annual loss exposure (ALE):  P50 ${:,.0f}   P90 ${:,.0f}   mean ${:,.0f}".format(
                    pf["ale_p50"], pf["ale_p90"], pf["mean_ale"]))
                print("    Reducible toward hardened posture: ~${:,.0f} (P90)".format(
                    fair_summary["reducible_ale_p90"]))
            else:
                print("    Scenario shape computed; NO currency figure is reported "
                      "for this organisation because none of its own loss figures "
                      "were supplied.")
        else:
            print("    CRQ engine not found - scenario JSON exported only. Quantify it with:")
            print(f"      python crq_engine.py {crq_json_path} --html")
            print("      (per-scenario detail + dashboard; the standalone engine's portfolio total")
            print("       sums per-scenario percentiles as an upper bound - this scanner's embedded")
            print("       ALE uses the correct element-wise Monte Carlo aggregation.)")

    # Generate report(s) — the findings knowledge base supplies the detailed
    # risk narrative + step-by-step remediation for each finding (both formats).
    kb = FindingKB()
    detail = f"detailed knowledge base: {len(kb)} checks" if kb.loaded else "finding descriptions (no KB)"

    # WHAT THE SCAN COULD NOT LOOK AT, COMPUTED HERE AND CARRIED INTO EVERY REPORT.
    #
    # A missing export file loads as None and every check that needs it self-skips
    # SILENTLY, so a customer who supplied a fraction of the sources got a
    # clean-looking report with nothing anywhere saying so. modules/coverage.py has
    # said that in its own docstring since it was written — and was wired to the
    # server's ingest path only, which is why no PDF ever carried a word of it.
    #
    # It is computed once and passed as data rather than imported by the report
    # tier, because a generator's job is to render what it was given.
    try:
        coverage_manifest = build_manifest(
            data, modules_run=sorted(run_modules) if run_modules else None,
            deployment_mode=args.deployment_mode)
        counts = coverage_manifest["counts"]
        print(f"\n[*] Coverage: supplied {counts['sources_supplied']} of "
              f"{counts['sources_known']} logical sources; "
              f"{counts['modules_degraded']} module(s) ran with incomplete input, "
              f"{counts['modules_skipped']} had no input supplied, "
              f"{counts.get('modules_not_run', 0)} were not executed.")
    except Exception:                                    # noqa: BLE001
        # A manifest that cannot be built must not lose the scan. The reports
        # then say the coverage is unknown, which is worse than knowing and
        # better than implying completeness.
        coverage_manifest = None
        print("\n[!] Coverage manifest could not be built; the reports will say so.")

    if args.format in ("html", "both", "all"):
        print(f"\n[*] Generating HTML report: {html_path}  ({detail})")
        ReportGenerator(all_findings, scan_meta, kb, priorities=prio_results,
                        fair=fair_summary, coverage=coverage_manifest,
                        full_findings=fair_findings).generate(html_path)
    if args.format in ("pdf", "both", "all"):
        print(f"[*] Generating PDF report: {pdf_path}  ({detail})")
        PDFReportGenerator(all_findings, scan_meta, kb, priorities=prio_results,
                           fair=fair_summary, coverage=coverage_manifest,
                           full_findings=fair_findings).generate(pdf_path)
    if args.format in ("pptx", "all"):
        full = args.pptx_mode == "full"
        kind = "full per-finding deck" if full else "summarised meeting deck"
        print(f"[*] Generating PPTX presentation: {pptx_path}  ({kind})")
        PPTXReportGenerator(all_findings, scan_meta, kb, priorities=prio_results,
                            coverage=coverage_manifest,
                            full_findings=fair_findings).generate(
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

    # ── Release gate ─────────────────────────────────────────────────────────
    # `fair_findings`, not `all_findings`: --severity is a DISPLAY option and the
    # gate decision must not move because somebody narrowed a report. Same
    # reasoning as the FAIR figure being priced on the unfiltered set — a control
    # whose verdict depends on a rendering flag is not a control.
    if args.gate_write_baseline:
        payload = release_gate.write_baseline(fair_findings)
        Path(args.gate_write_baseline).write_text(
            json.dumps(payload, indent=2), encoding="utf-8")
        print(f"[*] Baseline written: {args.gate_write_baseline} "
              f"({payload['count']} accepted finding(s))")
        sys.exit(0)

    if args.gate:
        try:
            policy = release_gate.load_policy(
                Path(args.gate_policy) if args.gate_policy else None)
            baseline = (release_gate.load_baseline(Path(args.gate_baseline))
                        if args.gate_baseline else None)
            scope = (release_gate.load_scope(Path(args.gate_scope))
                     if args.gate_scope else None)
        except (OSError, ValueError) as exc:
            # Rule 4. An unreadable policy is "could not assess", never "pass":
            # a typo in a config file must not quietly disarm the gate.
            print(f"\n[GATE] Cannot assess — {exc}")
            sys.exit(release_gate.EXIT_CANNOT_ASSESS)

        # Degraded coverage is reported by the scanner as a finding rather than a
        # side channel, so the gate reads the same evidence a human would.
        #
        # THIS USED TO MATCH ONE CHECK ID. It looked for ABAP-LEX-001 and nothing
        # else, which armed the gate for a mis-lexed file and left it disarmed for
        # every other way a scan can come back empty — an --abap-src typo, an
        # export carrying only metadata sidecars, files that failed to read. All of
        # those returned zero findings, and zero findings is exit 0. A module that
        # knows it could not look now marks the finding, and the gate reads the
        # mark, so a new coverage check arms the gate the day it is written instead
        # of the day someone remembers to add its id here.
        degraded_findings = [
            f for f in fair_findings
            if (f.get("details") or {}).get("degrades_coverage")]

        # ...AND THE MANIFEST ARMS IT TOO. The per-finding mark catches a module
        # that ran and knew it could not see everything; it cannot catch a module
        # that never ran, because such a module emits nothing — and nothing is
        # what the gate reads as "clean". The rule itself lives in
        # release_gate.coverage_reasons, beside the rule it completes.
        coverage_reasons = release_gate.coverage_reasons(coverage_manifest)

        result = release_gate.evaluate(
            fair_findings,
            policy=policy,
            baseline=baseline,
            scope=scope,
            degraded=bool(degraded_findings) or bool(coverage_reasons),
            degraded_detail=" ".join(
                [str(f.get("description", "")) for f in degraded_findings]
                + coverage_reasons).strip())

        print(release_gate.render(result))
        if args.gate_json:
            Path(args.gate_json).write_text(
                json.dumps(result.as_dict(), indent=2), encoding="utf-8")
            print(f"[*] Gate decision written: {args.gate_json}")
        sys.exit(result.exit_code)


if __name__ == "__main__":
    main()
