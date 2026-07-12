"""
Compliance / Control-Framework Mapping
======================================
Maps the scanner's technical findings onto the control frameworks an SAP RISE
landscape is typically audited against — ISO/IEC 27001:2022, NIST CSF 2.0,
CIS Controls v8, TISAX (VDA ISA), SOC 2 (Trust Services Criteria) and GDPR.

This is a *gap-mapping*, not a certification: each finding is attributed to the
control areas it is evidence against, so an auditor can navigate the technical
results by framework. A control that shows findings has open gaps; the absence
of findings is NOT an assertion of full compliance with that control.

Design: every finding CATEGORY maps to one or more canonical security THEMES
(access-control, cryptography, logging, …); each framework then declares which
of its controls each theme corresponds to. This keeps the mapping small,
consistent and independently verifiable (category->theme once, theme->control
once per framework) instead of hand-mapping every category to every framework.
"""
from collections import Counter
from typing import Dict, List, Any


class ComplianceMapper:

    # ── Canonical security themes (stable internal keys → display label) ──────
    THEME_LABELS = {
        "access-control": "Access control",
        "privileged-access": "Privileged access",
        "authentication": "Authentication & credentials",
        "sod": "Segregation of duties",
        "cryptography": "Cryptography & encryption",
        "data-protection": "Data protection & privacy",
        "logging-monitoring": "Logging & monitoring",
        "vuln-mgmt": "Vulnerability & patch management",
        "secure-config": "Secure configuration / hardening",
        "network-security": "Network & communications security",
        "change-management": "Change & transport management",
        "backup-recovery": "Backup & recoverability",
        "app-security": "Application & interface security",
        "incident-response": "Incident response",
        "supplier-cloud": "Cloud / supplier (shared responsibility)",
    }

    # ── Finding CATEGORY → security themes ────────────────────────────────────
    CATEGORY_THEMES = {
        "BTP Cloud Attack Surface": ["access-control", "authentication", "network-security",
                                     "supplier-cloud", "secure-config"],
        "Network & Integration Layer": ["network-security", "app-security", "access-control"],
        "Code & Transport Security": ["app-security", "change-management", "secure-config"],
        "Data Protection & Privacy": ["data-protection", "logging-monitoring"],
        "HANA Database Security": ["privileged-access", "access-control", "secure-config",
                                   "cryptography", "logging-monitoring", "backup-recovery"],
        "Identity & Access Management": ["access-control", "privileged-access", "sod",
                                         "authentication"],
        "ABAP Authorization & Critical Access": ["access-control", "privileged-access", "sod"],
        "Cryptographic Posture": ["cryptography", "network-security", "data-protection"],
        "GRC Access Control": ["sod", "access-control", "privileged-access"],
        "System Trust & Standard Users": ["access-control", "authentication",
                                          "network-security", "privileged-access"],
        "Security Baseline Parameters": ["secure-config", "authentication", "network-security"],
        "Basis Jobs & OS Commands": ["privileged-access", "secure-config", "app-security"],
        "Logging, Monitoring & IR": ["logging-monitoring", "incident-response"],
        "User & Authorization": ["access-control", "authentication", "privileged-access"],
        "RISE / BTP Security": ["supplier-cloud", "access-control", "network-security"],
        "S/4HANA & Cloud Authorization": ["access-control", "privileged-access", "sod",
                                          "app-security"],
        "Password Policy": ["authentication"],
        "Fiori & UI Layer": ["app-security", "access-control"],
        "Access Risk Analysis (SoD)": ["sod", "access-control"],
        "Financial Controls (SOX)": ["sod", "change-management", "access-control"],
        "Login Security": ["authentication", "access-control"],
        "SAP Security Notes (HotNews)": ["vuln-mgmt"],
        "RFC Security": ["network-security", "access-control"],
        "Network & Service Exposure": ["network-security", "secure-config"],
        "Audit Logging": ["logging-monitoring"],
        "Role Design & Governance": ["access-control", "sod", "change-management"],
        "Gateway Security": ["network-security", "secure-config"],
        "Transport Security": ["change-management", "app-security"],
        "Development Controls": ["change-management", "app-security"],
        "Security Parameters": ["secure-config"],
    }

    # ── Frameworks: theme → [(control-id, control-name)] ──────────────────────
    # Control identifiers verified against the published catalogues (see module
    # tests / review). TISAX is mapped at the VDA ISA chapter level.
    FRAMEWORKS = [
        {
            "id": "iso27001", "name": "ISO/IEC 27001:2022", "subtitle": "Annex A controls",
            "themes": {
                "access-control": [("A.5.15", "Access control"), ("A.5.18", "Access rights")],
                "privileged-access": [("A.8.2", "Privileged access rights")],
                "authentication": [("A.5.17", "Authentication information"),
                                   ("A.8.5", "Secure authentication")],
                "sod": [("A.5.3", "Segregation of duties")],
                "cryptography": [("A.8.24", "Use of cryptography")],
                "data-protection": [("A.5.34", "Privacy and protection of PII"),
                                    ("A.8.11", "Data masking")],
                "logging-monitoring": [("A.8.15", "Logging"), ("A.8.16", "Monitoring activities")],
                "vuln-mgmt": [("A.8.8", "Management of technical vulnerabilities")],
                "secure-config": [("A.8.9", "Configuration management")],
                "network-security": [("A.8.20", "Networks security"),
                                     ("A.8.21", "Security of network services")],
                "change-management": [("A.8.32", "Change management"),
                                      ("A.8.31", "Separation of development, test and production environments")],
                "backup-recovery": [("A.8.13", "Information backup")],
                "app-security": [("A.8.28", "Secure coding"),
                                 ("A.8.25", "Secure development life cycle")],
                "incident-response": [("A.5.26", "Response to information security incidents")],
                "supplier-cloud": [("A.5.23", "Information security for use of cloud services"),
                                   ("A.5.19", "Information security in supplier relationships")],
            },
        },
        {
            "id": "nistcsf", "name": "NIST CSF 2.0", "subtitle": "Function.Category",
            "themes": {
                "access-control": [("PR.AA", "Identity Management, Authentication & Access Control")],
                "privileged-access": [("PR.AA", "Identity Management, Authentication & Access Control")],
                "authentication": [("PR.AA", "Identity Management, Authentication & Access Control")],
                "sod": [("GV.RR", "Roles, Responsibilities, and Authorities"),
                        ("PR.AA", "Identity Management, Authentication & Access Control")],
                "cryptography": [("PR.DS", "Data Security")],
                "data-protection": [("PR.DS", "Data Security")],
                "logging-monitoring": [("DE.CM", "Continuous Monitoring"),
                                       ("DE.AE", "Adverse Event Analysis")],
                "vuln-mgmt": [("ID.RA", "Risk Assessment"), ("PR.PS", "Platform Security")],
                "secure-config": [("PR.PS", "Platform Security")],
                "network-security": [("PR.IR", "Technology Infrastructure Resilience")],
                "change-management": [("PR.PS", "Platform Security")],
                "backup-recovery": [("RC.RP", "Incident Recovery Plan Execution"),
                                    ("PR.DS", "Data Security")],
                "app-security": [("PR.PS", "Platform Security")],
                "incident-response": [("RS.MA", "Incident Management"),
                                      ("RS.AN", "Incident Analysis")],
                "supplier-cloud": [("GV.SC", "Cybersecurity Supply Chain Risk Management")],
            },
        },
        {
            "id": "cisv8", "name": "CIS Controls v8", "subtitle": "Critical Security Controls",
            "themes": {
                "access-control": [("CIS 6", "Access Control Management")],
                "privileged-access": [("CIS 5", "Account Management"),
                                      ("CIS 6", "Access Control Management")],
                "authentication": [("CIS 6", "Access Control Management")],
                "sod": [("CIS 6", "Access Control Management")],
                "cryptography": [("CIS 3", "Data Protection")],
                "data-protection": [("CIS 3", "Data Protection")],
                "logging-monitoring": [("CIS 8", "Audit Log Management")],
                "vuln-mgmt": [("CIS 7", "Continuous Vulnerability Management")],
                "secure-config": [("CIS 4", "Secure Configuration of Enterprise Assets and Software")],
                "network-security": [("CIS 12", "Network Infrastructure Management"),
                                     ("CIS 13", "Network Monitoring and Defense")],
                "change-management": [("CIS 4", "Secure Configuration of Enterprise Assets and Software")],
                "backup-recovery": [("CIS 11", "Data Recovery")],
                "app-security": [("CIS 16", "Application Software Security")],
                "incident-response": [("CIS 17", "Incident Response Management")],
                "supplier-cloud": [("CIS 15", "Service Provider Management")],
            },
        },
        {
            "id": "tisax", "name": "TISAX / VDA ISA", "subtitle": "Assessment control chapters",
            "themes": {
                "access-control": [("ISA 4", "Identity and Access Management")],
                "privileged-access": [("ISA 4", "Identity and Access Management")],
                "authentication": [("ISA 4", "Identity and Access Management")],
                "sod": [("ISA 4", "Identity and Access Management")],
                "cryptography": [("ISA 5", "IT Security / Cyber Security")],
                "data-protection": [("DP", "Data Protection module (GDPR)")],
                "logging-monitoring": [("ISA 5", "IT Security / Cyber Security")],
                "vuln-mgmt": [("ISA 5", "IT Security / Cyber Security")],
                "secure-config": [("ISA 5", "IT Security / Cyber Security")],
                "network-security": [("ISA 5", "IT Security / Cyber Security")],
                "change-management": [("ISA 5", "IT Security / Cyber Security")],
                "backup-recovery": [("ISA 3", "Physical Security and Business Continuity")],
                "app-security": [("ISA 5", "IT Security / Cyber Security")],
                "incident-response": [("ISA 1", "IS Policies and Organization")],
                "supplier-cloud": [("ISA 6", "Supplier Relationships")],
            },
        },
        {
            "id": "soc2", "name": "SOC 2", "subtitle": "Trust Services Criteria",
            "themes": {
                "access-control": [("CC6", "Logical and Physical Access Controls")],
                "privileged-access": [("CC6", "Logical and Physical Access Controls")],
                "authentication": [("CC6", "Logical and Physical Access Controls")],
                "sod": [("CC5", "Control Activities")],
                "cryptography": [("CC6", "Logical and Physical Access Controls"),
                                 ("C1", "Confidentiality")],
                "data-protection": [("C1", "Confidentiality"), ("P", "Privacy")],
                "logging-monitoring": [("CC7", "System Operations"),
                                       ("CC4", "Monitoring Activities")],
                "vuln-mgmt": [("CC7", "System Operations")],
                "secure-config": [("CC6", "Logical and Physical Access Controls")],
                "network-security": [("CC6", "Logical and Physical Access Controls")],
                "change-management": [("CC8", "Change Management")],
                "backup-recovery": [("A1", "Availability")],
                "app-security": [("CC8", "Change Management")],
                "incident-response": [("CC7", "System Operations")],
                "supplier-cloud": [("CC9", "Risk Mitigation")],
            },
        },
        {
            "id": "gdpr", "name": "EU GDPR", "subtitle": "Data-protection articles",
            "themes": {
                # GDPR only applies to the privacy/security-of-processing themes.
                "data-protection": [("Art. 32", "Security of processing"),
                                    ("Art. 25", "Data protection by design and by default"),
                                    ("Art. 5", "Principles relating to processing of personal data")],
                "access-control": [("Art. 32", "Security of processing")],
                "cryptography": [("Art. 32", "Security of processing")],
            },
        },
    ]

    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    def __init__(self, findings: List[Dict[str, Any]]):
        self.findings = findings or []

    def _themes_for(self, category: str) -> List[str]:
        return self.CATEGORY_THEMES.get(category, [])

    def assess(self) -> List[Dict[str, Any]]:
        """Return a per-framework mapping result (frameworks with ≥1 mapped
        finding, most-impacted first)."""
        themes_per_finding = [self._themes_for(f.get("category", "")) for f in self.findings]

        results = []
        for fw in self.FRAMEWORKS:
            # control-id -> {name, finding-index set, theme set}
            ctrl: Dict[str, Dict[str, Any]] = {}
            for i, themes in enumerate(themes_per_finding):
                for th in themes:
                    for cid, cname in fw["themes"].get(th, []):
                        e = ctrl.setdefault(cid, {"name": cname, "idx": set(), "themes": set()})
                        e["idx"].add(i)
                        e["themes"].add(self.THEME_LABELS.get(th, th))
            controls = []
            for cid, e in ctrl.items():
                sev = Counter(self.findings[i]["severity"] for i in e["idx"])
                controls.append({
                    "id": cid, "name": e["name"],
                    "themes": sorted(e["themes"]),
                    "crit": sev.get("CRITICAL", 0), "high": sev.get("HIGH", 0),
                    "med": sev.get("MEDIUM", 0), "low": sev.get("LOW", 0),
                    "total": len(e["idx"]),
                })
            controls.sort(key=lambda c: (c["crit"], c["high"], c["med"], c["low"], c["total"]),
                          reverse=True)
            mapped_findings = len({i for e in ctrl.values() for i in e["idx"]})
            total_controls = len({cid for lst in fw["themes"].values() for cid, _ in lst})
            results.append({
                "id": fw["id"], "name": fw["name"], "subtitle": fw["subtitle"],
                "controls": controls,
                "controls_flagged": len(controls),
                "total_controls": total_controls,
                "mapped_findings": mapped_findings,
            })
        # frameworks with the most mapped findings first
        results.sort(key=lambda r: r["mapped_findings"], reverse=True)
        return results
