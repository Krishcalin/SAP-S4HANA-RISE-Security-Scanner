# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
Compliance / Control-Framework Mapping
======================================
Maps the scanner's technical findings onto the control frameworks an SAP RISE
landscape is typically audited against — ISO/IEC 27001:2022, NIST CSF 2.0,
NIST SP 800-53 Rev 5, CIS Controls v8, TISAX (VDA ISA), SOC 2 (Trust Services
Criteria), EU GDPR and DORA (Regulation (EU) 2022/2554).

This is a *gap-mapping*, not a certification: each finding is attributed to the
control areas it is evidence against, so an auditor can navigate the technical
results by framework. A control that shows findings has open gaps; the absence
of findings is NOT an assertion of full compliance with that control.

Design: every finding CATEGORY maps to one or more canonical security THEMES
(access-control, cryptography, logging, …); each framework then declares which
of its controls each theme corresponds to. This keeps the mapping small,
consistent and independently verifiable (category->theme once, theme->control
once per framework) instead of hand-mapping every category to every framework.

────────────────────────────────────────────────────────────────────────────────
WHAT IS AND IS NOT CLAIMED
────────────────────────────────────────────────────────────────────────────────
Breadth here is worth nothing on its own. A control id that a customer's auditor
pulls on and we cannot defend costs more than the gap it was papering over, so
the rule for every entry below is: the control is listed only if it is one this
scanner's findings are genuinely evidence against.

  * ISO/IEC 27001 is mapped against the **2022** Annex A layout (93 controls in
    four themes A.5/A.6/A.7/A.8), not the 2013 114-control layout. A.6 (People)
    and A.7 (Physical) are deliberately absent: nothing this scanner reads out of
    an SAP export is evidence about screening, awareness training or door locks.

  * NIST SP 800-53 Rev 5 is mapped at the base-control level (AC-2, AU-6, …).
    Control ENHANCEMENTS (AC-2(1), …) are not claimed — which enhancements apply
    depends on the system's categorisation and baseline, which is the customer's
    determination and not something an export tells us. The Rev 5 privacy family
    (PT-*) is also not claimed: our data-protection findings are technical, and
    the PT controls are largely about processing authority and notice, which are
    programme artefacts we never see.

  * DORA is mapped to named requirement AREAS, NOT to article numbers.
    Article-level citation is deliberately not claimed here. An auditor reading
    "Art. 9(4)(c)" expects the sub-paragraph to say what we imply it says, and a
    theme→article mapping we have not verified line by line would be exactly the
    kind of coverage that collapses under examination. The area names below
    describe DORA's subject matter accurately and can be defended as scoping;
    they are not presented as citations, and the framework's subtitle says so on
    every rendered report.

  * No framework here carries a "% covered" figure, and none should be added.
    We see the findings, not the control environment, so any percentage would be
    a coverage claim about evidence we do not hold.
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
        # SPLIT from a single "app-security" theme, which conflated two different
        # kinds of evidence and over-mapped badly as a result: a dormant Fiori
        # tile was being reported as evidence against "Access to source code" and
        # "Developer Testing and Evaluation". An exposed running application and a
        # sound development process are separate claims, and a single finding is
        # almost never evidence about both.
        "app-runtime": "Application & interface exposure",
        "secure-development": "Secure development lifecycle",
        "incident-response": "Incident response",
        "supplier-cloud": "Cloud / supplier (shared responsibility)",
    }

    # ── Finding CATEGORY → security themes ────────────────────────────────────
    # A category missing from this table maps to NO control in ANY framework, and
    # it fails silently: the findings are still reported, they just vanish from
    # every compliance panel with nothing saying they were dropped. Three
    # categories were in exactly that state ("Advanced IAM", "Change Management",
    # "Security Audit Log Review") and are now mapped.
    # `tests/test_compliance_breadth.py` walks the shipped auditors and fails if a
    # new category is introduced without an entry here.
    CATEGORY_THEMES = {
        "BTP Cloud Attack Surface": ["access-control", "authentication", "network-security",
                                     "supplier-cloud", "secure-config"],
        "Network & Integration Layer": ["network-security", "app-runtime", "access-control"],
        "Code & Transport Security": ["secure-development", "change-management", "secure-config"],
        "Data Protection & Privacy": ["data-protection", "logging-monitoring"],
        "HANA Database Security": ["privileged-access", "access-control", "secure-config",
                                   "cryptography", "logging-monitoring", "backup-recovery"],
        "Identity & Access Management": ["access-control", "privileged-access", "sod",
                                         "authentication"],
        "ABAP Authorization & Critical Access": ["access-control", "privileged-access", "sod"],
        "Cryptographic Posture": ["cryptography"],
        "GRC Access Control": ["sod", "access-control", "privileged-access"],
        "System Trust & Standard Users": ["access-control", "authentication",
                                          "network-security", "privileged-access"],
        "Security Baseline Parameters": ["secure-config", "authentication", "network-security"],
        "Basis Jobs & OS Commands": ["privileged-access", "secure-config"],
        "Logging, Monitoring & IR": ["logging-monitoring", "incident-response"],
        "User & Authorization": ["access-control", "authentication", "privileged-access"],
        "RISE / BTP Security": ["supplier-cloud", "access-control", "network-security"],
        "S/4HANA & Cloud Authorization": ["access-control", "privileged-access", "sod"],
        "Password Policy": ["authentication"],
        "Fiori & UI Layer": ["app-runtime", "access-control"],
        "Access Risk Analysis (SoD)": ["sod", "access-control"],
        "Financial Controls (SOX)": ["sod", "change-management", "access-control"],
        "Login Security": ["authentication", "access-control"],
        "SAP Security Notes (HotNews)": ["vuln-mgmt"],
        "RFC Security": ["network-security", "access-control"],
        "Network & Service Exposure": ["network-security", "secure-config"],
        "Audit Logging": ["logging-monitoring"],
        "Role Design & Governance": ["access-control", "sod", "change-management"],
        "Gateway Security": ["network-security", "secure-config"],
        # TRANSPORT AS IN TLS, NOT AS IN THE CHANGE AND TRANSPORT SYSTEM.
        #
        # The name is a false friend in an SAP context and it mapped as one: the
        # only two checks in this category are `icm/HTTP/redirect_0` and
        # `icm/HTTPS/verify_client`, both Internet Communication Manager
        # settings. They were cited against change-management and
        # secure-development themes — so a weak TLS setting reached an auditor
        # under ISO A.8.28 "Secure coding", A.8.31 "Separation of development,
        # test and production" and A.8.32 "Change management", none of which it
        # is evidence about, while reaching A.8.24 "Use of cryptography" and
        # GDPR Art. 32 not at all.
        #
        # This is the failure mode the note at the head of this file already
        # records once: a mapping that is confidently wrong is worse than one
        # that is absent, because the reader has no reason to check it.
        "Transport Security": ["cryptography", "network-security", "secure-config"],
        "Development Controls": ["change-management", "secure-development"],
        "Security Parameters": ["secure-config"],
        # iam_advanced.py — firefighter/emergency access, role expiry, access
        # reviews, cross-system identity, privilege-escalation paths.
        "Advanced IAM": ["access-control", "privileged-access", "sod", "authentication"],
        # network_services.py — open/unreleased transports and transports whose
        # description indicates a direct debug/replace in production.
        "Change Management": ["change-management"],
        # log_review.py — retrospective review of an exported SM20 window. It is
        # evidence about detection AND about what an investigation would find, so
        # it carries incident-response as well as logging.
        "Security Audit Log Review": ["logging-monitoring", "incident-response"],
        # resilience_posture.py — evidence that backup and recovery controls exist
        # and were exercised. NOT evidence that a restore works; the module is
        # explicit about that, and the themes are chosen to match what it can
        # actually show. This is DORA's backup/response ground and ISO A.8.13 /
        # A.5.30, which is why the category is worth mapping rather than leaving
        # to fall out of the panels.
        "Resilience & Recovery Readiness": ["backup-recovery", "incident-response"],
    }

    # ── Frameworks: theme → [(control-id, control-name)] ──────────────────────
    # Control identifiers verified against the published catalogues. TISAX is
    # mapped at the VDA ISA chapter level.
    #
    # `tests/test_compliance_breadth.py` enforces the SHAPE of every id — that an
    # ISO clause lies inside the 2022 annex, that a NIST id is a real family and a
    # base control, that DORA cites no article — because shape is what a reviewer
    # can actually check mechanically. It cannot check that a control is the RIGHT
    # one for the theme; that stays a judgement, and it is the reason to add
    # controls sparingly. A defensible gap beats indefensible coverage.
    FRAMEWORKS = [
        {
            # ISO/IEC 27001:2022 Annex A — the 93-control, four-theme revision
            # (A.5 Organizational, A.6 People, A.7 Physical, A.8 Technological).
            # A.6 and A.7 are intentionally unmapped: an SAP export is not evidence
            # about people or premises, and claiming those themes would be the sort
            # of breadth that fails on the first auditor question.
            "id": "iso27001", "name": "ISO/IEC 27001:2022", "subtitle": "Annex A controls",
            "themes": {
                "access-control": [("A.5.15", "Access control"), ("A.5.18", "Access rights"),
                                   ("A.5.16", "Identity management"),
                                   ("A.8.3", "Information access restriction")],
                "privileged-access": [("A.8.2", "Privileged access rights"),
                                      ("A.8.18", "Use of privileged utility programs")],
                "authentication": [("A.5.17", "Authentication information"),
                                   ("A.8.5", "Secure authentication"),
                                   ("A.5.16", "Identity management")],
                "sod": [("A.5.3", "Segregation of duties")],
                "cryptography": [("A.8.24", "Use of cryptography")],
                "data-protection": [("A.5.34", "Privacy and protection of PII"),
                                    ("A.8.11", "Data masking"),
                                    ("A.8.10", "Information deletion"),
                                    ("A.8.12", "Data leakage prevention")],
                "logging-monitoring": [("A.8.15", "Logging"), ("A.8.16", "Monitoring activities")],
                # SAP HotNews is threat intelligence the customer is expected to
                # consume and act on, so a missing-Note finding is evidence against
                # A.5.7 as well as against the patching control.
                "vuln-mgmt": [("A.8.8", "Management of technical vulnerabilities"),
                              ("A.5.7", "Threat intelligence")],
                "secure-config": [("A.8.9", "Configuration management")],
                "network-security": [("A.8.20", "Networks security"),
                                     ("A.8.21", "Security of network services"),
                                     ("A.8.22", "Segregation of networks")],
                "change-management": [("A.8.32", "Change management"),
                                      ("A.8.31", "Separation of development, test and production environments"),
                                      ("A.8.19", "Installation of software on operational systems")],
                "backup-recovery": [("A.8.13", "Information backup"),
                                    ("A.5.30", "ICT readiness for business continuity")],
                "secure-development": [("A.8.28", "Secure coding"),
                                       ("A.8.25", "Secure development life cycle"),
                                       ("A.8.29", "Security testing in development and acceptance"),
                                       ("A.8.4", "Access to source code")],
                "app-runtime": [("A.8.26", "Application security requirements")],
                "incident-response": [("A.5.26", "Response to information security incidents"),
                                      ("A.5.24", "Information security incident management planning and preparation"),
                                      ("A.5.25", "Assessment and decision on information security events")],
                "supplier-cloud": [("A.5.23", "Information security for use of cloud services"),
                                   ("A.5.19", "Information security in supplier relationships"),
                                   ("A.5.21", "Managing information security in the ICT supply chain"),
                                   ("A.5.22", "Monitoring, review and change management of supplier services")],
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
                "app-runtime": [("PR.PS", "Platform Security")],
                "incident-response": [("RS.MA", "Incident Management"),
                                      ("RS.AN", "Incident Analysis")],
                "supplier-cloud": [("GV.SC", "Cybersecurity Supply Chain Risk Management")],
            },
        },
        {
            # NIST SP 800-53 Rev 5, BASE controls only.
            #
            # Enhancements (AC-2(1), AU-6(3), …) are not claimed: which ones apply
            # is a function of the system's impact categorisation and selected
            # baseline, which the customer determines and no SAP export reveals.
            # Listing them would turn a defensible technical mapping into a claim
            # about someone else's control selection.
            #
            # The Rev 5 privacy family (PT-*) is likewise not claimed — those
            # controls are about processing authority, purpose and notice, which
            # are programme artefacts, whereas our data-protection findings are
            # about read access, masking and deletion mechanics.
            "id": "nist80053", "name": "NIST SP 800-53 Rev 5", "subtitle": "Base security controls",
            "themes": {
                "access-control": [("AC-2", "Account Management"),
                                   ("AC-3", "Access Enforcement"),
                                   ("AC-6", "Least Privilege")],
                "privileged-access": [("AC-6", "Least Privilege"),
                                      ("AC-2", "Account Management")],
                "authentication": [("IA-2", "Identification and Authentication (Organizational Users)"),
                                   ("IA-5", "Authenticator Management")],
                "sod": [("AC-5", "Separation of Duties"), ("AC-6", "Least Privilege")],
                "cryptography": [("SC-13", "Cryptographic Protection"),
                                 ("SC-8", "Transmission Confidentiality and Integrity"),
                                 ("SC-28", "Protection of Information at Rest")],
                # Deliberately the two technical protection controls, not the PT
                # family — see the note above.
                "data-protection": [("SC-28", "Protection of Information at Rest"),
                                    ("AC-3", "Access Enforcement")],
                "logging-monitoring": [("AU-2", "Event Logging"),
                                       ("AU-6", "Audit Record Review, Analysis, and Reporting"),
                                       ("AU-12", "Audit Record Generation"),
                                       ("AU-9", "Protection of Audit Information"),
                                       ("SI-4", "System Monitoring")],
                "vuln-mgmt": [("RA-5", "Vulnerability Monitoring and Scanning"),
                              ("SI-2", "Flaw Remediation")],
                "secure-config": [("CM-6", "Configuration Settings"),
                                  ("CM-2", "Baseline Configuration"),
                                  ("CM-7", "Least Functionality")],
                "network-security": [("SC-7", "Boundary Protection"),
                                     ("SC-8", "Transmission Confidentiality and Integrity"),
                                     ("AC-17", "Remote Access")],
                "change-management": [("CM-3", "Configuration Change Control"),
                                      ("CM-5", "Access Restrictions for Change")],
                "backup-recovery": [("CP-9", "System Backup"),
                                    ("CP-10", "System Recovery and Reconstitution")],
                # SI-10 sits with the development controls, not the exposure ones:
                # input validation is a property of how the code was written. Under
                # "app-runtime" it was flagged by a dormant-tile inventory finding.
                "secure-development": [("SA-11", "Developer Testing and Evaluation"),
                                       ("SA-15", "Development Process, Standards, and Tools"),
                                       ("SI-10", "Information Input Validation")],
                "incident-response": [("IR-4", "Incident Handling"),
                                      ("IR-6", "Incident Reporting")],
                "supplier-cloud": [("SA-9", "External System Services"),
                                   ("SR-3", "Supply Chain Controls and Processes")],
            },
        },
        {
            # DORA — Regulation (EU) 2022/2554.
            #
            # ARTICLE-LEVEL MAPPING IS DELIBERATELY NOT CLAIMED. The ids below are
            # named requirement AREAS, not citations. A financial-services auditor
            # who sees "Art. 9(4)(c)" against a finding will read the sub-paragraph
            # and expect it to say what we implied; a theme→article table we have
            # not verified clause by clause is precisely the coverage that does not
            # survive that. The subtitle carries the caveat onto every rendered
            # report so the disclaimer travels with the table.
            #
            # Areas are scoped to what an SAP configuration export can evidence.
            # DORA's governance, contractual-register and information-sharing
            # obligations are real and are NOT mapped, because no finding this
            # scanner produces is evidence about them.
            "id": "dora", "name": "DORA (Regulation (EU) 2022/2554)",
            "subtitle": "Requirement areas — article-level mapping not claimed",
            "themes": {
                "access-control": [("ICT protection", "Protection and prevention of ICT risk"),
                                   ("ICT risk mgmt", "ICT risk management framework")],
                "privileged-access": [("ICT protection", "Protection and prevention of ICT risk")],
                "authentication": [("ICT protection", "Protection and prevention of ICT risk")],
                "sod": [("ICT risk mgmt", "ICT risk management framework"),
                        ("ICT protection", "Protection and prevention of ICT risk")],
                "cryptography": [("ICT protection", "Protection and prevention of ICT risk")],
                "data-protection": [("ICT protection", "Protection and prevention of ICT risk")],
                "logging-monitoring": [("ICT detection", "Detection of anomalous activities")],
                # A missing security patch is both a protection gap and a finding
                # a resilience-testing programme exists to surface.
                "vuln-mgmt": [("ICT protection", "Protection and prevention of ICT risk"),
                              ("ICT testing", "Digital operational resilience testing")],
                "secure-config": [("ICT protection", "Protection and prevention of ICT risk")],
                "network-security": [("ICT protection", "Protection and prevention of ICT risk")],
                "change-management": [("ICT risk mgmt", "ICT risk management framework")],
                "backup-recovery": [("ICT backup", "Backup, restoration and recovery"),
                                    ("ICT response", "Response and recovery")],
                "app-runtime": [("ICT protection", "Protection and prevention of ICT risk")],
                "secure-development": [("ICT testing", "Digital operational resilience testing")],
                "incident-response": [("ICT incidents", "ICT-related incident management and reporting"),
                                      ("ICT response", "Response and recovery")],
                # RISE is an ICT third-party arrangement by definition, so every
                # shared-responsibility finding lands here.
                "supplier-cloud": [("ICT third-party", "ICT third-party risk")],
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
                "secure-development": [("CIS 16", "Application Software Security")],
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
                "app-runtime": [("ISA 5", "IT Security / Cyber Security")],
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
                "secure-development": [("CC8", "Change Management")],
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
                # `.get`, not `[...]`. This runs at report time, after the scan
                # has finished, so a KeyError here destroys a completed
                # deliverable over one malformed finding dict. A finding with no
                # severity is then counted in `total` with no severity column
                # ticked — the same behaviour a finding with `severity: None`
                # already had, which is the honest shape: we know it mapped, we
                # do not know how badly.
                sev = Counter(f.get("severity") for f in
                              (self.findings[i] for i in e["idx"]))
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
