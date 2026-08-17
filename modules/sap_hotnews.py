# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
SAP Security Notes / HotNews Auditor
======================================
Flags missing critical SAP Security Notes — the monthly SAP Security Patch Day
fixes rated **HotNews** (Priority 1, CVSS 9.0-10.0) and **High** (Priority 2,
CVSS 7.0-8.9) — by comparing the notes actually implemented on the system
(SNOTE / System Recommendations export) against a curated catalog of
high-impact notes released since 2020.

Because the scanner is offline and dependency-free, it ships a **curated
catalog of the most significant / actively-exploited notes** (RECON, ICMAD,
the Visual Composer chain, the 2025 S/4HANA RFC code injection, …). It is NOT
an exhaustive list of every note SAP has released — for full coverage, export
the HotNews/High notes for your product versions from the SAP ONE Support
Launchpad and drop them in as `sap_security_notes.json`; the module merges
them with the built-in catalog.

WHAT COUNTS AGAINST THIS SYSTEM, AND WHAT CANNOT.

The audited system is an S/4HANA ABAP system — that is where every other
export this product reads comes from. So each entry carries `applies_to`, and
only ABAP-stack entries are counted against the applied-notes list. Notes for
ADJACENT landscape components — AS Java, BusinessObjects, BTP services,
Solution Manager — can be neither confirmed nor denied by this system's SNOTE
export: before this distinction existed, RECON (AS Java) rendered as "missing"
on a pure-ABAP export, a false alarm. Such entries now land in their own
disclosure finding (HOTNEWS-005) with their exploited flags intact, to be
verified on the systems that own them. An entry with `component_prereq` (the
SLT/DMIS note) moves there only when the system_component export POSITIVELY
shows the add-on absent; with no component export supplied the entry stays
counted — the fail-safe direction is a false alarm, never a silent pass.

Products that never sit inside an S/4HANA RISE system boundary are excluded
from the catalog entirely rather than tagged: Business One, Commerce Cloud
(including note 3771065 / CVE-2026-58231, exploited in the wild — a SaaS
product patched by SAP, invisible to any export this scanner reads), and apps
built with SAP Build Apps. The recurring Google Chromium note (2622660, SAP
Business Client) is also excluded: it re-ships almost monthly at CVSS 10.0,
patches a DESKTOP client by MSI rather than by SNOTE, and as a catalog entry
it would be a permanent false "missing" on every scan.

PROVENANCE, AND THE CORRECTION THAT WAS ITSELF WRONG.

Every note-to-CVE binding in this catalogue is now read from the SAP CNA record
in NVD. SAP is a CVE Numbering Authority, so its advisories reach NVD carrying
`sourceIdentifier: cna@sap.com` and a reference to `me.sap.com/notes/<note>` —
that reference is SAP itself binding the note number to the CVE, in public, with
no S-user. Every `exploited` flag is read from the CISA KEV feed, and where the
basis is a vendor report instead, `exploited_basis` says so.

That mattered, because this catalogue got the same pair wrong twice. It first
paired note 3084487 with CVE-2021-38163 (Visual Composer, exploited). An
operator-supplied reference said that was wrong, so it was "corrected": 3084487
was rewritten as CVE-2021-38176 / SQLDBC and the Visual Composer entry moved to
3097887. The SAP CNA records say the original was right about 3084487 and the
correction introduced two new errors:

    CVE-2021-38163 -> note 3084487   Visual Composer 7.0 RT, CISA KEV 2022-06-09
    CVE-2021-38176 -> note 3089831   NZDT function modules (never 3084487)
    CVE-2021-38178 -> note 3097887   AS ABAP software logistics, CVSS 8.8

The cost was not cosmetic. Note 3097887 is an ABAP note; the correction tagged it
`java`, which routes it to the adjacent-systems disclosure — so a HotNews-class
ABAP note could never be reported as missing from an ABAP export, whatever the
customer had or had not applied. A wrong `applies_to` does not produce a wrong
finding; it produces no finding, which is worse.

The general lesson, recorded because it has now applied twice: a secondary
summary is not evidence about a note number, in either direction. Neither is this
module's own history. The CNA record is, and it is free.

Two earlier judgements are also revised by it. CVE-2023-27500 was recorded as
"could not be confirmed" and left out; NVD binds it to note 3302162 and it is now
in. Note 3747367 was left out as post-dating every source, with a standing
instruction to confirm it in the Launchpad; it needed no such thing.

Products that never sit inside an S/4HANA RISE system boundary are still excluded
from the catalog entirely rather than tagged: Business One, Commerce Cloud SaaS,
and apps built with SAP Build Apps. The recurring Google Chromium note (2622660,
SAP Business Client) is also excluded: it re-ships almost monthly at CVSS 10.0,
patches a DESKTOP client by MSI rather than by SNOTE, and as a catalog entry it
would be a permanent false "missing" on every scan.

Data sources:
  - applied_notes.csv        → SNOTE / System Recommendations implementation
                               status export (columns: NOTE / STATUS [/ TITLE])
  - sap_security_notes.json  → (optional) catalog extension to merge — the
                               documented route for notes newer than the
                               built-in cut-off
  - system_component.csv     → (optional) CVERS component list, used only to
                               resolve `component_prereq` entries
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from modules.base_auditor import BaseAuditor


class SapHotNewsAuditor(BaseAuditor):

    CATEGORY = "SAP Security Notes (HotNews)"

    # SNOTE implementation states that mean a note is addressed on this system.
    ADDRESSED_STATUSES = {
        "completely implemented", "fully implemented", "implemented",
        "obsolete", "not relevant", "cannot be implemented",
        "cannot be implemented (obsolete)", "e0007", "e0013",
    }
    # States that mean a note is only partially / not effectively applied
    # (present, but the vulnerability is not fully closed → HOTNEWS-004).
    PARTIAL_STATUSES = {
        "incompletely implemented", "partially implemented",
    }
    # States that mean the note is known/downloaded but NOT applied → fail-safe:
    # treat as missing rather than silently assuming it is patched.
    NOT_APPLIED_STATUSES = {
        "can be implemented", "undefined implementation state", "new", "downloaded",
    }

    #: What this catalogue is, so the report can say it rather than imply
    #: completeness. The discipline is borrowed from data/ecs_hardening_3250501.json,
    #: which carries version/released/obtained — it existed in the repository and
    #: was simply not applied here.
    CATALOG_META = {
        # Advanced from 2025-08 when the catalogue was swept against a
        # 2020–Aug 2026 vulnerability-intelligence review, every entry of which
        # was then verified against the SAP CNA record in NVD. The date is what
        # the sweep covered; the SUBSET note below is what it selected within it,
        # and the two are different claims that must both be stated.
        "curated_through": "2026-08",
        "note": "A CURATED SUBSET of high-impact SAP HotNews and High notes, not "
                "the full SAP Security Patch Day history. The date range is swept "
                "to the month below; within it the selection is by impact — "
                "HotNews, actively-exploited, and High notes that reach an "
                "ECC/S4 landscape. Absence of a finding means none of the notes "
                "BELOW is missing — it is not a statement that the estate is "
                "fully patched.",
    }

    # Curated catalog of high-impact SAP HotNews / High Security Notes since 2020.
    # Fields: note, cve, cvss, priority ("HotNews"|"High"), component, released
    # ("YYYY-MM"), exploited (known in-the-wild), exploited_basis (WHICH kind of
    # evidence — "cisa-kev <date>" or "vendor-reported ..."; a KEV listing with a
    # remediation due date and a vendor saying it has seen exploitation are not
    # the same claim and the report should not present them as one), title,
    # applies_to ("abap" = assessable from this system's SNOTE export;
    # "java"|"bi"|"btp"|"solman" = adjacent landscape component → HOTNEWS-005),
    # component_prereq (optional ABAP add-on the note requires, checked against
    # the system_component export).
    # Provenance: SAP Security Patch Day summaries + CISA KEV, cross-checked
    # against the operator HotNews reference (2020 – Aug 2026); see docstring.
    HOTNEWS_CATALOG: List[Dict[str, Any]] = [
        {"note": "2890213", "cve": "CVE-2020-6207", "cvss": 10.0, "priority": "HotNews",
         "component": "Solution Manager (EEM / diagnostics agent)", "released": "2020-03",
         "exploited": True, "exploited_basis": "cisa-kev 2021-11-03", "applies_to": "solman",
         "title": "Missing authentication check in SAP Solution Manager"},
        {"note": "2934135", "cve": "CVE-2020-6287", "cvss": 10.0, "priority": "HotNews",
         "component": "NetWeaver AS Java (LM Configuration Wizard)", "released": "2020-07",
         "exploited": True, "exploited_basis": "cisa-kev 2021-11-03", "applies_to": "java",
         "title": "RECON — unauthenticated account takeover / full compromise"},
        # ── The 2021 pair this catalogue had BACKWARDS ──────────────────────
        # A previous correction moved the Visual Composer / KEV entry from note
        # 3084487 to 3097887 and rewrote 3084487 as CVE-2021-38176 "SQLDBC".
        # Every part of that is wrong, per the SAP CNA records in NVD:
        #   CVE-2021-38163 -> note 3084487 (Visual Composer 7.0 RT, KEV)
        #   CVE-2021-38176 -> note 3089831 (NZDT function modules)
        #   CVE-2021-38178 -> note 3097887 (AS ABAP software logistics)
        # The cost was not cosmetic. 3097887 is an ABAP note and was tagged
        # `java`, so it routed to the adjacent-systems disclosure and could never
        # be reported as missing from an ABAP export — a real HotNews-class note
        # this scanner structurally could not raise.
        {"note": "3084487", "cve": "CVE-2021-38163", "cvss": 9.9, "priority": "HotNews",
         "component": "NetWeaver (Visual Composer 7.0 RT) 7.30–7.50", "released": "2021-09",
         "exploited": True, "exploited_basis": "cisa-kev 2022-06-09", "applies_to": "java",
         "title": "Unrestricted file upload in Visual Composer 7.0 RT — RCE by a non-admin user"},
        {"note": "3089831", "cve": "CVE-2021-38176", "cvss": 8.8, "priority": "High",
         "component": "NetWeaver AS ABAP (NZDT near-zero-downtime function modules)",
         "released": "2021-09", "exploited": False, "applies_to": "abap",
         "title": "SQL injection via remotely callable NZDT function modules"},
        {"note": "3097887", "cve": "CVE-2021-38178", "cvss": 8.8, "priority": "High",
         "component": "NetWeaver AS ABAP / ABAP Platform 700–756 (software logistics)",
         "released": "2021-10", "exploited": False, "applies_to": "abap",
         "title": "Malicious ABAP code transfer through the software logistics system"},
        {"note": "3123396", "cve": "CVE-2022-22536", "cvss": 10.0, "priority": "HotNews",
         "component": "NetWeaver ABAP/Java, Web Dispatcher, Content Server (ICM)", "released": "2022-02",
         "exploited": True, "exploited_basis": "cisa-kev 2022-08-18", "applies_to": "abap",
         "title": "ICMAD — HTTP request smuggling in ICM / Web Dispatcher"},
        {"note": "3123427", "cve": "CVE-2022-22532 / CVE-2022-22533", "cvss": 8.1, "priority": "High",
         "component": "NetWeaver AS Java (Memory Pipe / MPI, ICMAD)", "released": "2022-02",
         "exploited": False, "applies_to": "java",
         "title": "ICMAD HTTP smuggling / MPI exhaustion in AS Java"},
        {"note": "3239152", "cve": "CVE-2022-41204", "cvss": 8.8, "priority": "High",
         "component": "SAP Commerce 1905–2205 (login page)", "released": "2022-10",
         "exploited": False, "applies_to": "commerce",
         "title": "URL manipulation on the Commerce login page — credential redirection"},
        {"note": "3242933", "cve": "CVE-2022-39802", "cvss": 7.5, "priority": "High",
         "component": "SAP Manufacturing Execution 15.1–15.3", "released": "2022-10",
         "exploited": False, "applies_to": "me",
         "title": "Path traversal through an unvalidated file-path request parameter"},
        {"note": "3245526", "cve": "CVE-2023-25616", "cvss": 9.9, "priority": "HotNews",
         "component": "BusinessObjects BI Platform (CMC)", "released": "2023-03",
         "exploited": False, "applies_to": "bi",
         "title": "Code injection in the BI Platform Central Management Console"},
        {"note": "3252433", "cve": "CVE-2023-23857", "cvss": 9.9, "priority": "HotNews",
         "component": "NetWeaver AS Java (P4 / open naming & directory API)", "released": "2023-02",
         "exploited": False, "applies_to": "java",
         "title": "Improper access control over the P4 protocol"},
        {"note": "3283438", "cve": "CVE-2023-25617", "cvss": 9.0, "priority": "HotNews",
         "component": "BusinessObjects (Adaptive Job Server) 420, 430", "released": "2023-03",
         "exploited": False, "applies_to": "bi",
         "title": "Remote OS command execution where program-object execution is enabled"},
        {"note": "3288480", "cve": "CVE-2023-27269", "cvss": 9.6, "priority": "HotNews",
         "component": "NetWeaver AS ABAP / ABAP Platform", "released": "2023-03",
         "exploited": False, "applies_to": "abap",
         "title": "Directory traversal allowing overwrite of system files"},
        {"note": "3302162", "cve": "CVE-2023-27500", "cvss": 9.6, "priority": "HotNews",
         "component": "NetWeaver AS ABAP / ABAP Platform (program SAPRSBRO)", "released": "2023-03",
         "exploited": False, "applies_to": "abap",
         "title": "Directory traversal in SAPRSBRO — overwrite system files from a non-admin user"},
        {"note": "3320355", "cve": "CVE-2023-40622", "cvss": 9.9, "priority": "HotNews",
         "component": "BusinessObjects BI Platform (Promotion Management)", "released": "2023-09",
         "exploited": False, "applies_to": "bi",
         "title": "Information disclosure in BI Promotion Management"},
        # Ships as a CommonCryptoLib / kernel patch, not an SNOTE correction, so a
        # pure SNOTE export may never show it. Kept assessable deliberately: the
        # fail-safe direction is to push the operator toward System
        # Recommendations, which tracks kernel-level notes.
        {"note": "3340576", "cve": "CVE-2023-40309", "cvss": 9.8, "priority": "HotNews",
         "component": "CommonCryptoLib (ABAP kernel, HANA, Web Dispatcher)", "released": "2023-09",
         "exploited": False, "applies_to": "abap",
         "title": "Missing authorization check in CommonCryptoLib"},
        {"note": "3411067", "cve": "CVE-2023-49583", "cvss": 9.1, "priority": "HotNews",
         "component": "BTP Security Services (@sap/xssec)", "released": "2023-12",
         "exploited": False, "applies_to": "btp",
         "title": "Privilege escalation in the @sap/xssec security library"},
        {"note": "3420923", "cve": "CVE-2024-22131", "cvss": 9.1, "priority": "HotNews",
         "component": "ABAP Platform (SAP ABA)", "released": "2024-01",
         "exploited": False, "applies_to": "abap",
         "title": "Code injection in the ABAP Platform administration layer"},
        {"note": "3448171", "cve": "CVE-2024-33006", "cvss": 9.6, "priority": "HotNews",
         "component": "NetWeaver AS ABAP (file upload)", "released": "2024-05",
         "exploited": False, "applies_to": "abap",
         "title": "Unrestricted file upload in AS ABAP"},
        {"note": "3469791", "cve": "CVE-2024-54198", "cvss": 8.5, "priority": "High",
         "component": "NetWeaver AS ABAP (RFC to restricted destinations)", "released": "2024-12",
         "exploited": False, "applies_to": "abap",
         "title": "Credential exposure via RFC calls to restricted destinations"},
        {"note": "3479478", "cve": "CVE-2024-41730", "cvss": 9.8, "priority": "HotNews",
         "component": "BusinessObjects BI Platform (REST / SSO)", "released": "2024-08",
         "exploited": False, "applies_to": "bi",
         "title": "Missing authentication — logon token obtainable through a REST endpoint"},
        {"note": "3536965", "cve": "CVE-2024-47578", "cvss": 9.1, "priority": "HotNews",
         "component": "NetWeaver AS Java (Adobe Document Services)", "released": "2024-12",
         "exploited": False, "applies_to": "java",
         "title": "SSRF in Adobe Document Services reaching systems behind the firewall"},
        {"note": "3537476", "cve": "CVE-2025-0070", "cvss": 9.9, "priority": "HotNews",
         "component": "NetWeaver AS ABAP / ABAP Platform", "released": "2025-01",
         "exploited": False, "applies_to": "abap",
         "title": "Improper authentication checks allowing privilege escalation"},
        {"note": "3550708", "cve": "CVE-2025-0066", "cvss": 9.9, "priority": "HotNews",
         "component": "NetWeaver AS ABAP (Internet Communication Framework)", "released": "2025-01",
         "exploited": False, "applies_to": "abap",
         "title": "Weak ICF access controls exposing restricted information"},
        {"note": "3581961", "cve": "CVE-2025-27429", "cvss": 9.9, "priority": "HotNews",
         "component": "S/4HANA Private Cloud / On-Premise (RFC function module)", "released": "2025-04",
         "exploited": False, "applies_to": "abap",
         "title": "ABAP code injection through an RFC-exposed function module"},
        {"note": "3594142", "cve": "CVE-2025-31324", "cvss": 10.0, "priority": "HotNews",
         "component": "NetWeaver Visual Composer (Metadata Uploader)", "released": "2025-04",
         "exploited": True, "exploited_basis": "cisa-kev 2025-04-29", "applies_to": "java",
         "title": "Unauthenticated file upload to the Visual Composer Metadata Uploader"},
        {"note": "3604119", "cve": "CVE-2025-42999", "cvss": 9.1, "priority": "HotNews",
         "component": "NetWeaver Visual Composer (Metadata Uploader)", "released": "2025-05",
         "exploited": True, "exploited_basis": "cisa-kev 2025-05-15", "applies_to": "java",
         "title": "Insecure deserialization in Visual Composer"},
        {"note": "3627998", "cve": "CVE-2025-42957", "cvss": 9.9, "priority": "HotNews",
         "component": "S/4HANA (remote-enabled RFC function module)", "released": "2025-08",
         "exploited": True, "exploited_basis": "vendor-reported (SecurityBridge, not in CISA KEV)",
         "applies_to": "abap",
         "title": "ABAP code injection in S/4HANA via RFC — full compromise from a low-privileged user"},
        {"note": "3633838", "cve": "CVE-2025-42950", "cvss": 9.9, "priority": "HotNews",
         "component": "Landscape Transformation / SLT (DMIS add-on)", "released": "2025-08",
         "exploited": False, "applies_to": "abap", "component_prereq": "DMIS",
         "title": "ABAP code injection in SAP Landscape Transformation (companion to CVE-2025-42957)"},
        {"note": "3634501", "cve": "CVE-2025-42944", "cvss": 10.0, "priority": "HotNews",
         "component": "NetWeaver AS Java (RMI-P4)", "released": "2025-09",
         "exploited": False, "applies_to": "java",
         "title": "Unauthenticated deserialization on the RMI-P4 port"},
        {"note": "3668705", "cve": "CVE-2025-42887", "cvss": 9.9, "priority": "HotNews",
         "component": "SAP Solution Manager (remote-enabled function module)", "released": "2025-11",
         "exploited": False, "applies_to": "solman",
         "title": "Code injection in a Solution Manager RFC function module"},
        {"note": "3685270", "cve": "CVE-2025-42880", "cvss": 9.9, "priority": "HotNews",
         "component": "SAP Solution Manager (remote-enabled function module)", "released": "2025-12",
         "exploited": False, "applies_to": "solman",
         "title": "Code injection in a Solution Manager RFC function module"},
        {"note": "3687749", "cve": "CVE-2026-0501", "cvss": 9.9, "priority": "HotNews",
         "component": "S/4HANA Private Cloud / On-Premise (Financials General Ledger)",
         "released": "2026-01", "exploited": False, "applies_to": "abap",
         "title": "SQL injection in Financials General Ledger — read, modify and delete backend data"},
        {"note": "3694242", "cve": "CVE-2026-0498", "cvss": 9.1, "priority": "HotNews",
         "component": "S/4HANA Private Cloud / On-Premise (RFC function module)",
         "released": "2026-01", "exploited": False, "applies_to": "abap",
         "title": "ABAP code injection through an RFC function module (admin privileges)"},
        {"note": "3674774", "cve": "CVE-2026-0509", "cvss": 9.6, "priority": "HotNews",
         "component": "NetWeaver AS ABAP / ABAP Platform (background RFC)", "released": "2026-02",
         "exploited": False, "applies_to": "abap",
         "title": "Background RFC executable without the required S_RFC authorization"},
        {"note": "3697099", "cve": "CVE-2026-0488", "cvss": 9.9, "priority": "HotNews",
         "component": "SAP CRM and S/4HANA (Scripting Editor)", "released": "2026-02",
         "exploited": False, "applies_to": "abap",
         "title": "Generic function-module call executing unauthorized critical functionality"},
        {"note": "3719353", "cve": "CVE-2026-27681", "cvss": 9.9, "priority": "HotNews",
         "component": "Business Planning and Consolidation / Business Warehouse",
         "released": "2026-04", "exploited": False, "applies_to": "abap",
         "title": "SQL injection in BPC / BW — workaround is to revoke S_GUI activity 60"},
        {"note": "3724838", "cve": "CVE-2026-34260", "cvss": 9.6, "priority": "HotNews",
         "component": "S/4HANA (SAP Enterprise Search for ABAP)", "released": "2026-05",
         "exploited": False, "applies_to": "abap",
         "title": "SQL injection through user-controlled input in Enterprise Search"},
        {"note": "3731908", "cve": "CVE-2026-34256", "cvss": 7.1, "priority": "High",
         "component": "SAP ERP and S/4HANA (Private Cloud and On-Premise)", "released": "2026-04",
         "exploited": False, "applies_to": "abap",
         "title": "Missing authorization check — an ABAP report can overwrite existing objects"},
        {"note": "3746332", "cve": "CVE-2026-44748", "cvss": 9.9, "priority": "HotNews",
         "component": "NetWeaver AS ABAP / ABAP Platform (SAML verifier)", "released": "2026-06",
         "exploited": False, "applies_to": "abap",
         "title": "XML signature wrapping — modified signed documents accepted by the verifier"},
        {"note": "3717897", "cve": "CVE-2026-27671", "cvss": 9.8, "priority": "HotNews",
         "component": "SAP Kernel (AS ABAP RFC protocol validation)", "released": "2026-06",
         "exploited": False, "applies_to": "abap",
         "title": "Unauthenticated crafted RFC request exploiting improper protocol validation"},
        {"note": "3714806", "cve": "CVE-2026-34265", "cvss": 9.8, "priority": "HotNews",
         "component": "NetWeaver AS ABAP (DIAG protocol parsing)", "released": "2026-08",
         "exploited": False, "applies_to": "abap",
         "title": "Unauthenticated memory corruption through DIAG protocol parsing"},
        # ── Beyond the systematic curation cut-off ──────────────────────────
        # Added individually, from SAP's OWN CNA record rather than a summary.
        # NVD CVE-2026-44747 carries sourceIdentifier `cna@sap.com` and
        # references `me.sap.com/notes/3747367` directly, which is what binds the
        # note number to the CVE — the binding this catalogue has been wrong
        # about before, twice, for the 2021 pair above.
        #
        # `exploited` is False because nothing establishes otherwise, NOT because
        # exploitation has been ruled out; CISA KEV was checked (1665 entries, 14
        # SAP) and it is not among them.
        {"note": "3747367", "cve": "CVE-2026-44747", "cvss": 9.9, "priority": "HotNews",
         "component": "NetWeaver AS ABAP (kernel — KRNL64NUC/UC 7.22 through 9.20)",
         "released": "2026-07", "exploited": False, "applies_to": "abap",
         "title": "Memory corruption in SAP NetWeaver AS ABAP — authenticated attacker, "
                  "out-of-bounds write"},
    ]

    def run_all_checks(self) -> List[Dict[str, Any]]:
        catalog = self._build_catalog()
        assessable, out_of_scope = self._partition(catalog)
        applied, partial = self._applied_sets()
        has_applied = self.data.get("applied_notes") is not None

        if not has_applied:
            self._report_no_data(catalog)
            # NOT a return. The exposure checks below read the component export
            # and the CVSS vector, neither of which needs an SNOTE list — and a
            # system whose operator cannot produce one is exactly the system that
            # most needs something said about it. Returning here was the reason
            # this module had one detection route instead of three.
            self._report_exposure(assessable, set(), has_applied=False)
            return self.findings

        # A note counts as "present" if it is fully addressed OR partially
        # implemented; partials are surfaced separately (they are not effective).
        present = applied | partial
        # ALWAYS, BEFORE ANY RESULT. A clean HotNews section is the single most
        # reassuring thing this product prints, and it was being printed off a
        # curated subset whose newest entry predates the report by more than a
        # year — with nothing anywhere saying so. "No missing notes from a list
        # that stops in August 2025" and "you are patched" are different
        # statements, and only the first one is ours to make.
        self._report_catalogue_scope(catalog, assessable, out_of_scope)
        # Only ABAP-assessable entries count as missing: the absence of an AS
        # Java note from this system's SNOTE export is not evidence about the
        # Java system, and alarming on it here was a false positive.
        self._report_missing(assessable, present, "HotNews", "HANDLED_HOTNEWS")
        self._report_missing(assessable, present, "High", "HANDLED_HIGH")
        # Exploited check uses fully-addressed only: a partial (incomplete) fix
        # of an actively-exploited note does NOT close it, so it must still raise
        # the CRITICAL exploited finding (not be hidden behind the HIGH partial one).
        self._report_exploited(assessable, applied)
        self._report_partial(catalog, partial)
        self._report_out_of_scope(out_of_scope, present)
        self._report_exposure(assessable, present, has_applied=True)
        return self.findings

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _norm_note(value: Any) -> str:
        # digits only, without leading zeros — SNOTE/table exports zero-pad note
        # numbers (NUMC "0002934135"); the catalog stores them bare ("2934135").
        return re.sub(r"\D", "", str(value or "")).lstrip("0")

    def _build_catalog(self) -> List[Dict[str, Any]]:
        """Built-in catalog merged with an optional user-supplied JSON catalog."""
        catalog = {self._norm_note(e["note"]): dict(e) for e in self.HOTNEWS_CATALOG}
        extra = self.data.get("sap_security_notes")
        rows = extra if isinstance(extra, list) else (
            extra.get("notes") if isinstance(extra, dict) else None)
        for e in (rows or []):
            if not isinstance(e, dict):
                continue
            note = self._norm_note(e.get("note") or e.get("note_number") or e.get("number"))
            if not note:
                continue
            # Merge into any existing (built-in) entry, overriding only the keys
            # the user actually supplied — so a user file does not silently blank
            # curated fields (e.g. the exploited flag).
            entry = catalog.get(note, {"note": note, "cve": "", "cvss": 0.0,
                     "priority": "", "component": "", "released": "",
                     "exploited": False, "title": ""})
            entry["note"] = note
            if e.get("cve"):
                entry["cve"] = e["cve"]
            if e.get("component"):
                entry["component"] = e["component"]
            if e.get("released") or e.get("date"):
                entry["released"] = e.get("released") or e.get("date")
            if e.get("title") or e.get("description"):
                entry["title"] = e.get("title") or e.get("description")
            if e.get("cvss") not in (None, ""):
                try:
                    entry["cvss"] = float(e["cvss"])
                except (ValueError, TypeError):
                    pass
            if e.get("priority"):
                entry["priority"] = str(e["priority"]).strip()
            elif not entry.get("priority"):
                c = entry.get("cvss") or 0
                entry["priority"] = "HotNews" if c >= 9.0 else "High" if c >= 7.0 else "Medium"
            if "exploited" in e:
                entry["exploited"] = bool(e["exploited"])
            if e.get("applies_to"):
                entry["applies_to"] = str(e["applies_to"]).strip().lower()
            if e.get("component_prereq"):
                entry["component_prereq"] = str(e["component_prereq"]).strip().upper()
            catalog[note] = entry
        return list(catalog.values())

    def _installed_components(self) -> Optional[Set[str]]:
        """Installed ABAP software components (CVERS export), or None if unknown.

        None and empty are deliberately the same answer: an empty component
        export is a broken export, not a system with no components, and treating
        it as knowledge would let `component_prereq` silently drop entries. Only
        a list that actually names components counts as evidence of absence.
        """
        comps: Set[str] = set()
        for row in (self.data.get("system_component") or []):
            if not isinstance(row, dict):
                continue
            c = str(row.get("COMPONENT", row.get("COMPONENT_NAME",
                    row.get("NAME", "")))).strip().upper()
            if c:
                comps.add(c)
        return comps or None

    def _partition(self, catalog: List[Dict[str, Any]]
                   ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Split the catalog into (assessable-here, out-of-scope-here).

        An entry with no `applies_to` at all — i.e. a user-supplied entry that
        did not say — defaults to assessable: the fail-safe direction is a false
        alarm on this system, never a silent pass. An entry the user explicitly
        tagged with another component is a statement that it belongs elsewhere,
        and it moves to the disclosure bucket.
        """
        comps = self._installed_components()
        assessable: List[Dict[str, Any]] = []
        out_of_scope: List[Dict[str, Any]] = []
        for e in catalog:
            scope = str(e.get("applies_to") or "abap").strip().lower()
            if scope != "abap":
                out_of_scope.append(e)
                continue
            prereq = str(e.get("component_prereq") or "").strip().upper()
            if prereq and comps is not None and prereq not in comps:
                out_of_scope.append(dict(
                    e, _scope_reason=f"requires add-on {prereq}, not in the component export"))
                continue
            assessable.append(e)
        return assessable, out_of_scope

    def _applied_sets(self):
        """Return (addressed_note_set, partial_note_set) from applied_notes."""
        addressed, partial = set(), set()
        for row in (self.data.get("applied_notes") or []):
            if not isinstance(row, dict):
                continue
            note = self._norm_note(row.get("NOTE", row.get("SAP_NOTE",
                   row.get("NOTE_NUMBER", row.get("NUMBER", "")))))
            if not note:
                continue
            status = str(row.get("STATUS", row.get("IMPLEMENTATION_STATUS",
                     row.get("PROCESSING_STATUS", "")))).strip().lower()
            if status in self.PARTIAL_STATUSES:
                partial.add(note)
            elif status in self.NOT_APPLIED_STATUSES:
                continue  # known but not applied → leave as missing (fail-safe)
            else:
                # addressed status, blank (present in an applied-notes export), or
                # an unrecognized tracked status → treat as addressed
                addressed.add(note)
        return addressed, partial

    @staticmethod
    def _note_objects(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Structured affected objects for a set of catalog entries: the SAP Notes.

        The note number is the only identifier these findings actually carry, and it is
        never invented — it comes from the built-in catalog or from the SNOTE /
        applied-notes export, already normalized by `_norm_note`.

        The catalog's `component` field is deliberately NOT emitted as a `package`
        object: values like "NetWeaver ABAP/Java, Web Dispatcher, Content Server (ICM)"
        are prose product descriptions, not ABAP package or software-component names,
        so typing them as packages would fabricate an SAP identifier that does not
        exist. The component stays in the display string, where it already was.

        Likewise no `system` object: applied_notes.csv carries no SID, so the system a
        finding belongs to comes from the run-level default rather than an invented name.
        """
        out: List[Dict[str, Any]] = []
        seen = set()
        for e in entries:
            note = str(e.get("note") or "").strip()
            if not note or note in seen:
                continue
            seen.add(note)
            out.append({"type": "sap_note", "name": note})
        return out

    @staticmethod
    def _label(e: Dict[str, Any]) -> str:
        bits = [f"Note {e['note']}"]
        if e.get("cve"):
            bits.append(e["cve"])
        if e.get("component"):
            bits.append(e["component"])
        meta = []
        if e.get("cvss"):
            meta.append(f"CVSS {e['cvss']}")
        if e.get("released"):
            meta.append(e["released"])
        tail = f" ({', '.join(meta)})" if meta else ""
        title = f" — {e['title']}" if e.get("title") else ""
        return f"{' / '.join(bits)}{tail}{title}"

    # -------------------------------------------------------------------- checks
    def _report_catalogue_scope(self, catalog, assessable, out_of_scope):
        """Disclose what the note catalogue is and when it stops.

        Emitted on EVERY run that has note data, whether or not anything is
        missing, and it carries `degrades_coverage` so the release gate treats a
        stale catalogue as a coverage problem rather than a clean bill.
        """
        meta = dict(self.CATALOG_META)
        through = meta.get("curated_through", "unknown")
        hotnews = sum(1 for e in catalog if e.get("priority") == "HotNews")
        high = len(catalog) - hotnews
        # Entries newer than the systematic sweep, added one at a time from a
        # primary source. They must be counted SEPARATELY: a single 2026 note in
        # the catalogue does not make the catalogue current to 2026, and saying
        # "the newest released <date>" would imply a sweep that never happened.
        beyond = sorted(e.get("released", "") for e in catalog
                        if e.get("released", "") > through)
        later = (" Beyond that sweep, %d note(s) have been added individually "
                 "from primary sources (newest %s); they are exceptions, not "
                 "coverage of their release months."
                 % (len(beyond), beyond[-1])) if beyond else ""
        self.finding(
            check_id="HOTNEWS-COVERAGE",
            title="SAP note check ran against a curated subset, not the full patch history",
            severity=self.SEVERITY_INFO,
            category=self.CATEGORY,
            description=(
                f"This check compared the applied notes against {len(catalog)} "
                f"curated entries ({hotnews} HotNews, {high} High; "
                f"{len(assessable)} assessable from this ABAP system's export, "
                f"{len(out_of_scope)} for adjacent landscape components, disclosed "
                f"separately), swept systematically through {through}.{later} It is "
                f"NOT the full SAP Security Patch Day history, and a clean result "
                f"here means none of those {len(catalog)} is missing — not that the "
                f"estate is fully patched. Notes released after {through}, other "
                f"than the individually-added ones above, and lower-priority notes "
                f"at any date, were not assessed."),
            affected_items=[
                "catalogue of %d notes, swept through %s%s"
                % (len(catalog), through,
                   ", plus %d added individually" % len(beyond) if beyond else "")],
            remediation=(
                "Confirm patch status against SAP Support Portal / Maintenance "
                "Planner for the periods this catalogue does not cover, and treat "
                "this check as a floor rather than a clearance."),
            references=["SAP Security Patch Day",
                        "SAP Note 2871952 - Security Patch Day process"],
            details={"catalogue_size": len(catalog),
                     "curated_through": through,
                     "added_beyond_sweep": len(beyond),
                     "hotnews": hotnews, "high": high,
                     "assessable": len(assessable),
                     "adjacent_or_not_applicable": len(out_of_scope),
                     "degrades_coverage": True},
        )

    def _report_missing(self, catalog, applied, priority, _cid):
        missing = [e for e in catalog
                   if e.get("priority") == priority and self._norm_note(e["note"]) not in applied]
        missing.sort(key=lambda e: (-float(e.get("cvss") or 0), e.get("released", "")))
        if not missing:
            return
        if priority == "HotNews":
            self.finding(
                check_id="HOTNEWS-001",
                title="Missing HotNews (Priority 1) SAP Security Notes",
                severity=self.SEVERITY_CRITICAL,
                category=self.CATEGORY,
                description=(
                    f"{len(missing)} HotNews security note(s) (Priority 1, CVSS 9.0-10.0) "
                    "from the catalog are not recorded as implemented on this system. "
                    "HotNews notes fix the most severe SAP vulnerabilities — several here "
                    "are unauthenticated remote-compromise flaws."
                ),
                affected_items=[self._label(e) for e in missing],
                # One finding rolls up every missing HotNews note, so it is an
                # aggregate: implementing one of the six must shrink the list without
                # retiring the finding and re-raising a fresh one with a reset age.
                # The notes still ride along as graph nodes.
                affected_objects=self._note_objects(missing),
                scope="aggregate",
                remediation=(
                    "Implement the listed SAP Security Notes via SNOTE (or the "
                    "correcting Support Package) after change control and testing. "
                    "Prioritise notes flagged as actively exploited. Verify the fix and "
                    "any manual post-implementation steps in each note."
                ),
                references=[
                    "SAP Security Patch Day — https://support.sap.com/en/my-support/knowledge-base/security-notes-news.html",
                    "SAP Note 3627998 (S/4HANA RFC code injection), 3123396 (ICMAD)",
                    "CISA — SAP exploitation advisories",
                ],
                details={"missing_notes": [e["note"] for e in missing]},
            )
        else:
            self.finding(
                check_id="HOTNEWS-002",
                title="Missing High-priority SAP Security Notes",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(missing)} High-priority security note(s) (Priority 2, CVSS "
                    "7.0-8.9) from the catalog are not recorded as implemented."
                ),
                affected_items=[self._label(e) for e in missing],
                # Aggregate for the same reason as HOTNEWS-001 above.
                affected_objects=self._note_objects(missing),
                scope="aggregate",
                remediation=(
                    "Schedule these High-priority notes into the next patch cycle; "
                    "implement via SNOTE / Support Package with testing."
                ),
                references=["SAP Security Patch Day"],
                details={"missing_notes": [e["note"] for e in missing]},
            )

    def _report_exploited(self, catalog, applied):
        exploited = [e for e in catalog
                     if e.get("exploited") and self._norm_note(e["note"]) not in applied]
        exploited.sort(key=lambda e: e.get("released", ""))
        if not exploited:
            return
        self.finding(
            check_id="HOTNEWS-003",
            title="Missing notes for actively-exploited SAP vulnerabilities",
            severity=self.SEVERITY_CRITICAL,
            category=self.CATEGORY,
            description=(
                f"{len(exploited)} unpatched vulnerability(ies) here are known to be "
                "exploited in the wild (public exploits / CISA KEV). These are the "
                "highest-urgency items — attackers actively scan for and weaponise them."
            ),
            affected_items=[self._label(e) for e in exploited],
            # Aggregate: this is the "you are exposed to in-the-wild exploitation"
            # finding, and it stays the same defect while any listed note is unpatched.
            # Patching the ICMAD note must not reset the clock on the S/4HANA one.
            affected_objects=self._note_objects(exploited),
            scope="aggregate",
            remediation=(
                "Treat as an emergency patch: implement the correcting SAP Notes now, "
                "and check for indicators of compromise (ICMAD: anomalous ICM "
                "responses; the S/4HANA RFC code injection CVE-2025-42957: unexpected "
                "administrator users, background jobs, or RFC calls from "
                "low-privileged accounts)."
            ),
            references=[
                "CISA Known Exploited Vulnerabilities Catalog",
                "SAP Security Patch Day",
            ],
            details={"exploited_notes": [e["note"] for e in exploited]},
        )

    def _report_partial(self, catalog, partial):
        by_note = {self._norm_note(e["note"]): e for e in catalog}
        hits = [by_note[n] for n in partial if n in by_note]
        if not hits:
            return
        self.finding(
            check_id="HOTNEWS-004",
            title="Critical SAP Notes only partially implemented",
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=(
                f"{len(hits)} catalog note(s) appear in SNOTE with an incomplete / "
                "not-effective implementation status. A partially implemented note does "
                "not close the vulnerability and can leave the system inconsistent."
            ),
            affected_items=[self._label(e) + " — status: incomplete" for e in hits],
            # Aggregate over every partially-implemented note in the export.
            affected_objects=self._note_objects(hits),
            scope="aggregate",
            remediation=(
                "Re-process these notes in SNOTE to 'Completely Implemented', completing "
                "all manual and automatic activities, then confirm."
            ),
            references=["SAP Note Implementation (SNOTE) — Best Practices"],
            details={"partial_notes": [e["note"] for e in hits]},
        )

    def _report_out_of_scope(self, out_of_scope, present):
        """Catalogue entries this system's export can neither confirm nor deny.

        These are NOT counted as missing — that was a false alarm — but they are
        not dropped either: several fix vulnerabilities exploited in the wild,
        and "not assessable from this export" must never quietly become
        "handled". One INFO finding names them, exploited flags intact, for the
        operator to verify on the systems that own them.
        """
        hits = [e for e in out_of_scope if self._norm_note(e["note"]) not in present]
        hits.sort(key=lambda e: (not e.get("exploited"), -float(e.get("cvss") or 0)))
        if not hits:
            return
        exploited = sum(1 for e in hits if e.get("exploited"))
        items = []
        for e in hits:
            reason = e.get("_scope_reason")
            tag = " [EXPLOITED IN THE WILD — verify urgently]" if e.get("exploited") else ""
            items.append(self._label(e) + (f" ({reason})" if reason else "") + tag)
        self.finding(
            check_id="HOTNEWS-005",
            title="Catalogue notes this system's export can neither confirm nor deny",
            severity=self.SEVERITY_INFO,
            category=self.CATEGORY,
            description=(
                f"{len(hits)} catalogue note(s) target adjacent landscape components "
                "(SAP AS Java, BusinessObjects, BTP services, Solution Manager) or "
                "ABAP add-ons this system does not have installed. An S/4HANA ABAP "
                "note export carries no evidence about them either way, so they are "
                f"not counted in the missing-note findings — but {exploited} of them "
                "fix vulnerabilities exploited in the wild, and 'not assessable "
                "here' must not be read as 'patched'. Verify each on the system "
                "that owns it."
            ),
            affected_items=items,
            # Aggregate: the statement is about the assessability boundary, and it
            # stays the same statement however many entries sit outside it.
            affected_objects=self._note_objects(hits),
            scope="aggregate",
            remediation=(
                "Run the equivalent patch check on the owning systems (AS Java, "
                "BI platform, Solution Manager), or confirm implementation for "
                "those installations in the SAP ONE Support Launchpad, and record "
                "the result alongside this scan."
            ),
            references=[
                "SAP Security Patch Day",
                "CISA Known Exploited Vulnerabilities Catalog",
            ],
            details={"unassessable_notes": [e["note"] for e in hits],
                     "exploited_among_them": exploited},
        )

    # ================================================================
    #  Tier three: exposure, not just patch status
    #
    #  Everything above answers one question — is this note in your
    #  applied-notes export. That is a good question and it is the only one this
    #  module could ask, which meant a customer who cannot produce an SNOTE
    #  export got a list of notes to check by hand and nothing else.
    #
    #  Three more axes are available without that export, and each is read from
    #  a source this scanner already loads and never used for CVEs:
    #
    #    version   the CVERS component release against the affected-version list
    #              NVD carries (data/cve_exposure.json)
    #    vector    the CVSS vector, which states whether an attacker needs
    #              credentials at all — authoritative, present for every entry
    #    workaround  SAP's own documented mitigation, where it is something this
    #              scanner can look for
    #
    #  WHAT THESE DO NOT DO. None of them is a patch check and none may be read
    #  as one. A release outside the affected list is NOT a clearance — see
    #  HOTNEWS-008 — because NVD's affected lists are frequently incomplete and
    #  absence from one is not evidence of anything.
    # ================================================================

    #: Per-note exposure evidence, harvested once from the SAP CNA records in NVD
    #: and shipped. Loaded lazily so a missing or malformed file degrades the
    #: exposure checks rather than the whole module.
    EXPOSURE_PATH = Path(__file__).resolve().parent.parent / "data" / "cve_exposure.json"

    def _exposure_data(self) -> Dict[str, Any]:
        cached = getattr(self, "_exposure_cache", None)
        if cached is not None:
            return cached
        try:
            payload = json.loads(self.EXPOSURE_PATH.read_text(encoding="utf-8"))
            data = payload.get("entries") or {}
        except (OSError, ValueError):
            data = {}
        self._exposure_cache = data
        return data

    def _release_of(self, component: str) -> Optional[str]:
        return self._components().get(component.upper())

    @staticmethod
    def _same_release(a: str, b: str) -> bool:
        """Are these the same SAP release, however each is written?

        `_release_key` is reused rather than string equality because an export
        may write 0755 where the CPE list says 755, and comparing those as
        strings would report an affected system as unaffected.
        """
        ka = SapHotNewsAuditor._release_key(a)
        kb = SapHotNewsAuditor._release_key(b)
        return ka is not None and ka == kb

    def _report_exposure(self, assessable: List[Dict[str, Any]],
                         present: Set[str], has_applied: bool) -> None:
        exposure = self._exposure_data()
        components = self._components()

        confirmed, off_list, unauth = [], [], []
        unassessed: List[str] = []

        for entry in assessable:
            note = self._norm_note(entry["note"])
            row = exposure.get(note) or exposure.get(entry["note"]) or {}
            addressed = note in present
            label = self._label(entry)

            # ── version axis ────────────────────────────────────────────────
            mapped = row.get("affected_by_component") or {}
            if not mapped:
                reason = row.get("version_reason") or "no exposure record for this note"
                unassessed.append("%s — version: %s" % (label, reason))
            elif not components:
                unassessed.append("%s — version: no component export supplied"
                                  % label)
            else:
                verdict = None
                for comp, releases in sorted(mapped.items()):
                    here = components.get(comp)
                    if not here:
                        continue
                    if any(self._same_release(here, r) for r in releases):
                        verdict = ("affected", comp, here)
                        break
                    verdict = verdict or ("outside", comp, here)
                if verdict is None:
                    unassessed.append(
                        "%s — version: none of %s is in the component export"
                        % (label, "/".join(sorted(mapped))))
                elif verdict[0] == "affected" and not addressed:
                    confirmed.append(
                        "%s — %s %s IS in the affected release list"
                        % (label, verdict[1], verdict[2]))
                elif verdict[0] == "outside" and not addressed:
                    off_list.append(
                        "%s — %s %s is not in the list NVD carries"
                        % (label, verdict[1], verdict[2]))

            # ── vector axis ─────────────────────────────────────────────────
            vector = row.get("vector") or ""
            if not addressed and "AV:N" in vector and "PR:N" in vector:
                unauth.append("%s — %s" % (label, vector))

        if confirmed:
            self.finding(
                check_id="HOTNEWS-006",
                title="Installed release is inside the affected range of an unpatched note",
                severity=self.SEVERITY_CRITICAL,
                category=self.CATEGORY,
                description=(
                    "%d note(s) are not recorded as implemented AND this system's "
                    "installed component release appears in the affected-version "
                    "list SAP published with the CVE. This is a stronger statement "
                    "than the missing-note findings above: those say a note is "
                    "absent from an export, while this says the release running "
                    "here is one the vendor named as vulnerable. It needs no SNOTE "
                    "export to be true — the component list alone establishes it, "
                    "which is why it is reported even when patch status is unknown."
                    % len(confirmed)),
                affected_items=confirmed,
                remediation=(
                    "1. Treat these as the top of the patch queue: the affected "
                    "release is confirmed rather than assumed.\n"
                    "2. Apply the SAP Notes listed, or the support package that "
                    "contains them.\n"
                    "3. Where a note cannot be applied immediately, apply the "
                    "workaround SAP publishes in the note text and record it as a "
                    "compensating control with an expiry.\n"
                    "4. Re-export applied_notes.csv and system_component.csv after "
                    "patching and re-run, so the change is evidenced rather than "
                    "asserted."),
                references=["SAP Security Patch Day",
                            "NVD — affected version data from the SAP CNA record"],
                affected_objects=self._note_objects(
                    [e for e in assessable
                     if any(self._label(e) in c for c in confirmed)]),
                details={"confirmed_affected": len(confirmed),
                         "patch_status_known": has_applied},
                scope="aggregate",
            )

        if unauth:
            self.finding(
                check_id="HOTNEWS-007",
                title="Unpatched notes exploitable without any credentials",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    "%d unimplemented note(s) fix vulnerabilities whose CVSS "
                    "vector is AV:N/PR:N — reachable over the network with NO "
                    "privileges of any kind. Every other missing note in this "
                    "report needs the attacker to hold something first: an "
                    "account, a role, a foothold. These need only a route to the "
                    "port. That distinction is what should order the patch queue "
                    "when it cannot all be done at once, and it is taken from the "
                    "vector SAP itself assigned rather than from any judgement "
                    "made here." % len(unauth)),
                affected_items=unauth,
                remediation=(
                    "1. Patch these before any authenticated-only issue of the "
                    "same or higher CVSS.\n"
                    "2. Until patched, reduce reachability: restrict the exposed "
                    "service, port or ICF node to trusted networks, and confirm "
                    "the system is not internet-facing.\n"
                    "3. Check the network-exposure findings elsewhere in this "
                    "report — an unauthenticated flaw on a system reachable from "
                    "the internet is a materially different risk from the same "
                    "flaw behind a gateway ACL.\n"
                    "4. Re-run after patching."),
                references=["NVD — CVSS vector from the SAP CNA record",
                            "SAP Security Patch Day"],
                details={"unauthenticated_unpatched": len(unauth)},
                scope="aggregate",
            )

        if off_list:
            self.finding(
                check_id="HOTNEWS-008",
                title="Installed release is not in the published affected list (verify before deprioritising)",
                severity=self.SEVERITY_INFO,
                category=self.CATEGORY,
                description=(
                    "%d unimplemented note(s) target releases that do not include "
                    "the one installed here. THIS IS NOT A CLEARANCE and must not "
                    "be used as one. NVD's affected-version lists are frequently "
                    "incomplete — a release can be missing because it was not "
                    "enumerated, because it did not exist when the CVE was "
                    "published, or because the record was never revisited — so "
                    "absence from the list is not evidence of anything. It is "
                    "published because a backlog of missing notes is easier to "
                    "work through when the ones least likely to apply are "
                    "identified, and the only safe way to use it is to check each "
                    "one against the note's own validity section." % len(off_list)),
                affected_items=off_list,
                remediation=(
                    "1. Open each note in the SAP Launchpad and read its validity "
                    "and support-package sections, which are authoritative for "
                    "your release in a way the CVE record is not.\n"
                    "2. Where the note genuinely does not apply, record that "
                    "decision with the evidence, so the next scan does not "
                    "re-litigate it.\n"
                    "3. Where it does apply, move it back into the patch queue — "
                    "the absence from a published list was not a reason to "
                    "deprioritise it."),
                references=["NVD — affected version data from the SAP CNA record"],
                details={"release_outside_published_list": len(off_list),
                         "is_not_a_clearance": True},
                scope="aggregate",
            )

        self._report_workaround(assessable, present)
        self._report_exposure_coverage(unassessed, bool(components), has_applied)

    # ── documented workarounds this scanner can actually look for ───────────

    def _report_workaround(self, assessable: List[Dict[str, Any]],
                           present: Set[str]) -> None:
        """Is the mitigation SAP publishes actually in place?

        Only entries carrying a workaround with a NAMED SOURCE are checked. An
        invented mitigation would be worse than none: a customer told their
        exposure is contained stops looking at it.
        """
        exposure = self._exposure_data()
        rows = self.data.get("role_auth_values")
        if not isinstance(rows, list):
            return

        offenders = []
        for entry in assessable:
            note = self._norm_note(entry["note"])
            work = (exposure.get(note) or {}).get("workaround") or {}
            if work.get("kind") != "authorization_absent" or note in present:
                continue
            holders = self._roles_granting(rows, work["object"], work["field"],
                                           work["value"])
            if holders:
                offenders.append(
                    "%s — workaround is to %s, but %d role(s) still grant "
                    "%s %s=%s: %s"
                    % (self._label(entry), work["statement"], len(holders),
                       work["object"], work["field"], work["value"],
                       ", ".join(sorted(holders)[:6])))

        if not offenders:
            return
        self.finding(
            check_id="HOTNEWS-009",
            title="Note not implemented and its published workaround is not in place either",
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=(
                "%d unimplemented note(s) have a documented workaround, and the "
                "authorization the workaround tells you to withdraw is still "
                "granted. This is the worst of the three states a known "
                "vulnerability can be in — not patched, and not mitigated either "
                "— and it is usually not a decision anybody made: the workaround "
                "was applied to some roles, or was applied and later reversed by "
                "a role rebuild. The roles naming it are listed so the gap can be "
                "closed today, without waiting for the patch window."
                % len(offenders)),
            affected_items=offenders,
            remediation=(
                "1. Remove the named authorization from the roles listed, or "
                "restrict its activity values, following the workaround in the "
                "SAP Note.\n"
                "2. Confirm no composite role re-grants it through a child.\n"
                "3. Record the workaround as a time-bound compensating control "
                "with the patch as its exit condition — a workaround with no "
                "expiry becomes permanent and the patch never lands.\n"
                "4. Apply the note itself at the next window and then restore the "
                "authorization if the business genuinely needs it.\n"
                "5. Re-run to confirm both the note and the authorization."),
            references=["SAP Security Patch Day — note text carries the workaround"],
            details={"unmitigated_notes": len(offenders)},
            scope="aggregate",
        )

    @staticmethod
    def _roles_granting(rows: List[Any], obj: str, field: str,
                        value: str) -> Set[str]:
        """Roles granting `value` for one authorization field.

        A range is a grant: LOW=01 HIGH=60 covers 60, and reading only LOW would
        miss most of the roles that actually hold it. `*` covers everything.
        """
        found: Set[str] = set()
        target = str(value).strip().lstrip("0") or "0"
        for row in rows:
            if not isinstance(row, dict):
                continue
            if str(row.get("OBJECT", "")).strip().upper() != obj.upper():
                continue
            if str(row.get("FIELD", "")).strip().upper() != field.upper():
                continue
            low = str(row.get("LOW", "")).strip()
            high = str(row.get("HIGH", "")).strip()
            role = str(row.get("AGR_NAME", "")).strip()
            if not role:
                continue
            if low == "*" or high == "*":
                found.add(role)
                continue
            lo = low.lstrip("0") or "0"
            hi = (high.lstrip("0") or "0") if high else lo
            try:
                if int(lo) <= int(target) <= int(hi):
                    found.add(role)
            except ValueError:
                if target in (lo, hi):
                    found.add(role)
        return found

    def _report_exposure_coverage(self, unassessed: List[str],
                                  have_components: bool,
                                  has_applied: bool) -> None:
        """What the exposure axes could NOT establish, and why.

        Emitted whenever anything was unassessable, because the three checks
        above are silent in exactly two situations that look identical from the
        report — nothing was exposed, and nothing could be examined.
        """
        if not unassessed and have_components:
            return
        items = list(unassessed)
        if not have_components:
            items.insert(0, "no system_component (CVERS) export — no note could be "
                            "assessed against an installed release at all")
        self.finding(
            check_id="HOTNEWS-010",
            title="Exposure could not be established for some notes",
            severity=self.SEVERITY_INFO,
            category=self.CATEGORY,
            description=(
                "%d note(s) could not be assessed against this system's installed "
                "releases. The reasons are individual and are listed: most often "
                "NVD carries no affected-version data for the CVE, or the versions "
                "it carries are kernel patch levels or S/4HANA product versions, "
                "which are on a different scale from a CVERS component release and "
                "cannot be compared against one without producing a confident wrong "
                "answer. Silence from the release checks above therefore means "
                "'not established', never 'not affected'.%s"
                % (len(items),
                   "" if has_applied else
                   " Patch status is also unknown for this system, so the only "
                   "axis that produced anything here was the CVSS vector.")),
            affected_items=items[:60],
            remediation=(
                "1. Supply system_component.csv (the CVERS list) if it is absent — "
                "it is a single SE16 export and it is what turns a missing-note "
                "list into an exposure statement.\n"
                "2. For notes whose affected versions are kernel patch levels, "
                "check the kernel release and patch number in System > Status "
                "against the note; this scanner reads no kernel source.\n"
                "3. For notes with no published version data, the note's own "
                "validity section in the SAP Launchpad is the authority.\n"
                "4. Treat this list as the boundary of the exposure assessment, "
                "not as a set of notes that do not apply."),
            details={"unassessed": len(items),
                     "component_export_supplied": have_components,
                     "degrades_coverage": True},
            scope="aggregate",
        )

    def _report_no_data(self, catalog):
        """No SNOTE export supplied — list the catalog notes to verify manually."""
        crit = [e for e in catalog if e.get("priority") == "HotNews"]
        crit.sort(key=lambda e: (not e.get("exploited"), -float(e.get("cvss") or 0)))
        self.finding(
            check_id="HOTNEWS-000",
            title="SAP Note implementation status not provided",
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=(
                "No SNOTE / applied-notes export (applied_notes.csv) was provided, so the "
                "scanner cannot confirm which critical SAP Security Notes are implemented. "
                f"Manually verify the following {len(crit)} HotNews note(s) are applied."
            ),
            affected_items=[self._label(e) + (" [EXPLOITED]" if e.get("exploited") else "")
                            for e in crit],
            # Aggregate: the defect is the MISSING SNOTE EXPORT, not any one note. The
            # catalog notes listed for manual verification are members — growing the
            # catalog must not re-raise this finding as new.
            affected_objects=self._note_objects(crit),
            scope="aggregate",
            remediation=(
                "Export note implementation status (transaction SNOTE, or the SAP "
                "EarlyWatch Alert / System Recommendations in Solution Manager / Cloud "
                "ALM) as applied_notes.csv and re-run so the scanner can diff automatically."
            ),
            references=["SAP System Recommendations (Solution Manager / Cloud ALM)"],
            details={"catalog_hotnews": [e["note"] for e in crit]},
        )
