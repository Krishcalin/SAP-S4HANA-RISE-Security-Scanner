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

PROVENANCE, AND ONE CORRECTION THIS CATALOG HAS ALREADY NEEDED.

The original entries were written against SAP Security Patch Day summaries and
CISA KEV. An operator-supplied HotNews reference (2020 – Aug 2026) was then
cross-checked against them, in both directions. It caught a real error here:
this catalog paired note 3084487 with CVE-2021-38163, Visual Composer,
exploited — but 3084487 is CVE-2021-38176, SQL injection in AS ABAP (SQLDBC),
and the Visual Composer upload in CISA KEV is note 3097887, now its own entry.
The exploited-in-the-wild flag had been sitting on the wrong note number. In
the other direction, the reference's numbers for CVE-2023-25616 ("3302162,
approx") and CVE-2023-23857 ("3299357") conflict with this catalog's 3245526 /
3252433, which stand — the reference itself warns that its 2021–2023 numbers
vary between sources.

Reference entries NOT added, and why: note numbers that conflict between
sources or could not be confirmed (CVE-2020-6364, CVE-2023-27500,
CVE-2025-30018, the Build Apps SSRF); out-of-product entries (above); 3413475,
whose CVE-2023-49583 is already represented by 3411067; the Jan-2026 rows,
which carry no note number at all and are therefore undetectable by note
matching; and note 3747367 (CVE-2026-44747, Feb 2026), which post-dates every
source this catalog was verified against — confirm it in the Launchpad and
supply it via `sap_security_notes.json`.

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
        "curated_through": "2025-08",
        "note": "A CURATED SUBSET of high-impact SAP HotNews and High notes, not "
                "the full SAP Security Patch Day history. Absence of a finding "
                "means none of the notes BELOW are missing — it is not a statement "
                "that the estate is fully patched.",
    }

    # Curated catalog of high-impact SAP HotNews / High Security Notes since 2020.
    # Fields: note, cve, cvss, priority ("HotNews"|"High"), component, released
    # ("YYYY-MM"), exploited (known in-the-wild / CISA KEV), title,
    # applies_to ("abap" = assessable from this system's SNOTE export;
    # "java"|"bi"|"btp"|"solman" = adjacent landscape component → HOTNEWS-005),
    # component_prereq (optional ABAP add-on the note requires, checked against
    # the system_component export).
    # Provenance: SAP Security Patch Day summaries + CISA KEV, cross-checked
    # against the operator HotNews reference (2020 – Aug 2026); see docstring.
    HOTNEWS_CATALOG: List[Dict[str, Any]] = [
        {"note": "2890213", "cve": "CVE-2020-6207", "cvss": 10.0, "priority": "HotNews",
         "component": "Solution Manager (EEM / diagnostics agent)", "released": "2020-03",
         "exploited": True, "applies_to": "solman",
         "title": "Missing authentication check in SAP Solution Manager"},
        {"note": "2934135", "cve": "CVE-2020-6287", "cvss": 10.0, "priority": "HotNews",
         "component": "NetWeaver AS Java (LM Configuration Wizard)", "released": "2020-07",
         "exploited": True, "applies_to": "java",
         "title": "RECON — unauthenticated account takeover / full compromise"},
        # 3084487 previously carried CVE-2021-38163 / Visual Composer / exploited.
        # That pairing was wrong — see the docstring correction note.
        {"note": "3084487", "cve": "CVE-2021-38176", "cvss": 9.9, "priority": "HotNews",
         "component": "NetWeaver AS ABAP (SQLDBC library)", "released": "2021-08",
         "exploited": False, "applies_to": "abap",
         "title": "SQL injection in SAP NetWeaver AS ABAP (SQLDBC)"},
        {"note": "3097887", "cve": "CVE-2021-38163", "cvss": 9.9, "priority": "HotNews",
         "component": "NetWeaver AS Java (Visual Composer 7.0 RT)", "released": "2021-09",
         "exploited": True, "applies_to": "java",
         "title": "Unrestricted file upload in SAP NetWeaver (Visual Composer)"},
        # ICMAD hit the ICM inside the ABAP kernel (and Web Dispatcher), so it IS
        # assessable from this system; the AS Java companion 3123427 is not.
        {"note": "3123396", "cve": "CVE-2022-22536", "cvss": 10.0, "priority": "HotNews",
         "component": "NetWeaver ABAP/Java, Web Dispatcher, Content Server (ICM)", "released": "2022-02",
         "exploited": True, "applies_to": "abap",
         "title": "ICMAD — HTTP request smuggling in ICM / Web Dispatcher"},
        {"note": "3123427", "cve": "CVE-2022-22532 / CVE-2022-22533", "cvss": 8.1, "priority": "High",
         "component": "NetWeaver AS Java (Memory Pipe / MPI, ICMAD)", "released": "2022-02",
         "exploited": False, "applies_to": "java",
         "title": "ICMAD HTTP smuggling / MPI exhaustion in AS Java"},
        {"note": "3245526", "cve": "CVE-2023-25616", "cvss": 9.9, "priority": "HotNews",
         "component": "BusinessObjects BI Platform (CMC)", "released": "2023-03",
         "exploited": False, "applies_to": "bi",
         "title": "Code injection / improper access in BusinessObjects BI"},
        {"note": "3252433", "cve": "CVE-2023-23857", "cvss": 9.9, "priority": "HotNews",
         "component": "NetWeaver AS Java (P4 / open naming & directory API)", "released": "2023-03",
         "exploited": False, "applies_to": "java",
         "title": "Improper access control (missing authentication check)"},
        {"note": "3288480", "cve": "CVE-2023-27269", "cvss": 9.6, "priority": "HotNews",
         "component": "NetWeaver AS ABAP / ABAP Platform", "released": "2023-03",
         "exploited": False, "applies_to": "abap",
         "title": "Directory traversal in SAP NetWeaver AS for ABAP"},
        # Ships as a CommonCryptoLib / kernel patch, not an SNOTE correction
        # instruction — one reason the export guide steers the applied-notes
        # export toward System Recommendations, which tracks kernel-level notes.
        {"note": "3340576", "cve": "CVE-2023-40309", "cvss": 9.8, "priority": "HotNews",
         "component": "CommonCryptoLib (ABAP kernel, HANA, Web Dispatcher)", "released": "2023-09",
         "exploited": False, "applies_to": "abap",
         "title": "Missing authorization check in CommonCryptoLib"},
        {"note": "3320355", "cve": "CVE-2023-40622", "cvss": 9.9, "priority": "HotNews",
         "component": "BusinessObjects BI Platform (Promotion Management)", "released": "2023-09",
         "exploited": False, "applies_to": "bi",
         "title": "Information disclosure enabling full compromise in BI Promotion Management"},
        {"note": "3411067", "cve": "CVE-2023-49583", "cvss": 9.1, "priority": "HotNews",
         "component": "BTP Security Services (@sap/xssec)", "released": "2024-01",
         "exploited": False, "applies_to": "btp",
         "title": "Privilege escalation via SAP BTP security-services library"},
        {"note": "3420923", "cve": "CVE-2024-22131", "cvss": 9.1, "priority": "HotNews",
         "component": "ABAP Platform (SAP ABA)", "released": "2024-02",
         "exploited": False, "applies_to": "abap",
         "title": "Code injection in SAP Application Basis (ABA)"},
        {"note": "3448171", "cve": "CVE-2024-33006", "cvss": 9.6, "priority": "HotNews",
         "component": "NetWeaver AS ABAP (file upload)", "released": "2024-05",
         "exploited": False, "applies_to": "abap",
         "title": "Unrestricted file upload in SAP NetWeaver ABAP"},
        {"note": "3479478", "cve": "CVE-2024-41730", "cvss": 9.8, "priority": "HotNews",
         "component": "BusinessObjects BI Platform (REST / SSO)", "released": "2024-08",
         "exploited": False, "applies_to": "bi",
         "title": "Missing authentication check — SSO token theft via REST"},
        {"note": "3594142", "cve": "CVE-2025-31324", "cvss": 10.0, "priority": "HotNews",
         "component": "NetWeaver Visual Composer (Metadata Uploader)", "released": "2025-04",
         "exploited": True, "applies_to": "java",
         "title": "Unrestricted file upload → RCE in Visual Composer"},
        {"note": "3604119", "cve": "CVE-2025-42999", "cvss": 9.1, "priority": "HotNews",
         "component": "NetWeaver Visual Composer (Metadata Uploader)", "released": "2025-05",
         "exploited": True, "applies_to": "java",
         "title": "Insecure deserialization — root cause behind CVE-2025-31324"},
        # The single most relevant entry for this product's audience: code
        # injection in S/4HANA itself, exploited in the wild within weeks.
        {"note": "3627998", "cve": "CVE-2025-42957", "cvss": 9.9, "priority": "HotNews",
         "component": "S/4HANA (remote-enabled RFC function module)", "released": "2025-08",
         "exploited": True, "applies_to": "abap",
         "title": "ABAP code injection in S/4HANA via RFC — full compromise from a low-privileged user"},
        {"note": "3633838", "cve": "CVE-2025-42950", "cvss": 9.9, "priority": "HotNews",
         "component": "Landscape Transformation / SLT (DMIS add-on)", "released": "2025-08",
         "exploited": False, "applies_to": "abap", "component_prereq": "DMIS",
         "title": "ABAP code injection in SAP Landscape Transformation (companion to CVE-2025-42957)"},
    ]

    def run_all_checks(self) -> List[Dict[str, Any]]:
        catalog = self._build_catalog()
        assessable, out_of_scope = self._partition(catalog)
        applied, partial = self._applied_sets()
        has_applied = self.data.get("applied_notes") is not None

        if not has_applied:
            self._report_no_data(catalog)
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
                f"separately), the newest released {through}. It is NOT the full "
                f"SAP Security Patch Day history, and a clean result here means "
                f"none of those {len(catalog)} is missing — not that the estate "
                f"is fully patched. Notes released after {through}, and "
                f"lower-priority notes at any date, were not assessed."),
            affected_items=[f"catalogue of {len(catalog)} notes, curated through {through}"],
            remediation=(
                "Confirm patch status against SAP Support Portal / Maintenance "
                "Planner for the periods this catalogue does not cover, and treat "
                "this check as a floor rather than a clearance."),
            references=["SAP Security Patch Day",
                        "SAP Note 2871952 - Security Patch Day process"],
            details={"catalogue_size": len(catalog),
                     "curated_through": through,
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
