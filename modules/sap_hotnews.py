"""
SAP Security Notes / HotNews Auditor
======================================
Flags missing critical SAP Security Notes — the monthly SAP Security Patch Day
fixes rated **HotNews** (Priority 1, CVSS 9.0-10.0) and **High** (Priority 2,
CVSS 7.0-8.9) — by comparing the notes actually implemented on the system
(SNOTE export) against a catalog of high-impact notes released since 2020.

Because the scanner is offline and dependency-free, it ships a **curated catalog
of the most significant / actively-exploited HotNews & High notes** (RECON,
ICMAD, the NetWeaver Visual Composer RCEs, Solution Manager auth bypass, …). It
is NOT an exhaustive list of every note SAP has released — for full coverage,
export the HotNews/High notes relevant to your product versions from the SAP ONE
Support Launchpad / EarlyWatch and drop them in as `sap_security_notes.json`;
the module merges them with the built-in catalog.

Data sources:
  - applied_notes.csv        → SNOTE / SAP Note implementation status export
                               (columns: NOTE / STATUS [/ TITLE / VERSION])
  - sap_security_notes.json  → (optional) additional/updated note catalog to
                               merge, list of objects with the catalog schema below
"""

import re
import json
from pathlib import Path
from typing import Dict, List, Any
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

    # Curated catalog of high-impact SAP HotNews / High Security Notes since 2020.
    # Fields: note, cve, cvss, priority ("HotNews"|"High"), component, released
    # ("YYYY-MM"), exploited (known in-the-wild / CISA KEV), title.
    # Verified against SAP Security Patch Day pages / CVE records / CISA KEV.
    HOTNEWS_CATALOG: List[Dict[str, Any]] = [
        {"note": "2934135", "cve": "CVE-2020-6287", "cvss": 10.0, "priority": "HotNews",
         "component": "NetWeaver AS Java (LM Configuration Wizard)", "released": "2020-07",
         "exploited": True, "title": "RECON — unauthenticated account takeover / full compromise"},
        {"note": "2890213", "cve": "CVE-2020-6207", "cvss": 9.8, "priority": "HotNews",
         "component": "Solution Manager (EEM / diagnostics agent)", "released": "2020-03",
         "exploited": True, "title": "Missing authentication check in SAP Solution Manager"},
        {"note": "3123396", "cve": "CVE-2022-22536", "cvss": 10.0, "priority": "HotNews",
         "component": "NetWeaver ABAP/Java, Web Dispatcher, Content Server (ICM)", "released": "2022-02",
         "exploited": True, "title": "ICMAD — HTTP request smuggling in ICM / Web Dispatcher"},
        {"note": "3594142", "cve": "CVE-2025-31324", "cvss": 10.0, "priority": "HotNews",
         "component": "NetWeaver Visual Composer (Metadata Uploader)", "released": "2025-04",
         "exploited": True, "title": "Unrestricted file upload → RCE in Visual Composer"},
        {"note": "3084487", "cve": "CVE-2021-38163", "cvss": 9.9, "priority": "HotNews",
         "component": "NetWeaver AS Java (Visual Composer 7.0 RT)", "released": "2021-09",
         "exploited": True, "title": "Unrestricted file upload in SAP NetWeaver"},
        {"note": "3245526", "cve": "CVE-2023-25616", "cvss": 9.9, "priority": "HotNews",
         "component": "BusinessObjects BI Platform (CMC)", "released": "2023-03",
         "exploited": False, "title": "Code injection / improper access in BusinessObjects BI"},
        {"note": "3252433", "cve": "CVE-2023-23857", "cvss": 9.9, "priority": "HotNews",
         "component": "NetWeaver AS Java (P4 / open naming & directory API)", "released": "2023-03",
         "exploited": False, "title": "Improper access control (missing authentication check)"},
        {"note": "3411067", "cve": "CVE-2023-49583", "cvss": 9.1, "priority": "HotNews",
         "component": "BTP Security Services (@sap/xssec)", "released": "2024-01",
         "exploited": False, "title": "Privilege escalation via SAP BTP security-services library"},
        {"note": "3420923", "cve": "CVE-2024-22131", "cvss": 9.1, "priority": "HotNews",
         "component": "ABAP Platform (SAP ABA)", "released": "2024-02",
         "exploited": False, "title": "Code injection in SAP Application Basis (ABA)"},
        {"note": "3448171", "cve": "CVE-2024-33006", "cvss": 9.6, "priority": "HotNews",
         "component": "NetWeaver AS ABAP (file upload)", "released": "2024-05",
         "exploited": False, "title": "Unrestricted file upload in SAP NetWeaver ABAP"},
        {"note": "3123427", "cve": "CVE-2022-22532 / CVE-2022-22533", "cvss": 8.1, "priority": "High",
         "component": "NetWeaver AS Java (Memory Pipe / MPI, ICMAD)", "released": "2022-02",
         "exploited": False, "title": "ICMAD HTTP smuggling / MPI exhaustion in AS Java"},
    ]

    def run_all_checks(self) -> List[Dict[str, Any]]:
        catalog = self._build_catalog()
        applied, partial = self._applied_sets()
        has_applied = self.data.get("applied_notes") is not None

        if not has_applied:
            self._report_no_data(catalog)
            return self.findings

        # A note counts as "present" if it is fully addressed OR partially
        # implemented; partials are surfaced separately (they are not effective).
        present = applied | partial
        self._report_missing(catalog, present, "HotNews", "HANDLED_HOTNEWS")
        self._report_missing(catalog, present, "High", "HANDLED_HIGH")
        # Exploited check uses fully-addressed only: a partial (incomplete) fix
        # of an actively-exploited note does NOT close it, so it must still raise
        # the CRITICAL exploited finding (not be hidden behind the HIGH partial one).
        self._report_exploited(catalog, applied)
        self._report_partial(catalog, partial)
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
            catalog[note] = entry
        return list(catalog.values())

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
                remediation=(
                    "Implement the listed SAP Security Notes via SNOTE (or the "
                    "correcting Support Package) after change control and testing. "
                    "Prioritise notes flagged as actively exploited. Verify the fix and "
                    "any manual post-implementation steps in each note."
                ),
                references=[
                    "SAP Security Patch Day — https://support.sap.com/en/my-support/knowledge-base/security-notes-news.html",
                    "SAP Note 2934135 (RECON), 3123396 (ICMAD)",
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
            remediation=(
                "Treat as an emergency patch: implement the correcting SAP Notes now, "
                "and check for indicators of compromise (RECON: unexpected admin users / "
                "LM Config Wizard access; ICMAD: anomalous ICM responses; Visual Composer "
                "uploads: unexpected files under the metadatauploader/developmentserver paths)."
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
            remediation=(
                "Re-process these notes in SNOTE to 'Completely Implemented', completing "
                "all manual and automatic activities, then confirm."
            ),
            references=["SAP Note Implementation (SNOTE) — Best Practices"],
            details={"partial_notes": [e["note"] for e in hits]},
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
            remediation=(
                "Export note implementation status (transaction SNOTE, or the SAP "
                "EarlyWatch Alert / System Recommendations in Solution Manager / Cloud "
                "ALM) as applied_notes.csv and re-run so the scanner can diff automatically."
            ),
            references=["SAP System Recommendations (Solution Manager / Cloud ALM)"],
            details={"catalog_hotnews": [e["note"] for e in crit]},
        )
