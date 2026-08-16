# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
Master Data Change Auditor
==========================
The EVIDENCE twin of the financial-controls CONFIGURATION checks. FIN-SF-001
reports whether vendor/customer bank fields are under dual control; this module
reads the change documents and reports the bank-detail changes that actually
went through — who, when, through which transaction, and what the value was
before and after. Where FIN-SF-001 found no dual control, these are the changes
nobody had to confirm.

SAP writes a change document for master-data changes as two tables: CDHDR (one
header per change: OBJECTCLAS, OBJECTID, CHANGENR, USERNAME, UDATE, TCODE) and
CDPOS (one row per changed field: TABNAME, FNAME, VALUE_OLD, VALUE_NEW,
CHNGIND). Both are core data-dictionary tables, stable across releases, and
verified twice over: SAP's data dictionary and the operator's field reference
agree on every column this module reads. The join runs over CHANGENR; an item
whose header was not exported is still reported, marked "(header not
supplied)" — the change is real even when the who/when is missing.

WHAT COUNTS AS A BANK-DETAIL CHANGE, AND WHY MATCHING IS TABLE-KEYED. A CDPOS
row is payment-relevant when TABNAME is one of LFBK (vendor bank), KNBK
(customer bank), BUT0BK (business-partner bank) or TIBAN (IBAN store). The
module deliberately does NOT match on field name alone: BANKS-like field names
appear in address and country contexts across the dictionary, and a register
that cries wolf on those teaches the reviewer to skip it. A table-keyed match
misses a bank field in a table this list does not name; that trade is accepted
and recorded here rather than hidden.

BANK VALUES ARE MASKED IN EVERY FINDING. The report this module feeds is
itself a document that travels — mailed, attached, archived. VALUE_OLD /
VALUE_NEW for a bank row ARE account numbers, so findings carry them masked to
the last four characters. The unmasked evidence stays in the operator's CSV,
which the export guide tells them to handle like the payment data it is.

WHAT THIS MODULE DOES NOT CLAIM. The classic fraud query — "bank changed, then
a payment run within days" — needs the payment-run export (REGUH) this product
does not yet define. Offline, this register is the half of that correlation
that exists; the finding text says to run the reconciliation, it does not
pretend to have run it.

Data sources (exported to CSV):
  - change_documents       → CDHDR   [verified: SAP data dictionary + operator
                             field reference] — shared with code_transport
  - change_document_items  → CDPOS   [verified: same]
"""

from typing import Any, Dict, List

from modules.base_auditor import BaseAuditor


class MasterDataChangeAuditor(BaseAuditor):

    CATEGORY = "Master Data Change Audit"

    #: CDPOS.TABNAME values that hold payment-routing master data. Table-keyed
    #: on purpose — see the docstring.
    _BANK_TABLES = {"LFBK", "KNBK", "BUT0BK", "TIBAN"}
    #: Direct table-maintenance transactions: a change document whose TCODE is
    #: one of these was made at TABLE level, past every application-level
    #: validation, dual-control lock and workflow the business transaction
    #: would have enforced.
    _DIRECT_TCODES = {"SE16", "SE16N", "SE16H", "SM30", "SM31", "SM34"}
    #: CDPOS.CHNGIND codes, for readable evidence lines.
    _CHNGIND = {"U": "changed", "I": "added", "D": "deleted", "E": "deleted"}

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_bank_detail_changes()
        self.check_direct_maintenance_changes()
        self.check_item_evidence_quality()
        return self.findings

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _get(row: dict, *names: str) -> str:
        if not isinstance(row, dict):
            return ""
        low = {str(k).strip().upper(): v for k, v in row.items()}
        for n in names:
            v = low.get(n.upper())
            if v not in (None, ""):
                return str(v).strip()
        return ""

    @staticmethod
    def _add_obj(bucket: List[Dict[str, Any]], obj_type: str, name: Any) -> None:
        """One de-duplicated structured object; a row with no identifier adds none."""
        n = "" if name is None else str(name).strip()
        if not n:
            return
        obj = {"type": obj_type, "name": n}
        if obj not in bucket:
            bucket.append(obj)

    @staticmethod
    def _mask(value: str) -> str:
        """Mask an account-number-like value to its last four characters.

        Empty stays visibly empty — "(empty)" — because for an insert (CHNGIND
        I) the old value being blank is itself the evidence."""
        v = str(value or "").strip()
        if not v:
            return "(empty)"
        if len(v) <= 4:
            return "****"
        return "*" * (len(v) - 4) + v[-4:]

    def _headers_by_changenr(self) -> Dict[str, Dict[str, str]]:
        out: Dict[str, Dict[str, str]] = {}
        for r in (self.data.get("change_documents") or []):
            nr = self._get(r, "CHANGENR", "CHANGE_NUMBER").lstrip("0")
            if not nr:
                continue
            out[nr] = {
                "user": self._get(r, "USERNAME", "UNAME", "USER"),
                "date": self._get(r, "UDATE", "DATE", "CHANGE_DATE"),
                "tcode": self._get(r, "TCODE", "TRANSACTION"),
            }
        return out

    # -------------------------------------------------------------------- checks
    def check_bank_detail_changes(self):
        """CDPOS rows on LFBK/KNBK/BUT0BK/TIBAN: the payment-redirection register."""
        items = self.data.get("change_document_items")
        if not items:
            return
        headers = self._headers_by_changenr()
        hits: List[str] = []
        objects: List[Dict[str, Any]] = []
        partners = set()
        users = set()
        for r in items:
            table = self._get(r, "TABNAME", "TABLE_NAME", "TABLE").upper()
            if table not in self._BANK_TABLES:
                continue
            partner = self._get(r, "OBJECTID", "OBJECT_ID", "PARTNER")
            field = self._get(r, "FNAME", "FIELD", "FIELD_NAME").upper()
            old = self._get(r, "VALUE_OLD", "OLD_VALUE")
            new = self._get(r, "VALUE_NEW", "NEW_VALUE")
            verb = self._CHNGIND.get(
                self._get(r, "CHNGIND", "CHANGE_IND", "CHANGE_INDICATOR").upper()[:1],
                "changed")
            nr = self._get(r, "CHANGENR", "CHANGE_NUMBER").lstrip("0")
            hdr = headers.get(nr)
            who = (f"by {hdr['user'] or '?'} on {hdr['date'] or '?'}"
                   + (f" via {hdr['tcode']}" if hdr and hdr["tcode"] else "")
                   ) if hdr else "(header not supplied)"
            hits.append(
                f"{table}.{field or 'row'} {verb}: {self._mask(old)} -> "
                f"{self._mask(new)} — partner {partner or '?'}, {who}")
            if partner:
                partners.add(partner)
            self._add_obj(objects, "business_partner", partner)
            if hdr and hdr["user"]:
                users.add(hdr["user"])
                self._add_obj(objects, "user", hdr["user"])
        if not hits:
            return
        self.finding(
            check_id="MDC-BANK-001",
            title="Vendor / customer / business-partner bank details were changed",
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=(
                f"{len(hits)} bank-detail change(s) across {len(partners)} "
                "partner(s) appear in the change documents (tables LFBK / KNBK / "
                "BUT0BK / TIBAN). A changed bank account redirects every payment "
                "that follows it — this is the single most direct payment-fraud "
                "vector in an ERP, and each of these changes should reconcile to "
                "an approved change request and (where FIN-SF-001 reports dual "
                "control configured) a second-person confirmation. Values are "
                "masked to the last four characters; the export holds the "
                "originals."
            ),
            affected_items=hits[:50],
            # Aggregate: one register of bank changes for the audit window.
            # Clearing one change against its approval must shrink the list,
            # not retire the register and restart its age.
            affected_objects=objects,
            scope="aggregate",
            remediation=(
                "Reconcile each listed change against an approved request and the "
                "FK09/FD09 confirmation trail; treat any change nobody claims as a "
                "payment-fraud incident (verify the CURRENT bank data with the "
                "partner out-of-band before the next payment run). Where dual "
                "control is not configured, FIN-SF-001 carries that remediation."
            ),
            references=[
                "SOX anti-fraud — payment master data change control (PCAOB AS 2201)",
                "SAP KBA 2518672 — Sensitive fields (FK08) dual control",
                "ACFE — vendor master / payment diversion fraud schemes",
            ],
            details={"count": len(hits), "partners": len(partners),
                     "changing_users": sorted(users)},
        )

    def check_direct_maintenance_changes(self):
        """CDHDR rows whose TCODE is raw table maintenance (SE16N, SM30, ...)."""
        rows = self.data.get("change_documents")
        if not rows:
            return
        hits: List[str] = []
        objects: List[Dict[str, Any]] = []
        for r in rows:
            tcode = self._get(r, "TCODE", "TRANSACTION").upper()
            if tcode not in self._DIRECT_TCODES:
                continue
            cls = self._get(r, "OBJECTCLAS", "OBJECT_CLASS", "OBJECT")
            objid = self._get(r, "OBJECTID", "OBJECT_ID")
            user = self._get(r, "USERNAME", "UNAME", "USER")
            date = self._get(r, "UDATE", "DATE", "CHANGE_DATE")
            hits.append(f"{cls or '?'} {objid or ''}".strip()
                        + f" changed via {tcode} by {user or '?'} on {date or '?'}")
            self._add_obj(objects, "user", user)
        if not hits:
            return
        self.finding(
            check_id="MDC-DIRECT-001",
            title="Master data changed through direct table maintenance",
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=(
                f"{len(hits)} change(s) were made through raw table-maintenance "
                "transactions (SE16N, SM30 and family) rather than the owning "
                "application transaction. A table-level edit skips every "
                "validation, sensitive-field dual-control lock and workflow the "
                "application would have enforced — it is the standard way to "
                "change data without leaving the application-level trail, and on "
                "production master data it is an audit finding regardless of "
                "what was changed."
            ),
            affected_items=hits[:50],
            # Aggregate: the defect is the change PATH; every direct edit in the
            # window is a member of the same register.
            affected_objects=objects,
            scope="aggregate",
            remediation=(
                "Review each listed change with its author; restrict S_TABU_DIS / "
                "S_TABU_NAM and the SE16N/SM30 family in production; where table "
                "edits are genuinely required, route them through a logged, "
                "approved firefighter session instead of standing access."
            ),
            references=[
                "SOX ITGC — direct data changes in production",
                "DSAG Prüfleitfaden — Tabellenpflege in Produktivsystemen",
                "SAP Note 1420281 — SE16N: deactivate &SAP_EDIT",
            ],
            details={"count": len(hits)},
        )

    def check_item_evidence_quality(self):
        """CDPOS supplied, but with no before/after values anywhere.

        The register still names WHAT changed, but not FROM and TO what — and a
        reviewer reading it could reasonably believe they had seen the change
        history. Thinner evidence than it looks is exactly what this product
        exists to say out loud.
        """
        items = self.data.get("change_document_items")
        if not items:
            return
        if any(self._get(r, "VALUE_OLD", "OLD_VALUE")
               or self._get(r, "VALUE_NEW", "NEW_VALUE") for r in items):
            return
        self.finding(
            check_id="MDC-EVD-001",
            title="Change-document items were supplied without before/after values",
            severity=self.SEVERITY_LOW,
            category=self.CATEGORY,
            description=(
                f"All {len(items)} change-document item row(s) lack VALUE_OLD and "
                "VALUE_NEW. The register can still say which fields changed, who "
                "changed them and when — but not what the values were, so a "
                "bank-account change and a typo correction read identically. "
                "Re-export CDPOS with the value columns included."
            ),
            affected_items=[f"{len(items)} item row(s), no VALUE_OLD/VALUE_NEW in any"],
            # Aggregate with NO objects: the statement is about the export's
            # columns, not about anything the export names.
            scope="aggregate",
            remediation=(
                "Re-export CDPOS including VALUE_OLD and VALUE_NEW (SE16 field "
                "selection), and note that some object classes legitimately "
                "suppress values for privacy-classified fields — say which on "
                "the export note."
            ),
            references=["SAP data dictionary — CDPOS change-document items"],
            details={"rows": len(items)},
        )
