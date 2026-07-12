"""
Financial Controls (SOX ITGC / application config) Auditor
==========================================================
The single largest genuinely-missing compliance domain for a production ERP: the
FINANCIAL application-configuration controls a SOX / external auditor tests. Every
other module here is technical/basis/authorization; this one inspects the FI/CO
Customizing that governs the integrity of the financial records themselves. All of
it is SE16-exportable Customizing, so the audit stays offline.

Checks:
  - FIN-PP-001  Posting-period governance (OB52 / T001B): periods left open too wide
                (a full year or more, or into the far future), open for ALL account
                types, and with no authorization group restricting who may post to the
                special/open period — a financial cutoff/completeness control.
  - FIN-TOL-001 FI tolerance groups (OBA4 / T043T) missing or effectively unlimited:
                no upper limit on what a clerk can post per document / open item — a
                preventive limit control.
  - FIN-SF-001  Sensitive fields for dual control (FK08/FD08 / T055F) not covering
                payment-relevant master data (bank account, payment method): vendor/
                customer bank details can be changed by one person without a second
                approval — the classic payment-redirection fraud path.
  - FIN-DOC-001 Document change rules (OB32 / TBAER) permit payment-relevant fields
                to be changed AFTER a document is posted/cleared — undermines the
                immutability of the financial record.
  - FIN-NR-001  FI document number ranges buffered (SNRO / TNRO): buffering causes
                number gaps, breaking the sequential-completeness assertion over
                financial documents.

Data sources (exported to CSV):
  - posting_periods    → T001B/V_T001B: VARIANT, ACCOUNT_TYPE, FROM/TO_PERIOD+YEAR, AUTH_GROUP
  - tolerance_groups   → T043T: GROUP, CURRENCY, AMOUNT_PER_DOC, AMOUNT_PER_OPEN_ITEM
  - dual_control_fields→ T055F: TABLE, FIELD (fields flagged sensitive for dual control)
  - doc_change_rules   → TBAER/V_TBAER: FIELD, ACCOUNT_TYPE, CHANGE_ALLOWED, AFTER_POSTING/CLEARING
  - fi_number_ranges   → TNRO/NRIV: OBJECT, BUFFERING
"""

from typing import Any, Dict, List

from modules.base_auditor import BaseAuditor


class FinancialControlsAuditor(BaseAuditor):

    CATEGORY = "Financial Controls (SOX)"

    _ALL_ACCT_TYPES = {"+", "", "*", "ALL"}
    _UNLIMITED = 1_000_000_000          # >= this per-document limit is treated as "no limit"
    # BANK-ROUTING / payee / payment-method document fields whose change AFTER posting
    # redirects a payment. Deliberately EXCLUDES ZLSPR (payment block) and ZTERM (terms):
    # those are routinely changed on posted documents as part of normal AP processing, so
    # flagging them would be a false positive. All below are real BSEG fields.
    _CRITICAL_DOC_FIELDS = {"BVTYP", "HBKID", "HKTID", "EMPFB", "UZAWE", "ZLSCH"}
    # Payment-relevant master-data fields (real field names) that MUST be under dual
    # control (T055F) — bank account/key/country, IBAN, partner-bank type, payment methods.
    _PAYMENT_MASTER_FIELDS = {"BANKN", "BANKL", "BANKS", "IBAN", "BVTYP", "ZWELS", "HBKID"}
    # Number-range objects for FI ACCOUNTING DOCUMENTS only (buffering => number gaps that
    # break the SOX sequential-completeness assertion). NOT master-data ranges (DEBITOR/
    # KREDITOR — gaps there are acceptable, SAP Note 62077) and NOT SD (RV_BELEG) / CO
    # (RK_BELEG) document ranges, which do not carry the FI-document completeness assertion.
    _FI_NR_OBJECTS = {"RF_BELEG", "FI_BELEG", "RF_BELEG_M"}

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_posting_periods()
        self.check_tolerance_groups()
        self.check_dual_control_fields()
        self.check_document_change_rules()
        self.check_fi_number_ranges()
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
    def _truthy(v: Any) -> bool:
        return str(v).strip().lower() in ("1", "x", "yes", "true", "on", "y")

    @staticmethod
    def _int(s: Any) -> int:
        t = str(s or "").strip().replace(",", "").replace(".", "")
        try:
            return int(t)
        except ValueError:
            return 0

    @staticmethod
    def _amount(s: Any) -> float:
        """Parse an amount tolerant of US (1,234.56) AND European (1.234,56) formats."""
        t = str(s or "").strip()
        if not t:
            return 0.0
        if "," in t and "." in t:
            # both present -> the LAST separator is the decimal point
            if t.rfind(",") > t.rfind("."):        # European: comma is decimal
                t = t.replace(".", "").replace(",", ".")
            else:                                  # US: dot is decimal, comma = thousands
                t = t.replace(",", "")
        elif "," in t:
            parts = t.split(",")
            if len(parts) == 2 and len(parts[1]) in (1, 2):   # "50000,00" -> decimal comma
                t = t.replace(",", ".")
            else:                                              # "1,234,567" -> thousands
                t = t.replace(",", "")
        elif t.count(".") > 1:                     # "1.000.000" -> European thousands
            t = t.replace(".", "")
        try:
            return float(t)
        except ValueError:
            return 0.0

    # =====================================================  POSTING PERIODS
    def check_posting_periods(self):
        rows = self.data.get("posting_periods")
        if not rows:
            return
        offenders = []
        for r in rows:
            variant = self._get(r, "VARIANT", "BUKRS", "PERIOD_VARIANT", "BKGRP") or "?"
            acct = self._get(r, "ACCOUNT_TYPE", "KOART", "ACCT_TYPE").upper()
            fp = self._int(self._get(r, "FROM_PERIOD", "FRPE1", "FROM_PER", "VON_PERIODE"))
            tp = self._int(self._get(r, "TO_PERIOD", "TOPE1", "TO_PER", "BIS_PERIODE"))
            fy = self._int(self._get(r, "FROM_YEAR", "FRYE1", "FROM_FYEAR"))
            ty = self._int(self._get(r, "TO_YEAR", "TOYE1", "TO_FYEAR"))
            ag = self._get(r, "AUTH_GROUP", "BRGRU", "AUTHORIZATION_GROUP", "TOLERANZ")
            # "open too wide" = spans a full year of periods, or crosses into another
            # fiscal year, or open to the far future.
            wide = (tp - fp >= 11) or (ty and fy and ty - fy >= 1) or ty >= 9999
            if wide and acct in self._ALL_ACCT_TYPES and not ag:
                yr = f"{fy or '?'}-{ty or '?'}"
                offenders.append(f"variant {variant}: all account types, periods {fp}-{tp}/{yr}, no auth group")
        if offenders:
            self.finding(
                check_id="FIN-PP-001",
                title="Posting periods open too wide with no authorization-group control",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} posting-period variant setting(s) leave the period open for all "
                    "account types across a full year or more (or into the far future) with no "
                    "authorization group (T001B-BRGRU) restricting who may post. Open posting periods "
                    "are the primary financial cutoff/completeness control: wide-open periods let "
                    "entries be posted or back-dated into closed/future periods, defeating period-end "
                    "cutoff and enabling manipulation of which period results land in — a core SOX "
                    "financial-reporting concern (PCAOB AS 2201)."
                ),
                affected_items=offenders[:50],
                remediation=(
                    "In OB52 (posting period variant, T001B) keep only the current open period(s) open, "
                    "close prior periods, and set an authorization group on the second/special period "
                    "range so only the close team (S_TABU_DIS / posting-period auth) can post to it. "
                    "Review the wide-open variants above."
                ),
                references=["SOX financial-reporting cutoff & completeness (PCAOB AS 2201)",
                            "DSAG Prüfleitfaden — Buchungsperioden (OB52)",
                            "SAP Help — Posting period variant / authorization group"],
                details={"count": len(offenders)},
            )

    # =====================================================  TOLERANCE GROUPS
    def check_tolerance_groups(self):
        rows = self.data.get("tolerance_groups")
        if rows is None:
            return
        if not rows:
            # export provided but empty -> no tolerances defined at all
            self.finding(
                check_id="FIN-TOL-002",
                title="No FI tolerance groups defined (no posting limits)",
                severity=self.SEVERITY_MEDIUM,
                category=self.CATEGORY,
                description=(
                    "No FI tolerance groups (OBA4 / T043T) are defined, so there is no upper limit on "
                    "the amount a user can post per document or clear per open item. Tolerance groups "
                    "are a preventive financial control that caps individual postings; without them a "
                    "single user can post arbitrarily large amounts."
                ),
                affected_items=["T043T export is empty"],
                remediation="Define FI tolerance groups (OBA4) with appropriate per-document and per-open-item limits and assign users (OB57).",
                references=["SOX preventive financial controls / authorization limits (PCAOB AS 2201)",
                            "DSAG Prüfleitfaden — Toleranzgruppen (OBA4)"],
            )
            return
        unlimited = []
        for r in rows:
            grp = self._get(r, "GROUP", "TOLERANZ", "TGROUP", "TOLERANCE_GROUP") or "(blank/default)"
            per_doc = self._amount(self._get(r, "AMOUNT_PER_DOC", "AMOUNT_DOC", "BETRG", "MAX_AMOUNT"))
            per_item = self._amount(self._get(r, "AMOUNT_PER_OPEN_ITEM", "AMOUNT_ITEM", "AMOUNT_PER_ITEM"))
            # An effectively-unlimited or zero/blank per-document cap = no real limit.
            if per_doc == 0 or per_doc >= self._UNLIMITED or per_item >= self._UNLIMITED:
                cap = "unset" if per_doc == 0 else f"{per_doc:,.0f}"
                unlimited.append(f"group {grp}: per-document limit {cap}")
        if unlimited:
            self.finding(
                check_id="FIN-TOL-001",
                title="FI tolerance groups have effectively unlimited posting limits",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(unlimited)} FI tolerance group(s) have a per-document limit that is unset or "
                    "effectively unlimited. The tolerance group is the preventive cap on how much a user "
                    "can post/clear in one document; an unset or huge limit means no monetary control on "
                    "individual postings, so errors or fraudulent entries of any size pass unchecked "
                    "(a SOX preventive-control gap)."
                ),
                affected_items=unlimited[:50],
                remediation=(
                    "In OBA4 set realistic per-document and per-open-item amount limits on each FI "
                    "tolerance group appropriate to the roles assigned, and confirm the default (blank) "
                    "group is not the one granting unlimited posting."
                ),
                references=["SOX preventive financial controls / authorization limits (PCAOB AS 2201)",
                            "DSAG Prüfleitfaden — Toleranzgruppen (OBA4/T043T)"],
                details={"count": len(unlimited)},
            )

    # =====================================================  DUAL CONTROL (T055F)
    def check_dual_control_fields(self):
        rows = self.data.get("dual_control_fields")
        if rows is None:
            return
        fields = set()
        for r in rows:
            f = self._get(r, "FIELD", "FIELDNAME", "FELDNAME", "FIELD_NAME").upper()
            if f:
                fields.add(f)
        covers_payment = bool(fields & self._PAYMENT_MASTER_FIELDS)
        if not covers_payment:
            detail = ("no sensitive fields are defined at all" if not fields
                      else "no PAYMENT-relevant fields (bank account, bank key, IBAN, payment method) are among them")
            self.finding(
                check_id="FIN-SF-001",
                title="Payment-relevant master-data fields are not under dual control (T055F)",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    "Sensitive-fields dual control (FK08/FD08, table T055F) is configured but " + detail +
                    ". When a vendor/customer bank account or payment method can be changed by ONE person "
                    "with no second-person confirmation, an attacker or insider can silently redirect "
                    "payments to their own account (the classic vendor-bank-change payment fraud). Dual "
                    "control over payment master data is a key SOX anti-fraud control."
                ),
                affected_items=(sorted(fields)[:50] or ["T055F export contains no sensitive fields"]),
                remediation=(
                    "In FK08 (vendor) / FD08 (customer) mark the bank-detail and payment-method fields "
                    "(LFBK-BANKN/BANKL/BANKS, IBAN, ZWELS, house bank) as 'sensitive' so a change locks "
                    "the master record until a second, segregated user confirms it (FK09/FD09)."
                ),
                references=["SOX anti-fraud / dual control over payment master data (PCAOB AS 2201)",
                            "SAP KBA 2518672 — Sensitive fields (FK08) dual control",
                            "DSAG Prüfleitfaden — Kritische Felder / Doppelkontrolle"],
                details={"defined_fields": len(fields)},
            )

    # =====================================================  DOC CHANGE RULES (TBAER)
    def check_document_change_rules(self):
        rows = self.data.get("doc_change_rules")
        if not rows:
            return
        offenders = []
        for r in rows:
            field = self._get(r, "FIELD", "FELDNAME", "FIELD_NAME").upper()
            acct = self._get(r, "ACCOUNT_TYPE", "KOART")
            changeable = self._get(r, "CHANGE_ALLOWED", "CHANGEABLE", "AENDERBAR", "MODIFIABLE")
            # Interpreted export columns: does the rule permit the change once the document
            # is posted / the line item is cleared? (Not the raw TBAER XAUSZ flag, whose
            # 'X' means the OPPOSITE — not changeable after clearing.)
            after_post = self._get(r, "AFTER_POSTING", "POSTED", "AFTER_POST")
            after_clear = self._get(r, "AFTER_CLEARING", "CLEARED", "AFTER_CLEAR")
            if field in self._CRITICAL_DOC_FIELDS and self._truthy(changeable) \
                    and (self._truthy(after_post) or self._truthy(after_clear)):
                when = "after posting" if self._truthy(after_post) else "after clearing"
                offenders.append(f"{field}" + (f" ({acct})" if acct else "") + f" changeable {when}")
        if offenders:
            self.finding(
                check_id="FIN-DOC-001",
                title="Payment-relevant document fields may be changed after posting/clearing",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} document change rule(s) (OB32 / TBAER) allow a payment-relevant "
                    "field (payment block, payment terms/method, partner bank, house bank, payee) to be "
                    "changed AFTER the document is posted (or even after it is cleared). Altering payment "
                    "routing on an already-approved/posted document bypasses the approval that authorised "
                    "it and undermines the immutability of the financial record — a SOX record-integrity "
                    "gap and a payment-fraud vector."
                ),
                affected_items=offenders[:50],
                remediation=(
                    "In OB32 (document change rules, TBAER) disallow changes to payment-relevant fields "
                    "once a line item is posted/cleared (uncheck 'field can be changed'), or gate them "
                    "behind a controlled process. Restrict who holds change authorization (FB02)."
                ),
                references=["SOX financial-record integrity (PCAOB AS 2201)",
                            "DSAG Prüfleitfaden — Belegänderungsregeln (OB32)",
                            "SAP Help — FB02 / OB32 document change rules"],
                details={"count": len(offenders)},
            )

    # =====================================================  NUMBER RANGES (TNRO)
    def check_fi_number_ranges(self):
        rows = self.data.get("fi_number_ranges")
        if not rows:
            return
        buffered = []
        for r in rows:
            obj = self._get(r, "OBJECT", "NROBJ", "NR_OBJECT", "NUMBER_RANGE_OBJECT").upper()
            buffering = self._get(r, "BUFFERING", "BUFFER", "PUFFER", "BUFFER_TYPE")
            no_buffer = self._get(r, "NO_BUFFER", "NOBUFFER", "NOIVBUFFER")   # inverse flag
            # TNRO buffer domain: SPACE=none, X=main-memory, L=local, P=extended-local,
            # S=parallel. ALL of X/L/P/S cause number gaps, so any non-"none" code counts.
            bv = buffering.strip().lower()
            is_buffered = (bv not in ("", "no", "none", "no buffering", "not buffered", "space", "0", "n")
                           and not self._truthy(no_buffer))
            if obj in self._FI_NR_OBJECTS and is_buffered:
                buffered.append(f"{obj}: buffering = {buffering}")
        if buffered:
            self.finding(
                check_id="FIN-NR-001",
                title="Financial document number ranges are buffered (completeness gaps)",
                severity=self.SEVERITY_MEDIUM,
                category=self.CATEGORY,
                description=(
                    f"{len(buffered)} financial number-range object(s) have number-range buffering "
                    "enabled. Buffering hands out blocks of numbers per application server and discards "
                    "the unused ones on restart, producing GAPS in the document number sequence. For FI "
                    "documents that breaks the sequential-completeness assertion auditors rely on to "
                    "confirm no financial document was deleted or is missing (SOX completeness)."
                ),
                affected_items=buffered[:50],
                remediation=(
                    "For financial document number-range objects (SNRO / TNRO, e.g. RF_BELEG), disable "
                    "buffering (set 'no buffering') so document numbers are assigned gap-free. Weigh the "
                    "performance trade-off with Basis, but completeness usually governs for FI documents."
                ),
                references=["SOX financial-reporting completeness / sequence integrity (PCAOB AS 2201)",
                            "DSAG Prüfleitfaden — Nummernkreispufferung",
                            "SAP Note 62077 / SAP Help — number range buffering"],
                details={"count": len(buffered)},
            )
