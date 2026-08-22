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

EVIDENCE CHECKS (FIN-EVD-*). The five checks above audit what the configuration
PERMITS; the three below read BKPF document headers and audit what actually
HAPPENED. FIN-PP-001 says whether the posting periods stand open — FIN-EVD-001
says whether anyone back-dated into them. Config and evidence are two halves of
one assertion, and an auditor is handed both or told which half is missing.

  - FIN-EVD-001 Back-dated postings: documents whose posting date (BUDAT) lies
                more than a threshold behind the entry date (CPUDT) — the
                cutoff-manipulation pattern the open-period config enables.
  - FIN-EVD-002 Weekend-entered postings: documents ENTERED (CPUDT) on a
                Saturday/Sunday. Scheduled interfaces post on weekends
                legitimately, so this is a review register, not an accusation —
                which is why it is LOW and lists the entering users.
  - FIN-EVD-003 Reversal rate: share of documents carrying a reversal (STBLG)
                above a threshold. Any single reversal is routine; a high rate
                is the post-and-reverse pattern that conceals activity inside
                a period.

BKPF is header-only, deliberately: no amounts leave the system, so the
amount-vs-tolerance check the doc-type data would invite is out of scope until
a line-item export (ACDOCA/BSEG) is defined and its privacy weighed.

THE FIVE CUSTOMIZING TABLES ARE VERIFIED, NOT GUESSED. T001B, T043T, T055F,
TBAER and TNRO are standard FI Customizing storage, each maintained by an IMG
transaction SAP has shipped for decades (OB52, OBA4, FK08/FD08, OB32, SNRO),
and the operator's design-spec field catalog corroborates the vocabulary. The
one deliberate translation: doc_change_rules takes INTERPRETED columns, never
raw TBAER — the raw XAUSZ flag means the opposite of what it looks like ('X'
= NOT changeable after clearing), and an export contract built on a negative
flag would invert somewhere between SE16 and the CSV. The export guide says
this out loud.

Data sources (exported to CSV):
  - posting_periods    → T001B/V_T001B: VARIANT, ACCOUNT_TYPE, FROM/TO_PERIOD+YEAR, AUTH_GROUP
  - tolerance_groups   → T043T: GROUP, CURRENCY, AMOUNT_PER_DOC, AMOUNT_PER_OPEN_ITEM
  - dual_control_fields→ T055F: TABLE, FIELD (fields flagged sensitive for dual control)
  - doc_change_rules   → TBAER/V_TBAER: FIELD, ACCOUNT_TYPE, CHANGE_ALLOWED, AFTER_POSTING/CLEARING
  - fi_number_ranges   → TNRO/NRIV: OBJECT, BUFFERING
  - fi_documents       → BKPF headers: BUKRS, BELNR, GJAHR, BUDAT, CPUDT
                         [, BLART, USNAM, TCODE, STBLG]  [verified: SAP data
                         dictionary + operator field reference]
"""

import datetime
from typing import Any, Dict, List, Optional

from modules.base_auditor import BaseAuditor


class FinancialControlsAuditor(BaseAuditor):

    CATEGORY = "Financial Controls (SOX)"

    # Evidence thresholds (FIN-EVD-*), all disclosed in the finding text.
    # Back-dating within a few days is normal period-end housekeeping; beyond a
    # week the posting was aimed at a period, not delayed by one.
    _MAX_BACKDATE_DAYS = 7
    # A reversal share above this, with at least _MIN_REVERSED reversed
    # documents, is screened as the post-and-reverse pattern. The floor keeps a
    # 3-document export from producing a 33% "rate".
    _MAX_REVERSAL_SHARE = 5.0
    _MIN_REVERSED = 3

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
        # Evidence half — reads BKPF headers when fi_documents is supplied.
        self.check_backdated_postings()
        self.check_weekend_postings()
        self.check_reversal_rate()
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
        objects = []
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
                # The offending config entry is the posting-period VARIANT (the T001B key
                # OB52 maintains), not table T001B — remediation closes periods on that
                # variant. "?" is the display fallback for a row that never named one, so
                # it stays a member string rather than becoming a fabricated node.
                # No qualifier: the period range, fiscal years and auth group are exactly
                # what change when the variant is remediated, so pinning them would spawn a
                # new graph node on every period close.
                if variant != "?":
                    objects.append({"type": "posting_period_variant", "name": variant})
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
                affected_objects=objects,
                # One finding rolling up every wide-open variant: closing periods on one
                # variant must shrink this finding, not retire it and raise a zero-age
                # clone, so the variants stay out of identity and ride along as members.
                scope="aggregate",
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
                # An ABSENCE, not an object: the defect is that T043T defines no tolerance
                # group at all, so there is nothing in the export to name. Identified by
                # (system, client, check_id) alone — correctly coarse.
                scope="aggregate",
                remediation="Define FI tolerance groups (OBA4) with appropriate per-document and per-open-item limits and assign users (OB57).",
                references=["SOX preventive financial controls / authorization limits (PCAOB AS 2201)",
                            "DSAG Prüfleitfaden — Toleranzgruppen (OBA4)"],
            )
            return
        unlimited = []
        objects = []
        for r in rows:
            grp = self._get(r, "GROUP", "TOLERANZ", "TGROUP", "TOLERANCE_GROUP") or "(blank/default)"
            per_doc = self._amount(self._get(r, "AMOUNT_PER_DOC", "AMOUNT_DOC", "BETRG", "MAX_AMOUNT"))
            per_item = self._amount(self._get(r, "AMOUNT_PER_OPEN_ITEM", "AMOUNT_ITEM", "AMOUNT_PER_ITEM"))
            # An effectively-unlimited or zero/blank per-document cap = no real limit.
            if per_doc == 0 or per_doc >= self._UNLIMITED or per_item >= self._UNLIMITED:
                cap = "unset" if per_doc == 0 else f"{per_doc:,.0f}"
                unlimited.append(f"group {grp}: per-document limit {cap}")
                # The T043T tolerance GROUP is the config entry at fault. The default
                # group's key is genuinely blank in T043T and "(blank/default)" is a
                # display label, not an identifier — it stays a member string rather than
                # becoming an invented node. No qualifier: the limit is the value being
                # remediated, so pinning it would re-node the group on every change.
                if grp != "(blank/default)":
                    objects.append({"type": "tolerance_group", "name": grp})
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
                affected_objects=objects,
                # One finding over the whole set of uncapped groups: setting a limit on
                # one group must shrink the member list, not reset the finding's age.
                scope="aggregate",
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
            # T055F-style exports often write the field as TABLE-FIELD
            # ("LFBK-BANKN"). Match on the FIELD half — otherwise a raw export
            # would read as "bank fields not under dual control" when they are.
            if "-" in f:
                f = f.rsplit("-", 1)[-1]
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
                # Aggregate, and deliberately WITHOUT affected_objects. The defect is an
                # ABSENCE — no payment-relevant field appears in T055F — so the offending
                # object is not in the export at all. The fields listed above are the ones
                # that ARE under dual control; promoting them to graph nodes would hang a
                # "not under dual control" finding off compliant objects. Naming T055F (or
                # FK08) instead would be naming a constant to dress the basis up as
                # "objects" without making the identity any more structural.
                scope="aggregate",
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
        objects = []
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
                # The config entry is the TBAER change rule, whose key is the document
                # FIELD plus the account type it applies to — not table TBAER itself. The
                # account type is a genuine key component, so it qualifies the object; the
                # "after posting / after clearing" trigger does not, because it is the
                # setting being remediated.
                obj = {"type": "document_field", "name": field}
                if acct:
                    obj["qualifier"] = f"account_type={acct}"
                objects.append(obj)
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
                affected_objects=objects,
                # One finding rolling up every over-permissive change rule: locking one
                # field down must shrink this finding rather than replace it.
                scope="aggregate",
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
        objects = []
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
                # The SNRO/TNRO number-range OBJECT is the config entry at fault. No
                # qualifier: every non-"none" buffer code (X/L/P/S) trips this check, so
                # putting the code in the node key would turn an X -> S change, which
                # fixes nothing, into a different object.
                objects.append({"type": "number_range_object", "name": obj})
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
                affected_objects=objects,
                # One finding over every buffered FI document range: unbuffering one
                # object must not retire the finding and restart its clock.
                scope="aggregate",
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

    # =====================================================  EVIDENCE (BKPF)
    @staticmethod
    def _parse_date(s: Any) -> Optional[datetime.date]:
        """8-digit SAP date or ISO date -> date; None when empty/unparseable."""
        digits = "".join(ch for ch in str(s or "") if ch.isdigit())
        if len(digits) < 8:
            return None
        try:
            return datetime.date(int(digits[:4]), int(digits[4:6]), int(digits[6:8]))
        except ValueError:
            return None

    def _doc_label(self, r: dict) -> str:
        doc = "/".join(x for x in (self._get(r, "BUKRS", "COMPANY_CODE"),
                                   self._get(r, "BELNR", "DOC_NUMBER", "DOCUMENT"),
                                   self._get(r, "GJAHR", "FISCAL_YEAR")) if x)
        return doc or "?"

    def check_backdated_postings(self):
        rows = self.data.get("fi_documents")
        if not rows:
            return
        hits, objects, max_gap = [], [], 0
        for r in rows:
            budat = self._parse_date(self._get(r, "BUDAT", "POSTING_DATE"))
            cpudt = self._parse_date(self._get(r, "CPUDT", "ENTRY_DATE"))
            if not budat or not cpudt:
                continue
            gap = (cpudt - budat).days
            if gap <= self._MAX_BACKDATE_DAYS:
                continue
            user = self._get(r, "USNAM", "USER", "USERNAME")
            tcode = self._get(r, "TCODE", "TRANSACTION")
            max_gap = max(max_gap, gap)
            hits.append(f"{self._doc_label(r)}: posted {budat.isoformat()}, "
                        f"entered {cpudt.isoformat()} ({gap} days later) "
                        f"by {user or '?'}" + (f" via {tcode}" if tcode else ""))
            # The entering USER is the graph object: the documents are members
            # of the register, but the pattern to review belongs to a person.
            if user:
                obj = {"type": "user", "name": user}
                if obj not in objects:
                    objects.append(obj)
        if not hits:
            return
        self.finding(
            check_id="FIN-EVD-001",
            title="Postings back-dated beyond the entry-lag threshold",
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=(
                f"{len(hits)} document(s) carry a posting date (BUDAT) more than "
                f"{self._MAX_BACKDATE_DAYS} days before the date they were "
                f"actually entered (CPUDT; worst gap {max_gap} days). Back-dating "
                "aims a posting at an earlier period after the fact — the cutoff "
                "manipulation that FIN-PP-001's open-period configuration makes "
                "possible. Each entry should trace to a documented period-end "
                "adjustment; the ones that do not are the finding."
            ),
            affected_items=hits[:50],
            # Aggregate register over the audit window, users as members.
            affected_objects=objects,
            scope="aggregate",
            remediation=(
                "Reconcile each listed posting against the period-end close "
                "documentation; close prior periods (OB52) and restrict the "
                "special-period authorization group so back-dating requires the "
                "close team, not any FI user."
            ),
            references=["SOX financial-reporting cutoff (PCAOB AS 2201)",
                        "DSAG Prüfleitfaden — Buchungen in Vorperioden"],
            details={"count": len(hits), "max_gap_days": max_gap,
                     "threshold_days": self._MAX_BACKDATE_DAYS},
        )

    def check_weekend_postings(self):
        rows = self.data.get("fi_documents")
        if not rows:
            return
        hits, objects = [], []
        for r in rows:
            cpudt = self._parse_date(self._get(r, "CPUDT", "ENTRY_DATE"))
            if not cpudt or cpudt.weekday() < 5:
                continue
            user = self._get(r, "USNAM", "USER", "USERNAME")
            tcode = self._get(r, "TCODE", "TRANSACTION")
            day = ("Saturday", "Sunday")[cpudt.weekday() - 5]
            hits.append(f"{self._doc_label(r)}: entered {cpudt.isoformat()} "
                        f"({day}) by {user or '?'}"
                        + (f" via {tcode}" if tcode else ""))
            if user:
                obj = {"type": "user", "name": user}
                if obj not in objects:
                    objects.append(obj)
        if not hits:
            return
        self.finding(
            check_id="FIN-EVD-002",
            title="FI documents entered on weekends",
            severity=self.SEVERITY_LOW,
            category=self.CATEGORY,
            description=(
                f"{len(hits)} document(s) were ENTERED on a Saturday or Sunday. "
                "Scheduled interfaces and batch runs post on weekends "
                "legitimately, so this is a review register rather than an "
                "accusation: the question is which of the entering users are "
                "people, and why a person was posting when the reviewers were "
                "not there."
            ),
            affected_items=hits[:50],
            affected_objects=objects,
            scope="aggregate",
            remediation=(
                "Classify the listed users (dialog vs system/interface); for "
                "dialog users, confirm the weekend activity with their manager "
                "and cross-check the same users against the back-dating and "
                "bank-change registers."
            ),
            references=["ACFE — off-hours activity as a fraud indicator",
                        "SOX ITGC — monitoring of manual journal activity"],
            details={"count": len(hits)},
        )

    def check_reversal_rate(self):
        rows = self.data.get("fi_documents")
        if not rows:
            return
        parsed = [r for r in rows if isinstance(r, dict)]
        total = len(parsed)
        reversed_docs = [r for r in parsed
                         if self._get(r, "STBLG", "REVERSAL_DOC", "REVERSED_BY")]
        if total == 0 or len(reversed_docs) < self._MIN_REVERSED:
            return
        share = 100.0 * len(reversed_docs) / total
        if share <= self._MAX_REVERSAL_SHARE:
            return
        hits, objects = [], []
        for r in reversed_docs[:50]:
            user = self._get(r, "USNAM", "USER", "USERNAME")
            hits.append(f"{self._doc_label(r)} reversed by document "
                        f"{self._get(r, 'STBLG', 'REVERSAL_DOC', 'REVERSED_BY')}"
                        + (f" — posted by {user}" if user else ""))
            if user:
                obj = {"type": "user", "name": user}
                if obj not in objects:
                    objects.append(obj)
        self.finding(
            check_id="FIN-EVD-003",
            title="Reversal rate above threshold in the FI document sample",
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=(
                f"{len(reversed_docs)} of {total} document(s) in the export were "
                f"reversed ({share:.1f}%, threshold "
                f"{self._MAX_REVERSAL_SHARE:.0f}%). Any single reversal is "
                "routine; a rate this high is the post-and-reverse pattern — "
                "entries that exist inside a period and vanish before scrutiny, "
                "or posting quality poor enough to be its own control issue. "
                "The rate is computed over the supplied export, so a "
                "pre-filtered export inflates it; export the full audit window."
            ),
            affected_items=hits,
            affected_objects=objects,
            scope="aggregate",
            remediation=(
                "Sample the listed reversal pairs: confirm each reversal has a "
                "documented reason and was not re-posted with altered values; "
                "review users with repeated post-and-reverse cycles."
            ),
            references=["SOX financial-record integrity (PCAOB AS 2201)",
                        "ACFE — journal-entry testing / reversal analysis"],
            details={"reversed": len(reversed_docs), "total": total,
                     "share_pct": round(share, 1),
                     "threshold_pct": self._MAX_REVERSAL_SHARE},
        )
