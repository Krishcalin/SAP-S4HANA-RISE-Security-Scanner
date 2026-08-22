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

THE CORRELATION, AND WHAT IT MATCHES ON. The classic fraud query — "bank
changed, then a payment run within days" — needs the payment-run export, and
`payment_runs` (REGUH) now supplies it. `MDC-PAY-001` does NOT implement the
query as it is usually described, because "a payment to that partner within
days" fires on every routine cycle and teaches the reviewer to skip it. It
matches on the ACCOUNT NUMBER: CDPOS `VALUE_NEW` on a bank-account field
against REGUH `ZBNKN`, so what it reports is a payment that left INTO THE
ACCOUNT THE CHANGE INTRODUCED. Legitimate changes still produce this — a
supplier who genuinely switches bank and is then paid looks identical in the
data — so the finding says to reconcile each one rather than treating it as
proof.

Two things the correlation deliberately refuses. Proposal runs (`XVORL`) are
not payments and are dropped; a row with no proposal column is kept, because
absence of the flag is not evidence. And account normalisation stops at
whitespace, punctuation, case and leading zeros: an account that matches only
after being truncated is not a match, and this finding accuses somebody of
payment fraud.

WHERE THE EXPORT IS ABSENT. If bank changes were found and no `payment_runs`
was supplied, `MDC-PAY-002` records that the one test separating a routine
update from a diversion did not run, and carries `degrades_coverage`. Silence
would read as "no payment followed those changes", which is a stronger claim
than the evidence supports.

Data sources (exported to CSV):
  - change_documents       → CDHDR   [verified: SAP data dictionary + operator
                             field reference] — shared with code_transport
  - change_document_items  → CDPOS   [verified: same]
"""

from datetime import date as _date
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
    #: CDPOS fields that carry an ACCOUNT NUMBER rather than a bank key, country
    #: or control key. Only these are worth correlating against what was paid:
    #: a changed bank country is not an account somebody can be paid into.
    _ACCOUNT_FIELDS = {"BANKN", "IBAN", "IBAN_VALUE", "ZBNKN", "BANKN_LONG"}
    #: How many days after a bank change a payment still counts as correlated.
    #: Thirty is a payment cycle, not a law; `payment_correlation_days` overrides
    #: it. A wider window finds more and proves less, which is why the finding
    #: states the window it used rather than leaving the reader to assume one.
    _PAYMENT_WINDOW_DAYS = 30

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_bank_detail_changes()
        self.check_bank_change_then_payment()
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

    @staticmethod
    def _account_key(value: str) -> str:
        """Normalise an account number for comparison, or "" if there is none.

        One side of this comparison is typed into a master-data screen and the
        other is written by the payment program, so the same account routinely
        differs by spaces, punctuation and leading zeros. Case is folded for
        IBANs. Nothing else is normalised: an account that matches only after
        being truncated or reordered is not a match, and a false positive here
        accuses somebody of payment fraud.
        """
        cleaned = "".join(c for c in str(value or "") if c.isalnum()).upper()
        return cleaned.lstrip("0") or cleaned

    @staticmethod
    def _sap_date(value: str):
        """`YYYYMMDD` or `YYYY-MM-DD` to a date, else None.

        None is returned rather than a guess. A correlation whose interval could
        not be computed is still reported — the accounts matched, which is the
        evidence — with the interval named as unknown.
        """
        raw = "".join(c for c in str(value or "") if c.isdigit())
        if len(raw) != 8:
            return None
        try:
            return _date(int(raw[:4]), int(raw[4:6]), int(raw[6:8]))
        except ValueError:
            return None

    def _bank_changes(self) -> List[Dict[str, Any]]:
        """Bank-detail changes as structured rows, shared by both bank checks."""
        headers = self._headers_by_changenr()
        out: List[Dict[str, Any]] = []
        for r in (self.data.get("change_document_items") or []):
            table = self._get(r, "TABNAME", "TABLE_NAME", "TABLE").upper()
            if table not in self._BANK_TABLES:
                continue
            nr = self._get(r, "CHANGENR", "CHANGE_NUMBER").lstrip("0")
            hdr = headers.get(nr) or {}
            out.append({
                "table": table,
                "field": self._get(r, "FNAME", "FIELD", "FIELD_NAME").upper(),
                "partner": self._get(r, "OBJECTID", "OBJECT_ID", "PARTNER"),
                "old": self._get(r, "VALUE_OLD", "OLD_VALUE"),
                "new": self._get(r, "VALUE_NEW", "NEW_VALUE"),
                "chngind": self._get(r, "CHNGIND", "CHANGE_IND",
                                     "CHANGE_INDICATOR").upper()[:1],
                "changenr": nr,
                "user": hdr.get("user", ""),
                "date": hdr.get("date", ""),
                "tcode": hdr.get("tcode", ""),
                "header": bool(hdr),
            })
        return out

    def _payments(self) -> List[Dict[str, Any]]:
        """REGUH rows as structured payments, proposal runs excluded.

        `XVORL` is the proposal flag: a proposal run is what the payment program
        INTENDS to pay, and it can be edited or deleted before the payment run
        proper. Counting one as a payment would report money that never moved.
        Rows with no proposal column at all are kept — absence of the flag is not
        evidence that the row is a proposal.
        """
        out: List[Dict[str, Any]] = []
        for r in (self.data.get("payment_runs") or []):
            if not isinstance(r, dict):
                continue
            proposal = self._get(r, "XVORL", "PROPOSAL", "IS_PROPOSAL").upper()
            if proposal in ("X", "TRUE", "YES", "1"):
                continue
            out.append({
                "payee": self._get(r, "LIFNR", "KUNNR", "EMPFG", "PARTNER",
                                   "VENDOR", "PAYEE"),
                "account": self._get(r, "ZBNKN", "BANKN", "ACCOUNT",
                                     "ACCOUNT_NUMBER", "IBAN", "ZIBAN"),
                "date": (self._get(r, "ZALDT", "PAYMENT_DATE", "POSTING_DATE")
                         or self._get(r, "LAUFD", "RUN_DATE", "DATE")),
                "run": self._get(r, "LAUFI", "RUN_ID", "RUN"),
                "doc": self._get(r, "VBLNR", "PAYMENT_DOCUMENT", "DOCUMENT"),
                "company": self._get(r, "ZBUKR", "BUKRS", "COMPANY_CODE"),
                "amount": self._get(r, "RWBTR", "AMOUNT", "PAYMENT_AMOUNT"),
                "currency": self._get(r, "WAERS", "CURRENCY"),
            })
        return out

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

    def check_bank_change_then_payment(self):
        """The classic fraud query, finally answerable: changed, then paid.

        MDC-BANK-001 reports that a bank account was changed. On its own that is
        a register to reconcile — most entries will be legitimate, and a reviewer
        working through fifty of them treats the fifty-first the same way.

        This check answers the question that actually distinguishes them: did a
        payment then LEAVE, into the account the change introduced. The evidence
        is a match between `VALUE_NEW` on a bank-account field in CDPOS and
        `ZBNKN` on a REGUH row — not merely a payment to that partner in the same
        week, which would fire on every routine cycle, but a payment INTO THE NEW
        ACCOUNT. Where both dates are readable the interval is stated; where
        either is not, the match is still reported and the interval named as
        unknown, because the account match is the evidence and the date is the
        context.

        Deletions and blank new values are skipped: there is no account to have
        been paid. Proposal runs are excluded in `_payments` — see there.
        """
        changes = [c for c in self._bank_changes()
                   if c["chngind"] != "D"
                   and (not c["field"] or c["field"] in self._ACCOUNT_FIELDS)
                   and self._account_key(c["new"])]
        payments = self._payments()

        if changes and not self.data.get("payment_runs"):
            # ASKED THE QUESTION, COULD NOT ANSWER IT. Silence here would be read
            # as "no payment followed those changes", which is a stronger claim
            # than any evidence supports.
            self.finding(
                check_id="MDC-PAY-002",
                title="Bank changes found, but no payment-run export to check them against",
                severity=self.SEVERITY_INFO,
                category=self.CATEGORY,
                description=(
                    "%d bank-account change(s) were found in the change "
                    "documents and no payment-run export (REGUH) was supplied, "
                    "so the one test that separates a routine master-data update "
                    "from a payment diversion — did money then leave into the new "
                    "account — was not run. This is recorded as a gap rather than "
                    "left silent: nothing here says those changes were not paid, "
                    "only that nobody looked." % len(changes)),
                affected_items=["%d bank-account change(s) unreconciled against "
                                "payments" % len(changes)],
                remediation=(
                    "1. Export REGUH for the same window as the change documents "
                    "— see `payment_runs.csv` in the export guide.\n"
                    "2. Re-run the scan. MDC-PAY-001 then reports any change "
                    "whose new account was subsequently paid.\n"
                    "3. Until then, reconcile MDC-BANK-001 by hand against the "
                    "payment history."),
                references=["docs/EXPORT_GUIDE.md — Payment runs (`payment_runs.csv`)"],
                details={"degrades_coverage": True, "bank_changes": len(changes),
                         "missing_source": "payment_runs"},
                scope="aggregate",
            )
            return

        if not changes or not payments:
            return

        window = int(self.get_config("payment_correlation_days",
                                     self._PAYMENT_WINDOW_DAYS))
        by_account: Dict[str, List[Dict[str, Any]]] = {}
        for p in payments:
            key = self._account_key(p["account"])
            if key:
                by_account.setdefault(key, []).append(p)

        hits: List[str] = []
        objects: List[Dict[str, Any]] = []
        partners, users = set(), set()
        undated = 0
        for c in changes:
            for p in by_account.get(self._account_key(c["new"]), []):
                changed_on = self._sap_date(c["date"])
                paid_on = self._sap_date(p["date"])
                if changed_on and paid_on:
                    gap = (paid_on - changed_on).days
                    if gap < 0 or gap > window:
                        continue
                    when = "%d day(s) later" % gap
                else:
                    undated += 1
                    when = "interval unknown (a date could not be read)"
                amount = ("%s %s" % (p["amount"], p["currency"])).strip()
                hits.append(
                    "%s.%s -> %s on %s by %s — paid %s to %s on %s%s [run %s, "
                    "doc %s, %s]"
                    % (c["table"], c["field"] or "row", self._mask(c["new"]),
                       c["date"] or "?", c["user"] or "?",
                       amount or "(amount not exported)",
                       self._mask(p["account"]), p["date"] or "?",
                       ", " + when, p["run"] or "?", p["doc"] or "?",
                       p["company"] or "?"))
                if c["partner"]:
                    partners.add(c["partner"])
                self._add_obj(objects, "business_partner", c["partner"])
                self._add_obj(objects, "business_partner", p["payee"])
                if c["user"]:
                    users.add(c["user"])
                    self._add_obj(objects, "user", c["user"])
                self._add_obj(objects, "payment_document", p["doc"])

        if not hits:
            return
        self.finding(
            check_id="MDC-PAY-001",
            title="A payment left into a bank account that had just been changed",
            severity=self.SEVERITY_CRITICAL,
            category=self.CATEGORY,
            description=(
                "%d payment(s) were made into an account that a master-data "
                "change had introduced within the preceding %d day(s). This is "
                "the completed shape of the payment-diversion pattern rather "
                "than one half of it: MDC-BANK-001 reports that an account was "
                "changed, and this reports that money then went to the new "
                "account. Each one is matched on the ACCOUNT NUMBER itself — "
                "CDPOS `VALUE_NEW` against REGUH `ZBNKN` — not on a payment to "
                "the same partner in the same period, which would fire on every "
                "routine cycle. Legitimate changes produce this pattern too: a "
                "supplier who genuinely changes bank and is then paid looks "
                "exactly like this in the data, which is why every one needs "
                "reconciling against the request that authorised it rather than "
                "dismissing. Account numbers are masked to the last four "
                "characters; the exports hold the originals."
                % (len(hits), window)),
            affected_items=hits[:50],
            affected_objects=objects,
            scope="aggregate",
            remediation=(
                "1. For each payment listed, find the change request that "
                "authorised the bank change and confirm a second person approved "
                "it. A change nobody claims, followed by a payment, is a "
                "payment-fraud incident and not an audit point.\n"
                "2. Verify the CURRENT bank details with the supplier "
                "out-of-band — by a phone number you already held, never one "
                "from the change or from correspondence about it — before the "
                "next payment run.\n"
                "3. Where the payment was not authorised, involve the bank "
                "immediately: recall windows are measured in days.\n"
                "4. Fix the control, not just the case: FIN-SF-001 reports "
                "whether the bank fields are under dual control, and this "
                "pattern is what its absence costs.\n"
                "5. Narrow `payment_correlation_days` only with a reason. A "
                "shorter window reports less and proves nothing more."),
            references=[
                "SOX anti-fraud — payment master data change control (PCAOB AS 2201)",
                "ACFE — vendor master / payment diversion (business email compromise)",
                "SAP KBA 2518672 — Sensitive fields (FK08) dual control",
            ],
            details={"count": len(hits), "partners": len(partners),
                     "window_days": window, "changing_users": sorted(users),
                     "matched_on": "account_number",
                     "undated_matches": undated},
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
