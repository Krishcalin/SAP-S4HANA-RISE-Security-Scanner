# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
Vendor / Business Partner Master Integrity Auditor
==================================================
The STATE half of the payment-master triangle. Its two siblings read
configuration and history:

  - FIN-SF-001 (financial_controls) asks whether bank fields are under dual
    control — what the system REQUIRES.
  - MDC-BANK-001 (master_data_changes) lists the bank details that were
    CHANGED — what HAPPENED.
  - this module reads the master data as it stands right now — what IS.

The signal it exists for is the one none of the others can see: a bank
account that appears on more than one business partner. Nothing changed
today, every change was approved, and two supplier records still pay the
same account. That is the ghost-vendor pattern — a real supplier duplicated
so invoices can be paid twice, or a fabricated supplier pointed at an
account somebody already controls — and it is invisible to a change log
because the accounts may have been identical since the day they were
created.

A SHARED ACCOUNT IS A REVIEW REGISTER, NOT AN ACCUSATION. Legitimate causes
are common and the finding says so up front: a factoring house collects for
many suppliers, a group treasury pays for its subsidiaries, and one supplier
is often duplicated deliberately for two purchasing organisations. That last
"benign" case is worth surfacing anyway — two live records for one supplier
is the standard duplicate-payment exposure, so the register is useful even
when the answer is "we know about that one".

BANK VALUES ARE MASKED, for the reason master_data_changes masks them: the
report travels. Findings carry the last four characters; the operator's CSV
holds the originals, and the export guide says to treat it like the payment
data it is.

WHAT THIS MODULE DOES NOT CLAIM. It cannot tell a factoring arrangement from
a fraud — that needs the supplier contract, which is not an SAP export. It
does not compare vendor bank accounts against EMPLOYEE bank accounts (the
other classic ghost-vendor test), because that needs HR infotype 0009 and
this product does not read payroll master data. Both limits are stated in
the findings rather than left for the reader to discover.

Data sources (exported to CSV):
  - vendor_master → BUT000 / LFA1 / KNA1: PARTNER, NAME, BU_GROUP, XDELE,
                    XBLCK, NOT_RELEASED, CRUSR, CRDAT, CHUSR, CHDAT
                    [verified: operator design specification field catalogue]
  - vendor_bank   → BUT0BK / LFBK / KNBK: PARTNER, BANKS, BANKL, BANKN, BKONT
                    [verified: same]
"""

from typing import Any, Dict, List

from modules.base_auditor import BaseAuditor


class VendorMasterAuditor(BaseAuditor):

    CATEGORY = "Vendor & Bank Master Integrity"

    #: Above this many partners on one account, the shared-account finding
    #: labels the group as a probable payment-service/factoring arrangement
    #: rather than a duplicate pair. It changes the WORDING, never whether
    #: the group is reported — a shared account stays reportable at any size.
    _SERVICE_PROVIDER_HINT = 5

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_shared_bank_accounts()
        self.check_sole_maintained_payment_partners()
        self.check_bank_export_quality()
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
        n = "" if name is None else str(name).strip()
        if not n:
            return
        obj = {"type": obj_type, "name": n}
        if obj not in bucket:
            bucket.append(obj)

    @staticmethod
    def _mask(value: str) -> str:
        v = str(value or "").strip()
        if not v:
            return "(empty)"
        if len(v) <= 4:
            return "****"
        return "*" * (len(v) - 4) + v[-4:]

    @staticmethod
    def _norm_account(*parts: str) -> str:
        """Account identity for comparison: case-folded, separators removed.

        Bank keys and account numbers are written inconsistently across
        clients and load programs ('0012 3456' vs '00123456'), and an
        identity that treats those as different accounts would miss exactly
        the duplicate this check exists to find."""
        out = []
        for p in parts:
            t = "".join(ch for ch in str(p or "") if ch.isalnum()).upper()
            out.append(t)
        return "|".join(out)

    def _partner_index(self) -> Dict[str, Dict[str, str]]:
        idx: Dict[str, Dict[str, str]] = {}
        for r in (self.data.get("vendor_master") or []):
            pid = self._get(r, "PARTNER", "LIFNR", "KUNNR", "PARTNER_ID", "VENDOR")
            if not pid:
                continue
            idx[pid.upper()] = {
                "name": self._get(r, "NAME1", "NAME", "PARTNER_NAME", "MC_NAME1"),
                "blocked": self._get(r, "XBLCK", "BLOCKED", "SPERR", "LOEVM_BLOCK"),
                "deleted": self._get(r, "XDELE", "DELETED", "LOEVM", "DELETE_FLAG"),
                "unreleased": self._get(r, "NOT_RELEASED", "UNRELEASED"),
                "created_by": self._get(r, "CRUSR", "ERNAM", "CREATED_BY").upper(),
                "changed_by": self._get(r, "CHUSR", "AENAM", "CHANGED_BY").upper(),
                "created_on": self._get(r, "CRDAT", "ERDAT", "CREATED_ON"),
                "changed_on": self._get(r, "CHDAT", "AEDAT", "CHANGED_ON"),
            }
        return idx

    @staticmethod
    def _truthy(v: Any) -> bool:
        return str(v).strip().upper() in ("X", "1", "TRUE", "YES", "Y")

    def _flags(self, meta: Dict[str, str]) -> str:
        bits = []
        if self._truthy(meta.get("deleted")):
            bits.append("flagged for deletion")
        if self._truthy(meta.get("blocked")):
            bits.append("blocked")
        if self._truthy(meta.get("unreleased")):
            bits.append("not released")
        return ", ".join(bits)

    # -------------------------------------------------------------------- checks
    def check_shared_bank_accounts(self):
        """One bank account, several partners — the ghost-vendor signal."""
        rows = self.data.get("vendor_bank")
        if not rows:
            return
        idx = self._partner_index()
        groups: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            pid = self._get(r, "PARTNER", "LIFNR", "KUNNR", "PARTNER_ID", "VENDOR").upper()
            acct = self._get(r, "BANKN", "ACCOUNT", "ACCOUNT_NUMBER", "IBAN")
            if not pid or not acct:
                continue
            key = self._norm_account(
                self._get(r, "BANKS", "BANK_COUNTRY", "COUNTRY"),
                self._get(r, "BANKL", "BANK_KEY", "BANK_NUMBER"),
                acct)
            g = groups.setdefault(key, {"display": acct, "partners": {}})
            g["partners"].setdefault(pid, acct)
        shared = {k: g for k, g in groups.items() if len(g["partners"]) > 1}
        if not shared:
            return
        items: List[str] = []
        objects: List[Dict[str, Any]] = []
        multi = 0
        for _key, g in sorted(shared.items(), key=lambda kv: -len(kv[1]["partners"])):
            pids = sorted(g["partners"])
            if len(pids) >= self._SERVICE_PROVIDER_HINT:
                multi += 1
            labelled = []
            for p in pids:
                meta = idx.get(p, {})
                name = meta.get("name") or ""
                flags = self._flags(meta) if meta else ""
                labelled.append(p + (f" ({name})" if name else "")
                                + (f" [{flags}]" if flags else ""))
                self._add_obj(objects, "business_partner", p)
            note = (" — many partners on one account; check for a factoring or "
                    "payment-service arrangement before treating as duplication"
                    if len(pids) >= self._SERVICE_PROVIDER_HINT else "")
            items.append(f"account {self._mask(g['display'])} shared by "
                         f"{len(pids)} partners: " + "; ".join(labelled) + note)
        self.finding(
            check_id="VBM-BANK-001",
            title="One bank account is shared by several business partners",
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=(
                f"{len(shared)} bank account(s) appear on more than one partner "
                "record. Two supplier records paying the same account is the "
                "ghost-vendor pattern — a real supplier duplicated so its "
                "invoices can be paid twice, or a fabricated supplier pointed "
                "at an account somebody already controls. Legitimate causes are "
                "common and must be checked first: a factoring house collecting "
                "for many suppliers, a group treasury account, or one supplier "
                "deliberately duplicated for two purchasing organisations — and "
                "that last case is still worth knowing, because two live "
                "records for one supplier is the standard duplicate-payment "
                "exposure. Account numbers are masked to the last four "
                "characters; the export holds the originals."
            ),
            affected_items=items[:50],
            # Aggregate: one register of shared accounts. Resolving one group
            # must shrink the list, not retire the register and reset its age.
            affected_objects=objects,
            scope="aggregate",
            remediation=(
                "For each group, establish which explanation applies: confirm a "
                "factoring or payment-service arrangement in the supplier "
                "contract, merge or block genuine duplicate records, and treat "
                "any group nobody can explain as a payment-fraud incident — "
                "verify the account with the supplier out-of-band before the "
                "next payment run. Cross-check each partner against the "
                "bank-change register (MDC-BANK-001) to see whether the "
                "accounts were always identical or converged later."
            ),
            references=[
                "SOX anti-fraud — duplicate/fictitious vendor controls (PCAOB AS 2201)",
                "ACFE — billing schemes: shell and duplicate vendors",
                "S/4HANA security design specification — Business Partner master (BUT0BK / LFBK)",
            ],
            details={"shared_accounts": len(shared),
                     "groups_over_service_provider_hint": multi},
        )

    def check_sole_maintained_payment_partners(self):
        """Partners with bank data created and last changed by one person.

        Not a claim that anything is wrong: creating a record and correcting
        a typo minutes later leaves exactly this trace. It is the population
        an approval-trail review starts from, restricted to the partners that
        actually carry payment data — which is why it is MEDIUM and named a
        register. Where FIN-SF-001 reports dual control is NOT configured,
        every partner listed here was genuinely maintainable end-to-end by
        one person.
        """
        master = self.data.get("vendor_master")
        bank = self.data.get("vendor_bank")
        if not master or not bank:
            return
        with_bank = set()
        for r in bank:
            pid = self._get(r, "PARTNER", "LIFNR", "KUNNR", "PARTNER_ID", "VENDOR").upper()
            if pid and self._get(r, "BANKN", "ACCOUNT", "ACCOUNT_NUMBER", "IBAN"):
                with_bank.add(pid)
        if not with_bank:
            return
        hits: List[str] = []
        objects: List[Dict[str, Any]] = []
        users = set()
        for pid, meta in sorted(self._partner_index().items()):
            if pid not in with_bank:
                continue
            crusr, chusr = meta.get("created_by", ""), meta.get("changed_by", "")
            if not crusr or not chusr or crusr != chusr:
                continue
            name = meta.get("name") or ""
            hits.append(f"{pid}" + (f" ({name})" if name else "")
                        + f" — created and last changed by {crusr}"
                        + (f" on {meta.get('changed_on')}" if meta.get("changed_on") else ""))
            self._add_obj(objects, "business_partner", pid)
            self._add_obj(objects, "user", crusr)
            users.add(crusr)
        if not hits:
            return
        self.finding(
            check_id="VBM-SOLE-001",
            title="Payment-relevant partners created and last changed by the same person",
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=(
                f"{len(hits)} partner record(s) carrying bank details were "
                f"created and last changed by the same user ({len(users)} "
                "user(s) in total). This is a review register, not a finding "
                "of wrongdoing: creating a record and correcting it minutes "
                "later leaves exactly this trace. It is the population an "
                "approval-trail review starts from — and where FIN-SF-001 "
                "reports that dual control is not configured, every record "
                "listed here was genuinely maintainable end-to-end by one "
                "person with no second pair of eyes required."
            ),
            affected_items=hits[:50],
            # Aggregate: the statement is about the population, and its
            # members change whenever anybody touches a partner record.
            affected_objects=objects,
            scope="aggregate",
            remediation=(
                "Sample the listed records against the approved supplier "
                "onboarding requests; where dual control is not configured, "
                "FIN-SF-001 carries that remediation and closing it prevents "
                "the pattern going forward rather than explaining it away."
            ),
            references=[
                "SOX ITGC — four-eyes principle over payment master data",
                "S/4HANA security design specification — BUT000 CRUSR/CHUSR fields",
            ],
            details={"count": len(hits), "maintaining_users": sorted(users)},
        )

    def check_bank_export_quality(self):
        """Bank export supplied, but with no account numbers in it.

        The shared-account check keys on the account number. Without it the
        module can say nothing — and a reader seeing this module run and
        report nothing would reasonably conclude no accounts are shared.
        """
        rows = self.data.get("vendor_bank")
        if not rows:
            return
        if any(self._get(r, "BANKN", "ACCOUNT", "ACCOUNT_NUMBER", "IBAN") for r in rows):
            return
        self.finding(
            check_id="VBM-DATA-001",
            title="Bank export contains no account numbers, so no account can be compared",
            severity=self.SEVERITY_LOW,
            category=self.CATEGORY,
            description=(
                f"A partner bank export was supplied ({len(rows)} row(s)) but "
                "no row carries an account number. The shared-account check "
                "keys on exactly that field, so it compared nothing — this "
                "scan says nothing about whether partners share bank accounts, "
                "which is not the same as finding that none do. The column may "
                "have been dropped deliberately for privacy; if so, the "
                "duplicate-vendor question has to be answered another way."
            ),
            affected_items=[f"{len(rows)} bank row(s), no BANKN/IBAN value in any"],
            # Aggregate with NO objects: the statement is about the export's
            # columns, not about any partner in it.
            scope="aggregate",
            remediation=(
                "Re-export the partner bank table including the account number "
                "(BANKN) or IBAN. If account numbers cannot leave the system, "
                "run the duplicate-account comparison inside SAP and supply the "
                "result instead — and record on the export note that this check "
                "was not able to run."
            ),
            references=["S/4HANA security design specification — BUT0BK / LFBK fields"],
            details={"rows": len(rows), "degrades_coverage": True},
        )
