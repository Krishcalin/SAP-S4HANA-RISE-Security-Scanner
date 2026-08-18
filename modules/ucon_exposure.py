# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""Unified Connectivity — which remote-callable functions are actually exposed.

WHY THIS IS PRIORITY 1 AND NOT A NICE-TO-HAVE
---------------------------------------------
`docs/RISE_SECURITY_MODEL.md` section 7.1 ranks UCON state first among the checks
to add, and section 3 records the reason: the gateway ACL files `secinfo` and
`reginfo` are OS artifacts and a RISE customer contractually never gets OS access,
so the product's whole view of remote-callable exposure is unreachable there. UCON
is the ABAP-layer equivalent, the R&R puts business-client UCON configuration with
the customer, and it is reached from a transaction they already have.

Section 3 has carried the line "**Gap in our ingest**" against UCON since it was
written, and `docs/EXPORT_GUIDE.md` repeats it: "UCON in particular is a known
ingest gap, not a translation problem."

WHAT ALREADY EXISTED, AND WHY THIS DOES NOT DUPLICATE IT
--------------------------------------------------------
`system_trust.check_ucon_allowlist` (TRUST-007) reads the profile parameter
`ucon/rfc/active` and stops there — it knows whether UCON is switched on, never
what UCON is holding. Its own remediation text tells the customer to "start the
UCON RFC scenario in the Logging phase to record which RFMs are actually called
from outside", and until now nothing consumed the recording it asked for. This
module is the other half of that sentence. TRUST-007 keeps the parameter; nothing
here re-reports it.

THE CHECK THIS EXISTS FOR
-------------------------
`UCON-002`. A function module sitting in the default Communication Assembly that
was never called from outside during the logging window is exposed for nothing —
externally reachable configuration with no evidence of use behind it. That is the
same configured-versus-used distinction `server/edges.py` draws on the graph, and
here it is the finding rather than a label, because an unused remote-callable
function is not a risk rating, it is a thing to remove.

WHAT THE ABSENCE OF THIS DATA MEANS
-----------------------------------
`UCON-COV-001` arms `degrades_coverage`. In a RISE tenant with no gateway ACLs and
no UCON export, this product can say nothing whatsoever about which functions are
remotely callable — and a report that stays silent about that reads as though the
question was asked and came back clean.

IDENTIFIERS
-----------
Every SAP identifier named here already appears in this repository's vetted
content — `UCONCOCKPIT` and `ucon/rfc/active` in `data/finding_details.json` and
`modules/system_trust.py`, the `HTTP_WHITELIST` table with SAP Note 2573569 in
`FIORI-ODATA-001`, `RFC_READ_TABLE` and `SXPG_COMMAND_EXECUTE` in `AUTH-006`, and
the config store `ABAP_UCON_HTTP_WHITE_LIST` in `data/sap_baseline_requirements.json`
where it was derived from SAP's own Apache-2.0 policy XML. Nothing is invented,
and the phase and Communication Assembly vocabulary is the transaction's own.

The column names the loader accepts are aliases rather than assertions: the export
is whatever UCONCOCKPIT's list view produces, and no table name is claimed for the
RFC scenario because none could be sourced from SAP-primary material.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from modules.base_auditor import BaseAuditor

#: Column aliases. UCONCOCKPIT's export is a list view and its headers vary by
#: release and language; matching on several is how every loader in this codebase
#: already works. Declaring one true header would be a claim about SAP's UI that
#: no primary source here supports.
_FUNCTION_KEYS = ("FUNCNAME", "FUNCTION", "FUNCTION_MODULE", "RFM", "FMODULE")
_GROUP_KEYS = ("AREA", "FUNCGROUP", "FUNCTION_GROUP", "GROUP")
_PHASE_KEYS = ("PHASE", "UCON_PHASE", "STATUS")
_CA_KEYS = ("CA", "DEFAULT_CA", "IN_DEFAULT_CA", "ASSEMBLY", "COMM_ASSEMBLY")
_CALLED_KEYS = ("CALLED", "CALL_COUNT", "COUNT", "EXTERNAL_CALLS", "CALLS")
_LASTCALL_KEYS = ("LAST_CALL", "LASTCALL", "LAST_CALLED", "LAST_CALL_DATE")

#: Phase names as the UCON RFC scenario uses them. Only `final` enforces; the
#: other two record. A customer who has been in logging for a year has an
#: allowlist and no allowlisting.
_LOGGING = ("LOGGING", "LOG")
_EVALUATION = ("EVALUATION", "EVALUATE", "EVAL")
_FINAL = ("FINAL", "ACTIVE", "ACTIVATED", "ENFORCING")

#: Function modules this repository already names as powerful in AUTH-006 and
#: AUTH-003. Deliberately short: a long list assembled from memory is exactly the
#: invention this project's conventions forbid, and a short sourced one still
#: catches the two that matter most.
POWERFUL_FUNCTION_MODULES = {
    "RFC_READ_TABLE": "reads any table the calling user's S_TABU_* allows, which "
                      "is the standard remote data-exfiltration path",
    "SXPG_COMMAND_EXECUTE": "runs external OS commands defined in SM69 — the "
                            "documented ABAP-to-OS bridge in a system where the "
                            "customer otherwise has no OS access",
}

_TRUE = ("X", "TRUE", "YES", "Y", "1")


def _first(row: Dict[str, Any], keys) -> str:
    upper = {str(k).strip().upper(): v for k, v in row.items()}
    for key in keys:
        val = upper.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()
    return ""


class UconExposureAuditor(BaseAuditor):
    """What UCON is actually holding, not merely whether it is switched on."""

    CATEGORY = "Unified Connectivity (UCON)"
    SOURCE_KEY = "ucon_rfc_state"

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.findings = []
        rows = self._rows()
        self.check_coverage(rows)
        if rows:
            self.check_phase(rows)
            self.check_exposed_but_never_called(rows)
            self.check_powerful_modules_exposed(rows)
        self.check_http_allowlist()
        return self.findings

    # ── the data ───────────────────────────────────────────────────────────

    def _rows(self) -> List[Dict[str, Any]]:
        return [r for r in (self.data.get("ucon_rfc_state") or [])
                if isinstance(r, dict)]

    def _in_default_ca(self, row: Dict[str, Any]) -> bool:
        """Whether this function module is externally callable.

        ABSENT AND BLANK ARE DIFFERENT, AND AN SAP EXPORT MEANS DIFFERENT THINGS
        BY THEM. A column that is not in the export at all says nothing, and the
        conservative direction on an exposure check is to report rather than
        excuse — the export exists to enumerate the default Communication
        Assembly, so a row in it with no column saying otherwise is in it. But a
        column that IS present and blank is SAP's own convention for false, and
        reading that as exposure would report every function the customer has
        already removed from the assembly.

        `_first` cannot tell the two apart, because it skips empty values by
        design. So this asks whether the KEY exists before asking what it holds.
        """
        upper = {str(k).strip().upper() for k in row}
        present = [k for k in _CA_KEYS if k in upper]
        if not present:
            return True                    # no such column: says nothing, assume exposed
        val = _first(row, _CA_KEYS)
        if not val:
            return False                   # present and blank: SAP's false
        return val.strip().upper() in _TRUE or "DEFAULT" in val.strip().upper()

    def _calls(self, row: Dict[str, Any]) -> Optional[int]:
        """External call count, or None when the export does not carry one.

        None is not zero. An export without a call column says nothing about use,
        and treating it as "never called" would turn a missing column into a
        finding against every function module in the system.
        """
        raw = _first(row, _CALLED_KEYS)
        if not raw:
            return None
        try:
            return int(float(raw.replace(",", "")))
        except ValueError:
            return None

    # ── checks ─────────────────────────────────────────────────────────────

    def check_coverage(self, rows: List[Dict[str, Any]]):
        """No UCON data at all, in an estate where the gateway ACLs are also gone.

        DEGRADES COVERAGE. In RISE the customer has no OS access, so `secinfo` and
        `reginfo` are unreachable and UCON is the only remaining view of which
        functions are remotely callable. With neither, the product's answer on
        remote-callable exposure is "we could not look" — and a report that simply
        omits the topic reads as though it was examined and found clean.
        """
        if rows:
            return
        gateway = bool(self.data.get("gw_secinfo") or self.data.get("gw_reginfo"))
        self.finding(
            check_id="UCON-COV-001",
            title="No UCON data was supplied, so remote-callable exposure was not assessed",
            severity="INFO",
            category=self.CATEGORY,
            description=(
                "No UCON RFC scenario export was provided, so this scan cannot say "
                "which function modules are callable from outside the system. "
                + ("The gateway ACL files were not supplied either, which in a RISE "
                   "tenant is expected — they are OS artifacts the customer cannot "
                   "reach — and it leaves UCON as the only available view of remote-"
                   "callable exposure. With neither, nothing in this report speaks to "
                   "that question at all."
                   if not gateway else
                   "Gateway ACL data was supplied and covers the registration and "
                   "start of external programs, which is a different question from "
                   "which function modules a caller may invoke once connected.")
            ),
            affected_items=["UCON RFC scenario export absent"],
            remediation=(
                "In transaction UCONCOCKPIT, open the UCON RFC scenario and export "
                "the function-module list with its phase, Communication Assembly "
                "membership and recorded external call counts. If the scenario has "
                "never been started, start it in the Logging phase — TRUST-007 asks "
                "for the same thing and this check consumes what it produces."
            ),
            references=["docs/RISE_SECURITY_MODEL.md section 7.1"],
            details={"degrades_coverage": True,
                     "gateway_acls_supplied": gateway},
        )

    def check_phase(self, rows: List[Dict[str, Any]]):
        """Recording is not enforcing.

        The logging and evaluation phases build the allowlist; only the final
        phase applies it. A scenario left in logging has all the appearance of
        UCON being "in place" and blocks nothing — which is a worse position than
        not having started, because somebody believes it is done.
        """
        phases = {}
        for row in rows:
            phase = _first(row, _PHASE_KEYS).upper()
            if phase:
                phases[phase] = phases.get(phase, 0) + 1
        if not phases:
            return
        enforcing = sum(n for p, n in phases.items()
                        if any(p.startswith(f) for f in _FINAL))
        recording = sum(n for p, n in phases.items()
                        if any(p.startswith(f) for f in _LOGGING + _EVALUATION))
        if not recording:
            return
        self.finding(
            check_id="UCON-001",
            title=f"UCON RFC scenario is still recording for {recording} function module(s)",
            severity="HIGH" if not enforcing else "MEDIUM",
            category=self.CATEGORY,
            description=(
                f"{recording} function module(s) are in the logging or evaluation "
                f"phase and {enforcing} are in the final phase. Only the final phase "
                "enforces the Communication Assembly; the earlier phases record what "
                "is being called and block nothing. A scenario left in logging looks "
                "like UCON is in place while every remote-callable function remains "
                "callable, which is more dangerous than never having started, because "
                "somebody believes the control is live."
            ),
            affected_items=[f"{p}: {n} function module(s)"
                            for p, n in sorted(phases.items())],
            remediation=(
                "In UCONCOCKPIT, review the recorded calls, confirm the allowlist "
                "covers everything the business genuinely needs, then move the "
                "scenario to the final phase. Keep a logging window long enough to "
                "include period-end and year-end processing before switching."
            ),
            details={"phases": phases, "enforcing": enforcing,
                     "recording": recording},
        )

    def check_exposed_but_never_called(self, rows: List[Dict[str, Any]]):
        """THE CHECK THIS MODULE EXISTS FOR — exposure with no use behind it.

        A function module in the default Communication Assembly that recorded zero
        external calls across the logging window is reachable from outside for no
        reason anybody can point at. Every one of them is attack surface that costs
        nothing to remove.

        Read carefully: this is only a finding where the export CARRIES a call
        count. Where it does not, the module says so in the coverage note rather
        than treating an absent column as evidence of silence — the same rule
        `server/edges.py` follows for logon evidence, and for the same reason.
        """
        exposed = [r for r in rows if self._in_default_ca(r)]
        counted = [(r, self._calls(r)) for r in exposed]
        with_counts = [(r, c) for r, c in counted if c is not None]
        if not with_counts:
            return
        never = [r for r, c in with_counts if c == 0]
        if not never:
            return
        names = sorted({_first(r, _FUNCTION_KEYS) for r in never} - {""})
        self.finding(
            check_id="UCON-002",
            title=f"{len(names)} externally callable function module(s) were never called",
            severity="MEDIUM",
            category=self.CATEGORY,
            description=(
                f"{len(names)} function module(s) sit in the default Communication "
                f"Assembly — callable from outside the system — and recorded zero "
                f"external calls over the window this export covers. They are "
                f"reachable for no observed reason. This is the cheapest reduction "
                f"of remote attack surface available in an ABAP system: removing a "
                f"function nobody calls from the assembly breaks nothing and closes "
                f"a real door.\n\n"
                f"The window matters. A function used only at period end will look "
                f"unused in a two-week export, so confirm the recording covers a "
                f"full business cycle before removing anything."
            ),
            affected_items=names[:60],
            affected_objects=[{"type": "function_module", "name": n} for n in names],
            remediation=(
                "In UCONCOCKPIT, review these function modules against the "
                "interfaces that are supposed to exist, and remove the ones no "
                "integration needs from the default Communication Assembly. Where "
                "the logging window is shorter than a full business cycle, extend "
                "it before acting rather than removing on this evidence alone."
            ),
            details={"never_called": len(names),
                     "exposed_with_call_data": len(with_counts),
                     "exposed_total": len(exposed),
                     "window_caveat": "zero calls within the exported window only"},
        )

    def check_powerful_modules_exposed(self, rows: List[Dict[str, Any]]):
        """The two this repository already names as the dangerous ones."""
        hits = []
        for row in rows:
            name = _first(row, _FUNCTION_KEYS).upper()
            if name in POWERFUL_FUNCTION_MODULES and self._in_default_ca(row):
                hits.append(name)
        if not hits:
            return
        for name in sorted(set(hits)):
            self.finding(
                check_id="UCON-003",
                title=f"{name} is callable from outside the system",
                severity="HIGH",
                category=self.CATEGORY,
                description=(
                    f"{name} is in the default Communication Assembly, so any caller "
                    f"who reaches the system over RFC and holds the matching S_RFC "
                    f"authorization can invoke it. It {POWERFUL_FUNCTION_MODULES[name]}."
                ),
                affected_items=[name],
                affected_objects=[{"type": "function_module", "name": name}],
                remediation=(
                    f"Remove {name} from the default Communication Assembly in "
                    f"UCONCOCKPIT unless a named integration requires it. Where it is "
                    f"required, restrict S_RFC to the specific function group for the "
                    f"specific interface users, and confirm no dialog user holds it."
                ),
                details={"function_module": name},
            )

    def check_http_allowlist(self):
        """The HTTP half of UCON, whose config store SAP's own baseline names.

        `ABAP_UCON_HTTP_WHITE_LIST` appears in `data/sap_baseline_requirements.json`,
        derived from SAP's Apache-2.0 policy XML, and `docs/EXPORT_GUIDE.md` records
        that no logical source consumed it. This is that source.
        """
        rows = self.data.get("ucon_http_allowlist")
        if rows is None:
            return
        entries = [r for r in rows if isinstance(r, dict)]
        if entries:
            return
        self.finding(
            check_id="UCON-004",
            title="The UCON HTTP allowlist was supplied and is empty",
            severity="MEDIUM",
            category=self.CATEGORY,
            description=(
                "The UCON HTTP allowlist export contains no entries. With no "
                "allowlist, every activated ICF service is reachable by any caller "
                "that can reach the HTTP port, and the ICF service inventory is the "
                "only thing standing between an external request and the endpoint."
            ),
            affected_items=["HTTP_WHITELIST is empty"],
            remediation=(
                "Populate the UCON HTTP allowlist (transaction UCONCOCKPIT, table "
                "HTTP_WHITELIST, delivered with SAP Note 2573569) so only approved "
                "ICF endpoints are reachable, and confirm it against the SICF "
                "service inventory."
            ),
            references=["SAP Note 2573569"],
            details={"entries": 0},
        )
