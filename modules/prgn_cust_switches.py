"""
PRGN_CUST customizing switches — three SAP Baseline v2.6 requirements
=====================================================================
SAP's Baseline v2.6 added three requirements that all read the same customizing
table, PRGN_CUST — the Profile Generator's central switch table (transaction
SM30 view PRGN_CUST / report PRGN_CUST_SWITCHES). Each row is one switch: a
column that SAP's policy names `ID`, and its value, which SAP's policy names
`PATH`. This module reads that one export and answers the three requirements
from it.

    AUTHASSIGN-A  Prohibit user–role assignments while transports move.
                  US_ASGM_TRANSPORT = NO blocks assignment during export,
                  USER_REL_IMPORT = NO blocks it during import. Left unset, a
                  transport can carry a role assignment into production without
                  the target system's own assignment controls ever seeing it.
    USRTYP-A      REF_USER_CHECK = E restricts which user types may serve as a
                  reference user, so a dialog user cannot inherit authorizations
                  by reference from an account nobody reviews as privileged.
    USRCHAR-A     BNAME_RESTRICT = XXX or ALL forbids 'wide' (multi-byte) space
                  characters in user names, which are used to forge a name that
                  renders identically to a real account (SAP Note 1731549).

WHY A CHECK ID PER REQUIREMENT, NOT ONE PER SWITCH. The three requirements route
to different reviews and read as three separate defects, so they take three ids
(AUTHASSIGN-001, USRTYP-001, USRCHAR-001) rather than a single PRGN_CUST- family.
AUTHASSIGN-001 covers BOTH transport switches because they are the two halves of
one control — one finding, listing whichever half is wrong, is the honest unit.

PROVENANCE. Every value compared here is transcribed from SAP's own CSA policy
predicate (BL260_3ASECSTO / the v2.6 ABAP_ALL baseline, Apache-2.0), carried
verbatim in each finding's `references` exactly as the security_params BASELINE
rules carry theirs. The comparison value is transcribable even though SAP's SQL
predicate is not executable here.

ABSENCE. PRGN_CUST holds a row only for a switch that was explicitly maintained,
so a switch ABSENT from a supplied export is unset and runs on its default —
which for all three is the permissive behaviour the requirement exists to close.
An absent switch is therefore reported (with its state named as "not set"), but
only when the export was supplied at all: with no PRGN_CUST export the module
stays silent and the finding's evidence marker records the gap, like every other
check here.

The `category` reused on all three is "User & Authorization", which already
exists in ComplianceMapper.CATEGORY_THEMES; the AUTHASSIGN-/USRTYP-/USRCHAR-
prefixes route to the authorizations team (rise_ownership.TEAM_BY_PREFIX), the
team that owns PRGN_CUST and the Profile Generator.
"""
from typing import Any, Dict, List

from modules.base_auditor import BaseAuditor

#: Logical data-source key. A key in modules/data_loader.py's FILE_MAP.
PRGN_CUST = "prgn_cust"

#: Column vocabularies. SAP's policy names the switch column `ID` and its value
#: `PATH`; an SE16/SM30 download of PRGN_CUST or a hand-made extract spells them
#: differently, so several aliases are accepted rather than one asserted.
_SWITCH_KEYS = ("ID", "SWITCH", "RECNAME", "NAME", "PARAM", "PARAMETER", "FIELDNAME")
_VALUE_KEYS = ("PATH", "VALUE", "VAL", "LOW", "SETTING", "CONTENT")


def _cell(row: Dict[str, Any], *names: str) -> str:
    """First non-empty value among `names`, matched case-insensitively."""
    lowered = {str(k).strip().lower(): v for k, v in row.items()}
    for name in names:
        value = lowered.get(name.lower())
        if value not in (None, ""):
            return str(value).strip()
    return ""


class PrgnCustSwitchAuditor(BaseAuditor):
    """SAP Baseline v2.6 requirements that read table PRGN_CUST."""

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_transport_user_assignments()
        self.check_reference_user_type()
        self.check_username_wide_spaces()
        return self.findings

    # ------------------------------------------------------------------ input
    def _switches(self) -> Dict[str, str]:
        """`{SWITCH_ID (upper): value}` from the supplied PRGN_CUST export.

        An absent or non-list source yields {} and every check stays silent —
        a customer who did not send this extract is told nothing about it.
        """
        raw = self.data.get("prgn_cust")
        if not isinstance(raw, list):
            return {}
        out: Dict[str, str] = {}
        for row in raw:
            if not isinstance(row, dict):
                continue
            switch = _cell(row, *_SWITCH_KEYS).upper()
            if switch:
                out[switch] = _cell(row, *_VALUE_KEYS)
        return out

    def _supplied(self) -> bool:
        return isinstance(self.data.get("prgn_cust"), list)

    @staticmethod
    def _obj(switch: str) -> Dict[str, Any]:
        # Identity is the switch name; the value is the finding, not the node, so
        # it is not a qualifier (a qualifier that changed on fix would churn the
        # graph node).
        return {"type": "config_switch", "name": switch}

    # ------------------------------------------------------------------ checks
    def check_transport_user_assignments(self):
        """AUTHASSIGN-A: US_ASGM_TRANSPORT = NO and USER_REL_IMPORT = NO."""
        if not self._supplied():
            return
        switches = self._switches()
        offenders: List[str] = []
        objects: List[Dict[str, Any]] = []
        for switch in ("US_ASGM_TRANSPORT", "USER_REL_IMPORT"):
            value = switches.get(switch)
            if value is None:
                offenders.append(f"{switch}: not set (defaults to permitting "
                                 f"user assignment during transport)")
                objects.append(self._obj(switch))
            elif value.strip().upper() != "NO":
                offenders.append(f"{switch} = {value} (must be NO)")
                objects.append(self._obj(switch))
        if not offenders:
            return
        self.finding(
            check_id="AUTHASSIGN-001",
            title="User assignments are not blocked while transports move",
            severity=self.SEVERITY_MEDIUM,
            category="User & Authorization",
            description=(
                "SAP Baseline AUTHASSIGN-A requires PRGN_CUST switches "
                "US_ASGM_TRANSPORT and USER_REL_IMPORT to be NO so that a "
                "transport cannot carry a user-to-role assignment past the "
                "target system's own assignment controls. The following are "
                "not set to NO:\n- " + "\n- ".join(offenders)),
            affected_items=offenders,
            remediation=(
                "In table PRGN_CUST (SM30) set US_ASGM_TRANSPORT = NO and "
                "USER_REL_IMPORT = NO, then re-export. See SAP Notes 1723881 "
                "(export) and 571276 (import)."),
            references=[
                "SAP Security Baseline AUTHASSIGN-A",
                "SAP policy check AUTHASSIGN-A_a — "
                "ID = 'US_ASGM_TRANSPORT' and UPPER(PATH) = 'NO'",
                "SAP policy check AUTHASSIGN-A_b — "
                "ID = 'USER_REL_IMPORT' and UPPER(PATH) = 'NO'",
            ],
            affected_objects=objects,
            scope="aggregate",
        )

    def check_reference_user_type(self):
        """USRTYP-A: REF_USER_CHECK = E."""
        if not self._supplied():
            return
        switches = self._switches()
        value = switches.get("REF_USER_CHECK")
        if value is not None and value.strip().upper() == "E":
            return
        state = "not set" if value is None else f"= {value}"
        self.finding(
            check_id="USRTYP-001",
            title="Reference-user type is not restricted (REF_USER_CHECK not E)",
            severity=self.SEVERITY_MEDIUM,
            category="User & Authorization",
            description=(
                "SAP Baseline USRTYP-A requires PRGN_CUST switch REF_USER_CHECK "
                "to be E, so only reference-type users may be assigned as a "
                f"reference user. It is {state}. Without it a dialog or system "
                "user can be named as a reference user and its authorizations "
                "inherited by reference, outside the review privileged accounts "
                "receive."),
            affected_items=[f"REF_USER_CHECK {state} (must be E)"],
            remediation=(
                "In table PRGN_CUST (SM30) set REF_USER_CHECK = E and re-export. "
                "Confirm no non-reference user is currently assigned as a "
                "reference user (SU01)."),
            references=[
                "SAP Security Baseline USRTYP-A",
                "SAP policy check USRTYP-A_a — "
                "ID = 'REF_USER_CHECK' and PATH = 'E'",
            ],
            affected_objects=[self._obj("REF_USER_CHECK")],
            scope="object",
        )

    def check_username_wide_spaces(self):
        """USRCHAR-A: BNAME_RESTRICT in ('XXX', 'ALL')."""
        if not self._supplied():
            return
        switches = self._switches()
        value = switches.get("BNAME_RESTRICT")
        if value is not None and value.strip().upper() in ("XXX", "ALL"):
            return
        state = "not set" if value is None else f"= {value}"
        self.finding(
            check_id="USRCHAR-001",
            title="User names may contain 'wide' space characters (BNAME_RESTRICT)",
            severity=self.SEVERITY_MEDIUM,
            category="User & Authorization",
            description=(
                "SAP Baseline USRCHAR-A requires PRGN_CUST switch BNAME_RESTRICT "
                "to be XXX or ALL, which forbids multi-byte 'wide' space "
                f"characters in user names. It is {state}. Wide spaces let an "
                "attacker create a user name that renders identically to a real "
                "account, so an operator approving or auditing it cannot tell "
                "the two apart (SAP Note 1731549)."),
            affected_items=[f"BNAME_RESTRICT {state} (must be XXX or ALL)"],
            remediation=(
                "In table PRGN_CUST (SM30) set BNAME_RESTRICT = ALL (or XXX for "
                "the documented narrower set) and re-export. SAP notes this "
                "matters most in development systems, where new names are "
                "created most freely."),
            references=[
                "SAP Security Baseline USRCHAR-A",
                "SAP policy check USRCHAR-A_a.1 — "
                "ID = 'BNAME_RESTRICT' and PATH in ('XXX', 'ALL')",
            ],
            affected_objects=[self._obj("BNAME_RESTRICT")],
            scope="object",
        )
