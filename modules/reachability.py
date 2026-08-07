"""
Is this custom code reachable?
==============================
The question that separates this product from a code scanner.

SAP's Code Vulnerability Analyzer, Onapsis, SecurityBridge and Fortify all read
ABAP and tell you a statement is dangerous. None of them can tell you whether
anybody can *get* to it, because they see the code and not the estate around it.
This product already holds the estate: the custom-code inventory, the ICF service
tree, the OData catalogue, the Fiori tiles, the RFC destinations.

An SQL injection in a program that is referenced and ran last week is an incident.
The identical statement in a program that nothing references and that has never
been executed is housekeeping. Reporting them at the same severity is how a
1,300-finding code report becomes something nobody works.

────────────────────────────────────────────────────────────────────────────────
WHAT THIS CAN AND CANNOT ANSWER TODAY  (measured 2026-08-07)
────────────────────────────────────────────────────────────────────────────────
Only the object-name join is available from the exports we currently take:

    code_inventory.csv   OBJECT_NAME, OBJECT_TYPE, REFERENCED, LAST_USED   YES

These do NOT join to an ABAP object, because the columns that would carry the
link are not in the export:

    icf_services.csv     ICF_NAME, ICF_ACTIVE, AUTH_REQUIRED    — no handler class
    odata_auth.csv       SERVICE_NAME, ALIAS, AUTH_CHECK, ...   — no DPC class
    fiori_tiles.csv      ... ODATA_SERVICE ...                  — stops at the service
    role_tcodes          role -> tcode                          — no tcode -> program

So `verdict()` returns one of three answers and never guesses:

  * ``reachable``    — positive evidence something reaches it
  * ``unreachable``  — positive evidence nothing does, AND it has never run
  * ``unknown``      — no evidence either way. The common case, and it must NOT be
                       read as either. An absent `code_inventory` export means we
                       know nothing, not that everything is dead.

`docs/CVA_MERGE_PLAN.md` Phase 4b specifies the two extra export columns — the
ICF node's handler class and the OData service's implementation class — that turn
`unknown` into a real answer for internet-facing code. Until then this module is
deliberately conservative: it dampens only when it can prove disuse.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

REACHABLE = "reachable"
UNREACHABLE = "unreachable"
UNKNOWN = "unknown"

#: `LAST_USED` older than this (or absent) stops counting as evidence of use. A
#: program last run three years ago is not "in use" in any sense a risk decision
#: should rest on.
_STALE_DAYS = 365

_TRUE = {"X", "YES", "Y", "TRUE", "1"}
#: Only an EXPLICIT negative counts. An empty cell, or a "-" placeholder, means the
#: export did not say — and "the column was blank" must never become "nothing
#: references this object", which is how absence of evidence turns into a tier
#: reduction on code that is perfectly reachable.
_FALSE = {"NO", "N", "FALSE", "0"}


def _cell(row: Dict[str, Any], *names: str) -> str:
    lowered = {str(k).strip().lower(): v for k, v in row.items()}
    for name in names:
        value = lowered.get(name.lower())
        if value not in (None, ""):
            return str(value).strip()
    return ""


def _parse_date(raw: str) -> Optional[int]:
    """SAP dates arrive as YYYYMMDD. Returns the int form, or None."""
    digits = "".join(c for c in raw if c.isdigit())
    if len(digits) != 8:
        return None
    try:
        year = int(digits[:4])
    except ValueError:
        return None
    return int(digits) if 1990 <= year <= 2100 else None


class ReachabilityIndex:
    """Object name -> what we can prove about who can reach it.

    Built once per scan and shared by every module that emits a code finding, so
    the ATC import and our own scanner agree about the same object.
    """

    def __init__(self, data: Dict[str, Any], *, today: Optional[int] = None):
        self._objects: Dict[str, Dict[str, Any]] = {}
        self._today = today
        self._build(data)

    # ------------------------------------------------------------------ #

    def _build(self, data: Dict[str, Any]) -> None:
        for row in data.get("code_inventory") or []:
            if not isinstance(row, dict):
                continue
            name = _cell(row, "OBJECT_NAME", "OBJECT", "PROGRAM", "REPORT").upper()
            if not name:
                continue
            referenced = _cell(row, "REFERENCED", "IS_REFERENCED", "USED").upper()
            self._objects[name] = {
                "type": _cell(row, "OBJECT_TYPE", "TYPE") or "PROG",
                "referenced": (True if referenced in _TRUE
                               else False if referenced in _FALSE else None),
                "last_used": _parse_date(_cell(row, "LAST_USED", "LAST_EXECUTED",
                                               "LASTUSED")),
            }

    # ------------------------------------------------------------------ #

    def verdict(self, object_name: str) -> Dict[str, Any]:
        """What we can prove about `object_name`, and why.

        `reasons` is returned so the console and the PDF can show the evidence
        rather than a bare verdict. A risk decision a customer cannot audit is a
        risk decision they will not accept.
        """
        name = (object_name or "").upper()
        entry = self._objects.get(name)
        if entry is None:
            return {"state": UNKNOWN,
                    "reasons": ["not listed in the custom-code inventory"]}

        reasons: List[str] = []
        recent = self._is_recent(entry["last_used"])

        if entry["referenced"] is True:
            reasons.append("referenced by other objects")
        if recent is True:
            reasons.append(f"executed on {entry['last_used']}")
        if reasons:
            return {"state": REACHABLE, "reasons": reasons}

        # Only call something unreachable with BOTH halves of the evidence. An
        # object that nothing references but which ran last week is reached
        # somehow — by a job, a tile, an RFC caller we cannot see — and calling it
        # dead would be the dangerous direction to be wrong in.
        if entry["referenced"] is False and recent is not True:
            reasons.append("nothing references it")
            reasons.append("no execution recorded" if entry["last_used"] is None
                           else f"last executed {entry['last_used']}, over "
                                f"{_STALE_DAYS} days ago")
            return {"state": UNREACHABLE, "reasons": reasons}

        return {"state": UNKNOWN,
                "reasons": ["inventory row gives no reference or usage evidence"]}

    def _is_recent(self, last_used: Optional[int]) -> Optional[bool]:
        if last_used is None:
            return None
        today = self._today
        if today is None:
            import datetime
            today = int(datetime.date.today().strftime("%Y%m%d"))
        # A date in the FUTURE is not evidence of recent use. Without this guard
        # the subtraction goes negative, compares as comfortably inside the
        # window, and a placeholder `LAST_USED` of 20991231 makes an unreferenced
        # object read as recently executed — so a clock-skewed or templated export
        # SUPPRESSED the dead-code finding instead of raising one.
        #
        # Treated as no evidence rather than as staleness: an impossible date does
        # not tell us whether the object runs, and inventing either verdict from it
        # would be worse than declining to answer.
        if last_used > today:
            return None
        # Whole-year arithmetic on YYYYMMDD is close enough for a one-year window
        # and keeps this module free of date parsing beyond the stdlib.
        return (today - last_used) < (_STALE_DAYS * 10000) // 365


def stamp(finding_details: Dict[str, Any], index: Optional[ReachabilityIndex],
          object_name: str) -> Dict[str, Any]:
    """Attach a reachability verdict to a finding's `details`.

    Always sets the key, even when the answer is `unknown`: a missing key and
    "we looked and could not tell" are different states, and the prioritiser has
    to be able to tell them apart.
    """
    verdict = (index.verdict(object_name) if index is not None
               else {"state": UNKNOWN, "reasons": ["no custom-code inventory supplied"]})
    finding_details["reachability"] = verdict["state"]
    finding_details["reachability_reasons"] = verdict["reasons"]
    return finding_details
