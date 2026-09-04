"""Which findings are about accounts that are actually in use.

THE PROBLEM THIS EXISTS FOR. A scan of eight systems produces several thousand
findings and every one of them is `derived_from_config`: a list of what COULD be
abused, with nothing saying which of it is live. "SAP_ALL held by an account that
logged on this morning" and "SAP_ALL held by an account dormant for a year" are
the same finding today, and they are not the same problem.

The evidence is already in the box. `logon_events.csv` is ingested, and
`server/edges.py` already reads it to decide whether a graph edge is `used` or
merely `configured`. This applies the same evidence one level up, to findings.

THREE STATES, NEVER TWO, and the third is the one that keeps this honest:

    active       a named account logged on successfully in the exported window
    quiet        every named account was covered by the export and none logged on
    unassessed   no logon export, or it covers none of the accounts named here

`quiet` and `unassessed` look identical in a list and mean opposite things: one
is a measurement, the other is the absence of one. Collapsing them would let a
missing export read as a clean bill, which is the failure this product exists to
report in other tools.

WHY THIS RAISES PRIORITY AND NEVER LOWERS IT. Boosting what is demonstrably live
is safe. Damping what looks quiet is not: an account dormant in a 30-day window
is one break-glass procedure away from being the most dangerous thing in the
estate, and a firefighter account is dormant BY DESIGN. So `quiet` is recorded
and shown, and it moves nothing down.

ABAP ACCOUNTS ONLY, deliberately. `logon_events` is an ABAP export; a HANA
database user or a BTP user has its own logon story and this file has no evidence
about either. Naming them here would be inventing a verdict, so their findings
come back `unassessed` and say so.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, Optional, Sequence, Set

#: Object types this evidence can speak to. `hana_user` and `btp_user` are
#: absent on purpose — see the module docstring.
ABAP_ACCOUNT_TYPES = ("user",)

ACTIVE = "active"
QUIET = "quiet"
UNASSESSED = "unassessed"


def _named_accounts(finding: Dict[str, Any]) -> Set[str]:
    """The ABAP accounts a finding names, upper-cased as the logon export is."""
    out: Set[str] = set()
    for raw in (finding.get("affected_objects") or finding.get("subject") or ()):
        if not isinstance(raw, dict):
            continue
        if str(raw.get("type") or "").strip().lower() not in ABAP_ACCOUNT_TYPES:
            continue
        name = str(raw.get("name") or "").strip().upper()
        if name:
            out.add(name)
    return out


def classify(finding: Dict[str, Any],
             active: Optional[Set[str]],
             observed: Optional[Set[str]]) -> Optional[Dict[str, Any]]:
    """`{state, accounts, ...}` for one finding, or None if it names no account.

    None rather than an `unassessed` verdict: a finding about a profile
    parameter has no account for this evidence to be about, and stamping it
    "activity unassessed" would add a caveat to something the question was never
    asked of. The console can then distinguish "no accounts here" from "accounts
    here, and nothing known about them".
    """
    accounts = _named_accounts(finding)
    if not accounts:
        return None

    # `active is None` means no logon export was supplied at all. Nothing is
    # known about anybody, and that is a different sentence from "these accounts
    # were checked and were quiet".
    if active is None or observed is None:
        return {"state": UNASSESSED, "accounts": sorted(accounts),
                "reason": "no logon export was supplied",
                "assessed": [], "live": []}

    covered = sorted(accounts & observed)
    live = sorted(accounts & active)
    if live:
        return {"state": ACTIVE, "accounts": sorted(accounts),
                "assessed": covered, "live": live,
                "reason": "%s logged on in the exported window"
                          % ", ".join(live[:3])}
    if covered:
        return {"state": QUIET, "accounts": sorted(accounts),
                "assessed": covered, "live": [],
                "reason": "%d account(s) covered by the logon export, none of "
                          "them logged on in the window" % len(covered)}
    return {"state": UNASSESSED, "accounts": sorted(accounts),
            "assessed": [], "live": [],
            "reason": "the logon export names none of these accounts, so "
                      "nothing was settled either way"}


def summarise(verdicts: Iterable[Optional[Dict[str, Any]]]) -> Dict[str, int]:
    """Counts by state, for a caller that wants to report the shape of a run."""
    out = {ACTIVE: 0, QUIET: 0, UNASSESSED: 0, "no_accounts": 0}
    for verdict in verdicts:
        if verdict is None:
            out["no_accounts"] += 1
        else:
            out[verdict["state"]] = out.get(verdict["state"], 0) + 1
    return out
