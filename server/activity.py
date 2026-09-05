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


# --------------------------------------------------------------------------- #
#  The object side: has anything actually been DONE to this thing              #
# --------------------------------------------------------------------------- #
#
# WHAT THE EXPORTS DO AND DO NOT SUPPORT, established by reading them rather
# than by assuming. `security_audit_log.csv` is NOT an event log: its columns are
# CONFIG_NAME, EVENT_CLASS, ACTIVE, PROFILE_TYPE, CLIENT — it records which SAL
# filters are switched on, not one thing anybody did. So "this transaction was
# executed" cannot be said from the corpus this product ingests, and nothing here
# says it.
#
# `change_documents.csv` can: OBJECTCLAS / OBJECTID / USERNAME / UDATE / TCODE is
# who changed which object, when, through which transaction. That is a different
# and weaker claim than execution — it says the object is actively maintained
# rather than a fossil — and it is stated as exactly that.
#
# `access_risk_analysis` already builds an execution index from the same file for
# SoD risks. This generalises the idea to every finding instead of one module's.

#: Object types this evidence can speak to, mapped to the OBJECTCLAS the change
#: document uses. A type absent here gets no verdict rather than a guess.
_CHANGE_CLASSES = {"role": "ROLE", "user": "USER", "profile": "PROFILE"}

CHANGED = "changed"


def _change_index(changes: Optional[Sequence[Dict[str, Any]]]
                  ) -> Optional[Dict[tuple, Dict[str, Any]]]:
    """`(OBJECTCLAS, OBJECTID) -> {who, when, tcode, n}`, or None if absent.

    None where no change-document export was supplied, for the same reason
    `active_users` returns None: nothing is known, and that is not the same
    sentence as "nothing has been changed".
    """
    if changes is None:
        return None
    out: Dict[tuple, Dict[str, Any]] = {}
    for raw in changes:
        if not isinstance(raw, dict):
            continue
        row = {str(k).strip().upper(): v for k, v in raw.items()}
        cls = str(row.get("OBJECTCLAS") or "").strip().upper()
        oid = str(row.get("OBJECTID") or "").strip().upper()
        if not cls or not oid:
            continue
        entry = out.setdefault((cls, oid), {"n": 0, "when": "", "who": "",
                                            "tcode": ""})
        entry["n"] += 1
        when = str(row.get("UDATE") or "").strip()
        # Keep the most recent, comparing as text: these are YYYYMMDD, and a
        # date parser here would be one more thing to be wrong about.
        if when >= entry["when"]:
            entry["when"] = when
            entry["who"] = str(row.get("USERNAME") or row.get("UNAME") or "").strip()
            entry["tcode"] = str(row.get("TCODE") or "").strip()
    return out


def classify_object(finding: Dict[str, Any],
                    index: Optional[Dict[tuple, Dict[str, Any]]]
                    ) -> Optional[Dict[str, Any]]:
    """`{state, ...}` for the objects a finding names, or None if none apply.

    `changed` means a change document names this exact object. It does NOT mean
    the privilege was exercised — no export here evidences that — so the wording
    it carries says "changed", never "used".
    """
    named = []
    for raw in (finding.get("affected_objects") or finding.get("subject") or ()):
        if not isinstance(raw, dict):
            continue
        cls = _CHANGE_CLASSES.get(str(raw.get("type") or "").strip().lower())
        name = str(raw.get("name") or "").strip().upper()
        if cls and name:
            named.append((cls, name))
    if not named:
        return None
    if index is None:
        return {"state": UNASSESSED, "objects": len(named),
                "reason": "no change-document export was supplied"}

    hits = [(cls, name, index[(cls, name)]) for cls, name in named
            if (cls, name) in index]
    if not hits:
        return {"state": QUIET, "objects": len(named),
                "reason": "the change documents record no change to %d object(s) "
                          "named here" % len(named)}
    cls, name, entry = hits[0]
    return {"state": CHANGED, "objects": len(named), "changed": len(hits),
            "last_changed": entry["when"], "changed_by": entry["who"],
            "via": entry["tcode"],
            "reason": "%s was changed on %s by %s%s"
                      % (name, entry["when"] or "an unrecorded date",
                         entry["who"] or "an unrecorded user",
                         " via %s" % entry["tcode"] if entry["tcode"] else "")}


def summarise(verdicts: Iterable[Optional[Dict[str, Any]]]) -> Dict[str, int]:
    """Counts by state, for a caller that wants to report the shape of a run."""
    out = {ACTIVE: 0, QUIET: 0, UNASSESSED: 0, "no_accounts": 0}
    for verdict in verdicts:
        if verdict is None:
            out["no_accounts"] += 1
        else:
            out[verdict["state"]] = out.get(verdict["state"], 0) + 1
    return out
