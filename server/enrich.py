"""
Finding enrichment: priority, ownership and remediation content.

Three things are attached to a finding at ingest time that the auditor modules do
not know about:

  1. **Priority** — `risk_prioritizer.py` already produces an explainable P1–P4 with
     named factors and an SLA window. It ran only inside report rendering, so the
     stored finding had no tier at all and the console could not sort by it.
  2. **Owning team** — which SAP team fixes this. Findings route to a *team*, not a
     person; that is what makes a 300-finding queue consumable rather than a wall.
  3. **Remediation owner** — WHO CAN ACT, which in RISE is not the same as who
     should. See below; this is the difference between an action and noise.

WHY REMEDIATION OWNER IS DEPLOYMENT-DEPENDENT
----------------------------------------------
Under RISE, profile parameter maintenance is SAP's; the customer can read a bad
parameter and cannot save a change to it. A report that tells them to "set
login/min_password_lng = 8" is unactionable — they have to raise a service request,
and their console should hand them the text for it.

The same check on an on-premise system is simply theirs to fix.

So the owner is derived from (check family x deployment mode), and the SLA clock is
NOT the same for the two: a ticket_to_sap finding's time-to-fix depends on the
provider's queue, so holding the customer to a 7-day window for it would produce a
breach report measuring the wrong organisation.
"""
from __future__ import annotations

import logging
from datetime import date, timedelta
from typing import Any, Dict, List, Optional, Tuple
from modules.deployment_modes import is_rise

log = logging.getLogger(__name__)

# ── Ownership moved to modules/rise_ownership.py ──────────────────────────────
# It answers "who can change this?" and needed nothing from the server: stdlib and
# modules.deployment_modes only. Living here meant the OFFLINE scanner — the one a
# customer runs before buying anything — produced reports with no ownership tag on
# any finding, which section 7.4 of the RISE model calls the argument that
# justifies the purchase. Re-exported under the original names so every existing
# import and test keeps working; this module is now a caller, not the definition.
from modules.rise_ownership import (           # noqa: F401  (re-export)
    OS_SOURCED_EVIDENCE,
    RISE_PROVIDER_PREFIXES,
    RISE_UNREACHABLE_CHECKS,
    RISE_UNREACHABLE_PREFIXES,
    SAP_MANAGED_DESTINATION_NAMES,
    SAP_MANAGED_DESTINATION_PREFIXES,
    SLA_DAYS,
    SLA_DAYS_PROVIDER,
    TEAM_BY_PREFIX,
    classify_destination_owner,
    destination_hosts,
    owner_for_finding,
    remediation_owner_for,
    sla_due_date,
    team_for,
)


def enrich(findings: List[Dict[str, Any]], deployment_mode: str = "on_prem",
           supplied_sources: Optional[set] = None,
           dest_hosts: Optional[Dict[str, str]] = None,
           data: Optional[Dict[str, Any]] = None) -> Dict[str, Dict[str, Any]]:
    """Compute priority, team, owner and SLA for a run's findings.

    Returns a mapping keyed by `id(finding)` so the caller can look each one up
    without mutating the auditor's dict — the same finding objects are consumed by
    the report renderers, and quietly adding keys to them there has bitten before.

    Degrades rather than fails: if the prioritiser raises on one finding, that
    finding simply has no tier and the rest of the run is unaffected.
    """
    out: Dict[int, Dict[str, Any]] = {}

    try:
        from modules.risk_prioritizer import RiskPrioritizer
        prioritizer = RiskPrioritizer()
    except Exception:                                   # noqa: BLE001
        log.exception("risk prioritiser unavailable; findings will have no tier")
        prioritizer = None

    # WHICH ACCOUNTS ARE ACTUALLY IN USE, read once for the whole run.
    #
    # `logon_events` is already ingested and already decides whether a graph edge
    # is `used` or merely `configured`. The same evidence answers a bigger
    # question one level up — which of several thousand config findings are about
    # accounts somebody is actually logging on as — and `server/activity.py`
    # keeps the three states apart. Absent `data` (the upload path carries
    # findings, not sources) every verdict is `unassessed`, which is the truth
    # there rather than a degradation.
    from server import activity as activity_mod
    from server.edges import active_users, observed_users
    active = active_users(data)
    observed = observed_users(data)
    # The object side of the same question: not "is the account live" but "has
    # anything been done to the thing this finding is about". `None` where no
    # change-document export was supplied, which is not the same as no changes.
    changes = activity_mod._change_index(
        data.get("change_documents") if data else None)

    for f in findings:
        cid = (f.get("check_id") or "").upper()
        entry: Dict[str, Any] = {
            "priority_tier": None,
            "priority_score": None,
            "priority_factors": [],
            "owning_team": team_for(cid),
        }

        verdict = activity_mod.classify(f, active, observed)
        if verdict is not None:
            entry["account_activity"] = verdict
        obj_verdict = activity_mod.classify_object(f, changes)
        if obj_verdict is not None:
            entry["object_activity"] = obj_verdict

        if prioritizer is not None:
            try:
                # A COPY, because this function does not mutate the auditor's
                # dicts — the same objects reach the report renderers, and
                # quietly adding keys here has bitten before. The prioritiser
                # reads evidence out of `details`, exactly as it already does
                # for the code-reachability verdict.
                extra = {}
                if verdict is not None:
                    extra["account_activity"] = verdict
                if obj_verdict is not None:
                    extra["object_activity"] = obj_verdict
                res = prioritizer.assess(
                    {**f, "details": {**(f.get("details") or {}), **extra}}
                    if extra else f)
                entry["priority_tier"] = res.tier
                entry["priority_score"] = int(getattr(res, "score", 0) or 0)
                entry["priority_factors"] = list(getattr(res, "factors", ()) or ())
                entry["priority_rationale"] = getattr(res, "rationale", "")
            except Exception:                           # noqa: BLE001
                log.exception("prioritiser failed on %s", cid)

        owner, note = owner_for_finding(f, deployment_mode, dest_hosts,
                                        supplied_sources)
        if note:
            entry["ownership_note"] = note

        entry["remediation_owner"] = owner
        entry["due_date"] = sla_due_date(entry["priority_tier"], entry["remediation_owner"])
        out[id(f)] = entry

    return out


def kb_content(check_id: str) -> Tuple[str, str]:
    """Detailed risk narrative and step-by-step remediation from the findings KB.

    Returns ``("", "")`` when the KB has nothing, so the caller falls back to the
    finding's own description and remediation rather than rendering an empty panel.
    """
    try:
        from modules.finding_kb import FindingKB
        entry = _kb().lookup(check_id)
    except Exception:                                   # noqa: BLE001
        return "", ""
    if not entry:
        return "", ""
    return entry.get("risk", "") or "", entry.get("mitigation", "") or ""


_KB_CACHE = None


def _kb():
    """Load the 323-entry knowledge base once per process, not once per finding."""
    global _KB_CACHE
    if _KB_CACHE is None:
        from modules.finding_kb import FindingKB
        _KB_CACHE = FindingKB()
    return _KB_CACHE
