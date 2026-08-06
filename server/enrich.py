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

log = logging.getLogger(__name__)

#: check_id prefix -> owning team. Longest prefix wins, so a specific family can
#: override its module's default.
TEAM_BY_PREFIX: List[Tuple[str, str]] = [
    ("AUTH-", "authorizations"),
    ("USR-", "identity"),
    ("STDUSR-", "basis"),
    ("IAM-", "identity"),
    ("ARA-", "authorizations"),
    ("RG-", "authorizations"),
    ("GRC-", "identity"),
    ("S4AUTHZ-", "authorizations"),
    ("PARAM-", "basis"),
    ("BASELINE-", "basis"),
    ("TRUST-", "basis"),
    ("JOBCMD-", "basis"),
    ("HANADB-", "basis"),
    ("CRYPTO-", "basis"),
    ("HOTNEWS-", "basis"),
    ("NET-", "integration"),
    ("INTG-", "integration"),
    ("BTP-", "integration"),
    ("RISE-", "integration"),
    ("CODE-", "development"),
    ("FIORI-", "development"),
    ("DPP-", "data_protection"),
    ("LOG-", "data_protection"),
    ("FIN-", "data_protection"),
]

#: Check families the CUSTOMER cannot change in a RISE tenant, because SAP operates
#: that layer. Verified against SAP's published Roles & Responsibilities and SAP KBA
#: 3460793 (RZ10 profile changes cannot be saved from business clients).
#: See docs/RISE_SECURITY_MODEL.md section 2.3.
RISE_PROVIDER_PREFIXES: Tuple[str, ...] = (
    "PARAM-",       # profile parameters — SAP executes, customer may only request
    "BASELINE-",    # ditto; the ECS mandatory hardening set
)

#: Families whose evidence comes from an OS-level artifact. A RISE customer
#: contractually never gets OS access, so these are not assessable there — and
#: saying so is more honest than reporting them as missing or as a failure.
RISE_UNREACHABLE_PREFIXES: Tuple[str, ...] = (
    "INTG-GW-",     # secinfo / reginfo are files on the application server
)

#: Specific check IDs that are OS-sourced even though their family is not.
RISE_UNREACHABLE_CHECKS = frozenset({
    "TRUST-005",    # SAProuter route table
    "TRUST-010",    # message server ACL file
})

#: SLA windows per tier, in days, matching risk_prioritizer.TIER_META's prose.
#: P4 has no clock — a backlog item with a due date is just a lie with a date on it.
SLA_DAYS: Dict[str, Optional[int]] = {"P1": 3, "P2": 7, "P3": 30, "P4": None}

#: Provider-bound work gets a longer clock. Not leniency — the customer does not
#: control the queue, so measuring them against the same window would attribute the
#: provider's latency to them.
SLA_DAYS_PROVIDER: Dict[str, Optional[int]] = {"P1": 14, "P2": 30, "P3": 90, "P4": None}


#: RFC destinations that SAP itself operates in a RISE tenant.
#:
#: SAP's contract distinguishes "technical RFC connections to central systems
#: managed by SAP used for system operations" (SAP's) from "any application-related
#: RFC connection" (the customer's). Flagging one of SAP's own monitoring
#: destinations as a customer misconfiguration wastes their time and costs us
#: credibility on the very first report.
#:
#: THESE ARE HEURISTICS, NOT FACTS. The names below are long-standing SAP support
#: and monitoring destinations, but SAP does not publish an exhaustive list and a
#: customer is free to name their own destination `SAPOSS`. So this classification
#: is a DEFAULT that the customer confirms once per landscape and which then
#: persists — never a silent, unchallengeable verdict. Where it is unsure it says
#: unknown rather than guessing, because a wrong "SAP's problem" hides a real
#: finding, which is worse than an extra one to dismiss.
SAP_MANAGED_DESTINATION_NAMES = frozenset({
    "SAPOSS",           # SAP support / OSS connection
    "SAP-SUPPORT_PORTAL",
    "SAPNET_RFC",
    "SAPNET_R3_READ",
})

#: Prefixes for SAP-operated monitoring and support routes.
SAP_MANAGED_DESTINATION_PREFIXES = (
    "SM_",              # Solution Manager managed-system destinations
    "SAPOSS",
    "SAPNET",
    "SDCC",             # Service Data Control Centre
    "SDCCN",
)


def classify_destination_owner(name: str, host: str = "",
                               deployment_mode: str = "on_prem") -> str:
    """Who operates this RFC destination: ``customer``, ``sap`` or ``unknown``.

    On premise everything is the customer's, so the question does not arise.
    """
    if not deployment_mode.startswith("rise"):
        return "customer"
    n = (name or "").strip().upper()
    if not n:
        return "unknown"
    if n in SAP_MANAGED_DESTINATION_NAMES or n.startswith(SAP_MANAGED_DESTINATION_PREFIXES):
        return "sap"
    # A destination pointing at SAP's own service network is operated by SAP even
    # when the customer created it — but ONLY the support domains, not every
    # *.sap.com host: an Ariba or SuccessFactors tenant is a customer integration
    # the customer very much owns.
    h = (host or "").strip().lower()
    if h.endswith(("sap-ag.de", "sapserv.com")) or ".sapservices." in h:
        return "sap"
    return "customer"


def team_for(check_id: str) -> str:
    cid = (check_id or "").upper()
    best = ""
    team = "unassigned"
    for prefix, name in TEAM_BY_PREFIX:
        if cid.startswith(prefix) and len(prefix) > len(best):
            best, team = prefix, name
    return team


def remediation_owner_for(check_id: str, deployment_mode: str,
                          data_was_supplied: bool = True) -> str:
    """Who can actually act on this finding.

    `data_was_supplied` matters: a gateway ACL check is only "not assessable" when
    we genuinely could not see the data. If the customer obtained the file some
    other way and uploaded it, the finding is real and should be reported as such —
    marking it unassessable because of a general rule would discard evidence they
    went to the trouble of providing.
    """
    cid = (check_id or "").upper()
    if not deployment_mode.startswith("rise"):
        return "customer_fixable"
    if not data_was_supplied and (cid.startswith(RISE_UNREACHABLE_PREFIXES)
                                  or cid in RISE_UNREACHABLE_CHECKS):
        return "not_assessable"
    if cid.startswith(RISE_PROVIDER_PREFIXES):
        return "ticket_to_sap"
    return "customer_fixable"


def sla_due_date(tier: Optional[str], owner: str,
                 from_date: Optional[date] = None) -> Optional[date]:
    table = SLA_DAYS_PROVIDER if owner == "ticket_to_sap" else SLA_DAYS
    days = table.get(tier or "")
    if days is None:
        return None
    return (from_date or date.today()) + timedelta(days=days)


def destination_hosts(data: Optional[Dict[str, Any]]) -> Dict[str, str]:
    """Destination name -> target host, from the SM59 export.

    Kept out of `classify_destination_owner` so that function stays pure and
    testable; the loader shape belongs here.
    """
    out: Dict[str, str] = {}
    for row in ((data or {}).get("rfc_destinations") or []):
        name = (row.get("RFCDEST") or row.get("DESTINATION") or "").strip().upper()
        if name:
            out[name] = (row.get("RFCHOST") or row.get("HOST") or "").strip()
    return out


def enrich(findings: List[Dict[str, Any]], deployment_mode: str = "on_prem",
           supplied_sources: Optional[set] = None,
           dest_hosts: Optional[Dict[str, str]] = None) -> Dict[str, Dict[str, Any]]:
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

    for f in findings:
        cid = (f.get("check_id") or "").upper()
        entry: Dict[str, Any] = {
            "priority_tier": None,
            "priority_score": None,
            "priority_factors": [],
            "owning_team": team_for(cid),
        }

        if prioritizer is not None:
            try:
                res = prioritizer.assess(f)
                entry["priority_tier"] = res.tier
                entry["priority_score"] = int(getattr(res, "score", 0) or 0)
                entry["priority_factors"] = list(getattr(res, "factors", ()) or ())
                entry["priority_rationale"] = getattr(res, "rationale", "")
            except Exception:                           # noqa: BLE001
                log.exception("prioritiser failed on %s", cid)

        supplied = True
        if supplied_sources is not None:
            # Only the two OS-sourced families need this distinction; everything
            # else is assessable whenever the module produced a finding at all.
            supplied = not (cid.startswith(RISE_UNREACHABLE_PREFIXES)
                            or cid in RISE_UNREACHABLE_CHECKS) or bool(
                supplied_sources & {"gw_secinfo", "gw_reginfo", "saprouttab", "ms_acl"})

        owner = remediation_owner_for(cid, deployment_mode, supplied)

        # A finding about a destination SAP itself operates is not the customer's
        # to fix, whatever its check family says. Only downgrade when EVERY
        # destination named is SAP's: a finding spanning both is still actionable
        # on the customer's own destinations, and marking it provider-owned would
        # hide real work.
        if owner == "customer_fixable" and dest_hosts is not None:
            dests = [o.get("name", "") for o in (f.get("affected_objects") or ())
                     if o.get("type") == "destination"]
            if dests:
                owners = {classify_destination_owner(
                    d, dest_hosts.get((d or "").upper(), ""), deployment_mode)
                    for d in dests}
                if owners == {"sap"}:
                    owner = "provider_owned"
                    entry["ownership_note"] = (
                        "Every RFC destination named here is one SAP operates in a "
                        "RISE tenant. Confirm this classification once for your "
                        "landscape — it is a naming heuristic, not a fact SAP "
                        "publishes.")

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
