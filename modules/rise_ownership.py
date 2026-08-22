"""Who owns a finding in a RISE tenant: the customer, SAP, or nobody yet.

WHY THIS MOVED OUT OF `server/`
-------------------------------
All of it lived in `server/enrich.py`, so only the CLIENT-SERVER product could
answer "is this mine to fix?". The offline scanner — the primary distribution,
the one a customer runs before they have bought anything — produced reports with
no ownership on any finding at all. `docs/RISE_SECURITY_MODEL.md` section 7.4
calls that tag "the argument that justifies buying anything at all in a RISE
tenant", and it was missing from the artefact that has to make the argument.

Nothing here needed a database. The whole block imported stdlib and
`modules.deployment_modes` and nothing else, so it belongs in `modules/` beside
`ecs_baseline` — the same shape of shared oracle, for the same reason: several
callers form an opinion about the same question, and before there was one home
for it they could disagree.

WHAT THIS ANSWERS, AND WHAT IT DOES NOT
---------------------------------------
This is "who can CHANGE it". `modules/rise_reachability.py` is "who can EXPORT
it", and they are genuinely different questions about the same estate: profile
parameters are freely exportable via RSPARAM and unfixable without an SAP ticket,
so `security_params` is `read_only` there and `PARAM-*` is `ticket_to_sap` here.
Neither derives from the other. They agree where they overlap because both read
the same published Roles & Responsibilities, not because one consults the other.

THE HEURISTIC IS LABELLED AS ONE
--------------------------------
`classify_destination_owner` guesses from naming patterns SAP does not publish
exhaustively, and says `unknown` rather than guessing when unsure — a wrong "SAP's
problem" hides a real finding, which is worse than an extra one to dismiss. Every
downgrade it drives carries `ownership_note` telling the customer to confirm the
classification once for their landscape.
"""
from __future__ import annotations

from datetime import date, timedelta
from typing import Any, Dict, List, Optional, Tuple

from modules.deployment_modes import is_rise


#: check_id prefix -> owning team. Longest prefix wins, so a specific family can
#: override its module's default.
TEAM_BY_PREFIX: List[Tuple[str, str]] = [
    ("ATC-", "development"),
    ("ABAP-", "development"),
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
    ("CAPX-", "development"),
    # `basis`, NOT "configuration" — which is not one of the seven teams the
    # schema allows and was rejected by check_definition_owning_team_check the
    # first time a CSA finding reached the database. It never had, because
    # cloudalm_verdicts produced nothing until its fixture arrived: an invalid
    # value in a prefix table costs nothing until the prefix is used. CSA
    # verdicts are SAP's Baseline results over ABAP and HANA configuration —
    # profile parameters, audit settings, gateway ACLs — which is the same
    # ground PARAM-, BASELINE- and HANADB- all route to basis for.
    ("CSA-", "basis"),
    ("CODE-", "development"),
    ("FIORI-", "development"),
    ("DPP-", "data_protection"),
    ("LOG-", "data_protection"),
    ("LREV-", "data_protection"),   # audit-log retrospective review — same owner as LOG-
    ("FIN-", "data_protection"),
    ("MDC-", "data_protection"),
    ("VBM-", "data_protection"),
    # Resilience & recovery readiness. Deliberately NOT under the LOG- prefix it
    # was first written with, for two reasons that were both measured:
    #   * LOG-RET-001 and LOG-IR-001 already existed in modules/log_monitoring.py,
    #     so two unrelated checks shared an id — which collides in the finding KB
    #     and in fingerprinting, and the uniqueness test did not look across
    #     modules.
    #   * modules/fair_adapter.py:_is_detection() matches on the check-id prefix,
    #     so everything under LOG- was priced as a DETECTION gap. A missing backup
    #     is not a detection gap, and the module's docstring claimed the prefix
    #     made it under-price when in fact it mis-priced.
    ("WDISP-", "basis"),   # instance profile maintenance
    ("UCON-", "integration"),   # remote-callable exposure is interface work
    ("RES-", "basis"),
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
    if not is_rise(deployment_mode):
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
    if not is_rise(deployment_mode):
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

def owner_for_finding(finding: Dict[str, Any], deployment_mode: str,
                      dest_hosts: Optional[Dict[str, str]] = None,
                      supplied_sources: Optional[set] = None
                      ) -> Tuple[str, Optional[str]]:
    """`(remediation_owner, ownership_note)` for one finding.

    Extracted so the offline scanner and the server reach the same verdict from
    the same code. It was inline in `server/enrich.py`'s loop, which is why the
    offline path had no way to share it short of copying — and a copied ownership
    rule that drifts is how one product tells a customer two different things
    about the same finding.

    THE DESTINATION DOWNGRADE, AND WHY IT IS ALL-OR-NOTHING. A finding naming only
    destinations SAP operates is not the customer's to fix whatever its check
    family says. But a finding spanning both is still actionable on their own
    destinations, and marking it provider-owned would hide real work — so the
    downgrade needs EVERY destination to be SAP's.
    """
    cid = (finding.get("check_id") or "").upper()

    supplied = True
    if supplied_sources is not None:
        # Only the two OS-sourced families need this distinction; everything else
        # is assessable whenever the module produced a finding at all.
        supplied = not (cid.startswith(RISE_UNREACHABLE_PREFIXES)
                        or cid in RISE_UNREACHABLE_CHECKS) or bool(
            set(supplied_sources) & OS_SOURCED_EVIDENCE)

    owner = remediation_owner_for(cid, deployment_mode, supplied)
    note: Optional[str] = None

    if owner == "customer_fixable" and dest_hosts is not None:
        dests = [o.get("name", "") for o in (finding.get("affected_objects") or ())
                 if o.get("type") == "destination"]
        if dests:
            owners = {classify_destination_owner(
                d, dest_hosts.get((d or "").upper(), ""), deployment_mode)
                for d in dests}
            if owners == {"sap"}:
                owner = "provider_owned"
                note = ("Every RFC destination named here is one SAP operates in a "
                        "RISE tenant. Confirm this classification once for your "
                        "landscape — it is a naming heuristic, not a fact SAP "
                        "publishes.")
    return owner, note


#: The logical sources behind the OS-sourced check families. Named once here
#: rather than spelled out at the call site, because `remediation_owner_for`'s
#: `data_was_supplied` argument is only meaningful against this exact set.
OS_SOURCED_EVIDENCE = frozenset({"gw_secinfo", "gw_reginfo", "saprouttab", "ms_acl"})
