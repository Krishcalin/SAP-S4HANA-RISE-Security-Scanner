"""Perceived Threats: everything observed from SAP LogServ, in one place.

MonitorRisk runs retrospective, offline detection over SAP LogServ logs (OCSF or
raw). Those findings — threat patterns, violations, per-class log review and the
config-vs-log correlation — are otherwise scattered across the queue and three
different domains. This groups them into one "what the logs observed" view, by log
class, and adds a section on whether the LogServ pipeline itself is forwarding
completely (a class that is not forwarded is a blind spot, not a clean result).

CONTENT, NOT CHECKS. This module emits no findings and defines no check ids; it is
a grouping of EXISTING check families by check-id prefix, for one screen. It lives
in server/ rather than modules/ deliberately, so it is not discovered as an audit
module and does not move the module / check counts.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

#: Severity buckets, worst first.
_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

#: Observed threats, grouped by log class / subject. Each group folds in the
#: config-vs-log correlation family (CORR-*) for its subject. Prefixes are matched
#: with str.startswith; none is a prefix of another across groups.
GROUPS: List[Dict[str, Any]] = [
    {"id": "audit_behaviour", "label": "Audit-log behaviour",
     "prefixes": ("LREV-PAT",),
     "blurb": "Threat patterns the Security Audit Log recorded — off-hours "
              "privileged logons, failed-then-success runs, default accounts "
              "active, debug activity, high-volume table access, audit-config "
              "changes, rare-terminal logons, external OS commands, password "
              "spraying."},
    {"id": "violations", "label": "Access violations",
     "prefixes": ("LVIO-",),
     "blurb": "Emergency-access (firefighter) use and privileged change outside "
              "business hours, crossed against the reviewed window."},
    {"id": "gateway", "label": "Gateway / RFC",
     "prefixes": ("GWLOG", "CORR-GW"),
     "blurb": "What the RFC gateway log recorded — external programs registered "
              "or started, blocked connections — and whether a gateway exposure "
              "is actually being used, not merely misconfigured."},
    {"id": "hana", "label": "HANA database",
     "prefixes": ("HANALOG", "CORR-HANA"),
     "blurb": "HANA audit-config changes, privileged database activity and failed "
              "logons, and privileged access used where auditing is weak."},
    {"id": "icm_web", "label": "ICM / web",
     "prefixes": ("ICMLOG", "CORR-ICM"),
     "blurb": "Admin web paths accessed, HTTP scanning and remote-execution "
              "endpoints seen in the ICM log, and exposed web services being "
              "reached."},
    {"id": "network", "label": "Network",
     "prefixes": ("NETLOG", "CORR-NET"),
     "blurb": "Connections to SAP service ports, blocked attempts and public "
              "sources reaching a service port, and exposed network services "
              "being reached."},
]

#: LogServ pipeline health — not threats, but they say whether the observations
#: above are complete. Shown in their own section on the screen.
HEALTH: List[Dict[str, Any]] = [
    {"id": "ingestion", "label": "LogServ ingestion health",
     "prefixes": ("LSRV-",),
     "blurb": "Whether SAP LogServ is forwarding each log class, with readable "
              "timestamps. A class that is not forwarded is a blind spot, not a "
              "clean result."},
    {"id": "audit_coverage", "label": "Audit-log coverage",
     "prefixes": ("LREV-SRC", "LREV-FLT", "LREV-WIN"),
     "blurb": "Whether the Security Audit Log could answer the question at all — "
              "supplied, filtered to cover every client, and over a long enough "
              "window."},
]

_ALL = GROUPS + HEALTH
_TIER_RANK = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
_SEV_RANK = {s: i for i, s in enumerate(_SEVERITIES)}


def group_for(check_id: Optional[str]):
    """(section, group_id) for a LogServ check id, else (None, None).

    section is "threat" for a GROUPS family, "health" for a HEALTH family. GROUPS
    is checked first so LREV-PAT lands in audit_behaviour rather than being caught
    by the LREV-* capability families in HEALTH.
    """
    cid = str(check_id or "")
    for g in GROUPS:
        if cid.startswith(g["prefixes"]):
            return "threat", g["id"]
    for h in HEALTH:
        if cid.startswith(h["prefixes"]):
            return "health", h["id"]
    return None, None


def _empty(g: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": g["id"], "label": g["label"], "blurb": g["blurb"],
            "counts": {s: 0 for s in _SEVERITIES}, "total": 0, "findings": []}


def _rank(f: Dict[str, Any]):
    return (_TIER_RANK.get(str(f.get("priority_tier") or ""), 9),
            _SEV_RANK.get(str(f.get("severity") or "").upper(), 9),
            str(f.get("check_id") or ""))


def roll_up(findings: Sequence[Dict[str, Any]],
            coverage: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Group LogServ findings into the threat groups and the health section.

    `findings` is the lightweight projection queries.findings_for_domains returns.
    Non-LogServ findings are ignored — they belong on the queue / domains screens.
    `coverage` supplies the `measured` timestamp, as on the domains screen.
    """
    buckets = {g["id"]: _empty(g) for g in _ALL}

    for f in findings:
        _section, gid = group_for(f.get("check_id"))
        if gid is None:
            continue
        b = buckets[gid]
        b["findings"].append({
            "id": f.get("id"), "check_id": f.get("check_id"),
            "severity": f.get("severity"), "priority_tier": f.get("priority_tier"),
            "title": f.get("title"), "category": f.get("category"),
            "sid": f.get("sid"), "state": f.get("state"),
        })
        b["total"] += 1
        sev = str(f.get("severity") or "").upper()
        if sev in b["counts"]:
            b["counts"][sev] += 1

    for b in buckets.values():
        b["findings"].sort(key=_rank)

    groups = [buckets[g["id"]] for g in GROUPS]
    health = [buckets[h["id"]] for h in HEALTH]
    return {
        "groups": groups,
        "health": health,
        "measured": (coverage or {}).get("measured"),
        "totals": {
            "threats": sum(g["total"] for g in groups),
            "health": sum(h["total"] for h in health),
            "counts": {s: sum(g["counts"][s] for g in groups) for s in _SEVERITIES},
        },
    }
