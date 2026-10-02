"""Vulnerabilities vs Mis-Configuration: the two posture lenses over findings.

The product has no stored "this is a vulnerability / this is a misconfiguration"
flag — every classifier-like field (category, owning_team, responsibility) is
something else. So the partition is derived from `check_id` prefix + `category`,
exactly as the domain roll-up and the other lens screens already do, over the
lightweight projection `queries.findings_for_domains` returns.

  * VULNERABILITY — a known flaw that needs a fix: a missing SAP Security Note
    (HOTNEWS-*, incl. actively-exploited notes) or an exploitable custom-code
    weakness (our ABAP SAST, imported SAP ATC/CVA, or the code scan).
  * MIS-CONFIGURATION — the system is set up insecurely: a profile parameter,
    policy, interface, authorization or other setting weaker than the baseline.

Deliberately in NEITHER bucket (they are a different kind of thing, or they have
their own screen): Segregation-of-Duties & GRC, compliance/process controls
(SOX, master-data, vendor), RISE shared-responsibility, resilience readiness,
imported SAP CloudALM verdicts, code hygiene/inventory, evidence/coverage/
suppression meta, and the SAP LogServ observations (those are Perceived Threats).

CONTENT, NOT CHECKS. This module emits no findings and defines no check ids; it
is a grouping of EXISTING checks by prefix/category, for two screens. It lives in
server/ rather than modules/ so it is not discovered as an audit module and does
not move the module / check counts.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

#: Severity buckets, worst first.
_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

# ── Vulnerabilities, grouped by source/type ──────────────────────────────────
VULN_GROUPS: List[Dict[str, Any]] = [
    {"id": "patches", "label": "Missing SAP Security Notes",
     "prefixes": ("HOTNEWS-",),
     "blurb": "SAP Security Notes that are missing or only partially applied — "
              "including HotNews and actively-exploited notes — leaving known "
              "CVEs unpatched on the declared stack."},
    {"id": "native_code", "label": "Custom code — our scanner",
     "prefixes": ("ABAP-",),
     "blurb": "Exploitable weaknesses our ABAP SAST found in custom code: "
              "injection, missing authorization, hardcoded secrets, weak crypto."},
    {"id": "atc_code", "label": "Custom code — SAP ATC / CVA",
     "prefixes": ("ATC-",),
     "blurb": "Code weaknesses imported from SAP's own Code Vulnerability "
              "Analyzer / ATC results."},
    {"id": "other_code", "label": "Other code weaknesses",
     "prefixes": ("CODE-INJ", "CODE-STMT"),
     "blurb": "Injection and dangerous-statement findings from the transport / "
              "code scan outside the ABAP SAST engine."},
]

#: Ids inside the vulnerability prefixes that are NOT live flaws — coverage /
#: disclosure / self-check meta. Checked before the prefix match.
_NOT_VULN_IDS = frozenset({"HOTNEWS-COVERAGE", "HOTNEWS-000",
                           "HOTNEWS-005", "HOTNEWS-011"})
_NOT_VULN_PREFIXES = ("ABAP-COV", "ABAP-LEX", "ABAP-NOSEC", "ATC-GOV")

# ── Mis-Configuration, grouped by subject. Classified by category, with a few
#    check-id prefixes for the families that share the "Code & Transport
#    Security" category with vulnerabilities. ──────────────────────────────────
MISCONFIG_GROUPS: List[Dict[str, Any]] = [
    {"id": "parameters", "label": "Parameters & policy", "prefixes": (),
     "categories": ("Security Baseline Parameters", "Security Parameters",
                    "Password Policy", "Login Security"),
     "blurb": "Profile parameters, password and logon policy weaker than the "
              "SAP Security Baseline."},
    {"id": "authorizations", "label": "Authorizations & users", "prefixes": (),
     "categories": ("ABAP Authorization & Critical Access",
                    "S/4HANA & Cloud Authorization", "User & Authorization",
                    "System Trust & Standard Users"),
     "blurb": "Excessive or critical authorizations, standard and technical "
              "users, and system trust relationships."},
    {"id": "network", "label": "Network, RFC & interfaces", "prefixes": (),
     "categories": ("Gateway Security", "RFC Security",
                    "Network & Service Exposure", "Network & Integration Layer",
                    "Unified Connectivity (UCON)", "Web Dispatcher Security"),
     "blurb": "Gateway, RFC, UCON, Web Dispatcher and network exposure left open "
              "or unrestricted."},
    {"id": "crypto", "label": "Cryptography & secure store", "prefixes": (),
     "categories": ("Cryptographic Posture",),
     "blurb": "SNC, TLS, secure storage and key material configured weakly or "
              "not at all."},
    {"id": "database", "label": "HANA database", "prefixes": (),
     "categories": ("HANA Database Security",),
     "blurb": "HANA database settings, users and privileges below baseline."},
    {"id": "app_ui", "label": "Application & UI", "prefixes": (),
     "categories": ("Fiori & UI Layer",),
     "blurb": "Fiori / UI layer exposure and insecure application settings."},
    {"id": "os_infra", "label": "OS & infrastructure", "prefixes": (),
     "categories": ("OS & Infrastructure Security", "Basis Jobs & OS Commands"),
     "blurb": "Operating-system, external-command and batch-job configuration."},
    {"id": "cloud_btp", "label": "Cloud & BTP", "prefixes": (),
     "categories": ("BTP Cloud Attack Surface",
                    "CAP & XSUAA Application Security"),
     "blurb": "SAP BTP cloud attack surface and CAP / XSUAA application "
              "descriptor configuration."},
    {"id": "identity_roles", "label": "Identity & roles", "prefixes": (),
     "categories": ("Identity & Access Management", "Advanced IAM",
                    "Role Design & Governance"),
     "blurb": "Identity-provider, IAM and role-design configuration."},
    {"id": "data_protection", "label": "Data protection & privacy", "prefixes": (),
     "categories": ("Data Protection & Privacy",),
     "blurb": "Data-protection and privacy settings — read-access logging, "
              "masking, retention."},
    {"id": "logging", "label": "Logging & monitoring", "prefixes": (),
     "categories": ("Audit Logging", "Logging, Monitoring & IR"),
     "blurb": "Whether the Security Audit Log and monitoring are switched on and "
              "configured to see enough. (What the logs then observed is on "
              "Perceived Threats.)"},
    {"id": "transport", "label": "Transport, change & development control",
     "prefixes": ("CODE-TMS", "CODE-CHG", "CODE-SYSCHG", "CODE-CLIENT",
                  "CODE-DEV"),
     "categories": ("Transport Security", "Change Management",
                    "Development Controls"),
     "blurb": "Transport Management System, client change options and controls "
              "on development in production."},
]

#: Categories that are deliberately in neither bucket. Maintained explicitly so
#: a test can assert every catalogue category is accounted for — a new or renamed
#: category then fails the build until it is bucketed, rather than silently
#: vanishing from both screens.
EXCLUDED_CATEGORIES = frozenset({
    # Segregation of duties / access governance
    "Access Risk Analysis (SoD)", "GRC Access Control", "SoD Ruleset Coverage",
    # Compliance / process controls
    "Financial Controls (SOX)", "Master Data Change Audit",
    "Vendor & Bank Master Integrity",
    # Shared-responsibility / readiness / imported verdicts
    "RISE / BTP Security", "Resilience & Recovery Readiness",
    "SAP Cloud ALM CSA Results",
    # Retrospective log observations — the Perceived Threats lens
    "Security Audit Log Review", "Gateway Log Review", "HANA Log Review",
    "ICM Log Review", "Network Log Review", "LogServ Ingestion Health",
    # Evidence / coverage meta
    "Export Integrity",
})

#: The two categories whose bucket is decided by check-id prefix, not category.
_PREFIX_DRIVEN_CATEGORIES = frozenset({
    "SAP Security Notes (HotNews)",   # HOTNEWS-* (minus the meta ids)
    "Code & Transport Security",      # ABAP-/ATC-/CODE-* split by sub-prefix
})

_TIER_RANK = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
_SEV_RANK = {s: i for i, s in enumerate(_SEVERITIES)}

#: Every category this module knows how to place (for the coverage guard).
KNOWN_CATEGORIES = (
    EXCLUDED_CATEGORIES
    | _PREFIX_DRIVEN_CATEGORIES
    | {c for g in MISCONFIG_GROUPS for c in g["categories"]}
)


def classify(check_id: Optional[str], category: Optional[str]):
    """(kind, group_id) for a finding, where kind is "vulnerability" /
    "misconfiguration" / None. Prefix rules win over category so the families
    that share the "Code & Transport Security" category land correctly; the
    non-flaw meta ids inside the vulnerability prefixes are removed first."""
    cid = str(check_id or "")
    cat = str(category or "")

    if cid in _NOT_VULN_IDS or cid.startswith(_NOT_VULN_PREFIXES):
        return (None, None)
    for g in VULN_GROUPS:
        if cid.startswith(g["prefixes"]):
            return ("vulnerability", g["id"])
    for g in MISCONFIG_GROUPS:
        if g["prefixes"] and cid.startswith(g["prefixes"]):
            return ("misconfiguration", g["id"])
    for g in MISCONFIG_GROUPS:
        if cat in g["categories"]:
            return ("misconfiguration", g["id"])
    return (None, None)


def _empty(g: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": g["id"], "label": g["label"], "blurb": g["blurb"],
            "counts": {s: 0 for s in _SEVERITIES}, "total": 0, "findings": []}


def _rank(f: Dict[str, Any]):
    return (_TIER_RANK.get(str(f.get("priority_tier") or ""), 9),
            _SEV_RANK.get(str(f.get("severity") or "").upper(), 9),
            str(f.get("check_id") or ""))


def roll_up(findings: Sequence[Dict[str, Any]], kind: str,
            coverage: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Group the findings of one class into that class's groups.

    `kind` is "vulnerability" or "misconfiguration". `findings` is the projection
    queries.findings_for_domains returns (carries check_id + category, which is
    all the partition needs). Findings of the other class, or in neither, are
    ignored. `coverage` supplies the `measured` timestamp, as on other screens.
    """
    groups_def = VULN_GROUPS if kind == "vulnerability" else MISCONFIG_GROUPS
    buckets = {g["id"]: _empty(g) for g in groups_def}

    for f in findings:
        k, gid = classify(f.get("check_id"), f.get("category"))
        if k != kind or gid is None:
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

    groups = [buckets[g["id"]] for g in groups_def]
    return {
        "kind": kind,
        "groups": groups,
        "measured": (coverage or {}).get("measured"),
        "totals": {
            "findings": sum(g["total"] for g in groups),
            "counts": {s: sum(g["counts"][s] for g in groups)
                       for s in _SEVERITIES},
        },
    }
