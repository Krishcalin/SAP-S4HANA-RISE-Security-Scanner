# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
The twelve security domains a buyer recognises, and what this product honestly
does in each.

WHY THIS FILE IS SHAPED THE WAY IT IS
-------------------------------------
The domain names below are the vocabulary SAP security buyers already use, and
they closely mirror a commercial competitor's module list. Adopting it is
deliberate: it makes the product legible to somebody holding an RFP checklist.

It also creates the obvious hazard. Several of these domains are CONTINUOUS or
RUNTIME capabilities — event monitoring, traffic monitoring, behavioural
analytics, exploit protection — and this product is an OFFLINE, POINT-IN-TIME
configuration assessment. Twelve tiles each showing a number would assert twelve
capabilities. Four of them would be false.

TWO AXES, NOT ONE ENUM, AND THAT IS THE WHOLE DESIGN
-----------------------------------------------------
The first attempt at this collapsed "what can we ever see here" and "what did
this run find" into a single status, and lost a real cell in doing so.

  REACH   what this product can EVER see in a domain. A property of the product,
          fixed at author time, identical on every customer and every run.
  STATE   what THIS run produced. Varies per scan, per scope, per export.

Merging them cannot express a CONFIG_ONLY domain that came back clean — and that
is a genuine, sellable observation: *we read every RFC destination, gateway ACL
and IDoc port you supplied and found nothing wrong in the configuration*. A single
enum has to pick between "configuration only" and "clear", and either choice
misleads.

ONE HARD CONSTRAINT, ENFORCED BEFORE ANY FINDING IS COUNTED:
    reach == NONE  =>  state == NOT_ASSESSED, always.
No data path can produce a number for a domain this product does not do.

MEMBERSHIP IS A STRICT PARTITION
--------------------------------
Every finding lands in exactly one domain or in `UNPLACED`. Not zero, not two.
`modules/nist_csf.py` records what happens otherwise: its first roll-up reported
"Protect: 148" for a system with 92 findings, and a number larger than the corpus
it summarises is indefensible in front of the reader it exists to serve.
"""
from typing import Any, Dict, List, Optional, Sequence, Tuple

# ── REACH: what the product can ever see. Author-time, never computed. ───────
FULL = "full"
PARTIAL = "partial"
CONFIG_ONLY = "config_only"
NONE = "none"

# ── STATE: what this run produced. Per scan. ─────────────────────────────────
ASSESSED = "assessed"          # we looked and found something
CLEAR = "clear"                # we looked and found nothing
NOT_SUPPLIED = "not_supplied"  # we would have looked; the export never arrived
NOT_ASSESSED = "not_assessed"  # we do not do this, in any run

#: Domain id -> definition.
#:
#: `label` is the buyer's word, VERBATIM. It is what a reader matches against an
#: RFP checklist, and renaming it forfeits the only reason to adopt this
#: vocabulary. The honesty lives in `scope`, which is rendered directly beneath
#: the label and never omitted.
#:
#: `categories` are finding categories owned OUTRIGHT. `prefixes` splits a
#: category whose checks genuinely belong to two domains — there are exactly
#: three such splits and that is the budget, because each is a permanent
#: maintenance liability and a place the partition test can break.
#:
#: `prefix_default` is where a split category's UNMATCHED checks go, and it is
#: not optional. Without it a check id that matches no prefix falls silently out
#: of the taxonomy: PARAM-MS/ACL_INFO, PARAM-MS/MONITOR and CODE-STMT-001 did
#: exactly that on the first run, and the only reason it was noticed is that the
#: placed and unplaced totals were checked against the corpus. A split with no
#: default is a hole that widens every time somebody adds a check.
DOMAINS: List[Dict[str, Any]] = [
    {
        "id": "baselining",
        "label": "Baselining and Benchmarking",
        "reach": FULL,
        "scope": None,
        "blurb": "Profile parameters, cryptographic posture and database settings "
                 "measured against SAP's own Security Baseline and CIS.",
        "categories": ["Security Baseline Parameters", "Security Parameters",
                       "Login Security", "Password Policy", "Cryptographic Posture",
                       "HANA Database Security", "Transport Security",
                       "Development Controls"],
    },
    {
        "id": "event_monitoring",
        "label": "Security Event Monitoring",
        "reach": CONFIG_ONLY,
        # THE SENTENCE THAT KEEPS THIS TILE HONEST. modules/log_review.py makes
        # the same argument in its own docstring and makes it better: the value is
        # in knowing whether the log COULD have recorded the answer, which a
        # monitoring product assumes and never checks.
        "scope": "We check that the Security Audit Log is switched on, filtered "
                 "correctly and retained long enough to answer a question later. "
                 "We do not monitor events — nothing here is live.",
        "blurb": "Whether your logging is capable of seeing an incident.",
        "categories": ["Logging, Monitoring & IR", "Audit Logging"],
        "prefixes": {"Security Audit Log Review": ["LREV-SRC", "LREV-FLT",
                                                   "LREV-WIN", "LREV-ECS"]},
        # Audit-log checks that are not a behavioural pattern are about
        # whether the log works, which is this domain.
        "prefix_default": "Security Audit Log Review",
    },
    {
        "id": "compliance",
        "label": "Security & Compliance Monitoring",
        "reach": PARTIAL,
        "scope": "Point-in-time, against the frameworks your auditor uses. There "
                 "is no compliance score here and there will not be one: we see "
                 "your findings, not your control environment.",
        "blurb": "Data protection, financial controls, and the framework mappings.",
        "categories": ["Data Protection & Privacy", "Financial Controls (SOX)",
                       "Master Data Change Audit",
                       "Vendor & Bank Master Integrity"],
    },
    {
        "id": "patch",
        "label": "Patch and Hotnews Management",
        "reach": PARTIAL,
        "scope": "Compared against a CURATED subset of high-impact SAP Notes, not "
                 "the full Patch Day history. The report states the subset's size "
                 "and cut-off on every run.",
        "blurb": "Missing high-impact and actively exploited SAP Security Notes.",
        "categories": ["SAP Security Notes (HotNews)"],
    },
    {
        "id": "custom_code",
        "label": "Custom Code Security",
        "reach": FULL,
        # THE ONE RENAME, AND IT IS NOT COSMETIC. "Code Vulnerability Analyzer" is
        # SAP'S OWN PRODUCT NAME for a separately licensed entitlement. A tile
        # carrying it implies either that we are CVA or that CVA is included, and
        # a customer who does not hold that licence would be misled about what
        # they are entitled to run. Every other label is a competitor's marketing
        # word, which is fair game; this one is a licence.
        "scope": "Static analysis of the custom ABAP and UI5 you export, over 133 "
                 "rules. Not SAP's Code Vulnerability Analyzer, which is a "
                 "separately licensed SAP product.",
        "blurb": "Injection, missing authority checks and dangerous statements in "
                 "your own code.",
        "categories": [],
        "prefixes": {"Code & Transport Security": ["ABAP-", "ATC-", "CODE-INV",
                                                   "CODE-INJ", "CODE-ATC",
                                                   "CODE-DEAD", "CODE-MOD",
                                                   "CODE-STMT"]},
        # A code check that is not a transport check is a code check.
        "prefix_default": "Code & Transport Security",
    },
    {
        "id": "interface",
        "label": "Interface Traffic Monitoring",
        "reach": CONFIG_ONLY,
        "scope": "We read how your interfaces are CONFIGURED — destinations, "
                 "gateway ACLs, exposed services, stored credentials. We do not "
                 "see traffic, and nothing here is live.",
        "blurb": "The interface surface, and what an attacker could reach through it.",
        "categories": ["Network & Integration Layer", "Network & Service Exposure",
                       "Gateway Security", "RFC Security",
                       "Unified Connectivity (UCON)",
                       "Web Dispatcher Security"],
        "prefixes": {"System Trust & Standard Users": ["TRUST", "PARAM-MS/",
                                              "PARAM-ms/"]},
        # A trust or message-server check that matches no prefix is still
        # about how systems reach each other.
        "prefix_default": "System Trust & Standard Users",
    },
    {
        "id": "violation",
        "label": "Violation Management",
        "reach": FULL,
        "scope": None,
        "blurb": "Segregation-of-duties conflicts and critical access, at "
                 "permission level rather than transaction level.",
        "categories": ["Access Risk Analysis (SoD)", "GRC Access Control"],
    },
    {
        "id": "transport",
        "label": "Comprehensive Transport Security",
        "reach": PARTIAL,
        "scope": "The transport route, client settings and change control that we "
                 "can read from an export. We do not inspect transport payloads.",
        "blurb": "Change and transport management, and whether production is open.",
        "categories": ["Change Management"],
        "prefixes": {"Code & Transport Security": ["CODE-TMS", "CODE-CHG",
                                                   "CODE-SYSCHG", "CODE-CLIENT",
                                                   "CODE-DEV"]},
    },
    {
        "id": "access",
        "label": "Access and Authorization",
        "reach": FULL,
        "scope": None,
        "blurb": "Authorization objects, critical access, role design and the "
                 "business layer.",
        "categories": ["ABAP Authorization & Critical Access",
                       "S/4HANA & Cloud Authorization", "Role Design & Governance",
                       "Basis Jobs & OS Commands", "Fiori & UI Layer"],
    },
    {
        "id": "identity",
        "label": "Identity Security",
        "reach": FULL,
        "scope": None,
        "blurb": "Users, standard accounts, federation and privileged identity.",
        "categories": ["Identity & Access Management", "User & Authorization",
                       "Advanced IAM"],
        "prefixes": {"System Trust & Standard Users": ["STDUSR"]},
    },
    {
        "id": "user_behaviour",
        "label": "Suspicious User Behaviour",
        "reach": PARTIAL,
        "scope": "A pattern library run RETROSPECTIVELY over the audit-log window "
                 "you export. It is not behavioural analytics and it is not live — "
                 "it reports what the log already recorded.",
        "blurb": "Patterns in an exported audit-log window worth a second look.",
        "categories": [],
        "prefixes": {"Security Audit Log Review": ["LREV-PAT"]},
    },
    {
        "id": "exploit",
        "label": "Exploit and 0-Day Protection",
        "reach": NONE,
        # NONE IS A PRODUCT STATEMENT, NOT A RESULT. It cannot become a number,
        # a zero, or a green tick, because roll_up() short-circuits on reach
        # before it counts anything. The nearest thing this product does is name
        # missing patches, which is prevention and lives in its own domain.
        "scope": "This product does not do this. Exploit protection and virtual "
                 "patching are runtime capabilities requiring an agent in your "
                 "system; we hold no connection and install nothing. The closest "
                 "we come is telling you which patches are missing — see Patch and "
                 "Hotnews Management.",
        "blurb": "Not assessed by this product.",
        "categories": [],
    },
]

#: Categories deliberately outside the twelve, with the reason. They are REAL
#: findings this product produces, and a taxonomy that silently dropped them
#: would understate the product while claiming to summarise it.
UNPLACED_CATEGORIES: Dict[str, str] = {
    "SAP Cloud ALM CSA Results":
        "Somebody else's assessment. These are SAP's own compliance verdicts, "
        "imported and reported as SAP's, and every one of the twelve domains "
        "describes something THIS PRODUCT measured. Filing a verdict under a "
        "domain would put SAP's conclusion into a count of ours — and because a "
        "verdict carries no parameter value or user, there is nothing behind it "
        "for a domain summary to be a summary OF. They belong beside the "
        "domains, not inside them.",
    "CAP & XSUAA Application Security":
        "Design-time application security: what a CAP project's own source and "
        "security descriptor declare, before any of it is deployed. It is not a "
        "property of a running SAP system, which is what all twelve domains "
        "describe, and filing it under one of them would say a system was "
        "measured when a repository was.",
    "BTP Cloud Attack Surface":
        "SAP BTP is a different estate from the ABAP stack these twelve domains "
        "describe, and folding it into them would hide which system a finding is "
        "about.",
    "RISE / BTP Security":
        "Shared-responsibility findings: things that are SAP's to fix under a RISE "
        "contract rather than yours. They belong beside a contract, not beside a "
        "control domain.",
    "Resilience & Recovery Readiness":
        "Backup, disaster recovery and ransomware readiness. A real domain, and one "
        "this taxonomy has no name for.",
}

_REACH_ORDER = {FULL: 0, PARTIAL: 1, CONFIG_ONLY: 2, NONE: 3}
_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def by_id(domain_id: str) -> Optional[Dict[str, Any]]:
    for d in DOMAINS:
        if d["id"] == domain_id:
            return d
    return None


def domain_for(check_id: Optional[str],
               category: Optional[str]) -> Optional[str]:
    """Which domain a finding belongs to, or None if it is outside the taxonomy.

    Prefix rules first, then outright ownership, then the split category's
    default. The default is what stops a new check id in a split category from
    dropping out of the taxonomy unnoticed.
    """
    cid = check_id or ""
    for d in DOMAINS:
        for owner, prefixes in (d.get("prefixes") or {}).items():
            if category == owner and any(cid.startswith(p) for p in prefixes):
                return d["id"]
    for d in DOMAINS:
        if category in (d.get("categories") or []):
            return d["id"]
    for d in DOMAINS:
        if category and category == d.get("prefix_default"):
            return d["id"]
    return None


def match_terms(domain_id: str) -> List[Dict[str, Any]]:
    """One domain's membership rules, in a form a query layer can compile.

    WHY THIS EXISTS RATHER THAN A SECOND COPY IN SQL
    A findings queue filtered by domain has to select rows in the database, and
    the obvious way to do that is to write the routing rules again as a WHERE
    clause. That is the failure this file has already met twice: a rule fixed in
    one place and not its sibling. So the rules are emitted from the SAME data
    `domain_for` reads, and `server/queries.py` compiles these terms mechanically
    without knowing what a domain is.

    Each term is a category plus optional prefix conditions, and a finding
    belongs to the domain when ANY term matches it:

        {"category": str,
         "starts_with":     (...)  # check id must begin with one of these
         "not_starts_with": (...)} # ...and with none of these

    `matches()` below is the reference reading of a term, and a test asserts it
    agrees with `domain_for` on every prefix in the taxonomy. An empty list means
    no finding can ever be in this domain — which is true of exactly one of the
    twelve, and it is a statement about the product, not about the data.
    """
    d = by_id(domain_id)
    if d is None:
        return []
    terms: List[Dict[str, Any]] = [
        {"category": cat, "starts_with": (), "not_starts_with": ()}
        for cat in sorted(d.get("categories") or [])
    ]
    for cat, prefixes in sorted((d.get("prefixes") or {}).items()):
        terms.append({"category": cat, "starts_with": tuple(prefixes),
                      "not_starts_with": ()})
    default = d.get("prefix_default")
    if default:
        # The default bucket is the category MINUS every prefix any domain
        # claims in it — including this domain's own, which the term above
        # already covers. Deriving the exclusion from the whole taxonomy rather
        # than from a hand-written list is what keeps it correct when somebody
        # adds a prefix to the OTHER domain in the split.
        claimed = sorted({p for other in DOMAINS
                          for p in (other.get("prefixes") or {}).get(default, [])})
        terms.append({"category": default, "starts_with": (),
                      "not_starts_with": tuple(claimed)})
    return terms


def matches(check_id: Optional[str], category: Optional[str],
            terms: Sequence[Dict[str, Any]]) -> bool:
    """Whether a finding satisfies any of `terms`. The reference reading."""
    cid = check_id or ""
    for t in terms:
        if category != t.get("category"):
            continue
        include = t.get("starts_with") or ()
        exclude = t.get("not_starts_with") or ()
        if include and not any(cid.startswith(p) for p in include):
            continue
        if exclude and any(cid.startswith(p) for p in exclude):
            continue
        return True
    return False


def roll_up(findings: Sequence[Dict[str, Any]],
            coverage: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Sort findings into the twelve domains.

    `coverage` is a manifest from modules/coverage.py. When supplied, a domain
    whose feeding modules never ran because the export was absent reports
    NOT_SUPPLIED rather than CLEAR — "you did not send us the file" and "we looked
    and it was fine" are different sentences and only one of them is reassuring.
    """
    buckets: Dict[str, Dict[str, Any]] = {
        d["id"]: {"counts": {s: 0 for s in _SEVERITIES}, "total": 0}
        for d in DOMAINS
    }
    unplaced: Dict[str, int] = {}

    for f in findings:
        severity = str(f.get("severity", "")).upper()
        did = domain_for(f.get("check_id"), f.get("category"))
        if did is None:
            name = f.get("category") or "(no category)"
            unplaced[name] = unplaced.get(name, 0) + 1
            continue
        bucket = buckets[did]
        bucket["total"] += 1
        if severity in bucket["counts"]:
            bucket["counts"][severity] += 1

    supplied_any = _supplied_lookup(coverage)

    out: List[Dict[str, Any]] = []
    for d in DOMAINS:
        bucket = buckets[d["id"]]
        # THE CONSTRAINT, APPLIED BEFORE ANY COUNT IS READ.
        if d["reach"] == NONE:
            state = NOT_ASSESSED
        elif bucket["total"]:
            state = ASSESSED
        elif supplied_any is not None and not supplied_any(d):
            state = NOT_SUPPLIED
        else:
            state = CLEAR
        out.append({
            "id": d["id"], "label": d["label"], "reach": d["reach"],
            "scope": d.get("scope"), "blurb": d.get("blurb"),
            "state": state,
            "total": 0 if d["reach"] == NONE else bucket["total"],
            "counts": ({s: 0 for s in _SEVERITIES} if d["reach"] == NONE
                       else bucket["counts"]),
            "categories": sorted(set((d.get("categories") or []))
                                 | set((d.get("prefixes") or {}))),
        })
    out.sort(key=lambda x: (_REACH_ORDER[x["reach"]], x["label"]))

    return {
        "domains": out,
        "unplaced": {
            "counts": dict(sorted(unplaced.items(), key=lambda kv: (-kv[1], kv[0]))),
            "total": sum(unplaced.values()),
            "reasons": dict(UNPLACED_CATEGORIES),
            "note": ("These are real findings this product produced that the "
                     "twelve-domain vocabulary has no home for. They are counted "
                     "here rather than dropped, because a taxonomy that silently "
                     "loses findings understates the product while claiming to "
                     "summarise it."),
        },
        "totals": {
            "domains": len(DOMAINS),
            "assessable": sum(1 for d in DOMAINS if d["reach"] != NONE),
            "findings": len(findings),
            "placed": sum(b["total"] for b in buckets.values()),
        },
    }


def _supplied_lookup(coverage: Optional[Dict[str, Any]]):
    """A predicate saying whether any module feeding a domain actually ran.

    Returns None when there is no manifest, and the caller then never reports
    NOT_SUPPLIED — claiming an export was missing without having checked would be
    the same class of error as claiming it was clean.

    PER DOMAIN, NOT PER RUN. This began as "did anything at all run?", which is
    only ever wrong in the reassuring direction: a scan with no audit-log export
    ran twenty-nine other modules, so "Suspicious User Behaviour" came back CLEAR
    — we looked and found nothing — about a log nobody supplied. The domain most
    likely to be read as a monitoring result was the one making the claim.

    The link from a domain to the modules that feed it is DERIVED from the code
    (modules/coverage.module_categories), not declared here. A declared table
    would be a second place for the same fact to be true, and this file already
    carries one prefix table too many for comfort.
    """
    if not coverage or not isinstance(coverage.get("modules"), dict):
        return None
    from modules.coverage import (
        UNSUPPLIED, look_verdict, module_categories, module_check_ids,
    )
    by_category = module_categories()
    by_check_id = module_check_ids()

    def supplied(domain: Dict[str, Any]) -> bool:
        # UNKNOWN counts as looked. Claiming an export was missing without having
        # checked tells a customer they forgot something they did send, which is
        # the opposite error and the one they cannot act on.
        feeders = feeders_for(domain, by_category, by_check_id)
        return look_verdict(feeders, coverage,
                            require_complete=True) != UNSUPPLIED

    return supplied


def feeders_for(domain: Dict[str, Any],
                by_category: Dict[str, Sequence[str]],
                by_check_id: Dict[str, Sequence[str]]) -> set:
    """Which modules can produce a finding in this domain.

    THE PREFIX TEST IS THE POINT OF THE SECOND ARGUMENT. Category alone is too
    coarse where two domains share one: `ecs_config_items` emits findings in
    "Security Audit Log Review" — audit-log configuration, which is Security
    Event Monitoring — and by category alone it also counted as a feeder of
    Suspicious User Behaviour, which owns only the LREV-PAT pattern checks in
    that category. That single over-attribution reinstated the exact claim this
    machinery exists to prevent: a scan with no audit-log EXPORT reported the
    behaviour domain as clean, because a different module had read the audit-log
    CONFIGURATION.

    So a module owned by a category outright feeds the domain; a module reaching
    the domain only through a prefix split must also carry a literal check id
    with one of that domain's prefixes.
    """
    outright = set(domain.get("categories") or [])
    prefixes: Dict[str, Sequence[str]] = domain.get("prefixes") or {}
    default = domain.get("prefix_default")
    found = set()
    for module, categories in by_category.items():
        cats = set(categories)
        if cats & outright:
            found.add(module)
            continue
        ids = by_check_id.get(module) or ()
        for split_category, split_prefixes in prefixes.items():
            if split_category in cats and any(
                    cid.startswith(p) for cid in ids for p in split_prefixes):
                found.add(module)
                break
        else:
            # The default bucket of a split takes whatever matched no prefix, so
            # a module emitting that category at all can land in it.
            if default and default in cats:
                found.add(module)
    return found
