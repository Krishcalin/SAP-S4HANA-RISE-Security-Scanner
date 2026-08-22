"""What a check IS, and what a Baseline requirement ASKS FOR.

Every screen in this console could already tell you that `LOG-AUD-001` fired.
None of them could tell you what `LOG-AUD-001` is. The check id was a dead
string everywhere it appeared -- on the coverage page it was not even a link --
so the product published 709 identifiers and explained them only in a markdown
file nobody reading the console can see.

THIS MODULE ASSEMBLES, IT DOES NOT AUTHOR. Every field comes from a source that
already existed and is already the authority for it:

    category            modules/coverage.check_catalogue()   (parsed from code)
    owning module       modules/coverage.module_check_ids()  (parsed from code)
    what it reads       modules/coverage.module_sources()    (parsed from code)
    risk + remediation  data/finding_details.json            (380 entries)
    Baseline mapping    server/sapcontent                    (SAP's own policies)
    risk paths          data/attack_paths.json               (content)

Assembling in one place rather than in the route is the same argument as
lib/pricing.ts on the console side: the moment two callers compute "what is this
check" separately, they get to disagree, and the one a customer reads will be
the one nobody checked.

    rule prose         abap_sast_rules / webdisp_baseline / security_params

THE HONEST GAP, STATED RATHER THAN PAPERED OVER. Of the 714 ids in the
catalogue:

    362   have a narrative written for that id
    127   inherit one written about their FAMILY (`ABAP-SQLI` covers -001..-016)
     71   carry the description of the rule that generates them
    154   have nothing, and say so

A check in the last group returns `documented: False` and the screen says so
plainly. The alternative -- rendering an empty panel, or worse, a generic
sentence assembled from the id -- would look like a description and carry no
information, which is the failure mode this codebase keeps finding in its own
reports.

THE THREE SOURCES ARE NOT PRESENTED AS EQUIVALENT. `doc_source` travels with the
text so the screen can say which kind of answer the reader is getting. Counting
them together would claim a written knowledge base of 560 where the part written
for a specific check is 362, and that overstatement is precisely what this module
exists to prevent.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

DATA = Path(__file__).resolve().parents[1] / "data"


@lru_cache(maxsize=1)
def _details() -> Dict[str, Dict[str, str]]:
    """The published risk/remediation knowledge base, keyed by check id."""
    with open(DATA / "finding_details.json", encoding="utf-8") as fh:
        return json.load(fh)


@lru_cache(maxsize=1)
def _requirements() -> Dict[str, Dict[str, Any]]:
    """SAP Baseline requirement families, keyed by requirement id."""
    with open(DATA / "sap_baseline_requirements.json", encoding="utf-8") as fh:
        doc = json.load(fh)
    return {r["requirement"]: r for r in doc.get("requirements", [])}


@lru_cache(maxsize=1)
def _paths() -> List[Dict[str, Any]]:
    with open(DATA / "attack_paths.json", encoding="utf-8") as fh:
        return json.load(fh).get("paths", [])


@lru_cache(maxsize=1)
def _catalogue() -> Dict[str, str]:
    """check id -> category. Parsed from the modules, so it cannot drift."""
    from modules.coverage import check_catalogue
    return check_catalogue()


@lru_cache(maxsize=1)
def _owner() -> Dict[str, str]:
    """check id -> the module that emits it."""
    from modules.coverage import module_check_ids
    return {cid: mod for mod, ids in module_check_ids().items() for cid in ids}


@lru_cache(maxsize=1)
def _sources() -> Dict[str, List[str]]:
    from modules.coverage import module_sources
    return module_sources()



# --------------------------------------------------------------------------- #
#  Prose the product already ships, in corpora that were never read from here  #
# --------------------------------------------------------------------------- #
#
# WHY THIS EXISTS. 352 of the 714 published check ids had no narrative, and
# `/checks/{id}` said so on every one of them. But many of those checks are
# GENERATED FROM RULE TABLES THAT ALREADY DESCRIBE THEM — a rule cannot match a
# pattern without saying what the pattern means, and every one of these tables
# carries the description and the fix next to the pattern. The prose existed; the
# only thing missing was a reader.
#
# Wiring these is also what uncovered the family entries above: counting how many
# knowledge-base entries the index could now reach found 23 of 385 that it could
# not, nineteen of which were narratives somebody wrote and an exact-match lookup
# had silently discarded. Between the two, 352 undocumented became 154.
#
# Which is the same argument as the rest of this module, applied one layer out:
# assemble from the authority, never author. Writing 175 fresh descriptions
# against rules that already have them would have produced a second opinion about
# our own checks, and the two would drift.
#
# THE THREE CORPORA, AND WHY EACH IS THE AUTHORITY FOR ITS OWN CHECKS:
#
#   abap_sast_rules   the 104 ABAP-* code rules. `description` says what the
#                     pattern catches and `recommendation` says what to write
#                     instead. The rule IS the check — there is no separate
#                     implementation that could disagree with it.
#   webdisp_baseline  the 14 WDISP-* rules, transcribed from SAP's own policy
#                     with `risk` and `fix` fields already named for this.
#   security_params   the 57 PARAM-* profile parameters, whose `desc` and `fix`
#                     were written when the threshold was.
#
# WHAT THIS DOES NOT DO. It does not make a derived description equal to a
# hand-written one, and the page must not pretend otherwise. A rule's description
# is two sentences about a pattern; a knowledge-base entry is a page about an
# attack, its business consequence and a numbered remediation. So the knowledge
# base always wins where both exist, and `doc_source` travels with the text so
# the screen can say which kind of answer the reader is getting.

#: `doc_source` values, weakest last.
#:
#: THE MIDDLE ONE WAS FOUND BY WIRING THE THIRD. Adding the rule corpora meant
#: counting how many knowledge-base entries the index could reach, and 23 of the
#: 385 could not be reached at all. Nineteen of those are FAMILY-LEVEL entries —
#: `ABAP-SQLI` is a full hand-written narrative about SQL injection in ABAP, and
#: the catalogue publishes `ABAP-SQLI-001` through `-016`. `_details().get()` is
#: an exact lookup, so somebody wrote nineteen narratives covering 128 checks and
#: not one of them has ever been rendered.
#:
#: A family narrative is hand-written and therefore better prose than a rule's
#: description, but it is about the family rather than about this rule — so it
#: ranks above the rule and below an entry written for the id itself, and the
#: rule's own line is carried alongside it as `doc_specific` rather than
#: discarded. The two answer different questions and the page can show both.
DOC_KNOWLEDGE_BASE = "knowledge_base"
DOC_FAMILY = "knowledge_base_family"
DOC_RULE = "rule_definition"


@lru_cache(maxsize=1)
def _derived() -> Dict[str, Dict[str, str]]:
    """`{check id: {risk, mitigation, doc_detail}}` read out of the rule tables.

    Every corpus is optional. One that cannot be imported or parsed contributes
    nothing and the checks it would have described go back to reporting
    themselves as undocumented, which is the honest degradation — the same
    position `sapcontent.requirement_exact()` takes when its rule file is
    unreadable.
    """
    out: Dict[str, Dict[str, str]] = {}

    def add(check_id, risk, mitigation, detail):
        if check_id and risk and mitigation and check_id not in out:
            out[str(check_id)] = {"risk": str(risk).strip(),
                                  "mitigation": str(mitigation).strip(),
                                  "doc_detail": detail}

    # ── the ABAP code rules ────────────────────────────────────────────────
    try:
        from modules import abap_sast_rules
    except Exception:                                    # pragma: no cover
        abap_sast_rules = None
    if abap_sast_rules is not None:
        seen = set()
        for attr in dir(abap_sast_rules):
            if attr.startswith("_"):
                continue
            table = getattr(abap_sast_rules, attr, None)
            if not isinstance(table, (list, tuple)):
                continue
            for rule in table:
                # The module exposes both the per-category tables and the
                # ALL_* unions, so the same rule arrives more than once. Keyed
                # by id, so the duplicate is free rather than a conflict.
                if not isinstance(rule, dict) or rule.get("id") in seen:
                    continue
                seen.add(rule.get("id"))
                add(rule.get("id"), rule.get("description"),
                    rule.get("recommendation"), "ABAP code rule")

    # ── the Web Dispatcher rules ───────────────────────────────────────────
    try:
        with open(DATA / "webdisp_baseline.json", encoding="utf-8") as fh:
            rules = json.load(fh).get("rules") or []
    except (OSError, ValueError):                        # pragma: no cover
        rules = []
    for rule in rules:
        if isinstance(rule, dict):
            add(rule.get("check_id"), rule.get("risk"), rule.get("fix"),
                "Web Dispatcher rule")

    # ── the profile parameters ─────────────────────────────────────────────
    try:
        from modules.security_params import SecurityParamAuditor
    except Exception:                                    # pragma: no cover
        SecurityParamAuditor = None
    if SecurityParamAuditor is not None:
        for attr, detail in (("BASELINE", "profile-parameter rule"),
                             ("ECS_RULES", "SAP ECS hardening rule")):
            table = getattr(SecurityParamAuditor, attr, None)
            if not isinstance(table, dict):
                continue
            for name, rule in table.items():
                if isinstance(rule, dict):
                    add("PARAM-%s" % name, rule.get("desc"), rule.get("fix"),
                        detail)
    return out


@lru_cache(maxsize=1)
def _families() -> Dict[str, str]:
    """`{catalogue check id: the family entry that describes it}`.

    Derived by asking which knowledge-base keys are NOT themselves published
    checks and are a prefix of ones that are. Derived rather than listed, because
    a hand-written list of nineteen prefixes would go stale the first time a rule
    family was added and nobody would notice — which is exactly how these
    nineteen came to be unread in the first place.

    `-` is required after the prefix so `ABAP-CD` could never claim `ABAP-CDS-001`.
    Longest prefix wins, so a narrower family entry beats a broader one.
    """
    details, catalogue = _details(), _catalogue()
    prefixes = sorted((k for k in details if k not in catalogue), key=len,
                      reverse=True)
    out: Dict[str, str] = {}
    for cid in catalogue:
        if cid in details:
            continue
        for prefix in prefixes:
            if cid.startswith(prefix + "-"):
                out[cid] = prefix
                break
    return out


def _narrative(check_id: str) -> Dict[str, Optional[str]]:
    """The best prose available for one check, and where it came from."""
    rule = _derived().get(check_id)
    # What THIS rule matches, as distinct from what its family is about. Carried
    # whenever a rule exists, including under a family narrative, because the
    # family cannot say which of its sixteen patterns fired.
    specific = (rule or {}).get("risk") if rule else None

    entry = _details().get(check_id)
    if entry:
        return {"risk": entry.get("risk"), "mitigation": entry.get("mitigation"),
                "doc_source": DOC_KNOWLEDGE_BASE, "doc_detail": None,
                "doc_specific": specific}

    family = _families().get(check_id)
    if family:
        entry = _details()[family]
        return {"risk": entry.get("risk"), "mitigation": entry.get("mitigation"),
                "doc_source": DOC_FAMILY, "doc_detail": family,
                "doc_specific": specific}

    if rule:
        return {"risk": rule["risk"], "mitigation": rule["mitigation"],
                "doc_source": DOC_RULE, "doc_detail": rule["doc_detail"],
                # Already the risk text above; repeating it as a lead line would
                # print the same sentences twice.
                "doc_specific": None}

    return {"risk": None, "mitigation": None, "doc_source": None,
            "doc_detail": None, "doc_specific": None}


def known_check(check_id: str) -> bool:
    """Is this an id the scanner actually publishes?

    Deliberately checks the CATALOGUE rather than the knowledge base. An id can
    be real and undocumented; those are different facts and the screen shows
    them differently. Checking the knowledge base here would 404 the 329 real
    checks that have no narrative yet, which is the wrong answer to "what is
    this?" -- we know a great deal about them beyond the prose.
    """
    return check_id in _catalogue()


def known_requirement(requirement_id: str) -> bool:
    return requirement_id in _requirements()


def _requirements_citing(check_id: str) -> List[Dict[str, Any]]:
    """Baseline requirements whose coverage this check contributes to.

    Uses the same mapping the coverage screen counts with, so a check that shows
    under AUDIT-A there names AUDIT-A here. Two mappings would eventually
    disagree and the page would quietly contradict the number beside it.
    """
    from server import sapcontent
    req = sapcontent.requirement_for(check_id)
    if not req:
        return []
    entry = _requirements().get(req)
    if not entry:
        return [{"requirement": req, "tier": None, "technology": None, "title": None}]
    return [{
        "requirement": req,
        "tier": entry.get("tier"),
        "technology": entry.get("technology"),
        "title": (entry.get("titles") or [None])[0],
    }]


def _paths_citing(check_id: str) -> List[Dict[str, Any]]:
    """Risk-path steps this check evidences.

    A check that is a CUT on some path is the most actionable thing this page
    can say about it -- closing it severs a route -- so the hop's cut flag comes
    with it rather than being left for the reader to go and find.
    """
    out: List[Dict[str, Any]] = []
    for path in _paths():
        for hop in path.get("hops", []):
            if check_id in (hop.get("checks") or []):
                out.append({
                    "template_id": path["id"],
                    "path_name": path.get("name"),
                    "severity": path.get("severity"),
                    "fair_scenario": path.get("fair_scenario"),
                    "hop": hop.get("name"),
                    "is_cut": bool(hop.get("cut")),
                    "required": bool(hop.get("required")),
                })
    return out


def check(check_id: str) -> Optional[Dict[str, Any]]:
    """Everything the product knows about one check id, or None if unknown."""
    if not known_check(check_id):
        return None
    prose = _narrative(check_id)
    module = _owner().get(check_id)
    return {
        "check_id": check_id,
        "category": _catalogue().get(check_id),
        "module": module,
        # Module-level, and labelled as such on the screen. The exports a MODULE
        # reads are derivable from the code; which of them any single check
        # touches is not, and inventing a narrower list would be a claim the
        # parser cannot support.
        "module_reads": sorted(_sources().get(module, [])) if module else [],
        "documented": prose["doc_source"] is not None,
        # WHERE THE PROSE CAME FROM, carried so the screen can say it. A rule's
        # description is two sentences about a pattern; a knowledge-base entry is
        # a page about an attack and its business consequence. Both are better
        # than "no published description", and presenting them as the same thing
        # would be the quiet overstatement this module exists to avoid.
        "doc_source": prose["doc_source"],
        "doc_detail": prose["doc_detail"],
        # What this particular rule matches, when the narrative above it is about
        # a family of them. Never a substitute for the narrative — a pattern
        # description is not a reason to care.
        "doc_specific": prose["doc_specific"],
        "risk": prose["risk"],
        "mitigation": prose["mitigation"],
        "requirements": _requirements_citing(check_id),
        "paths": _paths_citing(check_id),
    }


def requirement(requirement_id: str) -> Optional[Dict[str, Any]]:
    """One SAP Baseline requirement family, and how we answer it."""
    entry = _requirements().get(requirement_id)
    if entry is None:
        return None
    from modules.coverage import module_check_ids
    from server import sapcontent
    ours = sorted({cid for ids in module_check_ids().values() for cid in ids
                   if sapcontent.requirement_for(cid) == requirement_id})
    return {
        "requirement": requirement_id,
        "family": entry.get("family"),
        "technology": entry.get("technology"),
        "tier": entry.get("tier"),
        # SAP's own wording for every check item in the family, not a paraphrase.
        # A requirement page that reworded SAP would be answering a question the
        # auditor did not ask.
        "titles": entry.get("titles") or [],
        "config_stores": entry.get("config_stores") or [],
        "check_items": entry.get("check_items"),
        "policies": entry.get("policies") or [],
        "our_checks": ours,
        "covered": bool(ours),
    }


def catalogue_index() -> List[Dict[str, Any]]:
    """Every published check id with its category, for a browsable index."""
    owner = _owner()
    details = _details()
    derived = _derived()
    families = _families()

    def source(cid):
        # Same precedence as the detail page, and the same reason for keeping the
        # three apart: an index reporting them under one flag would let a reader
        # conclude the knowledge base is half again the size it is.
        if cid in details:
            return DOC_KNOWLEDGE_BASE
        if cid in families:
            return DOC_FAMILY
        return DOC_RULE if cid in derived else None

    return [{"check_id": cid, "category": cat, "module": owner.get(cid),
             "documented": source(cid) is not None,
             "doc_source": source(cid)}
            for cid, cat in sorted(_catalogue().items())]
