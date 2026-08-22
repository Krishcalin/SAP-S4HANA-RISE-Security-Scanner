# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

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

THE HONEST GAP, STATED RATHER THAN PAPERED OVER. The knowledge base covers 380
of the 709 ids in the catalogue. A check with no entry returns `documented:
False` and the screen says so plainly. The alternative -- rendering an empty
panel, or worse, a generic sentence assembled from the id -- would look like a
description and carry no information, which is the failure mode this codebase
keeps finding in its own reports.
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
    detail = _details().get(check_id)
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
        "documented": detail is not None,
        "risk": (detail or {}).get("risk"),
        "mitigation": (detail or {}).get("mitigation"),
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
    return [{"check_id": cid, "category": cat, "module": owner.get(cid),
             "documented": cid in details}
            for cid, cat in sorted(_catalogue().items())]
