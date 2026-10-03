"""Per-control audit evidence: a status and the findings that prove it.

For any framework in ComplianceMapper.FRAMEWORKS, this says — per control — whether
the estate has a GAP, is CLEAR, was NOT TESTED, or is NOT MAPPED, and attaches the
finding evidence the verdict rests on. It generalises the status recipe that
modules/nist_csf.py applies to the one CSF framework, to all of them, so an
auditor gets the same honest three-state answer for SOX/ITGC, CIS Controls, DORA
and the rest — not just a count of findings.

THE FOUR STATES, and why they must stay distinct (inherited from nist_csf /
coverage.look_verdict):
  * GAP        — a mapped check produced an open finding here.
  * CLEAR      — the checks that feed this control RAN and found nothing. We
                 looked. This is an observation, NOT an assertion of compliance.
  * NOT_TESTED — the checks that feed this control did not run (the export that
                 feeds them was not supplied). We did not look.
  * NOT_MAPPED — nothing this product checks maps to this control.
CLEAR and NOT_TESTED are different sentences and only one is reassuring; a control
that was never tested must never read as a pass. NO PERCENTAGE is computed.

CONTENT, NOT CHECKS. This reads existing findings + the coverage manifest; it emits
no findings and defines no check ids. stdlib-only (it lives in modules/).
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from .compliance_mapping import ComplianceMapper
from .coverage import UNSUPPLIED, look_verdict
from .coverage import modules_for_categories as _modules_for_categories

GAP = "gap"
CLEAR = "clear"
NOT_TESTED = "not_tested"
NOT_MAPPED = "not_mapped"

_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_SEV_RANK = {s: i for i, s in enumerate(_SEVERITIES)}
_TIER_RANK = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}

#: Status order for sorting controls worst-first on the screen.
_STATUS_RANK = {GAP: 0, NOT_TESTED: 1, CLEAR: 2, NOT_MAPPED: 3}


def frameworks() -> List[Dict[str, str]]:
    """The frameworks the evidence view can be drilled into (id/name/subtitle)."""
    return [{"id": f["id"], "name": f["name"], "subtitle": f.get("subtitle", "")}
            for f in ComplianceMapper.FRAMEWORKS]


def _framework(framework_id: str) -> Optional[Dict[str, Any]]:
    for f in ComplianceMapper.FRAMEWORKS:
        if f.get("id") == framework_id:
            return f
    return None


def _controls_to_themes(framework: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """control_id -> {name, themes set}. A control is reached by one or more
    themes; FRAMEWORKS stores theme -> [(control_id, name)], so invert it."""
    out: Dict[str, Dict[str, Any]] = {}
    for theme, controls in framework.get("themes", {}).items():
        for control_id, name in controls:
            entry = out.setdefault(control_id, {"name": name, "themes": set()})
            entry["themes"].add(theme)
    return out


def _feeding_categories(themes: Set[str]) -> Set[str]:
    """The finding categories whose themes intersect this control's themes."""
    return {cat for cat, cat_themes in ComplianceMapper.CATEGORY_THEMES.items()
            if themes & set(cat_themes)}


def _evidence(f: Dict[str, Any]) -> Dict[str, Any]:
    items = f.get("affected_items")
    return {
        "id": f.get("id"), "check_id": f.get("check_id"),
        "severity": f.get("severity"), "priority_tier": f.get("priority_tier"),
        "title": f.get("title"), "sid": f.get("sid"), "state": f.get("state"),
        "affected_items": list(items)[:8] if isinstance(items, (list, tuple)) else [],
    }


def _rank(f: Dict[str, Any]) -> Tuple[int, int, str]:
    return (_TIER_RANK.get(str(f.get("priority_tier") or ""), 9),
            _SEV_RANK.get(str(f.get("severity") or "").upper(), 9),
            str(f.get("check_id") or ""))


def assess_framework(framework_id: str, findings: Sequence[Dict[str, Any]],
                     coverage: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """Per-control status + evidence for one framework, or None if unknown.

    `findings` must carry at least `category`, `severity`, `check_id` and the
    display evidence (id/title/sid/state/affected_items) — the projection
    server.export.findings_for_report returns. `coverage` is the manifest from
    modules.coverage (queries.latest_coverage); supplied, a CLEAR control whose
    feeders never ran is reported NOT_TESTED instead.
    """
    framework = _framework(framework_id)
    if framework is None:
        return None

    controls: List[Dict[str, Any]] = []
    for control_id, meta in _controls_to_themes(framework).items():
        themes = meta["themes"]
        feed_cats = _feeding_categories(themes)
        hits = [f for f in findings
                if f.get("category") in feed_cats
                and str(f.get("severity") or "").upper() in _SEVERITIES]

        counts = {s: 0 for s in _SEVERITIES}
        for f in hits:
            counts[str(f["severity"]).upper()] += 1

        if hits:
            status = GAP
        elif not feed_cats:
            status = NOT_MAPPED
        else:
            feeders = _modules_for_categories(feed_cats)
            status = (NOT_TESTED
                      if feeders and look_verdict(feeders, coverage,
                                                  require_complete=True) == UNSUPPLIED
                      else CLEAR)

        controls.append({
            "id": control_id, "name": meta["name"], "themes": sorted(themes),
            "status": status, "counts": counts, "total": len(hits),
            "findings": [_evidence(f) for f in sorted(hits, key=_rank)],
        })

    controls.sort(key=lambda c: (_STATUS_RANK.get(c["status"], 9),
                                 -c["total"], c["id"]))
    tally = {GAP: 0, CLEAR: 0, NOT_TESTED: 0, NOT_MAPPED: 0}
    for c in controls:
        tally[c["status"]] += 1

    return {
        "id": framework["id"], "name": framework["name"],
        "subtitle": framework.get("subtitle", ""),
        "controls": controls,
        "totals": {
            "controls": len(controls),
            "by_status": tally,
            "findings": sum(c["total"] for c in controls),
            "measured": (coverage or {}).get("measured"),
        },
    }


# ── Control drift: how each control's status changed since the previous scan ──
NEWLY_FAILING = "newly_failing"      # was clear / not-tested, now a gap
REMEDIATED = "remediated"            # was a gap, now clear
STILL_FAILING = "still_failing"      # a gap at both scans
STOPPED_TESTING = "stopped_testing"  # was gap / clear, now not-tested (coverage dropped)
STARTED_TESTING = "started_testing"  # was not-tested, now gap / clear
UNCHANGED = "unchanged"
NO_BASELINE = "no_baseline"          # no previous complete scan to compare against

_CHANGE_ORDER = {NEWLY_FAILING: 0, STOPPED_TESTING: 1, STILL_FAILING: 2,
                 REMEDIATED: 3, STARTED_TESTING: 4, UNCHANGED: 5, NO_BASELINE: 6}


def _classify_change(was: Optional[str], now: str) -> str:
    if was is None:
        return NO_BASELINE
    if was == now:
        return STILL_FAILING if now == GAP else UNCHANGED
    if now == GAP:
        return NEWLY_FAILING
    if was == GAP and now == CLEAR:
        return REMEDIATED
    if now == NOT_TESTED:
        return STOPPED_TESTING
    if was == NOT_TESTED:
        return STARTED_TESTING
    return UNCHANGED


def drift(framework_id: str,
          now_findings: Sequence[Dict[str, Any]],
          now_coverage: Optional[Dict[str, Any]],
          before_findings: Optional[Sequence[Dict[str, Any]]],
          before_coverage: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Per-control status change between the previous scan and now, or None if the
    framework is unknown.

    `before_findings` is None when there is no previous complete scan to compare
    against — every control then reports NO_BASELINE rather than a fabricated
    "newly failing". Status at each scan is recomputed with its own coverage
    manifest, so a control that changed only because an export stopped arriving
    reads as `stopped_testing`, not a remediation or a new gap.
    """
    now = assess_framework(framework_id, now_findings, now_coverage)
    if now is None:
        return None
    has_baseline = before_findings is not None
    before = (assess_framework(framework_id, before_findings, before_coverage)
              if has_baseline else None)
    was_status = {c["id"]: c["status"] for c in (before["controls"] if before else [])}

    tally = {k: 0 for k in _CHANGE_ORDER}
    controls: List[Dict[str, Any]] = []
    for c in now["controls"]:
        was = was_status.get(c["id"]) if has_baseline else None
        change = _classify_change(was, c["status"]) if has_baseline else NO_BASELINE
        tally[change] += 1
        controls.append({"id": c["id"], "name": c["name"],
                         "status": c["status"], "was": was, "change": change})
    controls.sort(key=lambda c: (_CHANGE_ORDER.get(c["change"], 9), c["id"]))

    return {
        "id": now["id"], "name": now["name"], "subtitle": now["subtitle"],
        "has_baseline": has_baseline,
        "controls": controls,
        "totals": {
            "controls": len(controls),
            "by_change": tally,
            "measured": (now_coverage or {}).get("measured"),
        },
    }
