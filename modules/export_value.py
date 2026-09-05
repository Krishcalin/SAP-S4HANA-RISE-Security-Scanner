"""What each missing export would actually buy.

THE PROBLEM. Every scan ends with the same sentence: "Supplied 119 of 139
logical sources. 17 module(s) ran with incomplete input." It is true, it is
honest, and it is not actionable. A customer facing twenty missing extracts has
no way to know that two of them carry a third of the remaining value and the
other eighteen carry almost none — so the usual outcome is that none of them
arrive, and an offline product delivers 119/139 of itself forever.

The mapping to answer it already exists. `coverage.check_sources()` knows which
logical sources each of 438 checks reads. All that was missing is the arithmetic
and the ordering.

TWO NUMBERS, NOT ONE, AND THE DIFFERENCE IS THE POINT. A check reading three
sources needs all three, so a missing source is only worth what it UNBLOCKS:

    unlocks_now   checks whose ONLY missing source is this one — supply it and
                  they run on the next scan
    also_needed   checks that read it and are still blocked by something else —
                  real value, but not yet

Reporting only the second inflates every source into a headline. Reporting only
the first hides the fact that two exports together open a door neither opens
alone, which is exactly the case a ranked list should surface. Both are given.

WHAT IS NOT RECOMMENDED. A source RISE makes unobtainable is never advice: under
a RISE contract the customer cannot produce `ms_acl` or `saprouttab` at all, and
listing them as "next steps" wastes the reader's attention on a door that does
not open. They are returned separately, labelled, so the reason they are absent
is visible rather than mysterious.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Set

from modules import coverage, deployment_modes


def _missing_from(manifest: Optional[Dict[str, Any]]) -> Set[str]:
    if not manifest:
        return set()
    missing = set(manifest.get("missing") or ())
    # A file that was present and empty is missing for every purpose that
    # matters here: a check reading nothing cannot fire on it.
    missing |= set(manifest.get("empty") or ())
    return missing


def rank(manifest: Optional[Dict[str, Any]],
         deployment_mode: str = "on_prem") -> Dict[str, Any]:
    """Missing sources, ordered by how many checks each would let run.

    `manifest` is `coverage.build_manifest`'s output. Without one this returns
    an empty ranking rather than guessing at what an estate supplied — advice
    invented from no evidence is worse than no advice.
    """
    missing = _missing_from(manifest)
    if not missing:
        return {"ranked": [], "unobtainable": [], "missing": 0,
                "checks_blocked": 0}

    by_check = coverage.check_sources()
    unreachable = set(coverage.RISE_UNREACHABLE_SOURCES)
    # Asked through the one place that owns the question. I spelled it as a
    # `startswith` here and `test_deployment_modes.py` refused it: four call
    # sites once did the same, and the helper exists so a mode added later
    # cannot land on the wrong side of it in a file nobody thinks to update.
    rise = deployment_modes.is_rise(deployment_mode)

    unlocks: Dict[str, Set[str]] = {s: set() for s in missing}
    also: Dict[str, Set[str]] = {s: set() for s in missing}
    blocked: Set[str] = set()

    for check_id, sources in by_check.items():
        needed = {s for s in (sources or []) if s in missing}
        if not needed:
            continue
        blocked.add(check_id)
        if len(needed) == 1:
            unlocks[next(iter(needed))].add(check_id)
        else:
            for source in needed:
                also[source].add(check_id)

    modules_for = coverage.module_sources()
    readers: Dict[str, List[str]] = {s: [] for s in missing}
    for module, sources in modules_for.items():
        for source in sources or []:
            if source in readers:
                readers[source].append(module)

    rows = []
    for source in sorted(missing):
        rows.append({
            "source": source,
            "unlocks_now": len(unlocks[source]),
            "also_needed_by": len(also[source]),
            "checks": sorted(unlocks[source])[:12],
            "modules": sorted(set(readers[source])),
            "obtainable": not (rise and source in unreachable),
        })

    # Unobtainable sources are separated rather than ranked: under RISE the
    # customer cannot produce them, so they are an explanation for a gap and
    # never a next step.
    obtainable = [r for r in rows if r["obtainable"]]
    blocked_by_contract = [r for r in rows if not r["obtainable"]]

    # Worth most first; ties broken by the checks that would follow later, then
    # by name so the order is stable between runs on identical input.
    obtainable.sort(key=lambda r: (-r["unlocks_now"], -r["also_needed_by"],
                                   r["source"]))
    return {
        "ranked": obtainable,
        "unobtainable": sorted(blocked_by_contract, key=lambda r: r["source"]),
        "missing": len(missing),
        "checks_blocked": len(blocked),
    }


def sentence(ranking: Dict[str, Any], top: int = 3) -> str:
    """One line a person can act on, or "" when there is nothing to say.

    Deliberately short. The scan already prints a paragraph of coverage prose
    and a second paragraph would be read as more of the same; this is the one
    sentence that names what to do next.
    """
    rows = [r for r in (ranking.get("ranked") or []) if r["unlocks_now"] > 0]
    if not rows:
        return ""
    picked = rows[:top]
    names = ", ".join(r["source"] for r in picked)
    gained = sum(r["unlocks_now"] for r in picked)
    rest = ranking.get("missing", 0) - len(picked)
    tail = (" The other %d missing source(s) would add %d more."
            % (rest, ranking["checks_blocked"] - gained)) if rest > 0 else ""
    # No "next" in the wording: the callers prefix it ("next: ...") and the
    # sentence read "next: Supply X next: ..." when both said it.
    return ("Supply %s — %d more check(s) would run.%s"
            % (names, gained, tail))
