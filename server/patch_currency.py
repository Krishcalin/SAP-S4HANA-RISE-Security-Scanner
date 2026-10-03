"""Patch currency: how current the estate is on SAP Security Notes.

A lens over the HOTNEWS-* findings — it adds no checks. Onapsis and the rest
report WHICH notes are missing; none scores how far BEHIND the estate has fallen,
which is the question an auditor and a board actually ask. This answers it from
what the scan already produced.

NO PERCENTAGE, AND ON PURPOSE. A "percent patched" needs a denominator — every
note SAP ever released and whether each applies here — which no offline export
knows, so any percentage would be invented. The honest, checkable metrics are
LATENCY-based and need no denominator: how long a known-missing note has gone
unapplied (its release date is a fact), how many actively-exploited notes are
still open, and how old the support-package stack is. The headline is a BAND with
stated criteria, not a score.

NEVER "CURRENT" WHEN WE DID NOT LOOK. If no applied-notes export was supplied the
module raises HOTNEWS-000, and this reports `not_assessed` — the same discipline
as CLEAR-is-not-compliant elsewhere: an estate we could not assess must never read
as patched.

NEVER INVENTS A DATE. A note whose catalog entry carried no `released` is counted
in `undated` rather than assigned an age — the same refusal-to-fabricate the note
module applies to identifiers.

stdlib-only; reads server.queries.patch_findings output, emits no findings.
"""
from __future__ import annotations

import datetime as _dt
from typing import Any, Dict, List, Optional, Sequence

#: Age bands for a missing note, by days since release. Ascending; the last band
#: is open-ended. (id, human label, low, high-inclusive-or-None).
_BANDS = (
    ("fresh", "0–30 days", 0, 30),
    ("recent", "31–90 days", 31, 90),
    ("ageing", "91–180 days", 91, 180),
    ("old", "181–365 days", 181, 365),
    ("over_a_year", "over a year", 366, None),
)

# Band verdicts, worst to best. The UI renders the criteria; they are stated, not
# a magic number.
NOT_ASSESSED = "not_assessed"
CRITICALLY_BEHIND = "critically_behind"
LAGGING = "lagging"
BEHIND = "behind"
CURRENT = "current"


def _parse_released(released: Optional[str]) -> Optional[_dt.date]:
    """'YYYY-MM' -> first of that month, or None. A malformed or absent value is
    None (the note is then `undated`), never a guessed date."""
    if not released or not isinstance(released, str):
        return None
    parts = released.strip().split("-")
    try:
        year = int(parts[0])
        month = int(parts[1]) if len(parts) > 1 else 1
        return _dt.date(year, month, 1)
    except (ValueError, IndexError):
        return None


def _facts(findings: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The per-note facts sap_hotnews stamped into details.missing_note_facts,
    deduped by note number across HOTNEWS-001/002/003 (a note counts once even
    though it appears on both the HotNews finding and the exploited finding)."""
    out: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        details = f.get("details") or {}
        for fact in details.get("missing_note_facts") or []:
            note = str(fact.get("note") or "").strip()
            if not note:
                continue
            # First write wins, then OR the exploited flag — the exploited finding
            # and the priority finding describe the same note and must not disagree
            # about whether it is exploited.
            if note in out:
                out[note]["exploited"] = out[note]["exploited"] or bool(fact.get("exploited"))
                continue
            out[note] = {"note": note, "released": fact.get("released"),
                         "exploited": bool(fact.get("exploited")),
                         "cvss": fact.get("cvss"), "priority": fact.get("priority")}
    return list(out.values())


def _sp_stack(findings: Sequence[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    for f in findings:
        if f.get("check_id") == "HOTNEWS-SPAGE-001":
            d = f.get("details") or {}
            return {"release": d.get("release"), "sp": d.get("sp"),
                    "sp_release_date": d.get("sp_release_date"),
                    "age_days": d.get("age_days"),
                    "threshold_days": d.get("threshold_days")}
    return None


def _catalogue(findings: Sequence[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The catalogue-scope disclosure (HOTNEWS-COVERAGE), so the screen can repeat
    the note module's honesty: this is a curated subset, not the full patch day
    history, and a clean result is a floor not a clearance."""
    for f in findings:
        if f.get("check_id") == "HOTNEWS-COVERAGE":
            d = f.get("details") or {}
            return {"catalogue_size": d.get("catalogue_size"),
                    "curated_through": d.get("curated_through")}
    return None


def roll_up(findings: Sequence[Dict[str, Any]],
            coverage: Optional[Dict[str, Any]] = None,
            today: Optional[_dt.date] = None) -> Dict[str, Any]:
    """Patch-currency view over the HOTNEWS-* findings in scope.

    `today` is injectable so the age arithmetic is testable; it defaults to the
    real date. Returns the band verdict, the oldest unapplied note, the
    actively-exploited-and-open set, the age-band histogram, the SP-stack age, and
    an honesty flag — no percentage, and `not_assessed` whenever the applied-notes
    export was missing or the module did not run.
    """
    today = today or _dt.date.today()
    ids = {f.get("check_id") for f in findings}

    # Assessed? HOTNEWS-000 is the module's explicit "no applied-notes export"
    # signal; and if no HOTNEWS finding ran at all there is nothing to stand on.
    assessed = "HOTNEWS-000" not in ids and bool(findings)

    facts = _facts(findings)
    dated: List[Dict[str, Any]] = []
    undated: List[Dict[str, Any]] = []
    for fact in facts:
        released = _parse_released(fact.get("released"))
        if released is None:
            undated.append(fact)
        else:
            age = (today - released).days
            dated.append({**fact, "age_days": max(age, 0)})

    # Age-band histogram over the dated notes.
    band_counts = {b[0]: 0 for b in _BANDS}
    for d in dated:
        for bid, _label, low, high in _BANDS:
            if d["age_days"] >= low and (high is None or d["age_days"] <= high):
                band_counts[bid] += 1
                break
    age_bands = [{"id": bid, "label": label, "count": band_counts[bid]}
                 for bid, label, _lo, _hi in _BANDS]

    oldest = max(dated, key=lambda d: d["age_days"], default=None)
    exploited = sorted((d for d in dated if d["exploited"]),
                       key=lambda d: -d["age_days"])
    exploited_undated = [f for f in undated if f["exploited"]]

    by_priority: Dict[str, int] = {}
    for fact in facts:
        key = str(fact.get("priority") or "other")
        by_priority[key] = by_priority.get(key, 0) + 1

    sp_stack = _sp_stack(findings)
    sp_out_of_date = bool(sp_stack and sp_stack.get("age_days") is not None
                          and sp_stack.get("threshold_days") is not None
                          and sp_stack["age_days"] > sp_stack["threshold_days"])

    total_missing = len(facts)
    oldest_age = oldest["age_days"] if oldest else 0
    exploited_open = len(exploited) + len(exploited_undated)
    missing_hotnews = by_priority.get("HotNews", 0)

    if not assessed:
        band = NOT_ASSESSED
    elif exploited_open > 0 or oldest_age > 365:
        band = CRITICALLY_BEHIND
    elif missing_hotnews > 0 or oldest_age > 180 or sp_out_of_date:
        band = LAGGING
    elif total_missing > 0:
        band = BEHIND
    else:
        band = CURRENT

    return {
        "band": band,
        "assessed": assessed,
        "oldest": oldest,
        "exploited_missing": {
            "count": exploited_open,
            # dated first (we can show their age), then any undated exploited note.
            "notes": exploited + exploited_undated,
        },
        "age_bands": age_bands,
        "undated": {"count": len(undated), "notes": undated},
        "by_priority": by_priority,
        "sp_stack": sp_stack,
        "sp_out_of_date": sp_out_of_date,
        "catalogue": _catalogue(findings),
        "totals": {
            "missing": total_missing,
            "dated": len(dated),
            "measured": (coverage or {}).get("measured"),
        },
    }
