"""Patch currency — how far behind the estate is on SAP Security Notes.

server/patch_currency.py rolls the HOTNEWS-* findings into a LATENCY view: the band
verdict, the oldest unapplied note, the actively-exploited-and-open set, the age
histogram and the SP-stack age. What must hold: it is `not_assessed` (never
`current`) when no applied-notes export was supplied; it computes age only from a
real release date and counts a dateless note apart rather than guessing; the band
verdict follows its stated criteria; and NO percentage is produced (the standing
patch-honesty rule — there is no knowable denominator). Plus: the note module now
stamps the structured per-note facts the rollup reads into each finding's details.
"""
from __future__ import annotations

import datetime as _dt
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server import patch_currency as pc          # noqa: E402
from modules.sap_hotnews import SapHotNewsAuditor  # noqa: E402

TODAY = _dt.date(2026, 1, 1)


def _fact(note, released=None, exploited=False, cvss=None, priority="High"):
    return {"note": note, "released": released, "exploited": exploited,
            "cvss": cvss, "priority": priority}


def _missing(facts, cid="HOTNEWS-001"):
    return {"check_id": cid, "details": {"missing_note_facts": facts}}


# ═════════════════════════════════════════════════════════════════════════════
#  Never "current" when we did not look
# ═════════════════════════════════════════════════════════════════════════════

def test_no_applied_notes_export_reads_not_assessed_never_current():
    # HOTNEWS-000 is the module's "no applied-notes export" signal.
    r = pc.roll_up([{"check_id": "HOTNEWS-000", "details": {}}], today=TODAY)
    assert r["band"] == pc.NOT_ASSESSED and r["assessed"] is False


def test_nothing_ran_at_all_is_not_assessed():
    r = pc.roll_up([], today=TODAY)
    assert r["band"] == pc.NOT_ASSESSED and r["assessed"] is False


def test_assessed_with_nothing_missing_is_current():
    # A HOTNEWS finding ran (coverage disclosure), no 000, no missing facts.
    r = pc.roll_up([{"check_id": "HOTNEWS-COVERAGE", "details": {}}], today=TODAY)
    assert r["assessed"] is True
    assert r["band"] == pc.CURRENT and r["totals"]["missing"] == 0


# ═════════════════════════════════════════════════════════════════════════════
#  The band verdict follows its criteria
# ═════════════════════════════════════════════════════════════════════════════

def test_an_exploited_open_note_is_critically_behind():
    r = pc.roll_up([_missing([_fact("200", "2025-11", exploited=True)])], today=TODAY)
    assert r["band"] == pc.CRITICALLY_BEHIND
    assert r["exploited_missing"]["count"] == 1


def test_a_note_open_over_a_year_is_critically_behind():
    r = pc.roll_up([_missing([_fact("300", "2024-10")])], today=TODAY)  # ~14 months
    assert r["band"] == pc.CRITICALLY_BEHIND
    assert r["oldest"]["age_days"] > 365


def test_a_missing_hotnews_note_is_at_least_lagging():
    r = pc.roll_up([_missing([_fact("100", "2025-11", priority="HotNews")])], today=TODAY)
    assert r["band"] == pc.LAGGING          # recent (61d), but HotNews -> lagging


def test_a_recent_non_hotnews_note_is_only_behind():
    r = pc.roll_up([_missing([_fact("101", "2025-12", priority="High")])], today=TODAY)
    assert r["band"] == pc.BEHIND


def test_an_out_of_date_sp_stack_alone_is_lagging():
    sp = {"check_id": "HOTNEWS-SPAGE-001",
          "details": {"age_days": 1200, "threshold_days": 730,
                      "release": "7.52", "sp": "SP10", "sp_release_date": "2022-01"}}
    r = pc.roll_up([sp], today=TODAY)
    assert r["sp_out_of_date"] is True and r["band"] == pc.LAGGING
    assert r["sp_stack"]["age_days"] == 1200


# ═════════════════════════════════════════════════════════════════════════════
#  Age is measured, never guessed
# ═════════════════════════════════════════════════════════════════════════════

def test_a_dateless_note_is_counted_apart_not_aged():
    r = pc.roll_up([_missing([_fact("900", released=None)])], today=TODAY)
    assert r["undated"]["count"] == 1
    assert r["oldest"] is None                      # nothing datable to be "oldest"
    assert sum(b["count"] for b in r["age_bands"]) == 0


def test_notes_fall_into_the_right_age_band():
    facts = [_fact("1", "2025-12"),    # ~31d  -> recent
             _fact("2", "2025-09"),    # ~122d -> ageing
             _fact("3", "2024-06")]    # ~579d -> over a year
    r = pc.roll_up([_missing(facts)], today=TODAY)
    by = {b["id"]: b["count"] for b in r["age_bands"]}
    assert by["recent"] == 1 and by["ageing"] == 1 and by["over_a_year"] == 1
    assert by["fresh"] == 0 and by["old"] == 0


def test_a_note_on_two_findings_counts_once_and_keeps_exploited():
    # Same note on HOTNEWS-001 (priority) and HOTNEWS-003 (exploited) -> one note,
    # exploited true.
    r = pc.roll_up([_missing([_fact("500", "2025-06", exploited=False)], "HOTNEWS-001"),
                    _missing([_fact("500", "2025-06", exploited=True)], "HOTNEWS-003")],
                   today=TODAY)
    assert r["totals"]["missing"] == 1
    assert r["exploited_missing"]["count"] == 1


# ═════════════════════════════════════════════════════════════════════════════
#  No percentage, ever
# ═════════════════════════════════════════════════════════════════════════════

def test_no_percentage_is_produced():
    r = pc.roll_up([_missing([_fact("1", "2024-06", exploited=True)])], today=TODAY)
    blob = repr(r).lower()
    assert "%" not in blob and "percent" not in blob and "pct" not in blob


# ═════════════════════════════════════════════════════════════════════════════
#  The note module stamps the structured facts the rollup reads
# ═════════════════════════════════════════════════════════════════════════════

# An applied-notes export that is present (so patches ARE assessed) but names no
# real catalogue note, so the ABAP HotNews/High notes are all missing.
_APPLIED = {"applied_notes": [{"NOTE": "1", "STATUS": "E"}]}


def test_missing_findings_carry_structured_per_note_facts():
    findings = SapHotNewsAuditor(dict(_APPLIED)).run_all_checks()
    missing = next((f for f in findings
                    if f["check_id"] in ("HOTNEWS-001", "HOTNEWS-002")), None)
    assert missing is not None, "expected a missing-notes finding from the empty export"
    details = missing["details"]
    # additive: the number list is still there, the facts are new.
    assert details["missing_notes"]
    facts = details["missing_note_facts"]
    assert facts and len(facts) == len(details["missing_notes"])
    one = facts[0]
    assert set(one) >= {"note", "released", "exploited", "cvss", "priority"}
    assert any(isinstance(f.get("released"), str) and "-" in f["released"] for f in facts)


def test_the_facts_feed_the_rollup_end_to_end():
    # The module's own output, fed straight into the rollup (what the query does),
    # yields a real latency verdict rather than not-assessed.
    findings = SapHotNewsAuditor(dict(_APPLIED)).run_all_checks()
    r = pc.roll_up(findings, today=TODAY)
    assert r["assessed"] is True
    assert r["band"] in (pc.BEHIND, pc.LAGGING, pc.CRITICALLY_BEHIND)
    assert r["totals"]["missing"] > 0
