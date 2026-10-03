"""Threat Hunt — IoCs to hunt for each actively-exploited unapplied SAP note.

server/threat_hunt.py joins the exploited-and-missing notes (the `exploited` facts
sap_hotnews stamps into the missing-note findings) to data/cve_ioc_hunt.json, and
reports whether the log each indicator lives in was supplied. What must hold: only
EXPLOITED missing notes appear; a catalogued note gets its real IoCs while an
un-catalogued one is listed WITHOUT invented indicators; `huntable` reflects
whether the reading module ran (never claims a hunt you cannot run); and every
catalogue key is a real exploited note (no fabricated CVE/note identifiers).
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server import threat_hunt as th            # noqa: E402
from modules.sap_hotnews import SapHotNewsAuditor  # noqa: E402

# A catalogued exploited note hunted in the LogServ log, and one hunted in the SAL.
_LOGSERV_NOTE = "3594142"   # CVE-2025-31324 (metadata uploader) -> logserv_events
_SAL_NOTE = "3627998"       # CVE-2025-42957 (RFC code injection) -> security_audit_log

# coverage manifests look_verdict understands: a module present+complete = it ran.
_COV_LOGSERV = {"modules": {"logserv_review": {"status": "complete"}}, "measured": "2026-01-01"}
_COV_SAL = {"modules": {"log_review": {"status": "complete"}}}
_COV_NONE_RAN = {"modules": {}}


def _fact(note, exploited=True, cvss=9.8):
    return {"note": note, "released": "2025-04", "exploited": exploited,
            "cvss": cvss, "priority": "HotNews"}


def _finding(facts):
    return {"check_id": "HOTNEWS-003", "details": {"missing_note_facts": facts}}


# ═════════════════════════════════════════════════════════════════════════════
#  Only exploited missing notes, and catalogued ones get real IoCs
# ═════════════════════════════════════════════════════════════════════════════

def test_a_catalogued_exploited_note_becomes_a_hunt_pack():
    r = th.roll_up([_finding([_fact(_LOGSERV_NOTE)])], _COV_LOGSERV)
    assert r["totals"]["with_pack"] == 1 and r["without_pack"] == []
    pack = r["threats"][0]
    assert pack["note"] == _LOGSERV_NOTE and pack["cve"] == "CVE-2025-31324"
    assert pack["indicators"] and pack["references"]
    assert all(i["signature"] for i in pack["indicators"])


def test_a_non_exploited_missing_note_is_ignored():
    r = th.roll_up([_finding([_fact(_LOGSERV_NOTE, exploited=False)])], _COV_LOGSERV)
    assert r["totals"]["exploited_missing"] == 0
    assert r["threats"] == [] and r["without_pack"] == []


def test_an_uncatalogued_exploited_note_is_listed_without_invented_iocs():
    r = th.roll_up([_finding([_fact("9999999")])], _COV_LOGSERV)
    assert r["threats"] == []
    assert [w["note"] for w in r["without_pack"]] == ["9999999"]
    assert r["totals"]["without_pack"] == 1


def test_a_note_on_two_findings_counts_once():
    r = th.roll_up([_finding([_fact(_LOGSERV_NOTE)]),
                    _finding([_fact(_LOGSERV_NOTE)])], _COV_LOGSERV)
    assert r["totals"]["exploited_missing"] == 1 and r["totals"]["with_pack"] == 1


# ═════════════════════════════════════════════════════════════════════════════
#  huntable never claims a hunt you cannot run
# ═════════════════════════════════════════════════════════════════════════════

def test_huntable_true_when_the_logs_reading_module_ran():
    r = th.roll_up([_finding([_fact(_LOGSERV_NOTE)])], _COV_LOGSERV)
    assert r["threats"][0]["huntable"] is True
    assert r["totals"]["huntable_now"] == 1


def test_huntable_false_when_no_log_was_supplied():
    r = th.roll_up([_finding([_fact(_LOGSERV_NOTE)])], _COV_NONE_RAN)
    assert r["threats"][0]["huntable"] is False
    assert r["totals"]["huntable_now"] == 0


def test_huntable_unknown_when_there_is_no_coverage_manifest():
    r = th.roll_up([_finding([_fact(_LOGSERV_NOTE)])], None)
    assert r["threats"][0]["huntable"] is None


def test_the_right_log_is_marked_supplied_per_indicator():
    # A SAL-hunted note with only the SAL reader run -> its indicators read supplied.
    r = th.roll_up([_finding([_fact(_SAL_NOTE)])], _COV_SAL)
    pack = r["threats"][0]
    assert "security_audit_log" in pack["log_sources"]
    assert any(i["log"] == "security_audit_log" and i["log_supplied"] is True
               for i in pack["indicators"])


def test_huntable_packs_sort_before_unhuntable():
    r = th.roll_up([_finding([_fact(_SAL_NOTE), _fact(_LOGSERV_NOTE)])], _COV_LOGSERV)
    # LogServ note is huntable (logserv_review ran); SAL note is not (log_review did
    # not) -> the huntable one comes first.
    assert r["threats"][0]["note"] == _LOGSERV_NOTE
    assert r["threats"][0]["huntable"] is True


# ═════════════════════════════════════════════════════════════════════════════
#  The catalogue is accurate (no fabricated identifiers), and self-consistent
# ═════════════════════════════════════════════════════════════════════════════

def test_every_catalogue_key_is_a_real_exploited_note():
    catalog = th._catalog()
    exploited_notes = {str(e["note"]) for e in SapHotNewsAuditor.HOTNEWS_CATALOG
                       if e.get("exploited")}
    stray = sorted(set(catalog) - exploited_notes)
    assert not stray, f"IoC catalogue names notes that are not exploited in HOTNEWS_CATALOG: {stray}"


def test_every_indicator_names_a_known_hunt_log():
    catalog = th._catalog()
    known = set(th._LOG_MODULE)
    for note, entry in catalog.items():
        for ind in entry.get("indicators", []):
            assert ind.get("log") in known, f"{note}: indicator log {ind.get('log')!r} is not a known hunt log"
            assert ind.get("signature"), f"{note}: an indicator has no signature"


def test_every_catalogue_entry_has_a_cve_and_references():
    for note, entry in th._catalog().items():
        assert entry.get("cve"), f"{note}: no CVE"
        assert entry.get("indicators"), f"{note}: no indicators"
        assert entry.get("references"), f"{note}: no references"


def test_totals_reconcile():
    r = th.roll_up([_finding([_fact(_LOGSERV_NOTE), _fact("9999999")])], _COV_LOGSERV)
    t = r["totals"]
    assert t["exploited_missing"] == t["with_pack"] + t["without_pack"] == 2
