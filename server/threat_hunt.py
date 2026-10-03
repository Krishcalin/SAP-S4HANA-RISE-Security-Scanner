"""Threat Hunt: for every actively-exploited SAP note the estate has NOT applied,
the indicators to hunt for in the logs it already exported.

A lens, not a new analytic — it adds no checks. It bridges two things the product
already produces: the actively-exploited-and-missing notes (HOTNEWS-003 / the
`exploited` facts sap_hotnews stamps into each missing-note finding) and the
retrospective log review (log_review reads the Security Audit Log; logserv_review
reads the SAP LogServ ICM/gateway logs). Onapsis reports which patch is missing and,
separately, sells a real-time product that watches logs; nothing turns "you are
exposed to this exploited CVE" into "here is what to search your logs for." This
does, offline, over the logs the customer already has.

HONEST BY CONSTRUCTION.
  * An indicator exists only where public exploitation detail does (data/
    cve_ioc_hunt.json, sourced from CISA KEV / SAP / vendor reports). An exploited
    missing note with no authored pack is listed as such, never given invented IoCs.
  * `huntable` says whether the LOG an indicator lives in was even supplied — so a
    hunt the customer cannot run (because that export is missing) reads as "supply
    this log", not as a clean result.
  * It never asserts compromise. A matched indicator is evidence to investigate; the
    absence of a match over a short window is not an all-clear. The screen says so.

stdlib-only; reads existing findings + the coverage manifest; emits nothing.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from modules.coverage import UNSUPPLIED, look_verdict

_CATALOG_PATH = Path(__file__).resolve().parents[1] / "data" / "cve_ioc_hunt.json"

#: Which audit module reads each hunt log, so "huntable" can be answered from the
#: coverage manifest the same way the compliance/evidence machinery does it.
_LOG_MODULE = {
    "security_audit_log": "log_review",
    "logserv_events": "logserv_review",
}
_LOG_LABEL = {
    "security_audit_log": "Security Audit Log",
    "logserv_events": "SAP LogServ (ICM / gateway)",
}


@lru_cache(maxsize=1)
def _catalog() -> Dict[str, Any]:
    with open(_CATALOG_PATH, encoding="utf-8") as fh:
        doc = json.load(fh)
    return {k: v for k, v in doc.items() if k != "_meta"}


def _exploited_missing(findings: Sequence[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Note number -> {note, cvss} for every actively-exploited missing note, read
    from the per-note facts sap_hotnews stamps into the missing-note findings.
    Deduped across HOTNEWS-001/002/003 (a note appears on the priority finding and
    the exploited one)."""
    out: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        for fact in (f.get("details") or {}).get("missing_note_facts") or []:
            if not fact.get("exploited"):
                continue
            note = str(fact.get("note") or "").strip()
            if note and note not in out:
                out[note] = {"note": note, "cvss": fact.get("cvss")}
    return out


def _source_supplied(source: str, coverage: Optional[Dict[str, Any]]) -> Optional[bool]:
    """Was the log this indicator lives in supplied? None when unknown (no coverage
    manifest), so the screen can distinguish "not supplied" from "cannot tell"."""
    module = _LOG_MODULE.get(source)
    if module is None or coverage is None:
        return None
    return look_verdict({module}, coverage) != UNSUPPLIED


def roll_up(findings: Sequence[Dict[str, Any]],
            coverage: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Hunt packs for the actively-exploited notes the estate has not applied."""
    catalog = _catalog()
    exploited = _exploited_missing(findings)

    # Per-log supplied status, computed once.
    supplied_cache: Dict[str, Optional[bool]] = {
        src: _source_supplied(src, coverage) for src in _LOG_MODULE}

    threats: List[Dict[str, Any]] = []
    without_pack: List[Dict[str, Any]] = []
    for note, meta in exploited.items():
        entry = catalog.get(note)
        if not entry:
            without_pack.append({"note": note, "cvss": meta.get("cvss")})
            continue
        indicators = []
        used_logs: List[str] = []
        for ind in entry.get("indicators", []):
            src = ind.get("log")
            if src and src not in used_logs:
                used_logs.append(src)
            indicators.append({
                "log": src,
                "log_label": _LOG_LABEL.get(src, src),
                "signature": ind.get("signature", ""),
                "meaning": ind.get("meaning", ""),
                "log_supplied": supplied_cache.get(src),
            })
        # Huntable when at least one indicator's log was supplied. None (unknown)
        # only if every log's status is unknown.
        flags = [supplied_cache.get(s) for s in used_logs]
        huntable: Optional[bool]
        if any(flag is True for flag in flags):
            huntable = True
        elif all(flag is None for flag in flags):
            huntable = None
        else:
            huntable = False
        threats.append({
            "note": note,
            "cve": entry.get("cve"),
            "name": entry.get("name"),
            "summary": entry.get("summary", ""),
            "campaign": entry.get("campaign"),
            "cvss": meta.get("cvss"),
            "indicators": indicators,
            "confirm": entry.get("confirm", []),
            "references": entry.get("references", []),
            "log_sources": used_logs,
            "huntable": huntable,
        })

    # Worst first: huntable-now above not-huntable above unknown, then by CVSS.
    _rank = {True: 0, False: 1, None: 2}
    threats.sort(key=lambda t: (_rank[t["huntable"]],
                                -(t["cvss"] or 0), str(t["note"])))
    without_pack.sort(key=lambda t: (-(t["cvss"] or 0), str(t["note"])))

    logs = [{"id": src, "label": _LOG_LABEL[src], "module": _LOG_MODULE[src],
             "supplied": supplied_cache.get(src)} for src in _LOG_MODULE]

    return {
        "threats": threats,
        "without_pack": without_pack,
        "logs": logs,
        "totals": {
            "exploited_missing": len(exploited),
            "with_pack": len(threats),
            "without_pack": len(without_pack),
            "huntable_now": sum(1 for t in threats if t["huntable"] is True),
            "measured": (coverage or {}).get("measured"),
        },
    }
