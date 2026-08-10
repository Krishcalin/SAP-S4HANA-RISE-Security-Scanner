# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
Reachability: the thing a code scanner cannot compute.

SAP's Code Vulnerability Analyzer, Onapsis and Fortify all read ABAP and say a
statement is dangerous. None can say whether anyone can GET to it, because they
see the code and not the estate. This product holds both halves.

Two properties are protected here, and the second matters more than the first:

1. A reachable object's finding outranks the identical finding in dead code.
2. `unknown` is never read as either answer. Most objects will be unknown — an
   absent inventory means we know nothing, not that everything is dead — and a
   tool that quietly downgrades on absent evidence is worse than one that does
   not try.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.atc_import import AtcImportAuditor                # noqa: E402
from modules.reachability import (                             # noqa: E402
    REACHABLE, UNKNOWN, UNREACHABLE, ReachabilityIndex, stamp,
)
from modules.risk_prioritizer import RiskPrioritizer           # noqa: E402

TODAY = 20260807


def index(rows, today=TODAY):
    return ReachabilityIndex({"code_inventory": rows}, today=today)


def row(name, referenced="", last_used=""):
    return {"OBJECT_NAME": name, "OBJECT_TYPE": "PROG",
            "REFERENCED": referenced, "LAST_USED": last_used}


# --------------------------------------------------------------------------- #
#  The verdict                                                                #
# --------------------------------------------------------------------------- #

def test_referenced_code_is_reachable():
    assert index([row("Z_A", "YES")]).verdict("Z_A")["state"] == REACHABLE


def test_recently_executed_code_is_reachable_even_if_nothing_references_it():
    """Something ran it — a job, a tile, an RFC caller we cannot see. Calling that
    dead is the dangerous direction to be wrong in."""
    v = index([row("Z_A", "NO", "20260801")]).verdict("Z_A")
    assert v["state"] == REACHABLE


def test_unreferenced_and_never_executed_is_unreachable():
    v = index([row("Z_A", "NO", "")]).verdict("Z_A")
    assert v["state"] == UNREACHABLE
    assert "nothing references it" in v["reasons"]


def test_unreferenced_and_long_dormant_is_unreachable():
    assert index([row("Z_A", "NO", "20180101")]).verdict("Z_A")["state"] == UNREACHABLE


def test_an_object_missing_from_the_inventory_is_unknown_not_dead():
    v = index([row("Z_OTHER", "YES")]).verdict("Z_MISSING")
    assert v["state"] == UNKNOWN


def test_no_inventory_at_all_is_unknown_for_everything():
    assert ReachabilityIndex({}).verdict("Z_A")["state"] == UNKNOWN


def test_a_row_with_no_evidence_either_way_is_unknown():
    assert index([row("Z_A", "", "")]).verdict("Z_A")["state"] == UNKNOWN


@pytest.mark.parametrize("flag,expected", [
    ("X", REACHABLE), ("Yes", REACHABLE), ("TRUE", REACHABLE), ("1", REACHABLE),
    ("NO", UNREACHABLE), ("N", UNREACHABLE), ("FALSE", UNREACHABLE),
    # Placeholders are NOT negatives. A blank or a dash means the export did not
    # say, and reading that as "nothing references it" would dampen live code.
    ("", UNKNOWN), ("-", UNKNOWN),
])
def test_sap_boolean_spellings_are_understood(flag, expected):
    assert index([row("Z_A", flag, "")]).verdict("Z_A")["state"] == expected


def test_the_verdict_carries_its_evidence():
    """A risk decision a customer cannot audit is one they will not accept."""
    v = index([row("Z_A", "YES", "20260801")]).verdict("Z_A")
    assert v["reasons"] and all(isinstance(r, str) for r in v["reasons"])


def test_object_names_match_case_insensitively():
    assert index([row("Z_A", "YES")]).verdict("z_a")["state"] == REACHABLE


def test_stamp_always_sets_a_state_even_with_no_index():
    d = stamp({}, None, "Z_A")
    assert d["reachability"] == UNKNOWN and d["reachability_reasons"]


# --------------------------------------------------------------------------- #
#  What it does to the queue                                                  #
# --------------------------------------------------------------------------- #

CMDI = {"OBJECT_TYPE": "PROG", "FINDING_TYPE": "COMMAND_INJECTION",
        "SEVERITY": "CRITICAL", "LINE": "88",
        "DESCRIPTION": "OS command built from external input", "STATUS": "OPEN"}

INVENTORY = [row("Z_LIVE", "YES", "20260801"), row("Z_DEAD", "NO", "")]


def _tier_for(obj):
    data = {"custom_code_scan": [{**CMDI, "OBJECT_NAME": obj}],
            "code_inventory": INVENTORY}
    finding = next(f for f in AtcImportAuditor(data, {}).run_all_checks()
                   if f["check_id"] == "ATC-CMDI")
    return RiskPrioritizer().assess(finding), finding


def test_the_identical_finding_outranks_itself_when_the_code_is_live():
    live, _ = _tier_for("Z_LIVE")
    dead, _ = _tier_for("Z_DEAD")
    assert live.tier == "P1", live.tier
    assert dead.tier == "P3", dead.tier


def test_both_facts_appear_in_the_factor_list_with_their_points():
    live, _ = _tier_for("Z_LIVE")
    dead, _ = _tier_for("Z_DEAD")
    assert any(f["label"] == "Reachable code" and f["points"] > 0
               for f in live.factors)
    assert any(f["label"] == "Unreachable code" and f["points"] < 0
               for f in dead.factors)


def test_unreachable_never_drops_below_p3():
    """Dead code gets resurrected and copied. 'Nobody can reach it' is a statement
    about today, so the finding stays on a worked list rather than vanishing."""
    dead, _ = _tier_for("Z_DEAD")
    assert dead.tier == "P3", "an unreachable finding was buried at P4"


def test_an_unknown_object_is_tiered_as_if_the_signal_did_not_exist():
    data = {"custom_code_scan": [{**CMDI, "OBJECT_NAME": "Z_NOT_LISTED"}],
            "code_inventory": INVENTORY}
    f = next(x for x in AtcImportAuditor(data, {}).run_all_checks()
             if x["check_id"] == "ATC-CMDI")
    r = RiskPrioritizer().assess(f)
    assert f["details"]["reachability"] == UNKNOWN
    assert r.tier == "P2", "absent evidence moved the tier in one direction or the other"


# --------------------------------------------------------------------------- #
#  The FAIR-inflation defect this was really built to close                   #
# --------------------------------------------------------------------------- #

def test_a_code_findings_own_prose_can_no_longer_make_it_exposed():
    """`_EXPOSURE_KW` matches internet|external|publicly|exposed over the title and
    description. A code finding's description is a rule's canned explanation of a
    vulnerability CLASS, written once in exactly that vocabulary and reused for
    every occurrence — so it stamped `exposed` on essentially every ABAP finding,
    lifting each a tier and inflating the FAIR figure the board reads."""
    finding = {
        "check_id": "ABAP-SQLI-001", "severity": "HIGH",
        "category": "Code & Transport Security",
        "title": "Dynamic WHERE clause from variable",
        "description": ("An attacker can reach this endpoint from the internet and "
                        "supply external input that is publicly reachable."),
        "details": {"reachability": UNKNOWN},
    }
    assert RiskPrioritizer().assess(finding).exposed is False, \
        "an English word in a rule's canned description still sets `exposed`"


def test_a_non_code_finding_still_gets_exposure_from_its_text():
    """The keyword heuristic is fine where the description describes the thing
    that was actually found. Only code findings are carved out."""
    finding = {
        "check_id": "NET-001", "severity": "HIGH",
        "category": "Network & Service Exposure",
        "title": "Service listening on 0.0.0.0",
        "description": "Reachable from the internet without authentication.",
        "details": {},
    }
    assert RiskPrioritizer().assess(finding).exposed is True


def test_an_exploited_finding_is_never_dampened():
    """Reachability evidence must not override an actively-exploited signal."""
    finding = {
        "check_id": "ABAP-CMDI-001", "severity": "CRITICAL",
        "category": "Code & Transport Security",
        "title": "OS command injection",
        "description": "Actively exploited in the wild; public exploit available.",
        "details": {"reachability": UNREACHABLE, "reachability_reasons": ["dead"]},
    }
    r = RiskPrioritizer().assess(finding)
    assert not any(f["label"] == "Unreachable code" for f in r.factors)


# --------------------------------------------------------------------------- #
#  The attack path                                                            #
# --------------------------------------------------------------------------- #

def test_command_injection_in_custom_code_is_a_hop_in_the_os_command_path():
    """Custom ABAP that builds an OS command from external input is a way that hop
    becomes reachable without any gateway or job misconfiguration — the code is
    the mechanism."""
    import json
    d = json.loads((ROOT / "data" / "attack_paths.json").read_text(encoding="utf-8"))
    paths = d.get("paths", d) if isinstance(d, dict) else d
    tpl = next(p for p in paths if p["id"] == "SAPPATH-04")
    hop = next(h for h in tpl["hops"] if h["name"] == "OS command execution reachable")

    assert "ATC-CMDI" in hop["checks"]
    assert any(c.startswith("ABAP-CMDI-") for c in hop["checks"])
    assert "program" in hop["node_types"], \
        "the hop cannot name the object the finding is about"
    assert hop["cut"] is True, "this hop must remain a cut, or closing it means nothing"
