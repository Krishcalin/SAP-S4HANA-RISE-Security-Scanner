"""Remediation Roadmap — open findings sequenced into the P1-P4 action tiers.

server/remediation.py roadmap() (via the pure _build_roadmap over fetched rows)
sequences every open finding into the four action tiers, each tagged with the
owning team, its SLA due date, and whether it is the customer's to fix or a SAP
service request. What must hold: the four waves are always present in order; a
finding is placed by its STORED tier and parked in P4 (never dropped) when the
tier is absent; ownership drives the customer-vs-SAP split and the SLA table; and
within a wave the customer's own fixes sort first, worst-first.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.remediation import _build_roadmap   # noqa: E402


def _row(fid, check_id, severity="HIGH", tier="P2", owner="customer_fixable",
         system_id=1, sid="PRD", title=None):
    return {"id": fid, "check_id": check_id, "severity": severity,
            "priority_tier": tier, "remediation_owner": owner,
            "system_id": system_id, "sid": sid, "title": title or check_id}


def _waves(r):
    return {w["tier"]: w for w in r["waves"]}


def test_the_four_waves_are_always_present_in_order():
    r = _build_roadmap([])
    assert [w["tier"] for w in r["waves"]] == ["P1", "P2", "P3", "P4"]
    assert all(w["items"] == [] for w in r["waves"])
    assert r["totals"]["open"] == 0


def test_a_finding_is_placed_in_its_stored_tier():
    r = _build_roadmap([_row(1, "PARAM-login/x", tier="P1")])
    assert len(_waves(r)["P1"]["items"]) == 1
    assert _waves(r)["P1"]["items"][0]["check_id"] == "PARAM-login/x"


def test_an_untiered_finding_is_parked_in_p4_never_dropped():
    r = _build_roadmap([_row(1, "ABAP-SQLI-001", tier=None)])
    assert r["totals"]["open"] == 1
    assert len(_waves(r)["P4"]["items"]) == 1       # parked, not lost


def test_ownership_drives_the_customer_vs_sap_split():
    r = _build_roadmap([_row(1, "PARAM-x", owner="customer_fixable"),
                        _row(2, "OSEC-1", owner="ticket_to_sap")])
    items = {it["check_id"]: it for w in r["waves"] for it in w["items"]}
    assert items["PARAM-x"]["customer_fixable"] is True
    assert items["PARAM-x"]["owner_label"] == "Yours"
    assert items["OSEC-1"]["customer_fixable"] is False
    assert items["OSEC-1"]["owner_label"] == "SAP service request"
    assert r["totals"]["customer_fixable"] == 1 and r["totals"]["sap_owned"] == 1


def test_customer_fixes_sort_before_sap_then_worst_first():
    rows = [_row(1, "OSEC-1", severity="CRITICAL", tier="P1", owner="ticket_to_sap"),
            _row(2, "PARAM-low", severity="LOW", tier="P1", owner="customer_fixable"),
            _row(3, "PARAM-crit", severity="CRITICAL", tier="P1", owner="customer_fixable")]
    p1 = _waves(_build_roadmap(rows))["P1"]["items"]
    # customer-fixable first (actionable now), worst-first within that, SAP last
    assert [it["check_id"] for it in p1] == ["PARAM-crit", "PARAM-low", "OSEC-1"]


def test_sla_due_date_follows_tier_and_owner():
    r = _build_roadmap([_row(1, "PARAM-x", tier="P1", owner="customer_fixable"),
                        _row(2, "OSEC-1", tier="P1", owner="ticket_to_sap"),
                        _row(3, "PARAM-y", tier="P4", owner="customer_fixable")])
    items = {it["check_id"]: it for w in r["waves"] for it in w["items"]}
    # P1 both have a due date; the provider SLA is longer than the customer SLA.
    assert items["PARAM-x"]["due_date"] and items["OSEC-1"]["due_date"]
    assert items["OSEC-1"]["due_date"] > items["PARAM-x"]["due_date"]
    # P4 has no SLA.
    assert items["PARAM-y"]["due_date"] is None


def test_each_item_carries_a_team():
    r = _build_roadmap([_row(1, "PARAM-login/x")])
    assert r["waves"][1]["items"][0]["team"]   # non-empty (team_for)


def test_counts_and_measured_reconcile():
    rows = [_row(1, "PARAM-x", tier="P1", system_id=1, sid="PRD"),
            _row(2, "OSEC-1", tier="P2", owner="ticket_to_sap", system_id=2, sid="DEV")]
    r = _build_roadmap(rows, {"measured": "2026-01-01"})
    t = r["totals"]
    assert t["open"] == 2 == t["customer_fixable"] + t["sap_owned"]
    assert t["by_tier"]["P1"] == 1 and t["by_tier"]["P2"] == 1
    assert t["systems"] == 2
    assert t["measured"] == "2026-01-01"
    wave_items = sum(len(w["items"]) for w in r["waves"])
    assert wave_items == t["open"]             # nothing dropped
