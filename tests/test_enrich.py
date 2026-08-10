# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
Tests for finding enrichment — priority, ownership, SLA.

The load-bearing one is `test_every_check_the_scanner_emits_gets_a_team`: the
team mapping is a prefix table, and a prefix table silently mis-matches. The real
bug it was written for was `S4AUTH-` in the table against `S4AUTHZ-001` in the
scanner — eight checks fell into "unassigned" and simply never appeared on any
team's worklist. Nothing failed; the work just quietly belonged to nobody.
"""
from __future__ import annotations

import re
import sys
from datetime import date, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.enrich import (  # noqa: E402
    RISE_UNREACHABLE_CHECKS,
    SLA_DAYS,
    SLA_DAYS_PROVIDER,
    enrich,
    remediation_owner_for,
    sla_due_date,
    team_for,
)

SAMPLE = ROOT / "sample_data"

#: Check IDs invented by tests, which no scanner module emits.
_TEST_FIXTURE_IDS = re.compile(r"^(REB-|T-\d)")


def _all_findings():
    import importlib
    from modules.data_loader import DataLoader
    from server.ingest import AUDITORS
    data = DataLoader(SAMPLE).load_all()
    out = []
    for mod, cls in AUDITORS:
        out.extend(getattr(importlib.import_module(f"modules.{mod}"), cls)(
            data).run_all_checks() or [])
    return out


# --------------------------------------------------------------------------- #
#  Team routing                                                               #
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_every_check_the_scanner_emits_gets_a_team():
    """A prefix table mis-matches silently. Work that routes to no team is work
    that appears on nobody's list and is never done."""
    orphans = sorted({f["check_id"] for f in _all_findings()
                      if team_for(f["check_id"]) == "unassigned"
                      and not _TEST_FIXTURE_IDS.match(f["check_id"])})
    assert not orphans, (
        f"{len(orphans)} check id(s) route to no owning team, so they will not "
        f"appear on any team's worklist: {orphans[:12]}"
    )


def test_longest_prefix_wins():
    """A specific family must be able to override its module's default."""
    assert team_for("AUTH-001") == "authorizations"
    assert team_for("S4AUTHZ-001") == "authorizations"
    assert team_for("STDUSR-002") == "basis"     # not 'identity' via any USR- rule


def test_team_lookup_is_case_insensitive():
    assert team_for("param-001") == team_for("PARAM-001") == "basis"


# --------------------------------------------------------------------------- #
#  Remediation ownership — the RISE distinction                               #
# --------------------------------------------------------------------------- #

def test_on_premise_everything_is_the_customers_to_fix():
    for cid in ("PARAM-001", "AUTH-001", "INTG-GW-001", "TRUST-005"):
        assert remediation_owner_for(cid, "on_prem") == "customer_fixable"


def test_in_rise_profile_parameters_become_a_ticket_to_sap():
    """A RISE customer can SEE a bad parameter and cannot save a change to it, so
    telling them to change it is unactionable. This is the difference between an
    action and noise."""
    assert remediation_owner_for("PARAM-001", "rise_pce") == "ticket_to_sap"
    assert remediation_owner_for("BASELINE-003", "rise_pce") == "ticket_to_sap"
    # ...but authorization content is squarely theirs.
    assert remediation_owner_for("AUTH-001", "rise_pce") == "customer_fixable"


def test_os_sourced_checks_are_only_unassessable_when_the_data_is_absent():
    """If the customer obtained the file some other way and uploaded it, the
    finding is real. Marking it unassessable on a general rule would discard
    evidence they went to the trouble of providing."""
    assert remediation_owner_for("INTG-GW-001", "rise_pce",
                                 data_was_supplied=False) == "not_assessable"
    assert remediation_owner_for("INTG-GW-001", "rise_pce",
                                 data_was_supplied=True) == "customer_fixable"
    for cid in RISE_UNREACHABLE_CHECKS:
        assert remediation_owner_for(cid, "rise_pce", False) == "not_assessable"


# --------------------------------------------------------------------------- #
#  SLA                                                                        #
# --------------------------------------------------------------------------- #

def test_p4_has_no_due_date():
    """A backlog item with a due date is a lie with a date on it."""
    assert sla_due_date("P4", "customer_fixable") is None
    assert SLA_DAYS["P4"] is None and SLA_DAYS_PROVIDER["P4"] is None


def test_provider_bound_work_gets_a_longer_clock():
    """Not leniency: the customer does not control SAP's queue, so measuring them
    against the same window attributes the provider's latency to them."""
    base = date(2026, 1, 1)
    own = sla_due_date("P2", "customer_fixable", base)
    sap = sla_due_date("P2", "ticket_to_sap", base)
    assert own == base + timedelta(days=7)
    assert sap == base + timedelta(days=30)
    assert sap > own


def test_tiers_get_progressively_longer_windows():
    base = date(2026, 1, 1)
    dates = [sla_due_date(t, "customer_fixable", base) for t in ("P1", "P2", "P3")]
    assert dates == sorted(dates) and len(set(dates)) == 3


# --------------------------------------------------------------------------- #
#  End to end                                                                 #
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_enrich_tiers_every_finding_and_explains_itself():
    findings = _all_findings()
    out = enrich(findings, "rise_pce", supplied_sources=set())

    assert len(out) == len(findings)
    tiers = {e["priority_tier"] for e in out.values()}
    assert tiers <= {"P1", "P2", "P3", "P4"}, f"unexpected tier(s): {tiers}"
    assert None not in tiers, "a finding was stored without a priority tier"

    # Explainability is the product: a tier with no factors is an unarguable number.
    assert all(e["priority_factors"] for e in out.values()), \
        "some findings have a tier but no factors explaining it"

    # P4 carries no due date; everything else does.
    for e in out.values():
        if e["priority_tier"] == "P4":
            assert e["due_date"] is None
        else:
            assert e["due_date"] is not None


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_the_same_findings_are_owned_differently_under_rise():
    """The deployment-mode switch is the whole point: shipping the on-premise view
    into a RISE account produces a report full of findings the customer cannot act
    on."""
    findings = _all_findings()
    on_prem = enrich(findings, "on_prem")
    rise = enrich(findings, "rise_pce", supplied_sources=set())

    assert all(e["remediation_owner"] == "customer_fixable" for e in on_prem.values())
    to_sap = sum(1 for e in rise.values() if e["remediation_owner"] == "ticket_to_sap")
    assert to_sap > 0, "no finding was routed to SAP under RISE"


def test_enrichment_degrades_rather_than_failing(monkeypatch):
    """A broken prioritiser must cost the tier, not the run."""
    import server.enrich as mod
    import modules.risk_prioritizer as rp

    class Exploding:
        def assess(self, f):
            raise RuntimeError("boom")

    monkeypatch.setattr(rp, "RiskPrioritizer", Exploding)
    out = mod.enrich([{"check_id": "AUTH-001", "severity": "HIGH", "title": "t",
                       "description": "d"}], "on_prem")
    entry = next(iter(out.values()))
    assert entry["priority_tier"] is None
    # Ownership and team do not depend on the prioritiser and must survive it.
    assert entry["owning_team"] == "authorizations"
    assert entry["remediation_owner"] == "customer_fixable"
