# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""Tests for the FAIR-CAM control attribution and the trend's series-break guard.

The properties worth pinning are conservation (a finding is worth one finding
however many functions it touches) and the three-state discipline (a function no
check can reach is NOT a clean zero).
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import fair_cam                              # noqa: E402
from modules.compliance_mapping import ComplianceMapper   # noqa: E402


# ── the standard's own structure ─────────────────────────────────────────────

def test_there_are_nine_loss_event_control_functions():
    """FAIR-CAM: three domains of three."""
    assert len(fair_cam.FUNCTIONS) == 9
    assert len(fair_cam.FUNCTION_ORDER) == 9
    assert set(fair_cam.FUNCTION_ORDER) == set(fair_cam.FUNCTIONS)


def test_each_domain_has_exactly_three_functions():
    counts = {d: sum(1 for f in fair_cam.FUNCTIONS.values() if f[1] == d)
              for d in fair_cam.DOMAIN_ORDER}
    assert counts == {"Prevention": 3, "Detection": 3, "Response": 3}


def test_prevention_moves_frequency_and_the_rest_move_magnitude():
    """The mapping the FAIR-CAM paper gives as A/B/C/D.

    Detection and Response do NOT stop the event, they shorten it. Attributing
    them to frequency is the commonest way FAIR-CAM is implemented wrongly and it
    flatters detection spending enormously.
    """
    assert fair_cam.factor_of("avoidance") == "contact_frequency"
    assert fair_cam.factor_of("deterrence") == "probability_of_action"
    assert fair_cam.factor_of("resistance") == "susceptibility"
    for fid in ("visibility", "monitoring", "recognition",
                "event_termination", "resilience", "loss_reduction"):
        assert fair_cam.factor_of(fid) == "loss_magnitude", fid


def test_variance_management_moves_no_fair_factor():
    """VMCs act on the RELIABILITY of other controls. Giving them a factor would
    double-count them against the very controls they maintain."""
    assert fair_cam.factor_of(fair_cam.VARIANCE_MANAGEMENT) is None


# ── the theme mapping ────────────────────────────────────────────────────────

def test_every_theme_the_mapper_uses_is_classified():
    """A theme with no entry contributes to no function AND SAYS NOTHING while
    doing it — the findings would vanish from the attribution silently."""
    themes = {t for ts in ComplianceMapper.CATEGORY_THEMES.values() for t in ts}
    assert themes - set(fair_cam.THEME_FUNCTIONS) == set()


def test_no_classified_theme_is_unknown_to_the_mapper():
    themes = {t for ts in ComplianceMapper.CATEGORY_THEMES.values() for t in ts}
    assert set(fair_cam.THEME_FUNCTIONS) - themes == set()


def test_every_theme_split_sums_to_one():
    """Otherwise a finding is worth more or less than one finding."""
    for theme, (splits, _c, _n) in fair_cam.THEME_FUNCTIONS.items():
        assert sum(splits.values()) == pytest.approx(1.0), theme


def test_every_split_target_is_a_real_function():
    valid = set(fair_cam.FUNCTIONS) | {fair_cam.VARIANCE_MANAGEMENT}
    for theme, (splits, _c, _n) in fair_cam.THEME_FUNCTIONS.items():
        assert set(splits) <= valid, theme


def test_every_ambiguous_theme_explains_itself():
    """A split we are guessing at must not look like one we can defend."""
    for theme, (_s, confidence, note) in fair_cam.THEME_FUNCTIONS.items():
        assert confidence in ("high", "medium", "ambiguous"), theme
        assert note, theme


def test_ambiguity_is_admitted_rather_than_flattened():
    """If this ever reports zero ambiguous themes, somebody has forced a tidy
    single mapping onto themes that genuinely span functions."""
    ambiguous = [t for t, (_s, c, _n) in fair_cam.THEME_FUNCTIONS.items()
                 if c == "ambiguous"]
    assert len(ambiguous) >= 5
    assert "logging-monitoring" in ambiguous   # spans all three Detection functions
    assert "privileged-access" in ambiguous    # Resistance AND Loss Reduction


# ── conservation ─────────────────────────────────────────────────────────────

def _corpus():
    return [
        {"category": "User & Authorization", "severity": "CRITICAL"},
        {"category": "Network & Service Exposure", "severity": "HIGH"},
        {"category": "Logging, Monitoring & IR", "severity": "MEDIUM"},
        {"category": "Identity & Access Management", "severity": "HIGH"},
        {"category": "Code & Transport Security", "severity": "LOW"},
    ]


def test_a_finding_is_worth_exactly_one_finding():
    """CONSERVATION. A finding whose theme reaches three functions contributes a
    third to each. Without this the attribution triple-counts and the column sums
    to more than the corpus — the same defect the CSF roll-up had."""
    findings = _corpus()
    result = fair_cam.classify(findings)
    total = (sum(f["findings"] for f in result["functions"])
             + result["variance_management"]["findings"]
             + result["unattributed"]["count"])
    assert total == pytest.approx(len(findings), abs=0.01)


def test_an_unmapped_category_is_reported_not_dropped():
    result = fair_cam.classify([{"category": "Nope", "severity": "HIGH"}])
    assert result["unattributed"]["count"] == 1
    assert "Nope" in result["unattributed"]["categories"]
    assert sum(f["findings"] for f in result["functions"]) == 0


def test_domains_sum_to_their_member_functions():
    result = fair_cam.classify(_corpus())
    by_id = {f["id"]: f for f in result["functions"]}
    for domain in result["domains"]:
        members = sum(by_id[fid]["findings"] for fid in domain["functions"])
        assert domain["findings"] == pytest.approx(members, abs=0.01)


def test_severity_changes_weight_but_never_the_finding_count():
    critical = fair_cam.classify([{"category": "User & Authorization", "severity": "CRITICAL"}])
    low = fair_cam.classify([{"category": "User & Authorization", "severity": "LOW"}])
    c = {f["id"]: f for f in critical["functions"]}["resistance"]
    l = {f["id"]: f for f in low["functions"]}["resistance"]
    assert c["findings"] == pytest.approx(l["findings"])
    assert c["weight"] > l["weight"]


# ── the three states ─────────────────────────────────────────────────────────

def test_a_function_no_check_can_reach_is_not_assessed_not_clear():
    """THE CENTRAL PROPERTY, and the same one the CSF view exists for.

    Deterrence controls are logon banners and visible-monitoring notices. No SAP
    configuration export evidences one, so Deterrence can only ever report 0.0 —
    and 0.0 drawn like a measurement says "this prevention layer is healthy"
    about something nobody examined.
    """
    result = fair_cam.classify(_corpus())
    by_id = {f["id"]: f for f in result["functions"]}
    assert by_id["deterrence"]["status"] == fair_cam.NOT_ASSESSED
    assert by_id["deterrence"]["reason"]
    assert fair_cam.CLEAR != fair_cam.NOT_ASSESSED


def test_a_reachable_function_with_no_findings_is_clear():
    """Distinct from the above: we looked, and there was nothing."""
    result = fair_cam.classify([{"category": "User & Authorization", "severity": "HIGH"}])
    by_id = {f["id"]: f for f in result["functions"]}
    assert by_id["resilience"]["status"] == fair_cam.CLEAR
    assert by_id["resilience"]["reason"] is None
    assert by_id["resistance"]["status"] == fair_cam.ASSESSED


def test_every_unreachable_function_carries_a_reason():
    reachable = set()
    for splits, _c, _n in fair_cam.THEME_FUNCTIONS.values():
        reachable |= set(splits)
    for fid in fair_cam.FUNCTION_ORDER:
        if fid not in reachable:
            assert fair_cam.UNREACHABLE_FUNCTIONS.get(fid), fid


def test_a_function_confidence_takes_the_worst_contributing_theme():
    """Reporting the best case would hide exactly the doubt a reader needs."""
    result = fair_cam.classify([
        {"category": "User & Authorization", "severity": "HIGH"},        # medium-ish
        {"category": "Identity & Access Management", "severity": "HIGH"},  # ambiguous
    ])
    by_id = {f["id"]: f for f in result["functions"]}
    assert by_id["resistance"]["confidence"] == "ambiguous"


def test_an_empty_corpus_still_returns_all_nine_functions():
    """Absence from the answer would be a fourth, unlabelled state."""
    result = fair_cam.classify([])
    assert len(result["functions"]) == 9
    assert {f["id"] for f in result["functions"]} == set(fair_cam.FUNCTIONS)
