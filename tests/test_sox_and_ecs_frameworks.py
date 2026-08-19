# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""SOX/ITGC as a framework, and SAP's ECS hardening as deliberately not one.

TWO THINGS THAT LOOK LIKE ONE ITEM AND ARE NOT. The roadmap asked for "SOX/ITGC
framework mapping; 'SAP ECS mandatory hardening' framework" in one line, and only
the first is a framework in this product's sense.

Every framework here is a theme-to-control map: a finding about privileged access
reaches ISO A.8.2 because both describe a kind of control. SAP Note 3250501 is 92
named parameters with a mandated value each, and its question is "is this
parameter what SAP requires" one parameter at a time. Forcing it into a theme
table would lose the parameter — which IS the control — and report a domain score
where the note gives a list. So it is a roll-up beside the frameworks.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import ecs_baseline                                # noqa: E402
from modules.compliance_mapping import ComplianceMapper         # noqa: E402


def fw(fid: str) -> dict:
    return next(f for f in ComplianceMapper.FRAMEWORKS if f["id"] == fid)


def controls(fid: str) -> list:
    return [pair for lst in fw(fid)["themes"].values() for pair in lst]


# ═════════════════════════════════════════════════════════════════════════════
#  SOX / ITGC
# ═════════════════════════════════════════════════════════════════════════════

def test_the_framework_is_present():
    assert fw("soxitgc")["name"] == "SOX / ITGC"


def test_it_claims_no_clause_numbers_because_itgc_publishes_none():
    """Unlike ISO 27001 or NIST 800-53, ITGC has no single published catalogue —
    the domains are an audit convention derived from COBIT and every firm numbers
    its own testing programme differently. Inventing `ITGC-3.2.1` to look like a
    citation is the coverage that fails on the first auditor question."""
    for cid, _name in controls("soxitgc"):
        assert not re.search(r"\d", cid), cid


def test_the_caveat_travels_with_the_table():
    """The subtitle is rendered on every report, which is the only place a
    disclaimer survives being copied into a slide."""
    assert "not claimed" in fw("soxitgc")["subtitle"]


def test_the_four_domains_are_the_ones_an_audit_is_organised_around():
    ids = {cid for cid, _ in controls("soxitgc")}
    assert ids == {"APD", "PC", "PD", "CO"}


@pytest.mark.parametrize("theme,domain", [
    ("sod", "APD"),                    # the classic SOX finding
    ("access-control", "APD"),
    ("privileged-access", "APD"),
    ("change-management", "PC"),
    ("secure-development", "PD"),
    ("logging-monitoring", "CO"),
    ("backup-recovery", "CO"),
])
def test_a_theme_reaches_the_domain_an_auditor_would_test_it_under(theme, domain):
    assert domain in {cid for cid, _ in fw("soxitgc")["themes"][theme]}


@pytest.mark.parametrize("theme", ["secure-config", "vuln-mgmt", "network-security",
                                   "cryptography", "app-runtime", "supplier-cloud"])
def test_themes_an_itgc_audit_does_not_test_are_left_unmapped(theme):
    """A defensible gap beats indefensible coverage — this file's own rule. These
    are real controls and they are not what an ITGC auditor tests under Computer
    Operations, which is about whether jobs ran, failures were noticed and data
    could be recovered."""
    assert theme not in fw("soxitgc")["themes"]


def test_a_segregation_of_duties_finding_reaches_the_sox_framework():
    """End to end: SoD is the number-one SAP audit driver and the reason this
    framework was asked for."""
    results = ComplianceMapper([
        {"check_id": "ARA-BASIS-01", "severity": "HIGH",
         "category": "Access Risk Analysis (SoD)", "title": "t"}]).assess()
    sox = next(r for r in results if r["id"] == "soxitgc")
    assert any(c["id"] == "APD" for c in sox["controls"])


# ═════════════════════════════════════════════════════════════════════════════
#  SAP ECS mandatory hardening — a roll-up, not a framework
# ═════════════════════════════════════════════════════════════════════════════

def test_it_is_deliberately_not_in_the_framework_list():
    """The distinction is the point: a customer asking "am I ISO-aligned?" wants
    themes; one asking "am I compliant with what SAP mandates?" wants the
    parameter that is wrong."""
    assert "ecs" not in {f["id"] for f in ComplianceMapper.FRAMEWORKS}
    src = (ROOT / "modules" / "ecs_baseline.py").read_text(encoding="utf-8")
    assert "WHY THIS IS NOT A `compliance_mapping` FRAMEWORK" in src


def _params(*pairs):
    return [{"NAME": n, "VALUE": v} for n, v in pairs]


def test_a_parameter_absent_from_the_export_is_neither_compliant_nor_deviating():
    """THE DISTINCTION THAT MATTERS. Collapsing absent into deviating reports an
    incomplete export as a non-compliant system; collapsing it into compliant does
    the reverse and worse."""
    got = ecs_baseline.compliance(_params(("auth/no_check_in_some_cases", "Y")),
                                 "rise_pce")
    assert got["compliant"] == ["auth/no_check_in_some_cases"]
    assert got["deviating"] == []
    assert len(got["absent_from_export"]) == got["mandated"] - 1


def test_the_rate_is_over_what_was_assessed_not_over_what_is_mandated():
    """A rate over all 92 when 40 were exported reports the 52 nobody looked at as
    failures — the defect the coverage manifest exists to stop."""
    got = ecs_baseline.compliance(_params(("auth/no_check_in_some_cases", "Y")),
                                 "rise_pce")
    assert got["assessed"] == 1
    assert got["rate"] == 1.0


def test_a_deviation_names_the_value_found_and_the_value_sap_requires():
    """A finding that says "non-compliant" without both numbers cannot be acted
    on without going back to the note."""
    got = ecs_baseline.compliance(_params(("auth/no_check_in_some_cases", "N")),
                                 "rise_pce")
    dev = got["deviating"][0]
    assert dev["parameter"] == "auth/no_check_in_some_cases"
    assert dev["found"] == "N" and dev["sap_standard"] == "Y"


def test_an_export_with_none_of_the_mandated_parameters_says_so_plainly():
    """Not 0% compliant. Nothing was assessed, and a zero would be a verdict."""
    got = ecs_baseline.compliance(_params(("some/other/param", "1")), "rise_pce")
    assert got["rate"] is None
    assert "says nothing about compliance" in got["summary"]


def test_it_returns_nothing_outside_ecs():
    """The note governs SAP Enterprise Cloud Services. Scoring an on-premise
    estate against a contract it is not under is the confidently-wrong reporting
    this module was created to prevent."""
    assert ecs_baseline.compliance(_params(("auth/no_check_in_some_cases", "Y")),
                                  "on_prem") == {}


def test_it_cites_the_note_it_scores_against():
    got = ecs_baseline.compliance(_params(("auth/no_check_in_some_cases", "Y")),
                                 "rise_pce")
    assert got["note"] == "SAP Note 3250501"
    assert got["mandated"] == len(ecs_baseline.parameters())


def test_the_sample_corpus_produces_a_partial_answer_and_admits_it():
    import contextlib
    import io

    from modules.data_loader import DataLoader
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(ROOT / "sample_data").load_all()
    got = ecs_baseline.compliance(data.get("security_params"), "rise_pce")
    assert got["assessed"] < got["mandated"]
    assert got["absent_from_export"]
    assert "are neither" in got["summary"]
