"""
Unevidenced code findings must not price a loss scenario.

WHY THIS IS THE MOST DANGEROUS DEFECT IN THE PRODUCT
The FAIR figure is the number a board reads, and calibration is BAND SELECTION
driven by the worst finding routed to each scenario — not a sum. So one finding is
enough to move it. Measured: a single CRITICAL finding moves portfolio ALE p90 from
$7.87M to $11.22M, a 42% swing.

89% of what the ABAP engine emits is `pattern-only`: a regex matched a statement
and no data flow was shown to reach it. Before this gate, any one of those at
CRITICAL moved the board's number by that much, invisibly.

READ test_a_confirmed_finding_still_prices FIRST.
It is the negative control, and it matters more than the exclusion test. A filter
that excluded EVERYTHING would pass the exclusion test perfectly while destroying
the quantification. When this was first measured against the real sample estate the
answer came back "0.0% movement" and looked like a clean pass — it was worthless,
because the baseline already saturated those scenarios' bands, so nothing moved the
figure either way. These tests use an empty baseline for exactly that reason.
"""
from __future__ import annotations

import io
import contextlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import fair_adapter                              # noqa: E402
from modules.risk_prioritizer import RiskPrioritizer          # noqa: E402


def _ale(findings):
    """Portfolio ALE p90 and the disclosed unevidenced count."""
    prioritizer = RiskPrioritizer()
    with contextlib.redirect_stdout(io.StringIO()):
        result = fair_adapter.run(
            findings, prioritizer.prioritize(findings),
            catalog_path=None, simulations=4000, seed=7,
            # At the catalogue's own contact rate, so the scale is 1.0 and every
            # figure this file asserts is the one it has always asserted. These
            # tests are about whether a finding PRICES — band selection, not
            # frequency — and without a frequency answer there is deliberately no
            # ALE to compare.
            frequency_answers={"observed_contacts_per_year": 5})
    summary = result.get("summary")
    if summary is None:
        pytest.skip("CRQ engine not locatable in this environment")
    return summary["portfolio"]["ale_p90"], result.get("unevidenced", 0)


def code_finding(confidence, severity="CRITICAL", check_id="ABAP-CMDI-001"):
    return {
        "check_id": check_id, "title": "OS command injection - Z_X",
        "severity": severity, "category": "Code & Transport Security",
        "description": "An OS command is built from external input.",
        "affected_items": ["Z_X line 88"], "remediation": "Remove the interpolation.",
        "details": {"confidence": confidence, "cwe": "CWE-78", "source": "abap_scan"},
        "scope": "aggregate",
    }


# --------------------------------------------------------------------------- #
#  The control, and then the gate                                             #
# --------------------------------------------------------------------------- #

def test_a_confirmed_finding_still_prices():
    """THE NEGATIVE CONTROL. If this fails, the gate is too broad and the whole
    quantification has been switched off rather than made honest."""
    empty, _ = _ale([])
    confirmed, excluded = _ale([code_finding("confirmed")])

    assert confirmed != empty, \
        "a taint-confirmed CRITICAL did not move the figure — the evidence gate " \
        "is excluding findings it should be pricing"
    assert excluded == 0


def test_a_tentative_finding_still_prices():
    """`tentative` means the taint analyzer RAN on a real sink and found no
    evidence either way. That is weaker than confirmed and far stronger than a
    bare pattern match, and it comes only from the eight sink-carrying rules."""
    empty, _ = _ale([])
    tentative, excluded = _ale([code_finding("tentative")])
    assert tentative != empty
    assert excluded == 0


def test_a_pattern_only_finding_prices_as_if_it_were_absent():
    empty, _ = _ale([])
    pattern, excluded = _ale([code_finding("pattern-only")])

    assert pattern == empty, \
        "a regex match with no data-flow evidence moved a figure a board reads"
    assert excluded == 1, "it was excluded but not disclosed"


def test_the_swing_it_would_have_caused_is_large_enough_to_matter():
    """Documents WHY this gate exists, and fails if the effect ever becomes
    negligible — at which point the gate is complexity for nothing."""
    empty, _ = _ale([])
    confirmed, _ = _ale([code_finding("confirmed")])
    swing = abs(confirmed - empty) / max(empty, 1)
    assert swing > 0.10, (
        f"a single CRITICAL only moves the portfolio by {swing:.0%}; if that is "
        f"genuinely all it does, this gate is not earning its keep")


# --------------------------------------------------------------------------- #
#  What must NOT be caught by the gate                                        #
# --------------------------------------------------------------------------- #

def test_a_finding_from_saps_own_atc_is_never_excluded():
    """The strongest evidence in the system. ATC findings carry no `confidence`
    key at all, and absence of the field must never read as 'unevidenced'."""
    atc = {
        "check_id": "ATC-CMDI", "title": "OS command injection - Z_X",
        "severity": "CRITICAL", "category": "Code & Transport Security",
        "description": "SAP's own code analysis reported this.",
        "affected_items": ["Z_X line 88"], "remediation": "Fix it.",
        "details": {"source": "atc_export", "evidence": "sap_atc", "cwe": "CWE-78"},
        "scope": "object",
    }
    empty, _ = _ale([])
    with_atc, excluded = _ale([atc])
    assert with_atc != empty, "a finding SAP itself reported was not priced"
    assert excluded == 0


def test_a_configuration_finding_is_never_excluded():
    """Every non-SAST check has no `confidence` key either. If the gate keyed on
    absence rather than on the explicit value, it would silently switch off the
    entire quantification."""
    param = {
        "check_id": "PARAM-LOGIN-001", "title": "Weak password policy",
        "severity": "HIGH", "category": "Security Parameters",
        "description": "login/min_password_lng is too low.",
        "affected_items": ["login/min_password_lng = 6"], "remediation": "Raise it.",
        "details": {}, "scope": "aggregate",
    }
    empty, _ = _ale([])
    with_param, excluded = _ale([param])
    assert with_param != empty
    assert excluded == 0


def test_the_predicate_only_fires_on_the_explicit_value():
    from modules.fair_adapter import _is_unevidenced
    assert _is_unevidenced({"details": {"confidence": "pattern-only"}}) is True
    for details in ({}, {"details": {}}, {"details": {"confidence": "confirmed"}},
                    {"details": {"confidence": "tentative"}},
                    {"details": {"confidence": None}}):
        assert _is_unevidenced(details if "details" in details else details) is False


# --------------------------------------------------------------------------- #
#  Disclosure                                                                 #
# --------------------------------------------------------------------------- #

def test_the_excluded_count_is_carried_all_the_way_to_the_summary():
    """A number the reader cannot interrogate is a number they should not trust.
    The count travels the same route as `unrouted`."""
    prioritizer = RiskPrioritizer()
    findings = [code_finding("pattern-only"), code_finding("pattern-only",
                                                           check_id="ABAP-SQLI-001")]
    with contextlib.redirect_stdout(io.StringIO()):
        result = fair_adapter.run(findings, prioritizer.prioritize(findings),
                                  catalog_path=None, simulations=1000, seed=7)
    assert result["unevidenced"] == 2
    if result.get("summary"):
        assert result["summary"]["unevidenced"] == 2


def test_the_report_discloses_the_exclusion_rather_than_hiding_it():
    from modules.report_generator import ReportGenerator
    # `_render_fair` returns "" without a populated portfolio, so this needs a
    # realistic one — an empty dict would make the test pass for the wrong reason.
    gen = ReportGenerator(
        findings=[], meta={"scan_date": "2026-08-07"},
        fair={"unevidenced": 58, "unrouted": 0,
              "portfolio": {"ale_p90": 11_215_594, "mean_ale": 4_100_000,
                            "ale_p50": 3_000_000, "loss_exceedance": []},
              "target_portfolio": {"ale_p90": 5_000_000, "mean_ale": 1_800_000},
              "scenarios": [], "organization": {"industry": "manufacturing"},
              "detection": {}, "simulations": 4000, "reducible_ale_p90": 6_215_594})
    html = gen._render_fair()
    assert html, "the FAIR section did not render at all — fixture is wrong"
    assert "58 code finding(s)" in html, "the exclusion was silent"
    assert "did <strong>not</strong>" in html
