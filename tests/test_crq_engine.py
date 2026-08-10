# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
Tests for the bundled FAIR Monte-Carlo engine.

The load-bearing test here is `test_vulnerability_matches_the_catalogue_calibration`.
The engine's vulnerability function is NOT a free choice: `data/fair_scenarios.json`
documents it and its resistance-strength bands are calibrated against it. The first
implementation used a plain `TC > RS` comparison — defensible FAIR theory in the
abstract — and it was measurably wrong for this catalogue: the hardened band
(68/82/95) is barely reachable by threat capability (55/72/85), so vulnerability
collapsed to ~0 and the model reported that remediating everything drives residual
risk to exactly $0. A zero residual is the first number a risk professional would
challenge.

Everything money-facing in the product rests on this file.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.crq_engine import (  # noqa: E402
    FAIREngine,
    _pert,
    _poisson,
    _vulnerability,
)

SCENARIO = {
    "id": "TEST-01",
    "name": "Test scenario",
    "contact_frequency": {"min": 2, "likely": 5, "max": 12},
    "probability_of_action": {"min": 0.05, "likely": 0.15, "max": 0.4},
    "threat_capability": {"min": 55, "likely": 72, "max": 85},
    "resistance_strength": {"min": 22, "likely": 38, "max": 55},
    "primary_loss": {"productivity": {"min": 100_000, "likely": 500_000,
                                      "max": 2_000_000}},
    "secondary_loss": {"fines": {"min": 0, "likely": 250_000, "max": 1_000_000}},
}


# --------------------------------------------------------------------------- #
#  Calibration — the part that must not drift                                 #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("band_rs,low,high", [
    (82, 0.30, 0.42),    # "hardened" — catalogue states ~0.3-0.4
    (38, 0.80, 0.86),    # "CRITICAL" — catalogue states ~0.8-0.85
])
def test_vulnerability_matches_the_catalogue_calibration(band_rs, low, high):
    """`data/fair_scenarios.json` states the function AND the values its bands
    were tuned to produce. If this fails, either the engine changed or the bands
    did — and they must change together, in the same commit."""
    v = _vulnerability(72, band_rs)
    assert low <= v <= high, (
        f"vulnerability at TC=72, RS={band_rs} is {v:.2f}, outside the calibrated "
        f"range {low}-{high}. The catalogue's resistance-strength bands are now "
        f"meaningless.")


def test_vulnerability_is_monotonic_and_bounded():
    """Stronger controls can never increase the chance of a loss event."""
    values = [_vulnerability(72, rs) for rs in range(0, 121, 10)]
    assert values == sorted(values, reverse=True)
    assert all(0.0 <= v <= 1.0 for v in values)
    assert _vulnerability(100, 0) == 1.0      # saturates, does not exceed 1
    assert _vulnerability(0, 100) == 0.0      # floors, does not go negative


def test_the_documented_bands_stay_discriminating():
    """The catalogue's stated goal is that the threat/control axis keeps
    modulating loss frequency — i.e. the bands must not all saturate at 1.0,
    which would make control strength irrelevant."""
    import json
    bands = json.loads((ROOT / "data" / "fair_scenarios.json").read_text(
        encoding="utf-8"))["resistance_strength_bands"]
    got = {k: _vulnerability(72, v["likely"])
           for k, v in bands.items() if isinstance(v, dict)}
    assert len(set(round(v, 2) for v in got.values())) == len(got), \
        f"bands are not distinguishable: {got}"
    assert max(got.values()) < 1.0, f"a band saturates at certainty: {got}"
    assert min(got.values()) > 0.0, f"a band floors at impossible: {got}"


# --------------------------------------------------------------------------- #
#  Distribution behaviour                                                     #
# --------------------------------------------------------------------------- #

def test_pert_stays_within_bounds_and_peaks_near_the_likely_value():
    import random
    rng = random.Random(1)
    draws = [_pert(rng, 10, 40, 100) for _ in range(4000)]
    assert all(10 <= d <= 100 for d in draws)
    mean = sum(draws) / len(draws)
    # BetaPERT mean is (min + 4*likely + max)/6 = (10 + 160 + 100)/6 = 45
    assert 42 <= mean <= 48, f"PERT mean {mean:.1f} is not near the analytic 45"


def test_pert_handles_a_degenerate_three_point_estimate():
    """min == likely == max is a legitimate "we know this number" estimate and
    must not raise on a customer's scan."""
    import random
    rng = random.Random(1)
    assert _pert(rng, 5, 5, 5) == 5.0


def test_poisson_is_zero_inflated_at_low_frequency():
    """A 0.3 expected frequency means "usually zero, sometimes one" — not
    "0.3 of an incident every year". Multiplying a fractional frequency by a
    magnitude would give every year the same non-zero loss."""
    import random
    rng = random.Random(7)
    draws = [_poisson(rng, 0.3) for _ in range(5000)]
    zeros = draws.count(0) / len(draws)
    assert 0.68 <= zeros <= 0.79, f"P(zero events) = {zeros:.2f}, expected ~0.74"
    assert sum(draws) / len(draws) == pytest.approx(0.3, abs=0.05)


def test_poisson_handles_a_high_frequency_without_underflow():
    import random
    rng = random.Random(7)
    draws = [_poisson(rng, 50) for _ in range(500)]
    assert sum(draws) / len(draws) == pytest.approx(50, rel=0.1)
    assert all(d >= 0 for d in draws)


# --------------------------------------------------------------------------- #
#  Engine                                                                     #
# --------------------------------------------------------------------------- #

def test_a_scenario_produces_a_plausible_distribution():
    res = FAIREngine(simulations=4000, seed=42).simulate_scenario(SCENARIO, [], {})
    assert res.scenario_id == "TEST-01"
    assert len(res.ale_distribution) == 4000
    assert res.mean_ale > 0
    # Zero-inflated with a long right tail: the median sits well below the P90.
    assert res.percentiles[50] < res.percentiles[90] < res.percentiles[99]
    assert res.severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def test_the_same_input_gives_the_same_number():
    """A currency figure that drifts between runs of identical findings is
    indistinguishable from a real change in exposure, which would make the trend
    chart worthless."""
    a = FAIREngine(simulations=2000, seed=42).simulate_scenario(SCENARIO, [], {})
    b = FAIREngine(simulations=2000, seed=42).simulate_scenario(SCENARIO, [], {})
    assert a.ale_distribution == b.ale_distribution


def test_scenarios_do_not_share_a_random_stream():
    """Each scenario derives its own stream from its id, so adding or reordering
    scenarios cannot change any other scenario's result."""
    other = dict(SCENARIO, id="TEST-02")
    a = FAIREngine(simulations=1500, seed=42).simulate_scenario(SCENARIO, [], {})
    b = FAIREngine(simulations=1500, seed=42).simulate_scenario(other, [], {})
    assert a.ale_distribution != b.ale_distribution


def test_stronger_controls_reduce_exposure_but_never_to_zero():
    """THE regression test for the bug this engine shipped with. Hardening must
    cut exposure substantially — and must leave a residual, because a model that
    says 'fix everything and your risk is exactly $0' is not credible."""
    hardened = dict(SCENARIO, resistance_strength={"min": 68, "likely": 82, "max": 95})
    weak = FAIREngine(simulations=6000, seed=42).simulate_scenario(SCENARIO, [], {})
    strong = FAIREngine(simulations=6000, seed=42).simulate_scenario(hardened, [], {})

    assert strong.mean_ale < weak.mean_ale, "hardening did not reduce exposure"
    assert strong.mean_ale > 0, (
        "a fully hardened posture reported ZERO residual risk — the vulnerability "
        "function no longer matches the catalogue's calibrated bands")
    assert strong.percentiles[90] > 0


def test_a_scenario_with_no_contact_has_no_loss():
    quiet = dict(SCENARIO, contact_frequency={"min": 0, "likely": 0, "max": 0})
    res = FAIREngine(simulations=1000, seed=42).simulate_scenario(quiet, [], {})
    assert res.mean_ale == 0.0


def test_secondary_loss_is_conditional_not_universal():
    """Secondary loss applies to the fraction of events that escalate. Applying
    it to every event would roughly double every figure in the product."""
    no_secondary = {k: v for k, v in SCENARIO.items() if k != "secondary_loss"}
    with_secondary = FAIREngine(simulations=6000, seed=42).simulate_scenario(
        SCENARIO, [], {})
    without = FAIREngine(simulations=6000, seed=42).simulate_scenario(
        no_secondary, [], {})

    assert with_secondary.mean_ale > without.mean_ale
    # If secondary applied to every event the ratio would approach
    # (500k + 250k)/500k = 1.5; conditional escalation must keep it well below.
    ratio = with_secondary.mean_ale / without.mean_ale
    assert 1.0 < ratio < 1.45, f"secondary loss ratio {ratio:.2f} looks unconditional"


def test_loss_exceedance_curve_is_monotonic():
    res = FAIREngine(simulations=3000, seed=42).simulate_scenario(SCENARIO, [], {})
    curve = FAIREngine._calc_loss_exceedance(sorted(res.ale_distribution))
    assert curve
    losses = [p["loss"] for p in curve]
    assert losses == sorted(losses, reverse=True), \
        "a less likely outcome must not have a smaller loss"
    for point in curve:
        assert 0.0 <= point["probability"] <= 1.0


def test_the_engine_is_discoverable_by_the_adapter():
    """The adapter locates an engine on disk. If this stops resolving, `--crq`
    silently degrades to 'inputs exported, not simulated' — which is exactly the
    state this engine was written to fix, and it fails quietly."""
    from modules.fair_adapter import locate_engine
    mod = locate_engine()
    assert mod is not None, "no CRQ engine is discoverable; --crq will produce no number"
    assert hasattr(mod, "FAIREngine")


def test_the_curve_the_engine_emits_is_the_curve_the_report_can_draw():
    """The engine's output shape must be renderable, not merely well-formed.

    THE DEFECT THIS PINS. `_calc_loss_exceedance` returns
    `[{"probability": p, "loss": x}, ...]`; `ReportGenerator._svg_lec` was written
    against `[(loss, probability), ...]` and unpacked `for t, p in points`, which
    over dicts iterates their KEYS. Every `--crq` run raised
    `ValueError: could not convert string to float: 'probability'` in the final
    step, so the scan ran, the Monte-Carlo ran, the `.crq.json` was written — and
    NO HTML report was produced at all.

    Two existing tests both passed throughout: `test_loss_exceedance_curve_is_monotonic`
    checks the engine in isolation, and the report-side test supplied
    `"loss_exceedance": []`, which returns early before the unpacking. A contract
    between two components needs a test that spans BOTH, or each side stays
    internally consistent while the seam is broken.
    """
    from modules.report_generator import ReportGenerator

    res = FAIREngine(simulations=2000, seed=11).simulate_scenario(SCENARIO, [], {})
    curve = FAIREngine._calc_loss_exceedance(sorted(res.ale_distribution))
    assert curve, "no curve to render — fixture is wrong"

    svg = ReportGenerator(findings=[], meta={"scan_date": "2026-08-09"})._svg_lec(curve)
    assert svg, "the engine's own curve rendered to nothing"
    assert "<polyline" in svg and "<polygon" in svg


def test_the_curve_renderer_also_accepts_pair_tuples():
    """The renderer's original shape stays supported — an external engine supplied
    via --crq-engine / CRQ_ENGINE need not match the bundled one's container type,
    and a report must not be lost over that."""
    from modules.report_generator import ReportGenerator

    gen = ReportGenerator(findings=[], meta={"scan_date": "2026-08-09"})
    svg = gen._svg_lec([(1_000_000.0, 0.9), (5_000_000.0, 0.5), (9_000_000.0, 0.1)])
    assert "<polyline" in svg


def test_a_malformed_curve_costs_the_chart_and_not_the_report():
    """Degrade, never drop: an unusable point is skipped rather than raised. Losing
    a chart is cosmetic; losing the whole hand-over report is not."""
    from modules.report_generator import ReportGenerator

    gen = ReportGenerator(findings=[], meta={"scan_date": "2026-08-09"})
    # Nothing usable at all: no chart, and still no exception.
    assert gen._svg_lec([{"probability": "x", "loss": None}, "nonsense", None]) == ""
    # One bad point among good ones costs only that point — the curve still draws.
    svg = gen._svg_lec([{"loss": 10.0, "probability": 0.9},
                        {"bad": 1},
                        {"loss": 90.0, "probability": 0.1}])
    assert "<polyline" in svg
