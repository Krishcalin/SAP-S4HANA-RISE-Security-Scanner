# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
FAIR Monte-Carlo engine.

WHY THIS FILE EXISTS
--------------------
`modules/fair_adapter.py` builds calibrated FAIR scenario inputs and then hands
them to an engine it locates on disk — historically a sibling repository. That
repository is not present here, and never has been, so `--crq` silently degraded
to "scenario inputs exported, not simulated" and the product's headline
differentiator produced no number at all.

This is that engine, bundled, so the currency figure works out of the box. It is
LAST in `_ENGINE_CANDIDATES`, so an explicit `--crq-engine` path, the `CRQ_ENGINE`
environment variable, or an external sibling engine all still take precedence —
bundling must not silently change results for anyone who already has one.

Standard library only: `modules/` is stdlib-only by charter and CI enforces it.

THE MODEL
---------
Open FAIR, sampled per iteration:

    Loss Event Frequency = Threat Event Frequency x Vulnerability
      Threat Event Frequency = Contact Frequency x Probability of Action
      Vulnerability          = P(Threat Capability > Resistance Strength)

    Loss Magnitude = Primary Loss + (Secondary Loss x Secondary LEF)

    Annualised Loss Exposure = Loss Event Frequency x Loss Magnitude

Three modelling choices worth stating, because each is a place FAIR is commonly
implemented wrongly:

1. **Vulnerability uses the function the catalogue was calibrated against**, and
   is resolved per iteration. `data/fair_scenarios.json` states it explicitly:

       Vulnerability = clamp((TC - RS + 50) / 100, 0, 1)

   with its resistance-strength bands chosen so that a `hardened` posture lands
   near 0.3–0.4 and a `CRITICAL` open gap near 0.8–0.85 against threat
   capabilities of ~50–72.

   A naive `TC > RS` comparison — defensible FAIR theory in the abstract — is
   **wrong for this catalogue** and was measurably so: the hardened band (68/82/95)
   is barely reachable by threat capability (55/72/85), so vulnerability collapsed
   to ~0 and the model reported that remediating everything reduces residual risk
   to exactly $0. No risk professional accepts a zero residual, and it would be
   the first number challenged.

   Threat capability and resistance strength are still sampled per iteration and
   the event still either lands or does not — a Bernoulli draw against the
   computed probability — so the tail is preserved. What changed is the
   probability, not the resolution.

2. **Frequency is Poisson, magnitude is per event.** A year with an expected 0.3
   events is not "0.3 of an incident" — it is most often zero and occasionally
   one. Drawing an integer event count and sampling a fresh magnitude for each
   event is what produces a realistic zero-inflated distribution with a long
   right tail. Multiplying a fractional frequency by a single magnitude would
   give every year the same non-zero loss, which is both wrong and reassuring.

3. **Secondary loss is conditional.** It applies only to the fraction of events
   that escalate (regulatory action, disclosure, litigation), governed by the
   secondary loss event frequency rather than applied to every event.

Distributions are BetaPERT, the FAIR convention for a three-point
(min / most-likely / max) estimate: it concentrates mass near the most-likely
value while keeping the bounds reachable, unlike a triangular distribution which
is unrealistically peaked, or a uniform one which ignores the estimate entirely.
"""
from __future__ import annotations

import hashlib
import math
import random
from typing import Any, Dict, List, Optional, Sequence

#: BetaPERT shape parameter. 4 is the standard PERT weighting of the most-likely
#: value; higher concentrates more mass on it, lower approaches uniform.
PERT_LAMBDA = 4.0

#: Fraction of loss events that escalate into secondary losses (regulatory
#: response, notification, litigation) when a scenario does not state its own.
#: Conservative mid-range default — secondary loss applying to EVERY event would
#: roughly double every figure.
DEFAULT_SECONDARY_LEF = 0.35

#: ALE bands for the qualitative label. Presentation only; nothing computes from it.
_SEVERITY_BANDS = (
    (10_000_000, "CRITICAL"),
    (1_000_000, "HIGH"),
    (100_000, "MEDIUM"),
    (0, "LOW"),
)


def _stable_hash(text: str) -> int:
    """A 32-bit digest of `text` that is identical in every process, forever.

    random.Random(str) would also be stable, but it hashes the string through a
    different path and changing to it would move every existing figure for no
    gain. blake2b keeps the arithmetic below intact and only replaces the unstable
    term. Truncated to 32 bits because that is what the XOR expects.
    """
    return int.from_bytes(hashlib.blake2b(text.encode("utf-8"), digest_size=4).digest(),
                          "big")


def _pert(rng: random.Random, minimum: float, likely: float,
          maximum: float) -> float:
    """Sample a BetaPERT variate over [minimum, maximum] peaking at `likely`.

    Degenerate inputs are handled rather than raising: a scenario whose three
    points collapse to one value is a legitimate "we know this number" estimate,
    and a catalogue with min == max should not crash a customer's scan.
    """
    if maximum <= minimum:
        return float(minimum)
    likely = min(max(float(likely), float(minimum)), float(maximum))
    span = maximum - minimum

    alpha = 1.0 + PERT_LAMBDA * (likely - minimum) / span
    beta = 1.0 + PERT_LAMBDA * (maximum - likely) / span
    # betavariate is undefined for non-positive shapes; the arithmetic above
    # cannot produce them, but clamp rather than trust it.
    alpha = max(alpha, 1e-6)
    beta = max(beta, 1e-6)
    return minimum + rng.betavariate(alpha, beta) * span


def _three_point(spec: Any) -> Optional[Sequence[float]]:
    """Normalise a factor to (min, likely, max), or None if it is absent.

    Accepts the catalogue's ``{"min":..,"likely":..,"max":..}`` form and a bare
    number, so a scenario can pin a factor to a known constant.
    """
    if spec is None:
        return None
    if isinstance(spec, (int, float)):
        v = float(spec)
        return (v, v, v)
    if isinstance(spec, dict):
        if "likely" not in spec and "min" not in spec:
            return None
        lo = float(spec.get("min", spec.get("likely", 0.0)))
        ml = float(spec.get("likely", (lo + float(spec.get("max", lo))) / 2))
        hi = float(spec.get("max", ml))
        return (lo, ml, hi)
    return None


def _sum_loss_components(rng: random.Random,
                         block: Optional[Dict[str, Any]]) -> float:
    """Total one loss block by sampling each named component independently.

    Components are summed per draw rather than pre-aggregated, so a scenario with
    a wide `fines` range and a narrow `response` range produces the right shape
    instead of one dominated by whichever was widened.
    """
    if not block:
        return 0.0
    total = 0.0
    for spec in block.values():
        pts = _three_point(spec)
        if pts:
            total += _pert(rng, *pts)
    return total


class ScenarioResult:
    """Outcome of one scenario's simulation.

    Field names match what `fair_adapter._quantify` reads; changing them breaks
    the adapter.
    """

    __slots__ = ("scenario_id", "scenario_name", "ale_distribution", "percentiles",
                 "mean_ale", "mean_lef", "mean_lm", "severity")

    def __init__(self, scenario_id: str, scenario_name: str,
                 ale_distribution: List[float], percentiles: Dict[int, float],
                 mean_ale: float, mean_lef: float, mean_lm: float, severity: str):
        self.scenario_id = scenario_id
        self.scenario_name = scenario_name
        self.ale_distribution = ale_distribution
        self.percentiles = percentiles
        self.mean_ale = mean_ale
        self.mean_lef = mean_lef
        self.mean_lm = mean_lm
        self.severity = severity

    def __repr__(self) -> str:
        return (f"ScenarioResult({self.scenario_id!r}, mean_ale={self.mean_ale:,.0f}, "
                f"p90={self.percentiles.get(90, 0):,.0f})")


class FAIREngine:
    """Monte-Carlo simulator over Open FAIR scenarios.

    Seeded by default so a re-scan of unchanged findings reports an unchanged
    figure. A dollar number that drifts between runs of identical input would be
    indistinguishable from a real change in exposure, which would make the trend
    chart worthless.
    """

    def __init__(self, simulations: int = 10_000, seed: Optional[int] = 42):
        self.simulations = max(1, int(simulations or 1))
        self.seed = seed

    # ------------------------------------------------------------------ #

    def simulate_scenario(self, scenario: Dict[str, Any],
                          _findings: Optional[Sequence[Any]] = None,
                          organization: Optional[Dict[str, Any]] = None
                          ) -> ScenarioResult:
        """Simulate one scenario.

        `_findings` is accepted and ignored: calibration already happened in
        `fair_adapter.build_inputs`, which selected factor BANDS from the
        evidence. Re-deriving anything from findings here would double-count them
        — a finding is evidence that shifts a factor, never a loss in itself.
        """
        # Per-scenario stream, derived from the scenario id, so that adding or
        # reordering scenarios does not change any other scenario's draws.
        #
        # blake2b AND NOT hash(). THE CLASS DOCSTRING ABOVE PROMISES AN UNCHANGED
        # FIGURE FOR UNCHANGED INPUT, AND WITH hash() THAT PROMISE WAS FALSE.
        # Python salts hash() of a str per process (PEP 456), so every worker, every
        # request and every CLI invocation drew a different stream. Measured on the
        # shipped catalogue at seed=42, five processes returned portfolio P90s of
        # 8.38M, 7.71M, 6.92M, 7.40M and 7.56M — a 21% spread with nothing changed
        # but the process. Every one of those was reported as this landscape's risk,
        # and the trend chart plotted the difference as if it meant something.
        #
        # It only reproduced under PYTHONHASHSEED=0, which is how the test suite runs
        # a single process and why no test caught it. tests/test_crq_engine.py now
        # asserts across SUBPROCESSES, because that is the only place the bug lived.
        rng = random.Random(
            None if self.seed is None
            else (self.seed * 1_000_003) ^ _stable_hash(scenario.get("id", "")))

        cf = _three_point(scenario.get("contact_frequency")) or (0.0, 0.0, 0.0)
        poa = _three_point(scenario.get("probability_of_action")) or (1.0, 1.0, 1.0)
        tcap = _three_point(scenario.get("threat_capability"))
        rs = _three_point(scenario.get("resistance_strength"))
        slef = _three_point(scenario.get("secondary_loss_event_frequency"))

        primary = scenario.get("primary_loss")
        secondary = scenario.get("secondary_loss")

        ale: List[float] = []
        lef_total = 0.0
        lm_total = 0.0
        lm_samples = 0

        for _ in range(self.simulations):
            tef = _pert(rng, *cf) * _pert(rng, *poa)

            # Vulnerability, per iteration, using the function the catalogue was
            # calibrated against (see the module docstring). A plain TC > RS
            # comparison makes the hardened band unreachable and drives residual
            # risk to exactly zero.
            if tcap and rs:
                vuln = _vulnerability(_pert(rng, *tcap), _pert(rng, *rs))
                vulnerable = rng.random() < vuln
            else:
                vulnerable = True
            lef = tef if vulnerable else 0.0
            lef_total += lef

            # Integer event count for the year. A 0.3 expected frequency means
            # "usually zero, sometimes one", not "0.3 of an incident".
            events = _poisson(rng, lef)
            if not events:
                ale.append(0.0)
                continue

            year_loss = 0.0
            for _event in range(events):
                loss = _sum_loss_components(rng, primary)
                if secondary:
                    escalation = (_pert(rng, *slef) if slef else DEFAULT_SECONDARY_LEF)
                    if rng.random() < max(0.0, min(1.0, escalation)):
                        loss += _sum_loss_components(rng, secondary)
                year_loss += loss
                lm_total += loss
                lm_samples += 1
            ale.append(year_loss)

        ordered = sorted(ale)
        mean_ale = sum(ale) / len(ale) if ale else 0.0
        return ScenarioResult(
            scenario_id=scenario.get("id", ""),
            scenario_name=scenario.get("name", ""),
            ale_distribution=ale,
            percentiles={p: _percentile(ordered, p) for p in (10, 50, 90, 95, 99)},
            mean_ale=mean_ale,
            mean_lef=lef_total / self.simulations if self.simulations else 0.0,
            mean_lm=lm_total / lm_samples if lm_samples else 0.0,
            severity=_severity(mean_ale),
        )

    # ------------------------------------------------------------------ #

    @staticmethod
    def _calc_loss_exceedance(sorted_ale: Sequence[float]) -> List[Dict[str, float]]:
        """Loss-exceedance curve: P(annual loss >= X) at each sampled percentile.

        This is the chart a risk committee reads — "there is a 10% chance of
        losing at least this much in a year" — and it is far more useful than a
        single expected value, which for a zero-inflated distribution is a number
        that will almost never occur.
        """
        if not sorted_ale:
            return []
        out: List[Dict[str, float]] = []
        for pct in (99, 95, 90, 80, 70, 60, 50, 40, 30, 20, 10, 5, 1):
            out.append({
                "probability": round(1.0 - pct / 100.0, 4),   # exceedance
                "loss": _percentile(sorted_ale, pct),
            })
        return out


def _vulnerability(threat_capability: float, resistance_strength: float) -> float:
    """P(a contact event becomes a loss event), on the FAIR percentile scale.

    THE FORM OF THIS FUNCTION IS NOT FREE — `data/fair_scenarios.json` documents
    it and its resistance-strength bands are calibrated to it:

        hardened  RS 68/82/95  vs TC ~72  ->  ~0.40
        CRITICAL  RS 22/38/55  vs TC ~72  ->  ~0.84

    Changing it silently re-scales every scenario in the catalogue. If it ever
    needs to change, the bands must be re-calibrated in the same commit.
    """
    return max(0.0, min(1.0, (threat_capability - resistance_strength + 50.0) / 100.0))


def _poisson(rng: random.Random, lam: float) -> int:
    """Number of loss events in a year, given an expected frequency.

    Knuth's method below ~30; a normal approximation above it, where the product
    of uniforms underflows and the approximation is accurate anyway.
    """
    if lam <= 0:
        return 0
    if lam < 30:
        target = math.exp(-lam)
        k, product = 0, 1.0
        while True:
            product *= rng.random()
            if product <= target:
                return k
            k += 1
            if k > 1000:            # numerical guard; unreachable for lam < 30
                return k
    return max(0, int(round(rng.gauss(lam, math.sqrt(lam)))))


def _percentile(sorted_vals: Sequence[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = int(len(sorted_vals) * p / 100)
    return sorted_vals[min(idx, len(sorted_vals) - 1)]


def _severity(ale: float) -> str:
    for threshold, label in _SEVERITY_BANDS:
        if ale >= threshold:
            return label
    return "LOW"
