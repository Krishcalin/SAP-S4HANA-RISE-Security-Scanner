"""Tests for the CFO-input loss model and the engine's reproducibility contract.

The reproducibility test runs SUBPROCESSES. That is the whole point of it: the
defect it guards lived in `hash()`, which Python salts per process, so a test that
built two engines in one interpreter could never see it — and the previous suite
did exactly that and passed for the entire life of the bug.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import fair_adapter as fa            # noqa: E402
from modules import fair_loss_model as lm         # noqa: E402

#: A mid-size manufacturer: the size of business this product actually meets, and
#: deliberately NOT the catalogue's illustrative $1B.
ANSWERS = {
    "sap_revenue": 420_000_000, "gross_margin_pct": 34,
    "revenue_hours_per_year": 8760, "downtime_hours": 16,
    "response_staff_cost_hour": 140, "response_staff_hours": 900,
    "pii_records": 12_000, "cost_per_record": 45,
    "regulatory_max_fine": 16_800_000, "max_single_payment_run": 9_500_000,
}


# ── reproducibility: the contract the class docstring makes ──────────────────

_REPRO = """
import sys
sys.path.insert(0, %r)
from modules import fair_adapter as fa
cat = fa.load_catalog()
built = fa.build_inputs([], cat, dict(cat.get("organization_default", {})))
eng = fa.locate_engine()
p = fa._quantify(built["asis"], eng, 2000, 42)["portfolio"]
print(repr((round(p["mean_ale"], 6), round(p["ale_p90"], 6))))
"""


def _run_in_subprocess() -> str:
    out = subprocess.run([sys.executable, "-c", _REPRO % str(ROOT)],
                         capture_output=True, text=True, cwd=str(ROOT))
    assert out.returncode == 0, out.stderr
    return out.stdout.strip()


def test_identical_inputs_reproduce_across_processes():
    """THE BUG THIS EXISTS FOR, and why it must fork.

    The engine promises "a re-scan of unchanged findings reports an unchanged
    figure". It seeded from hash(scenario_id), which PEP 456 salts per process, so
    the promise was false in every deployment — five processes returned portfolio
    P90s spanning 6.92M to 8.38M with nothing changed but the interpreter. It only
    held under PYTHONHASHSEED=0, which is how a single-process test suite runs.

    Three subprocesses, unpinned hash seed. They must agree exactly.
    """
    results = {_run_in_subprocess() for _ in range(3)}
    assert len(results) == 1, f"figures differ across processes: {results}"


def test_the_engine_does_not_seed_from_the_unstable_builtin():
    """A regression guard on the mechanism, not just the symptom.

    The subprocess test above is slow and easy to delete under time pressure. This
    one is instant and names the exact construct that broke.
    """
    source = (ROOT / "modules" / "crq_engine.py").read_text(encoding="utf-8")
    import ast
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id != "hash", (
                "crq_engine seeds from hash(), which Python salts per process")


# ── the loss model prices from the customer's own figures ────────────────────

def test_every_component_traces_to_an_answer():
    priced = lm.build_loss_components(ANSWERS)
    assert priced["components"], "nothing priced from a full answer set"
    for name, component in priced["components"].items():
        assert component["basis"], f"{name} has no stated basis"
        assert component["inputs"], f"{name} names no source answer"
        assert component["mam_module"] in lm.MAM_MODULES
        band = component["band"]
        assert band["min"] <= band["likely"] <= band["max"], name


def test_business_interruption_is_hours_times_hourly_margin():
    """The arithmetic is checkable by hand, and this checks it by hand."""
    priced = lm.build_loss_components(ANSWERS)
    band = priced["components"]["business_interruption"]["band"]
    expected = (420_000_000 * 0.34 / 8760) * 16
    assert band["likely"] == pytest.approx(expected, rel=1e-9)


def test_an_unanswered_question_leaves_its_module_unpriced_not_zero():
    """UNPRICED AND ZERO ARE DIFFERENT CLAIMS. Zero says the exposure does not
    exist; unpriced says nobody told us. Conflating them is the house's cardinal
    sin, applied to money."""
    answers = dict(ANSWERS)
    answers.pop("cost_per_record")
    priced = lm.build_loss_components(answers)
    assert "information_privacy" not in priced["components"]
    unpriced = {u["module"] for u in priced["unpriced"]}
    assert "information_privacy" in unpriced


def test_zero_records_is_an_answer_and_prices_at_zero():
    """Distinct from the case above: 'we hold no personal data' is knowledge."""
    answers = dict(ANSWERS, pii_records=0)
    priced = lm.build_loss_components(answers)
    assert "information_privacy" in priced["components"]
    assert priced["components"]["information_privacy"]["band"]["likely"] == 0.0


def test_no_benchmark_figure_is_ever_invented():
    """With NOTHING answered, the model must price NOTHING.

    A default per-record cost or a default downtime figure would be indefensible —
    we do not hold the study behind it — and would silently become the customer's
    number. Every module must land in `unpriced`.
    """
    priced = lm.build_loss_components({})
    assert priced["components"] == {}
    assert len(priced["unpriced"]) >= 5
    for entry in priced["unpriced"]:
        assert entry["needs"], entry


def test_the_spread_is_declared_where_a_reader_can_argue_with_it():
    assert set(lm.SPREAD) == {"min", "likely", "max"}
    assert lm.SPREAD["min"] < lm.SPREAD["likely"] < lm.SPREAD["max"]


# ── applying to a scenario ───────────────────────────────────────────────────

def test_replacement_maps_to_hardware_not_to_payment_fraud():
    """THE MAPPING BUG THAT MADE THE CUSTOMER'S ANSWERS LOOK IRRELEVANT.

    'Replacement Cost' is a FAIR-MAM form of loss shared by several modules, so the
    bare component name was routed to Financial Fraud. That priced a RANSOMWARE
    scenario with a payment-run figure, raised the component 3.8x, and cancelled
    the reductions everywhere else — the end-to-end result moved by 1.0x and looked
    like the feature did nothing.
    """
    mapping = lm._default_map({})
    assert mapping["replacement"] == "hardware_bricking"
    assert mapping["replacement"] != "financial_fraud"


def test_a_scenario_never_acquires_a_loss_it_never_had():
    """The catalogue decides WHICH losses a scenario produces; the customer decides
    HOW BIG. Mixing those authorities invents exposures nobody has."""
    scenario = {"id": "T", "primary_loss": {"productivity": {"min": 1, "likely": 2, "max": 3}}}
    priced = lm.build_loss_components(ANSWERS)
    applied = lm.apply_to_scenario(scenario, priced)
    assert set(applied["primary_loss"]) == {"productivity"}
    assert "secondary_loss" not in applied


def test_unpriced_components_are_scaled_not_left_at_the_illustrative_size():
    """Reputational damage is frequently the LARGEST term and cannot be priced from
    the question set. Left alone it would keep a $1B company's absolute figure on a
    $420M business."""
    scenario = {"id": "T", "secondary_loss": {"reputation": {"min": 1000.0,
                                                            "likely": 2000.0,
                                                            "max": 3000.0}}}
    priced = lm.build_loss_components(ANSWERS)
    applied = lm.apply_to_scenario(scenario, priced, scale=0.42)
    assert applied["secondary_loss"]["reputation"]["likely"] == pytest.approx(840.0)
    assert applied["_loss_provenance"]["scaled_from_illustrative"] == [
        "secondary_loss.reputation"]
    assert applied["_loss_provenance"]["kept_illustrative"] == []


def test_scale_factor_is_none_without_a_revenue_answer():
    assert lm.scale_factor({}, 1_000_000_000.0) is None
    assert lm.scale_factor({"sap_revenue": 0}, 1_000_000_000.0) is None
    assert lm.scale_factor({"sap_revenue": 420_000_000}, 1_000_000_000.0) == pytest.approx(0.42)


# ── the properties that make the number defensible ───────────────────────────

def _portfolio(answers, scenarios=None, sims=3000):
    catalogue = fa.load_catalog()
    org = dict(catalogue.get("organization_default", {}))
    priced = lm.build_loss_components(answers)
    scale = lm.scale_factor(answers, float(org.get("revenue") or 0))
    calibrated = dict(catalogue)
    calibrated["scenarios"] = [lm.apply_to_scenario(s, priced, scale)
                               for s in (scenarios or catalogue["scenarios"])]
    built = fa.build_inputs([], calibrated, org)
    return fa._quantify(built["asis"], fa.locate_engine(), sims, 42)["portfolio"]


def test_a_smaller_business_carries_a_smaller_loss():
    """The defect that started all this: every customer got a $1B company's losses."""
    small = _portfolio(dict(ANSWERS, sap_revenue=42_000_000))
    large = _portfolio(dict(ANSWERS, sap_revenue=4_200_000_000))
    assert small["ale_p90"] < large["ale_p90"]


def test_a_longer_outage_never_reduces_risk():
    quick = _portfolio(dict(ANSWERS, downtime_hours=4))
    slow = _portfolio(dict(ANSWERS, downtime_hours=72))
    assert slow["ale_p90"] >= quick["ale_p90"]


def test_percentiles_are_ordered():
    p = _portfolio(ANSWERS)
    assert p["ale_p10"] <= p["ale_p50"] <= p["ale_p90"] <= p["ale_p95"] <= p["ale_p99"]


def test_the_portfolio_reports_how_many_years_are_quiet():
    """A P90 headline with a $0 median is a true number that reads as a typical
    year. p_no_loss is what stops that."""
    p = _portfolio(ANSWERS)
    assert 0.0 <= p["p_no_loss"] <= 1.0
    assert p["iterations"] > 0


def test_p10_is_emitted_because_the_database_column_asks_for_it():
    """crq_result.ale_p10 was NULL in all 30 rows of the reference deployment: the
    column, the query and the wire type existed, and only the value was missing."""
    p = _portfolio(ANSWERS)
    assert "ale_p10" in p and "ale_p95" in p
