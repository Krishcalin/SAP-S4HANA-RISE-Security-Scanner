"""The reports must not print a currency figure the customer never supplied.

THE DEFECT THESE LOCK OUT
The offline HTML and PDF used the scenario catalogue's illustrative $1bn
manufacturer whenever no figures were given, and printed its losses under the
customer's name to the cent. Measured on the reference estate before the fix: the
report said $8,825,060 while the console — which had the customer's own figures —
said $12,905,466. Same product, same estate, two numbers, and neither artefact
said why.

The report is the artefact that leaves the building, so it is the worse of the two
to be wrong.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import fair_adapter as fa                        # noqa: E402
from modules import fair_loss_model as lm                     # noqa: E402
from modules.report_generator import ReportGenerator          # noqa: E402

ANSWERS = {
    "sap_revenue": 420_000_000, "gross_margin_pct": 34,
    "revenue_hours_per_year": 8760, "downtime_hours": 16,
    "response_staff_cost_hour": 140, "response_staff_hours": 900,
    "pii_records": 12_000, "cost_per_record": 45,
    "max_single_payment_run": 9_500_000,
}


def _finding(check_id="USR-001", category="User & Authorization", sev="HIGH"):
    return {"check_id": check_id, "title": "t", "severity": sev,
            "category": category, "description": "d", "affected_items": []}


def _fair(loss_answers):
    findings = [_finding(), _finding("NET-001", "Network & Service Exposure", "CRITICAL")]
    return fa.run(findings, [], simulations=800, loss_answers=loss_answers)["summary"]


# ── the rule ─────────────────────────────────────────────────────────────────

def test_the_adapter_marks_whether_the_figures_were_the_customers():
    assert _fair(None)["loss_model"]["applied"] is False
    assert _fair(ANSWERS)["loss_model"]["applied"] is True


def test_the_html_report_prints_no_currency_without_customer_figures():
    """THE CENTRAL PROPERTY.

    A caveat under the number was considered and rejected: every caveat this
    product has written has been outlived by the figure above it, because a number
    in a board pack is screenshotted without its footnote. So the headline is
    ABSENT, not annotated.
    """
    findings = [_finding()]
    html = ReportGenerator(findings, {"target": "T"}, fair=_fair(None))._render_fair()
    assert "No currency figure is presented" in html
    # nothing shaped like a money total survives
    import re
    assert not re.search(r"\$\d[\d,]*\.?\d*\s*[MBK]\b", html), html[:400]


def test_the_html_report_does_print_currency_once_they_are_supplied():
    findings = [_finding()]
    html = ReportGenerator(findings, {"target": "T"}, fair=_fair(ANSWERS))._render_fair()
    assert "No currency figure is presented" not in html
    import re
    assert re.search(r"\$\d", html), "priced report shows no money at all"


def test_the_unpriced_section_still_reports_the_scenario_matching():
    """Withholding the money must not withhold the analysis. Scenario routing is
    driven by the customer's findings and is real."""
    findings = [_finding()]
    html = ReportGenerator(findings, {"target": "T"}, fair=_fair(None))._render_fair()
    assert "Findings routed" in html
    assert "Only the loss magnitude is unpriced" in html


# ── the console and the report cannot disagree ───────────────────────────────

def test_the_same_answers_give_the_same_scale_on_both_paths():
    """THE BUG THIS CATCHES WAS LIVE FOR A DAY.

    server/crq.py passes the customer's revenue as an org override AND as an
    answer. scale_factor read the POST-override org revenue as its denominator, so
    the ratio became revenue/revenue = 1.0 and the revenue scaling silently did
    nothing — measured at 1.0 where it should have been 0.42, leaving reputational
    damage and competitive advantage on a $420m business at a $1bn company's
    absolute figures.
    """
    console = fa.run([], [], org_overrides={"revenue": 420_000_000},
                     loss_answers=ANSWERS, simulations=500)
    offline = fa.run([], [], loss_answers=ANSWERS, simulations=500)
    assert (console["summary"]["loss_model"]["scale_factor"]
            == offline["summary"]["loss_model"]["scale_factor"] == pytest.approx(0.42))


def test_the_scale_denominator_is_the_catalogue_not_the_customer():
    """A scale of exactly 1.0 for a customer far from $1bn means the denominator
    was poisoned."""
    small = fa.run([], [], org_overrides={"revenue": 42_000_000},
                   loss_answers=dict(ANSWERS, sap_revenue=42_000_000), simulations=500)
    assert small["summary"]["loss_model"]["scale_factor"] == pytest.approx(0.042)


# ── the sidecar ──────────────────────────────────────────────────────────────

def test_the_loader_reads_crq_parameters_json(tmp_path):
    """Same convention as export_completeness.json, deliberately."""
    import json
    from modules.data_loader import DataLoader
    (tmp_path / "crq_parameters.json").write_text(
        json.dumps({"answers": ANSWERS, "revision": "r1"}), encoding="utf-8")
    data = DataLoader(tmp_path).load_all()
    payload = data.get(DataLoader.CRQ_PARAMETERS_KEY)
    assert payload and payload["answers"]["sap_revenue"] == 420_000_000


def test_an_absent_sidecar_means_unpriced_not_zero(tmp_path):
    from modules.data_loader import DataLoader
    data = DataLoader(tmp_path).load_all()
    assert data.get(DataLoader.CRQ_PARAMETERS_KEY) is None


def test_a_malformed_sidecar_is_ignored_rather_than_half_read(tmp_path):
    from modules.data_loader import DataLoader
    (tmp_path / "crq_parameters.json").write_text("[1,2,3]", encoding="utf-8")
    data = DataLoader(tmp_path).load_all()
    assert data.get(DataLoader.CRQ_PARAMETERS_KEY) is None


def test_the_sidecar_is_not_a_logical_source(tmp_path):
    """It must never appear in the coverage manifest as something the customer
    forgot to export — most customers have never heard of CRQ."""
    from modules.data_loader import DataLoader
    assert DataLoader.CRQ_PARAMETERS_KEY not in DataLoader.FILE_MAP
    assert DataLoader.CRQ_PARAMETERS_KEY.startswith("_")


# ── the new report sections ──────────────────────────────────────────────────

def test_the_html_report_carries_the_csf_section():
    findings = [_finding()]
    html = ReportGenerator(findings, {"target": "T"})._render_csf()
    assert "NIST Cybersecurity Framework 2.0" in html
    assert "not assessed" in html, "the three states must survive into print"
    assert "%" not in html.split("<table")[0] or "no score or percentage" in html


def test_the_csf_section_gives_no_score_or_percentage():
    """compliance_mapping.py forbids one and the reason holds here."""
    html = ReportGenerator([_finding()], {"target": "T"})._render_csf()
    import re
    assert not re.search(r"\d+\s*%", html), "a percentage reached the CSF section"


def test_the_html_report_carries_the_fair_cam_section():
    html = ReportGenerator([_finding()], {"target": "T"})._render_fair_cam()
    assert "FAIR-CAM" in html
    assert "Deterrence" in html
    assert "not assessed" in html, "Deterrence must not read as a clean zero"


def test_the_fair_cam_section_keeps_the_ambiguity_flag():
    """Nine of sixteen themes span more than one function. A printed table that
    hides that reads as a precise attribution, which is worse on paper."""
    findings = [_finding("IAM-001", "Identity & Access Management", "HIGH")]
    html = ReportGenerator(findings, {"target": "T"})._render_fair_cam()
    assert "ambiguous" in html


# ── the deck ─────────────────────────────────────────────────────────────────

def test_the_deck_no_longer_draws_a_compliance_percentage():
    """It drew controls_flagged / total_controls as a bar in a risk colour. A bar
    length is a percentage and the colour gives it a direction."""
    src = (ROOT / "modules" / "pptx_report.py").read_text(encoding="utf-8")
    assert 'controls_flagged"] / max(' not in src
    assert "frac" not in src.split("_compliance")[-1][:2000]
