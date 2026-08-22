"""The "yours under RISE / SAP's under RISE" tag, in the artefact that needs it.

WHAT WAS WRONG. Ownership was stamped onto every finding and the offline HTML
report threw it away at the last step, while the web console rendered it in three
places. `docs/RISE_SECURITY_MODEL.md` section 7.4 asks for the tag on every
finding and calls it "the argument that justifies buying anything at all in a RISE
tenant" — and it was missing from the artefact a customer reads before they have
bought anything.

WHAT THESE TESTS ARE FOR. That the split counts the SCAN and not the filtered
view, that it stays silent where it would say nothing, and that it never appears
on premise, where every finding is the customer's and a badge on all of them
trains the reader to ignore badges.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.report_generator import OWNER_LABELS, ReportGenerator   # noqa: E402

RISE = {"target": "T", "deployment_mode": "rise_pce"}
ONPREM = {"target": "T", "deployment_mode": "on_prem"}


def _f(check_id="PARAM-001", owner="customer_fixable", severity="HIGH", **kw):
    f = {"check_id": check_id, "title": "t", "severity": severity,
         "category": "Security Parameters", "description": "d",
         "affected_items": [], "affected_count": 0, "remediation": "r",
         "remediation_owner": owner}
    f.update(kw)
    return f


def _gen(findings, meta=RISE, **kw):
    return ReportGenerator(findings, meta, **kw)


# ═════════════════════════════════════════════════════════════════════════════
#  The split
# ═════════════════════════════════════════════════════════════════════════════

def test_the_report_states_how_much_of_it_is_not_the_customers_to_fix():
    html = _gen([_f(owner="ticket_to_sap"), _f(owner="ticket_to_sap"),
                 _f(owner="customer_fixable")])._render_ownership_split()
    assert "Who fixes what, under RISE" in html
    assert "2 of 3" in html
    assert "not yours to fix" in html


def test_the_split_counts_the_scan_and_not_the_severity_filtered_view():
    """THE RULE THE CLASS DOCSTRING SETS OUT. `--severity HIGH` decides what is
    LISTED, not what was found. Counting the filtered set would report "1 of 1 is
    yours" over a scan that found four findings, three of them SAP's."""
    shown = [_f(owner="customer_fixable", severity="HIGH")]
    whole = shown + [_f(owner="ticket_to_sap", severity="LOW") for _ in range(3)]
    html = _gen(shown, full_findings=whole)._render_ownership_split()
    assert "3 of 4" in html
    assert "1 of 1" not in html


def test_the_split_says_when_it_counted_more_than_the_page_shows():
    """Otherwise the reader compares the split against the findings below it and
    concludes one of the two is wrong."""
    shown = [_f(severity="HIGH")]
    whole = shown + [_f(owner="ticket_to_sap", severity="LOW")]
    html = _gen(shown, full_findings=whole)._render_ownership_split()
    assert "not the 1 shown below" in html


def test_a_scan_where_everything_is_the_customers_says_so_positively():
    html = _gen([_f(), _f()])._render_ownership_split()
    assert "All 2 findings are yours to fix" in html


def test_no_owner_on_any_finding_renders_nothing():
    """An empty split is not a finding that everything is the customer's. A
    report from an older run, or one whose findings never went through the
    stamping step, must not gain a governance claim it has no basis for."""
    stripped = [{"check_id": "X", "severity": "HIGH", "category": "c",
                 "title": "t", "affected_count": 0}]
    assert _gen(stripped)._render_ownership_split() == ""


def test_the_percentages_are_over_the_findings_that_carry_an_owner():
    html = _gen([_f(owner="ticket_to_sap")] * 3
                + [_f(owner="customer_fixable")])._render_ownership_split()
    assert "75%" in html and "25%" in html


def test_the_heuristic_behind_provider_owned_is_disclosed_in_the_footer():
    """`classify_destination_owner` guesses from naming patterns SAP does not
    publish exhaustively. A split that presents its output as fact invites the
    customer to close a finding SAP never owned."""
    html = _gen([_f(owner="provider_owned")])._render_ownership_split()
    assert "heuristic" in html
    assert "confirm once for your landscape" in html.lower()


# ═════════════════════════════════════════════════════════════════════════════
#  On premise the question does not arise
# ═════════════════════════════════════════════════════════════════════════════

def test_nothing_is_rendered_outside_rise():
    """Every finding is the customer's there, so a badge on all of them says
    nothing while teaching the reader to skip badges."""
    findings = [_f(owner="customer_fixable"), _f(owner="customer_fixable")]
    gen = _gen(findings, meta=ONPREM)
    assert gen._render_ownership_split() == ""
    assert gen._owner_badge(findings[0]) == ""


def test_an_unknown_deployment_mode_is_treated_as_not_rise():
    """A report built without the mode must not invent a RISE governance claim."""
    gen = _gen([_f()], meta={"target": "T"})
    assert gen._render_ownership_split() == ""


# ═════════════════════════════════════════════════════════════════════════════
#  The badge on each finding
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("owner", sorted(OWNER_LABELS))
def test_every_owner_state_has_a_badge(owner):
    badge = _gen([_f(owner=owner)])._owner_badge(_f(owner=owner))
    assert 'class="own-badge' in badge
    assert OWNER_LABELS[owner][0] in badge


def test_the_labels_are_what_the_reader_must_do_not_the_enum_name():
    """`ticket_to_sap` is an internal state. Section 7.4 asks for an argument,
    and nobody makes an argument in enum case."""
    for owner, (label, _css, tip) in OWNER_LABELS.items():
        assert "_" not in label, owner
        assert len(tip) > 30, owner


def test_not_assessable_says_it_is_not_a_pass():
    """The whole doctrine in one tooltip: we could not look must never render as
    we looked and found nothing."""
    assert "not a pass" in OWNER_LABELS["not_assessable"][2].lower()


def test_a_finding_specific_ownership_note_beats_the_generic_tooltip():
    """`provider_owned` carries a note naming the destinations and telling the
    customer to confirm the classification. Dropping it for the generic text
    would lose the only per-finding evidence the downgrade has."""
    note = "Every RFC destination named here is one SAP operates"
    badge = _gen([_f()])._owner_badge(_f(owner="provider_owned",
                                         ownership_note=note))
    assert note in badge


def test_an_unrecognised_owner_renders_no_badge_rather_than_a_blank_one():
    assert _gen([_f()])._owner_badge(_f(owner="something_new")) == ""


def test_the_card_carries_a_filterable_owner_attribute():
    """`data-severity`, `data-category` and `data-tier` are already there; a
    reader who wants only their own work should be able to get it."""
    html = _gen([_f(owner="ticket_to_sap")])._render_findings()
    assert 'data-owner="ticket_to_sap"' in html


# ═════════════════════════════════════════════════════════════════════════════
#  In the page
# ═════════════════════════════════════════════════════════════════════════════

def test_the_split_precedes_the_findings_in_the_template():
    """A reader who meets 359 findings before the split anchors on the wrong
    number and never revises it."""
    source = (ROOT / "modules" / "report_generator.py").read_text(encoding="utf-8")
    assert source.index("{ownership_html}") < source.index("{findings_html}")


def test_the_offline_scanner_passes_the_mode_to_the_report():
    """Without it the report cannot tell which estate it describes, and the split
    would never render for the customers it exists for."""
    src = (ROOT / "sap_scanner.py").read_text(encoding="utf-8")
    assert '"deployment_mode": args.deployment_mode' in src


def test_the_rendered_page_carries_both_in_rise_and_neither_on_premise(tmp_path):
    """End to end through generate(), because the split and the badges are wired
    through two different template holes and either could be dropped alone."""
    findings = [_f(owner="ticket_to_sap"), _f(owner="customer_fixable")]
    for meta, expected in ((RISE, True), (ONPREM, False)):
        out = tmp_path / ("r.html" if expected else "o.html")
        ReportGenerator(list(findings), meta).generate(str(out))
        page = out.read_text(encoding="utf-8")
        assert ('<div class="own-split">' in page) is expected
        assert ('<span class="own-badge' in page) is expected
