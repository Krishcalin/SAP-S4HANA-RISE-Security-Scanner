# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""No console screen may print a currency figure the customer did not price.

The reports have obeyed this since the console/report split was closed. The
console did not: `loss_model` was stored, put on the wire, and read by nothing,
so five screens printed the illustrative $1bn manufacturer's losses under the
customer's name.

THIS FILE IS DELIBERATELY STRUCTURAL. The last three defects fixed in this
codebase were all siblings of an earlier fix applied in one place and not looked
past — a percentage deleted from the deck but not the console, a flag repaired
but not the one beside it. A test that checked one screen would be the same
mistake in test form, so this walks EVERY route file and fails on a new one.
"""
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

ROUTES = ROOT / "frontend" / "src" / "routes"
PRICING = ROOT / "frontend" / "src" / "lib" / "pricing.ts"



def _code_only(path: Path) -> str:
    """The file with its comments stripped.

    A PLAIN SUBSTRING SEARCH CANNOT TELL CODE FROM PROSE ABOUT CODE, and the
    first version of this file proved it: the assertion that ExposureSeries is
    gone was failed by the comment explaining why it went. That is the fourth
    time this repository has hit the pattern — CLAUDE.md records the previous
    three — so the checks below read code and the comments are free to discuss
    whatever they need to.
    """
    text = path.read_text(encoding="utf-8")
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)      # block and JSX comments
    text = re.sub(r"^\s*//.*$", "", text, flags=re.M)        # line comments
    return text


def _sources():
    """Every SCREEN in the routes directory.

    `.test.tsx` is excluded deliberately. The rule is about what a customer can
    be shown, and a test file shows a customer nothing — but it lives in this
    directory and it discusses `money()`, so an unfiltered glob fails on a
    comment in a test that is doing its job. That is the same code-versus-prose
    confusion `_code_only` exists for, arriving through the file list instead of
    through the file contents.

    Narrowing a guard deserves suspicion, so: no screen is reachable from a
    `.test.tsx` file, and the widest thing this could hide is a screen someone
    named as a test, which would not render either.
    """
    return {p.name: p.read_text(encoding="utf-8")
            for p in ROUTES.glob("*.tsx") if not p.name.endswith(".test.tsx")}


# ── the rule exists in one place ─────────────────────────────────────────────

def test_there_is_a_single_pricing_predicate():
    """Five copies of this rule would be five chances to fix four."""
    assert PRICING.exists()
    source = PRICING.read_text(encoding="utf-8")
    assert "export function isPriced" in source


def test_unknown_provenance_counts_as_unpriced():
    """Every crq_result row written before loss_model existed has no record of
    where its number came from, and the honest reading of that is not "it was the
    customer's". The predicate must default to false, not to true."""
    source = PRICING.read_text(encoding="utf-8")
    body = source.split("export function isPriced")[1].split("\n}")[0]
    assert "return false" in body


def test_the_unpriced_cell_is_not_a_zero():
    """money(0) renders "$0", which claims the exposure was computed and came to
    nothing. Unpriced is the absence of a computation."""
    source = PRICING.read_text(encoding="utf-8")
    assert "UNPRICED_CELL = '—'" in source or 'UNPRICED_CELL = "—"' in source
    assert "UNPRICED_CELL = '0'" not in source


# ── every screen that shows money consults it ────────────────────────────────

def test_every_screen_that_prints_money_consults_the_guard():
    """THE STRUCTURAL ASSERTION. A new screen that renders money and forgets the
    guard fails here rather than in front of a customer."""
    offenders = []
    for name, source in _sources().items():
        if "money(" not in source:
            continue
        if "isPriced" in source or "resultIsPriced" in source \
                or "UNPRICED_CELL" in source or "scenario_ale ?" in source:
            continue
        offenders.append(name)
    assert not offenders, (
        f"these render currency without consulting lib/pricing: {offenders}")


@pytest.mark.parametrize("screen", ["Risk.tsx", "CrqInputs.tsx", "Dashboard.tsx"])
def test_the_headline_screens_gate_before_rendering(screen):
    source = (ROUTES / screen).read_text(encoding="utf-8")
    assert re.search(r"!?\s*(isPriced|resultIsPriced)\(", source), screen


def test_the_crq_screen_no_longer_promises_unconditionally():
    """It rendered "nothing here is a benchmark, an industry average, or a number
    we invented" on every load, and with no saved revision the Recompute button
    priced the illustrative company and showed it directly beneath."""
    source = (ROUTES / "CrqInputs.tsx").read_text(encoding="utf-8")
    idx = source.find("number we invented")
    assert idx > 0, "the promise has gone entirely; it should be conditional"
    before = source[max(0, idx - 700):idx]
    assert "resultIsPriced" in before, "the promise is still unconditional"


# ── the trend guard reaches the screen that most needed it ───────────────────

def test_the_risk_screen_uses_the_trend_that_breaks_on_model_changes():
    """ExposureSeries drew one continuous polyline through every run. Risk moves
    for reasons that are not remediation, and a line through such a change
    asserts the two ends are comparable."""
    source = _code_only(ROUTES / "Risk.tsx")
    assert "<RiskTrend" in source
    assert "<ExposureSeries" not in source


def test_the_superseded_series_is_gone_not_merely_unused():
    """A dead component invites someone to wire it back in."""
    source = _code_only(ROUTES / "Risk.tsx")
    assert "function ExposureSeries" not in source


# ── the weight that weights nothing ──────────────────────────────────────────

def test_the_criticality_weight_is_not_presented_as_a_model_input():
    """server/ingest.py calls compute_and_store WITHOUT revenue=, so the weight is
    computed, stored, and multiplies nothing. It is kept for the audit trail and
    labelled for what it is."""
    source = (ROUTES / "Risk.tsx").read_text(encoding="utf-8")
    if "criticality weight" in source:
        idx = source.find("criticality weight")
        assert "recorded, not applied" in source[idx:idx + 400]


def test_ingest_still_does_not_pass_revenue():
    """If this ever changes, the label above becomes wrong and should be revisited
    — the weight would start applying and the note would be stale."""
    source = (ROOT / "server" / "ingest.py").read_text(encoding="utf-8")
    call = re.search(r"compute_and_store\((.*?)\)", source, re.S)
    assert call, "compute_and_store call not found"
    assert "revenue" not in call.group(1)


# ── the server sends what the guard needs ────────────────────────────────────

def test_the_quantify_response_carries_the_provenance():
    """Only scale_factor was sent, and scale_factor is None both when nobody
    answered and when a customer happens to match the catalogue's revenue."""
    source = (ROOT / "server" / "crq.py").read_text(encoding="utf-8")
    assert '"loss_model": summary.get("loss_model")' in source


def test_the_no_engine_path_also_says_unpriced():
    source = (ROOT / "server" / "crq.py").read_text(encoding="utf-8")
    idx = source.find('"reason": "no FAIR engine available"')
    assert idx > 0
    assert '"loss_model"' in source[idx:idx + 300]
