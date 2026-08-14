# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""What /api/coverage counts, and why it must not be the database.

THE DEFECT
The endpoint sourced its check ids from `check_definition`, whose only writer is
server/ingest.py inserting a row per check id SEEN IN A FINDING. Nothing seeds
that table. So a check that ran and PASSED did not exist, and the screen listed
its SAP Baseline requirement under a heading calling the omission "a deliberate
scope decision, not an oversight".

Two consequences, both reassuring and both false: a fresh install reported 0 of
38 Baseline requirements and 0 checks beyond it, and a customer whose posture
IMPROVED lost coverage on the page as their findings closed. The endpoint's own
docstring said coverage "is computed from the check ids actually in the
catalogue, so the screen cannot drift from what the scanner really does" — true
of the intent, false of the implementation.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.coverage import module_check_ids                     # noqa: E402
from server import sapcontent                                     # noqa: E402


def _from_the_code():
    return sorted({cid for ids in module_check_ids().values() for cid in ids})


def test_the_product_covers_baseline_requirements_before_anyone_uploads_anything():
    """THE REGRESSION. On a fresh install this was 0 of 38."""
    cov = sapcontent.coverage(_from_the_code())
    assert cov["requirements_covered"] > 0
    assert cov["requirements_covered"] <= cov["requirements_published"]


def test_the_checks_beyond_the_baseline_are_not_zero_either():
    """SoD, GRC, financial controls and the attack-path content have no Baseline
    equivalent — that is where the product goes BEYOND it, and reporting zero
    understated the product while claiming to describe it."""
    assert len(sapcontent.coverage(_from_the_code())["beyond_baseline"]) > 100


def test_an_empty_database_would_have_reported_nothing_covered():
    """The premise, asserted rather than remembered: the old source really did
    produce the bad answer, so this file is testing a real difference."""
    cov = sapcontent.coverage([])
    assert cov["requirements_covered"] == 0
    assert cov["beyond_baseline"] == []


def test_the_endpoint_reads_the_code_and_names_the_database_figure_separately():
    """Both numbers are worth having; only one of them is about the product."""
    src = (ROOT / "server" / "app.py").read_text(encoding="utf-8")
    block = src[src.index("def api_coverage("):src.index("@app.post(\"/api/views\")")]
    assert "module_check_ids()" in block
    assert "observed_checks" in block
    assert "SELECT check_id FROM check_definition" not in block


def test_the_console_no_longer_calls_it_the_reference_dataset():
    """The old caption described the old number. A caption that survives the
    number it described is how a screen keeps lying after the fix."""
    page = (ROOT / "frontend" / "src" / "routes" / "Coverage.tsx").read_text(encoding="utf-8")
    assert "written into the scanner" in page
    assert "observed_checks" in page
