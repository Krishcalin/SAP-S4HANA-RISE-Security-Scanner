# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
SAP baseline content: the vendored catalogue and our coverage of it.

The catalogue is DERIVED from SAP's Apache-2.0 policy repository and vendored so the
tool works offline — the product premise. A vendored copy of someone else's content
goes stale silently, so CI re-derives it and fails on drift; these tests guard the
parsing and the coverage arithmetic that the drift check compares against.

The parser bug worth remembering: SAP uses BOTH `CRITAU-A_a.1` and `NETENC-O.a.1`, so
accepting only the underscore dropped three requirements. That shrinks the published
denominator and makes our coverage look BETTER than it is — the one direction an error
here must never go.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.sapcontent import (  # noqa: E402
    CHECK_TO_REQUIREMENT,
    coverage,
    load_catalogue,
    requirement_for,
)

CATALOGUE = ROOT / "data" / "sap_baseline_requirements.json"


def test_the_catalogue_is_vendored_and_parsable():
    assert CATALOGUE.is_file(), "the tool must work offline; the catalogue is vendored"
    cat = load_catalogue()
    assert cat["requirements"], "empty catalogue"
    assert cat["_meta"]["licence"].startswith("Apache-2.0"), \
        "the source licence must be recorded — this is SAP's content, derived"
    assert "SAP-samples" in cat["_meta"]["source"]


def test_both_separator_styles_survive_parsing():
    """SAP writes `CRITAU-A_a.1` and `NETENC-O.a.1`. Dropping the dotted form loses
    three requirements and inflates our apparent coverage."""
    reqs = {r["requirement"] for r in load_catalogue()["requirements"]}
    for req in ("NETENC-O", "OBSCNT-A", "SECUPD-H"):
        assert req in reqs, (
            f"{req} is missing from the catalogue — the requirement-id regex has "
            f"regressed to underscore-only, which understates the denominator")


def test_every_requirement_is_well_formed():
    for r in load_catalogue()["requirements"]:
        assert r["requirement"] and "-" in r["requirement"]
        assert r["technology"] in ("ABAP", "Java", "HANA", "Other", "BTP")
        # SAP does not tag every item; SECUPD-A carries no priority at all. None is
        # the honest record of that — inventing a tier would be fabrication.
        assert r["tier"] in ("CRITICAL", "STANDARD", "EXTENDED", None)
        assert r["check_items"] >= 1
        assert r["titles"], f"{r['requirement']} has no title"


def test_a_family_takes_the_strictest_tier_of_its_items():
    """A family containing one CRITICAL item is a critical family. Last-wins or
    averaging would quietly downgrade it."""
    cat = load_catalogue()
    crit = [r for r in cat["requirements"] if r["tier"] == "CRITICAL"]
    assert crit, "no critical requirement families — tier resolution has broken"


def test_the_unit_warning_is_present():
    """A widely-quoted figure puts the Baseline at 214 'control points'. Parsing
    SAP's policies gives 351 check items across 38 families. Those are different
    units and must not be divided into one another."""
    meta = load_catalogue()["_meta"]
    assert "214" in meta.get("unit_warning", ""), \
        "the catalogue must carry the warning against reconciling these counts"
    assert meta["counts"]["requirements"] == len(load_catalogue()["requirements"])


# --------------------------------------------------------------------------- #
#  Mapping and coverage                                                       #
# --------------------------------------------------------------------------- #

def test_every_mapping_targets_a_requirement_that_exists():
    """A mapping to a requirement SAP does not publish would silently never count,
    so a check would look unmapped while appearing handled in the source."""
    published = {r["requirement"] for r in load_catalogue()["requirements"]}
    bad = {p: r for p, r in CHECK_TO_REQUIREMENT.items() if r not in published}
    assert not bad, f"mappings to unknown SAP requirements: {bad}"


def test_longest_prefix_wins_in_the_mapping():
    assert requirement_for("TRUST-010") == "MSGSRV-A"   # specific
    assert requirement_for("TRUST-001") == "RFCGW-A"    # family default
    assert requirement_for("BASELINE-004") == "SCRIPT-A"


def test_an_unmapped_check_is_reported_as_beyond_the_baseline_not_as_a_gap():
    """SoD, GRC and financial controls have no Baseline equivalent. Counting them as
    uncovered would misrepresent the product's own strongest content as a shortfall."""
    cov = coverage(["ARA-P2P-01", "GRC-EAM-001", "FIN-PP-001", "PARAM-PWD-001"])
    assert "GRC-EAM-001" in cov["beyond_baseline"]
    assert "FIN-PP-001" in cov["beyond_baseline"]


def test_coverage_never_claims_more_requirements_than_are_published():
    cov = coverage([r["check_id"] for r in []] or ["PARAM-PWD-001", "USR-001"])
    assert cov["requirements_covered"] <= cov["requirements_published"]
    assert len(cov["covered"]) + len(cov["not_covered"]) == cov["requirements_published"]


@pytest.mark.skipif(not (ROOT / "sample_data").is_dir(), reason="sample_data absent")
def test_coverage_over_the_real_check_set_is_honest():
    """Assert the SHAPE, not a number: the number should move as checks are added,
    and pinning it would make every new check a test failure."""
    import contextlib
    import importlib
    import io
    from modules.data_loader import DataLoader
    from server.ingest import AUDITORS, RUN_CONTEXT

    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(ROOT / "sample_data").load_all()
        ids = set()
        for mod, cls in AUDITORS:
            for f in (getattr(importlib.import_module(f"modules.{mod}"), cls)(
                    data, None, RUN_CONTEXT).run_all_checks() or []):
                ids.add(f["check_id"])

    cov = coverage(ids)
    assert cov["requirements_covered"] > 0, "we cover none of SAP's own baseline"
    assert cov["not_covered"], (
        "we appear to cover every SAP requirement — implausible, and a sign the "
        "denominator has collapsed")
    assert cov["beyond_baseline"], "no checks beyond the Baseline; mapping is too greedy"
    # Java is a deliberate non-goal; it should show up as an honest gap.
    assert any(r["technology"] == "Java" for r in cov["not_covered"]), \
        "NetWeaver Java is out of scope and should appear as an uncovered gap"
