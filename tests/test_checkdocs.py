# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""Every check id and requirement id the console renders is now a LINK.

That is the point of the feature and it is also its whole risk. Before, an id
that resolved to nothing was grey text that resolved to nothing; now it is a
link, and a link that 404s is a worse experience than the dead text it replaced,
because it invites the click.

So the load-bearing tests here are the two that walk the ids the SCREENS
actually render and require every one of them to resolve. A test that checked a
handful of ids by hand would prove the endpoint works and say nothing about
whether the console can produce a link it cannot follow.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server import checkdocs  # noqa: E402


# ── no dead links ────────────────────────────────────────────────────────────

def test_every_published_check_id_resolves():
    """The coverage screen and the path screens render ids straight from the
    catalogue. Every one of them must open a page."""
    index = checkdocs.catalogue_index()
    assert len(index) > 600, f"catalogue collapsed to {len(index)} ids"
    missing = [e["check_id"] for e in index if checkdocs.check(e["check_id"]) is None]
    assert not missing, f"catalogue ids that do not resolve: {missing[:10]}"


def test_every_check_a_risk_path_cites_resolves():
    """Path templates cite checks by id, and PathDetail now renders each hop's
    checks as links. A template citing an id the catalogue does not publish would
    put a dead link on the busiest screen in the product.

    NOTE this is deliberately weaker than `test_required_hops_cite_checks_the_
    scanner_can_actually_emit` in test_graph_paths.py, which asks whether a check
    FIRES on sample_data. This asks only whether it EXISTS, because an optional
    hop may legitimately cite a check no fixture triggers — and that check still
    needs a page.
    """
    import json
    paths = json.loads((ROOT / "data" / "attack_paths.json").read_text(encoding="utf-8"))
    cited = {c for p in paths["paths"] for h in p["hops"] for c in h.get("checks", [])}
    assert cited, "no template cites any check"
    unknown = sorted(c for c in cited if not checkdocs.known_check(c))
    assert not unknown, (
        f"risk-path templates cite check ids the catalogue does not publish, so "
        f"PathDetail would render a dead link for each: {unknown}")


def test_every_requirement_the_coverage_screen_shows_resolves():
    """Coverage renders both `covered` and `not_covered` requirement ids, and both
    are now links. The not-covered half is the easy one to forget: it is rendered
    from SAP's catalogue rather than from ours."""
    from modules.coverage import module_check_ids
    from server import sapcontent
    ids = sorted({c for v in module_check_ids().values() for c in v})
    cov = sapcontent.coverage(ids, sapcontent.load_catalogue())
    shown = [r["requirement"] for r in cov["covered"]] + \
            [r["requirement"] for r in cov["not_covered"]]
    assert shown, "the coverage screen shows no requirements at all"
    missing = [r for r in shown if checkdocs.requirement(r) is None]
    assert not missing, f"requirement ids on screen that do not resolve: {missing}"


def test_every_check_a_requirement_claims_resolves():
    """The requirement page lists `our_checks` as links, in both directions of the
    mapping. A one-way mapping would put dead links on the page that exists to
    show the mapping."""
    from modules.coverage import module_check_ids
    from server import sapcontent
    ids = sorted({c for v in module_check_ids().values() for c in v})
    cov = sapcontent.coverage(ids, sapcontent.load_catalogue())
    for row in cov["covered"]:
        doc = checkdocs.requirement(row["requirement"])
        assert doc is not None
        bad = [c for c in doc["our_checks"] if not checkdocs.known_check(c)]
        assert not bad, f"{row['requirement']} claims unknown checks: {bad}"


# ── the honest gap ───────────────────────────────────────────────────────────

def test_an_undocumented_check_still_resolves():
    """357 of 709 ids have a knowledge-base entry. The other 352 are REAL checks
    that run like any other; only the prose is missing.

    404-ing them would be the wrong answer to "what is this?" — we know the
    category, the module, the exports it reads and the requirement it answers.
    `documented: False` lets the screen say which part is missing instead of
    implying the check is."""
    index = checkdocs.catalogue_index()
    undocumented = [e["check_id"] for e in index if not e["documented"]]
    assert undocumented, "expected some ids to have no narrative yet"
    doc = checkdocs.check(undocumented[0])
    assert doc is not None
    assert doc["documented"] is False
    assert doc["risk"] is None and doc["mitigation"] is None
    # Everything that is known is still there.
    assert doc["category"]


def test_documented_checks_carry_both_halves():
    """A risk narrative with no remediation is half an answer, and the screen
    renders two headings regardless."""
    index = checkdocs.catalogue_index()
    documented = [e["check_id"] for e in index if e["documented"]]
    assert len(documented) > 300
    thin = [c for c in documented
            if not (checkdocs.check(c)["risk"] and checkdocs.check(c)["mitigation"])]
    assert not thin, f"documented checks missing risk or mitigation: {thin[:10]}"


# ── unknown ids are refused, not answered ────────────────────────────────────

@pytest.mark.parametrize("bad", ["NOPE-999", "", "../etc/passwd", "LOG-AUD-9999"])
def test_an_unknown_check_is_none_rather_than_an_empty_shell(bad):
    assert checkdocs.check(bad) is None
    assert checkdocs.known_check(bad) is False


def test_an_unknown_requirement_is_none(bad="NOT-A-REQUIREMENT"):
    assert checkdocs.requirement(bad) is None


# ── the mapping agrees with the screen that counts it ────────────────────────

def test_the_check_page_names_the_same_requirement_the_coverage_page_counts():
    """Two mappings would eventually disagree, and the page would quietly
    contradict the number beside it."""
    from server import sapcontent
    for cid in ("LOG-AUD-001", "HANADB-AUDIT-001"):
        doc = checkdocs.check(cid)
        expected = sapcontent.requirement_for(cid)
        named = [r["requirement"] for r in doc["requirements"]]
        if expected:
            assert named == [expected], f"{cid}: {named} != {[expected]}"
        else:
            assert named == []


def test_a_cut_check_says_so():
    """The most actionable sentence the check page can produce. INTG-GW-001 is a
    cut on the gateway path; if it stops being one, the banner must stop too."""
    doc = checkdocs.check("INTG-GW-001")
    assert doc is not None
    cuts = [p for p in doc["paths"] if p["is_cut"]]
    assert cuts, "INTG-GW-001 is a cut on SAPPATH-04 and SAPPATH-13"
    assert {p["template_id"] for p in cuts} >= {"SAPPATH-04", "SAPPATH-13"}
