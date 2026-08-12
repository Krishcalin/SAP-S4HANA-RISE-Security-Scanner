# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""The CSF 2.0 Core is reference data, so these tests are mostly about drift.

The taxonomy is pinned to the PUBLISHED counts (6 / 22 / 106) rather than to
whatever the module currently holds. A test that asserts len(CATEGORIES) ==
len(CATEGORIES) passes forever and catches nothing; these numbers come from
NIST CSWP 29 and a diff against them means somebody mistyped the framework.

The rest guard the one property the whole feature rests on: that CLEAR and
NOT_ASSESSED never collapse into each other.
"""
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import nist_csf as csf                     # noqa: E402
from modules.compliance_mapping import ComplianceMapper  # noqa: E402


# ── the published Core ───────────────────────────────────────────────────────

def test_the_core_matches_the_published_counts():
    """NIST CSWP 29: 6 Functions, 22 Categories, 106 Subcategories."""
    assert len(csf.FUNCTIONS) == 6
    assert len(csf.CATEGORIES) == 22
    assert len(csf.SUBCATEGORIES) == 106


def test_categories_per_function_match_the_published_layout():
    counts = {f: sum(1 for c in csf.CATEGORIES if csf.function_of(c) == f)
              for f in csf.FUNCTION_ORDER}
    assert counts == {"GV": 6, "ID": 3, "PR": 5, "DE": 2, "RS": 4, "RC": 2}


def test_function_order_is_the_cores_own_not_alphabetical():
    """GOVERN leads because it informs the other five (CSWP 29 Fig. 2)."""
    assert csf.FUNCTION_ORDER == ("GV", "ID", "PR", "DE", "RS", "RC")
    assert csf.FUNCTION_ORDER != tuple(sorted(csf.FUNCTION_ORDER))


def test_every_subcategory_belongs_to_a_real_category():
    orphans = [s for s in csf.SUBCATEGORIES if s.rsplit("-", 1)[0] not in csf.CATEGORIES]
    assert orphans == []


def test_every_category_belongs_to_a_real_function():
    for category in csf.CATEGORIES:
        assert csf.function_of(category) in csf.FUNCTIONS


def test_function_of_rejects_something_that_is_not_a_category():
    for bogus in ("PR.XX", "XX.AA", "PR", "", "PR.AA-01"):
        with pytest.raises(KeyError):
            csf.function_of(bogus)


def test_the_intentional_numbering_gaps_are_preserved():
    """CSWP 29: gaps mark CSF 1.1 Subcategories relocated in 2.0. Not typos."""
    for absent in ("ID.AM-06", "PR.DS-03", "DE.CM-04", "RS.AN-01", "RC.CO-01"):
        assert absent not in csf.SUBCATEGORIES
    # …and the neighbours that prove the gap is a gap, not a truncation
    for present in ("ID.AM-05", "ID.AM-07", "PR.DS-02", "PR.DS-10"):
        assert present in csf.SUBCATEGORIES


# ── scope is derived, never declared twice ───────────────────────────────────

def test_scope_is_derived_from_the_compliance_mapper():
    """The set of assessable Categories IS the mapper's CSF entries.

    Not a copy of them. If this ever fails, someone has hand-written a second
    list and the two will drift silently.
    """
    from_mapper = set()
    for framework in ComplianceMapper.FRAMEWORKS:
        if framework.get("id") == "nistcsf":
            for controls in framework["themes"].values():
                from_mapper.update(cid for cid, _ in controls)
    assert set(csf.assessable_categories()) == from_mapper


def test_the_mapper_never_references_a_category_outside_the_core():
    """A mapper entry for 'PR.ZZ' would silently vanish from every roll-up."""
    unknown = set(csf.assessable_categories()) - set(csf.CATEGORIES)
    assert unknown == set()


def test_every_unassessable_category_says_why():
    """A dashed tile with no reason is just an unexplained blank."""
    assessable = set(csf.assessable_categories())
    for category in csf.CATEGORIES:
        if category not in assessable:
            assert csf.NOT_ASSESSED_REASON.get(category), category


def test_no_category_is_both_assessable_and_excused():
    assert set(csf.assessable_categories()) & set(csf.NOT_ASSESSED_REASON) == set()


# ── the three states ─────────────────────────────────────────────────────────

def test_an_empty_scan_reports_clear_and_not_assessed_separately():
    """THE CENTRAL PROPERTY. With no findings at all, a Category we assess is
    CLEAR and a Category we cannot assess is NOT_ASSESSED — never the same."""
    rolled = csf.roll_up([])
    states = {c["id"]: c["status"]
              for f in rolled["functions"] for c in f["categories"]}
    assert states["PR.AA"] == csf.CLEAR          # assessed, nothing found
    assert states["PR.AT"] == csf.NOT_ASSESSED   # no export answers training
    assert states["GV.PO"] == csf.NOT_ASSESSED
    assert csf.CLEAR != csf.NOT_ASSESSED
    assert rolled["totals"]["findings"] == 0


def test_the_whole_core_comes_back_even_with_no_findings():
    """Absence from the answer would be a fourth, unlabelled state."""
    rolled = csf.roll_up([])
    assert len(rolled["functions"]) == 6
    returned = {c["id"] for f in rolled["functions"] for c in f["categories"]}
    assert returned == set(csf.CATEGORIES)


def test_a_finding_moves_its_category_from_clear_to_assessed():
    findings = [{"category": "User & Authorization", "severity": "CRITICAL"}]
    states = {c["id"]: c
              for f in csf.roll_up(findings)["functions"] for c in f["categories"]}
    assert states["PR.AA"]["status"] == csf.ASSESSED
    assert states["PR.AA"]["counts"]["CRITICAL"] == 1
    # …and a Category we cannot assess is untouched by any finding
    assert states["PR.AT"]["status"] == csf.NOT_ASSESSED
    assert states["PR.AT"]["total"] == 0


# ── the counting rule ────────────────────────────────────────────────────────

def test_no_function_total_can_exceed_the_corpus():
    """A finding is evidence against several outcomes, so the naive roll-up
    counts it once per Category and reports more findings than exist. The first
    version of this code said "Protect: 148" for a 92-finding system."""
    findings = [{"category": "User & Authorization", "severity": "HIGH"},
                {"category": "Identity & Access Management", "severity": "CRITICAL"},
                {"category": "Network & Service Exposure", "severity": "LOW"}]
    rolled = csf.roll_up(findings)
    for function in rolled["functions"]:
        assert function["total"] <= len(findings), function["id"]
        assert sum(function["counts"].values()) <= len(findings)


def test_a_category_counts_a_finding_once_however_many_themes_reach_it():
    """'Identity & Access Management' reaches PR.AA through four themes."""
    findings = [{"category": "Identity & Access Management", "severity": "HIGH"}]
    states = {c["id"]: c
              for f in csf.roll_up(findings)["functions"] for c in f["categories"]}
    assert states["PR.AA"]["total"] == 1
    assert states["PR.AA"]["counts"]["HIGH"] == 1


# ── findings the view cannot place ───────────────────────────────────────────

def test_a_finding_with_an_unmappable_category_is_reported_not_dropped():
    """Silently discarding it would make the roll-up look like the whole corpus."""
    findings = [{"category": "User & Authorization", "severity": "HIGH"},
                {"category": "Not A Real Category", "severity": "CRITICAL"}]
    totals = csf.roll_up(findings)["totals"]
    assert totals["findings"] == 2
    assert totals["mapped"] == 1
    assert totals["unmapped"] == 1
    assert totals["unmapped_categories"] == {"Not A Real Category": 1}


def test_a_finding_with_no_category_at_all_is_still_counted():
    """check_definition.category is nullable, so this is a real row, not a fiction."""
    totals = csf.roll_up([{"category": None, "severity": "HIGH"}])["totals"]
    assert totals["unmapped"] == 1
    assert "(no category)" in totals["unmapped_categories"]


def test_mapped_plus_unmapped_accounts_for_every_finding_with_a_severity():
    findings = [{"category": "User & Authorization", "severity": "HIGH"},
                {"category": "Nope", "severity": "LOW"},
                {"category": "Cryptographic Posture", "severity": "MEDIUM"}]
    totals = csf.roll_up(findings)["totals"]
    assert totals["mapped"] + totals["unmapped"] == totals["findings"]


# ── no percentage, anywhere ──────────────────────────────────────────────────

def test_the_roll_up_publishes_no_compliance_percentage():
    """compliance_mapping.py forbids one and the reason holds here: we see the
    findings, not the control environment. A '% compliant' would be a claim
    about evidence we do not hold — and it is the number a reader most wants,
    which is exactly why its absence needs a test rather than a comment."""
    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                assert "percent" not in str(key).lower(), key
                assert not str(key).lower().endswith("_pct"), key
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)
    walk(csf.roll_up([{"category": "User & Authorization", "severity": "HIGH"}]))


# ── subcategory payload ──────────────────────────────────────────────────────

def test_subcategories_carry_their_outcome_text():
    subs = csf.subcategories_of("PR.AA")
    assert len(subs) == 6
    assert subs[0]["id"] == "PR.AA-01"
    assert "credentials" in subs[0]["text"]


def test_function_detail_rejects_an_unknown_function():
    for bogus in ("XX", "", "GV.RR", "governance"):
        assert csf.function_detail([], bogus) is None


def test_function_detail_is_case_insensitive_on_the_id():
    assert csf.function_detail([], "pr")["id"] == "PR"


def test_every_slug_the_console_links_to_resolves():
    """THIS TEST EXISTS BECAUSE ITS PREDECESSOR ASSERTED THE OPPOSITE.

    The first version pinned `function_detail([], "GOVERN") is None` — "the slug
    is not the id" — and then the console shipped links to /csf/govern. Every
    Function page 404'd, and the unit test passed the whole time because it had
    encoded the mistake as the requirement. The console's slugs are the contract
    now, so they are tested as one.
    """
    assert set(csf.SLUGS.values()) == {"govern", "identify", "protect",
                                       "detect", "respond", "recover"}
    assert set(csf.SLUGS) == set(csf.FUNCTIONS)
    for function_id, slug in csf.SLUGS.items():
        assert csf.resolve_function(slug) == function_id
        assert csf.resolve_function(slug.upper()) == function_id
        assert csf.resolve_function(function_id) == function_id
        assert csf.function_detail([], slug)["id"] == function_id


# ── the API surface ──────────────────────────────────────────────────────────

pg = pytest.mark.skipif(not os.getenv("DB_DSN"),
                        reason="set DB_DSN to a PostgreSQL 16 instance")


@pg
def test_an_anonymous_caller_gets_401_not_the_framework():
    from fastapi.testclient import TestClient
    from server import app as appmod
    client = TestClient(appmod.app)
    assert client.get("/api/csf").status_code == 401
    assert client.get("/api/csf/govern").status_code == 401


@pg
def test_an_unknown_function_is_404_not_an_empty_function():
    """An empty shell would render as a Function with nothing wrong in it."""
    import os as _os
    from fastapi.testclient import TestClient
    from server import app as appmod, auth, db
    db.init_schema()
    name = f"csf_{_os.urandom(4).hex()}"
    auth.create_user(name, "csf-test-password", "admin")
    try:
        client = TestClient(appmod.app)
        assert client.post("/api/auth/login",
                           json={"username": name, "password": "csf-test-password"}
                           ).status_code == 200
        assert client.get("/api/csf/govern").status_code == 200
        assert client.get("/api/csf/not-a-function").status_code == 404
    finally:
        db.execute("DELETE FROM app_user WHERE username = %s", (name,))
