"""The published catalogue: what each check reads, and which clause it answers.

WHAT THE SOURCES ACTUALLY ASKED FOR, because the roadmap had garbled it.
`docs/COMPETITIVE_ANALYSIS.md`, `docs/COMPETITOR_SECURITYBRIDGE.md` and
`docs/PIVOT_PLAN.md` all say the same thing: **323 published-and-auditable** is
OUR count and **550 asserted-and-unverifiable** is a competitor's, and the move is
to publish "our full check catalogue — ID, what it reads, which standard clause it
satisfies". It is a comparison between two products, not a split within ours. The
roadmap entry turned it into an internal taxonomy, which would have meant building
an `evidence_basis` attribute nobody asked for.

The catalogue published Check / Severity / Title. Two of the three things the
sources name were missing, and both were derivable from code that already existed.

WHAT PUBLISHING IMMEDIATELY FOUND. `PWDPOL-A` — minimum password length, CRITICAL —
rendered as "not addressed" while this product has always checked
`login/min_password_lng`. The mapping entry was the prefix `PARAM-PWD`, and every
id in that family is `PARAM-<parameter name>`, so it had matched none of the 81
for its whole life. Nothing published the result, so nothing contradicted it.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.coverage import all_check_ids, module_sources     # noqa: E402
from server import sapcontent                                  # noqa: E402

DOC = (ROOT / "docs" / "CHECKS_REFERENCE.md").read_text(encoding="utf-8")
ALL_IDS = sorted({c for ids in all_check_ids().values() for c in ids})


# ═════════════════════════════════════════════════════════════════════════════
#  The three things the sources name
# ═════════════════════════════════════════════════════════════════════════════

def test_the_catalogue_publishes_the_check_id():
    assert "`AUTH-001`" in DOC


def test_the_catalogue_publishes_what_each_module_reads():
    """"What it reads" is the second of the three, and it is what turns a count
    into something a reader can check."""
    assert "Reads:" in DOC
    assert "`role_auth_values`" in DOC


def test_what_it_reads_is_labelled_as_module_granularity():
    """A module reads several sources and any one check reads some subset; the
    subset is recorded nowhere. Publishing a per-check figure would be more
    precise than the truth."""
    assert "the sources the MODULE consumes" in DOC
    assert "reads some subset of them" in DOC


def test_the_catalogue_publishes_the_standard_clause_each_check_answers():
    assert "SAP Baseline" in DOC
    assert "`CRITAU-A`" in DOC


# ═════════════════════════════════════════════════════════════════════════════
#  The bug publication found
# ═════════════════════════════════════════════════════════════════════════════

def test_a_password_policy_parameter_maps_to_the_password_policy_requirement():
    """THE DEFECT. `PARAM-PWD` matched none of the 81 ids in its family, so a
    CRITICAL requirement this product does check read as unaddressed."""
    assert sapcontent.requirement_for("PARAM-login/min_password_lng") == "PWDPOL-A"


def test_the_dead_prefix_is_gone_and_its_epitaph_is_not():
    """A silently-removed wrong mapping is one somebody re-adds."""
    src = (ROOT / "server" / "sapcontent.py").read_text(encoding="utf-8")
    assert '"PARAM-PWD": "PWDPOL-A",' not in src.replace("# ", "")
    assert "NEVER MATCHED ANYTHING" in src


@pytest.mark.parametrize("parameter,requirement", [
    ("login/min_password_lng", "PWDPOL-A"),
    ("auth/check/calltransaction", "USRCTR-A"),
    ("dynp/checkskip1screen", "USRCTR-A"),
    ("snc/enable", "NETENC-A"),
])
def test_parameters_reach_the_requirement_their_own_title_names(parameter, requirement):
    assert sapcontent.requirement_for(f"PARAM-{parameter}") == requirement


def test_the_parameter_mapping_is_derived_from_saps_titles():
    """Not hand-assembled. The prefix guess is what produced a mapping that never
    matched, and a hand list of 81 would rot the same way."""
    derived = sapcontent.parameter_requirements()
    assert len(derived) > 15
    src = (ROOT / "server" / "sapcontent.py").read_text(encoding="utf-8")
    assert "WHY DERIVED" in src


def test_the_predicate_sourced_exceptions_stay_few_and_cite_their_source():
    """PWDPOL-A's titles are prose, so the derivation cannot reach it. A long
    hand-written list here would be the guessing the derivation replaced."""
    assert len(sapcontent._PARAMETERS_FROM_PREDICATE) <= 6
    src = (ROOT / "server" / "sapcontent.py").read_text(encoding="utf-8")
    assert "section 3.3" in src


def test_a_check_naming_its_sap_check_item_maps_exactly_not_by_prefix():
    """`WDISP-001` came from SAP check `DISCL-O_a.1` and `WDISP-014` from
    `NETENC-O.a1` — one prefix, two requirements. A prefix table cannot say
    that; the rules already record it."""
    assert sapcontent.requirement_for("WDISP-001") == "DISCL-O"
    assert sapcontent.requirement_for("WDISP-014") == "NETENC-O"


# ═════════════════════════════════════════════════════════════════════════════
#  The roll-up, and the claims it must not make
# ═════════════════════════════════════════════════════════════════════════════

def test_the_rollup_reports_three_numbers_rather_than_one_percentage():
    """A single percentage hides the interesting part, and the interesting part
    is which of the three kinds of absence a reader is looking at."""
    assert "three numbers rather than one percentage" in DOC
    assert re.search(r"\*\*\d+ of \d+\*\* requirements SAP publishes", DOC)


def test_an_unmapped_check_is_not_presented_as_a_gap():
    """SoD, GRC, financial controls and the attack-path content have no Baseline
    equivalent, and that is where the product goes beyond it. Calling those
    'unmapped' invites a reader to score the catalogue against a standard that
    does not describe the check."""
    assert "which is not a failure" in DOC
    assert "goes beyond it" in DOC


def test_the_unaddressed_requirements_are_listed_rather_than_counted():
    """A number a reader cannot inspect is the thing this document exists to stop
    a competitor doing."""
    assert "Published requirements this catalogue does not address" in DOC
    for requirement in ("`FILE-A`", "`OBSCNT-A`"):
        assert requirement in DOC


def test_the_two_kinds_of_absence_are_separated():
    """A Java requirement is outside the stack this product audits — a scope
    decision. An ABAP one is a gap inside it. Reported as one number, the larger
    and less interesting group hides the smaller and more interesting one."""
    assert "By technology:" in DOC
    assert "scope decision" in DOC


def test_the_unit_warning_survives_into_the_published_document():
    """The 214 'control points' are a different unit from the check items, and
    the catalogue must not let a reader build a percentage across them."""
    assert "do not reconcile" in DOC
    assert "214" in DOC


def test_the_published_figures_match_what_the_code_computes():
    """The document is generated, but a generated document that drifts is worse
    than a hand-written one because nobody re-reads it."""
    cov = sapcontent.coverage(ALL_IDS)
    assert (f"**{cov['requirements_covered']} of "
            f"{cov['requirements_published']}** requirements") in DOC
    beyond = len(set(cov["beyond_baseline"]))
    assert f"**{beyond} of {len(ALL_IDS)}** checks" in DOC


def test_every_module_with_sources_publishes_them():
    """A module whose Reads line went missing would silently drop back to being a
    list of ids."""
    published = {m for m in module_sources() if f"### `{m}`" in DOC}
    assert len(published) > 25
    for module in sorted(published):
        if not module_sources().get(module):
            continue
        section = DOC.split(f"### `{module}`", 1)[1].split("### `", 1)[0]
        assert "Reads:" in section, module
