"""A platform a tenant can be registered against, and what it will actually get.

WHAT WAS WRONG. `PLATFORMS` says which platforms a `sap_system` row may DECLARE.
It never said whether any check would look at one, and the two had drifted apart
in the direction that flatters the product: `add-tenant ... ariba acme-prod`
created a system row that no module can produce a finding for, silently. A
registered tenant that can never be assessed reads as coverage.

WHAT THESE TESTS ARE FOR. That every platform in the vocabulary has a recorded
position, that a decision recorded elsewhere is not quietly reversed here, and
that `undecided` stays a visible state rather than collapsing into a refusal
nobody made.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import platforms                                  # noqa: E402

DECISIONS = (ROOT / "docs" / "DECISIONS.md").read_text(encoding="utf-8")


# ═════════════════════════════════════════════════════════════════════════════
#  Every platform has a position
# ═════════════════════════════════════════════════════════════════════════════

def test_every_platform_in_the_vocabulary_has_a_recorded_status():
    """The drift this closes. A platform a row may declare, with no recorded
    position, is one a customer can register and never hear about again."""
    assert set(platforms.PLATFORM_STATUS) == set(platforms.PLATFORMS)


def test_no_status_outside_the_declared_vocabulary():
    for name, entry in platforms.PLATFORM_STATUS.items():
        assert entry["status"] in platforms.PLATFORM_STATUSES, name


def test_every_position_carries_a_reason_somebody_could_argue_with():
    """A one-word status is a label. The reason is what makes it reviewable."""
    for name, entry in platforms.PLATFORM_STATUS.items():
        assert len(entry["why"]) > 60, name
        assert entry["evidence"], name


# ═════════════════════════════════════════════════════════════════════════════
#  The decision this must not reverse
# ═════════════════════════════════════════════════════════════════════════════

def test_successfactors_is_in_scope_and_not_declined():
    """DECISION D1 MOVED IT INTO SCOPE — offline-first, security surface only.
    Recording it as an exclusion would reverse a documented decision without
    saying so, which is the failure this whole file guards against in the other
    direction."""
    entry = platforms.PLATFORM_STATUS["successfactors"]
    assert entry["status"] == "in_scope_unbuilt"
    assert entry["decision"] == "D1"
    assert "D1 " in DECISIONS or "D1 —" in DECISIONS


def test_in_scope_unbuilt_is_not_the_same_as_assessed():
    """Accepted into scope and read by nothing are different claims. Collapsing
    them would put SuccessFactors in the coverage story it is not yet in."""
    assert not platforms.is_assessed("successfactors")
    assert platforms.status_of("successfactors") == "in_scope_unbuilt"


def test_ariba_is_declined_and_the_decision_is_written_down():
    """A refusal with no record gets re-opened by the next person, and this one
    reached the vocabulary without ever appearing in a decision document."""
    entry = platforms.PLATFORM_STATUS["ariba"]
    assert entry["status"] == "declined"
    assert entry["decision"] == "D9"
    assert "## D9" in DECISIONS


def test_the_ariba_decision_records_the_weakness_of_the_evidence_that_prompted_it():
    """The competitor assessment that raised it rated its own Ariba claim
    'internal email only'. Declining on thin third-party evidence is the right
    way round, and the record has to say that is what happened."""
    entry = platforms.PLATFORM_STATUS["ariba"]
    assert "internal email only" in entry["why"]
    assert "revisit" in entry["why"]


def test_ariba_keeps_its_platform_value():
    """Removing it would invalidate an existing tenant row and would hide the
    refusal at the one moment somebody needs to see it."""
    assert "ariba" in platforms.PLATFORMS
    assert "ariba" in platforms.TENANT_PLATFORMS


@pytest.mark.parametrize("name", ["concur", "fieldglass"])
def test_an_unruled_platform_says_undecided_rather_than_declined(name):
    """Inventing a rationale nobody gave is how a decision comes to look settled
    without anyone making it. Both are in the vocabulary, assessed by nothing,
    and named in no decision document — which is a state, not a verdict."""
    entry = platforms.PLATFORM_STATUS[name]
    assert entry["status"] == "undecided"
    assert entry["decision"] is None
    # And genuinely unruled: no decision heading anywhere claims either of them.
    headings = [l for l in DECISIONS.splitlines() if l.startswith("## D")]
    assert not [h for h in headings if name in h.lower()], name


def test_the_undecided_ones_are_named_in_the_open_questions():
    """A visible open question, not a silent one."""
    assert "Concur and Fieldglass" in DECISIONS


# ═════════════════════════════════════════════════════════════════════════════
#  What a tenant registration is told
# ═════════════════════════════════════════════════════════════════════════════

def test_an_assessed_platform_produces_no_note():
    """A warning on the case that works is noise, and noise is how the warning
    that matters gets skipped."""
    for name in ("abap", "btp", "ias", "cloud_alm"):
        assert platforms.status_note(name) == "", name


@pytest.mark.parametrize("name", ["ariba", "successfactors", "concur", "fieldglass"])
def test_a_platform_nothing_assesses_says_so_before_the_row_exists(name):
    note = platforms.status_note(name)
    assert note and name in note
    assert len(note) > 80


def test_the_note_distinguishes_declined_from_merely_unbuilt():
    """A customer registering a SuccessFactors tenant is early; one registering
    an Ariba tenant is doing something the product has ruled out. Telling them
    the same thing would be wrong in both directions."""
    assert "out of scope" in platforms.status_note("ariba")
    assert "Accepted into scope" in platforms.status_note("successfactors")


def test_an_unknown_platform_is_not_silently_endorsed():
    assert "does not" in platforms.status_note("workday") or \
        "not a platform" in platforms.status_note("workday")


def test_add_tenant_prints_the_position():
    """Structurally, because the command needs a database to run. A recorded
    position nothing surfaces is the state this change was made to leave."""
    src = (ROOT / "server" / "cli.py").read_text(encoding="utf-8")
    assert "status_note" in src
    idx = src.index("def cmd_add_tenant")
    assert "status_note(args.platform)" in src[idx:idx + 3000]


# ═════════════════════════════════════════════════════════════════════════════
#  Declared, and honest about being declared
# ═════════════════════════════════════════════════════════════════════════════

def test_the_status_is_declared_rather_than_derived_and_says_why():
    """A name-matching derivation would report `abap` and `cloud_alm` as
    unassessed — abap's sources are `users` and `profiles`, cloud_alm's is
    `csa_findings`. That is the opposite of true, and the docstring records it so
    nobody 'improves' this into a derivation."""
    src = (ROOT / "modules" / "platforms.py").read_text(encoding="utf-8")
    assert "DECLARED, NOT DERIVED" in src
    assert "csa_findings" in src


def test_no_platform_claims_assessment_without_a_module_or_source():
    """The claim that would be easiest to make and hardest to notice."""
    from modules.coverage import all_logical_sources
    sources = set(all_logical_sources())
    for name, entry in platforms.PLATFORM_STATUS.items():
        if entry["status"] != "assessed" or name == platforms.ABAP:
            continue
        named = [s.strip(" ,;") for s in entry["evidence"].replace(";", ",").split(",")]
        assert any(s in sources for s in named), \
            f"{name} claims assessment but names no known logical source"
