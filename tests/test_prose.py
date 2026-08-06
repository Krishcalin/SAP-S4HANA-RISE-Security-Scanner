"""
Authored line breaks must reach the reader.

WHY THIS FILE EXISTS
A ten-step remediation procedure was rendering as a single run-on paragraph: the
knowledge base separates steps with "\\n", the template put the text in a <p>, and
HTML collapses newlines to spaces. Every step was present and the procedure was
unusable — you cannot work down a wall of text or say "I'm on step 4".

The half of this that is easy to get wrong is the REFUSAL. An <ol> renumbers from 1
whatever the source said, so text that is not already 1..N must not become one.
Most of the cases below are about not making a list.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.prose import paragraphs, steps          # noqa: E402


# --------------------------------------------------------------------------- #
#  Paragraphs                                                                 #
# --------------------------------------------------------------------------- #

def test_each_line_is_its_own_paragraph():
    assert paragraphs("First thought.\nSecond thought.") == \
        ["First thought.", "Second thought."]


def test_blank_lines_and_padding_are_dropped():
    assert paragraphs("  A  \n\n\n  B  \n") == ["A", "B"]


@pytest.mark.parametrize("empty", [None, "", "   ", "\n\n"])
def test_nothing_in_nothing_out(empty):
    assert paragraphs(empty) == []


# --------------------------------------------------------------------------- #
#  Steps — the accepting cases                                                #
# --------------------------------------------------------------------------- #

def test_a_numbered_procedure_becomes_steps_with_the_ordinals_stripped():
    got = steps("1. Inventory the accounts.\n2. Change the user type.\n3. Rotate.")
    assert got == ["Inventory the accounts.", "Change the user type.", "Rotate."]


def test_ordinals_may_use_a_bracket():
    assert steps("1) Do this.\n2) Then this.") == ["Do this.", "Then this."]


def test_it_counts_past_nine():
    text = "\n".join(f"{i}. Step {i}." for i in range(1, 13))
    assert steps(text) == [f"Step {i}." for i in range(1, 13)]


def test_a_hard_wrapped_step_is_joined_rather_than_collapsing_the_whole_list():
    """One unnumbered continuation line must not cost the reader the entire list."""
    got = steps("1. Change USR02-USTYP in SU01\n"
                "   (Logon Data > User Type) to C.\n"
                "2. Rotate the passwords.")
    assert got == ["Change USR02-USTYP in SU01 (Logon Data > User Type) to C.",
                   "Rotate the passwords."]


def test_a_trailing_caution_paragraph_stays_attached_rather_than_vanishing():
    got = steps("1. Do this.\n2. Do that.\nCaution: schedule in a quiet window.")
    assert got is not None and len(got) == 2
    assert "Caution" in got[-1], "trailing prose was dropped"


# --------------------------------------------------------------------------- #
#  Steps — the refusals, which is where the danger is                         #
# --------------------------------------------------------------------------- #

def test_an_excerpt_starting_at_three_is_refused():
    """<ol> would renumber 3,4,5 to 1,2,3 and the text would then contradict any
    cross-reference to it. Better to render it verbatim as prose."""
    assert steps("3. Third thing.\n4. Fourth thing.") is None


def test_a_duplicated_ordinal_is_refused():
    """1,2,2,3 is an authoring slip. Renumbering hides it; prose shows it."""
    assert steps("1. One.\n2. Two.\n2. Two again.\n3. Three.") is None


def test_a_gap_in_the_sequence_is_refused():
    assert steps("1. One.\n2. Two.\n4. Four.") is None


def test_plain_prose_is_refused():
    assert steps("Restrict the authorizations to the minimum needed.") is None


def test_multi_paragraph_prose_is_refused():
    assert steps("This finding flags active API proxies.\n"
                 "An API proxy is the internet-facing front door.") is None


def test_a_single_numbered_line_is_not_a_list():
    assert steps("1. The only thing to do.") is None


@pytest.mark.parametrize("empty", [None, "", "   "])
def test_nothing_is_not_a_list(empty):
    assert steps(empty) is None


def test_a_version_number_mid_sentence_does_not_start_a_list():
    assert steps("Upgrade to Cloud Connector 2.16.2 or later.\n"
                 "Then restart the service.") is None


# --------------------------------------------------------------------------- #
#  Against the real corpus                                                    #
# --------------------------------------------------------------------------- #

def test_every_remediation_in_the_knowledge_base_renders_as_a_list():
    """If a real entry falls back to prose it is not broken — but it does mean the
    authored numbering drifted, and this is where that shows up."""
    kb = json.loads((ROOT / "data" / "finding_details.json").read_text(encoding="utf-8"))
    entries = kb if isinstance(kb, list) else list(kb.values())

    refused = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        text = entry.get("mitigation") or ""
        if not text:
            continue
        if steps(text) is None:
            refused.append((entry.get("check_id") or entry.get("id") or "?",
                            text.splitlines()[0][:70]))

    assert not refused, (
        f"{len(refused)} knowledge-base remediations are not a clean 1..N list, so "
        f"they render as prose: {refused[:5]}")


def test_no_step_text_keeps_its_ordinal():
    """A leftover "1." inside an <ol> item renders as "1. 1. Inventory ..."."""
    kb = json.loads((ROOT / "data" / "finding_details.json").read_text(encoding="utf-8"))
    entries = kb if isinstance(kb, list) else list(kb.values())
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for step in steps(entry.get("mitigation") or "") or []:
            assert not step[:4].strip().rstrip(".)").isdigit() or not step[:4].strip(), \
                f"ordinal survived into the step text: {step[:40]!r}"


def test_the_corpus_never_loses_a_step():
    """Round-trip: the number of rendered steps must equal the number of authored
    ordinals, or the join-continuation rule is swallowing content."""
    import re
    kb = json.loads((ROOT / "data" / "finding_details.json").read_text(encoding="utf-8"))
    entries = kb if isinstance(kb, list) else list(kb.values())
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        text = entry.get("mitigation") or ""
        rendered = steps(text)
        if rendered is None:
            continue
        authored = len([l for l in text.splitlines()
                        if re.match(r"^\s*\d{1,3}[.)]\s", l)])
        assert len(rendered) == authored, \
            f"{entry.get('check_id')}: authored {authored} steps, rendered {len(rendered)}"
