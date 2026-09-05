"""What each missing export would actually buy.

THE SENTENCE THIS EXISTS TO ANSWER. Every scan ends with "Supplied 119 of 139
logical sources. 17 module(s) ran with incomplete input." True, honest, and
unactionable: a customer facing twenty absent extracts cannot tell that two of
them carry a third of the remaining value and eighteen carry almost none. The
usual outcome is that none of them arrive and an offline product delivers
119/139 of itself forever.

`coverage.check_sources()` already knew which sources each of 438 checks reads.
Only the arithmetic and the ordering were missing.

TWO NUMBERS, NOT ONE. A check reading three sources needs all three, so a
missing source is worth what it UNBLOCKS:

    unlocks_now    checks whose ONLY missing source is this one
    also_needed_by checks that read it and are still blocked by something else

Reporting only the second inflates every source into a headline. Reporting only
the first hides that two exports together open a door neither opens alone. Both
are given, and the ranking sorts on the first.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import coverage, export_value  # noqa: E402


def manifest(missing=(), empty=()):
    return {"missing": list(missing), "empty": list(empty)}


# --------------------------------------------------------------------------- #
#  The arithmetic                                                              #
# --------------------------------------------------------------------------- #

def test_nothing_missing_produces_no_advice():
    got = export_value.rank(manifest())
    assert got["ranked"] == [] and got["checks_blocked"] == 0
    assert export_value.sentence(got) == ""


def test_no_manifest_at_all_invents_nothing():
    """Advice from no evidence is worse than no advice."""
    assert export_value.rank(None)["ranked"] == []


def test_a_missing_source_is_credited_with_the_checks_it_alone_blocks():
    got = export_value.rank(manifest(missing=["security_params"]))
    row = next(r for r in got["ranked"] if r["source"] == "security_params")
    assert row["unlocks_now"] > 0
    assert row["modules"], "a source nothing reads should not rank at all"


def test_a_check_blocked_by_two_sources_counts_as_later_not_now():
    """The distinction the whole ranking rests on: supplying one of two does
    not make the check run, and saying it would is the inflation this avoids."""
    by_check = coverage.check_sources()
    pair = next(((cid, srcs) for cid, srcs in by_check.items()
                 if len(set(srcs or ())) >= 2), None)
    if pair is None:
        return                      # no multi-source check in the catalogue
    cid, srcs = pair
    two = sorted(set(srcs))[:2]
    got = export_value.rank(manifest(missing=two))
    for row in got["ranked"]:
        if row["source"] in two:
            assert cid not in row["checks"], (
                "%s was credited as unlocked by %s alone, and it needs %s"
                % (cid, row["source"], two))


def test_an_empty_file_counts_as_missing():
    """A check reading no rows cannot fire, so a file present-but-empty is
    missing for every purpose this ranking serves — and the scan already
    reports two such files on the sample corpus."""
    with_empty = export_value.rank(manifest(empty=["security_params"]))
    with_missing = export_value.rank(manifest(missing=["security_params"]))
    assert [r["source"] for r in with_empty["ranked"]] == \
           [r["source"] for r in with_missing["ranked"]]


def test_the_ranking_is_ordered_by_what_it_unlocks():
    got = export_value.rank(manifest(
        missing=["security_params", "users", "role_auth_values", "logon_events"]))
    counts = [r["unlocks_now"] for r in got["ranked"]]
    assert counts == sorted(counts, reverse=True), counts


def test_the_order_is_stable_between_identical_runs():
    """Two scans of one estate must not shuffle the advice; a reader comparing
    them would read movement that is not there."""
    args = manifest(missing=["users", "profiles", "role_details"])
    assert ([r["source"] for r in export_value.rank(args)["ranked"]]
            == [r["source"] for r in export_value.rank(args)["ranked"]])


# --------------------------------------------------------------------------- #
#  What must never be recommended                                              #
# --------------------------------------------------------------------------- #

def test_a_source_rise_cannot_produce_is_not_advice():
    """Under RISE the customer cannot produce ms_acl or saprouttab at all.
    Listing them as next steps spends the reader's attention on a door that
    does not open."""
    unreachable = sorted(coverage.RISE_UNREACHABLE_SOURCES)[:2]
    got = export_value.rank(manifest(missing=unreachable), "rise_pce")
    assert [r["source"] for r in got["ranked"]] == []
    assert sorted(r["source"] for r in got["unobtainable"]) == unreachable


def test_the_same_source_is_advice_on_premise():
    """The constraint is the RISE contract, not the file. On-premise the
    customer has OS access and can produce it."""
    one = sorted(coverage.RISE_UNREACHABLE_SOURCES)[:1]
    got = export_value.rank(manifest(missing=one), "on_prem")
    assert [r["source"] for r in got["ranked"]] == one
    assert got["unobtainable"] == []


def test_an_unobtainable_source_is_reported_rather_than_hidden():
    """Dropping it silently would leave the gap unexplained; the reader needs
    to know WHY it is absent, not just that it is."""
    one = sorted(coverage.RISE_UNREACHABLE_SOURCES)[:1]
    got = export_value.rank(manifest(missing=one), "rise_pce")
    assert got["unobtainable"] and got["missing"] == 1


# --------------------------------------------------------------------------- #
#  The one line a person acts on                                               #
# --------------------------------------------------------------------------- #

def test_the_sentence_names_sources_and_what_they_buy():
    got = export_value.rank(manifest(
        missing=["security_params", "users", "role_auth_values"]))
    line = export_value.sentence(got)
    assert "Supply" in line and "check(s) would run" in line


def test_the_sentence_says_nothing_when_nothing_would_be_unlocked():
    """A recommendation that unlocks no check is noise, and noise gets filtered
    out along with the signal."""
    assert export_value.sentence({"ranked": [{"source": "x", "unlocks_now": 0}],
                                  "missing": 1, "checks_blocked": 0}) == ""


def test_the_sentence_does_not_say_next_twice():
    """Both callers prefix it — "next: ..." — and the sentence said it too."""
    got = export_value.rank(manifest(missing=["security_params", "users"]))
    assert export_value.sentence(got).lower().count("next") == 0
