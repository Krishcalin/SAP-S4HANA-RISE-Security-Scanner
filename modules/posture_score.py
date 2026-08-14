# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""The headline posture score, and the two things that were wrong with it.

WHAT IT USED TO BE

    min(100, crit * 25 + high * 10 + med * 4 + low * 1)

Two defects, and the second is the one that matters.

IT COULD NOT MOVE. On a real estate the raw total reaches the thousands — 3693
on the reference dataset — so it clamped to 100 and stayed there. Four criticals
also score 100. A customer who closed sixty findings saw the same number as
before, which is the fastest way to teach somebody that a number means nothing.

IT IMPROVED WHEN THE CUSTOMER SUPPLIED LESS. Fewer exports meant fewer modules
ran, which meant fewer findings, which meant a lower score. The incentive pointed
exactly backwards, and it is the same incentive `server/analytics.py` names in
its own docstring about the pass rate.

WHAT IT IS NOW

    100 * sum(worst severity per CHECK) / (WORST_WEIGHT * checks_that_actually_ran)

Both halves count the same unit — checks, not findings — which is what makes the
anchor below literally true rather than roughly true.

A severity-weighted density over what was ASSESSED, not a count. Closing findings
moves it down, which is the whole point.

WHAT WITHHOLDING EXPORTS CAN AND CANNOT DO — STATED EXACTLY, BECAUSE THE FIRST
VERSION OF THIS DOCSTRING CLAIMED IMMUNITY AND MEASUREMENT SAID OTHERWISE.

A mean cannot be made monotone under subsetting. Written out:

    score = 100 * SUM(w) / (25 * A)     over the assessed set
    removing one check lowers it  <=>  w > SUM(w) / A

that is, removing any check whose severity is above the estate's OWN AVERAGE
pulls the average down. This is a property of averages, not of these weights, and
no reweighting removes it. A standalone offline report has no prior run to hold
the denominator against, so there is nothing to anchor it to. The honest position
is that this number describes WHAT WAS ASSESSED, the report prints how much that
was, and the guarantee is bounded rather than absolute.

Bounded, and measured on sample_data by removing each of the 108 exports in turn:

    counting degraded modules' unrun checks   61 of 108 lowered it, by up to 4
    not counting them, per-finding             3 of 108, by up to 3
    not counting them, per-check (current)    14 of 108, by 1-2

The middle row looks best on count alone and is the wrong choice: per-FINDING
scoring is what let a single check firing on 500 users contribute 500 findings'
worth against one check of denominator, which both concentrated the leverage and
made the ANCHOR below false. The current row spreads a smaller effect wider and
is the only one where the anchor is literally true.

What IS eliminated is the large, systematic version of the incentive: a module
that ran on partial input no longer contributes the checks it never got to run.
Before that fix a 20-of-108-file upload scored 9 against the full estate's 36 —
a whole band better for supplying less.

THE BANDS ARE THE WEIGHTS, NOT A JUDGEMENT. Every threshold is "what would this
score if every check that ran found one finding of this severity":

    100   every assessed check found a CRITICAL
     40   ...a HIGH
     16   ...a MEDIUM
      4   ...a LOW

so the bands are 40 / 16 / 4 rather than numbers somebody liked the look of, and
the report can state the anchor in one line. That is the whole defence of putting
a single number on a front page at all.

NO DENOMINATOR, NO SCORE. If the coverage manifest is absent we do not know what
ran, so there is nothing to divide by and the caller is told to print the counts
instead. Inventing a denominator here would be the same error as every other one
this codebase has spent two days removing: a confident number over an absence of
evidence.

KNOWN DEFECT, NOT YET FIXED: DISCOVERING MORE CAN LOWER IT.

A check built at runtime from a rule table is invisible unless it FAILS — there
is no literal id for `check_catalogue` to find — so it joins the denominator only
on failure. A newly discovered finding on such a check therefore adds a below-
average item to a mean, and the mean falls. Measured on sample_data:

    baseline                            38
    + 10 new LOW findings on unseen checks   37
    + 30                                     35
    +120                                     29

Nothing was remediated. The estate got worse and the number improved by nine
points, which is the same failure as the old formula in the opposite direction.
It is not visible on a single finding (rounding absorbs it) and it is the reason
this note exists rather than a caveat in the docstring's optimistic half.

THE FIX IS ENUMERATION, NOT PROVENANCE. The 255 runtime checks are built from
rule tables shipped in this repository — that is where docs/CHECKS_REFERENCE.md
gets 619 from. `check_catalogue()` stops at literals by choice, not necessity.
Counting rule-table rows per module makes the denominator complete and
independent of what was found, which closes this and shrinks the withholding
residue above at the same time, because a degraded module would then have a
knowable check count instead of an observed one.

THIS IS NOT A COMPLIANCE PERCENTAGE. It is findings per check weighted by
severity, and it has no upper meaning beyond the anchor above.
modules/compliance_mapping.py forbids the other thing and this does not become it.
"""
from typing import Any, Dict, Iterable, Optional, Tuple

#: Severity weights. The ONLY place they are written; the bands below are
#: derived from them so the two can never drift apart.
WEIGHTS = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 4, "LOW": 1, "INFO": 0}

WORST_WEIGHT = WEIGHTS["CRITICAL"]

#: (floor, label) worst first. Each floor is the score an estate would post if
#: every check that ran found exactly one finding of that severity.
BANDS: Tuple[Tuple[int, str], ...] = (
    (round(100 * WEIGHTS["HIGH"] / WORST_WEIGHT), "Critical"),
    (round(100 * WEIGHTS["MEDIUM"] / WORST_WEIGHT), "High"),
    (round(100 * WEIGHTS["LOW"] / WORST_WEIGHT), "Medium"),
    (0, "Low"),
)

#: The sentence a report prints beside the number. Without it a reader has no way
#: to know whether 36 is good, and a score nobody can interpret is decoration.
ANCHOR = ("100 would mean every check that ran found a critical; 40, a high; "
          "16, a medium; 4, a low.")


def assessed_check_count(coverage: Optional[Dict[str, Any]],
                         observed: Iterable[str] = ()) -> Optional[int]:
    """How many checks actually executed, or None when we cannot tell.

    Two sources, and the distinction between them is the whole correctness of
    this function:

      * every check this scan actually EMITTED. Those certainly ran. Roughly 255
        checks are built at runtime from rule tables rather than written as
        literals, and this is the only way they are counted at all.
      * every check declared by a module that ran ON COMPLETE INPUT. Those
        certainly ran too, whether or not they found anything.

    A DEGRADED MODULE CONTRIBUTES ONLY THE FIRST. This is the correction to a
    defect that made the rebase worse than useless. A module missing some of its
    sources still ran, so it was in `ran_modules(...)`, so it contributed its
    FULL declared check list — while the individual checks whose sources were
    absent self-skipped and produced nothing. The numerator fell and the
    denominator did not move, so WITHHOLDING EXPORTS IMPROVED THE SCORE, which is
    the exact incentive the rebase existed to remove. Measured over sample_data
    before the fix: all 108 exports scored 36, dropping four HANA files scored 34
    with the denominator pinned at 402, and a 20-file upload scored 9 — a whole
    band better with nothing remediated. Sweeping all 108 single-file removals,
    61 lowered the score and none raised it.

    So `require_complete=True`: a module with a missing source is no longer taken
    to have run every check it declares, because it did not. This is the
    four-state discipline applied to arithmetic — a check we could not run is not
    assessed capacity, and counting it as such let "we could not look" render as
    clean headroom.

    THE RESULT IS A FLOOR, DELIBERATELY. A degraded module now counts only the
    checks seen to fire, which over-states its density. That makes the score a
    CEILING — where it is wrong it over-states risk, the only direction a
    security report may be wrong in, and the direction that leaves withholding
    exports unprofitable.

    NOTHING RAN IS NOT A DENOMINATOR OF ONE. `{"modules": {}}` used to fall
    through to the observed set, so a manifest recording that no module executed
    still produced a confident number — and since every observed check had, by
    definition, produced a finding, that number was 100. `ran_modules` returns
    None for "we cannot tell" and an empty set for "nothing ran"; both mean there
    is nothing to divide by, and the two must not be allowed to diverge here.
    """
    from modules.coverage import module_check_ids, ran_modules

    if not ran_modules(coverage):
        return None
    intact = ran_modules(coverage, require_complete=True) or set()
    declared = {cid for module in intact
                for cid in module_check_ids().get(module, ())}
    total = declared | {c for c in observed if c}
    return len(total) or None


def scope_note(assessed: int) -> str:
    """The sentence that makes the score's CONDITION visible next to it.

    The number is a statement about the assessed portion of the estate, and any
    conditional statement can be moved by changing its condition (see the module
    docstring). Since the condition cannot be made irrelevant, it is printed:
    a reader comparing two reports can see immediately that one covered fewer
    checks than the other, and the coverage section says which and why.
    """
    return "Computed over the %d checks this scan actually ran." % assessed


def score_with_scope(findings: Iterable[Dict[str, Any]],
                     coverage: Optional[Dict[str, Any]] = None
                     ) -> Optional[Tuple[int, str, int]]:
    """(score, band, checks assessed), or None when nothing can be divided."""
    findings = list(findings)
    assessed = assessed_check_count(
        coverage, (f.get("check_id") for f in findings))
    if not assessed:
        return None
    got = score(findings, coverage)
    return None if got is None else (got[0], got[1], assessed)


def score(findings: Iterable[Dict[str, Any]],
          coverage: Optional[Dict[str, Any]] = None
          ) -> Optional[Tuple[int, str]]:
    """(score, band) over what was assessed, or None when nothing can be divided.

    `findings` should be the UNFILTERED corpus. A display filter must not move a
    claim about the estate — see sap_scanner.py's `full_findings`.
    """
    findings = list(findings)
    assessed = assessed_check_count(
        coverage, (f.get("check_id") for f in findings))
    if not assessed:
        return None

    # ONE CHECK, ONE CONTRIBUTION — its worst result.
    #
    # Summing per FINDING while dividing per CHECK made the two halves count
    # different things: a check that fires on 500 users added 500 findings' worth
    # to the numerator and 1 to the denominator. Two consequences, both bad.
    #
    # It kept the withholding incentive alive after the degraded-module fix had
    # removed most of it. Dropping custom_code_scan.csv from sample_data took 355
    # off the numerator and 12 off the denominator, so the score fell — three of
    # 108 single-file removals still paid.
    #
    # And it made the printed ANCHOR false. "100 would mean every check that ran
    # found a critical" is only true if a check can contribute at most one
    # critical; otherwise a handful of high-multiplicity checks reach 100 on
    # their own, which is how the OLD formula behaved and exactly what this
    # rebase set out to stop.
    #
    # Multiplicity is not lost, it is just not in the headline: the severity
    # cards, the finding tables and the FAIR figure all carry per-object counts.
    worst = {}
    for f in findings:
        weight = WEIGHTS.get(str(f.get("severity", "")).upper(), 0)
        key = f.get("check_id") or ("\\x00anonymous", id(f))
        if weight > worst.get(key, -1):
            worst[key] = weight
    weighted = sum(worst.values())
    value = min(100, round(100 * weighted / (WORST_WEIGHT * assessed)))
    for floor, label in BANDS:
        if value >= floor:
            return value, label
    return value, BANDS[-1][1]                       # unreachable; floor is 0
