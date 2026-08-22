"""
Resilience thresholds — the rules that fired on working systems, and the rules
that must still fire on broken ones.

WHY THIS FILE IS SEPARATE FROM tests/test_resilience_posture.py
---------------------------------------------------------------
That file establishes what each check MEANS. This one is about where each check's
line sits, and every test here is a PAIR: a shape that must be silent, followed by
the shape that must still be reported. A narrowing that also stops detecting the
real thing is not an improvement over over-reporting — it is the same failure
wearing a quieter coat, and it is the harder one to notice, because a report that
says nothing looks like a report about a healthy system.

THE MEASUREMENT THAT MOTIVATED IT
RES-BCK-002 counted ABSOLUTE lifetime backup failures. A customer with 3 failures
in 5,000 runs and a customer with 3 in 4 produced the identical MEDIUM finding, so
the check fired on essentially every customer who exported a real history — and a
customer with one bad week years ago could never clear it, because a lifetime
count only goes up.

THE OTHER FAILURE MODE THROUGHOUT
"Nothing to find" and "could not look" must never render the same. Several tests
below assert that a check which was DEFEATED by the export says so (RES-EVD-001)
instead of either falling silent — which reads as a clean result — or asserting a
HIGH finding manufactured out of a vocabulary gap.

DETERMINISM
Every dated fixture is built relative to a pinned "today" via the
`resilience_today` baseline override. A recency test that reads the real clock
passes today and fails in March, and a test that rots gets deleted rather than
fixed.
"""
from __future__ import annotations

import sys
from datetime import date, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.resilience_posture import ResiliencePostureAuditor  # noqa: E402

#: Pinned "today". Every date below is expressed as an offset from it.
TODAY = date(2026, 8, 7)


def run(data, **overrides):
    ov = {"resilience_today": TODAY.strftime("%Y%m%d")}
    ov.update(overrides)
    return ResiliencePostureAuditor(data, ov).run_all_checks()


def ids(findings):
    return sorted({f["check_id"] for f in findings})


def one(findings, check_id):
    return next(f for f in findings if f["check_id"] == check_id)


def ago(days: int) -> str:
    return (TODAY - timedelta(days=days)).isoformat()


def backup(kind, status, day, **extra):
    row = {"BACKUP_TYPE": kind, "STATUS": status, "START_TIME": day}
    row.update(extra)
    return row


def rec_test(kind, result, day, **extra):
    row = {"TEST_TYPE": kind, "RESULT": result, "DATE": day}
    row.update(extra)
    return row


def items(findings, check_id):
    return one(findings, check_id)["affected_items"]


#: A backup catalogue with nothing wrong in it, used as the quiet background for
#: tests that are about the recovery-test checks rather than the backup ones.
CLEAN_CATALOG = [
    backup("complete data backup", "successful", ago(1)),
    backup("log backup", "successful", ago(0)),
]

#: Passing tests of both kinds, recent, so RES-DR-001 is silent unless the test
#: below deliberately breaks one of them.
CLEAN_TESTS = [
    rec_test("Point-in-time restore", "pass", ago(60)),
    rec_test("DR failover", "pass", ago(90)),
]


# --------------------------------------------------------------------------- #
#  RES-BCK-002 — a rate inside a window, not a lifetime count                 #
# --------------------------------------------------------------------------- #

def _hourly_log_history(days: int, per_day: int = 24):
    """A realistic log-backup catalogue: `per_day` successful runs a day."""
    return [backup("log backup", "successful", ago(d))
            for d in range(days) for _ in range(per_day)]


def test_a_handful_of_failures_in_a_large_healthy_history_is_not_reported():
    """THE DEFECT THIS CHANGE EXISTS TO FIX.

    4,992 successful log backups and three failures. Under the lifetime count this
    was the same MEDIUM finding as a chain that fails three times out of four, so
    the check fired on any customer who exported more than a token history — and a
    rule that fires on almost everybody is one its reader learns to skip past,
    taking the true positives with it.
    """
    data = {"backup_catalog": _hourly_log_history(208) + [
        backup("log backup", "failed", ago(2)),
        backup("log backup", "failed", ago(3)),
        backup("log backup", "failed", ago(4)),
    ]}
    assert "RES-BCK-002" not in ids(run(data))


def test_three_failures_out_of_four_runs_is_still_reported():
    """THE CONTROL for the narrowing above, and the shape the check is named for:
    a chain that fails most of the time is unreliable however few runs there are."""
    data = {"backup_catalog": [
        backup("log backup", "successful", ago(1)),
        backup("log backup", "failed", ago(2)),
        backup("log backup", "failed", ago(3)),
        backup("log backup", "failed", ago(4)),
    ]}
    assert "RES-BCK-002" in ids(run(data))


def test_a_bad_week_that_has_since_been_fixed_stops_being_reported():
    """THE CASE THE LIFETIME COUNT GOT WRONG IN THE OTHER DIRECTION.

    Seven failures a year ago and clean ever since. A count that only goes up can
    never retire, so this customer failed the check permanently no matter what they
    did afterwards — the finding was a record of history rather than a statement
    about the system, and a control that cannot be closed stops being worked.
    """
    data = {"backup_catalog":
            [backup("log backup", "successful", ago(d)) for d in range(0, 60)]
            + [backup("log backup", "failed", ago(300 + d)) for d in range(7)]}
    assert "RES-BCK-002" not in ids(run(data))


def test_a_bad_week_happening_now_is_reported():
    """THE CONTROL for the window. The same seven failures, this week instead of
    last year, must fire — and a lifetime SHARE alone would have missed this on a
    large estate, which is why the rule is a share INSIDE a window rather than a
    share over the whole catalogue."""
    data = {"backup_catalog":
            [backup("log backup", "successful", ago(0))]
            + [backup("log backup", "failed", ago(1 + d)) for d in range(7)]
            + [backup("log backup", "successful", ago(d)) for d in range(8, 60)]}
    found = run(data)
    assert "RES-BCK-002" in ids(found)
    assert any("%" in item for item in items(found, "RES-BCK-002")), \
        "the finding must state the share it measured, or nobody can audit the rule"


def test_the_count_alone_does_not_fire_it():
    """Three failures among a hundred recent runs is normal operations at scale.
    This is the exact shape the old rule reported and the reason it was noise."""
    data = {"backup_catalog":
            [backup("log backup", "successful", ago(d % 30)) for d in range(100)]
            + [backup("log backup", "failed", ago(d)) for d in (2, 3, 4)]}
    assert "RES-BCK-002" not in ids(run(data))


def test_the_share_alone_does_not_fire_it():
    """Two failures in four runs is a 50% share, and a minimum count is what stops
    a four-row catalogue from being read as an unreliable chain. Both conditions
    are required precisely because either one alone has a shape it gets wrong."""
    data = {"backup_catalog": [
        backup("log backup", "successful", ago(1)),
        backup("log backup", "successful", ago(2)),
        backup("log backup", "failed", ago(3)),
        backup("log backup", "failed", ago(4)),
    ]}
    assert "RES-BCK-002" not in ids(run(data))


def test_the_share_and_the_window_are_configurable():
    """The defaults are defaults, not doctrine. A shop that treats any failure as
    reportable, and one that runs a longer window, are both entitled to say so."""
    noisy = {"backup_catalog":
             [backup("log backup", "successful", ago(d % 30)) for d in range(100)]
             + [backup("log backup", "failed", ago(d)) for d in (2, 3, 4)]}
    assert "RES-BCK-002" not in ids(run(noisy))
    assert "RES-BCK-002" in ids(run(noisy, resilience_backup_failure_ratio=0.01))

    recent = {"backup_catalog": [
        backup("log backup", "successful", ago(0)),
        backup("log backup", "failed", ago(3)),
        backup("log backup", "failed", ago(4)),
        backup("log backup", "failed", ago(5)),
    ]}
    assert "RES-BCK-002" in ids(run(recent))
    assert "RES-BCK-002" not in ids(
        run(recent, resilience_backup_failure_window_days=1))


def test_an_undated_catalogue_is_measured_whole_and_says_that_it_was():
    """A catalogue with no readable dates cannot be windowed. Dropping the check
    would make an unreadable date column look like a clean chain, so it falls back
    to the whole catalogue under the SAME count-and-share rule — and states the
    basis, because a lifetime figure read as a recent one is a different claim."""
    data = {"backup_catalog": [
        backup("complete data backup", "successful", ago(1)),
        backup("log backup", "successful", ""),
        backup("log backup", "failed", ""),
        backup("log backup", "failed", ""),
        backup("log backup", "failed", ""),
    ]}
    found = run(data)
    assert "RES-BCK-002" in ids(found)
    assert any("whole catalogue" in item for item in items(found, "RES-BCK-002"))


def test_the_undated_fallback_still_applies_the_share():
    """THE CONTROL for the fallback. If it reverted to a bare count it would
    reintroduce the original defect for every customer whose export happens to have
    an unreadable date column."""
    data = {"backup_catalog": [
        backup("complete data backup", "successful", ago(1)),
    ] + [backup("log backup", "successful", "") for _ in range(100)]
        + [backup("log backup", "failed", "") for _ in range(3)]}
    assert "RES-BCK-002" not in ids(run(data))


def test_a_healthy_chain_produces_nothing():
    """The negative control for this check specifically."""
    data = {"backup_catalog": CLEAN_CATALOG, "recovery_tests": CLEAN_TESTS}
    assert ids(run(data)) == []


# --------------------------------------------------------------------------- #
#  RES-BCK-001 — unclassifiable is not absent                                 #
# --------------------------------------------------------------------------- #

#: A backup type spelled in a way this scanner has no vocabulary for. Realistic:
#: these exports arrive from whatever locale the customer's Basis team works in.
FOREIGN_TYPE = "SICHERUNG KOMPLETT"


def test_a_successful_run_we_could_not_classify_is_not_reported_as_no_backup():
    """The catalogue records a SUCCESSFUL run whose type we could not read. It may
    well be the full data backup. Asserting at HIGH that none exists would be a
    false accusation manufactured by our own vocabulary — and it is the first
    finding a customer checks by hand, because they know whether their backups run.

    The verdict is withheld and the reason is disclosed, which is the same doctrine
    RES-BCK-004 already applies to an unreadable DATE.
    """
    data = {"backup_catalog": [
        backup(FOREIGN_TYPE, "successful", ago(1)),
        backup("log backup", "successful", ago(0)),
    ]}
    found = run(data)
    assert "RES-BCK-001" not in ids(found)
    assert "RES-EVD-001" in ids(found)
    assert one(found, "RES-EVD-001")["severity"] == "INFO"
    assert any(FOREIGN_TYPE in item for item in items(found, "RES-EVD-001")), \
        "the unreadable spelling must be quoted back, or the customer cannot fix it"


def test_a_fully_classified_catalogue_with_no_full_backup_still_reports_it():
    """THE CONTROL. Every row here was classified, and classified as something that
    is not a full data backup. That is positive evidence of a missing recovery
    point, and if the doctrine above silenced this too it would have traded a false
    HIGH for a silent one — which is the worse trade, every time."""
    data = {"backup_catalog": [
        backup("differential data backup", "successful", ago(1)),
        backup("log backup", "successful", ago(0)),
    ]}
    assert "RES-BCK-001" in ids(run(data))


def test_an_unclassifiable_run_that_FAILED_does_not_suppress_the_finding():
    """Only a SUCCESS we could not classify blocks the verdict, because only a
    success could have been the missing full backup. A failed row of an unknown
    type is no evidence of a recovery point at all."""
    data = {"backup_catalog": [
        backup(FOREIGN_TYPE, "failed", ago(1)),
        backup("log backup", "successful", ago(0)),
    ]}
    assert "RES-BCK-001" in ids(run(data))


def test_a_stale_full_backup_beside_an_unclassifiable_success_still_reports():
    """A stale CLASSIFIED chain is positive evidence and the finding stands. But the
    unclassified success might be a newer full backup, so the age is not presented
    as settled — the caveat is in the finding rather than in a reviewer's memory."""
    data = {"backup_catalog": [
        backup("complete data backup", "successful", ago(40)),
        backup(FOREIGN_TYPE, "successful", ago(1)),
        backup("log backup", "successful", ago(0)),
    ]}
    found = run(data)
    assert "RES-BCK-001" in ids(found)
    hit = one(found, "RES-BCK-001")
    assert "could not be classified" in hit["description"]
    assert hit["details"]["successful_runs_of_unclassifiable_type"] == 1


# --------------------------------------------------------------------------- #
#  RES-BCK-003 — the same doctrine, on the check that was left out of it      #
# --------------------------------------------------------------------------- #

def test_an_entirely_unclassifiable_catalogue_produces_no_high_log_backup_finding():
    """THE FALSE POSITIVE THIS PAIR EXISTS TO PIN DOWN, found by running the module
    rather than by reading it.

    A healthy estate whose catalogue is exported in German: seven daily full
    backups and 168 hourly log backups, every one successful and every one recent.
    RES-BCK-001 correctly withheld its verdict — the module knew perfectly well it
    could not classify these types, and said so — and RES-BCK-003 then asserted at
    HIGH that no successful log backup existed, beside an affected_item claiming
    "full data backup: 0 successful run(s)" about a system with seven.

    A vocabulary gap manufacturing a HIGH accusation is the single most damaging
    thing this module can do, and it is the one the rest of this change was written
    to prevent. It had been closed for the STATUS vocabulary and for RES-BCK-001,
    which left the remaining check on the TYPE vocabulary as the only way in.
    """
    catalog = ([backup("SICHERUNG KOMPLETT", "successful", ago(d)) for d in range(7)]
               + [backup("PROTOKOLLSICHERUNG", "successful", ago(d))
                  for d in range(7) for _ in range(24)])
    found = run({"backup_catalog": catalog, "recovery_tests": CLEAN_TESTS})
    assert "RES-BCK-003" not in ids(found)
    assert not [f for f in found if f["severity"] in ("HIGH", "CRITICAL")], \
        "a catalogue we cannot classify must not become a HIGH finding"
    assert "RES-EVD-001" in ids(found)
    assert any("log backup" in item and "could not classify" in item
               for item in items(found, "RES-EVD-001")), \
        "withholding the verdict is only honest if the reason is disclosed"


def test_a_fully_classified_catalogue_with_no_log_backup_still_reports_it():
    """THE CONTROL. Every row here was classified, and classified as something that
    is not a log backup. That is positive evidence that point-in-time recovery is
    not available, and a narrowing that also silenced this would have traded a
    false HIGH for a silent one — the worse trade, every time."""
    data = {"backup_catalog": [
        backup("complete data backup", "successful", ago(1)),
        backup("differential data backup", "successful", ago(0)),
    ], "recovery_tests": CLEAN_TESTS}
    assert "RES-BCK-003" in ids(run(data))


def test_an_unclassifiable_run_that_FAILED_does_not_suppress_the_log_finding():
    """Only a SUCCESS blocks the verdict, because only a success could have been
    the log backup we failed to recognise. Mirrors the same rule on RES-BCK-001."""
    data = {"backup_catalog": [
        backup("complete data backup", "successful", ago(1)),
        backup(FOREIGN_TYPE, "failed", ago(1)),
    ], "recovery_tests": CLEAN_TESTS}
    assert "RES-BCK-003" in ids(run(data))


# --------------------------------------------------------------------------- #
#  An unreadable status vocabulary is not a missing backup                    #
# --------------------------------------------------------------------------- #

def test_a_catalogue_with_no_readable_status_produces_no_high_finding():
    """Every backup check decides on the presence or absence of a recorded SUCCESS,
    so a catalogue whose entire status vocabulary is unknown to us yields two HIGH
    findings — "no full backup", "no log backup" — out of nothing but a spelling
    gap. That is the most damaging thing this module can do, so it declines to
    judge and says why."""
    data = {"backup_catalog": [
        backup("complete data backup", "3", ago(1)),
        backup("log backup", "3", ago(0)),
    ]}
    found = run(data)
    assert "RES-BCK-001" not in ids(found)
    assert "RES-BCK-003" not in ids(found)
    assert "RES-EVD-001" in ids(found)
    assert not [f for f in found if f["severity"] == "HIGH"]
    assert any("'3'" in item for item in items(found, "RES-EVD-001"))


def test_one_readable_status_is_enough_to_keep_judging():
    """THE CONTROL. Suppressing on ANY unknown status would let one odd row switch
    off the module's loudest checks — a much cheaper way to hide a missing backup
    than actually taking one."""
    data = {"backup_catalog": [
        backup("complete data backup", "3", ago(1)),
        backup("log backup", "successful", ago(0)),
    ]}
    found = run(data)
    assert "RES-BCK-001" in ids(found)
    assert one(found, "RES-BCK-001")["details"]["runs_with_unreadable_status"] == 1


def test_the_outcome_docstring_no_longer_claims_unknown_is_neutral():
    """It said an unknown status "contributes to neither side of any check". It does
    contribute: the checks fire on the ABSENCE of a success, so an unreadable status
    pushes them toward firing exactly as a failure would. A comment describing
    behaviour the code does not have is worse than no comment, because the next
    reader trusts it instead of reading the code — and this one was load-bearing,
    since it was the stated reason nobody needed to handle the vocabulary gap."""
    doc = ResiliencePostureAuditor._classify_outcome.__doc__ or ""
    assert "NOT neutral" in doc, "the docstring is back to claiming neutrality"
    assert "ABSENCE" in doc, "it must say WHY unknown is not neutral, not just that"


# --------------------------------------------------------------------------- #
#  RES-DR-003 — refuse a number rather than guess at it                       #
# --------------------------------------------------------------------------- #

def test_a_thousands_separator_is_not_read_as_a_decimal_point():
    """"1,000" is one thousand under one convention and one-point-nought under
    another. The old parser turned every comma into a decimal point, so a
    1,000-minute target became 1.0 and an achieved 1,500 read as a catastrophic
    breach of it — a fabricated MEDIUM on a test that met its objective."""
    data = {"backup_catalog": CLEAN_CATALOG, "recovery_tests": [
        rec_test("Restore", "pass", ago(60), RTO_TARGET="1,000",
                 RTO_ACHIEVED="1500"),
        rec_test("DR failover", "pass", ago(90)),
    ]}
    found = run(data)
    assert "RES-DR-003" not in ids(found)
    assert "RES-EVD-001" in ids(found), \
        "refusing to read a figure must be disclosed, not silently skipped"


def test_an_unrecognised_unit_is_not_read_as_minutes():
    """The old parser kept the leading digits and dropped the suffix it did not
    know, so "6 hours" against a 240-minute objective became 6 — comfortably inside
    a target it actually missed by two hours. A guess that inverts the verdict is
    worse than a refusal, and the refusal is now visible."""
    data = {"backup_catalog": CLEAN_CATALOG, "recovery_tests": [
        rec_test("Restore", "pass", ago(60), RTO_TARGET="240",
                 RTO_ACHIEVED="6 hours"),
        rec_test("DR failover", "pass", ago(90)),
    ]}
    found = run(data)
    assert "RES-DR-003" not in ids(found)
    assert any("6 hours" in item for item in items(found, "RES-EVD-001"))


@pytest.mark.parametrize("target, achieved", [
    ("240", "905"),
    ("240 min", "905 min"),
    ("240", "905 minutes"),
    ("240.0", "905.5"),
])
def test_a_missed_objective_in_a_readable_form_is_still_reported(target, achieved):
    """THE CONTROL for the refusals above. Tightening the parser is only worth
    shipping if it still reads the forms these exports actually use — a stricter
    rule that also stops detecting the real breach is not an improvement."""
    data = {"backup_catalog": CLEAN_CATALOG, "recovery_tests": [
        rec_test("Restore", "pass", ago(60), RTO_TARGET=target,
                 RTO_ACHIEVED=achieved),
        rec_test("DR failover", "pass", ago(90)),
    ]}
    found = run(data)
    assert "RES-DR-003" in ids(found)
    assert "RES-EVD-001" not in ids(found)


def test_a_column_the_customer_left_blank_is_not_reported_as_unreadable():
    """A missing measurement is an unmeasured control and correctly produces
    nothing. Only a cell they FILLED IN that we would not guess at is a gap in the
    export, and conflating the two would manufacture a coverage note out of a
    column that was never there."""
    data = {"backup_catalog": CLEAN_CATALOG, "recovery_tests": [
        rec_test("Restore", "pass", ago(60), RTO_TARGET="240"),
        rec_test("DR failover", "pass", ago(90)),
    ]}
    assert ids(run(data)) == []


# --------------------------------------------------------------------------- #
#  Test-type classification — the collisions that SILENCED a category         #
# --------------------------------------------------------------------------- #

def _dr_categories_missing(found):
    """Which of the two recovery-test categories RES-DR-001 reported as missing."""
    if "RES-DR-001" not in ids(found):
        return set()
    return {item.split(":")[0] for item in items(found, "RES-DR-001")}


def test_a_disaster_recovery_exercise_does_not_satisfy_the_data_restore_category():
    """"Disaster Recovery" contains "recover", so a continuity exercise was credited
    as a data restore as well and RES-DR-001 went quiet about restores on a customer
    who had never restored anything. The two questions are different — "can we get
    the data back" and "can we run somewhere else" — and a substring collision
    silencing one of them is the dangerous direction for this module to be wrong in.
    """
    data = {"backup_catalog": CLEAN_CATALOG, "recovery_tests": [
        rec_test("Disaster Recovery exercise", "pass", ago(60)),
    ]}
    assert "data restore" in _dr_categories_missing(run(data))


def test_a_restore_drill_does_not_satisfy_the_dr_category():
    """The same defect mirrored: the continuity vocabulary matched " dr" as a
    substring, which "drill" supplies, so a pure restore exercise was credited as a
    failover test. Both collisions removed a finding rather than adding one."""
    data = {"backup_catalog": CLEAN_CATALOG, "recovery_tests": [
        rec_test("Restore drill", "pass", ago(60)),
    ]}
    assert "DR / failover" in _dr_categories_missing(run(data))


def test_a_recovery_test_that_is_not_a_dr_exercise_still_credits_a_restore():
    """THE CONTROL for narrowing "recover". It is a perfectly ordinary way to name a
    restore test, and refusing to credit it at all would tell customers who run them
    that they never have."""
    data = {"backup_catalog": CLEAN_CATALOG, "recovery_tests": [
        rec_test("Database recovery test", "pass", ago(60)),
    ]}
    assert "data restore" not in _dr_categories_missing(run(data))


@pytest.mark.parametrize("spelling", [
    "DR", "DR test", "dr_test", "DR-failover", "Failover exercise",
    "fail-over test", "Switchover rehearsal", "table-top exercise", "Tabletop",
    "BCP walkthrough", "Business continuity exercise", "Disaster recovery",
])
def test_continuity_spellings_are_still_credited(spelling):
    """THE CONTROL for matching `dr` and `bcp` as whole words. These are the
    spellings a real evidence file uses, and losing any of them would report a
    customer who exercises failover annually as never having done it."""
    data = {"backup_catalog": CLEAN_CATALOG, "recovery_tests": [
        rec_test("Point-in-time restore", "pass", ago(60)),
        rec_test(spelling, "pass", ago(90)),
    ]}
    assert "RES-DR-001" not in ids(run(data)), f"{spelling!r} was not credited"


@pytest.mark.parametrize("spelling", ["Restore drill", "Restore rehearsal",
                                      "Point-in-time restore"])
def test_a_restore_exercise_never_credits_the_continuity_category(spelling):
    data = {"backup_catalog": CLEAN_CATALOG, "recovery_tests": [
        rec_test(spelling, "pass", ago(60)),
    ]}
    assert "DR / failover" in _dr_categories_missing(run(data))


# --------------------------------------------------------------------------- #
#  RES-DR-001 — "nobody ran one" is not "I could not read yours"              #
# --------------------------------------------------------------------------- #

def test_an_unclassifiable_test_record_is_named_as_such():
    """The two states take DIFFERENT actions — schedule an exercise, versus fix the
    export or tell us what your naming means — and one sentence for both told a
    customer who runs quarterly failover exercises under a local name that they had
    never run one. That is the accusation that ends the conversation."""
    data = {"backup_catalog": CLEAN_CATALOG, "recovery_tests": [
        rec_test("Point-in-time restore", "pass", ago(60)),
        rec_test("Quartalsuebung Ausweichrechenzentrum", "pass", ago(60)),
    ]}
    found = run(data)
    line = next(i for i in items(found, "RES-DR-001") if i.startswith("DR / failover"))
    assert "could not classify" in line
    assert "Quartalsuebung Ausweichrechenzentrum" in line


def test_a_genuinely_absent_category_is_still_stated_plainly():
    """THE CONTROL. With nothing unclassifiable in the evidence, "no test of this
    kind was recorded" is the true statement and must not be softened into a
    parser caveat — that would turn a real gap into an apology for our own reader."""
    data = {"backup_catalog": CLEAN_CATALOG, "recovery_tests": [
        rec_test("Point-in-time restore", "pass", ago(60)),
    ]}
    found = run(data)
    line = next(i for i in items(found, "RES-DR-001") if i.startswith("DR / failover"))
    assert "could not classify" not in line
    assert "no test of this kind recorded" in line


# --------------------------------------------------------------------------- #
#  RES-EVD-001 — the finding contract, and what it must not claim             #
# --------------------------------------------------------------------------- #

def _gap_finding():
    return one(run({"backup_catalog": [backup("SICHERUNG KOMPLETT", "successful",
                                              ago(1)),
                                       backup("log backup", "successful", ago(0))]}),
               "RES-EVD-001")


def test_the_gap_finding_routes_to_an_owning_team():
    """A check that routes nowhere appears on no team's worklist and is never
    worked, which makes shipping it indistinguishable from not shipping it."""
    from server.enrich import team_for
    assert team_for("RES-EVD-001") != "unassigned"


def test_the_gap_finding_honours_the_finding_contract():
    hit = _gap_finding()
    assert hit["severity"] == "INFO"
    assert hit["category"] == "Resilience & Recovery Readiness"
    assert isinstance(hit["description"], str) and hit["description"]
    assert isinstance(hit["remediation"], str) and hit["remediation"]
    assert isinstance(hit["references"], list) and hit["references"]
    assert hit["affected_items"] and all(isinstance(i, str)
                                         for i in hit["affected_items"])
    assert hit["scope"] == "aggregate"
    # A coverage gap names no defective object. Coining one would put a node in the
    # attack-path graph that the export never contained.
    assert "affected_objects" not in hit


def test_the_gap_finding_does_not_assert_a_defect():
    """It says a check could not run. It must not read as a verdict on the backups,
    because the whole reason it exists is that no verdict was reached."""
    hit = _gap_finding()
    text = " ".join([hit["title"], hit["description"], hit["remediation"],
                     *hit["affected_items"]]).lower()
    for claim in ("we verified", "we tested", "proves", "guarantees",
                  "backups are not", "no backup exists", "the backups failed"):
        assert claim not in text, f"overclaim {claim!r}"
    assert "could not" in text


def test_the_gap_finding_is_silent_on_a_readable_export():
    """THE NEGATIVE CONTROL. A coverage note that fires whether or not anything was
    actually unreadable is noise, and noise is what teaches a reader to skip the
    occasions it mattered."""
    data = {"backup_catalog": CLEAN_CATALOG, "recovery_tests": CLEAN_TESTS,
            "background_jobs": [{"JOBNAME": "ZBACKUP_DAILY", "STATUS": "S"}]}
    assert "RES-EVD-001" not in ids(run(data))


# --------------------------------------------------------------------------- #
#  Cited identifiers must exist                                               #
# --------------------------------------------------------------------------- #

def test_every_check_id_this_module_cites_actually_exists():
    """This module's non-duplication argument is made ENTIRELY in prose: each
    overlapping control is named, and the sibling module that owns it is named
    beside it. That argument is only checkable if the ids can be looked up.

    THE FAILURE THIS CATCHES, which had shipped: the LOG- -> RES- prefix
    correction was applied as a blanket rename and rewrote the prose along with
    the code, so the docstring cited RES-RET-001, RES-RET-002 and RES-IR-001 —
    three ids belonging to modules/log_monitoring.py that, under this module's own
    prefix, existed nowhere in the product. A reader checking whether RES-DR-001
    duplicated its sibling would have searched for a check that does not exist and
    had no way to tell whether the argument held.

    An id invented in a comment costs less than one invented in a finding, but the
    rule is the same rule, and this file's own docstring test exists because a
    comment the code does not support is worse than no comment.
    """
    import re

    module_path = ROOT / "modules" / "resilience_posture.py"
    cited = set(re.findall(r"\b[A-Z]{2,10}-[A-Z0-9]{2,8}-[0-9]{3}\b",
                           module_path.read_text(encoding="utf-8")))
    assert cited, "the id regex stopped matching; this test would pass vacuously"

    emitted = set()
    for path in (ROOT / "modules").glob("*.py"):
        emitted |= set(re.findall(r"""check_id\s*=\s*["']([^"']+)["']""",
                                  path.read_text(encoding="utf-8")))

    ghosts = sorted(cited - emitted)
    assert not ghosts, (
        f"cited but emitted by no module: {ghosts}. Either the id is wrong or the "
        "check it refers to does not exist; both make the argument uncheckable.")


# --------------------------------------------------------------------------- #
#  Absent and malformed input, over the new code paths                        #
# --------------------------------------------------------------------------- #

def test_empty_data_still_returns_nothing_and_does_not_raise():
    assert ResiliencePostureAuditor({}, {}).run_all_checks() == []


@pytest.mark.parametrize("key", ["backup_catalog", "recovery_tests"])
@pytest.mark.parametrize("junk", [None, "", [], {}, ["not a row"], [None], 42,
                                  {"records": None}])
def test_malformed_sources_do_not_crash_the_new_paths(key, junk):
    """Uploads arrive hand-edited, and a module that raises takes the other 26
    modules' results down with it for a customer who mangled one file."""
    run({key: junk})


def test_rows_with_no_columns_at_all_are_survivable():
    """A CSV that parsed into empty dicts. Every new code path here reads cells that
    are simply not there — the classification, the status vocabulary and the
    objective parser all have to degrade to "we could not tell"."""
    found = run({"backup_catalog": [{}], "recovery_tests": [{}],
                 "background_jobs": [{}]})
    assert "RES-EVD-001" in ids(found)
    assert not [f for f in found if f["severity"] in ("HIGH", "CRITICAL")], \
        "an empty export must not become a HIGH finding about the backups"
