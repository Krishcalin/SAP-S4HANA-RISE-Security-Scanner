"""
Resilience posture — what the checks must and must not claim.

THE FAILURE MODE THIS FILE GUARDS AGAINST
------------------------------------------
This module reports on the one control a customer will check by hand before
believing anything else in the report, because they know whether their backups
run. A false "you have no backups" on a system that backs up nightly is not one
wrong finding; it is the finding that decides the tool is not worth reading. So
every check here has a NEGATIVE CONTROL: a correct, complete resilience export
must produce ZERO findings, and the exit criterion at the bottom of this file
asserts exactly that over all eight checks at once.

The second failure mode is DOUBLE COUNTING. Four of these checks share input with
checks that already ship — `hana_db_security` owns HANA log_mode, `log_monitoring`
owns IR readiness, `basis_job_command` owns background jobs — and a duplicated
finding inflates the FAIR loss figure a board reads. The de-duplication tests here
are load-bearing, not tidiness.

The third is OVERCLAIMING. Nothing in this module tests a restore. There is a test
below that fails if a future edit starts writing as though it did.

DETERMINISM
-----------
Every dated fixture pins "today" through the `resilience_today` baseline override.
A recency test that reads the real clock passes today and fails in March, and a
test that rots gets deleted rather than fixed.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.resilience_posture import ResiliencePostureAuditor  # noqa: E402

MODULE_PATH = ROOT / "modules" / "resilience_posture.py"

#: Pinned "today" for every dated fixture below.
TODAY = "20260807"


def run(data, **overrides):
    ov = {"resilience_today": TODAY}
    ov.update(overrides)
    return ResiliencePostureAuditor(data, ov).run_all_checks()


def ids(findings):
    return sorted({f["check_id"] for f in findings})


# --------------------------------------------------------------------------- #
#  Fixtures: the shapes a real export takes                                   #
# --------------------------------------------------------------------------- #

def backup(kind, status, day, **extra):
    row = {"BACKUP_TYPE": kind, "STATUS": status, "START_TIME": day}
    row.update(extra)
    return row


def rec_test(kind, result, day, **extra):
    row = {"TEST_TYPE": kind, "RESULT": result, "DATE": day}
    row.update(extra)
    return row


#: A healthy estate. Full backup two days ago, log backups flowing, a restore and
#: a failover test inside the year, both passed, both inside their objectives.
HEALTHY_CATALOG = [
    backup("complete data backup", "successful", "2026-08-05"),
    backup("complete data backup", "successful", "2026-07-29"),
    backup("differential data backup", "successful", "2026-08-06"),
    backup("log backup", "successful", "2026-08-07"),
    backup("log backup", "successful", "2026-08-06"),
]

HEALTHY_TESTS = [
    rec_test("Point-in-time restore", "pass", "2026-05-14",
             RTO_TARGET="240", RTO_ACHIEVED="188",
             RPO_TARGET="60", RPO_ACHIEVED="15"),
    rec_test("DR failover", "pass", "2026-03-02",
             RTO_TARGET="480", RTO_ACHIEVED="410"),
]

HEALTHY_JOBS = [
    {"JOBNAME": "ZBACKUP_DAILY", "STATUS": "S"},
    {"JOBNAME": "ZARCHIVE_FI", "STATUS": "S"},
    {"JOBNAME": "JOB_FI_CLOSE", "STATUS": "F"},
]

HEALTHY = {
    "backup_catalog": HEALTHY_CATALOG,
    "recovery_tests": HEALTHY_TESTS,
    "background_jobs": HEALTHY_JOBS,
    "hana_parameters": [
        {"FILE_NAME": "global.ini", "SECTION": "persistence",
         "KEY": "log_mode", "VALUE": "normal"},
    ],
}


# --------------------------------------------------------------------------- #
#  THE EXIT CRITERION                                                         #
# --------------------------------------------------------------------------- #

def test_a_correct_resilience_posture_produces_nothing():
    """THE NEGATIVE CONTROL FOR THE WHOLE MODULE.

    Recent full backups, log backups flowing, a passed restore and a passed
    failover inside the year, objectives met, no aborted housekeeping. If this
    estate produces a finding, the module is reporting on correct configuration —
    and a customer who can see their own backups running will stop reading the
    report at that point, including the parts that are right.
    """
    found = run(HEALTHY)
    assert not found, \
        f"correct resilience evidence produced {[(f['check_id'], f['severity']) for f in found]}"


# --------------------------------------------------------------------------- #
#  Absent input — the hard requirement                                        #
# --------------------------------------------------------------------------- #

def test_empty_data_returns_nothing_and_does_not_raise():
    """Every export is optional. A module that raises on an absent key takes the
    whole scan down for a customer who simply did not send that file."""
    assert ResiliencePostureAuditor({}, {}).run_all_checks() == []


def test_every_source_absent_individually_is_survivable():
    """A partial upload is the normal case, not the exception."""
    for key in ("backup_catalog", "recovery_tests", "background_jobs",
                "hana_parameters"):
        data = {k: v for k, v in HEALTHY.items() if k != key}
        run(data)  # must not raise


@pytest.mark.parametrize("junk", [None, "", [], {}, ["a string, not a row"],
                                  [None], {"records": None}, 42])
def test_malformed_sources_do_not_crash(junk):
    """Uploads arrive hand-edited. A CSV that parsed to a list of strings, or a
    JSON envelope with a null inside, must degrade to 'no evidence' rather than
    to a stack trace that loses the other 26 modules' results too."""
    for key in ("backup_catalog", "recovery_tests", "background_jobs"):
        run({key: junk})


def test_no_backup_catalogue_means_no_backup_findings():
    """Absence of evidence is not evidence of absence. `server/coverage.py` already
    tells the customer the export was missing; inventing a HIGH finding from a file
    nobody sent would be this module accusing a customer of a defect we cannot see."""
    assert ids(run({"recovery_tests": HEALTHY_TESTS})) == []


# --------------------------------------------------------------------------- #
#  RES-BCK-001 — recovery point                                               #
# --------------------------------------------------------------------------- #

def test_a_stale_full_backup_is_reported():
    """The recovery point is the age of the last full backup. Six weeks of postings
    lost to a ransomware event is the difference this check exists to surface."""
    data = {"backup_catalog": [
        backup("complete data backup", "successful", "2026-06-20"),
        backup("log backup", "successful", "2026-08-07"),
    ]}
    assert "RES-BCK-001" in ids(run(data))


def test_a_recent_full_backup_is_not_reported():
    """The control. A two-day-old full backup is a working control and must be
    silent — including when older backups sit in the same catalogue."""
    assert "RES-BCK-001" not in ids(run(HEALTHY))


def test_incremental_backups_do_not_substitute_for_a_full_one():
    """A differential cannot be applied without the full backup it is based on, so a
    catalogue of nothing but differentials evidences no recovery point at all. If
    this ever passes silently, the check is counting the wrong rows."""
    data = {"backup_catalog": [
        backup("differential data backup", "successful", "2026-08-06"),
        backup("differential data backup", "successful", "2026-08-05"),
        backup("log backup", "successful", "2026-08-07"),
    ]}
    assert "RES-BCK-001" in ids(run(data))


def test_a_catalogue_of_only_failed_full_backups_is_reported():
    """Runs that all failed are not a recovery point; they are the absence of one."""
    data = {"backup_catalog": [
        backup("complete data backup", "failed", "2026-08-06"),
        backup("log backup", "successful", "2026-08-07"),
    ]}
    found = run(data)
    assert "RES-BCK-001" in ids(found)
    assert "RES-BCK-002" not in ids(found), \
        "a type with no success at all must be reported once, not by two checks"


def test_the_recency_threshold_is_configurable():
    """A weekly-full-backup shop is not defective; the default is a default."""
    data = {"backup_catalog": [
        backup("complete data backup", "successful", "2026-08-01"),
        backup("log backup", "successful", "2026-08-07"),
    ]}
    assert "RES-BCK-001" in ids(run(data, resilience_full_backup_max_age_days=3))
    assert "RES-BCK-001" not in ids(run(data, resilience_full_backup_max_age_days=30))


@pytest.mark.parametrize("spelling", ["COMPLETE_DATA_BACKUP", "complete-data-backup",
                                      "Full_Backup", "DATA_SNAPSHOT"])
def test_a_separator_convention_cannot_hide_a_working_full_backup(spelling):
    """A SQL download writes the documented value "complete data backup" as
    COMPLETE_DATA_BACKUP often enough to matter. Before the separator was
    normalised, that spelling fell into the unclassified bucket and a system whose
    full backup completed two days ago raised the module's loudest finding saying it
    had none — the exact false HIGH that makes a customer stop reading the report."""
    data = {"backup_catalog": [
        backup(spelling, "successful", "2026-08-06"),
        backup("log backup", "successful", "2026-08-07"),
    ], "recovery_tests": HEALTHY_TESTS}
    assert "RES-BCK-001" not in ids(run(data)), \
        f"{spelling!r} was not credited as a full data backup"


@pytest.mark.parametrize("spelling", ["log_backup", "LOG-BACKUP",
                                      "DIFFERENTIAL_DATA_BACKUP"])
def test_separator_normalisation_does_not_promote_a_non_full_backup(spelling):
    """The control for the normalisation above. It must only ever rescue a FULL
    backup spelling; if it also let a log or differential row satisfy the
    recovery-point check, it would have traded a false HIGH for a silent one, which
    is the worse trade."""
    data = {"backup_catalog": [
        backup(spelling, "successful", "2026-08-06"),
        backup("log backup", "successful", "2026-08-07"),
    ], "recovery_tests": HEALTHY_TESTS}
    assert "RES-BCK-001" in ids(run(data)), \
        f"{spelling!r} was credited as a full data backup"


@pytest.mark.parametrize("spelling", ["log backup (full)", "incremental snapshot"])
def test_a_two_token_type_never_resolves_to_full_data_backup(spelling):
    """Both of these carry a token from two classes. Resolving either toward "full
    data backup" would silently satisfy the recovery-point check on a system that
    has no full backup at all — the one misclassification that turns a HIGH finding
    into silence rather than into noise."""
    data = {"backup_catalog": [
        backup(spelling, "successful", "2026-08-06"),
        backup("log backup", "successful", "2026-08-07"),
    ], "recovery_tests": HEALTHY_TESTS}
    assert "RES-BCK-001" in ids(run(data)), \
        f"{spelling!r} was credited as a full data backup"


# --------------------------------------------------------------------------- #
#  RES-BCK-004 — say "I could not tell", never guess                          #
# --------------------------------------------------------------------------- #

def test_an_ambiguous_date_format_is_reported_as_unassessable_not_as_stale():
    """03/04/2026 is two dates nine months apart. Guessing wrong turns a healthy
    estate into a HIGH finding, so the parser refuses and the refusal is reported —
    visibly, at INFO — instead of silently becoming RES-BCK-001."""
    data = {"backup_catalog": [
        backup("complete data backup", "successful", "03/04/2026"),
        backup("log backup", "successful", "03/04/2026"),
    ]}
    found = run(data)
    assert "RES-BCK-004" in ids(found)
    assert "RES-BCK-001" not in ids(found), \
        "a parser limitation was reported as a missing backup"
    assert next(f for f in found if f["check_id"] == "RES-BCK-004")["severity"] == "INFO"


def test_unambiguous_formats_are_all_understood():
    """The control for the refusal above: rejecting slash dates must not also
    reject the formats SAP and ISO actually emit."""
    for day in ("2026-08-05", "20260805", "05.08.2026", "2026/08/05",
                "2026-08-05 03:15:22", "2026-08-05T03:15:22Z", "20260805031522"):
        data = {"backup_catalog": [
            backup("complete data backup", "successful", day),
            backup("log backup", "successful", day),
        ], "recovery_tests": HEALTHY_TESTS}
        assert ids(run(data)) == [], f"{day!r} was not understood"


# --------------------------------------------------------------------------- #
#  RES-BCK-003 — point-in-time recovery, and the HANA de-duplication          #
# --------------------------------------------------------------------------- #

def test_absent_log_backups_are_reported():
    """Without log backups the real RPO is the age of the last full backup, not the
    log-backup interval — usually a day of postings rather than an hour."""
    data = {"backup_catalog": [
        backup("complete data backup", "successful", "2026-08-06"),
    ]}
    assert "RES-BCK-003" in ids(run(data))


def test_log_mode_overwrite_leaves_the_finding_to_hana_db_security():
    """THE DE-DUPLICATION TEST. `hana_db_security` already reports
    global.ini [persistence] log_mode = overwrite, which is precisely why no log
    backups exist. Raising our own HIGH on top of theirs prices one defect twice and
    inflates the FAIR figure the board sees."""
    data = {
        "backup_catalog": [backup("complete data backup", "successful", "2026-08-06")],
        "hana_parameters": [
            {"FILE_NAME": "global.ini", "SECTION": "persistence",
             "KEY": "log_mode", "VALUE": "overwrite"},
        ],
    }
    assert "RES-BCK-003" not in ids(run(data))


def test_log_mode_normal_keeps_the_finding_ours():
    """The control for the suppression. If the guard silenced the check whenever a
    HANA export existed, the suppression would have quietly deleted the capability
    for every HANA customer — which is how a de-duplication becomes a coverage hole."""
    data = {
        "backup_catalog": [backup("complete data backup", "successful", "2026-08-06")],
        "hana_parameters": [
            {"FILE_NAME": "global.ini", "SECTION": "persistence",
             "KEY": "log_mode", "VALUE": "normal"},
        ],
    }
    assert "RES-BCK-003" in ids(run(data))


def test_a_log_mode_key_from_another_section_does_not_silence_the_check():
    """The guard is scoped to [persistence]. A same-named key elsewhere must not be
    able to switch off a HIGH finding."""
    data = {
        "backup_catalog": [backup("complete data backup", "successful", "2026-08-06")],
        "hana_parameters": [
            {"FILE_NAME": "global.ini", "SECTION": "some_other_section",
             "KEY": "log_mode", "VALUE": "overwrite"},
        ],
    }
    assert "RES-BCK-003" in ids(run(data))


def test_successful_log_backups_are_not_reported():
    """The control."""
    assert "RES-BCK-003" not in ids(run(HEALTHY))


# --------------------------------------------------------------------------- #
#  RES-BCK-002 — unreliable, not absent                                       #
# --------------------------------------------------------------------------- #

def test_repeated_failures_alongside_successes_are_reported():
    """A chain that fails intermittently leaves gaps discovered during a recovery.
    It is also what deliberate interference looks like from the catalogue."""
    data = {"backup_catalog": [
        backup("complete data backup", "successful", "2026-08-06"),
        backup("complete data backup", "failed", "2026-08-05"),
        backup("complete data backup", "failed", "2026-08-04"),
        backup("complete data backup", "failed", "2026-08-03"),
        backup("log backup", "successful", "2026-08-07"),
    ]}
    assert "RES-BCK-002" in ids(run(data))


def test_an_isolated_failure_is_not_reported():
    """THE NOISE CONTROL. One transient failure among many successes is normal
    operations. A rule that fires on it trains its reader to ignore the rule."""
    data = {"backup_catalog": [
        backup("complete data backup", "successful", "2026-08-06"),
        backup("complete data backup", "failed", "2026-08-05"),
        backup("complete data backup", "successful", "2026-08-04"),
        backup("log backup", "successful", "2026-08-07"),
    ]}
    assert "RES-BCK-002" not in ids(run(data))


def test_a_broken_backup_type_is_not_counted_by_two_checks():
    """DOUBLE-COUNT GUARD. A log-backup type with three failures and no success is
    already RES-BCK-003's finding. Reporting it as an unreliable chain as well
    would price one broken control twice in the FAIR roll-up."""
    data = {"backup_catalog": [
        backup("complete data backup", "successful", "2026-08-06"),
        backup("log backup", "failed", "2026-08-07"),
        backup("log backup", "failed", "2026-08-06"),
        backup("log backup", "failed", "2026-08-05"),
    ]}
    found = ids(run(data))
    assert "RES-BCK-003" in found
    assert "RES-BCK-002" not in found


# --------------------------------------------------------------------------- #
#  Status vocabulary — the substring traps                                    #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("status", ["successful", "Successful", "SUCCESS",
                                    "completed", "Complete", "finished",
                                    "completed successfully", "OK", "pass"])
def test_success_spellings_are_read_as_success(status):
    """One unrecognised success spelling turns a healthy catalogue into a HIGH
    finding, because the check then sees no successful backup at all."""
    data = {"backup_catalog": [
        backup("complete data backup", status, "2026-08-06"),
        backup("log backup", status, "2026-08-07"),
    ], "recovery_tests": HEALTHY_TESTS}
    assert ids(run(data)) == [], f"{status!r} was not read as a success"


@pytest.mark.parametrize("status", ["failed", "Failed", "canceled", "cancelled",
                                    "aborted", "terminated", "error",
                                    "unsuccessful", "incomplete", "not successful"])
def test_failure_spellings_are_read_as_failure(status):
    """The dangerous direction. "unsuccessful" and "incomplete" each CONTAIN their
    own opposite as a substring, and a naive success-first match reads both as a
    completed backup — reporting a system with no backups as fully protected."""
    data = {"backup_catalog": [
        backup("complete data backup", status, "2026-08-06"),
        backup("log backup", "successful", "2026-08-07"),
    ]}
    assert "RES-BCK-001" in ids(run(data)), f"{status!r} was not read as a failure"


@pytest.mark.parametrize("status", ["broken", "restored", "recovered", "abandoned",
                                    "bypassed"])
def test_words_that_merely_contain_a_verdict_are_not_a_verdict(status):
    """"broken" contains "ok"; "restored" and "recovered" contain "red";
    "abandoned" contains "done"; "bypassed" contains "passed". Each of those five
    substring matches inverts a verdict. An unrecognised status must classify as
    UNKNOWN — counting toward neither success nor failure — so the outcome here is
    the same as for a catalogue with no successful full backup, and never a silent
    pass."""
    data = {"backup_catalog": [
        backup("complete data backup", status, "2026-08-06"),
        backup("log backup", "successful", "2026-08-07"),
    ]}
    found = ids(run(data))
    assert "RES-BCK-001" in found, f"{status!r} was mis-read as a successful backup"
    assert "RES-BCK-002" not in found, f"{status!r} was mis-read as a failed backup"


# --------------------------------------------------------------------------- #
#  RES-DR-001 / 002 — the evidence a restore ever happened                    #
# --------------------------------------------------------------------------- #

def test_a_stale_restore_test_is_reported():
    """The gap `log_monitoring.RES-IR-001` cannot see: it asks whether a drill
    SCHEDULE is declared, and a declared annual test that last ran two years ago
    passes it."""
    data = {
        "backup_catalog": HEALTHY_CATALOG,
        "recovery_tests": [
            rec_test("Point-in-time restore", "pass", "2024-01-10"),
            rec_test("DR failover", "pass", "2026-03-02"),
        ],
    }
    found = run(data)
    assert "RES-DR-001" in ids(found)
    assert any("data restore" in item
               for item in next(f for f in found
                                if f["check_id"] == "RES-DR-001")["affected_items"])


def test_a_failed_restore_test_is_reported():
    """A test that ran and failed is worse than one that is merely overdue, and must
    not be credited as evidence just because it is recent."""
    data = {
        "backup_catalog": HEALTHY_CATALOG,
        "recovery_tests": [
            rec_test("Restore", "failed", "2026-07-01"),
            rec_test("DR failover", "pass", "2026-03-02"),
        ],
    }
    assert "RES-DR-001" in ids(run(data))


def test_a_partially_successful_restore_is_not_credited_as_a_pass():
    """A partial restore has not demonstrated recoverability. Reading it as a pass
    is the comfortable lie this module exists to avoid."""
    data = {
        "backup_catalog": HEALTHY_CATALOG,
        "recovery_tests": [
            rec_test("Restore", "partial", "2026-07-01"),
            rec_test("DR failover", "pass", "2026-03-02"),
        ],
    }
    assert "RES-DR-001" in ids(run(data))


def test_a_restore_test_does_not_substitute_for_a_failover_test():
    """They answer different questions — "can we get the data back" and "can we run
    somewhere else". A customer who has done one has not done the other."""
    data = {
        "backup_catalog": HEALTHY_CATALOG,
        "recovery_tests": [rec_test("Point-in-time restore", "pass", "2026-05-14")],
    }
    found = run(data)
    assert "RES-DR-001" in ids(found)
    assert any("DR / failover" in item
               for item in next(f for f in found
                                if f["check_id"] == "RES-DR-001")["affected_items"])


def test_recent_passing_tests_of_both_kinds_are_not_reported():
    """The control."""
    assert "RES-DR-001" not in ids(run(HEALTHY))


def test_missing_restore_evidence_beside_backup_evidence_is_informational():
    """You showed us backups and nothing about reading one back. Raised so it lands
    on the auditor's evidence checklist — but at INFO and worded as an evidence gap,
    because the customer may well test restores diligently and simply not have
    exported the file. Absence of evidence is not evidence of absence."""
    found = run({"backup_catalog": HEALTHY_CATALOG})
    hit = next(f for f in found if f["check_id"] == "RES-DR-002")
    assert hit["severity"] == "INFO"


def test_the_missing_restore_evidence_note_is_silent_when_evidence_is_supplied():
    assert "RES-DR-002" not in ids(run(HEALTHY))


def test_the_missing_restore_evidence_note_needs_something_to_pair_against():
    """It must not become a finding that fires on every scan of every system. With
    no backup evidence either, there is nothing to contrast and nothing to say."""
    assert "RES-DR-002" not in ids(run({"background_jobs": HEALTHY_JOBS}))


# --------------------------------------------------------------------------- #
#  RES-DR-003 — objectives                                                    #
# --------------------------------------------------------------------------- #

def test_a_missed_rto_is_reported():
    """The organisation's own published recovery time is not achievable on the
    evidence of its own test."""
    data = {
        "backup_catalog": HEALTHY_CATALOG,
        "recovery_tests": [
            rec_test("Point-in-time restore", "pass", "2026-05-14",
                     RTO_TARGET="240", RTO_ACHIEVED="905"),
            rec_test("DR failover", "pass", "2026-03-02"),
        ],
    }
    found = run(data)
    assert "RES-DR-003" in ids(found)
    assert "RTO" in next(f for f in found
                         if f["check_id"] == "RES-DR-003")["affected_items"][0]


def test_a_met_objective_is_not_reported():
    """The control — including the equality case, which is a met objective."""
    data = {
        "backup_catalog": HEALTHY_CATALOG,
        "recovery_tests": [
            rec_test("Restore", "pass", "2026-05-14",
                     RTO_TARGET="240", RTO_ACHIEVED="240",
                     RPO_TARGET="60", RPO_ACHIEVED="15"),
            rec_test("DR failover", "pass", "2026-03-02"),
        ],
    }
    assert "RES-DR-003" not in ids(run(data))


def test_a_target_with_nothing_measured_against_it_is_not_a_breach():
    """A stated objective and no measurement is an UNMEASURED control, not a
    breached one. Manufacturing a finding out of a missing column is how a tool
    teaches its user to stop trusting it."""
    data = {
        "backup_catalog": HEALTHY_CATALOG,
        "recovery_tests": [
            rec_test("Restore", "pass", "2026-05-14", RTO_TARGET="240"),
            rec_test("DR failover", "pass", "2026-03-02", RPO_TARGET="60"),
        ],
    }
    assert "RES-DR-003" not in ids(run(data))


# --------------------------------------------------------------------------- #
#  RES-JOB-001 — housekeeping that silently stopped                           #
# --------------------------------------------------------------------------- #

def test_an_aborted_backup_job_is_reported():
    """Housekeeping that silently stops is a slow-acting resilience failure: log
    areas fill and archive runs fall behind, and nobody notices until a recovery
    needs the output."""
    data = {"background_jobs": [{"JOBNAME": "ZBACKUP_DAILY", "STATUS": "A"}]}
    found = run(data)
    assert "RES-JOB-001" in ids(found)
    hit = next(f for f in found if f["check_id"] == "RES-JOB-001")
    assert hit["affected_objects"] == [{"type": "job", "name": "ZBACKUP_DAILY"}], \
        "the job must be the SAME graph node basis_job_command emits, keyed on " \
        "JOBNAME alone, or the two modules' findings cannot meet on one object"


@pytest.mark.parametrize("status", ["A", "aborted", "Cancelled", "terminated",
                                    "failed"])
def test_aborted_spellings_are_recognised(status):
    data = {"background_jobs": [{"JOBNAME": "ZARCHIVE_FI", "STATUS": status}]}
    assert "RES-JOB-001" in ids(run(data))


@pytest.mark.parametrize("status", ["S", "P", "Y", "R", "F", "Released",
                                    "Ready", "Finished", "Active"])
def test_healthy_job_statuses_are_not_reported(status):
    """THE NOISE CONTROL. "Released", "Ready" and "Finished" are the normal states
    of a working job. Any of them read as aborted would flood the report with the
    entire backup schedule."""
    data = {"background_jobs": [{"JOBNAME": "ZBACKUP_DAILY", "STATUS": status}]}
    assert "RES-JOB-001" not in ids(run(data))


def test_an_aborted_job_with_no_recovery_relevance_is_not_reported():
    """This is a resilience module, not a job monitor. An aborted FI posting job is
    somebody else's finding, and claiming it here would make the module a second,
    worse copy of SM37."""
    data = {"background_jobs": [{"JOBNAME": "JOB_FI_CLOSE", "STATUS": "A"}]}
    assert "RES-JOB-001" not in ids(run(data))


def test_the_name_heuristic_is_disclosed_in_the_finding():
    """Inferring a job's purpose from its NAME over-reports and under-reports, and a
    reader who is not told that will treat the list as an inventory of the backup
    chain. Saying so in the description is what makes the heuristic honest."""
    data = {"background_jobs": [{"JOBNAME": "ZBACKUP_DAILY", "STATUS": "A"}]}
    hit = next(f for f in run(data) if f["check_id"] == "RES-JOB-001")
    text = hit["description"].lower()
    assert "name" in text and ("over-report" in text or "infer" in text)


# --------------------------------------------------------------------------- #
#  Honesty guards                                                             #
# --------------------------------------------------------------------------- #

#: Phrasings that would assert we tested a recovery. We did not, and cannot: this
#: is an offline scanner over exported files. A report making this claim in writing
#: is worse for us than no report at all.
_OVERCLAIMS = (
    "we verified", "we tested", "we confirmed", "verified the restore",
    "tested the restore", "restore was verified", "recovery was verified",
    "proves", "guarantees", "guaranteed", "backups work", "recovery works",
)


def _all_text(findings):
    for f in findings:
        yield f["title"]
        yield f["description"]
        yield f["remediation"]
        for item in f["affected_items"]:
            yield item


def test_no_finding_claims_a_recovery_was_verified():
    """The claim this module must never make. It reads exported files; it does not
    connect to anything and it restores nothing. A finding implying otherwise would
    be dismantled in the first technical evaluation, and having written it down is
    the expensive part."""
    datasets = [
        {"backup_catalog": [backup("complete data backup", "failed", "2026-01-01")]},
        {"backup_catalog": HEALTHY_CATALOG,
         "recovery_tests": [rec_test("Restore", "failed", "2020-01-01",
                                     RTO_TARGET="10", RTO_ACHIEVED="900")]},
        {"background_jobs": [{"JOBNAME": "ZBACKUP_DAILY", "STATUS": "A"}]},
        {"backup_catalog": [backup("complete data backup", "successful",
                                   "03/04/2026")]},
    ]
    for data in datasets:
        for text in _all_text(run(data)):
            low = text.lower()
            for claim in _OVERCLAIMS:
                assert claim not in low, f"overclaim {claim!r} in: {text[:120]}"


def test_the_module_states_what_it_cannot_check():
    """Workflow-level resilience and backup immutability are asked for by the
    checklist this module answers and are NOT implemented, because no export we take
    carries the evidence. A future reader must find that written down rather than
    assume the axis is covered."""
    src = MODULE_PATH.read_text(encoding="utf-8")
    assert "Workflow-level resilience is NOT implemented" in src
    assert "immutability" in src


def test_the_module_imports_nothing_third_party():
    """modules/ is stdlib-only by charter. CI enforces it repository-wide; this
    catches it in one second instead of after a push."""
    allowed = set(sys.stdlib_module_names) | {"modules"}
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"), str(MODULE_PATH))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""] if not node.level else []
        else:
            continue
        for name in names:
            assert name.split(".")[0] in allowed, f"third-party import: {name}"


# --------------------------------------------------------------------------- #
#  Finding contract                                                           #
# --------------------------------------------------------------------------- #

def _every_finding():
    """One of each check, from the smallest data that triggers it."""
    out = []
    out += run({"backup_catalog": [
        backup("complete data backup", "failed", "2026-01-01"),
        backup("log backup", "failed", "2026-01-01"),
    ]})
    out += run({"backup_catalog": [
        backup("complete data backup", "successful", "2026-08-06"),
        backup("complete data backup", "failed", "2026-08-05"),
        backup("complete data backup", "failed", "2026-08-04"),
        backup("complete data backup", "failed", "2026-08-03"),
        backup("log backup", "successful", "2026-08-07"),
    ]})
    out += run({"backup_catalog": [
        backup("complete data backup", "successful", "03/04/2026")]})
    out += run({"backup_catalog": HEALTHY_CATALOG,
                "recovery_tests": [rec_test("Restore", "failed", "2020-01-01",
                                            RTO_TARGET="10", RTO_ACHIEVED="900")]})
    out += run({"background_jobs": [{"JOBNAME": "ZBACKUP_DAILY", "STATUS": "A"}]})
    return out


def test_all_eight_checks_are_reachable():
    """A check nobody can trigger is dead code that reads as coverage."""
    assert set(ids(_every_finding())) == {
        "RES-BCK-001", "RES-BCK-002", "RES-BCK-003", "RES-BCK-004",
        "RES-DR-001", "RES-DR-002", "RES-DR-003", "RES-JOB-001",
    }


def test_every_finding_honours_the_finding_contract():
    """A stray trailing comma turns a description into a tuple and the report
    renders the repr. The contract test catches that whole bug class."""
    for f in _every_finding():
        assert isinstance(f["check_id"], str) and f["check_id"]
        assert isinstance(f["title"], str) and f["title"]
        assert isinstance(f["description"], str) and f["description"]
        assert isinstance(f["remediation"], str) and f["remediation"]
        assert f["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        assert f["category"] == "Resilience & Recovery Readiness"
        assert isinstance(f["affected_items"], list)
        assert all(isinstance(i, str) for i in f["affected_items"])
        assert isinstance(f["references"], list) and f["references"]
        assert f.get("scope") in ("object", "aggregate")


def test_every_check_id_routes_to_an_owning_team():
    """A prefix table mis-matches silently, and work that routes to no team appears
    on nobody's list and is never done. This is why these ids are `LOG-` and not the
    better-reading `RESIL-`, which routes nowhere — see the module docstring."""
    from server.enrich import team_for
    orphans = sorted(c for c in ids(_every_finding()) if team_for(c) == "unassigned")
    assert not orphans, f"check ids routing nowhere: {orphans}"


def test_check_ids_follow_the_house_format():
    """MODULE-SUBAREA-NNN. A stray format is a check nobody will find again."""
    import re
    bad = [c for c in ids(_every_finding())
           if not re.fullmatch(r"[A-Z][A-Z0-9]*(-[A-Z0-9]+)+", c)]
    assert not bad, bad


def test_no_check_id_collides_with_a_shipped_module():
    """`check_id` is a foreign key into the remediation knowledge base, the
    compliance mapping and the attack-path templates. Two modules sharing one id
    means whichever fires last silently overwrites the other's catalogue row — the
    `BASELINE-011` defect. These ids share the LOG- family with log_monitoring, so
    the collision risk here is real rather than theoretical."""
    ours = set(ids(_every_finding()))
    import re
    theirs = set()
    for path in sorted((ROOT / "modules").glob("*.py")):
        if path.name == "resilience_posture.py":
            continue
        theirs |= set(re.findall(r'check_id\s*=\s*"([A-Z][A-Z0-9\-]+)"',
                                 path.read_text(encoding="utf-8")))
    clash = sorted(ours & theirs)
    assert not clash, f"check ids already used by another module: {clash}"


def test_findings_do_not_name_the_hana_parameter_that_another_module_owns():
    """`hana_db_security` emits the `parameter_name: log_mode` graph node. If we
    named it too, our check_id would attach to their defect's node and the console
    would show one parameter carrying two modules' findings for what is, on the
    log_mode path, one defect."""
    for f in _every_finding():
        for obj in f.get("affected_objects", []):
            assert obj.get("type") != "parameter_name", obj
