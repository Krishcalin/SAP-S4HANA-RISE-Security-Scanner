"""
Resilience & Ransomware-Readiness Posture
=========================================

WHAT THIS MODULE ACTUALLY CHECKS, AND THE WORDING THAT GOES WITH IT
-------------------------------------------------------------------
This is an OFFLINE scanner over exported configuration. **It cannot test a
restore, and it never claims to.** Every check here reads a FILE the customer
produced. What a file can carry is *evidence that a resilience control exists and
was exercised* — a backup catalogue row saying a backup completed, a test record
saying somebody restored something on a date and it passed. What no file can carry
is proof that the next recovery will work.

So a finding from this module means exactly one of:

  * the EVIDENCE of a recovery control is **absent** from what was supplied,
  * the evidence is **stale**,
  * the evidence records a **failure**, or
  * the evidence exists but is **not parseable enough to judge**.

It never means "your backups do not work", and it never means "your backups do
work". No finding, title, description, report section or sales claim derived from
this module may say or imply that a recovery was verified by us. That claim would
not survive the first technical evaluation, and having made it in writing is a far
more expensive outcome than losing the deal.

The honest pitch is the one the module is built around: an auditor asking "show me
that you can recover" wants the evidence chain, and this reports whether the
evidence chain exists. Published SAP audit checklists devote several items to this
axis — ransomware readiness, backup and restore SLAs, disaster-recovery testing,
workflow-level resilience — and EU DORA makes operational resilience a regulatory
obligation for financial services, so the
evidence question is the question that gets asked — not the restore itself, which
an auditor cannot perform either.

WHAT THIS MODULE DELIBERATELY DOES NOT CLAIM
---------------------------------------------
* **Workflow-level resilience is NOT implemented.** None of the exports we take
  carries workflow queue depth, stuck work items, dead-letter counts or retry
  configuration. A check built on the exports we do have would be a guess wearing a
  control's clothes, and this repository has shipped an invented identifier before.
  Left out on purpose; see `not_done` in the build report.
* **Backup immutability / air-gap / off-host copy is NOT checked.** It is the single
  most important ransomware-readiness control and a destination string in a
  catalogue cannot tell us whether the target is immutable, versioned, or merely a
  mount the same compromised host can encrypt. Reporting a guess here would be worse
  than reporting nothing, because it is precisely the control a customer would then
  stop looking at.
* **Restore SLA conformance** is only judged where the export states BOTH a target
  and an achieved figure (see RES-DR-003). A target with no measurement is not a
  breach, it is an unmeasured control, and saying otherwise would manufacture a
  finding out of a missing column.

WHAT THIS MODULE DOES NOT REPEAT
---------------------------------
Duplicated findings double-count in the FAIR figure, so every overlap below was
checked against the shipped module and deliberately left to its owner:

* `modules/hana_db_security.py` owns `global.ini [persistence] log_mode`
  (HANADB-PARAM-*), including the `overwrite` case that makes point-in-time
  recovery impossible. We read that parameter but never report on it — it is used
  ONLY as a guard, so that "no log backups were recorded" is raised by us when the
  configuration says log backups should exist, and is left entirely to
  hana_db_security when the configuration already explains their absence.
* `modules/crypto_posture.py` owns HANA data/log/backup ENCRYPTION (CRYPTO-HANA-*).
  That is the confidentiality of a backup; this module is about its existence.
* `modules/log_monitoring.py` owns log retention minimums and archiving
  (LOG-RET-001/002) and incident-response readiness (LOG-IR-001) — and LOG-IR-001
  already reports whether `incident_response.json` declares a `backupVerification`
  and a `drillSchedule`. **This module never reads `incident_response.json`.** The
  distinction that justifies RES-DR-001 existing alongside it: LOG-IR-001 asks
  whether a schedule is *declared*; RES-DR-001 asks whether a test actually *ran*,
  *when*, and whether it *passed*. A declared annual DR test that last ran in 2023
  passes LOG-IR-001 and fails RES-DR-001, and that gap is the whole point.
  (These three ids read `RES-` until 2026-08-08. They are the SIBLING's ids and
  they never carried this module's prefix — a blanket LOG-→RES- rename during the
  prefix correction rewrote the prose as well as the code, leaving three check ids
  cited here that exist nowhere in the product. Verified against
  `modules/log_monitoring.py`, which emits LOG-RET-001, LOG-RET-002 and
  LOG-IR-001. The citation is load-bearing — it is the whole non-duplication
  argument for RES-DR-001 — so an unfollowable one is worse than none.)
* `modules/basis_job_command.py` owns background-job privilege (JOBCMD-JOB-*). It
  reads TBTCO only to decide which jobs are *armed* and never reports a run
  OUTCOME. RES-JOB-001 reports outcome, and only for recovery-relevant jobs.
* `server/coverage.py` already tells the customer which exports were absent. This
  module therefore does not raise a finding merely because a file is missing — with
  one deliberate exception, RES-DR-002, whose reason is written at its call site.

WHY THE CHECK IDS ARE `RES-`  (decided 2026-08-07, corrected since)
--------------------------------------------------------------------
Two constraints, and the first attempt satisfied one by breaking the other.

An id must ROUTE. `server/enrich.py` `TEAM_BY_PREFIX` picks the owning team by
prefix and returns "unassigned" for a prefix it has no entry for — work that lands
on no team's worklist and is never done, the exact failure `tests/test_enrich.py`
was written for. `RESIL-` reads better than anything here and routes nowhere.

An id must also PRICE correctly. These ids were originally `LOG-`, which did route
(to `data_protection`) and which `modules/fair_adapter.py:_is_detection()` — a
check-id PREFIX match — therefore priced as a detection gap. A backup that is not
running is not a detection gap. The prefix chosen to solve routing had silently
created a valuation defect, which is why nothing here picks a prefix for its side
effects any more.

`RES-` now has its own `TEAM_BY_PREFIX` entry and routes to `basis`, the team that
operates the backup schedule.

WHAT IS STILL NOT MODELLED: `data/fair_scenarios.json` declares no recovery loss
scenario and no route for `RES-`, so `_route` returns None for these findings and
they fall through to the conservative access-control fallback. They therefore do
NOT price the availability loss of an unrecoverable outage. That under-prices
rather than over-prices, which is the safe direction, and it is a gap in the FAIR
model rather than in these ids.

TUNING  (all via baseline overrides; the defaults are defaults, not doctrine)
-----------------------------------------------------------------------------
  resilience_today                          pin "today"; see DETERMINISM below
  resilience_full_backup_max_age_days   7   RES-BCK-001 recovery-point window
  resilience_recovery_test_max_age_days 365 RES-DR-001 test recency
  resilience_backup_failure_threshold   3   RES-BCK-002 minimum failure COUNT
  resilience_backup_failure_ratio       0.10 RES-BCK-002 minimum failure SHARE
  resilience_backup_failure_window_days 30  RES-BCK-002 window; see the check

Data sources
------------
Two of these are NEW optional keys that `modules/data_loader.py` does not yet
register (another agent is in that file). Until they are registered they simply
load as absent and this module returns [] for them, which is the correct behaviour
for an export nobody supplied. Column names are matched case-insensitively and
several spellings are accepted, because these arrive as ALV/SQL downloads whose
headers depend on the layout the customer used.

  - backup_catalog   (NEW, optional)  one row per backup RUN. Suggested filename
                     `backup_catalog.csv`. Columns:
                       BACKUP_TYPE | ENTRY_TYPE_NAME | TYPE     — e.g. "complete data
                            backup", "log backup", "differential data backup",
                            "data snapshot"
                       STATUS | STATE_NAME | STATE | RESULT     — e.g. "successful",
                            "failed", "canceled", "running"
                       START_TIME | SYS_START_TIME | UTC_START_TIME | DATE | TIMESTAMP
                       DESTINATION_TYPE | DESTINATION_TYPE_NAME  (optional, recorded
                            as evidence only — see the immutability caveat above)
                       SYSTEM | SID                              (optional, display only)

  - recovery_tests   (NEW, optional)  one row per restore / failover / DR exercise.
                     Suggested filename `recovery_tests.csv`. Columns:
                       TEST_TYPE | TYPE | SCENARIO   — e.g. "restore", "point-in-time
                            restore", "failover", "dr", "tabletop"
                       DATE | TEST_DATE | LAST_TESTED | PERFORMED_ON
                       RESULT | STATUS | OUTCOME     — e.g. "pass", "fail", "partial"
                       RTO_TARGET | RTO_ACHIEVED     (optional, minutes)
                       RPO_TARGET | RPO_ACHIEVED     (optional, minutes)
                       SYSTEM | SID                  (optional, display only)
                       EVIDENCE | REFERENCE          (optional, a ticket/doc pointer)

  - background_jobs  (existing, TBTCO) — JOBNAME, STATUS. Read ONLY to report
                     recovery-relevant jobs the export records as aborted.
  - hana_parameters  (existing, M_INIFILE_CONTENTS) — `[persistence] log_mode`, read
                     ONLY as the guard described above. Never reported on.

DETERMINISM
-----------
Recency is measured against today, which makes a naive test rot on a particular
calendar day and then get deleted for being flaky. "Today" is therefore overridable
through the baseline overrides as `resilience_today` (YYYYMMDD), which is how the
tests pin it.
"""
from __future__ import annotations

from datetime import date, datetime
from typing import Any, Dict, List, Optional, Tuple

from modules.base_auditor import BaseAuditor


# --------------------------------------------------------------------------- #
#  Parsing helpers                                                            #
# --------------------------------------------------------------------------- #

#: Date formats we accept. Every one of them is UNAMBIGUOUS.
#:
#: `%m/%d/%Y` and `%d/%m/%Y` are deliberately absent: "03/04/2026" is two dates
#: nine months apart depending on who exported it, and a recency check that guesses
#: wrong by nine months is worse than one that says "I could not tell". A catalogue
#: written entirely in a slash format therefore lands in RES-BCK-004 — visible — and
#: not in a silently wrong RES-BCK-001.
_DATE_FORMATS = ("%Y-%m-%d", "%d.%m.%Y", "%Y/%m/%d")


def _parse_day(raw: Any) -> Optional[date]:
    """Best-effort date from an export cell. ``None`` means "we could not tell"."""
    if raw is None:
        return None
    s = str(raw).strip()
    if not s:
        return None
    # A timestamp is a date plus noise; keep the date part.
    s = s.replace("T", " ").split(" ")[0].strip()
    if not s:
        return None

    digits = "".join(c for c in s if c.isdigit())
    # 8 digits is SAP's YYYYMMDD; 14 is YYYYMMDDHHMMSS with the separators stripped.
    # Only treat a bare digit run as a date — "2026-08-01" also has 8 digits but must
    # go through strptime so an impossible day is rejected rather than reinterpreted.
    if s.isdigit() and len(digits) in (8, 14):
        try:
            return datetime.strptime(digits[:8], "%Y%m%d").date()
        except ValueError:
            return None

    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(s, fmt).date()
        except ValueError:
            continue
    return None


#: Unit suffixes accepted on an RTO/RPO cell. The columns are documented as
#: MINUTES, so an empty suffix means minutes and these spellings restate it.
#:
#: No hour, second or day suffix is here, and that is a decision rather than an
#: omission: converting "4 h" to 240 requires believing both that the customer meant
#: hours and that the number is in the unit they wrote rather than in the documented
#: one. Refusing costs a finding, which is the safe direction; guessing produces a
#: 60x error inside a comparison whose whole output is "your objective was missed by
#: this much", and the refusal is now disclosed as coverage (RES-EVD-001) where the
#: silent guess never was.
_MINUTE_UNITS = frozenset({"", "min", "min.", "mins", "minute", "minutes"})


def _minutes(raw: Any) -> Optional[float]:
    """An RTO/RPO cell as a number of MINUTES. ``None`` means "we could not read it".

    Strict for the same reason `_parse_day` rejects slash dates. The two readings the
    old parser guessed at were each off by orders of magnitude:

      * "1,234"    — a thousands separator under one convention and a decimal comma
                     under another, i.e. 1234 or 1.234. Any cell containing a comma
                     is refused rather than resolved by assuming a locale.
      * "4 hours"  — the old parser kept the leading digits, dropped the suffix it
                     did not recognise and returned 4 minutes, so a test that took
                     four hours against a 240-minute objective was recorded as having
                     met it comfortably.

    A refusal is not silence: the caller records the unreadable cell so it is
    reported as a gap in the export instead of vanishing into "no measurement".
    """
    if raw is None:
        return None
    s = str(raw).strip()
    if not s or "," in s:
        return None

    idx = 0
    if s[idx] in "+-":
        idx += 1
    digits_start = idx
    seen_dot = False
    while idx < len(s):
        ch = s[idx]
        if ch.isdigit():
            idx += 1
        elif ch == "." and not seen_dot:
            seen_dot = True
            idx += 1
        else:
            break
    # A leading "." counts as part of the number, so ".5" parses; a cell with no
    # digit at all ("N/A", "not measured") has nothing to read and is refused.
    if not any(c.isdigit() for c in s[digits_start:idx]):
        return None
    if s[idx:].strip().lower() not in _MINUTE_UNITS:
        return None
    try:
        return float(s[:idx])
    except ValueError:
        return None


class ResiliencePostureAuditor(BaseAuditor):
    """Evidence-of-recoverability posture. Reads exports; never tests a restore."""

    CATEGORY = "Resilience & Recovery Readiness"

    # ── column vocabularies ──────────────────────────────────────────────────
    # These are ACCEPTED SPELLINGS, not a schema we assert. The first name in each
    # tuple is the one this module documents and asks for; the rest are convenience
    # aliases for exports produced by other means.
    #
    # UNVERIFIED: `ENTRY_TYPE_NAME`, `STATE_NAME`, `SYS_START_TIME`, `UTC_START_TIME`
    # and `DESTINATION_TYPE_NAME` are believed to be HANA backup-catalogue column
    # names but have not been confirmed against SAP's documentation here. They cost
    # nothing to be wrong about — an alias that matches no column simply never fires,
    # and the documented name still works — which is why they are listed as aliases
    # rather than named in any finding, description or remediation.
    BACKUP_TYPE_KEYS = ("BACKUP_TYPE", "ENTRY_TYPE_NAME", "ENTRY_TYPE", "TYPE",
                        "BACKUP_KIND", "KIND")
    BACKUP_STATUS_KEYS = ("STATUS", "STATE_NAME", "STATE", "RESULT", "OUTCOME")
    BACKUP_TIME_KEYS = ("START_TIME", "SYS_START_TIME", "UTC_START_TIME", "DATE",
                        "BACKUP_DATE", "TIMESTAMP", "END_TIME", "SYS_END_TIME")
    BACKUP_DEST_KEYS = ("DESTINATION_TYPE", "DESTINATION_TYPE_NAME", "DESTINATION",
                        "TARGET")
    SYSTEM_KEYS = ("SYSTEM", "SID", "SYSTEM_ID", "DATABASE", "TENANT")

    TEST_TYPE_KEYS = ("TEST_TYPE", "TYPE", "SCENARIO", "EXERCISE", "TEST")
    TEST_DATE_KEYS = ("DATE", "TEST_DATE", "LAST_TESTED", "PERFORMED_ON",
                      "EXECUTED_ON", "TIMESTAMP")
    TEST_RESULT_KEYS = ("RESULT", "STATUS", "OUTCOME")
    TEST_EVIDENCE_KEYS = ("EVIDENCE", "REFERENCE", "TICKET", "DOCUMENT", "LINK")

    # ── vocabulary classification ────────────────────────────────────────────
    # Substring tests on a lower-cased cell, not equality. These exports are ALV
    # downloads and a customer's "Complete Data Backup" must classify the same as
    # HANA's "complete data backup" and a hand-rolled "FULL".
    _DATA_BACKUP_TOKENS = ("complete data", "full data", "complete backup",
                           "full backup", "data snapshot", "snapshot", "full")
    _INCREMENTAL_TOKENS = ("differential", "incremental", "delta")
    _LOG_BACKUP_TOKENS = ("log backup", "log_backup", "logbackup", "redo log",
                          "transaction log", "archive log")

    # SUBSTRING vs EXACT is not stylistic here — it is the difference between a
    # correct classification and an inverted one. Measured against the spellings
    # these exports actually use:
    #   "ok"       is a substring of "broken"
    #   "red"      is a substring of "restored" and of "recovered"
    #   "done"     is a substring of "abandoned"
    #   "passed"   is a substring of "bypassed"
    #   "complete" is a substring of "incomplete"
    # Every one of those five reads a FAILURE as a SUCCESS or the reverse, which is
    # the one error this module must not make. So short or swallowable words are
    # matched on the WHOLE cell, and only words that cannot be embedded in their own
    # negation are matched as substrings.
    _SUCCESS_EXACT = frozenset({"ok", "green", "pass", "passed", "done", "success",
                                "successful", "complete", "completed", "finished"})
    _SUCCESS_SUBSTRINGS = ("success",)          # "completed successfully"
    # "canceled"/"cancelled" both contain "cancel"; "aborted" contains "abort";
    # "terminat" catches terminated/termination. Checked BEFORE success, so
    # "unsuccessful" and "incomplete" cannot be read as their own opposites.
    _FAILURE_SUBSTRINGS = ("fail", "error", "abort", "cancel", "terminat",
                           "unsuccessful", "incomplete")
    # A bare "N" is NOT here. Single-character cells are status CODES in SAP
    # exports, and reading an unknown one-letter code as a failure would invent
    # findings out of a vocabulary we have not seen.
    _FAILURE_EXACT = frozenset({"red", "amber", "ko", "nok", "no"})
    _RUNNING_SUBSTRINGS = ("running", "in progress", "in_progress")
    _RUNNING_EXACT = frozenset({"active", "started"})

    # A restore test answers "can we get the data back"; a continuity test answers
    # "can we run somewhere else". They are separately evidenced and a customer who
    # has done one has not done the other, so they are tracked as two members of one
    # finding rather than being allowed to substitute for each other.
    #
    # THE TWO SUBSTRING COLLISIONS THAT MADE ONE SUBSTITUTE FOR THE OTHER, both of
    # which SILENCED a category rather than adding noise — the dangerous direction:
    #
    #   "Disaster Recovery test"  contains "recover", so a pure continuity exercise
    #        was credited as a data restore and RES-DR-001 went quiet about the
    #        restore category on a customer who had never restored anything.
    #   "Restore drill"           contains " dr", so a pure restore exercise was
    #        credited as a DR test and the failover category went quiet.
    #
    # Both are fixed by matching against a NORMALISED form (see `_normalise_type`)
    # instead of against the raw cell: `dr` and `bcp` are matched as whole WORDS, so
    # "drill" cannot supply them, and the compound names are matched against the
    # separator-free form so "fail-over", "fail over" and "failover" are one token.
    _CONTINUITY_COMPOUNDS = ("failover", "switchover", "disaster", "tabletop",
                             "continuity")
    _CONTINUITY_WORDS = frozenset({"dr", "bcp"})
    # Unambiguous: none of these appears in a continuity exercise's usual name.
    _RESTORE_COMPOUNDS = ("restore", "pitr", "pointintime")
    # "recover" is WEAK — "disaster recovery" is the phrase that broke this — so it
    # credits a data restore only when nothing marks the record as a continuity
    # exercise. A record naming both ("point-in-time recovery after failover") is
    # still credited to both, because a strong restore token carries it.
    _RESTORE_WEAK_COMPOUNDS = ("recover",)

    #: Job-NAME tokens that suggest a recovery-relevant job.
    #:
    #: This is a HEURISTIC and is described as one in the finding. TBTCO carries no
    #: purpose classification — there is no column that says "this job is part of the
    #: backup chain" — so the only signal available offline is what the customer
    #: named the job. Matching on the name over-reports a job called ZARCHIVE_SALES
    #: and misses one called ZJOB_0042, and both directions are stated in the
    #: description so nobody reads the finding as an inventory.
    RECOVERY_JOB_TOKENS = ("BACKUP", "ARCHIV", "RECOVER", "RESTORE", "REPLICAT",
                           "FAILOVER")

    #: UNVERIFIED: TBTCO-STATUS 'A' is taken to be the aborted/cancelled state. It is
    #: the complement of the armed set {P,S,Y,R} that `modules/basis_job_command.py`
    #: already relies on, and of 'F' (finished), which is the reasoning — not a
    #: citation. Nobody here has confirmed the code against SAP's own documentation,
    #: so it is marked rather than presented as fact.
    #:
    #: The cost of being wrong is bounded on purpose: textual spellings are accepted
    #: alongside the code, so an export that renders the status as text ("Cancelled")
    #: is classified without depending on this assumption at all, and a wrong code
    #: assumption loses a finding rather than inventing one.
    _ABORTED_STATUS_CODES = ("A",)

    # ── kind labels, used in display and as member keys ──────────────────────
    KIND_DATA = "full data backup"
    KIND_INCREMENTAL = "incremental / differential data backup"
    KIND_LOG = "log backup"
    KIND_OTHER = "other backup type"

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self._today = self._resolve_today()
        self._runs = self._backup_runs()
        self._tests = self._recovery_tests()
        #: Kinds already reported by RES-BCK-001/003 as having no usable success.
        #: RES-BCK-002 excludes them so one broken backup type is one finding, not
        #: two — a double count is a real defect here, it inflates the FAIR figure.
        self._reported_kinds: set = set()
        #: Things this scan could not READ, as opposed to things it read and judged.
        #: Collected here and reported once by `check_evidence_not_assessable`.
        self._gaps: List[str] = []
        self._gap_details: Dict[str, Any] = {}

        if self._runs and not self._any_outcome_readable():
            # NOT the same as "the backups failed", and it must not produce the same
            # output. Every backup check below decides on the presence or absence of
            # a recorded SUCCESS, so a catalogue whose entire status vocabulary is
            # unknown to us yields two HIGH findings — "no full backup", "no log
            # backup" — from nothing but a spelling gap. That is the single most
            # damaging thing this module can do, so we decline to judge and say why.
            statuses = sorted({r["raw_status"] for r in self._runs
                               if r["raw_status"]})
            self._gap(
                f"backup catalogue: none of the {len(self._runs)} run(s) carries a "
                "status this scanner recognises as a success or a failure "
                + (f"({', '.join(repr(s) for s in statuses[:5])})" if statuses
                   else "(the status column is blank throughout)")
                + ", so no verdict about the backups was reached — this is not a "
                "finding that the backups failed",
                unrecognised_backup_statuses=statuses[:20] or ["(all blank)"],
                backup_runs_supplied=len(self._runs),
            )
        else:
            self.check_data_backup_evidence()
            self.check_log_backup_evidence()
            self.check_backup_failure_rate()

        self.check_recovery_test_evidence()
        self.check_recovery_test_absent()
        self.check_recovery_objectives()
        self.check_recovery_relevant_jobs()
        self.check_evidence_not_assessable()
        return self.findings

    def _any_outcome_readable(self) -> bool:
        """Did ANY catalogue row carry a status we could classify?

        One readable row is enough. A partly-unknown vocabulary still supports a
        verdict — a recorded success is a recorded success whatever sits beside it —
        and suppressing on any unknown at all would let one odd row switch off the
        module's loudest checks.
        """
        return any(r["outcome"] != "unknown" for r in self._runs)

    def _gap(self, text: str, **details: Any) -> None:
        """Record something the scan could not read. See `check_evidence_not_assessable`."""
        self._gaps.append(text)
        self._gap_details.update(details)

    # ------------------------------------------------------------------ input
    @staticmethod
    def _rows(value: Any) -> List[Dict[str, Any]]:
        """Rows from a CSV-shaped or JSON-shaped source; [] for anything else.

        A JSON export may wrap its list in an envelope, and an absent export is
        ``None``. Both must come out as an empty list rather than an exception:
        `run_all_checks()` on empty data returning [] is a hard requirement, and a
        module that crashes on a malformed upload takes the whole scan down with it.
        """
        if isinstance(value, dict):
            for key in ("records", "runs", "tests", "entries", "policies", "items"):
                inner = value.get(key)
                if isinstance(inner, list):
                    value = inner
                    break
            else:
                return []
        if not isinstance(value, list):
            return []
        return [r for r in value if isinstance(r, dict)]

    @staticmethod
    def _cell(row: Dict[str, Any], *names: str) -> str:
        lowered = {str(k).strip().lower(): v for k, v in row.items()}
        for name in names:
            value = lowered.get(name.lower())
            if value not in (None, ""):
                return str(value).strip()
        return ""

    def _resolve_today(self) -> date:
        """Today, or the pinned override. See DETERMINISM in the module docstring."""
        pinned = self.get_config("resilience_today", None)
        parsed = _parse_day(pinned) if pinned else None
        return parsed or date.today()

    def _age_days(self, when: Optional[date]) -> Optional[int]:
        if when is None:
            return None
        return (self._today - when).days

    # ------------------------------------------------------- backup catalogue
    def _classify_kind(self, raw: str) -> str:
        text = (raw or "").strip().lower()
        # Separators are normalised to spaces BEFORE token matching. Measured: the
        # module's own documented value "complete data backup" arrives from a SQL
        # download as "COMPLETE_DATA_BACKUP" often enough to matter, and without this
        # it classifies as KIND_OTHER — which means a system with a successful full
        # backup two days ago raises RES-BCK-001 at HIGH saying it has none. A
        # separator convention must never be able to turn a working control into the
        # module's loudest finding. Safe in the other direction because the LOG and
        # INCREMENTAL tests run first and neither gains a match from this.
        text = text.replace("_", " ").replace("-", " ")
        # Order matters wherever a spelling carries two tokens, and both orderings
        # that matter resolve AWAY from "this is a full backup" — the classification
        # that, if wrong, silently satisfies RES-BCK-001 on a system that has no
        # full backup:
        #   "log backup (full)"      -> log backup, not a full data backup
        #   "incremental snapshot"   -> incremental, not a full data backup
        if any(t in text for t in self._LOG_BACKUP_TOKENS):
            return self.KIND_LOG
        if any(t in text for t in self._INCREMENTAL_TOKENS):
            return self.KIND_INCREMENTAL
        if any(t in text for t in self._DATA_BACKUP_TOKENS):
            return self.KIND_DATA
        return self.KIND_OTHER

    def _is_failure_text(self, text: str) -> bool:
        return (text in self._FAILURE_EXACT
                or text.startswith("not ")
                or any(t in text for t in self._FAILURE_SUBSTRINGS))

    def _classify_outcome(self, raw: str) -> str:
        """success / failed / running / unknown.

        `unknown` is a real answer and not a shrug: a status spelling we have not
        seen is not COUNTED as a successful backup and is not COUNTED as a failed
        one, so it never inflates the failure rate RES-BCK-002 measures.

        It is NOT neutral, and an earlier version of this docstring claiming it
        "contributes to neither side of any check" was false. RES-BCK-001 and
        RES-BCK-003 fire on the ABSENCE of a recorded success, so a run we cannot
        classify pushes them toward firing exactly as a failed run would. That
        asymmetry is deliberate — reading an unrecognised spelling as a success
        would report a system with no backups as protected — but it means the
        vocabulary gap has to be handled somewhere, and it is: `run_all_checks`
        refuses to judge a catalogue in which NOTHING is readable, and discloses it
        as RES-EVD-001 rather than emitting two HIGH findings about a spelling.
        """
        text = (raw or "").strip().lower()
        if not text:
            return "unknown"
        # Failure first: "not successful", "unsuccessful" and "incomplete" all
        # contain their own opposite, and reading one as a success is the dangerous
        # direction to be wrong in.
        if self._is_failure_text(text):
            return "failed"
        if text in self._RUNNING_EXACT or any(t in text
                                              for t in self._RUNNING_SUBSTRINGS):
            return "running"
        if text in self._SUCCESS_EXACT or any(t in text
                                              for t in self._SUCCESS_SUBSTRINGS):
            return "success"
        return "unknown"

    def _backup_runs(self) -> List[Dict[str, Any]]:
        runs = []
        for row in self._rows(self.data.get("backup_catalog")):
            raw_type = self._cell(row, *self.BACKUP_TYPE_KEYS)
            raw_status = self._cell(row, *self.BACKUP_STATUS_KEYS)
            runs.append({
                "kind": self._classify_kind(raw_type),
                "raw_type": raw_type,
                # Kept so an unreadable vocabulary can be QUOTED back to the customer.
                # "we could not read your statuses" is an instruction to go looking;
                # "we could not read 'Beendet' or 'Abgebrochen'" is a fix.
                "raw_status": raw_status,
                "outcome": self._classify_outcome(raw_status),
                "day": _parse_day(self._cell(row, *self.BACKUP_TIME_KEYS)),
                "destination": self._cell(row, *self.BACKUP_DEST_KEYS),
                "system": self._cell(row, *self.SYSTEM_KEYS),
            })
        return runs

    def _kind_summary(self, kind: str) -> Dict[str, Any]:
        rows = [r for r in self._runs if r["kind"] == kind]
        successes = [r for r in rows if r["outcome"] == "success"]
        dated = [r["day"] for r in successes if r["day"] is not None]
        return {
            "runs": len(rows),
            "successes": len(successes),
            "failures": len([r for r in rows if r["outcome"] == "failed"]),
            # Runs of this type whose status we could not classify. Reported in the
            # details of the checks that fire on the absence of a success, so a
            # reader can see how much of the verdict rested on unreadable rows.
            "unknown": len([r for r in rows if r["outcome"] == "unknown"]),
            "dated_successes": len(dated),
            "newest_success": max(dated) if dated else None,
        }

    def _failure_profile(self, kind: str) -> Dict[str, Any]:
        """How one backup type is behaving over its RECENT operation.

        WHY A WINDOW ANCHORED ON THE DATA AND NOT ON TODAY. The question is whether
        this backup type is failing repeatedly, and "recently" for a backup type is
        defined by its own record rather than by the calendar. Anchoring on the
        newest run OF THIS TYPE means the verdict does not change because an export
        was taken a month late, and it keeps a type that runs weekly comparable with
        one that runs hourly. It also means a catalogue that simply stops is judged
        on the last operation it recorded, which is the only evidence there is.

        A type with no readable date anywhere falls back to the whole catalogue. It
        is measured with the SAME count-and-share rule, so the fallback cannot fire
        on a shape the windowed path would clear; the basis is stated in the finding
        so nobody reads a lifetime figure as a recent one.
        """
        rows = [r for r in self._runs if r["kind"] == kind]
        dated = [r for r in rows if r["day"] is not None]
        window_days = int(self.get_config("resilience_backup_failure_window_days", 30))

        if dated:
            anchor = max(r["day"] for r in dated)
            considered = [r for r in dated
                          if (anchor - r["day"]).days <= window_days]
            basis = (f"the {window_days} day(s) of catalogue up to "
                     f"{anchor.isoformat()}")
        else:
            anchor = None
            considered = rows
            basis = ("the whole catalogue, because no run of this type carries a "
                     "date this scanner can read")

        failures = len([r for r in considered if r["outcome"] == "failed"])
        return {
            "considered": len(considered),
            "failures": failures,
            "share": (failures / len(considered)) if considered else 0.0,
            # Undated rows cannot be placed in the window, so they are left out of
            # the measurement rather than being assumed recent or assumed old. The
            # count is surfaced separately from rows that were simply older than the
            # window: a share computed over half the rows because the rest were
            # unreadable is a different claim from one computed over a clean window.
            "undated_excluded": len(rows) - len(dated) if dated else 0,
            "outside_window": len(dated) - len(considered) if dated else 0,
            "anchor": anchor,
            "basis": basis,
        }

    # ------------------------------------------------------- recovery tests
    @staticmethod
    def _normalise_type(raw: str) -> Tuple[str, set]:
        """``("pointintimerestore", {"point", "in", "time", "restore"})``.

        Two forms because two kinds of token need two kinds of match. A compound
        name arrives spelled three ways ("failover", "fail-over", "fail over") and
        is matched against the separator-free form; a short acronym must be matched
        as a WHOLE WORD or "dr" finds itself inside "drill" and credits a restore
        exercise as a disaster-recovery one.
        """
        spaced = "".join(ch if ch.isalnum() else " " for ch in (raw or "").lower())
        words = set(spaced.split())
        return "".join(spaced.split()), words

    def _classify_test(self, raw_type: str) -> List[str]:
        squashed, words = self._normalise_type(raw_type)
        continuity = (any(t in squashed for t in self._CONTINUITY_COMPOUNDS)
                      or bool(words & self._CONTINUITY_WORDS))
        restore = any(t in squashed for t in self._RESTORE_COMPOUNDS)
        if not restore and not continuity:
            # Only where nothing marks the record as a continuity exercise, because
            # "disaster recovery" contains the weak token and would otherwise be
            # credited as a data restore — silencing the restore half of RES-DR-001
            # on a customer who has never restored anything.
            restore = any(t in squashed for t in self._RESTORE_WEAK_COMPOUNDS)

        classes = []
        if restore:
            classes.append("data restore")
        if continuity:
            classes.append("DR / failover")
        return classes

    def _objective(self, row: Dict[str, Any], *names: str) -> Tuple[Optional[float], str]:
        """``(minutes, unreadable_text)``.

        The two failures a single ``Optional[float]`` cannot tell apart: a column
        the customer did not fill in, and one they DID fill in with something this
        scanner will not guess at. The first is an unmeasured control and correctly
        produces nothing; the second is a gap in the export and has to be said out
        loud, or "we could not read your number" is delivered as "you took no
        measurement".
        """
        raw = self._cell(row, *names)
        if not raw:
            return None, ""
        value = _minutes(raw)
        return value, ("" if value is not None else f"{names[0]}={raw!r}")

    def _recovery_tests(self) -> List[Dict[str, Any]]:
        out = []
        for row in self._rows(self.data.get("recovery_tests")):
            raw_type = self._cell(row, *self.TEST_TYPE_KEYS)
            objectives = {
                "rto_target": self._objective(row, "RTO_TARGET",
                                              "RTO_TARGET_MINUTES", "RTO"),
                "rto_achieved": self._objective(row, "RTO_ACHIEVED",
                                                "RTO_ACHIEVED_MINUTES", "RTO_ACTUAL"),
                "rpo_target": self._objective(row, "RPO_TARGET",
                                              "RPO_TARGET_MINUTES", "RPO"),
                "rpo_achieved": self._objective(row, "RPO_ACHIEVED",
                                                "RPO_ACHIEVED_MINUTES", "RPO_ACTUAL"),
            }
            entry = {
                "raw_type": raw_type,
                "classes": self._classify_test(raw_type),
                "result": self._classify_test_result(
                    self._cell(row, *self.TEST_RESULT_KEYS)),
                "day": _parse_day(self._cell(row, *self.TEST_DATE_KEYS)),
                "system": self._cell(row, *self.SYSTEM_KEYS),
                "evidence": self._cell(row, *self.TEST_EVIDENCE_KEYS),
                "unreadable_objectives": sorted(
                    note for _, note in objectives.values() if note),
            }
            entry.update({name: value for name, (value, _) in objectives.items()})
            out.append(entry)
        return out

    def _classify_test_result(self, raw: str) -> str:
        text = (raw or "").strip().lower()
        if not text:
            return "unknown"
        # "partial" is neither, and is checked first: a partially successful restore
        # has not demonstrated recoverability, and calling it a pass would be the
        # module telling the comfortable lie it exists to avoid.
        if "partial" in text:
            return "partial"
        if self._is_failure_text(text):
            return "failed"
        if text in self._SUCCESS_EXACT or any(t in text
                                              for t in self._SUCCESS_SUBSTRINGS):
            return "pass"
        return "unknown"

    # ------------------------------------------------------------ HANA guard
    def _log_backups_are_expected(self) -> bool:
        """Should this system be producing log backups at all?

        Returns False ONLY when the HANA export positively states
        ``[persistence] log_mode = overwrite`` — the one configuration in which the
        absence of log backups is expected rather than a defect, and which
        `modules/hana_db_security.py` already reports at HANADB severity. Raising
        our own finding on top of theirs would price the same defect twice.

        Absent export, unreadable value, anything else: True. Absence of evidence
        must not become evidence that log backups are unnecessary.
        """
        for row in self._rows(self.data.get("hana_parameters")):
            key = self._cell(row, "KEY", "PARAMETER", "NAME").strip().lower()
            if key != "log_mode":
                continue
            section = self._cell(row, "SECTION", "SECTION_NAME").strip().lower()
            # Only the persistence section defines the recovery log mode; a
            # same-named key elsewhere must not be allowed to silence our check.
            if section and section != "persistence":
                continue
            if self._cell(row, "VALUE", "PARAM_VALUE", "VALUE_1").strip().lower() \
                    == "overwrite":
                return False
        return True

    # ================================================================ CHECKS

    def check_data_backup_evidence(self):
        """Is there recorded evidence of a recent SUCCESSFUL full data backup?

        Two mutually exclusive outcomes, because "no recent backup" and "we cannot
        tell when the backups were" are different statements and collapsing them
        would let a date-format problem masquerade as a missing backup.
        """
        if not self._runs:
            return  # no catalogue supplied — server/coverage.py reports that

        max_age = int(self.get_config("resilience_full_backup_max_age_days", 7))
        summary = self._kind_summary(self.KIND_DATA)

        # Branch A — successes exist but not one of them carries a parseable date.
        # Reporting "no recent backup" here would be a false positive manufactured
        # by our own parser, so we say what we actually know instead.
        if summary["successes"] and not summary["dated_successes"]:
            self._reported_kinds.add(self.KIND_DATA)
            self.finding(
                check_id="RES-BCK-004",
                title="Backup recency could not be assessed from the supplied catalogue",
                severity=self.SEVERITY_INFO,
                category=self.CATEGORY,
                description=(
                    f"The backup catalogue records {summary['successes']} successful "
                    "full data backup(s), but no run carries a date this scanner can "
                    "read unambiguously, so the age of the most recent backup — the "
                    "recovery point — could not be determined. Ambiguous day/month "
                    "formats (03/04/2026) are rejected rather than guessed at, because "
                    "a recency judgement that is wrong by nine months is worse than no "
                    "judgement. This is a limitation of the EXPORT, not a statement "
                    "about the backups themselves, and it is reported so the gap is "
                    "visible rather than silently absorbed."
                ),
                affected_items=[
                    f"{summary['successes']} successful full data backup run(s), "
                    f"0 with a parseable date"
                ],
                # No affected_objects: a backup RUN is an event record, not a named
                # SAP object with a type in the identity registry, and coining one
                # would fabricate a graph node the export does not contain.
                # Aggregate keeps identity on (system, client, check_id), so fixing
                # the export format resolves this finding rather than churning it.
                scope="aggregate",
                remediation=(
                    "Re-export the backup catalogue with timestamps in an unambiguous "
                    "format — ISO 8601 (YYYY-MM-DD), SAP's YYYYMMDD, or DD.MM.YYYY. "
                    "Then re-run the scan so the recovery point can be assessed."
                ),
                references=["ISO 8601 — date and time representation"],
                details={"successful_runs": summary["successes"],
                         "runs_with_parseable_dates": summary["dated_successes"]},
            )
            return

        # Branch B — no success at all, or the newest one is older than the window.
        age = self._age_days(summary["newest_success"])
        if summary["successes"] and age is not None and age <= max_age:
            return

        # UNCLASSIFIABLE IS NOT ABSENT — the same doctrine as branch A, applied to
        # the backup TYPE rather than to its date. A successful run whose type
        # string this scanner could not classify may well BE the full data backup;
        # asserting at HIGH that none exists would be a false accusation
        # manufactured by our own vocabulary, and it is exactly the finding a
        # customer checks by hand first. So the verdict is withheld and the reason
        # is disclosed instead.
        unclassified = self._kind_summary(self.KIND_OTHER)
        if not summary["successes"] and unclassified["successes"]:
            spellings = sorted({r["raw_type"] for r in self._runs
                                if r["kind"] == self.KIND_OTHER
                                and r["outcome"] == "success" and r["raw_type"]})
            self._gap(
                f"full data backup: the catalogue records "
                f"{unclassified['successes']} successful run(s) whose backup type "
                f"this scanner could not classify"
                + (f" ({', '.join(repr(s) for s in spellings[:5])})" if spellings
                   else " (the type column is blank)")
                + ", and no successful run it could classify as a full data backup. "
                "Whether a full data backup exists therefore could not be "
                "established — this is not a finding that none exists",
                unclassified_successful_backup_types=spellings[:20] or ["(blank)"],
            )
            return

        if not summary["successes"]:
            # Only claim the ELIMINATION where there was something to eliminate. A
            # catalogue whose only rows are failed full-backup runs has no successes
            # of another type, and "every successful run was classified as something
            # else" would then be a vacuous sentence dressed as evidence.
            elsewhere = (self._kind_summary(self.KIND_LOG)["successes"]
                         + self._kind_summary(self.KIND_INCREMENTAL)["successes"])
            evidence = ("no successful full data backup is recorded in the supplied "
                        "catalogue at all")
            if elsewhere:
                evidence += (f", and each of the {elsewhere} successful run(s) it "
                             "does record was classified as a log or "
                             "incremental/differential backup rather than a full one")
            member = (f"full data backup: no successful run recorded "
                      f"({summary['runs']} run(s) of this type in the catalogue, "
                      f"{summary['failures']} recorded as failed)")
        else:
            evidence = (f"the most recent successful full data backup recorded is "
                        f"{summary['newest_success'].isoformat()}, {age} days old")
            member = (f"full data backup: newest success "
                      f"{summary['newest_success'].isoformat()} ({age} days old, "
                      f"threshold {max_age})")

        # A stale classified chain IS positive evidence and the finding stands, but
        # an unclassifiable success could be a newer full backup we failed to read,
        # so the age is not presented as settled when one exists.
        unclassified_note = (
            f" The catalogue also holds {unclassified['successes']} successful "
            "run(s) whose backup type could not be classified; if any of them is in "
            "fact a full data backup the recovery point may be more recent than the "
            "date above, and only the runs this scanner could classify are reported "
            "here."
            if summary["successes"] and unclassified["successes"] else "")
        # Runs whose STATUS was unreadable pushed this check toward firing without
        # being counted as failures. Saying how many keeps the reader able to judge
        # how much of the verdict rested on rows we could not read.
        unknown_note = (
            f" {summary['unknown']} run(s) of this type carry a status this scanner "
            "does not recognise and were counted as neither a success nor a failure."
            if summary["unknown"] else "")

        self._reported_kinds.add(self.KIND_DATA)
        self.finding(
            check_id="RES-BCK-001",
            title="No recent successful full data backup recorded in the supplied catalogue",
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=(
                f"A backup catalogue was supplied and {evidence}. The recovery point "
                f"this evidences is therefore older than the {max_age}-day threshold "
                "configured for this scan, or cannot be established at all. Everything "
                "changed since that point would be lost in a ransomware event, a "
                "storage failure or an erroneous mass update. Incremental and "
                "differential backups do not substitute: they cannot be applied "
                "without the full backup they are based on.\n"
                "This finding reports what the EXPORTED EVIDENCE shows. It is not a "
                "statement that backups are not running, and no restore was attempted "
                "or verified by this scan — if backups are taken by a mechanism that "
                "does not write to this catalogue, supply that system's evidence "
                "instead." + unclassified_note + unknown_note
            ),
            affected_items=[member],
            scope="aggregate",
            remediation=(
                "Confirm from the backup system itself whether full data backups are "
                "completing, and reconcile the discrepancy if they are and this "
                "catalogue does not show them. Where they are genuinely not "
                "completing, restore the schedule and re-verify. Independently of "
                "either, perform and record a test RESTORE — a completed backup is "
                "evidence of a written file, not of a recoverable system."
            ),
            references=[
                "ISO/IEC 27001:2022 A.8.13 — Information backup",
                "CIS Controls v8 — Control 11: Data Recovery",
                "NIST CSF 2.0 RC.RP — Incident Recovery Plan Execution",
                "SAP HANA Administration Guide — Backup and Recovery",
            ],
            details={"threshold_days": max_age,
                     "newest_successful_backup": (
                         summary["newest_success"].isoformat()
                         if summary["newest_success"] else None),
                     "successful_runs": summary["successes"],
                     "failed_runs": summary["failures"],
                     "runs_with_unreadable_status": summary["unknown"],
                     "successful_runs_of_unclassifiable_type":
                         unclassified["successes"]},
        )

    def check_log_backup_evidence(self):
        """Point-in-time recovery is only possible if log backups actually exist.

        Guarded by `_log_backups_are_expected()`: when the HANA export states
        log_mode = overwrite, their absence is already explained and already
        reported by `modules/hana_db_security.py`, and this check stays silent.

        Guarded a SECOND time by the unclassifiable-success rule that
        `check_data_backup_evidence` applies. Measured, on a healthy estate whose
        catalogue is exported in German: seven daily full backups and 168 hourly
        log backups, every one of them successful and recent, produced this finding
        at HIGH saying "no successful log backup", beside an affected_item claiming
        "full data backup: 0 successful run(s)". The whole point of this change was
        that a vocabulary gap must not manufacture a HIGH accusation, and that rule
        had been applied to RES-BCK-001 and to the STATUS vocabulary but not here —
        so the check that fires on a MISSING backup type was left as the one way in.
        """
        if not self._runs:
            return
        if not self._log_backups_are_expected():
            return

        summary = self._kind_summary(self.KIND_LOG)
        if summary["successes"]:
            return

        # UNCLASSIFIABLE IS NOT ABSENT, applied to the log-backup kind exactly as
        # `check_data_backup_evidence` applies it to the full-backup kind: a
        # successful run whose type string we could not classify may BE the log
        # backup, and only a SUCCESS blocks the verdict, because a failed row of an
        # unknown type is no evidence of a log backup either way.
        #
        # THE COST, stated so the next reader does not have to rediscover it: one
        # odd successful row of an unrecognised type will silence this check on a
        # system that genuinely has no log backups. That is the same trade
        # RES-BCK-001 already makes, it under-claims rather than over-claims, and
        # the reason is DISCLOSED as RES-EVD-001 rather than absorbed — which is
        # the difference between withholding a verdict and losing one.
        unclassified = self._kind_summary(self.KIND_OTHER)
        if unclassified["successes"]:
            spellings = sorted({r["raw_type"] for r in self._runs
                                if r["kind"] == self.KIND_OTHER
                                and r["outcome"] == "success" and r["raw_type"]})
            self._gap(
                f"log backup: the catalogue records {unclassified['successes']} "
                "successful run(s) whose backup type this scanner could not classify"
                + (f" ({', '.join(repr(s) for s in spellings[:5])})" if spellings
                   else " (the type column is blank)")
                + ", and no successful run it could classify as a log backup. "
                "Whether log backups exist therefore could not be established — "
                "this is not a finding that none exist",
                unclassified_successful_backup_types=spellings[:20] or ["(blank)"],
            )
            return

        data_summary = self._kind_summary(self.KIND_DATA)
        self._reported_kinds.add(self.KIND_LOG)
        self.finding(
            check_id="RES-BCK-003",
            title="No successful log backup recorded, so no point-in-time recovery evidence",
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=(
                "The supplied backup catalogue contains no successful log backup, and "
                "nothing in the configuration that was supplied explains its absence "
                "(the one configuration that would — HANA log_mode = overwrite — is "
                "either not set that way or was not exported; where it IS set that "
                "way, that defect is reported separately by the HANA database checks "
                "rather than twice here).\n"
                "Without log backups a recovery can only go back to the last full or "
                "delta data backup. Every transaction posted after it is lost, so the "
                "real recovery point objective is the age of that backup rather than "
                "the minutes a log-backup interval would give — which is typically the "
                "difference between losing an hour of postings and losing a day of "
                "them.\n"
                "This reports the absence of EVIDENCE in the catalogue supplied. It is "
                "not a statement that log backups are not being written elsewhere."
            ),
            affected_items=[
                f"log backup: {summary['runs']} run(s) in the catalogue, "
                f"0 successful ({summary['failures']} recorded as failed)",
                f"full data backup: {data_summary['successes']} successful run(s) — "
                f"the furthest back a recovery could reach on this evidence",
            ],
            # No affected_objects, for the same reason as RES-BCK-004: a backup run
            # is an event, not a named object. The HANA parameter is NOT named here
            # either — naming it would collide with the parameter_name node that
            # hana_db_security owns and attach our check_id to their defect.
            scope="aggregate",
            remediation=(
                "Confirm that automatic log backups are configured and reaching their "
                "target, and that a full data backup exists — log backups only begin "
                "once one does. Then confirm the chain end to end by performing and "
                "recording a point-in-time recovery test on a non-production copy; a "
                "log backup that exists but cannot be replayed is not a recovery point."
            ),
            references=[
                "SAP HANA Administration Guide — Backup and Recovery",
                "ISO/IEC 27001:2022 A.8.13 — Information backup",
                "NIST CSF 2.0 RC.RP — Incident Recovery Plan Execution",
            ],
            details={"log_backup_runs": summary["runs"],
                     "log_backup_failures": summary["failures"],
                     # Log-backup rows counted as neither success nor failure. This
                     # check fires on the ABSENCE of a success, so an unreadable
                     # status contributed to it; the reader is told how many did.
                     "log_backup_runs_with_unreadable_status": summary["unknown"]},
        )

    def check_backup_failure_rate(self):
        """Backups that succeed but keep failing are an unreliable recovery point.

        A RATE INSIDE A WINDOW, NOT A LIFETIME COUNT  (changed 2026-08-08)
        ------------------------------------------------------------------
        This check used to fire on an absolute lifetime failure count (>= 3, ever).
        A customer with 3 failures in 5,000 runs and one with 3 in 4 produced the
        same finding, so it fired on essentially every customer who exported a real
        history — and a rule that fires on everyone is a rule its reader learns to
        skip past, taking the true positives with it.

        It now requires BOTH conditions, and both are needed:

          * a minimum COUNT   (default 3) — a share alone fires on 1 failure in 2
            runs, which is a short catalogue rather than a broken chain;
          * a minimum SHARE   (default 10%) — a count alone is what produced the
            original defect, because any large healthy estate accumulates a handful
            of transient failures;

        measured over a WINDOW (default 30 days) anchored on that backup type's own
        newest run rather than over its lifetime.

        THE CASE THE LIFETIME COUNT GOT WRONG IN THE OTHER DIRECTION, which is why
        the window is here and not just the ratio: a customer with years of clean
        history and one bad week in 2023 kept failing this check forever. The
        failures were real, they were fixed, and no amount of subsequent success
        could ever retire the finding — the count only goes up. Under the window
        that customer is silent as soon as the bad week ages out, and a bad week
        happening NOW fires immediately (a week of failures is a large share of a
        30-day window), which is the behaviour the check was always meant to have.
        A lifetime SHARE would not have fixed it either: 20 failures against 5,000
        lifetime runs is 0.4%, so an active, total outage of the backup chain would
        have gone unreported. The window is what separates "is failing" from "once
        failed".

        Still deliberately narrow in one respect: only backup types that DO have a
        recorded success are considered. A type with no success at all is already
        reported by RES-BCK-001 or RES-BCK-003, and reporting it again here would
        price one broken backup type twice in the FAIR figure.
        """
        if not self._runs:
            return
        min_failures = int(self.get_config("resilience_backup_failure_threshold", 3))
        min_share = float(self.get_config("resilience_backup_failure_ratio", 0.10))
        window_days = int(self.get_config("resilience_backup_failure_window_days", 30))

        offenders = []
        measured: Dict[str, Any] = {}
        for kind in (self.KIND_DATA, self.KIND_INCREMENTAL, self.KIND_LOG,
                     self.KIND_OTHER):
            if kind in self._reported_kinds:
                continue
            summary = self._kind_summary(kind)
            if not summary["successes"]:
                continue
            profile = self._failure_profile(kind)
            measured[kind] = {"failures": profile["failures"],
                              "runs_measured": profile["considered"],
                              "share": round(profile["share"], 4),
                              "basis": profile["basis"]}
            if not profile["considered"]:
                continue
            if profile["failures"] < min_failures:
                continue
            if profile["share"] < min_share:
                continue
            excluded = ""
            if profile["undated_excluded"]:
                excluded = (f"; {profile['undated_excluded']} run(s) of this type "
                            "carry no readable date and could not be placed in the "
                            "window")
            offenders.append(
                f"{kind}: {profile['failures']} of {profile['considered']} run(s) "
                f"failed ({profile['share']:.0%}) in {profile['basis']}{excluded}")

        if not offenders:
            return

        self.finding(
            check_id="RES-BCK-002",
            title="Backup runs are failing repeatedly despite a recorded success",
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=(
                f"{len(offenders)} backup type(s) in the supplied catalogue failed at "
                f"least {min_failures} time(s) AND on at least {min_share:.0%} of the "
                f"runs recorded in the most recent {window_days} day(s) of that "
                "type's own catalogue history, while also recording successes. The "
                "recovery point therefore exists but is not dependable: a chain that "
                "fails intermittently produces gaps that are only discovered during a "
                "recovery, which is the worst possible moment to discover them, and an "
                "intermittent failure is also how a deliberate interference with the "
                "backup chain hides — a ransomware operator who disables backups a "
                "fortnight before encrypting produces exactly this pattern.\n"
                "Both a count and a share are required, over a recent window rather "
                "than over the whole catalogue, so that a large estate's handful of "
                "transient failures does not read the same as a chain that is failing "
                "now, and so that a bad week which has since been fixed stops being "
                "reported once it ages out.\n"
                "Reported separately from the recency check so the two are not "
                "confused: this says the backups run and sometimes fail, not that a "
                "recent backup is missing."
            ),
            affected_items=offenders,
            # Aggregate over the failing backup types: fixing one type shortens the
            # list, and the finding's age — how long the chain has been unreliable —
            # must survive that. No affected_objects; see RES-BCK-004.
            scope="aggregate",
            remediation=(
                "Investigate the recorded failures per backup type rather than per "
                "run: a repeating failure is usually a target, credential or capacity "
                "problem that will recur. Alert on backup failure at the time it "
                "happens, and treat an unexplained run of failures as a possible "
                "interference with the backup chain, not only as an operations issue."
            ),
            references=[
                "ISO/IEC 27001:2022 A.8.13 — Information backup",
                "CIS Controls v8 — Control 11: Data Recovery",
            ],
            details={"minimum_failure_count": min_failures,
                     "minimum_failure_share": min_share,
                     "window_days": window_days,
                     # Every type that was MEASURED, not only the offenders, so a
                     # reader can see what the rule cleared and on what numbers.
                     "measured": measured},
        )

    def check_recovery_test_evidence(self):
        """Has a restore / DR test actually RUN, recently, and PASSED?

        This is the check that LOG-IR-001 cannot make. LOG-IR-001 reads
        `incident_response.json` and reports whether a drill schedule is DECLARED;
        a declared annual test that last ran two years ago passes it. This one reads
        test RECORDS and asks when the last passing one was.
        """
        if not self._tests:
            return
        max_age = int(self.get_config("resilience_recovery_test_max_age_days", 365))

        # "Nobody ran this test" and "records were supplied whose type I could not
        # classify" take DIFFERENT actions — schedule an exercise, versus fix the
        # export or tell us what your naming means — and the old wording gave both
        # the same sentence. A customer who runs quarterly restores under a local
        # name for them was being told they had never run one.
        unclassified = [t for t in self._tests if not t["classes"]]
        unclassified_types = sorted({t["raw_type"] or "(blank)"
                                     for t in unclassified})

        offenders = []
        details: Dict[str, Any] = {
            "threshold_days": max_age,
            "records_of_unclassifiable_type": len(unclassified),
            "unclassifiable_test_types": unclassified_types[:20],
        }
        for label in ("data restore", "DR / failover"):
            of_class = [t for t in self._tests if label in t["classes"]]
            passed = [t for t in of_class if t["result"] == "pass"]
            dated = [t["day"] for t in passed if t["day"] is not None]
            newest = max(dated) if dated else None
            age = self._age_days(newest)
            details[label] = {
                "records": len(of_class),
                "passed": len(passed),
                "newest_pass": newest.isoformat() if newest else None,
            }

            if not of_class and unclassified:
                offenders.append(
                    f"{label}: no test of this kind was identified — but "
                    f"{len(unclassified)} supplied record(s) carry a test type this "
                    "scanner could not classify "
                    f"({', '.join(repr(t) for t in unclassified_types[:5])}), so "
                    "this may be a gap in what this scan can read rather than in "
                    "what was tested")
            elif not of_class:
                offenders.append(
                    f"{label}: no test of this kind recorded in the supplied evidence")
            elif not passed:
                results = ", ".join(sorted({t["result"] for t in of_class}))
                offenders.append(
                    f"{label}: {len(of_class)} test(s) recorded, none with a passing "
                    f"result (recorded outcomes: {results})")
            elif newest is None:
                offenders.append(
                    f"{label}: {len(passed)} passing test(s) recorded but none carries "
                    f"a readable date, so recency cannot be established")
            elif age is not None and age > max_age:
                offenders.append(
                    f"{label}: last passing test {newest.isoformat()} "
                    f"({age} days ago, threshold {max_age})")

        if not offenders:
            return

        self.finding(
            check_id="RES-DR-001",
            title="Recovery test evidence is missing, failed or stale",
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=(
                f"{len(offenders)} of the 2 recovery-test categories this scan looks "
                "for (data restore, DR / failover) has no recent passing test in the "
                "evidence supplied. A backup that has never been restored is a "
                "hypothesis: the failure modes that matter — an unreadable target, a "
                "missing encryption key, an incomplete log chain, a runbook nobody has "
                "followed under pressure — are precisely the ones that only appear "
                "when somebody tries. This is also the item an auditor asks for by "
                "name, and DORA makes periodic resilience testing a regulatory "
                "obligation rather than good practice for EU financial entities.\n"
                "This scanner reads the test RECORDS the customer exported. It did not "
                "perform, observe or verify any recovery itself, and a passing record "
                "here is the customer's assertion, not our measurement."
            ),
            affected_items=offenders,
            # Aggregate over the test categories: running a restore test while the
            # failover test is still stale must shorten the list, not retire the
            # finding and raise a zero-age clone. No affected_objects — a test record
            # is an event, and its "system" column is display context.
            scope="aggregate",
            remediation=(
                "Schedule and perform a full restore of a production backup into an "
                "isolated environment, and a failover exercise for the continuity "
                "plan, at least as often as your policy and regulator require. Record "
                "the date, the scope, the outcome and the elapsed time for each, and "
                "keep the record where it can be exported — an untested recovery plan "
                "and an unrecorded test are indistinguishable to an auditor."
            ),
            references=[
                "ISO/IEC 27001:2022 A.8.13 — Information backup",
                "CIS Controls v8 — Control 11: Data Recovery",
                "NIST CSF 2.0 RC.RP — Incident Recovery Plan Execution",
                "EU DORA — ICT business continuity and resilience testing obligations",
            ],
            details=details,
        )

    def check_recovery_test_absent(self):
        """Backup evidence was supplied and restore evidence was not.

        THE ONE DELIBERATE MISSING-EXPORT FINDING IN THIS MODULE, and the reason it
        is allowed where `server/coverage.py` already reports absent sources: the
        pairing is the point. A customer who can produce a backup catalogue is a
        customer whose backup tooling is instrumented and exportable; the absence of
        any restore record alongside it is a specific, nameable gap — backups are
        instrumented and restores are not — and it is worth naming.

        INFO, and worded as an evidence gap, because absence of evidence is not
        evidence of absence — the reachability module's doctrine, and it applies with
        full force here. They may test restores diligently and simply not have the
        file. The finding must not read as an accusation.
        """
        if not self._runs:
            return          # nothing to pair the missing evidence against
        if self._tests:
            return          # evidence supplied; RES-DR-001 judges it

        self.finding(
            check_id="RES-DR-002",
            title="Backup evidence supplied without any recovery-test evidence",
            severity=self.SEVERITY_INFO,
            category=self.CATEGORY,
            description=(
                "A backup catalogue was supplied for this system and no restore, "
                "failover or disaster-recovery test record was supplied alongside it. "
                "Recoverability therefore could not be assessed at all: this scan can "
                "see that backups were written and can see nothing about whether any "
                "of them has ever been read back.\n"
                "This is an EVIDENCE gap in the upload, not a finding that no test was "
                "performed. It is raised at informational severity so it appears on "
                "the evidence checklist an auditor works from, and it is closed by "
                "supplying the records, not by changing any system setting."
            ),
            affected_items=[
                f"backup catalogue: {len(self._runs)} run(s) supplied",
                "recovery test evidence: none supplied",
            ],
            # Aggregate: identity is (system, client, check_id). There is no object —
            # the finding is about something that is NOT in the export.
            scope="aggregate",
            remediation=(
                "Export the restore / failover test records for this system and "
                "re-run the scan, so recovery-test recency can be assessed rather "
                "than left unknown. If no such record is kept, start keeping one: the "
                "record is what an auditor and a regulator ask for, and it is what "
                "turns 'we take backups' into a demonstrable control."
            ),
            references=[
                "ISO/IEC 27001:2022 A.8.13 — Information backup",
                "EU DORA — ICT business continuity and resilience testing obligations",
            ],
            details={"backup_runs_supplied": len(self._runs),
                     "recovery_test_records_supplied": 0},
        )

    def check_recovery_objectives(self):
        """Did a recorded test meet the RTO / RPO it was measured against?

        Only fires where the export states BOTH a target and an achieved figure. A
        stated target with nothing measured against it is an unmeasured control, not
        a breached one, and manufacturing a finding from a missing column is how a
        tool teaches its user to stop trusting it.
        """
        if not self._tests:
            return

        offenders = []
        unreadable = []
        for test in self._tests:
            label = test["raw_type"] or "recovery test"
            when = test["day"].isoformat() if test["day"] else "date not stated"
            unreadable += test["unreadable_objectives"]
            for name, target, achieved in (
                ("RTO", test["rto_target"], test["rto_achieved"]),
                ("RPO", test["rpo_target"], test["rpo_achieved"]),
            ):
                if target is None or achieved is None:
                    continue
                if achieved <= target:
                    continue
                offenders.append(
                    f"{label} ({when}): {name} target {target:g} min, "
                    f"achieved {achieved:g} min")

        if unreadable:
            # A cell the customer FILLED IN and we would not guess at. Without this
            # it drops through the `target is None` branch above and becomes
            # indistinguishable from a column they left blank — the comparison is
            # skipped either way, but only one of the two is their omission.
            self._gap(
                f"recovery objectives: {len(unreadable)} RTO/RPO figure(s) were "
                "supplied in a form this scanner will not read as a number of "
                f"minutes ({', '.join(sorted(set(unreadable))[:5])}), so the "
                "objective(s) they belong to were not compared at all",
                unreadable_objective_cells=sorted(set(unreadable))[:20],
            )

        if not offenders:
            return

        self.finding(
            check_id="RES-DR-003",
            title="Recorded recovery test did not meet its stated RTO / RPO target",
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=(
                f"{len(offenders)} recorded recovery measurement(s) exceeded the "
                "objective they were measured against. The organisation's own stated "
                "recovery time or recovery point is therefore not achievable on the "
                "evidence of its own test — which is more actionable than an untested "
                "objective, because the gap is quantified: continuity plans, customer "
                "commitments and, for EU financial entities, regulatory submissions "
                "that assume the target figure are all resting on a number the test "
                "did not reach.\n"
                "Both figures are read from the customer's own test record. This scan "
                "measured nothing itself."
            ),
            affected_items=offenders,
            # Aggregate over the missed objectives. No affected_objects: an RTO
            # measurement is a number in a test record, not an SAP object.
            scope="aggregate",
            remediation=(
                "Either close the gap — usually by changing the recovery method rather "
                "than by trying harder at the same one — or revise the published "
                "objective to what the test demonstrates and re-agree it with the "
                "business owners who depend on it. An objective nobody has met is "
                "worse than a slower one everybody has planned around."
            ),
            references=[
                "ISO/IEC 27001:2022 A.8.13 — Information backup",
                "NIST CSF 2.0 RC.RP — Incident Recovery Plan Execution",
                "EU DORA — ICT business continuity and resilience testing obligations",
            ],
        )

    def check_recovery_relevant_jobs(self):
        """Recovery-relevant background jobs the export records as aborted.

        Distinct from every JOBCMD-JOB-* check in `modules/basis_job_command.py`,
        which reads TBTCO only to decide which jobs are ARMED (status in P/S/Y/R)
        and reports on the step user and on OS execution. It never reports a run
        OUTCOME, and an aborted archive or backup job is invisible to it by
        construction — the aborted status is exactly what excludes the job from its
        armed set.
        """
        jobs = self._rows(self.data.get("background_jobs"))
        if not jobs:
            return

        offenders = []
        objects = []
        for row in jobs:
            name = self._cell(row, "JOBNAME", "NAME", "JOB_NAME")
            if not name:
                continue
            upper = name.upper()
            if not any(token in upper for token in self.RECOVERY_JOB_TOKENS):
                continue
            status = self._cell(row, "STATUS", "JOBSTATUS", "JOB_STATUS")
            aborted = (status.strip().upper() in self._ABORTED_STATUS_CODES
                       or self._is_failure_text(status.strip().lower()))
            if not aborted:
                continue
            offenders.append(f"{name} — status {status or '(blank)'}")
            # The SAME job node `modules/basis_job_command.py` emits, keyed on
            # JOBNAME alone exactly as theirs is. That shared node is the join that
            # lets "this archive job aborted" meet "this job runs as DDIC" on one
            # object instead of two — qualifying it with the status would cut it.
            objects.append({"type": "job", "name": name})

        if not offenders:
            return

        self.finding(
            check_id="RES-JOB-001",
            title="Recovery-relevant background job recorded as aborted",
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=(
                f"{len(offenders)} background job(s) whose name indicates a "
                "backup, archiving, recovery or replication purpose are recorded in "
                "the job export as aborted or cancelled. Housekeeping that silently "
                "stops is a slow-acting resilience failure: log areas fill, archive "
                "runs fall behind, replication drifts, and none of it is noticed until "
                "a recovery needs the output.\n"
                "The purpose is inferred from the JOB NAME, because the job export "
                "carries no field stating what a job is for. That inference "
                "over-reports a job merely named after archiving and misses a "
                "recovery-critical job with an opaque name, so treat this as a prompt "
                "to look rather than as an inventory of the backup chain."
            ),
            affected_items=offenders,
            # Aggregate: the set of stalled recovery-relevant jobs. Re-running one
            # shortens the list; the finding's age — how long housekeeping has been
            # broken — must survive that.
            affected_objects=objects,
            scope="aggregate",
            remediation=(
                "Review each job's log for why it aborted, re-run it, and confirm the "
                "backlog it left has cleared. Add failure alerting for the jobs that "
                "feed the recovery chain specifically — an aborted archive job that "
                "nobody is paged about is indistinguishable from one that was "
                "deliberately stopped."
            ),
            references=[
                "ISO/IEC 27001:2022 A.8.13 — Information backup",
                "SAP Help — Background processing job monitoring (SM37)",
            ],
        )

    def check_evidence_not_assessable(self):
        """What this scan COULD NOT READ, said out loud.

        THE FAILURE THIS EXISTS TO PREVENT is the one that costs the customer most:
        a check that contributes nothing because its input defeated it looks, in a
        report, exactly like a check that looked and found nothing wrong. "Nothing
        to find" and "could not look" must never render the same, and the
        established way to say the second is a finding — `snc_posture`'s
        `check_family_not_assessable` is the same idea for a parameter family.

        ONE check for several gaps, because they are the same defect in the evidence
        and take the same fix: re-export the file in the form this scanner
        documents, or tell us what your local vocabulary means. The four ways in
        are a backup status vocabulary we cannot read at all, a successful backup
        whose TYPE we cannot classify while nothing else evidences a full backup,
        the same for a log backup, and an RTO/RPO figure we refused to guess at.

        Recency gaps are NOT collected here: RES-BCK-004 already reports an
        unreadable backup DATE, has shipped, and carries its own remediation about
        date formats. Folding it in would retire a check customers have already
        received without improving anything.

        INFO, because it is a gap in the upload and not a defect in the system. It
        is closed by supplying readable evidence, not by changing a setting.

        WHAT IS DELIBERATELY NOT REPORTED HERE: a gap that did not change a verdict.
        An unclassifiable backup type alongside a recent, readable full backup, or
        an unclassified test record alongside passing tests of both kinds, blocks
        nothing — and a coverage note that fires whether or not it mattered is noise
        that teaches its reader to skip the ones that did matter. Every gap
        collected above is collected at the point where it stopped a check from
        reaching an answer.
        """
        if not self._gaps:
            return

        self.finding(
            check_id="RES-EVD-001",
            title="Part of the resilience evidence could not be read by this scan",
            severity=self.SEVERITY_INFO,
            category=self.CATEGORY,
            description=(
                f"{len(self._gaps)} part(s) of the resilience evidence supplied for "
                "this system could not be interpreted, so the checks that depend on "
                "them reached no verdict. This is reported rather than absorbed "
                "because a check that silently contributes nothing reads as a clean "
                "result, and a customer would then believe this scan had assessed "
                "something it never managed to look at.\n"
                "Nothing here is a statement about the backups, the tests or the "
                "recovery objectives themselves. The evidence may show a healthy "
                "estate, a broken one or neither; this scan could not tell, and the "
                "specific cells that defeated it are listed so the export can be "
                "corrected."
            ),
            affected_items=list(self._gaps),
            # No affected_objects, and aggregate identity: the finding is about
            # something that is NOT legible in the export, so there is no SAP object
            # to name and inventing one would put a node in the attack-path graph
            # that the data never contained. Aggregate also keeps the finding's age
            # stable while individual gaps are closed one at a time.
            scope="aggregate",
            remediation=(
                "Re-export the values listed above in the form this scanner "
                "documents: backup status and backup type as the text the source "
                "system produces rather than a numeric code, and RTO/RPO as a plain "
                "number of minutes with no thousands separator and no unit other "
                "than minutes. Where the values are already text and this scan still "
                "could not classify them, they are a local vocabulary this scanner "
                "has not seen — send the list and it can be added, which is a better "
                "outcome than a report that quietly skipped them."
            ),
            references=[
                "ISO/IEC 27001:2022 A.8.13 — Information backup",
                "ISO 8601 — date and time representation",
            ],
            details=dict(self._gap_details, gaps=list(self._gaps)),
        )
