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
evidence chain exists. Onapsis's checklist devotes four items to this axis
("review SAP ransomware readiness", "validate SAP backups & restore SLAs", "test
SAP disaster recovery scenarios", "confirm workflow-level resilience") and EU DORA
makes operational resilience a regulatory obligation for financial services, so the
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
  (RES-RET-001/002) and incident-response readiness (RES-IR-001) — and RES-IR-001
  already reports whether `incident_response.json` declares a `backupVerification`
  and a `drillSchedule`. **This module never reads `incident_response.json`.** The
  distinction that justifies RES-DR-001 existing alongside it: RES-IR-001 asks
  whether a schedule is *declared*; RES-DR-001 asks whether a test actually *ran*,
  *when*, and whether it *passed*. A declared annual DR test that last ran in 2023
  passes RES-IR-001 and fails RES-DR-001, and that gap is the whole point.
* `modules/basis_job_command.py` owns background-job privilege (JOBCMD-JOB-*). It
  reads TBTCO only to decide which jobs are *armed* and never reports a run
  OUTCOME. RES-JOB-001 reports outcome, and only for recovery-relevant jobs.
* `server/coverage.py` already tells the customer which exports were absent. This
  module therefore does not raise a finding merely because a file is missing — with
  one deliberate exception, RES-DR-002, whose reason is written at its call site.

WHY THE CHECK IDS ARE `LOG-` AND NOT `RESIL-`  (decided 2026-08-07)
--------------------------------------------------------------------
A `RESIL-` prefix reads better and routes to **nobody**: `server/enrich.py`
`TEAM_BY_PREFIX` has no such entry, `team_for("RESIL-BCK-001")` returns
"unassigned", and an unrouted check appears on no team's worklist and is never
worked — the exact failure `tests/test_enrich.py` was written for. That file is not
ours to edit in this change.

`LOG-` routes to the `data_protection` team, which already owns RES-IR-001, the
nearest neighbouring control. It also lands these findings in the `detection`
bucket of `data/fair_scenarios.json` rather than in a loss scenario, which is the
conservative direction and is defensible on the model's own terms: that bucket
scales the DWELL-SENSITIVE loss components (productivity, response, fines,
reputation), and a recovery capability is a FAIR-CAM *loss-event-response* control
that acts on exactly those components. It does NOT model the availability loss of
an unrecoverable outage — that would need its own scenario — so these findings
currently under-price rather than over-price. Under-claiming is the safe direction.

If a `RESIL-` team route and a recovery loss scenario are added, renaming these
eight ids is a mechanical change; leaving them unrouted would not have been.

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


def _number(raw: Any) -> Optional[float]:
    """A numeric cell, or None. Tolerates a unit suffix ("240 min") and a comma."""
    if raw is None:
        return None
    s = str(raw).strip().replace(",", ".")
    if not s:
        return None
    kept = []
    for ch in s:
        if ch.isdigit() or ch == "." or (ch == "-" and not kept):
            kept.append(ch)
        elif kept:
            break
    text = "".join(kept)
    if not text or text in ("-", ".", "-."):
        return None
    try:
        return float(text)
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
    _RESTORE_TEST_TOKENS = ("restore", "recover", "recovery", "pitr",
                            "point-in-time", "point in time")
    _CONTINUITY_TEST_TOKENS = ("failover", "fail-over", "switchover", "disaster",
                               " dr", "dr ", "dr_", "dr-", "tabletop",
                               "table-top", "continuity", "bcp")

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

        self.check_data_backup_evidence()
        self.check_log_backup_evidence()
        self.check_backup_failure_rate()
        self.check_recovery_test_evidence()
        self.check_recovery_test_absent()
        self.check_recovery_objectives()
        self.check_recovery_relevant_jobs()
        return self.findings

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
        seen must not be counted as a successful backup, and must not be counted as
        a failed one either. It contributes to neither side of any check here.
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
            runs.append({
                "kind": self._classify_kind(raw_type),
                "raw_type": raw_type,
                "outcome": self._classify_outcome(
                    self._cell(row, *self.BACKUP_STATUS_KEYS)),
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
            "dated_successes": len(dated),
            "newest_success": max(dated) if dated else None,
        }

    # ------------------------------------------------------- recovery tests
    def _recovery_tests(self) -> List[Dict[str, Any]]:
        out = []
        for row in self._rows(self.data.get("recovery_tests")):
            raw_type = self._cell(row, *self.TEST_TYPE_KEYS)
            text = raw_type.strip().lower()
            classes = []
            if any(t in text for t in self._RESTORE_TEST_TOKENS):
                classes.append("data restore")
            if any(t in text for t in self._CONTINUITY_TEST_TOKENS):
                classes.append("DR / failover")
            out.append({
                "raw_type": raw_type,
                "classes": classes,
                "result": self._classify_test_result(
                    self._cell(row, *self.TEST_RESULT_KEYS)),
                "day": _parse_day(self._cell(row, *self.TEST_DATE_KEYS)),
                "system": self._cell(row, *self.SYSTEM_KEYS),
                "evidence": self._cell(row, *self.TEST_EVIDENCE_KEYS),
                "rto_target": _number(self._cell(row, "RTO_TARGET",
                                                 "RTO_TARGET_MINUTES", "RTO")),
                "rto_achieved": _number(self._cell(row, "RTO_ACHIEVED",
                                                   "RTO_ACHIEVED_MINUTES",
                                                   "RTO_ACTUAL")),
                "rpo_target": _number(self._cell(row, "RPO_TARGET",
                                                 "RPO_TARGET_MINUTES", "RPO")),
                "rpo_achieved": _number(self._cell(row, "RPO_ACHIEVED",
                                                   "RPO_ACHIEVED_MINUTES",
                                                   "RPO_ACTUAL")),
            })
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

        if not summary["successes"]:
            evidence = ("no successful full data backup is recorded in the supplied "
                        "catalogue at all")
            member = (f"full data backup: no successful run recorded "
                      f"({summary['runs']} run(s) of this type in the catalogue, "
                      f"{summary['failures']} recorded as failed)")
        else:
            evidence = (f"the most recent successful full data backup recorded is "
                        f"{summary['newest_success'].isoformat()}, {age} days old")
            member = (f"full data backup: newest success "
                      f"{summary['newest_success'].isoformat()} ({age} days old, "
                      f"threshold {max_age})")

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
                "instead."
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
                     "failed_runs": summary["failures"]},
        )

    def check_log_backup_evidence(self):
        """Point-in-time recovery is only possible if log backups actually exist.

        Guarded by `_log_backups_are_expected()`: when the HANA export states
        log_mode = overwrite, their absence is already explained and already
        reported by `modules/hana_db_security.py`, and this check stays silent.
        """
        if not self._runs:
            return
        if not self._log_backups_are_expected():
            return

        summary = self._kind_summary(self.KIND_LOG)
        if summary["successes"]:
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
                     "log_backup_failures": summary["failures"]},
        )

    def check_backup_failure_rate(self):
        """Backups that succeed but keep failing are an unreliable recovery point.

        Deliberately narrow: only backup types that DO have a recorded success are
        considered. A type with no success at all is already reported by
        RES-BCK-001 or RES-BCK-003, and reporting it again here would price one
        broken backup type twice in the FAIR figure.
        """
        if not self._runs:
            return
        threshold = int(self.get_config("resilience_backup_failure_threshold", 3))

        offenders = []
        for kind in (self.KIND_DATA, self.KIND_INCREMENTAL, self.KIND_LOG,
                     self.KIND_OTHER):
            if kind in self._reported_kinds:
                continue
            summary = self._kind_summary(kind)
            if not summary["successes"]:
                continue
            if summary["failures"] < threshold:
                continue
            offenders.append(
                f"{kind}: {summary['failures']} failed run(s) of "
                f"{summary['runs']} ({summary['successes']} successful)")

        if not offenders:
            return

        self.finding(
            check_id="RES-BCK-002",
            title="Backup runs are failing repeatedly despite a recorded success",
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=(
                f"{len(offenders)} backup type(s) in the supplied catalogue record at "
                f"least {threshold} failed run(s) alongside their successes. The "
                "recovery point therefore exists but is not dependable: a chain that "
                "fails intermittently produces gaps that are only discovered during a "
                "recovery, which is the worst possible moment to discover them, and an "
                "intermittent failure is also how a deliberate interference with the "
                "backup chain hides — a ransomware operator who disables backups a "
                "fortnight before encrypting produces exactly this pattern.\n"
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
            details={"failure_threshold": threshold},
        )

    def check_recovery_test_evidence(self):
        """Has a restore / DR test actually RUN, recently, and PASSED?

        This is the check that RES-IR-001 cannot make. RES-IR-001 reads
        `incident_response.json` and reports whether a drill schedule is DECLARED;
        a declared annual test that last ran two years ago passes it. This one reads
        test RECORDS and asks when the last passing one was.
        """
        if not self._tests:
            return
        max_age = int(self.get_config("resilience_recovery_test_max_age_days", 365))

        offenders = []
        details: Dict[str, Any] = {"threshold_days": max_age}
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

            if not of_class:
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
        any restore record alongside it is the specific gap Onapsis sells against
        ("validate SAP backups & restore SLAs") and is worth naming.

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
        for test in self._tests:
            label = test["raw_type"] or "recovery test"
            when = test["day"].isoformat() if test["day"] else "date not stated"
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
