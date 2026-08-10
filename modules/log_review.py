# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
Security Audit Log — Retrospective Review
=========================================

WHAT THIS IS, AND THE WORDING THAT GOES WITH IT
------------------------------------------------
This module performs a **retrospective review over the exported window**. The
customer runs a standard Security Audit Log extract for a date range, uploads the
file, and this module reports what the log shows happened inside that range.

It is NOT monitoring. It is NOT detection. It is NOT real-time, near-real-time,
continuous or streaming, and no finding, title, description or sales conversation
derived from this module may say or imply that it is. We hold no connection to the
customer's SAP system and no agent on their application server; everything here
reads a FILE the customer exported. A claim of live monitoring would be dismantled
in the first technical evaluation, and losing the deal would be the *cheap* outcome
compared with having claimed it in writing.

The honest and — we think — stronger pitch is the one this module is built around:
the value is in the PATTERN LIBRARY and in knowing whether the log could have
recorded the answer at all, not in privileged live access.

THE TWO HALVES, AND WHY THE FIRST ONE MATTERS MORE
---------------------------------------------------
1. LOG-SOURCE HEALTH — was the audit log actually capturing what the customer
   believes it captures? Filter coverage per event class, per client, and whether a
   class survives a restart. Pure configuration analysis, fully offline. Being able
   to say "your audit log was not recording direct table access during the period
   you asked us to review" is worth more than any individual pattern hit, because it
   converts a silent blind spot into a known one.

2. RETROSPECTIVE PATTERNS over the exported window — privileged dialog logons
   outside business hours, a run of failed logons followed by a success, standard /
   default user activity, debug activity, direct and high-volume table access,
   changes to the audit configuration itself, and privileged logons from terminals
   that barely appear in the window.

The two halves are wired together deliberately: a pattern that finds nothing is only
meaningful if the event class behind it was recording. `LREV-WIN-002` reports exactly
which questions the exported window cannot answer, so "we found nothing" is never
quietly mistaken for "nothing happened".

WHAT THIS MODULE DOES NOT REPEAT
---------------------------------
`modules/log_monitoring.py` owns the audit-log CONFIGURATION baseline and keeps it:
whether the SAL is switched on at all (LOG-AUD-010 `rsau/enable`), integrity
protection (LOG-AUD-011), whether any active filter exists and whether any static
profile exists (LOG-AUD-001/002), which required event classes are absent from the
configuration entirely (LOG-AUD-003), SIEM forwarding (LOG-SIEM-*), retention policy
(LOG-RET-*), table change logging (LOG-TBL-*), and the aggregate failed-logon counts
in `logon_events.csv` (LOG-LOGON-001/002).

This module extends that in three directions it does not cover:
  * a filter that EXISTS and was switched off — a named object, a deliberate act and
    a one-click fix, rather than "this class is not covered";
  * whether the active filters span every client, and whether a class survives the
    next restart (a dynamic-only class stops recording at restart, which the
    "is there any static profile" check cannot see);
  * the event stream itself, which `log_monitoring` never reads.

`LREV-PAT-002` and `LOG-LOGON-001` both concern failed logons and are not the same
check: LOG-LOGON-001 works from aggregate per-user counters and reports accounts
under pressure; LREV-PAT-002 works from the ORDERED event stream and reports the one
case that matters most — a run of failures that ended in a success.

IDENTITY: WHY NO LOG-DERIVED FINDING NAMES A TIMESTAMP
-------------------------------------------------------
A finding's identity must not contain anything that changes every export. If the
window's dates, an occurrence count or an event timestamp entered identity, every
new extract would mint a brand-new finding, the previous one would be "resolved",
and the mitigation journey would reset its age on every upload — the precise failure
`server/identity.py` exists to prevent.

So every pattern finding is `scope="aggregate"`: one finding per PATTERN, with the
occurrences riding along as members and as graph nodes. The window is carried in
`details["reviewed_window"]` — which is evidence, not identity — so the console can
state what period was reviewed without the dates ever touching the fingerprint.

Data sources:
  - security_audit_log.csv  → EITHER the SM19 / RSAU_CONFIG filter configuration
                              (CONFIG_NAME/FILTER_NAME, EVENT_CLASS, ACTIVE,
                              PROFILE_TYPE, CLIENT) OR an SM20 / RSAU_READ_LOG event
                              extract (DATE, TIME, USER, CLIENT, TERMINAL, TCODE,
                              EVENT_CLASS, TEXT). The shape is auto-detected per row,
                              so a file holding both is handled too. The loader takes
                              the first matching filename, so a customer with two
                              separate files should concatenate them.
  - audit_config.csv        → fallback filter configuration when the above is the
                              event extract.
  - logon_events.csv        → aggregate per-user logon counters, used only to
                              corroborate a failure run found in the event stream.
  - client_settings.csv     → the clients that exist, to test filter client coverage.
  - standard_users.csv      → which default accounts exist in this system.
  - profiles.csv            → USR04 profile assignments, to resolve privileged users.
  - log_retention.json      → retention policy, to test it against the exported window.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from modules.base_auditor import BaseAuditor


class LogReviewAuditor(BaseAuditor):
    """Retrospective review of an exported Security Audit Log window."""

    CATEGORY = "Security Audit Log Review"

    # ── column vocabularies ────────────────────────────────────────────────────
    # Deliberately generic English/German export headers. No invented SAP field
    # names: an SM20 / RSAU_READ_LOG extract is produced by ALV download and the
    # header text depends on the layout the customer used, so the module matches
    # what such a download actually looks like rather than asserting a table field.
    DATE_KEYS = ("DATE", "EVENT_DATE", "AUDIT_DATE", "LOG_DATE", "DATUM")
    TS_KEYS = ("TIMESTAMP", "EVENT_TIMESTAMP", "DATE_TIME", "DATETIME")
    TIME_KEYS = ("TIME", "EVENT_TIME", "LOG_TIME", "UZEIT")
    USER_KEYS = ("USER", "USERNAME", "BNAME", "USER_NAME", "USERID", "ACCOUNT")
    CLIENT_KEYS = ("CLIENT", "MANDT")
    TERMINAL_KEYS = ("TERMINAL", "TERM", "WORKSTATION", "HOSTNAME", "HOST")
    TCODE_KEYS = ("TCODE", "TRANSACTION", "TRANSACTION_CODE", "TCD")
    CLASS_KEYS = ("EVENT_CLASS", "AUDIT_CLASS", "MESSAGE_CLASS", "EVENT_TYPE", "CLASS")
    TEXT_KEYS = ("TEXT", "MSGTXT", "MESSAGE", "MESSAGE_TEXT", "EVENT_TEXT", "DESCRIPTION")
    RESULT_KEYS = ("RESULT", "OUTCOME", "EVENT_RESULT")

    FILTER_NAME_KEYS = ("FILTER_NAME", "CONFIG_NAME", "PROFILE_NAME", "NAME")
    ACTIVE_KEYS = ("ACTIVE", "STATUS", "ACTIVE_FLAG")
    PROFILE_TYPE_KEYS = ("PROFILE_TYPE", "TYPE", "FILTER_TYPE")

    ACTIVE_VALUES = {"X", "1", "TRUE", "YES", "ACTIVE", "ON", "Y", "J"}

    # ── SAP identifiers used below ────────────────────────────────────────────
    # Every transaction code named here is a standard SAP transaction. Nothing in
    # this module invents a transaction code, a table name, a profile parameter, an
    # authorization object or an SAP Note number.
    DIRECT_TABLE_TCODES = {"SE16", "SE16N", "SE17", "SM30", "SM31"}
    AUDIT_CONFIG_TCODES = {"SM19", "RSAU_CONFIG"}
    #: Standard SAP profiles that make their holder privileged.
    PRIVILEGED_PROFILES = {"SAP_ALL", "SAP_NEW", "S_A.SYSTEM"}
    #: SAP-delivered default accounts. Same list the system-trust and basis-job
    #: modules use, so one system does not disagree with itself about who is standard.
    STANDARD_USERS = {"SAP*", "DDIC", "SAPCPIC", "EARLYWATCH", "TMSADM"}

    #: The normalised event-class vocabulary. It is intentionally the SAME vocabulary
    #: `log_monitoring.REQUIRED_AUDIT_EVENTS` uses, because the whole credibility
    #: argument depends on being able to line a pattern up against the filter that
    #: was (or was not) recording the class behind it.
    #: (substring tests applied to a lower-cased, underscore-normalised class name)
    CLASS_RULES: Tuple[Tuple[Tuple[str, ...], str], ...] = (
        (("audit_config", "audit_filter", "audit_configuration"), "audit_config_change"),
        (("user_master", "user_change", "user_maintenance"), "user_master_change"),
        (("rfc_logon", "rfc_cpic", "cpic_logon"), "rfc_logon"),
        (("rfc_call", "rfc_function", "function_call"), "rfc_function_call"),
        (("authority", "authorization_check", "authorisation_check"), "authority_check_fail"),
        (("transaction",), "transaction_start"),
        (("report", "program_start"), "report_start"),
        (("table",), "table_access"),
        (("debug",), "debug"),
        (("system",), "system_event"),
    )

    #: Which event class each retrospective pattern depends on. This is what turns
    #: "we found nothing" into either "nothing happened" or "the log could not have
    #: told us" — see LREV-WIN-002.
    #:
    #: A dict rather than a list of tuples on purpose: tests/test_check_id_uniqueness.py
    #: scans module sources for a check id immediately followed by a comma and a string,
    #: and reads that shape as a second title for the check. A tuple here would trip it;
    #: keeping the id a KEY keeps that guard sharp instead of teaching it to ignore a
    #: shape it should keep catching. Insertion order is the report order.
    PATTERN_CLASS_REQUIREMENTS: Dict[str, Tuple[str, str]] = {
        "LREV-PAT-001": ("dialog_logon",
                         "privileged dialog logons outside business hours"),
        "LREV-PAT-002": ("dialog_logon_failure",
                         "a run of failed logons followed by a success"),
        "LREV-PAT-003": ("dialog_logon",
                         "activity by standard / default accounts"),
        "LREV-PAT-005": ("table_access",
                         "direct and high-volume table access"),
        "LREV-PAT-006": ("audit_config_change",
                         "changes to the audit configuration itself"),
        "LREV-PAT-007": ("dialog_logon",
                         "privileged logons from rarely-seen terminals"),
    }

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self._prepare()
        # Half 1 — log-source health (pure configuration, fully offline).
        self.check_event_extract_supplied()
        self.check_event_timestamps_usable()
        self.check_filter_config_supplied()
        self.check_inactive_filters()
        self.check_filter_client_coverage()
        self.check_dynamic_only_classes()
        # Half 2 — retrospective patterns over the exported window.
        self.check_window_length()
        self.check_window_blind_spots()
        self.check_offhours_privileged_logons()
        self.check_failure_run_then_success()
        self.check_standard_user_activity()
        self.check_debug_activity()
        self.check_direct_table_access()
        self.check_audit_config_changes()
        self.check_rare_terminals()
        return self.findings

    # ================================================================= plumbing
    @staticmethod
    def _rows(value: Any) -> List[Dict[str, Any]]:
        return [r for r in (value or []) if isinstance(r, dict)]

    @staticmethod
    def _get(row: Dict[str, Any], keys: Tuple[str, ...]) -> str:
        for key in keys:
            val = row.get(key)
            if val is not None and str(val).strip():
                return str(val).strip()
        return ""

    def _is_active(self, row: Dict[str, Any]) -> bool:
        return self._get(row, self.ACTIVE_KEYS).upper() in self.ACTIVE_VALUES

    # ---------------------------------------------------------------- parsing
    _DATE_FORMATS = ("%Y%m%d", "%Y-%m-%d", "%d.%m.%Y", "%Y/%m/%d", "%d-%m-%Y")
    _TIME_FORMATS = ("%H%M%S", "%H:%M:%S", "%H:%M", "%H%M")

    @classmethod
    def _parse_dt(cls, row: Dict[str, Any]) -> Optional[datetime]:
        """Best-effort event timestamp, or None.

        A row we cannot place in time is NOT discarded — it still counts towards
        volume patterns. It is only excluded from the analyses that genuinely need
        an ordering or an hour of day, and the finding says how many rows that was.
        Silently dropping them would understate the window.
        """
        raw = cls._get(row, cls.DATE_KEYS) or cls._get(row, cls.TS_KEYS)
        if not raw:
            return None
        time_part = cls._get(row, cls.TIME_KEYS)
        if not time_part:
            for sep in ("T", " "):
                if sep in raw:
                    raw, time_part = raw.split(sep, 1)
                    break
        raw = raw.strip()
        date_val = None
        for fmt in cls._DATE_FORMATS:
            try:
                date_val = datetime.strptime(raw, fmt)
                break
            except ValueError:
                continue
        if date_val is None:
            return None
        time_part = time_part.strip().split(".")[0].split("+")[0]
        if time_part:
            for fmt in cls._TIME_FORMATS:
                try:
                    parsed = datetime.strptime(time_part, fmt)
                    return date_val.replace(hour=parsed.hour, minute=parsed.minute,
                                            second=parsed.second)
                except ValueError:
                    continue
        return date_val

    @classmethod
    def _normalise_class(cls, raw: str) -> str:
        token = raw.strip().lower().replace(" ", "_").replace("-", "_")
        if not token:
            return ""
        # Failure must win over the generic logon rule, otherwise every failed
        # logon would be classified as a logon and LREV-PAT-002 would see nothing.
        if "logon" in token or "login" in token:
            if any(w in token for w in ("fail", "error", "unsuccessful", "denied", "reject")):
                return "dialog_logon_failure"
            if "rfc" in token or "cpic" in token:
                return "rfc_logon"
            return "dialog_logon"
        for needles, name in cls.CLASS_RULES:
            if any(n in token for n in needles):
                return name
        return ""

    def _classify(self, row: Dict[str, Any]) -> Set[str]:
        """The normalised event classes one log row belongs to.

        Three sources, in order of trust: the export's own class column, the free
        message text, and the transaction code. The message id column (MSGID and
        friends) is deliberately NOT interpreted — we do not hold a verified message
        catalogue, and guessing that some three-character id "means" a failed logon
        would be exactly the kind of fabricated SAP identifier the house rules forbid.
        """
        tags = set()
        explicit = self._normalise_class(self._get(row, self.CLASS_KEYS))
        if explicit:
            tags.add(explicit)

        text = self._get(row, self.TEXT_KEYS).lower()
        failed = any(w in text for w in
                     ("failed", "unsuccessful", "denied", "rejected", "not successful"))
        if "logon" in text or "log on" in text:
            if failed:
                tags.add("dialog_logon_failure")
            elif "rfc" in text or "cpic" in text:
                tags.add("rfc_logon")
            else:
                tags.add("dialog_logon")
        if "debug" in text:
            tags.add("debug")
        if "audit" in text and any(w in text for w in
                                   ("configuration", "config", "filter", "profile")):
            tags.add("audit_config_change")
        if "transaction" in text and "start" in text:
            tags.add("transaction_start")
        if "table" in text:
            tags.add("table_access")

        # An explicit result column overrides a text guess about success/failure. It
        # only ever RE-LABELS a logon we already identified — it never invents a class
        # for a row we could not classify, because "this row succeeded" says nothing
        # about what the row was.
        result = self._get(row, self.RESULT_KEYS).lower()
        if result and ("dialog_logon" in tags or "dialog_logon_failure" in tags):
            if any(w in result for w in ("fail", "error", "denied", "reject", "unsuccess")):
                tags.discard("dialog_logon")
                tags.add("dialog_logon_failure")
            elif any(w in result for w in ("success", "ok", "granted")):
                tags.discard("dialog_logon_failure")
                tags.add("dialog_logon")

        # Transaction codes are used only where the transaction IS the evidence. A row
        # merely carrying a TCODE column is not thereby a transaction-start event, and
        # tagging it as one would put events into a class the log never said they were in.
        tcode = self._get(row, self.TCODE_KEYS).upper()
        if tcode in self.DIRECT_TABLE_TCODES:
            tags.add("table_access")
        if tcode in self.AUDIT_CONFIG_TCODES:
            tags.add("audit_config_change")
        return tags

    # ------------------------------------------------------------- preparation
    def _prepare(self) -> None:
        raw = self._rows(self.data.get("security_audit_log"))
        self._config_rows: List[Dict[str, Any]] = []
        self._raw_events: List[Dict[str, Any]] = []
        for row in raw:
            if self._get(row, self.DATE_KEYS) or self._get(row, self.TS_KEYS):
                self._raw_events.append(row)
            else:
                self._config_rows.append(row)
        # An event-shaped security_audit_log.csv means the filter configuration must
        # come from the fallback export, if the customer sent one.
        if not self._config_rows:
            self._config_rows = self._rows(self.data.get("audit_config"))

        self._audit_log_supplied = bool(raw) or bool(self.data.get("audit_config"))

        self._events: List[Dict[str, Any]] = []
        for row in self._raw_events:
            when = self._parse_dt(row)
            self._events.append({
                "when": when,
                "user": self._get(row, self.USER_KEYS).upper(),
                "client": self._get(row, self.CLIENT_KEYS),
                "terminal": self._get(row, self.TERMINAL_KEYS),
                "tcode": self._get(row, self.TCODE_KEYS).upper(),
                "tags": self._classify(row),
            })
        self._timed = [e for e in self._events if e["when"] is not None]
        self._undated = len(self._events) - len(self._timed)

        moments = sorted(e["when"] for e in self._timed)
        self._window_start = moments[0] if moments else None
        self._window_end = moments[-1] if moments else None
        if self._window_start and self._window_end:
            self._window_days = (self._window_end.date() - self._window_start.date()).days + 1
        else:
            self._window_days = 0

        # Which event classes were ACTIVELY recording, per the filter configuration.
        self._active_classes: Set[str] = set()
        self._static_classes: Set[str] = set()
        self._dynamic_classes: Set[str] = set()
        self._filter_clients: Set[str] = set()
        self._covers_all_clients = False
        for row in self._config_rows:
            cls_name = self._normalise_class(self._get(row, self.CLASS_KEYS))
            raw_class = self._get(row, self.CLASS_KEYS).strip().upper()
            if not self._is_active(row):
                continue
            client = self._get(row, self.CLIENT_KEYS).upper()
            if client in ("*", "ALL"):
                self._covers_all_clients = True
            elif client:
                self._filter_clients.add(client)
            if raw_class == "ALL":
                self._active_classes.add("ALL")
            if not cls_name:
                continue
            self._active_classes.add(cls_name)
            ptype = self._get(row, self.PROFILE_TYPE_KEYS).upper()
            if ptype.startswith("S"):
                self._static_classes.add(cls_name)
            elif ptype.startswith("D"):
                self._dynamic_classes.add(cls_name)

        self._privileged = self._privileged_users()
        self._standard = self._standard_user_names()

    def _privileged_users(self) -> Set[str]:
        """Users holding a standard privileged profile, plus the default accounts."""
        priv = set(self._standard_user_names())
        for row in self._rows(self.data.get("profiles")):
            name = self._get(row, ("BNAME", "USER", "USERNAME")).upper()
            profile = self._get(row, ("PROFILE", "PROFILE_NAME", "PROFN")).upper()
            if name and profile in self.PRIVILEGED_PROFILES:
                priv.add(name)
        return priv

    def _standard_user_names(self) -> Set[str]:
        names = set(self.STANDARD_USERS)
        for row in self._rows(self.data.get("standard_users")):
            name = self._get(row, ("USER", "BNAME", "USERNAME")).upper()
            if name:
                names.add(name)
        return names

    def _class_is_recording(self, name: str) -> bool:
        return "ALL" in self._active_classes or name in self._active_classes

    # ------------------------------------------------------------- the window
    def _short_window(self) -> bool:
        minimum = int(self.get_config("logreview_min_window_days", 30))
        return bool(self._window_days) and self._window_days < minimum

    def _window_note(self) -> str:
        if not self._events:
            return ("No audit-log events were supplied, so no period was reviewed.")
        if not self._timed:
            return ("The extract carries no usable event timestamps, so the reviewed "
                    "period could not be established from the data.")
        minimum = int(self.get_config("logreview_min_window_days", 30))
        span = "{0} to {1}".format(self._window_start.strftime("%Y-%m-%d"),
                                   self._window_end.strftime("%Y-%m-%d"))
        if self._short_window():
            return (
                "The exported window covers only {0} day(s) ({1}), which is below the "
                "{2}-day minimum this review treats as representative. A window this "
                "short reports what happened inside it and nothing more: it cannot "
                "establish what is normal for this system, and the absence of a "
                "pattern in it is not evidence that the pattern does not occur."
            ).format(self._window_days, span, minimum)
        return "The exported window covers {0} day(s) ({1}).".format(self._window_days, span)

    def _details(self, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Every finding carries the reviewed window, so the console can always say
        what period the evidence comes from.

        None of this reaches the fingerprint — `server/identity.py` hashes check id,
        system, client and subject only. That is deliberate and load-bearing: dates
        and counts change with every export, and if they were part of identity each
        upload would retire the previous finding and raise a fresh one with its age
        reset to zero.
        """
        window: Dict[str, Any] = {
            "start": self._window_start.strftime("%Y-%m-%d") if self._window_start else None,
            "end": self._window_end.strftime("%Y-%m-%d") if self._window_end else None,
            "days": self._window_days,
            "events_in_export": len(self._events),
            "events_with_timestamp": len(self._timed),
            "events_without_timestamp": self._undated,
            "short_window": self._short_window(),
            "note": self._window_note(),
        }
        out: Dict[str, Any] = {
            "review_mode": "retrospective review over the exported window",
            "reviewed_window": window,
        }
        if extra:
            out.update(extra)
        return out

    def _with_window(self, text: str) -> str:
        """Append the window statement to a finding description.

        Descriptions are excluded from identity, so varying text here is safe — and
        a retrospective finding that does not state its period is unreadable.
        """
        return "{0} {1}".format(text.rstrip(), self._window_note())

    @staticmethod
    def _user_objects(names) -> List[Dict[str, Any]]:
        """Graph nodes for the accounts a pattern names.

        No client on the node: the rest of the estate emits `user` nodes without one,
        and stamping a client here would split one account into a different node from
        the same account named by the authorization modules — the graph would stop
        joining exactly where a reviewer wants it to join. No qualifier either: the
        occurrence counts are the finding's evidence, not the account's identity, and
        a count in the key would mint a new node on every export.
        """
        return [{"type": "user", "name": n} for n in sorted(names) if n]

    # ====================================================== half 1: log health
    def check_event_extract_supplied(self):
        """No events in the upload means no retrospective review was possible.

        Fires only when SOME audit-log export arrived and it turned out to be the
        filter configuration — i.e. we know the customer can produce the extract.
        When nothing at all was supplied, `log_monitoring.LOG-AUD-001` already says
        so and repeating it would be noise.
        """
        if self._events or not self._audit_log_supplied:
            return
        self.finding(
            check_id="LREV-SRC-001",
            title="No Security Audit Log event extract supplied — no window could be reviewed",
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=(
                "The upload contains the Security Audit Log filter CONFIGURATION but no "
                "event extract, so the retrospective review could only assess whether the "
                "log was capturing — not what it captured. The configuration half of this "
                "module ran; the pattern half had nothing to read. Without an event export "
                "no statement can be made about privileged access outside business hours, "
                "failed-logon runs that ended in a success, standard-account use, debug "
                "activity, direct table access or changes to the audit configuration itself."
            ),
            affected_items=[
                "security_audit_log.csv: {0} filter configuration row(s), 0 event row(s)".format(
                    len(self._config_rows)),
            ],
            # Nothing is named because the defect is an ABSENT export; inventing an
            # object would fabricate a graph node the upload does not contain.
            # Aggregate keeps identity on (system, client, check_id) so the gap holds
            # its age until an extract actually arrives.
            scope="aggregate",
            details=self._details({"config_rows": len(self._config_rows)}),
            remediation=(
                "Export the Security Audit Log for the period to be reviewed (SM20 / "
                "RSAU_READ_LOG, download the result list) and include it in the upload as "
                "security_audit_log.csv. Useful columns: date, time, client, user, "
                "terminal, transaction code, audit/event class and message text. A 90-day "
                "window is a reasonable first review; anything under 30 days cannot show "
                "what is normal for the system."
            ),
            references=[
                "SAP Note 2191612 — Security Audit Log",
                "SAP Security Baseline — Security Audit Log evaluation",
                "NIST SP 800-92 — Guide to Computer Security Log Management",
            ],
        )

    def check_event_timestamps_usable(self):
        """An extract without a parsable date is a broken export, not a clean system."""
        if not self._events or self._timed:
            return
        self.finding(
            check_id="LREV-SRC-002",
            title="Audit log extract carries no usable event timestamp",
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=(
                "{0} audit-log event row(s) were supplied but none carries a date this "
                "review can read, so the reviewed period cannot be established and every "
                "time-dependent pattern was skipped: business-hours analysis, ordered "
                "failed-logon runs and the window statement itself. Reporting a clean "
                "result from this data would be reporting a parsing failure as a good "
                "outcome."
            ).format(len(self._events)),
            affected_items=[
                "{0} event row(s) with no readable date column".format(len(self._events)),
            ],
            scope="aggregate",
            details=self._details({"unreadable_rows": len(self._events)}),
            remediation=(
                "Re-export the audit log with the date and time columns included and in an "
                "unambiguous format (YYYYMMDD or YYYY-MM-DD with HH:MM:SS). A spreadsheet "
                "round-trip commonly reformats or drops these columns — export to CSV "
                "directly from the download list rather than via a saved workbook."
            ),
            references=["SAP Note 2191612 — Security Audit Log"],
        )

    def check_filter_config_supplied(self):
        """Events without the filter configuration: the patterns run, but the review
        cannot say which questions the window was capable of answering."""
        if not self._events or self._config_rows:
            return
        self.finding(
            check_id="LREV-SRC-003",
            title="Audit filter configuration not supplied alongside the event extract",
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=self._with_window(
                "An audit-log event extract was reviewed, but no filter configuration was "
                "supplied with it. The patterns below therefore report what the window "
                "CONTAINS, with no way to state what the window was CAPABLE of containing. "
                "That distinction is the difference between 'no direct table access "
                "occurred' and 'direct table access was never being recorded', and without "
                "the filter configuration this review cannot tell the two apart."
            ),
            affected_items=[
                "{0} event row(s) reviewed with no filter configuration to interpret them "
                "against".format(len(self._events)),
            ],
            scope="aggregate",
            details=self._details({"event_rows": len(self._events)}),
            remediation=(
                "Include the audit filter configuration (SM19 / RSAU_CONFIG) in the upload "
                "as audit_config.csv, with one row per filter: filter name, event/audit "
                "class, active flag, static or dynamic, and client."
            ),
            references=["SAP Note 2191612 — Security Audit Log"],
        )

    def check_inactive_filters(self):
        """A filter that exists and is switched off.

        Distinct from `log_monitoring.LOG-AUD-003`, which reports event classes absent
        from the configuration ALTOGETHER. This one names a filter somebody defined and
        somebody then deactivated: a concrete object, a deliberate act and a one-line
        fix. One finding per filter — deactivated filters are independent defects and
        must not collapse into one, exactly as four unlocked default users are four
        findings.
        """
        for row in self._config_rows:
            if self._is_active(row):
                continue
            name = self._get(row, self.FILTER_NAME_KEYS)
            if not name:
                continue
            raw_class = self._get(row, self.CLASS_KEYS) or "(not stated)"
            client = self._get(row, self.CLIENT_KEYS)
            ptype = self._get(row, self.PROFILE_TYPE_KEYS) or "(not stated)"
            self.finding(
                check_id="LREV-FLT-001",
                title="Audit filter '{0}' is defined but switched off".format(name),
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    "Audit filter '{0}' exists in the Security Audit Log configuration for "
                    "event class '{1}' but is not active, so no event of that class is being "
                    "written. Somebody defined this filter deliberately and it is now off — "
                    "which is a different situation from a class that was never configured, "
                    "and a materially worse one: the configuration reads as though the class "
                    "is covered. Any retrospective review of a window in which this filter "
                    "was inactive cannot report on that class at all."
                ).format(name, raw_class),
                affected_items=[
                    "{0}: class={1}, type={2}, client={3}, active=no".format(
                        name, raw_class, ptype, client or "(not stated)"),
                ],
                # The filter IS the defect, so it is the subject and identity includes
                # it. Client participates because the same filter name in two clients is
                # two filters. No qualifier: the class and profile type are attributes we
                # display, and folding a changeable attribute into the key would re-mint
                # the finding the moment somebody edited the filter instead of enabling it.
                affected_objects=[{"type": "audit_filter", "name": name,
                                   "client": client or None}],
                scope="object",
                details=self._details({
                    "filter": name,
                    "event_class": raw_class,
                    "profile_type": ptype,
                    "client": client or None,
                }),
                remediation=(
                    "Activate the filter in SM19 / RSAU_CONFIG, or delete it if the class is "
                    "genuinely not required — an inactive filter left in place misrepresents "
                    "the coverage of the whole configuration. Confirm events appear "
                    "afterwards via SM20 / RSAU_READ_LOG."
                ),
                references=[
                    "SAP Note 2191612 — Security Audit Log",
                    "SAP Security Baseline — Security Audit Log configuration",
                ],
            )

    def check_filter_client_coverage(self):
        """Active filters bound to some clients leave the others unrecorded.

        Not covered anywhere else: `log_monitoring` never reads the filter's client.
        The gap matters most where it is easiest to miss — the SAP-delivered default
        accounts live in the technical clients, so an audit configuration scoped to the
        production client alone records nothing about them.
        """
        if not self._config_rows or self._covers_all_clients or not self._filter_clients:
            return
        clients = set()
        for row in self._rows(self.data.get("client_settings")):
            client = self._get(row, ("CLIENT", "MANDT", "CLIENT_ID"))
            if client:
                clients.add(client)
        if not clients:
            return
        uncovered = sorted(c for c in clients if c not in self._filter_clients)
        if not uncovered:
            return
        self.finding(
            check_id="LREV-FLT-002",
            title="Audit filters do not cover every client in the system",
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=(
                "{0} of the {1} client(s) in this system are not covered by any active audit "
                "filter: {2}. Nothing that happens in those clients is written to the "
                "Security Audit Log, so a retrospective review of any window can say nothing "
                "about them — including about the SAP-delivered default accounts, which "
                "reside in the technical clients rather than the production one. The active "
                "filters cover client(s) {3}."
            ).format(len(uncovered), len(clients), ", ".join(uncovered),
                     ", ".join(sorted(self._filter_clients))),
            affected_items=["Client {0}: no active audit filter".format(c) for c in uncovered],
            # Clients are real named objects and belong in the graph, but this is ONE
            # defect with ONE fix — the filters are scoped too narrowly, and the usual
            # remediation (set the filter client to '*') closes every member at once.
            # Aggregate so that covering one client shrinks the member list rather than
            # retiring the finding and resetting its age.
            affected_objects=[{"type": "client", "name": c} for c in uncovered],
            scope="aggregate",
            details=self._details({
                "uncovered_clients": uncovered,
                "covered_clients": sorted(self._filter_clients),
            }),
            remediation=(
                "Set the client field of the audit filters to '*' so every client is "
                "recorded, or add an explicit active filter per client. Client 000 and any "
                "other technical client must be included — the SAP-delivered default "
                "accounts sign on there."
            ),
            references=[
                "SAP Note 2191612 — Security Audit Log",
                "SAP Security Baseline — Security Audit Log configuration",
            ],
        )

    def check_dynamic_only_classes(self):
        """A class recorded only by a dynamic filter stops recording at the next restart.

        `log_monitoring.LOG-AUD-002` asks whether ANY static profile exists; it passes
        as soon as one does. That cannot see a class whose only coverage is dynamic,
        which is the case that actually bites: the configuration looks complete, the
        system restarts, and that class silently stops being written — so the next
        retrospective review covers a window with a hole in it that nothing announces.
        """
        if not self._config_rows:
            return
        dynamic_only = sorted(self._dynamic_classes - self._static_classes)
        if not dynamic_only:
            return
        self.finding(
            check_id="LREV-FLT-003",
            title="Event class recorded only by a dynamic filter — coverage is lost at restart",
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=(
                "{0} event class(es) are recorded only by a dynamic audit filter: {1}. "
                "Dynamic filters apply until the next system restart and are not "
                "reactivated automatically, so after the next restart these classes stop "
                "being written while the configuration continues to list them. A "
                "retrospective review of a window that spans a restart would then report "
                "no events of these classes without anything indicating why."
            ).format(len(dynamic_only), ", ".join(dynamic_only)),
            affected_items=[
                "{0}: dynamic filter only, no static coverage".format(c) for c in dynamic_only
            ],
            # Aggregate over the classes: giving one of them a static filter narrows the
            # gap without closing it, and no object is named because the members are
            # event CLASSES — a vocabulary, not objects the export contains.
            scope="aggregate",
            details=self._details({
                "dynamic_only_classes": dynamic_only,
                "static_classes": sorted(self._static_classes),
            }),
            remediation=(
                "Move these classes into a static audit profile in SM19 / RSAU_CONFIG so "
                "they are activated automatically at system start. Keep dynamic filters for "
                "temporary, targeted investigations only."
            ),
            references=[
                "SAP Note 2191612 — Security Audit Log (static vs dynamic profiles)",
                "SAP Security Baseline — Security Audit Log configuration",
            ],
        )

    # ================================================ half 2: the exported window
    def check_window_length(self):
        """Say plainly when the reviewed window is too short to carry conclusions."""
        if not self._timed or not self._short_window():
            return
        minimum = int(self.get_config("logreview_min_window_days", 30))
        self.finding(
            check_id="LREV-WIN-001",
            title="Reviewed window is too short to be representative",
            severity=self.SEVERITY_LOW,
            category=self.CATEGORY,
            description=self._with_window(
                "The retrospective review covered a window shorter than the {0}-day minimum "
                "this review treats as representative. Every pattern below is still a real "
                "observation about the period supplied, but a short window carries no "
                "baseline: a quiet week says nothing about the other fifty-one, and a "
                "pattern that did not appear may simply not have appeared yet. Read the "
                "findings as evidence about this window only."
            ).format(minimum),
            affected_items=[
                "Reviewed window: {0} day(s), {1} event(s)".format(
                    self._window_days, len(self._events)),
            ],
            # No object: the window is a property of the upload, not of the SAP system.
            scope="aggregate",
            details=self._details({"minimum_window_days": minimum}),
            remediation=(
                "Re-export the Security Audit Log over a longer period — 90 days is a "
                "reasonable first review and lets month-end and quarter-end activity appear "
                "at least once. Check the retention configured for the audit log before "
                "requesting the range; a window longer than retention returns only the part "
                "that still exists."
            ),
            references=["NIST SP 800-92 — Guide to Computer Security Log Management"],
        )

    def check_window_blind_spots(self):
        """WHICH QUESTIONS THIS WINDOW CANNOT ANSWER.

        The credibility centrepiece. Every retrospective pattern depends on an event
        class; if that class was not being recorded, the pattern finding nothing is not
        a clean result, it is no result. Saying so — precisely, per pattern — is the
        difference between a review a customer can rely on and one that flatters them.

        Deliberately narrower than `log_monitoring.LOG-AUD-003`, which is a
        configuration-completeness check against the required class list. This one
        fires only when a review actually ran, and reports the review's own blind spots.
        """
        if not self._events or not self._config_rows:
            return
        blind = []
        for check_id, (needed, question) in self.PATTERN_CLASS_REQUIREMENTS.items():
            if not self._class_is_recording(needed):
                blind.append((check_id, needed, question))
        if not blind:
            return
        self.finding(
            check_id="LREV-WIN-002",
            title="The reviewed window cannot answer {0} of the review's questions".format(
                len(blind)),
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=self._with_window(
                "{0} of the retrospective patterns depend on an event class that was not "
                "active in the audit filter configuration, so the exported window could not "
                "have contained the evidence they look for. For these questions a nil "
                "result means the log was not recording — it does NOT mean the activity did "
                "not happen. Treat them as unanswered rather than as clean."
            ).format(len(blind)),
            affected_items=[
                "{0}: '{1}' cannot be answered — event class '{2}' was not being recorded".format(
                    cid, question, needed) for cid, needed, question in blind
            ],
            # Aggregate over the unanswerable questions: activating one class narrows the
            # blind spot without closing it. No object — the members are event classes
            # that were NOT configured, which is precisely what the export does not name.
            scope="aggregate",
            details=self._details({
                "unanswerable": [{"check_id": c, "event_class": n, "question": q}
                                 for c, n, q in blind],
                "recording_classes": sorted(self._active_classes),
            }),
            remediation=(
                "Activate audit filters for the listed event classes in SM19 / RSAU_CONFIG, "
                "let them run for a full review period, then re-export. Until then, record "
                "these questions as unanswered in the review report rather than as passed."
            ),
            references=[
                "SAP Note 2191612 — Security Audit Log",
                "SAP Security Baseline — Security Audit Log evaluation",
                "NIST SP 800-92 — Guide to Computer Security Log Management",
            ],
        )

    # ----------------------------------------------------------- the patterns
    def check_offhours_privileged_logons(self):
        """Privileged DIALOG logons outside business hours.

        Dialog only, on purpose: an RFC or batch account signing on at 03:00 is its job,
        and reporting it would bury the one case that matters — a human privileged
        account signing on when no human is meant to be working.
        """
        if not self._timed:
            return
        start_h = int(self.get_config("logreview_business_hour_start", 7))
        end_h = int(self.get_config("logreview_business_hour_end", 19))
        by_user: Dict[str, int] = {}
        weekend = 0
        for ev in self._timed:
            user = ev["user"]
            if not user or user not in self._privileged:
                continue
            if "dialog_logon" not in ev["tags"]:
                continue
            hour = ev["when"].hour
            off_hour = hour < start_h or hour >= end_h
            off_day = ev["when"].weekday() >= 5
            if off_hour or off_day:
                by_user[user] = by_user.get(user, 0) + 1
                if off_day:
                    weekend += 1
        if not by_user:
            return
        total = sum(by_user.values())
        self.finding(
            check_id="LREV-PAT-001",
            title="Privileged dialog logons outside business hours in the reviewed window",
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=self._with_window(
                "{0} privileged dialog logon(s) by {1} account(s) occurred outside business "
                "hours ({2:02d}:00-{3:02d}:00, Monday to Friday) during the reviewed window; "
                "{4} of them fell on a weekend. Privileged access at a time when no business "
                "process requires it is the single most common signal of both credential "
                "misuse and unapproved administrative change, and each occurrence should be "
                "matched to an approved change or incident ticket."
            ).format(total, len(by_user), start_h, end_h, weekend),
            affected_items=[
                "{0}: {1} out-of-hours dialog logon(s)".format(u, n)
                for u, n in sorted(by_user.items(), key=lambda kv: (-kv[1], kv[0]))
            ],
            # ONE pattern, aggregated: the accounts are members and graph nodes, never
            # identity. Per-account identity would raise and resolve findings as people's
            # working hours changed, and the occurrence counts must stay out of the key
            # entirely or every export would re-mint the finding.
            affected_objects=self._user_objects(by_user),
            scope="aggregate",
            details=self._details({
                "occurrences": total,
                "accounts": len(by_user),
                "weekend_occurrences": weekend,
                "business_hours": "{0:02d}:00-{1:02d}:00".format(start_h, end_h),
                "per_account": by_user,
            }),
            remediation=(
                "Reconcile each out-of-hours privileged logon against an approved change or "
                "incident record. Where privileged work genuinely happens out of hours, "
                "route it through a firefighter / emergency-access process so it is "
                "pre-approved and logged as such, rather than through standing privileges."
            ),
            references=[
                "SAP Security Baseline — privileged access review",
                "SOX ITGC — privileged access review",
            ],
        )

    def check_failure_run_then_success(self):
        """A run of failed logons that ended in a success.

        Different evidence from `log_monitoring.LOG-LOGON-001`, which works from the
        aggregate per-user counters in logon_events.csv and reports accounts under
        pressure. This works from the ORDERED event stream and reports the outcome that
        actually matters: the guessing stopped because it worked.
        """
        if not self._timed:
            return
        threshold = int(self.get_config("logreview_failure_run_threshold", 5))
        per_user: Dict[str, List[Dict[str, Any]]] = {}
        for ev in self._timed:
            if not ev["user"]:
                continue
            if "dialog_logon" in ev["tags"] or "dialog_logon_failure" in ev["tags"] \
                    or "rfc_logon" in ev["tags"]:
                per_user.setdefault(ev["user"], []).append(ev)

        episodes: Dict[str, Dict[str, int]] = {}
        for user, evs in per_user.items():
            evs.sort(key=lambda e: e["when"])
            run = 0
            for ev in evs:
                if "dialog_logon_failure" in ev["tags"]:
                    run += 1
                    continue
                if run >= threshold:
                    rec = episodes.setdefault(user, {"episodes": 0, "longest_run": 0})
                    rec["episodes"] += 1
                    rec["longest_run"] = max(rec["longest_run"], run)
                run = 0
        if not episodes:
            return

        # Corroborate against the aggregate counters when they were supplied. They are
        # a different export of the same reality; agreeing strengthens the finding and
        # disagreeing is worth stating rather than hiding.
        aggregate_failures: Dict[str, int] = {}
        for row in self._rows(self.data.get("logon_events")):
            user = self._get(row, ("USERNAME", "BNAME", "USER")).upper()
            event = self._get(row, ("EVENT", "TYPE", "LOGON_TYPE")).upper()
            try:
                count = int(self._get(row, ("COUNT", "OCCURRENCES")) or "1")
            except ValueError:
                count = 1
            if user and ("FAIL" in event or "ERROR" in event or event in ("F", "0")):
                aggregate_failures[user] = aggregate_failures.get(user, 0) + count

        items = []
        for user, rec in sorted(episodes.items(), key=lambda kv: (-kv[1]["longest_run"], kv[0])):
            line = ("{0}: {1} episode(s) of {2}+ consecutive failed logons ending in a "
                    "success (longest run {3})").format(
                user, rec["episodes"], threshold, rec["longest_run"])
            if user in aggregate_failures:
                line += "; {0} total failures in logon_events.csv".format(
                    aggregate_failures[user])
            items.append(line)

        self.finding(
            check_id="LREV-PAT-002",
            title="Failed logon run followed by a successful logon in the reviewed window",
            severity=self.SEVERITY_CRITICAL,
            category=self.CATEGORY,
            description=self._with_window(
                "{0} account(s) show at least {1} consecutive failed logons immediately "
                "followed by a successful one during the reviewed window. Read in order, "
                "that sequence is the signature of password guessing that ended because it "
                "worked — materially different from a high failure count alone, which is "
                "usually an expired password or a misconfigured service account. Each "
                "episode needs to be reconciled with the account owner before the session "
                "that followed it is assumed legitimate."
            ).format(len(episodes), threshold),
            affected_items=items,
            # Aggregate: one finding per pattern. Locking one account must shrink the
            # membership, not retire the finding and restart its age in the middle of an
            # investigation. The run lengths stay in details, never in identity.
            affected_objects=self._user_objects(episodes),
            scope="aggregate",
            details=self._details({
                "threshold": threshold,
                "accounts": len(episodes),
                "per_account": episodes,
                "corroborated_by_logon_events": sorted(
                    set(episodes) & set(aggregate_failures)),
            }),
            remediation=(
                "Confirm with each account owner whether they were the one who eventually "
                "signed on. If not, treat the session as a compromise: reset the "
                "credential, review what the session did in the same window, and check "
                "whether the account lock policy (login/fails_to_user_lock) is set tightly "
                "enough to have stopped the run earlier."
            ),
            references=[
                "SAP Security Baseline — logon security and account lockout",
                "NIST SP 800-92 — Guide to Computer Security Log Management",
            ],
        )

    def check_standard_user_activity(self):
        """Any activity by an SAP-delivered default account in the window."""
        if not self._events:
            return
        by_user: Dict[str, int] = {}
        tcodes: Dict[str, Set[str]] = {}
        for ev in self._events:
            user = ev["user"]
            if user and user in self._standard:
                by_user[user] = by_user.get(user, 0) + 1
                if ev["tcode"]:
                    tcodes.setdefault(user, set()).add(ev["tcode"])
        if not by_user:
            return
        total = sum(by_user.values())
        items = []
        for user, count in sorted(by_user.items(), key=lambda kv: (-kv[1], kv[0])):
            line = "{0}: {1} event(s)".format(user, count)
            seen = sorted(tcodes.get(user, ()))
            if seen:
                line += "; transactions: {0}".format(", ".join(seen[:8]))
            items.append(line)
        self.finding(
            check_id="LREV-PAT-003",
            title="SAP-delivered default accounts were active in the reviewed window",
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=self._with_window(
                "{0} event(s) in the reviewed window were carried out by {1} SAP-delivered "
                "default account(s): {2}. These accounts are shared, are frequently exempt "
                "from the password policy and cannot be attributed to a person, so anything "
                "they did in this window is unattributable by construction — no reviewer can "
                "say afterwards who performed it. Their use in a production window is "
                "normally limited to a small number of documented Basis operations."
            ).format(total, len(by_user), ", ".join(sorted(by_user))),
            affected_items=items,
            # Aggregate: one finding for the pattern, the accounts as members. The
            # per-account defect ("SAP* is unlocked with a default password") belongs to
            # the system-trust module and is identified there; this finding is about
            # OBSERVED USE in an exported window and must not compete with it for identity.
            affected_objects=self._user_objects(by_user),
            scope="aggregate",
            details=self._details({
                "occurrences": total,
                "accounts": sorted(by_user),
                "per_account": by_user,
                "transactions_seen": {u: sorted(t) for u, t in tcodes.items()},
            }),
            remediation=(
                "Establish for each occurrence which person was at the keyboard and why a "
                "named account could not be used. Lock the default accounts, give them a "
                "generated password held in a break-glass safe, and route any genuine need "
                "through a firefighter / emergency-access process that records the person."
            ),
            references=[
                "SAP Security Baseline — protection of standard users",
                "SOX ITGC — accountability and attribution of privileged actions",
            ],
        )

    def check_debug_activity(self):
        """Debug activity in the window.

        In a productive system the ABAP debugger reads and can change data outside the
        application's own authorization checks, so debug activity is one of the few
        events that is worth reviewing individually.
        """
        if not self._events:
            return
        by_user: Dict[str, int] = {}
        for ev in self._events:
            if "debug" in ev["tags"]:
                by_user[ev["user"] or "(user not stated)"] = \
                    by_user.get(ev["user"] or "(user not stated)", 0) + 1
        if not by_user:
            return
        total = sum(by_user.values())
        named = {u for u in by_user if u != "(user not stated)"}
        self.finding(
            check_id="LREV-PAT-004",
            title="Debug activity recorded in the reviewed window",
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=self._with_window(
                "{0} debug event(s) by {1} account(s) appear in the reviewed window. The "
                "ABAP debugger reads and — with the change authorization — modifies data "
                "and program state outside the checks the application itself performs, so a "
                "debug session in a productive client is an authorization bypass whether or "
                "not it was intended as one. Each session should correspond to an approved "
                "incident or change record."
            ).format(total, len(by_user)),
            affected_items=[
                "{0}: {1} debug event(s)".format(u, n)
                for u, n in sorted(by_user.items(), key=lambda kv: (-kv[1], kv[0]))
            ],
            # Aggregate over the pattern; accounts ride along as members and nodes. The
            # placeholder used when the export omits the user is deliberately NOT turned
            # into a graph node — see _user_objects, which is fed only the named accounts.
            affected_objects=self._user_objects(named),
            scope="aggregate",
            details=self._details({
                "occurrences": total,
                "accounts": sorted(by_user),
                "per_account": by_user,
            }),
            remediation=(
                "Reconcile each debug session with an approved incident or change record. "
                "Remove debug-change authorization from productive clients and grant debug "
                "display only through a time-boxed emergency-access process."
            ),
            references=[
                "SAP Security Baseline — debugging in productive systems",
                "SOX ITGC — change control over production data",
            ],
        )

    def check_direct_table_access(self):
        """Direct and high-volume table access in the window."""
        if not self._events:
            return
        threshold = int(self.get_config("logreview_table_access_threshold", 50))
        by_user: Dict[str, int] = {}
        tools: Set[str] = set()
        for ev in self._events:
            if "table_access" not in ev["tags"]:
                continue
            if ev["user"]:
                by_user[ev["user"]] = by_user.get(ev["user"], 0) + 1
            if ev["tcode"] in self.DIRECT_TABLE_TCODES:
                tools.add(ev["tcode"])
        heavy = {u: n for u, n in by_user.items() if n >= threshold}
        if not heavy:
            return
        total = sum(heavy.values())
        self.finding(
            check_id="LREV-PAT-005",
            title="High-volume direct table access in the reviewed window",
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=self._with_window(
                "{0} account(s) each performed {1} or more direct table-access events during "
                "the reviewed window ({2} in total{3}). Direct table access bypasses the "
                "field-level and organisational restrictions built into the business "
                "transactions, so a high volume of it is the shape bulk data extraction "
                "takes in an SAP system — and it is equally often a report that should have "
                "been built properly. Both readings are worth resolving."
            ).format(len(heavy), threshold, total,
                     "; via " + ", ".join(sorted(tools)) if tools else ""),
            affected_items=[
                "{0}: {1} table-access event(s)".format(u, n)
                for u, n in sorted(heavy.items(), key=lambda kv: (-kv[1], kv[0]))
            ],
            # Aggregate. The counts are evidence and stay in details: a per-account
            # identity carrying a volume would churn on every export by construction.
            affected_objects=self._user_objects(heavy),
            scope="aggregate",
            details=self._details({
                "threshold": threshold,
                "occurrences": total,
                "accounts": sorted(heavy),
                "per_account": heavy,
                "transactions_seen": sorted(tools),
            }),
            remediation=(
                "Establish the business reason for each account's direct table access. Where "
                "it is recurring reporting, replace it with a report or CDS view carrying "
                "the proper authorization checks, then withdraw the direct table display "
                "authorization from the account."
            ),
            references=[
                "SAP Security Baseline — restriction of direct table access",
                "SOX ITGC — segregation of duties and data access review",
            ],
        )

    def check_audit_config_changes(self):
        """Changes to the audit configuration itself during the window.

        Ranked above every other pattern: an attacker who can change what is recorded
        does not need to evade what is recorded, and this is the one change that
        retroactively devalues the rest of the review.
        """
        if not self._events:
            return
        by_user: Dict[str, int] = {}
        when: List[str] = []
        for ev in self._events:
            if "audit_config_change" not in ev["tags"]:
                continue
            by_user[ev["user"] or "(user not stated)"] = \
                by_user.get(ev["user"] or "(user not stated)", 0) + 1
            if ev["when"] is not None:
                when.append(ev["when"].strftime("%Y-%m-%d %H:%M:%S"))
        if not by_user:
            return
        total = sum(by_user.values())
        named = {u for u in by_user if u != "(user not stated)"}
        self.finding(
            check_id="LREV-PAT-006",
            title="The audit configuration itself was changed during the reviewed window",
            severity=self.SEVERITY_CRITICAL,
            category=self.CATEGORY,
            description=self._with_window(
                "{0} change(s) to the Security Audit Log configuration by {1} account(s) "
                "appear in the reviewed window. A change to what the log records is the one "
                "change that devalues every other finding in this review: activity after a "
                "filter was switched off is simply absent, and absence here cannot be "
                "distinguished from good behaviour. Establish what was changed, by whom and "
                "under which approval before relying on the rest of the window."
            ).format(total, len(by_user)),
            affected_items=[
                "{0}: {1} audit configuration change event(s)".format(u, n)
                for u, n in sorted(by_user.items(), key=lambda kv: (-kv[1], kv[0]))
            ],
            # Aggregate over the pattern. Occurrence timestamps are listed in details as
            # evidence and are deliberately kept out of identity — putting an event time
            # in the key would mint a new finding on every single export.
            affected_objects=self._user_objects(named),
            scope="aggregate",
            details=self._details({
                "occurrences": total,
                "accounts": sorted(by_user),
                "per_account": by_user,
                "occurred_at": sorted(when)[:50],
            }),
            remediation=(
                "Reconstruct each change from the audit configuration history and match it "
                "to an approved change record. Restrict the authorization to maintain the "
                "audit configuration to a small, named Basis group separate from the "
                "administrators whose activity the log records, and re-review the window "
                "either side of each change."
            ),
            references=[
                "SAP Note 2191612 — Security Audit Log",
                "SAP Security Baseline — protection of the audit trail",
                "SOX ITGC — log integrity and chain of custody",
            ],
        )

    def check_rare_terminals(self):
        """Privileged or default accounts signing on from terminals that barely appear.

        Honest about what it is: a WITHIN-WINDOW relative measure. We hold no history
        before the export, so "unexpected" here means "rare inside the window you gave
        us", not "new relative to a baseline". Stated that way in the finding too — a
        reviewer who thinks this is baselined would over-trust it.
        """
        if not self._events:
            return
        max_events = int(self.get_config("logreview_rare_terminal_max_events", 3))
        totals: Dict[str, int] = {}
        for ev in self._events:
            if ev["terminal"]:
                totals[ev["terminal"]] = totals.get(ev["terminal"], 0) + 1
        if not totals:
            return
        pairs: Dict[str, Set[str]] = {}
        for ev in self._events:
            terminal, user = ev["terminal"], ev["user"]
            if not terminal or not user:
                continue
            if user not in self._privileged:
                continue
            if "dialog_logon" not in ev["tags"]:
                continue
            if totals.get(terminal, 0) <= max_events:
                pairs.setdefault(user, set()).add(terminal)
        if not pairs:
            return
        rare_terminals = sorted({t for ts in pairs.values() for t in ts})
        self.finding(
            check_id="LREV-PAT-007",
            title="Privileged logons from terminals that barely appear in the reviewed window",
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=self._with_window(
                "{0} privileged account(s) signed on from {1} terminal(s) that account for "
                "{2} event(s) or fewer across the whole exported window. This is a "
                "within-window comparison and nothing more: the review holds no history "
                "from before the export, so 'rare' means rare relative to this window, not "
                "new relative to a baseline. Read it as a short list worth asking about — a "
                "privileged sign-on from a workstation that appears once is either a "
                "laptop, a jump host or somebody else's machine."
            ).format(len(pairs), len(rare_terminals), max_events),
            affected_items=[
                "{0}: {1}".format(u, ", ".join(sorted(ts)))
                for u, ts in sorted(pairs.items())
            ],
            # Accounts are the graph nodes. Terminals stay display-only on purpose: the
            # terminal string in an audit extract is whatever the front end reported —
            # a hostname, an IP, or blank — it is not an object under configuration
            # control, and minting graph nodes for it would fill the graph with entities
            # nobody can resolve or remediate.
            affected_objects=self._user_objects(pairs),
            scope="aggregate",
            details=self._details({
                "rare_terminal_max_events": max_events,
                "accounts": sorted(pairs),
                "rare_terminals": rare_terminals,
                "per_account": {u: sorted(ts) for u, ts in pairs.items()},
            }),
            remediation=(
                "Confirm with each account owner that the terminal was theirs. Where "
                "privileged administration is meant to happen only from managed jump hosts, "
                "enforce it at the network layer rather than relying on review, and re-run "
                "this review over a longer window so 'rare' becomes a meaningful measure."
            ),
            references=[
                "SAP Security Baseline — privileged access review",
                "NIST SP 800-92 — Guide to Computer Security Log Management",
            ],
        )
