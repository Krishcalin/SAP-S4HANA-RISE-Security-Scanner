# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""Tests for the Security Audit Log retrospective review (modules/log_review.py).

Three things are being defended here, in order of how expensive they are to get wrong:

1. IDENTITY. A log-derived finding must not carry a timestamp, a window or an
   occurrence count in its identity. If it did, every export would retire the previous
   finding and raise a fresh one with its age reset — the mitigation journey would be
   silently worthless for this whole capability. `test_identity_survives_a_new_export`
   is the one that must never be weakened.

2. WORDING. The capability is a retrospective review over an exported window. It is
   not monitoring, not detection, not real-time, and no finding may say otherwise.

3. The two halves themselves: log-source health from the filter configuration, and the
   patterns over the exported window.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.log_review import LogReviewAuditor  # noqa: E402


# ── fixtures ────────────────────────────────────────────────────────────────────

# The SM19 / RSAU_CONFIG filter configuration shape, as sample_data ships it.
CONFIG = [
    {"CONFIG_NAME": "Dialog_Logon_Filter", "EVENT_CLASS": "dialog_logon",
     "ACTIVE": "ACTIVE", "PROFILE_TYPE": "STATIC", "CLIENT": "100"},
    {"CONFIG_NAME": "Failed_Logon_Filter", "EVENT_CLASS": "dialog_logon_failure",
     "ACTIVE": "ACTIVE", "PROFILE_TYPE": "STATIC", "CLIENT": "100"},
    {"CONFIG_NAME": "Table_Access_Filter", "EVENT_CLASS": "table_access",
     "ACTIVE": "ACTIVE", "PROFILE_TYPE": "STATIC", "CLIENT": "100"},
    {"CONFIG_NAME": "Audit_Config_Filter", "EVENT_CLASS": "audit_config_change",
     "ACTIVE": "ACTIVE", "PROFILE_TYPE": "STATIC", "CLIENT": "100"},
]

PROFILES = [
    {"BNAME": "JSMITH", "PROFILE": "SAP_ALL"},
    {"BNAME": "DLEE", "PROFILE": "SAP_NEW"},
    {"BNAME": "CLERK", "PROFILE": "Z_SD_USER"},
]


def _ev(date, time, user, **kw):
    row = {"DATE": date, "TIME": time, "USER": user, "CLIENT": "100"}
    row.update(kw)
    return row


def _events(day_offset=0, repeat=1):
    """A synthetic SM20 / RSAU_READ_LOG extract that triggers every pattern.

    `day_offset` shifts the whole window and `repeat` multiplies the occurrence
    counts — the two knobs the identity test turns to prove neither reaches the
    fingerprint.
    """
    def d(day):
        return "2026-0{0}-{1:02d}".format(1 + (day + day_offset) // 28,
                                          1 + (day + day_offset) % 28)

    rows = []
    for _ in range(repeat):
        # PAT-001: privileged dialog logon at 02:30 — outside business hours.
        rows.append(_ev(d(0), "02:30:00", "JSMITH", TERMINAL="WS-01",
                        EVENT_CLASS="dialog_logon", TEXT="Logon successful"))
        # PAT-002: a run of failures ending in a success.
        for i in range(6):
            rows.append(_ev(d(1), "09:0{0}:00".format(i), "CLERK", TERMINAL="WS-02",
                            EVENT_CLASS="dialog_logon_failure",
                            TEXT="Logon failed"))
        rows.append(_ev(d(1), "09:30:00", "CLERK", TERMINAL="WS-02",
                       EVENT_CLASS="dialog_logon", TEXT="Logon successful"))
        # PAT-003: an SAP-delivered default account was active.
        rows.append(_ev(d(2), "11:00:00", "DDIC", TERMINAL="WS-03",
                       EVENT_CLASS="dialog_logon", TEXT="Logon successful"))
        # PAT-004: debug activity.
        rows.append(_ev(d(3), "14:00:00", "DLEE", TERMINAL="WS-02",
                       EVENT_CLASS="other", TEXT="Debugging session started"))
        # PAT-005: high-volume direct table access.
        for i in range(60):
            rows.append(_ev(d(4), "1{0}:{1:02d}:00".format(i % 10, i), "DLEE",
                            TERMINAL="WS-02", TCODE="SE16",
                            EVENT_CLASS="table_access", TEXT="Table displayed"))
        # PAT-006: the audit configuration itself was changed.
        rows.append(_ev(d(5), "16:00:00", "JSMITH", TERMINAL="WS-01", TCODE="SM19",
                       EVENT_CLASS="audit_config_change",
                       TEXT="Audit configuration changed"))
        # PAT-007: a privileged logon from a terminal seen only once.
        rows.append(_ev(d(6), "10:00:00", "JSMITH", TERMINAL="LAPTOP-ROGUE",
                       EVENT_CLASS="dialog_logon", TEXT="Logon successful"))
        # Filler so the window is long enough not to be flagged as short.
        rows.append(_ev(d(70), "10:00:00", "CLERK", TERMINAL="WS-02",
                       EVENT_CLASS="dialog_logon", TEXT="Logon successful"))
    return rows


def _run(data):
    return LogReviewAuditor(data).run_all_checks()


def _ids(findings):
    return {f["check_id"] for f in findings}


def _full():
    return _run({"security_audit_log": _events(), "audit_config": CONFIG,
                 "profiles": PROFILES})


# ── the contract ────────────────────────────────────────────────────────────────

def test_empty_input_no_crash():
    assert LogReviewAuditor({}).run_all_checks() == []


def test_no_audit_export_at_all_stays_silent():
    """log_monitoring.LOG-AUD-001 already reports a missing audit export; repeating it
    here would be noise, not coverage."""
    assert _run({"profiles": PROFILES}) == []


def test_every_finding_declares_scope_and_carries_the_window():
    for f in _full():
        assert f.get("scope") in ("object", "aggregate"), f["check_id"]
        window = f["details"]["reviewed_window"]
        assert set(("start", "end", "days", "note")) <= set(window), f["check_id"]
        assert f["details"]["review_mode"] == "retrospective review over the exported window"


# ── 1. identity: the expensive one ──────────────────────────────────────────────

def test_identity_survives_a_new_export():
    """THE test for this module.

    Same defects, a window shifted by weeks and every occurrence count doubled. If any
    of that reached the fingerprint, the next export would resolve every finding and
    raise new ones whose age starts at zero — for a capability whose entire premise is
    reviewing a NEW export every month.
    """
    from server.identity import fingerprint_finding

    def prints(day_offset, repeat):
        findings = _run({"security_audit_log": _events(day_offset, repeat),
                         "audit_config": CONFIG, "profiles": PROFILES})
        return {f["check_id"]: fingerprint_finding(f, "PRD", "100")[0] for f in findings}

    first = prints(0, 1)
    second = prints(60, 2)          # different window, doubled counts, same defects
    assert first, "the fixture produced no findings; the test proves nothing"
    assert first == second, (
        "a new export re-identified findings — something volatile (a date, a count, a "
        "window) has entered identity:\n" + "\n".join(
            "  {0}: {1} -> {2}".format(k, first.get(k), second.get(k))
            for k in sorted(set(first) | set(second))
            if first.get(k) != second.get(k)))


def test_pattern_findings_are_aggregates_over_their_members():
    """One finding per PATTERN. Per-account identity would mean that locking one
    attacked account retires the finding and resets the rest mid-investigation."""
    for f in _full():
        if f["check_id"].startswith("LREV-PAT-"):
            assert f["scope"] == "aggregate", f["check_id"]
            assert f.get("affected_objects"), f["check_id"]


def test_named_accounts_become_graph_nodes_without_a_client_or_qualifier():
    """A user node here must be the SAME node the authorization modules emit, or the
    graph stops joining exactly where a reviewer wants it to join."""
    for f in _full():
        for obj in f.get("affected_objects", []):
            if obj["type"] == "user":
                assert set(obj) == {"type", "name"}, obj


def test_an_inactive_filter_is_one_finding_per_filter():
    """Deactivated filters are independent defects with independent fixes; collapsing
    them into one would hide all but the first."""
    config = CONFIG + [
        {"CONFIG_NAME": "Report_Exec", "EVENT_CLASS": "report_start",
         "ACTIVE": "INACTIVE", "PROFILE_TYPE": "DYNAMIC", "CLIENT": "100"},
        {"CONFIG_NAME": "RFC_Filter", "EVENT_CLASS": "rfc_logon",
         "ACTIVE": "INACTIVE", "PROFILE_TYPE": "STATIC", "CLIENT": "100"},
    ]
    findings = [f for f in _run({"security_audit_log": config})
                if f["check_id"] == "LREV-FLT-001"]
    assert len(findings) == 2
    for f in findings:
        assert f["scope"] == "object"
        obj = f["affected_objects"][0]
        assert obj["type"] == "audit_filter" and obj["client"] == "100"
        # No count, no date, no class in the key — only the filter and its client.
        assert "qualifier" not in obj

    from server.identity import fingerprint_finding
    prints = {fingerprint_finding(f, "PRD", "100") for f in findings}
    assert len(prints) == 2, "two switched-off filters collapsed into one identity"
    assert all(basis == "objects" for _fp, basis in prints)


def test_audit_filter_type_is_registered_case_sensitively():
    from server.identity import _CASE_SENSITIVE_TYPES, _UPPERCASE_TYPES, norm_name
    assert "audit_filter" in _CASE_SENSITIVE_TYPES
    assert "audit_filter" not in _UPPERCASE_TYPES
    assert norm_name("audit_filter", "Dialog_Logon_Filter") == "Dialog_Logon_Filter"


# ── 2. wording discipline ───────────────────────────────────────────────────────

FORBIDDEN = ("monitor", "detect", "real-time", "realtime", "near real time",
             "continuous", "streaming", "live ")


def test_no_finding_claims_monitoring_or_detection():
    """Claiming or implying live monitoring would be dismantled in the first technical
    evaluation. We read a file the customer exported; every word must say so."""
    findings = _full() + _run({"security_audit_log": CONFIG,
                               "client_settings": [{"CLIENT": "100"}, {"CLIENT": "200"}]})
    offenders = []
    for f in findings:
        blob = " ".join([f["title"], f["description"], f["remediation"]]
                        + list(f["affected_items"]) + list(f["references"])).lower()
        for word in FORBIDDEN:
            if word in blob:
                offenders.append("{0}: {1!r}".format(f["check_id"], word))
    assert not offenders, "findings claim a capability we do not have: " + "; ".join(offenders)


def test_the_module_docstring_states_the_wording_rule():
    import modules.log_review as mod
    doc = mod.__doc__.lower()
    assert "retrospective review over the exported window" in doc
    assert "not monitoring" in doc and "not detection" in doc and "not real-time" in doc


# ── 3a. log-source health ───────────────────────────────────────────────────────

def test_config_only_export_reports_that_no_window_was_reviewed():
    ids = _ids(_run({"security_audit_log": CONFIG}))
    assert "LREV-SRC-001" in ids


def test_event_only_export_reports_the_missing_filter_configuration():
    """Patterns can run without it; the review just cannot say what the window was
    CAPABLE of containing, which is the difference between 'nothing happened' and
    'nothing was being recorded'."""
    ids = _ids(_run({"security_audit_log": _events(), "profiles": PROFILES}))
    assert "LREV-SRC-003" in ids
    assert "LREV-WIN-002" not in ids     # cannot enumerate blind spots without the config


def test_unreadable_timestamps_are_reported_not_silently_dropped():
    rows = [{"DATE": "not-a-date", "USER": "JSMITH", "EVENT_CLASS": "dialog_logon"}]
    ids = _ids(_run({"security_audit_log": rows, "audit_config": CONFIG}))
    assert "LREV-SRC-002" in ids


def test_client_coverage_gap_is_reported():
    findings = _run({"security_audit_log": CONFIG,
                     "client_settings": [{"CLIENT": "000"}, {"CLIENT": "100"},
                                         {"CLIENT": "200"}]})
    flt = [f for f in findings if f["check_id"] == "LREV-FLT-002"][0]
    assert flt["scope"] == "aggregate"
    assert sorted(o["name"] for o in flt["affected_objects"]) == ["000", "200"]


def test_a_wildcard_client_filter_is_not_a_coverage_gap():
    config = [{"CONFIG_NAME": "All", "EVENT_CLASS": "dialog_logon", "ACTIVE": "X",
               "PROFILE_TYPE": "STATIC", "CLIENT": "*"}]
    ids = _ids(_run({"security_audit_log": config,
                     "client_settings": [{"CLIENT": "000"}, {"CLIENT": "100"}]}))
    assert "LREV-FLT-002" not in ids


def test_dynamic_only_class_is_reported_even_when_a_static_profile_exists():
    """log_monitoring.LOG-AUD-002 passes as soon as ANY static profile exists, so it
    cannot see the class that stops recording at the next restart."""
    config = CONFIG + [
        {"CONFIG_NAME": "Txn", "EVENT_CLASS": "transaction_start", "ACTIVE": "ACTIVE",
         "PROFILE_TYPE": "DYNAMIC", "CLIENT": "100"},
    ]
    findings = _run({"security_audit_log": config})
    flt = [f for f in findings if f["check_id"] == "LREV-FLT-003"][0]
    assert flt["details"]["dynamic_only_classes"] == ["transaction_start"]


# ── 3b. the retrospective patterns ──────────────────────────────────────────────

def test_all_patterns_fire_on_a_window_that_contains_them():
    ids = _ids(_full())
    for check in ("LREV-PAT-001", "LREV-PAT-002", "LREV-PAT-003", "LREV-PAT-004",
                  "LREV-PAT-005", "LREV-PAT-006", "LREV-PAT-007"):
        assert check in ids, "{0} did not fire on a window built to contain it".format(check)


def test_offhours_pattern_ignores_business_hours_and_non_privileged_users():
    rows = [
        _ev("2026-05-04", "10:00:00", "JSMITH", EVENT_CLASS="dialog_logon"),   # in hours
        _ev("2026-05-04", "03:00:00", "CLERK", EVENT_CLASS="dialog_logon"),    # not privileged
    ]
    ids = _ids(_run({"security_audit_log": rows, "audit_config": CONFIG,
                     "profiles": PROFILES}))
    assert "LREV-PAT-001" not in ids


def test_offhours_pattern_ignores_rfc_logons():
    """A service account signing on at 03:00 is its job; reporting it would bury the
    human privileged sign-on that actually matters."""
    rows = [_ev("2026-05-04", "03:00:00", "JSMITH", EVENT_CLASS="rfc_logon",
                TEXT="RFC logon successful")]
    ids = _ids(_run({"security_audit_log": rows, "audit_config": CONFIG,
                     "profiles": PROFILES}))
    assert "LREV-PAT-001" not in ids


def test_failure_run_needs_the_ordering_not_just_the_count():
    """Six failures AFTER the success is a different story from six failures BEFORE it,
    and the aggregate counters in logon_events.csv cannot tell them apart — which is
    exactly why this check reads the ordered stream."""
    rows = [_ev("2026-05-04", "09:00:00", "CLERK", EVENT_CLASS="dialog_logon")]
    rows += [_ev("2026-05-04", "09:1{0}:00".format(i), "CLERK",
                 EVENT_CLASS="dialog_logon_failure") for i in range(6)]
    ids = _ids(_run({"security_audit_log": rows, "audit_config": CONFIG,
                     "profiles": PROFILES}))
    assert "LREV-PAT-002" not in ids


def test_failure_run_is_corroborated_against_logon_events_when_supplied():
    findings = _run({"security_audit_log": _events(), "audit_config": CONFIG,
                     "profiles": PROFILES,
                     "logon_events": [{"USERNAME": "CLERK", "EVENT": "FAILURE",
                                       "COUNT": "42"}]})
    pat = [f for f in findings if f["check_id"] == "LREV-PAT-002"][0]
    assert pat["details"]["corroborated_by_logon_events"] == ["CLERK"]
    assert "42 total failures" in " ".join(pat["affected_items"])


def test_table_access_below_the_threshold_does_not_fire():
    rows = [_ev("2026-05-04", "10:0{0}:00".format(i % 10), "DLEE", TCODE="SE16",
                EVENT_CLASS="table_access") for i in range(5)]
    ids = _ids(_run({"security_audit_log": rows, "audit_config": CONFIG,
                     "profiles": PROFILES}))
    assert "LREV-PAT-005" not in ids


def test_thresholds_are_configurable():
    rows = [_ev("2026-05-04", "10:0{0}:00".format(i % 10), "DLEE", TCODE="SE16",
                EVENT_CLASS="table_access") for i in range(5)]
    auditor = LogReviewAuditor({"security_audit_log": rows, "audit_config": CONFIG,
                                "profiles": PROFILES},
                               {"logreview_table_access_threshold": 3})
    assert "LREV-PAT-005" in _ids(auditor.run_all_checks())


def test_message_ids_are_not_interpreted_as_event_classes():
    """We hold no verified audit message catalogue. Guessing that some three-character
    id 'means' a failed logon would be a fabricated SAP identifier."""
    rows = [_ev("2026-05-04", "03:00:00", "JSMITH", MSGID="AU2", MSG_ID="AU2")]
    ids = _ids(_run({"security_audit_log": rows, "audit_config": CONFIG,
                     "profiles": PROFILES}))
    assert not any(i.startswith("LREV-PAT-") for i in ids)


# ── the window statement ────────────────────────────────────────────────────────

def test_a_short_window_is_stated_plainly():
    rows = [_ev("2026-05-04", "03:00:00", "JSMITH", EVENT_CLASS="dialog_logon"),
            _ev("2026-05-05", "03:00:00", "JSMITH", EVENT_CLASS="dialog_logon")]
    findings = _run({"security_audit_log": rows, "audit_config": CONFIG,
                     "profiles": PROFILES})
    ids = _ids(findings)
    assert "LREV-WIN-001" in ids
    pat = [f for f in findings if f["check_id"] == "LREV-PAT-001"][0]
    assert pat["details"]["reviewed_window"]["short_window"] is True
    assert pat["details"]["reviewed_window"]["days"] == 2
    # The caveat travels with the finding, not just with a separate advisory nobody reads.
    assert "only 2 day(s)" in pat["description"]
    assert "is not evidence that the pattern does not occur" in pat["description"]


def test_a_long_window_is_not_flagged_as_short():
    findings = _full()
    assert "LREV-WIN-001" not in _ids(findings)
    window = findings[0]["details"]["reviewed_window"]
    assert window["short_window"] is False and window["days"] > 30


def test_the_window_start_and_end_are_carried_for_the_console():
    pat = [f for f in _full() if f["check_id"] == "LREV-PAT-001"][0]
    window = pat["details"]["reviewed_window"]
    assert window["start"] == "2026-01-01"
    assert window["end"] and window["end"] > window["start"]
    assert window["events_in_export"] > 0


def test_blind_spots_say_which_questions_the_window_cannot_answer():
    """The credibility centrepiece: a nil result from a class that was not recording is
    not a clean result, and the review has to say so."""
    config = [{"CONFIG_NAME": "Dialog", "EVENT_CLASS": "dialog_logon", "ACTIVE": "X",
               "PROFILE_TYPE": "STATIC", "CLIENT": "100"}]
    findings = _run({"security_audit_log": _events(), "audit_config": config,
                     "profiles": PROFILES})
    win = [f for f in findings if f["check_id"] == "LREV-WIN-002"][0]
    unanswerable = {u["check_id"] for u in win["details"]["unanswerable"]}
    assert {"LREV-PAT-002", "LREV-PAT-005", "LREV-PAT-006"} <= unanswerable
    assert "LREV-PAT-001" not in unanswerable      # dialog_logon WAS recording


def test_no_blind_spots_when_every_required_class_is_recording():
    config = CONFIG + [
        {"CONFIG_NAME": "All", "EVENT_CLASS": "ALL", "ACTIVE": "X",
         "PROFILE_TYPE": "STATIC", "CLIENT": "*"}]
    ids = _ids(_run({"security_audit_log": _events(), "audit_config": config,
                     "profiles": PROFILES}))
    assert "LREV-WIN-002" not in ids


# ── timestamp parsing ───────────────────────────────────────────────────────────

def test_common_sap_export_date_formats_are_understood():
    for date, time in (("20260504", "030000"), ("2026-05-04", "03:00:00"),
                       ("04.05.2026", "03:00:00"), ("2026-05-04T03:00:00", "")):
        row = {"DATE": date, "USER": "JSMITH", "EVENT_CLASS": "dialog_logon"}
        if time:
            row["TIME"] = time
        parsed = LogReviewAuditor._parse_dt(row)
        assert parsed is not None and parsed.hour == 3, (date, time)


def test_rows_without_a_timestamp_still_count_towards_volume():
    """Dropping them silently would understate the window; the finding says how many."""
    rows = [{"DATE": "2026-05-04", "TIME": "10:00:00", "USER": "DDIC",
             "EVENT_CLASS": "dialog_logon"},
            {"DATE": "", "TIMESTAMP": "", "USER": "DDIC", "EVENT_CLASS": "dialog_logon"}]
    # the second row has no date at all, so it is not an event row — use a real one
    rows[1] = {"DATE": "unparseable", "USER": "DDIC", "EVENT_CLASS": "dialog_logon"}
    findings = _run({"security_audit_log": rows, "audit_config": CONFIG})
    pat = [f for f in findings if f["check_id"] == "LREV-PAT-003"][0]
    assert pat["details"]["occurrences"] == 2
    assert pat["details"]["reviewed_window"]["events_without_timestamp"] == 1
