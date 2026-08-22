"""Focused tests for master_data_changes: the bank-change register masks
account values and joins headers over CHANGENR, table-keyed matching filters
non-bank rows, direct-maintenance detection keys on the TCODE set, and the
no-values export raises its own evidence-quality finding.
"""
import os
import sys
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.master_data_changes import MasterDataChangeAuditor as MDC  # noqa: E402


def _run(data):
    a = MDC(data)
    a.run_all_checks()
    return {f["check_id"]: f for f in a.findings}


def test_empty_input_no_crash():
    assert MDC({}).run_all_checks() == []


# ── MDC-BANK-001 ──────────────────────────────────────────────────────────────

def test_bank_changes_masked_joined_and_table_filtered():
    data = {
        "change_documents": [
            {"OBJECTCLAS": "KRED", "OBJECTID": "V1", "CHANGENR": "0000000100",
             "USERNAME": "AMILLER", "UDATE": "20260210", "TCODE": "FK02"},
        ],
        "change_document_items": [
            {"OBJECTID": "V1", "CHANGENR": "0000000100", "TABNAME": "LFBK",
             "FNAME": "BANKN", "VALUE_OLD": "DE44100100100000123456",
             "VALUE_NEW": "DE44100100109999887766", "CHNGIND": "U"},
            # non-bank table on the same change: must be filtered out
            {"OBJECTID": "V1", "CHANGENR": "0000000100", "TABNAME": "LFA1",
             "FNAME": "NAME1", "VALUE_OLD": "Alpha", "VALUE_NEW": "Beta",
             "CHNGIND": "U"},
            # bank row whose header was not exported
            {"OBJECTID": "BP9", "CHANGENR": "0000000999", "TABNAME": "BUT0BK",
             "FNAME": "BANKN", "VALUE_OLD": "", "VALUE_NEW": "CH9300762011623852957",
             "CHNGIND": "I"},
        ],
    }
    f = _run(data)["MDC-BANK-001"]
    assert f["details"]["count"] == 2                      # LFA1 row filtered
    joined = "\n".join(f["affected_items"])
    # masked: last four visible, full account number NEVER in the finding
    assert "3456" in joined and "7766" in joined and "2957" in joined
    assert "DE4410010010" not in joined
    assert "by AMILLER" in joined and "via FK02" in joined
    assert "(header not supplied)" in joined
    assert "added" in joined                               # CHNGIND I verb
    assert {"type": "business_partner", "name": "V1"} in f["affected_objects"]
    assert {"type": "user", "name": "AMILLER"} in f["affected_objects"]


# ── MDC-DIRECT-001 ────────────────────────────────────────────────────────────

def test_direct_maintenance_keys_on_the_tcode_set():
    data = {"change_documents": [
        {"OBJECTCLAS": "KRED", "OBJECTID": "V7", "CHANGENR": "1",
         "USERNAME": "TWILSON", "UDATE": "20260405", "TCODE": "SM30"},
        {"OBJECTCLAS": "KRED", "OBJECTID": "V8", "CHANGENR": "2",
         "USERNAME": "AMILLER", "UDATE": "20260406", "TCODE": "FK02"},
    ]}
    out = _run(data)
    f = out["MDC-DIRECT-001"]
    assert f["details"]["count"] == 1
    assert any("SM30" in i and "TWILSON" in i for i in f["affected_items"])
    assert not any("FK02" in i for i in f["affected_items"])


# ── MDC-EVD-001 ───────────────────────────────────────────────────────────────

def test_items_without_values_raise_the_evidence_note():
    rows = [{"OBJECTID": "V1", "CHANGENR": "1", "TABNAME": "LFBK",
             "FNAME": "BANKN", "VALUE_OLD": "", "VALUE_NEW": ""}]
    out = _run({"change_document_items": rows})
    assert "MDC-EVD-001" in out
    # a single populated value anywhere retires the note
    rows.append({"OBJECTID": "V2", "CHANGENR": "2", "TABNAME": "KNBK",
                 "FNAME": "BANKL", "VALUE_OLD": "1", "VALUE_NEW": "2"})
    assert "MDC-EVD-001" not in _run({"change_document_items": rows})


# ── MDC-PAY-001 / 002 — the correlation the register could not make ───────────

#: One vendor, one bank change on 10 February, one payment on 20 February into
#: the account the change introduced. Everything below is a variation on this.
_CHANGE = {
    "change_documents": [
        {"OBJECTCLAS": "KRED", "OBJECTID": "V1", "CHANGENR": "0000000100",
         "USERNAME": "AMILLER", "UDATE": "20260210", "TCODE": "FK02"},
    ],
    "change_document_items": [
        {"OBJECTID": "V1", "CHANGENR": "0000000100", "TABNAME": "LFBK",
         "FNAME": "BANKN", "VALUE_OLD": "DE44100100100000123456",
         "VALUE_NEW": "DE44100100109999887766", "CHNGIND": "U"},
    ],
}


def _paid(**over):
    row = {"LIFNR": "V1", "ZBNKN": "DE44100100109999887766", "ZALDT": "20260220",
           "LAUFI": "PR01", "VBLNR": "2000001234", "ZBUKR": "1000",
           "RWBTR": "48250.00", "WAERS": "EUR"}
    row.update(over)
    # DEEP copy. Several tests below mutate the change rows to make their point,
    # and a shallow dict() would hand them the module-level _CHANGE to edit —
    # after which every later test runs against a fixture an earlier one
    # rewrote, which is how a passing suite starts testing the wrong thing.
    return dict(deepcopy(_CHANGE), payment_runs=[row])


def test_a_payment_into_the_newly_changed_account_is_reported():
    """The whole point of the export. MDC-BANK-001 says an account changed;
    this says the money then went there."""
    f = _run(_paid())["MDC-PAY-001"]
    assert f["severity"] == "CRITICAL"
    assert f["details"]["count"] == 1
    assert f["details"]["matched_on"] == "account_number"
    line = f["affected_items"][0]
    assert "10 day(s) later" in line
    assert "48250.00 EUR" in line and "2000001234" in line


def test_the_account_number_is_masked_on_both_sides():
    """The finding travels — mailed, attached, archived. Neither the account the
    change introduced nor the account that was paid may appear in full."""
    joined = "\n".join(_run(_paid())["MDC-PAY-001"]["affected_items"])
    assert "7766" in joined
    assert "DE44100100109999887766" not in joined
    assert "DE441001001099" not in joined


def test_a_payment_to_a_different_account_is_not_a_match():
    """Matching on "a payment to that partner around then" would fire on every
    routine cycle. The match is the account itself."""
    assert "MDC-PAY-001" not in _run(_paid(ZBNKN="DE44100100100000123456"))


def test_a_payment_outside_the_window_is_not_a_match():
    assert "MDC-PAY-001" not in _run(_paid(ZALDT="20260620"))


def test_a_payment_before_the_change_is_not_a_match():
    """A payment that preceded the change cannot have been diverted by it. The
    direction of time is the difference between evidence and coincidence."""
    assert "MDC-PAY-001" not in _run(_paid(ZALDT="20260101"))


def test_the_window_is_configurable_and_the_finding_states_which_was_used():
    a = MDC(_paid(ZALDT="20260401"), {"payment_correlation_days": 90})
    a.run_all_checks()
    f = {x["check_id"]: x for x in a.findings}["MDC-PAY-001"]
    assert f["details"]["window_days"] == 90
    assert "90 day(s)" in f["description"]


def test_a_proposal_run_is_not_a_payment():
    """XVORL marks a payment PROPOSAL, which can still be edited or deleted
    before the run proper. Counting one would report money that never moved."""
    assert "MDC-PAY-001" not in _run(_paid(XVORL="X"))


def test_a_row_with_no_proposal_column_is_still_a_payment():
    """Absence of the flag is not evidence that the row is a proposal — and an
    export that dropped the column must not silently drop every finding."""
    data = _paid()
    data["payment_runs"][0].pop("XVORL", None)
    assert "MDC-PAY-001" in _run(data)


def test_formatting_differences_in_the_account_do_not_break_the_match():
    """One side is typed into a master-data screen, the other is written by the
    payment program. Spaces and leading zeros are not a different account."""
    assert "MDC-PAY-001" in _run(_paid(ZBNKN=" de4410 0100 1099 9988 7766 "))


def test_a_truncated_account_is_not_treated_as_a_match():
    """Normalisation stops at whitespace and case. An account that matches only
    after being cut short is not a match, and this finding accuses somebody of
    payment fraud."""
    assert "MDC-PAY-001" not in _run(_paid(ZBNKN="DE441001001099998877"))


def test_an_unreadable_date_still_reports_the_match_and_says_the_interval_is_unknown():
    """The account match is the evidence; the date is context. Dropping the
    match because a date would not parse would lose the finding entirely."""
    f = _run(_paid(ZALDT="not-a-date"))["MDC-PAY-001"]
    assert f["details"]["undated_matches"] == 1
    assert "interval unknown" in f["affected_items"][0]


def test_a_deleted_bank_row_has_no_account_to_have_been_paid():
    data = _paid()
    data["change_document_items"][0]["CHNGIND"] = "D"
    assert "MDC-PAY-001" not in _run(data)


def test_a_changed_bank_country_is_not_correlated():
    """BANKS is a country key, not an account. Correlating it would match every
    payment whose country happened to share the string."""
    data = _paid()
    data["change_document_items"][0].update(FNAME="BANKS", VALUE_NEW="DE")
    assert "MDC-PAY-001" not in _run(data)


# ── the gap, when the export is absent ────────────────────────────────────────

def test_bank_changes_with_no_payment_export_declare_the_gap():
    """Silence here reads as "no payment followed those changes", which is a
    stronger claim than any evidence supports."""
    f = _run(_CHANGE)["MDC-PAY-002"]
    assert f["severity"] == "INFO"
    assert f["details"]["degrades_coverage"] is True
    assert f["details"]["missing_source"] == "payment_runs"
    assert "REGUH" in f["remediation"]


def test_no_bank_changes_means_no_gap_to_declare():
    """The coverage finding exists because bank changes were found and could not
    be checked. With nothing to check, an export nobody supplied is not a gap —
    firing here would put a coverage warning on every scan that omits it."""
    data = {"change_document_items": [
        {"OBJECTID": "V1", "CHANGENR": "1", "TABNAME": "LFA1", "FNAME": "NAME1",
         "VALUE_OLD": "A", "VALUE_NEW": "B", "CHNGIND": "U"}]}
    fired = _run(data)
    assert "MDC-PAY-002" not in fired


def test_supplying_the_export_replaces_the_gap_with_an_answer():
    fired = _run(_paid())
    assert "MDC-PAY-002" not in fired
    assert "MDC-PAY-001" in fired


def test_a_payment_export_that_matches_nothing_is_silent_on_both_counts():
    """Supplied and no correlation found is a real answer, not a gap."""
    fired = _run(_paid(ZBNKN="DE99999999999999999999"))
    assert "MDC-PAY-001" not in fired and "MDC-PAY-002" not in fired
