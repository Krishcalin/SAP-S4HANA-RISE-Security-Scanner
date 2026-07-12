"""Focused tests for financial_controls + the adversarial-review fixes:
amount parsing is locale-tolerant, only FI accounting-document ranges (not master/SD/CO)
are number-range-checked, all buffer codes (X/L/P/S) count, routine ZLSPR is not a
post-posting violation, and posting-period / dual-control detection is accurate.
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.financial_controls import FinancialControlsAuditor as FC  # noqa: E402


def _ids(**data):
    a = FC(data)
    a.run_all_checks()
    return {f["check_id"]: f for f in a.findings}


def test_empty_input_no_crash():
    assert FC({}).run_all_checks() == []


# ── amount parsing (review fix #3) ─────────────────────────────────────────────

def test_amount_parsing_locale_tolerant():
    assert FC._amount("50.000,00") == 50000.0        # European
    assert FC._amount("1.000.000,00") == 1000000.0   # European millions
    assert FC._amount("1,234.56") == 1234.56         # US
    assert FC._amount("9999999999") == 9999999999.0
    assert FC._amount("") == 0.0


def test_tolerance_european_limit_not_flagged():
    got = _ids(tolerance_groups=[{"GROUP": "CLERK", "CURRENCY": "EUR",
                                  "AMOUNT_PER_DOC": "50.000,00", "AMOUNT_PER_OPEN_ITEM": "10.000,00"}])
    assert "FIN-TOL-001" not in got                   # real 50k limit must not read as unlimited


def test_tolerance_unset_and_unlimited_flagged():
    got = _ids(tolerance_groups=[{"GROUP": "", "AMOUNT_PER_DOC": "0"},
                                 {"GROUP": "SUPER", "AMOUNT_PER_DOC": "9999999999"}])
    assert "FIN-TOL-001" in got and got["FIN-TOL-001"]["details"]["count"] == 2


# ── number ranges (review fixes #1/#2) ─────────────────────────────────────────

def test_nr_only_fi_document_objects_and_all_buffer_codes():
    got = _ids(fi_number_ranges=[
        {"OBJECT": "RF_BELEG", "BUFFERING": "X"},      # FI doc, main-memory buffer -> flag
        {"OBJECT": "FI_BELEG", "BUFFERING": "S"},      # FI doc, parallel buffer -> flag (was missed)
        {"OBJECT": "RV_BELEG", "BUFFERING": "X"},      # SD doc -> NOT flagged
        {"OBJECT": "DEBITOR", "BUFFERING": "X"},       # master data -> NOT flagged (gaps OK)
        {"OBJECT": "RF_BELEG_M", "BUFFERING": "No buffering"}])  # not buffered -> NOT flagged
    assert "FIN-NR-001" in got
    items = " ".join(got["FIN-NR-001"]["affected_items"])
    assert "RF_BELEG" in items and "FI_BELEG" in items
    assert "RV_BELEG" not in items and "DEBITOR" not in items


# ── document change rules (review fixes #4/#5) ─────────────────────────────────

def test_doc_change_zlspr_not_flagged_but_bank_fields_are():
    got = _ids(doc_change_rules=[
        {"FIELD": "ZLSPR", "ACCOUNT_TYPE": "K", "CHANGE_ALLOWED": "X", "AFTER_POSTING": "X"},   # routine -> NOT
        {"FIELD": "HBKID", "ACCOUNT_TYPE": "K", "CHANGE_ALLOWED": "X", "AFTER_POSTING": "X"},   # house bank -> flag
        {"FIELD": "BVTYP", "ACCOUNT_TYPE": "K", "CHANGE_ALLOWED": "X", "AFTER_CLEARING": "X"}])  # partner bank -> flag
    assert "FIN-DOC-001" in got
    items = " ".join(got["FIN-DOC-001"]["affected_items"])
    assert "HBKID" in items and "BVTYP" in items and "ZLSPR" not in items


def test_doc_change_not_flagged_when_only_pre_posting():
    got = _ids(doc_change_rules=[{"FIELD": "HBKID", "CHANGE_ALLOWED": "X",
                                  "AFTER_POSTING": "", "AFTER_CLEARING": ""}])
    assert "FIN-DOC-001" not in got                   # changeable but not after posting/clearing


# ── posting periods ────────────────────────────────────────────────────────────

def test_posting_period_wide_open_flagged_controlled_not():
    got = _ids(posting_periods=[
        {"VARIANT": "1000", "ACCOUNT_TYPE": "+", "FROM_PERIOD": "1", "TO_PERIOD": "12",
         "FROM_YEAR": "2024", "TO_YEAR": "9999", "AUTH_GROUP": ""},                    # wide open -> flag
        {"VARIANT": "1000", "ACCOUNT_TYPE": "D", "FROM_PERIOD": "7", "TO_PERIOD": "7",
         "FROM_YEAR": "2026", "TO_YEAR": "2026", "AUTH_GROUP": "FICLOSE"}])            # narrow + auth -> not
    assert "FIN-PP-001" in got and got["FIN-PP-001"]["details"]["count"] == 1


# ── dual control ────────────────────────────────────────────────────────────────

def test_dual_control_missing_payment_fields_flagged():
    got = _ids(dual_control_fields=[{"TABLE": "LFA1", "FIELD": "NAME1"}])   # no bank/payment field
    assert "FIN-SF-001" in got


def test_dual_control_with_bank_field_not_flagged():
    got = _ids(dual_control_fields=[{"TABLE": "LFBK", "FIELD": "BANKN"},
                                    {"TABLE": "LFBK", "FIELD": "IBAN"}])
    assert "FIN-SF-001" not in got
