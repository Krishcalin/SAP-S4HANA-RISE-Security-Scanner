# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""Focused tests for master_data_changes: the bank-change register masks
account values and joins headers over CHANGENR, table-keyed matching filters
non-bank rows, direct-maintenance detection keys on the TCODE set, and the
no-values export raises its own evidence-quality finding.
"""
import os
import sys
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
