"""Focused tests for vendor_master: account identity survives formatting
differences, account numbers never leave the module unmasked, the
sole-maintenance register is scoped to partners that actually carry payment
data, and an export without account numbers says so instead of reporting
nothing found.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.vendor_master import VendorMasterAuditor as VM  # noqa: E402


def _run(data):
    a = VM(data)
    a.run_all_checks()
    return {f["check_id"]: f for f in a.findings}


def test_empty_input_no_crash():
    assert VM({}).run_all_checks() == []


# ── VBM-BANK-001 ──────────────────────────────────────────────────────────────

def test_same_account_written_differently_is_one_account():
    """The duplicate this check exists to find is often a re-keyed record, so
    formatting must not hide it: spaces and case are not part of identity."""
    data = {"vendor_bank": [
        {"PARTNER": "V1", "BANKS": "DE", "BANKL": "10010010", "BANKN": "9999887766"},
        {"PARTNER": "V2", "BANKS": "de", "BANKL": "100 100 10", "BANKN": "99998877 66"},
    ]}
    f = _run(data)["VBM-BANK-001"]
    assert f["details"]["shared_accounts"] == 1
    assert {"type": "business_partner", "name": "V1"} in f["affected_objects"]
    assert {"type": "business_partner", "name": "V2"} in f["affected_objects"]


def test_account_numbers_are_masked_everywhere():
    data = {"vendor_bank": [
        {"PARTNER": "V1", "BANKS": "DE", "BANKL": "1", "BANKN": "9999887766"},
        {"PARTNER": "V2", "BANKS": "DE", "BANKL": "1", "BANKN": "9999887766"},
    ]}
    f = _run(data)["VBM-BANK-001"]
    blob = " ".join(f["affected_items"])
    assert "7766" in blob and "9999887766" not in blob


def test_one_partner_per_account_is_not_a_finding():
    data = {"vendor_bank": [
        {"PARTNER": "V1", "BANKS": "DE", "BANKL": "1", "BANKN": "111"},
        {"PARTNER": "V2", "BANKS": "DE", "BANKL": "1", "BANKN": "222"},
    ]}
    assert "VBM-BANK-001" not in _run(data)


def test_the_same_partner_twice_is_not_sharing():
    """A partner with two rows for one account (two company codes, say) is one
    partner — counting rows instead of partners would report every estate."""
    data = {"vendor_bank": [
        {"PARTNER": "V1", "BANKS": "DE", "BANKL": "1", "BANKN": "111"},
        {"PARTNER": "V1", "BANKS": "DE", "BANKL": "1", "BANKN": "111"},
    ]}
    assert "VBM-BANK-001" not in _run(data)


def test_master_flags_annotate_the_register():
    data = {
        "vendor_master": [
            {"PARTNER": "V1", "NAME1": "Alpha", "XDELE": "X"},
            {"PARTNER": "V2", "NAME1": "Alpha 2", "XBLCK": "X"},
        ],
        "vendor_bank": [
            {"PARTNER": "V1", "BANKS": "DE", "BANKL": "1", "BANKN": "111"},
            {"PARTNER": "V2", "BANKS": "DE", "BANKL": "1", "BANKN": "111"},
        ],
    }
    blob = " ".join(_run(data)["VBM-BANK-001"]["affected_items"])
    assert "flagged for deletion" in blob and "blocked" in blob
    assert "Alpha" in blob


# ── VBM-SOLE-001 ──────────────────────────────────────────────────────────────

def test_sole_maintenance_is_scoped_to_partners_with_bank_data():
    data = {
        "vendor_master": [
            {"PARTNER": "V1", "CRUSR": "A", "CHUSR": "A"},   # has bank -> listed
            {"PARTNER": "V2", "CRUSR": "A", "CHUSR": "A"},   # no bank   -> not
            {"PARTNER": "V3", "CRUSR": "A", "CHUSR": "B"},   # two people -> not
        ],
        "vendor_bank": [
            {"PARTNER": "V1", "BANKS": "DE", "BANKL": "1", "BANKN": "111"},
            {"PARTNER": "V3", "BANKS": "DE", "BANKL": "1", "BANKN": "222"},
        ],
    }
    f = _run(data)["VBM-SOLE-001"]
    blob = " ".join(f["affected_items"])
    assert "V1" in blob and "V2" not in blob and "V3" not in blob
    assert f["details"]["maintaining_users"] == ["A"]


# ── VBM-DATA-001 ──────────────────────────────────────────────────────────────

def test_bank_export_without_account_numbers_says_so():
    rows = [{"PARTNER": "V1", "BANKS": "DE", "BANKL": "10010010", "BANKN": ""}]
    out = _run({"vendor_bank": rows})
    assert "VBM-DATA-001" in out
    assert out["VBM-DATA-001"]["details"]["degrades_coverage"] is True
    assert "VBM-BANK-001" not in out
    # one populated account anywhere retires the disclosure
    rows.append({"PARTNER": "V2", "BANKS": "DE", "BANKL": "1", "BANKN": "999"})
    assert "VBM-DATA-001" not in _run({"vendor_bank": rows})
