"""
Two SAP Baseline v2.6 checks that each read a new source:

  SECSTO-001    secure-store encryption status (crypto_posture, ABAP_SECSTORE_INFO)
  WDISP-COMP-001 Web Dispatcher component patch age (webdisp_security, COMP_LEVEL)

Positive tests, negative controls, and — for the patch-age check — a date
computed relative to now so the test does not rot.
"""
import sys
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.crypto_posture import CryptoPostureAuditor        # noqa: E402
from modules.webdisp_security import WebDispatcherAuditor       # noqa: E402


def _crypto(rows):
    data = {} if rows is None else {"secure_store": rows}
    return {f["check_id"] for f in CryptoPostureAuditor(data).run_all_checks()}


def _webdisp(rows):
    data = {} if rows is None else {"webdisp_components": rows}
    return {f["check_id"] for f in WebDispatcherAuditor(data, {}, {}).run_all_checks()}


# ── SECSTO-A ──────────────────────────────────────────────────────────────────
def test_secure_store_not_ok_fires_secsto():
    assert "SECSTO-001" in _crypto([{"NAME": "EncryptionMasterKey", "VALUE": "Default"}])


def test_secure_store_ok_is_silent():
    assert "SECSTO-001" not in _crypto([{"NAME": "EncryptionMasterKey", "VALUE": "OK"}])
    # an OK anywhere in the value satisfies SAP's 'like %OK%'
    assert "SECSTO-001" not in _crypto([{"NAME": "Encryption", "VALUE": "Status OK"}])


def test_non_encryption_records_are_ignored():
    # only NAME like 'Encryption%' is judged
    assert "SECSTO-001" not in _crypto([{"NAME": "SomethingElse", "VALUE": "bad"}])


def test_no_secure_store_export_is_silent():
    assert "SECSTO-001" not in _crypto(None)


# ── SECUPD-O ──────────────────────────────────────────────────────────────────
def _days_ago(n):
    return (datetime.now() - timedelta(days=n)).strftime("%Y-%m-%d")


def test_an_old_component_fires_secupd():
    ids = _webdisp([{"COMPONENT": "SAP WEB DISPATCHER", "CD_HIST_DATE": _days_ago(400)}])
    assert "WDISP-COMP-001" in ids


def test_a_recently_patched_component_is_silent():
    ids = _webdisp([{"COMPONENT": "SAP WEB DISPATCHER", "CD_HIST_DATE": _days_ago(30)}])
    assert "WDISP-COMP-001" not in ids


def test_a_component_with_no_date_is_not_judged():
    ids = _webdisp([{"COMPONENT": "SAP WEB DISPATCHER", "CD_HIST_DATE": ""}])
    assert "WDISP-COMP-001" not in ids


def test_no_component_export_is_silent_for_the_patch_check():
    # WDISP-COV-001 (no profile) may fire, but the component check must not.
    assert "WDISP-COMP-001" not in _webdisp(None)
