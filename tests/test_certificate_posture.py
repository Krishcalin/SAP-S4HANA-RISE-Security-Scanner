"""Which self-signed certificates count, and which certificates count as expired.

Both questions were answered wrongly, and both were found the same way: by
asking why `CRYPTO-CERT-002` and `CRYPTO-CERT-004` had never been observed to
fire anywhere in the suite.
"""
import sys
from datetime import date, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.crypto_posture import CryptoPostureAuditor              # noqa: E402


def fired(rows):
    return {f["check_id"] for f in
            CryptoPostureAuditor({"certificate_inventory": rows}).run_all_checks()}


def cert(purpose, issuer="DigiCert CA", name="X_Cert", valid_to=None):
    return {"CERT_NAME": name, "ISSUER": issuer, "PURPOSE": purpose,
            "VALID_TO": valid_to or (date.today() + timedelta(days=400)).isoformat(),
            "KEY_SIZE": 2048, "ALGORITHM": "SHA256withRSA"}


# ── the purposes an allowlist of transport keywords let through ────────────
#
# The old test was `any(p in purpose for p in ["PROD","SSL","HTTPS","SNC",
# "SERVER"])`. Every entry below fails that test, and every one of them is a
# certificate that authenticates identity rather than transport.

@pytest.mark.parametrize("purpose", [
    "SSO", "SAML Signing", "Logon Ticket", "Client Auth", "Token Signing",
])
def test_a_self_signed_identity_certificate_is_reported(purpose):
    """A self-signed SAML signing certificate means no relying party can tell
    a genuine assertion from a forged one. It matched none of the five
    transport keywords the check used to look for."""
    assert "CRYPTO-CERT-004" in fired([cert(purpose, issuer="X_Cert")]), purpose


@pytest.mark.parametrize("purpose", [
    "HTTPS Server", "SNC", "SSL Client", "Production API",
])
def test_the_transport_purposes_are_still_reported(purpose):
    """The inversion must not have traded one blind spot for another."""
    assert "CRYPTO-CERT-004" in fired([cert(purpose, issuer="X_Cert")]), purpose


@pytest.mark.parametrize("purpose", [
    "Testing", "Sandbox SSL", "DEV HTTPS", "Training", "QAS Server",
])
def test_a_certificate_that_names_itself_non_production_is_left_alone(purpose):
    assert "CRYPTO-CERT-004" not in fired([cert(purpose, issuer="X_Cert")]), purpose


def test_an_unstated_purpose_reads_as_production():
    """The direction this product errs in everywhere else: a value the export
    does not carry must not resolve to the reassuring answer on its own."""
    assert "CRYPTO-CERT-004" in fired([cert("", issuer="X_Cert")])


def test_a_ca_signed_certificate_is_not_the_finding():
    """Self-signed is the defect; the purpose only decides whether it matters."""
    assert "CRYPTO-CERT-004" not in fired([cert("SSO", issuer="DigiCert CA")])


def test_an_issuer_naming_itself_self_signed_is_caught_too():
    assert "CRYPTO-CERT-004" in fired(
        [cert("SSO", issuer="Self-Signed", name="Some_Cert")])


def test_the_shipped_corpus_row_that_went_unreported_now_reports():
    """sample_data has carried SSO_Signing_Cert — issuer SSO_Signing_Cert,
    purpose SSO — for as long as the check has existed, and the check said
    nothing about it."""
    assert "CRYPTO-CERT-004" in fired([{
        "CERT_NAME": "SSO_Signing_Cert", "VALID_TO": "2024-11-30",
        "KEY_SIZE": 1024, "ALGORITHM": "SHA1withRSA",
        "ISSUER": "SSO_Signing_Cert", "PURPOSE": "SSO"}])


# ── the last day of validity ───────────────────────────────────────────────

def test_a_certificate_valid_until_tomorrow_has_not_expired():
    """`(parsed - now).days` truncated toward zero, so a certificate valid
    until tomorrow gave days_left == 0 on any scan run after midnight and was
    reported "EXPIRED 0d ago" at CRITICAL — about a certificate that works."""
    got = fired([cert("HTTPS Server",
                      valid_to=(date.today() + timedelta(days=1)).isoformat())])
    assert "CRYPTO-CERT-002" in got
    assert "CRYPTO-CERT-001" not in got


def test_a_certificate_expiring_today_is_treated_as_expired():
    """It stops working at some point during today, and a scan cannot know
    when. Erring toward expired is the safe direction here."""
    got = fired([cert("HTTPS Server", valid_to=date.today().isoformat())])
    assert "CRYPTO-CERT-001" in got
