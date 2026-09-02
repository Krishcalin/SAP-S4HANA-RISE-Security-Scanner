"""Checks whose verdict depends on today's date, proven with dates computed today.

A FIXTURE DATE ROTS AND NOTHING SAYS SO. `sample_data` carried no date in the
future at all — every one of its 100-odd date values had slipped into the past
as wall-clock time moved. Two checks stopped being exercised by it, silently:

  CRYPTO-CERT-002  certificates expiring within 90 days — every certificate in
                   the corpus expired months ago, so the corpus could only ever
                   reach the EXPIRED branch (CRYPTO-CERT-001)
  IAM-EXP-003      role assignments with excessive validity — the classifier
                   returns at `parsed_to < now`, so an assignment that has
                   already expired is reported as expired and never measured for
                   length. Every TO_DAT in the corpus was in the past

Neither failed. Neither was reported. They simply stopped being covered, and
the coverage figure kept counting them.

The corpus is still worth refreshing — a realistic estate has a certificate
expiring next month — but a literal date put there today rots again by
Christmas. So the durable proof lives here instead, on dates computed from
`date.today()` at the moment the test runs. These cannot rot.

If you add a check that compares anything to `now`, add it here too.
"""
import sys
from datetime import date, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.crypto_posture import CryptoPostureAuditor              # noqa: E402
from modules.iam_advanced import AdvancedIamAuditor                  # noqa: E402


def iso(days_from_today):
    return (date.today() + timedelta(days=days_from_today)).isoformat()


def sap(days_from_today):
    """SAP's own date format, which is what AGR_USERS carries."""
    return (date.today() + timedelta(days=days_from_today)).strftime("%Y%m%d")


def ids(auditor):
    return {f["check_id"] for f in auditor.run_all_checks()}


def cert(name, valid_to, key=2048, algo="SHA256withRSA",
         issuer="DigiCert CA", purpose="HTTPS Server"):
    return {"CERT_NAME": name, "VALID_TO": valid_to, "KEY_SIZE": key,
            "ALGORITHM": algo, "ISSUER": issuer, "PURPOSE": purpose}


def certs(rows):
    return ids(CryptoPostureAuditor({"certificate_inventory": rows}))


# ── CRYPTO-CERT-002 — expiring, not yet expired ────────────────────────────

def test_a_certificate_expiring_inside_the_window_is_reported_as_expiring():
    got = certs([cert("SSL_Server_Cert", iso(30))])
    assert "CRYPTO-CERT-002" in got
    assert "CRYPTO-CERT-001" not in got, (
        "it has not expired yet — that is the whole distinction")


def test_a_certificate_beyond_the_window_is_not_reported():
    assert "CRYPTO-CERT-002" not in certs([cert("SSL_Server_Cert", iso(200))])


def test_a_certificate_that_has_already_expired_is_the_other_finding():
    got = certs([cert("SSL_Server_Cert", iso(-10))])
    assert "CRYPTO-CERT-001" in got
    assert "CRYPTO-CERT-002" not in got


def test_the_boundary_belongs_to_expiring_not_expired():
    """Tomorrow is one day of warning, not a failure that already happened."""
    got = certs([cert("SSL_Server_Cert", iso(1))])
    assert "CRYPTO-CERT-002" in got and "CRYPTO-CERT-001" not in got


def test_both_branches_are_reachable_from_one_inventory():
    """The state a real estate is actually in, and the one the corpus lost."""
    got = certs([cert("Expired_Cert", iso(-40)), cert("Expiring_Cert", iso(25))])
    assert {"CRYPTO-CERT-001", "CRYPTO-CERT-002"} <= got


# ── IAM-EXP-003 — validity longer than policy allows ───────────────────────

def role_expiry(rows):
    return ids(AdvancedIamAuditor({"role_expiry": rows}))


def assignment(user, role, from_days, to_days):
    return {"UNAME": user, "AGR_NAME": role,
            "FROM_DAT": sap(from_days), "TO_DAT": sap(to_days)}


def test_an_over_long_assignment_still_in_force_is_reported():
    """Default policy is 365 days. This one runs for roughly three years and
    has not expired, which is the only state the check can see."""
    assert "IAM-EXP-003" in role_expiry(
        [assignment("AGARCIA", "Z_MM_BUYER", -600, 500)])


def test_an_assignment_inside_the_policy_is_not_reported():
    assert "IAM-EXP-003" not in role_expiry(
        [assignment("AGARCIA", "Z_MM_BUYER", -100, 100)])


def test_an_expired_assignment_is_reported_as_expired_not_as_over_long():
    """THIS IS WHY THE CORPUS STOPPED PROVING IT. The classifier returns at
    `parsed_to < now`, so once an over-long assignment passes its end date it is
    only ever reported as expired — and every TO_DAT in sample_data had."""
    got = role_expiry([assignment("AGARCIA", "Z_MM_BUYER", -1200, -90)])
    assert "IAM-EXP-002" in got
    assert "IAM-EXP-003" not in got


def test_an_open_ended_assignment_is_the_third_finding():
    got = role_expiry([{"UNAME": "JSMITH", "AGR_NAME": "Z_FI_ACCOUNTANT",
                        "FROM_DAT": sap(-900), "TO_DAT": "99991231"}])
    assert "IAM-EXP-001" in got
    assert "IAM-EXP-003" not in got, (
        "an indefinite assignment is not an over-long one; it is the worse "
        "finding above, and double-counting it would inflate both")


def test_all_three_expiry_states_are_reachable_together():
    assert {"IAM-EXP-001", "IAM-EXP-002", "IAM-EXP-003"} <= role_expiry([
        {"UNAME": "JSMITH", "AGR_NAME": "Z_FI", "FROM_DAT": sap(-900),
         "TO_DAT": "99991231"},
        assignment("DLEE", "Z_SD_BILLING", -1200, -90),
        assignment("AGARCIA", "Z_MM_BUYER", -600, 500),
    ])


# ── the smell that started this ────────────────────────────────────────────

def test_the_shipped_corpus_still_carries_a_date_in_the_future():
    """Not a style rule — a coverage one.

    A corpus with no future date anywhere cannot exercise any "expiring",
    "still valid" or "not yet due" branch, and nothing else in the suite
    notices. When this fails, the fix is to move the forward-dated rows in
    sample_data on; `tests/test_time_relative_checks.py` names which columns
    are meant to be ahead of today.
    """
    import re
    pattern = re.compile(r"\b(20\d\d)-(\d\d)-(\d\d)\b")
    today, found = date.today(), []
    for path in sorted((ROOT / "sample_data").iterdir()):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for m in pattern.finditer(text):
            try:
                d = date(*map(int, m.groups()))
            except ValueError:
                continue
            if today < d < date(2100, 1, 1):
                found.append("%s: %s" % (path.name, d))
    assert found, (
        "no file in sample_data carries a date in the future. Every "
        "'expiring soon' / 'still valid' branch in the product is unreachable "
        "from the corpus, and the coverage figure will not say so. Move the "
        "forward-dated rows in certificate_inventory.csv, pse_inventory.csv "
        "and role_expiry.csv ahead of today.")
