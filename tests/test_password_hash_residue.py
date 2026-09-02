"""Turning the parameter down does not delete the hashes already written.

`login/password_downwards_compatibility` governs whether SAP writes the old
BCODE and PASSCODE hashes when a password is set. It does nothing to the rows
already in USR02, or in USH02 — the password history — which stay until every
affected user changes their password or the values are cleared deliberately.

This product checked the parameter and nothing else. So an estate that turned it
down years ago and never followed through had that check passing, a hardened
length policy, and a table of hashes a laptop can recover — and the report showed
the first two.

USER_PASSWD_HASH_USAGE is the third configuration store SAP's own Security
Baseline reads for requirement PWDPOL-A, after ABAP_INSTANCE_PAHI and
AUTH_SECURITY_POLICY. This closes it.
"""
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.security_params import SecurityParamAuditor                # noqa: E402

COMPLIANT = [{"PARAMETER": "login/password_downwards_compatibility", "VALUE": "0"}]


def fired(data):
    return {f["check_id"]: f for f in SecurityParamAuditor(data).run_all_checks()}


def only_current(user="MWILSON"):
    return {"BNAME": user, "PWDSALTEDHASH_EXISTS": "X", "CODVN": "H"}


# ── PWDHASH-001 — the residue itself ───────────────────────────────────────

def test_an_old_bcode_hash_is_reported():
    got = fired({"security_params": COMPLIANT,
                 "password_hashes": [{"BNAME": "JSMITH", "BCODE_EXISTS": "X"}]})
    assert "PWDHASH-001" in got
    assert got["PWDHASH-001"]["severity"] == "HIGH"


def test_a_system_with_only_current_hashes_is_silent():
    assert "PWDHASH-001" not in fired({"security_params": COMPLIANT,
                                       "password_hashes": [only_current()]})


def test_the_parameter_being_correct_does_not_excuse_the_residue():
    """The whole point. A compliant parameter and a full table are the common
    real state, and the finding must stand."""
    got = fired({"security_params": COMPLIANT,
                 "password_hashes": [{"BNAME": "JSMITH", "BCODE_EXISTS": "X"},
                                     only_current()]})
    assert "PWDHASH-001" in got
    assert any("does not remove the rows above" in i
               for i in got["PWDHASH-001"]["affected_items"]), (
        "the finding must say what the parameter does and does not do, or a "
        "reader who fixed it will read this as the same finding again")


def test_password_history_is_called_out_separately():
    """A hash in USH02 is exactly as crackable as one in USR02, and is missed
    by anybody who only cleans the current table."""
    got = fired({"security_params": COMPLIANT,
                 "password_hashes": [{"BNAME": "BATCH_FIN", "TABLE": "USH02",
                                      "PASSCODE_EXISTS": "X"}]})
    item, = [i for i in got["PWDHASH-001"]["affected_items"] if i.startswith("PASSCODE")]
    assert "USH02" in item


@pytest.mark.parametrize("codvn", ["A", "B", "D", "E", "F", "G"])
def test_a_weak_code_version_alone_is_enough(codvn):
    """Some exports carry only the generation, not per-column flags."""
    assert "PWDHASH-001" in fired({
        "security_params": COMPLIANT,
        "password_hashes": [{"BNAME": "JSMITH", "CODVN": codvn}]})


@pytest.mark.parametrize("codvn", ["H", "I"])
def test_a_current_code_version_is_not_reported(codvn):
    assert "PWDHASH-001" not in fired({
        "security_params": COMPLIANT,
        "password_hashes": [{"BNAME": "JSMITH", "CODVN": codvn}]})


def test_an_explicit_negative_flag_is_not_read_as_presence():
    for absent in ("", "0", "FALSE", "no", "-", "NULL"):
        assert "PWDHASH-001" not in fired({
            "security_params": COMPLIANT,
            "password_hashes": [{"BNAME": "JSMITH", "BCODE_EXISTS": absent,
                                 "PWDSALTEDHASH_EXISTS": "X"}]}), absent


# ── the safety rule ────────────────────────────────────────────────────────

HASHES = {
    "bcode": "A1B2C3D4E5F6A7B8",
    "passcode": "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
    "salted": "{x-issha, 1024}nEpUUAFOB1a6PFAvQvUqLoJHf7A=",
}


def test_a_hash_value_never_reaches_the_finding():
    """AN EXPORT THAT ANSWERS THIS QUESTION MAY CARRY THE HASHES THEMSELVES.

    A check that quoted its evidence the way every other check in this module
    does would copy password hashes into the report, into the findings database
    and into the PDF an auditor mails around — turning a scan of the problem
    into a second copy of it. Presence is the whole of what is needed, so
    presence is the whole of what is read.
    """
    got = fired({
        "security_params": COMPLIANT,
        "password_hashes": [{"BNAME": "JSMITH",
                             "BCODE": HASHES["bcode"],
                             "PASSCODE": HASHES["passcode"],
                             "PWDSALTEDHASH": HASHES["salted"]}],
    })
    rendered = repr(got["PWDHASH-001"])
    for label, value in HASHES.items():
        assert value not in rendered, "%s hash reached the finding" % label
    assert not re.search(r"\b[0-9A-Fa-f]{16,}\b", rendered), (
        "something hash-shaped is in the finding text")


def test_the_raw_columns_are_still_read_as_presence():
    """Redaction must not become blindness — a customer who exports the columns
    still gets the finding, just not their contents back."""
    assert "PWDHASH-001" in fired({
        "security_params": COMPLIANT,
        "password_hashes": [{"BNAME": "JSMITH", "BCODE": HASHES["bcode"]}]})


# ── why there is no coverage finding for the absent export ─────────────────

def test_an_absent_hash_export_produces_no_finding_of_its_own():
    """A first draft added PWDHASH-002 for the state that genuinely misleads —
    the parameter set compliantly, the residue never looked at, a clean report.

    The codebase had already settled it, and asserts the rule in four separate
    tests: an absent OPTIONAL input is not degraded coverage, because if it
    armed the gate then every scan omitting one input would fail and the gate's
    degraded signal would be worth nothing. `password_hashes` is optional. The
    connection is carried by PWDHASH-001's declared source instead, so the
    coverage manifest shows the check unevaluated rather than passed.
    """
    assert not [k for k in fired({"security_params": COMPLIANT})
                if k.startswith("PWDHASH")]


def test_a_scan_with_no_inputs_at_all_is_silent():
    assert not [k for k in fired({}) if k.startswith("PWDHASH")]


# ── the corpus, and the guide it must agree with ───────────────────────────

def test_the_corpus_carries_presence_flags_not_hash_values():
    """The export guide asks customers never to send the hash values. Shipping
    a fixture that models the shape we tell them not to send would teach the
    opposite of what the guide says."""
    for fixture in ("sample_data", "sample_data_ecc"):
        text = (ROOT / fixture / "password_hashes.csv").read_text(encoding="utf-8")
        header = text.splitlines()[0].split(",")
        assert "BCODE" not in header and "PASSCODE" not in header, (
            "%s carries raw hash columns" % fixture)
        assert "BCODE_EXISTS" in header
        assert not re.search(r"\b[0-9A-Fa-f]{16,}\b", text), (
            "%s contains something hash-shaped" % fixture)
