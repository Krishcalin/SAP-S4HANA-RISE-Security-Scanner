# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
TOTP, checked against the specification rather than against itself.

WHY THE RFC VECTORS ARE THE POINT OF THIS FILE.
A hand-rolled one-time-password scheme can be perfectly self-consistent and still
interoperate with nothing: generate and verify agree, every round-trip passes, and
Microsoft Authenticator produces codes this server rejects forever. RFC 6238
Appendix B publishes (time, expected code) pairs for a known seed, so those pairs
are an EXTERNAL oracle — passing them is evidence that a real authenticator app
will work, which no amount of round-tripping can give.

The published table is for EIGHT digits. The product uses six, and six is the low
six digits of the same value by construction (`value % 10**digits`), so both are
asserted: the eight-digit form against the RFC verbatim, and the six-digit form as
the truncation of it. Asserting only the six-digit form would silently accept an
implementation that had the dynamic-truncation offset wrong in the high bits.

This suite imports only `server.totp`, which is standard library only, so it runs
in CI's `cli` job (pytest and nothing else) rather than needing the server tier.
"""
from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server import totp                                            # noqa: E402

#: RFC 6238 Appendix B seed: the ASCII string "12345678901234567890" (20 bytes).
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode("ascii").rstrip("=")

#: RFC 6238 Appendix B, the SHA-1 rows. Eight digits, as published.
RFC_VECTORS = [
    (59,          "94287082"),
    (1111111109,  "07081804"),
    (1111111111,  "14050471"),
    (1234567890,  "89005924"),
    (2000000000,  "69279037"),
    (20000000000, "65353130"),
]


# --------------------------------------------------------------------------- #
#  The external oracle                                                        #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("when,expected", RFC_VECTORS)
def test_matches_the_rfc_6238_published_vectors(when, expected):
    assert totp.code_at(RFC_SECRET, totp.counter_at(when), digits=8) == expected


@pytest.mark.parametrize("when,expected", RFC_VECTORS)
def test_the_six_digit_code_is_the_truncation_of_the_published_eight(when, expected):
    assert totp.code_at(RFC_SECRET, totp.counter_at(when)) == expected[-6:]


def test_the_defaults_are_the_ones_every_authenticator_assumes():
    """MS and Google Authenticator ignore algorithm= and assume SHA-1 over a 30s
    step. Changing any of these silently produces codes that never match, which a
    user experiences as "the app is broken" rather than as a configuration change."""
    assert (totp.DIGITS, totp.PERIOD, totp.ALGORITHM) == (6, 30, "SHA1")


# --------------------------------------------------------------------------- #
#  Secrets                                                                    #
# --------------------------------------------------------------------------- #

def test_a_new_secret_is_unpadded_base32_of_the_recommended_length():
    s = totp.new_secret()
    assert len(s) == 32, "160 bits is a whole number of base32 chars; padding is a typo trap"
    assert "=" not in s
    assert s == s.upper()
    assert len(totp.normalise_secret(s)) == totp.SECRET_BYTES


def test_two_secrets_are_not_the_same():
    assert len({totp.new_secret() for _ in range(50)}) == 50


@pytest.mark.parametrize("typed", [
    "abcdefghijklmnop",                 # lower case
    "ABCD EFGH IJKL MNOP",              # the grouping this module itself prints
    "ABCD-EFGH-IJKL-MNOP",              # hyphens, because someone will
])
def test_a_hand_typed_secret_is_accepted_however_it_was_grouped(typed):
    canonical = totp.normalise_secret("ABCDEFGHIJKLMNOP")
    assert totp.normalise_secret(typed) == canonical


def test_format_secret_groups_for_a_human_reading_it_onto_a_phone():
    assert totp.format_secret("ABCDEFGH") == "ABCD EFGH"


# --------------------------------------------------------------------------- #
#  verify()                                                                   #
# --------------------------------------------------------------------------- #

def test_verify_returns_the_counter_rather_than_a_bool():
    """The whole replay defence depends on the caller learning WHICH counter
    matched, so it can refuse anything at or below it next time. A bool here would
    make `totp_last_counter` impossible to maintain."""
    at = 1_700_000_000
    counter = totp.counter_at(at)
    got = totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, counter), when=at)
    assert got == counter


@pytest.mark.parametrize("step", [-1, 0, 1])
def test_a_clock_off_by_one_step_still_works(step):
    at = 1_700_000_000
    code = totp.code_at(RFC_SECRET, totp.counter_at(at) + step)
    assert totp.verify(RFC_SECRET, code, when=at) is not None


@pytest.mark.parametrize("step", [-2, 2, 5])
def test_a_clock_further_out_than_the_window_is_refused(step):
    """Two steps either side would be 2.5 minutes of replay surface for a code read
    over somebody's shoulder."""
    at = 1_700_000_000
    code = totp.code_at(RFC_SECRET, totp.counter_at(at) + step)
    assert totp.verify(RFC_SECRET, code, when=at) is None


def test_a_code_cannot_be_used_twice_inside_its_own_valid_window():
    """The defect this exists for: a code stays valid for its whole step, so
    without `after_counter` an observer who sees six digits can replay them for up
    to 90 seconds. Verifying twice must not succeed twice."""
    at = 1_700_000_000
    counter = totp.counter_at(at)
    code = totp.code_at(RFC_SECRET, counter)

    first = totp.verify(RFC_SECRET, code, when=at)
    assert first == counter
    second = totp.verify(RFC_SECRET, code, when=at, after_counter=first)
    assert second is None, "the same code was accepted twice — replay is open"


def test_an_older_code_is_refused_once_a_newer_one_has_been_used():
    """Drift cuts both ways: after accepting counter N, the still-in-window code
    for N-1 must not be accepted, or the window becomes a replay buffer."""
    at = 1_700_000_000
    counter = totp.counter_at(at)
    older = totp.code_at(RFC_SECRET, counter - 1)
    assert totp.verify(RFC_SECRET, older, when=at, after_counter=counter) is None


@pytest.mark.parametrize("bad", ["", "  ", "12345", "1234567", "abcdef", "12 34 56",
                                 "12345a", None])
def test_a_malformed_code_is_refused_without_reaching_the_comparison(bad):
    assert totp.verify(RFC_SECRET, bad, when=1_700_000_000) is None


@pytest.mark.parametrize("absent", ["", None, "   ", "AB", "ABCDEFGH"])
def test_an_absent_or_short_secret_can_never_produce_a_match(absent):
    """The bypass this guard exists for, pinned so it cannot be tidied away.

    HMAC accepts an EMPTY key without complaint, so before the fail-closed check
    `code_now("")` returned six perfectly ordinary digits and `verify("", those)`
    returned a counter. Any caller that reached here with a NULL or empty secret —
    an account that never enrolled — would have authenticated an attacker who
    derived the code offline, and it would read as an ordinary success in the
    audit log.
    """
    assert totp.verify(absent, "000000") is None
    # Not just "the wrong code fails": the RIGHT code for that key must fail too.
    try:
        derived = totp.code_at(absent, totp.counter_at(1_700_000_000))
    except ValueError:
        derived = "000000"           # code_at refuses outright, which is stronger
    assert totp.verify(absent, derived, when=1_700_000_000) is None


@pytest.mark.parametrize("digits", ["١٢٣٤٥٦", "¹²³⁴⁵⁶", "１２３４５６"])
def test_non_ascii_digits_are_refused_rather_than_raising(digits):
    """`str.isdigit()` is True for Arabic-Indic, superscript and full-width digits,
    which sailed past the length guard and into `hmac.compare_digest`, which raises
    TypeError on non-ASCII. On the login route that is an unhandled 500 from six
    characters of user input."""
    assert digits.isdigit(), "the premise of this test is that isdigit() allows it"
    assert totp.verify(RFC_SECRET, digits, when=1_700_000_000) is None


def test_code_at_refuses_to_generate_for_a_key_that_is_not_one():
    """Generating a code for an account with no secret is a caller bug, so it
    raises rather than returning plausible digits."""
    for bad in ("", None, "AB"):
        with pytest.raises(ValueError):
            totp.code_at(bad, 0)


def test_a_wrong_code_of_the_right_shape_is_refused():
    at = 1_700_000_000
    right = totp.code_at(RFC_SECRET, totp.counter_at(at))
    wrong = "000000" if right != "000000" else "111111"
    assert totp.verify(RFC_SECRET, wrong, when=at) is None


# --------------------------------------------------------------------------- #
#  Provisioning                                                               #
# --------------------------------------------------------------------------- #

def test_the_provisioning_uri_carries_what_an_authenticator_reads():
    uri = totp.provisioning_uri("ABCDEFGH", "alice")
    assert uri.startswith("otpauth://totp/")
    for part in ("secret=ABCDEFGH", "issuer=MonitorRisk",
                 "algorithm=SHA1", "digits=6", "period=30"):
        assert part in uri, f"{part} missing — the app would assume its own default"


def test_the_account_label_is_url_encoded():
    """A username with a colon or a space would otherwise break the label grammar
    and the app would show a mangled account name, or refuse the URI outright."""
    uri = totp.provisioning_uri("ABCDEFGH", "some one:x")
    assert "some one:x" not in uri
    assert "%20" in uri and "%3A" in uri


def test_the_issuer_is_the_product_name():
    assert totp.ISSUER == "MonitorRisk"


# --------------------------------------------------------------------------- #
#  Recovery codes                                                             #
# --------------------------------------------------------------------------- #

def test_recovery_codes_are_generated_in_a_full_set():
    codes = totp.new_recovery_codes()
    assert len(codes) == totp.RECOVERY_CODE_COUNT == 10
    assert len(set(codes)) == len(codes)


def test_recovery_codes_avoid_the_characters_people_misread():
    """These get read down a phone line and copied onto paper. l/1 and o/0 are the
    pairs that produce a support call rather than a login."""
    joined = "".join(totp.new_recovery_codes(50)).replace("-", "")
    for ambiguous in "lo01i":
        assert ambiguous not in joined, f"{ambiguous!r} is misread when transcribed"


def test_recovery_codes_carry_enough_entropy_for_an_unsalted_hash():
    """The fingerprint is a single unsalted SHA-256 round, which is only defensible
    if the input really is high-entropy. At the original ten characters this was
    2**49.5 and a leaked table fell to a GPU in minutes."""
    import math
    alphabet = len(set("".join(totp.new_recovery_codes(200)).replace("-", "")))
    length = len(totp.new_recovery_codes(1)[0].replace("-", ""))
    bits = length * math.log2(alphabet)
    assert length >= 16, f"a {length}-character code is too short for an unsalted hash"
    assert bits >= 75, f"only {bits:.1f} bits of entropy behind a single SHA-256 round"


def test_a_recovery_code_fingerprint_does_not_contain_the_code():
    code = totp.new_recovery_codes(1)[0]
    fp = totp.recovery_fingerprint(code)
    assert code.replace("-", "") not in fp
    assert len(fp) == 64 and int(fp, 16) >= 0        # sha256 hex


@pytest.mark.parametrize("variant", [
    "{code}", "{upper}", " {code} ", "{nohyphen}",
])
def test_a_recovery_code_is_recognised_however_it_was_typed(variant):
    code = totp.new_recovery_codes(1)[0]
    typed = variant.format(code=code, upper=code.upper(),
                           nohyphen=code.replace("-", ""))
    assert totp.recovery_fingerprint(typed) == totp.recovery_fingerprint(code)


def test_different_recovery_codes_fingerprint_differently():
    a, b = totp.new_recovery_codes(2)
    assert totp.recovery_fingerprint(a) != totp.recovery_fingerprint(b)
