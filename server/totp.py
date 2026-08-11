# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
Time-based one-time passwords (RFC 6238) — pure, standard library only.

Works with Microsoft Authenticator, Google Authenticator, Authy, 1Password and
anything else that speaks the `otpauth://` URI scheme, because it implements the
actual specification rather than a lookalike.

STDLIB, AND THAT IS A CHARTER REQUIREMENT, NOT A PREFERENCE. requirements.txt
holds four runtime dependencies and tests/test_spa_mount.py asserts that list
verbatim. `pyotp` would be a fifth for roughly eighty lines of arithmetic. This
module is a port of the same approach used in the sibling OverWatch codebase
(`aws_totp.py`), which reached the same conclusion for the same reason.

CORRECTNESS IS TESTABLE HERE, SO IT IS TESTED AGAINST AN EXTERNAL ORACLE.
RFC 6238 Appendix B publishes a table of (time, expected code) for a known seed.
tests/test_totp.py asserts against those vectors, which is evidence of
interoperability with every conforming authenticator app — as opposed to evidence
that this file agrees with itself, which is all a round-trip test of a hand-rolled
scheme would give.

────────────────────────────────────────────────────────────────────────────────
WHY SHA-1, WHICH LOOKS WRONG AT FIRST GLANCE
────────────────────────────────────────────────────────────────────────────────
RFC 6238 permits SHA-1, SHA-256 and SHA-512, and the default is SHA-1. Microsoft
Authenticator and Google Authenticator ignore the `algorithm=` parameter and
assume SHA-1; an enrolment advertising SHA-256 silently produces codes that never
match, and the user experiences that as "the app is broken".

It is also not the SHA-1 weakness that matters. The break is collision
resistance, and HMAC-SHA-1 does not rely on it — the construction is still sound,
and the secret is 160 bits from `secrets`. Interoperability wins.

────────────────────────────────────────────────────────────────────────────────
WHAT THIS MODULE DELIBERATELY DOES NOT DO
────────────────────────────────────────────────────────────────────────────────
It does not remember which codes have been used. A TOTP code stays valid for its
whole time step, so the same six digits replay happily for up to 30 seconds (90
across the drift window) unless somebody records the last counter accepted for
that user. That is state, so it belongs in the store — `server/auth.py` holds it
in `app_totp.last_counter`, on its own table rather than as a column on `app_user`
— and the omission is called out here because "verify returned a match" reads like
the whole job and is not.

THE SEED IS STORED IN CLEAR, AND THAT IS A STATED RESIDUAL RATHER THAN AN
OVERSIGHT. Encrypting it needs key material, and the only candidate is
SESSION_SECRET, which would bind every enrolment to one environment variable and
turn a rotation that costs nothing today into silent mass lockout from the
product. Whoever can read `app_totp` holds every enrolled seed — and unlike a
session token, a seed outlives the 12-hour TTL. The response to a suspected
database dump is therefore `server.cli totp-disable` and re-enrolment, not a key
rotation.

It also generates no QR image; see `provisioning_uri` and `server/qr.py`.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
import struct
import time
from typing import List, Optional
from urllib.parse import quote

#: RFC 6238 defaults, and what every mainstream authenticator assumes.
DIGITS = 6
PERIOD = 30
ALGORITHM = "SHA1"

#: The name the authenticator app shows in its list. The console is MonitorRisk;
#: tests/test_branding.py owns the rule that retired names appear nowhere.
ISSUER = "MonitorRisk"

#: 160 bits, the RFC 4226 recommendation, and a whole number of base32 characters
#: (32) so the manual-entry string carries no padding for a user to mistype.
SECRET_BYTES = 20

#: How many steps either side of "now" are accepted. One step is +/-30s, which
#: covers an unsynchronised phone clock and a slow typist. Two would be 2.5
#: minutes of replay surface for a code read over a shoulder; zero fails honest
#: users whose clock drifted by a few seconds.
DEFAULT_DRIFT_STEPS = 1


def new_secret() -> str:
    """A fresh base32 secret, unpadded and upper-case — the shape every
    authenticator's manual-entry field expects."""
    return base64.b32encode(secrets.token_bytes(SECRET_BYTES)).decode("ascii").rstrip("=")


#: Refuse to treat anything shorter than 80 bits as a key. This is the fail-closed
#: half of a real defect: HMAC accepts an EMPTY key perfectly happily, so before
#: this guard `code_now("")` returned a computable six digits and `verify("", that)`
#: returned a match. An account whose secret column is NULL or '' would therefore
#: have accepted a code any attacker could derive offline — an authentication
#: bypass that reads as ordinary success in every log. The store is supposed to
#: prevent that (see `auth.totp_active`), but a primitive that authenticates
#: nothing-as-something is the wrong shape to hand to any caller.
MIN_SECRET_BYTES = 10


def normalise_secret(secret: str) -> bytes:
    """Base32 text -> key bytes, tolerating the spaces and lower case a human
    introduces when typing it in, and re-adding the padding b32decode insists on.

    Raises ValueError for anything that is not a usable key, including the empty
    string. `verify` turns that into a refusal; `code_at` lets it propagate,
    because generating a code for an account with no secret is a caller bug.
    """
    cleaned = (secret or "").replace(" ", "").replace("-", "").upper()
    cleaned += "=" * (-len(cleaned) % 8)
    try:
        key = base64.b32decode(cleaned, casefold=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("secret is not valid base32") from exc
    if len(key) < MIN_SECRET_BYTES:
        raise ValueError("secret is too short to be a TOTP key")
    return key


def code_at(secret: str, counter: int, *, digits: int = DIGITS) -> str:
    """The HOTP value for an explicit counter (RFC 4226 section 5.3)."""
    mac = hmac.new(normalise_secret(secret), struct.pack(">Q", int(counter)),
                   hashlib.sha1).digest()
    offset = mac[-1] & 0x0F                       # dynamic truncation
    value = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def counter_at(when: Optional[float] = None, *, period: int = PERIOD) -> int:
    return int((time.time() if when is None else when) // period)


def code_now(secret: str, *, when: Optional[float] = None) -> str:
    return code_at(secret, counter_at(when))


def verify(secret: str, code: str, *, when: Optional[float] = None,
           drift: int = DEFAULT_DRIFT_STEPS,
           after_counter: int = -1) -> Optional[int]:
    """Check a code. Returns the COUNTER it matched, or None.

    The counter is returned rather than a bool so the caller can persist it and
    refuse a replay — see the module docstring. `after_counter` is the last
    counter this user's account accepted, so a code cannot be used twice even
    inside its own still-valid window.

    Comparison is constant-time. Six digits is a small space and a timing side
    channel on the comparison would narrow it further.
    """
    cleaned = (code or "").strip().replace(" ", "")
    # `.isascii()` is not redundant with `.isdigit()`. str.isdigit() is TRUE for
    # Arabic-Indic "١٢٣٤٥٦" and for superscripts, which then reach
    # hmac.compare_digest and raise TypeError: "comparing strings with non-ASCII
    # characters is not supported". On the login path that is an unhandled 500
    # from six characters of user input.
    if not (cleaned.isascii() and cleaned.isdigit()) or len(cleaned) != DIGITS:
        return None
    try:
        normalise_secret(secret)          # fail closed on an absent/short key
    except ValueError:
        return None
    now = counter_at(when)
    for step in range(-abs(drift), abs(drift) + 1):
        candidate = now + step
        if candidate <= after_counter:
            continue                          # already used: replay, not a match
        if hmac.compare_digest(code_at(secret, candidate), cleaned):
            return candidate
    return None


def provisioning_uri(secret: str, account: str, *, issuer: str = ISSUER) -> str:
    """The `otpauth://` URI an authenticator app consumes.

    `server.qr.to_svg` renders this as a scannable QR. Two fallbacks are offered
    beside it and are not redundant: this URI is a LINK, so tapping it on a phone
    opens the authenticator directly with nothing to scan, and the secret itself
    works through "enter a setup key" when a camera is unavailable or the screen
    is being shared.

    Because enrolment is not active until the user has typed back a working code,
    a failed scan or a mistyped secret can never lock anyone out — it simply does
    not enrol.
    """
    label = quote(f"{issuer}:{account}", safe="")
    return (f"otpauth://totp/{label}?secret={secret}"
            f"&issuer={quote(issuer, safe='')}"
            f"&algorithm={ALGORITHM}&digits={DIGITS}&period={PERIOD}")


def format_secret(secret: str, *, group: int = 4) -> str:
    """`ABCD EFGH ...` — grouped for a human reading it off a screen onto a phone."""
    s = (secret or "").upper()
    return " ".join(s[i:i + group] for i in range(0, len(s), group))


# --------------------------------------------------------------------------- #
#  Recovery codes                                                             #
# --------------------------------------------------------------------------- #
# Without these a lost or wiped phone is a permanently locked account, and this
# product has no self-service password reset by design — so the only way back is
# an administrator, which for the FIRST administrator is nobody. See
# server/cli.py's totp-disable for the other half of that answer.

RECOVERY_CODE_COUNT = 10
#: No l/1/o/0. These get read aloud down a phone line and written on paper.
_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"

#: SIXTEEN characters, not ten, and the arithmetic is the whole reason.
#: `recovery_fingerprint` is an unsalted single-round SHA-256 — correct for a
#: high-entropy random string, and only if it really is high-entropy. At ten
#: characters over this 31-symbol alphabet a code is 31**10, about 2**49.5, which a
#: commodity GPU walks through against a leaked table in minutes; the digests are
#: unsalted, so all of them fall to one pass. At sixteen it is 31**16, about
#: 2**79.3, which puts the same attack out of reach and keeps the SHA-256
#: rationale honest instead of aspirational.
#:
#: Lengthening is deliberately preferred to peppering with SESSION_SECRET: that
#: would bind every stored code to one environment variable, turning a rotation
#: that costs nothing today into silent mass invalidation of everybody's last way
#: back into the product.
_RECOVERY_LENGTH = 16


def new_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> List[str]:
    """Single-use fallbacks, shown once at enrolment and stored only as hashes."""
    def one() -> str:
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET)
                      for _ in range(_RECOVERY_LENGTH))
        return "-".join(raw[i:i + 4] for i in range(0, _RECOVERY_LENGTH, 4))
    return [one() for _ in range(count)]


def recovery_fingerprint(code: str) -> str:
    """What the database stores.

    SHA-256 rather than PBKDF2, for the same reason session tokens are not
    stretched: a code is ~50 bits of uniform randomness with no structure to
    guess at, so stretching buys nothing against an offline attacker and would
    put a deliberate delay on a login path. What it does buy is that a leaked
    table yields no usable codes.

    Normalisation matches what a human types: case and the grouping hyphen are
    not part of the secret.
    """
    normalised = (code or "").strip().lower().replace(" ", "").replace("-", "")
    return hashlib.sha256(normalised.encode("utf-8")).hexdigest()
