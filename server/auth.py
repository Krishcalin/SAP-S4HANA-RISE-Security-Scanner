# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
Authentication and role-based access control.

Single-tenant, so the scoping axes are ROLE (what you may do) and SYSTEM (which
rows you may see). Per-system scoping exists from day one because a row filter
retrofitted later is a row filter that will be missing from somewhere.

Password hashing uses PBKDF2-HMAC-SHA256 from the standard library rather than
bcrypt/argon2. That is a deliberate trade: it keeps the dependency count in
single digits, and it is what `hashlib` actually gives us. The iteration count is
stored per-hash so it can be raised later without invalidating existing
passwords.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from server import db, totp
from server.config import settings

#: Raise freely; existing hashes carry their own iteration count and keep working.
PBKDF2_ITERATIONS = 600_000
_ALGO = "pbkdf2_sha256"

#: Rank order. A route requiring 'analyst' also admits 'admin'.
ROLE_RANK = {"viewer": 0, "analyst": 1, "admin": 2}


class AuthError(Exception):
    pass


def hash_password(password: str, *, iterations: int = PBKDF2_ITERATIONS) -> str:
    if len(password) < 12:
        raise AuthError("password must be at least 12 characters")
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{_ALGO}${iterations}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_hex, hash_hex = stored.split("$", 3)
        if algo != _ALGO:
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                 bytes.fromhex(salt_hex), int(iters))
    except (ValueError, TypeError):
        return False
    # Constant time: a timing oracle here leaks whether a prefix was correct.
    return hmac.compare_digest(dk.hex(), hash_hex)


def create_user(username: str, password: str, role: str = "viewer",
                display_name: str = "", must_change: bool = False) -> int:
    if role not in ROLE_RANK:
        raise AuthError(f"unknown role {role!r}")
    with db.connection() as conn:
        row = conn.execute(
            "INSERT INTO app_user (username, display_name, password_hash, role, "
            "must_change_password) VALUES (%s,%s,%s,%s,%s) RETURNING id",
            (username, display_name or username, hash_password(password), role,
             must_change)
        ).fetchone()
        db.audit(conn, "system", "user.create", "app_user", str(row["id"]),
                 {"username": username, "role": role})
        conn.commit()
        return row["id"]


def authenticate(username: str, password: str, *,
                 stamp_login: bool = True) -> Optional[Dict[str, Any]]:
    """Check a password. Returns the user row, or None.

    `stamp_login=False` EXISTS FOR THE SECOND FACTOR. This function used to record
    `last_login_at` the moment the password matched, which was correct while a
    correct password was a completed sign-in. It no longer is: a login refused at
    the code prompt would otherwise be written down as a successful login, so the
    column would report the attacker who knows the password rather than the person
    who actually got in. The login route passes False and stamps the column itself,
    on the same connection as the session INSERT, once BOTH factors have passed.

    The default stays True so every existing caller and test behaves as before.
    """
    user = db.one("SELECT * FROM app_user WHERE username = %s AND is_active",
                  (username,))
    if user is None:
        # Hash anyway so a missing user and a wrong password take the same time;
        # otherwise the response time enumerates valid usernames.
        hash_password("x" * 12)
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    if stamp_login:
        db.execute("UPDATE app_user SET last_login_at = now() WHERE id = %s",
                   (user["id"],))
    return user


def create_session(user_id: int, user_agent: str = "",
                   conn: Optional[Any] = None) -> str:
    """Mint a session token.

    `conn` lets the caller enrol this INSERT in a transaction it already owns. The
    login route needs that: consuming the TOTP counter (or a recovery code),
    creating the session and stamping `last_login_at` have to commit together, or a
    crash between them either hands out a session whose code can be replayed or
    burns a recovery code that bought nothing.
    """
    token = secrets.token_urlsafe(48)
    expires = datetime.now(timezone.utc) + timedelta(hours=settings.session_ttl_hours)
    sql = ("INSERT INTO session (token, user_id, expires_at, user_agent) "
           "VALUES (%s,%s,%s,%s)")
    params = (token, user_id, expires, user_agent[:500])
    if conn is not None:
        conn.execute(sql, params)
    else:
        db.execute(sql, params)
    return token


def resolve_session(token: Optional[str]) -> Optional[Dict[str, Any]]:
    """Return the session's user, or None. Expired sessions are deleted on sight."""
    if not token:
        return None
    row = db.one(
        "SELECT s.token, s.expires_at, u.* FROM session s "
        "JOIN app_user u ON u.id = s.user_id "
        "WHERE s.token = %s AND u.is_active", (token,))
    if row is None:
        return None
    if row["expires_at"] <= datetime.now(timezone.utc):
        db.execute("DELETE FROM session WHERE token = %s", (token,))
        return None
    return row


def destroy_session(token: str) -> None:
    db.execute("DELETE FROM session WHERE token = %s", (token,))


# --------------------------------------------------------------------------- #
#  Password change                                                            #
# --------------------------------------------------------------------------- #

def set_password(user_id: int, new_password: str, actor: str,
                 keep_token: Optional[str] = None) -> None:
    """Replace a user's password and invalidate their OTHER sessions.

    THE OTHER SESSIONS MATTER AS MUCH AS THE PASSWORD.
    Changing a password is what someone does when they believe a credential has
    leaked. If existing sessions kept working, the change would accomplish nothing
    against the case it exists for: whoever holds the stolen cookie keeps their
    access until it expires. So every session but the caller's own is dropped.

    `keep_token` is the caller's own session — "log me out everywhere else, not
    here". Omitting it logs the user out everywhere, which is the correct
    behaviour when an ADMIN resets somebody else's password.
    """
    hashed = hash_password(new_password)
    with db.connection() as conn:
        conn.execute(
            "UPDATE app_user SET password_hash = %s, must_change_password = false, "
            "password_changed_at = now() WHERE id = %s", (hashed, user_id))
        if keep_token:
            conn.execute("DELETE FROM session WHERE user_id = %s AND token <> %s",
                         (user_id, keep_token))
        else:
            conn.execute("DELETE FROM session WHERE user_id = %s", (user_id,))
        # UNUSED RECOVERY CODES GO TOO, and the reason is the same one the docstring
        # gives for the sessions. Someone changing their password believes a
        # credential has leaked. Recovery codes ARE credentials — each one is a
        # single-use bypass of the second factor — and they are handed out on paper,
        # which is exactly the kind of thing that leaks alongside a password. Leaving
        # them live would invalidate two of the three ways in and quietly keep the
        # third. Spent rows are kept so a used code can never be re-minted.
        dropped = conn.execute(
            "DELETE FROM recovery_code WHERE user_id = %s AND used_at IS NULL "
            "RETURNING id", (user_id,)).fetchall()
        # The EVENT is audited. The value never is, here or anywhere.
        db.audit(conn, actor, "user.password_change", "app_user", str(user_id),
                 {"other_sessions_revoked": True,
                  "recovery_codes_invalidated": len(dropped)})
        conn.commit()


def reset_password(user_id: int, actor: str) -> str:
    """Admin path: mint a new password and force the holder to replace it.

    Returns the generated password so it can be handed over ONCE. It is never
    stored in the clear and never written to the audit log — the log records that
    a reset happened, which is what an auditor needs; the secret is not.
    """
    new = secrets.token_urlsafe(18)
    set_password(user_id, new, actor)              # drops ALL that user's sessions
    db.execute("UPDATE app_user SET must_change_password = true WHERE id = %s",
               (user_id,))
    return new


def must_change_password(user: Dict[str, Any]) -> bool:
    return bool(user.get("must_change_password"))


def has_role(user: Dict[str, Any], required: str) -> bool:
    return ROLE_RANK.get(user.get("role", ""), -1) >= ROLE_RANK[required]


def scope_for(user: Dict[str, Any]) -> Optional[List[int]]:
    """The system ids this user may see, or None for all.

    Admins are unrestricted by design — an admin who cannot see a system cannot
    administer it, and a half-scoped admin produces confusing, silently
    incomplete answers.
    """
    if user.get("role") == "admin":
        return None
    return db.visible_system_ids(user["id"])


# --------------------------------------------------------------------------- #
#  Second factor (TOTP)                                                       #
# --------------------------------------------------------------------------- #
# THIS MODULE IS THE ONLY CALLER OF `totp.verify()`, AND THAT IS DELIBERATE.
# `totp.verify` returns the counter it matched rather than a bool precisely so the
# caller can persist it and refuse a replay. A route that called it directly would
# get a truthy value and a working login, and would silently skip the counter
# advance — leaving a code replayable for up to 90 seconds by anyone who read it
# over a shoulder. Keeping the primitive behind this layer means the advance and
# the answer cannot be separated. If you find `totp.verify` called anywhere else,
# that call is a bug.

#: An enrolment nobody has proved goes stale. Without this, a `pending_secret` mint
#: is permanent: a QR shown on a shared screen months ago would still confirm.
PENDING_TTL = timedelta(minutes=15)


def totp_row(user_id: int, conn: Optional[Any] = None) -> Optional[Dict[str, Any]]:
    sql = ("SELECT user_id, secret, pending_secret, pending_at, confirmed_at, "
           "last_counter, created_at FROM app_totp WHERE user_id = %s")
    if conn is not None:
        return conn.execute(sql, (user_id,)).fetchone()
    return db.one(sql, (user_id,))


def totp_active(user_id: int) -> bool:
    """Whether this account has a LIVE second factor.

    The one definition of "enrolled", so that no caller invents its own. In
    particular, never test `secret` for truthiness: a row can hold a pending
    secret and no live one, and reading that as enrolled would demand a code the
    user has never successfully produced — locking them out of their own account.
    """
    row = totp_row(user_id)
    return bool(row and row["secret"] and row["confirmed_at"])


def totp_status(user_id: int) -> Dict[str, Any]:
    """What the account screen and the CLI both render."""
    row = totp_row(user_id)
    pending = bool(row and row["pending_secret"] and not (row["confirmed_at"]))
    if pending and row["pending_at"] is not None:
        pending = (datetime.now(timezone.utc) - row["pending_at"]) <= PENDING_TTL
    return {
        "enabled": bool(row and row["secret"] and row["confirmed_at"]),
        "pending": pending,
        "confirmed_at": row["confirmed_at"] if row else None,
        "last_counter": row["last_counter"] if row else None,
        "recovery_codes_left": recovery_codes_left(user_id),
    }


def begin_totp(user: Dict[str, Any]) -> Dict[str, str]:
    """Mint a PENDING secret and return what the console needs to show.

    Writes `pending_secret` and nothing else — never `secret`, never
    `confirmed_at`. That is the whole reason those are separate columns: this call
    is reachable with a session cookie, so if it could touch the live secret then
    a stolen session could replace someone's factor with one in the attacker's own
    authenticator, or clear it and downgrade the account to password-only.

    Refusing while a factor is confirmed is enforced HERE as well as in the route,
    so the next caller inherits the guard instead of having to remember it.
    """
    if totp_active(user["id"]):
        raise AuthError("a second factor is already enabled for this account")

    secret = totp.new_secret()
    db.execute(
        "INSERT INTO app_totp (user_id, pending_secret, pending_at) "
        "VALUES (%s, %s, now()) "
        "ON CONFLICT (user_id) DO UPDATE SET pending_secret = EXCLUDED.pending_secret, "
        "pending_at = EXCLUDED.pending_at",
        (user["id"], secret))
    return {
        "secret": secret,
        "formatted_secret": totp.format_secret(secret),
        "uri": totp.provisioning_uri(secret, user["username"]),
    }


def confirm_totp(user: Dict[str, Any], code: str, actor: str,
                 keep_token: Optional[str] = None) -> List[str]:
    """Promote a pending enrolment to live and return the recovery codes ONCE.

    Requiring a working code before the factor goes live is what makes a mistyped
    secret or a failed scan harmless — it simply does not enrol, rather than
    locking the account behind a secret nobody holds.
    """
    row = totp_row(user["id"])
    if row and row["secret"] and row["confirmed_at"]:
        raise AuthError("a second factor is already enabled for this account")
    if not row or not row["pending_secret"]:
        raise AuthError("no enrolment is in progress")
    if row["pending_at"] is None or \
            (datetime.now(timezone.utc) - row["pending_at"]) > PENDING_TTL:
        raise AuthError("that enrolment expired — start again")

    counter = totp.verify(row["pending_secret"], code)
    if counter is None:
        raise AuthError("that code did not match")

    codes = totp.new_recovery_codes()
    with db.connection() as conn:
        # Promote and consume the counter in the same statement. Verifying a code
        # at enrolment IS a use of it: without this the code typed on a
        # screen-shared onboarding call stays valid for up to another 60 seconds.
        conn.execute(
            "UPDATE app_totp SET secret = pending_secret, confirmed_at = now(), "
            "last_counter = %s, pending_secret = NULL, pending_at = NULL "
            "WHERE user_id = %s", (counter, user["id"]))
        conn.execute("DELETE FROM recovery_code WHERE user_id = %s", (user["id"],))
        for plain in codes:
            conn.execute(
                "INSERT INTO recovery_code (user_id, code_hash) VALUES (%s, %s)",
                (user["id"], totp.recovery_fingerprint(plain)))
        # Every OTHER session predates the factor and was established with one
        # credential. Leaving them alive would mean enabling 2FA protects the next
        # sign-in and not the stolen cookie already in play.
        if keep_token:
            conn.execute("DELETE FROM session WHERE user_id = %s AND token <> %s",
                         (user["id"], keep_token))
        else:
            conn.execute("DELETE FROM session WHERE user_id = %s", (user["id"],))
        db.audit(conn, actor, "user.totp_enabled", "app_user", str(user["id"]),
                 {"recovery_codes_issued": len(codes)})
        conn.commit()
    return codes


def disable_totp(user_id: int, actor: str, *, reason: str = "self") -> bool:
    """Remove the factor entirely. Returns whether anything was there.

    DELETEs the row rather than nulling its columns, so a stale `last_counter`
    cannot survive to poison the next enrolment — a fresh secret with an inherited
    replay floor would reject perfectly good codes until the clock caught up.
    """
    with db.connection() as conn:
        gone = conn.execute("DELETE FROM app_totp WHERE user_id = %s RETURNING user_id",
                            (user_id,)).fetchone()
        conn.execute("DELETE FROM recovery_code WHERE user_id = %s", (user_id,))
        db.audit(conn, actor, "user.totp_disabled", "app_user", str(user_id),
                 {"reason": reason, "was_enrolled": bool(gone)})
        conn.commit()
    return bool(gone)


def regenerate_recovery_codes(user_id: int, actor: str) -> List[str]:
    """Replace the set and return the new codes once. The old ones stop working."""
    codes = totp.new_recovery_codes()
    with db.connection() as conn:
        conn.execute("DELETE FROM recovery_code WHERE user_id = %s", (user_id,))
        for plain in codes:
            conn.execute(
                "INSERT INTO recovery_code (user_id, code_hash) VALUES (%s, %s)",
                (user_id, totp.recovery_fingerprint(plain)))
        db.audit(conn, actor, "user.totp_recovery_regenerated", "app_user",
                 str(user_id), {"issued": len(codes)})
        conn.commit()
    return codes


def recovery_codes_left(user_id: int) -> int:
    row = db.one("SELECT count(*) AS n FROM recovery_code "
                 "WHERE user_id = %s AND used_at IS NULL", (user_id,))
    return int(row["n"]) if row else 0


def verify_second_factor(conn: Any, user_id: int, code: str) -> Optional[str]:
    """Check a code against the live factor. Returns 'totp', 'recovery', or None.

    TAKES THE CALLER'S CONNECTION ON PURPOSE. Both branches below AUTHORISE BY
    WRITING: the counter advance and the recovery-code consume are conditional
    UPDATEs whose `RETURNING` row is the proof, not a value read beforehand and
    compared afterwards. That closes the race where two requests carrying the same
    code both read the old state and both succeed — which, for a recovery code,
    means one code opening two sessions. Because it is the caller's transaction,
    the consume commits with the session INSERT or neither happens.

    A recovery code is a SECOND-FACTOR fallback, never a password fallback: this
    is only ever reached after `authenticate` has already returned a user.
    """
    row = totp_row(user_id, conn)
    if not row or not row["secret"] or not row["confirmed_at"]:
        return None                       # no live factor; caller should not be here

    counter = totp.verify(row["secret"], code, after_counter=row["last_counter"])
    if counter is not None:
        advanced = conn.execute(
            "UPDATE app_totp SET last_counter = %s "
            "WHERE user_id = %s AND last_counter < %s RETURNING user_id",
            (counter, user_id, counter)).fetchone()
        return "totp" if advanced else None

    spent = conn.execute(
        "UPDATE recovery_code SET used_at = now() "
        "WHERE user_id = %s AND code_hash = %s AND used_at IS NULL RETURNING id",
        (user_id, totp.recovery_fingerprint(code))).fetchone()
    return "recovery" if spent else None


# --------------------------------------------------------------------------- #
#  The attempt budget                                                         #
# --------------------------------------------------------------------------- #
# Six digits across a +/-1 step window is 10**6 possibilities with a ~90 second
# life. Unlimited guesses make the second factor decorative, so there is a cap.
#
# THE ARITHMETIC, WRITTEN DOWN SO NOBODY RELAXES IT WITHOUT SEEING THE COST.
# At 5 attempts per 15 minutes a persistent attacker gets 480 guesses a day, so
# the chance of hitting a specific 6-digit code inside a year is about
# 480*365/10**6, roughly 1 in 6. That is far too generous to leave uncapped and
# unremarkable once capped, because each guess must ALSO be accompanied by a
# correct password — this counter is only reachable after authentication succeeds.
#
# Three counters, not one, and they are separate on purpose:
#   pw:<username>   a password guesser must not be able to lock out the real user
#                   by burning their SECOND-FACTOR budget, and vice versa
#   2fa:<username>  only reachable by someone who already knows the password
#   ip:<address>    the denial-of-service half; generous, because behind a proxy
#                   every request appears to come from one address
#
# Blocks SELF-CLEAR. Nothing here ever sets is_active = false: a lockout an
# administrator must lift converts a nuisance into an outage, and that is how
# rate limiting gets removed rather than tuned.
_THROTTLE_POLICY = {
    "ip": (30, timedelta(minutes=15)),
    "pw": (10, timedelta(minutes=15)),
    "2fa": (5, timedelta(minutes=15)),
}


def throttle_scope(kind: str, value: str) -> str:
    """`kind:value`, with the value normalised.

    Keyed on the username AS SUBMITTED (folded and trimmed), not on a resolved
    user id — a budget that only exists for accounts that exist is a username
    oracle, because unknown names would never be throttled.
    """
    return f"{kind}:{(value or '').strip().lower()[:200]}"


def throttle_check(scope: str) -> bool:
    """True if the caller may proceed. Never raises, never blocks permanently."""
    row = db.one("SELECT blocked_until FROM auth_attempt WHERE scope = %s", (scope,))
    if row is None or row["blocked_until"] is None:
        return True
    return row["blocked_until"] <= datetime.now(timezone.utc)


def throttle_fail(scope: str) -> None:
    """Record a failure and start a block once the budget is spent."""
    kind = scope.split(":", 1)[0]
    limit, window = _THROTTLE_POLICY.get(kind, (10, timedelta(minutes=15)))
    row = db.one(
        "INSERT INTO auth_attempt (scope, failures, updated_at) VALUES (%s, 1, now()) "
        "ON CONFLICT (scope) DO UPDATE SET failures = CASE "
        "    WHEN auth_attempt.blocked_until IS NOT NULL "
        "         AND auth_attempt.blocked_until <= now() THEN 1 "
        "    WHEN auth_attempt.updated_at < now() - %s THEN 1 "
        "    ELSE auth_attempt.failures + 1 END, "
        "  blocked_until = CASE "
        "    WHEN auth_attempt.blocked_until IS NOT NULL "
        "         AND auth_attempt.blocked_until <= now() THEN NULL "
        "    ELSE auth_attempt.blocked_until END, "
        "  updated_at = now() "
        "RETURNING failures", (scope, window))
    if row and row["failures"] >= limit:
        db.execute("UPDATE auth_attempt SET blocked_until = now() + %s WHERE scope = %s",
                   (window, scope))


def throttle_clear(scope: str) -> None:
    """A success wipes the budget — otherwise a user who fat-fingers a code four
    times and then gets it right stays one typo from a lockout all afternoon."""
    db.execute("DELETE FROM auth_attempt WHERE scope = %s", (scope,))
