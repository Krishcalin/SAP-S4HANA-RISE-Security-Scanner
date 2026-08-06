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

from server import db
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


def authenticate(username: str, password: str) -> Optional[Dict[str, Any]]:
    user = db.one("SELECT * FROM app_user WHERE username = %s AND is_active",
                  (username,))
    if user is None:
        # Hash anyway so a missing user and a wrong password take the same time;
        # otherwise the response time enumerates valid usernames.
        hash_password("x" * 12)
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    db.execute("UPDATE app_user SET last_login_at = now() WHERE id = %s", (user["id"],))
    return user


def create_session(user_id: int, user_agent: str = "") -> str:
    token = secrets.token_urlsafe(48)
    expires = datetime.now(timezone.utc) + timedelta(hours=settings.session_ttl_hours)
    db.execute(
        "INSERT INTO session (token, user_id, expires_at, user_agent) VALUES (%s,%s,%s,%s)",
        (token, user_id, expires, user_agent[:500]))
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
        # The EVENT is audited. The value never is, here or anywhere.
        db.audit(conn, actor, "user.password_change", "app_user", str(user_id),
                 {"other_sessions_revoked": True})
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
