# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
The JSON authentication and account surface.

WHY THIS FILE EXISTS RATHER THAN A SECOND AUTH SYSTEM
-----------------------------------------------------
It was written while the console was migrating from server-rendered Jinja pages
to a React SPA. Those pages signed in with a form POST that answered with a 303
and a rendered page; a SPA cannot use that — it needs a status code and a body it
can branch on. So this module added a JSON *surface*, and nothing else. Every
credential decision below goes through `server.auth`: the same PBKDF2
verification, the same session table, the same "changing a password drops your
other sessions" rule. There is exactly one authentication scheme in this product
and this file is not a second one.

The Jinja routes are now deleted and this is the ONLY sign-in surface, which
changes nothing here: it was never a parallel implementation, so retiring the
other one removed a caller rather than a competitor.

WHY THE DEPENDENCIES LIVE HERE AND NOT IN app.py
`current_user` and `require` used to sit in app.py, which meant this module could
not import them without a cycle (app imports the router, the router imports app).
Rather than duplicate the resolution logic — the surest way to end up with two
subtly different notions of "signed in" — the dependencies moved down here and
app.py imports them. They are unchanged: same cookie, same forced-change gate,
same rank comparison. app.py is the only importer now and they still live here,
because moving them back would recreate the cycle the day anything else needs
them.

WHY THE BODIES ARE JSON AND NOT FORMS
It is a CSRF control, not a style choice. The session cookie is SameSite=Lax, so
a cross-site GET cannot carry it and a cross-site form POST is the remaining
worry. A browser will not send `Content-Type: application/json` cross-origin
without a preflight, and there is no CORS policy here to permit one — so a body
these routes will parse cannot be forged by a third-party page.

The rest of the API still takes `Form(...)` bodies, which the Jinja pages posted
to directly and which integrators now call. Do not "harmonise" the two by making
these routes accept form data: the asymmetry is the control. Sign-in and password
change are the two calls where a forged cross-site POST would actually be worth
something, and they are the two that refuse a form body.

WHAT IS DELIBERATELY NOT RETURNED
`auth.resolve_session` hands back the whole `app_user` row, `password_hash`
included. Every response below is built from an explicit field list rather than
by serialising that row. A `dict(user)` here would put a password hash on the
wire the first time someone added a column and forgot.
"""
from __future__ import annotations

from datetime import date, datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from server import auth, db, qr
from server.config import settings

#: The one session cookie name. app.py re-exports it — see the import note
#: there — so two modules can never hold two spellings of it.
SESSION_COOKIE = "sapsec_session"

#: Reachable while an account is still on a generated password. Every other API
#: call is refused with a 403 naming where to go until it is replaced, so a forced
#: account cannot simply be scripted around.
#:
#: These are how the console discovers it is being held at the gate
#: (`/api/auth/me`) and how it gets out (`/api/account/password`). Omitting them
#: would leave a forced account facing a console that 403s every request including
#: the one that would fix it — locked out by the mechanism meant to let them back
#: in.
#:
#: IT ONCE LISTED "/logout", "/login" AND "/health" TOO. Those were server-rendered
#: pages and their form targets; the pages are retired and the console is a static
#: bundle, which takes no session at all and never reaches this check — a compiled
#: file cannot be permission-gated and does not need to be, because it carries no
#: data. Strings that could not match anything were removed rather than left to
#: read as live policy: the only paths this gate can see are /api ones.
#:
#: EXACT PATHS, NOT PREFIXES, AND THAT CHANGED FOR A REASON.
#: This was `("/api/auth", "/api/account")` matched with `startswith`, which was
#: adequate while those prefixes held four routes. It stopped being adequate the
#: moment `/api/account/totp/*` existed: a prefix allowlist grants an exemption to
#: every route anyone adds under it, for ever, silently. `/api/account/totp/begin`
#: would have been reachable by an account still holding a generated password —
#: letting somebody bind a second factor to a credential that was printed to a
#: terminal and lives in `docker compose logs`, which is the one credential state
#: this product refuses to let anybody build on.
#:
#: Status and disable stay reachable so a forced account can SEE its factor and
#: remove one, and enrolling is what waits. `/api/account/reset/{user_id}` is now
#: also refused to a forced admin, which is correct and is asserted in the tests.
_ALLOWED_WHILE_FORCED = frozenset({
    "/api/auth/me",
    "/api/account",
    "/api/account/password",
    "/api/account/totp",
    "/api/account/totp/disable",
})


# --------------------------------------------------------------------------- #
#  Dependencies — the single definition of "signed in" and "allowed to"        #
# --------------------------------------------------------------------------- #

def current_user(request: Request) -> Dict[str, Any]:
    user = auth.resolve_session(request.cookies.get(SESSION_COOKIE))
    if user is None:
        raise HTTPException(status_code=401, detail="not authenticated")
    if auth.must_change_password(user) and \
            request.url.path not in _ALLOWED_WHILE_FORCED:
        # 303 is an INTERNAL signal, not what the caller sees. app.py's handler
        # for it answers 403 with `change_at`, naming the screen that fixes this.
        # It is raised as a 303 because it used to redirect a browser there, and
        # the code stayed when the redirect went: 403 is already raised by
        # `require` for "wrong role", and collapsing the two would lose the
        # distinction between "you may not" and "not until you replace that
        # password" at the only place the API can still tell them apart.
        raise HTTPException(status_code=303, detail="password change required")
    return user


def require(role: str):
    def dep(user: Dict[str, Any] = Depends(current_user)) -> Dict[str, Any]:
        if not auth.has_role(user, role):
            raise HTTPException(status_code=403, detail=f"requires {role}")
        return user
    return dep


# --------------------------------------------------------------------------- #
#  Serialisation                                                              #
# --------------------------------------------------------------------------- #

def _iso(value: Any) -> Optional[str]:
    """Timestamps as ISO-8601 strings, explicitly.

    NOT cosmetic. Two of the routes below build their own JSONResponse — login
    has to attach a Set-Cookie, and the rejections have to bypass the 401 handler
    that would rewrite their message — and a hand-built JSONResponse runs plain
    `json.dumps`, which does NOT know what a datetime is. FastAPI's automatic
    encoding hides that on the routes that return a dict, so the failure appears
    only on the SECOND sign-in of an account: `last_login_at` is null the first
    time and a datetime every time after. Converting here means both paths emit
    the same shape and neither can regress.
    """
    if value is None:
        return None
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return str(value)


def user_payload(user: Dict[str, Any]) -> Dict[str, Any]:
    """The signed-in user as the console may see them.

    An explicit field list. See the module docstring: the source row carries the
    password hash, and an allowlist is the only version of this that stays safe
    when a column is added.

    `scoped_system_ids` is null for an unrestricted user and a list otherwise,
    mirroring `auth.scope_for` exactly — the SPA needs to be able to say "you are
    seeing 3 of 11 systems" rather than quietly rendering a partial estate.
    """
    scope = auth.scope_for(user)
    return {
        "id": user["id"],
        "username": user["username"],
        "display_name": user.get("display_name") or user["username"],
        "role": user["role"],
        "is_admin": user["role"] == "admin",
        "can_write": auth.has_role(user, "analyst"),
        "must_change_password": auth.must_change_password(user),
        "last_login_at": _iso(user.get("last_login_at")),
        "password_changed_at": _iso(user.get("password_changed_at")),
        "scoped_system_ids": scope,
    }


# --------------------------------------------------------------------------- #
#  Request bodies                                                             #
# --------------------------------------------------------------------------- #
#  pydantic arrives with FastAPI — declaring a body shape is not a new runtime
#  dependency, and it is how FastAPI reports a malformed body as a 422 instead
#  of an AttributeError somewhere deeper.

class LoginBody(BaseModel):
    username: str
    password: str
    #: Six digits from an authenticator, OR a recovery code — deliberately the SAME
    #: field. Somebody whose phone is gone is already having a bad day and should
    #: not have to find a different box; the server tries the code as a TOTP first
    #: and falls through to consuming a recovery code. Optional because most
    #: accounts have no second factor and because the console cannot know whether
    #: this one does until the password has been accepted.
    totp_code: Optional[str] = None


class TotpAuthorisedBody(BaseModel):
    """Any change to the second factor re-proves the current password.

    `api_change_password` already states the rule this inherits — "a stolen session
    should not be enough to take an account over permanently" — and creating a
    factor is strictly more dangerous than changing a password, because it is what
    locks the legitimate owner out. Being a real body also means these routes
    inherit the refuse-a-form-body CSRF control described in the module docstring
    rather than being body-less POSTs.
    """
    current: str = Field(min_length=1)


class TotpCodeBody(TotpAuthorisedBody):
    #: A TOTP code, or an unused recovery code. Somebody who signed in WITH a
    #: recovery code cannot produce the former, and refusing them here would leave
    #: them able to sign in and unable to fix the state they are in.
    code: str = Field(min_length=1)


class PasswordBody(BaseModel):
    current: str
    #: `new1`/`new2` rather than one field: the confirmation exists so a typo in
    #: a password nobody can read back becomes an error message instead of a
    #: locked account. It is the only thing standing between a mistyped new
    #: password and an account nobody can sign into — there is no self-service
    #: reset, by design.
    new1: str = Field(min_length=1)
    new2: str = Field(min_length=1)


router = APIRouter(prefix="/api", tags=["auth"])


# --------------------------------------------------------------------------- #
#  Session                                                                    #
# --------------------------------------------------------------------------- #

@router.get("/auth/me")
def api_me(user: Dict[str, Any] = Depends(current_user)) -> Dict[str, Any]:
    """The signed-in user. 401 when there is no session.

    401 is the whole contract: it is what the SPA's AuthGate reads to decide
    between rendering the console and bouncing to the sign-in screen, and it is
    what makes an unauthenticated call fail closed. Answering 200 with a null
    user would be friendlier to write against and would turn every downstream
    screen's empty state into an indistinguishable "logged out or no data".
    """
    return user_payload(user)


@router.post("/auth/login")
def api_login(body: LoginBody, request: Request) -> Response:
    """Sign in and set the session cookie.

    The failure message is identical for an unknown username and a wrong
    password, and `auth.authenticate` hashes a dummy password when the user does
    not exist so the two take the same time. Do not "improve" either: both are
    username oracles.

    Returned rather than raised, because app.py's 401 handler rewrites every
    raised 401 under /api/ to "not authenticated" — which is true of a missing
    session and misleading on a rejected credential.
    """
    invalid = JSONResponse({"detail": "Invalid credentials"}, status_code=401)

    # THE BUDGET IS CHECKED BEFORE ANY HASHING, and that ordering is the control.
    # PBKDF2 at 600k iterations is the most expensive thing this process does, so
    # checking afterwards would leave the denial-of-service wide open. It also
    # keeps the refusal fast for EVERY username, known or not, so the throttle
    # cannot be timed to enumerate accounts.
    #
    # The refusal is byte-identical to a wrong password: never a 429, never a
    # "try again in N minutes". Both would confirm the account exists.
    ip_scope = auth.throttle_scope("ip", request.client.host if request.client else "")
    pw_scope = auth.throttle_scope("pw", body.username)
    tf_scope = auth.throttle_scope("2fa", body.username)
    if not (auth.throttle_check(ip_scope) and auth.throttle_check(pw_scope)
            and auth.throttle_check(tf_scope)):
        return invalid

    user = auth.authenticate(body.username, body.password, stamp_login=False)
    if user is None:
        auth.throttle_fail(ip_scope)
        auth.throttle_fail(pw_scope)
        return invalid
    auth.throttle_clear(pw_scope)

    # ONLY NOW may the existence of a second factor be revealed. Everything above
    # answers identically whether or not the account has one; asking before the
    # password is verified would hand out a map of which accounts are worth
    # phishing. The residual is deliberate and small: a caller holding a correct
    # password learns that this account has 2FA — by which point, if it did not,
    # they would simply be signed in.
    kind = "password"
    if auth.totp_active(user["id"]):
        code = (body.totp_code or "").strip()
        if not code:
            # `detail` is a plain string and the flag is TOP-LEVEL, because
            # app.py's 401 handler rewrites RAISED 401s and the console's
            # `failure()` helper drops dict-shaped details. Returned, not raised.
            return JSONResponse(
                {"detail": "Enter the 6-digit code from your authenticator app, "
                           "or a recovery code.",
                 "totp_required": True},
                status_code=401)

        with db.connection() as conn:
            kind = auth.verify_second_factor(conn, user["id"], code)
            if kind is None:
                db.audit(conn, user["username"], "auth.second_factor_failed",
                         "app_user", str(user["id"]), {})
                conn.commit()
                auth.throttle_fail(tf_scope)
                # The same body as a wrong password. A distinct message here would
                # tell a password-holder that they have the password.
                return invalid
            token = _finish_login(conn, user, request, kind)
        auth.throttle_clear(tf_scope)
    else:
        with db.connection() as conn:
            token = _finish_login(conn, user, request, kind)

    auth.throttle_clear(ip_scope)

    payload = user_payload(user)
    payload["used_recovery_code"] = kind == "recovery"
    payload["recovery_codes_left"] = (auth.recovery_codes_left(user["id"])
                                      if kind in ("totp", "recovery") else None)
    resp = JSONResponse(payload)
    resp.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax",
                    secure=request.url.scheme == "https",
                    max_age=settings.session_ttl_hours * 3600)
    return resp


def _finish_login(conn: Any, user: Dict[str, Any], request: Request,
                  kind: str) -> str:
    """Session, login stamp and audit — one transaction, or none of it.

    The second factor was consumed on this same connection. Committing the
    consume without the session would burn a recovery code that bought nothing;
    committing the session without the consume would leave the code replayable.
    `last_login_at` is stamped HERE rather than in `auth.authenticate` so a login
    refused at the code prompt is not recorded as a successful sign-in.
    """
    token = auth.create_session(user["id"], request.headers.get("user-agent", ""),
                                conn=conn)
    conn.execute("UPDATE app_user SET last_login_at = now() WHERE id = %s",
                 (user["id"],))
    db.audit(conn, user["username"], f"auth.login.{kind}", "app_user",
             str(user["id"]), {})
    conn.commit()
    return token


@router.post("/auth/logout")
def api_logout(request: Request) -> Response:
    """End the session SERVER-SIDE. Clearing the cookie is the consequence.

    Deleting only the cookie would leave a live row in `session` that anyone
    holding a copy of the token could keep using for its full TTL — a sign-out
    that signs nobody out. Answering 200 for a caller who had no session is
    deliberate: "you are now signed out" is true either way, and reporting
    otherwise would tell an attacker whether a token they hold is still live.
    """
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        auth.destroy_session(token)
    resp = JSONResponse({"signed_out": True})
    resp.delete_cookie(SESSION_COOKIE)
    return resp


# --------------------------------------------------------------------------- #
#  Account                                                                    #
# --------------------------------------------------------------------------- #

@router.get("/account")
def api_account(user: Dict[str, Any] = Depends(current_user)) -> Dict[str, Any]:
    """Everything the account screen renders, in one call.

    The user list is admin-only: a non-admin gets an empty list rather than a
    403, because the rest of the screen — their own password form — is theirs by
    right and must not be collateral damage of a permission they do not have.

    `password_changed_at` is on the list because the account screen's table has a
    "Password set" column and it is not decoration: an account whose password has
    NEVER been chosen is still holding the one that was generated for it and
    printed to a terminal, where it survives in scrollback and in
    `docker compose logs`. `must_change_password` answers a different question —
    it is cleared the moment somebody is let through — so an admin auditing which
    handover credentials are still live has only this column to read.
    """
    users: List[Dict[str, Any]] = []
    if user["role"] == "admin":
        users = [{"id": r["id"], "username": r["username"],
                  "display_name": r["display_name"], "role": r["role"],
                  "is_active": r["is_active"],
                  "last_login_at": _iso(r["last_login_at"]),
                  "password_changed_at": _iso(r["password_changed_at"]),
                  "must_change_password": r["must_change_password"]}
                 for r in db.query("SELECT * FROM app_user ORDER BY username")]
    sessions = db.one("SELECT count(*) n FROM session WHERE user_id = %s",
                      (user["id"],))
    return {
        "user": user_payload(user),
        "forced": auth.must_change_password(user),
        "sessions": sessions["n"] if sessions else 0,
        "users": users,
    }


@router.post("/account/password")
def api_change_password(body: PasswordBody, request: Request,
                        user: Dict[str, Any] = Depends(current_user)) -> Response:
    """Change your own password.

    The CURRENT password is required even though the caller is already signed in:
    a stolen session should not be enough to take an account over permanently.
    Three rules, in this order — they were written to match the Jinja form's so
    the two surfaces could not drift into accepting different passwords, and they
    are now simply the rules.

    `keep_token` is the caller's own session — every OTHER session for this
    account is dropped, which is the point of changing a password at all.
    """
    def refuse(msg: str) -> Response:
        # 400, not 401: the caller IS authenticated. A 401 here would send the
        # SPA's AuthGate to the sign-in screen and lose what they typed.
        return JSONResponse({"detail": msg}, status_code=400)

    if not auth.verify_password(body.current, user["password_hash"]):
        return refuse("Current password is incorrect.")
    if body.new1 != body.new2:
        return refuse("The new passwords do not match.")
    if body.new1 == body.current:
        return refuse("The new password must differ from the current one.")
    try:
        auth.set_password(user["id"], body.new1, user["username"],
                          keep_token=request.cookies.get(SESSION_COOKIE))
    except auth.AuthError as exc:
        return refuse(str(exc))
    return JSONResponse({"changed": True,
                         "other_sessions_revoked": True})


@router.post("/account/reset/{user_id}")
def api_reset_password(user_id: int,
                       admin: Dict[str, Any] = Depends(require("admin"))
                       ) -> Dict[str, Any]:
    """Admin resets someone else's password by GENERATING one.

    Never by choosing it: an admin who can set a known password can impersonate a
    user and leave nothing that user could distinguish from their own activity.

    The generated password is in THIS response body and nowhere else — never in a
    redirect, a query string or the audit log, all of which end up in browser
    history, proxy logs and the referer header. The screen that calls this must
    show it once and must not persist it.
    """
    target = db.one("SELECT username FROM app_user WHERE id = %s", (user_id,))
    if target is None:
        raise HTTPException(404, "no such user")
    if user_id == admin["id"]:
        raise HTTPException(400, "use the change-password form for your own account")
    new = auth.reset_password(user_id, admin["username"])
    return {"username": target["username"], "password": new}


# --------------------------------------------------------------------------- #
#  Second factor (TOTP)                                                       #
# --------------------------------------------------------------------------- #
# ONE RULE ACROSS ALL FOUR MUTATIONS: the current password is re-proved in the
# JSON body. Not just on `disable` — CREATING a factor is the dangerous direction,
# because a stolen session that enrols its own authenticator locks the legitimate
# owner out of an account whose password still works, and `disable` then demands a
# code only the attacker can produce.
#
# `disable` and `recovery` additionally require possession: a TOTP code or an
# unused recovery code. `begin` and `confirm` cannot, because at that point there
# is nothing to possess yet.


def _forced(user: Dict[str, Any]) -> Optional[Response]:
    """Belt and braces beside `_ALLOWED_WHILE_FORCED`.

    The allowlist already refuses these three paths, but that lives 300 lines away
    in a set a reader of this route will not necessarily look at. A second factor
    must not be bound to a password that was generated, printed to a terminal and
    left in `docker compose logs`.
    """
    if auth.must_change_password(user):
        return JSONResponse(
            {"detail": "Choose your own password before enrolling a second factor.",
             "change_at": "/account"}, status_code=403)
    return None


def _bad_password() -> Response:
    # 400, not 401: the caller IS authenticated. A 401 would bounce the SPA's
    # AuthGate to the sign-in screen and lose the form.
    return JSONResponse({"detail": "Current password is incorrect."}, status_code=400)


@router.get("/account/totp")
def api_totp_status(user: Dict[str, Any] = Depends(current_user)) -> Dict[str, Any]:
    """Whether this account has a second factor. No password required — it reports
    state the caller already has, and the account screen needs it on every load."""
    status = auth.totp_status(user["id"])
    return {
        "enabled": status["enabled"],
        "pending": status["pending"],
        "confirmed_at": _iso(status["confirmed_at"]),
        "recovery_codes_left": status["recovery_codes_left"],
    }


@router.post("/account/totp/begin")
def api_totp_begin(body: TotpAuthorisedBody,
                   user: Dict[str, Any] = Depends(current_user)) -> Response:
    """Mint a PENDING secret and return the QR, the URI and the typed fallback.

    Nothing here is a live factor yet. 409 while one is already enabled, so an
    existing enrolment can never be silently replaced — remove it first, which
    costs a code, which is the point.
    """
    refusal = _forced(user)
    if refusal is not None:
        return refusal
    if not auth.verify_password(body.current, user["password_hash"]):
        return _bad_password()
    try:
        started = auth.begin_totp(user)
    except auth.AuthError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=409)

    # `svg_or_empty`, never `to_svg`: the picture is a convenience and the secret
    # and the otpauth link each complete enrolment on their own, so a bug in the
    # encoder must degrade to "no image" rather than 500 the account screen.
    return JSONResponse({
        "secret": started["secret"],
        "formatted_secret": started["formatted_secret"],
        "uri": started["uri"],
        "qr_svg": qr.svg_or_empty(started["uri"]),
    })


@router.post("/account/totp/confirm")
def api_totp_confirm(body: TotpCodeBody, request: Request,
                     user: Dict[str, Any] = Depends(current_user)) -> Response:
    """Prove the pending secret works, then make it live.

    The recovery codes are in THIS response and nowhere else, exactly like a
    generated password: they are never stored in the clear and never audited.
    """
    refusal = _forced(user)
    if refusal is not None:
        return refusal
    if not auth.verify_password(body.current, user["password_hash"]):
        return _bad_password()
    try:
        codes = auth.confirm_totp(user, body.code, actor=user["username"],
                                  keep_token=request.cookies.get(SESSION_COOKIE))
    except auth.AuthError as exc:
        status = 409 if "already enabled" in str(exc) else 400
        return JSONResponse({"detail": str(exc)}, status_code=status)
    return JSONResponse({"enabled": True, "recovery_codes": codes,
                         "other_sessions_revoked": True})


@router.post("/account/totp/disable")
def api_totp_disable(body: TotpCodeBody,
                     user: Dict[str, Any] = Depends(current_user)) -> Response:
    """Remove the factor. Requires the password AND possession.

    Reachable while a password change is forced — see `_ALLOWED_WHILE_FORCED`.
    Someone locked out of their authenticator must be able to get back to a
    working account without an administrator, and they still have to prove both
    the password and a code or recovery code to do it.
    """
    if not auth.verify_password(body.current, user["password_hash"]):
        return _bad_password()
    if not auth.totp_active(user["id"]):
        return JSONResponse({"detail": "No second factor is enabled."},
                            status_code=409)
    with db.connection() as conn:
        kind = auth.verify_second_factor(conn, user["id"], body.code)
        conn.commit()
    if kind is None:
        return JSONResponse(
            {"detail": "That code did not match. Use a code from your "
                       "authenticator app, or one of your recovery codes."},
            status_code=400)
    auth.disable_totp(user["id"], actor=user["username"], reason=f"self:{kind}")
    return JSONResponse({"enabled": False})


@router.post("/account/totp/recovery")
def api_totp_recovery(body: TotpCodeBody,
                      user: Dict[str, Any] = Depends(current_user)) -> Response:
    """Replace the recovery codes. The previous set stops working immediately."""
    refusal = _forced(user)
    if refusal is not None:
        return refusal
    if not auth.verify_password(body.current, user["password_hash"]):
        return _bad_password()
    if not auth.totp_active(user["id"]):
        return JSONResponse({"detail": "No second factor is enabled."},
                            status_code=409)
    with db.connection() as conn:
        kind = auth.verify_second_factor(conn, user["id"], body.code)
        conn.commit()
    if kind is None:
        return JSONResponse({"detail": "That code did not match."}, status_code=400)
    codes = auth.regenerate_recovery_codes(user["id"], actor=user["username"])
    return JSONResponse({"recovery_codes": codes})
