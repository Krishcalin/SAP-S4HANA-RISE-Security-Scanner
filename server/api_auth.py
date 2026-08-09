"""
The JSON authentication and account surface.

WHY THIS FILE EXISTS RATHER THAN A SECOND AUTH SYSTEM
-----------------------------------------------------
The console is migrating from server-rendered Jinja pages to a React SPA. The
Jinja pages sign in with a form POST that answers with a 303 and a rendered page;
a SPA cannot use that — it needs a status code and a body it can branch on. So
this module adds a JSON *surface*, and nothing else. Every credential decision
below still goes through `server.auth`: the same PBKDF2 verification, the same
session table, the same "changing a password drops your other sessions" rule.
There is exactly one authentication scheme in this product and this file is not
a second one.

WHY THE DEPENDENCIES LIVE HERE AND NOT IN app.py
`current_user` and `require` used to sit in app.py, which meant this module could
not import them without a cycle (app imports the router, the router imports app).
Rather than duplicate the resolution logic — the surest way to end up with two
subtly different notions of "signed in" — the dependencies moved down here and
app.py imports them. They are unchanged: same cookie, same forced-change gate,
same rank comparison.

WHY THE BODIES ARE JSON AND NOT FORMS
It is a CSRF control, not a style choice. The session cookie is SameSite=Lax, so
a cross-site GET cannot carry it and a cross-site form POST is the remaining
worry. A browser will not send `Content-Type: application/json` cross-origin
without a preflight, and there is no CORS policy here to permit one — so a body
these routes will parse cannot be forged by a third-party page. The Jinja form
POSTs keep their form bodies and keep relying on SameSite; do not "harmonise"
these two by making the JSON routes accept form data.

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

from server import auth, db
from server.config import settings

#: The one session cookie name. app.py re-exports it for the Jinja routes.
SESSION_COOKIE = "sapsec_session"

#: Reachable while an account is still on a generated password. Everything else
#: redirects to /account until it is replaced — including the API, so a forced
#: account cannot simply be scripted around.
#:
#: The `/api/auth` and `/api/account` prefixes are on this list for the same
#: reason `/account` is: they are how the SPA discovers it is being held at the
#: gate and how it changes the password. Omitting them would leave a forced
#: account facing a console that 403s every request including the one that would
#: fix it — locked out by the mechanism meant to let them back in.
_ALLOWED_WHILE_FORCED = ("/account", "/logout", "/login", "/health",
                         "/api/auth", "/api/account")


# --------------------------------------------------------------------------- #
#  Dependencies — the single definition of "signed in" and "allowed to"        #
# --------------------------------------------------------------------------- #

def current_user(request: Request) -> Dict[str, Any]:
    user = auth.resolve_session(request.cookies.get(SESSION_COOKIE))
    if user is None:
        raise HTTPException(status_code=401, detail="not authenticated")
    if auth.must_change_password(user) and not request.url.path.startswith(
            _ALLOWED_WHILE_FORCED):
        # 303 rather than 403: the caller is authenticated and the fix is one
        # page away, so send them to it instead of refusing with no route out.
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


class PasswordBody(BaseModel):
    current: str
    #: `new1`/`new2` rather than one field: the confirmation exists so a typo in
    #: a password nobody can read back becomes an error message instead of a
    #: locked account, and dropping it here would delete that protection for
    #: every SPA user while the Jinja form kept it.
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
    user = auth.authenticate(body.username, body.password)
    if user is None:
        return JSONResponse({"detail": "Invalid credentials"}, status_code=401)

    token = auth.create_session(user["id"], request.headers.get("user-agent", ""))
    resp = JSONResponse(user_payload(user))
    resp.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax",
                    secure=request.url.scheme == "https",
                    max_age=settings.session_ttl_hours * 3600)
    return resp


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

    The user list is admin-only and mirrors the Jinja page exactly: a non-admin
    gets an empty list rather than a 403, because the rest of the screen — their
    own password form — is theirs by right and must not be collateral damage of
    a permission they do not have.

    `password_changed_at` is on the list because account.html's table has a
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
    Same three rules as the Jinja form, in the same order, so the two surfaces
    cannot drift into accepting different passwords.

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
