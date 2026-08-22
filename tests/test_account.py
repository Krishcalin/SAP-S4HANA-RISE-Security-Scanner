"""
Account self-service: changing a password, and being made to.

WHY THE FORM IS NOT ON THE LOGIN SCREEN
The obvious place to put "change password" is next to the sign-in box. It must not
go there: that screen is unauthenticated, so a change form on it would let anyone
change anyone's password. Changing a credential requires proving you hold it, so
the form lives inside the console and asks for the current password even though
the caller is already signed in — a stolen SESSION should not be enough to take an
account over permanently.

WHY A FORCED CHANGE EXISTS AT ALL
The first admin is created in a container with no TTY, so `create-user --generate`
mints a password and prints it to a terminal. It then lives in scrollback, in
`docker compose logs`, and in whatever recorded the session. That is a handover
credential, not a chosen one, so the account cannot use the console until it is
replaced.

WHAT MOVED WHEN THE SERVER-RENDERED CONSOLE WAS RETIRED
Every rule above is unchanged; only the surface that carries it is different. The
Jinja form POSTed to /account/password and reported failure by redirecting back
to /account?error=… , so these tests read a Location header. That form and its
route are deleted, and /api/account/password — which existed alongside them for
the whole migration and applies the SAME three rules in the same order — answers
400 with the reason in the body. The assertions below moved from the header to
the body and assert exactly what they asserted before.

The "is the console still gated" checks changed shape more deliberately. The
console is a static bundle: every screen address answers with the same index.html
whatever your session says, because a compiled file cannot be permission-checked.
That is not a weakening — it never carried data. The gate is on the API, so
"the whole console is gated" is now asserted where it is actually enforced, and
the screens are checked to be SERVED rather than to be authorised.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

pytestmark = pytest.mark.skipif(
    not os.getenv("DB_DSN"), reason="set DB_DSN to a PostgreSQL 16 instance")


@pytest.fixture()
def user():
    from server import auth, db
    db.init_schema()
    name = f"acct_{os.urandom(4).hex()}"
    uid = auth.create_user(name, "initial-password-1", "analyst")
    yield {"id": uid, "username": name, "password": "initial-password-1"}
    db.execute("DELETE FROM app_user WHERE id = %s", (uid,))


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient
    from server import app as appmod
    return TestClient(appmod.app, follow_redirects=False)


def _login(client, username, password):
    """Sign in the way the console does: a JSON body, a 200 and a Set-Cookie.

    The form POST that answered 303 went with the templates — it is unusable from
    a fetch, which cannot branch on a rendered page.
    """
    return client.post("/api/auth/login",
                       json={"username": username, "password": password})


def _change(client, current, new1, new2):
    return client.post("/api/account/password",
                       json={"current": current, "new1": new1, "new2": new2})


# --------------------------------------------------------------------------- #
#  Changing your own password                                                 #
# --------------------------------------------------------------------------- #

def test_the_current_password_is_required(client, user):
    """A stolen session must not be enough to take the account over permanently."""
    from server import auth

    assert _login(client, user["username"], user["password"]).status_code == 200
    resp = _change(client, "not-the-password", "replacement-pass-1",
                   "replacement-pass-1")
    # 400 and not 401: the caller IS authenticated. A 401 would send the console's
    # AuthGate to the sign-in screen and lose what they typed.
    assert resp.status_code == 400
    assert "incorrect" in resp.json()["detail"]

    # And the password genuinely did not change.
    assert auth.authenticate(user["username"], user["password"]) is not None
    assert auth.authenticate(user["username"], "replacement-pass-1") is None


def test_the_two_new_entries_must_match(client, user):
    _login(client, user["username"], user["password"])
    resp = _change(client, user["password"], "replacement-pass-1",
                   "different-pass-999")
    assert resp.status_code == 400
    assert "do not match" in resp.json()["detail"]


def test_the_new_password_must_differ_from_the_old(client, user):
    _login(client, user["username"], user["password"])
    resp = _change(client, user["password"], user["password"], user["password"])
    assert resp.status_code == 400
    assert "differ" in resp.json()["detail"]


def test_a_short_password_is_refused_by_the_same_rule_as_creation(client, user):
    _login(client, user["username"], user["password"])
    resp = _change(client, user["password"], "short", "short")
    assert resp.status_code == 400
    assert "12 characters" in resp.json()["detail"]


def test_changing_it_works_and_the_old_one_stops(client, user):
    from server import auth
    _login(client, user["username"], user["password"])
    resp = _change(client, user["password"], "replacement-pass-1",
                   "replacement-pass-1")
    assert resp.status_code == 200 and resp.json()["changed"] is True
    assert auth.authenticate(user["username"], user["password"]) is None
    assert auth.authenticate(user["username"], "replacement-pass-1") is not None


# --------------------------------------------------------------------------- #
#  Sessions                                                                   #
# --------------------------------------------------------------------------- #

def test_changing_a_password_signs_out_every_OTHER_session(user):
    """The point of changing a password is usually that a credential leaked. If old
    sessions kept working, the change would do nothing about the case it exists
    for — the holder of a stolen cookie keeps their access until it expires.

    Checked against /api/findings rather than the /findings screen: the screen is
    a static file and is served to anyone, so it can no longer tell a live session
    from a dead one. The API can, and it is where the data is.
    """
    from fastapi.testclient import TestClient
    from server import app as appmod

    a = TestClient(appmod.app, follow_redirects=False)
    b = TestClient(appmod.app, follow_redirects=False)
    _login(a, user["username"], user["password"])
    _login(b, user["username"], user["password"])
    assert a.get("/api/findings").status_code == 200
    assert b.get("/api/findings").status_code == 200

    _change(a, user["password"], "replacement-pass-1", "replacement-pass-1")

    assert a.get("/api/findings").status_code == 200, \
        "the session that changed the password was signed out"
    assert b.get("/api/findings").status_code != 200, \
        "another session survived the password change — a stolen cookie would too"


def test_an_admin_reset_signs_the_target_out_everywhere(user):
    """Including the session they are using: an admin resets because something is
    wrong, and leaving the target's current session alive defeats it."""
    from fastapi.testclient import TestClient
    from server import app as appmod, auth, db

    victim = TestClient(appmod.app, follow_redirects=False)
    _login(victim, user["username"], user["password"])
    assert victim.get("/api/findings").status_code == 200

    auth.reset_password(user["id"], "an-admin")
    assert victim.get("/api/findings").status_code != 200
    assert db.one("SELECT count(*) n FROM session WHERE user_id = %s",
                  (user["id"],))["n"] == 0


# --------------------------------------------------------------------------- #
#  Forced change                                                              #
# --------------------------------------------------------------------------- #

def test_a_generated_password_forces_a_change_and_gates_the_whole_console(client):
    """The gate, asserted where it is enforced.

    It used to be asserted on the PAGES: /, /findings, /paths each answered 303 to
    /account. Those addresses are now a static bundle and answer the same file to
    everyone, so a 200 from them says nothing about authorisation. Every one of
    them is useless without its data, and the data is what is checked here — which
    is the stronger claim of the two, because it is the one that would still hold
    if somebody scripted the console away entirely.
    """
    from server import auth, db

    name = f"forced_{os.urandom(4).hex()}"
    uid = auth.create_user(name, "generated-pass-999", "analyst", must_change=True)
    try:
        assert _login(client, name, "generated-pass-999").status_code == 200

        for endpoint in ("/api/dashboard", "/api/findings", "/api/paths",
                         "/api/risk", "/api/coverage", "/api/trend"):
            r = client.get(endpoint)
            assert r.status_code == 403, \
                f"{endpoint} was readable while a password change was outstanding"
            assert r.json()["change_at"] == "/account"

        # ...but the calls that fix it, and the way out, are reachable — or the
        # account is locked out by the mechanism meant to let it back in.
        assert client.get("/api/account").status_code == 200
        assert client.get("/api/auth/me").status_code == 200
        assert client.post("/api/auth/logout").status_code == 200

        _login(client, name, "generated-pass-999")
        _change(client, "generated-pass-999", "chosen-password-1", "chosen-password-1")
        assert client.get("/api/findings").status_code == 200, \
            "the console stayed gated after the password was replaced"
        assert not db.one("SELECT must_change_password FROM app_user WHERE id = %s",
                          (uid,))["must_change_password"]
    finally:
        db.execute("DELETE FROM app_user WHERE id = %s", (uid,))


def test_the_change_at_pointer_names_a_screen_that_exists():
    """`change_at` is the 403's only instruction, and a dangling one is worse than
    none: it sends a locked-out user to a URL that renders "page not found".

    It reads "/account" — the same string it carried when that was a Jinja page,
    because App.tsx declares a route at the identical path. The literal did not
    have to move, so it did not; what changed is WHO answers it. Asserting the
    string alone would pass on the day somebody renamed that route, so it is
    checked against the console's own route table instead.

    Needs no database — it is a claim about two files agreeing — but it lives here
    because it is the same decision as the test above, and the two must be read
    together.
    """
    from server import app as appmod

    handler_source = (ROOT / "server" / "app.py").read_text(encoding="utf-8")
    match = re.search(r'"change_at":\s*"([^"]+)"', handler_source)
    assert match, "the forced-change response no longer names where to go"
    change_at = match.group(1)

    app_tsx = (ROOT / "frontend" / "src" / "App.tsx").read_text(encoding="utf-8")
    routes = set(re.findall(r'<Route\s+path="([^"]+)"', app_tsx))
    assert change_at in routes, (
        f"change_at points at {change_at!r}, which the console does not declare as "
        f"a route: {sorted(routes)}")

    # And it is a console path, not an endpoint — the two are easy to confuse now
    # that both are served by the same process, and a client POSTing to it would
    # get a static file.
    assert not change_at.startswith("/api/"), \
        "change_at should name the screen a person opens, not the endpoint"
    paths = {r.path for r in appmod.app.routes if hasattr(r, "path")}
    assert change_at not in paths, \
        f"{change_at} is a server route again; it would shadow the console's screen"


def test_a_reset_password_is_generated_never_chosen(user):
    """An admin who can SET a known password can impersonate a user and leave
    nothing that user could distinguish from their own activity."""
    from server import auth, db
    new = auth.reset_password(user["id"], "an-admin")
    assert len(new) >= 20, "a generated password should not be guessable"
    assert auth.authenticate(user["username"], new) is not None
    assert db.one("SELECT must_change_password FROM app_user WHERE id = %s",
                  (user["id"],))["must_change_password"], \
        "the holder of a reset password must be made to replace it"


def test_a_non_admin_cannot_reset_anyone(client, user):
    _login(client, user["username"], user["password"])
    assert client.post("/api/account/reset/1").status_code == 403


def test_an_admin_cannot_reset_their_own_password_this_way(client):
    """It would leave them holding a generated credential for no reason — the
    change form is right there and requires proving they hold the current one."""
    from server import auth, db
    name = f"adm_{os.urandom(4).hex()}"
    uid = auth.create_user(name, "admin-password-12", "admin")
    try:
        _login(client, name, "admin-password-12")
        r = client.post(f"/api/account/reset/{uid}")
        assert r.status_code == 400
    finally:
        db.execute("DELETE FROM app_user WHERE id = %s", (uid,))


# --------------------------------------------------------------------------- #
#  Nothing leaks the secret                                                   #
# --------------------------------------------------------------------------- #

def test_the_audit_log_records_the_event_but_never_the_password(user):
    from server import auth, db
    auth.set_password(user["id"], "replacement-pass-1", user["username"])
    rows = db.query(
        "SELECT action, detail::text AS d FROM audit_log "
        "WHERE object_id = %s AND action = 'user.password_change'", (str(user["id"]),))
    assert rows, "a password change must be auditable"
    for r in rows:
        assert "replacement-pass-1" not in r["d"], "the audit log captured the secret"


def test_the_account_payload_never_carries_a_password_hash(client, user):
    """This used to read the rendered account page. The screen renders in the
    browser now, so the only thing it can put on screen is what this response
    contains — which makes the API the right place to assert it, and a stricter
    one: a hash absent from the page could still have been sent to the browser
    and read out of the network tab.

    Both halves of the payload are checked. `user` is built from an explicit
    field list in server/api_auth.py, and `users` — the admin list — is the one
    that would leak first, since it is built from `SELECT *`.
    """
    from server import db
    _login(client, user["username"], user["password"])
    body = client.get("/api/account").text
    stored = db.one("SELECT password_hash FROM app_user WHERE id = %s",
                    (user["id"],))["password_hash"]
    assert stored not in body
    assert "password_hash" not in body
    assert "pbkdf2" not in body.lower()


def test_an_admins_user_list_carries_no_hashes_either(client):
    """The `users` array is the one built from `SELECT *`, so it is the one an
    added column would leak through."""
    from server import auth, db
    name = f"adm_{os.urandom(4).hex()}"
    uid = auth.create_user(name, "admin-password-12", "admin")
    try:
        _login(client, name, "admin-password-12")
        body = client.get("/api/account").json()
        assert body["users"], "an admin was handed an empty user list"
        for row in body["users"]:
            assert "password_hash" not in row
            assert not any("pbkdf2" in str(v).lower() for v in row.values())
    finally:
        db.execute("DELETE FROM app_user WHERE id = %s", (uid,))
