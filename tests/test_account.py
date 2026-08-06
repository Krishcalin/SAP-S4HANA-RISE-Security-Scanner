"""
Account self-service: changing a password, and being made to.

WHY THE FORM IS NOT ON THE LOGIN PAGE
The obvious place to put "change password" is next to the sign-in box. It must not
go there: that page is unauthenticated, so a change form on it would let anyone
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
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from urllib.parse import unquote

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
    return client.post("/login", data={"username": username, "password": password,
                                       "next": "/"})


# --------------------------------------------------------------------------- #
#  Changing your own password                                                 #
# --------------------------------------------------------------------------- #

def test_the_current_password_is_required(client, user):
    """A stolen session must not be enough to take the account over permanently."""
    from server import auth

    assert _login(client, user["username"], user["password"]).status_code == 303
    resp = client.post("/account/password", data={
        "current": "not-the-password", "new1": "replacement-pass-1",
        "new2": "replacement-pass-1"})
    assert resp.status_code == 303
    assert "incorrect" in unquote(resp.headers["location"])

    # And the password genuinely did not change.
    assert auth.authenticate(user["username"], user["password"]) is not None
    assert auth.authenticate(user["username"], "replacement-pass-1") is None


def test_the_two_new_entries_must_match(client, user):
    _login(client, user["username"], user["password"])
    resp = client.post("/account/password", data={
        "current": user["password"], "new1": "replacement-pass-1",
        "new2": "different-pass-999"})
    assert "do not match" in unquote(resp.headers["location"])


def test_the_new_password_must_differ_from_the_old(client, user):
    _login(client, user["username"], user["password"])
    resp = client.post("/account/password", data={
        "current": user["password"], "new1": user["password"],
        "new2": user["password"]})
    assert "differ" in unquote(resp.headers["location"])


def test_a_short_password_is_refused_by_the_same_rule_as_creation(client, user):
    _login(client, user["username"], user["password"])
    resp = client.post("/account/password", data={
        "current": user["password"], "new1": "short", "new2": "short"})
    assert "12 characters" in unquote(resp.headers["location"])


def test_changing_it_works_and_the_old_one_stops(client, user):
    from server import auth
    _login(client, user["username"], user["password"])
    resp = client.post("/account/password", data={
        "current": user["password"], "new1": "replacement-pass-1",
        "new2": "replacement-pass-1"})
    assert resp.status_code == 303 and "changed=true" in resp.headers["location"]
    assert auth.authenticate(user["username"], user["password"]) is None
    assert auth.authenticate(user["username"], "replacement-pass-1") is not None


# --------------------------------------------------------------------------- #
#  Sessions                                                                   #
# --------------------------------------------------------------------------- #

def test_changing_a_password_signs_out_every_OTHER_session(user):
    """The point of changing a password is usually that a credential leaked. If old
    sessions kept working, the change would do nothing about the case it exists
    for — the holder of a stolen cookie keeps their access until it expires."""
    from fastapi.testclient import TestClient
    from server import app as appmod, auth

    a = TestClient(appmod.app, follow_redirects=False)
    b = TestClient(appmod.app, follow_redirects=False)
    _login(a, user["username"], user["password"])
    _login(b, user["username"], user["password"])
    assert a.get("/findings").status_code == 200
    assert b.get("/findings").status_code == 200

    a.post("/account/password", data={"current": user["password"],
                                      "new1": "replacement-pass-1",
                                      "new2": "replacement-pass-1"})

    assert a.get("/findings").status_code == 200, \
        "the session that changed the password was signed out"
    assert b.get("/findings").status_code != 200, \
        "another session survived the password change — a stolen cookie would too"


def test_an_admin_reset_signs_the_target_out_everywhere(user):
    """Including the session they are using: an admin resets because something is
    wrong, and leaving the target's current session alive defeats it."""
    from fastapi.testclient import TestClient
    from server import app as appmod, auth, db

    victim = TestClient(appmod.app, follow_redirects=False)
    _login(victim, user["username"], user["password"])
    assert victim.get("/findings").status_code == 200

    auth.reset_password(user["id"], "an-admin")
    assert victim.get("/findings").status_code != 200
    assert db.one("SELECT count(*) n FROM session WHERE user_id = %s",
                  (user["id"],))["n"] == 0


# --------------------------------------------------------------------------- #
#  Forced change                                                              #
# --------------------------------------------------------------------------- #

def test_a_generated_password_forces_a_change_and_gates_the_whole_console(client):
    from server import auth, db

    name = f"forced_{os.urandom(4).hex()}"
    uid = auth.create_user(name, "generated-pass-999", "analyst", must_change=True)
    try:
        assert _login(client, name, "generated-pass-999").status_code == 303

        for path in ("/", "/findings", "/paths", "/risk", "/coverage"):
            r = client.get(path)
            assert r.status_code == 303 and r.headers["location"] == "/account", \
                f"{path} was reachable while a password change was outstanding"

        # The API is gated too, so the requirement cannot be scripted around.
        api = client.get("/api/findings")
        assert api.status_code == 403
        assert api.json()["change_at"] == "/account"

        # ...but the page that fixes it, and the way out, are reachable.
        assert client.get("/account").status_code == 200
        assert client.post("/logout").status_code == 303

        _login(client, name, "generated-pass-999")
        client.post("/account/password", data={"current": "generated-pass-999",
                                               "new1": "chosen-password-1",
                                               "new2": "chosen-password-1"})
        assert client.get("/findings").status_code == 200, \
            "the console stayed gated after the password was replaced"
        assert not db.one("SELECT must_change_password FROM app_user WHERE id = %s",
                          (uid,))["must_change_password"]
    finally:
        db.execute("DELETE FROM app_user WHERE id = %s", (uid,))


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
    assert client.post("/account/reset/1").status_code == 403


def test_an_admin_cannot_reset_their_own_password_this_way(client):
    """It would leave them holding a generated credential for no reason — the
    change form is right there and requires proving they hold the current one."""
    from server import auth, db
    name = f"adm_{os.urandom(4).hex()}"
    uid = auth.create_user(name, "admin-password-12", "admin")
    try:
        _login(client, name, "admin-password-12")
        r = client.post(f"/account/reset/{uid}")
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


def test_the_account_page_never_renders_a_password_hash(client, user):
    _login(client, user["username"], user["password"])
    body = client.get("/account").text
    from server import db
    stored = db.one("SELECT password_hash FROM app_user WHERE id = %s",
                    (user["id"],))["password_hash"]
    assert stored not in body
    assert "pbkdf2" not in body.lower()
