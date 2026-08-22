"""
The JSON authentication and account surface.

WHAT THIS FILE IS DEFENDING
---------------------------
The SPA needed status codes and bodies where the Jinja console had redirects and
rendered pages, so `server/api_auth.py` added a JSON surface over the SAME session
and password machinery. The risk in that shape of change is not that the new
routes fail — it is that they succeed while quietly relaxing something: an error
message that distinguishes an unknown user from a wrong password, a response that
serialises the user row and takes the password hash with it, a forced-password
gate that the new endpoints happen to sit outside of.

The tests below were written as PARITY assertions against the form-POST console
that already worked. That console is retired, so they are no longer comparisons —
they are the specification, and they get MORE important rather than less: there
is nothing left to notice a regression by contrast with. Two of them exist only
because the surface is JSON at all: an unauthenticated call fails closed, and a
JSON route will not accept a cross-site form body.

The first block needs no database on purpose. An unauthenticated request is
refused before anything touches the connection pool, and "fails closed" is
exactly the assertion that must never be skipped because an environment variable
was missing.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@pytest.fixture()
def anon():
    from fastapi.testclient import TestClient
    from server import app as appmod
    return TestClient(appmod.app, follow_redirects=False)


# --------------------------------------------------------------------------- #
#  Fail-closed — no database required, and never skipped                      #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("method,path", [
    ("get", "/api/auth/me"),
    ("get", "/api/account"),
    ("post", "/api/account/password"),
    ("post", "/api/account/reset/1"),
])
def test_an_unauthenticated_call_is_refused(anon, method, path):
    resp = getattr(anon, method)(path)
    assert resp.status_code == 401, f"{path} answered {resp.status_code}"
    assert resp.json()["detail"] == "not authenticated"


def test_me_answers_401_rather_than_a_null_user(anon):
    """The whole contract of /auth/me. Answering 200 with a null body would be
    easier to write against and would make every downstream screen's empty state
    indistinguishable from "signed out"."""
    resp = anon.get("/api/auth/me")
    assert resp.status_code == 401
    assert "username" not in resp.text


def test_signing_out_without_a_session_still_succeeds(anon):
    """"You are now signed out" is true either way. Reporting otherwise would
    tell an attacker whether a token they hold is still live."""
    resp = anon.post("/api/auth/logout")
    assert resp.status_code == 200
    assert resp.json()["signed_out"] is True


def test_the_json_login_refuses_a_form_body(anon):
    """This is a CSRF control, not pedantry.

    The session cookie is SameSite=Lax, so a cross-site form POST is the residual
    worry. A browser will not send application/json cross-origin without a
    preflight and there is no CORS policy here to grant one — so a body this
    route will parse cannot be forged by a third-party page. If it ever starts
    accepting form data, that property is gone.

    Only /auth/login is checked here: /account/password is behind the session
    dependency, so it answers 401 to an anonymous form POST and the body is never
    reached. The signed-in half of that assertion is below, under `pg`.
    """
    resp = anon.post("/api/auth/login", data={"username": "x", "password": "y"})
    assert resp.status_code == 422, \
        "the login route accepted a form body — a cross-site form POST could reach it"


def test_a_malformed_login_body_is_a_422_not_a_500(anon):
    assert anon.post("/api/auth/login", json={"username": "only"}).status_code == 422
    assert anon.post("/api/auth/login", json={}).status_code == 422


def test_the_json_login_is_the_only_one_left():
    """This used to assert the opposite half: that the Jinja form login still
    worked beside the JSON one, because the migration stayed reversible until
    every screen was done.

    Every screen is done, the templates are deleted, and the form's routes went
    with them — so the claim worth making now is that nothing is left behind that
    would let a form POST set a session by a second code path. `GET /login` is a
    console address served by the static mount, and `POST /login` is not a route
    at all. server/auth remains the single place a credential is checked, which
    was true throughout and is the reason this file exists.
    """
    from fastapi.testclient import TestClient
    from server import app as appmod

    paths = {r.path for r in appmod.app.routes if hasattr(r, "path")}
    assert "/login" not in paths, \
        "a server-side /login is back; there must be exactly one sign-in path"

    c = TestClient(appmod.app, follow_redirects=False)
    # The address still resolves, because it is the console's own sign-in screen —
    # and a 503 is the unbuilt-bundle answer, which is about the build and not
    # about routing.
    assert c.get("/login").status_code in (200, 503)
    # And a form POST to the JSON route is refused rather than quietly parsed;
    # see the CSRF note in server/api_auth.py.
    assert c.post("/api/auth/login",
                  data={"username": "x", "password": "y"}).status_code == 422


def test_the_session_cookie_is_named_once_and_shared():
    """Two modules holding two spellings of the cookie name is a bug that
    presents as "signing in works but nothing is signed in"."""
    from server import api_auth
    from server import app as appmod

    assert appmod.SESSION_COOKIE is api_auth.SESSION_COOKIE


def test_the_forced_change_allowlist_lets_a_held_account_reach_the_way_out():
    """A forced account is refused everywhere except the routes that release it.
    If the JSON endpoints were not on that list, a SPA user handed a generated
    password would face a console that 403s every request — including the one
    that would fix it. Locked out by the mechanism meant to let them back in."""
    from server.api_auth import _ALLOWED_WHILE_FORCED, current_user, router

    # EXACT MEMBERSHIP, NOT A PREFIX. This assertion used to be
    # `path.startswith(_ALLOWED_WHILE_FORCED)` against the tuple
    # ("/api/auth", "/api/account"), which was adequate until routes appeared
    # underneath those prefixes: a prefix allowlist silently exempts every route
    # anyone adds below it, for ever. `/api/account/totp/begin` inherited the
    # exemption the day it was written, which would have let an account still
    # holding a GENERATED password bind a second factor to it.
    for path in ("/api/auth/me", "/api/account", "/api/account/password"):
        assert path in _ALLOWED_WHILE_FORCED, \
            f"{path} is gated for a forced account and is how they would escape it"

    # ...and the rest of the API is still gated, or the requirement is decorative.
    for path in ("/api/findings", "/api/dashboard", "/api/paths",
                 "/api/account/reset/{user_id}"):
        assert path not in _ALLOWED_WHILE_FORCED

    # Enrolling a second factor is NOT an escape route. Status and disable are, so
    # a held account can see what it has and remove one.
    assert "/api/account/totp" in _ALLOWED_WHILE_FORCED
    assert "/api/account/totp/disable" in _ALLOWED_WHILE_FORCED
    for path in ("/api/account/totp/begin", "/api/account/totp/confirm",
                 "/api/account/totp/recovery"):
        assert path not in _ALLOWED_WHILE_FORCED, \
            f"{path} would let a generated password become a 2FA-protected account"

    # /api/auth/login and /api/auth/logout are absent DELIBERATELY: neither depends
    # on `current_user`, so the gate never runs for them and listing them would be
    # policy that cannot fire. Asserted rather than assumed, because the old prefix
    # covered them and their absence now looks like an oversight.
    ungated = {r.path for r in router.routes
               if not any(getattr(d.call, "__name__", "") == current_user.__name__
                          for d in (r.dependant.dependencies or []))}
    for path in ("/api/auth/login", "/api/auth/logout"):
        assert path in ungated, f"{path} now takes a session and must be re-examined"


# --------------------------------------------------------------------------- #
#  Everything below needs a real PostgreSQL                                   #
# --------------------------------------------------------------------------- #

pg = pytest.mark.skipif(not os.getenv("DB_DSN"),
                        reason="set DB_DSN to a PostgreSQL 16 instance")

PASSWORD = "initial-password-1"


@pytest.fixture()
def analyst():
    from server import auth, db
    db.init_schema()
    name = f"apiauth_{os.urandom(4).hex()}"
    uid = auth.create_user(name, PASSWORD, "analyst")
    yield {"id": uid, "username": name, "password": PASSWORD}
    db.execute("DELETE FROM app_user WHERE id = %s", (uid,))


@pytest.fixture()
def admin():
    from server import auth, db
    db.init_schema()
    name = f"apiadm_{os.urandom(4).hex()}"
    uid = auth.create_user(name, PASSWORD, "admin")
    yield {"id": uid, "username": name, "password": PASSWORD}
    db.execute("DELETE FROM app_user WHERE id = %s", (uid,))


def _signed_in(user):
    from fastapi.testclient import TestClient
    from server import app as appmod

    c = TestClient(appmod.app, follow_redirects=False)
    resp = c.post("/api/auth/login",
                  json={"username": user["username"], "password": user["password"]})
    assert resp.status_code == 200, resp.text
    return c


@pg
def test_signing_in_returns_the_user_and_sets_the_session(analyst):
    from server.api_auth import SESSION_COOKIE

    c = _signed_in(analyst)
    assert c.cookies.get(SESSION_COOKIE), "no session cookie was set"

    body = c.get("/api/auth/me").json()
    assert body["username"] == analyst["username"]
    assert body["role"] == "analyst"
    assert body["is_admin"] is False
    assert body["can_write"] is True
    assert body["must_change_password"] is False


@pg
def test_signing_in_a_SECOND_time_still_works(analyst):
    """A regression test for a bug this suite actually caught.

    `/auth/login` builds its own JSONResponse — it has to attach a Set-Cookie —
    and a hand-built JSONResponse runs plain `json.dumps`, which does not know
    what a datetime is. `last_login_at` is null on a first sign-in and a datetime
    on every one after, so the route worked perfectly for exactly one login per
    account and then 500'd forever. Any test that created a fresh user and signed
    in once would have passed.
    """
    _signed_in(analyst)
    body = _signed_in(analyst).get("/api/auth/me").json()
    assert isinstance(body["last_login_at"], str), \
        "last_login_at did not survive serialisation as a string"


@pg
def test_the_session_cookie_is_httponly(analyst):
    """JavaScript must not be able to read it: an XSS bug in the console then
    cannot exfiltrate a session, which is why the client holds no token."""
    from fastapi.testclient import TestClient
    from server import app as appmod

    c = TestClient(appmod.app, follow_redirects=False)
    resp = c.post("/api/auth/login",
                  json={"username": analyst["username"], "password": analyst["password"]})
    header = resp.headers["set-cookie"].lower()
    assert "httponly" in header
    assert "samesite=lax" in header


@pg
def test_a_wrong_password_and_an_unknown_user_are_indistinguishable(analyst):
    from fastapi.testclient import TestClient
    from server import app as appmod

    c = TestClient(appmod.app)
    wrong = c.post("/api/auth/login",
                   json={"username": analyst["username"], "password": "not-the-password"})
    nobody = c.post("/api/auth/login",
                    json={"username": "no-such-user-at-all", "password": "whatever"})

    assert wrong.status_code == nobody.status_code == 401
    assert wrong.json() == nobody.json(), "the response distinguishes the two — a username oracle"
    assert analyst["username"] not in wrong.text


@pg
def test_no_response_ever_carries_a_password_hash(analyst):
    from server import db

    c = _signed_in(analyst)
    stored = db.one("SELECT password_hash FROM app_user WHERE id = %s",
                    (analyst["id"],))["password_hash"]
    for path in ("/api/auth/me", "/api/account"):
        body = c.get(path).text
        assert stored not in body
        assert "pbkdf2" not in body.lower()
        assert "password_hash" not in body


@pg
def test_signing_out_destroys_the_session_server_side(analyst):
    c = _signed_in(analyst)
    assert c.get("/api/auth/me").status_code == 200

    assert c.post("/api/auth/logout").status_code == 200
    # Not merely "the cookie is gone": the row must be gone, or a copy of the
    # token would keep working for its full TTL.
    assert c.get("/api/auth/me").status_code == 401


@pg
def test_the_account_payload_carries_everything_the_account_screen_renders(analyst):
    c = _signed_in(analyst)
    body = c.get("/api/account").json()
    assert body["forced"] is False
    assert body["sessions"] >= 1
    assert body["users"] == [], "a non-admin was handed the user list"
    assert body["user"]["username"] == analyst["username"]


@pg
def test_an_admin_sees_the_user_list_and_a_non_admin_does_not(admin, analyst):
    body = _signed_in(admin).get("/api/account").json()
    names = {u["username"] for u in body["users"]}
    assert analyst["username"] in names
    assert all("password_hash" not in u for u in body["users"])


# --------------------------------------------------------------------------- #
#  Changing a password — the same three rules as the form                     #
# --------------------------------------------------------------------------- #

@pg
@pytest.mark.parametrize("payload,expected", [
    ({"current": "not-the-password", "new1": "replacement-pass-1",
      "new2": "replacement-pass-1"}, "incorrect"),
    ({"current": PASSWORD, "new1": "replacement-pass-1",
      "new2": "different-pass-999"}, "do not match"),
    ({"current": PASSWORD, "new1": PASSWORD, "new2": PASSWORD}, "differ"),
    ({"current": PASSWORD, "new1": "short", "new2": "short"}, "12 characters"),
])
def test_a_bad_password_change_is_refused_with_a_reason(analyst, payload, expected):
    from server import auth

    c = _signed_in(analyst)
    resp = c.post("/api/account/password", json=payload)
    # 400, not 401: the caller IS authenticated, and a 401 would bounce the SPA
    # to the sign-in screen and lose what they typed.
    assert resp.status_code == 400
    assert expected in resp.json()["detail"]
    assert auth.authenticate(analyst["username"], PASSWORD) is not None, \
        "the password changed despite the refusal"


@pg
def test_the_password_route_refuses_a_form_body_even_from_a_valid_session(analyst):
    """The other half of the CSRF assertion above: a signed-in browser is exactly
    the caller a cross-site form POST would ride on, so this is the case that
    matters. Refusing the body is what makes the SameSite cookie sufficient."""
    resp = _signed_in(analyst).post(
        "/api/account/password",
        data={"current": PASSWORD, "new1": "replacement-pass-1",
              "new2": "replacement-pass-1"})
    assert resp.status_code == 422

    from server import auth
    assert auth.authenticate(analyst["username"], PASSWORD) is not None, \
        "a form-encoded body changed the password"


@pg
def test_changing_a_password_works_and_signs_out_every_OTHER_session(analyst):
    """The point of changing a password is usually that a credential leaked. If
    old sessions kept working, the change would do nothing about the case it
    exists for."""
    from server import auth

    a = _signed_in(analyst)
    b = _signed_in(analyst)
    assert b.get("/api/auth/me").status_code == 200

    resp = a.post("/api/account/password",
                  json={"current": PASSWORD, "new1": "replacement-pass-1",
                        "new2": "replacement-pass-1"})
    assert resp.status_code == 200 and resp.json()["changed"] is True

    assert a.get("/api/auth/me").status_code == 200, \
        "the session that changed the password was signed out"
    assert b.get("/api/auth/me").status_code == 401, \
        "another session survived — a stolen cookie would too"
    assert auth.authenticate(analyst["username"], PASSWORD) is None
    assert auth.authenticate(analyst["username"], "replacement-pass-1") is not None


# --------------------------------------------------------------------------- #
#  Admin reset                                                                #
# --------------------------------------------------------------------------- #

@pg
def test_an_admin_reset_generates_a_password_and_forces_its_replacement(admin, analyst):
    from server import auth, db

    resp = _signed_in(admin).post(f"/api/account/reset/{analyst['id']}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["username"] == analyst["username"]
    assert len(body["password"]) >= 20, "a generated password should not be guessable"
    assert auth.authenticate(analyst["username"], body["password"]) is not None
    assert db.one("SELECT must_change_password FROM app_user WHERE id = %s",
                  (analyst["id"],))["must_change_password"], \
        "the holder of a reset password must be made to replace it"


@pg
def test_a_non_admin_cannot_reset_anyone(analyst):
    resp = _signed_in(analyst).post("/api/account/reset/1")
    assert resp.status_code == 403


@pg
def test_an_admin_cannot_reset_their_own_password_this_way(admin):
    """It would leave them holding a generated credential for no reason — the
    change form is right there and requires proving they hold the current one."""
    resp = _signed_in(admin).post(f"/api/account/reset/{admin['id']}")
    assert resp.status_code == 400


@pg
def test_resetting_an_unknown_user_is_a_404(admin):
    assert _signed_in(admin).post("/api/account/reset/999999999").status_code == 404


@pg
def test_the_generated_password_is_never_written_to_the_audit_log(admin, analyst):
    from server import db

    new = _signed_in(admin).post(f"/api/account/reset/{analyst['id']}").json()["password"]
    rows = db.query("SELECT detail::text AS d FROM audit_log WHERE object_id = %s",
                    (str(analyst["id"]),))
    for row in rows:
        assert new not in row["d"], "the audit log captured the generated secret"


# --------------------------------------------------------------------------- #
#  The forced-change gate, over the JSON surface                              #
# --------------------------------------------------------------------------- #

@pg
def test_a_forced_account_can_reach_the_way_out_and_nothing_else():
    from fastapi.testclient import TestClient
    from server import app as appmod, auth, db

    db.init_schema()
    name = f"forced_{os.urandom(4).hex()}"
    uid = auth.create_user(name, "generated-pass-999", "analyst", must_change=True)
    try:
        c = TestClient(appmod.app, follow_redirects=False)
        assert c.post("/api/auth/login",
                      json={"username": name, "password": "generated-pass-999"}
                      ).status_code == 200

        me = c.get("/api/auth/me")
        assert me.status_code == 200, "a held account cannot even ask who it is"
        assert me.json()["must_change_password"] is True
        assert c.get("/api/account").status_code == 200

        # The rest of the API is gated, so the requirement cannot be scripted around.
        gated = c.get("/api/findings")
        assert gated.status_code == 403
        assert gated.json()["change_at"] == "/account"

        assert c.post("/api/account/password",
                      json={"current": "generated-pass-999",
                            "new1": "chosen-password-1",
                            "new2": "chosen-password-1"}).status_code == 200
        assert c.get("/api/findings").status_code == 200, \
            "the console stayed gated after the password was replaced"
    finally:
        db.execute("DELETE FROM app_user WHERE id = %s", (uid,))


# --------------------------------------------------------------------------- #
#  RBAC on the read endpoints the SPA screens use                             #
# --------------------------------------------------------------------------- #

@pg
@pytest.mark.parametrize("path", [
    "/api/dashboard", "/api/systems", "/api/landscapes", "/api/paths",
    "/api/risk", "/api/coverage", "/api/trend", "/api/findings", "/api/views",
])
def test_the_new_read_endpoints_are_readable_by_a_viewer(path):
    """They are reads behind `current_user`, scoped by `auth.scope_for`. A viewer
    may read; nothing here is a write."""
    from fastapi.testclient import TestClient
    from server import app as appmod, auth, db

    db.init_schema()
    name = f"viewer_{os.urandom(4).hex()}"
    uid = auth.create_user(name, PASSWORD, "viewer")
    try:
        c = TestClient(appmod.app, follow_redirects=False)
        c.post("/api/auth/login", json={"username": name, "password": PASSWORD})
        assert c.get(path).status_code == 200, f"{path} refused a viewer"
    finally:
        db.execute("DELETE FROM app_user WHERE id = %s", (uid,))


#: Every write `frontend/src/api/client.ts` can issue, as (path, form body).
#:
#: THE LIST IS THE POINT. The SPA hides these controls behind `user.can_write`,
#: and a hidden button is not a permission — the server is. This enumerates the
#: whole write surface rather than a sample of it, because the failure this
#: guards against is one endpoint being added to the client and the router
#: without `require("analyst")`, which no partial list would notice.
#:
#: The ids are deliberately fictional. `require("analyst")` is a dependency, so
#: it is resolved BEFORE the path and body are validated: a viewer gets 403 and
#: never reaches the handler, which is exactly the ordering being asserted. Using
#: real ids would need an estate fixture and would let a 404 masquerade as a pass.
_SPA_WRITES = [
    ("/api/findings/999999999/state", {"state": "mitigated"}),
    ("/api/findings/999999999/assign", {"assignee": "somebody"}),
    ("/api/findings/bulk-state", {"finding_ids": "1", "state": "open"}),
    ("/api/runs/999999999/cancel", None),
    ("/api/views", {"name": "x", "slug": "x"}),
    ("/api/upload", None),
]


@pg
def test_a_viewer_still_cannot_write(analyst):
    """Parity check: adding a JSON surface must not have loosened anything."""
    from fastapi.testclient import TestClient
    from server import app as appmod, auth, db

    name = f"viewer_{os.urandom(4).hex()}"
    uid = auth.create_user(name, PASSWORD, "viewer")
    try:
        c = TestClient(appmod.app, follow_redirects=False)
        c.post("/api/auth/login", json={"username": name, "password": PASSWORD})
        # The upload SCREEN used to 403 here, because it was a server-rendered
        # page behind `require("analyst")`. It is a static file now and is served
        # to everybody — a compiled bundle cannot be role-gated, and it never
        # carried data. The control moved to /api/upload in _SPA_WRITES below,
        # which is where it was always actually enforced; the nav merely stops
        # showing a viewer a door they cannot open.
        assert c.get("/upload").status_code in (200, 503)
        assert c.post("/api/upload").status_code == 403

        allowed = {path: (c.post(path, data=body) if body else c.post(path)).status_code
                   for path, body in _SPA_WRITES}
        assert all(s == 403 for s in allowed.values()), \
            f"a viewer was not refused: {[p for p, s in allowed.items() if s != 403]}"
    finally:
        db.execute("DELETE FROM app_user WHERE id = %s", (uid,))


@pytest.fixture()
def one_open_finding():
    """One finding of this test's own, in a landscape of its own.

    It does NOT reuse whatever happens to be in the database. A test that reads
    `SELECT ... FROM finding LIMIT 1` and skips when there is none passes loudly
    on a developer's populated database and skips silently in CI — which is the
    same "green, and asserting nothing" failure the DB_DSN guard above already
    costs this file once. Deleting the landscape cascades the rest.
    """
    from server import db
    db.init_schema()
    with db.connection() as conn:
        conn.execute("INSERT INTO check_definition (check_id, title) "
                     "VALUES ('RBAC-PROBE','Viewer write probe') "
                     "ON CONFLICT (check_id) DO NOTHING")
        lid = conn.execute("INSERT INTO landscape (name) VALUES (%s) RETURNING id",
                           (f"rbacprobe_{os.urandom(4).hex()}",)).fetchone()["id"]
        fid = conn.execute(
            "INSERT INTO finding (landscape_id, fingerprint, check_id, severity, state) "
            "VALUES (%s,%s,'RBAC-PROBE','HIGH','open') RETURNING id",
            (lid, f"rbacprobe_{os.urandom(6).hex()}")).fetchone()["id"]
        conn.commit()
    yield fid
    db.execute("DELETE FROM landscape WHERE id = %s", (lid,))


@pg
def test_a_viewers_refused_write_did_not_happen(one_open_finding):
    """403 is the response; NOTHING CHANGED is the property.

    Asserting the status code alone would pass on a route that refuses the caller
    after it has already written — not a hypothetical shape, it is what an
    audit-then-authorise ordering produces. The state is read back from the
    database rather than from the API so no caching layer can answer this
    question on the store's behalf.
    """
    from fastapi.testclient import TestClient
    from server import app as appmod, auth, db

    name = f"viewer_{os.urandom(4).hex()}"
    uid = auth.create_user(name, PASSWORD, "viewer")
    try:
        c = TestClient(appmod.app, follow_redirects=False)
        c.post("/api/auth/login", json={"username": name, "password": PASSWORD})
        assert c.post(f"/api/findings/{one_open_finding}/state",
                      data={"state": "resolved", "reason": "probe"}).status_code == 403
        after = db.one("SELECT state FROM finding WHERE id = %s", (one_open_finding,))
        assert after["state"] == "open", \
            "the refusal came after the write — the finding moved anyway"
    finally:
        db.execute("DELETE FROM app_user WHERE id = %s", (uid,))


@pg
def test_an_unknown_id_is_404_not_500_on_the_new_endpoints(analyst):
    c = _signed_in(analyst)
    for path in ("/api/paths/999999999", "/api/runs/999999999/diff",
                 "/api/findings/999999999/history", "/api/views/no-such-view"):
        assert c.get(path).status_code == 404, path
