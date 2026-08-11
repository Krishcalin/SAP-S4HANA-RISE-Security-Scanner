# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
The second factor, end to end, with PostgreSQL as the oracle.

WHY THIS FILE NEEDS A REAL DATABASE AND A MOCK WOULD PROVE NOTHING.
Two of the guarantees here are not properties of the Python at all — they are
properties of what happens when two requests race. "A code cannot be used twice"
and "a recovery code is consumed exactly once" are implemented as conditional
UPDATEs whose returned row IS the authorisation, and the only thing that can
demonstrate a conditional UPDATE is a database executing concurrent ones. Against
a mock, a read-then-write implementation with the identical bug passes.

EVERY TEST SEEDS ITS OWN USER. The `server` CI job fails when more than one test
skips, and the data-dependent suites in this repo have self-skipped for want of
rows before. Nothing here is allowed to depend on what another test left behind.

⚠️ This file imports server/ at module level, so it MUST be in the `cli` job's
--ignore list in .github/workflows/tests.yml — that job installs pytest and
nothing else, and a module-level `import psycopg` aborts collection for the whole
matrix. tests/test_totp.py and tests/test_qr.py deliberately do NOT need that:
they import only stdlib modules and run everywhere.
"""
from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

pg = pytest.mark.skipif(not os.getenv("DB_DSN"),
                        reason="set DB_DSN to a PostgreSQL 16 instance")

PASSWORD = "second-factor-password"


@pytest.fixture()
def person():
    """A fresh account with nothing enrolled."""
    from server import auth, db
    db.init_schema()
    name = f"totp_{os.urandom(4).hex()}"
    uid = auth.create_user(name, PASSWORD, "analyst")
    row = db.one("SELECT * FROM app_user WHERE id = %s", (uid,))
    yield dict(row)
    db.execute("DELETE FROM app_user WHERE id = %s", (uid,))
    for kind in ("pw", "2fa"):
        auth.throttle_clear(auth.throttle_scope(kind, name))


@pytest.fixture()
def enrolled(person):
    """The same account with a live factor and ten recovery codes."""
    from server import auth, totp
    started = auth.begin_totp(person)
    codes = auth.confirm_totp(person, totp.code_now(started["secret"]),
                              actor=person["username"])
    person["secret"] = started["secret"]
    person["recovery"] = codes
    return person


def _client():
    from fastapi.testclient import TestClient
    from server import app as appmod
    return TestClient(appmod.app)


def _fresh_code(secret):
    """A code from the NEXT window.

    Enrolment consumes the counter it verified, so the code that turned the
    factor on is legitimately spent. A test that reuses it is testing its own
    mistake.
    """
    from server import totp
    return totp.code_at(secret, totp.counter_at() + 1)


def _login(client, person, code=None):
    body = {"username": person["username"], "password": PASSWORD}
    if code is not None:
        body["totp_code"] = code
    return client.post("/api/auth/login", json=body)


# --------------------------------------------------------------------------- #
#  The races. PostgreSQL is the oracle.                                       #
# --------------------------------------------------------------------------- #

@pg
def test_one_valid_code_opens_exactly_one_session_under_concurrency(enrolled):
    """The replay defence as a RACE, not as a value comparison.

    A read-then-write implementation — check `last_counter`, then update it —
    passes every sequential test and fails here: both requests read the old floor
    and both are authorised. The counter advance is written as
    `UPDATE ... WHERE last_counter < %s RETURNING`, so the database decides, once.
    """
    from server import db

    code = _fresh_code(enrolled["secret"])
    before = db.one("SELECT count(*) AS n FROM session WHERE user_id = %s",
                    (enrolled["id"],))["n"]

    results = []
    barrier = threading.Barrier(8)

    def attempt():
        c = _client()
        barrier.wait()                      # fire together, not merely in a loop
        results.append(_login(c, enrolled, code).status_code)

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    after = db.one("SELECT count(*) AS n FROM session WHERE user_id = %s",
                   (enrolled["id"],))["n"]
    assert results.count(200) == 1, f"{results.count(200)} of 8 racing logins succeeded"
    assert after - before == 1, f"{after - before} sessions opened for one code"


@pg
def test_one_recovery_code_is_spent_exactly_once_under_concurrency(enrolled):
    """Same shape, and it matters more: a recovery code is a bearer credential
    printed on paper. Two sessions from one code is two people from one slip."""
    from server import db, totp

    code = enrolled["recovery"][0]
    results = []
    barrier = threading.Barrier(8)

    def attempt():
        c = _client()
        barrier.wait()
        results.append(_login(c, enrolled, code).status_code)

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    spent = db.one(
        "SELECT count(*) AS n FROM recovery_code "
        "WHERE user_id = %s AND code_hash = %s AND used_at IS NOT NULL",
        (enrolled["id"], totp.recovery_fingerprint(code)))["n"]
    assert results.count(200) == 1, f"{results.count(200)} of 8 racing logins succeeded"
    assert spent == 1


# --------------------------------------------------------------------------- #
#  Oracles: what the login route may and may not reveal                       #
# --------------------------------------------------------------------------- #

@pg
def test_a_wrong_password_never_reveals_that_the_account_has_a_factor(enrolled):
    """`totp_required` may only appear on a path `authenticate` already passed.

    Leaking it earlier hands out a map of which accounts are worth phishing, and
    it is the easy mistake to make: the natural implementation checks for a factor
    as soon as it has a username.
    """
    c = _client()
    r = c.post("/api/auth/login",
               json={"username": enrolled["username"], "password": "not-the-password"})
    assert r.status_code == 401
    assert "totp_required" not in r.json()
    assert r.json() == {"detail": "Invalid credentials"}


@pg
def test_an_unknown_username_is_answered_identically(enrolled):
    c = _client()
    known = c.post("/api/auth/login",
                   json={"username": enrolled["username"], "password": "wrong"})
    unknown = c.post("/api/auth/login",
                     json={"username": "no-such-account", "password": "wrong"})
    assert known.status_code == unknown.status_code == 401
    assert known.json() == unknown.json()


@pg
def test_the_prompt_for_a_code_is_a_401_with_a_top_level_flag(enrolled):
    """The shape the console branches on. `detail` must be a STRING — app.py's
    handler rewrites raised 401s and the client only unwraps string details — and
    the flag must be top-level, not nested inside `detail`."""
    r = _login(_client(), enrolled)
    assert r.status_code == 401
    body = r.json()
    assert body["totp_required"] is True
    assert isinstance(body["detail"], str) and "recovery code" in body["detail"]


@pg
def test_a_wrong_code_is_indistinguishable_from_a_wrong_password(enrolled):
    r = _login(_client(), enrolled, "000000")
    assert r.status_code == 401
    assert r.json() == {"detail": "Invalid credentials"}


@pg
def test_a_failed_second_factor_does_not_record_a_successful_sign_in(enrolled):
    """`last_login_at` would otherwise report the attacker who knows the password
    rather than the person who actually got in."""
    from server import db
    before = db.one("SELECT last_login_at FROM app_user WHERE id = %s",
                    (enrolled["id"],))["last_login_at"]
    _login(_client(), enrolled, "000000")
    after = db.one("SELECT last_login_at FROM app_user WHERE id = %s",
                   (enrolled["id"],))["last_login_at"]
    assert before == after


@pg
def test_a_successful_sign_in_does_record_one(enrolled):
    from server import db
    r = _login(_client(), enrolled, _fresh_code(enrolled["secret"]))
    assert r.status_code == 200
    assert db.one("SELECT last_login_at FROM app_user WHERE id = %s",
                  (enrolled["id"],))["last_login_at"] is not None


# --------------------------------------------------------------------------- #
#  The attempt budget                                                         #
# --------------------------------------------------------------------------- #

@pg
def test_the_second_factor_budget_refuses_after_five_and_stays_quiet(enrolled):
    """Over-budget refusals must be byte-identical to an ordinary rejection: a 429,
    or a "try again in N minutes", confirms the account exists."""
    c = _client()
    bodies = []
    for _ in range(8):
        r = _login(c, enrolled, "000000")
        bodies.append((r.status_code, r.text))
    assert len({b for b in bodies}) == 1, "an over-budget refusal is distinguishable"
    assert bodies[0][0] == 401

    # ...and a correct code is now refused too, which is what "budget" means.
    assert _login(c, enrolled, _fresh_code(enrolled["secret"])).status_code == 401


@pg
def test_an_over_budget_refusal_is_fast_because_it_precedes_the_hashing(person):
    """The throttle is checked BEFORE `authenticate`, so a refused attempt never
    pays PBKDF2. If that ordering is ever reversed the denial-of-service reopens,
    and the timing is the only thing that shows it."""
    from server import auth
    scope = auth.throttle_scope("pw", person["username"])
    for _ in range(12):
        auth.throttle_fail(scope)

    c = _client()
    start = time.perf_counter()
    for _ in range(5):
        c.post("/api/auth/login",
               json={"username": person["username"], "password": "wrong"})
    blocked = (time.perf_counter() - start) / 5

    auth.throttle_clear(scope)
    start = time.perf_counter()
    c.post("/api/auth/login",
           json={"username": person["username"], "password": "wrong"})
    hashed = time.perf_counter() - start

    assert blocked < hashed, (
        f"a blocked attempt took {blocked * 1000:.0f}ms and a hashed one "
        f"{hashed * 1000:.0f}ms — the throttle is running after the hash")


@pg
def test_a_code_typo_does_not_burn_the_password_budget(enrolled):
    """Separate counters. Otherwise somebody who knows a password can lock the
    real owner out of it by failing codes, and a fat-fingered code costs the user
    their password attempts."""
    from server import auth
    c = _client()
    for _ in range(6):
        _login(c, enrolled, "000000")
    assert not auth.throttle_check(auth.throttle_scope("2fa", enrolled["username"]))
    assert auth.throttle_check(auth.throttle_scope("pw", enrolled["username"]))


# --------------------------------------------------------------------------- #
#  Enrolment state machine                                                    #
# --------------------------------------------------------------------------- #

@pg
def test_a_pending_secret_cannot_satisfy_a_login(person):
    """`begin` mints a secret nobody has proved. If it counted as a factor, a
    failed scan would lock the account behind a secret the user never captured."""
    from server import auth, db, totp
    started = auth.begin_totp(person)
    assert auth.totp_active(person["id"]) is False
    with db.connection() as conn:
        assert auth.verify_second_factor(
            conn, person["id"], totp.code_now(started["secret"])) is None
    assert _login(_client(), person).status_code == 200   # password alone still works


@pg
def test_begin_refuses_while_a_factor_is_live(enrolled):
    """409, not a silent replacement. A stolen session must not be able to swap
    the factor for one in the attacker's own authenticator."""
    from server import auth
    with pytest.raises(auth.AuthError):
        auth.begin_totp(enrolled)

    c = _client()
    assert _login(c, enrolled, _fresh_code(enrolled["secret"])).status_code == 200
    r = c.post("/api/account/totp/begin", json={"current": PASSWORD})
    assert r.status_code == 409


@pg
def test_enrolment_expires(person):
    from server import auth, db, totp
    started = auth.begin_totp(person)
    db.execute("UPDATE app_totp SET pending_at = now() - interval '20 minutes' "
               "WHERE user_id = %s", (person["id"],))
    with pytest.raises(auth.AuthError):
        auth.confirm_totp(person, totp.code_now(started["secret"]),
                          actor=person["username"])


@pg
def test_confirming_consumes_the_code_it_verified(person):
    """Verifying at enrolment IS a use. Otherwise the code typed on a
    screen-shared onboarding call stays live for up to another minute."""
    from server import auth, db, totp
    started = auth.begin_totp(person)
    code = totp.code_now(started["secret"])
    auth.confirm_totp(person, code, actor=person["username"])
    with db.connection() as conn:
        assert auth.verify_second_factor(conn, person["id"], code) is None


@pg
def test_every_management_route_requires_the_current_password(enrolled):
    """Creating a factor is more dangerous than removing one — it is what locks
    the legitimate owner out — so the rule covers all four, not just disable."""
    c = _client()
    assert _login(c, enrolled, _fresh_code(enrolled["secret"])).status_code == 200
    for path, body in (
        ("/api/account/totp/begin", {"current": "wrong"}),
        ("/api/account/totp/confirm", {"current": "wrong", "code": "000000"}),
        ("/api/account/totp/disable", {"current": "wrong", "code": "000000"}),
        ("/api/account/totp/recovery", {"current": "wrong", "code": "000000"}),
    ):
        r = c.post(path, json=body)
        assert r.status_code == 400, f"{path} accepted a wrong password ({r.status_code})"


# --------------------------------------------------------------------------- #
#  Recovery                                                                   #
# --------------------------------------------------------------------------- #

@pg
def test_a_recovery_code_signs_in_and_is_reported_as_such(enrolled):
    r = _login(_client(), enrolled, enrolled["recovery"][0])
    assert r.status_code == 200
    assert r.json()["used_recovery_code"] is True
    assert r.json()["recovery_codes_left"] == 9


@pg
def test_someone_who_used_a_recovery_code_can_still_turn_the_factor_off(enrolled):
    """The dead end this closes: `disable` demanding a TOTP code would leave a
    person able to sign in and unable to fix the state they are in."""
    c = _client()
    assert _login(c, enrolled, enrolled["recovery"][0]).status_code == 200
    r = c.post("/api/account/totp/disable",
               json={"current": PASSWORD, "code": enrolled["recovery"][1]})
    assert r.status_code == 200 and r.json()["enabled"] is False

    from server import auth
    assert auth.totp_active(enrolled["id"]) is False


@pg
def test_changing_the_password_invalidates_unused_recovery_codes(enrolled):
    """A password change is what somebody does when they think a credential
    leaked. Recovery codes are credentials, on paper, that leak alongside it."""
    from server import auth
    assert auth.recovery_codes_left(enrolled["id"]) == 10
    auth.set_password(enrolled["id"], "a-brand-new-password", actor="test")
    assert auth.recovery_codes_left(enrolled["id"]) == 0
    # ...but the FACTOR survives: a new password is not a new phone.
    assert auth.totp_active(enrolled["id"]) is True


@pg
def test_an_admin_reset_leaves_the_factor_intact(enrolled):
    from server import auth
    auth.reset_password(enrolled["id"], actor="admin")
    assert auth.totp_active(enrolled["id"]) is True


@pg
def test_disabling_removes_the_row_so_a_stale_counter_cannot_poison_a_re_enrolment(
        enrolled):
    """A fresh secret inheriting an old replay floor would refuse perfectly good
    codes until the clock caught up — which reads as "the app is broken"."""
    from server import auth, db, totp
    db.execute("UPDATE app_totp SET last_counter = %s WHERE user_id = %s",
               (totp.counter_at() + 5000, enrolled["id"]))
    auth.disable_totp(enrolled["id"], actor="test")
    assert db.one("SELECT 1 AS x FROM app_totp WHERE user_id = %s",
                  (enrolled["id"],)) is None

    started = auth.begin_totp(enrolled)
    auth.confirm_totp(enrolled, totp.code_now(started["secret"]), actor="test")
    row = db.one("SELECT last_counter FROM app_totp WHERE user_id = %s",
                 (enrolled["id"],))
    assert row["last_counter"] < totp.counter_at() + 5000


# --------------------------------------------------------------------------- #
#  The forced-password gate                                                   #
# --------------------------------------------------------------------------- #

@pg
def test_a_forced_account_cannot_enrol_but_can_still_see_and_remove(person):
    """The prefix-allowlist hole, as a behaviour rather than a string comparison.

    This walks the ROUTER rather than a hand-written list, so a new
    /api/account/totp/* route added later is covered by this test on the day it is
    written instead of silently inheriting an exemption.
    """
    from server import api_auth, db
    db.execute("UPDATE app_user SET must_change_password = true WHERE id = %s",
               (person["id"],))
    c = _client()
    assert _login(c, person).status_code == 200

    reachable = {"/api/account/totp", "/api/account/totp/disable"}
    totp_paths = [r.path for r in api_auth.router.routes
                  if r.path.startswith("/api/account/totp")]
    assert len(totp_paths) == 5, f"route count changed: {totp_paths}"

    for path in totp_paths:
        methods = {m for m in next(r for r in api_auth.router.routes
                                   if r.path == path).methods if m != "HEAD"}
        r = (c.get(path) if methods == {"GET"}
             else c.post(path, json={"current": PASSWORD, "code": "000000"}))
        if path in reachable:
            assert r.status_code != 403, f"{path} should stay reachable while forced"
        else:
            assert r.status_code == 403, \
                f"{path} is exempt from the forced-password gate"


# --------------------------------------------------------------------------- #
#  Audit                                                                      #
# --------------------------------------------------------------------------- #

@pg
def test_the_second_factor_writes_an_audit_trail_and_never_the_secret(enrolled):
    """The EVENT is recorded, the value never is — the rule `set_password` already
    follows for passwords."""
    from server import db

    c = _client()
    _login(c, enrolled, "000000")                               # a failure
    _login(_client(), enrolled, _fresh_code(enrolled["secret"]))  # a success

    rows = db.query(
        "SELECT action, detail::text AS detail FROM audit_log "
        "WHERE object_id = %s ORDER BY id", (str(enrolled["id"]),))
    actions = {r["action"] for r in rows}
    assert "user.totp_enabled" in actions
    assert "auth.second_factor_failed" in actions
    assert "auth.login.totp" in actions

    blob = " ".join(r["detail"] for r in rows)
    assert enrolled["secret"] not in blob
    for code in enrolled["recovery"]:
        assert code not in blob
