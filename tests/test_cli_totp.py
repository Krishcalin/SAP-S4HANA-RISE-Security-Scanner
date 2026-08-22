"""
The lost-device escape hatch.

WHY THIS IS TESTED AT ALL. This product deliberately has no self-service password
reset — an unauthenticated reset is a way in — and that decision is only
survivable because a documented path exists on the other side of it. Adding a
second factor without extending that path turns a lost phone into a permanently
dead account, and for a single-admin install into a dead deployment recoverable
only by hand-editing PostgreSQL.

So these tests are about a support call, not about a feature: somebody rings up
locked out, and the two commands below have to be enough.

⚠️ Imports server/ at module level — must appear in the `cli` job's --ignore list.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

pg = pytest.mark.skipif(not os.getenv("DB_DSN"),
                        reason="set DB_DSN to a PostgreSQL 16 instance")

PASSWORD = "cli-totp-password"


@pytest.fixture()
def enrolled():
    from server import auth, db, totp
    db.init_schema()
    name = f"clitotp_{os.urandom(4).hex()}"
    uid = auth.create_user(name, PASSWORD, "admin")
    user = dict(db.one("SELECT * FROM app_user WHERE id = %s", (uid,)))
    started = auth.begin_totp(user)
    codes = auth.confirm_totp(user, totp.code_now(started["secret"]), actor=name)
    user["secret"] = started["secret"]
    user["recovery"] = codes
    yield user
    db.execute("DELETE FROM app_user WHERE id = %s", (uid,))


def _run(argv):
    """Invoke the CLI the way an operator does, returning (exit_code, stdout)."""
    import io
    from contextlib import redirect_stdout
    from server import cli
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = cli.main(argv)
    return code, buf.getvalue()


@pg
def test_totp_disable_clears_the_factor_the_codes_and_the_sessions(enrolled):
    """All three, because the person saying "my phone is gone" is telling you the
    device may still be holding a live session."""
    from server import auth, db
    auth.create_session(enrolled["id"], "the lost phone")
    assert auth.totp_active(enrolled["id"]) is True

    code, out = _run(["totp-disable", enrolled["username"]])
    assert code == 0
    assert "second factor cleared" in out

    assert auth.totp_active(enrolled["id"]) is False
    assert auth.recovery_codes_left(enrolled["id"]) == 0
    assert db.one("SELECT count(*) AS n FROM session WHERE user_id = %s",
                  (enrolled["id"],))["n"] == 0


@pg
def test_totp_disable_is_honest_when_there_was_nothing_to_clear(enrolled):
    from server import auth
    auth.disable_totp(enrolled["id"], actor="test")
    code, out = _run(["totp-disable", enrolled["username"]])
    assert code == 0 and "had no second factor" in out


@pg
def test_totp_disable_reports_an_unknown_user_rather_than_succeeding_silently():
    code, _out = _run(["totp-disable", "definitely-not-a-user"])
    assert code == 1


@pg
def test_set_password_warns_that_it_is_not_enough_on_a_2fa_account(enrolled):
    """THE TRAP THIS CLOSES. `set-password` is the command CLAUDE.md and the
    account screen both name for a locked-out user, and on an enrolled account it
    reported success while they still could not sign in."""
    import io
    from contextlib import redirect_stdout, redirect_stderr

    buf, err = io.StringIO(), io.StringIO()
    monkey = io.StringIO("a-replacement-password\n")
    real_stdin = sys.stdin
    sys.stdin = monkey
    try:
        from server import cli
        with redirect_stdout(buf), redirect_stderr(err):
            code = cli.main(["set-password", enrolled["username"]])
    finally:
        sys.stdin = real_stdin

    out = buf.getvalue()
    assert code == 0
    assert "still has a second factor enabled" in out
    assert f"totp-disable {enrolled['username']}" in out


@pg
def test_totp_status_names_accounts_that_cannot_be_recovered(enrolled):
    """The question nobody asks until somebody leaves: an estate where every admin
    is enrolled and nobody has codes left is one lost phone from needing a DBA."""
    from server import db
    db.execute("UPDATE recovery_code SET used_at = now() WHERE user_id = %s",
               (enrolled["id"],))
    code, out = _run(["totp-status", enrolled["username"]])
    assert code == 0
    assert enrolled["username"] in out
    assert "NO recovery codes left" in out
    assert "totp-disable" in out, "the warning must name the command that fixes it"


@pg
def test_totp_status_shows_a_clock_that_jumped_forward(enrolled):
    """The confusing failure: a replay floor in the future refuses every correct
    code, and the user experiences it as "the app stopped working". This is the
    only place in the product where that is diagnosable."""
    from server import db, totp
    db.execute("UPDATE app_totp SET last_counter = %s WHERE user_id = %s",
               (totp.counter_at() + 400, enrolled["id"]))
    _code, out = _run(["totp-status", enrolled["username"]])
    assert "AHEAD by" in out and "codes will be refused" in out


@pg
def test_totp_status_lists_an_account_with_no_factor_without_inventing_one(enrolled):
    from server import auth
    auth.disable_totp(enrolled["id"], actor="test")
    _code, out = _run(["totp-status", enrolled["username"]])
    assert "none" in out
    assert "AHEAD" not in out


@pg
def test_the_whole_support_call_works_end_to_end(enrolled):
    """Rung up locked out: phone gone, codes never saved. Two commands, then in."""
    from fastapi.testclient import TestClient
    from server import app as appmod, db

    db.execute("UPDATE recovery_code SET used_at = now() WHERE user_id = %s",
               (enrolled["id"],))
    c = TestClient(appmod.app)

    # Before: the password alone is refused, and there is no code to give.
    r = c.post("/api/auth/login",
               json={"username": enrolled["username"], "password": PASSWORD})
    assert r.status_code == 401 and r.json().get("totp_required") is True

    assert _run(["totp-status", enrolled["username"]])[0] == 0
    assert _run(["totp-disable", enrolled["username"]])[0] == 0

    # After: the password alone is enough again, and they can re-enrol.
    r = c.post("/api/auth/login",
               json={"username": enrolled["username"], "password": PASSWORD})
    assert r.status_code == 200, r.text
    assert c.post("/api/account/totp/begin",
                  json={"current": PASSWORD}).status_code == 200
