"""Run the suite the way CI runs it, including the database half.

    python -m tools.db_test              # seed, run everything, apply the guard
    python -m tools.db_test --no-seed    # you already seeded
    python -m tools.db_test -k journey   # pass anything through to pytest

WHY THIS EXISTS
───────────────
A plain `pytest` on a developer machine runs about 3,940 tests and skips 200 —
every one of the skips for want of `DB_DSN`. It prints a green line and it has
verified none of the journey, none of the analytics and none of the HTTP layer.

That is not hypothetical. Five consecutive commits pushed green locally and
landed RED in CI, starting at "Make every module reachable": `rise_ownership.py`
mapped the `CSA-` prefix to a team the `check_definition_owning_team_check`
constraint does not allow, so every scan producing a CSA finding was rejected by
PostgreSQL at insert. The constraint lives in the database, so only the database
job could reach it, and that job skips without a DSN — the ordinary local state.

CI already refuses to be fooled: it fails if PostgreSQL is unreachable, seeds
before testing, and fails if MORE THAN ONE test skips. This gives the same three
guarantees locally, so the loop is push-then-discover only when the change is
genuinely environmental.

WHAT IT DOES NOT DO
───────────────────
It does not start a database. Standing one up is one command and it is the
developer's choice where it lives:

    docker run -d --name sap-test-db -p 127.0.0.1:55432:5432 \\
      -e POSTGRES_USER=sapsec -e POSTGRES_PASSWORD=x -e POSTGRES_DB=sapsec \\
      postgres:16

    export DB_DSN=postgresql://sapsec:x@127.0.0.1:55432/sapsec
    export SESSION_SECRET=$(python -c "import secrets;print(secrets.token_hex(24))")

Both variables are required. `SESSION_SECRET` is checked here rather than left
to fail deep inside the first HTTP test, because the message there does not say
what is missing.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

#: CI tolerates exactly this many skips. One, for a scanner test that needs an
#: optional sibling engine absent on some runners. More than that means a
#: database-backed suite is silently not running.
#:
#: Kept identical to the workflow ON PURPOSE. A local guard looser than CI's is
#: a local guard that passes the run CI is about to fail.
MAX_SKIPS = 1

REQUIRED_ENV = ("DB_DSN", "SESSION_SECRET")


def _missing_environment() -> list:
    return [name for name in REQUIRED_ENV if not os.environ.get(name)]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--no-seed", action="store_true",
                        help="skip seeding; the fixture is already present")
    parser.add_argument("--allow-skips", type=int, default=MAX_SKIPS,
                        help="raise the skip ceiling (default %d, same as CI)"
                             % MAX_SKIPS)
    parser.add_argument("pytest_args", nargs=argparse.REMAINDER,
                        help="everything after -- goes to pytest")
    args = parser.parse_args(argv)

    missing = _missing_environment()
    if missing:
        print("missing: %s\n\nThe database-backed suites would SKIP and this "
              "run would look green having tested none of them. See this "
              "module's docstring for the two commands that fix it."
              % ", ".join(missing), file=sys.stderr)
        return 2

    if not args.no_seed:
        print("seeding ...")
        from tools import seed_test_db
        try:
            counts = seed_test_db.seed()
        except SystemExit as failure:                 # the seed's own asserts
            print(str(failure), file=sys.stderr)
            return 2
        print("seeded %(findings)d findings, %(systems)d systems, "
              "%(landscapes)d landscapes\n" % counts)

    extra = [a for a in args.pytest_args if a != "--"]
    command = [sys.executable, "-m", "pytest", "-q",
               "-W", "ignore::DeprecationWarning"] + extra
    print("$ %s\n" % " ".join(command))
    completed = subprocess.run(command, capture_output=True, text=True)
    sys.stdout.write(completed.stdout)
    sys.stderr.write(completed.stderr)

    # THE GUARD, same as the workflow's. A suite that silently skips is worse
    # than one that does not exist, because it LOOKS verified.
    found = re.search(r"(\d+) skipped", completed.stdout)
    skipped = int(found.group(1)) if found else 0
    if skipped > args.allow_skips:
        print("\n%d skipped, ceiling is %d — a database-backed suite is not "
              "executing. A suite that silently skips is worse than one that "
              "does not exist, because it LOOKS verified."
              % (skipped, args.allow_skips), file=sys.stderr)
        return 1

    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
