"""The fixture the database-backed suites need before they will run at all.

WHY THIS EXISTS
───────────────
A fifth of this suite is database-backed, and a further handful of tests skip on
DATA rather than on a missing `DB_DSN` — they need a scan to have happened, a
second system to scope a viewer to, a second landscape to tell a union from a
narrowing. Without that fixture they skip, and a suite that skips is worse than
one that does not exist, because it LOOKS verified.

CI has always seeded this. It did so as forty lines of Python inlined in
`.github/workflows/tests.yml`, which meant there was no way to reproduce a CI
run locally without copying them — and a copy is a second thing to keep in step.
This project has been bitten twice by exactly that: a hand-written ignore list
that rotted twice before `tools/stdlib_only_ignores.py` derived it, and an
ownership vocabulary held in a Python dict and a SQL constraint that disagreed
for weeks because only one job could see both.

So the seed lives here, and both callers use it:

    .github/workflows/tests.yml   python -m tools.seed_test_db
    tools/db_test.py             (imports and calls `seed`)

`tests/test_ci_seed_is_not_inlined.py` fails if the workflow grows its own copy
back.

WHAT IT ASSERTS, AND WHY EACH ASSERTION IS THERE
────────────────────────────────────────────────
Every check below corresponds to a suite that once skipped while the job went
green:

  findings > 0        the finding-detail and code-console suites are
                      data-dependent; with an empty database they skip
  >= 2 systems        a row-scoping test needs some system that is NOT the one
                      holding the finding, or it reports success having never
                      exercised scoping
  >= 2 landscapes     the coverage-narrowing test cannot tell a union from a
                      narrowing with only one

Seeding is therefore not setup. It is the difference between running those
suites and appearing to.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict

#: Where the sample exports live. The seed deliberately uses the SAME fixture
#: the smoke-run uses, so a change that breaks ingest breaks both.
SAMPLE_DATA = "sample_data"

#: The scan the data-dependent suites read.
SEED_LANDSCAPE = "seed"
SEED_SID = "SED"
SEED_CLIENT = "100"
SEED_MODE = "rise_pce"

#: A second system and a second landscape, both otherwise EMPTY. Neither needs
#: findings of its own: the assertions in the suites that need them are about
#: what a narrowing EXCLUDES.
SECOND_SID = "SE2"
SECOND_CLIENT = "200"
SECOND_LANDSCAPE = "seed-second"


def seed(root: Path | None = None) -> Dict[str, int]:
    """Create the fixture. Returns the counts, and raises if any is short.

    Idempotent only in the sense that running it twice yields a second seed
    landscape rather than an error — which is harmless, since every assertion
    below is a floor rather than an equality.
    """
    root = root or Path.cwd()
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    from server import db, ingest                              # noqa: E402

    db.init_schema()

    landscape = db.one(
        "INSERT INTO landscape (name, deployment_mode) "
        "VALUES (%s,%s) RETURNING id", (SEED_LANDSCAPE, SEED_MODE))["id"]
    system = db.one(
        "INSERT INTO sap_system (landscape_id, sid, client, tier) "
        "VALUES (%s,%s,%s,'prod') RETURNING id",
        (landscape, SEED_SID, SEED_CLIENT))["id"]
    run = db.one(
        "INSERT INTO scan_run (landscape_id, system_id, status) "
        "VALUES (%s,%s,'pending') RETURNING id", (landscape, system))["id"]

    ingest.scan_directory(root / SAMPLE_DATA, landscape, system, run,
                          deployment_mode=SEED_MODE,
                          default_sid=SEED_SID, default_client=SEED_CLIENT)

    db.execute("INSERT INTO sap_system (landscape_id, sid, client, tier) "
               "VALUES (%s,%s,%s,'dev')",
               (landscape, SECOND_SID, SECOND_CLIENT))
    db.execute("INSERT INTO landscape (name, deployment_mode) VALUES (%s,%s)",
               (SECOND_LANDSCAPE, SEED_MODE))

    counts = {
        "findings": db.one("SELECT count(*) AS n FROM finding")["n"],
        "systems": db.one("SELECT count(*) AS n FROM sap_system")["n"],
        "landscapes": db.one("SELECT count(*) AS n FROM landscape")["n"],
    }

    if not counts["findings"]:
        raise SystemExit(
            "the seed produced no findings — the data-dependent suites would "
            "still skip, and the job would go green having tested neither the "
            "finding detail nor the code console")
    if counts["systems"] < 2 or counts["landscapes"] < 2:
        raise SystemExit(
            "the scoping and narrowing suites need a second system AND a second "
            "landscape or they skip, and the job goes green having exercised "
            "neither scoping nor narrowing (got %d systems, %d landscapes)"
            % (counts["systems"], counts["landscapes"]))
    return counts


def main() -> int:
    counts = seed()
    print("seeded %(findings)d findings, %(systems)d systems, "
          "%(landscapes)d landscapes" % counts)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
