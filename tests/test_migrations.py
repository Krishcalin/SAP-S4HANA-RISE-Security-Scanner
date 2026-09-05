"""The one-off data migrations, and the property that makes them worth running.

A migration that rewrites finding IDENTITY has exactly one success condition:
the value it computes must equal the value the scanner will compute on the next
run. Miss it and the migration is worse than useless -- every affected finding
churns new+resolved on the next scan, losing its age, assignee and risk
acceptance, which is the outcome the migration existed to prevent.

So the load-bearing test is not "did rows change" but "does the recomputed
identity agree with `server.ingest`". That is checkable without a database,
because `fingerprint_finding` is pure.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server import migrations  # noqa: E402
from server.identity import fingerprint_finding  # noqa: E402


def test_the_retype_is_the_only_change_it_makes():
    """A migration that also normalised a name, or dropped a qualifier, would
    move identity for a second undeclared reason."""
    before = [{"type": "parameter", "name": "login/show_detailed_errors"},
              {"type": "user", "name": "ADMIN1", "qualifier": "x"}]
    after = migrations._renamed(before)
    assert after == [{"type": "parameter_name", "name": "login/show_detailed_errors"},
                     {"type": "user", "name": "ADMIN1", "qualifier": "x"}]


def test_a_subject_with_nothing_to_retype_is_left_alone():
    """Returning a rewritten copy for every row would rewrite fingerprints that
    were already correct, and each rewrite is an identity change."""
    assert migrations._renamed([{"type": "user", "name": "ADMIN1"}]) is None
    assert migrations._renamed([]) is None
    assert migrations._renamed(None) is None
    assert migrations._renamed("not a list") is None


def test_the_recomputed_identity_is_what_the_scanner_will_compute():
    """THE ONE THAT MATTERS.

    The migration reconstructs a finding dict and fingerprints it. If that
    reconstruction differs from what `server.ingest` hands the fingerprinter --
    a missing scope, the wrong system, a different key name -- the migration
    writes an identity no scan will ever produce, and every WDISP finding churns
    on the next run with its history gone.

    This asserts the two agree, on the shape webdisp_security actually emits.
    """
    emitted = {
        "check_id": "WDISP-004",
        "affected_objects": [{"type": "parameter_name",
                              "name": "login/show_detailed_errors"}],
    }
    scanner_fp, scanner_basis = fingerprint_finding(emitted, "PRD", "100")

    # What the migration reconstructs from the stored row.
    stored_subject = [{"type": "parameter", "name": "login/show_detailed_errors"}]
    migrated_fp, migrated_basis = fingerprint_finding(
        {"check_id": "WDISP-004",
         "subject": migrations._renamed(stored_subject),
         "scope": "object"},
        "PRD", "100")

    assert migrated_fp == scanner_fp, (
        "the migration would write an identity the scanner never produces")
    assert migrated_basis == scanner_basis == "objects"


def test_the_retype_actually_moves_the_fingerprint():
    """If it did not, the migration would be a no-op dressed as a fix -- and the
    duplicate nodes it exists to merge would still be two."""
    old, _ = fingerprint_finding(
        {"check_id": "WDISP-004", "scope": "object",
         "subject": [{"type": "parameter", "name": "login/show_detailed_errors"}]},
        "PRD", "100")
    new, _ = fingerprint_finding(
        {"check_id": "WDISP-004", "scope": "object",
         "subject": [{"type": "parameter_name", "name": "login/show_detailed_errors"}]},
        "PRD", "100")
    assert old != new


def test_the_module_no_longer_emits_the_duplicate_type():
    """The migration fixes stored rows; this is what stops new ones arriving."""
    src = (ROOT / "modules" / "webdisp_security.py").read_text(encoding="utf-8")
    assert '"type": "parameter"' not in src, \
        "webdisp_security still emits the duplicate object type"
    assert '"type": "parameter_name"' in src


def test_the_registry_no_longer_carries_the_duplicate():
    """`parameter` was registered so the duplication was declared rather than
    silent. Nothing emits it now, so the entry goes -- and
    test_every_emitted_object_type_is_registered would fail if anything still did."""
    from server.identity import _CASE_SENSITIVE_TYPES, _UPPERCASE_TYPES
    assert "parameter" not in (_UPPERCASE_TYPES | _CASE_SENSITIVE_TYPES)
    assert "parameter_name" in _UPPERCASE_TYPES


def test_the_migration_is_guarded_by_a_version_marker():
    src = (ROOT / "server" / "migrations.py").read_text(encoding="utf-8")
    assert "SELECT 1 FROM schema_version WHERE version = %s" in src
    assert "already applied" in src


def test_a_collision_is_refused_rather_than_merged():
    """Merging two findings discards one row's age, assignee and acceptance. The
    migration makes the same call `_rebase` does when several candidates match:
    do nothing, and say so."""
    src = (ROOT / "server" / "migrations.py").read_text(encoding="utf-8")
    body = src.split("def migrate_parameter_type")[1]
    assert "collided.append" in body
    assert "continue" in body.split("collided.append")[1][:200], \
        "a collision must skip the row, not fall through to the UPDATE"


# --------------------------------------------------------------------------- #
#  What `init-db` prints                                                       #
# --------------------------------------------------------------------------- #
#
# THE DEFECT THIS EXISTS FOR. `server/cli.py` read `result["migrated"]` straight
# out of every migration's return value, which made each new migration owe the
# FIRST one its vocabulary. The second migration returned `backfilled` instead
# and `init-db` died with a KeyError — on a green suite of 5,829 tests, because
# nothing in it runs the CLI. It surfaced when the container was rebuilt and the
# command actually executed.
#
# The fix was not to add the missing key. Each migration now words its own
# `summary`, and these tests hold that contract so the third one cannot repeat it.

def test_every_migration_words_its_own_result():
    """`cli.cmd_init_db` prints `summary` and nothing else about the shape."""
    import inspect

    from server import migrations as m

    reported = []
    for name, fn in vars(m).items():
        if not name.startswith(("migrate_", "backfill_")):
            continue
        if not inspect.isfunction(fn):
            continue
        reported.append(name)
    assert reported, "no migrations found to check"

    # The `already applied` path returns no summary and the CLI skips it, so the
    # contract is on the APPLIED path. Checked against the source rather than by
    # running them, because running needs a database and this must hold anyway.
    source = inspect.getsource(m)
    for name in reported:
        body = source.split("def %s(" % name, 1)[1]
        body = body.split("\ndef ", 1)[0]
        assert '"summary"' in body, (
            "%s returns no `summary`, so `init-db` would print nothing for it — "
            "or, if the CLI is ever changed back to reading a specific key, "
            "raise a KeyError the test suite cannot see" % name)


def test_the_cli_does_not_reach_into_a_migrations_own_keys():
    """Structural, because the behavioural test cannot run the CLI without a
    database. `cli.py` may read `summary` and `status`; a specific migration's
    counter is what broke last time."""
    import inspect

    from server import cli

    body = inspect.getsource(cli.cmd_init_db)
    for forbidden in ("result['migrated']", 'result["migrated"]',
                      "result['backfilled']", 'result["backfilled"]'):
        assert forbidden not in body, (
            "cli.cmd_init_db reads %s, which makes every future migration owe "
            "this one a key it has no reason to carry" % forbidden)
