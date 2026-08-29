"""The CI seed and the local runner must use ONE fixture.

WHY THIS FILE EXISTS
────────────────────
The database-backed suites need a fixture before they will run at all: a scan
that produced findings, a second system to scope a viewer to, a second landscape
to tell a union from a narrowing. Without it they skip, the job goes green, and
it has verified none of the journey, none of the analytics and none of the HTTP
layer.

CI seeded that fixture as forty lines of Python inlined in the workflow. The
consequence was not that CI was wrong — CI was right — it was that a developer
could not reproduce a CI run locally without copying those forty lines, and a
copy is a second thing to keep in step.

This project has paid for that pattern twice already:

  * a hand-written `--ignore=` list in the workflow rotted twice, until
    `tools/stdlib_only_ignores.py` derived it instead. By the second rot,
    ELEVEN test files imported `server` without being listed, and survived only
    because the modules they happened to import were dependency-free.
  * the check-ownership vocabulary lived in a Python dict AND a SQL constraint,
    which disagreed for weeks because only the database job could see both, and
    that job skips by default.

So the seed is `tools/seed_test_db.py`, and both the workflow and
`tools/db_test.py` call it. These tests fail if the workflow grows its own copy
back, or if the two guards drift apart.
"""
from __future__ import annotations

import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOW = os.path.join(ROOT, ".github", "workflows", "tests.yml")


@pytest.fixture(scope="module")
def workflow() -> str:
    with open(WORKFLOW, encoding="utf-8") as handle:
        return handle.read()


def test_the_workflow_calls_the_shared_seed(workflow):
    assert "python -m tools.seed_test_db" in workflow, (
        "the CI seed step no longer calls tools/seed_test_db.py — if it has "
        "grown its own copy, the local runner and CI will drift")


def test_the_workflow_does_not_inline_a_seed_of_its_own(workflow):
    """The specific shape that was extracted. A workflow that starts building
    landscapes and systems again has forked the fixture."""
    step = re.search(r"- name: Seed a scan.*?(?=\n      - name: )",
                     workflow, re.S)
    assert step, "the seed step is gone entirely"
    body = step.group(0)
    for forbidden in ("INSERT INTO landscape", "INSERT INTO sap_system",
                      "ingest.scan_directory"):
        assert forbidden not in body, (
            "the CI seed step inlines %r again. It belongs in "
            "tools/seed_test_db.py, which tools/db_test.py also calls; two "
            "copies is how the ignore list and the ownership vocabulary both "
            "rotted." % forbidden)


def test_the_local_guard_matches_the_one_in_ci():
    """A local ceiling looser than CI's is a local guard that passes the run CI
    is about to fail — which is the whole problem this was built to end."""
    from tools import db_test

    found = re.search(r'if \[ "\$count" -gt (\d+) \]',
                      open(WORKFLOW, encoding="utf-8").read())
    assert found, "the workflow's skip guard no longer has a numeric ceiling"
    assert db_test.MAX_SKIPS == int(found.group(1)), (
        "tools/db_test.MAX_SKIPS is %d but CI fails above %s"
        % (db_test.MAX_SKIPS, found.group(1)))


def test_the_seed_asserts_on_every_fixture_a_suite_needs():
    """Each of these corresponds to a suite that once skipped while the job
    reported success. Dropping an assertion re-opens that hole silently."""
    from tools import seed_test_db

    source = open(seed_test_db.__file__, encoding="utf-8").read()
    assert 'counts["findings"]' in source, "no floor on findings"
    assert 'counts["systems"] < 2' in source, "no floor on systems"
    assert 'counts["landscapes"] < 2' in source, "no floor on landscapes"


def test_the_runner_refuses_to_run_without_both_variables(monkeypatch):
    """SESSION_SECRET is checked up front rather than left to fail deep inside
    the first HTTP test, where the message does not say what is missing."""
    from tools import db_test

    monkeypatch.delenv("DB_DSN", raising=False)
    monkeypatch.delenv("SESSION_SECRET", raising=False)
    assert set(db_test._missing_environment()) == {"DB_DSN", "SESSION_SECRET"}

    monkeypatch.setenv("DB_DSN", "postgresql://x")
    assert db_test._missing_environment() == ["SESSION_SECRET"]
