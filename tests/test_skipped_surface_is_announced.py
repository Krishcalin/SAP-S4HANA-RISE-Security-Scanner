"""The suite must say what it did not do.

A plain `pytest` run ends with "5,087 passed, 246 skipped" and every one of those
skips is the console: ingest, the journey, graph paths, saved views, bulk
actions, the HTTP API and all of the RBAC coverage. They skip because DB_DSN is
unset, and the count sat on screen being read past.

That is the failure this whole product exists to report on — a clean result and
an unasked question rendering the same — reproduced in its own test suite. The
`pytest_terminal_summary` hook in conftest fixes it. These tests keep it fixed.
"""
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import conftest as suite_conftest  # noqa: E402  (tests/conftest.py)


class FakeReport:
    def __init__(self, longrepr):
        self.longrepr = longrepr


class FakeReporter:
    """Just enough of pytest's terminal reporter to drive the hook."""

    def __init__(self, skipped):
        self.stats = {"skipped": skipped}
        self.lines = []

    def write_line(self, text=""):
        self.lines.append(text)


def run_hook(monkeypatch, dsn, skipped):
    if dsn is None:
        monkeypatch.delenv("DB_DSN", raising=False)
    else:
        monkeypatch.setenv("DB_DSN", dsn)
    reporter = FakeReporter(skipped)
    suite_conftest.pytest_terminal_summary(reporter, 0, None)
    return "\n".join(reporter.lines)


DB_SKIP = FakeReport("('/x/test_api_auth.py', 12, 'Skipped: set DB_DSN to a "
                     "PostgreSQL 16 instance')")
OTHER_SKIP = FakeReport("('/x/test_ecc.py', 8, 'Skipped: sample_data_ecc/ is "
                        "not present')")


def test_it_names_the_surface_that_did_not_run(monkeypatch):
    out = run_hook(monkeypatch, None, [DB_SKIP, DB_SKIP])
    assert "2 TEST(S) DID NOT RUN" in out
    assert "RBAC" in out, "the reader has to know what was skipped, not just how many"
    assert "tools.db_test" in out, "and how to run it"


def test_it_says_nothing_when_the_database_was_there(monkeypatch):
    """A banner that fires on a complete run is noise, and noise gets filtered
    out along with the signal."""
    out = run_hook(monkeypatch, "postgresql://x/y", [DB_SKIP])
    assert out == ""


def test_it_says_nothing_when_the_skips_are_unrelated(monkeypatch):
    """`sample_data_ecc` missing is a different skip with a different remedy."""
    out = run_hook(monkeypatch, None, [OTHER_SKIP])
    assert out == ""


def test_it_counts_only_the_database_skips(monkeypatch):
    out = run_hook(monkeypatch, None, [DB_SKIP, OTHER_SKIP, DB_SKIP, OTHER_SKIP])
    assert "2 TEST(S) DID NOT RUN" in out


def test_it_survives_a_run_with_no_skips_at_all(monkeypatch):
    assert run_hook(monkeypatch, None, []) == ""


def test_the_command_it_prints_is_the_one_the_project_documents():
    """If CLAUDE.md and the banner drift apart, one of them sends somebody the
    wrong way — and the banner is the one they will read first."""
    banner_src = (ROOT / "tests" / "conftest.py").read_text(encoding="utf-8")
    claude_md = (ROOT / "CLAUDE.md").read_text(encoding="utf-8")
    for fragment in ("sap-test-db", "127.0.0.1:55432", "tools.db_test"):
        assert fragment in banner_src, "banner lost %s" % fragment
        assert fragment in claude_md, (
            "%s is in the banner but no longer in CLAUDE.md" % fragment)


@pytest.mark.skipif(os.getenv("DB_DSN") is not None,
                    reason="only meaningful when the database is absent")
def test_this_very_run_would_have_been_told():
    """Self-referential on purpose: if the hook is ever removed, a plain run
    goes quiet again and this fails."""
    assert hasattr(suite_conftest, "pytest_terminal_summary")
