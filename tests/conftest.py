"""Shared pytest fixtures for the SAP scanner test suite.

The tests run every audit module against the bundled ``sample_data`` and
validate the finding contract + the full report pipeline. They need only the
standard library + pytest — no SAP system.

``sample_data`` used to be described here as "crafted to trigger each check".
It is not, and the difference matters: 392 of the 790 check ids never fire on
either shipped fixture, so for half the catalogue "correctly silent" and "can
never fire" look identical. This file now RECORDS which check ids fire anywhere
in the suite, so the real figure is measured rather than asserted — see
``tools/build_firing_reference.py`` and ``docs/CHECK_FIRING.md``.
"""
import contextlib
import io
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.data_loader import DataLoader  # noqa: E402


@pytest.fixture(scope="session")
def root():
    return ROOT


@pytest.fixture(scope="session")
def sample_dir():
    return ROOT / "sample_data"


@pytest.fixture(scope="session")
def data(sample_dir):
    """The loaded sample_data dict (loader chatter suppressed)."""
    with contextlib.redirect_stdout(io.StringIO()):
        return DataLoader(sample_dir).load_all()


# ── which checks this suite actually exercises ─────────────────────────────
#
# Counting how many check ids fire against the two FIXTURES understates the
# answer: SODCOV-004..010 never appear in a fixture run while 57 unit tests
# drive them directly. The only way to know what the suite proves is to watch
# every finding it produces, wherever it is produced.
#
# The wrapper is transparent — it records an id and delegates — so a test that
# passes with it installed passes without it.

FIRED_CHECK_IDS: set = set()


def pytest_configure(config):
    from modules.base_auditor import BaseAuditor
    if getattr(BaseAuditor.finding, "_records_firing", False):
        return
    original = BaseAuditor.finding

    def recording(self, check_id, *args, **kwargs):
        FIRED_CHECK_IDS.add(check_id)
        return original(self, check_id, *args, **kwargs)

    recording._records_firing = True
    recording.__doc__ = original.__doc__
    BaseAuditor.finding = recording


def pytest_sessionfinish(session, exitstatus):
    """Write what fired, for tools/build_firing_reference.py to read.

    Only on a FULL run: a partial run records a partial set, and publishing that
    as "these checks are unproven" would be the same confident-answer-over-an-
    unasked-question this product reports on.
    """
    import json
    if session.config.option.keyword or session.config.option.markexpr:
        return
    if len(getattr(session, "items", []) or []) < 3000:
        return
    out = ROOT / "reports" / "check_firing.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"fired": sorted(FIRED_CHECK_IDS),
                               "tests_collected": len(session.items)},
                              indent=1), encoding="utf-8")

# ── the skips this suite does not mention loudly enough ────────────────────
#
# THIS PRODUCT EXISTS TO SAY THAT A CLEAN RESULT AND AN UNASKED QUESTION LOOK
# ALIKE, and its own test suite was doing exactly that. A plain `pytest` run
# ends with "5,096 passed, 246 skipped" — and EVERY ONE of those 246 is the
# console: ingest, the journey, graph paths, saved views, bulk actions, the
# HTTP API and ALL of the RBAC coverage. They skip because DB_DSN is unset.
#
# The number was on screen every single run and read past every single time,
# which is the failure mode this repository keeps finding in other people's
# reports. `tools/db_test.py` and CLAUDE.md both document the fix; neither is
# in front of somebody watching a green summary line scroll past.
#
# So the suite now says what it did not do, in the place the reader is already
# looking, and says how to do it.

def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """Name the surface that did not run, rather than counting it as a skip."""
    if os.getenv("DB_DSN"):
        return
    skipped = terminalreporter.stats.get("skipped") or []
    db_skips = [r for r in skipped
                if "DB_DSN" in str(getattr(r, "longrepr", ""))]
    if not db_skips:
        return
    write = terminalreporter.write_line
    write("")
    write("=" * 72)
    write("%d TEST(S) DID NOT RUN because DB_DSN is unset." % len(db_skips))
    write("")
    write("That is the console half of this product: ingest, the journey,")
    write("graph paths, saved views, bulk actions, the HTTP API and all of")
    write("the RBAC coverage. The journey is implemented in SQL, so nothing")
    write("above proves any of it works.")
    write("")
    write("  docker run -d --name sap-test-db -p 127.0.0.1:55432:5432 \\")
    write("      -e POSTGRES_USER=sapsec -e POSTGRES_PASSWORD=x \\")
    write("      -e POSTGRES_DB=sapsec postgres:16")
    write("  set DB_DSN=postgresql://sapsec:x@127.0.0.1:55432/sapsec")
    write("  python -m tools.db_test")
    write("=" * 72)
