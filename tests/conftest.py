"""Shared pytest fixtures for the SAP scanner test suite.

The tests run every audit module against the bundled ``sample_data`` (which is
crafted to trigger each check) and validate the finding contract + the full
report pipeline. They need only the standard library + pytest — no SAP system.
"""
import contextlib
import io
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
