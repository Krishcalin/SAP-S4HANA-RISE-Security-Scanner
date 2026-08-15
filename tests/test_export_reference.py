# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""A source the customer is never told about is a check that can never fire.

THE DEFECT
docs/EXPORT_GUIDE.md is hand-written and covers the sources a first scan needs.
It names 36 of the 123 logical sources the loader accepts. The other 87 appeared
nowhere at all — not in the guide, not in the README, nowhere a customer would
look. So they were never supplied, the coverage manifest reported them "not
supplied" for ever, and the checks behind them could never run. Everything the
product said about that was accurate and none of it was actionable, because the
reader could not know the file existed.

WHAT IS FIXED, AND WHAT IS NOT
docs/EXPORT_SOURCES.md is generated from the loader's own table and lists all
123 with the filenames accepted, the modules each feeds, and whether a procedure
is written. What it does NOT do is invent the missing procedures: a fabricated
SAP transaction code in an export guide is worse than an absent one, and this
codebase does not guess at SAP identifiers.

WHAT THESE TESTS ENFORCE
That the catalogue is complete and current, so a source cannot be added to the
scanner and remain invisible to the person who has to produce it.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

REFERENCE = ROOT / "docs" / "EXPORT_SOURCES.md"
GUIDE = ROOT / "docs" / "EXPORT_GUIDE.md"


@pytest.fixture(scope="module")
def reference():
    assert REFERENCE.exists(), "the export source reference is missing"
    return REFERENCE.read_text(encoding="utf-8")


def test_every_logical_source_the_scanner_reads_is_listed(reference):
    """The whole point. A source the loader accepts and nobody documents is a
    check that cannot fire for a reason the customer cannot act on."""
    from modules.coverage import all_logical_sources

    listed = set(re.findall(r"^\| `([^`]+)` \|", reference, re.M))
    missing = sorted(set(all_logical_sources()) - listed)
    assert not missing, (
        "%d sources the scanner reads are in no document a customer would find: "
        "%s" % (len(missing), missing[:12]))


def test_the_reference_is_current(reference):
    """Generated, so it can drift the moment somebody adds a source and does not
    regenerate. The tool checks itself."""
    from tools.build_export_reference import build

    assert reference == build(), (
        "docs/EXPORT_SOURCES.md is out of date — regenerate it with "
        "`python -m tools.build_export_reference`")


def test_it_names_the_files_the_loader_will_actually_accept(reference):
    """The row is only useful if supplying the named file works. Every filename
    in the reference must be one the loader maps."""
    from modules.data_loader import DataLoader

    accepted = {n for names in DataLoader.FILE_MAP.values() for n in names}
    quoted = set(re.findall(r"`([\w./-]+\.(?:csv|json|zip))`", reference))
    invented = sorted(quoted - accepted)
    assert not invented, (
        "the reference names files the loader does not accept: %s" % invented[:8])


def test_the_undocumented_ones_are_marked_rather_than_quietly_listed(reference):
    """A row that looks like the others but has no procedure behind it would send
    a reader to a guide that says nothing. It says so instead."""
    rows = re.findall(r"^\| `[^`]+` \|.*$", reference, re.M)
    assert len(rows) >= 100, "only %d rows — the table is not complete" % len(rows)
    marked = [r for r in rows if "not yet written" in r]
    assert marked, "nothing is marked as undocumented; the guide covers 36 of 123"
    documented = [r for r in rows if "| documented |" in r]
    assert documented, "nothing is marked as documented either — the check is broken"


def test_it_does_not_invent_sap_transaction_codes(reference):
    """The reason the missing procedures are missing rather than written.

    A transaction code is a claim a reader will act on. This file is generated
    from the loader's table and knows nothing about SAP's screens, so it must
    contain no procedure at all — anything that looked like one would have been
    guessed by the generator.
    """
    body = reference.split("## What", 1)[0]
    for verb in ("run transaction", "execute transaction", "go to transaction",
                 "in transaction "):
        assert verb not in body.lower(), (
            "the generated reference is describing a procedure it cannot know: %r"
            % verb)


def test_the_guide_points_at_the_full_catalogue():
    """Otherwise the reference is another document nobody finds."""
    guide = GUIDE.read_text(encoding="utf-8")
    assert "EXPORT_SOURCES.md" in guide, \
        "the export guide does not link the full source catalogue"
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "EXPORT_SOURCES.md" in readme, \
        "the README does not list the full source catalogue"
