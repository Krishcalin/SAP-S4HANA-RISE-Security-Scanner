# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""Detecting that SAP's Baseline Template moved, without downloading 99 MB.

WHAT THIS COMPLETES. The `sap-content` CI job already re-derives both catalogues
from SAP's Apache-2.0 policy repository and fails on drift. That covers the
POLICIES. The Baseline Template ZIP is a different artefact on a different
cadence, and the gap is not hypothetical: the policy set this product derives
from is v2.4 and the archive ships V2.6.

WHY THE CHANGE MARKERS ARE THE POINT. Each version carries a
`*_change_marker.pdf`. They are what makes "the REQUIREMENT changed"
distinguishable from "the SYSTEM changed" across two scans of one estate, and a
customer cannot make that distinction for themselves once a finding's text has
moved underneath them.

EVERY TEST HERE IS OFFLINE. A unit suite that reaches SAP's support host would
fail on their outage and pass on ours, which is the wrong way round for a test
whose subject is somebody else's release cadence. The parser is exercised against
a real ZIP built in memory; the comparison against the pinned record.
"""
from __future__ import annotations

import io
import json
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import check_baseline_zip as chk                    # noqa: E402

PINNED = json.loads((ROOT / "data" / "sap_baseline_zip.json").read_text(encoding="utf-8"))


def _zip(*names: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name in names:
            zf.writestr(name, b"x")
    return buf.getvalue()


# ═════════════════════════════════════════════════════════════════════════════
#  Reading the directory out of the tail
# ═════════════════════════════════════════════════════════════════════════════

def test_entry_names_are_read_from_a_real_archives_central_directory():
    raw = _zip("V2.6/doc.pdf", "V2.5/other.pdf")
    assert set(chk.entry_names(raw)) == {"V2.6/doc.pdf", "V2.5/other.pdf"}


def test_a_truncated_tail_still_yields_what_it_can():
    """A ranged read lands wherever the byte offset falls, mid-structure as often
    as not. Scanning for the signature tolerates that; parsing from the
    end-of-central-directory record would not."""
    raw = _zip(*[f"V2.{n}/f.pdf" for n in range(6)])
    cut = raw[len(raw) // 3:]
    assert chk.entry_names(cut)          # some, not necessarily all
    assert all(n.startswith("V2.") for n in chk.entry_names(cut))


def test_versions_are_extracted_and_ordered():
    names = ["V2.10/a.pdf", "V2.2/b.pdf", "V2.6/c.pdf"]
    assert chk.versions_of(names) == ["V2.10", "V2.2", "V2.6"]


def test_change_markers_are_picked_out_by_name():
    names = ["V2.6/Security_Baseline_Template_V2.6_change_marker.pdf",
             "V2.6/Security_Baseline_Template_V2.6.pdf"]
    assert chk.change_markers(names) == [names[0]]


def test_the_tail_is_a_small_fraction_of_the_archive():
    """CI runs on every push. Downloading 99 MB to learn a version number is the
    kind of cost that gets a useful check deleted."""
    assert chk.TAIL_BYTES <= 500_000
    assert chk.TAIL_BYTES < PINNED["content_length"] / 100


# ═════════════════════════════════════════════════════════════════════════════
#  What counts as movement
# ═════════════════════════════════════════════════════════════════════════════

def _live(**over):
    base = {"content_length": PINNED["content_length"],
            "last_modified": PINNED["last_modified"],
            "entries": PINNED["entries"],
            "versions": list(PINNED["versions"]),
            "change_markers": list(PINNED["change_markers"])}
    base.update(over)
    return base


def test_an_unchanged_archive_reports_nothing():
    assert chk.compare(_live(), PINNED) == []


def test_a_new_version_tells_the_reader_to_read_its_change_marker():
    """"content_length differs" tells nobody anything. The instruction is the
    whole reason this runs."""
    problems = chk.compare(_live(versions=PINNED["versions"] + ["V2.7"]), PINNED)
    assert any("V2.7" in p and "CHANGE MARKER" in p for p in problems)


def test_a_republished_archive_is_noticed_by_size():
    problems = chk.compare(_live(content_length=PINNED["content_length"] + 1), PINNED)
    assert any("size changed" in p for p in problems)


def test_a_withdrawn_version_is_noticed_too():
    """A version SAP removed is worth knowing about before citing it."""
    fewer = [v for v in PINNED["versions"] if v != "V2.5"]
    problems = chk.compare(_live(versions=fewer), PINNED)
    assert any("V2.5" in p and "no longer" in p for p in problems)


def test_a_timestamp_move_alone_is_still_reported():
    problems = chk.compare(_live(last_modified="Thu, 01 Jan 2026 00:00:00 GMT"), PINNED)
    assert problems


# ═════════════════════════════════════════════════════════════════════════════
#  The pinned record
# ═════════════════════════════════════════════════════════════════════════════

def test_the_record_pins_what_was_measured_rather_than_quoted():
    assert PINNED["content_length"] == 99336484
    assert PINNED["entries"] == 545
    assert PINNED["current"] == "V2.6"
    assert "re-measured rather than copied" in PINNED["_meta"]["source"]


def test_the_record_names_the_gap_between_the_archive_and_our_content():
    """The archive ships V2.6 and this product derives from policy set v2.4.
    Nothing else in the repository would have shown that."""
    assert PINNED["derived_catalogue_version"] == "v2.4"
    assert PINNED["current"] != PINNED["derived_catalogue_version"]
    assert "two versions ahead" in PINNED["_meta"]["the_gap_worth_knowing"]


def test_the_record_distinguishes_itself_from_the_policy_repository():
    """Two SAP artefacts on two cadences. Conflating them would make one check
    look like it covered both."""
    assert "Not the policy repository" in PINNED["_meta"]["what_this_is_not"]


def test_every_version_from_v2_1_onward_has_a_change_marker():
    """V2.0 is the base and has nothing to mark against. Every later version
    does, which is what makes the requirement-changed question answerable."""
    for version in PINNED["versions"]:
        if version == "V2.0":
            continue
        assert any(m.startswith(version + "/") for m in PINNED["change_markers"]), version


def test_the_absence_of_a_login_wall_is_recorded():
    """It is the only reason this can run in CI rather than on somebody's laptop
    with an S-user, and it is the kind of fact that gets forgotten and then
    re-litigated."""
    assert "200" in PINNED["_meta"]["no_login_wall"]


# ═════════════════════════════════════════════════════════════════════════════
#  Wiring
# ═════════════════════════════════════════════════════════════════════════════

def test_ci_runs_the_check():
    workflow = (ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")
    assert "tools.check_baseline_zip" in workflow


def test_ci_does_not_let_saps_outage_fail_an_unrelated_pull_request():
    """Their support host is outside our control. The step still goes red, which
    is the signal; it does not block a merge that has nothing to do with it."""
    workflow = (ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")
    step = workflow.split("SAP's Baseline Template archive has not moved", 1)[1]
    assert "continue-on-error: true" in step.split("- name:", 1)[0]


def test_update_is_documented_as_something_you_do_after_reading():
    """`--update` exists to re-pin after a person has read the change marker. A
    flag that silently makes a failing build pass is one somebody reaches for at
    the wrong moment."""
    src = (ROOT / "tools" / "check_baseline_zip.py").read_text(encoding="utf-8")
    assert "never to make a" in src and "failing build pass" in src


def test_the_offline_mode_needs_no_network():
    assert chk.main(["--offline"]) == 0
