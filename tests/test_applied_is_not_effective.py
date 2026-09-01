"""Recorded as applied, and demonstrably not delivered.

WHAT THIS CLOSES. Every other check in `modules/sap_hotnews.py` asks whether a
note is MISSING from the applied-notes export. None of them asked whether a note
recorded as PRESENT actually landed — and an operator cannot answer that from
SNOTE, which records that a note was implemented, not that the software carrying
its correction is installed. Onapsis sells exactly this distinction as the
headline of its SAP Notes Command Center; see `docs/COMPETITOR_ONAPSIS.md` §2.1.

WHY IT IS NARROW, AND WHY THAT IS THE HONEST WIDTH. `_report_below_fix_level`
already refuses the obvious version of this and says why: a note applied through
correction instructions legitimately does not move a component's support-package
level, so "applied AND below the component SP" is the normal case and reporting
it would be the loudest possible false positive.

The exception is a fix SNOTE CANNOT DELIVER. A HANA revision is installed by
upgrading the database; no ABAP correction instruction produces one. So a note
whose ONLY published fix is a HANA revision, recorded as applied while the
database is still below it, is two of the customer's own exports disagreeing.
SAP publishes such a fix for 26 notes in `data/sap_notes_catalogue.json`.

Kernel notes would qualify under identical reasoning — SAP publishes a kernel
fix level for 71 more — but this module reads no kernel source, so there is no
installed level to compare against. They are not examined rather than reported
as fine, which is the distinction this whole product turns on.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.sap_hotnews import SapHotNewsAuditor                 # noqa: E402

#: A real note, read out of SAP's own catalogue rather than typed here: its only
#: published fix is a HANA revision, and it is the highest-CVSS note of that
#: shape (9.8, missing authorization check in CommonCryptoLib).
NOTE = "3340576"


def _catalogue_entry(note=NOTE):
    data = json.loads((ROOT / "data" / "sap_notes_catalogue.json")
                      .read_text(encoding="utf-8"))
    return data["notes"][note]


def _run(applied, hana, **extra):
    data = {
        "applied_notes": applied,
        "hana_version": hana,
        "system_component": [],
        **extra,
    }
    return SapHotNewsAuditor(data, {}, {}).run_all_checks()


def _found(findings, check_id):
    return [f for f in findings if f["check_id"] == check_id]


def test_the_note_this_rests_on_is_still_shaped_the_way_we_think():
    """If SAP restates this note with a component support package, the premise
    goes with it — the contradiction only holds while the database revision is
    the ONLY published fix."""
    entry = _catalogue_entry()
    assert entry["hana_fix"], "the note no longer carries a HANA fix level"
    assert not entry["fix_levels"], \
        "the note now has a component SP path, so applied-and-below is normal"


def test_a_note_recorded_as_applied_below_its_hana_fix_is_reported():
    """The whole point. SNOTE says handled; the database says otherwise."""
    findings = _run(
        applied=[{"NOTE": NOTE, "STATUS": "Fully implemented"}],
        # Branch 2.00.06, where SAP's fix is 2.00.067.02.
        hana=[{"NAME": "VERSION", "VALUE": "2.00.061.00.1234"}])
    hits = _found(findings, "HOTNEWS-014")
    assert hits, "an applied note below its only published fix went unreported"
    assert NOTE in hits[0]["affected_items"]
    assert hits[0]["severity"] == "CRITICAL", "CVSS 9.8 reported below critical"
    # The evidence, not just the verdict: a reader has to be able to check it.
    assert "2.00.061" in hits[0]["description"]
    assert "2.00.067.02" in hits[0]["description"]


def test_it_says_which_export_it_contradicts():
    """This finding disagrees with something the customer supplied, and saying
    which is what separates it from HOTNEWS-013 — that one is about notes that
    are ABSENT."""
    findings = _run(
        applied=[{"NOTE": NOTE, "STATUS": "Fully implemented"}],
        hana=[{"NAME": "VERSION", "VALUE": "2.00.061.00.1234"}])
    hit = _found(findings, "HOTNEWS-014")[0]
    assert hit["details"]["contradicts"] == "applied_notes"
    assert hit["details"]["installed_hana"].startswith("2.00.061")
    # And tells the reader not to close it on the SNOTE status, which is the
    # one piece of evidence they will reach for first and the one this
    # contradicts.
    assert "SNOTE status" in hit["remediation"]


def test_a_database_at_or_above_the_fix_is_not_reported():
    findings = _run(
        applied=[{"NOTE": NOTE, "STATUS": "Fully implemented"}],
        hana=[{"NAME": "VERSION", "VALUE": "2.00.067.02.9999"}])
    assert not _found(findings, "HOTNEWS-014")


def test_a_note_that_was_never_applied_is_not_this_finding():
    """That is HOTNEWS-013's job, and a note cannot be both absent and
    contradicted by its own presence."""
    findings = _run(applied=[{"NOTE": "9999999", "STATUS": "Fully implemented"}],
                    hana=[{"NAME": "VERSION", "VALUE": "2.00.061.00.1234"}])
    assert not _found(findings, "HOTNEWS-014")


def test_without_a_hana_version_nothing_is_claimed():
    """No installed revision is not a passing revision. Reporting nothing here
    is correct; reporting the note as fine would not be.

    WHAT THIS CAN AND CANNOT HOLD, measured by mutation. Replacing the early
    return with a fabricated FAILING revision is caught here — that is the
    direction that invents a finding out of a missing export. Replacing it with
    a fabricated PASSING one is not, and cannot be: both it and the correct
    early return emit nothing, so the difference is invisible from outside the
    check. Stated rather than left for the next reader to re-derive."""
    findings = _run(applied=[{"NOTE": NOTE, "STATUS": "Fully implemented"}],
                    hana=[])
    assert not _found(findings, "HOTNEWS-014")


def test_a_revision_on_a_branch_sap_does_not_list_is_not_guessed_at():
    """`_hana_verdict` returns unknown for an unlisted branch, and unknown must
    not become "below" — an ordering this product cannot perform is not
    evidence of exposure."""
    findings = _run(
        applied=[{"NOTE": NOTE, "STATUS": "Fully implemented"}],
        hana=[{"NAME": "VERSION", "VALUE": "4.00.001.00.0001"}])
    assert not _found(findings, "HOTNEWS-014")


@pytest.mark.parametrize("status", ["Fully implemented", "Partially implemented"])
def test_partial_implementations_count_as_recorded_too(status):
    """A partially implemented note is still one the operator sees in SNOTE and
    reads as handled — and a partial correction cannot deliver a database
    revision either."""
    findings = _run(applied=[{"NOTE": NOTE, "STATUS": status}],
                    hana=[{"NAME": "VERSION", "VALUE": "2.00.061.00.1234"}])
    assert _found(findings, "HOTNEWS-014"), status


def test_the_kernel_notes_are_left_unexamined_rather_than_passed():
    """71 notes qualify under identical reasoning and cannot be judged, because
    this module reads no kernel source. The catalogue is asserted here so that
    whoever adds a kernel export finds this test waiting."""
    data = json.loads((ROOT / "data" / "sap_notes_catalogue.json")
                      .read_text(encoding="utf-8"))["notes"]
    kernel_only = [k for k, v in data.items()
                   if v["kernel_fix"] and not v["fix_levels"]]
    assert len(kernel_only) >= 60, \
        "the kernel-only population moved; re-read the docstring's claim"
    source = (ROOT / "modules" / "sap_hotnews.py").read_text(encoding="utf-8")
    assert "reads no kernel source" in source, \
        "the reason kernel notes are unexamined is no longer written down"


# ── the guard against the false positive HOTNEWS-013 refuses ─────────────────

def test_a_note_with_a_component_path_too_is_not_reported(monkeypatch):
    """THE FALSE POSITIVE THIS CHECK EXISTS TO AVOID.

    If SAP publishes a component support package for a note as well as a
    database revision, the SNOTE correction could have delivered the ABAP half
    — so "applied AND the database is below" is no longer a contradiction, and
    reporting it would be exactly what `_report_below_fix_level` refuses.

    THE CATALOGUE CONTAINS NO SUCH NOTE TODAY (see the test below), so the
    record here is SYNTHETIC and marked as such: it is built to exercise the
    guard, and asserts nothing about any real SAP note.
    """
    synthetic = dict(_catalogue_entry())
    synthetic["fix_levels"] = [{"component": "SAP_BASIS", "release": "757",
                                "min_sp": 5}]

    auditor = SapHotNewsAuditor(
        {"applied_notes": [{"NOTE": NOTE, "STATUS": "Fully implemented"}],
         "hana_version": [{"NAME": "VERSION", "VALUE": "2.00.061.00.1234"}],
         "system_component": []}, {}, {})
    monkeypatch.setattr(auditor, "_sap_catalogue", lambda: {NOTE: synthetic})

    findings = auditor.run_all_checks()
    assert not _found(findings, "HOTNEWS-014"), \
        "a note SNOTE could have fixed was reported as undelivered"


def test_that_guard_is_defensive_today_and_the_reader_should_know():
    """No note in SAP's published catalogue carries both paths, so the guard
    above is unexercised by real data. Asserted rather than assumed: if SAP
    ever publishes one, this fails and whoever sees it finds the reasoning."""
    data = json.loads((ROOT / "data" / "sap_notes_catalogue.json")
                      .read_text(encoding="utf-8"))["notes"]
    both = [k for k, v in data.items() if v["hana_fix"] and v["fix_levels"]]
    assert not both, (
        "SAP now publishes notes with both a HANA revision and a component "
        "support package (%s). The guard in _report_applied_but_undelivered is "
        "no longer defensive — check it still reads correctly." % both[:5])


def test_an_unreadable_hana_export_is_not_treated_as_a_passing_one():
    """Silence here must mean "could not tell", not "fine". A default installed
    revision would turn an unreadable export into a clean result — the failure
    this product exists to prevent."""
    findings = _run(applied=[{"NOTE": NOTE, "STATUS": "Fully implemented"}],
                    hana=[{"NAME": "SOMETHING_ELSE", "VALUE": ""}])
    assert not _found(findings, "HOTNEWS-014")
    # And the module reached no verdict rather than a favourable one: with a
    # readable BELOW revision the same input does report.
    again = _run(applied=[{"NOTE": NOTE, "STATUS": "Fully implemented"}],
                 hana=[{"NAME": "VERSION", "VALUE": "2.00.061.00.1234"}])
    assert _found(again, "HOTNEWS-014"), \
        "the check cannot report at all, so its silence proves nothing"
