# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""Exposure, as distinct from patch status.

Before these checks the module asked one question — is this note in your
applied-notes export — and a customer who could not produce that export got a
list to check by hand and nothing else. Three further axes were available the
whole time from sources the scanner already loads: the installed component
release against the affected-version list SAP published with the CVE, the CVSS
vector's statement about whether credentials are needed at all, and SAP's own
documented workaround where it is something we can look for.

The tests that matter most here are the ones about NOT answering. An affected
-version list that is on a different scale from a CVERS release will happily
compare and return "not in the list", and the scanner would then tell a
vulnerable system it is fine. Every test below that asserts silence is guarding
that.
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.sap_hotnews import SapHotNewsAuditor            # noqa: E402

EXPOSURE = ROOT / "data" / "cve_exposure.json"


def _run(**data):
    with contextlib.redirect_stdout(io.StringIO()):
        findings = SapHotNewsAuditor(dict(data), {}).run_all_checks()
    return {f["check_id"]: f for f in findings}


S4_SYSTEM = [{"COMPONENT": "SAP_BASIS", "RELEASE": "755"},
             {"COMPONENT": "S4CORE", "RELEASE": "105"}]


# ═════════════════════════════════════════════════════════════════════════════
#  The headline: an answer without an SNOTE export
# ═════════════════════════════════════════════════════════════════════════════

def test_exposure_is_established_with_no_applied_notes_export_at_all():
    """THE POINT OF THIS WORK.

    `run_all_checks` used to return immediately when applied_notes was absent,
    so the system whose operator cannot produce an SNOTE list — the one that
    most needs something said about it — got a manual to-do list and nothing
    else. The component export alone establishes exposure.
    """
    fired = _run(system_component=S4_SYSTEM)
    assert "HOTNEWS-000" in fired          # the export is still asked for
    assert "HOTNEWS-006" in fired, "no exposure established without applied_notes"
    assert fired["HOTNEWS-006"]["affected_items"]
    assert fired["HOTNEWS-006"]["details"]["patch_status_known"] is False


def test_the_release_confirmed_finding_is_critical_and_names_the_component():
    fired = _run(system_component=S4_SYSTEM, applied_notes=[])
    item = fired["HOTNEWS-006"]["affected_items"][0]
    assert fired["HOTNEWS-006"]["severity"] == "CRITICAL"
    assert "IS in the affected release list" in item
    assert ("SAP_BASIS 755" in item or "S4CORE 105" in item)


def test_an_implemented_note_is_not_reported_as_exposed():
    """Patch status still wins where it is known."""
    applied = [{"NOTE": n, "STATUS": "Completely implemented"}
               for n in ("3097887", "3288480", "3302162", "3550708",
                         "3694242", "3697099")]
    fired = _run(system_component=S4_SYSTEM, applied_notes=applied)
    assert "HOTNEWS-006" not in fired


# ═════════════════════════════════════════════════════════════════════════════
#  The version-scale trap — what must NOT produce a verdict
# ═════════════════════════════════════════════════════════════════════════════

def test_kernel_version_lists_never_produce_a_release_verdict():
    """THE TRAP THIS DESIGN EXISTS FOR.

    NVD lists ICMAD (3123396) against netweaver_application_server_abap with
    versions 7.22, 7.49, 7.53 — those are KERNEL patch levels, not SAP_BASIS
    releases. Compared against SAP_BASIS 755 they simply do not match, so a naive
    check would report an ICMAD-vulnerable system as outside the affected range.
    The entry must carry no component mapping at all.
    """
    data = json.loads(EXPOSURE.read_text(encoding="utf-8"))["entries"]
    icmad = data["3123396"]
    assert "affected_by_component" not in icmad
    assert icmad["version_match"] == "unavailable"
    assert "kernel" in icmad["version_reason"].lower()

    fired = _run(system_component=S4_SYSTEM, applied_notes=[])
    for cid in ("HOTNEWS-006", "HOTNEWS-008"):
        listed = " ".join(fired.get(cid, {}).get("affected_items", []))
        assert "3123396" not in listed, "%s gave ICMAD a release verdict" % cid


def test_every_mappable_component_is_kept_not_just_the_first():
    """A defect caught while generating the data. NVD lists note 3697099 against
    netweaver_application_server_abap ["700"] AND s\\/4hana [102..109]. Keeping
    only the first gave SAP_BASIS ["700"], so a system on SAP_BASIS 755 with
    S4CORE 105 — squarely affected — would have been reported as not affected."""
    data = json.loads(EXPOSURE.read_text(encoding="utf-8"))["entries"]
    mapped = data["3697099"]["affected_by_component"]
    assert set(mapped) == {"SAP_BASIS", "S4CORE"}
    assert "105" in mapped["S4CORE"]

    fired = _run(system_component=S4_SYSTEM, applied_notes=[])
    assert any("3697099" in i for i in fired["HOTNEWS-006"]["affected_items"])


def test_a_release_written_with_a_leading_zero_still_matches():
    """`0755` is how some CVERS exports write 755. String equality would report
    an affected system as unaffected."""
    fired = _run(system_component=[{"COMPONENT": "SAP_BASIS", "RELEASE": "0755"}],
                 applied_notes=[])
    assert any("3550708" in i for i in fired["HOTNEWS-006"]["affected_items"])


# ═════════════════════════════════════════════════════════════════════════════
#  Not-in-the-list is not a clearance
# ═════════════════════════════════════════════════════════════════════════════

def test_the_two_release_verdicts_partition_the_same_system_correctly():
    """One release, two opposite verdicts, and neither may leak into the other.

    SAP_BASIS 758 is inside note 3550708's published list (…757, 758, 912…) and
    outside note 3097887's (700–756). Both findings must therefore fire on this
    one system, each naming only its own notes. An earlier version of this test
    asserted 758 was outside everything and failed — correctly, because it was
    the test that was wrong, not the check.
    """
    fired = _run(system_component=[{"COMPONENT": "SAP_BASIS", "RELEASE": "758"}],
                 applied_notes=[])
    exposed = " ".join(fired["HOTNEWS-006"]["affected_items"])
    advisory = " ".join(fired["HOTNEWS-008"]["affected_items"])

    assert "3550708" in exposed and "3550708" not in advisory
    assert "3097887" in advisory and "3097887" not in exposed


def test_a_release_outside_the_list_is_advisory_and_says_so():
    """NVD's affected lists are frequently incomplete — a release can be absent
    because nobody enumerated it, or because it did not exist when the CVE was
    published. Presenting that as "not affected" would be the scanner clearing a
    vulnerability on the strength of a gap in someone else's data."""
    fired = _run(system_component=[{"COMPONENT": "SAP_BASIS", "RELEASE": "758"}],
                 applied_notes=[])
    finding = fired["HOTNEWS-008"]
    assert finding["severity"] == "INFO"
    assert finding["details"]["is_not_a_clearance"] is True
    assert "NOT A CLEARANCE" in finding["description"]


# ═════════════════════════════════════════════════════════════════════════════
#  The vector axis
# ═════════════════════════════════════════════════════════════════════════════

def test_only_unauthenticated_network_vectors_reach_the_vector_finding():
    fired = _run(applied_notes=[])
    assert "HOTNEWS-007" in fired
    for item in fired["HOTNEWS-007"]["affected_items"]:
        assert "AV:N" in item and "PR:N" in item


def test_the_vector_axis_needs_no_component_export():
    """It is read from the shipped CVSS vector, so it works on the thinnest
    export a customer can send."""
    fired = _run(applied_notes=[])
    assert fired["HOTNEWS-007"]["affected_items"]


def test_an_authenticated_only_note_is_not_in_the_vector_finding():
    """CVE-2026-44747 is AV:N/PR:L — network reachable but needs credentials.
    It belongs in the ordinary missing-note findings, not the one that says no
    credentials are needed."""
    fired = _run(applied_notes=[])
    listed = " ".join(fired["HOTNEWS-007"]["affected_items"])
    assert "3747367" not in listed


# ═════════════════════════════════════════════════════════════════════════════
#  Workarounds
# ═════════════════════════════════════════════════════════════════════════════

def _roles(*rows):
    return [dict(zip(("AGR_NAME", "OBJECT", "FIELD", "LOW", "HIGH"), r)) for r in rows]


def test_a_role_granting_the_value_through_a_range_is_caught():
    """`LOW=01 HIGH=60` grants activity 60. Reading only LOW would miss most of
    the roles that actually hold it."""
    fired = _run(applied_notes=[],
                 role_auth_values=_roles(("Z_POWER", "S_GUI", "ACTVT", "01", "60")))
    assert "HOTNEWS-009" in fired
    assert "Z_POWER" in fired["HOTNEWS-009"]["affected_items"][0]


def test_a_role_outside_the_range_is_not_caught():
    fired = _run(applied_notes=[],
                 role_auth_values=_roles(("Z_VIEW", "S_GUI", "ACTVT", "03", "")))
    assert "HOTNEWS-009" not in fired


def test_a_wildcard_grant_counts():
    fired = _run(applied_notes=[],
                 role_auth_values=_roles(("Z_ALL", "S_GUI", "ACTVT", "*", "")))
    assert "HOTNEWS-009" in fired


def test_the_workaround_is_not_reported_once_the_note_is_implemented():
    """A patched system does not need the mitigation."""
    fired = _run(applied_notes=[{"NOTE": "3719353", "STATUS": "Completely implemented"}],
                 role_auth_values=_roles(("Z_POWER", "S_GUI", "ACTVT", "01", "60")))
    assert "HOTNEWS-009" not in fired


def test_only_workarounds_with_a_named_source_are_shipped():
    """An invented mitigation is worse than none: a customer told their exposure
    is contained stops looking at it."""
    data = json.loads(EXPOSURE.read_text(encoding="utf-8"))["entries"]
    for note, entry in data.items():
        work = entry.get("workaround")
        if work:
            assert work.get("source"), "%s has a workaround with no source" % note
            assert work.get("statement")


# ═════════════════════════════════════════════════════════════════════════════
#  Coverage — silence must be explained
# ═════════════════════════════════════════════════════════════════════════════

def test_no_component_export_is_reported_rather_than_silently_skipped():
    fired = _run(applied_notes=[])
    assert "HOTNEWS-010" in fired
    assert fired["HOTNEWS-010"]["details"]["component_export_supplied"] is False
    assert any("no system_component" in i
               for i in fired["HOTNEWS-010"]["affected_items"])


def test_the_coverage_finding_arms_the_release_gate():
    fired = _run(applied_notes=[])
    assert fired["HOTNEWS-010"]["details"]["degrades_coverage"] is True


def test_notes_with_no_published_version_data_are_named_not_dropped():
    """18 of 43 catalogue entries have no affected-version data in NVD at all,
    and they are disproportionately the recent ABAP ones. Their absence from the
    exposure findings must be stated, not inferred."""
    fired = _run(system_component=S4_SYSTEM, applied_notes=[])
    assert "HOTNEWS-010" in fired
    assert fired["HOTNEWS-010"]["details"]["unassessed"] > 0


# ═════════════════════════════════════════════════════════════════════════════
#  The shipped data
# ═════════════════════════════════════════════════════════════════════════════

def test_the_exposure_data_declares_its_provenance():
    """The discipline data/ecs_hardening_3250501.json already uses: a reader can
    tell a measurement from a memory."""
    meta = json.loads(EXPOSURE.read_text(encoding="utf-8"))["meta"]
    assert "NVD" in meta["source"] and "SAP CNA" in meta["source"]
    assert meta["obtained"]
    assert "not a patch-status source" in meta["what_this_is"].lower()


def test_every_catalogue_entry_has_an_exposure_record():
    """A note in the catalogue with no exposure record would be silently skipped
    by all three axes."""
    data = json.loads(EXPOSURE.read_text(encoding="utf-8"))["entries"]
    missing = [e["note"] for e in SapHotNewsAuditor.HOTNEWS_CATALOG
               if e["note"] not in data]
    assert not missing, "catalogue notes with no exposure record: %s" % missing


def test_every_exposure_record_carries_a_cvss_vector():
    """The vector axis is the only one that works on every entry, so a missing
    vector silently removes a note from it."""
    data = json.loads(EXPOSURE.read_text(encoding="utf-8"))["entries"]
    for note, entry in data.items():
        if "cve" in entry:
            assert entry.get("vector"), "%s has no CVSS vector" % note


def test_a_missing_data_file_degrades_the_exposure_checks_not_the_module(monkeypatch):
    """A malformed or absent data file must not take the missing-note findings
    down with it."""
    monkeypatch.setattr(SapHotNewsAuditor, "EXPOSURE_PATH",
                        ROOT / "data" / "does-not-exist.json")
    fired = _run(system_component=S4_SYSTEM, applied_notes=[])
    assert "HOTNEWS-001" in fired          # the ordinary checks still ran
    assert "HOTNEWS-006" not in fired
