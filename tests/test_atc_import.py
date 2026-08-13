# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
ATC / Code Inspector / SAP CVA result import.

WHAT THIS FILE IS REALLY PROTECTING
The mitigation journey. An ATC export names an object and a LINE, and line numbers
move whenever anyone edits the code above them. If the line reached a finding's
identity, re-exporting after a cosmetic change would resolve every finding in that
program and raise a fresh set — age and MTTR would reset to zero on a run where
nothing was fixed, and the report would look like progress.

So the load-bearing test here is not "does it find things". It is
`test_line_numbers_can_move_without_resolving_anything`.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.atc_import import AtcImportAuditor          # noqa: E402
from server.identity import compute_fingerprint          # noqa: E402


def _fingerprint(finding):
    return compute_fingerprint(
        finding["check_id"], finding.get("system"), finding.get("client"),
        finding.get("subject"), finding.get("affected_items"),
        finding.get("scope") or "object")


def _identity_set(findings):
    return {(f["check_id"], _fingerprint(f)[0]) for f in findings}


def _run(rows, **extra):
    data = {"custom_code_scan": rows}
    data.update(extra)
    return AtcImportAuditor(data, {}).run_all_checks()


SQLI_ROW = {"OBJECT_NAME": "Z_VENDOR_REPORT", "OBJECT_TYPE": "PROG",
            "FINDING_TYPE": "SQL_INJECTION", "SEVERITY": "CRITICAL", "LINE": "145",
            "DESCRIPTION": "Dynamic WHERE clause built via CONCATENATE",
            "STATUS": "OPEN"}


# --------------------------------------------------------------------------- #
#  Identity — the whole point                                                 #
# --------------------------------------------------------------------------- #

def test_line_numbers_can_move_without_resolving_anything():
    """Somebody adds a header comment; every line below shifts. Nothing was fixed,
    so nothing may resolve and nothing may appear as new."""
    before = _run([SQLI_ROW])
    after = _run([{**SQLI_ROW, "LINE": "182"}])

    assert _identity_set(before) == _identity_set(after), \
        "a line-number shift changed finding identity — every fix-tracking metric " \
        "in the product would reset on a cosmetic edit"


def test_the_same_export_twice_is_a_no_op():
    rows = [SQLI_ROW, {**SQLI_ROW, "OBJECT_NAME": "Z_OTHER", "LINE": "12"}]
    assert _identity_set(_run(rows)) == _identity_set(_run(rows))


def test_identity_is_per_object_not_per_estate():
    """Two programs with the same defect are two findings, so fixing one is visible."""
    rows = [SQLI_ROW, {**SQLI_ROW, "OBJECT_NAME": "Z_SECOND_PROG"}]
    ids = _identity_set(_run(rows))
    assert len(ids) == 2, "two objects collapsed into one finding"


def test_several_hits_in_one_object_are_one_finding_that_names_them_all():
    rows = [SQLI_ROW,
            {**SQLI_ROW, "LINE": "200"},
            {**SQLI_ROW, "LINE": "310"}]
    findings = [f for f in _run(rows) if f["check_id"] == "ATC-SQLI"]
    assert len(findings) == 1
    assert findings[0]["details"]["occurrences"] == 3
    assert findings[0]["details"]["lines"] == ["145", "200", "310"]


def test_fixing_one_of_three_shrinks_the_finding_without_resolving_it():
    """Partial progress must be visible AND must not read as completion."""
    three = _run([SQLI_ROW, {**SQLI_ROW, "LINE": "200"}, {**SQLI_ROW, "LINE": "310"}])
    two = _run([SQLI_ROW, {**SQLI_ROW, "LINE": "200"}])

    assert _identity_set(three) == _identity_set(two), "the finding was replaced, not shrunk"
    f3 = next(f for f in three if f["check_id"] == "ATC-SQLI")
    f2 = next(f for f in two if f["check_id"] == "ATC-SQLI")
    assert f3["details"]["occurrences"] == 3 and f2["details"]["occurrences"] == 2


def test_fixing_them_all_resolves_the_finding():
    assert not [f for f in _run([]) if f["check_id"] == "ATC-SQLI"]


def test_every_object_finding_identifies_by_structured_object_not_display_text():
    for f in _run([SQLI_ROW]):
        if f.get("scope") == "object":
            assert _fingerprint(f)[1] == "objects", \
                f"{f['check_id']} fingerprints over display text, which is not stable"


def test_a_governance_finding_does_not_fingerprint_over_its_own_count():
    """ATC-GOV-002 reports how many rows were unclassified. If that number were part
    of its identity it would resolve and re-raise every time it changed."""
    # DESCRIPTION must be cleared too: classification reads the check name AND the
    # description, so leaving SQLI_ROW's "Dynamic WHERE" text in would classify these
    # as SQL injection rather than leaving them unclassified.
    noise = {**SQLI_ROW, "FINDING_TYPE": "PERFORMANCE_LOOP", "DESCRIPTION": "nested loop"}
    few = _run([SQLI_ROW, noise])
    many = _run([SQLI_ROW] + [{**noise, "OBJECT_NAME": f"Z_P{i}"} for i in range(9)])
    a = next(f for f in few if f["check_id"] == "ATC-GOV-002")
    b = next(f for f in many if f["check_id"] == "ATC-GOV-002")
    assert a["details"]["unclassified_rows"] != b["details"]["unclassified_rows"]
    assert _fingerprint(a)[0] == _fingerprint(b)[0], \
        "the unclassified COUNT reached the fingerprint"


# --------------------------------------------------------------------------- #
#  Classification                                                             #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("finding_type,expected", [
    ("SQL_INJECTION", "ATC-SQLI"),
    ("CODE_INJECTION", "ATC-CINJ"),
    ("COMMAND_INJECTION", "ATC-CMDI"),
    ("MISSING_AUTH", "ATC-AUTHCHK"),
    ("DIRECTORY_TRAVERSAL", "ATC-PATH"),
    ("XSS", "ATC-XSS"),
    ("HARDCODED", "ATC-CRED"),
])
def test_check_families_are_recognised(finding_type, expected):
    ids = {f["check_id"] for f in _run([{**SQLI_ROW, "FINDING_TYPE": finding_type,
                                         "DESCRIPTION": ""}])}
    assert expected in ids


def test_column_names_are_matched_case_insensitively():
    """The same export arrives with different casing from SE80, the ATC result
    browser and an ADT extract. A silent miss here looks like a clean estate."""
    lower = {"object_name": "Z_X", "object_type": "PROG",
             "finding_type": "SQL_INJECTION", "line": "10",
             "description": "dynamic where", "status": "OPEN"}
    assert any(f["check_id"] == "ATC-SQLI" for f in _run([lower]))


def test_an_unrecognised_check_is_disclosed_rather_than_dropped():
    findings = _run([{**SQLI_ROW, "FINDING_TYPE": "NAMING_CONVENTION",
                      "DESCRIPTION": "name does not match"}])
    gov = [f for f in findings if f["check_id"] == "ATC-GOV-002"]
    assert gov, "an unmatched row vanished with nothing anywhere saying so"
    assert gov[0]["details"]["unclassified_rows"] == 1


# --------------------------------------------------------------------------- #
#  Respecting the customer's own workflow                                     #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("status", ["EXEMPTED", "Approved", "fixed", "FALSE_POSITIVE"])
def test_rows_the_customer_already_closed_are_not_re_raised(status):
    """An ATC exemption is a decision somebody made in their own system. Re-raising
    it as open is how a tool gets ignored."""
    assert not [f for f in _run([{**SQLI_ROW, "STATUS": status}])
                if f["check_id"] == "ATC-SQLI"]


def test_sap_severity_wins_when_it_is_harsher_than_our_floor():
    f = next(f for f in _run([{**SQLI_ROW, "FINDING_TYPE": "WEAK_CRYPTO",
                               "SEVERITY": "CRITICAL", "DESCRIPTION": ""}])
             if f["check_id"] == "ATC-CRYP")
    assert f["severity"] == "CRITICAL", "SAP graded it in the customer's own context"


def test_our_floor_wins_when_the_export_understates_it():
    f = next(f for f in _run([{**SQLI_ROW, "SEVERITY": "LOW"}])
             if f["check_id"] == "ATC-SQLI")
    assert f["severity"] == "CRITICAL"


def test_atc_priority_1_2_3_is_understood_when_there_is_no_severity_column():
    row = {"OBJECT_NAME": "Z_P", "OBJECT_TYPE": "PROG", "FINDING_TYPE": "WEAK_CRYPTO",
           "PRIORITY": "1", "LINE": "5", "DESCRIPTION": ""}
    f = next(f for f in _run([row]) if f["check_id"] == "ATC-CRYP")
    assert f["severity"] == "CRITICAL"


# --------------------------------------------------------------------------- #
#  Is anybody scanning at all?                                                #
# --------------------------------------------------------------------------- #

def test_custom_code_with_no_scan_result_is_a_finding():
    findings = _run([], code_inventory=[
        {"OBJECT_NAME": "Z_VENDOR_REPORT", "OBJECT_TYPE": "PROG"},
        {"OBJECT_NAME": "Y_OLD_THING", "OBJECT_TYPE": "PROG"}])
    gov = [f for f in findings if f["check_id"] == "ATC-GOV-001"]
    assert gov and gov[0]["details"]["custom_object_count"] == 2


def test_no_custom_code_means_no_complaint():
    """Asserting an absence over an estate with nothing to scan is noise."""
    findings = _run([], code_inventory=[{"OBJECT_NAME": "SAPLSUSR", "OBJECT_TYPE": "PROG"}])
    assert not [f for f in findings if f["check_id"] == "ATC-GOV-001"]


def test_a_supplied_scan_silences_the_governance_finding():
    findings = _run([SQLI_ROW], code_inventory=[{"OBJECT_NAME": "Z_A"}])
    assert not [f for f in findings if f["check_id"] == "ATC-GOV-001"]


def test_nothing_at_all_produces_nothing():
    """No inventory and no scan is not evidence of a problem; it is no evidence."""
    assert _run([]) == []


# --------------------------------------------------------------------------- #
#  Registration                                                               #
# --------------------------------------------------------------------------- #

def test_the_module_is_registered_everywhere_it_has_to_be():
    """The documented recipe covers 7 sites; three more fail SILENTLY when missed."""
    assert "(\"atc_import\", \"AtcImportAuditor\")" in \
        (ROOT / "server" / "ingest.py").read_text(encoding="utf-8"), \
        "server ingest would never run this auditor"
    assert '"atc"' in (ROOT / "sap_scanner.py").read_text(encoding="utf-8")
    assert '"atc_import"' in (ROOT / "modules" / "coverage.py").read_text(encoding="utf-8"), \
        "the coverage manifest would not mention this module"


def test_every_emitted_check_id_routes_to_a_team():
    """team_for() silently returns 'unassigned' for an unrouted prefix."""
    from server.enrich import team_for
    rows = [{**SQLI_ROW, "FINDING_TYPE": t} for t in
            ("SQL_INJECTION", "CODE_INJECTION", "COMMAND_INJECTION", "MISSING_AUTH",
             "DIRECTORY_TRAVERSAL", "XSS", "HARDCODED", "RFC_INJECTION",
             "WEAK_CRYPTO", "INFORMATION_DISCLOSURE", "NAMING_CONVENTION")]
    ids = {f["check_id"] for f in _run(rows, code_inventory=[{"OBJECT_NAME": "Z_A"}])}
    ids.add("ATC-GOV-001")
    unrouted = sorted(cid for cid in ids if team_for(cid) == "unassigned")
    assert not unrouted, f"these check ids route nowhere: {unrouted}"
