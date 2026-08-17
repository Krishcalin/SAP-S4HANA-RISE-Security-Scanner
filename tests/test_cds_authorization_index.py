# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""Access control that was never written, as opposed to switched off.

Every CDS/RAP rule before this one matched something a developer typed —
`#NOT_ALLOWED`, `authorization master ( none )`. Those are deliberate and rare.
The common failure is that nobody wrote a DCL role at all, and no per-file rule
can see it, because the defect is a file that does not exist.

`ABAP-CDS-001`'s own comment claimed to cover this: *"A CDS view without a DCL
role is readable by anyone … which is why this is a check on what is ABSENT."*
Its pattern matches an explicit annotation. `test_the_defect_this_file_exists_for`
pins the gap that comment described and the code did not close.

The tests that matter most here are the ones about NOT reporting. A check that
flags every roleless view would be trivial to write and worthless to receive:
SAP's own guidance is that a view consumed only through another view is supposed
to have no role. The discriminations below are what make the finding usable.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.abap_sast import AbapSastAuditor, AbapSourceScanner   # noqa: E402
from modules.cds_authorization_index import (                      # noqa: E402
    CdsAuthorizationIndex, cross_artifact_findings)


def _tree(tmp_path, **files):
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    for name, body in files.items():
        (src / name).write_text(body, encoding="utf-8")
    return tmp_path


def _scan(tmp_path, **files):
    scanner = AbapSourceScanner(data_flow=True)
    raw = scanner.scan_tree(_tree(tmp_path, **files))
    return {f["rule_id"] for f in raw}, scanner


def _audit(tmp_path, **files):
    findings = AbapSastAuditor(
        {"abap_source_dir": str(_tree(tmp_path, **files))}, {}).run_all_checks()
    return {f["check_id"]: f for f in findings}


EXPOSED_NO_ROLE = "@OData.publish: true\ndefine view entity Z_Salary as select from pa0008 { key pernr }\n"
ROLE_FOR_ORDERS = "define role Z_R { grant select on Z_Orders where ( bukrs ) = aspect pfcg_auth ( F_BKPF_BUK, BUKRS ); }\n"


# ═════════════════════════════════════════════════════════════════════════════
#  The defect
# ═════════════════════════════════════════════════════════════════════════════

def test_the_defect_this_file_exists_for(tmp_path):
    """An exposed view with no annotation and no DCL role produced NOTHING —
    verified by running the scanner over exactly that pair before this was
    written. The rule that claimed to cover it matches an explicit disable."""
    fired, _ = _scan(tmp_path,
                     **{"z_salary.asddls": EXPOSED_NO_ROLE,
                        "z_other.asdcls": ROLE_FOR_ORDERS})
    assert "ABAP-CDS-003" in fired


def test_a_behaviour_that_declares_no_authorization_at_all_is_reported(tmp_path):
    """Distinct from ABAP-RAP-001/002, which report a behaviour that declares
    authorization and disables it. That was a decision; this is one nobody
    made."""
    fired, _ = _scan(tmp_path, **{
        "z.asbdef": "define behavior for Z_Salary alias S\npersistent table pa0008\n{ create; update; }\n",
        "z.asdcls": ROLE_FOR_ORDERS})
    assert "ABAP-RAP-005" in fired


# ═════════════════════════════════════════════════════════════════════════════
#  What must NOT be reported — the half that makes it usable
# ═════════════════════════════════════════════════════════════════════════════

def test_a_view_a_role_grants_on_is_not_reported(tmp_path):
    fired, _ = _scan(tmp_path, **{
        "z_orders.asddls": "@OData.publish: true\ndefine view entity Z_Orders as select from vbak { key vbeln }\n",
        "z_orders.asdcls": ROLE_FOR_ORDERS})
    assert "ABAP-CDS-003" not in fired


def test_a_basic_view_with_no_exposure_evidence_is_not_reported(tmp_path):
    """SAP: "accesses made on CDS entities without associated CDS role can be
    wrapped in CDS views with associated roles". A view consumed only through
    another view is SUPPOSED to have no role, and flagging every one would bury
    the report."""
    fired, scanner = _scan(tmp_path, **{
        "z_basic.asddls": "define view entity Z_Basic as select from t001 { key bukrs }\n",
        "z_o.asdcls": ROLE_FOR_ORDERS})
    assert "ABAP-CDS-003" not in fired
    assert scanner.cds_index.unexposed_roleless_views() == 1


@pytest.mark.parametrize("annotation", ["#NOT_ALLOWED", "#NOT_REQUIRED",
                                        "#MANDATORY", "#PRIVILEGED_ONLY"])
def test_an_annotation_that_settles_the_question_is_not_double_reported(
        tmp_path, annotation):
    """`#NOT_ALLOWED` and `#NOT_REQUIRED` are ABAP-CDS-001's subject and must not
    appear twice under a second id. `#MANDATORY` cannot activate without a role,
    so seeing one means the export is partial, not that the view is open."""
    fired, _ = _scan(tmp_path, **{
        "z.asddls": "@OData.publish: true\n@AccessControl.authorizationCheck: %s\n"
                    "define view entity Z_V as select from t { key a }\n" % annotation,
        "z.asdcls": ROLE_FOR_ORDERS})
    assert "ABAP-CDS-003" not in fired


def test_a_behaviour_that_declares_authorization_is_not_reported(tmp_path):
    fired, _ = _scan(tmp_path, **{
        "z.asbdef": "define behavior for Z_S alias S\nauthorization master ( global )\n{ create; }\n",
        "z.asdcls": ROLE_FOR_ORDERS})
    assert "ABAP-RAP-005" not in fired


def test_a_second_behaviour_does_not_inherit_the_first_ones_clause(tmp_path):
    """The same statement-boundary trap `cap_xsuaa` hit: an authorization clause
    belongs to the behaviour block it sits in, and crediting it to the next one
    would hide an unprotected behaviour."""
    index = CdsAuthorizationIndex()
    index.add_file(
        "define behavior for Z_A alias A\nauthorization master ( global )\n{ create; }\n"
        "define behavior for Z_B alias B\n{ create; update; }\n", "x.asbdef", "x.asbdef")
    missing = {b["entity"] for b in index.behaviors_without_authorization()}
    assert missing == {"Z_B"}


# ═════════════════════════════════════════════════════════════════════════════
#  The false positive that would have discredited the check
# ═════════════════════════════════════════════════════════════════════════════

def test_an_export_with_no_dcl_at_all_reports_coverage_not_every_view(tmp_path):
    """THE ONE THAT MATTERS MOST.

    An abapGit checkout of a single package, or an interrupted pull, contains no
    .asdcls at all — and then every view in it looks roleless. Reporting the whole
    tree at HIGH would be derived correctly from evidence the scan does not have,
    and a reviewer who checked two of them would stop trusting the report.
    """
    fired = _audit(tmp_path, **{
        "a.asddls": EXPOSED_NO_ROLE,
        "b.asddls": "@OData.publish: true\ndefine view entity Z_Two as select from t { key a }\n"})
    assert "ABAP-CDS-003" not in fired
    assert "ABAP-COV-005" in fired
    assert fired["ABAP-COV-005"]["details"]["degrades_coverage"] is True
    assert fired["ABAP-COV-005"]["details"]["dcl_files"] == 0


def test_the_views_set_aside_as_unexposed_are_counted_in_the_report(tmp_path):
    """Not a defect and not silence. A reader needs to know how many views were
    set aside on the wrapped-view reasoning rather than examined."""
    fired = _audit(tmp_path, **{
        "z_basic.asddls": "define view entity Z_Basic as select from t001 { key bukrs }\n",
        "z_o.asdcls": ROLE_FOR_ORDERS})
    assert "ABAP-COV-006" in fired
    assert fired["ABAP-COV-006"]["details"]["roleless_unexposed_views"] == 1


# ═════════════════════════════════════════════════════════════════════════════
#  Exposure evidence and finding shape
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("extra,body", [
    ("odata", "@OData.publish: true\ndefine view entity Z_Salary as select from t { key a }\n"),
    ("service", "define service Z_SRV { expose Z_Salary; }\n"
                "define view entity Z_Salary as select from t { key a }\n"),
])
def test_each_kind_of_exposure_evidence_is_recognised(tmp_path, extra, body):
    fired, _ = _scan(tmp_path, **{"z.asddls": body, "z.asdcls": ROLE_FOR_ORDERS})
    assert "ABAP-CDS-003" in fired, extra


def test_a_rap_behaviour_exposes_the_view_it_is_defined_for(tmp_path):
    """A behaviour reaches the entity over OData, which is the strongest exposure
    evidence a source tree carries — stronger than an annotation, because it is
    a whole artefact whose purpose is exposure."""
    fired, _ = _scan(tmp_path, **{
        "z.asddls": "define view entity Z_Salary as select from t { key a }\n",
        "z.asbdef": "define behavior for Z_Salary alias S\nauthorization master ( global )\n{ create; }\n",
        "z.asdcls": ROLE_FOR_ORDERS})
    assert "ABAP-CDS-003" in fired


def test_these_findings_are_confirmed_not_pattern_only(tmp_path):
    """`pattern-only` is the evidence class for a regex that may be describing
    correct code, and --gate lets it through. This is the absence of an artefact
    established by reading every file in the tree; grading it pattern-only would
    let the gate ignore it."""
    scanner = AbapSourceScanner(data_flow=True)
    raw = scanner.scan_tree(_tree(tmp_path, **{"z.asddls": EXPOSED_NO_ROLE,
                                               "z.asdcls": ROLE_FOR_ORDERS}))
    hit = [f for f in raw if f["rule_id"] == "ABAP-CDS-003"][0]
    assert hit["confidence"] == "confirmed"
    assert hit["cwe"] == "CWE-862"
    assert hit["severity"] == "HIGH"


def test_no_project_no_findings():
    """An index built from nothing asserts nothing."""
    assert cross_artifact_findings(CdsAuthorizationIndex()) == []


# ═════════════════════════════════════════════════════════════════════════════
#  Global vs instance authorization (FR-05: "RAP global/instance authorization")
# ═════════════════════════════════════════════════════════════════════════════

GLOBAL_ONLY = ("define behavior for Z_Order alias O\n"
               "authorization master ( global )\n{ create; update; delete; }\n")
BOTH = ("define behavior for Z_Item alias I\n"
        "authorization master ( global, instance )\n{ update; }\n")


def test_a_behaviour_authorised_only_globally_is_reported(tmp_path):
    """SAP: global authorization restricts operations for an entire RAP BO
    "regardless of individual instances", while instance authorization "applies
    checks based on the state of an entity instance". Global-only means a user
    cleared to update any instance is cleared to update every instance."""
    fired, _ = _scan(tmp_path, **{"b.asbdef": GLOBAL_ONLY,
                                  "r.asdcls": ROLE_FOR_ORDERS})
    assert "ABAP-RAP-006" in fired


def test_a_behaviour_declaring_both_kinds_is_not_reported(tmp_path):
    """`( global, instance )` is the complete form and must be silent, or the
    check punishes the correct answer."""
    fired, _ = _scan(tmp_path, **{"b.asbdef": BOTH, "r.asdcls": ROLE_FOR_ORDERS})
    assert "ABAP-RAP-006" not in fired


def test_instance_only_is_not_reported_as_global_only(tmp_path):
    fired, _ = _scan(tmp_path, **{
        "b.asbdef": "define behavior for Z_A alias A\nauthorization master ( instance )\n{ update; }\n",
        "r.asdcls": ROLE_FOR_ORDERS})
    assert "ABAP-RAP-006" not in fired


def test_no_authorization_clause_is_rap_005_not_rap_006(tmp_path):
    """The two findings must partition: an absent clause is a decision nobody
    made, a global-only clause is a decision that may be the wrong one."""
    fired, _ = _scan(tmp_path, **{
        "b.asbdef": "define behavior for Z_L alias L\n{ create; }\n",
        "r.asdcls": ROLE_FOR_ORDERS})
    assert "ABAP-RAP-005" in fired and "ABAP-RAP-006" not in fired


def test_three_behaviours_in_one_file_are_judged_separately(tmp_path):
    fired, scanner = _scan(tmp_path, **{
        "b.asbdef": GLOBAL_ONLY + "\n" + BOTH +
                    "\ndefine behavior for Z_Loose alias L\n{ create; }\n",
        "r.asdcls": ROLE_FOR_ORDERS})
    assert {"ABAP-RAP-005", "ABAP-RAP-006"} <= fired
    kinds = {e: i.get("auth_master") for e, i in scanner.cds_index.behaviors.items()}
    assert kinds["Z_ORDER"] == {"global"}
    assert kinds["Z_ITEM"] == {"global", "instance"}
    assert kinds["Z_LOOSE"] is None
