# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
Tier 3: the coverage gap, and the sources that made every finding tentative.

THE MEASUREMENT
40 of 49 dynamic statements taken verbatim from SAP-authored material matched no
rule in the whole 99-rule corpus. The gap is not tuning: the existing rules anchor
on "keyword immediately followed by (", and ABAP's dominant dynamic forms put the
parenthesis after a selector, after an addition, or in a clause no rule covers.

WHY EVERY NEW RULE HERE HAS A NEGATIVE CONTROL
Adding coverage is the easiest way to undo Tier 2. Every pattern in Group A was
measured against the safe form of the same construct before it shipped, and the
control is in this file next to the positive case. Two of the originally proposed
patterns were changed as a result and one was dropped outright — see the bottom
section.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.abap_sast import (                                    # noqa: E402
    ALL_ABAP_SAST_RULES, AbapSourceScanner, RiseTaintAnalyzer,
)

SRC = Path("z_tier3.prog.abap")


def rule_ids(text, path=SRC):
    return sorted({f["rule_id"] for f in
                   AbapSourceScanner(data_flow=False).scan_text(text, Path(path))})


def state(src, var, line):
    return RiseTaintAnalyzer(src).state_of(var, line)


# --------------------------------------------------------------------------- #
#  Group A — the dynamic-token inventory                                      #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("rule,vulnerable,safe", [
    # A1 — the construct SAP's own security example uses to motivate an allowlist
    ("ABAP-SQLI-013",
     "SELECT (select_list) FROM zt INTO TABLE @DATA(it).",
     "SELECT ( a + b ) AS tot FROM zt INTO TABLE @DATA(it)."),
    # A2 — the write side. Both SQLI-010 and -011 require a literal FROM.
    ("ABAP-SQLI-014",
     "UPDATE (table) FROM @dref->*.",
     "UPDATE zt FROM @ls_row."),
    ("ABAP-SQLI-015",
     "UPDATE zt SET (lv_set) WHERE k = @lv_k.",
     "UPDATE zt SET f = 'Y' WHERE k = @lv_k."),
    # A3 — we flagged the spelling SAP calls obsolete and missed all three live ones
    ("ABAP-AUTH-010",
     "SELECT * FROM zt USING ALL CLIENTS INTO TABLE @DATA(it).",
     "SELECT * FROM zt INTO TABLE @DATA(it)."),
    ("ABAP-AUTH-011",
     "SELECT * FROM zt USING CLIENT @cl INTO TABLE @DATA(it).",
     "SELECT * FROM zt USING client_dependent_view INTO TABLE @DATA(it)."),
    # A8 — the qualified forms, which are the majority of real calls
    ("ABAP-CINJ-013",
     "CALL METHOD lo_ref->(lv_meth).",
     "CALL METHOD lo_ref->run( )."),
    # A9 — the compound type forms
    ("ABAP-CINJ-014",
     "CREATE DATA dref TYPE TABLE OF (lv_type).",
     "CREATE DATA dref TYPE TABLE OF mara."),
    # A11
    ("ABAP-CINJ-015",
     "EXPORT (lv_params) TO MEMORY ID 'K'.",
     "EXPORT tab = lt_x TO MEMORY ID 'K'."),
    # A15 — the selector form
    ("ABAP-CINJ-016",
     "ASSIGN lo_ref->(lv_attr) TO <fs>.",
     "ASSIGN lo_ref->mandt TO <fs>."),
    ("ABAP-CINJ-017",
     "ASSIGN lv_x TO <fs> CASTING TYPE (lv_type).",
     "ASSIGN lv_x TO <fs> CASTING TYPE mara."),
    # A10 — internal tables, which are not SQL
    ("ABAP-DYNT-001",
     "DELETE lt_rows WHERE (lv_cond).",
     "LOOP AT lt_rows INTO ls WHERE ( a = 'X' AND b > 1 )."),
    ("ABAP-DYNT-002",
     "SORT lt_rows BY (lv_field).",
     "SORT lt_rows BY matnr."),
])
def test_a_dynamic_form_is_detected_and_its_safe_twin_is_not(rule, vulnerable, safe):
    assert rule in rule_ids(vulnerable), f"{rule} missed the dynamic form"
    assert rule not in rule_ids(safe), \
        f"{rule} also fires on the safe form, which is how Tier 2 gets undone"


def test_a_literal_operand_does_not_light_up_the_assign_family():
    """Measured over ~525 KB of SAP-authored ABAP the widened ASSIGN pattern fired
    11 distinct times and 10 were hard-coded literals or integers. The
    literal/integer exclusion is not optional."""
    assert "ABAP-CINJ-016" not in rule_ids("ASSIGN lo_ref->('MANDT') TO <fs>.")


def test_an_internal_table_delete_is_not_reported_as_sql_injection():
    """The one internal-table dynamic form that DID match a rule was reported
    CRITICAL, CWE-89, "Dynamic WHERE clause", with a host-variable recommendation —
    on a statement that never touches the database and has no statement to bind
    against."""
    found = rule_ids("DELETE lt_rows WHERE (lv_cond).")
    assert "ABAP-SQLI-001" not in found
    assert "ABAP-DYNT-001" in found


def test_a_database_delete_is_still_sql():
    """The control for that guard: `DELETE FROM` must keep its SQL rule."""
    assert "ABAP-SQLI-001" in rule_ids("DELETE FROM mara WHERE (lv_cond).")


# --------------------------------------------------------------------------- #
#  A4 / A5 / A12 / A13 — AMDP                                                 #
# --------------------------------------------------------------------------- #

def test_an_amdp_function_is_covered_not_just_a_procedure():
    """A5. A table function is consumable by any ABAP SQL SELECT, not only by a
    deliberate method call, which makes it the wider exposure of the two — and it
    matched nothing."""
    assert "ABAP-AMDP-003" in rule_ids(
        "METHOD get BY DATABASE FUNCTION FOR HDB LANGUAGE SQLSCRIPT.")


def test_an_amdp_method_that_may_write_is_distinguishable_from_one_that_reads():
    """A4. Both produced the same single MEDIUM, so a procedure that MODIFIES
    business data outside every ABAP authorization mechanism looked like one that
    reports on it."""
    writes = "METHOD upd BY DATABASE PROCEDURE FOR HDB LANGUAGE SQLSCRIPT."
    reads = ("METHOD get BY DATABASE PROCEDURE FOR HDB LANGUAGE SQLSCRIPT "
             "OPTIONS READ-ONLY.")
    assert "ABAP-AMDP-004" in rule_ids(writes)
    assert "ABAP-AMDP-004" not in rule_ids(reads)


def test_the_bare_exec_call_form_is_covered():
    """A12. Restricted to the call shape so it cannot collide with EXEC SQL and
    double-report the same statement as ABAP-NSQL-001."""
    found = rule_ids("lt = EXEC('SELECT * FROM t');")
    assert "ABAP-AMDP-001" in found
    assert "ABAP-NSQL-001" not in found, "EXEC SQL and EXEC( ) are double-reporting"


def test_an_amdp_declaration_without_client_handling_is_reported():
    """A13. AMDP has no implicit client handling — unlike Open SQL, nothing adds a
    client column to the procedure's own statements."""
    assert "ABAP-AMDP-005" in rule_ids("CLASS-METHODS get AMDP OPTIONS SUPPRESS.")
    assert "ABAP-AMDP-005" not in rule_ids(
        "CLASS-METHODS get AMDP OPTIONS CDS SESSION CLIENT DEPENDENT.")


# --------------------------------------------------------------------------- #
#  A6 / A14 — RAP                                                             #
# --------------------------------------------------------------------------- #

def test_a_behaviour_definition_that_disables_authorization_is_no_longer_silent():
    """`.asbdef` routed to a rule set holding only two DDL/DCL shapes that cannot
    occur in a behaviour definition, so a BDEF disabling authorization produced
    ZERO findings — the same silent-zero-coverage failure this module's docstring
    records as fixed for CDS."""
    assert "ABAP-RAP-001" in rule_ids(
        "define behavior for ZI_X authorization master ( none );", "zb.asbdef")
    assert "ABAP-RAP-002" in rule_ids(
        "define behavior for ZI_X { update; authorization : none };", "zb.asbdef")


def test_a_behaviour_definition_with_authorization_is_silent():
    assert not rule_ids(
        "define behavior for ZI_X authorization master ( instance ) { update; };",
        "zb.asbdef")


@pytest.mark.parametrize("rule,statement", [
    ("ABAP-RAP-003", "READ ENTITIES OF zi_x IN LOCAL MODE ENTITY x ALL FIELDS."),
    ("ABAP-RAP-004", "SELECT * FROM zi_x WITH PRIVILEGED ACCESS INTO TABLE @lt."),
])
def test_an_authorization_bypass_in_a_behaviour_pool_is_reported(rule, statement):
    """A14. We reported the SAFE construct two lines away and said nothing about
    the one that bypasses the check."""
    assert rule in rule_ids(statement)


def test_the_behaviour_pool_findings_say_they_are_a_question_not_a_defect():
    """Both are LEGITIMATE inside a behaviour pool, so a finding that reads as a
    defect to schedule would be a false positive dressed as a MEDIUM."""
    by_id = {r["id"]: r for r in ALL_ABAP_SAST_RULES}
    for rid in ("ABAP-RAP-003", "ABAP-RAP-004"):
        assert by_id[rid]["severity"] == "MEDIUM"
        assert "confirm" in by_id[rid]["recommendation"].lower()


# --------------------------------------------------------------------------- #
#  A7 — the CDS annotation                                                    #
# --------------------------------------------------------------------------- #

def test_the_second_full_exposure_annotation_value_is_covered():
    """A7. #NOT_ALLOWED was missed entirely, and it is the worse of the two: it
    does not merely skip the check, it causes a DCL role that DOES exist for the
    view to be disregarded — so a reviewer who finds the role has no reason to
    suspect it is inert."""
    assert "ABAP-CDS-001" in rule_ids(
        "@AccessControl.authorizationCheck: #NOT_ALLOWED", "zi_x.asddls")


def test_the_recommendation_names_the_value_that_forces_a_role_to_exist():
    """It named the value whose missing role is only a WARNING, so following our
    advice could leave a view unprotected and looking remediated."""
    rec = next(r for r in ALL_ABAP_SAST_RULES
               if r["id"] == "ABAP-CDS-001")["recommendation"]
    assert "#MANDATORY" in rec
    assert "only warns" in rec


# --------------------------------------------------------------------------- #
#  Group B — the taint sources                                                #
# --------------------------------------------------------------------------- #

B_CASES = [
    ("B2 FORM parameter",
     "REPORT z.\nFORM do_it USING p_tab TYPE tabname.\n"
     "  SELECT * FROM (p_tab) INTO TABLE @DATA(l).\nENDFORM.\n", "p_tab", 3),
    ("B2/B4 METHOD parameter",
     "CLASS c DEFINITION.\n  METHODS run IMPORTING iv_tab TYPE tabname.\nENDCLASS.\n"
     "CLASS c IMPLEMENTATION.\n  METHOD run.\n"
     "    SELECT * FROM (iv_tab) INTO TABLE @DATA(l).\n  ENDMETHOD.\nENDCLASS.\n",
     "iv_tab", 6),
    ("B3 output binding",
     "REPORT z.\nPARAMETERS: p_f TYPE string.\nSTART-OF-SELECTION.\n"
     "  cl_gui_frontend_services=>gui_upload( EXPORTING filename = p_f "
     "CHANGING data_tab = lt_d ).\n  WRITE lt_d.\n", "lt_d", 5),
    ("B5 parsed XML result",
     "REPORT z.\nSTART-OF-SELECTION.\n"
     "  CALL TRANSFORMATION id SOURCE XML lv_xml RESULT root = lt_data.\n"
     "  WRITE lt_data.\n", "lt_data", 4),
    ("B6 data cluster",
     "REPORT z.\nSTART-OF-SELECTION.\n"
     "  IMPORT tab = lt_c FROM MEMORY ID lc_key.\n  WRITE lt_c.\n", "lt_c", 4),
    ("B7 classic list read",
     "REPORT z.\nSTART-OF-SELECTION.\n  READ LINE 3 INTO lv_sel.\n"
     "  WRITE lv_sel.\n", "lv_sel", 4),
    ("B8 selection-screen command",
     "REPORT z.\nSTART-OF-SELECTION.\n  lv_cmd = sscrfields-ucomm.\n"
     "  WRITE lv_cmd.\n", "lv_cmd", 4),
]


@pytest.mark.parametrize("label,src,var,line", B_CASES,
                         ids=[c[0] for c in B_CASES])
def test_a_source_family_taints_what_it_writes_into(label, src, var, line):
    """Each of these classified UNKNOWN before, which since Phase 5 means the
    finding downstream never priced into FAIR at all — it was not merely
    under-graded, it was invisible to the money."""
    assert state(src, var, line) == RiseTaintAnalyzer.TAINTED


def test_gui_upload_can_finally_fire():
    """It has been in the vendored source list since day one and could never fire:
    the value arrives through CHANGING, so there was never an assignment for the
    analyzer to see — and the class-qualified call was itself misparsed as an
    assignment to the class name."""
    src = ("REPORT z.\nPARAMETERS: p_f TYPE string.\nSTART-OF-SELECTION.\n"
           "  cl_gui_frontend_services=>gui_upload( CHANGING data_tab = lv_w ).\n"
           "  SELECT * FROM mara WHERE (lv_w) INTO TABLE @DATA(lt).\n")
    hit = next(f for f in AbapSourceScanner(data_flow=True).scan_text(src, SRC)
               if f["rule_id"] == "ABAP-SQLI-001")
    assert hit["confidence"] == "confirmed"


def test_a_parameter_name_does_not_leak_between_sibling_procedures():
    """Inbound parameters are seeded PER SCOPE and never into `_globals`. A name
    shared by two procedures would otherwise carry taint from one into the other —
    which is a false positive that is very hard to argue with, because the name
    really is tainted somewhere."""
    src = ("REPORT z.\n"
           "FORM tainted USING p_v TYPE string.\n"
           "  WRITE p_v.\n"
           "ENDFORM.\n"
           "FORM clean.\n"
           "  SELECT * FROM mara WHERE (p_v) INTO TABLE @DATA(lt).\n"
           "ENDFORM.\n")
    assert state(src, "p_v", 6) != RiseTaintAnalyzer.TAINTED, \
        "taint leaked out of FORM tainted into FORM clean"


def test_an_outbound_transformation_is_not_a_source():
    """`SOURCE root = ...` serialises the program's OWN data outward. Only
    `SOURCE XML` is input, and treating both as sources would taint half the
    serialisation code in an estate."""
    src = ("REPORT z.\nSTART-OF-SELECTION.\n"
           "  CALL TRANSFORMATION id SOURCE root = lt_own RESULT XML lv_out.\n"
           "  WRITE lv_out.\n")
    assert state(src, "lv_out", 4) != RiseTaintAnalyzer.TAINTED


# --------------------------------------------------------------------------- #
#  House rules                                                                #
# --------------------------------------------------------------------------- #

def test_no_rule_id_is_used_twice():
    ids = [r["id"] for r in ALL_ABAP_SAST_RULES]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    assert not dupes, f"duplicate rule ids: {dupes}"


def test_b9_was_declined_rather_than_anchored_on_a_guessed_identifier():
    """HTTP response bodies need the released-classes listing to anchor on client
    identity. Anchoring on a bare accessor name instead would taint every CATCH
    block in the estate, because that accessor is overwhelmingly the exception
    message getter. U10 records that the identifiers originally proposed for
    `_SOURCE_RE` were never grep-confirmed in a fetched SAP file, and this repo has
    shipped fabricated identifiers before.
    """
    src = (ROOT / "modules" / "abap_sast.py").read_text(encoding="utf-8")
    assert "B9 (HTTP response bodies) is not here" in src, \
        "B9 was added or the decision not to add it stopped being recorded"


def test_the_new_source_families_are_abap_keywords_not_library_names():
    """The discipline that keeps this tier honest: a keyword or system field is a
    language construct anyone can verify. A class or method name is a claim about
    SAP's shipped code, and an unverified one is a fabricated identifier."""
    added = RiseTaintAnalyzer._SOURCE_RE.pattern.replace(
        __import__("modules.abap_sast_rules", fromlist=["TaintAnalyzer"])
        .TaintAnalyzer._SOURCE_RE.pattern, "")
    for token in ("sy-lisel", "sy-ucomm", "sscrfields"):
        assert token in added
    assert "=>" not in added, "a class-qualified identifier entered the source list"
