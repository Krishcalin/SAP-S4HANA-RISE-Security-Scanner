"""
Tier 2: the rules that fired on correct code.

EVERY TEST HERE IS A PAIR
A narrowing is only worth shipping if the true positive survives it, so each
false-positive case is followed by the control that must still fire. A rule that
stops detecting the real thing is not an improvement over one that over-reports —
it is the same failure wearing a quieter coat.

The measurement that motivated the tier: 24 lines of correct, idiomatic ABAP
produced three findings, two of them CRITICAL, with no dynamic SQL anywhere in it.

Every fix is a side-table entry — `PATTERN_FIXES`, `DESCRIPTION_FIXES`,
`SEVERITY_FIXES`, `RETIRED_RULES` — because `tools/build_abap_rules.py` regenerates
`modules/abap_sast_rules.py` verbatim and a fix made there dies on the next refresh
with no test failing.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.abap_sast import AbapSourceScanner, split_cds_statements   # noqa: E402

SRC = Path("z_tier2.prog.abap")


def scan(text):
    return AbapSourceScanner(data_flow=False).scan_text(text, SRC)


def rule_ids(text):
    return sorted({f["rule_id"] for f in scan(text)})


def severity_of(text, rule):
    return next(f["severity"] for f in scan(text) if f["rule_id"] == rule)


# --------------------------------------------------------------------------- #
#  F1 — every CONCATENATE in the estate                                       #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("statement", [
    "CONCATENATE s4 s5 INTO s3.",
    "CONCATENATE lv_first lv_last INTO lv_full SEPARATED BY space.",
])
def test_a_plain_concatenate_is_not_sql_injection(statement):
    """`INTO` is MANDATORY syntax for CONCATENATE, so `(?:CONCATENATE|&&).*INTO\\b`
    matched 100% of them — at CRITICAL, CWE-89, with no taint sink and therefore no
    way to ever be downgraded."""
    assert "ABAP-SQLI-002" not in rule_ids(statement)


def test_the_english_word_from_is_not_an_sql_clause():
    """The `&&` arm matched prose."""
    assert "ABAP-SQLI-002" not in rule_ids(
        "DATA(m) = `Deleted ` && lv_n && ` rows from the staging buffer`.")


def test_an_sql_keyword_inside_a_concatenated_literal_still_fires():
    """The control, and the actual danger the rule is named for."""
    assert "ABAP-SQLI-002" in rule_ids("CONCATENATE 'WHERE matnr = ' lv_x INTO lv_w.")


# --------------------------------------------------------------------------- #
#  F2 — parenthesised grouping is not a dynamic clause                        #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("statement", [
    "SELECT * FROM dbtab WHERE ( comp1 = 'X' AND comp2 > 100 ) INTO TABLE @DATA(it).",
    "UPDATE zt SET f = 'Y' WHERE ( k = @lv_a AND f = @lv_b ).",
    "DELETE FROM zt WHERE ( kunnr = @lv_k OR lifnr = @lv_l ).",
])
def test_logical_grouping_in_a_where_clause_is_not_dynamic_sql(statement):
    """`\\bWHERE\\s*\\(` cannot tell a dynamic clause from a parenthesised logical
    expression, and the second is pervasive in correct ABAP. `_sink_argument` found
    no bare `( name )` either, so the finding could not even be downgraded — it was
    emitted CRITICAL, pattern-only."""
    assert "ABAP-SQLI-001" not in rule_ids(statement)


def test_a_genuinely_dynamic_where_clause_still_fires():
    assert "ABAP-SQLI-001" in rule_ids(
        "SELECT * FROM mara WHERE (lv_where) INTO TABLE @DATA(lt).")


# --------------------------------------------------------------------------- #
#  F3 — the inverted rule                                                     #
# --------------------------------------------------------------------------- #

def test_a_static_transformation_name_is_not_code_injection():
    """EXACTLY INVERTED. The rule assumed "static means quoted", which holds for
    CALL FUNCTION and CALL TRANSACTION and is backwards for CALL TRANSFORMATION: a
    static name is bare, a dynamic one is parenthesised. Every object doing XML or
    serialisation lit up CRITICAL, and the real dynamic form was silent."""
    assert "ABAP-CINJ-007" not in rule_ids(
        "CALL TRANSFORMATION id SOURCE root = ls_data RESULT XML lv_xml.")


def test_a_dynamic_transformation_name_now_fires():
    """The half that was silent, which is the half that matters."""
    assert "ABAP-CINJ-007" in rule_ids(
        "CALL TRANSFORMATION (lv_dyn) SOURCE root = ls_data RESULT XML lv_xml.")


# --------------------------------------------------------------------------- #
#  F4 — a literal operand is inventory, not an injection                      #
# --------------------------------------------------------------------------- #

def test_a_compile_time_literal_operand_is_demoted_but_kept():
    """SAP writes a literal operand as the NORMAL safe form: measured over ~525 KB
    of SAP-authored ABAP, the ASSIGN rule fired 11 times and 10 were hard-coded
    literals. The finding is kept, because a literal class or report name is a real
    inventory entry — it is just not a HIGH one."""
    assert severity_of("ASSIGN ('LV_X') TO <fs>.", "ABAP-CINJ-009") == "LOW"


def test_a_variable_operand_keeps_its_severity():
    assert severity_of("ASSIGN (lv_name) TO <fs>.", "ABAP-CINJ-009") == "MEDIUM"


def test_the_demotion_says_why_in_the_evidence_not_in_a_new_confidence_class(tmp_path):
    """`finding.taint_confidence` is CHECK-constrained to confirmed / tentative /
    pattern-only in `server/schema.sql`, and those classes are what
    `modules/fair_adapter.py` prices. So this is reported as evidence text, and the
    confidence field keeps meaning what the database says it means."""
    from modules.abap_sast import AbapSastAuditor
    (tmp_path / "z_lit.prog.abap").write_text("ASSIGN ('LV_X') TO <fs>.\n",
                                              encoding="utf-8")
    findings = AbapSastAuditor({"abap_source_dir": str(tmp_path)}, {}).run_all_checks()
    hit = next(f for f in findings if f["check_id"] == "ABAP-CINJ-009")
    assert hit["details"]["confidence"] in ("confirmed", "tentative", "pattern-only")
    assert hit["details"]["literal_operand"] is True
    assert "compile-time literal" in hit["description"]


# --------------------------------------------------------------------------- #
#  F5 — a namespace URI is an identifier, not an endpoint                     #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("uri", [
    "http://www.w3.org/2001/XMLSchema",
    "http://www.sap.com/abapxml",
    "http://schemas.xmlsoap.org/soap/envelope/",
])
def test_an_xml_namespace_is_not_an_insecure_endpoint(uri):
    """Every object that serialises XML or SOAP carries several of these. We were
    reporting SAP's own asXML namespace as insecure transport."""
    assert "ABAP-CONF-002" not in rule_ids(f"lv_ns = '{uri}'.")


def test_a_real_cleartext_endpoint_still_fires():
    assert "ABAP-CONF-002" in rule_ids("lv_url = 'http://internal.corp.example/api'.")


# --------------------------------------------------------------------------- #
#  F6 — SUBMIT                                                                #
# --------------------------------------------------------------------------- #

def test_a_static_submit_with_an_addition_is_not_dynamic():
    """`SUBMIT zdemo_report AND RETURN.` was clean but adding `LINE-SIZE 132` made
    it fire, because the addition-exclusion list was incomplete. A variable program
    name REQUIRES the parentheses, so a bare name after SUBMIT is always a literal
    report name and the bare-identifier arm never detected anything real."""
    assert "ABAP-CINJ-005" not in rule_ids("SUBMIT zdemo_report LINE-SIZE 132 AND RETURN.")


def test_a_report_name_ending_in_submit_does_not_match_itself():
    """The rule was unanchored, so the statement matched on its own identifier."""
    assert "ABAP-CINJ-005" not in rule_ids("SUBMIT z_batch_submit AND RETURN.")


def test_a_dynamic_submit_still_fires():
    assert "ABAP-CINJ-005" in rule_ids("SUBMIT (lv_prog) AND RETURN.")


# --------------------------------------------------------------------------- #
#  F7 — DUMMY                                                                 #
# --------------------------------------------------------------------------- #

def test_a_partial_dummy_is_not_a_disabled_check():
    """DUMMY exempts ONE field; the remaining ID/FIELD pairs are still enforced and
    the check can still fail. The rule fired on correct RAP authorization code and
    told the reviewer a three-field check was disabled when two were enforced."""
    assert "ABAP-AUTH-002" not in rule_ids(
        "AUTHORITY-CHECK OBJECT 'X' ID 'ACTVT' FIELD '02' ID 'BUKRS' DUMMY.")


def test_an_all_dummy_check_still_fires_at_a_truthful_severity():
    text = "AUTHORITY-CHECK OBJECT 'X' ID 'ACTVT' DUMMY ID 'BUKRS' DUMMY."
    assert "ABAP-AUTH-002" in rule_ids(text)
    assert severity_of(text, "ABAP-AUTH-002") == "MEDIUM"


def test_the_description_no_longer_asserts_what_the_source_contradicts():
    """It said DUMMY "always passes ... effectively disables the authorization
    check". SAP's own worked examples show a partial DUMMY still yielding a
    non-zero sy-subrc."""
    hit = next(f for f in scan(
        "AUTHORITY-CHECK OBJECT 'X' ID 'ACTVT' DUMMY ID 'BUKRS' DUMMY.")
        if f["rule_id"] == "ABAP-AUTH-002")
    assert "always passes" not in hit["description"]
    assert "no field value" in hit["description"]


# --------------------------------------------------------------------------- #
#  F9 — retired rather than narrowed                                          #
# --------------------------------------------------------------------------- #

def test_the_http_utility_rule_is_retired_not_guessed_at():
    """Its lookahead excluded exactly ONE method name, so every other use of a
    general HTTP utility class was reported as missing HTML escaping. Narrowing it
    means naming the methods that class exposes, and nobody has read that listing —
    inventing them is how fabricated identifiers enter this repository."""
    assert "ABAP-XSS-006" not in rule_ids("lv_x = cl_http_utility=>escape_url( lv_y ).")


def test_the_output_sinks_it_covered_are_still_covered_by_other_rules():
    """Retiring a rule is only safe if something else holds the ground."""
    from modules.abap_sast import ALL_ABAP_SAST_RULES, RETIRED_RULES
    live = {r["id"] for r in ALL_ABAP_SAST_RULES
            if r["id"].startswith("ABAP-XSS-") and r["id"] not in RETIRED_RULES}
    assert len(live) >= 4, f"XSS coverage collapsed to {sorted(live)}"


# --------------------------------------------------------------------------- #
#  F10 — the same regex shape, losing a finding instead of inventing one      #
# --------------------------------------------------------------------------- #

def test_a_wildcard_activity_check_is_detected_in_the_form_real_code_uses():
    """The pattern required whitespace straight after `ACTVT`, but the quoted form
    has a closing apostrophe there. It was silent on every real occurrence and
    matched only a spelling nobody writes."""
    assert "ABAP-CONF-005" in rule_ids(
        "AUTHORITY-CHECK OBJECT 'ZO' ID 'ACTVT' FIELD '*'.")


def test_a_specific_activity_is_not_reported_as_a_wildcard():
    assert "ABAP-CONF-005" not in rule_ids(
        "AUTHORITY-CHECK OBJECT 'ZO' ID 'ACTVT' FIELD '02'.")


# --------------------------------------------------------------------------- #
#  F11 — CDS block comments                                                   #
# --------------------------------------------------------------------------- #

def test_a_cds_block_comment_is_not_code():
    """`split_cds_statements` stripped only `//`, so a commented-out annotation
    inside `/* */` was emitted as a statement and raised a HIGH finding — and the
    stray `*/` leaked into the next statement's text."""
    stmts = split_cds_statements(
        "/* @AccessControl.authorizationCheck: #NOT_REQUIRED */\n"
        "define view entity ZI_X as select from lfa1 { key lifnr }\n")
    assert not [s for s in stmts if "NOT_REQUIRED" in s.text], \
        [s.text for s in stmts]
    assert not [s for s in stmts if "*/" in s.text], "the terminator leaked"


def test_a_multi_line_cds_block_comment_does_not_shift_line_numbers():
    """Newlines are preserved when the comment is removed, so every reported line
    number still means what it meant."""
    stmts = split_cds_statements(
        "/* one\n   two\n   three */\n"
        "@AccessControl.authorizationCheck: #NOT_REQUIRED\n")
    assert stmts and stmts[0].line == 4, [(s.line, s.text) for s in stmts]


# --------------------------------------------------------------------------- #
#  F8 — say what is unverified rather than imply coverage                     #
# --------------------------------------------------------------------------- #

def test_the_unverified_dcl_grant_syntax_is_marked_as_such():
    """`GRANT SELECT ON x WHERE TRUE` was not found in any fetched SAP-authored
    material. The rule is kept — if the syntax does not exist it simply never fires,
    which costs nothing — but it must not be presented as coverage. This test exists
    so a future reader finds the caveat instead of trusting the rule."""
    src = (ROOT / "modules" / "abap_sast_extra.py").read_text(encoding="utf-8")
    marker = src.index("ABAP-CDS-002")
    window = src[marker:marker + 1400]
    assert "UNVERIFIED SYNTAX" in window, \
        "the unverified DCL grant syntax is being presented as coverage"


# --------------------------------------------------------------------------- #
#  The tier's own exit criterion                                              #
# --------------------------------------------------------------------------- #

CORRECT_ABAP = """CLASS zcl_vendor_report IMPLEMENTATION.
  METHOD build.
    DATA: lv_full TYPE string,
          lt_rows TYPE TABLE OF lfa1.

    CONCATENATE lv_first lv_last INTO lv_full SEPARATED BY space.

    AUTHORITY-CHECK OBJECT 'F_LFA1_BUK'
      ID 'ACTVT' FIELD '03'
      ID 'BUKRS' DUMMY.
    IF sy-subrc <> 0.
      MESSAGE 'Not authorised' TYPE 'E'.
    ENDIF.

    SELECT * FROM lfa1
      WHERE ( land1 = 'DE' AND ktokk = 'KRED' )
      INTO TABLE @lt_rows.

    CALL TRANSFORMATION id
      SOURCE vendors = lt_rows
      RESULT XML lv_xml.

    SUBMIT z_vendor_print LINE-SIZE 132 AND RETURN.
  ENDMETHOD.
ENDCLASS.
"""


def test_a_correct_method_produces_nothing():
    """THE EXIT CRITERION FOR THIS TIER.

    Every statement here is correct, idiomatic and correctly authorised. Before the
    narrowings this shape produced findings — several CRITICAL — with no dynamic
    SQL in it anywhere. A tool that reports CRITICALs on clean code does not get a
    second look from the person evaluating it.
    """
    found = scan(CORRECT_ABAP)
    assert not found, \
        f"correct code produced {[(f['rule_id'], f['severity']) for f in found]}"
