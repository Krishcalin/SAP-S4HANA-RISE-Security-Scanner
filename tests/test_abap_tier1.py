# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
Tier 1 of the CVA engine plan: the defects that made a verdict unsafe.

WHY THESE ARE ONE FILE
Every test here failed before the change and each one is a case where the scanner
was confidently wrong rather than merely incomplete — a clean report on a mis-lexed
file, a fabricated data-flow trace, a guard credited to a comment, an XSS escaper
clearing a SQL injection. A missing rule costs coverage; these cost trust.

The measurements behind them are in docs/CVA_ENGINE_IMPROVEMENT_PLAN.md.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.abap_sast import (                                    # noqa: E402
    AbapSourceScanner, RiseTaintAnalyzer, _sink_argument, split_statements,
)

SRC = Path("z_tier1.prog.abap")


def scan(text, **kw):
    return AbapSourceScanner(data_flow=kw.pop("data_flow", False)).scan_text(text, SRC)


def rule_ids(text, **kw):
    return sorted({f["rule_id"] for f in scan(text, **kw)})


# --------------------------------------------------------------------------- #
#  T1.1 — the mode stack                                                      #
# --------------------------------------------------------------------------- #

EMBEDDED_PIPE = (
    "METHOD m1.\n"
    "  DATA(msg) = |Result: { replace( val = txt pcre = `a|b` with = `#` ) }|.\n"
    "  SELECT * FROM (lv_tab) INTO TABLE @DATA(lt).\n"
    "ENDMETHOD.\n"
    "METHOD m2.\n"
    "  AUTHORITY-CHECK OBJECT 'S_X' ID 'ACTVT' FIELD '03'.\n"
    "  IF sy-subrc <> 0. RETURN. ENDIF.\n"
    "  DELETE FROM zcust WHERE kunnr = lv_k.\n"
    "ENDMETHOD.\n")


def test_a_literal_pipe_inside_an_embedded_expression_does_not_eat_the_file():
    """THE HEADLINE DEFECT.

    A string template embeds expressions in `{ }`, and an embedded expression
    carries its own literals — which routinely contain pipes (a regex alternation,
    a delimiter constant). Neither lexer had a `{ }` mode, so that pipe closed the
    template, the following backquote opened a literal that never closed, and
    EVERYTHING FROM THERE TO END-OF-FILE collapsed into one statement.

    Silently, and in the direction that looks clean: both ENDMETHODs were swallowed
    with it, so the block model collapsed too.
    """
    stmts = split_statements(EMBEDDED_PIPE)
    assert len(stmts) > 2, \
        f"the file collapsed into {len(stmts)} statement(s): {[s.text[:70] for s in stmts]}"
    heads = [s.text.split()[0].upper() for s in stmts if s.text]
    assert heads.count("ENDMETHOD") == 2, \
        f"method boundaries were lost: {heads}"


def test_the_collapse_did_not_silently_move_a_guard_between_methods():
    """The consequence that matters. With both ENDMETHODs swallowed, m2's
    AUTHORITY-CHECK landed in the same block as m1's dynamic SELECT and silenced
    findings in a method it has nothing to do with."""
    blocks = {s.text.split()[0].upper(): s.block for s in split_statements(EMBEDDED_PIPE)
              if s.text.upper().startswith(("SELECT", "AUTHORITY-CHECK"))}
    assert blocks["SELECT"] != blocks["AUTHORITY-CHECK"], \
        "a guard in m2 is being credited to a sink in m1"


@pytest.mark.parametrize("label,source,expected", [
    ("literal inside { }",     "x = |a { f( `p|q` ) } b|. WRITE x.\n", 2),
    ("period inside { }",      "x = |{ lines( t ) } rows.|. WRITE x.\n", 2),
    ("nested braces",          "x = |{ COND #( WHEN a = 1 THEN `y` ) }|. WRITE x.\n", 2),
    ("escaped brace",          "x = |a \\{ b|. WRITE x.\n", 2),
    ("quote in embedded expr", 'x = |{ f( `a"b` ) }|. WRITE x.\n', 2),
])
def test_embedded_expressions_lex_as_code_not_as_template_text(label, source, expected):
    assert len(split_statements(source)) == expected, \
        [s.text for s in split_statements(source)]


def test_a_column_one_star_inside_an_open_template_is_text_not_a_comment():
    """`*` comments a line only in column 1 of CODE. Inside a template left open at
    a line end it is content, and treating it as a comment dropped the line."""
    stmts = split_statements("x = |first\n* still template|. WRITE x.\n")
    assert len(stmts) == 2, [s.text for s in stmts]


# --------------------------------------------------------------------------- #
#  T1.2 — the runaway guard                                                   #
# --------------------------------------------------------------------------- #

def test_an_unterminated_literal_is_flushed_and_counted_not_reported_clean():
    """Defence rather than a bet. Two grammar questions about templates remain
    unsettled (U1 in the plan), so when the lexer does lose its place the file has
    to report as DEGRADED COVERAGE — never as a clean object."""
    runaway = "REPORT z.\nx = 'never closed\n" + "".join(
        f"WRITE lv_{i}.\n" for i in range(80))
    sc = AbapSourceScanner(data_flow=False)
    sc.scan_text(runaway, SRC)
    assert sc.lex_degraded >= 1, \
        "the lexer ran off the end of the file and said nothing about it"


def test_degraded_lexing_reaches_the_report_not_just_a_counter(tmp_path):
    """"Nothing to find" and "could not look" are indistinguishable in a report and
    only one of them is true. This is the same discipline `metadata_skipped` and
    `server/coverage.py` exist for."""
    from modules.abap_sast import AbapSastAuditor
    (tmp_path / "z_bad.prog.abap").write_text(
        "REPORT z.\nx = 'never closed\n" + "".join(
            f"WRITE lv_{i}.\n" for i in range(80)), encoding="utf-8")
    findings = AbapSastAuditor({"abap_source_dir": str(tmp_path)}, {}).run_all_checks()
    assert any(f["check_id"] == "ABAP-LEX-001" for f in findings), \
        "the scan degraded silently and the report looks clean"


def test_a_normal_file_is_never_marked_degraded():
    """The control: the counter is worthless if it fires on correct code."""
    sc = AbapSourceScanner(data_flow=False)
    sc.scan_text("".join(f"WRITE lv_{i}.\n" for i in range(200)), SRC)
    assert sc.lex_degraded == 0


# --------------------------------------------------------------------------- #
#  T1.3 — literal content is not code                                         #
# --------------------------------------------------------------------------- #

def test_prose_in_a_message_does_not_invent_a_finding():
    """Comments were stripped; literals were not. So a developer writing ABOUT a
    dangerous construct was reported as using one."""
    assert "ABAP-NSQL-001" not in rule_ids(
        "MESSAGE |Never use EXEC SQL in this program| TYPE 'I'.\n")


def test_prose_in_a_message_does_not_silence_a_finding():
    """The same defect in the direction that loses findings, and the worse of the
    two: a developer's TODO about missing authorization suppressed the finding
    about missing authorization."""
    unguarded = ("FORM f.\n"
                 "  DELETE FROM zcust WHERE kunnr = lv_k.\n"
                 "ENDFORM.\n")
    with_todo = ("FORM f.\n"
                 "  MESSAGE |Remember to AUTHORITY-CHECK before delete| TYPE 'I'.\n"
                 "  DELETE FROM zcust WHERE kunnr = lv_k.\n"
                 "ENDFORM.\n")
    assert "ABAP-AUTH-005" in rule_ids(unguarded), "the control case stopped firing"
    assert "ABAP-AUTH-005" in rule_ids(with_todo), \
        "a string literal mentioning AUTHORITY-CHECK counted as one"


@pytest.mark.parametrize("rule,statement", [
    ("ABAP-CRYP-003", "lv_alg = 'DES'.\n"),
    ("ABAP-CRED-001", "lv_password = 'secret123'.\n"),
])
def test_a_rule_that_keys_on_a_literal_value_still_sees_the_value(rule, statement):
    """Masking is deliberately NOT global, and `LITERAL_BLIND` is the opt-in list
    that keeps it that way. Rules about WHAT IS IN a literal — a cipher name, a
    credential, a URL — must keep reading it."""
    assert rule in rule_ids(statement), \
        "masking was applied globally and blinded the value-based rules"


# --------------------------------------------------------------------------- #
#  T1.4 — each sink grades its own operand                                    #
# --------------------------------------------------------------------------- #

def test_a_two_clause_statement_grades_each_finding_on_its_own_operand():
    """Every sink rule ships a precise `_sink_arg` and none of them was ever read —
    `_refine` used one generic "first ( identifier ) anywhere" regex. So the WHERE
    finding was graded on the FROM operand, and the `taint_flow` printed in a
    customer report traced a variable that is not the WHERE operand at all."""
    stmt = "SELECT * FROM (lv_tab) WHERE (lv_where) INTO TABLE @DATA(lt)."
    assert _sink_argument(stmt, "ABAP-SQLI-001") == "lv_where"
    assert _sink_argument(stmt, "ABAP-SQLI-011") == "lv_tab"


def test_a_sink_whose_operand_is_not_parenthesised_can_be_confirmed():
    """`OPEN DATASET lv_file` and `create_by_url( url = lv_url )` returned None from
    the generic extractor, were skipped, and could NEVER reach `confirmed` despite
    shipping working sink patterns."""
    assert _sink_argument("OPEN DATASET lv_file FOR OUTPUT IN TEXT MODE",
                          "ABAP-PATH-001") == "lv_file"
    assert _sink_argument("lo_c = cl_http_client=>create_by_url( url = lv_url )",
                          "ABAP-SSRF-001") == "lv_url"


def test_an_inline_declaration_is_never_taken_for_the_dynamic_operand():
    """`INTO TABLE @DATA(lt)` is the statement's target, not its operand."""
    assert _sink_argument("SELECT * FROM mara INTO TABLE @DATA(lt).") is None


# --------------------------------------------------------------------------- #
#  T1.7 / T1.8 / T1.9 — sanitizers                                            #
# --------------------------------------------------------------------------- #

def test_a_variable_merely_named_like_a_sanitizer_is_still_tainted():
    """The sanitizer regex had no word boundaries and no call syntax, and
    `classify_sink` tests it against the RAW SINK ARGUMENT. So a tainted variable
    NAMED `lv_escape_quotes` returned `sanitized` outright — the finding was
    downgraded by its own operand's name."""
    src = ("REPORT z.\n"
           "PARAMETERS: p_in TYPE string.\n"
           "START-OF-SELECTION.\n"
           "  lv_escape_quotes = p_in.\n"
           "  SELECT * FROM mara WHERE (lv_escape_quotes) INTO TABLE @DATA(lt).\n")
    a = RiseTaintAnalyzer(src)
    assert a.classify_sink("lv_escape_quotes", 5) == a.TAINTED


def test_an_xss_escaper_does_not_clear_a_dynamic_from_clause():
    """The blanket `cl_abap_dyn_prg=>` prefix credited ANY method on the class.
    An escaper for JavaScript output was clearing a SQL table name."""
    src = ("REPORT z.\n"
           "PARAMETERS: p_in TYPE string.\n"
           "START-OF-SELECTION.\n"
           "  lv_tab = cl_abap_dyn_prg=>escape_xss_javascript( p_in ).\n"
           "  SELECT * FROM (lv_tab) INTO TABLE @DATA(lt).\n")
    from modules.abap_sast import _analyzer_for
    a = _analyzer_for("ABAP-SQLI-011", src)
    assert a.classify_sink("lv_tab", 5) == a.TAINTED, \
        "an XSS escaper was accepted as a guard for a dynamic table name"


def test_a_guard_wrapping_a_literal_does_not_clear_the_tainted_value_beside_it():
    """`_classify` returned SANITIZED for the whole expression on seeing a guard
    anywhere in it, before ever looking for a source. Here the guard wraps the safe
    literal and the tainted value sitting next to it was never examined."""
    src = ("REPORT z.\n"
           "PARAMETERS: p_in TYPE string.\n"
           "START-OF-SELECTION.\n"
           "  CONCATENATE cl_abap_dyn_prg=>quote( 'LH' ) p_in INTO lv_where.\n"
           "  SELECT * FROM mara WHERE (lv_where) INTO TABLE @DATA(lt).\n")
    from modules.abap_sast import _analyzer_for
    a = _analyzer_for("ABAP-SQLI-001", src)
    assert a.classify_sink("lv_where", 5) == a.TAINTED


def test_the_right_guard_for_the_sink_is_still_accepted():
    """The control. Narrowing the inventory is only correct if correct code still
    reads as guarded — otherwise every modern estate becomes a false positive."""
    src = ("REPORT z.\n"
           "PARAMETERS: p_in TYPE string.\n"
           "START-OF-SELECTION.\n"
           "  lv_tab = cl_abap_dyn_prg=>check_table_name_str( p_in ).\n"
           "  SELECT * FROM (lv_tab) INTO TABLE @DATA(lt).\n")
    from modules.abap_sast import _analyzer_for
    a = _analyzer_for("ABAP-SQLI-011", src)
    assert a.classify_sink("lv_tab", 5) == a.SANITIZED


# --------------------------------------------------------------------------- #
#  T1.10 — what the analyzer is given                                         #
# --------------------------------------------------------------------------- #

def test_a_chained_parameters_declaration_taints_every_member():
    """`_PARAM_RE` captured one name per LINE, so `PARAMETERS: p_a ..., p_tab ...`
    tainted only `p_a` and every injection through a later member of the chain
    classified UNKNOWN — which since Phase 5 means it never prices into FAIR."""
    src = ("REPORT z.\n"
           "PARAMETERS: p_a TYPE c, p_tab TYPE tabname, p_c TYPE i.\n"
           "START-OF-SELECTION.\n"
           "  SELECT * FROM (p_tab) INTO TABLE @DATA(lt).\n")
    a = RiseTaintAnalyzer(src)
    assert a.state_of("p_tab", 4) == a.TAINTED
    assert a.state_of("p_c", 4) == a.TAINTED


def test_an_inline_declaration_propagates_taint():
    """`DATA(lv_tab) = p_tab.` defeated `^\\s*([\\w/]+)\\s*=` — it found the `(`
    first — so the propagation was invisible and the finding downgraded."""
    src = ("REPORT z.\n"
           "PARAMETERS: p_tab TYPE tabname.\n"
           "START-OF-SELECTION.\n"
           "  DATA(lv_tab) = p_tab.\n"
           "  SELECT * FROM (lv_tab) INTO TABLE @DATA(lt).\n")
    a = RiseTaintAnalyzer(src)
    assert a.state_of("lv_tab", 5) == a.TAINTED


def test_a_class_qualified_call_is_not_read_as_an_assignment():
    """`cl_gui_frontend_services=>gui_upload( ... )` parsed as an assignment TO the
    class name, because the `[=<>]=` guard does not exclude `=>`. `gui_upload` is in
    the source list and could therefore never fire as intended."""
    src = ("REPORT z.\n"
           "PARAMETERS: p_f TYPE string.\n"
           "START-OF-SELECTION.\n"
           "  cl_gui_frontend_services=>gui_upload( EXPORTING filename = p_f ).\n"
           "  WRITE lv_x.\n")
    a = RiseTaintAnalyzer(src)
    assert a.state_of("cl_gui_frontend_services", 5) != a.TAINTED, \
        "the class name itself was marked tainted by its own method call"


def test_a_compile_time_constant_clause_is_clean_not_a_tentative_critical():
    """There was no declaration case at all, so a WHERE clause fixed at compile
    time reported as a tentative CRITICAL. This was the largest single block of
    tentative findings."""
    src = ("REPORT z.\n"
           "CONSTANTS lc_where TYPE string VALUE 'MANDT = SY-MANDT'.\n"
           "START-OF-SELECTION.\n"
           "  SELECT * FROM mara WHERE (lc_where) INTO TABLE @DATA(lt).\n")
    a = RiseTaintAnalyzer(src)
    assert a.state_of("lc_where", 4) == a.CLEAN


def test_a_concatenation_split_over_two_lines_is_seen():
    """The analyzer re-lexed the RAW file one line at a time — the exact
    line-oriented model this module exists to replace — so the second line of a
    wrapped statement was never applied."""
    src = ("REPORT z.\n"
           "PARAMETERS: p_in TYPE string.\n"
           "START-OF-SELECTION.\n"
           "  CONCATENATE 'MATNR = ' p_in\n"
           "    INTO lv_where.\n"
           "  SELECT * FROM mara WHERE (lv_where) INTO TABLE @DATA(lt).\n")
    hit = next(f for f in scan(src, data_flow=True) if f["rule_id"] == "ABAP-SQLI-001")
    assert hit["confidence"] == "confirmed", \
        "a wrapped concatenation lost the taint the same way the old engine did"


def test_a_quote_inside_a_literal_no_longer_truncates_the_taint_input():
    """The analyzer cut every line at the first `"`, so a literal containing one
    lost the source — and, in the mirror case, the sanitizer."""
    src = ("REPORT z.\n"
           "PARAMETERS: p_in TYPE string.\n"
           "START-OF-SELECTION.\n"
           "  lv_where = p_in && ' say \"hi\" '.\n"
           "  SELECT * FROM mara WHERE (lv_where) INTO TABLE @DATA(lt).\n")
    a = RiseTaintAnalyzer(src)
    assert a.state_of("lv_where", 5) == a.TAINTED


# --------------------------------------------------------------------------- #
#  T1.5 / T1.6 — the authorization guard                                      #
# --------------------------------------------------------------------------- #

def test_an_authority_check_inside_a_string_literal_is_not_a_guard():
    text = ("FORM f.\n"
            "  WRITE 'TODO: add AUTHORITY-CHECK here'.\n"
            "  DELETE FROM zcust WHERE kunnr = lv_k.\n"
            "ENDFORM.\n")
    assert "ABAP-AUTH-005" in rule_ids(text)


def test_an_authority_check_with_no_field_pair_is_not_a_guard():
    """`AUTHORITY-CHECK OBJECT 'X'.` with no FIELD checks nothing."""
    text = ("FORM f.\n"
            "  AUTHORITY-CHECK OBJECT 'S_X'.\n"
            "  DELETE FROM zcust WHERE kunnr = lv_k.\n"
            "ENDFORM.\n")
    assert "ABAP-AUTH-005" in rule_ids(text)


def test_an_authority_check_whose_result_is_discarded_is_not_a_guard():
    """A real check whose `sy-subrc` is never read is a no-op, and the old guard
    credited it in full — so the check that does nothing silenced the finding."""
    text = ("FORM f.\n"
            "  AUTHORITY-CHECK OBJECT 'S_X' ID 'ACTVT' FIELD '02'.\n"
            "  DELETE FROM zcust WHERE kunnr = lv_k.\n"
            "ENDFORM.\n")
    assert "ABAP-AUTH-005" in rule_ids(text)


def test_that_discarded_check_is_reported_in_its_own_right():
    """T1.6. ABAP-AUTH-003 is exactly this finding, and it was DEAD CODE: its
    pattern needed a literal `.` that the splitter strips plus a lookahead at the
    next statement, so it could only ever fire when a period appeared inside a
    literal — a guaranteed false positive in the one case that reached it."""
    text = ("FORM f.\n"
            "  AUTHORITY-CHECK OBJECT 'S_X' ID 'ACTVT' FIELD '02'.\n"
            "  DELETE FROM zcust WHERE kunnr = lv_k.\n"
            "ENDFORM.\n")
    assert "ABAP-AUTH-003" in rule_ids(text)


def test_a_checked_subrc_does_not_raise_auth_003():
    """The control."""
    text = ("FORM f.\n"
            "  AUTHORITY-CHECK OBJECT 'S_X' ID 'ACTVT' FIELD '02'.\n"
            "  IF sy-subrc <> 0.\n"
            "    MESSAGE 'no' TYPE 'E'.\n"
            "  ENDIF.\n"
            "ENDFORM.\n")
    assert "ABAP-AUTH-003" not in rule_ids(text)


def test_the_undocumented_spellings_are_not_accepted_as_a_guard():
    """`[-\\s]?` admitted `AUTHORITY CHECK` and `AUTHORITYCHECK`, neither of which
    is the documented statement."""
    text = ("FORM f.\n"
            "  AUTHORITYCHECK OBJECT 'S_X' ID 'ACTVT' FIELD '02'.\n"
            "  IF sy-subrc <> 0. RETURN. ENDIF.\n"
            "  DELETE FROM zcust WHERE kunnr = lv_k.\n"
            "ENDFORM.\n")
    assert "ABAP-AUTH-005" in rule_ids(text)


# --------------------------------------------------------------------------- #
#  T1.12 — an AMDP body is SQLScript, not ABAP                                #
# --------------------------------------------------------------------------- #

AMDP = (
    "CLASS zcl_x IMPLEMENTATION.\n"
    "  METHOD get_data BY DATABASE PROCEDURE FOR HDB LANGUAGE SQLSCRIPT.\n"
    "    -- legacy: EXECUTE IMMEDIATE :lv_sql;\n"
    "    lt_f = APPLY_FILTER(\"ZDEMO_VIEW\", :lv_filter);\n"
    "  ENDMETHOD.\n"
    "ENDCLASS.\n")


def test_a_sqlscript_line_comment_is_not_executable_code():
    """`--` comments are never stripped by the ABAP lexer, so a commented-out
    EXECUTE IMMEDIATE raised a CRITICAL — precisely the commented-code false
    positive this module's docstring claims to have eliminated."""
    assert "ABAP-AMDP-001" not in rule_ids(AMDP), \
        "a `--` commented line was matched as executable SQLScript"


def test_a_quoted_identifier_does_not_truncate_a_sqlscript_statement():
    """In SQLScript `"` delimits an IDENTIFIER; in ABAP it starts a comment. So
    `APPLY_FILTER("ZDEMO_VIEW", :filter)` was truncated to `APPLY_FILTER(` and the
    rule could not fire on the form real code uses."""
    text = " ".join(s.text for s in split_statements(AMDP))
    assert ":lv_filter" in text, \
        "the statement was cut at the quoted identifier"


def test_the_amdp_body_does_not_swallow_endmethod():
    """SQLScript has no ABAP period, so the whole body plus ENDMETHOD collapsed
    into one blob — which is why AMDP findings reported the wrong line."""
    heads = [s.text.split()[0].upper() for s in split_statements(AMDP) if s.text]
    assert "ENDMETHOD" in heads, heads


def test_leaving_the_amdp_body_restores_abap_lexing():
    """The mode has to be left, or every statement after the class is SQLScript."""
    stmts = split_statements(AMDP + "WRITE 'after'.\nWRITE 'again'.\n")
    tail = [s.text for s in stmts if s.text.upper().startswith("WRITE")]
    assert len(tail) == 2, tail
