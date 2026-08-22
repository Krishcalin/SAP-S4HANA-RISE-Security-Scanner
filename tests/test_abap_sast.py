"""
ABAP source scanning: statements, not lines.

THE TWO MEASUREMENTS THAT JUSTIFIED THIS MODULE'S REWRITE
The upstream engine matched one line of text at a time. ABAP statements end at a
period and routinely span several lines, and that single mismatch produced both
failure modes at once:

  * 50 lines of secure, idiomatic ABAP -> 3 HIGH findings, two of them "DES
    encryption" caused by the letters `des` inside `lv_modes` and `lt_codes`, in a
    file with no cryptography in it.
  * A genuine SQL injection written across four lines -> nothing at all, while the
    identical statement on one line -> CRITICAL.

`test_secure_code_is_silent` and `test_a_wrapped_statement_is_still_one_statement`
are those two, and they are the reason this file exists.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.abap_sast import (                                   # noqa: E402
    AbapSastAuditor, AbapSourceScanner, split_statements,
)
from server.identity import compute_fingerprint                   # noqa: E402

SRC = Path("z_test.prog.abap")


def scan(text, **kw):
    return AbapSourceScanner(data_flow=kw.pop("data_flow", False)).scan_text(text, SRC)


def rule_ids(text, **kw):
    return [f["rule_id"] for f in scan(text, **kw)]


# --------------------------------------------------------------------------- #
#  Statement splitting                                                        #
# --------------------------------------------------------------------------- #

def test_a_wrapped_statement_is_still_one_statement():
    """The false NEGATIVE. Real ABAP is wrapped; the injection must survive it."""
    wrapped = (
        "REPORT z.\n"
        "DATA lv_where TYPE string.\n"
        "START-OF-SELECTION.\n"
        "  lv_where = request->get_form_field( 'q' ).\n"
        "  SELECT *\n"
        "    FROM mara\n"
        "    WHERE (lv_where)\n"
        "    INTO TABLE @DATA(lt).\n")
    assert "ABAP-SQLI-001" in rule_ids(wrapped), \
        "a dynamic WHERE split across lines was invisible — the way ABAP is written"


def test_the_same_statement_on_one_line_is_still_caught():
    """The control. Fixing the wrapped case must not lose the simple one."""
    one = ("REPORT z.\nDATA lv_where TYPE string.\n"
           "lv_where = request->get_form_field( 'q' ).\n"
           "SELECT * FROM mara WHERE (lv_where) INTO TABLE @DATA(lt).\n")
    assert "ABAP-SQLI-001" in rule_ids(one)


@pytest.mark.parametrize("label,source,expected", [
    ("plain template",        "lv_m = |Total. Done|. WRITE lv_m.\n", 2),
    ("escaped pipe",          "lv_m = |a\\|b. c|. WRITE lv_m.\n", 2),
    ("quote inside template", 'lv_m = |say "hi". now|. WRITE lv_m.\n', 2),
    ("embedded expression",   "lv_m = |Total: { n } items. Done|. WRITE lv_m.\n", 2),
    ("template over 2 lines", "lv_m = |first. line\n  second. line|.\nWRITE lv_m.\n", 2),
])
def test_a_string_template_is_a_literal(label, source, expected):
    """ABAP string templates `|...|` were not lexed as literals at all, so any
    statement containing one with a period was chopped into pieces — losing the
    real statement AND inventing garbage ones that got reported. Templates are
    pervasive in modern ABAP, so this mis-lexed a large share of real source.

    The two-line case is why the template flag is threaded ACROSS lines rather
    than recomputed per line, and the quote case is why: a `"` inside an open
    template is text, and treating it as a comment truncated the statement.
    """
    assert len(split_statements(source)) == expected, \
        [s.text for s in split_statements(source)]


def test_an_injection_survives_being_surrounded_by_string_templates():
    """The realistic shape: modern ABAP logs with templates either side of the
    statement that actually matters."""
    src = ("REPORT z_modern.\n"
           "DATA lv_where TYPE string.\n"
           "START-OF-SELECTION.\n"
           "  lv_where = request->get_form_field( 'q' ).\n"
           "  WRITE |Filtering on: { lv_where }. Please wait|.\n"
           "  SELECT * FROM lfa1 WHERE (lv_where) INTO TABLE @DATA(lt).\n"
           "  WRITE |Found { lines( lt ) } rows. Done|.\n")
    hit = next(f for f in scan(src, data_flow=True) if f["rule_id"] == "ABAP-SQLI-001")
    assert hit["confidence"] == "confirmed"


def test_a_period_inside_a_string_literal_does_not_end_a_statement():
    stmts = split_statements("WRITE 'a. b. c'. WRITE 'x'.\n")
    assert len(stmts) == 2, [s.text for s in stmts]


def test_a_decimal_number_does_not_end_a_statement():
    stmts = split_statements("lv_x = 1.5 + 2.5. WRITE lv_x.\n")
    assert len(stmts) == 2, [s.text for s in stmts]


def test_a_full_line_comment_is_not_code():
    assert not rule_ids("REPORT z.\n* SELECT * FROM mara WHERE (lv_w) INTO TABLE @t.\n")


def test_an_inline_comment_is_not_code():
    assert not rule_ids('REPORT z.\n" SELECT * FROM mara WHERE (lv_w) INTO TABLE @t.\n')


def test_a_quote_inside_a_literal_does_not_start_a_comment():
    stmts = split_statements("""WRITE 'it''s fine'. WRITE 'x'.\n""")
    assert len(stmts) == 2


def test_the_reported_line_is_where_the_statement_starts():
    wrapped = ("REPORT z.\n"          # 1
               "\n"                   # 2
               "SELECT *\n"           # 3  <- statement starts here
               "  FROM mara\n"
               "  WHERE (lv_w)\n"
               "  INTO TABLE @DATA(t).\n")
    hit = next(f for f in scan(wrapped) if f["rule_id"] == "ABAP-SQLI-001")
    assert hit["line"] == 3, f"reported line {hit['line']}, statement starts at 3"


# --------------------------------------------------------------------------- #
#  The false positives                                                        #
# --------------------------------------------------------------------------- #

SECURE = """REPORT z_secure_example.

DATA: lv_modes TYPE string,
      lt_codes TYPE TABLE OF string,
      lv_matnr TYPE matnr.

START-OF-SELECTION.

  AUTHORITY-CHECK OBJECT 'M_MATE_MAT'
           ID 'ACTVT' FIELD '02'.
  IF sy-subrc <> 0.
    MESSAGE 'Not authorised' TYPE 'E'.
  ENDIF.

  SELECT SINGLE matnr FROM mara
    INTO @lv_matnr
    WHERE matnr = @lv_matnr.

  UPDATE mara SET pstat = 'X'
    WHERE matnr = @lv_matnr.
"""


def test_secure_code_is_silent():
    """Secure, idiomatic, correctly-authorised ABAP must produce nothing.

    A tool that reports three HIGH findings on clean code does not get a second
    look from the person evaluating it.
    """
    assert scan(SECURE) == [], \
        f"clean code produced {[f['rule_id'] for f in scan(SECURE)]}"


@pytest.mark.parametrize("identifier", ["lv_modes", "lt_codes", "lv_nodes", "lv_desc"])
def test_des_inside_an_identifier_is_not_the_des_cipher(identifier):
    """`(?:DES|3DES|TRIPLE.?DES)\\b` had no LEADING boundary."""
    assert "ABAP-CRYP-003" not in rule_ids(f"DATA {identifier} TYPE string.\n")


def test_the_des_rule_still_fires_on_actual_des():
    assert "ABAP-CRYP-003" in rule_ids("lv_alg = 'DES'.\n")


@pytest.mark.parametrize("rule,statement", [
    ("ABAP-AUTH-006", "UPDATE mara SET pstat = 'X' WHERE matnr = @lv_m."),
    ("ABAP-AUTH-005", "DELETE FROM mara WHERE matnr = @lv_m."),
    ("ABAP-AUTH-007", "INSERT INTO mara VALUES @ls_m."),
])
def test_an_authority_check_in_the_same_block_silences_the_guarded_rules(rule, statement):
    """Six rules are NAMED "... without AUTHORITY-CHECK"; only one shipped with the
    metadata to look for one. The other five fired on every such statement in the
    estate, guarded or not.

    The guard here evaluates `sy-subrc`, because that is what makes it a guard —
    see `test_an_authority_check_whose_result_is_discarded_is_not_a_guard`.
    """
    guarded = (f"FORM do_it.\n"
               f"  AUTHORITY-CHECK OBJECT 'M_MATE_MAT' ID 'ACTVT' FIELD '02'.\n"
               f"  IF sy-subrc <> 0.\n"
               f"    MESSAGE 'Not authorised' TYPE 'E'.\n"
               f"  ENDIF.\n"
               f"  {statement}\n"
               f"ENDFORM.\n")
    unguarded = f"FORM do_it.\n  {statement}\nENDFORM.\n"

    assert rule not in rule_ids(guarded), f"{rule} fired despite a guard above it"
    assert rule in rule_ids(unguarded), f"{rule} stopped detecting the real case"


def test_a_guard_in_another_form_does_not_protect_this_one():
    """Block scoping has to mean something, or it is just a global mute button."""
    text = ("FORM safe.\n"
            "  AUTHORITY-CHECK OBJECT 'X' ID 'ACTVT' FIELD '02'.\n"
            "  IF sy-subrc <> 0. RETURN. ENDIF.\n"
            "ENDFORM.\n"
            "FORM unsafe.\n"
            "  UPDATE mara SET pstat = 'X' WHERE matnr = @lv_m.\n"
            "ENDFORM.\n")
    assert "ABAP-AUTH-006" in rule_ids(text)


# --------------------------------------------------------------------------- #
#  abapGit reality                                                            #
# --------------------------------------------------------------------------- #

def test_every_abapgit_source_extension_is_read(tmp_path):
    """`.ddls.abap` / `.dcls.abap` are not what abapGit writes. It writes
    `.asddls` / `.asdcls` / `.asbdef`, so CDS and RAP coverage was silently zero on
    every real export."""
    stmt = "SELECT * FROM mara WHERE (lv_w) INTO TABLE @DATA(t).\n"
    names = ("zcl_x.clas.abap", "z_r.prog.abap", "zif_i.intf.abap",
             "zi_v.asddls", "zi_v.asdcls", "zb_v.asbdef")
    for n in names:
        (tmp_path / n).write_text(stmt, encoding="utf-8")

    sc = AbapSourceScanner(data_flow=False)
    sc.scan_tree(tmp_path)
    assert sc.files_scanned == len(names), \
        f"scanned {sc.files_scanned} of {len(names)} abapGit source files"


def test_xml_sidecars_are_counted_not_silently_ignored(tmp_path):
    """abapGit writes one metadata XML per object. Skipping them is right; skipping
    them WITHOUT SAYING SO is the failure `server/coverage.py` exists to prevent."""
    (tmp_path / "zcl_x.clas.abap").write_text("WRITE 'x'.\n", encoding="utf-8")
    (tmp_path / "zcl_x.clas.xml").write_text("<abapGit/>\n", encoding="utf-8")
    sc = AbapSourceScanner(data_flow=False)
    sc.scan_tree(tmp_path)
    assert sc.files_scanned == 1 and sc.metadata_skipped == 1


def test_the_object_name_comes_from_the_file_not_the_path(tmp_path):
    from modules.abap_sast import _object_name
    assert _object_name(Path("/x/y/zcl_vendor_api.clas.abap")) == "ZCL_VENDOR_API"


# --------------------------------------------------------------------------- #
#  Host contract                                                              #
# --------------------------------------------------------------------------- #

def _audit(tmp_path, text, name="z_vendor.prog.abap"):
    (tmp_path / name).write_text(text, encoding="utf-8")
    return AbapSastAuditor({"abap_source_dir": str(tmp_path)}, {}).run_all_checks()


def test_no_source_directory_means_no_findings_and_no_crash():
    """No `--abap-src` at all: the module has nothing to do, and says nothing.

    An absent optional input is not a failure to look, and must stay silent — if
    it produced a coverage finding, every scan that omits one input would fail the
    release gate and the gate's degraded signal would be worth nothing.
    """
    assert AbapSastAuditor({}, {}).run_all_checks() == []


def test_a_source_directory_that_is_not_there_is_reported_not_swallowed():
    """THIS TEST ASSERTED `== []` FOR BOTH CASES, WHICH IS HOW THE DEFECT SURVIVED.

    Returning nothing for a path that does not exist looks like the same "no
    findings, no crash" contract as the case above, and it is not: the caller ASKED
    for a source scan and got silence, which `--gate` then read as exit 0. A typo
    in --abap-src, or an export step that failed earlier in the pipeline, shipped
    the build on a scan that never ran.

    The two halves of the old assertion were testing opposite things, and pairing
    them in one test is what made the wrong half look right.
    """
    findings = AbapSastAuditor({"abap_source_dir": "/no/such/dir"}, {}).run_all_checks()
    assert [f["check_id"] for f in findings] == ["ABAP-COV-001"]
    assert findings[0]["details"]["degrades_coverage"] is True


def test_identity_is_the_object_never_the_line(tmp_path):
    """The whole mitigation journey rests on this."""
    stmt = "SELECT * FROM mara WHERE (lv_w) INTO TABLE @DATA(t).\n"
    a = _audit(tmp_path, stmt)
    b = _audit(tmp_path, "\n\n\n\n" + stmt)          # four blank lines pushed it down

    def ids(fs):
        return {(f["check_id"], compute_fingerprint(
            f["check_id"], f.get("system"), f.get("client"), f.get("subject"),
            f.get("affected_items"), f.get("scope") or "object")[0]) for f in fs}

    assert ids(a) == ids(b), "moving the statement down four lines changed its identity"


def test_pattern_only_findings_aggregate_per_object(tmp_path):
    """A 200k-line estate must not produce one tracked finding per pattern hit."""
    text = "".join(f"DATA lv_p{i} TYPE string VALUE 'password123'.\n" for i in range(8))
    findings = _audit(tmp_path, text)
    for f in findings:
        if f["details"].get("confidence") == "pattern-only":
            assert f["scope"] == "aggregate", f"{f['check_id']} is tracked per hit"


TAINTED = ("REPORT z.\nDATA lv_where TYPE string.\nSTART-OF-SELECTION.\n"
           "  lv_where = request->get_form_field( 'q' ).\n"
           "  SELECT * FROM mara WHERE (lv_where) INTO TABLE @DATA(lt).\n")


def test_the_taint_pass_actually_runs():
    """A REGRESSION TEST FOR A SILENT NO-OP.

    The first version of `_refine` called a `refine()` method that does not exist
    on TaintAnalyzer and wrapped the call in `except Exception: continue`. The
    AttributeError went into the except, every finding stayed `pattern-only`, and
    the taint pass appeared to run while doing nothing whatsoever. Nothing failed;
    the only symptom was that no finding was ever `confirmed`.

    So this asserts the positive outcome rather than the absence of an error.
    """
    hit = next(f for f in scan(TAINTED, data_flow=True)
               if f["rule_id"] == "ABAP-SQLI-001")
    assert hit["confidence"] == "confirmed", \
        "the taint pass did not confirm a textbook source-to-sink flow — check it " \
        "is being called at all"
    assert hit["flow"], "confirmed, but with no trace to show for it"
    roles = [h.get("role") for h in hit["flow"]]
    assert "source" in roles and "sink" in roles


def test_a_literal_argument_is_tentative_not_confirmed():
    literal = ("REPORT z.\nDATA lv_where TYPE string.\nSTART-OF-SELECTION.\n"
               "  lv_where = 'MATNR = ''X'''.\n"
               "  SELECT * FROM mara WHERE (lv_where) INTO TABLE @DATA(lt).\n")
    hit = next(f for f in scan(literal, data_flow=True)
               if f["rule_id"] == "ABAP-SQLI-001")
    assert hit["confidence"] == "tentative"


def test_a_sanitized_argument_is_downgraded_but_never_hidden():
    """The walk is path-insensitive, so a sanitizer inside one branch of an IF is
    credited on every path — including the ones it does not cover. Upstream that
    silently deleted genuine injections."""
    guarded = ("REPORT z.\nDATA lv_where TYPE string.\nSTART-OF-SELECTION.\n"
               "  lv_where = request->get_form_field( 'q' ).\n"
               "  IF lv_ok = abap_true.\n"
               "    lv_where = cl_abap_dyn_prg=>quote( lv_where ).\n"
               "  ENDIF.\n"
               "  SELECT * FROM mara WHERE (lv_where) INTO TABLE @DATA(lt).\n")
    hits = [f for f in scan(guarded, data_flow=True)
            if f["rule_id"] == "ABAP-SQLI-001"]
    assert hits, "a sanitizer in one branch removed the finding entirely"


def test_every_finding_states_the_evidence_it_rests_on(tmp_path):
    stmt = "SELECT * FROM mara WHERE (lv_w) INTO TABLE @DATA(t).\n"
    for f in _audit(tmp_path, stmt):
        assert f["details"]["confidence"] in ("confirmed", "tentative", "pattern-only")
        assert "Evidence:" in f["description"]


def test_nosec_is_reported_rather_than_deleted(tmp_path):
    """A suppression that leaves no record is indistinguishable from a clean
    estate, which is the failure mode this product exists to prevent."""
    text = "CALL FUNCTION 'Z_X' DESTINATION lv_d. \"#NOSEC\n"
    findings = _audit(tmp_path, text)
    assert any(f["check_id"] == "ABAP-NOSEC-001" for f in findings), \
        "a #NOSEC marker silently removed evidence"


def test_every_emitted_check_id_routes_to_a_team():
    from server.enrich import team_for
    from modules.abap_sast_rules import (
        ALL_ABAP_SAST_RULES, ALL_BTP_CONFIG_RULES, ALL_JS_RULES)
    ids = [r["id"] for r in
           ALL_ABAP_SAST_RULES + ALL_JS_RULES + ALL_BTP_CONFIG_RULES] + \
          ["ABAP-NOSEC-001"]
    unrouted = sorted({cid for cid in ids if team_for(cid) == "unassigned"})
    assert not unrouted, f"check ids routing nowhere: {unrouted[:10]}"


def test_the_module_is_registered_everywhere():
    assert '("abap_sast", "AbapSastAuditor")' in \
        (ROOT / "server" / "ingest.py").read_text(encoding="utf-8")
    assert '"abap_sast"' in (ROOT / "modules" / "coverage.py").read_text(encoding="utf-8")
    assert '"cva"' in (ROOT / "sap_scanner.py").read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
#  What was deliberately left behind                                          #
# --------------------------------------------------------------------------- #

def test_the_live_btp_client_did_not_come_across():
    """It made OAuth calls to a tenant. This product is offline by premise, and
    `modules/btp_import.py` rejected live connections in writing."""
    import ast

    # Match DEFINITIONS, not prose. Both modules document in their docstrings what
    # was deliberately left behind, so a substring search hits that explanation and
    # fails on the very comment that records the decision.
    banned = {"BTP_API_CHECKS", "AbapBtpScanner", "SAP_VULNERABLE_PACKAGES",
              "security_grade", "BTP_RULES_BY_ID", "owasp_taxonomy",
              "CATEGORY_TO_OWASP", "RuleSelector"}
    for name in ("abap_sast_rules.py", "abap_sast.py"):
        tree = ast.parse((ROOT / "modules" / name).read_text(encoding="utf-8"))
        defined = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.ClassDef, ast.FunctionDef)):
                defined.add(node.name)
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                defined.add(node.id)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                mod = getattr(node, "module", None) or ""
                imported = [a.name for a in node.names]
                assert "requests" != mod and "requests" not in imported, \
                    f"{name} imports requests — the live BTP client came across"
        leaked = defined & banned
        assert not leaked, \
            f"{name} defines {sorted(leaked)}; the merge plan says it must not"


def test_the_vendored_corpus_is_the_expected_size():
    """Guards the extraction in tools/build_abap_rules.py against silent drift."""
    from modules.abap_sast_rules import (
        ALL_ABAP_SAST_RULES, ALL_BTP_CONFIG_RULES, ALL_JS_RULES)
    assert len(ALL_ABAP_SAST_RULES) == 89
    assert len(ALL_JS_RULES) == 7
    assert len(ALL_BTP_CONFIG_RULES) == 8
    ids = [r["id"] for r in
           ALL_ABAP_SAST_RULES + ALL_JS_RULES + ALL_BTP_CONFIG_RULES]
    assert len(ids) == len(set(ids)) == 104
