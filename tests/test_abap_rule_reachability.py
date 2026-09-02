"""Custom-code rules that had never been seen to report anything.

Same audit as `test_never_observed_checks.py`, applied to the `ABAP-*` family:
21 of its ids appeared in no test and in no run against the bundled corpus. Each
test here writes the smallest source file that the rule is looking for.

Two of the 21 turned out to be defects rather than gaps:

  ABAP-BTP-003  could not match JSON at all — see the test below
  ABAP-XSS-006  is in `RETIRED_RULES`, deliberately and permanently, and was
                still being counted in the check catalogue

The rest simply had no example anywhere. Note that several rules' EFFECTIVE
pattern comes from `PATTERN_FIXES`, not from the vendored rule table — reading
the vendored pattern and building a snippet for it produces a file the scanner
ignores, which is its own small trap and is why the snippets below look the way
they do.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.abap_sast import (ALL_ABAP_SAST_RULES, ALL_BTP_CONFIG_RULES,   # noqa: E402
                               ALL_JS_RULES, CDS_RULES, PATTERN_FIXES,
                               RETIRED_RULES, AbapSastAuditor)


def scan(tmp_path, filename, source):
    (tmp_path / filename).write_text(source, encoding="utf-8")
    findings = AbapSastAuditor({"abap_source_dir": str(tmp_path)}, {}).run_all_checks()
    return {f["check_id"] for f in (findings or [])}


#: (check id, file name, source). One entry per rule that had never fired.
CASES = [
    ("ABAP-SQLI-002", "z_sqli.prog.abap",
     "REPORT z_sqli.\nCONCATENATE lv_w ' AND bukrs = ' p_bukrs INTO lv_w.\n"),
    ("ABAP-SQLI-015", "z_upd.prog.abap",
     "REPORT z_upd.\nUPDATE bkpf SET (lv_set) WHERE belnr = @lv_belnr.\n"),
    ("ABAP-CINJ-007", "z_xslt.prog.abap",
     "REPORT z_xslt.\nCALL TRANSFORMATION (lv_tf) SOURCE root = ls_x RESULT XML lv_y.\n"),
    ("ABAP-CINJ-016", "z_assign.prog.abap",
     "REPORT z_assign.\nFIELD-SYMBOLS <fs> TYPE any.\nASSIGN lo_ref->( lv_attr ) TO <fs>.\n"),
    ("ABAP-DYNT-001", "z_dynt.prog.abap",
     "REPORT z_dynt.\nREAD TABLE lt_items INTO ls_item WHERE (lv_cond).\n"),
    ("ABAP-CRED-001", "z_cred1.prog.abap",
     "REPORT z_cred1.\nlo_conn->password = 'Hunter2xyz'.\n"),
    ("ABAP-CRED-002", "z_cred2.prog.abap",
     "REPORT z_cred2.\nlv_api_key = 'ak_live_9f2b7c14aa03'.\n"),
    ("ABAP-CRED-004", "z_cred4.prog.abap",
     "REPORT z_cred4.\nlo_request->set_request_header( name = 'Authorization'\n"
     "                                value = 'Basic YWRtaW46c2VjcmV0MTIz' ).\n"),
    ("ABAP-CRED-005", "z_cred5.prog.abap",
     "REPORT z_cred5.\nCONSTANTS gc_password TYPE string VALUE 'P@ssw0rd123'.\n"),
    ("ABAP-CRYP-004", "z_cryp4.prog.abap",
     "REPORT z_cryp4.\nlv_key = '00112233445566778899AABBCCDDEEFF'.\n"),
    ("ABAP-PATH-004", "z_path4.prog.abap",
     "REPORT z_path4.\nCONCATENATE lv_base '../../etc/passwd' INTO lv_path.\n"),
    ("ABAP-XSS-004", "z_xss4.prog.abap",
     "REPORT z_xss4.\nlo_response->set_header_field( name = 'Set-Cookie'\n"
     "                               value = 'SESSIONID=abc123; Path=/' ).\n"),
    ("ABAP-AUTH-003", "z_auth3.prog.abap",
     "REPORT z_auth3.\nAUTHORITY-CHECK OBJECT 'S_TCODE' ID 'TCD' FIELD 'SE38'.\n"
     "WRITE 'done'.\n"),
    ("ABAP-AMDP-005", "zcl_amdp.clas.abap",
     "CLASS zcl_amdp DEFINITION.\nENDCLASS.\n"
     "CLASS zcl_amdp IMPLEMENTATION.\n"
     "  METHOD get_data BY DATABASE PROCEDURE FOR HDB LANGUAGE SQLSCRIPT.\n"
     "    AMDP OPTIONS READ-ONLY.\n  ENDMETHOD.\nENDCLASS.\n"),
    # The semicolon is not decoration: it is DCL syntax, and without it the
    # scanner's statement splitting does not present the GRANT as a statement
    # of its own inside the brace block.
    ("ABAP-CDS-002", "z_role.asddls",
     "define role Z_R {\n  GRANT SELECT ON Z_I_Bkpf;\n}\n"),
    ("ABAP-JS-004", "app.js",
     'const config = {\n  api_key: "sk_live_9f2b7c14aa0312"\n};\n'),
]


@pytest.mark.parametrize("check_id, filename, source", CASES,
                         ids=[c[0] for c in CASES])
def test_the_rule_reports_the_code_it_was_written_to_find(
        tmp_path, check_id, filename, source):
    got = scan(tmp_path, filename, source)
    assert check_id in got, (
        "%s reported nothing on source written to match it. Reported instead: "
        "%s. Note the rule's effective pattern may come from PATTERN_FIXES "
        "rather than from the vendored table." % (check_id, sorted(got) or "nothing"))


# ── ABAP-BTP-003: a rule that could not match the format it reads ──────────

def test_btp_003_finds_a_hard_coded_secret_in_json(tmp_path):
    """THE DEFECT. The vendored pattern asked for the key word, then optional
    whitespace, then a colon — which is YAML's shape. JSON quotes its keys, so
    a closing quote sits between the word and the colon:

        "clientsecret": "s3cr3t-value"
                    ^ the pattern stopped here

    Three of the five files this rule is applied to are .json, including
    xs-security.json — the file a hard-coded client secret actually lives in.
    The rule was reading it and could not report what was there.
    """
    assert "ABAP-BTP-003" in scan(tmp_path, "xs-security.json",
                                  '{\n  "xsappname": "z-app",\n'
                                  '  "clientsecret": "s3cr3t-value-here"\n}\n')


def test_btp_003_still_finds_the_yaml_form(tmp_path):
    """The shape that always worked must keep working."""
    assert "ABAP-BTP-003" in scan(tmp_path, "mta.yaml",
                                  "modules:\n  - name: app\n    properties:\n"
                                  "      clientsecret: s3cr3tvalue123\n")


def test_btp_003_ignores_an_environment_placeholder(tmp_path):
    """`${...}` is a reference to a secret, not a secret. The value half of the
    pattern is unchanged by the fix, and this is what that half is for."""
    assert "ABAP-BTP-003" not in scan(tmp_path, "xs-security.json",
                                      '{\n  "clientsecret": "${CLIENT_SECRET}"\n}\n')


# ── retired rules are not checks ───────────────────────────────────────────

def test_a_retired_rule_is_not_counted_in_the_catalogue():
    """`abap_sast` skips RETIRED_RULES at scan time, so a retired rule cannot
    produce a finding on any estate — by design. Counting it put a check that
    will never fire into the denominator every coverage figure is measured
    against, and then into the unproven list, where a deliberate withdrawal
    looked like a rule nobody had got round to testing."""
    from modules import coverage
    catalogue = coverage.check_catalogue()
    assert RETIRED_RULES, "the guard below is vacuous with an empty tuple"
    for rule_id in RETIRED_RULES:
        assert rule_id not in catalogue, (
            "%s is retired and can never fire, but is still counted as a check"
            % rule_id)


def test_every_rule_the_scanner_runs_has_a_usable_pattern():
    """A rule with no pattern and no engine handler matches nothing at all."""
    from modules.abap_sast import RULE_HANDLED_IN_ENGINE
    unusable = []
    for table in (ALL_ABAP_SAST_RULES, ALL_JS_RULES, ALL_BTP_CONFIG_RULES,
                  CDS_RULES):
        for rule in table:
            rid = rule.get("id")
            if rid in RETIRED_RULES or rid in RULE_HANDLED_IN_ENGINE:
                continue
            if not (PATTERN_FIXES.get(rid) or rule.get("pattern")):
                unusable.append(rid)
    assert not unusable, "rules with nothing to match on: %s" % unusable
