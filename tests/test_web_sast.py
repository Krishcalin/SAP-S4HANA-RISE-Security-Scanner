# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""The non-ABAP half of the source scanner: JavaScript/TypeScript, the BTP
descriptor JSON files, and mta.yaml.

WHY THIS FILE EXISTS. All four types were routed to rule sets and counted in
`files_scanned` long before anything could read them — they were handed to the
ABAP splitter, where `"` opens a comment and `.` ends a statement. Measured
before the fix: only three of seven JS rules could fire (and only with single
quotes), every one of the eight BTP descriptor rules was unreachable because
each pattern begins `["']key["']`, and mta.yaml always reported line 1.

The rules were asserted for COUNT and never for behaviour, which is exactly how
that survived. These tests assert behaviour: every rule that was dead must fire
on a vulnerable fixture, secure fixtures must stay silent, and the scanner must
say which languages it did not read.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.abap_sast import (                                    # noqa: E402
    AbapSourceScanner, split_web_statements)

WEB = ROOT / "tests" / "fixtures" / "web"


def _scan(name):
    s = AbapSourceScanner(data_flow=False)
    path = WEB / name
    return s.scan_text(path.read_text(encoding="utf-8"), path)


def _ids(name):
    return {f["rule_id"] for f in _scan(name)}


# ── the rules that were structurally unreachable ─────────────────────────────

@pytest.mark.parametrize("rule_id", ["ABAP-JS-001", "ABAP-JS-002",
                                     "ABAP-JS-003", "ABAP-JS-004",
                                     "ABAP-JS-005"])
def test_javascript_rules_fire(rule_id):
    """ABAP-JS-002/003 were unreachable: their patterns need a `.` that the
    ABAP splitter consumed as a statement terminator."""
    assert rule_id in _ids("ui5_vulnerable.js")


@pytest.mark.parametrize("name,rule_id", [
    ("xs-security.json", "ABAP-BTP-001"),
    ("xs-security.json", "ABAP-BTP-002"),
    ("xs-app.json", "ABAP-BTP-005"),
    ("xs-app.json", "ABAP-BTP-006"),
    ("mta.yaml", "ABAP-BTP-003"),
])
def test_btp_descriptor_rules_fire(name, rule_id):
    """All eight began `["']key["']` and the first quote ended the statement,
    so none of them could ever match. Five are exercised by these fixtures."""
    assert rule_id in _ids(name)


def test_a_multiline_json_array_is_one_statement():
    """`"scope-references": [` and `"$XSAPPNAME.*"` sit on different lines in
    every pretty-printed descriptor. A line-at-a-time split would miss the rule
    that reads the key's array, which is why JSON joins a key to its value."""
    assert "ABAP-BTP-002" in _ids("xs-security.json")


# ── the properties that keep it honest ───────────────────────────────────────

def test_secure_javascript_is_silent():
    """Including a comment that names eval( and document.write( — a comment is
    not code, and a scanner that cannot tell does not get a second look."""
    assert _ids("ui5_secure.js") == set()


def test_a_url_inside_a_string_is_not_a_comment():
    """`//` in `"http://host"` must not start a comment. Getting this wrong
    silences the rule that looks for plaintext HTTP — the same rule whose own
    pattern contains the `//`."""
    assert "ABAP-JS-005" in _ids("ui5_vulnerable.js")
    # ... and JSON has no comments at all, so a URL there survives whole.
    stmts = split_web_statements('{"doc": "see http://x/y for details"}', "json")
    assert any("http://x/y" in s.text for s in stmts)


def test_reported_lines_are_real():
    """mta.yaml collapsed to a single statement and every finding claimed line
    1. A line number that is always 1 is worse than none: it looks like data."""
    hits = [f for f in _scan("mta.yaml") if f["rule_id"] == "ABAP-BTP-003"]
    assert hits and all(f["line"] > 1 for f in hits)
    js = {f["rule_id"]: f["line"] for f in _scan("ui5_vulnerable.js")}
    assert js["ABAP-JS-002"] != js["ABAP-JS-003"]


def test_a_yaml_comment_is_not_a_secret():
    stmts = split_web_statements("key: value   # password: notreallyasecret\n", "yaml")
    assert all("notreallyasecret" not in s.text for s in stmts)


# ── coverage: what the scanner did NOT read ──────────────────────────────────

def test_languages_are_counted_separately(tmp_path):
    (tmp_path / "a.js").write_text("eval(x);\n", encoding="utf-8")
    (tmp_path / "mta.yaml").write_text("password: abcdefgh12\n", encoding="utf-8")
    (tmp_path / "xs-app.json").write_text('{"authenticationType": "none"}\n',
                                          encoding="utf-8")
    s = AbapSourceScanner(data_flow=False)
    s.scan_tree(tmp_path)
    assert s.files_by_language == {"js": 1, "yaml": 1, "json": 1}


def test_unread_languages_are_counted_not_skipped_silently(tmp_path):
    """A CAP project is mostly Java or Node. Before this, those files produced
    no finding, no error and no count — indistinguishable from clean."""
    (tmp_path / "Main.java").write_text("class X {}\n", encoding="utf-8")
    (tmp_path / "proc.hdbprocedure").write_text("BEGIN END;\n", encoding="utf-8")
    (tmp_path / "a.js").write_text("eval(x);\n", encoding="utf-8")
    s = AbapSourceScanner(data_flow=False)
    s.scan_tree(tmp_path)
    assert s.unscanned_by_suffix == {".java": 1, ".hdbprocedure": 1}
    assert s.files_by_language == {"js": 1}


def test_the_unread_languages_are_disclosed_as_a_finding(tmp_path):
    from modules.abap_sast import AbapSastAuditor
    (tmp_path / "Main.java").write_text("class X {}\n", encoding="utf-8")
    (tmp_path / "a.js").write_text("eval(x);\n", encoding="utf-8")
    findings = AbapSastAuditor({"abap_source_dir": str(tmp_path)}).run_all_checks()
    cov = [f for f in findings if f["check_id"] == "ABAP-COV-004"]
    assert len(cov) == 1
    assert cov[0]["details"]["degrades_coverage"] is True
    assert cov[0]["details"]["unscanned_by_suffix"] == {".java": 1}
    assert "js" in cov[0]["details"]["languages_read"]


def test_no_disclosure_when_everything_was_read(tmp_path):
    (tmp_path / "a.js").write_text("eval(x);\n", encoding="utf-8")
    from modules.abap_sast import AbapSastAuditor
    findings = AbapSastAuditor({"abap_source_dir": str(tmp_path)}).run_all_checks()
    assert not [f for f in findings if f["check_id"] == "ABAP-COV-004"]
