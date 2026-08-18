# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""The Web Dispatcher profile, against SAP's own WEBDISP_ALL baseline.

WHAT WAS WRONG. Not "the Web Dispatcher is unsupported" — three modules already
checked `is/HTTP/show_server_header` and `is/HTTP/show_detailed_errors`, against
`security_params`, which is the ABAP INSTANCE profile. The dispatcher is a
separate instance with its own profile and it is the internet-facing one, so the
same parameter names were audited on the stack behind the door and never on the
door itself.

WHAT THESE TESTS ARE FOR. That the rules stay SAP's rather than ours, that an
unset parameter is not a finding, and above all that a comma inside a profile
value cannot manufacture a HIGH finding against a correctly configured system.
"""
from __future__ import annotations

import csv
import io
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.webdisp_security import WebDispatcherAuditor, load   # noqa: E402


def _run(**params):
    rows = [{"NAME": k, "VALUE": v} for k, v in params.items()]
    return WebDispatcherAuditor({"webdisp_params": rows}, {}, {}).run_all_checks()


def _run_csv(text):
    """Through a real csv.DictReader, so the overflow behaviour is the real one."""
    rows = list(csv.DictReader(io.StringIO(text)))
    return WebDispatcherAuditor({"webdisp_params": rows}, {}, {}).run_all_checks()


def _ids(findings):
    return {f["check_id"] for f in findings}


# ═════════════════════════════════════════════════════════════════════════════
#  A comma in a value must not manufacture a finding
# ═════════════════════════════════════════════════════════════════════════════

def test_an_unquoted_comma_value_does_not_invent_a_high_finding():
    """THE DEFECT THIS MODULE NEARLY SHIPPED. SAP profile values contain commas —
    `PREFIX=/x,CLIENTHOST=1.2.3.4` is one value. An export that does not quote it
    overflows into csv.DictReader's None key, and WDISP-011 then reports the admin
    handler as unrestricted BECAUSE IT WAS RESTRICTED and the restriction fell off
    the end of the row. The customer is sent to fix a correct configuration on the
    strength of how their spreadsheet saved the file."""
    findings = _run_csv(
        "NAME,VALUE\n"
        "icm/HTTP/admin_0,PREFIX=/sap/admin,CLIENTHOST=10.0.0.1,PORT=8443\n")
    assert "WDISP-011" not in _ids(findings)
    assert "WDISP-012" not in _ids(findings)


def test_the_quoted_form_of_the_same_line_agrees():
    """The recovery must produce the same verdict as a correct export, or it is
    just a second parser with its own opinions."""
    quoted = _run_csv('NAME,VALUE\n'
                      'icm/HTTP/admin_0,"PREFIX=/sap/admin,CLIENTHOST=10.0.0.1,PORT=8443"\n')
    unquoted = _run_csv("NAME,VALUE\n"
                        "icm/HTTP/admin_0,PREFIX=/sap/admin,CLIENTHOST=10.0.0.1,PORT=8443\n")
    assert _ids(quoted) == _ids(unquoted)


def test_a_genuinely_unrestricted_admin_handler_is_still_reported():
    """The recovery must not swallow the real finding along with the false one."""
    findings = _run_csv('NAME,VALUE\n'
                        'icm/HTTP/admin_0,"PREFIX=/sap/admin,DOCROOT=/usr/sap"\n')
    assert "WDISP-011" in _ids(findings)


def test_the_recovered_value_is_shown_whole_in_the_evidence():
    """A finding quoting a truncated value invites the reader to conclude the
    scanner misread the file — which, before the recovery, it had."""
    findings = _run_csv("NAME,VALUE\n"
                        "icm/server_port_0,PROT=HTTP,PORT=8000,TIMEOUT=60\n")
    item = [f for f in findings if f["check_id"] == "WDISP-014"][0]
    assert "PROT=HTTP,PORT=8000,TIMEOUT=60" in item["affected_items"][0]


# ═════════════════════════════════════════════════════════════════════════════
#  Absent is not non-compliant
# ═════════════════════════════════════════════════════════════════════════════

def test_an_unset_parameter_is_not_a_finding():
    """A profile lists what was SET. An unset parameter takes SAP's default,
    which no export tells us, and reporting it would fabricate a value."""
    findings = _run(**{"icm/max_conn": "500"})
    assert "WDISP-001" not in _ids(findings)
    assert "WDISP-005" not in _ids(findings)


def test_the_missing_https_listener_is_the_one_absence_that_does_report():
    """"No icm/server_port_* serving HTTPS anywhere in this profile" is a
    statement the profile does make, which is why SAP's rule is written that
    way and why this rule alone sets report_when_absent."""
    assert "WDISP-014" in _ids(_run(**{"icm/max_conn": "500"}))
    rules = {r["check_id"]: r for r in load()["rules"]}
    assert rules["WDISP-014"].get("report_when_absent") is True
    assert [c for c, r in rules.items() if r.get("report_when_absent")] == ["WDISP-014"]


def test_one_https_listener_satisfies_the_rule_even_beside_plain_ones():
    """SAP asks whether ANY listener serves HTTPS, not whether all do. Reporting
    the plain listeners here would be our argument wearing SAP's check id."""
    findings = _run(**{"icm/server_port_0": "PROT=HTTP,PORT=8000",
                       "icm/server_port_1": "PROT=HTTPS,PORT=8443"})
    assert "WDISP-014" not in _ids(findings)


# ═════════════════════════════════════════════════════════════════════════════
#  The rules are SAP's
# ═════════════════════════════════════════════════════════════════════════════

def test_every_rule_cites_the_sap_check_it_was_transcribed_from():
    """Section 3.3's argument: deriving from an SAP-authored predicate cannot
    invent a parameter name, and hand-authoring can. The citation is what makes
    the transcription checkable rather than trusted."""
    for rule in load()["rules"]:
        assert rule.get("policy") in ("2ODISCL", "2ONETENC"), rule["check_id"]
        assert rule.get("sap_check_id"), rule["check_id"]
        assert len(rule.get("sap_predicate", "")) > 30, rule["check_id"]


def test_every_rule_names_the_parameter_inside_its_own_predicate():
    """A transcription error that pointed a rule at a different parameter would
    be invisible: the check would run, pass or fail, and cite a predicate about
    something else."""
    for rule in load()["rules"]:
        target = rule.get("name") or rule.get("name_prefix")
        assert target in rule["sap_predicate"], rule["check_id"]


def test_the_finding_carries_sap_s_predicate_so_a_customer_argues_with_sap():
    findings = _run(**{"is/HTTP/show_server_header": "TRUE"})
    f = [x for x in findings if x["check_id"] == "WDISP-001"][0]
    assert f["details"]["sap_check_id"] == "DISCL-O_a.1"
    assert "is/HTTP/show_server_header" in f["details"]["sap_predicate"]
    assert "2ODISCL" in " ".join(f["references"])


def test_the_two_unimplemented_sap_checks_are_recorded_with_reasons():
    """A refusal with no record gets re-opened by the next person. Both are
    listed with why, rather than quietly absent."""
    skipped = load()["_meta"]["_not_implemented"]
    ids = {s["sap_check_id"] for s in skipped}
    assert ids == {"DISCL-O_a.2", "1OSECUPD"}
    for entry in skipped:
        assert len(entry["reason"]) > 80, entry["sap_check_id"]


def test_the_content_file_records_where_it_came_from():
    meta = load()["_meta"]
    src = meta["source"]
    assert src["licence"] == "Apache-2.0"
    assert "frun-csa-policies-best-practices" in src["repository"]
    assert "WEBDISP_ALL" in src["path"]
    assert src["files"]


def test_an_unreadable_content_file_leaves_the_dispatcher_unaudited_not_misaudited():
    """The right failure is where we were, not a partial ruleset presented as
    complete."""
    import modules.webdisp_security as mod
    mod._CACHE = None
    try:
        assert load(ROOT / "data" / "nope.json")["rules"] == []
    finally:
        mod._CACHE = None


# ═════════════════════════════════════════════════════════════════════════════
#  Coverage, and per-listener reporting
# ═════════════════════════════════════════════════════════════════════════════

def test_no_profile_degrades_coverage_rather_than_passing():
    """Every other module in a scan describes a system BEHIND the dispatcher.
    Silence about the dispatcher, in a report that lists what it did examine,
    reads as though it was examined."""
    findings = WebDispatcherAuditor({}, {}, {}).run_all_checks()
    assert _ids(findings) == {"WDISP-COV-001"}
    assert findings[0]["details"]["degrades_coverage"] is True


def test_the_coverage_note_admits_the_landscape_might_have_no_dispatcher():
    """Otherwise it is an unanswerable finding on every estate without one."""
    f = WebDispatcherAuditor({}, {}, {}).run_all_checks()[0]
    assert "no Web Dispatcher" in f["description"]
    assert "service request" in f["description"]


def test_two_admin_listeners_are_two_offenders_not_one():
    """icm/HTTP/admin_0 and admin_1 are two listeners. Collapsing them would hide
    that the second is exposed, and closing the finding would close both."""
    findings = _run(**{"icm/HTTP/admin_0": "PREFIX=/a",
                       "icm/HTTP/admin_1": "PREFIX=/b"})
    f = [x for x in findings if x["check_id"] == "WDISP-011"][0]
    assert len(f["affected_items"]) == 2
    assert {o["name"] for o in f["affected_objects"]} == {"icm/HTTP/admin_0",
                                                          "icm/HTTP/admin_1"}


@pytest.mark.parametrize("check_id,params", [
    ("WDISP-001", {"is/HTTP/show_server_header": "TRUE"}),
    ("WDISP-002", {"is/HTTP/show_detailed_errors": "TRUE"}),
    ("WDISP-004", {"login/show_detailed_errors": "1"}),
    ("WDISP-005", {"rdisp/TRACE_HIDE_SEC_DATA": "off"}),
    ("WDISP-007", {"icm/accept_forwarded_cert_via_http": "TRUE"}),
    ("WDISP-008", {"service/protectedwebmethods": "NONE"}),
    ("WDISP-009", {"wdisp/permission_table": "   "}),
    ("WDISP-013", {"icm/trusted_reverse_proxy_0": 'SUBJECT="*", ISSUER="*"'}),
])
def test_each_rule_fires_on_its_own_violation(check_id, params):
    assert check_id in _ids(_run(**params))


@pytest.mark.parametrize("check_id,params", [
    ("WDISP-001", {"is/HTTP/show_server_header": "FALSE"}),
    ("WDISP-005", {"rdisp/TRACE_HIDE_SEC_DATA": "on"}),
    ("WDISP-008", {"service/protectedwebmethods": "SDEFAULT"}),
    ("WDISP-009", {"wdisp/permission_table": "/usr/sap/WD1/permissions.txt"}),
    ("WDISP-013", {"icm/trusted_reverse_proxy_0": 'SUBJECT="CN=proxy", ISSUER="CN=ca"'}),
])
def test_a_compliant_value_raises_nothing(check_id, params):
    assert check_id not in _ids(_run(**params))


def test_the_sample_profile_exercises_the_module_end_to_end():
    import contextlib
    from modules.data_loader import DataLoader
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(ROOT / "sample_data").load_all()
    findings = WebDispatcherAuditor(data, {}, {}).run_all_checks()
    assert findings and "WDISP-COV-001" not in _ids(findings)
    assert "WDISP-014" in _ids(findings)
