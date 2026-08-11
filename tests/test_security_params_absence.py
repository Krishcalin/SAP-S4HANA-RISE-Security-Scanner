# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""What the parameter modules do when the export does not tell them something.

PHASE 3 DID NOT BUILD WHAT THE PLAN ASKED FOR, AND THIS FILE RECORDS WHY.

The plan proposed judging an absent parameter against SAP's documented default,
on the reasoning that an unset parameter takes its default and SAP's defaults are
insecure. That was not built. Five reasons, each verified against this repository:

  1. There are ZERO SAP default values here. The 78 parameter rules carry
     `expected`, `allowed` and `ecs` — what a parameter SHOULD be — and no
     `default` field. `data/ecs_hardening_3250501.json` records the note's
     MANDATED values, not what SAP ships. Building the fix meant supplying ~59
     SAP facts that do not exist in this repository, which is the fabrication the
     project's own rules forbid.
  2. CLAUDE.md states the opposite convention verbatim: "Fire only on
     present-and-risky … absence != secure/insecure."
  3. So does the code, on the very line the plan proposed to delete —
     `baseline_params.py`: `return  # absent != insecure; self-skip`.
  4. The export guide offers RZ11, a SINGLE-parameter transaction, as an equal
     route to RSPARAM. Absence is therefore ambiguous by construction, and
     re-exporting by a different route would make up to 42 of 78 findings appear
     or disappear with no system change — all classed `new`, all blocking the
     release gate.
  5. The plan's arithmetic was wrong: one skip site in `security_params`, not
     eight, governing all 78 rules.

What WAS built is the honest half of the same intent: absence is reported rather
than passed over, as coverage rather than as a verdict. Nothing here asserts a
single new fact about SAP.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.base_auditor import BaseAuditor                          # noqa: E402
from modules.baseline_params import BaselineParamAuditor              # noqa: E402
from modules.security_params import SecurityParamAuditor              # noqa: E402


# --------------------------------------------------------------------------- #
#  A — the false positive on a COMPLIANT system                               #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("value_column",
                         ["VALUE", "PARAM_VALUE", "CURRENT_VALUE", "VAL"])
def test_a_compliant_system_is_silent_whatever_the_column_is_called(value_column):
    """THE LIVE BUG THIS FILE OPENED WITH.

    `service/protectedwebmethods = SDEFAULT` is the hardened value. Before the
    fix, an export spelling the column CURRENT_VALUE — which `security_params`
    documents as supported — produced:

        BASELINE-006  HIGH  'service/protectedwebmethods = '

    A HIGH finding against a correctly configured system, assembled entirely from
    a column-spelling mismatch: `baseline_params` read VALUE/PARAM_VALUE/VAL, its
    sibling read VALUE/PARAM_VALUE/CURRENT_VALUE, and the unreadable value was
    stored as "" rather than treated as absent. CLAUDE.md's criterion is that a
    compliant system must be silent.
    """
    export = [{"NAME": "service/protectedwebmethods", value_column: "SDEFAULT"}]
    findings = BaselineParamAuditor({"security_params": export}, {}).run_all_checks()
    offenders = [f for f in findings if f["check_id"] == "BASELINE-006"]
    assert not offenders, (
        f"a compliant system was accused via the {value_column} spelling: "
        f"{[f['affected_items'] for f in offenders]}")


def test_a_genuinely_unprotected_value_still_fires():
    """The fix must not have bought silence by breaking the check."""
    export = [{"NAME": "service/protectedwebmethods", "CURRENT_VALUE": "NONE"}]
    findings = BaselineParamAuditor({"security_params": export}, {}).run_all_checks()
    assert any(f["check_id"] == "BASELINE-006" for f in findings)


def test_both_modules_read_the_export_through_one_implementation():
    """A rule that must hold for two modules belongs to neither of them.

    The drift WAS the bug, so a copy is not an acceptable fix — the two
    vocabularies would part again on the next spelling somebody added.
    """
    assert BaselineParamAuditor._param_index is not None
    a = BaseAuditor.param_lookup([{"NAME": "x", "CURRENT_VALUE": "1"}])
    b = SecurityParamAuditor._param_lookup([{"NAME": "x", "CURRENT_VALUE": "1"}])
    assert a == b == {"x": "1"}
    src = (ROOT / "modules" / "baseline_params.py").read_text(encoding="utf-8")
    assert "param_lookup" in src, \
        "baseline_params has stopped using the shared reader"


def test_an_unreadable_value_column_is_absent_not_empty():
    """Defaulting to "" reads "this export does not tell us" as "this parameter
    is empty" — and empty IS a finding for gw/sec_info, ms/acl_info and
    service/admin_users. An unrecognised spelling would produce a page of
    confident accusations built from nothing."""
    lookup = BaseAuditor.param_lookup([{"NAME": "gw/sec_info", "MYSTERY": "x"}])
    assert lookup == {}, "a row with no recognised value column was given a value"


def test_an_empty_value_that_is_actually_present_stays_a_real_answer():
    """`gw/sec_info` with nothing after the comma is the unset ACL, and must keep
    firing. The fix must not turn a real empty into an absence."""
    assert BaseAuditor.param_lookup(
        [{"NAME": "gw/sec_info", "VALUE": ""}]) == {"gw/sec_info": ""}


def test_a_malformed_export_does_not_take_the_scan_down():
    for junk in (None, 42, "not a list", [None, 7, {"no": "name"}]):
        assert BaseAuditor.param_lookup(junk) == {}


# --------------------------------------------------------------------------- #
#  B — the module that said nothing at all                                    #
# --------------------------------------------------------------------------- #

def test_a_missing_export_is_reported_rather_than_passed_over():
    """It returned an empty list. Twelve checks over eighteen parameters did not
    run and nothing anywhere said so — while the sibling module reading the SAME
    file raises PARAM-000 for the same condition. One report, two doctrines, and
    the quieter one won by producing no evidence of itself."""
    findings = BaselineParamAuditor({}, {}).run_all_checks()
    assert findings, "no profile export still produces total silence"
    f = findings[0]
    assert f["check_id"] == "BASELINE-000"
    assert f["severity"] == "INFO", "a coverage gap is not a vulnerability"
    assert f["details"]["degrades_coverage"] is True
    assert "not a verdict on the system" in f["description"]
    # It must NAME them: "twelve checks did not run" is not actionable, and a
    # customer cannot re-export what nobody names.
    assert len(f["affected_items"]) == len(BaselineParamAuditor.JUDGED_PARAMETERS)
    assert "snc/accept_insecure_rfc" in f["affected_items"]


def test_the_six_parameters_no_other_module_covers_are_named():
    """Four `snc/accept_insecure_*` are deliberately excluded from
    security_params' rule set, and two more are MEDIUM/LOW so its PARAM-MISSING
    roll-up skips them. For those six the silence was total — nothing anywhere
    mentioned them when absent."""
    named = set(BaselineParamAuditor.JUDGED_PARAMETERS)
    for p in ("snc/accept_insecure_rfc", "snc/accept_insecure_gui",
              "snc/accept_insecure_cpic", "snc/accept_insecure_r3int_rfc",
              "icm/security_log", "is/HTTP/show_detailed_errors"):
        assert p in named, f"{p} is covered by nothing when absent"


def test_a_supplied_export_does_not_produce_the_coverage_finding():
    """The gap finding must appear only when there is a gap."""
    export = [{"NAME": "service/protectedwebmethods", "VALUE": "SDEFAULT"}]
    findings = BaselineParamAuditor({"security_params": export}, {}).run_all_checks()
    assert not [f for f in findings if f["check_id"] == "BASELINE-000"]


# --------------------------------------------------------------------------- #
#  D — the fall-through that accused                                          #
# --------------------------------------------------------------------------- #

def test_an_unknown_operator_is_silent_rather_than_an_accusation():
    """It returned False, which the caller reads as "does not pass" and turns
    into a finding — so a typo'd `op` fired on EVERY system carrying that
    parameter. Five is inside one-to-nine; the verdict came from the operator
    being unknown, not from the value being wrong."""
    assert SecurityParamAuditor._rule_passes(
        {"op": "range", "expected": "1 to 9"}, "5") is True


def test_an_unknown_operator_does_not_raise_either():
    """Raising was the first attempt at this fix and it was worse: `_rule_passes`
    calls the evaluator outside any try/except and the runner skips a raising
    module, so one typo would have cost the customer EVERY parameter finding.
    Trading a false positive for a silent total loss is not an improvement."""
    findings = SecurityParamAuditor(
        {"security_params": [{"NAME": "login/min_password_lng", "VALUE": "15"}]},
        {"param.login/min_password_lng": {"op": "range", "expected": "1 to 9"}},
    ).run_all_checks()
    assert isinstance(findings, list)


def test_every_shipped_rule_uses_an_operator_the_evaluator_knows():
    """WHERE THE PROGRAMMING ERROR IS CAUGHT INSTEAD.

    The evaluator is silent on an unknown operator so it cannot accuse anyone;
    this is what stops that silence hiding a broken rule. A new operator fails CI
    rather than a customer's report.
    """
    rules = SecurityParamAuditor({}, {}).effective_rules()
    bad = {n: r["op"] for n, r in rules.items()
           if r.get("op") and r["op"] not in SecurityParamAuditor._KNOWN_OPS}
    assert not bad, f"rules use operators the evaluator cannot evaluate: {bad}"


def test_a_non_numeric_value_under_a_numeric_operator_still_fails():
    """The one case where the wrong shape IS the finding: the parameter really is
    not a number that can satisfy the comparison."""
    assert SecurityParamAuditor._rule_passes({"op": ">=", "expected": "8"},
                                             "abc") is False


# --------------------------------------------------------------------------- #
#  The boundary — what was deliberately NOT done                              #
# --------------------------------------------------------------------------- #

def test_no_sap_default_value_has_been_introduced():
    """THE LINE PHASE 3 DID NOT CROSS.

    Judging an absent parameter requires knowing what SAP ships it as, and this
    repository records that for zero of its 78 rules. Adding those values is new
    SAP-sourced content with citable provenance — the shape
    `data/ecs_hardening_3250501.json` uses, with `source.note`, `source.version`
    and `source.obtained` — not a code change. Until then, absence is reported as
    a gap and never as a verdict.
    """
    rules = SecurityParamAuditor({}, {}).effective_rules()
    with_default = {n: r for n, r in rules.items()
                    if any(k in r for k in ("default", "sap_default",
                                            "shipped_default"))}
    assert not with_default, (
        "a default value appeared in the rule table. If it is sourced and cited, "
        "this test should be replaced by one asserting its provenance — and the "
        "absence handling above can then judge rather than disclose.")


def test_absence_is_still_not_treated_as_insecure():
    """CLAUDE.md: "Fire only on present-and-risky … absence != secure/insecure."
    A parameter absent from the export must not produce a non-compliance finding
    for that parameter."""
    # One parameter present and GENUINELY non-compliant, so there is a real
    # accusation to inspect, while 77 others are absent. If the absent ones were
    # being judged, they would appear here too — with no observed value to show.
    export = [{"NAME": "login/min_password_lng", "VALUE": "6"}]
    findings = SecurityParamAuditor({"security_params": export}, {}).run_all_checks()
    # The roll-ups are DISCLOSURES about the export, not accusations about a
    # parameter, so they are excluded by name. They are also the reason this
    # filter cannot be "starts with PARAM-": PARAM-MISSING-OTHER does, and it is
    # the very finding that exists to report absence honestly.
    ROLLUPS = {"PARAM-000", "PARAM-MISSING", "PARAM-MISSING-OTHER"}
    accusations = [f for f in findings
                   if f["check_id"].startswith("PARAM-")
                   and f["check_id"] not in ROLLUPS]
    assert accusations, "no per-parameter findings at all; the test proves nothing"
    for f in accusations:
        assert "= " in " ".join(f["affected_items"]), \
            f"{f['check_id']} accused without an observed value: {f['affected_items']}"


# --------------------------------------------------------------------------- #
#  C — the 48 rules the roll-up never mentioned                               #
# --------------------------------------------------------------------------- #

def _ecc_findings():
    import contextlib, io
    from modules.data_loader import DataLoader
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(ROOT / "sample_data_ecc").load_all()
    return SecurityParamAuditor(data, {}).run_all_checks()


def test_every_absent_parameter_is_now_named_somewhere():
    """PARAM-MISSING covered only CRITICAL and HIGH — 30 of 78 rules — so 48 were
    never mentioned when absent, by anything. On the shipped ECC fixture that was
    34 parameters about which the report said precisely nothing, which reads
    exactly like 34 parameters that were checked and passed."""
    findings = {f["check_id"]: f for f in _ecc_findings()}
    high = findings.get("PARAM-MISSING")
    info = findings.get("PARAM-MISSING-OTHER")
    assert high and info, "one of the two absence roll-ups is missing"
    named = len(high["affected_items"]) + len(info["affected_items"])
    assert named == 42, f"{named} of the 42 absent parameters are named"


def test_the_further_parameters_finding_is_a_disclosure_not_a_verdict():
    info = {f["check_id"]: f for f in _ecc_findings()}["PARAM-MISSING-OTHER"]
    assert info["severity"] == "INFO", \
        "a statement about the export is not a vulnerability"
    assert info["details"]["degrades_coverage"] is True
    assert "not a pass" in info["description"]
    # It must not claim to know what the values are.
    for word in ("insecure", "non-compliant", "violation"):
        assert word not in info["description"].lower(), \
            f"the disclosure asserts {word!r} about parameters it never saw"


def test_the_two_rollups_do_not_double_count():
    """A parameter in both would be reported twice and counted twice."""
    findings = {f["check_id"]: f for f in _ecc_findings()}
    a = {i.split(" (")[0] for i in findings["PARAM-MISSING"]["affected_items"]}
    b = {i.split(" (")[0] for i in findings["PARAM-MISSING-OTHER"]["affected_items"]}
    assert not (a & b), f"reported by both roll-ups: {sorted(a & b)}"


def test_a_compliant_ecs_system_stays_silent_on_both_rollups():
    """The criterion the ECS scoping exists for: an export containing every
    mandated parameter is a compliant system, and a compliant system must be
    silent. Widening the roll-up must not have broken that."""
    rules = SecurityParamAuditor({}, {}).effective_rules()
    export = [{"NAME": n, "VALUE": "x"} for n in rules]
    findings = SecurityParamAuditor(
        {"security_params": export}, {}, {"deployment_mode": "rise_pce"}
    ).run_all_checks()
    assert not [f for f in findings if "MISSING" in f["check_id"]]


def test_the_further_parameters_finding_keeps_its_age_as_the_export_improves():
    """Members stay out of identity. Exporting one more parameter shrinks the list
    without closing the gap, so folding members into identity would retire the
    finding and raise a new one with its age reset — every time somebody made
    things slightly better."""
    from server.identity import compute_fingerprint
    findings = {f["check_id"]: f for f in _ecc_findings()}
    info = findings["PARAM-MISSING-OTHER"]
    assert info["scope"] == "aggregate"
    a, _ = compute_fingerprint("PARAM-MISSING-OTHER", "PRD", "100",
                               info.get("subject"), info["affected_items"],
                               "aggregate")
    b, _ = compute_fingerprint("PARAM-MISSING-OTHER", "PRD", "100",
                               info.get("subject"), info["affected_items"][:-5],
                               "aggregate")
    assert a == b, "the finding's identity moves when the export improves"
