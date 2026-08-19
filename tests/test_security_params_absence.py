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
    # 42 -> 43 when abap/path_normalization joined the legacy table to close SAP
    # Baseline requirement FILE-A. The number moves whenever the rule set does;
    # what must not move is that EVERY absent parameter is named by one of the
    # two roll-ups, which is what this compares against.
    assert named == 43, f"{named} of the 43 absent parameters are named"


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


# --------------------------------------------------------------------------- #
#  Completeness — the input that lets absence mean something                  #
# --------------------------------------------------------------------------- #
#  Absence has two causes the file cannot tell apart: the setting is not there,
#  or the export did not ask. The guide offers RZ11 — one parameter at a time —
#  as an equal route to RSPARAM, so the second is the documented workflow, not an
#  edge case. `export_completeness.json` is where somebody states that a source
#  IS the whole list, which turns absence within it into an observation.
#
#  It is a DECLARATION, never a proof, and every test below is about keeping that
#  distinction visible rather than letting it quietly become a fact.

import contextlib                                                     # noqa: E402
import csv                                                            # noqa: E402
import io                                                             # noqa: E402
import json                                                           # noqa: E402

from modules.data_loader import DataLoader                            # noqa: E402

DECL = {"complete_sources": ["security_params"],
        "declared_by": "basis@acme.example", "declared_at": "2026-08-11",
        "method": "RSPARAM, full list, no name filter"}


def _load(tmp_path, rows, declaration=None):
    with (tmp_path / "security_params.csv").open("w", encoding="utf-8",
                                                 newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(("NAME", "VALUE"))
        for name, value in rows:
            writer.writerow((name, value))
    if declaration is not None:
        (tmp_path / "export_completeness.json").write_text(
            json.dumps(declaration), encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()):
        return DataLoader(tmp_path).load_all()


def _unset(findings):
    return [f for f in findings
            if f.get("details", {}).get("observed") == "not_set"]


def test_without_a_declaration_absence_is_disclosed_not_judged(tmp_path):
    """Today's behaviour, and it must survive: nobody has said the export is the
    whole list, so a missing parameter still means nothing."""
    data = _load(tmp_path, [("login/min_password_lng", "15")])
    findings = SecurityParamAuditor(data, {}).run_all_checks()
    assert not _unset(findings)
    assert [f for f in findings if "MISSING" in f["check_id"]], \
        "absence was neither judged nor disclosed"


def test_with_a_declaration_absence_becomes_a_verdict(tmp_path):
    """The unlock, and note what it does NOT need: no SAP default value. The
    claim is "the baseline requires this to be set, and it is not set", which is
    true whatever SAP ships it as."""
    data = _load(tmp_path, [("login/min_password_lng", "15")], DECL)
    findings = SecurityParamAuditor(data, {}).run_all_checks()
    assert _unset(findings), \
        "a declared-complete export still disclosed instead of judging"
    assert not [f for f in findings if "MISSING" in f["check_id"]], \
        "both the verdicts and the roll-up were raised; absence reported twice"


def test_the_verdict_names_the_declaration_it_rests_on(tmp_path):
    """Nothing verifies the declaration. Naming it is what makes a WRONG one
    diagnosable from the report, instead of leaving the reader a confident
    finding with no way to tell where it came from."""
    data = _load(tmp_path, [("login/min_password_lng", "15")], DECL)
    finding = _unset(SecurityParamAuditor(data, {}).run_all_checks())[0]
    assert finding["details"]["rests_on_declaration"] is True
    assert finding["details"]["declared_by"] == "basis@acme.example"
    assert "rests on that declaration" in finding["description"]
    assert "export_completeness.json" in finding["description"], \
        "the reader is not told which file to correct"


def test_an_unset_parameter_shares_identity_with_a_wrongly_set_one(tmp_path):
    """Same check_id, deliberately. Setting a previously-absent parameter to a
    still non-compliant value is PROGRESS, and a separate id would retire one
    finding and raise another — reporting the improvement as a brand-new problem
    with its age reset to zero."""
    target = "PARAM-login/password_expiration_time"

    absent = _load(tmp_path, [("login/min_password_lng", "15")], DECL)
    unset = next(f for f in SecurityParamAuditor(absent, {}).run_all_checks()
                 if f["check_id"] == target)

    later = tmp_path / "later"
    later.mkdir()
    now_wrong = _load(later, [("login/min_password_lng", "15"),
                              ("login/password_expiration_time", "0")], DECL)
    wrong = next(f for f in SecurityParamAuditor(now_wrong, {}).run_all_checks()
                 if f["check_id"] == target)

    assert unset["check_id"] == wrong["check_id"]
    assert unset["affected_objects"] == wrong["affected_objects"], \
        "the finding's identity moves when an absent parameter is finally set"


def test_a_source_not_listed_in_the_declaration_stays_unknown(tmp_path):
    """A declaration about one source says nothing about another."""
    data = _load(tmp_path, [("login/min_password_lng", "15")],
                 {"complete_sources": ["users"], "declared_by": "x"})
    assert not _unset(SecurityParamAuditor(data, {}).run_all_checks())


@pytest.mark.parametrize("junk", [
    ["not", "an", "object"],
    {"no_complete_sources_key": True},
    {"complete_sources": "security_params"},
])
def test_a_malformed_declaration_leaves_completeness_unknown(tmp_path, junk):
    """It must fail towards disclosure. A malformed file read as "complete" would
    turn every absent parameter into a confident verdict on the strength of a
    file nobody could parse."""
    data = _load(tmp_path, [("login/min_password_lng", "15")], junk)
    assert data.get("_export_completeness") is None
    assert not _unset(SecurityParamAuditor(data, {}).run_all_checks())


def test_the_declaration_is_not_a_logical_source():
    """It must never appear in the coverage manifest as something the customer
    forgot to send — it is metadata about an export, not an export."""
    from server import coverage
    assert "_export_completeness" not in coverage.all_logical_sources()
    for module, needs in coverage.module_sources().items():
        assert "_export_completeness" not in needs, module


def test_the_connector_declares_only_what_it_actually_read(tmp_path):
    """Declaring completeness on the strength of a call that returned nothing
    would assert that a system has no parameters — never true of an ABAP
    instance — and would turn every rule into a confident "not set"."""
    from collect import extract
    assert extract.declare_complete(tmp_path, [], declared_by="x", method="y",
                                    when="z") is None
    assert not (tmp_path / "export_completeness.json").exists()

    path = extract.declare_complete(tmp_path, ["security_params"],
                                    declared_by="collect/sapcontrol",
                                    method="ParameterValue, no argument",
                                    when="2026-08-11T00:00:00+00:00")
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["complete_sources"] == ["security_params"]
    assert "coverage disclosures again" in payload["read_this"], \
        "the file does not tell the reader how to undo the claim"


def test_what_the_connector_writes_is_what_the_loader_reads(tmp_path):
    """The two halves must agree, or the connector declares completeness into a
    void and the scanner keeps disclosing."""
    from collect import extract
    extract.declare_complete(tmp_path, ["security_params"],
                             declared_by="collect/sapcontrol",
                             method="ParameterValue, no argument", when="t")
    data = _load(tmp_path, [("login/min_password_lng", "15")])
    auditor = SecurityParamAuditor(data, {})
    assert auditor.absence_is_observable("security_params") is True
    assert auditor.export_completeness("security_params")["declared_by"] \
        == "collect/sapcontrol"


def test_a_wrong_declaration_is_undone_by_deleting_one_file(tmp_path):
    """The escape hatch has to be obvious, because the declaration is the one
    input that converts disclosures into accusations. If it is wrong, a customer
    must be able to undo every finding built on it in a single step."""
    data = _load(tmp_path, [("login/min_password_lng", "15")], DECL)
    assert _unset(SecurityParamAuditor(data, {}).run_all_checks())

    (tmp_path / "export_completeness.json").unlink()
    with contextlib.redirect_stdout(io.StringIO()):
        again = DataLoader(tmp_path).load_all()
    assert not _unset(SecurityParamAuditor(again, {}).run_all_checks())


# --------------------------------------------------------------------------- #
#  The system's own defaults, rather than a table of SAP facts                #
# --------------------------------------------------------------------------- #
#  It was proposed that this repository carry SAP's documented default values so
#  an unset parameter could be judged. That is NOT what was built, for two
#  reasons that are worth keeping written down:
#
#    1. It would have meant importing ~59 SAP facts that are not here, which the
#       project's own rules forbid without citable provenance.
#    2. It would have been WRONG more often than it looked. A default varies by
#       release and by kernel patch, so one recorded value cannot be right for
#       every system — and a wrong default produces a confident finding about a
#       system that is fine.
#
#  RSPARAM already prints the actual default for the system in front of you,
#  beside a user-value column it leaves BLANK when the parameter is at that
#  default. Reading it invents nothing and is more accurate than any table.

def test_a_parameter_at_its_kernel_default_is_read_as_that_value(tmp_path):
    """Before this, the blank user-value column was read as the literal empty
    string: `login/min_password_lng = `. Wrong about the value, and wrong about
    the system."""
    rows = [{"NAME": "login/min_password_lng", "VALUE": "",
             "DEFAULT_VALUE": "6"}]
    assert BaseAuditor.param_lookup(rows) == {"login/min_password_lng": "6"}


def test_a_compliant_default_no_longer_produces_a_false_positive():
    """The case that made this a correctness fix rather than a cosmetic one. A
    parameter left at a default that MEETS the baseline was being reported as
    non-compliant with an empty value."""
    rows = [{"NAME": "login/min_password_lng", "VALUE": "", "DEFAULT_VALUE": "15"}]
    findings = SecurityParamAuditor({"security_params": rows}, {}).run_all_checks()
    assert not [f for f in findings
                if f["check_id"] == "PARAM-login/min_password_lng"]


def test_the_finding_says_when_a_value_came_from_the_default():
    """At-default and set-to-that-value are different facts with different fixes:
    one is "change it", the other is "set it at all" — and a profile that never
    names the parameter drifts the next time SAP changes the default."""
    rows = [{"NAME": "login/min_password_lng", "VALUE": "", "DEFAULT_VALUE": "6"}]
    f = next(x for x in SecurityParamAuditor({"security_params": rows}, {}).run_all_checks()
             if x["check_id"] == "PARAM-login/min_password_lng")
    assert "kernel default" in f["affected_items"][0]
    assert "not set in any profile" in f["affected_items"][0]


def test_an_explicitly_set_value_is_not_labelled_a_default():
    rows = [{"NAME": "login/min_password_lng", "VALUE": "6", "DEFAULT_VALUE": "6"}]
    f = next(x for x in SecurityParamAuditor({"security_params": rows}, {}).run_all_checks()
             if x["check_id"] == "PARAM-login/min_password_lng")
    assert "kernel default" not in f["affected_items"][0]


def test_without_a_default_column_nothing_changes(tmp_path):
    """The substitution is narrow on purpose. An empty value that is genuinely
    present IS a real answer — `gw/sec_info` with nothing after the comma is the
    unset ACL and must keep firing — so with no default column the old behaviour
    must be untouched."""
    assert BaseAuditor.param_lookup([{"NAME": "gw/sec_info", "VALUE": ""}]) \
        == {"gw/sec_info": ""}
    assert BaseAuditor.param_provenance([{"NAME": "gw/sec_info", "VALUE": ""}]) \
        == {"gw/sec_info": BaseAuditor.PARAM_SET}


def test_no_table_of_sap_defaults_was_introduced():
    """THE LINE THIS WORK DID NOT CROSS, again. The defaults used are the
    system's own, read from the export. If a documented-default table ever
    appears it needs citable provenance per value — the shape
    data/ecs_hardening_3250501.json uses — and this test should be replaced by
    one asserting it."""
    import json
    from pathlib import Path as _P
    for path in sorted((ROOT / "data").glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        text = json.dumps(payload)
        assert '"sap_default"' not in text and '"kernel_default"' not in text, \
            f"{path.name} has grown a default-value table without provenance"


def test_provenance_is_reported_separately_from_the_value():
    """Adding provenance must not have changed what any existing caller of
    param_lookup receives — the two are separate functions for that reason."""
    rows = [{"NAME": "p", "VALUE": "15", "DEFAULT_VALUE": "6"}]
    assert BaseAuditor.param_lookup(rows) == {"p": "15"}
    assert BaseAuditor.param_provenance(rows) == {"p": BaseAuditor.PARAM_SET}
