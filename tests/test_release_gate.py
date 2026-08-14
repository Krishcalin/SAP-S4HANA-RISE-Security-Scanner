# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
The release gate: the step that makes this a control rather than a report.

WHAT THESE TESTS ARE REALLY ABOUT
Gates get switched off. Every test here corresponds to one of the specific ways
that happens — it fails on a backlog nobody introduced, it demands a fix the
developer cannot make, it blocks on a rule that was wrong, or (worst) it goes
green on a scan that could not see the code. The rules in `modules/release_gate.py`
exist to prevent those four outcomes and these tests hold them in place.

`test_a_degraded_scan_can_never_pass` is the one that matters most. A gate that
fails OPEN is worse than no gate: the build goes through, the report looks clean,
and it happens automatically on every build until somebody notices.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import release_gate as rg                              # noqa: E402


def finding(check_id="ABAP-SQLI-001", severity="CRITICAL", obj="ZCL_A",
            confidence="confirmed", owner="customer_fixable", qualifier="q"):
    return {
        "check_id": check_id,
        "title": f"{check_id} in {obj}",
        "severity": severity,
        "remediation_owner": owner,
        "details": {"confidence": confidence},
        "subject": [{"type": "program", "name": obj, "qualifier": qualifier}],
        "affected_items": [f"{obj}: something"],
    }


# --------------------------------------------------------------------------- #
#  Rule 4 — never fail open                                                   #
# --------------------------------------------------------------------------- #

def test_a_degraded_scan_can_never_pass():
    """THE ONE THAT MATTERS MOST.

    "We found nothing" and "we could not look" must never produce the same exit
    code. A mis-lexed ABAP file that yields a green pipeline is a lie told
    automatically, on every build, until somebody notices.
    """
    result = rg.evaluate([], degraded=True,
                         degraded_detail="2 statement(s) ran past the runaway bound.")
    assert result.decision == "cannot_assess"
    assert result.exit_code == rg.EXIT_CANNOT_ASSESS
    assert "cannot support a pass" in " ".join(result.reasons)


def test_degraded_coverage_is_checked_before_any_finding_is_looked_at():
    """Even a completely clean finding set cannot rescue a scan that did not run
    properly — the check is first, not a tie-breaker."""
    result = rg.evaluate([finding(severity="INFO")], degraded=True)
    assert result.decision == "cannot_assess"


def test_an_unreadable_policy_is_cannot_assess_not_pass(tmp_path):
    """A typo in a config file must not quietly disarm the gate."""
    bad = tmp_path / "policy.json"
    bad.write_text('{"max_new": {"CRITICAL": 0}, "max_nwe": {}}', encoding="utf-8")
    with pytest.raises(ValueError, match="unknown gate policy key"):
        rg.load_policy(bad)


def test_a_partial_policy_cannot_switch_off_the_keys_it_omits(tmp_path):
    """Merged over the defaults, not replacing them. Fail-open by omission is
    still fail-open."""
    p = tmp_path / "policy.json"
    p.write_text('{"max_new": {"HIGH": 5}}', encoding="utf-8")
    policy = rg.load_policy(p)
    assert policy["block_on_degraded_coverage"] is True
    assert policy["max_new"] == {"HIGH": 5}


# --------------------------------------------------------------------------- #
#  Rule 1 — judge the delta, not the backlog                                  #
# --------------------------------------------------------------------------- #

def test_an_existing_backlog_does_not_block_a_change_that_did_not_cause_it():
    """The reason gates get disabled in week one: red on the first run, on a
    change that introduced none of it."""
    backlog = [finding(obj=f"ZCL_{i}") for i in range(5)]
    baseline = set(rg.write_baseline(backlog)["fingerprints"])
    result = rg.evaluate(backlog, baseline=baseline)
    assert result.decision == "pass"
    assert result.new_total == 0


def test_a_newly_introduced_critical_does_block():
    """The control. Ignoring the backlog is only correct if new problems still
    stop the build."""
    backlog = [finding(obj="ZCL_OLD")]
    baseline = set(rg.write_baseline(backlog)["fingerprints"])
    result = rg.evaluate(backlog + [finding(obj="ZCL_NEW")], baseline=baseline)
    assert result.decision == "blocked"
    assert result.exit_code == rg.EXIT_BLOCKED
    assert [f["check_id"] for f in result.blocking] == ["ABAP-SQLI-001"]


def test_moving_a_finding_down_the_file_does_not_re_block_it():
    """Identity is the subject and its qualifier, never the line number — the same
    contract as server/identity.py. A baseline that disagreed would re-block every
    unrelated edit and be abandoned immediately."""
    before = finding(obj="ZCL_A", qualifier="SELECT * FROM (lv_t)")
    baseline = set(rg.write_baseline([before])["fingerprints"])
    after = dict(before)
    after["affected_items"] = ["ZCL_A line 412: SELECT * FROM (lv_t)"]
    assert rg.evaluate([after], baseline=baseline).decision == "pass"


def test_with_no_baseline_everything_counts_as_new_and_says_so():
    """Correct for a first run, wrong for a pipeline — and the gate must say which
    it is rather than let an operator assume."""
    result = rg.evaluate([finding()])
    assert result.decision == "blocked"
    assert "No baseline supplied" in " ".join(result.reasons)


# --------------------------------------------------------------------------- #
#  Rule 2 — judge only what the change touches                                #
# --------------------------------------------------------------------------- #

def test_a_transport_is_judged_only_on_the_objects_it_contains():
    """A developer cannot be asked to fix somebody else's object to ship their
    own."""
    findings = [finding(obj="ZCL_MINE"), finding(obj="ZCL_SOMEONE_ELSES")]
    result = rg.evaluate(findings, scope={"ZCL_MINE"})
    assert result.considered == 1
    assert [f["subject"][0]["name"] for f in result.blocking] == ["ZCL_MINE"]


def test_scope_matching_is_case_insensitive(tmp_path):
    """SAP object names are upper case; a scope file written by a human may not be,
    and a transport that silently matched nothing would pass everything."""
    f = tmp_path / "scope.txt"
    f.write_text("zcl_mine\n", encoding="utf-8")
    result = rg.evaluate([finding(obj="ZCL_MINE")], scope=rg.load_scope(f))
    assert result.considered == 1, "a lower-case scope entry matched nothing"


def test_a_scope_file_ignores_comments_and_blanks(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text("# transport K900123\nzcl_mine\n\n  ZCL_OTHER  # note\n",
                 encoding="utf-8")
    assert rg.load_scope(f) == {"ZCL_MINE", "ZCL_OTHER"}


# --------------------------------------------------------------------------- #
#  Rule 3 — never block on something the customer cannot fix                  #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("owner", ["provider_owned", "ticket_to_sap"])
def test_a_finding_the_customer_cannot_fix_does_not_block_their_transport(owner):
    """In RISE this is a demand that cannot be satisfied at any effort, and it is
    the fastest possible route to the gate being bypassed permanently. The
    four-state remediation_owner model is what lets the gate be strict AND fair."""
    result = rg.evaluate([finding(owner=owner)])
    assert result.decision == "pass"


def test_a_customer_fixable_finding_does_block():
    assert rg.evaluate([finding(owner="customer_fixable")]).decision == "blocked"


def test_an_unknown_owner_still_blocks():
    """Unknown is not a licence to ship. The offline CLI has no ownership data at
    all, so this is the common case there, and it must be the safe one."""
    f = finding()
    del f["remediation_owner"]
    assert rg.evaluate([f]).decision == "blocked"


# --------------------------------------------------------------------------- #
#  Evidence class                                                             #
# --------------------------------------------------------------------------- #

def test_a_pattern_only_finding_does_not_hold_a_release():
    """That evidence class is exactly the population Tier 2 of the engine plan was
    about — rules that matched correct code. It is still reported; it just does not
    get to stop a build."""
    result = rg.evaluate([finding(confidence="pattern-only")])
    assert result.decision == "pass"


@pytest.mark.parametrize("confidence", ["confirmed", "tentative"])
def test_a_finding_with_data_flow_evidence_does_hold_a_release(confidence):
    assert rg.evaluate([finding(confidence=confidence)]).decision == "blocked"


def test_a_non_code_finding_with_no_confidence_field_still_blocks():
    """Most modules are not the ABAP scanner and carry no evidence class at all.
    Excluding them would silently limit the gate to one module."""
    f = finding(check_id="SEC-PARAM-001")
    f["details"] = {}
    assert rg.evaluate([f]).decision == "blocked"


# --------------------------------------------------------------------------- #
#  Policy behaviour                                                           #
# --------------------------------------------------------------------------- #

def test_severities_outside_the_policy_are_never_gated():
    policy = rg.load_policy(None)
    assert rg.evaluate([finding(severity="MEDIUM")], policy=policy).decision == "pass"


def test_an_exempt_check_never_blocks():
    """For risks accepted through the dismissal workflow, which has an audit trail
    and an expiry — unlike a #NOSEC in source."""
    policy = rg.load_policy(None)
    policy["exempt_checks"] = ["ABAP-SQLI-"]
    assert rg.evaluate([finding()], policy=policy).decision == "pass"


def test_warn_only_reports_the_block_but_exits_zero():
    """A hard gate cannot be dropped onto an existing estate on day one."""
    policy = rg.load_policy(None)
    policy["warn_only"] = True
    result = rg.evaluate([finding()], policy=policy)
    assert result.decision == "blocked"
    assert result.exit_code == rg.EXIT_PASS
    assert "not enforced" in " ".join(result.reasons).lower()


def test_warn_only_also_softens_a_degraded_scan():
    """Consistency: warn_only means "tell me, do not stop me" for every outcome,
    or an operator adopting it hits an exit 2 they did not expect."""
    policy = rg.load_policy(None)
    policy["warn_only"] = True
    result = rg.evaluate([], policy=policy, degraded=True)
    assert result.decision == "cannot_assess"
    assert result.exit_code == rg.EXIT_PASS


def test_the_blocking_list_names_findings_rather_than_counting_them():
    """A developer who cannot see what to fix routes around the gate."""
    out = rg.render(rg.evaluate([finding(obj="ZCL_PAY")]))
    assert "ZCL_PAY" in out and "ABAP-SQLI-001" in out
    assert "exit 1" in out


# --------------------------------------------------------------------------- #
#  Baseline round trip                                                        #
# --------------------------------------------------------------------------- #

def test_a_baseline_round_trips_through_a_file(tmp_path):
    findings = [finding(obj=f"ZCL_{i}") for i in range(3)]
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(rg.write_baseline(findings)), encoding="utf-8")
    assert rg.load_baseline(path) == {rg.fingerprint(f) for f in findings}


def test_a_bare_list_is_accepted_as_a_baseline(tmp_path):
    """So a pipeline can build one with jq without knowing the envelope."""
    path = tmp_path / "b.json"
    path.write_text(json.dumps([rg.fingerprint(finding())]), encoding="utf-8")
    assert rg.load_baseline(path) == {rg.fingerprint(finding())}


# --------------------------------------------------------------------------- #
#  Wiring                                                                     #
# --------------------------------------------------------------------------- #

def test_the_gate_reads_the_unfiltered_finding_set():
    """`--severity` is a DISPLAY option. A control whose verdict moves because
    somebody narrowed a report is not a control — the same reasoning that keeps the
    FAIR figure priced on the unfiltered set."""
    src = (ROOT / "sap_scanner.py").read_text(encoding="utf-8")
    gate_block = src[src.index("# ── Release gate ─", src.index("SCAN COMPLETE")):]
    assert "fair_findings" in gate_block
    assert "release_gate.evaluate(\n            fair_findings" in gate_block


def test_degraded_coverage_reaches_the_gate_from_the_scanner():
    """A module that could not look marks the finding; the gate reads the mark.

    THIS TEST USED TO ASSERT `"ABAP-LEX-001" in src`. That is a string being
    present in a file, which is not the same claim as the wiring working, and it
    would have passed unchanged while the gate was disarmed for every coverage
    check except that one. It now exercises the derivation itself.
    """
    src = (ROOT / "sap_scanner.py").read_text(encoding="utf-8")
    gate_block = src[src.index("# ── Release gate ─", src.index("SCAN COMPLETE")):]

    # The flag, not a list of ids the caller has to be taught. Asserted against
    # CODE with the comments stripped: the comment block above the derivation
    # names the old id deliberately, to record what was wrong with it, and an
    # assertion that cannot tell prose from code would forbid explaining itself.
    code = "\n".join(line.split("#")[0] for line in gate_block.splitlines())
    assert "degrades_coverage" in code
    assert "ABAP-LEX-001" not in code, \
        "the gate is matching one check id again; a coverage check added " \
        "afterwards would leave it returning green"

    # And the derivation behaves: any marked finding arms it, unmarked ones do not.
    marked = finding(check_id="ABAP-COV-002", severity="INFO")
    marked["details"] = {"degrades_coverage": True}
    plain = finding(check_id="ABAP-SQLI-001", severity="CRITICAL")

    def derive(findings):
        return [f for f in findings
                if (f.get("details") or {}).get("degrades_coverage")]

    assert rg.evaluate(
        [plain, marked], degraded=bool(derive([plain, marked]))
    ).exit_code == rg.EXIT_CANNOT_ASSESS
    assert derive([plain]) == []


# --------------------------------------------------------------------------- #
#  "We could not look" must never render as "we found nothing"                #
# --------------------------------------------------------------------------- #

def _gate_on(source_dir):
    """Run the ABAP module over `source_dir` and gate on what it produced."""
    from modules.abap_sast import AbapSastAuditor
    data = {} if source_dir is None else {"abap_source_dir": str(source_dir)}
    findings = AbapSastAuditor(data, {}).run_all_checks()
    degraded = [f for f in findings
                if (f.get("details") or {}).get("degrades_coverage")]
    result = rg.evaluate(findings, degraded=bool(degraded))
    return [f["check_id"] for f in findings], result


def test_an_abap_src_typo_cannot_produce_a_green_gate(tmp_path):
    """The defect this family exists for. `--abap-src` pointing at a path that is
    not a directory scanned nothing, returned no findings, and `--gate` turned no
    findings into exit 0 — so a pipeline whose export step had failed shipped on a
    scan that never ran, with a clean-looking report to show for it."""
    ids, result = _gate_on(tmp_path / "does-not-exist")
    assert "ABAP-COV-001" in ids
    assert result.decision == "cannot_assess"
    assert result.exit_code == rg.EXIT_CANNOT_ASSESS


def test_a_source_tree_with_no_source_in_it_cannot_produce_a_green_gate(tmp_path):
    """A real directory holding only abapGit's .xml sidecars: object metadata
    without object source, which is what a partial export leaves behind. Every rule
    ran against nothing and the report was silent about it."""
    (tmp_path / "zcl_thing.clas.xml").write_text("<abapGit/>", encoding="utf-8")
    ids, result = _gate_on(tmp_path)
    assert "ABAP-COV-002" in ids
    assert result.exit_code == rg.EXIT_CANNOT_ASSESS

    # And it says how much it skipped, so the reader can tell this apart from an
    # empty checkout without going back to the source tree.
    cov = next(f for f in AbapSastAuditor_findings(tmp_path)
               if f["check_id"] == "ABAP-COV-002")
    assert cov["details"]["metadata_skipped"] == 1
    assert cov["details"]["files_scanned"] == 0


def test_files_that_could_not_be_read_are_reported_not_dropped(tmp_path, monkeypatch):
    """`scan_tree` has collected unreadable files since it was written and nothing
    ever reported them: a locked or unreadable file left the scan silently, and the
    objects in it read as clean."""
    from modules import abap_sast

    good = tmp_path / "zcl_good.clas.abap"
    good.write_text("CLASS zcl_good DEFINITION. ENDCLASS.", encoding="utf-8")
    bad = tmp_path / "zcl_bad.clas.abap"
    bad.write_text("CLASS zcl_bad DEFINITION. ENDCLASS.", encoding="utf-8")

    real_read = Path.read_text

    def refuse(self, *a, **kw):
        if self.name == "zcl_bad.clas.abap":
            raise OSError("Permission denied")
        return real_read(self, *a, **kw)

    monkeypatch.setattr(abap_sast.Path, "read_text", refuse)

    ids, result = _gate_on(tmp_path)
    assert "ABAP-COV-003" in ids
    assert result.exit_code == rg.EXIT_CANNOT_ASSESS
    # Not COV-002: one file WAS scanned. Partial coverage and zero coverage are
    # different facts and must not collapse into one message.
    assert "ABAP-COV-002" not in ids


def test_not_asking_for_a_source_scan_is_not_degraded_coverage(tmp_path):
    """The other direction, and the reason this is not simply 'no findings means
    cannot_assess'. An absent optional input is not a failure to look — if it armed
    the gate, every scan that omits one input would return cannot_assess and the
    signal would be worth nothing."""
    ids, result = _gate_on(None)
    assert ids == []
    assert result.decision == "pass"
    assert result.exit_code == rg.EXIT_PASS


def test_a_source_tree_that_really_is_clean_still_passes(tmp_path):
    """The claim the gate has to keep making. Coverage findings must fire when the
    scanner could not look and stay silent when it looked and found nothing."""
    (tmp_path / "zcl_ok.clas.abap").write_text(
        "CLASS zcl_ok DEFINITION. PUBLIC SECTION. ENDCLASS.", encoding="utf-8")
    ids, result = _gate_on(tmp_path)
    assert not [i for i in ids if i.startswith("ABAP-COV")]
    assert result.decision == "pass"
    assert result.exit_code == rg.EXIT_PASS


def AbapSastAuditor_findings(source_dir):
    from modules.abap_sast import AbapSastAuditor
    return AbapSastAuditor({"abap_source_dir": str(source_dir)}, {}).run_all_checks()


def test_the_whole_chain_holds_through_the_real_cli(tmp_path):
    """In-process tests wire the module to the gate by hand, which is the thing
    that was broken. This runs the actual CLI so the assertion covers the
    derivation as `main()` performs it, not as the test performs it."""
    import subprocess
    out = tmp_path / "r.html"
    proc = subprocess.run(
        [sys.executable, "sap_scanner.py", "--data-dir", "sample_data",
         "--abap-src", str(tmp_path / "nope"), "--modules", "cva",
         "--gate", "--output", str(out)],
        capture_output=True, encoding="utf-8", errors="replace", cwd=str(ROOT))
    assert proc.returncode == rg.EXIT_CANNOT_ASSESS, (
        f"the CLI gated green on a source path that does not exist "
        f"(exit {proc.returncode})\n{proc.stdout[-1500:]}")
    # And it must SAY why, not just exit non-zero: an exit code alone sends the
    # engineer looking for a finding that does not exist.
    assert "no source was scanned at all" in proc.stdout, \
        f"the gate blocked without explaining what went unscanned\n{proc.stdout[-1500:]}"


def test_the_scanner_survives_having_its_output_redirected():
    """A CI pipeline ALWAYS redirects stdout, and on Windows that drops Python to
    the ANSI code page — where the banner's box-drawing characters raised
    UnicodeEncodeError before any work started. The scanner died before it reached
    the gate, and the traceback named an encodings module so it read like a broken
    install rather than an unprintable character.

    Run as a subprocess with a captured (non-tty) stdout, which is the condition
    that triggered it. An in-process assertion would not reproduce it.
    """
    import subprocess
    # The child now emits UTF-8 deliberately, so decode it as UTF-8. `text=True`
    # alone would decode with the parent's locale — cp1252 on this platform — and
    # fail on the very banner this test exists to prove is printable.
    proc = subprocess.run([sys.executable, str(ROOT / "sap_scanner.py"), "--help"],
                          capture_output=True, encoding="utf-8", errors="replace",
                          cwd=str(ROOT))
    assert proc.returncode == 0, \
        f"the scanner cannot run with redirected output:\n{proc.stderr[-500:]}"
    assert "--gate" in proc.stdout


def test_the_gate_is_stdlib_only():
    """modules/ ships with no third-party dependency, and a CI gate is exactly the
    place that matters: it runs in someone else's pipeline."""
    import ast
    tree = ast.parse((ROOT / "modules" / "release_gate.py").read_text(encoding="utf-8"))
    allowed = {"hashlib", "json", "pathlib", "typing", "__future__"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


# ── a module that never ran cannot vouch for anything ────────────────────────
#
# THE FALSE GREEN THIS CLOSES. `evaluate(degraded=...)` was armed only from
# findings that MARK THEMSELVES as degrading coverage — which catches a module
# that ran and knew it could not see everything, and cannot catch a module that
# never ran, because such a module emits nothing at all. Nothing is what the gate
# reads as "clean".
#
# Reproduced against the shipped CLI before the fix: `--modules users --gate`
# with a baseline accepting its nine findings printed "29 were not executed" and
# then "RELEASE GATE: PASS", exit 0. Of every place in this product for that bug
# to live, a CI exit code is the worst — the reader is a machine with no other
# signal to consult.

def test_a_module_that_never_ran_arms_the_gate():
    reasons = rg.coverage_reasons(
        {"modules": {"users": {"status": "complete"},
                     "abap_sast": {"status": "not_run"}}})
    assert reasons
    assert "abap_sast" in reasons[0]


def test_a_module_with_no_input_supplied_arms_the_gate():
    reasons = rg.coverage_reasons(
        {"modules": {"log_review": {"status": "skipped"}}})
    assert reasons
    assert "log_review" in reasons[0]


def test_a_manifest_that_could_not_be_built_arms_the_gate():
    """Fail-closed. Not knowing what we saw is not the same as having seen it,
    and the scanner tolerates a manifest failure precisely so the scan is not
    lost — which must not quietly become a pass."""
    assert rg.coverage_reasons(None)
    assert rg.coverage_reasons({})


def test_a_degraded_module_does_not_arm_the_gate():
    """WHY THIS RESTRAINT IS DELIBERATE. A degraded module DID look, at part of
    its input. A complete run over sample_data has eleven degraded modules and
    none skipped or not-run, so arming on degraded would return cannot_assess for
    every realistic upload — and a gate that always blocks gets switched off
    wholesale, taking the real signal with it. The precise per-module form of "I
    saw less than everything" is the `degrades_coverage` mark the scanner already
    reads, and `test_degraded_coverage_reaches_the_gate_from_the_scanner` holds
    that wiring in place."""
    assert rg.coverage_reasons(
        {"modules": {"a": {"status": "degraded"},
                     "b": {"status": "complete"},
                     "c": {"status": "no_file_inputs"}}}) == []


def test_the_reason_names_the_modules_rather_than_counting_them():
    """"29 modules did not run" tells an engineer to go and look; the names tell
    them where. Truncated, because thirty names in a CI log is a wall."""
    manifest = {"modules": {f"mod_{i:02d}": {"status": "not_run"} for i in range(9)}}
    reason = rg.coverage_reasons(manifest)[0]
    assert "mod_00" in reason
    assert "and 3 more" in reason


def test_a_blind_scan_cannot_pass_even_with_everything_baselined():
    """End to end through evaluate(): Rule 4 is checked before any finding is
    looked at, so a baseline accepting the lot cannot buy a green."""
    findings = [finding("USR-001", "HIGH")]
    baseline = {rg.fingerprint(findings[0])}
    reasons = rg.coverage_reasons({"modules": {"x": {"status": "not_run"}}})
    result = rg.evaluate(findings, baseline=baseline,
                                   degraded=bool(reasons),
                                   degraded_detail=" ".join(reasons))
    assert result.decision == "cannot_assess"
    assert result.exit_code == rg.EXIT_CANNOT_ASSESS


def test_the_operator_can_still_opt_out_deliberately():
    """A targeted pipeline that gates on one module is a legitimate pattern. The
    policy key already existed for it; this rule composes with it rather than
    overriding it, because a rule with no escape hatch is a rule people delete."""
    reasons = rg.coverage_reasons({"modules": {"x": {"status": "not_run"}}})
    result = rg.evaluate([], policy={"block_on_degraded_coverage": False},
                                   degraded=bool(reasons),
                                   degraded_detail=" ".join(reasons))
    assert result.exit_code == rg.EXIT_PASS


def test_the_scanner_arms_the_gate_from_the_manifest():
    """The wiring, not just the rule. The rule existing and nothing calling it is
    the shape of the defect it replaces."""
    src = (ROOT / "sap_scanner.py").read_text(encoding="utf-8")
    gate_block = src[src.index("# ── Release gate ─", src.index("SCAN COMPLETE")):]
    assert "release_gate.coverage_reasons(coverage_manifest)" in gate_block
    assert "or bool(coverage_reasons)" in gate_block


# ── the scope file the README tells you to write ─────────────────────────────
#
# THE DOCUMENTED INVOCATION WAS THE ONE THAT DISARMED THE GATE.
#
#     --gate-scope transport-objects.json
#
# `load_scope` split that file line by line, so a JSON document parsed into
# "object names" like `{`, `"objects":` and `]`. None matched anything, Rule 2
# narrowed the verdict to zero findings, and a CRITICAL SQL-injection finding in
# ZCL_A exited 0. Measured, before and after, on the same file:
#
#     OLD -> ['"OBJECTS": [', '"ZCL_A",', '"ZPROG_B"', ']', '{', '}']   pass, exit 0
#     NEW -> ['ZCL_A', 'ZPROG_B']                                      blocked, exit 1

def test_a_json_scope_names_the_objects_and_not_the_punctuation(tmp_path):
    p = tmp_path / "transport-objects.json"
    p.write_text(json.dumps({"objects": ["ZCL_A", "ZPROG_B"]}), encoding="utf-8")
    assert rg.load_scope(p) == {"ZCL_A", "ZPROG_B"}


def test_a_bare_json_list_is_accepted_too(tmp_path):
    p = tmp_path / "scope.json"
    p.write_text(json.dumps(["zcl_a", " zprog_b "]), encoding="utf-8")
    assert rg.load_scope(p) == {"ZCL_A", "ZPROG_B"}


def test_the_line_format_still_works(tmp_path):
    """It was the only format that worked, and it must not stop working."""
    p = tmp_path / "scope.txt"
    p.write_text("# objects in TR001\nZCL_A\nzprog_b  # a comment\n", encoding="utf-8")
    assert rg.load_scope(p) == {"ZCL_A", "ZPROG_B"}


def test_a_scope_that_names_nothing_is_refused_not_obeyed(tmp_path):
    """THE MORE IMPORTANT HALF. A scope matching nothing narrows the gate to
    nothing and would pass every build. Silently scoping to zero is
    indistinguishable from a transport that touches nothing, and only one of
    those should let a build through — so it raises, and sap_scanner.py's
    handler turns that into EXIT_CANNOT_ASSESS, which is Rule 4's answer."""
    for name, body in (("empty.json", "[]"),
                       ("empty-obj.json", '{"objects": []}'),
                       ("comments.txt", "# nothing here\n\n"),
                       ("unknown-shape.json", '{"transports": {"TR1": []}}')):
        p = tmp_path / name
        p.write_text(body, encoding="utf-8")
        with pytest.raises(ValueError) as excinfo:
            rg.load_scope(p)
        assert "named no objects" in str(excinfo.value), name


def test_a_scoped_gate_still_blocks_a_finding_the_transport_touches(tmp_path):
    """End to end: the point of scoping is to judge what changed, and that only
    works if the scope reaches the findings."""
    p = tmp_path / "transport-objects.json"
    p.write_text(json.dumps({"objects": ["ZCL_A"]}), encoding="utf-8")
    result = rg.evaluate([finding(obj="ZCL_A")], scope=rg.load_scope(p))
    assert result.decision == "blocked"
    assert result.exit_code == rg.EXIT_BLOCKED


def test_a_scoped_gate_still_ignores_a_finding_it_did_not_touch(tmp_path):
    p = tmp_path / "transport-objects.json"
    p.write_text(json.dumps({"objects": ["ZCL_UNRELATED"]}), encoding="utf-8")
    result = rg.evaluate([finding(obj="ZCL_A")], scope=rg.load_scope(p))
    assert result.exit_code == rg.EXIT_PASS
