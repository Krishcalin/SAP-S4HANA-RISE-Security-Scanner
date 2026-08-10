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
    """ABAP-LEX-001 is how the ABAP scanner reports that it lost its place, and the
    gate reads the same evidence a human would rather than a side channel."""
    src = (ROOT / "sap_scanner.py").read_text(encoding="utf-8")
    assert "ABAP-LEX-001" in src


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
