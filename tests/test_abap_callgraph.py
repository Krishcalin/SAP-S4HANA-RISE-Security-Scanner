"""Taint that crosses a procedure boundary, and a confidence grade that means
something.

THE MEASUREMENT THAT STARTED THIS
`RiseTaintAnalyzer` seeded every inbound parameter of every FORM, METHOD and
FUNCTION as tainted. Run over every ABAP fixture in this repository, **11 of 11
sink-carrying findings came back `confirmed` and none came back `tentative`.** A
grade with one value is not a grade, and the label it printed — "tainted input
reaches this sink" — was going on a subroutine whose only caller passes the
string literal 'SFLIGHT'.

It is safe to change because `confirmed` and `tentative` behave identically
downstream: `fair_adapter._is_unevidenced` treats only `pattern-only` as
unevidenced, and `release_gate`'s default policy blocks on both. Nothing is
dropped from pricing and nothing stops holding a build. Only the claim changes.

WHAT IS AND IS NOT CLEARED
Only a FORM whose visible callers all pass literals is cleared. A METHOD or a
FUNCTION keeps the conservative seed however clean its visible callers look,
because a public method is called by whatever imports the class and a
remote-enabled function module by another system — "no caller in this artefact"
is their ordinary state, and for the RFC case it is the dangerous one.

And a non-literal actual is taken as tainted without asking whether it really is.
Proving that needs a fixpoint over the call graph; treating it as tainted cannot
lose a finding, and a literal is decidable by looking at it.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.abap_callgraph import (CALLER_TAINTED, LITERAL_ONLY,  # noqa: E402
                                    NO_CALLER, CallGraph, is_literal)
from modules.abap_sast import AbapSourceScanner, split_statements  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "abap" / "interproc_vulnerable.prog.abap"


@pytest.fixture(scope="module")
def graph():
    return CallGraph(split_statements(FIXTURE.read_text(encoding="utf-8")))


@pytest.fixture(scope="module")
def findings():
    scanner = AbapSourceScanner(data_flow=True)
    return scanner.scan_text(FIXTURE.read_text(encoding="utf-8"), FIXTURE)


def at(findings, line):
    return [f for f in findings if f["line"] == line]


# --------------------------------------------------------------------------- #
#  The graph                                                                   #
# --------------------------------------------------------------------------- #

def test_it_finds_the_procedures_and_their_kinds(graph):
    kinds = {n: k for n, (k, _f) in graph.procedures.items()}
    assert kinds["run_query"] == "form"
    assert kinds["run"] == "method"


def test_a_forms_signature_does_not_swallow_its_types(graph):
    """`USING iv_carrid TYPE string` is ONE parameter. With the type in the list,
    every positional bind after the first lands on the wrong argument —
    silently, and in the direction that reads as a real data flow."""
    _kind, formals = graph.procedures["run_query"]
    assert formals == {"USING": ["iv_carrid"]}, formals


def test_positional_and_named_calls_are_both_read(graph):
    callees = {c.callee for c in graph.calls}
    assert {"run_query", "outer", "inner", "housekeeping", "run"} <= callees
    perform = next(c for c in graph.calls if c.callee == "run_query")
    assert perform.positional == {"USING": ["p_carr"]}
    method = next(c for c in graph.calls if c.callee == "run")
    assert method.named == {"iv_where": "p_carr"}


@pytest.mark.parametrize("proc,param,expect", [
    ("run_query", "iv_carrid", CALLER_TAINTED),     # PERFORM ... USING p_carr
    ("inner", "iv_name", CALLER_TAINTED),           # two hops from the screen
    ("run", "iv_where", CALLER_TAINTED),            # named method argument
    ("housekeeping", "iv_fixed", LITERAL_ONLY),     # PERFORM ... USING 'SFLIGHT'
    ("literal_fed", "iv_lit", LITERAL_ONLY),        # method, literal argument
    ("safe_run", "iv_where", NO_CALLER),            # nothing in the file calls it
    ("orphan", "iv_orphan", NO_CALLER),             # a FORM nothing calls
])
def test_what_the_callers_say(graph, proc, param, expect):
    verdict, _line = graph.evidence_for(proc, param)
    assert verdict == expect


def test_a_literal_argument_containing_an_equals_sign_is_still_one_argument(graph):
    """Read off the raw text, `_BIND` anchored on the `=` INSIDE the literal and
    reported a formal named by a word from the string, losing the real one. Call
    structure is read off the masked text for exactly this."""
    call = next(c for c in graph.calls if c.callee == "literal_fed")
    assert list(call.named) == ["iv_lit"], call.named


def test_only_a_form_is_ever_cleared(graph):
    """The kind guard, on the case that distinguishes it.

    `literal_fed` is a METHOD whose only visible caller passes a literal — the
    same evidence that clears `housekeeping`. It must NOT be cleared: a public
    method is called by whatever imports the class, and this artefact's callers
    are not the ones that matter."""
    assert graph.seeds_clean("housekeeping", "iv_fixed")[0] is True
    assert graph.seeds_clean("literal_fed", "iv_lit")[0] is False
    assert graph.seeds_clean("run", "iv_where")[0] is False
    assert graph.seeds_clean("safe_run", "iv_where")[0] is False


def test_no_caller_visible_is_not_a_clean_bill_even_for_a_form(graph):
    """`orphan` is a FORM and nothing in this artefact performs it. That is the
    absence of evidence, not evidence of absence — an external PERFORM lives in
    the calling program, which is not the file being scanned."""
    clean, verdict, _line = graph.seeds_clean("orphan", "iv_orphan")
    assert verdict == NO_CALLER
    assert clean is False


def test_an_unknown_procedure_changes_nothing(graph):
    assert graph.evidence_for("does_not_exist", "iv_x") == (NO_CALLER, None)
    assert graph.seeds_clean("does_not_exist", "iv_x")[0] is False


def test_a_name_defined_twice_is_refused_rather_than_guessed():
    """Resolution is by name. Two procedures with one name make every answer a
    coin flip, so no answer is given."""
    src = ("FORM dup USING iv_a TYPE string.\nENDFORM.\n"
           "FORM dup USING iv_b TYPE string.\nENDFORM.\n"
           "PERFORM dup USING 'X'.\n")
    g = CallGraph(split_statements(src))
    assert "dup" in g.ambiguous
    assert g.evidence_for("dup", "iv_a") == (NO_CALLER, None)


@pytest.mark.parametrize("actual,literal", [
    ("'SFLIGHT'", True), ("`SFLIGHT`", True), ("|SFLIGHT|", True),
    ("42", True), ("abap_true", True),
    ("lv_table", False), ("p_carr", False),
    ("|{ lv_x }|", False),          # a template with an expression in it
    ("lc_constant", False),         # an identifier is never a literal here
])
def test_what_counts_as_fixed_at_compile_time(actual, literal):
    assert is_literal(actual) is literal


# --------------------------------------------------------------------------- #
#  What the scanner now reports                                                #
# --------------------------------------------------------------------------- #

def test_the_grade_is_no_longer_constant(findings):
    """The defect, stated as a property. Before the call graph every sink on this
    fixture was `confirmed`, including the two that are only ever fed a literal."""
    grades = {f.get("confidence") for f in findings}
    assert "confirmed" in grades and "tentative" in grades, grades


def test_a_form_fed_only_a_literal_is_no_longer_confirmed(findings):
    """`PERFORM housekeeping USING 'SFLIGHT'` is the only call to it."""
    graded = at(findings, 45)
    assert graded, "the dynamic FROM in housekeeping stopped being reported"
    assert all(f["confidence"] == "tentative" for f in graded), \
        [(f["rule_id"], f["confidence"]) for f in graded]


def test_it_is_downgraded_and_not_hidden(findings):
    """The contract in `_refine`: nothing is deleted on the strength of the walk.
    A reader still sees the finding; what changes is what we claim about it."""
    assert at(findings, 45)


@pytest.mark.parametrize("line", [29, 38, 71])
def test_a_real_flow_across_the_boundary_stays_confirmed(findings, line):
    graded = at(findings, line)
    assert graded and all(f["confidence"] == "confirmed" for f in graded), \
        [(f["rule_id"], f["confidence"]) for f in graded]


def test_a_method_nobody_visibly_calls_keeps_the_conservative_grade(findings):
    graded = at(findings, 76)
    assert graded and all(f["confidence"] == "confirmed" for f in graded)


# --------------------------------------------------------------------------- #
#  The trace                                                                   #
# --------------------------------------------------------------------------- #

def test_the_trace_names_the_call_that_fed_the_parameter(findings):
    """Without this the trace stops at the FORM header and tells a developer
    `iv_carrid` is tainted — while the value they have to go and look at is one
    PERFORM away, in a part of the file the trace never mentions."""
    flow = at(findings, 29)[0]["flow"]
    roles = [s["role"] for s in flow]
    assert roles == ["call", "source", "sink"], flow
    call = flow[0]
    assert call["line"] == 17
    assert "PERFORM run_query" in call["code"]


def test_the_trace_crosses_two_hops(findings):
    """`inner` is reached from `outer`, which is reached from the screen. The
    step names the PERFORM inside `outer`, which is the caller `inner` has."""
    flow = at(findings, 38)[0]["flow"]
    assert flow[0]["role"] == "call" and flow[0]["line"] == 33


def test_no_call_step_is_invented_where_there_is_no_caller(findings):
    """`safe_run` has no visible caller, so the trace is exactly what it was."""
    flow = at(findings, 76)[0]["flow"]
    assert [s["role"] for s in flow] == ["source", "sink"], flow


def test_two_procedures_sharing_a_parameter_name_get_their_own_callers(findings):
    """`run` and `safe_run` both take `iv_where`, and only one of them is called.

    This passes with the evidence keyed on the parameter NAME alone as well —
    a line's walk runs immediately before that line is traced, so the dict is
    freshly correct for whichever line is being asked about. That is an ordering
    accident and not a guarantee, which is why the key is pinned structurally
    below rather than left to this."""
    run_flow = next(f for f in findings if f["line"] == 71)["flow"]
    safe_flow = next(f for f in findings if f["line"] == 76)["flow"]
    assert run_flow[0]["role"] == "call" and run_flow[0]["line"] == 25
    assert safe_flow[0]["role"] != "call"


def test_parameter_evidence_is_keyed_on_the_procedure_and_not_the_name():
    """Structural, because the behavioural test above cannot separate the two.

    Keyed on the name, an evidence dict populated by a walk that crosses more
    than one procedure header hands the earlier parameter the later one's caller.
    Keyed on the header line it cannot, whatever order the walks run in."""
    from modules.abap_sast import RiseTaintAnalyzer
    from modules.abap_callgraph import CallGraph as _CG
    src = FIXTURE.read_text(encoding="utf-8")
    analyzer = RiseTaintAnalyzer(src, callgraph=_CG(split_statements(src)))
    analyzer._walk(len(src.splitlines()))       # walk far enough to seed several
    assert analyzer._param_evidence, "no parameter evidence was recorded at all"
    headers = {st.line for st in split_statements(src)
               if re.match(r"^\s*(?:FORM|METHOD|FUNCTION)\s+", st.text, re.I)}
    for key in analyzer._param_evidence:
        assert isinstance(key, tuple) and len(key) == 2 and isinstance(key[0], int), (
            "parameter evidence is keyed on %r; it must carry the procedure's "
            "header line so two procedures sharing a parameter name cannot "
            "borrow each other's caller" % (key,))
        # And the line has to be a real header. A constant first element keeps
        # the tuple shape while throwing away the only part that discriminates.
        assert key[0] in headers, (
            "parameter evidence is keyed on line %d, which is not a procedure "
            "header (headers are at %s)" % (key[0], sorted(headers)))


# --------------------------------------------------------------------------- #
#  Not breaking what worked                                                    #
# --------------------------------------------------------------------------- #

def test_without_a_call_graph_the_analyzer_behaves_as_before():
    """Every existing caller constructs the analyzer with two arguments. With no
    graph, a parameter is seeded tainted exactly as it always was."""
    from modules.abap_sast import RiseTaintAnalyzer
    src = ("FORM only USING iv_x TYPE string.\n"
           "SELECT * FROM (iv_x) INTO TABLE @DATA(lt).\n"
           "ENDFORM.\n")
    analyzer = RiseTaintAnalyzer(src)
    assert analyzer.state_of("iv_x", 2) == analyzer.TAINTED


def test_a_source_inside_the_procedure_still_confirms_on_its_own():
    """Nothing about the call graph should be needed for a flow that never
    leaves one procedure."""
    scanner = AbapSourceScanner(data_flow=True)
    found = scanner.scan_text(
        "REPORT z.\n"
        "PARAMETERS p_t TYPE string.\n"
        "SELECT * FROM (p_t) INTO TABLE @DATA(lt).\n",
        Path("z.prog.abap"))
    sqli = [f for f in found if f["rule_id"].startswith("ABAP-SQLI")]
    assert sqli and any(f["confidence"] == "confirmed" for f in sqli)
