"""The call graph over a whole tree, and who ABAP lets call what.

WHY A TREE PASS EXISTS AT ALL
A per-artefact graph answers nothing about class-based code. Measured on
`sample_data/abap_src`, every method parameter came back `no_caller` — a class's
callers live in other files by construction, so a graph that sees one file has no
evidence about any method in it, and class-based ABAP is most modern ABAP.

SEEING THE TREE IS NOT PERMISSION TO CLEAR A METHOD
Who may call a procedure is decided by ABAP, not by what we happen to have
parsed:

    FORM        file-local in every codebase anyone writes
    PRIVATE     only from inside its class — one artefact holds every caller
    PROTECTED   its class and its subclasses, which can be in other artefacts
    PUBLIC      anything that imports the class, including code never exported
    FUNCTION    another system entirely, if it carries the RFC flag

So a whole-tree graph makes PROTECTED answerable and leaves PUBLIC exactly where
it was. `tests/fixtures/abap_tree` has one of each, and the pair that matters is
`by_public_literal` and `priv_literal`: identical evidence — every visible call
passes a literal — and only one of them may be downgraded.

RESOLUTION IS BY CLASS, NOT BY NAME
`run`, `execute` and `get_data` are defined dozens of times in a real custom-code
base. Resolving a call by its bare name across a tree would make almost every
method ambiguous, and the tree graph would answer LESS than the per-artefact one
it replaced. Receivers are typed from `TYPE REF TO`, `NEW`, `me->` and `zcl_x=>`;
one that cannot be typed may add taint to every method of that name and may never
clear any of them.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.abap_callgraph import NO_CALLER, CallGraph  # noqa: E402
from modules.abap_sast import AbapSourceScanner, split_statements  # noqa: E402

TREE = ROOT / "tests" / "fixtures" / "abap_tree"


@pytest.fixture(scope="module")
def tree_findings():
    return AbapSourceScanner(data_flow=True).scan_tree(TREE)


@pytest.fixture(scope="module")
def tree_graph():
    graph = CallGraph(tree_wide=True)
    for path in sorted(TREE.glob("*.abap")):
        graph.add_artefact(split_statements(path.read_text(encoding="utf-8")),
                           path.name)
    return graph


def graded(findings, line):
    return [f for f in findings if f["line"] == line]


# --------------------------------------------------------------------------- #
#  Visibility decides what may be cleared                                      #
# --------------------------------------------------------------------------- #

def test_a_private_method_fed_only_literals_is_downgraded(tree_findings):
    """`priv_literal` is PRIVATE and its one caller passes 'SFLIGHT'. ABAP
    guarantees there is no other caller, so this is the one class member the
    visible evidence can actually settle."""
    rows = graded(tree_findings, 48)
    assert rows, "the dynamic FROM in priv_literal stopped being reported"
    assert all(f["confidence"] == "tentative" for f in rows), \
        [(f["rule_id"], f["confidence"]) for f in rows]


def test_a_public_method_fed_only_literals_is_not(tree_findings):
    """The pair that makes the rule a rule. `by_public_literal` has exactly the
    same evidence as `priv_literal` — every call in the whole tree passes a
    literal — and it stays confirmed, because public means callable by code that
    was never in the export."""
    rows = graded(tree_findings, 40)
    assert rows and all(f["confidence"] == "confirmed" for f in rows), \
        [(f["rule_id"], f["confidence"]) for f in rows]


def test_a_method_nothing_in_the_tree_calls_stays_conservative(tree_findings):
    rows = graded(tree_findings, 44)
    assert rows and all(f["confidence"] == "confirmed" for f in rows)


def test_a_protected_member_is_answerable_only_with_the_whole_tree():
    """A subclass can live in another artefact, so one file cannot say who calls
    a PROTECTED method — and a whole tree can."""
    src = ("CLASS zcl_b DEFINITION PUBLIC.\n"
           "  PUBLIC SECTION.\n"
           "    METHODS go.\n"
           "  PROTECTED SECTION.\n"
           "    METHODS prot IMPORTING iv_t TYPE string.\n"
           "ENDCLASS.\n"
           "CLASS zcl_b IMPLEMENTATION.\n"
           "  METHOD go.\n"
           "    me->prot( iv_t = 'SFLIGHT' ).\n"
           "  ENDMETHOD.\n"
           "  METHOD prot.\n"
           "    SELECT * FROM (iv_t) INTO TABLE @DATA(lt).\n"
           "  ENDMETHOD.\n"
           "ENDCLASS.\n")
    statements = split_statements(src)
    per_file = CallGraph(statements, "zcl_b.clas.abap", tree_wide=False)
    whole = CallGraph(statements, "zcl_b.clas.abap", tree_wide=True)
    assert per_file.seeds_clean("zcl_b~prot", "iv_t")[0] is False
    assert whole.seeds_clean("zcl_b~prot", "iv_t")[0] is True


def test_visibility_is_read_off_the_section_it_was_declared_in(tree_graph):
    assert tree_graph.visibility["zcl_tree_worker~by_public_tainted"] == "public"
    assert tree_graph.visibility["zcl_tree_worker~priv_literal"] == "private"


# --------------------------------------------------------------------------- #
#  Resolution                                                                  #
# --------------------------------------------------------------------------- #

def test_receivers_are_resolved_to_their_class(tree_graph):
    """All three spellings the fixture uses."""
    resolved = {c.callee for c in tree_graph.calls if c.qualified}
    assert "zcl_tree_worker~by_public_tainted" in resolved   # DATA ... TYPE REF TO
    assert "zcl_tree_worker~entry" in resolved               # DATA(x) = NEW
    assert "zcl_tree_worker~priv_literal" in resolved        # me->


def test_an_unresolved_receiver_can_never_clear_a_parameter():
    """A call whose receiver cannot be typed might reach any method of that name.
    That is a reason to be careful about all of them, and no reason at all to
    declare one of them safe."""
    src = ("CLASS zcl_a DEFINITION PUBLIC.\n"
           "  PRIVATE SECTION.\n"
           "    METHODS run IMPORTING iv_t TYPE string.\n"
           "ENDCLASS.\n"
           "CLASS zcl_a IMPLEMENTATION.\n"
           "  METHOD run.\n"
           "    SELECT * FROM (iv_t) INTO TABLE @DATA(lt).\n"
           "  ENDMETHOD.\n"
           "  METHOD other.\n"
           "    me->run( iv_t = 'SFLIGHT' ).\n"
           "    lo_untyped->run( iv_t = lv_anything ).\n"
           "  ENDMETHOD.\n"
           "ENDCLASS.\n")
    graph = CallGraph(split_statements(src), "zcl_a.clas.abap", tree_wide=True)
    clean, evidence = graph.seeds_clean("zcl_a~run", "iv_t")
    assert clean is False, "an untypeable receiver was allowed to clear a method"
    assert evidence.verdict == NO_CALLER


def test_local_variable_types_do_not_leak_between_files():
    """`lo` in two artefacts is two variables. Carrying a type across would
    resolve one file's call against another file's declaration."""
    declared = ("CLASS zcl_q DEFINITION PUBLIC.\n  PUBLIC SECTION.\n"
                "    METHODS go.\nENDCLASS.\n"
                "CLASS zcl_q IMPLEMENTATION.\n  METHOD go.\n"
                "    DATA lo TYPE REF TO zcl_p.\n"
                "    lo->run( iv_t = lv_x ).\n"
                "  ENDMETHOD.\nENDCLASS.\n")
    undeclared = ("CLASS zcl_r DEFINITION PUBLIC.\n  PUBLIC SECTION.\n"
                  "    METHODS go2.\nENDCLASS.\n"
                  "CLASS zcl_r IMPLEMENTATION.\n  METHOD go2.\n"
                  "    lo->run( iv_t = lv_y ).\n"
                  "  ENDMETHOD.\nENDCLASS.\n")
    graph = CallGraph(tree_wide=True)
    graph.add_artefact(split_statements(declared), "b.clas.abap")
    graph.add_artefact(split_statements(undeclared), "c.clas.abap")
    from_c = [c for c in graph.calls if c.file == "c.clas.abap"]
    assert from_c and all(not c.qualified for c in from_c), \
        [(c.callee, c.qualified) for c in from_c]


def test_the_graph_records_where_each_procedure_was_defined(tree_graph):
    """Needed to say which artefact a cross-file caller reached into."""
    assert (tree_graph.defined_in["zcl_tree_worker~by_public_tainted"]
            == "zcl_tree_worker.clas.abap")
    assert tree_graph.defined_in["zcl_tree_caller~drive"] == "zcl_tree_caller.clas.abap"


# --------------------------------------------------------------------------- #
#  The trace                                                                   #
# --------------------------------------------------------------------------- #

def test_the_trace_reaches_into_another_file(tree_findings):
    """The point of the tree pass. `by_public_tainted` has no caller in its own
    artefact, so without it the trace stops at the METHOD header with nothing to
    point at."""
    call = graded(tree_findings, 36)[0]["flow"][0]
    assert call["role"] == "call"
    assert call["file"] == "zcl_tree_caller.clas.abap"
    assert call["line"] == 20
    assert "by_public_tainted" in call["code"]


def test_a_cross_file_step_shows_the_callers_own_statement(tree_findings):
    """Read off this file's line 20 the step would show an unrelated statement —
    the line number means something different in every artefact."""
    call = graded(tree_findings, 36)[0]["flow"][0]
    worker = (TREE / "zcl_tree_worker.clas.abap").read_text(encoding="utf-8")
    assert call["code"].strip() != worker.splitlines()[19].strip()


def test_a_cross_file_step_names_the_variable_the_caller_passed(tree_findings):
    """`iv_user_input`, not `iv_where`. The callee's parameter name does not
    appear on the caller's line, and naming it there sends the reader looking for
    a variable that is not in the statement they are shown."""
    assert graded(tree_findings, 36)[0]["flow"][0]["var"] == "iv_user_input"


def test_a_same_file_call_step_carries_no_file(tree_findings):
    """`priv_tainted` is called from `entry` in its own artefact. A `file` key on
    every same-file step would be noise on most traces in the product."""
    call = graded(tree_findings, 52)[0]["flow"][0]
    assert call["role"] == "call" and "file" not in call


def test_scanning_one_artefact_directly_still_works():
    """`scan_text` is a public entry point and must answer without a tree."""
    scanner = AbapSourceScanner(data_flow=True)
    found = scanner.scan_text(
        (TREE / "zcl_tree_worker.clas.abap").read_text(encoding="utf-8"),
        TREE / "zcl_tree_worker.clas.abap")
    assert found and any(f["rule_id"].startswith("ABAP-SQLI") for f in found)
