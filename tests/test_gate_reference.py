# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""The release gate's coverage table, and why it is generated.

THE DEFECT, TWICE. `docs/RELEASE_GATE.md` lists the findings that arm `--gate`'s
fail-closed path. It carried a note saying the table "is derived by reading
`details["degrades_coverage"]` out of the modules, not maintained from memory —
which is how `ABAP-COV-004` came to be missing from it". Nothing derived it. It
was maintained from memory, it drifted again when `MDC-PAY-002` shipped, and the
paragraph explaining why hand-maintained id lists drift was sitting inside one.

WHAT WAS NEVER WRONG. The gate itself. It reads the flag off the finding and
knows none of these ids, so a coverage check arms it the day it is written. Only
the document drifted — but the document is what somebody reads before wiring the
gate into CI, and a table that silently omits a check is how a reader concludes
their pipeline is covered when it is not.

WHAT THESE TESTS ENFORCE. That the committed table matches what the modules
actually emit, that the derivation sees BOTH emission shapes, and that it does
not sweep up findings which merely sit next to a coverage finding — the first
version of the generator did exactly that, and a wrong row in a generated table
is worse than a wrong row in a hand-written one because it carries more
authority.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DOC = ROOT / "docs" / "RELEASE_GATE.md"


@pytest.fixture(scope="module")
def derived():
    from tools.build_gate_reference import gather
    return gather()


def test_the_committed_table_is_current(derived):
    """The invariant the generator exists for. Add a coverage check and forget to
    regenerate, and this fails instead of the table quietly going stale."""
    from tools.build_gate_reference import main
    assert main(["--check"]) == 0, (
        "docs/RELEASE_GATE.md is out of date — regenerate it with "
        "`python -m tools.build_gate_reference`")


def test_every_derived_id_appears_in_the_document(derived):
    doc = DOC.read_text(encoding="utf-8")
    missing = sorted(cid for cid in derived if "`%s`" % cid not in doc)
    assert not missing, missing


def test_the_id_that_drifted_is_there_now():
    """`MDC-PAY-002` shipped with the REGUH correlation and never reached the
    table. It is the second id to go missing, and the reason the table is
    generated rather than corrected."""
    assert "`MDC-PAY-002`" in DOC.read_text(encoding="utf-8")


# ═════════════════════════════════════════════════════════════════════════════
#  The derivation has to see both shapes, and only the right things
# ═════════════════════════════════════════════════════════════════════════════

def test_it_finds_ids_that_reach_the_flag_through_a_helper(derived):
    """Eight of the fifteen rows never appear beside `degrades_coverage` at all:
    `_coverage` and `_coverage_finding` set the flag and forward a check_id from
    their caller. A generator handling only the direct shape would have produced
    a table missing more than it listed."""
    for cid in ("ABAP-COV-001", "ABAP-COV-006", "CAPX-COV-001"):
        assert cid in derived, cid


def test_it_finds_ids_declared_directly_on_the_call(derived):
    for cid in ("BTP-AUD-001", "MDC-PAY-002", "VBM-DATA-001"):
        assert cid in derived, cid


@pytest.mark.parametrize("neighbour", ["MDC-PAY-001", "PARAM-MISSING",
                                       "ABAP-NOSEC-001"])
def test_a_finding_beside_a_coverage_finding_is_not_swept_up(derived, neighbour):
    """THE BUG THE FIRST VERSION OF THIS GENERATOR HAD. It asked whether a
    FUNCTION mentioned the flag anywhere and then took every check id in it, so
    `check_bank_change_then_payment` — which raises MDC-PAY-002 (coverage) and
    MDC-PAY-001 (a CRITICAL payment finding) from one body — contributed both.
    The table would have claimed the gate fails closed on a finding that has no
    such relationship with it.
    """
    assert neighbour not in derived


def test_the_computed_pattern_is_listed_but_not_as_an_id(derived):
    """`BaseAuditor` emits `f"{check_id}-COVERAGE"`, which cannot be enumerated
    because it is built per caller. It is a row so the reader knows the shape
    exists, and deliberately not an id."""
    doc = DOC.read_text(encoding="utf-8")
    assert "`<CHECK>-COVERAGE`" in doc
    assert not any(cid.endswith("-COVERAGE") and cid.startswith("<")
                   for cid in derived)


def test_an_undescribed_id_would_still_reach_the_table():
    """The ids are derived; the sentences are not, because no AST holds "what
    could not be looked at". A new coverage check must therefore appear as
    UNDESCRIBED rather than not appear — the failure being fixed here is an
    omission, and a generator that dropped unknown ids would reproduce it."""
    from tools.build_gate_reference import DESCRIPTIONS, build
    import tools.build_gate_reference as mod

    original = dict(DESCRIPTIONS)
    try:
        mod.DESCRIPTIONS.pop("BTP-AUD-001")
        table = build()
        assert "`BTP-AUD-001`" in table
        assert "undescribed" in table
    finally:
        mod.DESCRIPTIONS.clear()
        mod.DESCRIPTIONS.update(original)


def test_the_document_no_longer_claims_a_derivation_it_does_not_do():
    """The sentence that was false. It now describes what actually happens, and
    names both drifts rather than only the first."""
    doc = DOC.read_text(encoding="utf-8")
    assert "**This table is generated**" in doc
    assert "ABAP-COV-004" in doc and "MDC-PAY-002" in doc
