# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""A check must be countable before it fails, not because it failed.

THE DEFECT
`module_check_ids` read one of the three ways a check id is written — a
`check_id="X"` keyword — and treated the other two as non-existent:

    _emit("AUTH-001", ...)          passed positionally to a wrapper
    "PARAM-" + parameter name       composed at runtime from a rule table

So 78 of the 333 ids a real scan emits were invisible until the moment one
failed. Anything using that count as a DENOMINATOR was therefore not measuring
what it claimed to: `posture_score` fell when a scan discovered more problems,
because an unseen id joined the denominator only on failure and diluted a mean it
had not previously been part of. 120 newly discovered LOW findings moved
sample_data from 38 to 29 with nothing remediated.

WHAT THIS FILE ENFORCES
The property, measured against the real auditors: every check id a scan can
produce must be enumerable in advance. Not a count — counts are pinned in
tests/test_checks_reference.py, which is generated. This asks whether the
derivation can still be blindsided, which is the question that actually matters.
"""
from __future__ import annotations

import contextlib
import importlib
import io
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.coverage import (all_check_ids, module_check_ids,      # noqa: E402
                              positional_check_ids, runtime_check_families,
                              wrapper_signatures)


# ─────────────────────── the property, against real output ──────────────────

@pytest.fixture(scope="module")
def emitted():
    """Every check id the real auditors produce over the bundled sample data."""
    from modules.data_loader import DataLoader
    from server import ingest

    with contextlib.redirect_stdout(io.StringIO()), \
         contextlib.redirect_stderr(io.StringIO()):
        data = DataLoader(ROOT / "sample_data").load_all()
        found = set()
        for name, cls_name in ingest.AUDITORS:
            cls = getattr(importlib.import_module("modules." + name), cls_name)
            try:
                auditor = cls(data, {}, {"deployment_mode": "on_prem",
                                         "modules": set()})
            except TypeError:
                auditor = cls(data, {})
            found.update(f.get("check_id") for f in auditor.run_all_checks())
    return {c for c in found if c}


def test_every_check_a_real_scan_emits_was_enumerable_in_advance(emitted):
    """The whole point. A denominator that learns of a check by being failed by
    it is a tally of failures wearing a denominator's clothes."""
    known = {cid for ids in all_check_ids().values() for cid in ids}
    missing = sorted(emitted - known)
    assert not missing, (
        "%d check ids were emitted but cannot be enumerated in advance: %s"
        % (len(missing), missing[:15]))


def test_the_keyword_reader_alone_is_still_not_enough(emitted):
    """Guards the guard. If `module_check_ids` ever became complete on its own,
    the test above would pass without the other two readers doing anything, and
    the next silently-invisible family would go unnoticed."""
    literals = {cid for ids in module_check_ids().values() for cid in ids}
    assert emitted - literals, (
        "the keyword reader now covers everything, so the test above no longer "
        "demonstrates that the positional and runtime readers are required")


# ─────────────────────── the three readers, individually ────────────────────

def test_positional_ids_are_read_from_the_wrappers_own_signature():
    """`_emit("AUTH-001", ...)` is invisible to a keyword-only reader."""
    found = positional_check_ids()
    assert "abap_authorizations" in found, "no module contributed positional ids"
    assert "AUTH-001" in found["abap_authorizations"]
    # The signature is READ, not assumed: every emitter this resolves must
    # genuinely take the check id first, or the reader is collecting titles.
    for emitter, params in wrapper_signatures().items():
        assert params, emitter
    assert any(p[0] == "check_id" for p in wrapper_signatures().values()), \
        "no emitter takes check_id first; the positional reader cannot be right"


def test_a_placeholder_free_f_string_is_a_string():
    """`check_id=f"CODE-STMT-001"` parses as JoinedStr, not Constant, and that
    one stray `f` hid a check from the coverage derivation, the score denominator
    and the generated reference at once."""
    from modules.coverage import _const_str
    import ast

    assert _const_str(ast.parse('f"CODE-STMT-001"', mode="eval").body) \
        == "CODE-STMT-001"
    assert _const_str(ast.parse('"PLAIN-001"', mode="eval").body) == "PLAIN-001"
    # A template is not an id. Guessing one would put a placeholder in the
    # catalogue where a check belongs.
    assert _const_str(ast.parse('f"PARAM-{name}"', mode="eval").body) is None


def test_runtime_families_carry_the_prefix_the_auditor_emits():
    """The tables hold bare keys (`BASIS-01`); the auditors raise `ARA-BASIS-01`.
    Enumerating the bare keys would fill the denominator with ids no finding can
    ever match — the count would look right and every entry would be unmatchable.
    """
    by_module = {f["module"]: f for f in runtime_check_families()}
    assert set(by_module) == {"security_params", "abap_sast",
                              "access_risk_analysis", "atc_import",
                              "iam_advanced", "webdisp_security"}
    for module, prefix in [("access_risk_analysis", "ARA-"), ("atc_import", "ATC-"),
                           ("iam_advanced", "IAM-"), ("security_params", "PARAM-"),
                           ("abap_sast", "ABAP-"), ("webdisp_security", "WDISP-")]:
        ids = by_module[module]["ids"]
        assert ids, module
        assert all(cid.startswith(prefix) for cid in ids), (
            "%s emits ids without the %r prefix: %s"
            % (module, prefix, [c for c in ids if not c.startswith(prefix)][:5]))


def test_a_family_that_resolves_to_nothing_is_an_error_not_an_empty_table():
    """A broken table reference must break the run. The reference generator's
    first version wrapped these imports, guessed two class names wrong, and
    shipped a catalogue missing 37 ids while printing a success line.

    ASKED OF THE SYNTAX TREE, NOT THE TEXT. The first version of this test
    searched the source for the substring "except" and was failed by the comment
    explaining why there is no except — the fifth time in this codebase a textual
    check has matched prose about the thing instead of the thing.
    """
    import ast
    import inspect
    import textwrap

    from modules import coverage

    tree = ast.parse(textwrap.dedent(
        inspect.getsource(coverage.runtime_check_families)))
    handlers = [n for n in ast.walk(tree) if isinstance(n, ast.ExceptHandler)]
    assert not handlers, (
        "an except here would restore the silent undercount this function ends")
    assert any(isinstance(n, ast.Raise) for n in ast.walk(tree)), \
        "nothing raises, so an unresolvable family would pass silently"


def test_all_check_ids_is_the_union_and_not_merely_one_of_them():
    complete = all_check_ids()
    literals = module_check_ids()
    for module, ids in literals.items():
        assert set(ids) <= set(complete.get(module, ())), module
    for family in runtime_check_families():
        assert set(family["ids"]) <= set(complete[family["module"]]), family["module"]
    for module, ids in positional_check_ids().items():
        assert set(ids) <= set(complete.get(module, ())), module


def test_the_reference_generator_and_the_scanner_share_one_definition():
    """Two readers of the same wrapper signatures could disagree, and the tool
    that documents the product disagreeing with the one that scores it is a
    particularly bad pair to let drift."""
    from tools import build_checks_reference

    assert build_checks_reference.wrapper_signatures is wrapper_signatures
    from modules.coverage import EMITTERS

    assert build_checks_reference.EMITTERS is EMITTERS
