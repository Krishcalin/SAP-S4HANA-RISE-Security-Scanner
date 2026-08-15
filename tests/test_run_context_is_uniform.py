# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""Every auditor is handed the same run context.

WHAT WAS WRONG, AND WHY IT WAS NOT YET A BUG.

`run_ctx` carries `deployment_mode` and the set of modules in this run. It was
threaded through the auditors that needed it, one at a time, as each need
appeared. That produced three call shapes in `sap_scanner.py`:

    21 auditors  (data, baseline_overrides)                            no context
     6 auditors  (data, baseline_overrides, run_ctx)                   the whole one
     3 auditors  (data, baseline_overrides, run_context={"modules": …}) a partial one

Nothing misbehaved. The three modules that read `deployment_mode` were all inside
the six that received it, so the three hand-rolled dicts missing that key were
never asked for it.

That is the whole reason to close it. The next field added to `run_ctx` would
reach six auditors out of thirty; the twenty-four omissions would each look like a
module choosing not to use it rather than a module never offered it; and the
symptom would be a check judging an ECS estate by on-premise rules, silently, in
one module and not its neighbour. This codebase already has that shape of defect
on record — `security_params` and `baseline_params` reading a profile export with
two different column vocabularies until one raised a HIGH against a hardened
system. A rule that lives in one place cannot drift from itself.

These tests assert the shape rather than the behaviour, because there is no
behaviour to assert yet — which is precisely when this is cheap to hold shut.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.base_auditor import BaseAuditor                      # noqa: E402

SCANNER = ROOT / "sap_scanner.py"


def _tree() -> ast.Module:
    return ast.parse(SCANNER.read_text(encoding="utf-8"))


def _auditor_names(tree: ast.Module) -> set:
    """The classes sap_scanner imports from `modules.*` that are actually auditors.

    DERIVED, NOT LISTED, AND NOT MATCHED ON THE NAME. A suffix rule ("…Auditor")
    would miss one named otherwise and would sweep in `DataLoader` and
    `RiskPrioritizer`, which take a deliberately different shape — the loader
    reads a directory and the prioritiser is handed findings; neither has any
    business knowing which modules ran. The question this test asks is "does it
    inherit the constructor that accepts a run context", so it asks exactly that.
    """
    import importlib

    names = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        if not (node.module or "").startswith("modules"):
            continue
        module = importlib.import_module(node.module)
        for alias in node.names:
            obj = getattr(module, alias.name, None)
            if isinstance(obj, type) and issubclass(obj, BaseAuditor):
                names.add(alias.asname or alias.name)
    return names


def _auditor_calls(tree: ast.Module):
    """(class name, line, ast.Call) for each auditor construction in the scanner."""
    wanted = _auditor_names(tree)
    return [(node.func.id, node.lineno, node)
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in wanted]


def test_the_scanner_constructs_the_auditors_this_test_thinks_it_does():
    """A test that finds nothing passes vacuously, and this file has exactly one
    input. If the scanner is restructured so these calls are no longer literal
    constructions, this test must fail rather than quietly assert nothing."""
    calls = _auditor_calls(_tree())
    assert len(calls) >= 25, (
        "only %d auditor constructions found in sap_scanner.py; the rest of this "
        "file is asserting nothing" % len(calls))


def _names_passed(node: ast.Call):
    """The bare identifiers this call hands over, positionally or as run_context.

    Node types rather than `ast.unparse`: that is 3.9+, the cli job runs 3.8, and
    tests/test_python_matrix.py holds this file to the oldest interpreter in the
    matrix like every other.
    """
    values = list(node.args)
    values += [k.value for k in node.keywords if k.arg == "run_context"]
    return {v.id for v in values if isinstance(v, ast.Name)}


def test_every_auditor_receives_the_run_context():
    tree = _tree()
    missing = []
    for name, lineno, node in _auditor_calls(tree):
        if "run_ctx" not in _names_passed(node):
            missing.append("%s (sap_scanner.py:%d)" % (name, lineno))
    assert not missing, (
        "auditor(s) constructed without the run context: %s. Every auditor gets "
        "the same one, so a field added to it reaches all of them." % ", ".join(missing))


def test_no_call_site_builds_a_run_context_of_its_own():
    """The partial dict is the failure mode, not the missing argument: a call site
    passing `run_context={"modules": …}` looks correct at a glance and drops
    `deployment_mode` on the floor."""
    tree = _tree()
    home_made = []
    for name, lineno, node in _auditor_calls(tree):
        for keyword in node.keywords:
            if keyword.arg == "run_context" and isinstance(keyword.value, ast.Dict):
                home_made.append("%s (sap_scanner.py:%d)" % (name, lineno))
        for arg in node.args:
            if isinstance(arg, ast.Dict) and any(
                    isinstance(k, ast.Constant) and k.value in ("modules", "deployment_mode")
                    for k in arg.keys):
                home_made.append("%s (sap_scanner.py:%d)" % (name, lineno))
    assert not home_made, (
        "call site(s) assembling their own run context: %s. Use the one built at "
        "the top of the scan." % ", ".join(sorted(set(home_made))))


def test_the_run_context_is_built_once_and_carries_both_keys():
    tree = _tree()
    built = [node for node in ast.walk(tree)
             if isinstance(node, ast.Assign)
             and any(isinstance(t, ast.Name) and t.id == "run_ctx" for t in node.targets)]
    assert len(built) == 1, "run_ctx is assigned %d times; it must be built once" % len(built)
    keys = {k.value for k in built[0].value.keys if isinstance(k, ast.Constant)}
    assert {"deployment_mode", "modules"} <= keys, keys


@pytest.mark.parametrize("attribute", ["deployment_mode", "modules"])
def test_a_reader_gets_the_same_answer_from_any_auditor(attribute):
    """The shape assertions above say the argument arrives. This says it survives
    the constructor — including in the two auditors that override `__init__`."""
    from modules.base_auditor import BaseAuditor
    from modules.code_inventory_report import CodeInventoryAuditor
    from modules.snc_posture import SncPostureAuditor

    ctx = {"deployment_mode": "rise_ecs", "modules": {"users", "snc"}}
    for cls in (BaseAuditor, CodeInventoryAuditor, SncPostureAuditor):
        auditor = cls({}, None, ctx)
        assert auditor.run_context.get(attribute) == ctx[attribute], cls.__name__
