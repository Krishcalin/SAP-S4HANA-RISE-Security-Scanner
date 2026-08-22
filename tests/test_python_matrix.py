"""Every test the `cli` job runs must actually run on the oldest Python it uses.

WHY THIS FILE EXISTS: THE SAME BUG, TWICE, IN ONE DAY
`sys.stdlib_module_names` arrived in Python 3.10. The `cli` CI job runs a
3.8-3.12 matrix. A test that calls it therefore passes on three interpreters and
fails on two — a shape of failure that gets read as "CI is just red for the
matrix" and ignored.

It happened once in `tests/test_resilience_posture.py`, where it went unnoticed
for months. It was fixed. Then a NEW test file reintroduced it the same day, in
`tests/test_collect.py`, because the fix lived in a docstring in a different file
and nobody thought to look for a pattern that already existed.

A fix that relies on the next author remembering is not a fix. This asserts the
rule mechanically, over every test file the job actually runs — and it derives
that list from the workflow rather than repeating it, so the two cannot drift.

WHAT IT DOES NOT CLAIM
Parsing with `feature_version=(3, 8)` catches SYNTAX that is too new — `match`,
`X | Y` outside `from __future__ import annotations`, parenthesised context
managers. It cannot catch every too-new library call, so the API list below is
maintained by hand. It covers the ones that have actually caused a red build here
plus the obvious neighbours; it is a net, not a proof.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "tests.yml"

#: Standard-library names that do not exist on the oldest interpreter in the
#: matrix, with the version that introduced them. Hand-maintained; see the module
#: docstring on why this is a net rather than a proof.
#:
#: Matched by ATTRIBUTE NAME through the AST, not by text. The first draft grepped
#: the source and promptly flagged its own docstring, which mentions
#: `sys.stdlib_module_names` in order to explain why the rule exists. That is the
#: third time in one working day that a textual check could not tell code from
#: prose about code, and it is the reason this one parses.
LATE_APIS = {
    "stdlib_module_names": "3.10",
    "removeprefix": "3.9",
    "removesuffix": "3.9",
    "graphlib": "3.9",
    "zoneinfo": "3.9",
    "unparse": "3.9",
    "pairwise": "3.10",
    "anext": "3.10",
    "tomllib": "3.11",
    "ExceptionGroup": "3.11",
    "StrEnum": "3.11",
    "batched": "3.12",
    "override": "3.12",
}


def _matrix_floor() -> tuple:
    """The oldest Python version the `cli` job runs, read from the workflow."""
    text = WORKFLOW.read_text(encoding="utf-8")
    versions = re.findall(r'"(3\.\d+)"', text)
    assert versions, "no python versions found in the workflow; this test has " \
                     "stopped checking anything"
    parsed = sorted({tuple(int(p) for p in v.split(".")) for v in versions})
    return parsed[0]


def _ignored_by_cli_job() -> set:
    """The test files the `cli` job skips, from the tool that computes them.

    IT USED TO GREP THE WORKFLOW FOR `--ignore=`, and that stopped working the
    moment the list became derived: with no literal flags left, the regex matched
    a single BACKTICK out of a comment reading "it used to be eighteen
    `--ignore=` lines", and `assert _ignored_by_cli_job()` was satisfied by
    punctuation. The guard-on-the-guard passed while the guard measured nothing.

    That is the fourth time in this codebase a textual check has read prose about
    the thing instead of the thing, and the third time in one working day. It now
    calls the same function the job calls, so the two cannot disagree at all —
    there is nothing left to parse.
    """
    from tools.stdlib_only_ignores import unavailable_here

    return {Path(name).name for name in unavailable_here()}


def _files_the_cli_job_runs():
    """Every file the job EXECUTES, not merely every test it collects.

    WHY THIS IS WIDER THAN IT WAS. The job runs the whole scanner core and, since
    the ignore list became derived, a tool of its own — `pytest -q $(python -m
    tools.stdlib_only_ignores)`. Only `tests/` was ever checked.

    So `tools/stdlib_only_ignores.py` was written using `sys.stdlib_module_names`
    — 3.10+, in a 3.8 matrix — and this file caught the identical call in the
    TEST beside it while being structurally blind to the tool the job needs in
    order to start. A file that crashes the runner is worse than a test that
    fails inside it, and that is the sixth appearance of that one attribute here.
    """
    ignored = _ignored_by_cli_job()
    tests = [p for p in (ROOT / "tests").glob("test_*.py") if p.name not in ignored]
    core = [p for directory in ("modules", "collect", "tools")
            for p in (ROOT / directory).glob("*.py")]
    return sorted(tests + core + [ROOT / "sap_scanner.py"])


def test_the_workflow_still_declares_a_matrix_this_test_can_read():
    """A guard on the guard. If the workflow is restructured so the version list
    or the ignore list stops parsing, this file would quietly start asserting
    nothing — which is the failure mode it was written to prevent."""
    floor = _matrix_floor()
    assert floor < (3, 12), f"parsed an implausible matrix floor: {floor}"

    # NAMED FILES, not "something truthy". The previous version asserted only
    # that the ignored set was non-empty, and a stray backtick satisfied it.
    ignored = _ignored_by_cli_job()
    assert len(ignored) > 5, f"implausibly few files ignored: {sorted(ignored)}"
    assert all(name.endswith(".py") for name in ignored), sorted(ignored)
    assert "test_api_auth.py" in ignored, \
        "a suite that plainly needs fastapi is not being skipped"

    checked = {p.name for p in _files_the_cli_job_runs()}
    assert len(checked) > 60, "implausibly few files matched"
    # The three kinds this must cover, one witness each.
    assert "test_domains.py" in checked, "tests are not being checked"
    assert "coverage.py" in checked, "the scanner core is not being checked"
    assert "stdlib_only_ignores.py" in checked, \
        "the tool the job runs to start is not being checked"
    assert not (checked & ignored), "a skipped suite is being checked anyway"


@pytest.mark.parametrize("path", _files_the_cli_job_runs(),
                         ids=lambda p: p.name)
def test_the_file_parses_on_the_oldest_interpreter_in_the_matrix(path):
    floor = _matrix_floor()
    src = path.read_text(encoding="utf-8")
    try:
        ast.parse(src, feature_version=floor)
    except SyntaxError as exc:
        pytest.fail(
            f"{path.name}:{exc.lineno} uses syntax newer than Python "
            f"{'.'.join(map(str, floor))}, which the cli job runs: {exc.msg}")


@pytest.mark.parametrize("path", _files_the_cli_job_runs(),
                         ids=lambda p: p.name)
def test_the_file_guards_every_too_new_library_call(path):
    """A use is acceptable when it sits behind a skipif for the same name.

    That is the established pattern in this repository — see
    `tests/test_resilience_posture.py` — and it is honest rather than a
    workaround: the `purity` job enforces the same guarantee repository-wide on
    3.12, so the local test is only the fast copy of it.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))

    # Which symbols the file protects with `hasattr(x, "name")`. Read from the
    # AST too, so a mention in prose neither guards nor accuses.
    guarded = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "hasattr" and len(node.args) == 2
                and isinstance(node.args[1], ast.Constant)
                and isinstance(node.args[1].value, str)):
            guarded.add(node.args[1].value)

    offences = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            symbol = node.attr
        elif isinstance(node, ast.Name):
            symbol = node.id
        elif isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in LATE_APIS and root not in guarded:
                    offences.append(f"line {node.lineno}: import {root} "
                                    f"needs Python {LATE_APIS[root]}")
            continue
        elif isinstance(node, ast.ImportFrom):
            symbol = (node.module or "").split(".")[0]
        else:
            continue
        if symbol in LATE_APIS and symbol not in guarded:
            offences.append(f"line {node.lineno}: {symbol} needs Python "
                            f"{LATE_APIS[symbol]}")

    assert not offences, (
        f"{path.name} uses library calls newer than the oldest interpreter the "
        f"cli job runs, without a skipif guard:\n  "
        + "\n  ".join(sorted(set(offences)))
        + "\n\nGuard it the way tests/test_resilience_posture.py does:\n"
          '  @pytest.mark.skipif(not hasattr(sys, "<name>"), reason="...")')
