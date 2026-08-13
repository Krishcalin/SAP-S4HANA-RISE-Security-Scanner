# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""The CLI's module names and the coverage manifest's module names.

THE DEFECT THIS FILE EXISTS FOR
sap_scanner.py dispatches on "users", "params", "authz". modules/coverage.py keys
on "user_auth_audit", "security_params", "abap_authorizations". The scanner passed
the first vocabulary into `build_manifest(modules_run=...)`, every name failed the
membership test, and all thirty modules were stamped `not_run` — in reports
carrying hundreds of findings produced by those very modules.

It survived because the failure was TOTAL and therefore looked deliberate: a table
of thirty `not_run` rows reads exactly like a scan that did nothing, and the four
summary cards above it count `modules_skipped`, not `modules_not_run`, so they
stayed reassuringly at zero.

A hand-written alias table would be the same defect one layer down, so the test
below RE-DERIVES the mapping from sap_scanner.py's own dispatch — the `if "x" in
run_modules:` blocks and the auditor class each one constructs — and fails when
the table and the scanner disagree. Adding a module to the CLI without an alias
breaks this test rather than one column of a report nobody rereads.
"""
import ast
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.coverage import (                                    # noqa: E402
    CLI_MODULE_ALIASES, build_manifest, module_sources,
)


def _dispatch_from_the_scanner():
    """{cli name: module file name}, read out of sap_scanner.py's main()."""
    tree = ast.parse((ROOT / "sap_scanner.py").read_text(encoding="utf-8"))
    class_to_module = {
        alias.name: node.module.split(".", 1)[1]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("modules.")
        for alias in node.names
    }
    main = next(n for n in tree.body
                if isinstance(n, ast.FunctionDef) and n.name == "main")
    found = {}
    for node in ast.walk(main):
        if not isinstance(node, ast.If):
            continue
        test = node.test
        if not (isinstance(test, ast.Compare)
                and isinstance(test.ops[0], ast.In)
                and isinstance(test.left, ast.Constant)
                and getattr(test.comparators[0], "id", "") == "run_modules"):
            continue
        constructed = {call.func.id for call in ast.walk(node)
                       if isinstance(call, ast.Call)
                       and isinstance(call.func, ast.Name)
                       and call.func.id in class_to_module}
        for cls in constructed:
            found[test.left.value] = class_to_module[cls]
    return found


def test_every_cli_module_maps_to_a_real_manifest_module():
    known = set(module_sources())
    unknown = {cli: mod for cli, mod in CLI_MODULE_ALIASES.items() if mod not in known}
    assert not unknown, f"alias points at no module: {unknown}"


def test_the_alias_table_matches_what_the_scanner_actually_dispatches():
    """The drift check. The table is data; the scanner is the truth."""
    actual = _dispatch_from_the_scanner()
    assert actual, "could not read the scanner's dispatch — the parser needs updating"
    assert CLI_MODULE_ALIASES == actual, (
        "sap_scanner.py and CLI_MODULE_ALIASES disagree.\n"
        f"  in the scanner, not the table: "
        f"{ {k: v for k, v in actual.items() if CLI_MODULE_ALIASES.get(k) != v} }\n"
        f"  in the table, not the scanner: "
        f"{ {k: v for k, v in CLI_MODULE_ALIASES.items() if actual.get(k) != v} }")


def test_a_full_cli_run_does_not_report_every_module_as_not_run():
    """THE REGRESSION, in one assertion.

    Every module the CLI can run, passed in the CLI's own words. If the manifest
    comes back saying none of them ran, the vocabularies have parted again.
    """
    manifest = build_manifest({}, modules_run=sorted(CLI_MODULE_ALIASES))
    states = {name: m["status"] for name, m in manifest["modules"].items()}
    assert states, "no modules in the manifest at all"
    assert not all(s == "not_run" for s in states.values()), (
        "every module reported not_run for a run that named all of them")
    assert manifest["counts"]["modules_not_run"] == 0, states


def test_module_names_are_accepted_as_well_as_cli_names():
    """The server passes the module file names; the CLI passes short ones. Both
    are legitimate and neither may be silently reinterpreted as "did not run"."""
    manifest = build_manifest({}, modules_run=sorted(module_sources()))
    assert manifest["counts"]["modules_not_run"] == 0


def test_a_list_in_a_third_vocabulary_is_refused_not_reported_as_a_blackout():
    """The class of bug, not the instance.

    "Nothing ran" and "you asked me in a language I do not speak" produce the
    same manifest, and only one of them is a fact about the scan. The caller is
    told rather than the customer being shown a blackout.
    """
    with pytest.raises(ValueError) as excinfo:
        build_manifest({}, modules_run=["Users", "Params", "Authz"])
    assert "vocabulary" in str(excinfo.value)


def test_an_unrecognised_name_beside_real_ones_is_still_reported_as_not_run():
    """A single unknown name is a genuine `not_run`, not a reason to refuse: a
    module that was filtered out or that crashed must still show as absent."""
    manifest = build_manifest({}, modules_run=["users", "no_such_module"])
    assert manifest["modules"]["user_auth_audit"]["status"] != "not_run"
    assert manifest["counts"]["modules_not_run"] > 0
