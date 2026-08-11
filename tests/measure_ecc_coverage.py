# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""Phase 1, corrected: all 30 auditors, against a fixture, with two independent
views of the same question.

WHY TWO VIEWS. `server/coverage.build_manifest` computes a status from DATA
PRESENCE — whether the sources a module reads were supplied. That is a claim
about inputs. Whether a module actually PRODUCES anything is a different claim,
and the two disagree in both directions: a module can be `complete` and silent,
or `degraded` and still emit every finding that matters.

The estimate this phase exists to test — "fourteen of the thirty run on an ECC
export with no code change" — is a claim about the second. So the second is
measured by running them.

THE DENOMINATOR IS 30 AND IT IS DERIVED. An earlier version of this script used
the registry mirrored in tests/test_scanner.py, which holds 24. Measuring 24 and
reporting it against a claim about 30 would have been wrong by six modules, in
the flattering direction. Auditors are now enumerated by walking modules/ for
BaseAuditor subclasses.
"""
from __future__ import annotations

import ast, contextlib, importlib, io, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from modules.data_loader import DataLoader          # noqa: E402
from server import coverage                          # noqa: E402


def all_auditors():
    """(module stem, class) for every BaseAuditor subclass in modules/."""
    found = []
    for path in sorted((ROOT / "modules").glob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and any(
                    getattr(b, "id", getattr(b, "attr", "")) == "BaseAuditor"
                    for b in node.bases):
                mod = importlib.import_module(f"modules.{path.stem}")
                found.append((path.stem, getattr(mod, node.name)))
    return found


def run(fixture: str, mode: str = "on_prem"):
    quiet = io.StringIO()
    with contextlib.redirect_stdout(quiet):
        data = DataLoader(ROOT / fixture).load_all()
    manifest = coverage.build_manifest(data, deployment_mode=mode)
    mods = manifest["modules"]

    rows = []
    for stem, cls in all_auditors():
        entry = mods.get(stem)
        status = entry.get("status") if entry else "NOT-IN-MANIFEST"
        missing = entry.get("sources_missing", []) if entry else []
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                try:
                    findings = cls(data, {}, {}).run_all_checks()
                except TypeError:
                    findings = cls(data, {}).run_all_checks()
            err = ""
        except Exception as exc:                        # noqa: BLE001
            findings, err = [], f"{type(exc).__name__}: {exc}"[:70]
        rows.append({"module": stem, "status": status,
                     "findings": len(findings), "missing": missing,
                     "error": err})
    return manifest, rows


if __name__ == "__main__":
    fixture = sys.argv[1] if len(sys.argv) > 1 else "sample_data_ecc"
    manifest, rows = run(fixture)
    print(json.dumps({"fixture": fixture,
                      "counts": manifest.get("counts", {}),
                      "modules": rows}, indent=1))
