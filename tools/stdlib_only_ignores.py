"""Which test files the stdlib-only CI job must skip, derived rather than listed.

WHY THIS EXISTS
`.github/workflows/tests.yml` runs the whole suite on five Pythons with ONLY
pytest installed — that job is what proves a third-party import has not crept
into the scanner core. Tests that exercise the SERVER tier cannot run there, so
they were excluded by a hand-written `--ignore=` list.

The list rotted twice. Its own comment recorded the first time; by the second,
ELEVEN test files imported `server` at module level without being listed, and
survived only because the particular modules they imported happened to be
dependency-free. That is not a passing job, it is a job that has not failed yet.

WHAT IS AND IS NOT SKIPPED
The question is NOT "does this test import server". `server/totp.py` and
`server/qr.py` import only the standard library, and running their suites on
every Python in the matrix is deliberate — 86 tests of the RFC 6238 core and the
ISO/IEC 18004 encoder against published vectors. A naive rule would have thrown
that away.

The question is "does importing this test REQUIRE a package the job does not
install". So: resolve each test's module-level `server.*` imports, follow them
transitively through server/, and skip the test only if something on that path
needs a third-party import.

Run it directly to see the answer:

    python -m tools.stdlib_only_ignores            # one --ignore= per line
    python -m tools.stdlib_only_ignores --explain  # and why

Stdlib only, because the job that calls it has nothing else.
"""
from __future__ import annotations

import argparse
import ast
from pathlib import Path
from typing import Dict, Set

ROOT = Path(__file__).resolve().parents[1]

#: Packages the stdlib-only job DOES install. pytest is the runner; everything
#: else on this list would be a lie.
AVAILABLE = {"pytest", "_pytest", "py"}

#: First-party roots, which are never third-party by definition.
FIRST_PARTY = {"server", "modules", "collect", "data", "tools", "tests"}

#: Import names for the packages the project declares. `python-multipart`
#: installs as `multipart`, and the others carry transitive imports that appear
#: in source without ever being named in requirements — starlette and anyio
#: arrive with fastapi, and code imports them directly.
#:
#: WHY THIS LIST EXISTS RATHER THAN `sys.stdlib_module_names`. That attribute
#: arrived in Python 3.10 and this file RUNS INSIDE the job it configures, which
#: is a 3.8-to-3.12 matrix — using it here would have crashed the job on two
#: interpreters, and the guard in tests/test_python_matrix.py only inspects test
#: files, so nothing would have caught it before CI did. Asking "is this one of
#: the four packages we depend on" is both version-proof and a smaller question
#: than "is this in the standard library".
#:
#: tests/test_coverage_cli_names.py holds it against requirements.txt, so a new
#: dependency cannot be added without appearing here.
DECLARED_IMPORT_NAMES = {
    "fastapi": "fastapi",
    "uvicorn": "uvicorn",
    "psycopg": "psycopg",
    "python-multipart": "multipart",
}

#: Everything the four declared packages drag in that source imports by name.
THIRD_PARTY = set(DECLARED_IMPORT_NAMES.values()) | {
    "starlette",      # arrives with fastapi; imported directly by server/app.py
    "anyio",          # arrives with starlette; imported by a test
    "httpx",          # test-only, installed by the server job alone
    "yaml",           # PyYAML, dev-only
    "PIL",            # Pillow, used by the brand-asset job only
}


def _imports(tree: ast.AST) -> Set[str]:
    """EVERY import, at any depth — not only the module-level ones.

    The first version of this looked at top-level imports only, reasoning that a
    nested import cannot break COLLECTION. True, and beside the point: it breaks
    the TEST. Measured in a pytest-only virtualenv, the module-level rule left 28
    failures and 13 errors, because a suite that does `from server import db`
    inside a fixture imports it the moment the fixture runs.

    So the rule is deliberately conservative. Over-excluding costs a little
    matrix coverage for a test the `server` job runs anyway; under-excluding
    turns the job red for a reason unrelated to the change that tripped it, which
    is precisely how the hand-written list wasted people's time twice.
    """
    found: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            found.add(node.module)
            # `from server import ingest` names the PACKAGE, not the submodule,
            # so resolving only `node.module` looked for a file called
            # `server.py` — which does not exist — and concluded the import was
            # harmless. That is how tests/test_derivations_match_the_corpus.py,
            # which pulls server.ingest inside a fixture, went on erroring in a
            # pytest-only environment after the first repair.
            found |= {f"{node.module}.{alias.name}" for alias in node.names}
    return found


def _needs_third_party(module_path: Path, seen: Dict[Path, bool]) -> bool:
    """Does importing this file require a package the job does not install?

    Transitive within the first-party tree: `server.queries` importing
    `server.db` importing `psycopg` makes queries — and anything importing it —
    unavailable here.
    """
    resolved = module_path.resolve()
    if resolved in seen:
        return seen[resolved]
    seen[resolved] = False                       # cycles resolve to "no", then settle
    if not resolved.exists():
        return False

    tree = ast.parse(resolved.read_text(encoding="utf-8"), str(resolved))
    verdict = False
    for name in _imports(tree):
        root = name.split(".")[0]
        if root in THIRD_PARTY:
            verdict = True
            break
        if root not in FIRST_PARTY:
            continue                      # stdlib, or the runner itself
        target = ROOT / Path(*name.split(".")).with_suffix(".py")
        if target.exists() and _needs_third_party(target, seen):
            verdict = True
            break
    seen[resolved] = verdict
    return verdict


def unavailable_here() -> Dict[str, str]:
    """{test file: the first-party module that makes it unrunnable}."""
    seen: Dict[Path, bool] = {}
    out: Dict[str, str] = {}
    for path in sorted((ROOT / "tests").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
        for name in sorted(_imports(tree)):
            root = name.split(".")[0]
            if root in THIRD_PARTY:
                out[path.relative_to(ROOT).as_posix()] = name
                break
            if root not in FIRST_PARTY:
                continue                  # stdlib, or the runner itself
            target = ROOT / Path(*name.split(".")).with_suffix(".py")
            if target.exists() and _needs_third_party(target, seen):
                out[path.relative_to(ROOT).as_posix()] = name
                break
    return out


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--explain", action="store_true",
                        help="print what makes each file unrunnable")
    args = parser.parse_args(argv)

    found = unavailable_here()
    for test, because in found.items():
        if args.explain:
            print(f"{test:<46} needs {because}")
        else:
            print(f"--ignore={test}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
