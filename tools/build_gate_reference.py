"""Regenerate the degraded-coverage table in docs/RELEASE_GATE.md.

Run:  python -m tools.build_gate_reference

WHY THIS EXISTS, AND THE IRONY THAT PROMPTED IT. `docs/RELEASE_GATE.md` carries a
table of the findings that arm `--gate`'s fail-closed path, under a note saying:
"This table is derived by reading `details["degrades_coverage"]` out of the
modules, not maintained from memory — which is how `ABAP-COV-004` came to be
missing from it." Nothing derived it. It was maintained from memory, it drifted a
second time — `MDC-PAY-002` shipped and never reached the table — and the
paragraph explaining why hand-maintained id lists drift was itself sitting inside
one.

THE GATE WAS NEVER WRONG, and that distinction matters for anyone reading this
after a scare. `--gate` keys on `details["degrades_coverage"]` on the finding, not
on a list of ids, so a coverage check arms the gate the day it is written. Only
the DOCUMENTATION drifted. But the document is what somebody reads before wiring
this into CI, and a table that silently omits a check is how a reader concludes
their pipeline is covered when it is.

HOW THE IDS ARE FOUND, INCLUDING THE INDIRECTION THAT WOULD OTHERWISE HIDE HALF
OF THEM. Two shapes emit the flag and a naive grep sees only the first:

  1. Direct — `self.finding(check_id="BTP-AUD-001", ..., details={..., "degrades_coverage": True})`
  2. Via a helper — a module defines `_coverage(check_id, ...)` or
     `_coverage_finding(*, check_id, ...)` which sets the flag and forwards, so
     the id lives at the CALL SITE and never appears beside the flag at all.

Shape 2 covers `ABAP-COV-001..006` and `CAPX-COV-001` — eight of the fifteen
rows. A generator that handled only shape 1 would have produced a table missing
more than it listed, which is a worse failure than the hand-maintained one it
replaced, because it would carry the authority of being generated.

There is a third: `BaseAuditor` emits `f"{check_id}-COVERAGE"` for a release-gated
check that could not determine whether it applied. That id is computed per caller
and cannot be enumerated, so it is listed as the pattern `<CHECK>-COVERAGE` — the
one row that is deliberately not an id.
"""
from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DOC = ROOT / "docs" / "RELEASE_GATE.md"
START = "<!-- BEGIN GENERATED: degraded-coverage findings -->"
END = "<!-- END GENERATED: degraded-coverage findings -->"

#: What each id means, in the reader's terms rather than the code's. The IDS are
#: derived; these sentences are not, because "what could not be looked at" is a
#: human sentence and no AST holds it. An id with no entry here still appears —
#: with its description blank and a marker — so a new coverage check shows up as
#: undescribed rather than not at all.
DESCRIPTIONS = {
    "ABAP-LEX-001": "the lexer lost its place in a source file",
    "ABAP-COV-001": "`--abap-src` names a path that is not a directory — the scan never ran",
    "ABAP-COV-002": "the source tree held no file the scanner recognises",
    "ABAP-COV-003": "files that could not be read were skipped",
    "ABAP-COV-004": "source files were present in a language this scanner has no rules for",
    "ABAP-COV-005": "no CDS access-control artefact in the tree, so view protection was not assessed",
    "ABAP-COV-006": "roleless views whose exposure could not be established",
    "BASELINE-000": "no profile parameter export, so eighteen parameters went unjudged",
    "PARAM-MISSING-OTHER": "parameters absent from an export nobody declared complete",
    "BTP-AUD-001": "subaccounts whose audit-log state no supplied export settles",
    "CAPX-COV-001": "`--cap-src` unreadable, or a descriptor or CDS construct that would not parse",
    "VBM-DATA-001": "the vendor / bank master export carried no usable rows",
    "MDC-PAY-002": "bank changes were found and no payment-run export was supplied, so "
                   "whether any were paid was never tested",
    "HOTNEWS-COVERAGE": "the note catalogue is a curated subset, not the full patch history",
    "HOTNEWS-010": "exposure could not be established against the installed releases",
    "CSA-SAP-002": "SAP Cloud ALM could not evaluate some policies, so its silence "
                   "on them is not a pass",
    "CSA-COV-001": "a CSA results export was supplied and no row in it named a policy",
}

#: Computed per caller, so it cannot be enumerated. Kept as a row because a
#: reader needs to know the shape exists.
PATTERN_ROWS = [
    ("`<CHECK>-COVERAGE`", "any",
     "a release-gated check could not determine whether it applied"),
]

#: Helpers that set the flag themselves and take the id from their caller.
#: Detected structurally below; named here only for the error message when a
#: module grows a third one.
_KNOWN_HELPERS = ("_coverage", "_coverage_finding")


def _mentions_flag(node: ast.AST) -> bool:
    """Does this subtree name `degrades_coverage`?"""
    return any(isinstance(sub, ast.Constant) and sub.value == "degrades_coverage"
               for sub in ast.walk(node))


def _literal_kwarg(call: ast.Call, name: str):
    for kw in call.keywords:
        if kw.arg == name and isinstance(kw.value, ast.Constant):
            return kw.value.value
    return None


def _is_finding_call(call: ast.Call) -> bool:
    fn = call.func
    return (fn.attr if isinstance(fn, ast.Attribute)
            else getattr(fn, "id", "")) == "finding"


def collect(module: Path):
    """(ids, helpers) for one module.

    PER CALL, NOT PER FUNCTION, and the difference is not academic. The first
    version of this asked "does this function mention the flag anywhere, and what
    check ids does it name" — which swept up every SIBLING emission in the same
    method. `check_bank_change_then_payment` raises MDC-PAY-002 (a coverage
    finding) and MDC-PAY-001 (a CRITICAL payment finding) from one body, so the
    table gained a row claiming the gate fails closed on a real finding it has no
    such relationship with. A generated table carries more authority than a
    hand-written one; being wrong in it is worse, not better.

    So a direct emission is a call to `finding(...)` whose OWN `details` argument
    names the flag, and nothing else counts.
    """
    tree = ast.parse(module.read_text(encoding="utf-8", errors="replace"))
    ids, helpers = set(), set()

    for node in ast.walk(tree):
        # Shape 1 — the flag is in this call's own details mapping.
        if isinstance(node, ast.Call) and _is_finding_call(node):
            details = next((kw.value for kw in node.keywords
                            if kw.arg == "details"), None)
            if details is not None and _mentions_flag(details):
                literal = _literal_kwarg(node, "check_id")
                if literal:
                    ids.add(literal)
            continue

        # Shape 2 — a helper that sets the flag on a details mapping it was
        # handed, then forwards a check_id it received. The id lives at the call
        # site and never appears beside the flag.
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            assigns_flag = any(
                isinstance(sub, ast.Assign)
                and any(isinstance(tgt, ast.Subscript)
                        and isinstance(tgt.slice, ast.Constant)
                        and tgt.slice.value == "degrades_coverage"
                        for tgt in sub.targets)
                for sub in ast.walk(node))
            if assigns_flag:
                helpers.add(node.name)
    return ids, helpers


def resolve_helper_calls(module: Path, helpers: set) -> set:
    """Ids passed to a coverage helper, positionally or by keyword."""
    if not helpers:
        return set()
    tree = ast.parse(module.read_text(encoding="utf-8", errors="replace"))
    ids = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
        if name not in helpers:
            continue
        literal = _literal_kwarg(node, "check_id")
        if literal:
            ids.add(literal)
            continue
        if node.args and isinstance(node.args[0], ast.Constant) \
                and isinstance(node.args[0].value, str):
            ids.add(node.args[0].value)
    return ids


def gather():
    """{check_id: module_stem} across every module."""
    found = {}
    for module in sorted((ROOT / "modules").glob("*.py")):
        text = module.read_text(encoding="utf-8", errors="replace")
        if "degrades_coverage" not in text:
            continue
        ids, helpers = collect(module)
        ids |= resolve_helper_calls(module, helpers)
        # `BaseAuditor`'s is the computed `<CHECK>-COVERAGE` shape, listed as a
        # pattern rather than an id.
        if module.stem == "base_auditor":
            continue
        for cid in ids:
            found.setdefault(cid, module.stem)
    return found


def build() -> str:
    found = gather()
    rows = []
    for cid in sorted(found, key=lambda c: (found[c], c)):
        description = DESCRIPTIONS.get(cid)
        if description is None:
            description = ("**undescribed** — add it to DESCRIPTIONS in "
                           "tools/build_gate_reference.py")
        rows.append("| `%s` | `%s` | %s |" % (cid, found[cid], description))
    for cid, module, description in PATTERN_ROWS:
        rows.append("| %s | %s | %s |" % (cid, module, description))

    return "\n".join([
        START,
        "",
        "| check | module | what could not be looked at |",
        "|---|---|---|",
        *rows,
        "",
        "> **This table is generated** by `python -m tools.build_gate_reference`,",
        "> which reads `details[\"degrades_coverage\"]` out of the modules —",
        "> including the ids that reach it through a `_coverage` helper and never",
        "> appear beside the flag. It used to say it was derived while being",
        "> maintained by hand, which is how `ABAP-COV-004` and then `MDC-PAY-002`",
        "> came to be missing from it.",
        ">",
        "> The gate itself was never wrong either time: it reads the flag on the",
        "> finding and does not know these ids, which is exactly the property the",
        "> paragraph above describes. Only the documentation drifted — and this is",
        "> the document somebody reads before wiring the gate into CI, so a table",
        "> that silently omits a check is how a reader concludes their pipeline is",
        "> covered when it is not.",
        END,
    ])


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
                        help="fail if the committed document is not current")
    args = parser.parse_args(argv)

    doc = DOC.read_text(encoding="utf-8")
    block = build()
    if START not in doc or END not in doc:
        print("docs/RELEASE_GATE.md has no generated block; add the markers:\n"
              "  %s\n  %s" % (START, END), file=sys.stderr)
        return 1
    updated = re.sub(re.escape(START) + r".*?" + re.escape(END), lambda _: block,
                     doc, count=1, flags=re.S)

    if args.check:
        if updated != doc:
            print("docs/RELEASE_GATE.md is out of date — regenerate it with "
                  "`python -m tools.build_gate_reference`", file=sys.stderr)
            return 1
        print("docs/RELEASE_GATE.md is current")
        return 0

    DOC.write_text(updated, encoding="utf-8")
    print("Wrote docs/RELEASE_GATE.md: %d degraded-coverage findings"
          % len(gather()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
