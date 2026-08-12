# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""Generate docs/CHECKS_REFERENCE.md from the code, and fail CI when it drifts.

    python -m tools.build_checks_reference           # rewrite the document
    python -m tools.build_checks_reference --check   # exit 1 if it is stale

WHY THIS EXISTS
---------------
The hand-written reference was measured at 31% coverage: 193 of the 621 check ids
the code can emit, with twelve of the thirty audit modules absent entirely. That
was the tolerable part. The intolerable part was that eleven GRC rows and one FIN
row carried the WRONG TITLE for a real id, and four rows carried the WRONG
SEVERITY — a reader trusting it was misinformed rather than under-informed, and a
wrong severity is the kind of error that reaches a customer's report.

It had drifted through four generations of check families without one edit. The
answer to that is not another careful edit; it is to stop writing it by hand and
fail the build when the file and the code disagree, exactly as the `sap-content`
and `schema-upgrade` jobs already do for the other two vocabularies.

WHAT IT REFUSES TO INVENT
-------------------------
Roughly one title in seven is an f-string — `f"Default user {uname} is unlocked"`
— and a dozen severities are conditional on what the check found. A generator that
picked one branch would produce exactly the failure that made the old document
dangerous: a plausible, specific, wrong claim, this time with a machine's
authority behind it.

So a field that cannot be determined statically is rendered as VARIES with its
template shown, never resolved to one example. That is less tidy and it is the
whole point: the code genuinely does not have one title for those checks.
"""
from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

TARGET = ROOT / "docs" / "CHECKS_REFERENCE.md"

#: Calls that emit a finding. The three wrappers forward `check_id` positionally,
#: which is why a naive grep for `finding(` undercounts the catalogue.
EMITTERS = {"finding", "_emit", "_flag", "_coverage_finding",
            "_finding_for_unset_parameter"}

#: BaseAuditor's severity constants, resolved so `self.SEVERITY_HIGH` reads as
#: HIGH rather than as an unresolvable attribute.
SEVERITY_CONSTANTS = {
    "SEVERITY_CRITICAL": "CRITICAL", "SEVERITY_HIGH": "HIGH",
    "SEVERITY_MEDIUM": "MEDIUM", "SEVERITY_LOW": "LOW", "SEVERITY_INFO": "INFO",
}

VARIES = "*varies*"


def _literal(node: Optional[ast.AST]) -> Optional[str]:
    """The string this expression definitely is, or None if it varies."""
    if node is None:
        return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Attribute) and node.attr in SEVERITY_CONSTANTS:
        return SEVERITY_CONSTANTS[node.attr]
    return None


def _template(node: Optional[ast.AST]) -> Optional[str]:
    """A readable sketch of a dynamic value, so VARIES is not a dead end.

    An f-string becomes its literal parts with the substitutions marked, which is
    enough for a reader to recognise the finding without claiming a value the
    code does not have.
    """
    if isinstance(node, ast.JoinedStr):
        out = []
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                out.append(part.value)
            else:
                out.append("…")
        return "".join(out).strip()
    if isinstance(node, ast.IfExp):
        a, b = _literal(node.body), _literal(node.orelse)
        if a and b:
            return f"{a} or {b}"
    return None


def _severities(node: Optional[ast.AST]) -> Tuple[Optional[str], Optional[str]]:
    """(resolved, template). A conditional severity yields both its branches."""
    lit = _literal(node)
    if lit:
        return lit, None
    if isinstance(node, ast.IfExp):
        a, b = _literal(node.body), _literal(node.orelse)
        if a and b:
            return None, " or ".join(sorted({a, b}))
    return None, None


class Check:
    __slots__ = ("check_id", "title", "title_template", "severity",
                 "severity_template", "category", "module", "line")

    def __init__(self, **kw: Any) -> None:
        for k in self.__slots__:
            setattr(self, k, kw.get(k))

    def sort_key(self) -> Tuple[str, str]:
        m = re.match(r"^([A-Z0-9]+(?:-[A-Z]+)*)-(\d+)$", self.check_id or "")
        return (m.group(1), m.group(2).zfill(4)) if m else (self.check_id or "", "")


def wrapper_signatures() -> Dict[str, List[str]]:
    """Positional parameter names for each emitter, READ FROM ITS OWN `def`.

    The wrappers forward positionally — `_emit("AUTH-001", "title", SEVERITY, …)`
    — so a keyword-only reader finds nothing and renders sixteen checks as
    "varies / varies", which is noise dressed as documentation.

    Derived rather than hardcoded because a hardcoded order is a second copy of
    the signature, and the day somebody inserts a parameter the table silently
    starts reporting the description as the title. Read the def, and it cannot
    drift.
    """
    sigs: Dict[str, List[str]] = {}
    for path in sorted((ROOT / "modules").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name not in EMITTERS:
                continue
            names = [a.arg for a in node.args.args if a.arg != "self"]
            if names and node.name not in sigs:
                sigs[node.name] = names
    return sigs


def collect_literal_checks() -> List[Check]:
    """Every check id written as a literal, with what can be known about it."""
    found: Dict[str, Check] = {}
    sigs = wrapper_signatures()
    for path in sorted((ROOT / "modules").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = getattr(node.func, "attr", getattr(node.func, "id", ""))
            if fn not in EMITTERS:
                continue
            kw = {k.arg: k.value for k in node.keywords if k.arg}
            # Positional arguments, resolved through the emitter's own signature.
            for index, value in enumerate(node.args):
                names = sigs.get(fn) or ["check_id", "title", "severity", "category",
                                         "description"]
                if index < len(names):
                    kw.setdefault(names[index], value)
            cid_node = kw.get("check_id")
            cid = _literal(cid_node)
            if not cid or not re.match(r"^[A-Z]", cid):
                continue
            severity, sev_template = _severities(kw.get("severity"))
            check = Check(
                check_id=cid,
                title=_literal(kw.get("title")),
                title_template=_template(kw.get("title")),
                severity=severity,
                severity_template=sev_template,
                category=_literal(kw.get("category")),
                module=path.stem,
                line=node.lineno,
            )
            # The SAME id emitted from several sites is normal — one check, several
            # branches. Keep the first, but if a later site disagrees on severity,
            # the id genuinely has more than one and must say so rather than
            # inheriting whichever branch the walk happened to reach first.
            if cid in found:
                prev = found[cid]
                if prev.severity and check.severity and prev.severity != check.severity:
                    prev.severity = None
                    prev.severity_template = " or ".join(
                        sorted({prev.severity_template or "", check.severity}
                               - {""}) or [check.severity])
                if prev.title and check.title and prev.title != check.title:
                    prev.title_template = prev.title
                    prev.title = None
                continue
            found[cid] = check
    return sorted(found.values(), key=lambda c: c.sort_key())


def collect_dynamic_families() -> List[Dict[str, Any]]:
    """Id families built at runtime from a shipped table.

    Resolved by IMPORTING the tables rather than by parsing them, because the
    tables are the authority and a second reading of them could disagree.
    """
    families: List[Dict[str, Any]] = []

    from modules.security_params import SecurityParamAuditor
    rules = SecurityParamAuditor({}, {}).effective_rules()
    families.append({
        "pattern": "PARAM-<parameter name>",
        "count": len(rules),
        "source": "modules/security_params.py — BASELINE + ECS_RULES",
        "examples": sorted(rules)[:6],
        "note": "One id per judged profile parameter. `PARAM-000`, `PARAM-MISSING` "
                "and `PARAM-MISSING-OTHER` are fixed ids and appear in the literal "
                "table above.",
    })

    # THREE TABLES, NOT ONE. ALL_ABAP_SAST_RULES is the ABAP/UI5 set; the
    # JavaScript and BTP-descriptor rules live in their own tables and emit ids in
    # the SAME `ABAP-` namespace (ABAP-JS-001, ABAP-BTP-001). Reading only the
    # first table undercounted the catalogue by 15 and the shortfall was invisible,
    # because 118 is a plausible-looking number.
    from modules.abap_sast import (ALL_ABAP_SAST_RULES, ALL_BTP_CONFIG_RULES,
                                   ALL_JS_RULES)

    def _rule_ids(table: Any) -> List[str]:
        return [str(r.get("id")) if isinstance(r, dict) else str(r) for r in table]

    abap_ids = (_rule_ids(ALL_ABAP_SAST_RULES) + _rule_ids(ALL_JS_RULES)
                + _rule_ids(ALL_BTP_CONFIG_RULES))
    families.append({
        "pattern": "ABAP-<rule id>",
        "count": len(abap_ids),
        "source": ("modules/abap_sast.py — ALL_ABAP_SAST_RULES "
                   f"({len(ALL_ABAP_SAST_RULES)}) + ALL_JS_RULES "
                   f"({len(ALL_JS_RULES)}) + ALL_BTP_CONFIG_RULES "
                   f"({len(ALL_BTP_CONFIG_RULES)})"),
        "examples": sorted(abap_ids)[:6],
        "note": "Custom-code scan rules. All three tables emit into the same "
                "`ABAP-` namespace: ABAP/UI5, JavaScript, and BTP descriptors.",
    })

    from modules.access_risk_analysis import AccessRiskAnalysisAuditor
    families.append({
        "pattern": "ARA-<risk id>",
        "count": len(AccessRiskAnalysisAuditor.RULESET),
        "source": "modules/access_risk_analysis.py — RULESET",
        "examples": sorted(map(str, AccessRiskAnalysisAuditor.RULESET))[:6],
        "note": "Segregation-of-duties and critical-access risks, extendable by a "
                "customer's own `ara_ruleset.json`.",
    })

    from modules.atc_import import AtcImportAuditor
    families.append({
        "pattern": "ATC-<family>",
        "count": len(AtcImportAuditor.FAMILIES),
        "source": "modules/atc_import.py — FAMILIES",
        "examples": [str(f.get("family")) for f in AtcImportAuditor.FAMILIES][:6],
        "note": "ABAP Test Cockpit finding families, imported from an ATC export.",
    })

    from modules.iam_advanced import AdvancedIamAuditor
    families.append({
        "pattern": "IAM-<sod rule>",
        "count": len(AdvancedIamAuditor.DEFAULT_SOD_RULES),
        "source": "modules/iam_advanced.py — DEFAULT_SOD_RULES",
        "examples": sorted(map(str, AdvancedIamAuditor.DEFAULT_SOD_RULES))[:6],
        "note": "Conflicting-duty pairs.",
    })

    # NO try/except HERE, DELIBERATELY, AND THIS IS THE SECOND TIME TODAY.
    #
    # The first version wrapped these imports in `except Exception: pass`, guessed
    # two class names wrong, and silently produced a reference missing 37 ids —
    # the ARA ruleset and every ATC family. It printed a cheerful success line
    # while doing it. That is exactly the bare-except failure that was just
    # removed from locate_engine, reintroduced by me in the tool built to stop
    # documents lying.
    #
    # A family that cannot be resolved must break the build. A generated document
    # that quietly omits a family is worse than the hand-written one it replaced,
    # because nobody re-reads a generated file.
    empty = [f["pattern"] for f in families if not f["count"]]
    if empty:
        raise RuntimeError(
            f"runtime check families resolved to zero entries: {empty}. "
            f"A family with no members is a broken table reference, not an empty "
            f"table — fix the source rather than shipping a reference without it.")
    return families


def _cell(value: Optional[str], template: Optional[str]) -> str:
    if value:
        return value.replace("|", "\\|")
    if template:
        return f"{VARIES} — {template.replace('|', chr(92) + '|')}"
    return VARIES


def render() -> str:
    checks = collect_literal_checks()
    families = collect_dynamic_families()
    by_module: Dict[str, List[Check]] = {}
    for c in checks:
        by_module.setdefault(c.module, []).append(c)

    dynamic_total = sum(f["count"] for f in families)
    varying_titles = sum(1 for c in checks if not c.title)
    varying_sev = sum(1 for c in checks if not c.severity)

    out: List[str] = []
    w = out.append
    w("# Check reference")
    w("")
    w("<!-- GENERATED FILE — DO NOT EDIT BY HAND.")
    w("     Produced by tools/build_checks_reference.py from the code itself.")
    w("     CI re-runs the generator and fails if this file disagrees, so an edit")
    w("     here is reverted by the next build rather than merged. Change the")
    w("     check, then regenerate:  python -m tools.build_checks_reference -->")
    w("")
    w(f"**{len(checks)}** check ids are written as literals in `modules/`, across "
      f"**{len(by_module)}** modules. A further **{dynamic_total}** are built at "
      f"runtime from shipped rule tables, giving **{len(checks) + dynamic_total}** "
      f"in total.")
    w("")
    w("## What this file does not claim")
    w("")
    w(f"**{varying_titles} of the {len(checks)} titles and {varying_sev} of the "
      f"severities are not fixed.** A title is often an f-string naming the object "
      f"it found, and a severity is often conditional on what was found — a locked "
      f"account and an unlocked one are the same check at different severities.")
    w("")
    w(f"Those are rendered as {VARIES}, with the template where one can be shown. "
      "They are **not** resolved to one example. The previous hand-written version "
      "of this file froze one branch as fact and ended up carrying eleven wrong "
      "titles and four wrong severities; a generator repeating that mistake would "
      "carry a machine's authority while doing it.")
    w("")
    w("A check's **identity** is its id. Severity is a judgement about a particular "
      "finding and is not part of it.")
    w("")
    w("## Checks by module")
    w("")
    for module in sorted(by_module):
        rows = by_module[module]
        categories = sorted({c.category for c in rows if c.category})
        w(f"### `{module}` — {len(rows)} check"
          f"{'' if len(rows) == 1 else 's'}")
        w("")
        if categories:
            w(f"Category: {', '.join(categories)}")
            w("")
        w("| Check | Severity | Title |")
        w("|---|---|---|")
        for c in rows:
            w(f"| `{c.check_id}` | {_cell(c.severity, c.severity_template)} "
              f"| {_cell(c.title, c.title_template)} |")
        w("")

    if families:
        w("## Runtime check families")
        w("")
        w("These ids are constructed per entry in a shipped table, so the catalogue "
          "grows with the table and not with the code.")
        w("")
        for f in families:
            w(f"### `{f['pattern']}` — {f['count']}")
            w("")
            w(f"Source: `{f['source']}`")
            w("")
            if f.get("examples"):
                w("Examples: " + ", ".join(f"`{e}`" for e in f["examples"]))
                w("")
            if f.get("note"):
                w(f["note"])
                w("")

    w("---")
    w("")
    w("Generated by `tools/build_checks_reference.py`. Run "
      "`python -m tools.build_checks_reference` after changing a check.")
    return "\n".join(out) + "\n"


def _display(path: Path) -> str:
    """A repo-relative path where possible, the full path otherwise.

    `relative_to` RAISES when the target is outside the repo, and the raise
    happened while building an error message — so a tool reporting a stale
    document crashed instead of reporting it. Diagnostics must not be the thing
    that fails.
    """
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if the committed file is stale; write nothing")
    args = ap.parse_args(argv)

    generated = render()
    if args.check:
        current = TARGET.read_text(encoding="utf-8") if TARGET.exists() else ""
        if current.replace("\r\n", "\n") == generated:
            print(f"{_display(TARGET)} is up to date.")
            return 0
        print(f"{_display(TARGET)} IS STALE.\n"
              f"The code emits checks this file does not describe, or describes "
              f"them differently.\n"
              f"Regenerate with:  python -m tools.build_checks_reference",
              file=sys.stderr)
        return 1

    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(generated, encoding="utf-8")
    checks = collect_literal_checks()
    families = collect_dynamic_families()
    print(f"Wrote {_display(TARGET)}: {len(checks)} literal ids + "
          f"{sum(f['count'] for f in families)} from {len(families)} runtime "
          f"families.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
