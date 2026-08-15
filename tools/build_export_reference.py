# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""Generate docs/EXPORT_SOURCES.md — every file the scanner can read.

Run:  python -m tools.build_export_reference

WHY THIS EXISTS. docs/EXPORT_GUIDE.md is hand-written and gives a step-by-step
procedure for the sources a first scan needs. It names 36 of the 123 logical
sources the loader accepts. The other 87 were mentioned nowhere at all — so a
customer could not supply them, the coverage manifest reported them "not
supplied" for ever, and the checks behind them could never fire. A gap nobody can
see is worse than a gap on a list.

WHAT IT DELIBERATELY DOES NOT DO. It does not invent an export procedure. Writing
"run transaction XY12 and save the result" for a source whose procedure has not
been verified would put a fabricated SAP transaction code in front of a customer,
which is precisely the confidently-wrong failure the whole product is built to
avoid. Where no procedure is documented, this file says so in that row and leaves
it for someone who can verify it.

Everything here is derived: the filenames from the loader's own table, the
consumers from the AST, the RISE reachability from the coverage registry.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

OUT = ROOT / "docs" / "EXPORT_SOURCES.md"
GUIDE = ROOT / "docs" / "EXPORT_GUIDE.md"

HEADER = """# Export source reference

<!-- GENERATED FILE — DO NOT EDIT BY HAND.
     Produced by tools/build_export_reference.py from the code itself.
     Change the loader or the modules, then regenerate:
       python -m tools.build_export_reference -->

Every logical source the scanner can read, what it enables, and whether
[`EXPORT_GUIDE.md`](EXPORT_GUIDE.md) tells you how to produce it.

**{total} logical sources.** {documented} have a written procedure in the export
guide; **{undocumented} do not yet** — those rows name the files the loader will
accept, so a source you already have to hand can be supplied today, but the
step-by-step extraction has not been verified and is deliberately not guessed.

Omitting a source is always safe. The checks behind it do not run, and the
coverage manifest counts it as *not supplied* rather than passing it off as
clean — see chapter 13 of the architecture guide.

"""


def build() -> str:
    from modules.coverage import (RISE_UNREACHABLE_SOURCES, all_logical_sources,
                                  module_sources)
    from modules.data_loader import DataLoader

    guide = GUIDE.read_text(encoding="utf-8")
    files = {slot: list(names) for slot, names in DataLoader.FILE_MAP.items()}

    consumers: dict = {}
    for module, srcs in module_sources().items():
        for src in srcs:
            consumers.setdefault(src, set()).add(module)

    sources = sorted(all_logical_sources())
    rows, documented = [], 0
    for src in sources:
        names = files.get(src, [])
        has_doc = any(c in guide for c in [src] + names)
        documented += bool(has_doc)
        rise = "not obtainable" if src in RISE_UNREACHABLE_SOURCES else ""
        rows.append((src, names, sorted(consumers.get(src, [])), has_doc, rise))

    out = [HEADER.format(total=len(sources), documented=documented,
                         undocumented=len(sources) - documented)]
    out.append("| Source | Files the loader accepts | Feeds | Procedure |")
    out.append("|---|---|---|---|")
    for src, names, mods, has_doc, rise in rows:
        note = "documented" if has_doc else "**not yet written**"
        if rise:
            note += " · not obtainable in RISE"
        out.append("| `%s` | %s | %s | %s |"
                   % (src,
                      ", ".join("`%s`" % n for n in names) or "—",
                      ", ".join("`%s`" % m for m in mods) or "—",
                      note))
    out.append("")
    out.append("## What “not yet written” means")
    out.append("")
    out.append("The scanner will read the file if you supply it under one of the "
               "names above. What is missing is a verified procedure for "
               "producing it — which transaction, which selection, which "
               "columns. Those are not guessed here: a wrong transaction code in "
               "an export guide costs a customer an afternoon and costs the "
               "product its credibility.")
    out.append("")
    return "\n".join(out)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
                        help="fail if the file on disk is not what this would write")
    args = parser.parse_args(argv)

    text = build()
    if args.check:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != text:
            print("docs/EXPORT_SOURCES.md is out of date — regenerate with "
                  "`python -m tools.build_export_reference`", file=sys.stderr)
            return 1
        print("docs/EXPORT_SOURCES.md is current")
        return 0

    OUT.write_text(text, encoding="utf-8")
    total = text.count("\n| `")
    print("Wrote docs/EXPORT_SOURCES.md: %d sources" % total)
    return 0


if __name__ == "__main__":
    sys.exit(main())
