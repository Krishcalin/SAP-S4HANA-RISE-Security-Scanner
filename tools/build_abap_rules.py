# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""Assemble modules/abap_sast_rules.py from the standalone CVA repository.

The rule tables and the taint analyzer are CONTENT: ~1,400 lines of regexes,
severities, CWEs and remediation prose that were written and tested elsewhere.
Retyping them would introduce transcription errors and lose the provenance, so
they are vendored verbatim between markers, and this script is how they are
re-derived. Everything else in the source file — the BTP scanner, the reporting
mixin, the A-F grade, the hardcoded CVE table, the CLI — is dropped, per
docs/CVA_MERGE_PLAN.md §2.
"""
from pathlib import Path

CVA = Path(r"d:/KIZEN/SAP-Security-Tool/SAP-Code-Vulnerability-Analyzer/abap_scanner.py")
OUT = Path(r"d:/KIZEN/SAP-Security-Tool/SAP-S4HANA-RISE-Security-Scanner/modules/abap_sast_rules.py")

src = CVA.read_text(encoding="utf-8").splitlines(keepends=True)


def seg(first, last):
    """1-based, inclusive of `first`, exclusive of `last` — matches the line map."""
    return "".join(src[first - 1:last - 1])


HEADER = '''"""
ABAP security rule corpus and taint analyzer — VENDORED, DO NOT HAND-EDIT
=========================================================================
Derived from the standalone SAP-Code-Vulnerability-Analyzer (abap_scanner.py
v1.9.0) by ``tools/build_abap_rules.py``. Re-run that script to refresh; edits
made here will be overwritten and lose their provenance.

WHAT WAS TAKEN, AND WHAT WAS LEFT
---------------------------------
Taken: the 89 ABAP source rules, the 7 UI5/JavaScript rules, the 8 deployment
-descriptor rules, and ``TaintAnalyzer``. Those are content and one algorithm,
and there is no host analogue for either.

Left behind, per ``docs/CVA_MERGE_PLAN.md`` §2:

* ``AbapBtpScanner`` and the 30 ``BTP_API_CHECKS`` — a live OAuth client against
  SAP endpoints. This product is offline by premise, ``modules/btp_import.py``
  rejected live connections in writing, roughly three quarters of those checks
  duplicate ``modules/btp_cloud_surface.py``, and it carried the only non-stdlib
  import in the source file.
* ``SAP_VULNERABLE_PACKAGES`` — hardcoded CVE and Note numbers.
  ``modules/sap_hotnews.py`` owns that knowledge and has a customer override path.
* ``_ReportMixin`` — the host has three report engines already.
* ``security_grade()`` — computed after CLI filters, so the same file scored B or
  A/100 depending only on flags. The host has P1-P4 and a FAIR figure.
* ``Finding``, ``fingerprint()``, the OWASP category map and ``RuleSelector``.

RULE DICT SHAPE
---------------
``{"id", "name", "pattern", "severity", "category", "cwe", "description",
"recommendation"}``, optionally ``_taint_sink`` (the argument index a taint
verdict applies to) and ``_block_check``.

**The patterns are matched against a whole ABAP STATEMENT, not a line.** The
upstream engine matched lines, which both invented findings and missed real ones
depending only on formatting — see ``modules/abap_sast.py``. The patterns
themselves did not need to change for that; the unit they are fed does.
"""
from __future__ import annotations

import re

'''

MARK_RULES = "# ─── vendored: rule tables ───────────────────────────────────────────── #\n"
MARK_TAINT = "\n# ─── vendored: taint analyzer ────────────────────────────────────────── #\n"

body = (HEADER + MARK_RULES
        + seg(54, 880)        # SQLI … BTP rule tables
        + seg(939, 1263)      # EXTRA, BACKDOOR, JS, ALL_*, _ABAP_RULES_BY_ID
        + MARK_TAINT
        + seg(1647, 1903))    # noise words + TaintAnalyzer

OUT.write_text(body, encoding="utf-8")

import ast
ast.parse(body)
print(f"wrote {OUT}  ({body.count(chr(10))} lines) — parses clean")
