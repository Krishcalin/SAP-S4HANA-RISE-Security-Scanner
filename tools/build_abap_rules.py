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


# THE COPYRIGHT HEADER FOR THE GENERATED FILE LIVES HERE, NOT IN THE OUTPUT.
# The repo-wide header was hand-added to modules/abap_sast_rules.py on 2026-08-10,
# which is exactly what that file's own docstring forbids: this script writes
# HEADER + slices from scratch, so a hand-added notice is silently deleted the next
# time anyone refreshes the corpus, with no test and no CI job to notice. Put it in
# the generator and regeneration reproduces it.
#
# THE WORDING IS NOT THE REPO-WIDE ONE, AND THAT IS DELIBERATE. About 1,400 of the
# lines below are vendored verbatim from SAP-Code-Vulnerability-Analyzer, whose
# LICENSE is MIT under a different holder ("Copyright (c) 2026 KRISH"). MIT keeps
# its grant only while the notice travels with the copy, so stamping a bare
# "All Rights Reserved" over it would both misstate the terms and drop the
# attribution the licence requires. The assembled file is therefore marked as what
# it is: our assembly, around someone else's MIT-licensed content.
_COPYRIGHT = '''# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL
#
# GENERATED FILE — the rights above cover this assembly only.
# Portions vendored verbatim from SAP-Code-Vulnerability-Analyzer (abap_scanner.py
# v1.9.0), which is MIT licensed, Copyright (c) 2026 KRISH. That notice is
# reproduced here because the MIT terms require it to travel with the copy.

'''

HEADER = _COPYRIGHT + '''"""
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

# VALIDATE BEFORE WRITING, NOT AFTER. These slices are ABSOLUTE line offsets into
# a file in another repository, so anything that shifts its lines — a copyright
# header, an added import — silently reslices this one mid-expression. With the
# write first, that lands a syntax-error module on disk and only then raises: the
# scanner core stops byte-compiling on all five matrix Pythons and pytest aborts
# collection for every ABAP suite, from a script that "failed". Parsing first makes
# a bad splice leave the previous good file untouched.
import ast

ast.parse(body)
OUT.write_text(body, encoding="utf-8")
print(f"wrote {OUT}  ({body.count(chr(10))} lines) — parses clean")
