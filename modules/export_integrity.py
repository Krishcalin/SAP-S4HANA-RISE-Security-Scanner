"""Whether the evidence this report rests on could actually be read.

WHY THIS IS ITS OWN MODULE
--------------------------
Every other module here answers a question about the SAP estate. This one
answers a question about the EVIDENCE, and it exists because that question was
being answered wrongly in the quietest possible way.

The loader used to open every export as UTF-8. Two of the most ordinary files a
customer produces are not UTF-8:

    UTF-16LE with a BOM    what SAP GUI writes for a list download or a
                           spreadsheet export on Windows
    latin-1 / cp1252       what a German-language system produces the moment a
                           name carries an umlaut

Both raised, both were caught, and both became an EMPTY LIST. An empty list is
indistinguishable from an export that genuinely held nothing, so the scan
continued and reported over whatever remained. Measured on the sample estate,
re-encoding one file as UTF-16 took the scan from 407 findings to 383 and the
segregation-of-duties conflicts disappeared entirely, while the customer-facing
report said nothing at all about it. The only signal was one WARN line among a
hundred and thirty loaded sources.

THREE STATES, NOT TWO
---------------------
The decoder is fixed, so most of these files now load. This module covers what
remains, and it exists because a supplied file is a third state:

    absent       the customer did not send it. Already handled everywhere:
                 the source is None and every check that needs it self-skips.
    empty        the customer sent it and it held no rows. A real answer.
    unreadable   the customer sent it, believes they sent it, and we could not
                 read it. NOT an answer, and the one state that used to render
                 as one of the other two.

The loader now records the third case as None, so the coverage manifest and
every "was this supplied?" test get the honest answer without knowing anything
about encodings. That much is a correctness fix. The finding here is the other
half: a customer who supplied a file needs to be told it did not arrive, and
being quietly counted among the sources they did not send does not tell them.

FALLBACK DECODING IS REPORTED SEPARATELY, AND ON PURPOSE
--------------------------------------------------------
cp1252 decodes any byte sequence at all and never raises. That makes it a useful
last resort and a dangerous one: reaching it means the file was read, but the
text may be mojibake rather than correct - an umlaut arriving as two characters,
a name that will not match the same name in another export. That is a different
failure from a file that would not open, so it is a different finding at a lower
severity, and it names the files so somebody can look.
"""
from typing import Any, Dict, List

from modules.base_auditor import BaseAuditor


class ExportIntegrityAuditor(BaseAuditor):
    """Reports exports that were supplied but could not be read as intended."""

    CATEGORY = "Export Integrity"

    #: Set by the loader. Absent or None means every file decoded on the first
    #: attempt, which is the ordinary case and produces no findings at all.
    UNREADABLE_KEY = "_unreadable_sources"

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.findings = []
        record = self.data.get(self.UNREADABLE_KEY) or {}
        self._emit_unreadable(record)
        self._emit_fallback_decoding(record)
        return self.findings

    # ------------------------------------------------------------------ #
    def _emit_unreadable(self, record: Dict[str, Any]) -> None:
        files = record.get("files") or {}
        if not files:
            return
        sources = record.get("sources") or []
        self.finding(
            check_id="EXPORT-001",
            title="%d supplied export(s) could not be read and were treated as "
                  "missing" % len(files),
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=(
                "These files were present in the upload and could not be "
                "decoded, so the checks that depend on them did not run. They "
                "are counted as NOT supplied, which is the honest treatment - "
                "but it is not what the person who sent them believes. Every "
                "result in this report is drawn from the exports that did load, "
                "and a clean result in the areas these files feed means the "
                "question was not asked rather than that the answer was good. "
                "The most common cause is the encoding: SAP GUI writes list and "
                "spreadsheet downloads as UTF-16 on Windows, and a "
                "German-language system writes latin-1 as soon as a value "
                "carries an umlaut. Both are read correctly now, so a file "
                "still failing here is likelier to be truncated, locked by "
                "another application, or not the format its name claims.%s"
                % ("" if not sources else
                   " The logical sources lost are: %s."
                   % ", ".join(sources[:20]))),
            affected_items=["%s — %s" % (name, reason)
                            for name, reason in sorted(files.items())][:50],
            remediation=(
                "1. Re-export the named files and keep the default encoding, or "
                "save them as UTF-8 if the export tool offers the choice.\n"
                "2. Confirm the file is complete: a download interrupted part "
                "way through fails here in exactly the same way as a wrong "
                "encoding.\n"
                "3. Check the extension matches the content - a spreadsheet "
                "saved with a .csv name is a common cause.\n"
                "4. Re-run the scan once they load, and compare the finding "
                "count. The areas these sources feed were not assessed in this "
                "run, so treat any clean result in them as unmeasured rather "
                "than passed."),
            references=["docs/EXPORT_SOURCES.md — the expected file names",
                        "SAP GUI list download encodings (UTF-16 on Windows)"],
            details={
                "unreadable_files": sorted(files),
                "logical_sources_lost": sources,
                "coverage_state": "complete",
            },
            scope="aggregate",
        )

    def _emit_fallback_decoding(self, record: Dict[str, Any]) -> None:
        fallback = record.get("fallback_encodings") or {}
        if not fallback:
            return
        self.finding(
            check_id="EXPORT-002",
            title="%d export(s) decoded only via a fallback encoding"
                  % len(fallback),
            severity=self.SEVERITY_LOW,
            category=self.CATEGORY,
            description=(
                "These files were not valid UTF-8 and were read using a "
                "single-byte fallback. That fallback never fails - it maps every "
                "possible byte to some character - so the file was READ but the "
                "text may not be what was written. The usual symptom is an "
                "accented character arriving as two, which matters here because "
                "values are matched across exports by exact string: a user or "
                "vendor whose name decoded differently in two files will not "
                "join up, and the mismatch looks like absence rather than error. "
                "This is reported low because the data did load and most rows "
                "are unaffected; it is reported at all because a silently wrong "
                "decode is harder to notice than a failed one."),
            affected_items=["%s — decoded as %s" % (name, enc)
                            for name, enc in sorted(fallback.items())][:50],
            remediation=(
                "1. Open one of the named files and check any value carrying an "
                "accent, umlaut or currency symbol against the same value in "
                "SAP.\n"
                "2. If the characters are wrong, re-export as UTF-8 and re-run; "
                "if they are right, no action is needed and this finding can be "
                "accepted.\n"
                "3. Prefer UTF-8 for future exports so the fallback is never "
                "reached."),
            references=["docs/EXPORT_SOURCES.md — the expected file names"],
            details={
                "files": {k: v for k, v in sorted(fallback.items())},
                "coverage_state": "complete",
            },
            scope="aggregate",
        )
