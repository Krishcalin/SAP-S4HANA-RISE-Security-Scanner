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

A THIRD CAUSE, WITH THE SAME OUTCOME
------------------------------------
The two states above are about whether the BYTES could be read. A file can
decode perfectly, parse into rows, be counted among the sources the customer
supplied - and still be useless, because the column its consumers join on is not
in it. Excel drops a column when somebody deletes what looks like an empty one;
a hand-built extract omits a field nobody thought mattered; a report variant is
saved with a narrower layout.

The outcome is identical to the encoding failure this module was built for, and
it was measured the same way. Dropping ONE column from the sample estate:

    security_params.csv   NAME       58 checks stop firing
    security_params.csv   VALUE      53
    role_auth_values.csv  OBJECT     30
    role_auth_values.csv  FIELD      28
    role_auth_values.csv  AGR_NAME   27
    role_auth_values.csv  LOW        27
    user_roles.csv        AGR_NAME    9   (every segregation-of-duties finding)

In each case the scan completed, the report was produced, the coverage manifest
counted the file as SUPPLIED, and nothing anywhere said a column was missing.
`REQUIRED_COLUMNS` below is that measurement written down: every entry earns its
place by a counted number of checks that go silent without it, and the test
re-runs the drop to prove the number is still true.

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

    #: source -> [(accepted spellings, what it is, checks lost without it)]
    #:
    #: THE SPELLINGS ARE THE READERS', NOT THIS MODULE'S. Where the consumers
    #: share a vocabulary it is imported rather than restated - a check that
    #: rejected a column `security_params` happily reads would be a false alarm
    #: on a valid export, which is a worse failure than the silence it replaces.
    #:
    #: The counts come from dropping each column from the sample estate and
    #: re-running every auditor. `tests/test_export_missing_columns.py` repeats
    #: that measurement, so an entry whose cost falls to zero fails rather than
    #: lingering as a claim nobody rechecked.
    REQUIRED_COLUMNS = {
        "security_params": [
            (BaseAuditor.PARAM_NAME_COLUMNS, "the parameter name", 58),
            (BaseAuditor.PARAM_VALUE_COLUMNS, "the parameter value", 53),
        ],
        "role_auth_values": [
            (("OBJECT", "AUTH_OBJECT"), "the authorization object", 30),
            (("FIELD", "FIELD_NAME"), "the authorization field", 28),
            (("AGR_NAME", "ROLE", "AGR"), "the role name", 27),
            (("LOW", "VALUE", "VON"), "the authorization value", 27),
        ],
        "user_roles": [
            (("AGR_NAME", "ROLE", "AGR"), "the role name", 9),
            (("UNAME", "USER", "BNAME", "USERNAME"), "the user name", 8),
        ],
        "hana_granted_privileges": [
            (("PRIVILEGE", "PRIVILEGE_NAME", "SYSTEM_PRIVILEGE"),
             "the privilege", 6),
        ],
        "users": [
            (("BNAME", "USERNAME", "NAME"), "the user name", 3),
        ],
    }

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.findings = []
        record = self.data.get(self.UNREADABLE_KEY) or {}
        self._emit_unreadable(record)
        self._emit_fallback_decoding(record)
        self._emit_missing_columns()
        return self.findings

    # ------------------------------------------------------------------ #
    def _emit_missing_columns(self) -> None:
        """A file that parsed into rows and lost a column its readers need.

        ONLY WHERE THERE ARE ROWS TO LOOK AT. An absent source is already
        handled everywhere - the value is None and every consumer self-skips -
        and a source that is present and EMPTY is a real answer this module has
        no business second-guessing. Columns can only be judged where a row
        exists to carry them.
        """
        missing = []
        for source, requirements in sorted(self.REQUIRED_COLUMNS.items()):
            rows = self.data.get(source)
            if not isinstance(rows, (list, tuple)) or not rows:
                continue
            present = set()
            for row in rows[:20]:
                if isinstance(row, dict):
                    present.update(str(k).strip().upper() for k in row)
            if not present:
                continue
            for spellings, what, cost in requirements:
                if any(s.upper() in present for s in spellings):
                    continue
                missing.append({"source": source, "what": what, "cost": cost,
                                "accepted": list(spellings),
                                "found": sorted(present)[:12]})
        if not missing:
            return
        total = sum(m["cost"] for m in missing)
        items = [
            "%s.csv is missing %s - no column named %s. %d check(s) cannot run. "
            "Columns found: %s"
            % (m["source"], m["what"], " or ".join(m["accepted"]), m["cost"],
               ", ".join(m["found"]))
            for m in sorted(missing, key=lambda m: -m["cost"])
        ]
        self.finding(
            check_id="EXPORT-003",
            title="A supplied export is missing a column its checks read",
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=(
                "%d export(s) parsed into rows and were counted among the "
                "sources you supplied, but do not carry a column the checks "
                "that read them join on. Roughly %d check(s) therefore produced "
                "no finding - not because the estate is clean, but because the "
                "question could not be asked.\n\n"
                "This is the same failure as an export that will not decode, "
                "reached by a different route: the file opens, the rows parse, "
                "the coverage manifest says it arrived, and the report is "
                "quieter than the estate deserves. It happens when a column is "
                "deleted in a spreadsheet, when a hand-built extract omits a "
                "field nobody thought mattered, or when a report variant is "
                "saved with a narrower layout.\n\n"
                "The spellings listed as accepted are the readers' own "
                "vocabulary, not a stricter one invented here - any one of them "
                "is enough."
                % (len(missing), total)
            ),
            affected_items=items,
            remediation=(
                "1. Re-export each file listed with the missing column "
                "included. docs/EXPORT_GUIDE.md gives the required columns per "
                "export and every spelling that is accepted.\n"
                "2. Check how the file was produced. A column deleted in a "
                "spreadsheet is the usual cause, and it will recur on the next "
                "export unless the step that drops it is found.\n"
                "3. Do not read the affected checks as passing in this report. "
                "They did not run.\n"
                "4. Re-run the scan afterwards and compare the finding count - "
                "it should rise by roughly the number stated above."
            ),
            references=["docs/EXPORT_GUIDE.md - required columns per export"],
            # A coverage statement, not a defect in the estate: the gate must
            # not return green on a scan that could not ask the question.
            details={"degrades_coverage": True,
                     "sources": sorted({m["source"] for m in missing}),
                     "checks_not_run": total},
            scope="aggregate",
        )

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
