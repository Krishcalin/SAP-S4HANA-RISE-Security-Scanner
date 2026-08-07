"""
ABAP Test Cockpit / Code Inspector / SAP CVA result importer
============================================================
Turns a customer's **existing** ATC export into first-class findings.

WHY THIS SHIPS BEFORE OUR OWN SCANNER
-------------------------------------
These findings are SAP's, produced by SAP's own engine running inside the system
where the code lives. They carry no false positives of our making, they need no
source code to leave the customer's estate, and a customer who already runs ATC
gets value from this product without our scanner executing at all. Our engine
(``modules/abap_sast.py``) is the fallback for customers who do not have SAP's
Code Vulnerability Analyzer — which, contrary to what this repository used to
say, is fee-free only inside a purchased BTP ABAP Environment entitlement.
See ``docs/CVA_MERGE_PLAN.md`` §0 and Phase 1.

WHY THIS IS NOT ONE FINDING PER EXPORTED ROW
--------------------------------------------
The plan's exit criterion asked for *n* findings from *n* rows. It is not built
that way, deliberately, and this is the one place the implementation departs from
the plan.

An ATC export gives an object name and a **line number**, but not the source line
itself. Line numbers move: insert one comment at the top of a program and every
finding below it shifts. If the line entered a finding's identity, re-exporting
after a cosmetic edit would resolve every finding in that program and raise a
fresh set, resetting age and MTTR to zero — the mitigation journey would report
noise. `identity._rebase` cannot rescue that, because it only fires when exactly
one candidate exists and here there are many.

So identity is **(ATC check × object)**: one finding per check per program, with
every reported line listed as an affected item and the occurrence count in
`details`. Fixing one of three SQL injections in a program shrinks the finding;
fixing all three resolves it. That is a truthful mitigation journey, which strict
per-row identity would not have been.

Contrast ``modules/code_transport.py``, which keeps its estate-wide CODE-INJ-*
roll-ups. Those answer "does this estate have an injection problem at all"; these
answer "which object, and has it been fixed". Both fire; §2 of the merge plan
records the precedence rule.
"""

from typing import Any, Dict, List, Optional

from modules.base_auditor import BaseAuditor
from modules.reachability import ReachabilityIndex, stamp


class AtcImportAuditor(BaseAuditor):
    """Reads `custom_code_scan` rows produced by ATC / Code Inspector / SAP CVA."""

    #: ATC and Code Inspector name their checks inconsistently across releases and
    #: export routes — the same defect arrives as a message id, a check title or a
    #: free-text description. Each entry maps the tokens we have actually seen to a
    #: stable local family, a severity floor and a CWE.
    #:
    #: `severity` is a FLOOR, not an override: when the export states its own
    #: severity we keep the harsher of the two. SAP graded it in the customer's own
    #: context and we did not.
    FAMILIES: List[Dict[str, Any]] = [
        {"family": "SQLI", "cwe": "CWE-89", "severity": BaseAuditor.SEVERITY_CRITICAL,
         "title": "SQL injection in custom ABAP",
         "tokens": ("SQL_INJECTION", "SQL INJECTION", "DYNAMIC WHERE", "DYNAMIC SQL",
                    "NATIVE SQL", "EXEC SQL", "OPEN SQL INJECTION")},
        {"family": "CINJ", "cwe": "CWE-94", "severity": BaseAuditor.SEVERITY_CRITICAL,
         "title": "Code / call injection in custom ABAP",
         "tokens": ("CODE_INJECTION", "CODE INJECTION", "CALL_INJECTION",
                    "GENERATE SUBROUTINE", "INSERT REPORT", "DYNAMIC CALL",
                    "DYNAMIC METHOD")},
        {"family": "CMDI", "cwe": "CWE-78", "severity": BaseAuditor.SEVERITY_CRITICAL,
         "title": "OS command injection in custom ABAP",
         "tokens": ("COMMAND_INJECTION", "OS COMMAND", "SXPG", "EXTERNAL COMMAND")},
        {"family": "AUTHCHK", "cwe": "CWE-862", "severity": BaseAuditor.SEVERITY_HIGH,
         "title": "Missing authorization check in custom ABAP",
         "tokens": ("MISSING_AUTH", "MISSING AUTHORITY", "AUTHORITY-CHECK",
                    "AUTHORITY CHECK", "NO_AUTH_CHECK", "AUTH_CHECK_MISSING")},
        {"family": "PATH", "cwe": "CWE-22", "severity": BaseAuditor.SEVERITY_HIGH,
         "title": "Directory traversal in custom ABAP",
         "tokens": ("DIRECTORY_TRAVERSAL", "PATH TRAVERSAL", "PATH_TRAVERSAL",
                    "FILE ACCESS", "DATASET")},
        {"family": "XSS", "cwe": "CWE-79", "severity": BaseAuditor.SEVERITY_HIGH,
         "title": "Cross-site scripting in custom ABAP / BSP",
         "tokens": ("XSS", "CROSS_SITE", "CROSS-SITE SCRIPTING", "HTML INJECTION")},
        {"family": "CRED", "cwe": "CWE-798", "severity": BaseAuditor.SEVERITY_HIGH,
         "title": "Hardcoded credentials in custom ABAP",
         "tokens": ("HARDCODED", "HARD-CODED", "CLEARTEXT PASSWORD", "PASSWORD IN CODE")},
        {"family": "RFC", "cwe": "CWE-306", "severity": BaseAuditor.SEVERITY_HIGH,
         "title": "Unsafe RFC / remote call in custom ABAP",
         "tokens": ("RFC_INJECTION", "UNSAFE RFC", "CALL FUNCTION DESTINATION",
                    "RFC CALLBACK")},
        {"family": "CRYP", "cwe": "CWE-327", "severity": BaseAuditor.SEVERITY_MEDIUM,
         "title": "Weak cryptography in custom ABAP",
         "tokens": ("WEAK_CRYPTO", "WEAK CIPHER", "MD5", "SHA1", "DES ")},
        {"family": "INFO", "cwe": "CWE-200", "severity": BaseAuditor.SEVERITY_MEDIUM,
         "title": "Information disclosure in custom ABAP",
         "tokens": ("INFORMATION_DISCLOSURE", "INFO DISCLOSURE", "SYSTEM INFO",
                    "STACK TRACE")},
    ]

    #: Rows whose status says the customer already dealt with it. ATC exemptions are
    #: a real workflow in the customer's system and re-raising an approved exemption
    #: as an open finding is how a tool loses trust.
    _CLOSED_STATUS = {"EXEMPTED", "EXEMPTION", "APPROVED", "FIXED", "CLOSED",
                      "OBSOLETE", "FALSE POSITIVE", "FALSE_POSITIVE"}

    _SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    #: Priority 1/2/3 is ATC's own scale; map it onto ours when no severity column
    #: is present. Priority 1 is ATC's most severe.
    _PRIORITY_MAP = {"1": BaseAuditor.SEVERITY_CRITICAL, "2": BaseAuditor.SEVERITY_HIGH,
                     "3": BaseAuditor.SEVERITY_MEDIUM}

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.findings = []
        self._reach = ReachabilityIndex(self.data)
        self.check_atc_findings()
        self.check_atc_is_being_run()
        return self.findings

    # ------------------------------------------------------------------ #
    #  Row normalisation                                                 #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _first(row: Dict[str, Any], *names: str) -> str:
        """First non-empty value among `names`, case-insensitively.

        Export column names vary by release and by whether the export came from
        SE80, the ATC result browser or an ADT/OData extract. Matching case
        -insensitively costs nothing and avoids a whole class of silent misses.
        """
        lowered = {str(k).strip().lower(): v for k, v in row.items()}
        for name in names:
            value = lowered.get(name.lower())
            if value not in (None, ""):
                return str(value).strip()
        return ""

    def _classify(self, text: str) -> Optional[Dict[str, Any]]:
        """Map an ATC check/message/description onto a local family.

        Longest token first so "SQL INJECTION" is not shadowed by a shorter token
        of another family that happens to be a substring.
        """
        haystack = text.upper()
        best: Optional[Dict[str, Any]] = None
        best_len = 0
        for entry in self.FAMILIES:
            for token in entry["tokens"]:
                if token in haystack and len(token) > best_len:
                    best, best_len = entry, len(token)
        return best

    def _severity_for(self, entry: Dict[str, Any], row: Dict[str, Any]) -> str:
        """The harsher of SAP's stated severity and our floor for the family."""
        stated = self._first(row, "SEVERITY", "PRIORITY", "PRIO").upper()
        if stated in self._PRIORITY_MAP:
            stated = self._PRIORITY_MAP[stated]
        floor = entry["severity"]
        if stated not in self._SEVERITY_RANK:
            return floor
        return stated if self._SEVERITY_RANK[stated] > self._SEVERITY_RANK[floor] else floor

    # ------------------------------------------------------------------ #
    #  ATC-<FAMILY>: one finding per (check family x object)             #
    # ------------------------------------------------------------------ #

    def check_atc_findings(self):
        scan = self.data.get("custom_code_scan")
        if not scan:
            return

        # (family, object) -> accumulated occurrences
        grouped: Dict[tuple, Dict[str, Any]] = {}
        unclassified = 0

        for row in scan:
            if not isinstance(row, dict):
                continue

            status = self._first(row, "STATUS", "STATE", "EXEMPTION").upper()
            if status in self._CLOSED_STATUS:
                continue

            obj_name = self._first(row, "OBJECT_NAME", "OBJECT", "PROGRAM",
                                   "REPORT", "INCLUDE", "CLASS")
            if not obj_name:
                continue
            obj_type = self._first(row, "OBJECT_TYPE", "TYPE", "OBJTYPE") or "PROG"
            check = self._first(row, "FINDING_TYPE", "CHECK", "CHECK_TITLE",
                                "MESSAGE_ID", "MSG_ID", "CHECK_ID")
            description = self._first(row, "DESCRIPTION", "MESSAGE", "TEXT",
                                      "MESSAGE_TEXT")
            line = self._first(row, "LINE", "LINE_NUMBER", "LINE_NO", "ROW")

            entry = self._classify(f"{check} {description}")
            if entry is None:
                # A non-security ATC check (performance, syntax, naming) or a
                # security check we do not recognise. Counted and disclosed rather
                # than dropped — an undisclosed drop is how a partial import looks
                # like a clean estate.
                unclassified += 1
                continue

            key = (entry["family"], obj_name.upper())
            bucket = grouped.setdefault(key, {
                "entry": entry, "object": obj_name, "obj_type": obj_type,
                "lines": [], "descriptions": [], "checks": set(),
                "severity": entry["severity"],
            })
            if line:
                bucket["lines"].append(line)
            if description:
                bucket["descriptions"].append(description)
            if check:
                bucket["checks"].add(check)
            sev = self._severity_for(entry, row)
            if self._SEVERITY_RANK[sev] > self._SEVERITY_RANK[bucket["severity"]]:
                bucket["severity"] = sev

        for (family, _obj_upper), bucket in sorted(grouped.items()):
            entry = bucket["entry"]
            obj_name = bucket["object"]
            lines = bucket["lines"]
            count = max(len(lines), len(bucket["descriptions"]), 1)

            where = f" at line{'s' if len(lines) > 1 else ''} {', '.join(lines[:20])}" \
                    if lines else ""
            sample = bucket["descriptions"][0][:160] if bucket["descriptions"] else ""

            self.finding(
                check_id=f"ATC-{family}",
                title=f"{entry['title']} — {obj_name}",
                severity=bucket["severity"],
                category="Code & Transport Security",
                description=(
                    f"SAP's own code analysis (ABAP Test Cockpit / Code Inspector / "
                    f"Code Vulnerability Analyzer) reported {count} "
                    f"{entry['family']} finding(s) in {obj_type} {obj_name}{where}. "
                    f"{sample}"
                ).strip(),
                affected_items=[
                    f"{obj_name} ({obj_type}) line {ln}" for ln in lines[:50]
                ] or [f"{obj_name} ({obj_type})"],
                remediation=(
                    f"1. Open {obj_name} in ATC (transaction ATC, or the ABAP Test "
                    f"Cockpit view in ADT) and re-run the check to see the current "
                    f"line positions — the line numbers above are from the export "
                    f"and move as the code is edited.\n"
                    f"2. Fix the reported statements at their source; do not add an "
                    f"exemption to clear the finding unless the code is genuinely "
                    f"safe and the reason is recorded.\n"
                    f"3. Re-export the ATC result and re-upload it here. This finding "
                    f"shrinks as occurrences are fixed and resolves when the object is "
                    f"clean, so partial progress is visible.\n"
                    f"4. Wire ATC into the transport release path so the same defect "
                    f"class cannot be re-introduced by the next change."
                ),
                references=[
                    "SAP Security Baseline — secure custom code",
                    f"{entry['cwe']}",
                ],
                details={
                    "source": "atc_export",
                    "cwe": entry["cwe"],
                    "family": family,
                    "occurrences": count,
                    "lines": lines[:200],
                    "atc_checks": sorted(bucket["checks"])[:20],
                    # SAP's engine produced this, not ours. The console uses this to
                    # say so, because it is the difference between "SAP found it" and
                    # "our regex thinks so".
                    "evidence": "sap_atc",
                    **stamp({}, self._reach, obj_name),
                },
                # Identity is the OBJECT, not the line. See the module docstring.
                affected_objects=[{"type": "program", "name": obj_name}],
                subject=[{"type": "program", "name": obj_name}],
                scope="object",
            )

        if unclassified:
            self.finding(
                check_id="ATC-GOV-002",
                title="ATC export rows not classified as security findings",
                severity=self.SEVERITY_INFO,
                category="Code & Transport Security",
                description=(
                    f"{unclassified} row(s) in the ATC export did not match a known "
                    "security check family and were not raised as findings. Most ATC "
                    "checks are performance, syntax or naming rather than security, so "
                    "a large number here is normal — it is disclosed so that a small "
                    "number is not mistaken for a clean estate."
                ),
                # Deliberately CONSTANT. A `check_only` finding fingerprints over its
                # display items, so putting the count here would change identity every
                # time the count moved: the finding would "resolve" and a "new" one
                # appear on a run where nothing was fixed. The number lives in the
                # description and in `details`, neither of which is part of identity.
                affected_items=["ATC export contains rows outside the security check set"],
                remediation=(
                    "1. If the export was produced with a non-security check variant, "
                    "re-run ATC with the security variant so the security checks are "
                    "actually present.\n"
                    "2. If security findings are being missed, send a sample of the "
                    "unmatched CHECK / MESSAGE_ID values so the mapping can be extended."
                ),
                details={"unclassified_rows": unclassified, "source": "atc_export"},
                scope="aggregate",
            )

    # ------------------------------------------------------------------ #
    #  ATC-GOV-001: is SAP's own code scanning switched on at all?        #
    # ------------------------------------------------------------------ #

    def check_atc_is_being_run(self):
        """Control-existence assurance, not code scanning.

        This is the check ``docs/RISE_SECURITY_MODEL.md`` always intended: custom
        code is contractually 100% the customer's under RISE, and the first
        question is not "which line is wrong" but "is anybody looking".
        """
        scan = self.data.get("custom_code_scan")
        inventory = self.data.get("code_inventory")

        if scan:
            return          # they are running it; the findings above are the output

        # Only assert the absence when we know there IS custom code to scan.
        if not inventory:
            return

        custom_objects = [
            r for r in inventory
            if isinstance(r, dict)
            and str(self._first(r, "OBJECT_NAME", "OBJECT")).upper().startswith(("Z", "Y"))
        ]
        if not custom_objects:
            return

        self.finding(
            check_id="ATC-GOV-001",
            title="Custom code security scanning is not evidenced",
            severity=self.SEVERITY_HIGH,
            category="Code & Transport Security",
            description=(
                f"The estate contains {len(custom_objects)} custom (Z*/Y*) object(s) "
                "but no ABAP Test Cockpit / Code Inspector / Code Vulnerability "
                "Analyzer result was supplied. Under RISE, custom ABAP is "
                "contractually the customer's responsibility in full — SAP's support "
                "and SLA do not extend to customer ABAP add-ons — so an unscanned "
                "custom code base is an unowned risk rather than a shared one."
            ),
            # Constant for the same reason as ATC-GOV-002: the count belongs in the
            # description and in `details`, never in the identity.
            affected_items=["Custom (Z*/Y*) code present with no ATC/CVA result supplied"],
            remediation=(
                "1. Confirm whether ABAP Test Cockpit is configured and whether a "
                "security check variant is assigned (transaction ATC).\n"
                "2. SAP's Code Vulnerability Analyzer is the security check set "
                "inside ATC; confirm your entitlement, since it is fee-free only "
                "within a purchased BTP ABAP Environment entitlement and is otherwise "
                "licensed separately.\n"
                "3. If CVA is not licensed, run this product's own ABAP scanner over "
                "an abapGit offline export instead — it needs no OS access and no SAP "
                "ticket.\n"
                "4. Wire the check into the transport release path so new custom code "
                "is scanned before it reaches production.\n"
                "5. Export the ATC result and upload it here so the findings are "
                "tracked to closure alongside the rest of the estate."
            ),
            references=["SAP Security Baseline — secure custom code"],
            details={
                "custom_object_count": len(custom_objects),
                "source": "absence_of_atc_export",
            },
            scope="aggregate",
        )
