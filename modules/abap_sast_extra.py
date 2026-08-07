"""
Coverage the vendored corpus does not have.

Kept OUT of ``modules/abap_sast_rules.py`` on purpose: that file is regenerated
verbatim from the upstream repository by ``tools/build_abap_rules.py``, so
anything written there is destroyed the next time the corpus is refreshed. These
rules are ours.

Each family here was confirmed by grep to have **zero** coverage in the 104-rule
corpus before it was written. The order below is the order they were built, and
AMDP came first deliberately: SAP's own ABAP keyword documentation states that no
test tool exists for AMDP, which makes it the one place this module can be ahead
of SAP's Code Vulnerability Analyzer rather than behind it.

WHAT IS DELIBERATELY NOT HERE
ABAP Cloud / RAP released-API compliance. It is a different ATC variant, it is
measured against SAP's continuously-updated released-object catalogue, and the
catalogue is the whole check — shipping a snapshot of it would be a
content-currency treadmill of exactly the kind this repository survives elsewhere
only because CI re-derives the SAP baseline from source. Declined explicitly
rather than half-built. See ``docs/CVA_MERGE_PLAN.md`` §6.

MATCHING UNIT
These patterns are matched against a whole ABAP **statement**, never a line — see
``modules/abap_sast.py``. That is what makes multi-line AMDP bodies and wrapped
EXEC SQL blocks matchable at all.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

#: AMDP / SQLScript. An AMDP method body is SQLScript executed inside HANA, and
#: the ABAP compiler does not analyse it: everything between METHOD and ENDMETHOD
#: is passed through. So APPLY_FILTER and EXECUTE IMMEDIATE inside one are the
#: same class of defect as a dynamic WHERE in Open SQL, with none of the tooling.
AMDP_RULES: List[Dict[str, Any]] = [
    {
        "id": "ABAP-AMDP-001",
        "category": "SQL Injection",
        "name": "AMDP EXECUTE IMMEDIATE with a constructed statement",
        "severity": "CRITICAL",
        "pattern": r"\bEXEC(?:UTE)?\s+IMMEDIATE\b",
        "cwe": "CWE-89",
        "description": (
            "An AMDP method executes a SQLScript statement built at runtime. The "
            "method body runs inside HANA and is not analysed by the ABAP compiler "
            "or by the Open SQL checks, so a value concatenated into it reaches the "
            "database engine directly."),
        "recommendation": (
            "Replace EXECUTE IMMEDIATE with a static statement and parameters. "
            "Where the statement genuinely must vary, use APPLY_FILTER with a "
            "filter built by CL_ABAP_DYN_PRG rather than by concatenation, and "
            "validate any identifier against an allowlist of column names."),
    },
    {
        "id": "ABAP-AMDP-002",
        "category": "SQL Injection",
        "name": "AMDP APPLY_FILTER with a non-literal filter",
        "severity": "HIGH",
        "pattern": r"\bAPPLY_FILTER\s*\(\s*[^)'\"]*,\s*:?[a-zA-Z_]\w*\s*\)",
        "cwe": "CWE-89",
        "description": (
            "APPLY_FILTER injects a WHERE condition into a HANA view at runtime. "
            "When the filter comes from a variable rather than a literal, whoever "
            "controls that variable controls the condition."),
        "recommendation": (
            "Build the filter with CL_ABAP_DYN_PRG on the ABAP side before passing "
            "it in, so quoting and identifier validation are done by SAP's own "
            "utility rather than by hand."),
    },
    {
        "id": "ABAP-AMDP-003",
        "category": "Missing Authorization",
        "name": "AMDP method reads business data with no ABAP-side authorization",
        "severity": "MEDIUM",
        "pattern": r"\bBY\s+DATABASE\s+PROCEDURE\b",
        "cwe": "CWE-862",
        "description": (
            "Code pushed down to the database bypasses every ABAP authorization "
            "mechanism: AUTHORITY-CHECK does not run inside HANA, and CDS access "
            "control is not applied to a database procedure. Whatever the "
            "procedure selects, it selects in full."),
        "recommendation": (
            "Perform the AUTHORITY-CHECK in the calling ABAP method, before the "
            "AMDP method is invoked, and pass the already-authorised selection as "
            "a parameter. Do not rely on the caller of the caller."),
    },
]

#: Native SQL. EXEC SQL and ADBC hand a statement straight to the database with
#: no Open SQL layer in between — no automatic client handling, no table buffering
#: and, relevantly here, no syntax check on what was concatenated.
NATIVE_SQL_RULES: List[Dict[str, Any]] = [
    {
        "id": "ABAP-NSQL-001",
        "category": "SQL Injection",
        "name": "Native SQL block (EXEC SQL)",
        "severity": "HIGH",
        "pattern": r"\bEXEC\s+SQL\b",
        "cwe": "CWE-89",
        "description": (
            "A native SQL block passes a statement directly to the database. Open "
            "SQL's protections do not apply: there is no automatic client handling "
            "and no parameterisation unless the developer supplies it."),
        "recommendation": (
            "Rewrite the block in Open SQL, which is portable, client-aware and "
            "parameterised by construction. Where native SQL is genuinely required, "
            "use ADBC with bound parameters rather than a concatenated string."),
    },
    {
        "id": "ABAP-NSQL-002",
        "category": "SQL Injection",
        "name": "ADBC statement built from a variable",
        "severity": "CRITICAL",
        "pattern": r"\b(?:EXECUTE_QUERY|EXECUTE_UPDATE|EXECUTE_DDL)\s*\(\s*[^)'\"]*[a-zA-Z_]\w*\s*\)",
        "cwe": "CWE-89",
        "description": (
            "An ADBC statement is executed from a variable rather than a literal. "
            "CL_SQL_STATEMENT executes exactly what it is given, against the "
            "database, with no Open SQL layer to constrain it."),
        "recommendation": (
            "Bind values with SET_PARAM instead of concatenating them into the "
            "statement text, and keep the statement itself a literal."),
    },
]

#: CDS access control. A CDS view without a DCL role is readable by anyone who can
#: read the view, and the omission is invisible in the view's own source — which is
#: why this is a check on what is ABSENT.
CDS_RULES: List[Dict[str, Any]] = [
    {
        "id": "ABAP-CDS-001",
        "category": "Missing Authorization",
        "name": "CDS view exposed without access control",
        "severity": "HIGH",
        "pattern": r"@AccessControl\.authorizationCheck\s*:\s*#NOT_REQUIRED",
        "cwe": "CWE-862",
        "description": (
            "The view declares that no authorization check is required. Every user "
            "who can reach the view reads every row of it, regardless of the "
            "authorizations that protect the underlying tables."),
        "recommendation": (
            "Set @AccessControl.authorizationCheck to #CHECK and supply a DCL role "
            "that constrains the rows. #NOT_REQUIRED is defensible only for a view "
            "over data that is genuinely public within the system, and that "
            "judgement should be recorded next to the annotation."),
    },
    {
        "id": "ABAP-CDS-002",
        "category": "Missing Authorization",
        "name": "CDS DCL role grants unconditionally",
        "severity": "HIGH",
        "pattern": r"\bGRANT\s+SELECT\s+ON\s+\w+\s+WHERE\s+TRUE\b",
        "cwe": "CWE-863",
        "description": (
            "The access-control role grants SELECT with a condition that is always "
            "true, so the DCL exists but constrains nothing. This is worse than "
            "having no role: a review sees that access control is defined."),
        "recommendation": (
            "Replace the condition with one bound to an authorization object via "
            "the aspect pfcg_auth, so the grant is evaluated against the user's "
            "actual authorizations."),
    },
]

#: XML external entities, SSRF and a backdoor primitive the corpus missed.
MISC_RULES: List[Dict[str, Any]] = [
    {
        "id": "ABAP-XXE-001",
        "category": "Insecure Configuration",
        "name": "XML parsed without disabling external entities",
        "severity": "HIGH",
        # Matches the ENTRY POINT, not the factory. Real code reaches the parser
        # through a chained call — `lo_ixml->create_stream_factory( )->
        # create_stream_for_string( lv_xml )` — where `cl_ixml` appeared in an
        # earlier statement entirely, so a pattern requiring both together never
        # fired on anything a developer would actually write.
        "pattern": r"\b(?:create_stream_for_string|import_from_string|"
                   r"parse_string|if_ixml_parser~parse)\b",
        "cwe": "CWE-611",
        "description": (
            "An XML document is parsed from input. If the parser resolves external "
            "entities, a crafted document reads files from the application server "
            "or makes the server issue requests on the attacker's behalf."),
        "recommendation": (
            "Disable DTD processing and external entity resolution on the parser "
            "before parsing untrusted XML. Where the document comes from a trusted "
            "partner, validate it against a schema rather than trusting its origin."),
    },
    {
        "id": "ABAP-SSRF-001",
        "category": "Insecure Configuration",
        "name": "HTTP client created from a non-literal URL",
        "severity": "HIGH",
        "pattern": r"create_by_url\s*\(\s*(?:url\s*=\s*)?(?!')[a-zA-Z_]\w*",
        "cwe": "CWE-918",
        "description": (
            "The destination URL of an outbound HTTP call comes from a variable. "
            "Whoever controls that value makes the SAP application server issue "
            "requests of their choosing — including to hosts only the server can "
            "reach, which is the whole point of the technique."),
        "recommendation": (
            "Call through an RFC destination configured in SM59 rather than a URL "
            "built at runtime, so the reachable targets are administered rather "
            "than computed. Where a dynamic URL is unavoidable, validate the host "
            "against an allowlist — never the path or the scheme alone."),
        # The URL argument is the sink; a taint verdict on it is exactly the
        # question "can the caller choose where this server connects to".
        "_taint_sink": True,
        # Without this the generic extractor looked for a parenthesised bare
        # identifier, found none in `create_by_url( url = lv_url )`, and the rule
        # could never reach `confirmed` despite shipping a working sink pattern.
        "_sink_arg": r"create_by_url\s*\([^)]*?\burl\s*=\s*([A-Za-z_]\w*)",
    },
    {
        "id": "ABAP-BKDR-008",
        "category": "Backdoor / Malicious Code",
        "name": "TEST-SEAM / TEST-INJECTION in transportable code",
        "severity": "HIGH",
        "pattern": r"\bTEST-(?:SEAM|INJECTION)\b",
        "cwe": "CWE-489",
        "description": (
            "A test seam lets code be replaced at runtime by an injection defined "
            "elsewhere. It is a legitimate unit-testing facility with a "
            "legitimate-looking name, and it is also a way to leave a replaceable "
            "hole in production code that reads as ordinary test scaffolding."),
        "recommendation": (
            "Confirm the seam is exercised only by unit tests and that no "
            "TEST-INJECTION for it exists in transportable code. Where the seam is "
            "no longer used by a test, remove it — an unused seam is a hole with "
            "no purpose. Treat an unexplained seam in production code as an "
            "investigation, not a defect to schedule."),
    },
]

EXTRA_ABAP_RULES: List[Dict[str, Any]] = (
    AMDP_RULES + NATIVE_SQL_RULES + CDS_RULES + MISC_RULES
)


# --------------------------------------------------------------------------- #
#  Sanitizers — which guard actually clears which sink                        #
# --------------------------------------------------------------------------- #
# The vendored analyzer consults ONE flat sanitizer regex for all nine sinks, and
# it is wrong in three separate directions:
#
#   * A blanket `cl_abap_dyn_prg=>` prefix credits ANY method on the class. An XSS
#     escaper therefore cleared a dynamic FROM clause: five genuine injections were
#     reproduced being downgraded that way.
#   * No word boundaries and no call syntax, so the bare identifiers
#     `lv_escape_quotes` or `lt_check_int_values` matched. Since the regex is
#     tested against the raw SINK ARGUMENT, a tainted variable merely NAMED like a
#     guard returned `sanitized` outright.
#   * The escaping half was listed and the quoting half — the one that adds the
#     delimiters, without which escaping does not make a value safe — was not.
#
# These guards are not interchangeable. A table-name check does not make a column
# name safe, and neither makes a file path safe. So the mapping is per sink, and
# a sink with no verified guard gets an empty tuple rather than a guess.
#
# Kept here rather than in `abap_sast_rules.py` because that file is regenerated
# verbatim by `tools/build_abap_rules.py`.

#: Membership in a fixed set constrains a value in ANY position, so this appears
#: in every entry below.
_ALLOWLIST = ("check_allowlist", "check_whitelist")

#: `check_whitelist` is retained as an alias only. It is NOT confirmed to be a
#: released method name — it survived in the vendored list by accident, via the
#: blanket class prefix — and removing it outright would turn every estate still
#: using it into a false positive. UNVERIFIED: see U3 in
#: docs/CVA_ENGINE_IMPROVEMENT_PLAN.md.

SINK_SANITIZERS: Dict[str, Tuple[str, ...]] = {
    # Dynamic table name
    "ABAP-SQLI-010": ("check_table_name_str", "check_table_name_tab") + _ALLOWLIST,
    "ABAP-SQLI-011": ("check_table_name_str", "check_table_name_tab") + _ALLOWLIST,
    # Dynamic column / sort / grouping term
    "ABAP-SQLI-006": ("check_column_name",) + _ALLOWLIST,
    "ABAP-SQLI-007": ("check_column_name",) + _ALLOWLIST,
    # Dynamic condition or value — quoting, not column checking, is the guard
    "ABAP-SQLI-001": ("quote", "quote_str", "check_char_literal", "check_int_value")
                     + _ALLOWLIST,
    "ABAP-SQLI-008": ("quote", "quote_str", "check_char_literal", "check_int_value")
                     + _ALLOWLIST,
    # Dynamic program / class / method name
    "ABAP-CINJ-005": ("check_variable_name",) + _ALLOWLIST,
    # Outbound URL: only membership of a known-good set constrains a destination
    "ABAP-SSRF-001": _ALLOWLIST,
    # Application-server file path. `file_validate_name` is the documented
    # physical-path guard; nothing else in the inventory constrains a path.
    "ABAP-PATH-001": ("file_validate_name",),
}

#: The default for a sink with no entry above: every guard we know of. Wider than
#: any per-sink set, so an unmapped sink can only ever be MORE forgiving — a new
#: sink cannot silently become a false positive by omission.
DEFAULT_SANITIZERS: Tuple[str, ...] = tuple(sorted({
    m for methods in SINK_SANITIZERS.values() for m in methods
}))

#: Output-encoding guards. Deliberately a SEPARATE set that no SQL, path, program
#: or URL sink may consult: escaping a value for HTML or JavaScript says nothing
#: about whether it is safe in a FROM clause.
XSS_SANITIZERS: Tuple[str, ...] = (
    "escape_xss_html", "escape_xss_javascript", "escape_xss_url",
    "escape_html", "escape_url",
)
