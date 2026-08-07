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
        # A12. The bare call form was missed. `EXEC\s*\(` is restricted to the call
        # shape so it cannot collide with `EXEC SQL` (ABAP-NSQL-001) and
        # double-report the same statement.
        "pattern": r"\b(?:EXEC(?:UTE)?\s+IMMEDIATE\b|EXEC\s*\()",
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
        # A5. Matched only PROCEDURE, so every AMDP *function* was missed — and a
        # table function is consumable by any ABAP SQL SELECT, not only by a
        # deliberate method call, which makes it the wider exposure of the two.
        "pattern": r"\bBY\s+DATABASE\s+(?:PROCEDURE|FUNCTION)\b",
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
        # A7. #NOT_ALLOWED was missed entirely, and it is the worse of the two: it
        # does not merely skip the check, it causes an access-control role that
        # DOES exist for the view to be disregarded.
        "pattern":
            r"@AccessControl\.authorizationCheck\s*:\s*#(?:NOT_REQUIRED|NOT_ALLOWED)",
        "cwe": "CWE-862",
        "description": (
            "The view declares that no authorization check is performed. Every user "
            "who can reach the view reads every row of it, regardless of the "
            "authorizations that protect the underlying tables. With #NOT_ALLOWED "
            "this holds even when a DCL role has been written for the view: the "
            "role is disregarded, so a reviewer who finds the role has no reason to "
            "suspect it is inert."),
        "recommendation": (
            "Set @AccessControl.authorizationCheck to #MANDATORY and supply a DCL "
            "role that constrains the rows. #MANDATORY is the value that FORCES an "
            "access-control object to exist; #CHECK only warns when one is missing, "
            "so a view can ship unprotected and still look remediated. Either value "
            "is defensible only over data that is genuinely public within the "
            "system, and that judgement belongs in a comment beside the annotation."),
    },
    {
        "id": "ABAP-CDS-002",
        "category": "Missing Authorization",
        "name": "CDS DCL role grants unconditionally",
        "severity": "HIGH",
        # UNVERIFIED SYNTAX — do not present this rule as covering anything.
        # `GRANT SELECT ON x WHERE TRUE` was not found in any fetched SAP-authored
        # DCL material, so this may be matching a construct that does not exist,
        # in which case its coverage is silently zero rather than wrong. The
        # fixture it passes against is our own and proves only self-consistency.
        # U5 in docs/CVA_ENGINE_IMPROVEMENT_PLAN.md names what would settle it.
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

# --------------------------------------------------------------------------- #
#  Tier 3 — the dynamic-token inventory                                       #
# --------------------------------------------------------------------------- #
# 40 of 49 dynamic statements taken verbatim from SAP-authored material matched no
# rule in the whole 99-rule corpus. The gap is not tuning: the existing rules
# anchor on "keyword immediately followed by (", and ABAP's dominant dynamic forms
# put the parenthesis after a selector (`oref->(meth)`), after an addition
# (`CASTING TYPE (t)`), or in a clause no rule covers at all.
#
# NOTHING HERE USES `[^)]*` INSIDE THE PARENTHESIS WHERE A NAME IS EXPECTED.
# Measured: unbounded, these fire on parenthesised SELECT-list arithmetic and on
# the parenthesised logical expressions SAP documents as CORRECT in LOOP AT and
# READ TABLE. That is Tier 2's F2 defect re-introduced under a new id.

#: ONE dynamic name or ONE literal — the same bound Tier 2 applied to WHERE.
_NAME = r"(?:`[^`]*`|'[^']*'|[A-Za-z_]\w*(?:->\w+|-\w+)*)"

#: A parenthesised operand that is NOT a compile-time literal or a bare integer.
#: Without this the ASSIGN family fires almost entirely on hard-coded values.
_NOT_LITERAL = r"\(\s*(?!['\"`0-9])[A-Za-z_]\w*\s*\)"

DYNAMIC_SQL_RULES: List[Dict[str, Any]] = [
    {
        "id": "ABAP-SQLI-013",
        "category": "SQL Injection",
        "name": "Dynamic SELECT column list",
        "severity": "HIGH",
        # A1. Bounded deliberately: with `[^)]*` this fires on parenthesised
        # arithmetic in a static select list — three HIGH CWE-89 findings on
        # correct code, measured.
        "pattern": r"\bSELECT\s+(?:SINGLE\s+|DISTINCT\s+)*\(\s*" + _NAME + r"\s*\)",
        "cwe": "CWE-89",
        "description": (
            "The list of columns a SELECT reads is chosen at runtime. This is the "
            "exact construct SAP's own security example uses to motivate an "
            "allowlist check, and nothing in the corpus matched it. A caller who "
            "controls the column list reads columns the query was never meant to "
            "return."),
        "recommendation": (
            "Validate the column list against an allowlist of names the caller is "
            "permitted to read — CL_ABAP_DYN_PRG's column-name check does exactly "
            "this. A quoting function does not help here: a column name is an "
            "identifier, not a value."),
        # No `_sink_arg`: the generic extractor already returns the operand
        # correctly for this shape, and a redundant one is a second thing to keep
        # in step with the pattern.
        "_taint_sink": True,
    },
    {
        "id": "ABAP-SQLI-014",
        "category": "SQL Injection",
        "name": "Dynamic table name in a write statement",
        "severity": "HIGH",
        # A2. ABAP-SQLI-010/-011 both require the literal `FROM` before the
        # parenthesis, so the write side was invisible. The parenthesis must follow
        # the keyword directly, so `INSERT REPORT` and
        # `INSERT dbtab FROM ( SELECT ... )` cannot match.
        "pattern": r"\b(?:UPDATE|MODIFY|INSERT)\s+\(\s*" + _NAME + r"\s*\)",
        "cwe": "CWE-89",
        "description": (
            "The table a write statement targets is chosen at runtime. Whoever "
            "controls the name chooses which table is modified."),
        "recommendation": (
            "Validate the table name against an allowlist, or against the "
            "table-name check in CL_ABAP_DYN_PRG, before it reaches the statement."),
        "_taint_sink": True,
        "_sink_arg": r"(?:UPDATE|MODIFY|INSERT)\s+\(\s*([A-Za-z_]\w*)",
    },
    {
        "id": "ABAP-SQLI-015",
        "category": "SQL Injection",
        "name": "Dynamic SET clause in an UPDATE",
        "severity": "CRITICAL",
        # A2. `ABAP-AUTH-006`'s `UPDATE\s+\w+\s+SET` cannot match `(table)` either,
        # so this was doubly invisible.
        "pattern": r"\bUPDATE\b[^.]*\bSET\s*\(\s*" + _NAME + r"\s*\)",
        "cwe": "CWE-89",
        "description": (
            "The SET clause of an UPDATE is built at runtime. A controlled SET "
            "clause rewrites arbitrary columns to arbitrary values, which outranks "
            "a controlled WHERE: a controlled WHERE chooses which rows are "
            "affected, a controlled SET chooses what they become."),
        "recommendation": (
            "Build the SET clause from a fixed set of column names chosen by the "
            "program, and bind the values as host variables rather than splicing "
            "them into the clause text."),
        "_taint_sink": True,
        "_sink_arg": r"\bSET\s*\(\s*([^)]*)\)",
    },
    {
        "id": "ABAP-SQLI-016",
        "category": "SQL Injection",
        "name": "Dynamic null-indicator list",
        "severity": "MEDIUM",
        "pattern": r"\bINDICATORS\s*\(\s*" + _NAME + r"\s*\)",
        "cwe": "CWE-89",
        "description": (
            "The indicator structure controlling which fields participate in a "
            "write is chosen at runtime, so which columns are written is decided "
            "outside the program text."),
        "recommendation": (
            "Choose the indicator structure in the program rather than from input."),
    },
]

CROSS_CLIENT_RULES: List[Dict[str, Any]] = [
    {
        "id": "ABAP-AUTH-010",
        "category": "Missing Authorization",
        "name": "Statement reads across all clients",
        "severity": "HIGH",
        # A3. `ABAP-AUTH-009` matches `CLIENT SPECIFIED`, which SAP calls OBSOLETE.
        # We were flagging the dead spelling and missing all three live ones. Both
        # patterns are verified silent on `USING zdemo_view` and on
        # `USING client_dependent_view` — `\bCLIENT\b` cannot match inside
        # `CLIENTS` or inside an identifier.
        "pattern": r"\bUSING\s+(?:ALL\s+CLIENTS|CLIENTS\s+IN)\b",
        "cwe": "CWE-863",
        "description": (
            "The statement suspends automatic client handling and reads more than "
            "the caller's own client. Client separation is the boundary most SAP "
            "authorization concepts are built on top of, and this steps over it."),
        "recommendation": (
            "Remove the addition unless the program is a genuine cross-client "
            "administrative tool. Where it is, protect it with an authorization "
            "check that is itself client-independent, and record why."),
    },
    {
        "id": "ABAP-AUTH-011",
        "category": "Missing Authorization",
        "name": "Statement reads a single explicit client",
        "severity": "MEDIUM",
        # Deliberately a lower severity than -010: reading one named client is a
        # redirect, reading all of them is a disclosure. Collapsing the two would
        # make the higher finding unfindable in a large estate.
        "pattern": r"\bUSING\s+CLIENT\b",
        "cwe": "CWE-863",
        "description": (
            "The statement reads a client chosen by the program rather than the "
            "caller's own. Where that client comes from input, the caller chooses "
            "whose data they read."),
        "recommendation": (
            "Confirm the client is fixed by the program and not taken from input. "
            "If it is configurable, check the caller's authorization for the target "
            "client rather than for their own."),
    },
]

AMDP_EXTRA_RULES: List[Dict[str, Any]] = [
    {
        "id": "ABAP-AMDP-004",
        "category": "Missing Authorization",
        "name": "AMDP method is not declared read-only",
        "severity": "HIGH",
        # A4. The negative lookahead is safe because a METHOD header is one
        # complete statement, so `.*` cannot run into the next one.
        "pattern":
            r"\bBY\s+DATABASE\s+(?:PROCEDURE|FUNCTION)\b(?!.*\bOPTIONS\s+READ-ONLY\b)",
        "cwe": "CWE-862",
        "description": (
            "An AMDP method that may write produced the same single finding as a "
            "read-only one, so a database procedure that MODIFIES business data "
            "was indistinguishable from one that reports on it — while running "
            "outside every ABAP authorization mechanism."),
        "recommendation": (
            "Declare READ-ONLY on any AMDP method that only reads, so the ones that "
            "write are visible as the smaller, reviewable set. Where a method must "
            "write, perform the AUTHORITY-CHECK in the calling ABAP method."),
    },
    {
        "id": "ABAP-AMDP-005",
        "category": "Missing Authorization",
        "name": "AMDP declaration is not client-safe",
        "severity": "MEDIUM",
        # A13. Anchored on `AMDP OPTIONS` so the lookahead stays inside one
        # statement.
        "pattern":
            r"\bAMDP\s+OPTIONS\b(?!.*\b(?:CDS\s+SESSION\s+CLIENT\s+DEPENDENT"
            r"|CLIENT\s+INDEPENDENT)\b)",
        "cwe": "CWE-284",
        "description": (
            "AMDP has no implicit client handling: unlike Open SQL, nothing adds a "
            "client column to the procedure's own statements. A declaration that "
            "does not state its client behaviour reads every client by default."),
        "recommendation": (
            "State the client behaviour explicitly on the declaration. NOTE ON "
            "ROLLOUT: a classic estate that predates these additions will light up "
            "broadly. That is a real exposure rather than noise, and aggregate "
            "scoping already collapses it to one finding per object."),
    },
]

#: A6 / A14. RAP. `.asbdef` routed to CDS_RULES, which held only two DDL/DCL shapes
#: that cannot occur in a behaviour definition — so a BDEF that disables
#: authorization produced ZERO findings. That is the same silent-zero-coverage
#: failure this module's docstring records as fixed for CDS.
#:
#: `split_cds_statements` already emits matchable units for both, so no lexer work.
RAP_BDEF_RULES: List[Dict[str, Any]] = [
    {
        "id": "ABAP-RAP-001",
        "category": "Missing Authorization",
        "name": "RAP behaviour definition disables the authorization master",
        "severity": "HIGH",
        "pattern": r"\bauthorization\s+master\s*\(\s*none\s*\)",
        "cwe": "CWE-862",
        "description": (
            "The behaviour definition declares that no authorization master exists, "
            "so no authorization handler is called for the entity. Every operation "
            "the behaviour exposes — including over OData — runs unchecked."),
        "recommendation": (
            "Name the entity that owns authorization for this behaviour and "
            "implement the corresponding handler. `none` is defensible only for a "
            "behaviour reachable exclusively from an already-authorised caller, and "
            "that reasoning belongs beside the declaration."),
    },
    {
        "id": "ABAP-RAP-002",
        "category": "Missing Authorization",
        "name": "RAP behaviour definition declares no authorization",
        "severity": "MEDIUM",
        "pattern": r"\bauthorization\s*:\s*none\b",
        "cwe": "CWE-862",
        "description": (
            "An operation in the behaviour definition is declared with no "
            "authorization, so it is not covered by the entity's authorization "
            "handler."),
        "recommendation": (
            "Remove the declaration so the operation inherits the entity's "
            "authorization, or state explicitly why this one operation is safe "
            "without it."),
    },
    {
        "id": "ABAP-RAP-003",
        "category": "Missing Authorization",
        "name": "RAP handler runs in local mode",
        "severity": "MEDIUM",
        "pattern": r"\bIN\s+LOCAL\s+MODE\b",
        "cwe": "CWE-862",
        "description": (
            "The call is made in local mode, which bypasses the authorization and "
            "feature-control checks the behaviour would otherwise apply. We were "
            "reporting the safe construct two lines away and saying nothing about "
            "this one."),
        "recommendation": (
            "This is LEGITIMATE inside a behaviour pool and in auxiliary classes, "
            "so the action is to CONFIRM the authorization decision was already "
            "taken upstream — not to remove the addition. Treat it as a question "
            "for the reviewer rather than a defect to schedule."),
    },
    {
        "id": "ABAP-RAP-004",
        "category": "Missing Authorization",
        "name": "RAP privileged access",
        "severity": "MEDIUM",
        "pattern": r"\bPRIVILEGED\b",
        "cwe": "CWE-862",
        "description": (
            "The code requests privileged access, which suspends the authorization "
            "the behaviour would normally enforce."),
        "recommendation": (
            "As with local mode, this is legitimate in a behaviour pool: confirm "
            "the caller was already authorised for what this code goes on to do, "
            "and that the privileged scope is as narrow as the task requires."),
    },
]

DYNAMIC_TOKEN_EXTRA_RULES: List[Dict[str, Any]] = [
    {
        "id": "ABAP-CINJ-013",
        "category": "Code Injection",
        "name": "Dynamic method call on a qualified reference",
        "severity": "HIGH",
        # A8. ABAP-CINJ-010 needs the parenthesis DIRECTLY after CALL METHOD, so
        # the class- and object-qualified forms — the majority of real calls —
        # matched no rule in the corpus. Disjoint from CINJ-010, so no
        # double-reporting.
        "pattern": r"\bCALL\s+METHOD\s+[\w/]+\s*(?:=>|->)\s*\(\s*" + _NAME + r"\s*\)",
        "cwe": "CWE-94",
        "description": (
            "The method invoked is named at runtime. Whoever controls the name "
            "chooses which method of that class or object runs."),
        "recommendation": (
            "Dispatch through an interface or a CASE over a fixed set of methods, "
            "so the reachable set is written in the program rather than supplied to "
            "it."),
    },
    {
        "id": "ABAP-CINJ-014",
        "category": "Code Injection",
        "name": "Dynamic compound type in CREATE DATA",
        "severity": "MEDIUM",
        # A9. ABAP-CINJ-012 sees only `TYPE (t)`. Bounded length so a mis-split
        # statement cannot drag the match across unrelated text.
        "pattern":
            r"\bCREATE\s+DATA\s+[\w<>/-]+\s+(?:TYPE|LIKE)\b[^.]{0,200}?\(\s*"
            + _NAME + r"\s*\)",
        "cwe": "CWE-913",
        "description": (
            "The type of a data object created at runtime is itself chosen at "
            "runtime, in one of the compound forms (TABLE OF, REF TO, LINE OF) that "
            "no existing rule covers."),
        "recommendation": (
            "Constrain the type name to a set the program knows about before "
            "passing it to CREATE DATA."),
    },
    {
        "id": "ABAP-CINJ-015",
        "category": "Code Injection",
        "name": "Dynamic parameter list in EXPORT / IMPORT",
        "severity": "MEDIUM",
        # A11. The trailing TO/FROM keeps this off unrelated parenthesised
        # expressions.
        "pattern": r"\b(?:EXPORT|IMPORT)\s+\(\s*" + _NAME + r"\s*\)\s+(?:TO|FROM)\b",
        "cwe": "CWE-913",
        "description": (
            "The names moved into or out of a data cluster are chosen at runtime. "
            "No rule in the corpus mentioned either statement as a dynamic "
            "construct."),
        "recommendation": (
            "Name the parameters statically. MEDIUM rather than HIGH because this "
            "governs which names move in and out of a cluster, not what code runs."),
    },
    {
        "id": "ABAP-CINJ-016",
        "category": "Code Injection",
        "name": "Dynamic component or method selector",
        "severity": "MEDIUM",
        # A15. ABAP-CINJ-009 covers only `ASSIGN (`; 16 of 18 enumerated dynamic
        # forms matched nothing. The literal/integer exclusion is NOT optional —
        # unbounded, this collapsed 11 distinct hits over SAP-authored source to 1,
        # and that survivor was the only genuinely dynamic one.
        "pattern": r"\bASSIGN\b[^.]{0,200}?(?:->|=>|-)" + _NOT_LITERAL,
        "cwe": "CWE-913",
        "description": (
            "A component, attribute or method is selected by a name computed at "
            "runtime. The parenthesis follows a selector rather than the keyword, "
            "which is why no existing rule matched it."),
        "recommendation": (
            "Validate the name against the component list of the type concerned "
            "before using it as a selector."),
    },
    {
        "id": "ABAP-CINJ-017",
        "category": "Code Injection",
        "name": "Dynamic type in a CASTING addition",
        "severity": "MEDIUM",
        "pattern": r"\bCASTING\s+TYPE\s*\(\s*(?!['\"`0-9])[A-Za-z_]",
        "cwe": "CWE-913",
        "description": (
            "A field symbol is cast to a type named at runtime, so the memory it "
            "exposes is reinterpreted according to a value rather than a "
            "declaration."),
        "recommendation": (
            "Constrain the type name to a set the program knows about."),
    },
]

#: A10. Internal-table dynamics. 10 of 11 forms matched nothing; the eleventh
#: matched ABAP-SQLI-001 and was reported CRITICAL, CWE-89, "Dynamic WHERE clause",
#: with a host-variable recommendation — on a statement that never touches the
#: database. That is why these are CWE-913 and not CWE-89.
INTERNAL_TABLE_RULES: List[Dict[str, Any]] = [
    {
        "id": "ABAP-DYNT-001",
        "category": "Code Injection",
        "name": "Dynamic WHERE condition on an internal table",
        "severity": "MEDIUM",
        # DELETE must be in the alternation, or the engine guard below opens a
        # blind spot exactly where it suppresses ABAP-SQLI-001. The parenthesis
        # must stay bounded, or this flags the parenthesised logical expressions
        # SAP documents as correct in LOOP AT and READ TABLE.
        "pattern":
            r"\b(?:READ\s+TABLE|LOOP\s+AT|MODIFY|DELETE)\s+[\w<>/-]+[^.]*"
            r"\bWHERE\s*\(\s*" + _NAME + r"\s*\)",
        "cwe": "CWE-913",
        "description": (
            "The condition selecting rows from an internal table is built at "
            "runtime. This is not SQL injection — no database is involved — but the "
            "rows a caller can reach are chosen by a value rather than by the "
            "program."),
        "recommendation": (
            "Build the condition from a fixed set of component names. Note that a "
            "host-variable recommendation does not apply here: there is no "
            "database statement to bind against."),
    },
    {
        "id": "ABAP-DYNT-002",
        "category": "Code Injection",
        "name": "Dynamic key, sort or component list on an internal table",
        "severity": "MEDIUM",
        # No constructible false positive: every static form puts a bare name where
        # the dynamic form puts a parenthesis.
        "pattern":
            r"\b(?:SORT\s+[\w<>/-]+\s+BY|USING\s+KEY|WITH\s+(?:TABLE\s+)?KEY"
            r"|COMPONENTS|TRANSPORTING|COMPARING)\s*\(\s*" + _NAME + r"\s*\)",
        "cwe": "CWE-913",
        "description": (
            "The key, sort order or component list is chosen at runtime, so which "
            "fields are read, compared or transported is decided outside the "
            "program text."),
        "recommendation": (
            "Choose the component list in the program. Where it must vary, "
            "constrain it to the components of the row type."),
    },
]

# The RAP behaviour-definition rules belong to the CDS/BDEF rule set, because that
# is what `.asbdef` routes to. Extending in place rather than rebinding keeps the
# `from ... import CDS_RULES` in abap_sast.py pointing at the same list.
CDS_RULES.extend(RAP_BDEF_RULES[:2])

EXTRA_ABAP_RULES: List[Dict[str, Any]] = (
    AMDP_RULES + NATIVE_SQL_RULES + CDS_RULES + MISC_RULES
    + DYNAMIC_SQL_RULES + CROSS_CLIENT_RULES + AMDP_EXTRA_RULES
    + RAP_BDEF_RULES[2:] + DYNAMIC_TOKEN_EXTRA_RULES + INTERNAL_TABLE_RULES
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
