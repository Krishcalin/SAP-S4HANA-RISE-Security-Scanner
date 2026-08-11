# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL
#
# GENERATED FILE — assembled by tools/build_abap_rules.py from the author's own
# sibling project SAP-Code-Vulnerability-Analyzer (abap_scanner.py v1.9.0). Same
# copyright holder; see LICENSE and THIRD_PARTY_NOTICES.md. Do not hand-edit:
# every edit here is discarded by the next regeneration.

"""
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

# ─── vendored: rule tables ───────────────────────────────────────────── #
ABAP_SQLI_RULES: list[dict] = [
    {
        "id": "ABAP-SQLI-001",
        "category": "SQL Injection",
        "name": "Dynamic WHERE clause from variable",
        "severity": "CRITICAL",
        "pattern": r"(?:SELECT|UPDATE|DELETE)\s+.*\bWHERE\s*\(",
        "description": "A SELECT, UPDATE, or DELETE statement uses a dynamic WHERE clause supplied via a variable. If the variable contains user-controlled input, an attacker can manipulate the query.",
        "cwe": "CWE-89",
        "recommendation": "Use static WHERE conditions with host variables (@variable) instead of dynamic WHERE (variable).",
        "_taint_sink": True,
        "_sink_arg": r"WHERE\s*\(\s*([^)]*)\)",
    },
    {
        "id": "ABAP-SQLI-002",
        "category": "SQL Injection",
        "name": "String concatenation into SQL condition",
        "severity": "CRITICAL",
        "pattern": r"(?:CONCATENATE|&&).*(?:WHERE|INTO|FROM)\b",
        "description": "String concatenation is used to build part of an SQL statement, risking injection if any operand is user-controlled.",
        "cwe": "CWE-89",
        "recommendation": "Use parameterised Open SQL with host variables (@iv_param) instead of concatenating strings into queries.",
    },
    {
        "id": "ABAP-SQLI-003",
        "category": "SQL Injection",
        "name": "ADBC native SQL with dynamic query",
        "severity": "CRITICAL",
        "pattern": r"cl_sql_statement\s*->\s*execute_query",
        "description": "ADBC (ABAP Database Connectivity) native SQL is used, which bypasses Open SQL protections. Dynamic query strings are especially dangerous.",
        "cwe": "CWE-89",
        "recommendation": "Prefer Open SQL with host variables. If ADBC is required, use cl_sql_prepared_statement with bind parameters.",
    },
    {
        "id": "ABAP-SQLI-004",
        "category": "SQL Injection",
        "name": "ADBC connection with dynamic SQL",
        "severity": "CRITICAL",
        "pattern": r"cl_sql_connection\s*=>\s*get_connection",
        "description": "A raw ADBC connection is obtained, often preceding unparameterised native SQL execution.",
        "cwe": "CWE-89",
        "recommendation": "If native SQL is required, always use prepared statements with bind variables to prevent injection.",
    },
    {
        "id": "ABAP-SQLI-005",
        "category": "SQL Injection",
        "name": "OPEN CURSOR with dynamic WHERE",
        "severity": "HIGH",
        "pattern": r"OPEN\s+CURSOR\b.*\bWHERE\s*\(",
        "description": "OPEN CURSOR uses a dynamic WHERE clause which may be susceptible to SQL injection.",
        "cwe": "CWE-89",
        "recommendation": "Replace dynamic WHERE conditions with static Open SQL and host variables.",
    },
    {
        "id": "ABAP-SQLI-006",
        "category": "SQL Injection",
        "name": "Dynamic ORDER BY clause",
        "severity": "HIGH",
        "pattern": r"ORDER\s+BY\s*\(",
        "description": "Dynamic ORDER BY allows an attacker to influence query execution order, potentially leaking data via timing or error-based techniques.",
        "cwe": "CWE-89",
        "recommendation": "Use a static ORDER BY clause or validate the dynamic value against an allowlist.",
        "_taint_sink": True,
        "_sink_arg": r"ORDER\s+BY\s*\(\s*([^)]*)\)",
    },
    {
        "id": "ABAP-SQLI-007",
        "category": "SQL Injection",
        "name": "Dynamic GROUP BY clause",
        "severity": "HIGH",
        "pattern": r"GROUP\s+BY\s*\(",
        "description": "Dynamic GROUP BY may allow query manipulation when the grouped column name comes from user input.",
        "cwe": "CWE-89",
        "recommendation": "Validate the column name against a strict allowlist before use in GROUP BY.",
        "_taint_sink": True,
        "_sink_arg": r"GROUP\s+BY\s*\(\s*([^)]*)\)",
    },
    {
        "id": "ABAP-SQLI-008",
        "category": "SQL Injection",
        "name": "Dynamic HAVING clause",
        "severity": "HIGH",
        "pattern": r"HAVING\s*\(",
        "description": "A dynamic HAVING clause can be exploited similarly to a dynamic WHERE clause.",
        "cwe": "CWE-89",
        "recommendation": "Use static HAVING conditions with host variables.",
        "_taint_sink": True,
        "_sink_arg": r"HAVING\s*\(\s*([^)]*)\)",
    },
    {
        "id": "ABAP-SQLI-009",
        "category": "SQL Injection",
        "name": "Prepared statement defeated by concatenation",
        "severity": "CRITICAL",
        "pattern": r"cl_sql_prepared_statement.*(?:CONCATENATE|&&)",
        "description": "A prepared statement is combined with string concatenation, defeating the purpose of parameterisation.",
        "cwe": "CWE-89",
        "recommendation": "Never concatenate user input into the SQL string passed to a prepared statement. Use bind parameters exclusively.",
    },
    {
        "id": "ABAP-SQLI-010",
        "category": "SQL Injection",
        "name": "Dynamic FROM clause",
        "severity": "MEDIUM",
        "pattern": r"(?:SELECT|DELETE)\s+.*\bFROM\s*\(",
        "description": "The table name in a SELECT/DELETE is supplied dynamically, which may allow an attacker to target arbitrary tables.",
        "cwe": "CWE-89",
        "recommendation": "Validate the table name against an allowlist of permitted tables.",
        "_taint_sink": True,
        "_sink_arg": r"FROM\s*\(\s*([^)]*)\)",
    },
]

# ---------- 2. Code Injection (CWE-94) ----------
ABAP_CINJ_RULES: list[dict] = [
    {
        "id": "ABAP-CINJ-001",
        "category": "Code Injection",
        "name": "INSERT REPORT — runtime code injection",
        "severity": "CRITICAL",
        "pattern": r"INSERT\s+REPORT\s+.*\bFROM\b",
        "description": "INSERT REPORT replaces the source code of an ABAP program at runtime. If the source table is influenced by user input, arbitrary code execution is possible.",
        "cwe": "CWE-94",
        "recommendation": "Avoid INSERT REPORT in application code. If unavoidable, enforce S_DEVELOP AUTHORITY-CHECK and input validation.",
    },
    {
        "id": "ABAP-CINJ-002",
        "category": "Code Injection",
        "name": "GENERATE SUBROUTINE POOL — dynamic code generation",
        "severity": "CRITICAL",
        "pattern": r"GENERATE\s+SUBROUTINE\s+POOL",
        "description": "GENERATE SUBROUTINE POOL compiles and loads ABAP source at runtime, enabling arbitrary code execution if the source is tainted.",
        "cwe": "CWE-94",
        "recommendation": "Remove dynamic code generation. Use pre-built function modules or BAdIs instead.",
    },
    {
        "id": "ABAP-CINJ-003",
        "category": "Code Injection",
        "name": "Dynamic CALL FUNCTION from variable",
        "severity": "HIGH",
        "pattern": r"CALL\s+FUNCTION\s+(?!')[a-zA-Z_]\w*",
        "description": "CALL FUNCTION with a variable name (not a string literal) allows calling arbitrary function modules if the variable is user-controlled.",
        "cwe": "CWE-94",
        "recommendation": "Use a static function name or validate the variable against an allowlist. Add AUTHORITY-CHECK OBJECT 'S_RFC'.",
    },
    {
        "id": "ABAP-CINJ-004",
        "category": "Code Injection",
        "name": "Dynamic CALL TRANSACTION",
        "severity": "HIGH",
        "pattern": r"CALL\s+TRANSACTION\s+(?!')[a-zA-Z_]\w*",
        "description": "CALL TRANSACTION with a variable transaction code allows execution of arbitrary transactions if the code is user-supplied.",
        "cwe": "CWE-94",
        "recommendation": "Validate the transaction code against an allowlist and add AUTHORITY-CHECK OBJECT 'S_TCODE'.",
    },
    {
        "id": "ABAP-CINJ-005",
        "category": "Code Injection",
        "name": "Dynamic SUBMIT report",
        "severity": "HIGH",
        "pattern": r"SUBMIT\s+(?:\(|[a-zA-Z_]\w*\s+(?!AND\b|WITH\b|VIA\b|TO\b|USING\b|EXPORTING\b))",
        "description": "SUBMIT with a dynamic report name can execute arbitrary programs if the name is user-controlled.",
        "cwe": "CWE-94",
        "recommendation": "Validate the report name against an allowlist before SUBMIT.",
        "_taint_sink": True,
        "_sink_arg": r"SUBMIT\s+\(?\s*([a-zA-Z_]\w*)",
    },
    {
        "id": "ABAP-CINJ-006",
        "category": "Code Injection",
        "name": "Dynamic object creation (CREATE OBJECT TYPE variable)",
        "severity": "MEDIUM",
        "pattern": r"CREATE\s+OBJECT\s+.*\bTYPE\s*\(",
        "description": "CREATE OBJECT with a dynamic TYPE may instantiate arbitrary classes if the type name is user-controlled.",
        "cwe": "CWE-94",
        "recommendation": "Validate the class name against an allowlist of permitted types.",
    },
    {
        "id": "ABAP-CINJ-007",
        "category": "Code Injection",
        "name": "Dynamic XSLT/Simple Transformation",
        "severity": "CRITICAL",
        "pattern": r"CALL\s+TRANSFORMATION\s+(?!')[a-zA-Z_]\w*",
        "description": "CALL TRANSFORMATION with a dynamic name can invoke arbitrary transformations, potentially executing malicious XSLT.",
        "cwe": "CWE-94",
        "recommendation": "Use static transformation names or validate against an allowlist.",
    },
    {
        "id": "ABAP-CINJ-008",
        "category": "Code Injection",
        "name": "READ REPORT to extract source code",
        "severity": "HIGH",
        "pattern": r"READ\s+REPORT\s+.*\bINTO\b",
        "description": "READ REPORT extracts ABAP source code into an internal table. Combined with INSERT REPORT, this enables code-tampering attacks.",
        "cwe": "CWE-94",
        "recommendation": "Restrict usage with AUTHORITY-CHECK OBJECT 'S_DEVELOP'. Review whether this pattern is truly needed.",
    },
]

# ---------- 3. OS Command Injection (CWE-78) ----------
ABAP_CMDI_RULES: list[dict] = [
    {
        "id": "ABAP-CMDI-001",
        "category": "OS Command Injection",
        "name": "Kernel call SYSTEM — direct OS command execution",
        "severity": "CRITICAL",
        "pattern": r"CALL\s+['\"]SYSTEM['\"]",
        "description": "The ABAP kernel call 'SYSTEM' executes operating-system commands directly. This is extremely dangerous if any parameter is user-controlled.",
        "cwe": "CWE-78",
        "recommendation": "Never use CALL 'SYSTEM'. Use SAP-managed APIs or allowlisted SM49 commands via SXPG_COMMAND_EXECUTE with proper authorization.",
    },
    {
        "id": "ABAP-CMDI-002",
        "category": "OS Command Injection",
        "name": "External command execution via SXPG_COMMAND_EXECUTE",
        "severity": "HIGH",
        "pattern": r"SXPG_COMMAND_EXECUTE",
        "description": "SXPG_COMMAND_EXECUTE runs OS commands registered in SM49/SM69. If the command name or parameters are user-influenced, injection is possible.",
        "cwe": "CWE-78",
        "recommendation": "Ensure only pre-registered commands are callable, validate all parameters, and add AUTHORITY-CHECK OBJECT 'S_LOG_COM'.",
    },
    {
        "id": "ABAP-CMDI-003",
        "category": "OS Command Injection",
        "name": "SXPG_CALL_SYSTEM — external command call",
        "severity": "HIGH",
        "pattern": r"SXPG_CALL_SYSTEM",
        "description": "SXPG_CALL_SYSTEM is an alternative function module for OS command execution with similar risks to SXPG_COMMAND_EXECUTE.",
        "cwe": "CWE-78",
        "recommendation": "Use SXPG_COMMAND_EXECUTE with proper authorization checks instead. Validate all parameters.",
    },
    {
        "id": "ABAP-CMDI-004",
        "category": "OS Command Injection",
        "name": "OPEN PIPE — command piping",
        "severity": "HIGH",
        "pattern": r"OPEN\s+(?:DATASET|PIPE)\b.*\bFILTER\b",
        "description": "OPEN DATASET/PIPE with FILTER pipes data through an OS command, enabling command injection if the filter is dynamic.",
        "cwe": "CWE-78",
        "recommendation": "Avoid FILTER with user-controlled values. Use SAP application-level processing instead of OS pipes.",
    },
]

# ---------- 4. Directory Traversal (CWE-22) ----------
ABAP_PATH_RULES: list[dict] = [
    {
        "id": "ABAP-PATH-001",
        "category": "Directory Traversal",
        "name": "OPEN DATASET without path validation",
        "severity": "HIGH",
        "pattern": r"OPEN\s+DATASET\s+[a-zA-Z_]\w*\s+FOR\s+(?:INPUT|OUTPUT|APPENDING|UPDATE)",
        "description": "OPEN DATASET opens a server-side file using a variable path. Without FILE_VALIDATE_NAME, an attacker may traverse directories.",
        "cwe": "CWE-22",
        "recommendation": "Always call FILE_VALIDATE_NAME before OPEN DATASET to validate the physical path against logical file names.",
        "_taint_sink": True,
        "_sink_arg": r"OPEN\s+DATASET\s+([a-zA-Z_]\w*)",
    },
    {
        "id": "ABAP-PATH-002",
        "category": "Directory Traversal",
        "name": "DELETE DATASET without path validation",
        "severity": "HIGH",
        "pattern": r"DELETE\s+DATASET\b",
        "description": "DELETE DATASET removes a server-side file. Without path validation, an attacker may delete arbitrary files.",
        "cwe": "CWE-22",
        "recommendation": "Validate the file path with FILE_VALIDATE_NAME and add AUTHORITY-CHECK OBJECT 'S_DATASET' before deletion.",
    },
    {
        "id": "ABAP-PATH-003",
        "category": "Directory Traversal",
        "name": "TRANSFER without path validation",
        "severity": "HIGH",
        "pattern": r"TRANSFER\s+.*\bTO\s+[a-zA-Z_]\w*",
        "description": "TRANSFER writes data to a file identified by a variable. Path traversal is possible if the variable is user-controlled.",
        "cwe": "CWE-22",
        "recommendation": "Validate the target path with FILE_VALIDATE_NAME before TRANSFER.",
    },
    {
        "id": "ABAP-PATH-004",
        "category": "Directory Traversal",
        "name": "Path traversal sequence in string",
        "severity": "MEDIUM",
        "pattern": r"""(?:CONCATENATE|&&).*['"`]\.\.[/\\]""",
        "description": "A path traversal sequence (../ or ..\\) is found in a string operation, indicating potential directory escape.",
        "cwe": "CWE-22",
        "recommendation": "Sanitise file paths by removing '..' sequences and validate against logical file names.",
    },
    {
        "id": "ABAP-PATH-005",
        "category": "Directory Traversal",
        "name": "READ DATASET without path validation",
        "severity": "HIGH",
        "pattern": r"READ\s+DATASET\b",
        "description": "READ DATASET reads a server-side file. Without path validation, sensitive files may be exposed.",
        "cwe": "CWE-22",
        "recommendation": "Validate file paths with FILE_VALIDATE_NAME before reading.",
    },
]

# ---------- 5. Cross-Site Scripting (CWE-79) ----------
ABAP_XSS_RULES: list[dict] = [
    {
        "id": "ABAP-XSS-001",
        "category": "Cross-Site Scripting",
        "name": "HTML output without cl_abap_format escaping",
        "severity": "HIGH",
        "pattern": r"(?:set_cdata|set_data|set_body)\s*\(",
        "description": "HTTP response data is set without evidence of XSS escaping via cl_abap_format=>e_xss_ml or cl_http_utility=>escape_html.",
        "cwe": "CWE-79",
        "recommendation": "Escape all user-controlled output with: escape( val = data format = cl_abap_format=>e_xss_ml ).",
    },
    {
        "id": "ABAP-XSS-002",
        "category": "Cross-Site Scripting",
        "name": "HTML tag concatenation with variable",
        "severity": "HIGH",
        "pattern": r"""(?:CONCATENATE|&&)\s*.*['"`]<(?:script|img|iframe|div|span|a|form|input|body|html|style|svg|object|embed|link|meta)\b""",
        "description": "An HTML tag is concatenated with a variable, enabling reflected or stored XSS if the variable is user-controlled.",
        "cwe": "CWE-79",
        "recommendation": "Use server-side templating with automatic escaping. Apply cl_abap_format=>e_xss_ml to all dynamic values.",
    },
    {
        "id": "ABAP-XSS-003",
        "category": "Cross-Site Scripting",
        "name": "BSP/ICF response with unescaped data",
        "severity": "HIGH",
        "pattern": r"server\s*->\s*response\s*->\s*set_",
        "description": "Data is written to an ICF/BSP HTTP response. Without escaping, this may introduce XSS vulnerabilities.",
        "cwe": "CWE-79",
        "recommendation": "Escape dynamic values before writing to the HTTP response object.",
    },
    {
        "id": "ABAP-XSS-004",
        "category": "Cross-Site Scripting",
        "name": "Cookie without Secure/HttpOnly flags",
        "severity": "MEDIUM",
        "pattern": r"set_header_field.*(?:set-cookie|cookie)\b(?!.*(?:Secure|HttpOnly))",
        "description": "A cookie is set via HTTP header without Secure or HttpOnly flags, increasing XSS and session-hijacking risk.",
        "cwe": "CWE-79",
        "recommendation": "Always set cookies with the Secure and HttpOnly flags.",
    },
    {
        "id": "ABAP-XSS-005",
        "category": "Cross-Site Scripting",
        "name": "cl_abap_browser show_html with dynamic content",
        "severity": "HIGH",
        "pattern": r"cl_abap_browser\s*=>\s*show_html",
        "description": "cl_abap_browser=>show_html renders HTML in the SAP GUI browser control. Unescaped dynamic content may trigger XSS.",
        "cwe": "CWE-79",
        "recommendation": "Escape all dynamic values before passing them to show_html.",
    },
    {
        "id": "ABAP-XSS-006",
        "category": "Cross-Site Scripting",
        "name": "CL_HTTP_UTILITY missing escape_html",
        "severity": "MEDIUM",
        "pattern": r"cl_http_utility\s*=>\s*(?!escape_html)\w+",
        "description": "CL_HTTP_UTILITY is used without its escape_html method, suggesting HTML output may not be properly encoded.",
        "cwe": "CWE-79",
        "recommendation": "Use cl_http_utility=>escape_html() for all user-facing HTML output.",
    },
]

# ---------- 6. Missing Authorization (CWE-862) ----------
ABAP_AUTH_RULES: list[dict] = [
    {
        "id": "ABAP-AUTH-001",
        "category": "Missing Authorization",
        "name": "Function module without AUTHORITY-CHECK",
        "severity": "CRITICAL",
        "pattern": r"^\s*FUNCTION\s+[\w/]+",
        "description": "A FUNCTION … ENDFUNCTION block contains no AUTHORITY-CHECK statement. RFC-enabled function modules in particular must perform an AUTHORITY-CHECK (object S_RFC plus a function-specific object) to prevent unauthorised remote invocation.",
        "cwe": "CWE-862",
        "recommendation": "Add AUTHORITY-CHECK OBJECT 'S_RFC' (and a function-specific authorization object) near the start of every function module, then verify SY-SUBRC.",
        "_block_check": True,
        "_block_start": r"^\s*FUNCTION\s+[\w/]+",
        "_block_end": r"^\s*ENDFUNCTION\b",
        "_absent": r"\bAUTHORITY-CHECK\b",
    },
    {
        "id": "ABAP-AUTH-002",
        "category": "Missing Authorization",
        "name": "AUTHORITY-CHECK with DUMMY value",
        "severity": "HIGH",
        "pattern": r"AUTHORITY-CHECK\s+OBJECT\s+.*\bDUMMY\b",
        "description": "AUTHORITY-CHECK uses the DUMMY value, which always passes. This effectively disables the authorization check.",
        "cwe": "CWE-862",
        "recommendation": "Replace DUMMY with the actual authorization field values that should be checked.",
    },
    {
        "id": "ABAP-AUTH-003",
        "category": "Missing Authorization",
        "name": "SY-SUBRC not checked after AUTHORITY-CHECK",
        "severity": "HIGH",
        "pattern": r"AUTHORITY-CHECK\s+OBJECT\s+.*\.\s*(?!\s*IF\s+SY-SUBRC)",
        "description": "AUTHORITY-CHECK is present but SY-SUBRC is not checked immediately after. The authorization result is ignored.",
        "cwe": "CWE-862",
        "recommendation": "Always check SY-SUBRC immediately after AUTHORITY-CHECK and raise an exception or return on failure (SY-SUBRC <> 0).",
    },
    {
        "id": "ABAP-AUTH-004",
        "category": "Missing Authorization",
        "name": "RFC call without prior AUTHORITY-CHECK",
        "severity": "HIGH",
        "pattern": r"CALL\s+FUNCTION\s+.*\bDESTINATION\b",
        "description": "An RFC call is made to a remote destination without evidence of a preceding AUTHORITY-CHECK in the same block.",
        "cwe": "CWE-862",
        "recommendation": "Add AUTHORITY-CHECK OBJECT 'S_RFC' before making RFC calls.",
    },
    {
        "id": "ABAP-AUTH-005",
        "category": "Missing Authorization",
        "name": "DELETE FROM table without AUTHORITY-CHECK",
        "severity": "HIGH",
        "pattern": r"DELETE\s+FROM\s+\w+\s+WHERE",
        "description": "Database records are deleted without evidence of a preceding authorization check in the same code block.",
        "cwe": "CWE-862",
        "recommendation": "Add AUTHORITY-CHECK for the relevant authorization object before DELETE operations on business data.",
    },
    {
        "id": "ABAP-AUTH-006",
        "category": "Missing Authorization",
        "name": "UPDATE table SET without AUTHORITY-CHECK",
        "severity": "HIGH",
        "pattern": r"UPDATE\s+\w+\s+SET\b",
        "description": "Database records are updated without evidence of a preceding authorization check.",
        "cwe": "CWE-862",
        "recommendation": "Add AUTHORITY-CHECK for the relevant authorization object before UPDATE operations.",
    },
    {
        "id": "ABAP-AUTH-007",
        "category": "Missing Authorization",
        "name": "INSERT INTO table without AUTHORITY-CHECK",
        "severity": "MEDIUM",
        "pattern": r"INSERT\s+INTO\s+\w+\b(?!\s+REPORT)",
        "description": "Records are inserted into a database table without evidence of a preceding authorization check.",
        "cwe": "CWE-862",
        "recommendation": "Add AUTHORITY-CHECK for the relevant authorization object before INSERT operations on business data.",
    },
    {
        "id": "ABAP-AUTH-008",
        "category": "Missing Authorization",
        "name": "CALL TRANSACTION without S_TCODE check",
        "severity": "HIGH",
        "pattern": r"CALL\s+TRANSACTION\b",
        "description": "A transaction is called without evidence of AUTHORITY-CHECK OBJECT 'S_TCODE' in the same code block.",
        "cwe": "CWE-862",
        "recommendation": "Add AUTHORITY-CHECK OBJECT 'S_TCODE' ID 'TCD' FIELD <tcode> before CALL TRANSACTION.",
    },
]

# ---------- 7. Hardcoded Credentials (CWE-798) ----------
ABAP_CRED_RULES: list[dict] = [
    {
        "id": "ABAP-CRED-001",
        "category": "Hardcoded Credentials",
        "name": "Hardcoded password literal",
        "severity": "CRITICAL",
        "pattern": r"""(?:password|passwd|pwd|kennwort)\s*=\s*['"`][^'"`]{4,}['"`]""",
        "description": "A password is hardcoded as a string literal in ABAP source code, exposing it to anyone with read access.",
        "cwe": "CWE-798",
        "recommendation": "Store credentials in the SAP Secure Store (SSF/SSFC) or use destination services. Never hardcode passwords.",
    },
    {
        "id": "ABAP-CRED-002",
        "category": "Hardcoded Credentials",
        "name": "Hardcoded API key or token",
        "severity": "CRITICAL",
        "pattern": r"""(?:api_key|apikey|api_secret|token|secret|bearer|auth_token|access_token)\s*=\s*['"`][^'"`]{8,}['"`]""",
        "description": "An API key, secret, or token is hardcoded in the source code.",
        "cwe": "CWE-798",
        "recommendation": "Use SAP Destination Service or BTP Credential Store for API keys and tokens.",
    },
    {
        "id": "ABAP-CRED-003",
        "category": "Hardcoded Credentials",
        "name": "RFC destination with hardcoded password",
        "severity": "HIGH",
        "pattern": r"DESTINATION\s+.*(?:PASSWORD|PASSWD)\s*=\s*'[^']+'",
        "description": "An RFC destination call includes a hardcoded password, exposing credentials in transport logs and source code.",
        "cwe": "CWE-798",
        "recommendation": "Configure RFC destinations in SM59 with stored credentials instead of embedding passwords in code.",
    },
    {
        "id": "ABAP-CRED-004",
        "category": "Hardcoded Credentials",
        "name": "Hardcoded Basic auth header",
        "severity": "HIGH",
        "pattern": r"""(?:authorization|set_request_header).*['"`]Basic\s+[A-Za-z0-9+/=]{8,}['"`]""",
        "description": "A Base64-encoded Basic authentication header is hardcoded, embedding credentials directly in source code.",
        "cwe": "CWE-798",
        "recommendation": "Use SAP Destination Service or compute the auth header at runtime from securely stored credentials.",
    },
    {
        "id": "ABAP-CRED-005",
        "category": "Hardcoded Credentials",
        "name": "Credentials defined as CONSTANTS",
        "severity": "MEDIUM",
        "pattern": r"""CONSTANTS?\s+.*(?:password|secret|key|token|passwd|pwd).*\bVALUE\s+['"`][^'"`]{4,}['"`]""",
        "description": "A credential value is defined as a CONSTANT, making it visible in the source and immutable at runtime.",
        "cwe": "CWE-798",
        "recommendation": "Move credentials to secure storage and retrieve them at runtime.",
    },
    {
        "id": "ABAP-CRED-006",
        "category": "Hardcoded Credentials",
        "name": "RFC call with embedded USER/PASSWORD",
        "severity": "HIGH",
        "pattern": r"(?:RFC_|BAPI_)\w+.*(?:USER|PASSWORD)\s*=\s*'[^']+'",
        "description": "An RFC or BAPI call includes hardcoded USER or PASSWORD exporting parameters.",
        "cwe": "CWE-798",
        "recommendation": "Configure RFC connections in SM59 with stored credentials instead of passing them in code.",
    },
]

# ---------- 8. Weak Cryptography (CWE-327) ----------
ABAP_CRYP_RULES: list[dict] = [
    {
        "id": "ABAP-CRYP-001",
        "category": "Weak Cryptography",
        "name": "MD5 hash algorithm usage",
        "severity": "HIGH",
        "pattern": r"""cl_abap_message_digest\s*=>.*['"`]MD5['"`]""",
        "description": "The MD5 hash algorithm is cryptographically broken and should not be used for security purposes.",
        "cwe": "CWE-327",
        "recommendation": "Use SHA-256 or stronger: cl_abap_message_digest=>calculate_hash_for_char( if_algorithm = 'SHA256' ... ).",
    },
    {
        "id": "ABAP-CRYP-002",
        "category": "Weak Cryptography",
        "name": "SHA-1 hash algorithm usage",
        "severity": "MEDIUM",
        "pattern": r"""cl_abap_message_digest\s*=>.*['"`]SHA[-]?1['"`]""",
        "description": "SHA-1 is deprecated for security-sensitive operations due to known collision attacks.",
        "cwe": "CWE-327",
        "recommendation": "Migrate to SHA-256 or SHA-512 for all cryptographic hashing.",
    },
    {
        "id": "ABAP-CRYP-003",
        "category": "Weak Cryptography",
        "name": "DES encryption algorithm",
        "severity": "HIGH",
        "pattern": r"""(?:DES|3DES|TRIPLE.?DES)\b""",
        "description": "DES/3DES is considered weak. The 56-bit (DES) or 112-bit effective (3DES) key size is insufficient for modern security.",
        "cwe": "CWE-327",
        "recommendation": "Use AES-256 encryption instead of DES/3DES.",
    },
    {
        "id": "ABAP-CRYP-004",
        "category": "Weak Cryptography",
        "name": "Hardcoded encryption key or IV",
        "severity": "HIGH",
        "pattern": r"""(?:key|iv|init.?vector)\s*=\s*['"`][0-9a-fA-F]{16,}['"`]""",
        "description": "An encryption key or initialisation vector is hardcoded as a hex string, defeating the purpose of encryption.",
        "cwe": "CWE-327",
        "recommendation": "Generate keys dynamically and store them in SAP Secure Store or a key-management service.",
    },
    {
        "id": "ABAP-CRYP-005",
        "category": "Weak Cryptography",
        "name": "HMAC with weak hash algorithm",
        "severity": "MEDIUM",
        "pattern": r"""cl_abap_hmac\s*=>.*['"`](?:MD5|SHA[-]?1)['"`]""",
        "description": "HMAC is computed with a weak underlying hash algorithm (MD5 or SHA-1).",
        "cwe": "CWE-327",
        "recommendation": "Use HMAC-SHA256 or HMAC-SHA512 for message authentication.",
    },
]

# ---------- 9. Information Disclosure (CWE-200) ----------
ABAP_INFO_RULES: list[dict] = [
    {
        "id": "ABAP-INFO-001",
        "category": "Information Disclosure",
        "name": "Overly broad exception catch (cx_root)",
        "severity": "MEDIUM",
        "pattern": r"CATCH\s+cx_root\b",
        "description": "Catching cx_root swallows all exceptions indiscriminately, which may hide errors and expose internal details in error messages.",
        "cwe": "CWE-200",
        "recommendation": "Catch specific exception classes and sanitise any messages exposed to users.",
    },
    {
        "id": "ABAP-INFO-002",
        "category": "Information Disclosure",
        "name": "BREAK-POINT left in production code",
        "severity": "LOW",
        "pattern": r"BREAK[\s-]POINT\b",
        "description": "A BREAK-POINT statement is present, which will halt execution in debug mode and may expose internal state.",
        "cwe": "CWE-200",
        "recommendation": "Remove all BREAK-POINT statements before transporting to production.",
    },
    {
        "id": "ABAP-INFO-003",
        "category": "Information Disclosure",
        "name": "System variable exposure in output",
        "severity": "LOW",
        "pattern": r"WRITE\s+.*\bSY-(?:UNAME|MANDT|SYSID|HOST|DBSYS|OPSYS)\b",
        "description": "System variables (client, user, host, database type) are written to output, potentially exposing infrastructure details.",
        "cwe": "CWE-200",
        "recommendation": "Avoid exposing system variables to end users. Log them server-side if needed for debugging.",
    },
    {
        "id": "ABAP-INFO-004",
        "category": "Information Disclosure",
        "name": "Exception message exposed to user",
        "severity": "MEDIUM",
        "pattern": r"MESSAGE\s+.*(?:get_text|get_longtext)\s*\(",
        "description": "An exception's text is directly displayed to the user via MESSAGE, potentially revealing internal implementation details.",
        "cwe": "CWE-200",
        "recommendation": "Display a generic error message to users. Log the full exception details server-side.",
    },
    {
        "id": "ABAP-INFO-005",
        "category": "Information Disclosure",
        "name": "Sensitive data written to output",
        "severity": "HIGH",
        "pattern": r"WRITE\s+.*(?:password|passwd|secret|token|credential|ssn|credit.?card)\b",
        "description": "Potentially sensitive data (passwords, tokens, SSNs) is written to screen output.",
        "cwe": "CWE-200",
        "recommendation": "Never write sensitive data to screen output. Use secure logging or mask the values.",
    },
]

# ---------- 10. Insecure Configuration (CWE-16) ----------
ABAP_CONF_RULES: list[dict] = [
    {
        "id": "ABAP-CONF-001",
        "category": "Insecure Configuration",
        "name": "Anonymous SSL profile (no certificate validation)",
        "severity": "HIGH",
        "pattern": r"""ssl_id\s*=\s*['"`]ANONYM['"`]""",
        "description": "The ANONYM SSL profile disables certificate validation, enabling man-in-the-middle attacks.",
        "cwe": "CWE-16",
        "recommendation": "Use a named SSL client identity (e.g., DFAULT or a custom PSE) with proper certificate validation.",
    },
    {
        "id": "ABAP-CONF-002",
        "category": "Insecure Configuration",
        "name": "HTTP (unencrypted) in connection URL",
        "severity": "HIGH",
        "pattern": r"""['"`]http://[^'"`]+['"`]""",
        "description": "An unencrypted HTTP URL is used for a connection, exposing data in transit to interception.",
        "cwe": "CWE-16",
        "recommendation": "Use HTTPS for all network connections to ensure data-in-transit encryption.",
    },
    {
        "id": "ABAP-CONF-003",
        "category": "Insecure Configuration",
        "name": "CSRF protection disabled",
        "severity": "MEDIUM",
        "pattern": r"""(?:csrf|xsrf).*(?:=\s*['"`]?(?:0|false|off|disabled)['"`]?|disable)""",
        "description": "CSRF/XSRF protection appears to be disabled, leaving state-changing requests vulnerable to cross-site request forgery.",
        "cwe": "CWE-16",
        "recommendation": "Enable CSRF token validation for all state-changing HTTP endpoints.",
    },
    {
        "id": "ABAP-CONF-004",
        "category": "Insecure Configuration",
        "name": "HTTP URL in HTTP client creation",
        "severity": "HIGH",
        "pattern": r"cl_http_client\s*=>\s*create_by_url.*http://",
        "description": "An HTTP client is created with an unencrypted HTTP URL.",
        "cwe": "CWE-16",
        "recommendation": "Use HTTPS URLs when creating HTTP clients.",
    },
    {
        "id": "ABAP-CONF-005",
        "category": "Insecure Configuration",
        "name": "Wildcard activity in AUTHORITY-CHECK",
        "severity": "MEDIUM",
        "pattern": r"""AUTHORITY-CHECK\s+.*ACTVT\s*(?:FIELD)?\s+['"`]\*['"`]""",
        "description": "A wildcard '*' is used for the ACTVT (activity) field in AUTHORITY-CHECK, effectively granting all activities.",
        "cwe": "CWE-16",
        "recommendation": "Specify explicit activity values (01=Create, 02=Change, 03=Display, 06=Delete) instead of wildcards.",
    },
    {
        "id": "ABAP-CONF-006",
        "category": "Insecure Configuration",
        "name": "SSL verification disabled",
        "severity": "HIGH",
        "pattern": r"""ssl_verify\s*=\s*(?:['"`]?(?:0|false|abap_false)['"`]?)""",
        "description": "SSL/TLS certificate verification is explicitly disabled, enabling man-in-the-middle attacks.",
        "cwe": "CWE-16",
        "recommendation": "Always enable SSL verification. Configure the SAP trust store with the required CA certificates.",
    },
]

# ---------- 11. RFC Security (CWE-284) ----------
ABAP_RFC_RULES: list[dict] = [
    {
        "id": "ABAP-RFC-001",
        "category": "RFC Security",
        "name": "Trusted RFC connection without validation",
        "severity": "HIGH",
        "pattern": r"""(?:TRUSTED|trusted)\s*=\s*['"`]?(?:X|abap_true|true)['"`]?""",
        "description": "A trusted RFC connection is established, which may skip authentication checks between systems.",
        "cwe": "CWE-284",
        "recommendation": "Review whether trusted RFC is justified. Ensure the target system validates the caller's authority.",
    },
    {
        "id": "ABAP-RFC-002",
        "category": "RFC Security",
        "name": "Dynamic RFC destination from variable",
        "severity": "HIGH",
        "pattern": r"DESTINATION\s+(?!')[a-zA-Z_]\w*",
        "description": "The RFC destination is supplied via a variable. If user-controlled, an attacker may redirect calls to a malicious system.",
        "cwe": "CWE-284",
        "recommendation": "Validate the destination name against an allowlist of configured RFC connections.",
    },
    {
        "id": "ABAP-RFC-003",
        "category": "RFC Security",
        "name": "RFC callback to external system",
        "severity": "HIGH",
        "pattern": r"CALL\s+FUNCTION\s+.*\bCALLBACK\b",
        "description": "An RFC callback pattern is detected, which may allow an external system to invoke functions on this system.",
        "cwe": "CWE-284",
        "recommendation": "Restrict RFC callbacks with proper authorization checks and network-level controls.",
    },
    {
        "id": "ABAP-RFC-004",
        "category": "RFC Security",
        "name": "Registered server program (inbound RFC trust)",
        "severity": "CRITICAL",
        "pattern": r"RFC_REGISTER|REGISTERED\s+SERVER\s+PROGRAM",
        "description": "A registered server program pattern is detected, enabling external systems to call into this SAP system via RFC.",
        "cwe": "CWE-284",
        "recommendation": "Restrict registered server programs with S_RFC authorization and network ACLs.",
    },
    {
        "id": "ABAP-RFC-005",
        "category": "RFC Security",
        "name": "Async RFC without error handling",
        "severity": "MEDIUM",
        "pattern": r"STARTING\s+NEW\s+TASK\s+.*\bDESTINATION\b",
        "description": "An asynchronous RFC call is made without evidence of RECEIVE RESULTS or error handling.",
        "cwe": "CWE-284",
        "recommendation": "Always handle RECEIVE RESULTS FROM FUNCTION and check SY-SUBRC for async RFC calls.",
    },
]

# ---------- 12. BTP-Specific Config (various CWEs) ----------
ABAP_BTP_RULES: list[dict] = [
    {
        "id": "ABAP-BTP-001",
        "category": "BTP Security",
        "name": "Overly permissive scope grant in xs-security.json",
        "severity": "HIGH",
        "pattern": r"""["']grant-as-authority-to-apps["']\s*:\s*\[["']\$ACCEPT_GRANTED_AUTHORITIES["']\]""",
        "description": "xs-security.json grants authority acceptance to all requesting apps, effectively bypassing scope restrictions.",
        "cwe": "CWE-269",
        "recommendation": "Restrict grant-as-authority-to-apps to specific named applications only.",
    },
    {
        "id": "ABAP-BTP-002",
        "category": "BTP Security",
        "name": "Wildcard scope in role template",
        "severity": "HIGH",
        "pattern": r"""["']scope-references["']\s*:\s*\[.*["']\$XSAPPNAME\.\*["']""",
        "description": "A role template references all scopes via wildcard, granting excessive permissions.",
        "cwe": "CWE-269",
        "recommendation": "Enumerate specific required scopes instead of using wildcard references.",
    },
    {
        "id": "ABAP-BTP-003",
        "category": "BTP Security",
        "name": "Hardcoded credentials in mta.yaml",
        "severity": "CRITICAL",
        "pattern": r"""(?:password|secret|key|token|credential)\s*:\s*['"]?[^\s'"${}]{8,}['"]?""",
        "description": "Credentials appear to be hardcoded in the MTA deployment descriptor.",
        "cwe": "CWE-798",
        "recommendation": "Use BTP environment variables, Destination Service, or Credential Store for secrets.",
    },
    {
        "id": "ABAP-BTP-004",
        "category": "BTP Security",
        "name": "Missing @requires annotation in CDS",
        "severity": "HIGH",
        "pattern": r"service\s+\w+\s*\{(?![^}]*@requires)",
        "description": "A CDS service definition lacks an @requires annotation, meaning it may be accessible without authentication.",
        "cwe": "CWE-862",
        "recommendation": "Add @requires: 'authenticated-user' or a specific role to the service definition.",
    },
    {
        "id": "ABAP-BTP-005",
        "category": "BTP Security",
        "name": "Unauthenticated route in xs-app.json",
        "severity": "HIGH",
        "pattern": r"""["']authenticationType["']\s*:\s*["']none["']""",
        "description": "An xs-app.json route is configured without authentication, making it publicly accessible.",
        "cwe": "CWE-862",
        "recommendation": "Set authenticationType to 'xsuaa' or 'ias' unless the route genuinely needs to be public.",
    },
    {
        "id": "ABAP-BTP-006",
        "category": "BTP Security",
        "name": "Missing Content-Security-Policy in xs-app.json",
        "severity": "MEDIUM",
        "pattern": r"""["']routes["']\s*:.*(?!.*Content-Security-Policy)""",
        "description": "xs-app.json routes do not include a Content-Security-Policy header, increasing XSS risk.",
        "cwe": "CWE-16",
        "recommendation": "Add Content-Security-Policy headers to xs-app.json route configurations.",
    },
    {
        "id": "ABAP-BTP-007",
        "category": "BTP Security",
        "name": "XSUAA token validation disabled",
        "severity": "HIGH",
        "pattern": r"""(?:validateToken|tokenValidation)\s*[=:]\s*(?:false|0|off)""",
        "description": "XSUAA JWT token validation is disabled, allowing unauthenticated or forged requests.",
        "cwe": "CWE-287",
        "recommendation": "Always enable JWT token validation for XSUAA-protected endpoints.",
    },
    {
        "id": "ABAP-BTP-008",
        "category": "BTP Security",
        "name": "Insecure CORS configuration",
        "severity": "MEDIUM",
        "pattern": r"""(?:allowedOrigin|cors).*['"`]\*['"`]""",
        "description": "CORS is configured to allow all origins (*), enabling cross-origin attacks.",
        "cwe": "CWE-16",
        "recommendation": "Restrict allowed origins to specific trusted domains.",
    },
]

# ---------- 13. Vulnerable SAP Dependencies ----------
ABAP_EXTRA_RULES: list[dict] = [
    {
        # SQLI-011 (not -007): -007 is "Dynamic GROUP BY" in the base rules.
        # This complements SQLI-010 by also catching FROM (var) on a
        # continuation line and rating it HIGH.
        "id": "ABAP-SQLI-011",
        "category": "SQL Injection",
        "name": "Dynamic table name in FROM clause",
        "severity": "HIGH",
        "pattern": r"\bFROM\s*\(\s*\w+\s*\)",
        "description": "A SELECT reads from a dynamically supplied table name (FROM (var)); an attacker who controls the variable can read arbitrary tables.",
        "cwe": "CWE-89",
        "recommendation": "Validate dynamic table names against an allow-list (e.g. cl_abap_dyn_prg=>check_table_name_str) or use a static FROM clause.",
        "_taint_sink": True,
        "_sink_arg": r"FROM\s*\(\s*([^)]*)\)",
    },
    {
        "id": "ABAP-AUTH-009",
        "category": "Missing Authorization",
        "name": "Cross-client access via CLIENT SPECIFIED",
        "severity": "MEDIUM",
        "pattern": r"\bCLIENT\s+SPECIFIED\b",
        "description": "CLIENT SPECIFIED bypasses automatic client handling, allowing reads/writes across SAP clients (mandants).",
        "cwe": "CWE-284",
        "recommendation": "Avoid CLIENT SPECIFIED unless cross-client access is required and authorized; add an explicit AUTHORITY-CHECK and validate the client value.",
    },
    {
        "id": "ABAP-CINJ-009",
        "category": "Code Injection",
        "name": "Dynamic field-symbol assignment",
        "severity": "MEDIUM",
        "pattern": r"\bASSIGN\s+\(",
        "description": "ASSIGN (var) resolves a data-object / component name at runtime; attacker-controlled names enable access to unintended fields or memory.",
        "cwe": "CWE-913",
        "recommendation": "Validate the dynamic name against an allow-list before ASSIGN, or use statically typed field symbols.",
    },
    {
        "id": "ABAP-CINJ-010",
        "category": "Code Injection",
        "name": "Dynamic method invocation",
        "severity": "HIGH",
        "pattern": r"\bCALL\s+METHOD\s+\(",
        "description": "CALL METHOD (var) invokes a method whose name is computed at runtime; attacker-controlled input can call unintended methods.",
        "cwe": "CWE-94",
        "recommendation": "Restrict dynamically called method names to a vetted allow-list.",
    },
    {
        "id": "ABAP-CMDI-005",
        "category": "OS Command Injection",
        "name": "Frontend OS command execution",
        "severity": "HIGH",
        "pattern": r"cl_gui_frontend_services=>execute",
        "description": "cl_gui_frontend_services=>execute runs an executable/command on the user's frontend; dynamic parameters allow command injection.",
        "cwe": "CWE-78",
        "recommendation": "Avoid launching OS commands from ABAP; if unavoidable, hard-code the command and never pass user input to application/parameter.",
    },
    {
        "id": "ABAP-CRYP-006",
        "category": "Weak Cryptography",
        "name": "Non-cryptographic random number generator",
        "severity": "LOW",
        "pattern": r"\bcl_abap_random\b",
        "description": "cl_abap_random is a pseudo-random generator that is not suitable for security tokens, keys, or nonces.",
        "cwe": "CWE-330",
        "recommendation": "Use a cryptographically secure source for security-sensitive values; cl_abap_random is acceptable only for non-security use.",
    },
    # --- Checks added for parity with SAP CVA (hex IDs noted in descriptions) ---
    {
        "id": "ABAP-CINJ-011",
        "category": "Code Injection",
        "name": "Remote ABAP execution via RFC_ABAP_INSTALL_AND_RUN",
        "severity": "CRITICAL",
        "pattern": r"'RFC_ABAP_INSTALL_AND_RUN'",
        "description": "RFC_ABAP_INSTALL_AND_RUN compiles and runs arbitrary ABAP source passed at runtime — full remote code execution if the source is attacker-influenced (CVA check 1109).",
        "cwe": "CWE-94",
        "recommendation": "Never call RFC_ABAP_INSTALL_AND_RUN from application code; it should be disabled/locked down on production systems.",
    },
    {
        "id": "ABAP-CINJ-012",
        "category": "Code Injection",
        "name": "Dynamic data type in CREATE DATA",
        "severity": "MEDIUM",
        "pattern": r"\bCREATE\s+DATA\s+\w+\s+TYPE\s+(?:HANDLE\s+)?\(",
        "description": "CREATE DATA ... TYPE (var) resolves a type name at runtime; attacker-controlled type names can instantiate unintended objects/structures.",
        "cwe": "CWE-913",
        "recommendation": "Validate the dynamic type name against an allow-list, or use a statically declared type.",
    },
    {
        "id": "ABAP-SQLI-012",
        "category": "SQL Injection",
        "name": "Open SQL with dynamic secondary connection",
        "severity": "MEDIUM",
        "pattern": r"\bCONNECTION\s*\(",
        "description": "An Open SQL statement targets a dynamically named secondary database connection (CONNECTION (var)); a controlled connection name can redirect queries to an unintended database (CVA check 1121).",
        "cwe": "CWE-89",
        "recommendation": "Use a static, validated connection name; never derive the secondary connection from external input.",
    },
    {
        "id": "ABAP-PATH-006",
        "category": "Directory Traversal",
        "name": "Frontend file access via cl_gui_frontend_services",
        "severity": "MEDIUM",
        "pattern": r"cl_gui_frontend_services\s*=>\s*(?:gui_upload|gui_download|file_open_dialog|file_save_dialog|directory_browse)",
        "description": "Frontend file up/download uses a path that, if user-controlled and unvalidated, allows reading or writing arbitrary files on the user's workstation (CVA check 1124/1126 family).",
        "cwe": "CWE-22",
        "recommendation": "Validate/normalise the file path and restrict to an expected directory; do not pass unchecked paths to frontend file services.",
    },
    {
        "id": "ABAP-INFO-006",
        "category": "Information Disclosure",
        "name": "Read of a security-sensitive table",
        "severity": "HIGH",
        "pattern": r"\bSELECT\b.*\bFROM\s+(?:usr02|usr04|usrpwdhistory|ush02|ush04|rfcdes|rsecactb|pa0008|pa0009|pa0006|bseg)\b",
        "description": "Custom code reads a security-sensitive table (password hashes, RFC destinations, payroll/finance). Such reads must be tightly authorization-controlled (CVA check 11G0).",
        "cwe": "CWE-200",
        "recommendation": "Avoid reading sensitive tables directly; use released APIs and enforce an AUTHORITY-CHECK for the relevant authorization object.",
    },
    {
        "id": "ABAP-CONF-007",
        "category": "Insecure Configuration",
        "name": "Unvalidated URL redirect (open redirect)",
        "severity": "HIGH",
        "pattern": r"(?:->redirect\s*\(|goto_page\s*\(|set_header_field\s*\(\s*name\s*=\s*'location')",
        "description": "A redirect/navigation target is set from a variable; if user-controlled this is an open redirect that aids phishing and token theft (CVA check 11P1).",
        "cwe": "CWE-601",
        "recommendation": "Validate redirect targets against an allow-list of permitted URLs/pages; never redirect to a raw external value.",
    },
    {
        "id": "ABAP-CONF-008",
        "category": "Insecure Configuration",
        "name": "Obsolete COMMUNICATION statement",
        "severity": "LOW",
        "pattern": r"^\s*COMMUNICATION\s+(?:INIT|ALLOCATE|ACCEPT|SEND|RECEIVE|DEALLOCATE)\b",
        "description": "The obsolete COMMUNICATION statement opens raw, unencrypted network communication with no modern security controls (CVA check 11C1).",
        "cwe": "CWE-477",
        "recommendation": "Replace COMMUNICATION with secure, supported APIs (e.g. cl_http_client over HTTPS or RFC with SNC).",
    },
    {
        "id": "ABAP-CONF-009",
        "category": "Insecure Configuration",
        "name": "Hardcoded IP address",
        "severity": "MEDIUM",
        "pattern": r"'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'",
        "description": "A hardcoded IP address ties the code to a fixed host, bypasses name resolution / failover, and often points at an unintended system after a copy (CVA check 11S1).",
        "cwe": "CWE-547",
        "recommendation": "Externalise hosts to configuration (RFC destinations, TVARVC, logical destinations) instead of hardcoding IP addresses.",
    },
]

# ---------- Backdoor / Malicious Code (CWE-912 Hidden Functionality) ----------
# These patterns target the deliberate subversion of access control — the
# hallmark of an insider backdoor or a supply-chain implant — rather than the
# accidental coding mistakes the other categories cover. Runtime code-generation
# backdoors (INSERT REPORT, GENERATE SUBROUTINE POOL) are already flagged by the
# Code Injection category and are intentionally NOT duplicated here.
ABAP_BACKDOOR_RULES: list[dict] = [
    {
        "id": "ABAP-BKDR-001",
        "category": "Backdoor / Malicious Code",
        "name": "Hardcoded user-name check (logic bomb / privilege bypass)",
        "severity": "CRITICAL",
        "pattern": r"\bSY-UNAME\b\s*(?:=|<>|EQ|NE|CP|CO|CA)\s*'",
        "description": "Code branches on SY-UNAME compared to a hardcoded user name. This is the classic ABAP backdoor: a specific account is granted hidden behaviour (e.g. an authorization check is skipped or elevated logic runs) that is invisible to the normal authorization concept.",
        "cwe": "CWE-912",
        "recommendation": "Never gate logic on a hardcoded user name. Drive behaviour from roles/authorization objects (AUTHORITY-CHECK) so it is governed by the standard SAP authorization concept and is auditable.",
    },
    {
        "id": "ABAP-BKDR-002",
        "category": "Backdoor / Malicious Code",
        "name": "Reference to standard/superuser account name",
        "severity": "HIGH",
        "pattern": r"'(?:SAP\*|DDIC|EARLYWATCH|SAPCPIC|TMSADM)'",
        "description": "The code references a standard SAP superuser/technical account (SAP*, DDIC, EARLYWATCH, SAPCPIC, TMSADM) as a literal. Custom code special-casing or authenticating as these accounts is a strong backdoor indicator.",
        "cwe": "CWE-912",
        "recommendation": "Remove references to standard accounts from custom code. These accounts must be locked/secured and never used programmatically.",
    },
    {
        "id": "ABAP-BKDR-003",
        "category": "Backdoor / Malicious Code",
        "name": "Direct write to user/authorization tables",
        "severity": "CRITICAL",
        "pattern": r"\b(?:INSERT|MODIFY|UPDATE|DELETE)\s+(?:FROM\s+|INTO\s+)?(?:USR02|USR04|USR10|USR21|USR40|UST04|UST10C|UST10S|USGRP|AGR_USERS|AGR_1251|AGR_1252|AGR_DEFINE|USRBF2|USOBT|USOBX|USOBT_C|USOBX_C)\b",
        "description": "Custom code performs a direct DML write to a user-master or authorization table, bypassing transactions SU01/PFCG and their authorization checks. This is a covert way to create users, grant roles, or alter authorizations without an audit trail.",
        "cwe": "CWE-269",
        "recommendation": "Never write to user/authorization tables directly. Use the supported BAPIs (with proper AUTHORITY-CHECK) or SU01/PFCG so changes are validated and logged.",
    },
    {
        "id": "ABAP-BKDR-004",
        "category": "Backdoor / Malicious Code",
        "name": "Programmatic user/role administration",
        "severity": "HIGH",
        "pattern": r"\bCALL\s+FUNCTION\s+'(?:BAPI_USER_CREATE1?|BAPI_USER_CHANGE|BAPI_USER_ACTGROUPS_ASSIGN|BAPI_USER_LOCACTGROUPS_ASSIGN|BAPI_USER_PROFILES_ASSIGN|SUSR_USER_AUTH_FOR_OBJ)'",
        "description": "Custom code creates users, changes users, or assigns roles/profiles programmatically. While occasionally legitimate (e.g. HR provisioning), in application code this is a common backdoor for silently granting privileges and must be reviewed.",
        "cwe": "CWE-269",
        "recommendation": "Restrict user/role provisioning to dedicated, authorization-protected provisioning code. Add AUTHORITY-CHECK on S_USER_GRP / S_USER_AGR and log every change.",
    },
    {
        "id": "ABAP-BKDR-005",
        "category": "Backdoor / Malicious Code",
        "name": "Hardcoded client (SY-MANDT) check",
        "severity": "MEDIUM",
        "pattern": r"\bSY-MANDT\b\s*(?:=|<>|EQ|NE|CP)\s*'",
        "description": "Code branches on SY-MANDT compared to a hardcoded client. This can hide behaviour that only triggers in a specific client (e.g. production), a technique used to conceal malicious logic from test systems.",
        "cwe": "CWE-912",
        "recommendation": "Avoid client-specific hardcoded behaviour. If client-dependent logic is genuinely required, derive it from configuration (TVARVC / customizing), not a literal.",
    },
    {
        "id": "ABAP-BKDR-006",
        "category": "Backdoor / Malicious Code",
        "name": "Programmatic grant of wide authorization profile",
        "severity": "CRITICAL",
        "pattern": r"'(?:SAP_ALL|SAP_NEW)'",
        "description": "The code references the all-powerful SAP_ALL/SAP_NEW profile as a literal, suggesting it may be assigned programmatically. Granting SAP_ALL from custom code gives an account unrestricted access and is a severe backdoor.",
        "cwe": "CWE-269",
        "recommendation": "Never assign SAP_ALL/SAP_NEW from code. Grant only the specific roles required, through PFCG, following least privilege.",
    },
    {
        "id": "ABAP-BKDR-007",
        "category": "Backdoor / Malicious Code",
        "name": "Hardcoded system-ID (SY-SYSID) check",
        "severity": "MEDIUM",
        "pattern": r"\bSY-SYSID\b\s*(?:=|<>|EQ|NE|CP)\s*'",
        "description": "Code branches on SY-SYSID compared to a hardcoded system ID, hiding behaviour that only triggers on a specific system (e.g. production) — a technique used to conceal malicious logic from test/QA systems (CVA check 11S2).",
        "cwe": "CWE-912",
        "recommendation": "Avoid system-specific hardcoded behaviour; derive any landscape-dependent logic from configuration (TVARVC / customizing), not a literal SID.",
    },
]

# UI5 / JavaScript rules (Fiori front-end and CAP Node.js apps).
ABAP_JS_RULES: list[dict] = [
    {
        "id": "ABAP-JS-001",
        "category": "UI5 / JavaScript",
        "name": "Use of eval()",
        "severity": "CRITICAL",
        "pattern": r"\beval\s*\(",
        "description": "eval() executes arbitrary JavaScript; attacker-controlled input leads to code injection / XSS in UI5/Fiori apps.",
        "cwe": "CWE-95",
        "recommendation": "Remove eval(); use JSON.parse for data and proper UI5 APIs for dynamic behaviour.",
    },
    {
        "id": "ABAP-JS-002",
        "category": "UI5 / JavaScript",
        "name": "Direct innerHTML assignment",
        "severity": "HIGH",
        "pattern": r"\.innerHTML\s*=",
        "description": "Assigning unescaped data to innerHTML is a DOM-based XSS sink.",
        "cwe": "CWE-79",
        "recommendation": "Use textContent or UI5 controls / encodeXML; never inject raw HTML from user input.",
    },
    {
        "id": "ABAP-JS-003",
        "category": "UI5 / JavaScript",
        "name": "document.write()",
        "severity": "HIGH",
        "pattern": r"document\.write\s*\(",
        "description": "document.write() with dynamic content is an XSS sink and breaks UI5 rendering.",
        "cwe": "CWE-79",
        "recommendation": "Use UI5 controls / DOM APIs with proper encoding instead of document.write().",
    },
    {
        "id": "ABAP-JS-004",
        "category": "UI5 / JavaScript",
        "name": "Hardcoded secret in JavaScript",
        "severity": "HIGH",
        "pattern": r"(?:api[_-]?key|secret|token|passwd|password)\s*[:=]\s*[\"'][^\"']{8,}[\"']",
        "description": "A credential / API key is hard-coded in client-side JavaScript, where it is fully exposed to end users.",
        "cwe": "CWE-798",
        "recommendation": "Never store secrets in front-end code; use a destination / BTP service binding and a backend proxy.",
    },
    {
        "id": "ABAP-JS-005",
        "category": "UI5 / JavaScript",
        "name": "Insecure HTTP URL",
        "severity": "MEDIUM",
        "pattern": r"[\"']http://",
        "description": "An http:// (cleartext) URL is used; data in transit is exposed to interception.",
        "cwe": "CWE-319",
        "recommendation": "Use https:// for all endpoints.",
    },
    {
        "id": "ABAP-JS-006",
        "category": "UI5 / JavaScript",
        "name": "jQuery .html() sink",
        "severity": "LOW",
        "pattern": r"\.html\s*\(\s*[^)]",
        "description": "jQuery .html(arg) writes raw HTML; with unescaped data this is a DOM XSS sink.",
        "cwe": "CWE-79",
        "recommendation": "Use .text() for data, or sanitise/encode before inserting HTML.",
    },
    {
        "id": "ABAP-JS-007",
        "category": "UI5 / JavaScript",
        "name": "Reverse tabnabbing (target=_blank without rel=noopener)",
        "severity": "LOW",
        "pattern": r"""target\s*=\s*["']_blank["'](?![^>]*\brel\s*=\s*["'][^"']*noopener)""",
        "description": "A link opens in a new tab via target=\"_blank\" without rel=\"noopener\"; the opened page can rewrite window.opener.location (reverse tabnabbing / phishing) (CVA check 11R1).",
        "cwe": "CWE-1022",
        "recommendation": "Add rel=\"noopener noreferrer\" to every target=\"_blank\" link.",
    },
]

ALL_ABAP_SAST_RULES: list[dict] = (
    ABAP_SQLI_RULES
    + ABAP_CINJ_RULES
    + ABAP_CMDI_RULES
    + ABAP_PATH_RULES
    + ABAP_XSS_RULES
    + ABAP_AUTH_RULES
    + ABAP_CRED_RULES
    + ABAP_CRYP_RULES
    + ABAP_INFO_RULES
    + ABAP_CONF_RULES
    + ABAP_RFC_RULES
    + ABAP_EXTRA_RULES
    + ABAP_BACKDOOR_RULES
)

ALL_BTP_CONFIG_RULES: list[dict] = ABAP_BTP_RULES
ALL_JS_RULES: list[dict] = ABAP_JS_RULES

# Fast id -> rule lookup (used by the taint analyzer to find _sink_arg).
_ABAP_RULES_BY_ID: dict[str, dict] = {r["id"]: r for r in ALL_ABAP_SAST_RULES}


# ─── vendored: taint analyzer ────────────────────────────────────────── #
_ABAP_NOISE_WORDS: frozenset = frozenset({
    "abap_true", "abap_false", "abap_undefined", "space", "sy", "is",
    "initial", "and", "or", "not", "in", "where", "from", "by", "having",
    "group", "order", "into", "to", "value", "boolc", "xsdbool",
})


class TaintAnalyzer:
    """Intra-procedural data-flow ("taint") analysis for ABAP source.

    A pragmatic, regex-driven approximation of what SAP's Code Vulnerability
    Analyzer does with the parse tree: track which variables carry external
    ("tainted") input versus which have been sanitized, so an injection finding
    can be **confirmed** (tainted input reaches the sink), **suppressed** (the
    sink argument is a literal/constant or has been sanitized), or left
    **tentative** (no evidence either way).

    Scope is one procedure block (FORM/METHOD/FUNCTION) or the report body.
    PARAMETERS / SELECT-OPTIONS are treated as globally tainted (classic Dynpro
    input). The walk is line-oriented and deliberately conservative: when unsure
    it returns UNKNOWN so the finding is kept (no new false negatives). Recognised
    sanitizers mirror CVA's (CL_ABAP_DYN_PRG methods, FILE_VALIDATE_NAME,
    allow-list checks, HTML escaping).
    """

    TAINTED = "tainted"
    SANITIZED = "sanitized"
    CLEAN = "clean"
    UNKNOWN = "unknown"

    _SOURCE_RE = re.compile(
        r"get_form_field|get_header_field|get_form_data|get_cdata|get_data\b"
        r"|->request->|server->request|get_user_command|gui_upload"
        r"|GET\s+PARAMETER\s+ID|cl_http_server",
        re.IGNORECASE,
    )
    _SANITIZER_RE = re.compile(
        r"cl_abap_dyn_prg=>|file_validate_name|escape_quotes"
        r"|cl_http_utility=>escape|check_whitelist|check_char_literal"
        r"|check_column_name|check_table_name|check_int_value|check_variable_name",
        re.IGNORECASE,
    )
    _SCOPE_START_RE = re.compile(r"^\s*(?:FORM|METHOD|FUNCTION)\b", re.IGNORECASE)
    _SCOPE_END_RE = re.compile(r"^\s*END(?:FORM|METHOD|FUNCTION)\b", re.IGNORECASE)
    _PARAM_RE = re.compile(
        r"^\s*(?:PARAMETERS?|SELECT-OPTIONS)\s*:?\s*([\w/]+)", re.IGNORECASE)
    _IDENT_RE = re.compile(r"[A-Za-z_]\w*")
    _LITERAL_RE = re.compile(r"^(?:'[^']*'|`[^`]*`|[0-9]+)$")

    def __init__(self, text: str):
        self._raw = text.splitlines()
        self._code: list[str] = []
        for line in self._raw:                 # comment-stripped, line-aligned
            if line.lstrip().startswith("*"):
                self._code.append("")
            else:
                self._code.append(line.split('"', 1)[0] if '"' in line else line)
        self._globals = self._collect_globals()   # var -> declaration line (1-based)
        self._scopes = self._segment_scopes()

    def _raw_line(self, line_no: int) -> str:
        idx = line_no - 1
        return self._raw[idx].strip() if 0 <= idx < len(self._raw) else ""

    def _collect_globals(self) -> dict:
        g: dict = {}
        depth = 0
        for i, c in enumerate(self._code):
            if self._SCOPE_START_RE.search(c):
                depth += 1
            elif self._SCOPE_END_RE.search(c):
                depth = max(0, depth - 1)
            elif depth == 0:
                m = self._PARAM_RE.match(c)
                if m:
                    g[m.group(1).lower()] = i + 1
        return g

    def _segment_scopes(self) -> list:
        scopes, stack = [], []
        for i, c in enumerate(self._code):
            if self._SCOPE_START_RE.search(c):
                stack.append(i)
            elif self._SCOPE_END_RE.search(c) and stack:
                scopes.append((stack.pop(), i))
        return scopes

    def _scope_start(self, line_no: int) -> int:
        idx, best = line_no - 1, None
        for (s, e) in self._scopes:
            if s <= idx <= e and (best is None or s > best):
                best = s
        return best if best is not None else 0

    def _walk(self, line_no: int) -> tuple[dict, dict]:
        """Return (state, origin) for the scope containing ``line_no``, walked
        up to (but not including) that line. ``origin[var] = (line, pred)`` records
        where a tainted var got its taint (pred = predecessor var, or None = a
        source/declaration)."""
        start = self._scope_start(line_no)
        state: dict = {}
        origin: dict = {}
        for idx in range(start, min(line_no - 1, len(self._code))):
            self._apply(self._code[idx], state, origin, idx + 1)
        return state, origin

    def state_of(self, var: str, line_no: int) -> str:
        """Taint state of ``var`` immediately before 1-based ``line_no``."""
        var = var.lower()
        state, _ = self._walk(line_no)
        if var in state:
            return state[var]
        return self.TAINTED if var in self._globals else self.UNKNOWN

    def _set(self, tgt: str, st: str, pred, line_no: int,
             state: dict, origin: dict) -> None:
        state[tgt] = st
        if st == self.TAINTED:
            origin[tgt] = (line_no, pred)
        else:
            origin.pop(tgt, None)

    def _first_tainted(self, expr: str, state: dict):
        for i in self._IDENT_RE.findall(expr):
            il = i.lower()
            if il in _ABAP_NOISE_WORDS:
                continue
            if state.get(il) == self.TAINTED or il in self._globals:
                return il
        return None

    def _apply(self, code: str, state: dict, origin: dict, line_no: int) -> None:
        m = re.search(r"GET\s+PARAMETER\s+ID\s+\S+\s+FIELD\s+([\w/]+)",
                      code, re.IGNORECASE)
        if m:
            self._set(m.group(1).lower(), self.TAINTED, None, line_no, state, origin)
            return
        m = re.search(r"\bCONCATENATE\b(.+?)\bINTO\b\s+([\w/]+)", code, re.IGNORECASE)
        if m:
            st = self._combine(m.group(1), state)
            pred = self._first_tainted(m.group(1), state) if st == self.TAINTED else None
            self._set(m.group(2).lower(), st, pred, line_no, state, origin)
            return
        m = re.match(r"\s*MOVE\s+(.+?)\s+TO\s+([\w/]+)", code, re.IGNORECASE)
        if m:
            self._assign(m.group(2).lower(), m.group(1), line_no, state, origin)
            return
        m = re.match(r"\s*([\w/]+)\s*=\s*(.+?)\.?\s*$", code)
        if m and not re.search(r"[=<>]=|<>", code):
            self._assign(m.group(1).lower(), m.group(2), line_no, state, origin)

    def _assign(self, tgt: str, rhs: str, line_no: int,
                state: dict, origin: dict) -> None:
        st = self._classify(rhs, state)
        pred = None
        if st == self.TAINTED and not self._SOURCE_RE.search(rhs):
            pred = self._first_tainted(rhs, state)
        self._set(tgt, st, pred, line_no, state, origin)

    def _classify(self, rhs: str, state: dict) -> str:
        rhs = rhs.strip()
        if self._SANITIZER_RE.search(rhs):
            return self.SANITIZED
        if self._SOURCE_RE.search(rhs):
            return self.TAINTED
        if self._LITERAL_RE.match(rhs):
            return self.CLEAN
        return self._combine(rhs, state)

    def _combine(self, expr: str, state: dict) -> str:
        if self._SANITIZER_RE.search(expr):
            return self.SANITIZED
        if self._SOURCE_RE.search(expr):
            return self.TAINTED
        idents = [i for i in self._IDENT_RE.findall(expr)
                  if i.lower() not in _ABAP_NOISE_WORDS]
        if not idents:
            has_lit = "'" in expr or "`" in expr or any(ch.isdigit() for ch in expr)
            return self.CLEAN if has_lit else self.UNKNOWN
        states = [state.get(i.lower(),
                            self.TAINTED if i.lower() in self._globals else self.UNKNOWN)
                  for i in idents]
        if self.TAINTED in states:
            return self.TAINTED
        if all(s == self.CLEAN for s in states):
            return self.CLEAN
        if all(s in (self.CLEAN, self.SANITIZED) for s in states):
            return self.SANITIZED
        return self.UNKNOWN

    def classify_sink(self, arg_expr: str, line_no: int) -> str:
        """Verdict for a sink's dynamic argument expression at ``line_no``."""
        arg = (arg_expr or "").strip()
        if not arg:
            return self.CLEAN                      # nothing dynamic captured
        if self._SANITIZER_RE.search(arg):
            return self.SANITIZED
        if self._LITERAL_RE.match(arg) or arg[:1] in ("'", "`"):
            return self.CLEAN                      # literal table/condition
        idents = [i for i in self._IDENT_RE.findall(arg)
                  if i.lower() not in _ABAP_NOISE_WORDS]
        if not idents:
            return self.CLEAN
        states = [self.state_of(i, line_no) for i in idents]
        if self.TAINTED in states:
            return self.TAINTED
        if all(s == self.SANITIZED for s in states):
            return self.SANITIZED
        if all(s == self.CLEAN for s in states):
            return self.CLEAN
        return self.UNKNOWN

    def _trace_var(self, var: str, line_no: int) -> list:
        """Ordered data-flow steps for a tainted ``var`` reaching ``line_no``:
        source first, propagations next, sink last. Each step is a dict
        {line, role, var, code}."""
        _, origin = self._walk(line_no)
        chain: list = []
        cur, seen = var.lower(), set()
        while cur and cur not in seen:
            seen.add(cur)
            if cur in origin:
                ln, pred = origin[cur]
                chain.append({"line": ln, "role": "source" if pred is None else "propagation",
                              "var": cur, "code": self._raw_line(ln)})
                cur = pred
            elif cur in self._globals:
                ln = self._globals[cur]
                chain.append({"line": ln, "role": "source", "var": cur,
                              "code": self._raw_line(ln)})
                cur = None
            else:
                break
        chain.reverse()                                    # source -> ... order
        chain.append({"line": line_no, "role": "sink", "var": var.lower(),
                      "code": self._raw_line(line_no)})
        # collapse a source/sink that landed on the same line
        out: list = []
        for step in chain:
            if out and out[-1]["line"] == step["line"] and out[-1]["role"] != "sink":
                out[-1] = step
            else:
                out.append(step)
        return out

    def sink_trace(self, arg_expr: str, line_no: int) -> list | None:
        """Data-flow trace for the first tainted identifier in a sink argument,
        or None if the argument is not tainted."""
        for i in self._IDENT_RE.findall(arg_expr or ""):
            if i.lower() in _ABAP_NOISE_WORDS:
                continue
            if self.state_of(i, line_no) == self.TAINTED:
                return self._trace_var(i, line_no)
        return None


