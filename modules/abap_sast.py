# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
ABAP / UI5 source scanning
==========================
Our own code scanner, for customers who do not have SAP's Code Vulnerability
Analyzer. Where they do, ``modules/atc_import.py`` ingests SAP's own results and
should be preferred — those findings cost nothing and carry no false positives of
our making.

Input is an **abapGit offline ZIP export** unpacked to a directory: the one route
by which ABAP source leaves a RISE PCE system with no OS access, no outbound
network and no SAP ticket.

────────────────────────────────────────────────────────────────────────────────
WHY THIS FILE EXISTS RATHER THAN THE UPSTREAM SCANNER
────────────────────────────────────────────────────────────────────────────────
The rule corpus came across intact (``modules/abap_sast_rules.py``). The scanning
core did not, because the upstream one analysed **one line of text at a time** and
ABAP statements are not lines — they end at a period and routinely span four or
five lines. Measured on the upstream engine, that single decision produced both
failure modes at once:

    " one line  ->  CRITICAL, data-flow confirmed
    SELECT * FROM mara WHERE (lv_where) INTO TABLE @DATA(lt).

    " the same statement, formatted the way real ABAP is written  ->  NOTHING
    SELECT *
      FROM mara
      WHERE (lv_where)
      INTO TABLE @DATA(lt).

and, in the other direction, 50 lines of secure idiomatic ABAP produced three
HIGH findings — two "DES encryption" hits caused by the letters ``des`` inside
``lv_modes`` and ``lt_codes``, in a file containing no cryptography at all.

So this module keeps the patterns and changes the unit they are matched against:

1. **Statements, not lines.** Comments are stripped, string literals are respected,
   and the text is split on statement-terminating periods. A rule now sees the
   whole statement regardless of how it was wrapped.
2. **Word boundaries.** ``PATTERN_FIXES`` repairs rules whose regex was anchored on
   only one side, which is what let ``des`` match inside an identifier.
3. **Block-scoped guards.** Five rules are named "... without AUTHORITY-CHECK" but
   only one carried the metadata to check for one. All five now look at the
   enclosing FORM / METHOD / FUNCTION before firing.

None of this makes the analysis interprocedural. It is statement-pattern matching
with optional intra-procedural taint refinement, and that is what it should be
called in front of a customer — the competitors ship global data-flow analysis and
this does not.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from modules.abap_sast_extra import (
    CDS_RULES, DEFAULT_SANITIZERS, EXTRA_ABAP_RULES, SINK_SANITIZERS,
)
from modules.abap_sast_rules import (
    ALL_ABAP_SAST_RULES as _VENDORED_ABAP_RULES,
    ALL_BTP_CONFIG_RULES,
    ALL_JS_RULES,
    TaintAnalyzer,
    _ABAP_NOISE_WORDS,
)
from modules.base_auditor import BaseAuditor
from modules.cds_authorization_index import (CROSS_ARTIFACT_RULES,
                                             CdsAuthorizationIndex,
                                             cross_artifact_findings)
from modules.reachability import ReachabilityIndex, stamp

#: The vendored corpus plus our own. Kept in separate modules because
#: `tools/build_abap_rules.py` regenerates the vendored one verbatim from the
#: upstream repository — anything added there would be destroyed on the next
#: refresh, silently and with no test failing.
ALL_ABAP_SAST_RULES = _VENDORED_ABAP_RULES + EXTRA_ABAP_RULES

#: For rules the engine emits itself rather than through the generic pattern loop,
#: so their severity, CWE and customer-facing text stay vendored.
_RULES_BY_ID: Dict[str, Dict[str, Any]] = {r["id"]: r for r in ALL_ABAP_SAST_RULES}

# --------------------------------------------------------------------------- #
#  What an abapGit export actually contains                                   #
# --------------------------------------------------------------------------- #

#: Source we analyse. The upstream set stopped at `.ddls.abap`/`.dcls.abap`, which
#: abapGit does not produce — it writes `.asddls` and `.asdcls`, so CDS coverage
#: was silently zero on every real export.
ABAP_SUFFIXES: Tuple[str, ...] = (".abap", ".abp", ".aclrl")

#: CDS / DCL / RAP artefacts. A DIFFERENT LANGUAGE, and it must not be parsed as
#: ABAP or matched with ABAP rules. Two things went wrong when it was, both caught
#: by the requirement that a secure fixture produce zero findings:
#:
#:   * `@AccessControl.authorizationCheck` was chopped in half, because ABAP ends a
#:     statement at a period and CDS does not — so no annotation rule could ever
#:     match one, and CDS coverage was zero while appearing to work.
#:   * ABAP's dynamic-WHERE rule fired on a DCL grant's
#:     `where ( lifnr ) = aspect pfcg_auth (...)`, reporting SQL injection in a
#:     correctly written access-control role.
CDS_SUFFIXES: Tuple[str, ...] = (
    ".asddls",          # CDS data definition
    ".asdcls",          # CDS access control (DCL)
    ".asbdef",          # RAP behaviour definition
    ".ddls.abap",       # older ADT export naming
    ".dcls.abap",
    ".cds",
)
JS_SUFFIXES: Tuple[str, ...] = (".js", ".ts", ".xml.js")
DESCRIPTOR_NAMES: Tuple[str, ...] = (
    "xs-security.json", "xs-app.json", "mta.yaml", "mta.yml", "manifest.json",
)

#: abapGit writes one XML sidecar per object carrying its metadata. They are not
#: source and are deliberately not scanned — but they ARE counted, because
#: "skipped silently" and "nothing to scan" look identical in a report and only one
#: of them is true.
METADATA_SUFFIXES: Tuple[str, ...] = (".xml",)

#: Rules whose regex was anchored on one side only, so it matched inside an
#: identifier. Keyed by rule id; the value replaces `pattern`.
#:
#: Fixed here rather than in the vendored corpus so that re-deriving the corpus
#: from the upstream repository cannot silently undo the fix.
#: A quote character in any of ABAP's three spellings.
_Q = r"['\"`]"

#: ONE dynamic name or ONE literal. Bounding the parenthesis to this is what
#: separates a dynamic clause from ordinary logical grouping — `[^)]*` cannot.
_DYN_NAME = r"(?:`[^`]*`|'[^']*'|[A-Za-z_]\w*(?:->\w+|-\w+)*)"

#: Namespace authorities whose `http://` URIs are IDENTIFIERS, NOT ENDPOINTS.
#: Every object that serialises XML or SOAP carries several, and reporting them
#: as insecure protocol use (F5) flagged SAP's own asXML namespace.
#:
#: U12, settled — by relabelling rather than by research, because the question
#: was never "is this list right" but "whose list is it". Checking that turned up
#: a claim that was too strong: the previous comment said "the W3C and SAP
#: entries are confirmed from SAP-authored material", and only ONE of them is.
#: `http://www.sap.com/abapxml` appears in SAP's own XML cheat sheet; `w3.org`
#: and `xml.sap.com` were carrying a "verified" marker they had not earned.
#:
#: Nothing was removed, because nothing is wrong. The W3C and SOAP hosts really
#: are namespace authorities and dropping them would resurrect exactly the false
#: positives F5 fixed. What changes is that the two classes are now DATA rather
#: than a comment, so a host added later has to declare which it is — and an
#: entry claiming SAP's authority has to name the file.
_NAMESPACE_HOSTS_VERIFIED: Dict[str, str] = {
    "www.sap.com":
        "http://www.sap.com/abapxml, SAP's asXML namespace — "
        "SAP-samples/abap-cheat-sheets 21_XML_JSON.md",
}

#: OURS. A maintained allowlist and not a claim about SAP: each entry is a
#: judgement, and the reason is the judgement. If one of these turns out to be
#: wrong, it is this project's error to correct and not SAP's to explain.
_NAMESPACE_HOSTS_OURS: Dict[str, str] = {
    "sap.com":
        "the bare host, so SAP namespaces served from subdomains other than "
        "www are covered without listing each one",
    "xml.sap.com":
        "an SAP host in namespace position; not found in any file fetched for "
        "this project, so it is kept on judgement rather than evidence",
    "www.w3.org":
        "the XML Schema, XSL and XML Signature namespaces live here. Any object "
        "doing schema-aware serialisation carries at least one",
    "w3.org":
        "the same authority written without the www prefix",
    "schemas.xmlsoap.org":
        "the SOAP 1.1 envelope and WSDL namespaces. Every classic SOAP consumer "
        "or provider carries them",
    "schemas.microsoft.com":
        "carried by Office Open XML and by OData payloads that pass through "
        "ABAP; an identifier in every case",
}

#: The order is verified-then-ours so a reader of the compiled pattern meets the
#: attested entries first. Behaviour does not depend on it.
_NAMESPACE_HOSTS: Tuple[str, ...] = (tuple(_NAMESPACE_HOSTS_VERIFIED)
                                     + tuple(_NAMESPACE_HOSTS_OURS))

#: U5, settled, and the rule was matching nothing.
#:
#: `ABAP-CDS-002` shipped as `GRANT SELECT ON \w+ WHERE TRUE`. SAP's keyword
#: documentation gives the full-access rule as `GRANT SELECT ON cds_entity
#: [ REDEFINITION ] ;` and says it in words: "A full access rule GRANT SELECT ON
#: WITHOUT THE ADDITION WHERE provides access to a CDS entity cds_entity without
#: conditions." DCL has no `WHERE TRUE`. The rule could never fire, and a
#: HIGH/CWE-863 rule that cannot fire is worse than an absent one — it makes a
#: clean result look like evidence.
#:
#: The real construct is the ABSENCE of the WHERE, so the pattern matches a
#: grant that ends at its terminator. `REDEFINITION` is allowed between, because
#: SAP's syntax permits it and it does not add a condition. This also matters
#: more than it looks: SAP notes that it "does not as a rule supply any CDS roles
#: with full access rules. Partners and customers can use full access rules to
#: override roles supplied by SAP" — so a full-access rule in customer DCL is
#: frequently an override of an SAP-delivered restriction.
#: Anchored at the END OF THE STATEMENT, not on a `;`. The CDS/DCL splitter
#: divides on the terminator and discards it, so by the time a rule sees the
#: text there is no `;` left to match — and "the statement ends after the
#: entity" is exactly what "without the addition WHERE" means once the source
#: has been split into statements.
_DCL_FULL_ACCESS = r"\bGRANT\s+SELECT\s+ON\s+[\w./]+\s*(?:REDEFINITION\s*)?$"

PATTERN_FIXES: Dict[str, str] = {
    "ABAP-CDS-002": _DCL_FULL_ACCESS,
    # `(?:DES|3DES|TRIPLE.?DES)\b` has no LEADING boundary, so the `des` in
    # `lv_modes` and `lt_codes` matched and reported HIGH "DES encryption".
    "ABAP-CRYP-003": r"\b(?:3DES|TRIPLE.?DES|DES)\b",

    # F1. `(?:CONCATENATE|&&).*(?:WHERE|INTO|FROM)\b` matched EVERY CONCATENATE in
    # the estate at CRITICAL, because `INTO` is mandatory syntax — and the `&&` arm
    # matched the English word "from", so `|Deleted { n } rows from the buffer|`
    # was reported as SQL injection. The danger is an SQL keyword inside a LITERAL
    # being concatenated, which is what this now says.
    "ABAP-SQLI-002":
        r"(?:\bCONCATENATE\b|&&)[^.]*" + _Q +
        r"\s*(?:WHERE|AND|OR|ORDER\s+BY|GROUP\s+BY|HAVING|FROM)\b",

    # F2. `\bWHERE\s*\(` cannot tell a dynamic clause from logical grouping, so
    # `WHERE ( comp1 = 'X' AND comp2 > 100 )` — idiomatic, static, safe — reported
    # CRITICAL. Bounded to one name or one literal, exactly as ABAP-SQLI-011
    # already does for FROM. Both documented dynamic forms are a single bare name,
    # so they still match; grouping, tuples and value lists drop out.
    "ABAP-SQLI-001":
        r"\b(?:SELECT|UPDATE|DELETE|MODIFY)\b.*?\bWHERE\s*\(\s*" + _DYN_NAME + r"\s*\)",

    # F3. INVERTED. `CALL\s+TRANSFORMATION\s+(?!')[a-zA-Z_]\w*` assumed "static
    # means quoted", which holds for CALL FUNCTION and CALL TRANSACTION and is
    # exactly backwards here: a static transformation is named bare, a dynamic one
    # is parenthesised. It fired CRITICAL on `CALL TRANSFORMATION id` and was
    # silent on `CALL TRANSFORMATION (lv_dyn)`.
    "ABAP-CINJ-007": r"\bCALL\s+TRANSFORMATION\s*\(",

    # F6. Unanchored, and the addition-exclusion list is incomplete: a report name
    # ending in `submit` made the statement match on its own identifier, and
    # `SUBMIT zdemo_report LINE-SIZE 132` fired while `SUBMIT zdemo_report` did
    # not. The bare-identifier arm never detected anything real in any case —
    # a variable program name REQUIRES the parentheses, so a bare name after
    # SUBMIT is always a literal report name.
    "ABAP-CINJ-005": r"^\s*SUBMIT\s+\(",

    # F7. Fired on correct code: a partial DUMMY exempts ONE field and the
    # remaining pairs are still enforced. Only a check with no FIELD pair at all
    # is the "checks nothing" case the rule is named for.
    "ABAP-AUTH-002": r"^AUTHORITY-CHECK\s+OBJECT\b(?!.*\bFIELD\b).*\bDUMMY\b",

    # F5. Every object that serialises XML or SOAP carries several `http://`
    # namespace URIs. They are identifiers, not endpoints — including SAP's own
    # asXML namespace, which we were reporting as an insecure protocol. The hosts
    # come from `_NAMESPACE_HOSTS_VERIFIED` and `_NAMESPACE_HOSTS_OURS`; see U12
    # there for which is which and why the distinction is kept in data.
    "ABAP-CONF-002":
        _Q + r"http://(?!(?:" + "|".join(h.replace(".", r"\.")
                                         for h in _NAMESPACE_HOSTS) + r")\b)"
        r"[^'\"`]+" + _Q,

    # F10. A FALSE NEGATIVE of the same regex-shape family: the pattern requires
    # whitespace straight after `ACTVT`, but the form real code uses has a closing
    # apostrophe there. So it was silent on `ID 'ACTVT' FIELD '*'` — a wildcard
    # activity check — while matching only a spelling nobody writes.
    "ABAP-CONF-005":
        r"AUTHORITY-CHECK\b[^.]*\bACTVT\b\W{0,3}FIELD\s+" + _Q + r"\*" + _Q,
}

#: `PATTERN_FIXES` cannot reach a rule's customer-facing text, and one rule's text
#: asserts something the source contradicts.
DESCRIPTION_FIXES: Dict[str, str] = {
    "ABAP-CDS-002":
        "A DCL access rule grants unrestricted access to a CDS entity. SAP's "
        "full access rule is `GRANT SELECT ON <entity>;` with no WHERE "
        "addition, and it has the same effect as having no role at all: "
        "authorization control for that entity is switched off. SAP states it "
        "does not as a rule supply CDS roles with full access rules, so one in "
        "customer DCL is often an override of an SAP-delivered restriction "
        "rather than a gap — confirm it was intended, and that the entity it "
        "opens is not one carrying personal or financial data.",
    "ABAP-AUTH-002": (
        "This AUTHORITY-CHECK specifies DUMMY for every field, so no field value "
        "is actually compared and the statement checks only that the authorization "
        "object is assigned at all. Note that DUMMY on SOME fields is legitimate "
        "and is not this finding: it exempts those fields while the remaining "
        "ID/FIELD pairs are still enforced, and the check can still fail."),
}

#: Severity corrections. Separate from `PATTERN_FIXES` for the same reason: the
#: vendored corpus is regenerated verbatim.
SEVERITY_FIXES: Dict[str, str] = {
    # No longer "the check is disabled" — it is "no field value is compared",
    # which is worth reporting and is not a CRITICAL-adjacent finding.
    "ABAP-AUTH-002": "MEDIUM",
}

#: Rules withdrawn rather than narrowed. F9: `cl_http_utility=>(?!escape_html)\w+`
#: excludes exactly one method name, so every OTHER use of a general HTTP utility
#: class is reported as missing HTML escaping. ABAP-XSS-001/002/003/005 cover the
#: real output sinks.
#:
#: U4 IS NOW SETTLED, AND THE RETIREMENT IS PERMANENT RATHER THAN PENDING.
#: `CL_HTTP_UTILITY` does not appear in SAP's released-classes listing at all, so
#: it is not a released API — and its ABAP Cloud counterpart `CL_WEB_HTTP_UTILITY`
#: is described there as "Encoding strings/xstrings in Base64 and decoding
#: Base64-encoded strings/xstrings", exposing `encode_base64`, `decode_base64`,
#: `encode_x_base64` and `decode_x_base64`. It has no HTML-escaping method at all.
#:
#: That undermines the rule's premise rather than its precision. It assumed that
#: using this class family without one particular method means HTML escaping was
#: skipped; the successor class does not escape anything, so its use says nothing
#: either way. Narrowing was never going to fix a rule aimed at the wrong idea.
#:
#: What the listing does NOT establish, and this matters: it covers released ABAP
#: Cloud APIs, so `CL_HTTP_UTILITY`'s absence proves it is unreleased, NOT that
#: the classic class lacks `escape_html`. Its method list is still unread, which
#: is why nothing here narrows the rule instead of retiring it.
RETIRED_RULES: Tuple[str, ...] = ("ABAP-XSS-006",)

#: F4. Rules that fire on a dynamically-named token. SAP writes a LITERAL operand
#: as the normal safe form — measured over ~525 KB of SAP-authored ABAP, the ASSIGN
#: rule fired 11 times and 10 were hard-coded literals or integers.
#:
#: The finding is KEPT: a literal class or report name is a genuine inventory
#: entry. It is just not a HIGH one, and saying so is the difference between an
#: inventory and a false positive.
DYNAMIC_TOKEN_RULES: Tuple[str, ...] = (
    "ABAP-CINJ-005", "ABAP-CINJ-006", "ABAP-CINJ-009", "ABAP-CINJ-012",
    "ABAP-SQLI-010", "ABAP-SQLI-011", "ABAP-SQLI-012",
)

_LITERAL_OPERAND = re.compile(r"\(\s*" + _Q)

#: A10. `DELETE itab WHERE (cond)` touches no database, but it was the one
#: internal-table dynamic form that DID match a rule — and it was reported CRITICAL,
#: CWE-89, "Dynamic WHERE clause", with a host-variable recommendation there is no
#: statement to bind against. `ABAP-DYNT-001` reports it as what it actually is.
_INTERNAL_TABLE_DELETE = re.compile(
    r"^\s*DELETE\s+(?!FROM\b)[\w<>/-]+\s", re.IGNORECASE)

#: Rules named "... without AUTHORITY-CHECK" whose pattern cannot express the
#: "without" half. Only ABAP-AUTH-001 shipped with the metadata to check; the other
#: five fired on every UPDATE/DELETE/INSERT/RFC/transaction call in the estate,
#: guarded or not.
AUTHORITY_GUARDED: Tuple[str, ...] = (
    "ABAP-AUTH-001", "ABAP-AUTH-004", "ABAP-AUTH-005",
    "ABAP-AUTH-006", "ABAP-AUTH-007",
    # Literally named "... without S_TCODE check" and fired on correctly guarded
    # code because it was never in this table.
    "ABAP-AUTH-008",
)

#: Rules the generic pattern loop must NOT emit, because the engine emits them
#: itself with evidence a single-statement regex cannot express.
RULE_HANDLED_IN_ENGINE: Tuple[str, ...] = (
    # Its pattern needs a literal `.` that `split_statements` strips, plus a
    # lookahead at the NEXT statement. It could only ever fire when a period
    # appeared inside a literal — dead in general, and a guaranteed false
    # positive in the one case that reached it.
    "ABAP-AUTH-003",
)

#: Rules matched against `Statement.text_masked` — literal and template CONTENT
#: blanked — because for these the danger is a keyword appearing as *code*, and a
#: developer writing the same keyword in a message or a comment-like literal is
#: not a finding. Measured, both directions were live:
#:
#:   * `MESSAGE |Never use EXEC SQL in this program| TYPE 'I'.` raised NSQL-001.
#:   * A FORM with an unguarded DELETE + UPDATE reported AUTH-005/-006; adding only
#:     `MESSAGE |Remember to AUTHORITY-CHECK before delete| TYPE 'I'.` silenced
#:     both — a developer's TODO about missing authorization suppressed the finding
#:     about missing authorization.
#:
#: Deliberately NOT global: rules that key on a literal's VALUE (hardcoded
#: credentials, `ABAP-SSRF-001`'s URL, `ABAP-CONF-002`) need the content.
LITERAL_BLIND: frozenset = frozenset({
    "ABAP-NSQL-001", "ABAP-CINJ-004", "ABAP-AMDP-001", *AUTHORITY_GUARDED,
})

#: A guard is a STATEMENT, never a message text. Anchored, and it requires the
#: `FIELD` half: `AUTHORITY-CHECK OBJECT` with no field pair checks nothing.
#: `[-\s]?` also admitted `AUTHORITY CHECK` and `AUTHORITYCHECK`, neither of which
#: is the documented spelling.
_AUTHORITY_CHECK_STMT = re.compile(
    r"^AUTHORITY-CHECK\s+OBJECT\b(?=.*\bFIELD\b)", re.IGNORECASE)

#: U6, settled. SAP's syntax is
#: `AUTHORITY-CHECK OBJECT auth_obj [FOR USER user] ID id1 {FIELD val1}|DUMMY`,
#: and of the addition SAP says: "If the addition FOR USER is specified, the
#: authorization of the user is checked whose user name is specified in user."
#:
#: That is a different question from the one every AUTHORITY_GUARDED rule asks.
#: Those rules report an operation performed WITHOUT checking whether THIS user
#: may perform it; a check aimed at somebody else answers nothing about the
#: caller, and crediting it silenced the finding. It is the shape a user-admin
#: or workflow-substitution report legitimately uses — so the construct is not
#: wrong, it is simply not a guard for the current user, and this is a
#: false-negative fix rather than a new finding.
_AUTHORITY_FOR_OTHER_USER = re.compile(
    r"^AUTHORITY-CHECK\s+OBJECT\b[^.]*?\bFOR\s+USER\b", re.IGNORECASE)

#: U6's second half: every `sy-subrc` AUTHORITY-CHECK sets, from SAP's keyword
#: documentation. The plan recorded only 0, 4 and 12 as documented.
#:
#: 40 arises ONLY with the FOR USER addition, which is why the two halves of U6
#: were always one question. And 0 is the value worth reading twice — it means
#: success OR THAT NO CHECK WAS CARRIED OUT, so `sy-subrc = 0` after an
#: AUTHORITY-CHECK is not by itself proof that an authorization was tested.
#: `_subrc_evaluated` therefore asks only whether the result is READ, and
#: deliberately does not try to infer which branch means authorised.
AUTHORITY_CHECK_SUBRC: Dict[int, str] = {
    0: "authorization successful, or no check was carried out",
    4: "authorization check not successful — authorizations exist for the "
       "object but not for the values specified",
    12: "no authorization was found for the object in the user master record",
    40: "an invalid user ID was specified in user (FOR USER only)",
}
#: Documented as no longer set. Kept so nobody re-derives it from an old system.
AUTHORITY_CHECK_SUBRC_OBSOLETE: Tuple[int, ...] = (24,)

#: An AUTHORITY-CHECK whose result is never read is a no-op that the old guard
#: credited in full.
_SUBRC = re.compile(r"\bSY-SUBRC\b", re.IGNORECASE)
_CONTROL_FLOW = re.compile(r"^(?:IF|CASE|CHECK|ELSEIF|ASSERT)\b", re.IGNORECASE)

#: Statements that open and close a processing block. A guard inside one FORM does
#: not protect a sink in the next one.
_BLOCK_OPEN = re.compile(
    r"^\s*(?:FORM|METHOD|FUNCTION|MODULE)\b", re.IGNORECASE)
_BLOCK_CLOSE = re.compile(
    r"^\s*(?:ENDFORM|ENDMETHOD|ENDFUNCTION|ENDMODULE)\b", re.IGNORECASE)

_NOSEC = re.compile(r"#NOSEC(?P<ids>(?:\s+[A-Z0-9][A-Z0-9\-]*,?)*)", re.IGNORECASE)

#: An AMDP method body is SQLScript, not ABAP, and the two disagree about `"`,
#: `--` and the statement terminator. Entered on the method header, left on a RAW
#: `ENDMETHOD` line — a SQLScript body contains no ABAP period, so it emits no
#: statement the loop could react to.
_AMDP_OPEN = re.compile(r"\bBY\s+DATABASE\s+(?:PROCEDURE|FUNCTION)\b", re.IGNORECASE)
_AMDP_CLOSE = re.compile(r"^\s*ENDMETHOD\b", re.IGNORECASE)

#: A statement spanning more than this many source lines means the lexer lost its
#: place. The module's own motivating example is a four-line SELECT.
_RUNAWAY_LINES = 50


class Statement:
    """One ABAP statement, with the source it came from."""

    __slots__ = ("text", "line", "raw", "block", "nosec", "text_masked", "degraded")

    def __init__(self, text: str, line: int, raw: str, block: int,
                 nosec: Optional[List[str]], text_masked: Optional[str] = None,
                 degraded: bool = False):
        #: Comments stripped, newlines collapsed — what the rules match against.
        self.text = text
        #: 1-based line where the statement STARTS. Display only; never identity.
        self.line = line
        #: The statement as written, for the report snippet.
        self.raw = raw
        #: Index of the enclosing processing block, for block-scoped guards.
        self.block = block
        #: Rule ids suppressed by a `#NOSEC` marker, or [] for "all rules".
        self.nosec = nosec
        #: `text` with the CONTENT of literals and of string-template text blanked
        #: to `#`, delimiters and offsets preserved. What `LITERAL_BLIND` rules and
        #: the AUTHORITY-CHECK guard match against, so that prose in a message
        #: cannot invent a finding or silence one. Embedded `{ }` expressions are
        #: code and are NOT blanked.
        self.text_masked = text if text_masked is None else text_masked
        #: True when the runaway guard flushed this — the lexer lost its place and
        #: everything matched here is suspect. Counted, never silent.
        self.degraded = degraded


def split_statements(source: str) -> List[Statement]:
    """Split ABAP source into statements.

    ABAP terminates a statement with a period, and the whole difficulty is the
    places a period does not terminate anything: inside a text literal, inside a
    string template, inside a template's embedded `{ }` expression, inside a
    comment, and between two digits.

    WHY ONE MODE STACK RATHER THAN TWO SCANNERS
    There used to be two hand-written scanners over this grammar — one stripping
    comments per raw line, one re-deriving literal state from the joined buffer —
    and they disagreed about whether literal state survives a newline. Neither
    modelled `{ }`, so a template embedding an expression that contains its own
    literal with a pipe in it, e.g.

        DATA(msg) = |Result: { replace( val = t pcre = `a|b` with = `#` ) }|.

    closed the template early, opened a literal that never closed, and collapsed
    **the entire remainder of the file into one statement** — swallowing every
    ENDMETHOD, so a guard in one method was credited to a sink in another. One
    literal pipe turned a whole object into a clean report.

    `_scan_line` is now the single authority. It returns three parallel strings —
    code, mask, terminator markers — that are joined and normalised in lockstep, so
    "is this period a terminator" is answered once, where the state lives, instead
    of being re-derived downstream.
    """
    statements: List[Statement] = []
    buf_c: List[str] = []
    buf_m: List[str] = []
    buf_t: List[str] = []
    raw: List[str] = []
    start_line = 1
    block = 0
    pending_nosec: List[str] = []
    have_nosec = False
    stack: List[Tuple[str, str]] = []

    def emit(text: str, masked: str, degraded: bool = False) -> None:
        nonlocal block
        if not text:
            return
        if _BLOCK_OPEN.match(text):
            block += 1
        statements.append(Statement(
            text, start_line, "\n".join(raw).strip(), block,
            pending_nosec if have_nosec else None, masked, degraded))
        if _BLOCK_CLOSE.match(text):
            block += 1

    for lineno, line in enumerate(source.splitlines(), start=1):
        if not buf_c:
            start_line = lineno

        marker = _NOSEC.search(line)
        if marker:
            ids = [i.strip().rstrip(",").upper()
                   for i in marker.group("ids").split() if i.strip()]
            pending_nosec, have_nosec = ids, True

        # An AMDP body ends at a raw ENDMETHOD. It cannot end at a statement,
        # because SQLScript terminates on `;` and emits no ABAP statement here.
        if _in_amdp(stack) and _AMDP_CLOSE.match(line):
            while _in_amdp(stack):
                stack.pop()

        code, mask, term, stack = _scan_line(line, stack)
        raw.append(line)

        if not code.strip():
            if not "".join(buf_c).strip():
                buf_c, buf_m, buf_t, raw = [], [], [], []
            continue

        buf_c.append(code + " ")
        buf_m.append(mask + " ")
        buf_t.append(term + "0")
        c, m, t = _norm3("".join(buf_c), "".join(buf_m), "".join(buf_t))

        while True:
            end = t.find("1")
            if end < 0:
                break
            (text, masked, _), (c, m, t) = _cut3(c, m, t, end)
            emit(text, masked)
            # A method header carrying the AMDP addition opens a SQLScript body.
            if text and _AMDP_OPEN.search(masked):
                stack.append((_M_AMDP, ""))
            pending_nosec, have_nosec = [], False
            raw = []
            start_line = lineno

        # T1.2 — the lexer lost its place. Flush what is buffered, reset the mode
        # stack, and mark it: a mis-lexed file must report as degraded coverage,
        # never as a clean object.
        if c and lineno - start_line + 1 > _RUNAWAY_LINES:
            emit(c, m, degraded=True)
            c = m = t = ""
            stack = []
            pending_nosec, have_nosec = [], False
            raw = []
            start_line = lineno + 1

        buf_c, buf_m, buf_t = ([c], [m], [t]) if c else ([], [], [])

    tail_c, tail_m, _ = _norm3("".join(buf_c), "".join(buf_m), "".join(buf_t))
    emit(tail_c, tail_m)
    return statements


def _in_amdp(stack: List[Tuple[str, str]]) -> bool:
    return any(mode in _AMDP_MODES for mode, _ in stack)


def split_cds_statements(source: str) -> List["Statement"]:
    """Split a CDS / DCL / RAP artefact.

    CDS is not ABAP. It terminates on `;` and braces, uses `//` for comments, and
    — the reason this function exists — a period inside `@AccessControl.
    authorizationCheck` is part of an identifier, not the end of anything.

    Annotations are emitted as whole lines so a rule can match a complete
    `@Annotation.path: #VALUE` pair, which is the shape every CDS security check
    takes.
    """
    statements: List[Statement] = []
    buf: List[str] = []
    raw: List[str] = []
    start = 1

    # F11. Only `//` was stripped, so a commented-out annotation inside a block
    # comment was emitted as a statement and raised a HIGH finding — and the stray
    # `*/` leaked into the next statement's text. Newlines are preserved so every
    # reported line number still means what it meant.
    source = re.sub(r"/\*.*?\*/",
                    lambda m: "\n" * m.group(0).count("\n"),
                    source, flags=re.S)

    for lineno, line in enumerate(source.splitlines(), start=1):
        code = line.split("//")[0]
        if not buf:
            start = lineno
        raw.append(line)

        stripped = code.strip()
        if not stripped:
            continue

        # An annotation is self-contained: emit it on its own so the whole
        # `@path: #VALUE` is one matchable unit.
        if stripped.startswith("@"):
            statements.append(Statement(" ".join(stripped.split()), lineno,
                                        line.strip(), 0, None))
            raw, buf, start = [], [], lineno + 1
            continue

        buf.append(stripped)
        joined = " ".join(" ".join(buf).split())
        while ";" in joined:
            head, joined = joined.split(";", 1)
            if head.strip():
                statements.append(Statement(head.strip(), start,
                                            "\n".join(raw).strip(), 0, None))
            raw, start = [], lineno
        buf = [joined] if joined.strip() else []

    tail = " ".join(" ".join(buf).split()).strip()
    if tail:
        statements.append(Statement(tail, start, "\n".join(raw).strip(), 0, None))
    return statements


def split_web_statements(source: str, style: str) -> List["Statement"]:
    """Split JavaScript/TypeScript, JSON or YAML into matchable statements.

    WHY THIS EXISTS. These four file types were already ROUTED — `.js`, `.ts`,
    and the five BTP descriptor names had rule sets and were counted in
    `files_scanned` — but they were handed to the ABAP splitter, where `"` opens
    a comment and `.` ends a statement. Measured against the shipped rules, that
    left `document.getElementById("a"); el.innerHTML = x` as
    `['var el = document', 'getElementById(']`, and `{"authenticationType":
    "none"}` as `'{'`. Only three of the seven JS rules could fire at all, and
    every one of the eight BTP descriptor rules was unreachable, because each
    begins `["']key["']` and that first quote ended the statement.

    So the engine reported a clean scan of files it had not read, and counted
    them as scanned while doing it. That is the one failure this scanner must
    never have, and it is the reason this splitter is not an enhancement.

    THREE STYLES, ONE CONCERN. All three need the same thing the ABAP lexer
    needs — to know when it is inside a string — and for the same reason: `//`
    inside `"http://host"` is not a comment, and `#` inside a YAML quoted scalar
    is not one either. What differs is only where a statement ends:

      `js`    `;`, `{`, `}` and end-of-line (semicolons are optional in JS, so a
              newline has to end a statement or a whole file becomes one).
      `json`  a key and the WHOLE of its value, however many lines the value
              spans. Pretty-printed JSON puts `"scope-references": [` and its
              entries on different lines, and a line-at-a-time split would miss
              exactly the two rules that read a key's array.
      `yaml`  the line. YAML is line-oriented; nothing is gained by more.

    Line numbers are the line the statement STARTS on, as everywhere else in
    this module: display detail, never identity.
    """
    if style == "json":
        return _split_json(source)
    if style == "yaml":
        return _split_yaml(source)
    return _split_js(source)


def _strip_web_comments(line: str, in_block: bool,
                        line_comment: Optional[str]) -> Tuple[str, str, bool]:
    """Remove comments from one line, respecting string literals.

    Returns `(code, mask, in_block)` where `mask` blanks literal CONTENT to `#`
    with offsets preserved — the same contract `_scan_line` gives the ABAP
    lexer, so `LITERAL_BLIND` behaves identically whatever the language.

    `line_comment` is None for JSON, which has no comments: stripping `//` there
    would eat the `//` of every `"http://..."` value and silence the rule that
    looks for one.
    """
    code: List[str] = []
    mask: List[str] = []
    quote = ""
    escaped = False
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if in_block:
            if line.startswith("*/", i):
                in_block = False
                i += 2
                continue
            i += 1
            continue
        if quote:
            code.append(ch)
            if escaped:
                mask.append("#")
                escaped = False
            elif ch == "\\":
                mask.append("#")
                escaped = True
            elif ch == quote:
                mask.append(ch)
                quote = ""
            else:
                mask.append("#")
            i += 1
            continue
        # not in a string
        if line.startswith("/*", i):
            in_block = True
            i += 2
            continue
        if line_comment and line.startswith(line_comment, i):
            break
        if ch in "\"'`":
            quote = ch
            code.append(ch)
            mask.append(ch)
            i += 1
            continue
        code.append(ch)
        mask.append(ch)
        i += 1
    return "".join(code), "".join(mask), in_block


def _split_js(source: str) -> List["Statement"]:
    statements: List["Statement"] = []
    in_block = False
    buf: List[str] = []
    buf_mask: List[str] = []
    raw: List[str] = []
    start = 1

    def flush() -> None:
        text = " ".join("".join(buf).split()).strip()
        if text:
            statements.append(Statement(
                text, start, "\n".join(raw).strip()[:2000], 0, None,
                " ".join("".join(buf_mask).split()).strip()))
        del buf[:], buf_mask[:], raw[:]

    for lineno, line in enumerate(source.splitlines(), 1):
        code, mask, in_block = _strip_web_comments(line, in_block, "//")
        if not buf:
            start = lineno
        raw.append(line)
        segment: List[str] = []
        seg_mask: List[str] = []
        for ch, mch in zip(code, mask):
            segment.append(ch)
            seg_mask.append(mch)
            if mch in ";{}":
                buf.append("".join(segment))
                buf_mask.append("".join(seg_mask))
                segment, seg_mask = [], []
                flush()
                start = lineno
        if segment:
            buf.append("".join(segment))
            buf_mask.append("".join(seg_mask))
        # End of line ends a statement: JavaScript makes the semicolon optional,
        # and without this a minified or semicolon-free file is one statement.
        flush()
        start = lineno + 1
    flush()
    return statements


#: Start of a JSON member: a quoted key followed by a colon.
_JSON_KEY = re.compile(r'"(?:[^"\\]|\\.)*"\s*:')


def _split_json(source: str) -> List["Statement"]:
    """One statement per member, spanning the whole of its value.

    Written against the joined document rather than line by line, because that
    is the only way `"scope-references": [` on one line and `"$XSAPPNAME.*"` on
    the next reach the same regex.
    """
    # Comment-strip with line_comment=None: JSON has no comments, and `//`
    # appears inside URL values that a rule looks for.
    codes, masks = [], []
    in_block = False
    for line in source.splitlines():
        code, mask, in_block = _strip_web_comments(line, in_block, None)
        codes.append(code)
        masks.append(mask)
    text = "\n".join(codes)
    mask_text = "\n".join(masks)

    statements: List["Statement"] = []
    for m in _JSON_KEY.finditer(mask_text):
        begin = m.start()
        i = m.end()
        depth = 0
        n = len(mask_text)
        while i < n:
            ch = mask_text[i]
            if ch in "[{":
                depth += 1
            elif ch in "]}":
                if depth == 0:
                    break
                depth -= 1
            elif ch == "," and depth == 0:
                break
            i += 1
        line = text.count("\n", 0, begin) + 1
        raw = text[begin:i]
        stmt = " ".join(raw.split()).strip()
        if stmt:
            statements.append(Statement(
                stmt, line, raw.strip()[:2000], 0, None,
                " ".join(mask_text[begin:i].split()).strip()))
    return statements


def _split_yaml(source: str) -> List["Statement"]:
    statements: List["Statement"] = []
    in_block = False
    for lineno, line in enumerate(source.splitlines(), 1):
        code, mask, in_block = _strip_web_comments(line, in_block, "#")
        stmt = " ".join(code.split()).strip()
        if stmt:
            statements.append(Statement(
                stmt, lineno, line.rstrip()[:2000], 0, None,
                " ".join(mask.split()).strip()))
    return statements


# --------------------------------------------------------------------------- #
#  The lexer                                                                  #
# --------------------------------------------------------------------------- #
#: Lexer modes. The stack carries `(mode, delimiter)`; only `_M_LIT` uses the
#: delimiter. Threading the whole STACK across lines — rather than the single
#: `in_template` boolean this replaced — is what makes a template that embeds an
#: expression that opens its own literal lex correctly.
_M_CODE = "code"
_M_LIT = "lit"            # '...' or `...`
_M_TPL = "tpl"            # |...|
_M_EMB = "emb"            # { ... } inside a template: CODE again
_M_AMDP = "amdp"          # SQLScript body of an AMDP method
_M_AMDP_ID = "amdp_id"    # "quoted identifier" — NOT a comment in SQLScript
_M_AMDP_LIT = "amdp_lit"  # 'string literal' in SQLScript
_M_AMDP_BLK = "amdp_blk"  # /* ... */, threads across lines

_AMDP_MODES = (_M_AMDP, _M_AMDP_ID, _M_AMDP_LIT, _M_AMDP_BLK)


def _scan_line(line: str, stack: List[Tuple[str, str]]
               ) -> Tuple[str, str, str, List[Tuple[str, str]]]:
    """Lex one source line under a carried mode stack.

    Returns `(code, mask, term, stack)` — three strings of equal length plus the
    stack to carry to the next line.

        code   the line with comments removed
        mask   the same text with the CONTENT of literals and template text
               replaced by `#`, delimiters and offsets preserved
        term   `1` where a character terminates a statement, `0` elsewhere

    Keeping the terminator decision here, beside the state that determines it, is
    the point: downstream only has to find a `1`.
    """
    stack = list(stack)
    code: List[str] = []
    mask: List[str] = []
    term: List[str] = []

    def put(ch: str, m: Optional[str] = None, t: str = "0") -> None:
        code.append(ch)
        mask.append(ch if m is None else m)
        term.append(t)

    mode = stack[-1][0] if stack else _M_CODE

    # A `*` in column 1 comments the whole line — but only when we are not inside
    # a literal or template left open on a previous line, where it is text.
    if line[:1] == "*" and mode in (_M_CODE, _M_EMB, _M_AMDP):
        return "", "", "", stack

    i, n = 0, len(line)
    while i < n:
        ch = line[i]
        mode = stack[-1][0] if stack else _M_CODE

        if mode == _M_LIT:
            delim = stack[-1][1]
            if ch == delim:
                if i + 1 < n and line[i + 1] == delim:
                    put(ch, "#")             # doubled delimiter escapes itself
                    put(delim, "#")
                    i += 2
                    continue
                stack.pop()
                put(ch)                      # the delimiter itself is not content
                i += 1
                continue
            put(ch, "#")                     # backslash is NOT an escape here
            i += 1
            continue

        if mode == _M_TPL:
            if ch == "\\":                   # \\ \| \{ \} — consumes one char
                put(ch, "#")
                if i + 1 < n:
                    put(line[i + 1], "#")
                    i += 2
                else:
                    i += 1
                continue
            if ch == "|":
                stack.pop()
                put(ch)
                i += 1
                continue
            if ch == "{":                    # an embedded expression is CODE
                stack.append((_M_EMB, ""))
                put(ch)
                i += 1
                continue
            put(ch, "#")                     # `"` and `.` are template text
            i += 1
            continue

        if mode == _M_AMDP_ID:
            if ch == '"':
                stack.pop()
                put(ch)
            else:
                put(ch, "#")
            i += 1
            continue

        if mode == _M_AMDP_LIT:
            if ch == "'":
                if i + 1 < n and line[i + 1] == "'":
                    put(ch, "#")
                    put("'", "#")
                    i += 2
                    continue
                stack.pop()
                put(ch)
            else:
                put(ch, "#")
            i += 1
            continue

        if mode == _M_AMDP_BLK:
            if ch == "*" and i + 1 < n and line[i + 1] == "/":
                stack.pop()
                i += 2
            else:
                i += 1                       # block-comment content is dropped
            continue

        if mode == _M_AMDP:
            if ch == "-" and i + 1 < n and line[i + 1] == "-":
                break                        # SQLScript comment to end of line
            if ch == "/" and i + 1 < n and line[i + 1] == "*":
                stack.append((_M_AMDP_BLK, ""))
                i += 2
                continue
            if ch == '"':                    # quoted IDENTIFIER, not a comment
                stack.append((_M_AMDP_ID, ""))
                put(ch)
                i += 1
                continue
            if ch == "'":
                stack.append((_M_AMDP_LIT, ""))
                put(ch)
                i += 1
                continue
            if ch == ";":                    # SQLScript terminates on `;`
                put(ch, ch, "1")
                i += 1
                continue
            put(ch)
            i += 1
            continue

        # _M_CODE or _M_EMB
        if mode == _M_EMB and ch == "}":
            stack.pop()
            put(ch)
            i += 1
            continue
        if ch in "'`":
            stack.append((_M_LIT, ch))
            put(ch)
            i += 1
            continue
        if ch == "|":
            stack.append((_M_TPL, ""))
            put(ch)
            i += 1
            continue
        if ch == '"':
            break                            # ABAP comment to end of line
        if ch == "." and mode == _M_CODE:
            before = line[i - 1] if i else ""
            after = line[i + 1] if i + 1 < n else ""
            # Bare decimals. NOT only "decimal literal": this splitter also sees
            # SQLScript and native SQL, which live inside `.abap` files, and
            # removing this manufactured statements like `75 AND rate < 12`.
            if before.isdigit() and after.isdigit():
                put(ch)
            else:
                put(ch, ch, "1")
            i += 1
            continue
        put(ch)
        i += 1

    return "".join(code), "".join(mask), "".join(term), stack


def _trim3(c: str, m: str, t: str) -> Tuple[str, str, str]:
    """Strip `c` and cut `m`/`t` at exactly the same offsets."""
    lead = len(c) - len(c.lstrip())
    c, m, t = c[lead:], m[lead:], t[lead:]
    trail = len(c) - len(c.rstrip())
    if trail:
        c, m, t = c[:-trail], m[:-trail], t[:-trail]
    return c, m, t


def _norm3(c: str, m: str, t: str) -> Tuple[str, str, str]:
    """Collapse whitespace runs across three parallel strings in lockstep."""
    oc: List[str] = []
    om: List[str] = []
    ot: List[str] = []
    prev_space = True
    for i, ch in enumerate(c):
        if ch.isspace():
            if not prev_space:
                oc.append(" ")
                om.append(" ")
                ot.append("0")
            prev_space = True
        else:
            oc.append(ch)
            om.append(m[i])
            ot.append(t[i])
            prev_space = False
    return _trim3("".join(oc), "".join(om), "".join(ot))


def _cut3(c: str, m: str, t: str, end: int):
    """Split three parallel strings at `end`, discarding the terminator."""
    return (_trim3(c[:end], m[:end], t[:end]),
            _trim3(c[end + 1:], m[end + 1:], t[end + 1:]))


class AbapSourceScanner:
    """Statement-level pattern matching with optional taint refinement."""

    def __init__(self, *, data_flow: bool = True):
        self.data_flow = data_flow
        self._compiled: Dict[str, Any] = {}
        self.files_scanned = 0
        self.metadata_skipped = 0
        self.unreadable: List[str] = []
        #: Scanned files per language, so the report can say WHICH languages it
        #: read rather than only how many files it opened.
        self.files_by_language: Dict[str, int] = {}
        #: Files this scanner has no rules for, by suffix. Counted rather than
        #: skipped in silence — see the note in `scan_tree`.
        self.unscanned_by_suffix: Dict[str, int] = {}
        #: Statements the runaway guard had to flush because the lexer lost its
        #: place. Reported beside `metadata_skipped`, because a mis-lexed file that
        #: reports as clean is the one failure this scanner must never have.
        self.lex_degraded = 0
        #: CDS/DCL/RAP artefacts indexed across the WHOLE tree, so the questions
        #: no single file can answer — is this exposed view granted on by any
        #: role, does this behaviour declare authorization anywhere — can be
        #: asked once the walk is finished. See modules/cds_authorization_index.py.
        self.cds_index = CdsAuthorizationIndex()

    def _pattern(self, rule: Dict[str, Any]):
        rid = rule["id"]
        if rid not in self._compiled:
            src = PATTERN_FIXES.get(rid, rule["pattern"])
            self._compiled[rid] = re.compile(src, re.IGNORECASE)
        return self._compiled[rid]

    # ------------------------------------------------------------------ #

    @staticmethod
    def _language_for(path: Path) -> Optional[str]:
        """The LANGUAGE of a file, or None when this scanner does not read it.

        Routing and lexing were one decision before, expressed as a suffix
        ladder returning a rule set — so a file could be routed to rules
        without anything choosing a splitter that could read it. Naming the
        language separately is what lets `scan_text` pick a lexer and gate the
        ABAP-only passes, and what lets the report count by language.
        """
        name = path.name.lower()
        if name.endswith(METADATA_SUFFIXES):
            return None
        if name.endswith(CDS_SUFFIXES):
            return "cds"
        if name.endswith(ABAP_SUFFIXES):
            return "abap"
        if name.endswith(JS_SUFFIXES):
            return "js"
        if name in DESCRIPTOR_NAMES:
            return "yaml" if name.endswith((".yaml", ".yml")) else "json"
        return None

    _RULES_BY_LANGUAGE = {
        "cds": "CDS_RULES", "abap": "ALL_ABAP_SAST_RULES",
        "js": "ALL_JS_RULES", "json": "ALL_BTP_CONFIG_RULES",
        "yaml": "ALL_BTP_CONFIG_RULES",
    }

    @classmethod
    def _rules_for(cls, path: Path) -> Optional[List[Dict[str, Any]]]:
        """The rule set for a file, by type. None when the file is not source."""
        lang = cls._language_for(path)
        if lang is None:
            return None
        return {"cds": CDS_RULES, "abap": ALL_ABAP_SAST_RULES,
                "js": ALL_JS_RULES, "json": ALL_BTP_CONFIG_RULES,
                "yaml": ALL_BTP_CONFIG_RULES}[lang]

    def scan_tree(self, root: Path) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for path in sorted(p for p in root.rglob("*") if p.is_file()):
            name = path.name.lower()
            if name.endswith(METADATA_SUFFIXES):
                self.metadata_skipped += 1
                continue
            lang = self._language_for(path)
            if lang is None:
                # NOT scanned, and therefore counted. A CAP project's .java, a
                # HANA .hdbprocedure or a .py helper produce no finding and no
                # error today; without this the report cannot distinguish "we
                # read it and it was clean" from "we never opened it".
                suffix = path.suffix.lower() or path.name.lower()
                self.unscanned_by_suffix[suffix] = (
                    self.unscanned_by_suffix.get(suffix, 0) + 1)
                continue
            rules = self._rules_for(path)
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:                       # noqa: PERF203
                self.unreadable.append(f"{path}: {exc}")
                continue
            self.files_scanned += 1
            self.files_by_language[lang] = self.files_by_language.get(lang, 0) + 1
            if lang == "cds":
                # Indexed as well as matched. The per-file rules answer "what does
                # this artefact say"; the index answers "what does this tree not
                # contain", which is where missing access control lives.
                self.cds_index.add_file(text, str(path), path.name.lower())
            findings.extend(self.scan_text(text, path, rules))

        findings.extend(cross_artifact_findings(self.cds_index))
        return findings

    def scan_text(self, source: str, path: Path,
                  rules: Optional[Iterable[Dict[str, Any]]] = None
                  ) -> List[Dict[str, Any]]:
        """Scan one artefact. `rules` defaults to the right set FOR THE FILE TYPE.

        It used to default to the ABAP corpus whatever the path said, so calling
        this directly on a `.asdcls` ran ABAP rules over DCL and reported SQL
        injection in a correct access-control role. Only `scan_tree` routed
        properly, which made the default a trap for every other caller.
        """
        if rules is None:
            rules = self._rules_for(path)
        # Each language gets the lexer that can read it. Handing CDS to the ABAP
        # splitter both lost every annotation and invented SQL-injection
        # findings in DCL; handing JavaScript and JSON to it lost the file
        # almost entirely while still counting it as scanned.
        language = self._language_for(path) or "abap"
        is_cds = language == "cds"
        is_abap = language == "abap"
        if is_cds:
            statements = split_cds_statements(source)
        elif language in ("js", "json", "yaml"):
            statements = split_web_statements(source, language)
        else:
            statements = split_statements(source)
        self.lex_degraded += sum(1 for st in statements if st.degraded)
        # Block-scoped ABAP guards. A JS/JSON/YAML artefact has no FORM/METHOD
        # blocks and no AUTHORITY-CHECK, so the guard is not merely unnecessary
        # there — computing it over another grammar is meaningless.
        guarded_blocks = _guarded_blocks(statements) if is_abap else set()

        out: List[Dict[str, Any]] = []

        def record(rule: Dict[str, Any], st: Statement) -> None:
            rid = rule["id"]
            suppressed = st.nosec is not None and (
                not st.nosec or rid.upper() in st.nosec)
            severity = SEVERITY_FIXES.get(rid, rule["severity"])
            # F4 — the dynamic name is a compile-time literal. Kept as an
            # inventory entry, demoted because there is nothing to inject into.
            literal_operand = (rid in DYNAMIC_TOKEN_RULES
                               and bool(_LITERAL_OPERAND.search(st.text)))
            if literal_operand:
                severity = "LOW"
            out.append({
                "rule_id": rid,
                "name": rule["name"],
                "category": rule.get("category", ""),
                "severity": severity,
                "literal_operand": literal_operand,
                "cwe": rule.get("cwe"),
                "file": str(path),
                "object": _object_name(path),
                "line": st.line,
                "statement": st.text[:400],
                "snippet": st.raw[:600],
                "description": DESCRIPTION_FIXES.get(
                    rid, rule.get("description", "")),
                "recommendation": rule.get("recommendation", ""),
                # `pattern-only` until taint says otherwise. The evidence class
                # is the single most decision-relevant field a SAST finding has.
                "confidence": "pattern-only",
                "flow": None,
                "suppressed_by_nosec": suppressed,
                "lex_degraded": st.degraded,
            })

        for rule in rules:
            rid = rule["id"]
            if rid in RULE_HANDLED_IN_ENGINE or rid in RETIRED_RULES:
                continue
            pattern = self._pattern(rule)
            blind = rid in LITERAL_BLIND
            for st in statements:
                if not pattern.search(st.text_masked if blind else st.text):
                    continue
                # Named "... without AUTHORITY-CHECK": honour the "without".
                if rid in AUTHORITY_GUARDED and st.block in guarded_blocks:
                    continue
                if (is_abap and rid == "ABAP-SQLI-001"
                        and _INTERNAL_TABLE_DELETE.match(st.text)):
                    continue
                record(rule, st)

        # T1.6 — ABAP-AUTH-003 could not be expressed as a single-statement regex
        # (it needed a literal `.` the splitter strips, and a lookahead at the NEXT
        # statement), so it was dead code. The engine has both.
        auth003 = _RULES_BY_ID.get("ABAP-AUTH-003")
        if auth003 is not None and is_abap:
            for i, st in enumerate(statements):
                if (_AUTHORITY_CHECK_STMT.match(st.text_masked)
                        and not _subrc_evaluated(statements, i)):
                    record(auth003, st)

        # Taint refinement is ABAP-syntax throughout (sy-subrc, ->, abap_true),
        # so it is asked only about ABAP. On any other language it would have
        # nothing to say and would say it slowly.
        if self.data_flow and is_abap:
            self._refine(out, statements, source)
        return out

    def _refine(self, findings: List[Dict[str, Any]],
                statements: List[Statement], source: str) -> None:
        """Ask the taint analyzer about the rules that carry a sink.

        A verdict is only ever ADDED — `confirmed` when tainted input reaches the
        sink, `tentative` when the walk found no evidence either way. Nothing is
        deleted on the strength of a sanitizer, because the walk is
        path-insensitive: upstream, a sanitizer inside an `IF` branch silently
        removed a genuine injection. A tool that hides findings it is not sure
        about is worse than one that grades them.
        """
        sinks = {r["id"] for r in ALL_ABAP_SAST_RULES if r.get("_taint_sink")}
        relevant = [f for f in findings if f["rule_id"] in sinks]
        if not relevant:
            return

        # T1.10 — the analyzer used to be handed the RAW file and re-lexed it one
        # line at a time with `line.split('"', 1)[0]`, which is the exact
        # line-oriented model this module exists to replace. It could not see a
        # concatenation split over two lines, and truncated any line containing a
        # `"` inside a literal. It now gets our statements, laid out on their own
        # start lines so every line number still means what it meant.
        aligned = _taint_source(statements, len(source.splitlines()))

        # NO try/except around these calls, on purpose. An earlier version wrapped
        # them and called a `refine()` method that does not exist; the
        # AttributeError went straight into the `except` and every finding stayed
        # `pattern-only`. The taint pass appeared to run and did nothing at all,
        # which is worse than not having it. A broken analyzer must fail loudly.
        cache: Dict[str, TaintAnalyzer] = {}

        for finding in relevant:
            rid = finding["rule_id"]
            arg = _sink_argument(finding["statement"], rid)
            if not arg:
                continue
            if rid not in cache:
                cache[rid] = _analyzer_for(rid, aligned)
            analyzer = cache[rid]
            verdict = analyzer.classify_sink(arg, finding["line"])
            if verdict == analyzer.TAINTED:
                finding["confidence"] = "confirmed"
                finding["flow"] = analyzer.sink_trace(arg, finding["line"])
            else:
                # Downgrade, never hide — including on SANITIZED. The walk is
                # path-insensitive, so a sanitizer inside one branch of an IF is
                # credited on every path including the ones it does not cover.
                # Upstream that silently deleted genuine injections.
                finding["confidence"] = "tentative"


# --------------------------------------------------------------------------- #
#  Sink arguments                                                             #
# --------------------------------------------------------------------------- #
#: Every rule carrying `_taint_sink` also ships a precise `_sink_arg` naming the
#: clause its dynamic operand lives in. None of them was ever read: `_refine`
#: called one generic "first `( identifier )` anywhere in the statement" regex.
#:
#: `SELECT * FROM (lv_tab) WHERE (lv_where)` therefore graded the WHERE finding on
#: `lv_tab` — and emitted a `taint_flow` tracing a variable that is not the WHERE
#: operand, which is a fabricated data-flow trace in a customer report. The two
#: sinks whose token is not parenthesised at all (`OPEN DATASET lv_file`,
#: `create_by_url( url = lv_url )`) returned None and could never be confirmed.
_SINK_ARG_BY_ID: Dict[str, Any] = {
    r["id"]: re.compile(r["_sink_arg"], re.IGNORECASE)
    for r in ALL_ABAP_SAST_RULES if r.get("_sink_arg")
}

#: The generic fallback, for sinks that ship no `_sink_arg`. `DATA(` / `FINAL(`
#: are skipped: an inline declaration is the statement's TARGET, never its
#: dynamic operand.
_SINK_ARG = re.compile(
    r"(?P<pre>[A-Za-z_]\w*)?\(\s*"
    r"(?P<arg>[A-Za-z_][A-Za-z0-9_\-]*(?:->[A-Za-z0-9_]+)*)\s*\)")


def _sink_argument(statement: str, rule_id: Optional[str] = None) -> Optional[str]:
    """The dynamic operand a sink is built from, using the rule's own regex."""
    pattern = _SINK_ARG_BY_ID.get(rule_id or "")
    if pattern is not None:
        match = pattern.search(statement)
        return match.group(1).strip() if match else None
    for match in _SINK_ARG.finditer(statement):
        if (match.group("pre") or "").upper() in ("DATA", "FINAL"):
            continue
        return match.group("arg")
    return None


# --------------------------------------------------------------------------- #
#  Authorization guards                                                       #
# --------------------------------------------------------------------------- #

def _subrc_evaluated(statements: List[Statement], index: int) -> bool:
    """Was the AUTHORITY-CHECK at `index` actually acted on?

    A check whose `sy-subrc` is never read is a no-op, and the old guard credited
    it in full — so `AUTHORITY-CHECK ... .` followed directly by the unguarded
    DELETE silenced the finding about the unguarded DELETE.

    Three statements forward rather than one: it absorbs residual mis-splitting and
    the `COND #( WHEN sy-subrc = 0 ... )` form.
    """
    here = statements[index]
    for st in statements[index + 1:index + 4]:
        if st.block != here.block:
            return False
        if _SUBRC.search(st.text_masked):
            return True
        if _CONTROL_FLOW.match(st.text_masked):
            return False
    return False


def _guarded_blocks(statements: List[Statement]) -> set:
    """Blocks holding a real AUTHORITY-CHECK.

    The old test was `\\bAUTHORITY[-\\s]?CHECK\\b` searched anywhere in the raw
    statement text, which credited a block for four separate no-ops: the keyword
    inside a string literal (`WRITE 'TODO: add AUTHORITY-CHECK here'`), a check
    with no FIELD pair at all, a check whose result is discarded, and the
    undocumented spellings `AUTHORITY CHECK` / `AUTHORITYCHECK`.

    A fifth was added once SAP's keyword documentation settled U6: a check
    carrying the `FOR USER` addition asks about a DIFFERENT user, and answers
    nothing about whether the caller may perform the operation. See
    `_AUTHORITY_FOR_OTHER_USER`.
    """
    return {st.block for i, st in enumerate(statements)
            if _AUTHORITY_CHECK_STMT.match(st.text_masked)
            and not _AUTHORITY_FOR_OTHER_USER.match(st.text_masked)
            and _subrc_evaluated(statements, i)}


# --------------------------------------------------------------------------- #
#  Taint input                                                                #
# --------------------------------------------------------------------------- #
#: An inline declaration is a target, not an operator. `DATA(lv_tab) = p_tab.`
#: defeated the analyzer's `^\s*([\w/]+)\s*=` because it found the `(` first, so
#: the assignment was never seen and the propagation was lost.
_INLINE_DECL = re.compile(r"^\s*@?(?:DATA|FINAL)\s*\(\s*([\w/]+)\s*\)\s*=", re.IGNORECASE)

#: `x &&= y` is `x = x && y`. Written the short way it matched no assignment form.
_CONCAT_ASSIGN = re.compile(r"^\s*([\w/]+)\s*&&=\s*(.+?)\s*$")

#: ABAP words that appear in a parameter list without being parameter names. Only
#: consulted for the untyped fallback, where there is no `TYPE` to anchor on.
_PARAM_KEYWORDS: frozenset = frozenset({
    "type", "ref", "to", "standard", "sorted", "hashed", "table", "of", "like",
    "value", "optional", "default", "structure", "any", "data", "string",
    "instance", "authorization", "request", "result", "entity", "update",
    "create", "delete", "read", "for", "with", "key", "importing", "changing",
    "using", "tables", "exporting", "returning", "raising", "begin", "end",
})


def _taint_rewrite(text: str) -> str:
    """Normalise the two assignment spellings the analyzer cannot parse."""
    match = _INLINE_DECL.match(text)
    if match:
        text = f"{match.group(1)} =" + text[match.end():]
    match = _CONCAT_ASSIGN.match(text)
    if match:
        text = f"{match.group(1)} = {match.group(1)} && {match.group(2)}"
    return text


def _taint_source(statements: List[Statement], line_count: int) -> str:
    """Lay our statements out on their own start lines, one per line.

    The analyzer is line-oriented and every line number it reports has to keep
    meaning what it meant, so the shape is "same line count, each statement on the
    line it starts at, consumed lines blank". Alignment is free: findings carry
    `Statement.line` and the walk only ever moves strictly before it.

    Masked text, deliberately: it removes the `"` that made the analyzer's own
    `line.split('"', 1)[0]` truncate a statement, and it stops a source or
    sanitizer NAME written inside a string literal from being read as one.
    """
    lines = [""] * max(line_count, 1)
    for st in statements:
        idx = st.line - 1
        if not 0 <= idx < len(lines):
            continue
        while idx < len(lines) and lines[idx]:
            idx += 1                    # another statement already claimed it
        if idx < len(lines):
            lines[idx] = _taint_rewrite(st.text_masked)
    return "\n".join(lines)


class RiseTaintAnalyzer(TaintAnalyzer):
    """The vendored analyzer with the defects that made its verdicts unsafe fixed.

    Everything here is a narrowing or a correction, never a new suppression: the
    downgrade-never-hide contract in `AbapSourceScanner._refine` is unchanged.
    """

    #: Chained declarations. `_PARAM_RE` captured ONE name per line, so
    #: `PARAMETERS: p_a ..., p_tab ...` tainted only `p_a` and every injection
    #: through a later member of the chain classified UNKNOWN.
    _CHAIN_HEAD = re.compile(r"^\s*(?:PARAMETERS?|SELECT-OPTIONS)\s*:?\s*", re.IGNORECASE)
    _CHAIN_NAME = re.compile(r"(?:^|,)\s*([A-Za-z_][\w/]*)")

    #: `CONSTANTS lc_where TYPE string VALUE 'MANDT = SY-MANDT'.` had no case at
    #: all, so a clause fixed at compile time reported as a tentative CRITICAL.
    _DECL_VALUE = re.compile(
        r"^\s*(?:CONSTANTS|DATA|STATICS)\s*:?\s*([\w/]+)\b[^=]*?\bVALUE\s+(.+?)\s*$",
        re.IGNORECASE)

    #: `=(?!>)`: `cl_gui_frontend_services=>gui_upload( ... )` parsed as an
    #: assignment TO the class name, so `gui_upload` — already in the source list —
    #: could never fire as intended, and every later mention of the class carried
    #: taint it never had.
    _ASSIGN = re.compile(r"\s*([\w/]+)\s*=(?!>)\s*(.+?)\.?\s*$")

    #: The sanitizer alternation without the trailing call syntax, for asking
    #: "does this guard WRAP that identifier".
    _SAN_NAMES = r"(?:cl_abap_dyn_prg\s*=>\s*)?(?:%s)"

    # ------------------------------------------------------------------ #
    #  Group B — the source families the analyzer had no case for         #
    # ------------------------------------------------------------------ #
    # Additions here are ABAP KEYWORDS, SYSTEM FIELDS, or identifiers listed in
    # `CONFIRMED_SOURCE_IDENTIFIERS` with the SAP file they were read from. The
    # first two are language constructs anyone can verify; the third is a claim
    # about SAP's shipped code, which is why it carries a citation rather than a
    # judgement. U10 in docs/CVA_ENGINE_IMPROVEMENT_PLAN.md is the record of
    # those four being confirmed.
    #
    # B9 (HTTP response bodies) is not here, for the reason it never was: it needs
    # the released-classes listing to anchor on client identity, and anchoring on
    # a bare accessor name instead would taint every CATCH block in the estate,
    # because that accessor is overwhelmingly the exception message getter.
    #: U10, settled. Each identifier here was grep-confirmed in a NAMED SAP file
    #: before it shipped, and the file is recorded beside it. That is the whole
    #: bar: not "this looks like a real class", but "here is where SAP writes it".
    #:
    #: The guard that used to enforce this refused any class-qualified name
    #: outright, which was right while nothing was confirmed and wrong once
    #: something was. It now requires provenance instead — strictly stronger,
    #: because it catches an unverified identifier AND records where the verified
    #: ones came from. B9 is still absent for the original reason: an HTTP
    #: response accessor cannot be anchored without the released-classes listing,
    #: and anchoring on the bare name taints every CATCH block in the estate.
    CONFIRMED_SOURCE_IDENTIFIERS = {
        # JSON text arriving from outside, deserialised into ABAP data.
        "/ui2/cl_json=>deserialize":
            "SAP-samples/abap-cheat-sheets 21_XML_JSON.md",
        # A reader constructed OVER input: everything pulled through it carries
        # the input's provenance, which is exactly what taint means.
        "cl_sxml_string_reader=>create":
            "SAP-samples/abap-cheat-sheets 21_XML_JSON.md",
        # Screen field values, read back into the program. The values are the
        # user's, which is the definition of a source.
        "DYNP_VALUES_READ":
            "SAP-samples/abap-cheat-sheets 18_Dynpro.md",
        # The value the user picked from an F4 help.
        "F4IF_INT_TABLE_VALUE_REQUEST":
            "SAP-samples/abap-cheat-sheets 18_Dynpro.md",
    }

    _SOURCE_RE = re.compile(
        TaintAnalyzer._SOURCE_RE.pattern
        + r"|\bsy-lisel\b|\bsy-ucomm\b|\bsscrfields-\w+"
        + "".join("|" + re.escape(name)
                  for name in sorted(CONFIRMED_SOURCE_IDENTIFIERS)),
        re.IGNORECASE)

    #: B8. Dialog modules are blocks in `abap_sast.py`'s own model but were not
    #: scopes here, so taint leaked between them.
    _SCOPE_START_RE = re.compile(
        r"^\s*(?:FORM|METHOD|FUNCTION|MODULE)\b", re.IGNORECASE)
    _SCOPE_END_RE = re.compile(
        r"^\s*END(?:FORM|METHOD|FUNCTION|MODULE)\b", re.IGNORECASE)

    #: B6. A data cluster read back is external input: whoever wrote the cluster
    #: chose the values. The `IMPORT (param_table) FROM ...` form binds by a
    #: RUNTIME name table and is deliberately left alone rather than guessed at.
    #:
    #: U9, settled. SAP's syntax for the medium gives exactly six alternatives:
    #: `DATA BUFFER xstr`, `INTERNAL TABLE itab`, `MEMORY ID id`,
    #: `DATABASE dbtab(ar) [TO wa] [CLIENT cl] ID id`, `SHARED MEMORY ...` and
    #: `SHARED BUFFER ...`. Three were covered; the other three were left out
    #: because they had been proposed on structural symmetry alone and no fetched
    #: file named them. They are named now, so they are in.
    #:
    #: The argument for including them is the same one that admitted the first
    #: three, and it gets STRONGER the further the medium is from the program: a
    #: cluster in ABAP Memory was at least written by the same session, while
    #: `DATABASE` and the two cross-program `SHARED` areas hold data some other
    #: program wrote, possibly on another day. SAP's own words for the last two
    #: are "a cross-program memory area".
    _IMPORT_CLUSTER = re.compile(
        r"^\s*IMPORT\b(?P<binds>(?:(?!\().)*?)"
        r"\bFROM\s+(?:MEMORY\s+ID|DATA\s+BUFFER|INTERNAL\s+TABLE"
        r"|DATABASE|SHARED\s+MEMORY|SHARED\s+BUFFER)\b", re.IGNORECASE)

    #: B7. Classic list interaction — the user picks a line and the program reads
    #: it back.
    _READ_LINE = re.compile(
        r"^\s*READ\s+(?:CURRENT\s+)?LINE\b.*?\bINTO\s+(?P<tgt>[\w/]+)", re.IGNORECASE)

    #: B5. Parsed XML. The trap is capturing the LEFT-hand root name instead of the
    #: ABAP variable it binds to, so the extraction is deliberately `= <name>`.
    #: Restricted to `SOURCE XML`, because `SOURCE root = ...` is serialising the
    #: program's own data outward and is not a source at all.
    _CALL_XSLT = re.compile(
        r"\bCALL\s+TRANSFORMATION\b.*?\bSOURCE\s+XML\b.*?\bRESULT\b(?P<binds>.+)$",
        re.IGNORECASE)

    #: B3. Output-parameter binding on a call that is ALREADY a known source.
    #: This is what makes `gui_upload` — in the vendored source list since day one —
    #: able to fire at all: the value arrives through CHANGING, not through a
    #: return value, so there was never an assignment for the analyzer to see.
    _OUT_BIND = re.compile(
        r"\b(?:IMPORTING|CHANGING|RECEIVING|TABLES)\b(?P<binds>.+)$", re.IGNORECASE)
    _BIND_TGT = re.compile(r"=\s*([A-Za-z_][\w/]*)")

    #: B2 / B4. Procedure and handler inbound parameters. Seeded PER SCOPE and
    #: never into `_globals`: a parameter name shared by two procedures would
    #: otherwise leak taint from one into the other.
    _METHODS_DECL = re.compile(
        r"^\s*(?:CLASS-)?METHODS\s*:?\s*(?P<name>[\w/]+)(?P<rest>.*)$", re.IGNORECASE)
    _FORM_DECL = re.compile(
        r"^\s*(?:FORM|METHOD|FUNCTION)\s+(?P<name>[\w/]+)(?P<rest>.*)$", re.IGNORECASE)
    _IN_SECTION = re.compile(
        r"\b(?:IMPORTING|CHANGING|USING|TABLES|FOR)\b(?P<params>.*?)"
        r"(?=\bEXPORTING\b|\bRETURNING\b|\bRAISING\b|$)", re.IGNORECASE)
    #: `iv_x TYPE string` and `VALUE(iv_x)`, plus the bare `USING p_a` form old
    #: FORMs use. `%` is admitted because RAP handler parameters carry it and
    #: `_IDENT_RE` silently drops a leading one.
    _PARAM_NAME = re.compile(
        r"\bVALUE\s*\(\s*([A-Za-z_%][\w/]*)\s*\)|\b([A-Za-z_%][\w/]*)\s+TYPE\b"
        r"|\b(?:USING|CHANGING)\s+([A-Za-z_][\w/]*)", re.IGNORECASE)

    def __init__(self, text: str, sanitizers: Iterable[str] = DEFAULT_SANITIZERS):
        names = "|".join(sorted(sanitizers, key=len, reverse=True))
        # Anchored on both sides AND requiring call syntax. Without the `\(` a
        # variable merely NAMED `lv_escape_quotes` read as sanitized.
        self._SANITIZER_RE = re.compile(
            r"\b" + (self._SAN_NAMES % names) + r"\s*\(", re.IGNORECASE)
        self._san_names = re.compile(
            r"\b" + (self._SAN_NAMES % names), re.IGNORECASE)

        # The base built `_code` by cutting each line at the first `"`, which has no
        # literal awareness at all. Lexing it properly here rather than only in
        # `_taint_source` keeps the class correct for any caller, not just ours.
        self._raw = text.splitlines()
        code_lines: List[str] = []
        stack: List[Tuple[str, str]] = []
        for line in self._raw:
            _code, mask, _term, stack = _scan_line(line, stack)
            code_lines.append(_taint_rewrite(mask.strip()))
        self._code = code_lines
        # B2/B4 — a METHOD implementation header carries no signature, so the
        # declarations are indexed once and looked up when the scope opens.
        self._method_params: Dict[str, str] = {}
        for line in self._code:
            decl = self._METHODS_DECL.match(line)
            if decl:
                self._method_params[decl.group("name").lower()] = decl.group("rest")
        self._globals = self._collect_globals()
        self._scopes = self._segment_scopes()

    # -- sources ------------------------------------------------------- #

    def _collect_globals(self) -> dict:
        g: dict = {}
        depth = 0
        for i, c in enumerate(self._code):
            if self._SCOPE_START_RE.search(c):
                depth += 1
            elif self._SCOPE_END_RE.search(c):
                depth = max(0, depth - 1)
            elif depth == 0:
                head = self._CHAIN_HEAD.match(c)
                if head:
                    for name in self._CHAIN_NAME.findall(c[head.end():]):
                        g.setdefault(name.lower(), i + 1)
        return g

    # -- propagation ---------------------------------------------------- #

    @staticmethod
    def _names_in(params: str) -> List[str]:
        """Parameter names in a declaration fragment.

        Typed parameters are unambiguous (`iv_x TYPE string`, `VALUE(iv_x)`), so
        they are preferred. The bare fallback is for the untyped `USING p_a p_b`
        form classic FORMs use, and drops the ABAP words that would otherwise be
        mistaken for names.
        """
        typed = re.findall(
            r"\bVALUE\s*\(\s*([A-Za-z_%][\w/]*)\s*\)|\b([A-Za-z_%][\w/]*)\s+TYPE\b",
            params, re.IGNORECASE)
        names = [a or b for a, b in typed]
        if names:
            return names
        return [t for t in re.findall(r"[A-Za-z_%][\w/]*", params)
                if t.lower() not in _PARAM_KEYWORDS]

    def _inbound_params(self, name: str, rest: str) -> List[str]:
        """Inbound parameters of the procedure whose header this is.

        A METHOD implementation header carries no signature — it lives on the
        METHODS declaration elsewhere in the file — so that is looked up. Without
        this, every injection reachable over RFC or OData classified UNKNOWN, and
        since Phase 5 an UNKNOWN never prices into FAIR.
        """
        text = self._method_params.get(name.lower()) or rest
        out: List[str] = []
        for section in self._IN_SECTION.finditer(text):
            out.extend(n.lower() for n in self._names_in(section.group("params")))
        return out

    def _tainted_targets(self, code: str) -> List[str]:
        """Statements that taint what they WRITE INTO rather than being an RHS."""
        m = self._IMPORT_CLUSTER.match(code)
        if m:
            binds = m.group("binds")
            return self._BIND_TGT.findall(binds) or [
                t for t in self._IDENT_RE.findall(binds)
                if t.lower() not in _ABAP_NOISE_WORDS]
        m = self._READ_LINE.match(code)
        if m:
            return [m.group("tgt")]
        m = self._CALL_XSLT.search(code)
        if m:
            return self._BIND_TGT.findall(m.group("binds"))
        if self._SOURCE_RE.search(code):
            m = self._OUT_BIND.search(code)
            if m:
                return self._BIND_TGT.findall(m.group("binds"))
        return []

    def _apply(self, code: str, state: dict, origin: dict, line_no: int) -> None:
        head = self._FORM_DECL.match(code)
        if head:
            for name in self._inbound_params(head.group("name"), head.group("rest")):
                self._set(name, self.TAINTED, None, line_no, state, origin)
            return
        targets = self._tainted_targets(code)
        if targets:
            for name in targets:
                self._set(name.lower(), self.TAINTED, None, line_no, state, origin)
            return
        m = re.search(r"GET\s+PARAMETER\s+ID\s+\S+\s+FIELD\s+([\w/]+)",
                      code, re.IGNORECASE)
        if m:
            self._set(m.group(1).lower(), self.TAINTED, None, line_no, state, origin)
            return
        m = self._DECL_VALUE.match(code)
        if m:
            self._assign(m.group(1).lower(), m.group(2), line_no, state, origin)
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
        m = self._ASSIGN.match(code)
        if m and not re.search(r"[=<>]=|<>", code):
            self._assign(m.group(1).lower(), m.group(2), line_no, state, origin)

    # -- classification -------------------------------------------------- #

    def _wraps(self, expr: str, ident: str) -> bool:
        """Does a recognised guard have `ident` inside its own parentheses?"""
        return bool(re.search(
            self._san_names.pattern + r"\s*\([^()]*\b" + re.escape(ident) + r"\b",
            expr, re.IGNORECASE))

    def _unguarded_tainted(self, expr: str, state: dict) -> Optional[str]:
        for ident in self._IDENT_RE.findall(expr):
            il = ident.lower()
            if il in _ABAP_NOISE_WORDS:
                continue
            if (state.get(il) == self.TAINTED or il in self._globals) \
                    and not self._wraps(expr, ident):
                return il
        return None

    def _classify(self, rhs: str, state: dict) -> str:
        rhs = rhs.strip()
        # A source is tested FIRST. The base tested the sanitizer first and
        # returned SANITIZED for the whole expression, so a guard wrapping a safe
        # literal cleared a tainted value sitting next to it.
        if self._SOURCE_RE.search(rhs):
            return self.TAINTED
        if self._LITERAL_RE.match(rhs):
            return self.CLEAN
        return self._combine(rhs, state)

    def _combine(self, expr: str, state: dict) -> str:
        if self._SOURCE_RE.search(expr):
            return self.TAINTED
        if self._SANITIZER_RE.search(expr):
            # Credit a guard only for what it actually wraps.
            # `CONCATENATE cl_abap_dyn_prg=>quote( 'LH' ) p_in INTO lv_w` used to
            # return SANITIZED: the guard wrapped the safe literal and the tainted
            # `p_in` beside it was never examined.
            return self.TAINTED if self._unguarded_tainted(expr, state) \
                else self.SANITIZED
        return super()._combine(expr, state)


def _analyzer_for(rule_id: str, source: str) -> TaintAnalyzer:
    """One analyzer per sink, because the accepted guards differ by sink.

    A table-name check does not make a column name safe and neither makes a file
    path safe, but one flat regex was consulted identically for all nine.
    """
    return RiseTaintAnalyzer(source, SINK_SANITIZERS.get(rule_id, DEFAULT_SANITIZERS))


def _object_name(path: Path) -> str:
    """The ABAP object an abapGit file belongs to.

    `zcl_thing.clas.abap` -> `ZCL_THING`. The object is a durable SAP name and is
    what a finding is ABOUT; the file name and line are display detail.
    """
    return path.name.split(".")[0].upper()


# --------------------------------------------------------------------------- #
#  Host contract                                                              #
# --------------------------------------------------------------------------- #

class AbapSastAuditor(BaseAuditor):
    """Emits host findings from an unpacked abapGit export.

    IDENTITY — WHY THE LINE NUMBER IS NOWHERE NEAR IT
    The subject is the ABAP OBJECT and the qualifier is the normalised offending
    statement. Line numbers move on every edit above them; the statement text does
    not. This is the upstream engine's own conclusion — its baseline fingerprint
    was already `rule|file|normalised-line` and explicitly line-number-independent
    — expressed through the host's existing subject/qualifier contract, so
    `server/identity.py` needed no change at all.

    SCOPE — WHY MOST FINDINGS ARE AGGREGATES
    Taint-*confirmed* findings are per-statement `scope="object"`: there is real
    evidence, and each one is worth tracking on its own. Everything else — which is
    all but the 8 rules carrying a sink — is `scope="aggregate"`, one finding per
    (rule × object), naming its occurrences as members. A 200k-line estate would
    otherwise produce thousands of individually-tracked pattern hits, and the FAIR
    figure is priced on the unfiltered set.
    """

    #: The directory holding an unpacked abapGit export, supplied via
    #: `--abap-src`. Absent means the module has nothing to do, which the coverage
    #: manifest states rather than passing over in silence.
    SOURCE_KEY = "abap_source_dir"

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.findings = []
        root = self.data.get(self.SOURCE_KEY)
        if not root:
            # Nobody asked for a source scan. That is not degraded coverage, it is
            # an absent input, and the two must not be conflated: if "you did not
            # ask me to look" armed the gate, every scan that omits one optional
            # input would come back cannot_assess and the signal would be worth
            # nothing. The coverage manifest states the absence.
            return self.findings

        path = Path(root)
        if not path.is_dir():
            # ASKED TO LOOK, COULD NOT. This returned an empty list silently, and
            # silence here is indistinguishable from clean code: a typo in
            # --abap-src produced zero findings, and --gate turned zero findings
            # into exit 0. The scan the pipeline believed it was running never ran.
            self._coverage_finding(
                check_id="ABAP-COV-001",
                title="ABAP source scan was requested but the source path is not readable",
                description=(
                    f"--abap-src named {root!r}, which is not a directory, so no "
                    "source was scanned at all. This is reported as a finding "
                    "rather than an empty result because an empty result is "
                    "indistinguishable from a clean estate: the scan did not come "
                    "back clean, it did not happen."
                ),
                affected_items=[f"{root} (not a directory)"],
                remediation=(
                    "1. Check the path given to --abap-src: it must be the root of "
                    "an unpacked abapGit export, not the archive and not a file "
                    "inside it.\n"
                    "2. In a pipeline, confirm the export step ran and wrote to the "
                    "path the scan step reads — a failed export upstream is the "
                    "usual cause.\n"
                    "3. Re-run the scan. Until it reads real source, treat its "
                    "silence on code findings as unknown, not clean."
                ),
                details={"abap_source_dir": str(root), "reason": "not_a_directory"},
            )
            return self.findings

        scanner = AbapSourceScanner(data_flow=True)
        raw = scanner.scan_tree(path)
        # Built once and shared, so this module and the ATC import agree about the
        # same object rather than reaching two verdicts from the same inventory.
        self._reach = ReachabilityIndex(self.data)
        self._emit(raw, scanner)
        return self.findings

    def _coverage_finding(self, *, check_id: str, title: str, description: str,
                          affected_items: List[str], remediation: str,
                          details: Dict[str, Any]) -> None:
        """A finding that says the scan could not see something.

        Every one of these carries ``details["degrades_coverage"] = True``, which is
        what arms the release gate's fail-closed path. The flag lives on the finding
        rather than in a list of check ids held by the caller, because the caller
        cannot know what a module has learned: `--gate` used to derive "degraded"
        by matching one hardcoded id, so every coverage check added afterwards left
        the gate returning green. A module that knows it could not look now says so
        in a way the gate reads without being taught the id.

        These are INFO because they are not vulnerabilities — nothing here says the
        code is bad. Severity is the wrong axis for them entirely: the point is not
        how serious the finding is, it is that the rest of the report is not
        evidence of absence.
        """
        details = dict(details)
        details["degrades_coverage"] = True
        details["source"] = "abap_scan"
        self.finding(
            check_id=check_id,
            title=title,
            severity=self.SEVERITY_INFO,
            category="Code & Transport Security",
            description=description,
            affected_items=affected_items,
            remediation=remediation,
            details=details,
            scope="aggregate",
        )

    def _emit(self, raw: List[Dict[str, Any]], scanner: AbapSourceScanner) -> None:
        if not scanner.files_scanned:
            # A real directory containing nothing this scanner can read. The usual
            # causes are an export that only wrote metadata sidecars, a path one
            # level too high or too low, or an empty checkout — all of which
            # produced zero findings and a green gate.
            self._coverage_finding(
                check_id="ABAP-COV-002",
                title="ABAP source scan read no source files",
                description=(
                    "The source directory was readable but contained no file this "
                    "scanner recognises as source, so no rule ran against any code. "
                    f"{scanner.metadata_skipped} metadata sidecar(s) were seen and "
                    "skipped, which is normal on its own but means the export "
                    "carried object metadata without object source. Zero findings "
                    "here is not a clean result: nothing was examined."
                ),
                affected_items=[
                    f"0 source file(s) scanned, "
                    f"{scanner.metadata_skipped} metadata file(s) skipped"],
                remediation=(
                    "1. Confirm --abap-src points at the abapGit repository root — "
                    "the level holding the object folders, not the .git directory "
                    "and not one folder above the checkout.\n"
                    "2. Confirm the export included source and not only the .xml "
                    "sidecars; an interrupted or partial abapGit pull produces "
                    "exactly this shape.\n"
                    "3. Re-run once real source is present. Do not read the current "
                    "report as evidence that the code is clean."
                ),
                details={"files_scanned": 0,
                         "metadata_skipped": scanner.metadata_skipped,
                         "reason": "no_source_files"},
            )

        if scanner.unscanned_by_suffix:
            # THE LANGUAGES THIS SCANNER DOES NOT READ, NAMED.
            #
            # A CAP project is Java or Node; a HANA artefact is .hdbprocedure;
            # a Fiori app carries .html and .properties. None of them have rules
            # here, and before this they were skipped without being counted —
            # so a scan of a repository that is 90% Java produced no findings,
            # no error, and nothing anywhere saying the code had not been read.
            # That is indistinguishable from a clean result and only one of the
            # two is true.
            top = sorted(scanner.unscanned_by_suffix.items(),
                         key=lambda kv: (-kv[1], kv[0]))
            total = sum(n for _s, n in top)
            langs = ", ".join(f"{s} ({n})" for s, n in top[:12])
            self._coverage_finding(
                check_id="ABAP-COV-004",
                title="Files in languages this scanner does not read were not examined",
                description=(
                    f"{total} file(s) in the source tree are in a language this "
                    f"scanner has no rules for and were not opened: {langs}. "
                    "The scanner reads ABAP, CDS/DCL/RAP, JavaScript/TypeScript "
                    "and the BTP descriptor files (xs-security.json, xs-app.json, "
                    "manifest.json, mta.yaml). Everything else is outside its "
                    "corpus. This is not a defect in the code that was skipped — "
                    "it is a statement about the boundary of this report, and it "
                    "is stated because silence about an unread file and silence "
                    "about a clean file look identical."
                ),
                affected_items=[f"{s} — {n} file(s) not scanned" for s, n in top[:50]],
                remediation=(
                    "Cover the listed languages with a tool that reads them and "
                    "bring the results in beside these findings; where a language "
                    "is out of scope by decision, record that decision so the gap "
                    "is a choice on the record rather than an omission."
                ),
                details={"unscanned_by_suffix": dict(top),
                         "unscanned_total": total,
                         "languages_read": sorted(scanner.files_by_language),
                         "reason": "language_not_covered"},
            )

        index = scanner.cds_index
        if index.dcl_is_missing_entirely():
            # THE FALSE POSITIVE THAT WOULD HAVE DISCREDITED THE CHECK.
            # ABAP-CDS-003 reports an exposed view that no DCL role grants on. In
            # an export that simply did not include the access-control artefacts —
            # an abapGit checkout of one package, an interrupted pull — that is
            # every view in the tree, at HIGH. The finding would be technically
            # derived and completely wrong, and a reviewer who checked two of them
            # would stop trusting the whole report. So the absence of ALL access
            # control is treated as a missing input rather than a universal defect.
            self._coverage_finding(
                check_id="ABAP-COV-005",
                title="No CDS access-control artefact was found, so view protection was not assessed",
                description=(
                    f"{len(index.exposed)} exposed CDS view(s) were found and NOT "
                    "one access-control artefact (.asdcls / DCL) exists anywhere "
                    "in this tree. Two very different situations produce that: "
                    "either no view in this package is protected at all, or the "
                    "export did not include the access controls. They are "
                    "indistinguishable from here, and the second is far more "
                    "common — so ABAP-CDS-003 did not run rather than report "
                    "every view as unprotected on evidence it does not have. "
                    "Read this as the check not having been performed."
                ),
                affected_items=[
                    "%d exposed view(s), 0 DCL artefacts" % len(index.exposed),
                    "views seen: %s" % ", ".join(sorted(index.exposed)[:20]),
                ],
                remediation=(
                    "1. Confirm the export includes CDS access controls — in "
                    "abapGit they are the .asdcls files, and a package filter or "
                    "an interrupted pull is the usual reason they are absent.\n"
                    "2. Re-export including DCL and re-run.\n"
                    "3. If the package genuinely contains no access control, that "
                    "is itself the finding — and it will be reported per view "
                    "once the scan can tell the difference."
                ),
                details={"exposed_views": len(index.exposed),
                         "dcl_files": 0,
                         "reason": "no_access_control_artefacts"},
            )
        elif index.unexposed_roleless_views():
            # Not a defect and not a pass: SAP's guidance is that a basic view
            # consumed only through another view is SUPPOSED to have no role. The
            # number is published so a reader knows how many views were set aside
            # on that reasoning rather than examined.
            skipped = index.unexposed_roleless_views()
            self._coverage_finding(
                check_id="ABAP-COV-006",
                title="Views without an access-control role whose exposure could not be established",
                description=(
                    f"{skipped} CDS view(s) have no DCL role and no evidence in "
                    "this tree of being exposed — not published as OData, not "
                    "named by a service definition, not given a RAP behaviour. "
                    "They are NOT reported as unprotected, because SAP's own "
                    "guidance is that a view consumed only as a data source "
                    "inside another view is supposed to have no role of its own: "
                    "implicit access control applies to direct access, and "
                    "wrapping an unprotected entity in a view that does carry a "
                    "role is the documented pattern. But exposure was judged from "
                    "what this tree contains, and a consumer outside it would not "
                    "be visible. This is the population that judgement set aside."
                ),
                affected_items=["%d view(s) with no role and no exposure evidence"
                                % skipped],
                remediation=(
                    "1. Confirm these views are consumed only through other CDS "
                    "entities, and not read directly by ABAP, an OData service or "
                    "an SADL query defined outside this export.\n"
                    "2. Widen the export to include the consuming service "
                    "definitions and behaviour definitions if it does not already, "
                    "so exposure can be established rather than assumed.\n"
                    "3. Any of these that IS reached directly needs a role, and "
                    "the scan cannot tell you which from this tree alone."
                ),
                details={"roleless_unexposed_views": skipped,
                         "reason": "exposure_not_established"},
            )

        if scanner.unreadable:
            # Collected by scan_tree since it was written and never reported: the
            # files that raised on read were dropped from the scan in silence.
            self._coverage_finding(
                check_id="ABAP-COV-003",
                title="Some source files could not be read and were not scanned",
                description=(
                    f"{len(scanner.unreadable)} file(s) raised an error on read and "
                    f"were skipped. {scanner.files_scanned} file(s) were scanned "
                    "successfully, so this report covers most of the estate but not "
                    "all of it — and the gap is not visible in the findings list, "
                    "which is why it is stated here."
                ),
                affected_items=list(scanner.unreadable[:50]),
                remediation=(
                    "1. Check the permissions and encoding of the listed files; a "
                    "locked file or a broken symlink in the export is the usual "
                    "cause.\n"
                    "2. Re-export or repair them and re-run.\n"
                    "3. Until then, treat those objects as unscanned rather than "
                    "clean."
                ),
                details={"unreadable_count": len(scanner.unreadable),
                         "files_scanned": scanner.files_scanned,
                         "unreadable": list(scanner.unreadable[:50]),
                         "reason": "unreadable_files"},
            )

        confirmed = [f for f in raw if f["confidence"] == "confirmed"]
        rest = [f for f in raw if f["confidence"] != "confirmed"]

        for f in confirmed:
            self._finding(f, [f], scope="object")

        grouped: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        for f in rest:
            grouped.setdefault((f["rule_id"], f["object"]), []).append(f)
        for (_rid, _obj), members in sorted(grouped.items()):
            self._finding(members[0], members, scope="aggregate")

        if scanner.lex_degraded:
            self.finding(
                check_id="ABAP-LEX-001",
                title="Source the scanner could not lex reliably",
                severity=self.SEVERITY_INFO,
                category="Code & Transport Security",
                description=(
                    f"{scanner.lex_degraded} statement(s) ran past the runaway "
                    "bound, which means the lexer lost track of a literal or "
                    "string template and the statement boundaries after that point "
                    "are unreliable. Findings in the affected objects are reported "
                    "as usual, but their absence is NOT evidence of clean code: a "
                    "mis-lexed file produces a quiet, plausible-looking report. "
                    "This is stated rather than counted silently because "
                    "'nothing to find' and 'could not look' are indistinguishable "
                    "in a report and only one of them is true."
                ),
                affected_items=[
                    f"{scanner.lex_degraded} statement(s) flushed by the runaway "
                    "guard during this scan"],
                remediation=(
                    "1. Identify the objects reported with a degraded statement: "
                    "the cause is almost always an unterminated literal or a "
                    "string template the lexer cannot close.\n"
                    "2. Re-export those objects from abapGit and confirm the "
                    "source is complete and not truncated in transit.\n"
                    "3. If the source is intact and complete, the lexer has a gap "
                    "— raise it, because the statement in question is a case this "
                    "scanner does not yet model."
                ),
                details={"lex_degraded": scanner.lex_degraded, "source": "abap_scan",
                         # The gate reads this flag, not this check's id.
                         "degrades_coverage": True},
                scope="aggregate",
            )

        suppressed = [f for f in raw if f["suppressed_by_nosec"]]
        if suppressed:
            self.finding(
                check_id="ABAP-NOSEC-001",
                title="Findings suppressed by #NOSEC markers in source",
                severity=self.SEVERITY_INFO,
                category="Code & Transport Security",
                description=(
                    f"{len(suppressed)} finding(s) carry a #NOSEC marker in the "
                    "source. They are reported rather than removed: a suppression "
                    "that leaves no record is indistinguishable from a clean estate, "
                    "and the decision belongs in this product's dismissal workflow, "
                    "which has an audit trail and an expiry."
                ),
                affected_items=["#NOSEC markers present in the scanned source"],
                remediation=(
                    "1. Review each marked statement: a #NOSEC is a claim that the "
                    "code is safe, made by whoever wrote it, with no expiry.\n"
                    "2. Where the claim holds, dismiss the finding here instead so "
                    "the decision is recorded, attributed and re-reviewed.\n"
                    "3. Where it does not, fix the code and delete the marker."
                ),
                details={"suppressed_count": len(suppressed), "source": "abap_scan"},
                scope="aggregate",
            )

    def _finding(self, lead: Dict[str, Any], members: List[Dict[str, Any]],
                 *, scope: str) -> None:
        obj = lead["object"]
        lines = [m["line"] for m in members]
        confidence = lead["confidence"]

        evidence = {
            "confirmed": "tainted input provably reaches this statement",
            "tentative": "the data-flow walk found no evidence either way",
            "pattern-only": "matched by statement pattern; no data-flow evidence",
        }[confidence]
        # F4. Reported as evidence rather than as a fourth confidence class,
        # because `finding.taint_confidence` is CHECK-constrained to the three
        # above and the taint classes are what FAIR prices.
        if lead.get("literal_operand"):
            evidence = ("the dynamically-named token is a compile-time literal, "
                        "so there is no value for a caller to control — recorded "
                        "as inventory, not as an injection")

        self.finding(
            check_id=lead["rule_id"],
            title=f"{lead['name']} — {obj}",
            severity=lead["severity"],
            category="Code & Transport Security",
            description=(
                f"{lead['description']} Found in {obj} at line"
                f"{'s' if len(lines) > 1 else ''} "
                f"{', '.join(str(x) for x in lines[:20])}. Evidence: {evidence}."
            ),
            affected_items=[f"{obj} line {m['line']}: {m['statement'][:120]}"
                            for m in members[:50]],
            remediation=lead["recommendation"],
            references=[r for r in (lead.get("cwe"),) if r] +
                       ["SAP Security Baseline — secure custom code"],
            details={
                "source": "abap_scan",
                "cwe": lead.get("cwe"),
                "confidence": confidence,
                "occurrences": len(members),
                "file": lead["file"],
                "lines": lines[:200],
                "snippet": lead["snippet"],
                "taint_flow": lead.get("flow"),
                "suppressed_by_source_marker": lead["suppressed_by_nosec"],
                # True when the runaway guard had to flush the statement this
                # finding sits in — its boundaries, and therefore its match, are
                # not trustworthy.
                "lex_degraded": lead.get("lex_degraded", False),
                # The dynamically-named token was a compile-time literal.
                "literal_operand": lead.get("literal_operand", False),
                **stamp({}, getattr(self, "_reach", None), obj),
            },
            affected_objects=[{"type": "program", "name": obj}],
            # Identity: the object, qualified by the offending statement. Never the
            # line number.
            subject=[{"type": "program", "name": obj,
                      "qualifier": lead["statement"][:200]}]
            if scope == "object" else [{"type": "program", "name": obj}],
            scope=scope,
        )
