# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
Security Parameters Auditor
============================
Validates SAP profile parameters (RZ10/RZ11/RSPARAM exports) against the
MANDATORY hardening baseline for AS ABAP in SAP Enterprise Cloud Services —
SAP Note 3250501 — plus the small set of legacy checks that note does not cover.

────────────────────────────────────────────────────────────────────────────────
WHERE THE EXPECTED VALUES COME FROM, AND WHY NOT FROM THIS FILE
────────────────────────────────────────────────────────────────────────────────
`data/ecs_hardening_3250501.json` holds the extracted FACTS of note 3250501 v46:
for each parameter, the ECS standard value and the exceptions SAP explicitly
permits. Nothing in this module hand-types one of those values.

That is not tidiness. This module previously required `login/min_password_lng >= 8`
while the note mandates >= 15, so a system SAP considers non-compliant was told it
passed. One mistyped digit reproduces that defect, and it fails in the direction
nobody notices — a false CLEAN. So the numbers live in the JSON, this file supplies
only OUR judgement (severity, category, wording, remediation), and `ECS_META` is
joined to the JSON by parameter name with a test that fails the moment either side
gains a parameter the other lacks.

SAP's prose is copyright and is NOT in the JSON. Every description and remediation
here is written from scratch.

────────────────────────────────────────────────────────────────────────────────
THE COMPLIANT VALUE IS WHATEVER THE NOTE SAYS
────────────────────────────────────────────────────────────────────────────────
Some values SAP MANDATES read as insecure if you reason from the parameter name:

    icf/set_HTTPonly_flag_on_cookies = 0      <-- the ECS standard
    snc/accept_insecure_gui          = 1      <-- the ECS standard (another module)

A check that treats "insecure-sounding" as "finding" reports SAP's own baseline as
a defect on every ECS system in existence. So compliance here is decided ONLY by
the JSON: the ECS standard value, or any exception the `allowed` list permits. A
system sitting on a permitted exception is COMPLIANT and produces no finding.

────────────────────────────────────────────────────────────────────────────────
WHAT THE OLD OPERATOR SET COULD NOT SAY
────────────────────────────────────────────────────────────────────────────────
`==`, `>=`, `<=`, `!=`, `in`, `not_in`, `contains` cannot express what the note
actually mandates, and each gap let a non-compliant system pass:

  * A RANGE — `login/password_expiration_time` is "30 to 90". A single-sided
    `<= 90` passes a system set to 10 days, which SAP fails.
  * NOT-ZERO — several read "<= 3 (not 0)". Zero DISABLES the control outright and
    is the most dangerous value the parameter can hold, yet it sails through `<=`.
  * The exception list — `login/password_change_for_SSO` permits 2 and 3 as well
    as the standard 1. Demanding the standard alone invents a finding.

`_compile_spec` implements exactly the four grammars the note uses ("N to M",
"<=N not 0", ">=N", and a literal). An unrecognised grammar is NOT guessed at: the
parameter is skipped (the safe direction — silence, not a false accusation) and
recorded in `UNPARSED_SPECS`, which a test asserts is empty. So a future edit to
the JSON that introduces a fifth grammar fails the build instead of quietly
disabling a check.

────────────────────────────────────────────────────────────────────────────────
WHAT IS CHECKED STRUCTURALLY RATHER THAN EXACTLY
────────────────────────────────────────────────────────────────────────────────
Several mandated values are paths containing `$(DIR_GLOBAL)` placeholders, or
compound settings whose remaining sub-parameters legitimately differ per host and
SID (`gw/logging`, `icm/HTTP/logging_0`, `login/password_hash_algorithm`). A
byte-exact comparison on those fires on every real system, which is the same
false-positive class this file exists to avoid. `_STRUCTURAL` names them, verifies
the part that IS verifiable from a profile export, and every such finding states in
its own description what was checked and what was not.

────────────────────────────────────────────────────────────────────────────────
SCOPE AND OVERLAPS
────────────────────────────────────────────────────────────────────────────────
  * `snc/*` and `igs/snc/*` are deliberately NOT handled here — they belong to the
    cryptographic-posture module. `SNC_PREFIXES` is the single point of that split.
  * The note's 18 `configuration_items` (client settings, standard users, ICF
    services, gateway ACL file CONTENT) are not profile parameters and cannot be
    answered from `security_params`; they are out of scope for this module.
  * `modules/baseline_params.py` independently checks about a dozen of the same
    parameters against the SAP Security Baseline Template, whose thresholds are
    NOT identical to the ECS mandate. Where both fire, a customer sees two findings
    for one parameter. That de-duplication is a wiring decision and is not made
    here, because this module does not own that file.

Data source:
  - security_params.csv → RSPARAM / RZ11 / RZ10 export (NAME, VALUE)
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

from modules.base_auditor import BaseAuditor

# --------------------------------------------------------------------------- #
#  The note itself                                                            #
# --------------------------------------------------------------------------- #

ECS_NOTE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "ecs_hardening_3250501.json")

#: The only SAP note number this module cites. Note 3250501 references nine others
#: (65968, 2654391, 3584984, 3674774, 2715519, 3318423, 3346659, 3480723, 3381209),
#: but which of them governs which parameter is not recorded in the extract — so
#: attaching one to a specific check would be inventing a citation. One certain
#: reference beats ten plausible ones.
ECS_NOTE_REF = "SAP Note 3250501 — mandatory hardening for AS ABAP in SAP ECS"

#: Owned by the cryptographic-posture module. Kept as one constant so the split is
#: visible in a single place rather than implied by scattered `startswith` calls.
SNC_PREFIXES: Tuple[str, ...] = ("snc/", "igs/snc/")

#: (parameter, spec) pairs whose `allowed` grammar this module does not understand.
#: Populated at rule-build time; asserted empty by tests/test_ecs_parameters.py.
#: A parameter that lands here is SKIPPED, never guessed at in either direction.
UNPARSED_SPECS: List[Tuple[str, str]] = []


def load_ecs_note(path: Optional[str] = None) -> Dict[str, Any]:
    """The extracted facts of note 3250501, or an empty shell if unreadable.

    Never raises. A missing or corrupt data file must degrade this module to its
    legacy checks, not take down every scan that touches profile parameters.
    """
    try:
        with open(path or ECS_NOTE_PATH, "r", encoding="utf-8") as handle:
            note = json.load(handle)
    except (OSError, ValueError):
        return {"source": {}, "parameters": {}, "configuration_items": [],
                "referenced_notes": []}
    if not isinstance(note, dict) or not isinstance(note.get("parameters"), dict):
        return {"source": {}, "parameters": {}, "configuration_items": [],
                "referenced_notes": []}
    return note


# --------------------------------------------------------------------------- #
#  The value grammars the note uses                                           #
# --------------------------------------------------------------------------- #

_RANGE_RE = re.compile(r"^(-?\d+)\s+to\s+(-?\d+)$", re.IGNORECASE)
_LE_NONZERO_RE = re.compile(r"^<=\s*(-?\d+)\s+not\s+0$", re.IGNORECASE)
_GE_RE = re.compile(r"^>=\s*(-?\d+)$")
_LE_RE = re.compile(r"^<=\s*(-?\d+)$")

#: What separates a LITERAL permitted value ("U", "expansion", "TRUE", a
#: cipher-suite string) from a comparison none of the four grammars above parsed.
#:
#: Without it the literal branch is a catch-all and the refusal path below is
#: unreachable: a future `allowed` entry like "<=8 or 0" would compile to "the
#: permitted value is the nine-character string '<=8 or 0'", which no real value
#: can equal. The exception SAP granted would silently vanish, compliant systems
#: sitting on it would be accused, `UNPARSED_SPECS` would stay empty and the test
#: guarding it would still pass — it can only mean something if the refusal is
#: reachable, which `test_a_novel_grammar_is_refused_and_recorded` now proves.
#:
#: Deliberately narrow — only the vocabulary comparisons are built from. No real
#: literal in the note ("0", "expansion", "545:PFS:HIGH::EC_X25519:EC_P256:EC_HIGH")
#: contains any of it, so no permitted value is refused by mistake.
_COMPARISON_VOCABULARY_RE = re.compile(
    r"[<>]|\bto\b|\bnot\b|\bor\b|\band\b|^-?\d+\s*-\s*-?\d+$", re.IGNORECASE)


def _as_int(value: Any) -> Optional[int]:
    """`value` as an int, or None when it is not one."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _norm(value: Any) -> str:
    """Case- and whitespace-insensitive form for comparing string values.

    Profile exports vary in spacing and case ("TRUE"/"true", the cipher-suite
    string with or without padding). Accepting those spellings is the safe
    direction: the alternative is a finding raised because a CSV had a space in it.
    """
    return " ".join(str(value).split()).casefold()


def _literal_pred(expected: str) -> Callable[[str], bool]:
    """Equality against one permitted spelling.

    Numeric when BOTH sides are numeric, so "01", " 1 " and "1" are one value and
    not three; textual otherwise.
    """
    expected_int = _as_int(expected)
    expected_text = _norm(expected)

    def pred(actual: str) -> bool:
        if expected_int is not None:
            actual_int = _as_int(actual)
            if actual_int is not None:
                return actual_int == expected_int
        return _norm(actual) == expected_text

    return pred


def _compile_spec(spec: str) -> Optional[Callable[[str], bool]]:
    """One entry of the note's `allowed` list -> a predicate, or None if unknown.

    None is a REFUSAL, not a default. The caller records it and skips the
    parameter; inventing an interpretation of an unrecognised spec is how a check
    starts silently passing everything.
    """
    text = str(spec).strip()

    match = _RANGE_RE.match(text)
    if match:
        low, high = int(match.group(1)), int(match.group(2))
        return lambda actual: (
            (value := _as_int(actual)) is not None and low <= value <= high)

    match = _LE_NONZERO_RE.match(text)
    if match:
        high = int(match.group(1))
        # The whole point of this grammar is that 0 is excluded — it switches the
        # control off entirely. The lower bound is 1 rather than "!= 0" because a
        # negative counter is not a permitted setting either, and `!= 0` would
        # accept one.
        return lambda actual: (
            (value := _as_int(actual)) is not None and 1 <= value <= high)

    match = _GE_RE.match(text)
    if match:
        low = int(match.group(1))
        return lambda actual: (
            (value := _as_int(actual)) is not None and value >= low)

    match = _LE_RE.match(text)
    if match:
        high = int(match.group(1))
        return lambda actual: (
            (value := _as_int(actual)) is not None and value <= high)

    if text and not _COMPARISON_VOCABULARY_RE.search(text):
        return _literal_pred(text)
    return None


# --------------------------------------------------------------------------- #
#  Structural checks — values that legitimately vary per host and SID          #
# --------------------------------------------------------------------------- #

def _kv(value: str, key: str) -> Optional[str]:
    """The `KEY=value` sub-parameter out of a compound profile value."""
    match = re.search(rf"\b{re.escape(key)}\s*=\s*([^,;\s]+)", str(value), re.IGNORECASE)
    return match.group(1) if match else None


def _action_letters(value: str) -> str:
    return _kv(value, "ACTION") or ""


def _gw_logging(actual: str, ecs: str) -> bool:
    """Every gateway log action the note mandates is switched on.

    The letters are CASE-SENSITIVE — `S` and `s` are different actions — so this
    compares sets of characters, not a casefolded string. Additional actions,
    LOGFILE and rotation settings are ignored: they are per-host and adding one
    does not weaken the mandated set.
    """
    required = set(_action_letters(ecs))
    present = set(_action_letters(actual))
    return bool(required) and required.issubset(present)


def _path_configured(actual: str, ecs: str) -> bool:
    """A file path is configured at all.

    The mandated value is `$(DIR_GLOBAL)$(DIR_SEP)…$(FT_DAT)`, which resolves to a
    different absolute path on every host, and the file's CONTENT — the actual ACL
    — is an OS artifact that no profile export contains. So the only honest answer
    from this data is whether a path is set.
    """
    return bool(str(actual).strip())


def _icm_logging(actual: str, ecs: str) -> bool:
    """An HTTP(S) access log is configured for a URL prefix.

    LOGFILE, LOGFORMAT and rotation are per-host; PREFIX is the sub-parameter that
    decides whether anything is logged at all.
    """
    return bool(_kv(actual, "PREFIX"))


def _icm_redirect_prot(actual: str, ecs: str) -> bool:
    """The redirect declares the protocol the note mandates (https).

    Only the PROT sub-parameter is compared. The rest of a redirect rule — host,
    port, target path — is site-specific by design.
    """
    required = _norm(_kv(ecs, "PROT") or "")
    present = _norm(_kv(actual, "PROT") or "")
    return bool(required) and present == required


def _icm_security_log_level(actual: str, ecs: str) -> bool:
    """LEVEL is at least the mandated level.

    `>=` rather than `==`: a higher security-log level records strictly more, so
    demanding equality would report a system that logs MORE than SAP requires.
    """
    required = _as_int(_kv(ecs, "LEVEL"))
    present = _as_int(_kv(actual, "LEVEL"))
    if required is None:
        return True
    return present is not None and present >= required


def _password_hash(actual: str, ecs: str) -> bool:
    """The stored-password hash is the mandated construction or stronger.

    Compared: encoding, algorithm, iterations (>=), saltsize (>=). The two numeric
    work factors use `>=` because raising them is a hardening, and a system that
    exceeds the note must not be reported as deviating from it. `algorithm` and
    `encoding` are compared for equality — they name a construction rather than a
    strength, and this module has no basis for ranking one construction above
    another.
    """
    for key in ("encoding", "algorithm"):
        required = _kv(ecs, key)
        if required is None:
            continue
        present = _kv(actual, key)
        if present is None or _norm(present).replace("-", "") != _norm(required).replace("-", ""):
            return False
    for key in ("iterations", "saltsize"):
        required = _as_int(_kv(ecs, key))
        if required is None:
            continue
        present = _as_int(_kv(actual, key))
        if present is None or present < required:
            return False
    return True


def _admin_users(actual: str, ecs: str) -> bool:
    """An explicit, wildcard-free administrator list.

    The mandated list names SAP's own ECS agent accounts, but which operator
    accounts a landscape legitimately carries varies, so requiring the exact three
    names would fire on real systems. An empty list or a wildcard, on the other
    hand, is unambiguously wrong whatever the landscape.
    """
    text = str(actual).strip()
    return bool(text) and "*" not in text


#: parameter -> how to verify it, what "expected" reads as, and the caveat that
#: goes into the finding so the reader knows the limit of the check.
_STRUCTURAL: Dict[str, Dict[str, Any]] = {
    "gw/logging": {
        "check": _gw_logging,
        "expected": lambda ecs: f"ACTION= containing every letter of '{_action_letters(ecs)}'",
        "caveat": ("Verified: gateway logging is active and every log action the "
                   "baseline mandates is switched on. Not verified: the log file "
                   "name, rotation and any additional actions, which are per-host."),
    },
    "gw/prxy_info": {
        "check": _path_configured,
        "expected": lambda ecs: "a configured proxy-info ACL file path",
        "caveat": ("Verified: a path is configured. Not verified: that the file "
                   "exists or what rules it contains — the ECS value is a "
                   "$(DIR_GLOBAL) placeholder and the file is an OS artifact no "
                   "profile export carries."),
    },
    "gw/reg_info": {
        "check": _path_configured,
        "expected": lambda ecs: "a configured reginfo ACL file path",
        "caveat": ("Verified: a path is configured. Not verified: that the file "
                   "exists or what rules it contains — the ECS value is a "
                   "$(DIR_GLOBAL) placeholder and the file is an OS artifact no "
                   "profile export carries."),
    },
    "gw/sec_info": {
        "check": _path_configured,
        "expected": lambda ecs: "a configured secinfo ACL file path",
        "caveat": ("Verified: a path is configured. Not verified: that the file "
                   "exists or what rules it contains — the ECS value is a "
                   "$(DIR_GLOBAL) placeholder and the file is an OS artifact no "
                   "profile export carries."),
    },
    "ms/acl_info": {
        "check": _path_configured,
        "expected": lambda ecs: "a configured message-server ACL file path",
        "caveat": ("Verified: a path is configured. Not verified: the file's "
                   "contents — the ECS value is built entirely from placeholders "
                   "and the ACL itself is an OS artifact."),
    },
    "icm/HTTP/logging_0": {
        "check": _icm_logging,
        "expected": lambda ecs: "a logging rule with a PREFIX= sub-parameter",
        "caveat": ("Verified: server-side HTTP access logging is switched on for a "
                   "URL prefix. Not verified: LOGFILE, LOGFORMAT or rotation, "
                   "which vary per host."),
    },
    "icm/HTTP/logging_client_0": {
        "check": _icm_logging,
        "expected": lambda ecs: "a logging rule with a PREFIX= sub-parameter",
        "caveat": ("Verified: client-side HTTP access logging is switched on for a "
                   "URL prefix. Not verified: LOGFILE, LOGFORMAT or rotation, "
                   "which vary per host."),
    },
    "icm/HTTP/redirect_0": {
        "check": _icm_redirect_prot,
        "expected": lambda ecs: f"a redirect rule with {_kv(ecs, 'PROT') and 'PROT=' + _kv(ecs, 'PROT')}",
        "caveat": ("Verified: the redirect declares the mandated protocol. Not "
                   "verified: the host, port and target path of the rule, which "
                   "are site-specific."),
    },
    "icm/security_log": {
        "check": _icm_security_log_level,
        "expected": lambda ecs: f"LEVEL >= {_as_int(_kv(ecs, 'LEVEL'))}",
        "caveat": ("Verified: the security-log LEVEL. Not verified: the log file "
                   "name or size limit, which are per-host."),
    },
    "login/password_hash_algorithm": {
        "check": _password_hash,
        "expected": lambda ecs: ecs,
        "caveat": ("Verified: encoding and algorithm match the mandated "
                   "construction, and iterations and saltsize are at least the "
                   "mandated work factors (a higher value is accepted as a "
                   "hardening)."),
    },
    "service/admin_users": {
        "check": _admin_users,
        "expected": lambda ecs: "a non-empty administrator list with no '*' wildcard",
        "caveat": ("Verified: the list is set and contains no wildcard. Not "
                   "verified: the exact account names — the mandated list names "
                   "SAP's ECS agent accounts and the operator accounts a landscape "
                   "carries legitimately differ, so an exact match would fire on "
                   "real systems."),
    },
}


# --------------------------------------------------------------------------- #
#  OUR judgement: severity, category, wording, remediation                    #
# --------------------------------------------------------------------------- #
#
# Joined to the JSON by parameter name. NO expected values here — those come from
# the note. `desc` states what the control does; the runtime appends the actual
# value, the ECS standard and any permitted exception, so no description repeats a
# number that could drift out of step with the JSON.
#
# Severities match the risk of the likely deviation and are not inflated: most
# single parameters are MEDIUM. CRITICAL is reserved for controls whose failure
# removes the audit trail or hands over an unauthenticated path in.
#
# Every `category` string must already exist in
# `modules/compliance_mapping.py:CATEGORY_THEMES`; a category that does not is
# still reported but vanishes silently from every compliance panel.

_ECS_REMEDIATION_TAIL = (
    "In an ECS/RISE tenant profile parameters are maintained by SAP: raise a "
    "service request quoting SAP Note 3250501 rather than attempting the change "
    "in RZ10. Re-export the profile parameters (RSPARAM) afterwards and confirm "
    "the active value on every instance.")

ECS_META: Dict[str, Dict[str, str]] = {

    # ── ABAP authorization engine ────────────────────────────────────────────
    "auth/object_disabling_active": {
        "severity": "HIGH", "category": "ABAP Authorization & Critical Access",
        "desc": ("Governs whether authorization objects may be globally switched "
                 "off for the whole system. Where that is possible, a single "
                 "change silently removes an authorization check everywhere it is "
                 "coded, and the roles still look correct."),
        "fix": "Set auth/object_disabling_active to the ECS standard value.",
    },
    "auth/no_check_in_some_cases": {
        "severity": "HIGH", "category": "ABAP Authorization & Critical Access",
        "desc": ("Controls whether the Profile Generator evaluates the SU24 check "
                 "indicators when deriving authorization defaults for roles. With "
                 "it inactive, roles are built from a weaker set of defaults than "
                 "the ones maintained for the transactions they contain."),
        "fix": ("Set auth/no_check_in_some_cases to the ECS standard value and keep "
                "SU24 check indicators maintained (SU25 after upgrades)."),
    },
    "auth/check/calltransaction": {
        "severity": "MEDIUM", "category": "ABAP Authorization & Critical Access",
        "desc": ("Decides how strictly the transaction-start authorization is "
                 "re-checked when one transaction is invoked from another with "
                 "CALL TRANSACTION. A weak setting lets a user reach a transaction "
                 "indirectly that they cannot start directly."),
        "fix": "Set auth/check/calltransaction to the ECS standard value.",
    },
    "auth/rfc_authority_check": {
        "severity": "HIGH", "category": "RFC Security",
        "desc": ("Controls the S_RFC authorization check applied to remote function "
                 "calls. Weakened, an authenticated RFC caller can invoke "
                 "remote-enabled function modules the role model never granted."),
        "fix": "Set auth/rfc_authority_check to the ECS standard value.",
    },

    # ── Debugging and tracing ────────────────────────────────────────────────
    "abap/ext_debugging_possible": {
        "severity": "MEDIUM", "category": "Development Controls",
        "desc": ("Controls whether external debugging of running sessions is "
                 "possible. Debugging a foreign session exposes that session's "
                 "data in memory and, with Debug/Replace, allows its behaviour to "
                 "be altered."),
        "fix": "Set abap/ext_debugging_possible to the ECS standard value.",
    },
    "gw/accept_remote_trace_level": {
        "severity": "MEDIUM", "category": "Development Controls",
        "desc": ("Controls whether a remote peer may raise the RFC gateway's trace "
                 "level. Where it can, a caller can turn tracing up and harvest "
                 "the payloads that then land in the trace files."),
        "fix": "Set gw/accept_remote_trace_level to the ECS standard value.",
    },
    "icm/accept_remote_trace_level": {
        "severity": "MEDIUM", "category": "Development Controls",
        "desc": ("Controls whether a remote peer may raise the ICM's trace level. "
                 "Where it can, a caller can turn tracing up and harvest the HTTP "
                 "payloads that then land in the trace files."),
        "fix": "Set icm/accept_remote_trace_level to the ECS standard value.",
    },
    "rdisp/accept_remote_trace_level": {
        "severity": "MEDIUM", "category": "Development Controls",
        "desc": ("Controls whether a remote peer may raise the dispatcher's trace "
                 "level. Where it can, a caller can turn tracing up and harvest "
                 "the data that then lands in the work-process traces."),
        "fix": "Set rdisp/accept_remote_trace_level to the ECS standard value.",
    },
    "rdisp/TRACE_HIDE_SEC_DATA": {
        "severity": "MEDIUM", "category": "Data Protection & Privacy",
        "desc": ("Masks security-relevant data — credentials and tokens among them "
                 "— before it is written to a trace file. Traces are routinely "
                 "collected for support and travel outside the system, so anything "
                 "unmasked in them has effectively left the boundary."),
        "fix": "Set rdisp/TRACE_HIDE_SEC_DATA to the ECS standard value.",
    },

    # ── DBA cockpit ──────────────────────────────────────────────────────────
    "dbs/dba/ccms_maintenance": {
        "severity": "LOW", "category": "Security Parameters",
        "desc": ("Governs which database-administration functions the CCMS / DBA "
                 "Cockpit layer exposes inside the ABAP system."),
        "fix": "Set dbs/dba/ccms_maintenance to the ECS standard value.",
    },
    "dbs/dba/ccms_security_level": {
        "severity": "LOW", "category": "Security Parameters",
        "desc": ("Sets how restrictively the CCMS / DBA Cockpit layer treats "
                 "database-administration requests."),
        "fix": "Set dbs/dba/ccms_security_level to the ECS standard value.",
    },

    # ── RFC gateway ──────────────────────────────────────────────────────────
    "gw/acl_mode": {
        "severity": "HIGH", "category": "Gateway Security",
        "desc": ("Decides how the RFC gateway behaves when no explicit ACL rule "
                 "matches. A permissive default lets an external program register "
                 "with the gateway and receive RFC traffic — the misconfiguration "
                 "class behind the 10KBLAZE gateway attacks."),
        "fix": ("Set gw/acl_mode to the ECS standard value and maintain explicit "
                "secinfo and reginfo ACL files."),
    },
    "gw/acl_mode_proxy": {
        "severity": "LOW", "category": "Gateway Security",
        "desc": ("The equivalent default for gateway proxy requests: how the "
                 "gateway behaves when no prxyinfo rule matches."),
        "fix": "Set gw/acl_mode_proxy to the ECS standard value.",
    },
    "gw/rem_start": {
        "severity": "HIGH", "category": "Gateway Security",
        "desc": ("Controls how the gateway may start external programs on request. "
                 "Remote program start is a direct path from an RFC connection to "
                 "command execution on the application server host."),
        "fix": "Set gw/rem_start to the ECS standard value.",
    },
    "gw/logging": {
        "severity": "HIGH", "category": "Gateway Security",
        "desc": ("Selects which gateway actions are written to the gateway log. "
                 "Without the mandated actions there is no record of external "
                 "program registration or of connections the ACLs rejected, so a "
                 "gateway attack leaves no trail to investigate."),
        "fix": ("Set gw/logging so that every log action the ECS baseline mandates "
                "is enabled, and confirm in SMGW that the log is being written."),
    },
    "gw/prxy_info": {
        "severity": "HIGH", "category": "Gateway Security",
        "desc": ("Names the prxyinfo ACL file that decides which systems may use "
                 "this gateway as a proxy. Unset, the proxy path is governed by "
                 "the default behaviour alone."),
        "fix": ("Point gw/prxy_info at a maintained prxyinfo ACL file and reload it "
                "in SMGW (Goto > Expert Functions > Reread)."),
    },
    "gw/reg_info": {
        "severity": "CRITICAL", "category": "Gateway Security",
        "desc": ("Names the reginfo ACL file that decides which external programs "
                 "may register with the RFC gateway. Unset, an attacker who can "
                 "reach the gateway port can register a program and have RFC "
                 "traffic routed to it."),
        "fix": ("Point gw/reg_info at a maintained reginfo ACL file listing only "
                "the programs that must register, and reload it in SMGW."),
    },
    "gw/sec_info": {
        "severity": "CRITICAL", "category": "Gateway Security",
        "desc": ("Names the secinfo ACL file that decides which programs the "
                 "gateway may start and for whom. Unset, the gateway's program "
                 "start path is unconstrained by an explicit allowlist."),
        "fix": ("Point gw/sec_info at a maintained secinfo ACL file with "
                "restrictive rules, and reload it in SMGW."),
    },
    "gw/reg_no_conn_info": {
        "severity": "HIGH", "category": "Gateway Security",
        "desc": ("A bit mask enabling the gateway's stricter interpretations of "
                 "the reginfo and secinfo rules. Bits left off mean rules that "
                 "look restrictive in the file are not enforced as written."),
        "fix": "Set gw/reg_no_conn_info to the ECS standard value.",
    },

    # ── ICF / web tier ───────────────────────────────────────────────────────
    "icf/reject_expired_passwd": {
        "severity": "MEDIUM", "category": "Network & Service Exposure",
        "desc": ("Decides whether an HTTP logon is refused when the account's "
                 "password has expired. Accepting one lets an account whose "
                 "credential should have been rotated keep working over the web "
                 "channel indefinitely."),
        "fix": "Set icf/reject_expired_passwd to the ECS standard value.",
    },
    "icf/user_recheck": {
        "severity": "MEDIUM", "category": "Network & Service Exposure",
        "desc": ("Controls how often the ICF runtime re-validates the logged-on "
                 "user during a session rather than trusting cached state. Without "
                 "it, locking or expiring a user does not necessarily end the "
                 "sessions they already hold."),
        "fix": "Set icf/user_recheck to the ECS standard value.",
    },
    "icf/set_HTTPonly_flag_on_cookies": {
        "severity": "MEDIUM", "category": "Network & Service Exposure",
        "desc": ("Governs the HttpOnly attribute on ICF session cookies. READ THE "
                 "MANDATED VALUE, NOT THE PARAMETER NAME: the ECS baseline fixes "
                 "this parameter at a specific value, and a system sitting on it "
                 "is compliant however the number reads. This check reports only a "
                 "deviation from the value SAP mandates."),
        "fix": "Set icf/set_HTTPonly_flag_on_cookies to the ECS standard value.",
    },

    # ── ICM / TLS ────────────────────────────────────────────────────────────
    "icm/HTTP/logging_0": {
        "severity": "MEDIUM", "category": "Audit Logging",
        "desc": ("Configures the ICM's server-side HTTP access log. Without it "
                 "there is no request-level record of who reached which service "
                 "over the web channel, which is the first thing an investigation "
                 "asks for."),
        "fix": ("Configure icm/HTTP/logging_0 with a URL PREFIX so all inbound "
                "HTTP(S) requests are logged, plus a log file and rotation."),
    },
    "icm/HTTP/logging_client_0": {
        "severity": "MEDIUM", "category": "Audit Logging",
        "desc": ("Configures the ICM's client-side HTTP access log — the record of "
                 "outbound calls this system makes. Without it, data leaving over "
                 "HTTP is unrecorded."),
        "fix": ("Configure icm/HTTP/logging_client_0 with a URL PREFIX so outbound "
                "HTTP(S) calls are logged, plus a log file and rotation."),
    },
    "icm/HTTP/redirect_0": {
        "severity": "MEDIUM", "category": "Transport Security",
        "desc": ("Redirects inbound plain-HTTP requests onto the encrypted "
                 "channel. Without it a client that arrives on the HTTP port stays "
                 "there, and its credentials and session cookie cross the network "
                 "in clear."),
        "fix": ("Configure icm/HTTP/redirect_0 to redirect with the protocol the "
                "ECS baseline mandates."),
    },
    "icm/HTTPS/verify_client": {
        "severity": "MEDIUM", "category": "Transport Security",
        "desc": ("Sets how the ICM treats client certificates on inbound TLS "
                 "connections. It decides whether certificate-based logon can work "
                 "at all and whether a presented certificate is validated."),
        "fix": "Set icm/HTTPS/verify_client to the ECS standard value.",
    },
    "icm/HTTPS/client_sni_enabled": {
        "severity": "LOW", "category": "Transport Security",
        "desc": ("Sends the Server Name Indication extension on outbound TLS "
                 "connections from the ICM. Without SNI a multi-tenant endpoint "
                 "cannot present the right certificate, which tends to be resolved "
                 "by relaxing validation."),
        "fix": "Set icm/HTTPS/client_sni_enabled to the ECS standard value.",
    },
    "icm/security_log": {
        "severity": "MEDIUM", "category": "Audit Logging",
        "desc": ("Sets the detail level of the ICM security log — the web tier's "
                 "record of rejected and suspicious requests. Below the mandated "
                 "level, attacks on the HTTP channel are not recorded in enough "
                 "detail to reconstruct."),
        "fix": ("Configure icm/security_log at or above the mandated LEVEL, with a "
                "log file and rotation."),
    },

    # ── Information disclosure ───────────────────────────────────────────────
    "is/HTTP/show_detailed_errors": {
        "severity": "MEDIUM", "category": "Network & Service Exposure",
        "desc": ("Decides whether internal error detail is returned to an HTTP "
                 "client. Detailed pages disclose stack, component and path "
                 "information that turns blind probing into targeted probing."),
        "fix": "Set is/HTTP/show_detailed_errors to the ECS standard value.",
    },
    "is/HTTP/show_server_header": {
        "severity": "LOW", "category": "Network & Service Exposure",
        "desc": ("Decides whether the HTTP Server response header names the "
                 "product and release. It hands an unauthenticated caller the "
                 "version they need to select an exploit."),
        "fix": "Set is/HTTP/show_server_header to the ECS standard value.",
    },
    "login/show_detailed_errors": {
        "severity": "MEDIUM", "category": "Login Security",
        "desc": ("Decides whether the logon screen distinguishes a wrong password "
                 "from an unknown or locked user. Distinguishing them turns the "
                 "logon screen into a user-enumeration oracle."),
        "fix": "Set login/show_detailed_errors to the ECS standard value.",
    },

    # ── XML parsing ──────────────────────────────────────────────────────────
    "ixml/dtd_restriction": {
        "severity": "HIGH", "category": "Network & Service Exposure",
        "desc": ("Restricts what the iXML parser will do with a Document Type "
                 "Definition in inbound XML. Unrestricted DTD processing is the "
                 "mechanism behind XML external entity attacks — file disclosure "
                 "and server-side request forgery from a document the system was "
                 "merely asked to parse — and behind entity-expansion denial of "
                 "service."),
        "fix": "Set ixml/dtd_restriction to the ECS standard value.",
    },

    # ── Logon and session ────────────────────────────────────────────────────
    "login/disable_cpic": {
        "severity": "MEDIUM", "category": "Login Security",
        "desc": ("Disables the legacy CPIC logon path. It predates the current "
                 "authentication controls and is an alternative way in that the "
                 "rest of the logon hardening does not cover."),
        "fix": "Set login/disable_cpic to the ECS standard value.",
    },
    "login/failed_user_auto_unlock": {
        "severity": "MEDIUM", "category": "Login Security",
        "desc": ("Decides whether an account locked by failed logons is released "
                 "automatically. Automatic release converts a lockout into a "
                 "delay: an attacker simply resumes guessing after it, and nobody "
                 "is ever asked to investigate the lock."),
        "fix": "Set login/failed_user_auto_unlock to the ECS standard value.",
    },
    "login/fails_to_session_end": {
        "severity": "HIGH", "category": "Login Security",
        "desc": ("Failed attempts allowed before the logon session is terminated. "
                 "Note that 0 does not mean 'strict' — it switches the control off "
                 "entirely, which is why the baseline states an upper bound AND "
                 "excludes zero."),
        "fix": "Set login/fails_to_session_end within the range the baseline permits.",
    },
    "login/fails_to_user_lock": {
        "severity": "HIGH", "category": "Login Security",
        "desc": ("Failed attempts allowed before the account itself is locked. "
                 "Zero disables locking altogether and leaves password guessing "
                 "unbounded, so it is excluded from the permitted range rather "
                 "than treated as the strictest value."),
        "fix": "Set login/fails_to_user_lock within the range the baseline permits.",
    },
    "login/no_automatic_user_sapstar": {
        "severity": "CRITICAL", "category": "Login Security",
        "desc": ("Disables the built-in SAP* emergency identity that the kernel "
                 "otherwise makes available with a well-known default password "
                 "when no SAP* user record exists in a client. It is the single "
                 "most reliably exploited default in an ABAP system."),
        "fix": ("Set login/no_automatic_user_sapstar to the ECS standard value, and "
                "ensure a real, locked SAP* user record exists in every client."),
    },
    "login/create_virtual_user_sapstar": {
        "severity": "HIGH", "category": "Login Security",
        "desc": ("Companion control to login/no_automatic_user_sapstar over the "
                 "built-in SAP* identity. Both must hold the mandated value for "
                 "that path to be closed; hardening one and leaving the other is a "
                 "common way the emergency identity survives."),
        "fix": "Set login/create_virtual_user_sapstar to the ECS standard value.",
    },
    "login/accept_sso2_ticket": {
        "severity": "MEDIUM", "category": "Login Security",
        "desc": ("Whether this system accepts SSO2 logon tickets, and how it "
                 "treats them. A ticket is a bearer credential: anything holding "
                 "one is the user until it expires."),
        "fix": "Set login/accept_sso2_ticket to a value the baseline permits.",
    },
    "login/create_sso2_ticket": {
        "severity": "MEDIUM", "category": "Login Security",
        "desc": ("Whether this system issues SSO2 logon tickets, and of what kind. "
                 "Every ticket issued is a bearer credential that other systems in "
                 "the trust circle will honour."),
        "fix": "Set login/create_sso2_ticket to a value the baseline permits.",
    },
    "login/ticket_only_by_https": {
        "severity": "HIGH", "category": "Login Security",
        "desc": ("Restricts the logon ticket cookie to encrypted connections. "
                 "Without it the ticket is sent over plain HTTP, where anyone on "
                 "the path can lift it and replay it as the user."),
        "fix": "Set login/ticket_only_by_https to the ECS standard value.",
    },
    "login/ticket_only_to_host": {
        "severity": "MEDIUM", "category": "Login Security",
        "desc": ("Binds the logon ticket cookie to the host that issued it. "
                 "Unbound, the browser will offer the ticket to other hosts in the "
                 "domain, widening where a stolen ticket is useful."),
        "fix": "Set login/ticket_only_to_host to the ECS standard value.",
    },
    "rdisp/gui_auto_logout": {
        "severity": "MEDIUM", "category": "Login Security",
        "desc": ("Seconds of inactivity after which a SAP GUI session is closed. "
                 "Zero does not mean 'immediately' — it disables automatic logout, "
                 "leaving idle sessions open indefinitely on unattended "
                 "workstations, which is why the baseline excludes it."),
        "fix": ("Set rdisp/gui_auto_logout within the range the baseline permits "
                "(and never 0)."),
    },

    # ── Password policy ──────────────────────────────────────────────────────
    "login/min_password_lng": {
        "severity": "HIGH", "category": "Password Policy",
        "desc": ("Minimum password length. This is the single most load-bearing "
                 "password parameter: it sets the floor on offline cracking cost "
                 "once a hash is obtained. The ECS mandate is materially higher "
                 "than the eight characters older guidance settled on."),
        "fix": "Set login/min_password_lng to at least the mandated minimum.",
    },
    "login/min_password_digits": {
        "severity": "MEDIUM", "category": "Password Policy",
        "desc": "Minimum number of digits a password must contain.",
        "fix": "Set login/min_password_digits to at least the mandated minimum.",
    },
    "login/min_password_letters": {
        "severity": "MEDIUM", "category": "Password Policy",
        "desc": "Minimum number of letters a password must contain.",
        "fix": "Set login/min_password_letters to at least the mandated minimum.",
    },
    "login/min_password_lowercase": {
        "severity": "MEDIUM", "category": "Password Policy",
        "desc": "Minimum number of lowercase characters a password must contain.",
        "fix": "Set login/min_password_lowercase to at least the mandated minimum.",
    },
    "login/min_password_uppercase": {
        "severity": "MEDIUM", "category": "Password Policy",
        "desc": "Minimum number of uppercase characters a password must contain.",
        "fix": "Set login/min_password_uppercase to at least the mandated minimum.",
    },
    "login/min_password_specials": {
        "severity": "MEDIUM", "category": "Password Policy",
        "desc": "Minimum number of special characters a password must contain.",
        "fix": "Set login/min_password_specials to at least the mandated minimum.",
    },
    "login/min_password_diff": {
        "severity": "LOW", "category": "Password Policy",
        "desc": ("How many characters a new password must differ by from the "
                 "previous one. Without it, history size is easily defeated by "
                 "incrementing a trailing digit."),
        "fix": "Set login/min_password_diff to at least the mandated minimum.",
    },
    "login/password_history_size": {
        "severity": "MEDIUM", "category": "Password Policy",
        "desc": ("How many previous passwords are remembered and refused. A short "
                 "history lets a user cycle straight back to a password that may "
                 "already be in a breach corpus."),
        "fix": "Set login/password_history_size to at least the mandated minimum.",
    },
    "login/password_change_waittime": {
        "severity": "LOW", "category": "Password Policy",
        "desc": ("Minimum days between password changes. Without a wait, a user "
                 "can change the password repeatedly in one sitting to flush the "
                 "history and return to the original."),
        "fix": "Set login/password_change_waittime to at least the mandated minimum.",
    },
    "login/password_expiration_time": {
        "severity": "MEDIUM", "category": "Password Policy",
        "desc": ("Days before a password must be changed. The baseline states a "
                 "RANGE, not a ceiling: too short is a finding as well as too "
                 "long, because a very short interval drives predictable "
                 "incremental passwords and written-down credentials."),
        "fix": ("Set login/password_expiration_time inside the range the baseline "
                "permits."),
    },
    "login/password_max_idle_initial": {
        "severity": "MEDIUM", "category": "Password Policy",
        "desc": ("How long an initial (administrator-set) password stays usable "
                 "while unused. These are the weakest credentials in the system — "
                 "often issued in bulk and communicated over email — so an unused "
                 "one should expire quickly. Zero disables the expiry rather than "
                 "tightening it."),
        "fix": ("Set login/password_max_idle_initial inside the range the baseline "
                "permits (and never 0)."),
    },
    "login/password_max_idle_productive": {
        "severity": "MEDIUM", "category": "Password Policy",
        "desc": ("How long a user-chosen password stays usable while unused. It is "
                 "what retires the credentials of accounts that quietly stopped "
                 "being used without being deprovisioned."),
        "fix": ("Set login/password_max_idle_productive inside the range the "
                "baseline permits."),
    },
    "login/password_compliance_to_current_policy": {
        "severity": "MEDIUM", "category": "Password Policy",
        "desc": ("Forces users whose stored password predates a policy tightening "
                 "to set a new one. Without it, raising the policy protects only "
                 "new passwords and every legacy weak password stays valid."),
        "fix": ("Set login/password_compliance_to_current_policy to the ECS "
                "standard value."),
    },
    "login/password_downwards_compatibility": {
        "severity": "HIGH", "category": "Password Policy",
        "desc": ("Whether the weak, downward-compatible password hash is still "
                 "generated alongside the strong one. While it is, the strong hash "
                 "provides no protection: an attacker who reads the password table "
                 "simply cracks the weak hash instead."),
        "fix": ("Set login/password_downwards_compatibility to the ECS standard "
                "value, then run CLEANUP_PASSWORD_HASH_VALUES to purge the "
                "residual weak hashes already stored."),
    },
    "login/password_hash_algorithm": {
        "severity": "HIGH", "category": "Password Policy",
        "desc": ("The one-way function, work factor and salt size used to store "
                 "password hashes. It decides what an attacker who obtains the "
                 "password table can recover offline, and it governs every dialog "
                 "user at once regardless of how strong the composition rules are."),
        "fix": ("Set login/password_hash_algorithm to the mandated construction and "
                "work factors, then force a password change so the new hashes are "
                "generated."),
    },
    "login/password_change_for_SSO": {
        "severity": "MEDIUM", "category": "Password Policy",
        "desc": ("Whether a user logging on through single sign-on is still made to "
                 "deal with an initial or expired password. Skipping it leaves "
                 "initial passwords alive indefinitely on the accounts that never "
                 "use the logon screen."),
        "fix": "Set login/password_change_for_SSO to a value the baseline permits.",
    },

    # ── Message server ───────────────────────────────────────────────────────
    "ms/acl_info": {
        "severity": "HIGH", "category": "System Trust & Standard Users",
        "desc": ("Names the message server ACL file, which decides which hosts may "
                 "register as application servers. Without it, a host that can "
                 "reach the internal message server port can join the system as an "
                 "application server."),
        "fix": ("Point ms/acl_info at a maintained ACL file listing only the known "
                "application server hosts, with no wildcard entry."),
    },
    "ms/monitor": {
        "severity": "MEDIUM", "category": "System Trust & Standard Users",
        "desc": ("Whether the message server accepts external monitoring and "
                 "administration requests. Enabled, it answers questions about the "
                 "landscape to callers who have not authenticated to the ABAP "
                 "stack at all."),
        "fix": "Set ms/monitor to the ECS standard value.",
    },

    # ── RFC ──────────────────────────────────────────────────────────────────
    "rfc/allowoldticket4tt": {
        "severity": "MEDIUM", "category": "RFC Security",
        "desc": ("Whether the old ticket format is still accepted for trusted / "
                 "trusting RFC. The legacy format carries weaker assurance about "
                 "which system and user it really represents, and trusted RFC is "
                 "precisely where that assurance is load-bearing."),
        "fix": "Set rfc/allowoldticket4tt to the ECS standard value.",
    },
    "rfc/callback_security_method": {
        "severity": "HIGH", "category": "RFC Security",
        "desc": ("Constrains RFC callbacks. When this system calls out to a less "
                 "protected system, the callee can call back through the "
                 "predefined BACK destination and execute in the context of the "
                 "user who made the outbound call — no credentials needed, with "
                 "the trust flowing opposite to the data."),
        "fix": ("Set rfc/callback_security_method to a value the baseline permits "
                "and maintain the per-destination callback allowlist in SM59."),
    },
    "rfc/reject_expired_passwd": {
        "severity": "MEDIUM", "category": "RFC Security",
        "desc": ("Whether an RFC logon is refused when the account's password has "
                 "expired. Accepting one lets service accounts whose credentials "
                 "should have been rotated keep working indefinitely."),
        "fix": "Set rfc/reject_expired_passwd to the ECS standard value.",
    },
    "rfc/authCheckInPlayback": {
        "severity": "MEDIUM", "category": "RFC Security",
        "desc": ("Governs how strictly authorizations are checked in playback "
                 "mode. Any mode that replays recorded calls with a weaker check "
                 "than the original is a way around the authorization concept."),
        "fix": "Set rfc/authCheckInPlayback to the ECS standard value.",
    },

    # ── Audit logging ────────────────────────────────────────────────────────
    "rsau/enable": {
        "severity": "CRITICAL", "category": "Audit Logging",
        "desc": ("Switches on the Security Audit Log. Disabled, there is no record "
                 "of logons, RFC calls, debugging, transaction starts or "
                 "administrative changes — no detection, and no investigation "
                 "after the fact."),
        "fix": ("Set rsau/enable to the ECS standard value and configure the "
                "filters (RSAU_CONFIG) to cover all clients and all users."),
    },
    "rec/client": {
        "severity": "HIGH", "category": "Audit Logging",
        "desc": ("Which clients have table logging active. Table logging is the "
                 "record of changes to customising and to security-relevant "
                 "tables; a client left out of it has no such record at all."),
        "fix": "Set rec/client to the ECS standard value.",
    },

    # ── SAP GUI, services and TLS ────────────────────────────────────────────
    "sapgui/user_scripting": {
        "severity": "LOW", "category": "Security Parameters",
        "desc": ("Server-side switch for the SAP GUI Scripting API, which lets a "
                 "script drive the GUI as the user. Note that the ECS baseline "
                 "PERMITS this to be switched on: a system that has it enabled is "
                 "sitting on an exception SAP allows, and is reported here only if "
                 "the value is neither the standard nor that exception."),
        "fix": ("Set sapgui/user_scripting to the ECS standard value or to the "
                "exception the baseline permits; where it is on, restrict it per "
                "user."),
    },
    "service/protectedwebmethods": {
        "severity": "HIGH", "category": "Network & Service Exposure",
        "desc": ("Which sapstartsrv / SAP Host Agent SOAP methods require "
                 "authentication. Left unprotected they expose instance start and "
                 "stop, process listings and log and trace file retrieval to "
                 "whoever can reach the port."),
        "fix": "Set service/protectedwebmethods to the ECS standard value.",
    },
    "service/admin_users": {
        "severity": "MEDIUM", "category": "Network & Service Exposure",
        "desc": ("Which operating-system accounts may call the protected "
                 "sapstartsrv administrative methods. An empty or wildcarded list "
                 "removes the distinction the protected-web-methods setting exists "
                 "to draw."),
        "fix": ("Set service/admin_users to an explicit list of the operator "
                "accounts that need it, with no wildcard."),
    },
    "ssl/ciphersuites": {
        "severity": "HIGH", "category": "Transport Security",
        "desc": ("The cipher suites this system offers on inbound TLS. The "
                 "mandated string selects forward secrecy and modern curves; a "
                 "different one re-admits negotiation down to suites without "
                 "forward secrecy, where one key compromise retrospectively opens "
                 "recorded traffic."),
        "fix": "Set ssl/ciphersuites to a value the baseline permits.",
    },
    "ssl/client_ciphersuites": {
        "severity": "HIGH", "category": "Transport Security",
        "desc": ("The cipher suites this system offers when it is the TLS client. "
                 "Outbound calls carry credentials to the systems they integrate "
                 "with, so a weak client-side list exposes exactly the traffic that "
                 "authenticates this system elsewhere."),
        "fix": "Set ssl/client_ciphersuites to a value the baseline permits.",
    },
    "ssl/client_sni_enabled": {
        "severity": "LOW", "category": "Transport Security",
        "desc": ("Sends Server Name Indication on outbound TLS connections. "
                 "Without SNI a multi-tenant endpoint cannot present the right "
                 "certificate, and the usual workaround is to relax certificate "
                 "validation."),
        "fix": "Set ssl/client_sni_enabled to the ECS standard value.",
    },
    "system/secure_communication": {
        "severity": "HIGH", "category": "Transport Security",
        "desc": ("The system-wide switch that makes internal communication use the "
                 "secure variant of each protocol by default. Off, individual "
                 "connections fall back to their unprotected form unless every one "
                 "of them was configured otherwise by hand."),
        "fix": "Set system/secure_communication to the ECS standard value.",
    },
}


# --------------------------------------------------------------------------- #
#  Joining OUR judgement to THEIR values                                      #
# --------------------------------------------------------------------------- #

def build_ecs_rules(note: Optional[Dict[str, Any]] = None,
                    meta: Optional[Dict[str, Dict[str, str]]] = None,
                    unparsed: Optional[List[Tuple[str, str]]] = None,
                    ) -> Dict[str, Dict[str, Any]]:
    """One rule per non-SNC parameter of note 3250501.

    The values are the note's; the severity, category, description and remediation
    are ours. A parameter present in one side and not the other is left out and is
    caught by the parity test rather than being papered over here — a rule with an
    invented expected value, or a mandated parameter silently unchecked, are both
    worse than a failing build.
    """
    note = load_ecs_note() if note is None else note
    meta = ECS_META if meta is None else meta
    sink = UNPARSED_SPECS if unparsed is None else unparsed

    source = (note.get("source") or {}) if isinstance(note, dict) else {}
    version = source.get("version")
    released = source.get("released")
    provenance = ECS_NOTE_REF + (f" (v{version}, {released})" if version else "")

    rules: Dict[str, Dict[str, Any]] = {}
    for name, entry in sorted((note.get("parameters") or {}).items()):
        if name.startswith(SNC_PREFIXES) or not isinstance(entry, dict):
            continue
        judgement = meta.get(name)
        if judgement is None:
            continue

        ecs = str(entry.get("ecs", ""))
        allowed = [str(a) for a in (entry.get("allowed") or [])]

        structural = _STRUCTURAL.get(name)
        if structural is not None:
            check = _bind_structural(structural["check"], ecs)
            expected = structural["expected"](ecs)
            caveat = structural["caveat"]
        else:
            predicates = [_literal_pred(ecs)]
            unknown = False
            for spec in allowed:
                predicate = _compile_spec(spec)
                if predicate is None:
                    sink.append((name, spec))
                    unknown = True
                    break
                predicates.append(predicate)
            if unknown:
                # Refuse rather than guess. A half-understood rule would either
                # accuse a compliant system or clear a non-compliant one, and we
                # cannot tell which.
                continue
            check = _any_of(predicates)
            expected = _expected_display(ecs, allowed)
            caveat = ""

        rules[name] = {
            "check": check,
            "expected": expected,
            "ecs": ecs,
            "allowed": allowed,
            "caveat": caveat,
            "source": "ecs_note_3250501",
            "severity": judgement["severity"],
            "category": judgement["category"],
            "desc": judgement["desc"],
            "fix": f"{judgement['fix']} {_ECS_REMEDIATION_TAIL}",
            "refs": [provenance],
        }
    return rules


def _bind_structural(check: Callable[[str, str], bool], ecs: str) -> Callable[[str], bool]:
    return lambda actual: check(actual, ecs)


def _any_of(predicates: List[Callable[[str], bool]]) -> Callable[[str], bool]:
    """Compliant = the ECS standard OR any exception SAP permits.

    The `allowed` list is not decoration. A system sitting on a permitted
    exception is compliant and must produce no finding; treating the standard
    value as the only acceptable one manufactures findings against SAP's own note.
    """
    return lambda actual: any(predicate(actual) for predicate in predicates)


def _expected_display(ecs: str, allowed: List[str]) -> str:
    if not allowed:
        return ecs
    return f"{ecs} (SAP standard) or one of: {', '.join(allowed)}"


#: Built once at import. A test asserts it covers every non-SNC parameter of the
#: note, so an empty or short table is a build failure and not a silent gap.
ECS_RULES: Dict[str, Dict[str, Any]] = build_ecs_rules()


from modules import ecs_baseline


class SecurityParamAuditor(BaseAuditor):

    # Legacy baseline: parameter → (expected_value, operator, severity, description,
    # remediation). Operators: "==", ">=", "<=", "!=", "in", "not_in", "contains".
    #
    # Retained ONLY for the parameters note 3250501 does not mention. Where a
    # parameter appears in both, the ECS rule wins — see `effective_rules`. The
    # entries kept here are not the note's and their thresholds are ours; the SAP
    # note numbers and CIS clause numbers they cite predate this work and have NOT
    # been verified against note 3250501's own reference list, so treat them as
    # UNVERIFIED: SAP Notes 68048, 2416093, 1408081, 510007, 2191612 and every
    # "CIS SAP Benchmark n.n.n" string below.
    BASELINE = {
        # --- Password Policy ---
        "login/min_password_lng": {
            "expected": "15",
            "op": ">=",
            "severity": "HIGH",
            "category": "Password Policy",
            "desc": "Minimum password length must be at least 15 characters (mandatory in ECS)",
            "fix": "Set login/min_password_lng >= 15 in DEFAULT.PFL. SAP Note 3250501 makes this mandatory for ECS/RISE; the older >= 8 guidance is not sufficient there.",
            "refs": ["SAP Note 3250501", "CIS SAP Benchmark 1.1.1"],
        },
        "login/min_password_digits": {
            "expected": "1",
            "op": ">=",
            "severity": "MEDIUM",
            "category": "Password Policy",
            "desc": "Passwords should require at least 1 digit",
            "fix": "Set login/min_password_digits >= 1 in RZ10",
            "refs": ["CIS SAP Benchmark 1.1.2"],
        },
        "login/min_password_letters": {
            "expected": "1",
            "op": ">=",
            "severity": "MEDIUM",
            "category": "Password Policy",
            "desc": "Passwords should require at least 1 letter",
            "fix": "Set login/min_password_letters >= 1 in RZ10",
            "refs": ["CIS SAP Benchmark 1.1.3"],
        },
        "login/min_password_specials": {
            "expected": "1",
            "op": ">=",
            "severity": "MEDIUM",
            "category": "Password Policy",
            "desc": "Passwords should require at least 1 special character",
            "fix": "Set login/min_password_specials >= 1 in RZ10",
            "refs": ["CIS SAP Benchmark 1.1.4"],
        },
        "login/password_expiration_time": {
            "expected": "90",
            "op": "<=",
            "severity": "MEDIUM",
            "category": "Password Policy",
            "desc": "Password expiration should be 90 days or less",
            "fix": "Set login/password_expiration_time <= 90 in RZ10",
            "refs": ["CIS SAP Benchmark 1.1.6"],
        },
        "login/password_max_idle_initial": {
            "expected": "7",
            "op": "<=",
            "severity": "MEDIUM",
            "category": "Password Policy",
            "desc": "Initial passwords should expire within 14 days if unused",
            "fix": "Set login/password_max_idle_initial <= 14",
            "refs": ["CIS SAP Benchmark 1.1.7"],
        },
        "login/password_history_size": {
            "expected": "15",
            "op": ">=",
            "severity": "LOW",
            "category": "Password Policy",
            "desc": "Password history should prevent reuse of last 5+ passwords",
            "fix": "Set login/password_history_size >= 15 (mandatory in ECS, SAP Note 3250501)",
            "refs": ["CIS SAP Benchmark 1.1.8"],
        },

        # --- Login Security ---
        "login/fails_to_session_end": {
            "expected": "3",
            "op": "<=",
            "severity": "HIGH",
            "category": "Login Security",
            "desc": "Session should end after max 3 failed logon attempts",
            "fix": "Set login/fails_to_session_end <= 3",
            "refs": ["CIS SAP Benchmark 1.2.1"],
        },
        "login/fails_to_user_lock": {
            "expected": "6",
            "op": "<=",
            "severity": "HIGH",
            "category": "Login Security",
            "desc": "Account should lock after max 5 failed logon attempts",
            "fix": "Set login/fails_to_user_lock <= 6 and not 0 (SAP Note 3250501)",
            "refs": ["CIS SAP Benchmark 1.2.2"],
        },
        "login/no_automatic_user_sapstar": {
            "expected": "1",
            "op": "==",
            "severity": "CRITICAL",
            "category": "Login Security",
            "desc": "Must disable automatic SAP* user logon (prevents default password attack)",
            "fix": "Set login/no_automatic_user_sapstar = 1",
            "refs": ["SAP Note 68048", "CIS SAP Benchmark 1.2.5"],
        },
        "login/disable_multi_gui_login": {
            "expected": "1",
            "op": "==",
            "severity": "LOW",
            "category": "Login Security",
            "desc": "Should disable multiple GUI sessions per user",
            "fix": "Set login/disable_multi_gui_login = 1",
            "refs": ["CIS SAP Benchmark 1.2.6"],
        },

        # --- RFC Security ---
        "rfc/reject_insecure_logon": {
            "expected": "1",
            "op": "==",
            "severity": "HIGH",
            "category": "RFC Security",
            "desc": "Must reject insecure RFC logons (plaintext password transmission)",
            "fix": "Set rfc/reject_insecure_logon = 1",
            "refs": ["SAP Note 2416093", "CIS SAP Benchmark 4.1"],
        },
        "rfc/reject_insecure_logon_data": {
            "expected": "1",
            "op": "==",
            "severity": "HIGH",
            "category": "RFC Security",
            "desc": "Must reject insecure RFC data transmission",
            "fix": "Set rfc/reject_insecure_logon_data = 1",
            "refs": ["SAP Note 2416093"],
        },
        "rfc/allowoldticket4tt": {
            "expected": "0",
            "op": "==",
            "severity": "MEDIUM",
            "category": "RFC Security",
            "desc": "Should disable old-format RFC tickets (weaker crypto)",
            "fix": "Set rfc/allowoldticket4tt = 0",
            "refs": ["SAP Note 2416093"],
        },

        # --- Gateway Security ---
        "gw/sec_info": {
            "expected": "",
            "op": "!=",
            "severity": "CRITICAL",
            "category": "Gateway Security",
            "desc": "Gateway security info file must be configured (secinfo)",
            "fix": "Configure gw/sec_info to point to a secinfo file with restrictive rules",
            "refs": ["SAP Note 1408081", "CIS SAP Benchmark 3.1"],
        },
        "gw/reg_info": {
            "expected": "",
            "op": "!=",
            "severity": "CRITICAL",
            "category": "Gateway Security",
            "desc": "Gateway registration info file must be configured (reginfo)",
            "fix": "Configure gw/reg_info to point to a reginfo file with restrictive rules",
            "refs": ["SAP Note 1408081", "CIS SAP Benchmark 3.2"],
        },
        "gw/reg_no_conn_info": {
            "expected": "255",
            "op": ">=",
            "severity": "HIGH",
            "category": "Gateway Security",
            "desc": "Should limit gateway connection logging level",
            "fix": "Set gw/reg_no_conn_info appropriately",
            "refs": ["SAP Note 1408081"],
        },

        # --- ICM / TLS ---
        "icm/HTTPS/verify_client": {
            "expected": "1",
            "op": ">=",
            "severity": "HIGH",
            "category": "Transport Security",
            "desc": "ICM should verify client certificates for HTTPS",
            "fix": "Set icm/HTTPS/verify_client = 1 (require) or 2 (optional verify)",
            "refs": ["SAP Note 510007"],
        },
        "ssl/ciphersuites": {
            "expected": "",
            "op": "!=",
            "severity": "HIGH",
            "category": "Transport Security",
            "desc": "TLS cipher suites must be explicitly configured (not defaults)",
            "fix": "Configure ssl/ciphersuites to allow only strong ciphers (TLS 1.2+, AES-256)",
            "refs": ["SAP Note 510007", "CIS SAP Benchmark 5.1"],
        },

        # --- Audit Logging ---
        "rsau/enable": {
            "expected": "1",
            "op": "==",
            "severity": "CRITICAL",
            "category": "Audit Logging",
            "desc": "Security Audit Log must be enabled",
            "fix": "Set rsau/enable = 1 and configure filters in SM19",
            "refs": ["SAP Note 2191612", "CIS SAP Benchmark 6.1"],
        },
        "rec/client": {
            "expected": "",
            "op": "!=",
            "severity": "HIGH",
            "category": "Audit Logging",
            "desc": "Table logging client must be configured",
            "fix": "Set rec/client to log critical client(s), e.g. rec/client = ALL",
            "refs": ["CIS SAP Benchmark 6.2"],
        },

        # --- Debug / Development in Production ---
        "rdisp/wpdbug_max_no": {
            "expected": "0",
            "op": "==",
            "severity": "HIGH",
            "category": "Development Controls",
            "desc": "Debugging in production should be disabled (zero debug work processes)",
            "fix": "Set rdisp/wpdbug_max_no = 0 in production systems",
            "refs": ["CIS SAP Benchmark 7.1"],
        },
    }

    #: The note's rules, exposed on the class so a test (or a caller with a
    #: different extract) can substitute one.
    ECS_RULES = ECS_RULES

    #: Operators whose FAILING condition admits exactly one value, so the actual value
    #: may safely be carried as the object's qualifier (it participates in identity).
    #:
    #:   "!="  fails only when the value EQUALS `expected` — one string, pinned.
    #:
    #: Every other operator here fails over a range or over "anything but one string":
    #: `>= 8` fails at 0..7, `== 1` fails at 0, 2 and "". Putting the value in identity
    #: for those would retire the finding and raise a fresh one — resetting its age —
    #: the moment somebody changed min_password_lng from 4 to 6, which fixes nothing.
    #:
    #: ECS rules never pin: their failing condition is "anything outside the permitted
    #: set", which is always more than one value.
    _VALUE_PINNING_OPS = frozenset({"!="})

    def effective_rules(self) -> Dict[str, Dict[str, Any]]:
        """The rules actually applied: note 3250501 first, legacy for the rest.

        ONE rule per parameter, deliberately. Layering the ECS rule on top of the
        legacy one would emit two findings for a single wrong value — with two
        different thresholds, since the legacy `<= 90` and the note's "30 to 90"
        disagree about a system set to 10 days — and the reader has no way to tell
        which is authoritative.

        The ECS rules reuse the legacy `PARAM-<name>` id scheme on purpose. That id
        is a foreign key into `data/finding_details.json` and into every stored
        finding's identity, so a system whose `login/min_password_lng` was already
        being reported keeps the same finding rather than having it retired and
        re-raised with its age reset.
        """
        rules = dict(self.BASELINE)
        rules.update(self.ECS_RULES)
        return rules

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_params_against_baseline()
        self.check_missing_critical_params()
        return self.findings

    def check_params_against_baseline(self):
        """Compare each exported parameter against the security baseline."""
        params = self.data.get("security_params")
        if not params:
            self.finding(
                check_id="PARAM-000",
                title="No security parameters data available",
                severity=self.SEVERITY_HIGH,
                category="Security Parameters",
                description=(
                    "No profile parameter export was found. Cannot validate "
                    "security configuration baseline."
                ),
                remediation=(
                    "Export parameters using RZ11 (single) or RZ10 (profiles). "
                    "Alternatively, run report RSPARAM and export to CSV."
                ),
                # A coverage gap, not a defect in any named object: the whole point is
                # that no parameter export exists, so there is no parameter to name and
                # inventing one would fabricate a graph node the data never contained.
                # Identity is (system, client, PARAM-000) and `check_only` is the honest
                # basis for it.
                scope="aggregate",
            )
            return

        param_lookup = self._param_lookup(params)

        for param_name, rule in self.effective_rules().items():
            # Allow baseline overrides
            override_key = f"param.{param_name}"
            if override_key in self.overrides:
                rule = {**rule, **self.overrides[override_key]}

            actual_value = param_lookup.get(param_name.lower())

            if actual_value is None:
                continue  # Will be caught by missing params check

            if self._rule_passes(rule, actual_value):
                continue

            # One finding per non-compliant parameter, and the parameter IS the
            # defect — identity must include it, or every PARAM-* finding would
            # differ only by check_id.
            param_object = {"type": "parameter_name", "name": param_name}
            if rule.get("op") in self._VALUE_PINNING_OPS:
                param_object["qualifier"] = str(actual_value).strip()
            self.finding(
                check_id=f"PARAM-{param_name}",
                title=f"Parameter {param_name} non-compliant",
                severity=rule["severity"],
                category=rule["category"],
                description=self._describe(rule, actual_value),
                affected_items=[f"{param_name} = {actual_value}"],
                affected_objects=[param_object],
                scope="object",
                remediation=rule["fix"],
                references=rule.get("refs", []),
                details=self._details(param_name, rule, actual_value),
            )

    def _deployment_mode(self) -> str:
        """Which estate we are auditing — `user_auth_audit`'s vocabulary.

        Defaults to `on_prem` when the caller is silent: guessing ECS would
        relax genuine on-premise findings, which is the wrong way to be wrong.
        """
        mode = (self.run_context or {}).get("deployment_mode") or ""
        return str(mode).strip().lower() or "on_prem"

    def check_missing_critical_params(self):
        """Flag critical parameters that are missing from export entirely."""
        params = self.data.get("security_params")
        if not params:
            return

        param_lookup = set(self._param_lookup(params))

        critical_missing = []
        missing_objects = []
        # In ECS the governing baseline is SAP Note 3250501, so only a parameter the
        # NOTE mandates can be an ECS coverage gap. Without this scoping, an export
        # containing all 92 mandated parameters — a fully compliant ECS system —
        # still produced a HIGH finding, because legacy checks this module also
        # carries (rfc/reject_insecure_logon and friends, which appear nowhere in
        # the note) were counted as missing. That failed the one criterion this
        # whole exercise is measured against: a compliant system must be silent.
        ecs = self._deployment_mode().startswith(ecs_baseline.ECS_MODE_PREFIX)
        for param_name, rule in self.effective_rules().items():
            if ecs and not ecs_baseline.is_mandated(param_name):
                continue
            if rule["severity"] in ("CRITICAL", "HIGH"):
                if param_name.lower() not in param_lookup:
                    critical_missing.append(f"{param_name} ({rule['category']})")
                    # No qualifier: the parameter is absent, so there is no value to
                    # pin — and the node must be the same `parameter_name` node the
                    # PARAM-<name> checks produce once the parameter does appear.
                    missing_objects.append({"type": "parameter_name", "name": param_name})

        if critical_missing:
            self.finding(
                check_id="PARAM-MISSING",
                title="Critical security parameters not found in export",
                severity=self.SEVERITY_HIGH,
                category="Security Parameters",
                description=(
                    f"{len(critical_missing)} critical/high-severity parameters "
                    "were not found in the exported data. They may be at default "
                    "values (often insecure) or not exported."
                ),
                affected_items=critical_missing,
                # One roll-up of every parameter absent from the export. Exporting one
                # more parameter shrinks the list but does not close the gap, so the
                # member list must stay OUT of identity — otherwise each incremental
                # export improvement would retire this finding and raise a new one with
                # its age reset to zero. The members still ride along as graph nodes.
                affected_objects=missing_objects,
                scope="aggregate",
                remediation=(
                    "Export all profile parameters using RSPARAM or RZ10. "
                    "Ensure the listed parameters are explicitly set to secure values."
                ),
            )

    # ------------------------------------------------------------------ helpers

    #: The column spellings the various exports use, in precedence order.
    _NAME_COLUMNS = ("NAME", "PARAMETER", "PARAM_NAME")
    _VALUE_COLUMNS = ("VALUE", "PARAM_VALUE", "CURRENT_VALUE")

    @staticmethod
    def _param_lookup(params: Any) -> Dict[str, str]:
        """parameter name (lowercased) → exported value.

        Tolerates the column spellings the various exports use, and rows that
        carry none of them: a malformed row is skipped, never raised on.

        A row is only judged when it actually CARRIES a value column. Defaulting a
        missing one to "" reads "this export does not tell us" as "this parameter
        is empty", and empty is a finding for `gw/sec_info`, `ms/acl_info` and
        `service/admin_users` — so an export using an unrecognised value-column
        spelling would produce a page of confident accusations built from nothing.
        Skipping instead leaves the parameter unverified, where the PARAM-MISSING
        roll-up says so honestly. An empty value that IS present stays a real
        answer: `gw/sec_info` with nothing after the comma is the unset ACL, and
        must keep firing.
        """
        lookup: Dict[str, str] = {}
        # A non-list (an int, say) is not an export we can read. Iterating it
        # raised TypeError and took down the whole scan with it.
        if not isinstance(params, (list, tuple)):
            return lookup
        for row in params:
            if not isinstance(row, dict):
                continue
            name = next((row[c] for c in SecurityParamAuditor._NAME_COLUMNS
                         if row.get(c) is not None), "")
            name = str(name or "").strip().lower()
            if not name:
                continue
            value = next((row[c] for c in SecurityParamAuditor._VALUE_COLUMNS
                          if row.get(c) is not None), None)
            if value is None:
                continue
            lookup[name] = str(value)
        return lookup

    @staticmethod
    def _rule_passes(rule: Dict[str, Any], actual: str) -> bool:
        """Is this value compliant with this rule?

        `op` is consulted FIRST so a baseline override that supplies one still
        takes effect over a compiled ECS predicate — otherwise an operator could
        set an override and silently have it ignored.
        """
        if rule.get("op"):
            return SecurityParamAuditor._evaluate_rule(actual, rule.get("expected", ""),
                                                       rule["op"])
        check = rule.get("check")
        if check is None:
            # No way to evaluate: stay silent rather than accuse.
            return True
        try:
            return bool(check(actual))
        except Exception:                                   # noqa: BLE001
            return True

    @staticmethod
    def _describe(rule: Dict[str, Any], actual: str) -> str:
        """Finding text: what the control is, what was found, what is required.

        The ECS branch states the note's standard value AND its permitted
        exceptions, because "expected 90" next to a permitted "30 to 90" reads as
        a contradiction to the person who has to action it.
        """
        if rule.get("source") != "ecs_note_3250501":
            return (f"{rule['desc']}. "
                    f"Current value: '{actual}', "
                    f"Expected: {rule['op']} '{rule['expected']}'")

        allowed = rule.get("allowed") or []
        permitted = (f" SAP additionally permits: {', '.join(allowed)}." if allowed
                     else " SAP permits no exception to this value.")
        # `expected` only earns its place where it says something the standard and
        # the exception list do not — i.e. on the structural checks, where it names
        # the narrower thing that was actually compared. Restating "30 to 90" twice
        # in one paragraph reads as a contradiction rather than as emphasis.
        required = f" Checked here: {rule['expected']}." if rule.get("caveat") else ""
        caveat = f" {rule['caveat']}" if rule.get("caveat") else ""
        return (f"{rule['desc']} Current value: '{actual}'. "
                f"The ECS standard value is '{rule['ecs']}'.{permitted}"
                f"{required}{caveat}")

    @staticmethod
    def _details(param_name: str, rule: Dict[str, Any], actual: str) -> Dict[str, Any]:
        details: Dict[str, Any] = {
            "parameter": param_name,
            "current_value": actual,
            "expected_value": rule.get("expected", ""),
            "operator": rule.get("op", "ecs-baseline"),
        }
        if rule.get("source") == "ecs_note_3250501":
            details["ecs_standard"] = rule.get("ecs", "")
            details["ecs_allowed"] = list(rule.get("allowed") or [])
            details["baseline_source"] = "SAP Note 3250501"
            if rule.get("caveat"):
                details["verification_caveat"] = rule["caveat"]
        return details

    @staticmethod
    def _evaluate_rule(actual: str, expected: str, op: str) -> bool:
        """Evaluate a parameter value against a rule."""
        try:
            if op == "==":
                return actual.strip() == expected.strip()
            elif op == "!=":
                return actual.strip() != expected.strip()
            elif op == ">=":
                return int(actual) >= int(expected)
            elif op == "<=":
                return int(actual) <= int(expected)
            elif op == "contains":
                return expected.lower() in actual.lower()
            elif op == "in":
                return actual.strip() in [v.strip() for v in expected.split(",")]
            elif op == "not_in":
                return actual.strip() not in [v.strip() for v in expected.split(",")]
        except (ValueError, TypeError):
            return False
        return False
