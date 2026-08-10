# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
SAP Cloud ALM — Configuration & Security Analysis (CSA) store importer
======================================================================
Translates Cloud ALM CSA **configuration-store exports** into the logical data
sources ``modules/data_loader.py`` already understands, so every existing check
runs unchanged against Cloud ALM data.

WHY THIS PATH MATTERS
---------------------
Cloud ALM is included with every RISE subscription at no extra fee and is already
collecting ABAP configuration stores in most tenants. It therefore needs no ABAP
transport, no RFC user and no agent — it removes the largest adoption objection
we have. See ``docs/RISE_SECURITY_MODEL.md`` §5 and §7.3, where this is ranked the
second ingestion path after plain file upload.

⚠️ THE CAVEAT THAT SCOPES THIS ENTIRE MODULE
--------------------------------------------
**Our research could not confirm whether Cloud ALM's API returns RAW configuration-
store values or only SAP's own policy compliance verdicts** (``docs/RISE_SECURITY_MODEL.md``
§7.3 and §8, listed there as an open question that gates this path). The question
is unresolved because we hold no live Cloud ALM tenant to test against.

If the API returns only verdicts, then **this importer covers the raw-export path
only** — a store export whose rows are the configuration values themselves. It
cannot turn "SAP's policy 1ASTDUSR reports non-compliant" into the parameter and
user rows our checks read, and nothing here should be read as claiming it can.

This module reads **files the customer exported**. There is no live connection to
Cloud ALM, to SAP, or to anything else, and none is planned here: an API client we
cannot exercise would be a capability claim we cannot stand behind.

WHAT IS TRANSLATED, AND WHAT IS DELIBERATELY NOT
-------------------------------------------------
``STORE_TARGETS`` lists the stores we translate. ``UNMAPPED_STORES`` lists the
stores we recognise and deliberately refuse to translate, each with its reason.
The refusals are the load-bearing half of this module:

* ``AUTH_PROFILE_USER`` becomes ``profiles`` (profile assignment is exactly what
  the store is) but **never** ``users``. It contains only users who hold a
  profile, and feeding a partial population to checks that compute rates over the
  user master — dormancy, password age, never-logged-on — makes them silently
  understate. §3.1 of the RISE model calls that out as the defect an auditor
  catches. **No CSA store in SAP's own baseline policies carries a full USR02 user
  master, so ``users`` still has to come from RSUSR002.**
* ``AUDIT_CONFIGURATION`` is not translated even though ``AUDIT_CONFIGURATION_SLOT``
  is. The slots are the audit filter slots SAP's 2AAUDIT policy counts; the other
  store holds global audit settings. Mixing global settings into a list the checks
  treat as filters would inflate the filter count and turn "no audit filters
  configured" into a silent pass.
* Java, HANA, BTP and Web Dispatcher stores are recognised and skipped. This is not
  bookkeeping: SAP's Java stack has a store literally named ``Parameters``, and
  translating it into ``security_params`` would score Java AS settings against ABAP
  profile-parameter thresholds. Likewise ``AUTH_ROLE_USER`` is the **Java** store
  behind requirement CRITAU-J and is not an ABAP role assignment.

COLUMN NAMES
------------
SAP's published policies (``SAP-samples/frun-csa-policies-best-practices``,
Apache-2.0) name the stores and some of their fields — ``AUTH_PROFILE_USER`` with
``PROFILE`` / ``USERNAME`` / ``USER_TYPE`` / ``STATUS``, and ``VALUE`` on
``ABAP_INSTANCE_PAHI``. They do not name every column, and the header a customer
actually gets depends on the export route. Every field is therefore resolved
through an **alias list**: the SAP-documented spelling first, then the spellings a
CSV download or an OData projection plausibly produces. Aliases are our accepted
spellings, not a claim about SAP's schema.

Values are normalised only where the token is unambiguous (``X`` / ``1`` / ``YES``
/ ``ACTIVE`` and their negatives). Anything else is passed through untouched and
counted under ``unrecognised_values`` in the import report, so an export we do not
fully understand shows up as a visible gap rather than as a quiet pass.

Standard library only, Python 3.8 compatible. This module creates no findings; it
is pure translation, and every finding still comes from the audit modules.
"""

import csv
import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


# --------------------------------------------------------------------------- #
#  Store catalogue                                                            #
# --------------------------------------------------------------------------- #

#: Stores we translate -> the logical loader keys they can populate.
#: Kept as data so the import report, the docs and the tests all read one list.
STORE_TARGETS = {
    "ABAP_INSTANCE_PAHI":      ["security_params"],
    "STANDARD_USERS":          ["standard_users"],
    "AUTH_PROFILE_USER":       ["profiles"],
    "SICF_SERVICES":           ["icf_services"],
    "GW_SECINFO":              ["gw_secinfo"],
    "GW_REGINFO":              ["gw_reginfo"],
    "AUDIT_CONFIGURATION_SLOT": ["audit_config"],
    "CLIENTS":                 ["client_settings"],
    "MS_SECINFO":              ["ms_acl"],
}

#: Stores named in SAP's baseline policies that we recognise and do NOT translate.
#: A recognised refusal with a reason beats silence: the operator can see that the
#: store arrived, that we read its name, and why nothing came of it.
UNMAPPED_STORES = {
    # --- ABAP, no logical source yet -------------------------------------- #
    "AUDIT_CONFIGURATION":
        "global audit settings, not filter slots — merging them into audit_config "
        "would inflate the filter count and mask 'no audit filters configured'. "
        "AUDIT_CONFIGURATION_SLOT is translated instead.",
    "AUTH_PROFILE_USER_CHANGE_DOC":
        "profile-assignment change documents; our change_documents source is "
        "CDHDR-shaped and the two do not line up field for field.",
    "AUTH_COMB_USER":
        "SAP's critical-authorisation COMBINATION content. Our checks read "
        "AGR_1251 authorisation values; a combination list is a different artifact "
        "and we could not confirm whether the store carries the rules or the "
        "matches. Mapping it would be a guess.",
    "AUTH_COMB_ROLE":
        "as AUTH_COMB_USER, on the role side.",
    "AUTH_SECURITY_POLICY":
        "per-client security policies (SECPOL). Their attribute names differ from "
        "the instance profile parameters security_params holds; merging the two "
        "would score a policy attribute against a parameter threshold.",
    "ABAP_UCON_HTTP_WHITE_LIST":
        "UCON allowlists. We consume no UCON data source today — this is a known "
        "ingest gap (RISE model §7.1), not a translation problem.",
    "COMP_LEVEL":
        "software component / support-package levels. No logical source yet; "
        "applied_notes is note status, which is not the same thing.",
    "SAP_KERNEL":
        "kernel release and patch level. No logical source yet.",
    "TRANSPORT_TOOL":
        "transport tool configuration. No logical source yet.",
    "GLOBAL":
        "global system settings behind requirement CHANGE-A. We could not confirm "
        "its field names, and system_change expects SCOPE/MODIFIABLE — guessing "
        "would put a fabricated shape into a CRITICAL check.",
    "TDDAT":
        "table authorisation groups. No logical source yet.",
    "ABAP_SACF_INFO":
        "switchable authorisation check scenarios. No logical source yet.",
    "USER_PASSWD_HASH_USAGE":
        "password hash algorithm usage. No logical source yet.",
    # --- other stacks: recognised so they are never mistaken for ABAP ------ #
    "PARAMETERS":
        "JAVA AS / Web Dispatcher parameters. NOT ABAP profile parameters — "
        "translating them into security_params would score Java settings against "
        "ABAP thresholds.",
    "HTTP":
        "Java AS / Web Dispatcher HTTP configuration.",
    "SERVLET_JSP":
        "Java AS servlet configuration.",
    "XMLHARDENER_SRV":
        "Java AS XML hardener service.",
    "COM.SAP.SECURITY.CORE.UME.SERVICE":
        "Java AS UME service configuration.",
    "AUTH_ROLE_USER":
        "JAVA role assignment (requirement CRITAU-J). Not ABAP AGR_USERS.",
    "HDB_PARAMETER":
        "HANA. Technical HANA configuration is SAP-operated under RISE "
        "(RISE model §4).",
    "HDB_VERSION":            "HANA. SAP-operated under RISE.",
    "HDB_SYSTEM_USER":        "HANA. SAP-operated under RISE.",
    "HDB_SYSTEMPRIVILEGES":   "HANA. SAP-operated under RISE.",
    "HDB_USERGROUP_PARAMETERS": "HANA. SAP-operated under RISE.",
    "SCC_CONFIG":             "Cloud Connector configuration; our BTP path reads "
                              "cloud_connector.json from the connector's own API.",
    "SCC_VERSION":            "Cloud Connector version; see SCC_CONFIG.",
}

#: Which stack a store belongs to. Only ABAP stores are candidates for translation.
STORE_TECHNOLOGY = {}
for _s in STORE_TARGETS:
    STORE_TECHNOLOGY[_s] = "ABAP"
for _s in ("PARAMETERS", "HTTP", "SERVLET_JSP", "XMLHARDENER_SRV",
           "COM.SAP.SECURITY.CORE.UME.SERVICE", "AUTH_ROLE_USER"):
    STORE_TECHNOLOGY[_s] = "JAVA"
for _s in ("HDB_PARAMETER", "HDB_VERSION", "HDB_SYSTEM_USER",
           "HDB_SYSTEMPRIVILEGES", "HDB_USERGROUP_PARAMETERS"):
    STORE_TECHNOLOGY[_s] = "HANA"
for _s in ("SCC_CONFIG", "SCC_VERSION"):
    STORE_TECHNOLOGY[_s] = "BTP"
for _s in UNMAPPED_STORES:
    STORE_TECHNOLOGY.setdefault(_s, "ABAP")
del _s

#: Every store name this module recognises, longest first. Longest-first matters:
#: `AUDIT_CONFIGURATION_SLOT` starts with `AUDIT_CONFIGURATION`, and a shortest-
#: first prefix match would file the slots under the store we deliberately refuse.
KNOWN_STORES = sorted(
    set(STORE_TARGETS) | set(UNMAPPED_STORES), key=lambda s: (-len(s), s)
)

#: Filename prefixes a Cloud ALM download may carry before the store name.
_FILE_PREFIXES = ("CSA_", "CALM_", "CLOUDALM_")

#: Separators allowed between the store name and an export suffix such as a SID,
#: an instance number or a collection date.
_SUFFIX_SEPARATORS = ("_", "-", ".", "@")

_DATA_SUFFIXES = (".csv", ".json", ".txt", ".tsv")


# --------------------------------------------------------------------------- #
#  Field / value helpers                                                      #
# --------------------------------------------------------------------------- #

_TRUE_TOKENS = frozenset({"X", "1", "TRUE", "YES", "Y", "ACTIVE", "ENABLED", "ON"})
_FALSE_TOKENS = frozenset({"", "0", "FALSE", "NO", "N", "INACTIVE", "DISABLED",
                           "OFF", "-"})


def _norm_row(row: Any) -> Dict[str, str]:
    """Upper-case the headers and strip the values of one exported row."""
    out = {}  # type: Dict[str, str]
    if not isinstance(row, dict):
        return out
    for key, value in row.items():
        if key is None:
            continue
        name = str(key).strip().upper().replace(" ", "_")
        if not name:
            continue
        out[name] = "" if value is None else str(value).strip()
    return out


def _pick(row: Dict[str, str], *names: str) -> str:
    """First non-empty value among `names`. Aliases are tried in order."""
    for name in names:
        value = row.get(name)
        if value not in (None, ""):
            return value
    return ""


def _pick_pathlike(row: Dict[str, str], *names: str) -> str:
    """Like `_pick`, but prefers a value that actually looks like an ICF path.

    A SICF export may carry both a leaf name ("webrfc") and the full path
    ("/sap/bc/webrfc") and we cannot rely on which column holds which. The
    high-risk-service check substring-matches on the path, so picking the leaf
    would make every match miss.
    """
    candidates = [row[n] for n in names if row.get(n)]
    for value in candidates:
        if value.startswith("/"):
            return value
    return candidates[0] if candidates else ""


def _norm_flag(value: str, notes: Dict[str, Any], field: str) -> str:
    """Normalise a boolean-ish token to ``"X"`` / ``""``, or pass it through.

    Passing an unrecognised token through — and recording it — is deliberate.
    Guessing that some single letter means "active" would, when wrong, turn an
    exposed service into a compliant one with nothing anywhere saying so.
    """
    token = (value or "").strip().upper()
    if token in _TRUE_TOKENS:
        return "X"
    if token in _FALSE_TOKENS:
        return ""
    notes.setdefault("unrecognised_values", []).append(
        "{0}={1}".format(field, value))
    return value


def _is_code_like(value: str) -> bool:
    """A raw single-character table code (T000's ``CCCORACTIV`` is ``' '``/1/2/3).

    We do not decode these. The meanings are not in any source we hold, and a
    wrong decode either invents a CRITICAL finding or silently clears a real one.
    """
    token = (value or "").strip()
    return len(token) == 1 and token not in ("X", "*")


# --------------------------------------------------------------------------- #
#  Per-store translators                                                      #
# --------------------------------------------------------------------------- #
#  Each takes normalised rows plus a mutable `notes` dict it may annotate, and
#  returns {logical loader key: rows}. None of them raises on a shape it does not
#  recognise; a row it cannot use is counted in `notes["skipped_rows"]`.

def _skip(notes: Dict[str, Any]) -> None:
    notes["skipped_rows"] = notes.get("skipped_rows", 0) + 1


def _t_abap_instance_pahi(rows: List[Dict[str, str]],
                          notes: Dict[str, Any]) -> Dict[str, List[Dict[str, str]]]:
    """ABAP_INSTANCE_PAHI -> security_params (NAME / VALUE).

    SAP's 1APWDPOL / 1ARFCGW / 2AAUDIT policies read this store for the profile
    parameters our security_params and baseline_params modules score.
    """
    out = []
    for row in rows:
        name = _pick(row, "PARAMETER", "PARAMETER_NAME", "PARAM", "NAME", "KEY")
        if not name:
            _skip(notes)
            continue
        translated = {
            "NAME": name,
            # `VALUE` is the spelling SAP's own policy predicates use.
            "VALUE": _pick(row, "VALUE", "PARAMETER_VALUE", "PARAM_VALUE",
                           "CURRENT_VALUE", "VAL"),
            "SOURCE_STORE": "ABAP_INSTANCE_PAHI",
        }
        instance = _pick(row, "INSTANCE", "INSTANCE_NAME", "HOST", "HOSTNAME",
                         "SERVER")
        if instance:
            translated["INSTANCE"] = instance
        out.append(translated)
    return {"security_params": out}


def _t_standard_users(rows: List[Dict[str, str]],
                      notes: Dict[str, Any]) -> Dict[str, List[Dict[str, str]]]:
    """STANDARD_USERS -> standard_users (SAP* / DDIC / SAPCPIC / TMSADM / EARLYWATCH).

    Cross-client by nature. The clients actually present are recorded in the import
    report so a report can say "compliant in the clients we saw" rather than
    "compliant" — RISE model §3.1.
    """
    out = []
    clients = set()
    for row in rows:
        user = _pick(row, "USERNAME", "USER", "BNAME", "USER_NAME")
        if not user:
            _skip(notes)
            continue
        client = _pick(row, "CLIENT", "MANDT", "CLNT")
        if client:
            clients.add(client)

        default_pw = _pick(row, "DEFAULT_PASSWORD", "PASSWORD_STATUS", "PWD_STATUS",
                           "DEFAULT_PWD", "HAS_DEFAULT_PW")
        locked = _pick(row, "LOCKED", "LOCK_STATUS", "IS_LOCKED", "USER_LOCK",
                       "UFLAG")

        # A single free-text STATUS column is the shape SAP's own 1ASTDUSR policy
        # description implies ("SAP*, DDIC, SAPCPIC, TMSADM, EARLYWATCH status").
        # Only consulted when the dedicated columns are absent, so an export that
        # has both is never second-guessed.
        status = _pick(row, "STATUS", "USER_STATUS")
        status_l = status.lower()
        if not default_pw and "default" in status_l:
            default_pw = "" if ("no default" in status_l or
                                "not default" in status_l) else "X"
        if not locked and "lock" in status_l:
            locked = "" if ("unlock" in status_l or "not lock" in status_l) else "X"

        # UFLAG is numeric: 0 is unlocked, any set bit is a lock. `_truthy` in
        # system_trust reads "64" as false, so an untranslated UFLAG would report
        # every locked standard user as unlocked.
        if locked.isdigit():
            locked = "" if int(locked) == 0 else "X"
        else:
            locked = _norm_flag(locked, notes, "LOCKED") if locked else ""

        out.append({
            "USER": user.upper(),
            "CLIENT": client,
            "DEFAULT_PASSWORD": _norm_flag(default_pw, notes, "DEFAULT_PASSWORD")
                                if default_pw else "",
            "LOCKED": locked,
            "USER_TYPE": _pick(row, "USER_TYPE", "USTYP", "TYPE"),
            "SOURCE_STORE": "STANDARD_USERS",
        })
    if clients:
        notes["clients_seen"] = sorted(clients)
    return {"standard_users": out}


def _t_auth_profile_user(rows: List[Dict[str, str]],
                         notes: Dict[str, Any]) -> Dict[str, List[Dict[str, str]]]:
    """AUTH_PROFILE_USER -> profiles (USR04-shaped BNAME / PROFILE).

    Field names PROFILE / USERNAME / USER_TYPE / STATUS come from SAP's
    1ACRITA_CSTO policy, which reads this store for SAP_ALL holders (CRITAU-A).

    Deliberately does NOT populate `users`: see the module docstring.
    """
    out = []
    for row in rows:
        user = _pick(row, "USERNAME", "USER", "BNAME", "USER_NAME")
        profile = _pick(row, "PROFILE", "PROFILE_NAME", "PROFN")
        if not user or not profile:
            _skip(notes)
            continue
        translated = {
            "BNAME": user.upper(),
            "PROFILE": profile.upper(),
            "SOURCE_STORE": "AUTH_PROFILE_USER",
        }
        # Carried for context only — no check reads them, and STATUS semantics on
        # this store are not documented anywhere we could read, so nothing here
        # filters rows on it.
        for field, alias in (("USER_TYPE", "USER_TYPE"), ("STATUS", "STATUS")):
            value = _pick(row, alias, "USTYP" if field == "USER_TYPE" else "STATE")
            if value:
                translated[field] = value
        out.append(translated)
    return {"profiles": out}


def _t_sicf_services(rows: List[Dict[str, str]],
                     notes: Dict[str, Any]) -> Dict[str, List[Dict[str, str]]]:
    """SICF_SERVICES -> icf_services (ICF_NAME / ICF_ACTIVE / AUTH_REQUIRED).

    SAP's 2ANETCF policy reads this store for its 27 service-deactivation checks
    (webrfc, IDoc/IDoc_XML, bsp_veri, certmap, certreq, echo, sample paths).
    """
    out = []
    for row in rows:
        path = _pick_pathlike(row, "ICF_NAME", "PATH", "ICF_PATH", "SERVICE_PATH",
                              "URL", "SERVICE", "NAME")
        if not path:
            _skip(notes)
            continue
        active = _pick(row, "ICF_ACTIVE", "ACTIVE", "STATUS", "SERVICE_STATUS")
        auth = _pick(row, "AUTH_REQUIRED", "AUTH", "AUTHENTICATION", "AUTH_TYPE")
        out.append({
            "ICF_NAME": path,
            "ICF_ACTIVE": _norm_flag(active, notes, "ICF_ACTIVE"),
            # Left verbatim: the consumer already reads NO / N / 0 / NONE /
            # ANONYMOUS, and folding "BASIC" or "SSO" into a boolean here would
            # discard which mechanism is in force.
            "AUTH_REQUIRED": auth,
            "SOURCE_STORE": "SICF_SERVICES",
        })
    return {"icf_services": out}


def _norm_action(value: str) -> str:
    """Gateway ACL verdict -> the ``P`` / ``D`` the ACL files themselves use."""
    token = (value or "").strip().upper()
    if token in ("P", "PERMIT", "ALLOW", "ALLOWED", "GRANT"):
        return "P"
    if token in ("D", "DENY", "DENIED", "BLOCK", "REJECT"):
        return "D"
    return token


def _gateway_rows(rows: List[Dict[str, str]], store: str, with_user: bool,
                  notes: Dict[str, Any]) -> List[Dict[str, str]]:
    """Shared secinfo/reginfo translation.

    ⚠️ Worth knowing where this lands: RISE model §3 records secinfo/reginfo as
    OS filesystem artifacts a RISE customer cannot reach, so the gateway ACL
    checks were written off as unreachable. SAP's own 1ARFCGW policy reads them as
    CSA config stores — which means this ingestion path *closes* that gap rather
    than merely restating it.

    WHY ONLY `RULE` COMES OUT, WHEN THE CHECK ALSO READS ACTION/TP/HOST/USER
    -----------------------------------------------------------------------
    Forwarding the structured columns as well is tempting and was tried. It makes
    the gateway checks behave DIFFERENTLY on a CSA export than on the identical
    ACL supplied as a native file: the permit-all detection matches the literal
    word "PERMIT" in the rule text, but takes a structured `ACTION` column of "P"
    as a permit — so the same system produces three extra CRITICAL findings purely
    because of which file it arrived in.

    An importer that changes which findings fire is not a translator. So the
    structured fields are folded back into the ACL's own notation, which is what a
    native export carries and what the checks were written against. Nothing is
    lost: `P TP=* HOST=* USER=*` states every field verbatim.

    (The underlying false negative — a `P `-prefixed permit-all rule not being
    recognised as a permit — is real and is a defect in the gateway check, not in
    this translation. It affects native exports today and is out of scope here.)
    """
    out = []
    for row in rows:
        raw = _pick(row, "RULE", "LINE", "ENTRY", "RAW", "TEXT")
        action = _norm_action(_pick(row, "ACTION", "ACCESS", "PERMISSION",
                                    "VERDICT"))
        program = _pick(row, "TP", "PROGRAM", "TP_NAME", "PROGRAM_NAME")
        host = _pick(row, "HOST", "FROM_HOST", "HOSTNAME", "SOURCE_HOST")
        user = _pick(row, "USER", "USER_NAME", "USERNAME") if with_user else ""

        if not raw:
            parts = []
            if action:
                parts.append(action)
            if program:
                parts.append("TP={0}".format(program))
            if host:
                parts.append("HOST={0}".format(host))
            if user:
                parts.append("USER={0}".format(user))
            raw = " ".join(parts)
        if not raw:
            _skip(notes)
            continue
        out.append({"RULE": raw, "SOURCE_STORE": store})
    return out


def _t_gw_secinfo(rows: List[Dict[str, str]],
                  notes: Dict[str, Any]) -> Dict[str, List[Dict[str, str]]]:
    """GW_SECINFO -> gw_secinfo (external program start ACL)."""
    return {"gw_secinfo": _gateway_rows(rows, "GW_SECINFO", True, notes)}


def _t_gw_reginfo(rows: List[Dict[str, str]],
                  notes: Dict[str, Any]) -> Dict[str, List[Dict[str, str]]]:
    """GW_REGINFO -> gw_reginfo (RFC server registration ACL)."""
    return {"gw_reginfo": _gateway_rows(rows, "GW_REGINFO", False, notes)}


def _t_audit_configuration_slot(rows: List[Dict[str, str]],
                                notes: Dict[str, Any]) -> Dict[str, List[Dict[str, str]]]:
    """AUDIT_CONFIGURATION_SLOT -> audit_config (RSAU_CONFIG filter slots).

    Slots are what SAP's 2AAUDIT policy counts when it requires a minimum of ten
    filter slots, and they are what our audit-filter checks read.
    """
    out = []
    for row in rows:
        slot = _pick(row, "SLOT", "SLOT_NO", "SLOT_NUMBER", "FILTER_ID", "SLOT_ID")
        name = _pick(row, "FILTER_NAME", "SLOT_NAME", "PROFILE_NAME", "NAME",
                     "FILTER")
        if not name and slot:
            name = "SLOT_{0}".format(slot)
        if not name:
            _skip(notes)
            continue
        translated = {
            "FILTER_NAME": name,
            "ACTIVE": _norm_flag(_pick(row, "ACTIVE", "IS_ACTIVE", "STATUS",
                                       "ENABLED"), notes, "ACTIVE"),
            "EVENT_CLASS": _pick(row, "EVENT_CLASS", "CLASS", "AUDIT_CLASS",
                                 "EVENT_TYPE"),
            "CLIENT": _pick(row, "CLIENT", "MANDT", "CLNT"),
            "SOURCE_STORE": "AUDIT_CONFIGURATION_SLOT",
        }
        if slot:
            translated["SLOT"] = slot
        # Only forwarded when the export says so. Defaulting an absent value to
        # STATIC would make a dynamic-only configuration look permanent.
        profile_type = _pick(row, "PROFILE_TYPE", "TYPE", "FILTER_TYPE")
        if profile_type:
            translated["PROFILE_TYPE"] = profile_type
        user = _pick(row, "USER", "USERNAME", "AUDIT_USER")
        if user:
            translated["USER"] = user
        out.append(translated)
    return {"audit_config": out}


def _t_clients(rows: List[Dict[str, str]],
               notes: Dict[str, Any]) -> Dict[str, List[Dict[str, str]]]:
    """CLIENTS -> client_settings (T000 / SCC4).

    Client number and role translate cleanly: the role code ``P`` is already what
    the production test reads.

    The three change-option fields do NOT translate cleanly. T000 stores them as
    single-character codes whose meanings are in no source we hold, and the
    consumer's risky-value test reads text. Decoding them by guess would either
    invent a CRITICAL "production client is modifiable" finding or clear a real
    one. So a code-shaped value is forwarded under a ``RAW_`` name — invisible to
    the check, visible in the import report as ``undecoded_client_codes``.
    """
    out = []
    for row in rows:
        client = _pick(row, "CLIENT", "MANDT", "CLNT", "CLIENT_NUMBER")
        if not client:
            _skip(notes)
            continue
        translated = {
            "CLIENT": client,
            "ROLE": _pick(row, "ROLE", "CLIENT_ROLE", "CCCATEGORY", "CATEGORY"),
            "SOURCE_STORE": "CLIENTS",
        }
        for canonical, aliases in (
            ("CHANGES_ALLOWED", ("CHANGES_ALLOWED", "CCCORACTIV", "CHANGE_OPTION")),
            ("CROSS_CLIENT_CHANGES", ("CROSS_CLIENT_CHANGES", "CCNOCLIIND",
                                      "CROSS_CLIENT")),
            ("REPOSITORY_CHANGES", ("REPOSITORY_CHANGES", "CCCOPYLOCK",
                                    "REPO_CHANGES")),
        ):
            value = _pick(row, *aliases)
            if not value:
                continue
            if _is_code_like(value):
                translated["RAW_" + canonical] = value
                notes.setdefault("undecoded_client_codes", []).append(
                    "client {0}: {1}={2}".format(client, canonical, value))
            else:
                translated[canonical] = value
        out.append(translated)
    return {"client_settings": out}


def _t_ms_secinfo(rows: List[Dict[str, str]],
                  notes: Dict[str, Any]) -> Dict[str, List[Dict[str, str]]]:
    """MS_SECINFO -> ms_acl (message server ACL).

    Like the gateway ACLs, RISE model §3 records this as an OS-level file out of
    the customer's reach. As a CSA config store it is reachable.
    """
    out = []
    for row in rows:
        host = _pick(row, "HOST", "HOSTNAME", "ADDR", "IP", "SOURCE_HOST")
        line = _pick(row, "LINE", "RULE", "ACL", "ENTRY", "RAW")
        service = _pick(row, "SERVICE", "PORT")
        if not line:
            parts = []
            if host:
                parts.append("HOST={0}".format(host))
            if service:
                parts.append("SERVICE={0}".format(service))
            line = " ".join(parts)
        if not host and not line:
            _skip(notes)
            continue
        out.append({
            "HOST": host,
            "LINE": line,
            "SOURCE_STORE": "MS_SECINFO",
        })
    return {"ms_acl": out}


#: store -> translator. Keys must match STORE_TARGETS exactly; the test suite
#: asserts it, because a store listed as translatable with no translator would
#: report coverage we do not have.
TRANSLATORS = {
    "ABAP_INSTANCE_PAHI": _t_abap_instance_pahi,
    "STANDARD_USERS": _t_standard_users,
    "AUTH_PROFILE_USER": _t_auth_profile_user,
    "SICF_SERVICES": _t_sicf_services,
    "GW_SECINFO": _t_gw_secinfo,
    "GW_REGINFO": _t_gw_reginfo,
    "AUDIT_CONFIGURATION_SLOT": _t_audit_configuration_slot,
    "CLIENTS": _t_clients,
    "MS_SECINFO": _t_ms_secinfo,
}  # type: Dict[str, Callable[[List[Dict[str, str]], Dict[str, Any]], Dict[str, List[Dict[str, str]]]]]


# --------------------------------------------------------------------------- #
#  Discovery                                                                  #
# --------------------------------------------------------------------------- #

def store_for_filename(filename: str) -> Optional[str]:
    """Which CSA store does this filename name, if any?

    Accepts ``ABAP_INSTANCE_PAHI.csv``, ``CSA_ABAP_INSTANCE_PAHI.json`` and
    ``ABAP_INSTANCE_PAHI_PRD_00.csv``. Matching is longest-store-first so that
    ``AUDIT_CONFIGURATION_SLOT`` is never filed as ``AUDIT_CONFIGURATION``.
    """
    name = str(filename or "").strip()
    if not name:
        return None
    lowered = name.lower()
    if not lowered.endswith(_DATA_SUFFIXES):
        return None
    stem = name.rsplit(".", 1)[0].strip().upper().replace(" ", "_")
    for prefix in _FILE_PREFIXES:
        if stem.startswith(prefix):
            stem = stem[len(prefix):]
            break
    for store in KNOWN_STORES:
        if stem == store:
            return store
        if stem.startswith(store) and stem[len(store):len(store) + 1] in _SUFFIX_SEPARATORS:
            return store
    return None


def discover_stores(directory: Any,
                    skip_files: Optional[Any] = None) -> Dict[str, Path]:
    """Map recognised store name -> file, for one export directory.

    `skip_files` are filenames (case-insensitive) already claimed by the loader's
    filename map. Without it a native ``standard_users.csv`` would be discovered a
    second time as the STANDARD_USERS store and reported as a Cloud ALM import it
    is not.
    """
    path = Path(directory)
    if not path.is_dir():
        return {}
    skip = set(f.lower() for f in (skip_files or ()))
    found = {}  # type: Dict[str, Path]
    for entry in sorted(path.iterdir()):
        if not entry.is_file() or entry.name.lower() in skip:
            continue
        store = store_for_filename(entry.name)
        # First file wins, deterministically: iteration is sorted.
        if store and store not in found:
            found[store] = entry
    return found


#: There is deliberately no `looks_like_cloudalm_export(directory)` helper. Three
#: store names collide with our own filenames — STANDARD_USERS, GW_SECINFO,
#: GW_REGINFO — so any such predicate answers "yes, Cloud ALM" for a perfectly
#: ordinary native export directory unless the caller also passes the list of files
#: the filename pass already claimed. A convenience function whose one-argument form
#: is wrong is worse than no function. Call `discover_stores` and decide.


# --------------------------------------------------------------------------- #
#  Reading + translation                                                      #
# --------------------------------------------------------------------------- #

def _read_json_rows(path: Path) -> List[Any]:
    """Rows out of a JSON store export.

    Accepts a bare list, and the ``{"value": [...]}`` envelope an OData response
    uses — Cloud ALM's documented analytics interface is OData, so an operator who
    saves a response body straight to disk gets the envelope.
    """
    with open(str(path), "r", encoding="utf-8-sig") as handle:
        payload = json.load(handle)
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("value", "rows", "records", "results", "d", "items"):
            inner = payload.get(key)
            if isinstance(inner, list):
                return inner
            if isinstance(inner, dict) and isinstance(inner.get("results"), list):
                return inner["results"]
    return []


def translate_store(store: str,
                    rows: Any) -> Tuple[Dict[str, List[Dict[str, str]]], Dict[str, Any]]:
    """Translate one store's rows. Returns ``(logical sources, notes)``.

    An unknown or untranslatable store yields ``({}, notes)`` with a reason in
    ``notes["status"]`` rather than an exception: an export carrying a store we do
    not handle must not abort the ones we do.
    """
    name = str(store or "").strip().upper()
    notes = {"store": name, "rows_in": 0, "status": "unknown_store"}  # type: Dict[str, Any]
    if name in UNMAPPED_STORES:
        notes["status"] = "recognised_not_translated"
        notes["reason"] = UNMAPPED_STORES[name]
        notes["technology"] = STORE_TECHNOLOGY.get(name, "ABAP")
        return {}, notes
    translator = TRANSLATORS.get(name)
    if translator is None:
        return {}, notes

    normalised = [_norm_row(row) for row in (rows or [])]
    normalised = [row for row in normalised if row]
    notes["rows_in"] = len(normalised)
    notes["status"] = "translated"
    notes["technology"] = "ABAP"
    translated = translator(normalised, notes)
    translated = {key: value for key, value in translated.items() if value}
    notes["targets"] = dict((key, len(value)) for key, value in translated.items())
    return translated, notes


def load_cloudalm(directory: Any,
                  csv_reader: Optional[Callable[[Path], List[Dict[str, str]]]] = None,
                  json_reader: Optional[Callable[[Path], Any]] = None,
                  skip_files: Optional[Any] = None
                  ) -> Tuple[Dict[str, List[Dict[str, str]]], List[Dict[str, Any]]]:
    """Translate every recognised store in `directory`.

    Returns ``(logical sources, import report)``. The report is one entry per
    store file found — including the ones we refused — so the operator can see
    exactly what arrived and what became of it.

    `csv_reader` / `json_reader` let the caller supply its own file readers; the
    DataLoader passes its own so delimiter sniffing and header normalisation stay
    in one place. Standalone callers get a stdlib default.
    """
    report = []  # type: List[Dict[str, Any]]
    merged = {}  # type: Dict[str, List[Dict[str, str]]]

    for store, path in sorted(discover_stores(directory, skip_files).items()):
        entry = {"store": store, "file": path.name}
        try:
            if path.suffix.lower() == ".json":
                rows = (json_reader(path) if json_reader else _read_json_rows(path))
                if isinstance(rows, dict):
                    rows = _rows_from_mapping(rows)
            elif csv_reader is not None:
                rows = csv_reader(path)
            else:
                rows = _read_csv_rows(path)
        except Exception as exc:                      # noqa: BLE001 - reported, not raised
            entry["status"] = "unreadable"
            entry["reason"] = "{0}: {1}".format(type(exc).__name__, exc)
            report.append(entry)
            continue

        translated, notes = translate_store(store, rows if isinstance(rows, list) else [])
        entry.update(notes)
        report.append(entry)
        for key, value in translated.items():
            merged.setdefault(key, []).extend(value)

    return merged, report


def _rows_from_mapping(payload: Dict[str, Any]) -> List[Any]:
    """Unwrap an OData-style envelope a caller's json_reader handed back."""
    for key in ("value", "rows", "records", "results", "d", "items"):
        inner = payload.get(key)
        if isinstance(inner, list):
            return inner
        if isinstance(inner, dict) and isinstance(inner.get("results"), list):
            return inner["results"]
    return []


def _read_csv_rows(path: Path) -> List[Dict[str, str]]:
    """Stdlib CSV fallback for standalone use.

    Deliberately minimal: the DataLoader has the delimiter-sniffing reader and
    passes it in, so this exists only so the module can be used, and tested,
    without one.
    """
    rows = []  # type: List[Dict[str, str]]
    with open(str(path), "r", encoding="utf-8-sig", newline="") as handle:
        sample = handle.read(4096)
        handle.seek(0)
        delimiter = ","
        for candidate in ("\t", ";", "|"):
            if sample.count(candidate) > sample.count(","):
                delimiter = candidate
                break
        for row in csv.DictReader(handle, delimiter=delimiter):
            rows.append(row)
    return rows


def summarise(report: List[Dict[str, Any]]) -> List[str]:
    """One human-readable line per store, for the loader's console output."""
    lines = []
    for entry in report or ():
        store = entry.get("store", "?")
        status = entry.get("status")
        if status == "translated":
            targets = entry.get("targets") or {}
            filled = ", ".join("{0}={1}".format(k, v)
                               for k, v in sorted(targets.items()))
            lines.append("{0} -> {1}".format(store, filled or "(no usable rows)"))
        elif status == "recognised_not_translated":
            lines.append("{0} -> not translated ({1})".format(
                store, (entry.get("reason") or "").split(".")[0]))
        elif status == "unreadable":
            lines.append("{0} -> unreadable ({1})".format(store, entry.get("reason")))
        else:
            lines.append("{0} -> {1}".format(store, status or "unknown"))
    return lines
