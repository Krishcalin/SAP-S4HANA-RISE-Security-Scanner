# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
BTP Administrative Export Importers
=====================================
Translators from the OUTPUT of documented SAP BTP administration tooling into the
logical data sources the existing ``btpcloud`` / ``s4authz`` checks already read.

WHY THIS MODULE EXISTS
----------------------
BTP is the mirror image of the ABAP stack in a RISE landscape: the customer owns
it outright and SAP publishes a proper CLI and proper APIs for it, so it is the one
layer where evidence collection can be complete and automated with no SAP ticket,
no transport and no ECS involvement (docs/RISE_SECURITY_MODEL.md §7.3).

WHY FILES AND NOT A LIVE CLIENT
-------------------------------
There is no live connection to SAP anywhere in `modules/` or `server/`, and there
is none here. Decision D2 (docs/DECISIONS.md) admitted connectors to an
out-of-process `collect/` package, and this paragraph is deliberately UNCHANGED in
substance by that: a connector's only output is a file, so what reaches the
function below is an already-parsed payload either way. If a connector ever
imports this module rather than writing a file, that is the boundary being
crossed and the mistake this note exists to prevent. Every function below takes an ALREADY-PARSED JSON payload — a file the
customer produced by running the `btp` CLI, by curling their own Cloud Connector
(which runs on their infrastructure), or by retrieving audit-log records — and
returns our shapes. An OAuth + pagination client against SAP's endpoints cannot be
exercised or verified in this repository, and shipping unverifiable network code
would be a capability claim we could not stand behind.

WHAT EACH COMMAND ACTUALLY RETURNS, AND WHAT IS UNCERTAIN
----------------------------------------------------------
Read this before changing a field name. The shapes below are what the importers
LOOK FOR; every one of them degrades to "skip the record" rather than to a guess.

``btp --format json list accounts/subaccount``
    The Accounts Service subaccount list. Records carry ``guid``,
    ``technicalName``, ``displayName``, ``globalAccountGUID``, ``parentGUID``,
    ``region``, ``subdomain``, ``state``, ``usedForProduction``, ``createdDate``,
    ``modifiedDate``, ``description``, ``labels``, ``customProperties``.
    UNCERTAIN: whether the CLI emits a bare array or wraps it as ``{"value": [...]}``
    — both are accepted, along with ``subaccounts`` / ``items`` / ``content``.
    NOT PRESENT in this output: audit-log enablement, and the environment type
    (Cloud Foundry / Kyma) which is a separate `list accounts/environment-instance`.
    Neither is invented here.

``btp --format json list security/settings``
    The subaccount's security settings. Fields observed in SAP's documentation for
    this settings object: ``defaultIdentityProvider``,
    ``treatUsersWithSameEmailAsSameUser``, ``accessTokenValidity``,
    ``refreshTokenValidity``, ``iframeDomains`` / ``iframeDomainsList``,
    ``customEmailDomains``.
    UNCERTAIN, and the reason this importer is written defensively: whether the verb
    is `list` or `get`, whether the output is one object or an array, and — the part
    that matters for correctness — whether the output NAMES the subaccount it
    describes. It is emitted for the CURRENTLY TARGETED subaccount, so a payload
    that carries no subaccount id can only be attributed when exactly one subaccount
    is known. When several are known and the payload names none, the settings are
    kept as their own source and attributed to nothing. Guessing here would put one
    subaccount's identity provider on another subaccount's finding.

``btp --format json list security/role-collection``
    Role collections of the targeted subaccount: ``name``, ``description``,
    ``isReadOnly``, and — when the output is the detailed form — ``roleReferences``,
    ``userReferences``, ``groupReferences`` and ``attributeReferences``.
    UNCERTAIN: whether the LIST verb returns the references at all (the GET verb for
    a single collection certainly does). A collection with no references therefore
    yields a row with an empty mapping rather than an assertion that it is unmapped.

Cloud Connector ``/api/v1/configuration`` (customer-hosted, curl-able)
    Sub-resources of interest: ``.../connector/version`` (``{"version": "2.16.2"}``),
    ``.../subaccounts`` (tunnel state + subaccount certificate),
    ``.../subaccounts/{regionHost}/{subaccount}/systemMappings``
    (``virtualHost``, ``virtualPort``, ``localHost``, ``localPort``, ``protocol``,
    ``backendType``, ``authenticationMode``, ``sid``, ``description``), and
    ``.../systemMappings/{virtualHost}:{virtualPort}/resources``
    (``id`` — the PATH — plus ``enabled``, ``exactMatchOnly``,
    ``websocketUpgradeAllowed``, ``description``).
    UNCERTAIN: the exact certificate field names, and whether a deployment returns
    timestamps as epoch milliseconds or as strings. Both are accepted.
    Because the customer curls several endpoints, the importer accepts one combined
    document, a bare array of system mappings, or a dict keyed by endpoint path, and
    harvests whatever it recognises out of any of them.

auditlog-management ``/auditlog/v2/auditlogrecords``
    Audit log records: ``uuid``, ``user``, ``time``, ``tenant``, ``org_id``,
    ``space_id``, ``category``, ``format_version``, ``message``, ``attributes``.
    UNCERTAIN: whether a page is a bare array or an object carrying a ``handle`` for
    the next page. Both are accepted; multiple concatenated pages are also accepted.

WHAT IS DELIBERATELY **NOT** DERIVED
--------------------------------------
These are the places where a plausible-looking translation would manufacture a
finding out of an export that cannot support it:

  * **Audit-log retention is not derived from the records.** The span of records in
    an export is a function of the time window the customer asked for, not of the
    retention the plan provides. Reporting "90 days of retention" from a 90-day pull
    would be a fabricated measurement.
  * **Cloud Connector host ACLs are not synthesised.** The Cloud Connector's access
    control IS its system mappings plus their resource lists; the configuration API
    exposes no per-subaccount allowed-host list. Emitting an empty
    ``accessControlLists`` entry would make BTP-CC-004 report "unrestricted ACL"
    from data that has no such concept.
  * **A system mapping's ``creationDate`` is not mapped to ``lastUsed``.** They are
    different facts, and conflating them would make BTP-CC-007 call a busy backend
    stale.
  * **Absence is never read as "disabled".** ``auditLogEnabled`` and ``customIdp``
    are written as the literal ``"unknown"`` on records this module mints when no
    export carries the fact, because the consuming checks treat a MISSING flag as
    "off" — and "you have no audit logging" inferred from a subaccount list that
    never contained the field is a false finding, not a conservative one. Positive
    evidence (a settings export, records observed for a tenant) replaces the
    placeholder; nothing else does.
  * **A subaccount absent from an audit-log export is not marked as lacking audit
    logging.** An export scoped to one subaccount says nothing about the others.

TOLERANCE IS THE DESIGN
-----------------------
Every importer returns ``None`` when it does not RECOGNISE the payload, and
``apply()`` then leaves the existing data untouched. That is what lets these
translators sit directly on the canonical logical sources: a hand-made
``cloud_connector.json`` in our own shape is not recognised as API-shaped, so it
passes through unmodified, while a curl dump of the configuration API is translated.
Unrecognised records inside a recognised payload are skipped, not guessed at.
"""

import datetime
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

#: Written into a field the consuming check reads as a boolean, when NO export
#: carries the fact. The checks treat a missing/false value as "the control is
#: off"; this placeholder is falsy to a human and truthy to `if not value`, so it
#: suppresses a claim we cannot support instead of asserting one. Positive
#: evidence overwrites it; nothing else does.
UNKNOWN = "unknown"

#: Container keys a JSON API or CLI might wrap a record list in.
_WRAPPER_KEYS = ("value", "items", "content", "results", "result", "records",
                 "data", "elements", "entries")

_EPOCH = datetime.datetime(1970, 1, 1)

_ISO_DATE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})")
_DE_DATE = re.compile(r"^(\d{2})\.(\d{2})\.(\d{4})")
_VERSION = re.compile(r"^\d+(\.\d+)+")


# ═══════════════════════════════════════════════════════════════════════════
#  Generic tolerant helpers
# ═══════════════════════════════════════════════════════════════════════════

def _dicts(value: Any) -> List[Dict[str, Any]]:
    """The dict elements of a list, or an empty list for anything else."""
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return []


def _collect(raw: Any,
             looks_like: Callable[[Dict[str, Any]], bool],
             extra_keys: Tuple[str, ...] = (),
             _depth: int = 0) -> List[Dict[str, Any]]:
    """Pull the records matching `looks_like` out of a tolerant container.

    Accepts a bare list, a wrapped list (``{"value": [...]}``), a single record, a
    dict keyed by endpoint path or by object id, and one or two levels of nesting
    of any of those. The predicate is what keeps the breadth honest: without it a
    recursive search would happily return the first list of dicts it met, whatever
    it actually was.
    """
    if _depth > 6:
        return []

    if isinstance(raw, list):
        matched = [r for r in _dicts(raw) if looks_like(r)]
        if matched:
            return matched
        out: List[Dict[str, Any]] = []
        for item in raw:
            if isinstance(item, (list, dict)):
                out.extend(_collect(item, looks_like, extra_keys, _depth + 1))
        return _dedupe(out)

    if isinstance(raw, dict):
        if looks_like(raw):
            return [raw]
        for key in tuple(extra_keys) + _WRAPPER_KEYS:
            if key in raw:
                got = _collect(raw[key], looks_like, extra_keys, _depth + 1)
                if got:
                    return got
        out = []
        for value in raw.values():
            if isinstance(value, (list, dict)):
                out.extend(_collect(value, looks_like, extra_keys, _depth + 1))
        return _dedupe(out)

    return []


def _dedupe(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Drop repeats by object identity, preserving order.

    A record reachable by two paths through a nested payload is one record, not two.
    """
    seen = set()
    out = []
    for rec in records:
        if id(rec) not in seen:
            seen.add(id(rec))
            out.append(rec)
    return out


def _s(record: Dict[str, Any], *keys: str) -> str:
    """First non-empty value among `keys`, as a stripped string."""
    for key in keys:
        value = record.get(key)
        if value is None:
            continue
        if isinstance(value, bool):
            return str(value).lower()
        text = str(value).strip()
        if text:
            return text
    return ""


def _has_any(record: Dict[str, Any], *keys: str) -> bool:
    return any(key in record for key in keys)


def _count(value: Any) -> int:
    """How many entries a reference list holds. Anything else counts as none."""
    return len(value) if isinstance(value, list) else 0


def _date_string(value: Any) -> str:
    """Normalise a timestamp to ``YYYY-MM-DD``, or pass it through unchanged.

    Cloud Connector timestamps are documented as epoch values in some places and
    rendered as strings in others, so both are accepted. Anything unrecognised is
    handed on verbatim — the consuming checks carry their own flexible date parser,
    and mangling a format we merely failed to recognise would be worse than passing
    it along.
    """
    if value is None or isinstance(value, bool):
        return ""
    if isinstance(value, (int, float)):
        seconds = float(value)
        if seconds <= 0:
            return ""
        if seconds > 1e11:            # milliseconds since the epoch
            seconds /= 1000.0
        if seconds > 4e10:            # not a plausible epoch second either
            return ""
        try:
            return (_EPOCH + datetime.timedelta(seconds=seconds)).strftime("%Y-%m-%d")
        except (OverflowError, ValueError):
            return ""
    text = str(value).strip()
    if not text:
        return ""
    if text.isdigit() and len(text) >= 10:
        return _date_string(int(text))
    match = _ISO_DATE.match(text)
    if match:
        return match.group(0)
    match = _DE_DATE.match(text)
    if match:
        return "%s-%s-%s" % (match.group(3), match.group(2), match.group(1))
    return text


# ═══════════════════════════════════════════════════════════════════════════
#  btp --format json list accounts/subaccount   ->  btp_subaccounts
# ═══════════════════════════════════════════════════════════════════════════

#: Keys that identify an Accounts-Service subaccount record as opposed to one of
#: our own hand-made ``btp_subaccounts.json`` rows. A hand-made row is left alone.
_ACCOUNTS_API_KEYS = ("guid", "technicalName", "globalAccountGUID", "globalAccountGuid",
                      "parentGUID", "parentGuid", "usedForProduction")


def _looks_like_subaccount(record: Dict[str, Any]) -> bool:
    return isinstance(record, dict) and _has_any(record, *_ACCOUNTS_API_KEYS)


def import_subaccounts(raw: Any) -> Optional[Dict[str, Any]]:
    """Translate ``btp list accounts/subaccount`` output into the ``btp_subaccounts``
    shape read by BTP-GOV-001 / BTP-GOV-002.

    Returns ``None`` when the payload is not Accounts-Service shaped, which is how a
    hand-made export in our own shape passes through untouched.
    """
    records = _collect(raw, _looks_like_subaccount, ("subaccounts",))
    if not records:
        return None

    out: List[Dict[str, Any]] = []
    for record in records:
        guid = _s(record, "guid", "id", "subaccountId", "subaccount_id", "subaccount")
        name = _s(record, "displayName", "name", "technicalName", "subdomain")
        if not guid and not name:
            continue                      # unnamed row: nothing to identify it by

        # Start from the record itself so nothing is DISCARDED: a field this
        # translator does not know about is still the customer's data, and dropping
        # it would also make the translation lossy on a second pass — evidence
        # merged onto a record by a later step would vanish the next time apply()
        # ran over the same dict.
        entry: Dict[str, Any] = dict(record)
        entry["id"] = guid
        entry["name"] = name or guid
        # `region` only — the Cloud Connector's `regionHost` is a different fact
        # (a landscape hostname) and must not be folded in here.
        entry["region"] = _s(record, "region", "dataCenter")

        # The two flags the governance checks read. An export that already carries
        # them keeps its own value; only a record that is genuinely silent gets the
        # placeholder, so re-running the importer over a richer export never
        # downgrades a fact to "unknown".
        if _has_any(record, "auditLogEnabled", "hasAuditLog"):
            entry["auditLogEnabled"] = record.get(
                "auditLogEnabled", record.get("hasAuditLog"))
        else:
            entry["auditLogEnabled"] = UNKNOWN

        if _has_any(record, "customIdp", "identityProvider", "trustConfiguration"):
            entry["customIdp"] = record.get(
                "customIdp", record.get("identityProvider",
                                        record.get("trustConfiguration")))
        else:
            entry["customIdp"] = UNKNOWN

        for source_key, target_key in (
            ("subdomain", "subdomain"),
            ("state", "state"),
            ("usedForProduction", "usedForProduction"),
            ("globalAccountGUID", "globalAccountGuid"),
            ("globalAccountGuid", "globalAccountGuid"),
            ("parentGUID", "parentGuid"),
            ("parentGuid", "parentGuid"),
            ("description", "description"),
            ("createdDate", "createdDate"),
            ("modifiedDate", "modifiedDate"),
            ("betaEnabled", "betaEnabled"),
        ):
            value = record.get(source_key)
            if value not in (None, ""):
                entry.setdefault(target_key, value)

        out.append(entry)

    if not out:
        return None
    return {"subaccounts": out}


# ═══════════════════════════════════════════════════════════════════════════
#  btp --format json list security/settings   ->  btp_security_settings
# ═══════════════════════════════════════════════════════════════════════════

_SETTINGS_KEYS = ("defaultIdentityProvider", "treatUsersWithSameEmailAsSameUser",
                  "accessTokenValidity", "refreshTokenValidity",
                  "iframeDomains", "iframeDomainsList", "customEmailDomains")


def _looks_like_settings(record: Dict[str, Any]) -> bool:
    return isinstance(record, dict) and _has_any(record, *_SETTINGS_KEYS)


def import_security_settings(raw: Any) -> Optional[List[Dict[str, Any]]]:
    """Normalise ``btp list security/settings`` output.

    Returns one record per settings object, each carrying the subaccount it names
    (``""`` when the payload does not name one — see the module docstring: the CLI
    reports on the currently TARGETED subaccount and the output is not known to
    repeat its id).
    """
    records = _collect(raw, _looks_like_settings, ("settings", "securitySettings"))
    if not records:
        return None

    # A map keyed by subaccount id — {"<guid>": {...settings...}} — is a shape a
    # customer producing one file per subaccount would plausibly assemble by hand,
    # and the key is then the only place the subaccount is named.
    keyed: Dict[int, str] = {}
    if isinstance(raw, dict):
        for key, value in raw.items():
            if isinstance(value, dict) and _looks_like_settings(value):
                keyed[id(value)] = str(key).strip()

    out: List[Dict[str, Any]] = []
    for record in records:
        entry: Dict[str, Any] = {
            "subaccount": _s(record, "subaccount", "subaccountId", "subaccount_id",
                             "guid", "subaccountGuid") or keyed.get(id(record), ""),
        }
        for key in _SETTINGS_KEYS:
            if key in record:
                entry[key] = record[key]
        out.append(entry)

    return out or None


# ═══════════════════════════════════════════════════════════════════════════
#  btp --format json list security/role-collection
#      ->  btp_role_collection_mappings
# ═══════════════════════════════════════════════════════════════════════════

_ROLE_COLLECTION_KEYS = ("roleReferences", "userReferences", "groupReferences",
                         "attributeReferences", "isReadOnly", "roleTemplateName")


def _looks_like_role_collection(record: Dict[str, Any]) -> bool:
    if not isinstance(record, dict):
        return False
    if not _has_any(record, "name", "roleCollectionName"):
        return False
    return _has_any(record, *_ROLE_COLLECTION_KEYS)


def _reference_name(reference: Any) -> Tuple[str, str]:
    """(mapped value, origin) for one group or attribute reference."""
    if isinstance(reference, str):
        return reference.strip(), ""
    if not isinstance(reference, dict):
        return "", ""
    origin = _s(reference, "origin", "originKey", "identityProvider", "idp")
    # An attribute reference maps an IdP ASSERTION ATTRIBUTE to the collection
    # ("Groups" = "Default"); the value is the group-equivalent, the name qualifies
    # which attribute carried it.
    value = _s(reference, "attributeValue", "groupName", "name", "value", "group")
    return value, origin


def import_role_collections(raw: Any) -> Optional[List[Dict[str, Any]]]:
    """Translate ``btp list security/role-collection`` output into the CSV-shaped
    rows read by S4AUTHZ-008 (birthright role collections).

    Values are stringified so the rows are indistinguishable from the CSV loader's
    output, which produces all-string values.
    """
    records = _collect(raw, _looks_like_role_collection,
                       ("roleCollections", "role_collections"))
    if not records:
        return None

    rows: List[Dict[str, Any]] = []
    for record in records:
        name = _s(record, "name", "roleCollectionName")
        if not name:
            continue

        base = {
            "ROLE_COLLECTION": name,
            "DESCRIPTION": _s(record, "description"),
            "READ_ONLY": _s(record, "isReadOnly", "readOnly"),
            "ROLE_COUNT": str(_count(record.get("roleReferences"))),
            "USER_COUNT": str(_count(record.get("userReferences"))),
        }

        mappings: List[Tuple[str, str, str]] = []   # (group, origin, kind)
        for reference in (record.get("groupReferences") or []):
            value, origin = _reference_name(reference)
            if value:
                mappings.append((value, origin, "group"))
        for reference in (record.get("attributeReferences") or []):
            value, origin = _reference_name(reference)
            attribute = (_s(reference, "attributeName")
                         if isinstance(reference, dict) else "")
            if value:
                mappings.append((value, origin, attribute or "attribute"))

        if not mappings:
            # No reference in the payload is NOT the same as "mapped to nothing" —
            # the list verb may simply not return references. The row is emitted so
            # the collection stays visible in the inventory, with an empty group,
            # which S4AUTHZ-008 correctly ignores rather than treating as birthright.
            row = dict(base)
            row["IDP_GROUP"] = ""
            row["ORIGIN"] = ""
            row["MAPPING_TYPE"] = ""
            rows.append(row)
            continue

        for value, origin, kind in mappings:
            row = dict(base)
            row["IDP_GROUP"] = value
            row["ORIGIN"] = origin
            row["MAPPING_TYPE"] = kind
            rows.append(row)

    return rows or None


# ═══════════════════════════════════════════════════════════════════════════
#  Cloud Connector /api/v1/configuration   ->  cloud_connector
# ═══════════════════════════════════════════════════════════════════════════

#: Cloud Connector `authenticationMode` -> the `principalType` our checks read.
#: Only recognised modes are translated: an unrecognised mode leaves the field
#: ABSENT, and S4AUTHZ-006 explicitly treats absent as "unknown, do not flag".
_AUTH_MODE_TO_PRINCIPAL = {
    "NONE": "None",
    "KERBEROS": "Kerberos",
    "X509_GENERAL": "X509",
    "X509_RESTRICTED": "X509",
    "X509_ATTRIBUTE": "X509",
}

_VERSION_KEYS = ("version", "connectorVersion", "sccVersion", "softwareVersion")

_EXPIRY_KEYS = ("notAfterTimeStamp", "notAfter", "not_after", "validTo",
                "expiryDate", "validUntil")
#: Ordered by preference: an explicit alias/name is what a certificate is CALLED,
#: and only when there is none do we fall back to reading it out of the DN.
_SUBJECT_KEYS = ("alias", "commonName", "name", "subjectDN", "subject")

_CN = re.compile(r"(?:^|,)\s*CN\s*=\s*([^,]+)")


def _looks_like_system_mapping(record: Dict[str, Any]) -> bool:
    if not isinstance(record, dict):
        return False
    if _has_any(record, "virtualHost", "virtual_host"):
        return True
    return ("localHost" in record
            and _has_any(record, "protocol", "localPort", "backendType"))


def _looks_like_certificate(record: Dict[str, Any]) -> bool:
    if not isinstance(record, dict):
        return False
    return _has_any(record, *_EXPIRY_KEYS) and _has_any(record, *_SUBJECT_KEYS)


def _certificate_name(record: Dict[str, Any]) -> str:
    """What to CALL this certificate.

    The Cloud Connector reports a certificate by its distinguished name; every
    other certificate the scanner names — `crypto_posture` reading a STRUST export
    — is named by its short alias. Reducing a DN to its common name keeps one
    convention across both, and keeps the comma out of an identity string that is
    itself comma-joined.
    """
    raw = _s(record, *_SUBJECT_KEYS)
    if not raw:
        return ""
    match = _CN.search(raw)
    return match.group(1).strip() if match else raw


def _looks_like_cc_resource(record: Dict[str, Any]) -> bool:
    if not isinstance(record, dict):
        return False
    if not _has_any(record, "id", "path"):
        return False
    return _has_any(record, "exactMatchOnly", "enabled", "websocketUpgradeAllowed",
                    "workerHost")


def _find_version(raw: Any, _depth: int = 0) -> str:
    """The connector software version, if the payload states it."""
    if _depth > 4:
        return ""
    if isinstance(raw, str):
        return raw.strip() if _VERSION.match(raw.strip()) else ""
    if isinstance(raw, dict):
        for key in _VERSION_KEYS:
            if key in raw:
                found = _find_version(raw[key], _depth + 1)
                if found:
                    return found
        for value in raw.values():
            if isinstance(value, (dict, list)):
                found = _find_version(value, _depth + 1)
                if found:
                    return found
    elif isinstance(raw, list):
        for item in raw:
            found = _find_version(item, _depth + 1)
            if found:
                return found
    return ""


def _resources_for(mapping: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Canonical resource entries for one system mapping.

    The configuration API calls a resource's PATH ``id``; our checks read ``path``.
    That single rename is the whole reason a raw API dump does not work as-is.
    """
    raw = mapping.get("resources", mapping.get("resourceList"))
    out = []
    for resource in _dicts(raw):
        path = _s(resource, "id", "path", "url", "resource")
        if not path:
            continue
        entry: Dict[str, Any] = {"path": path}
        if "exactMatchOnly" in resource:
            entry["exactMatchOnly"] = resource["exactMatchOnly"]
        elif "exact" in resource:
            entry["exactMatchOnly"] = resource["exact"]
        if "enabled" in resource:
            entry["enabled"] = resource["enabled"]
        if "description" in resource:
            entry["description"] = resource["description"]
        out.append(entry)
    if isinstance(raw, list):
        for resource in raw:
            if isinstance(resource, str) and resource.strip():
                out.append({"path": resource.strip()})
    return out


def _backend_label(mapping: Dict[str, Any]) -> str:
    """The one name every check must use for this backend.

    BTP-CC-* reads ``name`` and S4AUTHZ-006 reads ``virtualHost``. If the two
    disagree the same backend becomes two graph nodes, so the translation writes
    ONE string into both.
    """
    host = _s(mapping, "virtualHost", "virtual_host", "name", "backend")
    port = _s(mapping, "virtualPort", "virtual_port")
    if host and port:
        return "%s:%s" % (host, port)
    return host


def import_cloud_connector(raw: Any) -> Optional[Dict[str, Any]]:
    """Translate Cloud Connector ``/api/v1/configuration`` responses into the
    ``cloud_connector`` shape read by BTP-CC-* and S4AUTHZ-006.

    The payload is recognised by its SYSTEM MAPPINGS, and by nothing else. A
    certificate list on its own is not enough: our own hand-made
    ``cloud_connector.json`` also carries one, and translating on that signal would
    rewrite a working export — dropping the backends and the ACLs the checks need,
    because those are in our shape and not the API's. So a dump containing only
    certificates is left alone, and a hand-made export passes through untouched.

    Anything in the payload this translator does not produce — ``accessControlLists``
    and backends already in our own shape — is carried forward rather than dropped,
    so a file holding both a hand-made section and an API dump loses neither.

    No ``accessControlLists`` is ever SYNTHESISED — see the module docstring.
    """
    mappings = _collect(raw, _looks_like_system_mapping,
                        ("systemMappings", "system_mappings", "mappings"))
    if not mappings:
        return None

    certificates_raw = _collect(raw, _looks_like_certificate,
                                ("certificates", "tlsCertificates"))
    version = _find_version(raw)

    # Resources curled separately arrive as their own list. They can only be
    # attributed to a mapping when there is exactly one — otherwise they are
    # dropped, because attaching a resource to the wrong backend would move a
    # wildcard or a WebGUI path onto an innocent system.
    loose_resources: List[Dict[str, Any]] = []
    if len(mappings) == 1 and not mappings[0].get("resources"):
        for candidate in _collect(raw, _looks_like_cc_resource, ("resources",)):
            if candidate not in mappings:
                loose_resources.append(candidate)

    backends: List[Dict[str, Any]] = []
    for mapping in mappings:
        label = _backend_label(mapping)
        if not label:
            continue
        local_host = _s(mapping, "localHost", "local_host", "internalHost", "host")
        local_port = _s(mapping, "localPort", "local_port")
        backend: Dict[str, Any] = {
            "name": label,
            "virtualHost": label,
            "internalHost": ("%s:%s" % (local_host, local_port)
                             if local_host and local_port else local_host),
            "protocol": _s(mapping, "protocol", "type"),
        }
        # Unlike a subaccount record — a flat property bag the governance checks
        # read by explicit key — a backend is read through several FALLBACK chains
        # (`internalHost` -> `host` -> `backendHost`, a resource's `path` -> `url`
        # -> `resource`). Carrying unrecognised raw API keys into it could quietly
        # change what a check sees, so this dict is built field by field. The one
        # cost of that is that a value we already normalised has to be recognised
        # on the way back in, or a second pass over translated data would drop it.
        auth_mode = _s(mapping, "authenticationMode", "authentication_mode").upper()
        principal = (_AUTH_MODE_TO_PRINCIPAL.get(auth_mode)
                     or _s(mapping, "principalType", "principal_type"))
        if principal:
            backend["principalType"] = principal
        for source_key, target_key in (("backendType", "backendType"),
                                       ("sid", "sid"),
                                       ("description", "description")):
            value = _s(mapping, source_key)
            if value:
                backend[target_key] = value

        resources = _resources_for(mapping)
        if not resources and loose_resources:
            resources = _resources_for({"resources": loose_resources})
        if resources:
            backend["resources"] = resources
        backends.append(backend)

    certificates: List[Dict[str, Any]] = []
    for record in certificates_raw:
        name = _certificate_name(record)
        if not name:
            continue
        entry: Dict[str, Any] = {"name": name}
        expiry = _date_string(_s(record, *_EXPIRY_KEYS)
                              or record.get("notAfterTimeStamp"))
        if expiry:
            entry["expiryDate"] = expiry
        key_size = _s(record, "keySize", "key_length", "bits", "keyLength")
        if key_size:
            entry["keySize"] = key_size
        algorithm = _s(record, "algorithm", "signatureAlgorithm", "keyAlgorithm")
        if algorithm:
            entry["algorithm"] = algorithm
        certificates.append(entry)

    out: Dict[str, Any] = {}
    if isinstance(raw, dict):
        # Carry forward the parts of an existing canonical payload this translator
        # does not produce, so translating an API dump never silently deletes them.
        for key in ("accessControlLists", "acls", "allowedSubaccounts"):
            if key in raw:
                out[key] = raw[key]
        backends = [b for b in _dicts(raw.get("backends"))
                    if not _looks_like_system_mapping(b)] + backends
        certificates = [c for c in _dicts(raw.get("certificates"))
                        if not _looks_like_certificate(c)] + certificates

    if version:
        out["version"] = version
    if backends:
        out["backends"] = backends
    if certificates:
        out["certificates"] = certificates
    return out or None


# ═══════════════════════════════════════════════════════════════════════════
#  /auditlog/v2/auditlogrecords   ->  btp_audit_log
# ═══════════════════════════════════════════════════════════════════════════

def _looks_like_audit_record(record: Dict[str, Any]) -> bool:
    if not isinstance(record, dict):
        return False
    if _has_any(record, "uuid", "recordid", "record_id"):
        return True
    return "time" in record and _has_any(record, "category", "tenant", "user")


def import_audit_log_records(raw: Any) -> Optional[Dict[str, Any]]:
    """Summarise auditlog-management records into per-tenant EVIDENCE.

    The output is deliberately a summary and not the records themselves: the
    records are personal data and a scan report is not the place for them. What the
    scanner needs from them is one fact — that this tenant is producing audit
    records — plus enough context for a human to see the window they were pulled
    over. Retention is NOT inferred from that window; see the module docstring.
    """
    records = _collect(raw, _looks_like_audit_record,
                       ("auditlogrecords", "auditLogRecords", "logs"))
    if not records:
        return None

    tenants: Dict[str, Dict[str, Any]] = {}
    categories: Dict[str, int] = {}
    for record in records:
        tenant = _s(record, "tenant", "tenant_id", "tenantId", "subaccount",
                    "subaccountId", "subaccount_id")
        category = _s(record, "category", "eventType", "type")
        if category:
            categories[category] = categories.get(category, 0) + 1
        key = tenant or ""
        bucket = tenants.get(key)
        if bucket is None:
            bucket = {"tenant": key, "records": 0, "earliest": "", "latest": "",
                      "categories": []}
            tenants[key] = bucket
        bucket["records"] += 1
        if category and category not in bucket["categories"]:
            bucket["categories"].append(category)
        stamp = _date_string(_s(record, "time", "timestamp", "recorded_at"))
        if stamp and _ISO_DATE.match(stamp):
            if not bucket["earliest"] or stamp < bucket["earliest"]:
                bucket["earliest"] = stamp
            if not bucket["latest"] or stamp > bucket["latest"]:
                bucket["latest"] = stamp

    for bucket in tenants.values():
        bucket["categories"].sort()

    return {
        "source": "auditlog-management /auditlog/v2/auditlogrecords",
        "record_count": len(records),
        "tenants": [tenants[k] for k in sorted(tenants)],
        "categories": [{"category": c, "records": categories[c]}
                       for c in sorted(categories)],
    }


# ═══════════════════════════════════════════════════════════════════════════
#  Wiring
# ═══════════════════════════════════════════════════════════════════════════

def _subaccount_list(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The mutable subaccount records inside whatever `btp_subaccounts` holds."""
    payload = data.get("btp_subaccounts")
    if isinstance(payload, list):
        return _dicts(payload)
    if isinstance(payload, dict):
        for key in ("subaccounts", "items", "value"):
            found = _dicts(payload.get(key))
            if found:
                return found
    return []


def _match_subaccount(records: List[Dict[str, Any]], key: str) -> Optional[Dict[str, Any]]:
    """The subaccount a settings/audit payload names, or None.

    Matched on the guid first, then subdomain, then display name — every one an
    exact (case-folded) match. A fuzzy match here would attribute one subaccount's
    identity provider to another.
    """
    if not key:
        return None
    wanted = key.strip().lower()
    for field in ("id", "subaccountId", "guid", "subdomain", "name", "displayName"):
        for record in records:
            value = record.get(field)
            if value is not None and str(value).strip().lower() == wanted:
                return record
    return None


def _is_unset(record: Dict[str, Any], *keys: str) -> bool:
    """True when the record makes no claim about these fields.

    A value we ourselves wrote as UNKNOWN counts as no claim; a value the customer's
    own export carries does not, and is never overwritten.
    """
    for key in keys:
        if key not in record:
            continue
        value = record[key]
        if value is None:
            continue
        if isinstance(value, str) and (not value.strip()
                                       or value.strip().lower() == UNKNOWN):
            continue
        return False
    return True


def _merge_settings(data: Dict[str, Any],
                    settings: List[Dict[str, Any]]) -> Tuple[int, int]:
    """Fold security settings onto the subaccounts they describe.

    Returns (attributed, unattributed).
    """
    records = _subaccount_list(data)
    attributed = 0
    unattributed = 0
    for entry in settings:
        target = _match_subaccount(records, entry.get("subaccount", ""))
        if target is None:
            # The settings output reports on the CURRENTLY TARGETED subaccount. With
            # exactly one subaccount known there is no ambiguity; with several there
            # is, and a wrong attribution is worse than none.
            if not entry.get("subaccount") and len(records) == 1:
                target = records[0]
            else:
                unattributed += 1
                continue

        idp = entry.get("defaultIdentityProvider")
        if (idp not in (None, "")
                and _is_unset(target, "customIdp", "identityProvider",
                              "trustConfiguration")):
            target["customIdp"] = idp
        for key in ("accessTokenValidity", "refreshTokenValidity",
                    "treatUsersWithSameEmailAsSameUser", "iframeDomains",
                    "iframeDomainsList", "customEmailDomains"):
            if key in entry and key not in target:
                target[key] = entry[key]
        attributed += 1
    return attributed, unattributed


def _merge_audit_evidence(data: Dict[str, Any],
                          audit: Dict[str, Any]) -> int:
    """Mark subaccounts that DEMONSTRABLY produce audit records.

    Only ever sets the flag to True, and only for a tenant the export actually
    names. A subaccount missing from the export is left as it was: an export scoped
    to one subaccount is not evidence about the others.
    """
    records = _subaccount_list(data)
    marked = 0
    for bucket in audit.get("tenants", []):
        tenant = bucket.get("tenant", "")
        if not tenant or not bucket.get("records"):
            continue
        target = _match_subaccount(records, tenant)
        if target is None:
            continue
        if _is_unset(target, "auditLogEnabled", "hasAuditLog"):
            target["auditLogEnabled"] = True
            target["auditLogEvidence"] = "%d record(s) retrieved" % bucket["records"]
            marked += 1
    return marked


def apply(data: Dict[str, Any]) -> List[str]:
    """Translate any BTP administrative exports in `data`, in place.

    Returns human-readable notes for the loader to print. A translator that does not
    RECOGNISE its payload changes nothing, which is what lets these run
    unconditionally over every scan without touching hand-made exports.

    Order matters: subaccounts are normalised first so the settings and audit-log
    evidence have something to attach to.
    """
    notes: List[str] = []

    translated = _safe(import_subaccounts, data.get("btp_subaccounts"), notes,
                       "btp_subaccounts")
    if translated is not None:
        data["btp_subaccounts"] = translated
        notes.append("btp_import: %d subaccount(s) from `btp list accounts/subaccount`"
                     % len(translated.get("subaccounts", [])))

    settings = _safe(import_security_settings, data.get("btp_security_settings"),
                     notes, "btp_security_settings")
    if settings is not None:
        data["btp_security_settings"] = settings
        attributed, unattributed = _merge_settings(data, settings)
        note = ("btp_import: %d security-settings record(s), %d attributed to a subaccount"
                % (len(settings), attributed))
        if unattributed:
            note += (" (%d not attributed — the payload names no subaccount and "
                     "several are known)" % unattributed)
        notes.append(note)

    audit = _safe(import_audit_log_records, data.get("btp_audit_log_records"),
                  notes, "btp_audit_log_records")
    if audit is not None:
        data["btp_audit_log"] = audit
        marked = _merge_audit_evidence(data, audit)
        notes.append("btp_import: %d audit log record(s) over %d tenant(s); "
                     "%d subaccount(s) evidenced as logging"
                     % (audit["record_count"], len(audit["tenants"]), marked))

    rows = _safe(import_role_collections, data.get("btp_role_collection_mappings"),
                 notes, "btp_role_collection_mappings")
    if rows is not None:
        data["btp_role_collection_mappings"] = rows
        notes.append("btp_import: %d role-collection mapping row(s) from "
                     "`btp list security/role-collection`" % len(rows))

    connector = _safe(import_cloud_connector, data.get("cloud_connector"), notes,
                      "cloud_connector")
    if connector is not None:
        data["cloud_connector"] = connector
        notes.append("btp_import: Cloud Connector configuration API — %d backend(s), "
                     "%d certificate(s)" % (len(connector.get("backends", [])),
                                            len(connector.get("certificates", []))))

    return notes


def _safe(importer: Callable[[Any], Any], payload: Any, notes: List[str],
          label: str) -> Any:
    """Run one importer, converting a malformed payload into a note.

    A broken export must degrade that one source, not abort the scan — but it must
    also never pass silently, because a silently-skipped import looks exactly like
    an export the customer forgot to send.
    """
    if payload is None:
        return None
    try:
        return importer(payload)
    except Exception as exc:                      # noqa: BLE001 - reported, not swallowed
        notes.append("[WARN] btp_import: could not translate %s: %s" % (label, exc))
        return None
