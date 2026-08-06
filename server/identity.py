"""
Finding identity
================
The load-bearing module of the client-server pivot.

WHY THIS EXISTS
---------------
The offline scanner emitted findings with no stable identity. `check_id` is not unique
within a single run — on the bundled sample_data, `USR-001` fires 4 times (once per
unlocked default user), `CODE-STMT-001` 4 times and `RISE-002` twice. Nothing in the
finding dict fingerprinted *which object* was at fault: `affected_items` is a list of
display strings such as "MM_CLERK_01 -> SAP_ALL".

Consequently no finding could be matched against itself across two runs, so the
mitigation journey — the whole point of the pivot — was not computable, and every
re-upload would have reported the entire estate as new.

THE TWO KINDS OF FINDING, AND WHY IT MATTERS
--------------------------------------------
Not every finding names an object, and treating them alike breaks the journey in
opposite directions:

  * OBJECT findings identify one offending thing. "Default user SAP* is unlocked" is
    about SAP*. Its identity must include SAP*, otherwise the four USR-001 rows collapse
    into one and three defects vanish.

  * AGGREGATE findings summarise a set. "23 dormant accounts" is about the check, not
    about any one account. If its identity included the account list, then dismissing a
    single dormant user would retire the old finding and raise a brand-new one — the
    finding would churn every run and its age would reset to zero forever.

So identity is computed over the finding's SUBJECT, never over its full membership. An
object finding's subject is the object; an aggregate finding has no subject and is
identified by (system, client, check_id) alone. Members ride along as data.

FINGERPRINT INPUTS, AND WHAT IS DELIBERATELY EXCLUDED
------------------------------------------------------
Included: schema version, system, client, check_id, and the normalized subject.

Excluded, on purpose:
  * severity — a check whose severity we retune must not orphan its own history
  * title and description — wording changes are editorial, not new defects
  * timestamp — obviously
  * affected_count and the member list — see AGGREGATE above

The schema version is first so that a future change to normalization is a visible,
deliberate break rather than a silent one that quietly resets every customer's history.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

#: Bump ONLY for a deliberate identity break. Doing so resets every stored finding's
#: history, so a migration must map old fingerprints forward before this changes.
FINGERPRINT_SCHEMA = "v1"

#: Object types whose names are SAP identifiers and are therefore case-insensitive.
#: SAP upper-cases these itself; an export that round-trips through Excel may not.
_UPPERCASE_TYPES = frozenset({
    "user", "role", "profile", "system", "client", "destination", "trusted_system",
    "auth_object", "auth_field", "tcode", "program", "report", "table", "function_module",
    "package", "job", "os_command", "hana_user", "hana_role", "hana_privilege",
    "transport", "transport_request", "message_server", "gateway", "parameter_name",
    "idoc_port", "idoc_partner",
    # SE06 system-change-option scopes: SAP namespaces ("/CUST/") and software
    # components ("SAP", "HOME", "LOCAL"). Both are upper-case SAP identifiers.
    "namespace",
    # OData / Gateway service technical name (/IWFND/MAINT_SERVICE SERVICE_NAME, e.g.
    # "API_BUSINESS_PARTNER_SRV"). This is an ABAP repository object name and is
    # therefore upper-cased — deliberately distinct from `endpoint` below, which names
    # case-bearing API-proxy / webhook / web-service-binding entities.
    "odata_service",
    # FI Customizing config-entry keys (financial_controls). The offending object is the
    # ENTRY, not the Customizing table it lives in: a posting-period variant (T001B key,
    # "1000"), an FI tolerance group (T043T, "SUPER"), a document field governed by a
    # change rule (TBAER, "BVTYP") and a number-range object (SNRO/TNRO, "RF_BELEG").
    # All four are upper-case SAP Customizing identifiers.
    "posting_period_variant", "tolerance_group", "document_field", "number_range_object",
    # S/4HANA repository + platform identifiers: a CDS view is a DDL name
    # ("ZC_CUSTOMER_MASTER"), an OData V4 service group a gateway identifier
    # ("ZSG_SALES_ORDER_V4"), and a Cloud Foundry platform role a fixed enumerated
    # name that exports spell "Space Developer", "SPACE_DEVELOPER" or "space developer"
    # for the one role — folding case keeps those one node rather than three.
    "cds_view", "service_group", "cf_role",
    # SAP Security Note numbers (sap_hotnews) and GRC Access Control ruleset objects
    # (grc_access_control). A note number is a numeric SAP identifier ("2934135" — NUMC
    # exports zero-pad it to "0002934135" and the module normalizes it back); a
    # GRACSODRISK risk id ("P2P_01") and a GRACMITCNT mitigating-control id ("MIT_007")
    # are upper-case identifiers maintained in the ABAP GRC system. None of the three
    # is case-bearing.
    "sap_note", "sod_risk", "mitigating_control",
    # Cryptographic library / software component as named by the crypto-library export
    # ("CommonCryptoLib", "sapcryptolib"). This is the component name, not the file it
    # ships as: the installation path is exported separately and is case-bearing, but
    # the component identifier is not, so an export that lower-cases it must not mint a
    # second node for the same library.
    "crypto_library",
})

#: Object types whose names are case-SENSITIVE and must never be upper-cased.
#: An ICF path, a URL, a filesystem path and a BTP entity are all case-bearing;
#: upper-casing them would merge genuinely different objects into one identity.
_CASE_SENSITIVE_TYPES = frozenset({
    "icf_path", "url", "path", "file", "endpoint", "iflow", "destination_url",
    "subaccount", "role_collection", "service_binding", "certificate", "schema",
    "oauth_client", "cpi_datastore", "cpi_variable",
    # BTP / cloud-surface entities. `btp_destination` is deliberately distinct from
    # `destination` above: an SM59 RFC destination is an upper-cased SAP identifier,
    # whereas a BTP Destination-service entry is a case-bearing name ("S4H_Backend"),
    # and folding the two together would upper-case the latter.
    "btp_destination", "ias_application", "cc_backend", "event_queue",
    "cpi_credential", "btp_service",
    # Fiori launchpad content IDs — catalogs, spaces, apps and tiles. These are
    # authored in the launchpad designer / delivered as content and keep the case they
    # were created with ("Finance_Home", "Z_ADMIN_CATALOG", "TILE_001"); they are not
    # ABAP repository names that SAP upper-cases, so folding case here would merge
    # genuinely different launchpad content into one identity and one graph node.
    "fiori_catalog", "fiori_app", "fiori_tile", "fiori_space",
    # Data-protection config entries (data_protection). RAL configurations and log
    # channels (SRALMANAGER), ILM retention policies (IRMPOL), purpose-of-processing
    # entries and cross-border transfer flows are all authored names that keep the case
    # they were typed with ("HR_PersonalData", "HR_MasterData_Retention", "Employment
    # Administration", "EU_to_US_Analytics") — they are not ABAP repository objects that
    # SAP upper-cases, so folding case would merge distinct config entries into one node.
    # `dsar_request` is a data-subject request/ticket id ("DSAR-2025-001"), issued by a
    # ticketing system rather than by SAP, and is likewise case-bearing.
    "ral_config", "ral_channel", "ilm_policy", "processing_purpose",
    "data_transfer", "dsar_request",
    # RISE / S/4HANA Cloud surface. A BTP trust configuration is keyed by its
    # originKey ("sap.default", "corp-aad-tenant") and a communication arrangement by
    # an admin-entered name — both are cloud-cockpit entities that keep the case they
    # were created with, exactly like the BTP entities above, not ABAP repository
    # objects that SAP upper-cases.
    "idp_trust", "comm_arrangement",
})

_WS = re.compile(r"\s+")


class IdentityError(ValueError):
    """Raised when a finding cannot be given a stable identity."""


def norm_sid(value: Any) -> Optional[str]:
    """Normalize an SAP System ID. Three characters, upper case, or None."""
    if value is None:
        return None
    s = _WS.sub("", str(value)).upper()
    return s or None


def norm_client(value: Any) -> Optional[str]:
    """Normalize an SAP client to three digits.

    SAP clients are three-character keys that are conventionally numeric and
    zero-padded: `100`, `000`. Exports routinely lose the padding — a CSV opened in
    Excel turns client 000 into 0 and client 100 stays 100. Left-padding numeric
    values keeps `0`, `00` and `000` one client rather than three.

    A non-numeric client is left alone rather than mangled; SAP permits alphanumeric
    clients even though they are rare.
    """
    if value is None:
        return None
    s = _WS.sub("", str(value))
    if not s:
        return None
    if s.isdigit():
        return s.rjust(3, "0")[-3:] if len(s) > 3 else s.rjust(3, "0")
    return s.upper()


def norm_name(obj_type: str, value: Any) -> str:
    """Normalize an object name according to its type's case rules.

    Internal whitespace is collapsed rather than stripped entirely: a role named
    "Z FIN CLERK" is not the same object as "ZFINCLERK", and silently equating them
    would merge two findings.
    """
    if value is None:
        raise IdentityError("affected object has no name")
    s = _WS.sub(" ", str(value)).strip()
    if not s:
        raise IdentityError("affected object has an empty name")
    t = (obj_type or "").strip().lower()
    if t in _CASE_SENSITIVE_TYPES:
        return s
    if t in _UPPERCASE_TYPES:
        return s.upper()
    # Unknown type: upper-case, because the overwhelming majority of SAP object names
    # are case-insensitive identifiers. A new case-bearing type must be registered in
    # _CASE_SENSITIVE_TYPES — see test_identity.py, which asserts the registries are
    # disjoint and that every type used by a shipped module is registered.
    return s.upper()


class AffectedObject:
    """One concrete SAP object a finding is about.

    `qualifier` narrows the object where the name alone is not the whole story — an
    authorization field value, an RFC destination type, a parameter's actual value. It
    participates in identity, because `S_TABU_DIS` with `DICBERCLS=*` and the same
    object with a narrow class are different defects.
    """

    __slots__ = ("type", "name", "system", "client", "qualifier")

    def __init__(self, type: str, name: Any, system: Any = None,
                 client: Any = None, qualifier: Any = None) -> None:
        t = (type or "").strip().lower()
        if not t:
            raise IdentityError("affected object has no type")
        self.type = t
        self.name = norm_name(t, name)
        self.system = norm_sid(system)
        self.client = norm_client(client)
        q = None if qualifier is None else _WS.sub(" ", str(qualifier)).strip()
        self.qualifier = q or None

    @classmethod
    def coerce(cls, value: Any) -> "AffectedObject":
        if isinstance(value, cls):
            return value
        if isinstance(value, dict):
            return cls(
                type=value.get("type", ""),
                name=value.get("name"),
                system=value.get("system"),
                client=value.get("client"),
                qualifier=value.get("qualifier"),
            )
        raise IdentityError(f"cannot coerce {type(value).__name__} to AffectedObject")

    def key(self) -> str:
        """Canonical string form. This is what the fingerprint hashes."""
        parts = [f"{self.type}:{self.name}"]
        if self.system:
            parts.append(f"@{self.system}")
        if self.client:
            parts.append(f"/{self.client}")
        if self.qualifier:
            parts.append(f"#{self.qualifier}")
        return "".join(parts)

    def as_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"type": self.type, "name": self.name}
        if self.system:
            d["system"] = self.system
        if self.client:
            d["client"] = self.client
        if self.qualifier:
            d["qualifier"] = self.qualifier
        return d

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, AffectedObject) and self.key() == other.key()

    def __hash__(self) -> int:
        return hash(self.key())

    def __repr__(self) -> str:
        return f"AffectedObject({self.key()!r})"


def _canonical_subject(subject: Sequence[AffectedObject]) -> str:
    """Sorted, de-duplicated subject keys joined by a separator that cannot appear in
    a key. Sorting gives set semantics: the order a module happens to append objects
    in is not part of the defect's identity."""
    return ",".join(sorted({o.key() for o in subject}))


def _normalize_display(items: Iterable[Any]) -> str:
    """Fallback basis: the legacy display strings, whitespace-collapsed and sorted.

    This is weaker than a structured subject — an editorial change to how a module
    formats its display string silently re-identifies the finding — which is exactly
    why `fingerprint_basis` is stored alongside, and why the console can show which
    findings have identity we actually trust.
    """
    seen = set()
    for it in items or ():
        s = _WS.sub(" ", str(it)).strip()
        if s:
            seen.add(s)
    return ",".join(sorted(seen))


def compute_fingerprint(
    check_id: str,
    system: Optional[str] = None,
    client: Optional[str] = None,
    subject: Optional[Sequence[Any]] = None,
    affected_items: Optional[Sequence[Any]] = None,
    scope: str = "object",
) -> Tuple[str, str]:
    """Return `(fingerprint, basis)` for one finding.

    `basis` is one of:
      * ``objects``     — identity came from structured affected objects. Trustworthy.
      * ``display``     — identity came from legacy display strings. Stable only while
                          the module's formatting is stable.
      * ``check_only``  — an aggregate finding, or a finding with no object at all.
                          Correct, and correctly coarse.

    The basis is returned rather than inferred later because the console must be able to
    tell a user *why* two findings did or did not match across runs. A journey feature
    that cannot explain a non-match is not trustworthy.
    """
    cid = (check_id or "").strip().upper()
    if not cid:
        raise IdentityError("finding has no check_id")

    sid = norm_sid(system) or ""
    cli = norm_client(client) or ""

    if scope == "aggregate":
        # Deliberately ignores subject and members: see the module docstring.
        payload, basis = "", "check_only"
    else:
        objs = [AffectedObject.coerce(o) for o in (subject or ())]
        if objs:
            payload, basis = _canonical_subject(objs), "objects"
        else:
            display = _normalize_display(affected_items or ())
            payload, basis = (display, "display") if display else ("", "check_only")

    canonical = "|".join((FINGERPRINT_SCHEMA, sid, cli, cid, payload))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return digest, basis


def fingerprint_finding(
    finding: Dict[str, Any],
    system: Optional[str] = None,
    client: Optional[str] = None,
) -> Tuple[str, str]:
    """Fingerprint a finding dict as produced by `BaseAuditor.finding`.

    `system` and `client` are the run-level defaults. A finding that names its own
    system — a cross-system trust finding, for instance — overrides them, because such
    a finding belongs to the system it is *about*, not to the system whose export
    happened to reveal it.
    """
    subject = finding.get("subject") or finding.get("affected_objects") or ()
    objs = [AffectedObject.coerce(o) for o in subject]

    # A finding's own scope declaration wins; otherwise a single named object is
    # treated as the subject and several are treated as a summarised set.
    scope = finding.get("scope")
    if scope not in ("object", "aggregate"):
        scope = "object" if len(objs) == 1 else ("aggregate" if len(objs) > 1 else "object")

    eff_system = finding.get("system") or (objs[0].system if objs else None) or system
    eff_client = finding.get("client") or (objs[0].client if objs else None) or client

    return compute_fingerprint(
        check_id=finding.get("check_id", ""),
        system=eff_system,
        client=eff_client,
        subject=objs if scope == "object" else (),
        affected_items=finding.get("affected_items"),
        scope=scope,
    )


def extract_nodes(findings: Iterable[Dict[str, Any]],
                  default_system: Optional[str] = None) -> List[Dict[str, Any]]:
    """Collect the distinct graph nodes named across a set of findings.

    This is the seam the attack-path graph is built on, and the reason the contract
    change had to land before any console work: with free-text `affected_items`, every
    node here would be a string.
    """
    nodes: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        for raw in (f.get("affected_objects") or f.get("subject") or ()):
            try:
                obj = AffectedObject.coerce(raw)
            except IdentityError:
                continue          # a malformed object must not abort node extraction
            if obj.system is None and default_system:
                obj = AffectedObject(obj.type, obj.name, default_system,
                                     obj.client, obj.qualifier)
            key = obj.key()
            node = nodes.get(key)
            if node is None:
                node = obj.as_dict()
                node["key"] = key
                node["finding_count"] = 0
                node["check_ids"] = set()
                nodes[key] = node
            node["finding_count"] += 1
            node["check_ids"].add(f.get("check_id", ""))
    for node in nodes.values():
        node["check_ids"] = sorted(c for c in node["check_ids"] if c)
    return [nodes[k] for k in sorted(nodes)]
