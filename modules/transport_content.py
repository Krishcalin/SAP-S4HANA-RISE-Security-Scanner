"""Transport Content Auditor — what each transport CARRIES, not just how TMS is set up.

modules/code_transport.py audits the transport SYSTEM: routes, the import history,
approvals, the system-change option. This audits transport CONTENT — the object
directory (E071) of each request, with the request function (E070 TRFUNCTION) —
because a transport's danger is often in WHAT it moves, invisible to a route or
approval check:

  * a single `R3TR TABU TOBJ_OFF` entry (the AUTH_SWITCH_OBJECTS table) globally
    DEACTIVATES an authorization check in the target system;
  * a maintenance-view swap that carries `USRBF2` (the authorization buffer) or the
    user/role tables moves live AUTHORIZATIONS into production as table content;
  * authorization objects, auth defaults and PFCG roles (`R3TR SUSO/SUSH/ACGR`)
    ride through TMS as repository objects;
  * a "transport of copies" (E070 TRFUNCTION 'T') imported to production delivers
    objects OUTSIDE the dev→QA→prod path the route checks assume.

SAP's own release check offers to warn on "critical objects" for exactly these
reasons; this reads them from the E070/E071 object directory the customer exports,
never from the binary cofile/datafile (that parsing is a deliberate non-goal — the
object directory answers the security question without it).

Data sources:
  - transport_objects.csv  → E071 object entries + E070 request function:
                             TRKORR, TRFUNCTION, PGMID, OBJECT, OBJ_NAME
  - transport_history.csv  → STMS import log (reused) — which request reached a
                             production target.

NEVER FABRICATES. Request ids, object types, tables and names come straight from
the export; a row missing its identifier contributes no graph object. The critical-
table and security-object-type lists below are real SAP identifiers, and the risk
is the payload riding through TMS, not the table itself.
"""
from typing import Any, Dict, List, Set

from modules.base_auditor import BaseAuditor


class TransportContentAuditor(BaseAuditor):

    CATEGORY = "Code & Transport Security"

    # ── R3TR TABU table names whose CONTENT in a transport is a security event ──
    # The AUTH_SWITCH_OBJECTS global authorization-check switch-off.
    _AUTH_DEACTIVATION_TABLES: Set[str] = {"TOBJ_OFF"}
    # User master, logon, the authorization buffer, role assignment and SU24
    # defaults — moving any of these as table content transports authorizations.
    _AUTH_USER_TABLES: Set[str] = {
        "USRBF2", "UST04", "UST10C", "UST10S", "UST12",     # auth buffer / profiles
        "USR02", "USR04", "USR12", "USR21", "USR40",        # user master / logon
        "USH02", "USH04", "USH12",                           # user change history
        "AGR_1251", "AGR_1252", "AGR_USERS", "AGR_DEFINE", "AGR_AGRS",  # PFCG roles
        "USOBT", "USOBX", "USOBT_C", "USOBX_C",             # SU24 auth defaults
        "USGRP", "USGRP_USER",                               # user groups
    }
    # R3TR object TYPES that are security configuration carried as repository objects.
    _SECURITY_OBJECT_TYPES: Dict[str, str] = {
        "SUSO": "authorization object",
        "SUSC": "authorization object class",
        "SUSH": "authorization default (SU22/SU24)",
        "SUSM": "authorization profile",
        "SUCR": "authorization field",
        "ACGR": "role (PFCG)",
    }
    _PROD_INDICATORS = ("PRD", "PROD", "PRODUCTION")
    # TRFUNCTION 'T' = transport of copies (SAP's own request-type key).
    _TRANSPORT_OF_COPIES = "T"

    def run_all_checks(self) -> List[Dict[str, Any]]:
        objects = self.data.get("transport_objects")
        if not objects:
            # The object directory was not supplied, so transport CONTENT was not
            # assessed. Disclose it ONLY where it is meaningful — the customer gave
            # us the import HISTORY (so transports exist) but not what they carry.
            # Firing on every estate that supplies no transport data at all would be
            # noise, not honesty.
            if self.data.get("transport_history"):
                self.check_content_not_assessed()
            return self.findings
        self.check_auth_check_deactivation(objects)      # CODE-TMS-006
        self.check_auth_user_table_content(objects)      # CODE-TMS-007
        self.check_transport_of_copies_to_prod(objects)  # CODE-TMS-008
        self.check_security_object_types(objects)        # CODE-TMS-009
        self.check_table_content_transports(objects)     # CODE-TMS-010
        return self.findings

    # ────────────────────────────────────────────────────────────── helpers
    @staticmethod
    def _get(row: dict, *names: str) -> str:
        """Case-insensitive first-non-empty column accessor (as code_transport)."""
        if not isinstance(row, dict):
            return ""
        low = {str(k).strip().upper(): v for k, v in row.items()}
        for n in names:
            v = low.get(n.upper())
            if v not in (None, ""):
                return str(v).strip()
        return ""

    @staticmethod
    def _add_obj(bucket: List[Dict[str, Any]], obj_type: str, name: Any,
                 qualifier: Any = None) -> None:
        n = "" if name is None else str(name).strip()
        if not n:
            return
        obj: Dict[str, Any] = {"type": obj_type, "name": n}
        q = "" if qualifier is None else str(qualifier).strip()
        if q:
            obj["qualifier"] = q
        if obj not in bucket:
            bucket.append(obj)

    def _row_fields(self, row: dict):
        """(trkorr, trfunction, pgmid, object_type, obj_name) from one E071 row."""
        return (self._get(row, "TRKORR", "TRANSPORT", "REQUEST"),
                self._get(row, "TRFUNCTION", "FUNCTION", "REQUEST_TYPE").upper(),
                self._get(row, "PGMID", "PROGRAM_ID").upper(),
                self._get(row, "OBJECT", "OBJECT_TYPE", "OBJ_TYPE").upper(),
                self._get(row, "OBJ_NAME", "OBJECT_NAME", "NAME"))

    @staticmethod
    def _table_name(obj_name: str) -> str:
        """For R3TR TABU the OBJ_NAME is `TABLE/key…`; the table is the part before
        the first slash. Upper-cased for the membership tests."""
        return obj_name.split("/", 1)[0].strip().upper()

    def _is_prod(self, system: str) -> bool:
        s = (system or "").upper()
        return any(p in s for p in self._PROD_INDICATORS)

    # ────────────────────────────────────────────────────── CODE-TMS-006
    def check_auth_check_deactivation(self, objects):
        """A transport that carries the AUTH_SWITCH_OBJECTS table (TOBJ_OFF) applies
        a GLOBAL authorization-check deactivation in the target — the single most
        dangerous thing a transport can carry, because it silently switches off a
        check everywhere the request lands."""
        items, objs = [], []
        for row in objects:
            trkorr, _fn, pgmid, obj_type, obj_name = self._row_fields(row)
            if pgmid == "R3TR" and obj_type == "TABU" \
                    and self._table_name(obj_name) in self._AUTH_DEACTIVATION_TABLES:
                items.append(f"{trkorr}: R3TR TABU {obj_name} "
                             "(AUTH_SWITCH_OBJECTS — deactivates an authorization check)")
                self._add_obj(objs, "transport_request", trkorr)
        if items:
            self.finding(
                check_id="CODE-TMS-006",
                title="Transport deactivates an authorization check (AUTH_SWITCH_OBJECTS)",
                severity=self.SEVERITY_CRITICAL,
                category=self.CATEGORY,
                description=(
                    f"{len(items)} transport(s) carry content for TOBJ_OFF, the "
                    "AUTH_SWITCH_OBJECTS table. Transporting this table's content "
                    "GLOBALLY deactivates one or more authorization checks in the "
                    "target system — an attacker who can get such a request imported "
                    "turns off a security check estate-wide, and no route or approval "
                    "check sees it, because the request looks like ordinary "
                    "customizing."),
                affected_items=items,
                remediation=(
                    "Treat any transport of TOBJ_OFF content as a security change: "
                    "confirm which authorization object it switches off and why, via "
                    "AUTH_SWITCH_OBJECTS, and reverse it unless there is an approved, "
                    "documented reason. Add TOBJ_OFF to the critical-object list of "
                    "the transport release check so future requests are flagged."),
                references=[
                    "SAP transaction AUTH_SWITCH_OBJECTS (global auth-check switch-off)",
                    "SAP transport release check — critical objects",
                ],
                affected_objects=objs,
                scope="aggregate",
            )

    # ────────────────────────────────────────────────────── CODE-TMS-007
    def check_auth_user_table_content(self, objects):
        """Transports carrying user / role / authorization table CONTENT move live
        authorizations between systems — e.g. USRBF2 (the authorization buffer) or
        the AGR_* role tables delivered into production."""
        items, objs = [], []
        hit_tables: Set[str] = set()
        for row in objects:
            trkorr, _fn, pgmid, obj_type, obj_name = self._row_fields(row)
            if pgmid == "R3TR" and obj_type == "TABU":
                table = self._table_name(obj_name)
                if table in self._AUTH_USER_TABLES:
                    hit_tables.add(table)
                    items.append(f"{trkorr}: R3TR TABU {obj_name}")
                    self._add_obj(objs, "transport_request", trkorr)
                    self._add_obj(objs, "table", table)
        if items:
            self.finding(
                check_id="CODE-TMS-007",
                title="Transport carries authorization / user table content",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(items)} transport(s) carry table content for "
                    f"security-relevant tables ({', '.join(sorted(hit_tables))}). "
                    "Moving user master, the authorization buffer (USRBF2), SU24 "
                    "defaults or the AGR_* role tables as transport content delivers "
                    "AUTHORIZATIONS from the source system into the target — "
                    "authorizations that were never granted in the target by its own "
                    "role administration."),
                affected_items=items,
                remediation=(
                    "Authorizations must be built by role administration in each "
                    "system, not transported as table content. Confirm why these "
                    "tables are in a transport, reverse where unintended, and add "
                    "them to the transport release check's critical-object list."),
                references=[
                    "SAP authorization tables (USRBF2 buffer, AGR_* roles, USOBT/USOBX SU24)",
                    "SAP transport release check — critical objects",
                ],
                affected_objects=objs,
                scope="aggregate",
            )

    # ────────────────────────────────────────────────────── CODE-TMS-008
    def check_transport_of_copies_to_prod(self, objects):
        """A transport of copies (E070 TRFUNCTION 'T') imported to production
        delivers objects outside the normal dev→QA→prod path — the route-integrity
        check cannot see it, because a transport of copies does not follow a route."""
        toc_requests: Set[str] = set()
        for row in objects:
            trkorr, fn, _pgmid, _obj_type, _obj_name = self._row_fields(row)
            if trkorr and fn == self._TRANSPORT_OF_COPIES:
                toc_requests.add(trkorr)
        if not toc_requests:
            return
        history = self.data.get("transport_history") or []
        items, objs = [], []
        for row in history:
            trkorr = self._get(row, "TRKORR", "TRANSPORT", "REQUEST")
            target = self._get(row, "TARGET", "TARGET_SYSTEM", "TARGET_SID", "TO_SYSTEM")
            if trkorr in toc_requests and self._is_prod(target):
                items.append(f"{trkorr} → {target} (transport of copies, imported to production)")
                self._add_obj(objs, "transport_request", trkorr)
                self._add_obj(objs, "system", target)
        if items:
            self.finding(
                check_id="CODE-TMS-008",
                title="Transport of copies imported to production",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(items)} transport(s) of copies were imported to a "
                    "production target. A transport of copies carries objects without "
                    "following a transport route, so it bypasses the dev→QA→prod "
                    "sequence the route-integrity control enforces — a way to deliver "
                    "a change straight to production that a routes-only review misses."),
                affected_items=items,
                remediation=(
                    "Restrict who may create and import transports of copies to "
                    "production (S_TRANSPRT, request type TRAN, activity 60). Require "
                    "that production changes follow the normal release path, and "
                    "review each transport of copies that reached production for what "
                    "it delivered."),
                references=[
                    "SAP S_TRANSPRT authorization object (request type TRAN, activity 60)",
                    "SAP transport of copies (TRFUNCTION 'T')",
                ],
                affected_objects=objs,
                scope="aggregate",
            )

    # ────────────────────────────────────────────────────── CODE-TMS-009
    def check_security_object_types(self, objects):
        """Authorization objects, auth defaults and PFCG roles carried as repository
        objects (R3TR SUSO/SUSH/ACGR…): security configuration moving through TMS,
        which should be deliberate and reviewed, not incidental."""
        items, objs = [], []
        hit_types: Set[str] = set()
        for row in objects:
            trkorr, _fn, pgmid, obj_type, obj_name = self._row_fields(row)
            if pgmid == "R3TR" and obj_type in self._SECURITY_OBJECT_TYPES and obj_name:
                hit_types.add(obj_type)
                items.append(f"{trkorr}: R3TR {obj_type} {obj_name} "
                             f"({self._SECURITY_OBJECT_TYPES[obj_type]})")
                self._add_obj(objs, "transport_request", trkorr)
        if items:
            self.finding(
                check_id="CODE-TMS-009",
                title="Transport carries security-configuration objects",
                severity=self.SEVERITY_MEDIUM,
                category=self.CATEGORY,
                description=(
                    f"{len(items)} transport(s) carry security-configuration objects "
                    f"({', '.join(sorted(hit_types))}) — authorization objects, SU24 "
                    "defaults, authorization profiles or PFCG roles. Moving these "
                    "through TMS changes the security configuration of the target; it "
                    "is legitimate when deliberate, but each one should be a reviewed, "
                    "intended security change rather than an incidental passenger."),
                affected_items=items,
                remediation=(
                    "Review each transport that carries authorization objects or "
                    "roles: confirm the security change was intended and approved, "
                    "and that role content matches the target system's design."),
                references=[
                    "SAP object types SUSO/SUSC/SUSH/ACGR (authorization repository objects)",
                ],
                affected_objects=objs,
                scope="aggregate",
            )

    # ────────────────────────────────────────────────────── CODE-TMS-010
    def check_table_content_transports(self, objects):
        """Any remaining R3TR TABU entry: table CONTENT (data, not code) moving
        through TMS. A review item — config-as-data in transports is how settings
        diverge silently between systems — excluding the auth/user tables already
        raised above at higher severity."""
        items, objs = [], []
        raised = self._AUTH_DEACTIVATION_TABLES | self._AUTH_USER_TABLES
        seen: Set[str] = set()
        for row in objects:
            trkorr, _fn, pgmid, obj_type, obj_name = self._row_fields(row)
            if pgmid == "R3TR" and obj_type == "TABU":
                table = self._table_name(obj_name)
                if not table or table in raised:
                    continue
                key = f"{trkorr}:{table}"
                if key in seen:
                    continue
                seen.add(key)
                items.append(f"{trkorr}: R3TR TABU {obj_name}")
                self._add_obj(objs, "transport_request", trkorr)
                self._add_obj(objs, "table", table)
        if items:
            self.finding(
                check_id="CODE-TMS-010",
                title="Table content moved through the transport system",
                severity=self.SEVERITY_MEDIUM,
                category=self.CATEGORY,
                description=(
                    f"{len(items)} transport(s) carry table content (R3TR TABU) other "
                    "than the authorization tables raised separately. Transporting "
                    "table CONTENT moves configuration as data; it is often "
                    "legitimate (currencies, number ranges) but is also how settings "
                    "diverge silently between systems, and content transports warrant "
                    "a review of which table and which keys travelled."),
                affected_items=items,
                remediation=(
                    "Review table-content transports: confirm the table and its keys "
                    "are intended to be delivered rather than maintained per system, "
                    "and that no critical or security-relevant table rides along."),
                references=[
                    "SAP transport object directory — R3TR TABU (table content)",
                ],
                affected_objects=objs,
                scope="aggregate",
            )

    # ────────────────────────────────────────────────────── CODE-TMS-011
    def check_content_not_assessed(self):
        """Import history was supplied but no transport object directory (E070/E071),
        so transport CONTENT was not assessed. An explicit, low-severity disclosure
        so the empty result is not read as a clean one."""
        self.finding(
            check_id="CODE-TMS-011",
            title="Transport content was not assessed (no object directory supplied)",
            severity=self.SEVERITY_INFO,
            category=self.CATEGORY,
            description=(
                "Transport import history was supplied, so transports exist in this "
                "estate — but no transport object directory export (E070/E071, "
                "transport_objects.csv) was, so what those transports CARRY was not "
                "assessed. Only how the transport system is configured (routes, "
                "import history) could be checked. The absence of content findings "
                "here therefore means they were not looked for, not that no transport "
                "carries a security-relevant payload."),
            affected_items=[
                "transport_objects.csv (E070/E071 object directory) not supplied"],
            remediation=(
                "Export the transport object directory (tables E070 and E071, e.g. "
                "via SE16/transport tools) as transport_objects.csv and re-run, to "
                "assess what each transport carries (authorization deactivation, "
                "user/role table content, transports of copies to production)."),
            references=[
                "SAP transport object directory tables E070 (headers) / E071 (objects)",
            ],
        )
