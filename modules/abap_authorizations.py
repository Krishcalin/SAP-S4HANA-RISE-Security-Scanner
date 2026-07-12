"""
ABAP Authorization & Critical Access Auditor
==============================================
Evaluates the CONTENT of ABAP roles at the authorization-object / field / value
level — the deep SAP authorization analysis that a flat user-value scan cannot
do. It parses an AGR_1251 export (role → object → field → LOW/HIGH) and flags
roles that grant critical authorizations: runtime auth bypass (Debug & Replace),
trusted-RFC impersonation, OS command / file access, authorization forging,
generic table maintenance, broad RFC, run-any-report, batch impersonation, and
sensitive Basis transactions — attributing each to the users who hold the role.

Grounded in the SAP Security Baseline, DSAG audit guidelines, RSUSR008_009_NEW
critical-authorization catalogs, and SAP Notes 65968 / 1416085 / 1481950.

Data sources:
  - role_auth_values.csv  → AGR_1251 export (AGR_NAME, OBJECT, AUTH, FIELD, LOW,
                            HIGH [, DELETED]) — the role authorization values
  - user_roles.csv        → AGR_USERS (UNAME, AGR_NAME) — to count/list holders
  - security_params.csv   → (optional) profile parameters, for auth/object_disabling_active
"""

from typing import Dict, List, Any, Optional
from modules.base_auditor import BaseAuditor


class AbapAuthorizationAuditor(BaseAuditor):

    CATEGORY = "ABAP Authorization & Critical Access"

    # Sensitive Basis / administration transactions that should not sit in
    # broadly-assigned productive roles (grouped by the risk they carry).
    CRITICAL_TCODES = {
        # direct table display/maintenance
        "SE16": "table browser", "SE16N": "table browser (edit)", "SE17": "table display",
        "SM30": "table maintenance", "SM31": "table maintenance", "SE11": "ABAP dictionary",
        "SE14": "DB utility",
        # ABAP development / report execution
        "SE38": "ABAP editor", "SA38": "report execution", "SE80": "object navigator",
        "SE37": "function builder", "SE24": "class builder", "SE93": "maintain transaction codes",
        # OS command execution
        "SM49": "execute external OS command", "SM69": "maintain external OS command",
        # user / role administration
        "SU01": "user maintenance", "SU10": "mass user maintenance", "SU12": "mass user",
        "PFCG": "role maintenance", "SU02": "profile maintenance", "SU03": "authorization maint.",
        # RFC / connectivity
        "SM59": "RFC destinations", "SMT1": "trusted RFC", "SMGW": "gateway monitor",
        # client / system administration
        "SCC4": "client administration", "SCC5": "client delete", "RZ10": "profile parameters",
        "RZ11": "profile parameters", "SICF": "ICF services", "SMICM": "ICM monitor",
        # transport
        "STMS": "transport mgmt", "SE09": "transport organizer", "SE10": "transport organizer",
        # audit / security
        "SM19": "security audit config", "RSAU_CONFIG": "security audit", "SM20": "audit log",
        "SUIM": "user info system", "ST01": "system trace",
        # database / lock & update administration
        "DBACOCKPIT": "DBA cockpit", "DB02": "database monitor",
        "SM12": "lock entries", "SM13": "update administration",
    }

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self._instances = self._build_instances()
        if self._instances is None:
            return self.findings  # no AGR_1251 export → module self-skips
        self._user_by_role = self._user_map()

        self.check_debug_replace()
        self.check_trusted_rfc_acl()
        self.check_os_command()
        self.check_auth_forging()
        self.check_start_any_tcode()
        self.check_broad_s_rfc()
        self.check_icf_destination()
        self.check_table_name_write()
        self.check_table_dis_generic()
        self.check_table_cross_client()
        self.check_os_file_access()
        self.check_run_any_report()
        self.check_batch_impersonation()
        self.check_sensitive_tcodes()
        self.check_developer_change_access()
        self.check_object_disabling()
        return self.findings

    # ------------------------------------------------------------------ parsing
    def _build_instances(self) -> Optional[List[Dict[str, Any]]]:
        rows = self.data.get("role_auth_values")
        if not rows:
            return None
        grouped: Dict[tuple, Dict[str, Any]] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            if str(row.get("DELETED", row.get("DELETED_FLAG", ""))).strip().upper() in ("X", "TRUE", "1"):
                continue
            role = str(row.get("AGR_NAME", row.get("ROLE", row.get("AGR", "")))).strip()
            obj = str(row.get("OBJECT", row.get("AUTH_OBJECT", ""))).strip().upper()
            auth = str(row.get("AUTH", row.get("AUTHORIZATION", row.get("VARIANT", "")))).strip()
            field = str(row.get("FIELD", row.get("FIELD_NAME", ""))).strip().upper()
            low = str(row.get("LOW", row.get("VALUE", row.get("VON", "")))).strip()
            high = str(row.get("HIGH", row.get("BIS", ""))).strip()
            if not role or not obj or not field:
                continue
            key = (role, obj, auth or f"{obj}#default")
            inst = grouped.setdefault(key, {"role": role, "object": obj, "auth": auth, "fields": {}})
            inst["fields"].setdefault(field, []).append((low, high))
        return list(grouped.values())

    def _user_map(self) -> Dict[str, List[str]]:
        by_role: Dict[str, List[str]] = {}
        for row in (self.data.get("user_roles") or []):
            if not isinstance(row, dict):
                continue
            user = str(row.get("UNAME", row.get("USER", row.get("BNAME", "")))).strip()
            role = str(row.get("AGR_NAME", row.get("ROLE", row.get("AGR", "")))).strip()
            if user and role:
                by_role.setdefault(role, []).append(user)
        return by_role

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _covers(pairs: List[tuple], target: str) -> bool:
        """True if a (LOW,HIGH) value set covers `target` (exact / '*' / numeric range).
        Ranges are honoured only for numeric fields (e.g. ACTVT '01'..'99'); a lexical
        range on a symbolic field (OBJTYPE/DICBERCLS/TCD) must NOT bracket the target
        (else 'CLAS'..'FUGR' would falsely 'cover' 'DEBUG')."""
        t = str(target).strip().upper()
        for low, high in pairs:
            lo, hi = str(low).strip().upper(), str(high).strip().upper()
            if lo == "*" or lo == t:
                return True
            if hi and lo.isdigit() and hi.isdigit() and t.isdigit() and lo <= t <= hi:
                return True
        return False

    @staticmethod
    def _has_star(pairs: List[tuple]) -> bool:
        return any(str(low).strip() == "*" for low, _ in pairs)

    @staticmethod
    def _field(inst: Dict[str, Any], field: str) -> List[tuple]:
        return inst["fields"].get(field.upper(), [])

    def _objects(self, *objs: str):
        want = {o.upper() for o in objs}
        return (i for i in self._instances if i["object"] in want)

    def _holders(self, role: str) -> List[str]:
        return self._user_by_role.get(role, [])

    def _role_label(self, role: str, detail: str = "") -> str:
        users = self._holders(role)
        who = f"{len(users)} user(s)" if users else "0 users (unassigned)"
        sample = f" [{', '.join(users[:4])}{'…' if len(users) > 4 else ''}]" if users else ""
        return f"Role {role} — {who}{sample}" + (f" — {detail}" if detail else "")

    def _emit(self, check_id, title, severity, description, offenders, remediation,
              references, details=None):
        if not offenders:
            return
        # sort assigned roles first (higher impact)
        offenders.sort(key=lambda lbl: (0 if "0 users" not in lbl else 1, lbl))
        self.finding(check_id=check_id, title=title, severity=severity, category=self.CATEGORY,
                     description=description, affected_items=offenders, remediation=remediation,
                     references=references, details=details or {})

    # ==================================================================  CRITICAL
    def check_debug_replace(self):
        """S_DEVELOP OBJTYPE=DEBUG + ACTVT=02 → Debug & Replace (runtime auth bypass)."""
        bad = [self._role_label(i["role"], "S_DEVELOP OBJTYPE=DEBUG, ACTVT=02")
               for i in self._objects("S_DEVELOP")
               if self._covers(self._field(i, "OBJTYPE"), "DEBUG")
               and self._covers(self._field(i, "ACTVT"), "02")]
        self._emit(
            "AUTH-001", "Debug & Replace authorization (runtime authorization bypass)",
            self.SEVERITY_CRITICAL,
            f"{len(bad)} role(s) grant S_DEVELOP with OBJTYPE=DEBUG and ACTVT=02. "
            "'Debug & Replace' lets a user halt any program, step over AUTHORITY-CHECK "
            "statements and overwrite field contents (e.g. set SY-SUBRC=0) — bypassing "
            "virtually every ABAP authorization check and altering business data at runtime. "
            "It must never exist in a productive role.",
            bad,
            "Remove ACTVT 02 for OBJTYPE=DEBUG from all productive roles (display-only debug, "
            "ACTVT 03, is normally enough for support). Restrict change-debugging to a "
            "firefighter role in non-production only.",
            ["SAP Note 65968 — Debugging authorizations", "SAP Security Baseline — S_DEVELOP",
             "DSAG Audit Guideline — Debug & Replace"])

    def check_trusted_rfc_acl(self):
        """S_RFCACL with wildcard trust fields → trusted-RFC logon as any user/system."""
        bad = []
        for i in self._objects("S_RFCACL"):
            eq = self._field(i, "RFC_EQUSER")
            eq_forced = self._covers(eq, "Y") and not self._has_star(eq)
            if eq_forced:
                continue  # RFC_EQUSER=Y binds logon to the same user → safe
            if (self._has_star(self._field(i, "RFC_USER"))
                    or self._has_star(self._field(i, "RFC_SYSID"))
                    or self._has_star(self._field(i, "RFC_CLIENT"))):
                bad.append(self._role_label(i["role"], "S_RFCACL RFC_USER/RFC_SYSID = *"))
        self._emit(
            "AUTH-002", "Trusted-RFC logon as any user (S_RFCACL wildcard)",
            self.SEVERITY_CRITICAL,
            f"{len(bad)} role(s) grant S_RFCACL with '*' in the trusted-system/user fields "
            "(and RFC_EQUSER not forced to Y). This allows a trusted calling system to log on "
            "to this system as ANY user without a password — landscape-wide impersonation and "
            "the primary lateral-movement path between trusted SAP systems.",
            bad,
            "Never grant '*' in S_RFCACL. Bind trusted-RFC to specific calling systems/clients "
            "and set RFC_EQUSER='Y' (same-user logon). Migrate to the current trusted-RFC "
            "security model (SAP Note 3157268 / migration of trust relationships).",
            ["SAP Note 1416085 — S_RFCACL wildcard risk", "SAP Note 3157268 — Trusted RFC migration"])

    def check_os_command(self):
        """S_LOG_COM all-wildcard → run any external OS command on any host (SM49/SM69)."""
        bad = [self._role_label(i["role"], "S_LOG_COM COMMAND/HOST/OPSYSTEM = *")
               for i in self._objects("S_LOG_COM")
               if self._has_star(self._field(i, "COMMAND"))
               and self._has_star(self._field(i, "HOST"))]
        self._emit(
            "AUTH-003", "Unrestricted external OS-command execution (S_LOG_COM)",
            self.SEVERITY_CRITICAL,
            f"{len(bad)} role(s) grant S_LOG_COM with COMMAND=* and HOST=*. Combined with the "
            "SM49/SM69 transactions (or SXPG_COMMAND_EXECUTE over RFC) this permits running any "
            "external operating-system command on any application-server host — direct OS-level "
            "code execution and privilege escalation off the ABAP stack.",
            bad,
            "Restrict S_LOG_COM to specific, pre-defined external commands and hosts; never '*'. "
            "Review who holds SM49/SM69 and the defined external OS commands (transaction SM69).",
            ["SAP Security Baseline — S_LOG_COM", "SAP Help — SM49 External OS Commands"])

    def check_auth_forging(self):
        """S_USER_AUT / S_USER_TCD / S_USER_VAL with wildcards → self-escalation."""
        bad = []
        for i in self._objects("S_USER_AUT"):
            if self._has_star(self._field(i, "AUTH")) and (
                    self._covers(self._field(i, "ACTVT"), "01")
                    or self._covers(self._field(i, "ACTVT"), "02")
                    or self._covers(self._field(i, "ACTVT"), "07")):
                bad.append(self._role_label(i["role"], "S_USER_AUT AUTH=* (build any authorization)"))
        for i in self._objects("S_USER_TCD"):
            if self._has_star(self._field(i, "TCD")):
                bad.append(self._role_label(i["role"], "S_USER_TCD TCD=* (put any tcode in a role)"))
        for i in self._objects("S_USER_VAL"):
            bad.append(self._role_label(i["role"], "S_USER_VAL (maintain any field value in a role)"))
        self._emit(
            "AUTH-004", "Authorization forging via role-content control objects",
            self.SEVERITY_CRITICAL,
            f"{len(bad)} role(s) grant S_USER_AUT/S_USER_TCD/S_USER_VAL with wildcards. A role "
            "administrator holding these can define arbitrary authorization values, insert any "
            "transaction, or maintain any field value in a role — building a SAP_ALL-equivalent "
            "for themselves without ever touching S_USER_GRP/AGR/PRO. Classic privilege-escalation.",
            bad,
            "Remove S_USER_AUT/TCD/VAL from non-security-admin roles. Even security administrators "
            "should be scoped (no AUTH=*/TCD=*) and covered by four-eyes change control.",
            ["SAP Security Baseline — role administration objects", "DSAG Audit — self-escalation"])

    def check_start_any_tcode(self):
        """S_TCODE TCD=* → start any transaction."""
        bad = [self._role_label(i["role"], "S_TCODE TCD=*")
               for i in self._objects("S_TCODE")
               if self._has_star(self._field(i, "TCD"))]
        self._emit(
            "AUTH-005", "Role allows starting any transaction (S_TCODE = *)",
            self.SEVERITY_CRITICAL,
            f"{len(bad)} role(s) grant S_TCODE with TCD='*', letting the holder start every "
            "transaction in the system. Combined with the underlying object authorizations this "
            "is effectively unrestricted access and defeats menu-based restriction.",
            bad,
            "Never grant S_TCODE TCD=*. Grant only the specific transactions each role needs "
            "(PFCG menu). Review why the role was built with a full transaction wildcard.",
            ["SAP Security Baseline — S_TCODE", "DSAG Audit Guideline"])

    # ==================================================================  HIGH
    def check_broad_s_rfc(self):
        """S_RFC RFC_TYPE=FUGR + RFC_NAME=* → call any RFC-enabled function module."""
        bad = [self._role_label(i["role"], "S_RFC RFC_NAME=*")
               for i in self._objects("S_RFC")
               if self._has_star(self._field(i, "RFC_NAME"))]
        self._emit(
            "AUTH-006", "Broad RFC authorization (S_RFC RFC_NAME = *)",
            self.SEVERITY_HIGH,
            f"{len(bad)} role(s) grant S_RFC with RFC_NAME='*', permitting remote invocation of "
            "ANY RFC-enabled function module — including RFC_READ_TABLE (read any table), "
            "SXPG_COMMAND_EXECUTE (OS commands) and mass-data BAPIs. A primary data-exfiltration "
            "and lateral-movement surface for any account reachable over RFC / OData.",
            bad,
            "Scope S_RFC to the specific function groups (RFC_NAME) each interface needs; never "
            "'*'. Enable UCON RFC allowlisting to further restrict externally-callable modules.",
            ["SAP Note 1416085", "SAP Help — S_RFC authorization", "Onapsis — RFC FM abuse"])

    def check_icf_destination(self):
        """S_ICF ICF_FIELD=DEST + ICF_VALUE=* → use any RFC/HTTP destination (stored creds)."""
        bad = []
        for i in self._objects("S_ICF"):
            field_vals = self._field(i, "ICF_FIELD")   # DEST (destinations) / SERVICE
            value_vals = self._field(i, "ICF_VALUE")
            # A grant that covers the DEST field (or is '*') combined with ICF_VALUE='*'
            # lets the role select ANY destination maintained in the system.
            if self._covers(field_vals, "DEST") and self._has_star(value_vals):
                bad.append(self._role_label(i["role"], "S_ICF ICF_FIELD=DEST, ICF_VALUE=*"))
        self._emit(
            "AUTH-016", "Use of any RFC/HTTP destination (S_ICF ICF_FIELD=DEST, ICF_VALUE=*)",
            self.SEVERITY_HIGH,
            f"{len(bad)} role(s) grant S_ICF with the DEST field and ICF_VALUE='*', which lets "
            "the holder use ANY RFC or HTTP destination defined in the system (SM59/RFCDES). "
            "Destinations frequently store embedded logon credentials or are configured for "
            "trusted-RFC, so the ability to pick an arbitrary destination is effectively the "
            "ability to authenticate to the connected target systems as whatever principal that "
            "destination carries — including high-privilege service accounts and connections to "
            "more sensitive systems (e.g. from a sandbox toward production). Combined with a "
            "generic RFC/OData caller this becomes a credential-reuse and lateral-movement path "
            "that bypasses the intent of per-interface destination scoping, and it is easy to "
            "overlook because S_ICF is often copied wholesale from a template role.",
            bad,
            "Restrict S_ICF ICF_FIELD=DEST to the specific destination names (ICF_VALUE) a role "
            "legitimately needs, and never grant ICF_VALUE='*'. Review which destinations store "
            "credentials or use trusted-RFC and treat authorization to those as privileged. "
            "Prefer destinations without stored credentials (current-user / SSO propagation) so "
            "that destination selection cannot escalate privilege, and reconcile S_ICF grants "
            "against the trusted-RFC findings (S_RFCACL, AUTH-002).",
            ["SAP Help — S_ICF authorization object (DEST/SERVICE)",
             "SAP Note 1416085 — RFC / destination authorization risks"])

    def check_table_name_write(self):
        """S_TABU_NAM TABLE=* + ACTVT=02 → write any table (bypasses table auth groups)."""
        bad = [self._role_label(i["role"], "S_TABU_NAM TABLE=*, ACTVT=02")
               for i in self._objects("S_TABU_NAM")
               if self._has_star(self._field(i, "TABLE"))
               and self._covers(self._field(i, "ACTVT"), "02")]
        self._emit(
            "AUTH-007", "Generic table write via S_TABU_NAM (TABLE = *)",
            self.SEVERITY_HIGH,
            f"{len(bad)} role(s) grant S_TABU_NAM with TABLE='*' and ACTVT=02 (change). "
            "S_TABU_NAM authorizes maintenance by table name (the fallback to S_TABU_DIS); "
            "with '*' it grants direct write to virtually any table via SE16N/SM30, bypassing "
            "table authorization groups entirely.",
            bad,
            "Restrict S_TABU_NAM to the specific tables a role must maintain, and prefer display "
            "(ACTVT 03) over change. Review broad table-maintenance access.",
            ["SAP Note 1481950 — S_TABU_NAM", "SAP Help — Table authorizations"])

    def check_table_dis_generic(self):
        """S_TABU_DIS DICBERCLS=&NC&/* + ACTVT=02 → maintain tables without an auth group."""
        bad = []
        for i in self._objects("S_TABU_DIS"):
            dic = self._field(i, "DICBERCLS")
            if (self._has_star(dic) or self._covers(dic, "&NC&")) and self._covers(self._field(i, "ACTVT"), "02"):
                val = "*" if self._has_star(dic) else "&NC&"
                bad.append(self._role_label(i["role"], f"S_TABU_DIS DICBERCLS={val}, ACTVT=02"))
        self._emit(
            "AUTH-008", "Generic table maintenance via S_TABU_DIS (all / no auth group)",
            self.SEVERITY_HIGH,
            f"{len(bad)} role(s) grant S_TABU_DIS change (ACTVT=02) for authorization group '*' "
            "or '&NC&' (tables that have no authorization group). This is broad direct "
            "table-maintenance access covering most sensitive customizing/master tables.",
            bad,
            "Assign narrow table authorization groups (transaction SE54) and grant S_TABU_DIS "
            "only for the specific groups needed; avoid '*' and '&NC&' with change access.",
            ["SAP Security Baseline — S_TABU_DIS", "SAP Help — Table authorization groups"])

    def check_table_cross_client(self):
        """S_TABU_CLI CLIIDMAINT=X → maintain client-independent (cross-client) tables."""
        bad = [self._role_label(i["role"], "S_TABU_CLI CLIIDMAINT=X")
               for i in self._objects("S_TABU_CLI")
               if self._covers(self._field(i, "CLIIDMAINT"), "X")]
        self._emit(
            "AUTH-009", "Cross-client table maintenance (S_TABU_CLI)",
            self.SEVERITY_HIGH,
            f"{len(bad)} role(s) grant S_TABU_CLI with CLIIDMAINT=X, allowing maintenance of "
            "client-independent (cross-client) tables such as T000. Combined with SCC4 this can "
            "change client protection settings that affect every client on the system.",
            bad,
            "Grant S_TABU_CLI only to a small set of system administrators; changes to "
            "client-independent tables must be tightly controlled and logged.",
            ["SAP Help — S_TABU_CLI", "SAP Security Baseline"])

    def check_os_file_access(self):
        """S_DATASET FILENAME=* + PROGRAM=* → arbitrary OS file read/write from ABAP."""
        bad = [self._role_label(i["role"], "S_DATASET FILENAME=*, PROGRAM=*")
               for i in self._objects("S_DATASET")
               if self._has_star(self._field(i, "FILENAME"))
               and self._has_star(self._field(i, "PROGRAM"))]
        self._emit(
            "AUTH-010", "Arbitrary OS file access from ABAP (S_DATASET)",
            self.SEVERITY_HIGH,
            f"{len(bad)} role(s) grant S_DATASET with FILENAME='*' and PROGRAM='*'. S_DATASET "
            "governs OPEN DATASET file access at the OS layer; wildcards let ABAP read or "
            "overwrite arbitrary application-server files — secure store, transport files, logs.",
            bad,
            "Scope S_DATASET to specific file paths and programs; never grant FILENAME='*' with "
            "write access (ACTVT 34). Review custom programs that use OPEN DATASET.",
            ["SAP Security Baseline — S_DATASET", "SAP Help — S_DATASET"])

    def check_run_any_report(self):
        """S_PROGRAM P_ACTION=SUBMIT + P_GROUP=* / blank → run any ABAP report."""
        bad = []
        for i in self._objects("S_PROGRAM"):
            act = self._field(i, "P_ACTION")
            grp = self._field(i, "P_GROUP")
            runs = self._covers(act, "SUBMIT") or self._covers(act, "BTCSUBMIT") or not act
            wide = self._has_star(grp) or any(low.strip() == "" for low, _ in grp) or not grp
            if runs and wide:
                bad.append(self._role_label(i["role"], "S_PROGRAM P_ACTION=SUBMIT, P_GROUP=*/blank"))
        self._emit(
            "AUTH-011", "Run-any-report authorization (S_PROGRAM)",
            self.SEVERITY_HIGH,
            f"{len(bad)} role(s) grant S_PROGRAM SUBMIT with P_GROUP='*' or blank, allowing "
            "execution of any ABAP report regardless of its program authorization group via "
            "SA38/SE38 — including powerful standard reports (RSUSR*, mass maintenance). This "
            "bypasses transaction-menu restrictions.",
            bad,
            "Assign program authorization groups (transaction SE38 → attributes) to sensitive "
            "reports and grant S_PROGRAM only for the required groups.",
            ["SAP Help — S_PROGRAM", "DSAG Audit — report execution"])

    def check_batch_impersonation(self):
        """S_BTCH_NAM BTCUNAME=* → schedule job steps under any other user."""
        bad = [self._role_label(i["role"], "S_BTCH_NAM BTCUNAME=*")
               for i in self._objects("S_BTCH_NAM")
               if self._has_star(self._field(i, "BTCUNAME"))]
        self._emit(
            "AUTH-012", "Background-job impersonation (S_BTCH_NAM BTCUNAME = *)",
            self.SEVERITY_HIGH,
            f"{len(bad)} role(s) grant S_BTCH_NAM with BTCUNAME='*', letting the holder run "
            "background job steps under ANY other user's identity — e.g. a step user that holds "
            "SAP_ALL — executing privileged code in another security context.",
            bad,
            "Restrict S_BTCH_NAM to the specific step-users a role legitimately needs; never '*'. "
            "Review scheduled jobs that run under privileged batch users.",
            ["SAP Security Baseline — S_BTCH_NAM", "DSAG Audit — batch impersonation"])

    def check_sensitive_tcodes(self):
        """Sensitive Basis/admin transactions (S_TCODE) present in roles."""
        role_tcodes: Dict[str, set] = {}
        for i in self._objects("S_TCODE"):
            for low, high in self._field(i, "TCD"):
                t = str(low).strip().upper()
                if t in self.CRITICAL_TCODES:
                    role_tcodes.setdefault(i["role"], set()).add(t)
        bad = [self._role_label(r, "sensitive tcodes: " + ", ".join(sorted(tcs)))
               for r, tcs in role_tcodes.items()]
        self._emit(
            "AUTH-013", "Sensitive Basis / administration transactions in roles",
            self.SEVERITY_HIGH,
            f"{len(bad)} role(s) contain sensitive Basis/administration transactions (table "
            "editing, ABAP, OS commands, user/role admin, client admin, transports, audit). "
            "In productive roles assigned to non-Basis users these are high-risk and often "
            "violate segregation of duties.",
            bad,
            "Review each sensitive transaction against the role's business purpose. Move Basis "
            "transactions into dedicated administrator roles under least privilege and four-eyes.",
            ["DSAG Audit Guideline — critical transactions", "SAP Security Baseline"])

    def check_developer_change_access(self):
        """S_DEVELOP change access (ACTVT 01/02) on development objects in productive roles."""
        bad = []
        for i in self._objects("S_DEVELOP"):
            objtype = self._field(i, "OBJTYPE")
            # skip pure Debug&Replace (handled by AUTH-001): only DEBUG present. Any
            # concrete non-DEBUG object type, or '*', is code create/change access.
            has_non_debug = any(str(lo).strip().upper() not in ("DEBUG", "") for lo, _ in objtype)
            if not has_non_debug:
                continue
            if self._covers(self._field(i, "ACTVT"), "01") or self._covers(self._field(i, "ACTVT"), "02"):
                bad.append(self._role_label(i["role"], "S_DEVELOP ACTVT=01/02 (create/change ABAP objects)"))
        self._emit(
            "AUTH-014", "ABAP development change access (S_DEVELOP create/change)",
            self.SEVERITY_HIGH,
            f"{len(bad)} role(s) grant S_DEVELOP with create/change (ACTVT 01/02) on development "
            "objects. Developer access lets a holder create or modify ABAP programs, classes and "
            "function modules; in a production system this is a code-integrity and backdoor risk "
            "(all changes should arrive via the transport system).",
            bad,
            "Remove development authorizations from productive-system roles; enforce "
            "change-and-transport. Restrict S_DEVELOP to the development system and to developers.",
            ["SAP Security Baseline — S_DEVELOP", "DSAG Audit — developer access in production"])

    # ==================================================================  MEDIUM
    def check_object_disabling(self):
        """auth/object_disabling_active = Y → authorization objects can be globally switched off."""
        params = self.data.get("security_params") or []
        for row in params:
            if not isinstance(row, dict):
                continue
            name = str(row.get("NAME", row.get("PARAMETER", ""))).strip().lower()
            value = str(row.get("VALUE", row.get("PARAM_VALUE", ""))).strip().upper()
            if name == "auth/object_disabling_active" and value in ("Y", "YES", "1", "ON"):
                self.finding(
                    check_id="AUTH-015",
                    title="Global authorization-object disabling is active",
                    severity=self.SEVERITY_MEDIUM,
                    category=self.CATEGORY,
                    description=(
                        "Profile parameter auth/object_disabling_active = Y allows individual "
                        "authorization objects to be globally switched off (transaction "
                        "AUTH_SWITCH_OBJECTS). A disabled object is no longer checked anywhere, "
                        "silently removing an authorization control system-wide."
                    ),
                    affected_items=[f"auth/object_disabling_active = {value}"],
                    remediation=(
                        "Set auth/object_disabling_active = N unless a specific, documented object "
                        "must be disabled. Review AUTH_SWITCH_OBJECTS for any globally-disabled "
                        "authorization objects and re-enable them."
                    ),
                    references=["SAP Security Baseline — auth/object_disabling_active",
                                "SAP Help — Globally deactivating authorization checks"],
                )
                return
