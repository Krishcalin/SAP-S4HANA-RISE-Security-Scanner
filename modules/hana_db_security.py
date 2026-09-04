"""
HANA Database Security Auditor
================================
Audits the SAP HANA database layer that sits underneath S/4HANA — the
privileged-access, audit and parameter surface that the application-layer
modules do not cover. (Encryption-at-rest of the HANA data/log volumes is
handled separately by the Cryptographic Posture module.)

Covers:
  - Privileged / standard DB users (SYSTEM and DBADMIN deactivation, password
    lifetime, dormancy) and setup accounts left active after installation
  - System privileges and the PUBLIC role (least privilege, grantable options),
    resolved THROUGH role membership as well as directly
  - Privilege COMBINATIONS SAP names as critical, which no per-privilege check
    can see
  - Analytic-privilege bypass (_SYS_BI_CP_ALL) and powerful predefined roles
  - Object rights that confer broad extract without a system privilege
    (FULL_SYSTEM_INFO_DUMP)
  - Database auditing (enabled, trail target, critical action coverage)
  - Security-relevant HANA parameters: password policy, error disclosure, SQL
    TLS, log mode, cross-database access, internal listen interface, the system
    replication channel, IMPORT/EXPORT file access, [trace] levels, and the
    multidb.ini blocklist that decides whether a tenant can undo any of them

WHAT A DATABASE EXPORT CANNOT SETTLE, so that it is not re-derived every time
somebody reads SAP's checklist against this file. None of the following is a
gap in the checks; each is a fact no HANA view carries:

  - Operating-system users, groups, sudoers, file permissions and OS patch
    level — including whether an XS Advanced space runs as its own OS user
    rather than as <sid>adm
  - Open ports, network zoning, and which endpoints are externally reachable
  - The XS Advanced controller: spaces, applications, space role assignments,
    the platform router's TLS configuration and its server certificate
  - The hdbuserstore, the SSFS and PKI master keys, and root-key change dates
  - Trace-file deletion, and anything about a file after it was written

Two of these are collector gaps rather than impossibilities and are worth
closing: AUDIT_POLICIES.TRAIL_TYPE (per-policy trail target, finer than the
system-wide default read today), and the PSES view (per-tenant certificate
collections, which is what would settle whether tenants share a SAML trust
store). Both are ordinary SQL against views SAP publishes.

Data sources — and which of these view names SAP has actually published.

ALL FIVE ARE NOW VERIFIED. Three of them were this file's own working knowledge,
marked UNVERIFIED with the reason stated: "a view name a customer cannot query
is a support call". SAP's *SAP HANA Security Checklists and Recommendations*
(SAP HANA Platform 2.0 SPS 05, document version 1.1, 2021-07-09, PUBLIC) queries
all three by name in executable SQL, which settles them:

  - hana_db_users.csv           → USERS                  [verified: User Types;
                                  CREATOR, CREATE_PROVIDER_TYPE and
                                  CREATE_PROVIDER_NAME are named columns. The
                                  checklist adds USER_DEACTIVATED,
                                  DEACTIVATION_TIME, LAST_SUCCESSFUL_CONNECT,
                                  IS_PASSWORD_LIFETIME_CHECK_ENABLED and
                                  LAST_PASSWORD_CHANGE_TIME]
  - hana_granted_privileges.csv → GRANTED_PRIVILEGES     [verified: named as the
                                  view that reports the granting user; the
                                  checklist queries it for DEBUG / ATTACH
                                  DEBUGGER]
  - hana_granted_roles.csv      → GRANTED_ROLES          [verified: the checklist
                                  queries `GRANTED_ROLES WHERE ROLE_NAME =
                                  'CONTENT_ADMIN'` and again for MODELING]
  - hana_parameters.csv         → M_INIFILE_CONTENTS     [verified: the checklist
                                  queries `"PUBLIC"."M_INIFILE_CONTENTS"`
                                  throughout, and names FILE_NAME, SECTION, KEY
                                  and VALUE as columns]
  - hana_audit_policies.csv     → AUDIT_POLICIES         [verified: the checklist
                                  queries `"PUBLIC"."AUDIT_POLICIES" WHERE
                                  TRAIL_TYPE='CSV'` — which also names a
                                  TRAIL_TYPE column this product does not yet
                                  export]

The checklist names further views this product does not read, and they are
recorded here so nobody has to re-derive them: EFFECTIVE_PRIVILEGE_GRANTEES and
EFFECTIVE_PRIVILEGES (privileges including those held through roles),
EFFECTIVE_ROLE_GRANTEES, PSES (certificate collections, per tenant),
ENCRYPTION_ROOT_KEYS, M_ENCRYPTION_OVERVIEW (SCOPE 'LOG' / 'PERSISTENCE'),
M_CUSTOMIZABLE_FUNCTIONALITIES and USER_PARAMETERS.

DEPLOYMENT CHANGES WHAT "NOT SUPPLIED" MEANS HERE. SAP HANA Cloud runs a shared
responsibility model: the customer owns users, authorisation, auditing, masking
and anonymisation; SAP owns secure operation, encryption and system auditing.
The customer has no operating-system access, no file-system access and no access
to the system database — only their tenant. So on HANA Cloud several of these
checks are *not applicable* rather than *not assessed*, and data-at-rest
encryption cannot be switched off at all, which makes "encryption is disabled"
an unreachable finding rather than a clean one.

Aligned to the CIS SAP HANA Benchmark and the SAP HANA Security Guide.
"""

from typing import Dict, List, Any
from datetime import datetime
from modules.base_auditor import BaseAuditor


class HanaDbSecurityAuditor(BaseAuditor):

    CATEGORY = "HANA Database Security"

    # HANA built-in / internal users that legitimately never expire or are
    # technical; excluded from user-level least-privilege findings.
    TECHNICAL_USERS = {
        "SYS", "_SYS_REPO", "_SYS_STATISTICS", "_SYS_EPM", "_SYS_DATA_ANONYMIZATION",
        "_SYS_AFL", "_SYS_PLAN_STABILITY", "_SYS_TABLE_REPLICAS", "_SYS_TASK",
        "_SYS_WORKLOAD_REPLAY", "_SYS_SQL_ANALYZER", "_SYS_DI", "_SYS_DI_SU",
        "_SYS_DI_CATALOG", "_SYS_XB", "_SYS_TELEMETRY", "SYSTEM",
    }

    # HANA system privileges that confer broad administrative power. Granting
    # these to individual users (rather than via a reviewed role) breaks least
    # privilege; the CRITICAL subset are effectively "keys to the kingdom".
    CRITICAL_SYSTEM_PRIVS = {
        "DATA ADMIN", "USER ADMIN", "ROLE ADMIN", "INIFILE ADMIN", "DEVELOPMENT",
        "ENCRYPTION ROOT KEY ADMIN", "CERTIFICATE ADMIN", "CREDENTIAL ADMIN",
        "TRUST ADMIN", "AUDIT ADMIN", "DATABASE ADMIN", "LICENSE ADMIN",
    }
    HIGH_SYSTEM_PRIVS = CRITICAL_SYSTEM_PRIVS | {
        "CATALOG READ", "BACKUP ADMIN", "RESOURCE ADMIN", "SERVICE ADMIN",
        "TABLE ADMIN", "TRACE ADMIN", "SESSION ADMIN", "MONITOR ADMIN",
        "EXTENDED STORAGE ADMIN", "IMPORT", "EXPORT", "ADAPTER ADMIN",
        "AGENT ADMIN", "STRUCTUREDPRIVILEGE ADMIN", "CREATE STRUCTURED PRIVILEGE",
        "AUDIT OPERATOR", "LOG ADMIN", "SAVEPOINT ADMIN",
    }

    #: Privileges SAP's HANA Security Checklist names as administrator-only that
    #: neither set above carried. TWO OF THEM CONTAIN NO "ADMIN" SUBSTRING —
    #: BACKUP OPERATOR and CREATE REMOTE SOURCE — so the `"ADMIN" in priv`
    #: fallback in `check_public_grants` missed them as well as the sets did.
    #: CREATE REMOTE SOURCE defines an outbound connection to another database
    #: and BACKUP OPERATOR takes a full copy of this one; neither is a
    #: configuration change and both move data off the system.
    CHECKLIST_ADMIN_PRIVS = frozenset({
        "BACKUP OPERATOR", "CREATE REMOTE SOURCE", "LDAP ADMIN", "OPTIMIZER ADMIN",
        "SSL ADMIN", "VERSION ADMIN", "WORKLOAD ADMIN", "CREATE SCENARIO",
        "SCENARIO ADMIN", "CLIENT PARAMETER ADMIN",
    })
    HIGH_SYSTEM_PRIVS = HIGH_SYSTEM_PRIVS | CHECKLIST_ADMIN_PRIVS

    #: Pairs SAP's checklist names as critical *combinations*.
    #:
    #: A PAIR IS NOT VISIBLE ONE PRIVILEGE AT A TIME, which is why no amount of
    #: tuning the sets above finds one. USER ADMIN with ROLE ADMIN is
    #: self-service escalation — create a role, grant it anything, grant it to
    #: yourself — and each half on its own is ordinary enough that this module
    #: reports it at HIGH and an auditor moves on. AUDIT ADMIN with AUDIT
    #: OPERATOR is the ability to decide what is recorded and then to delete
    #: what was.
    CRITICAL_PRIV_PAIRS = (
        ("USER ADMIN", "ROLE ADMIN",
         "can create a role, grant any privilege to it, and grant it to itself"),
        ("CREATE SCENARIO", "SCENARIO ADMIN",
         "can create a calculation scenario and then run it with its own rights"),
        ("AUDIT ADMIN", "AUDIT OPERATOR",
         "can change what is audited and then delete the audit trail"),
        ("CREATE STRUCTURED PRIVILEGE", "STRUCTUREDPRIVILEGE ADMIN",
         "can author an analytic privilege and activate it without review"),
    )

    #: Accounts SAP documents as setup-only: created by an installation step and
    #: meant to be deactivated once it is finished. XSA_ADMIN is not in
    #: SUPERUSERS deliberately — that set drives HANADB-USER-001, whose
    #: remediation is about break-glass recovery, and this account has no
    #: break-glass role. Its remediation is "deactivate it permanently, having
    #: first granted XS_AUTHORIZATION_ADMIN and XS_USER_ADMIN elsewhere".
    SETUP_ACCOUNTS = {
        "XSA_ADMIN": ("SAP HANA XS Advanced installation",
                      "granted every XS Advanced controller role collection"),
    }

    # Analytic (structured) privilege that disables all analytic-privilege row
    # filtering in modeled views — effectively unrestricted reporting-data access.
    CP_ALL = "_SYS_BI_CP_ALL"

    # Predefined roles that carry broad administrative capability.
    POWERFUL_ROLES = {
        "CONTENT_ADMIN", "MODELING", "MONITORING", "SAP_INTERNAL_HANA_SUPPORT",
        "AFL__SYS_AFL_AFLPAL_EXECUTE",
    }

    #: HANA revision lines SAP still issues security corrections for.
    #:
    #: SOURCED, AND DELIBERATELY COARSE. SAP publishes the maintained revision of
    #: each SPS line in its release strategy, and that number moves. Rather than
    #: restate a moving number, this check asks the weaker question an export can
    #: settle on its own: is the installed line one SAP still maintains at all? A
    #: line below the oldest entry here is out of maintenance whatever its patch
    #: level, which is a verdict that does not go stale in the direction that
    #: matters — it can only become more conservative as SAP retires lines.
    HANA_MAINTAINED_LINES = {
        (2, 0, 67): "SPS06",
        (2, 0, 76): "SPS07",
        (2, 0, 79): "SPS08",
    }

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_privileged_users()
        self.check_password_lifetime()
        self.check_dormant_users()
        self.check_public_grants()
        self.check_system_privileges()
        self.check_grantable_privileges()
        self.check_analytic_privilege_bypass()
        self.check_powerful_roles()
        self.check_role_held_privileges()
        self.check_critical_privilege_combinations()
        self.check_setup_accounts()
        self.check_system_info_dump_grants()
        self.check_auditing_enabled()
        self.check_audit_trail_target()
        self.check_audit_policy_coverage()
        self.check_password_policy()
        self.check_error_disclosure()
        self.check_sql_tls_enforced()
        self.check_log_mode()
        self.check_cross_database_access()
        self.check_debug_privileges()
        self.check_internal_listen_interface()
        self.check_sql_trace_results()
        self.check_replication_channel()
        self.check_import_export_file_security()
        self.check_trace_levels()
        self.check_tenant_parameter_blocklist()
        self.check_hana_maintenance_status()
        return self.findings

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _truthy(value: Any) -> bool:
        return str(value).strip().lower() in ("true", "1", "yes", "on", "enabled", "x")

    @staticmethod
    def _falsy(value: Any) -> bool:
        return str(value).strip().lower() in ("false", "0", "no", "off", "disabled", "", "none")

    @staticmethod
    def _add_obj(objects: List[Dict[str, Any]], otype: str, name: Any,
                 qualifier: Any = None) -> None:
        """Append one structured affected object, de-duplicated.

        A row whose identifying field is missing is SKIPPED rather than given a
        placeholder: an object with no name cannot be fingerprinted, and inventing one
        would put a graph node into the attack path that does not exist in the system.
        """
        n = "" if name is None else str(name).strip()
        if not n:
            return
        obj: Dict[str, Any] = {"type": otype, "name": n}
        q = "" if qualifier is None else str(qualifier).strip()
        if q:
            obj["qualifier"] = q
        if obj not in objects:
            objects.append(obj)

    @staticmethod
    def _add_grant(relations: List[Dict[str, Any]], grantee: Any,
                   to_type: str, name: Any, qualifier: Any = None) -> None:
        """Record WHICH holder holds WHICH privilege or role, de-duplicated.

        `check_system_privileges` already carried the comment "a grant is an
        edge: both ends become graph nodes" — and both ends did, while which end
        went with which did not, because `affected_objects` is flat. The graph
        then saw a list of HANA users and a list of privileges with no way to
        pair them, declined to guess, and the entire database half of the estate
        produced no privilege edges.

        Skips an incomplete pair for the same reason `_add_obj` skips a nameless
        object: half a relationship is not a relationship, and inventing the
        other half would put a grant into the attack graph that nobody made.
        """
        g = "" if grantee is None else str(grantee).strip()
        n = "" if name is None else str(name).strip()
        if not g or not n:
            return
        target: Dict[str, Any] = {"type": to_type, "name": n}
        q = "" if qualifier is None else str(qualifier).strip()
        if q:
            target["qualifier"] = q
        entry = {"from": {"type": "hana_user", "name": g}, "to": target}
        if entry not in relations:
            relations.append(entry)

    def _param_index(self):
        """Build {(file, section, key_lower): value} from hana_parameters.csv."""
        rows = self.data.get("hana_parameters") or []
        idx = {}
        for row in rows:
            fname = str(row.get("FILE_NAME", row.get("FILE", row.get("LAYER", "")))).lower()
            section = str(row.get("SECTION", row.get("SECTION_NAME", ""))).strip().lower()
            key = str(row.get("KEY", row.get("PARAMETER", row.get("NAME", "")))).strip().lower()
            value = row.get("VALUE", row.get("PARAM_VALUE", row.get("VALUE_1", "")))
            if key:
                idx[(fname, section, key)] = value
                idx[key] = value  # loose lookup by key alone
        return idx

    def _get_param(self, idx: dict, key: str, section: str = None, strict: bool = False):
        key = key.lower()
        if section:
            section = section.lower()
            for keytuple, v in idx.items():
                if isinstance(keytuple, tuple) and keytuple[1] == section and keytuple[2] == key:
                    return v
            if strict:
                # do not fall back to a same-named key from a DIFFERENT section
                # (e.g. [expensive_statement] enabled) — that would misattribute the value
                return None
        return idx.get(key)

    @staticmethod
    def _parse_date(date_str: str):
        if not date_str or not str(date_str).strip():
            return None
        s = str(date_str).strip()
        for suffix in ("Z", "+00:00"):
            if s.endswith(suffix):
                s = s[:-len(suffix)]
        if "T" in s:
            s = s.split("T")[0]
        if " " in s:
            s = s.split(" ")[0]
        for fmt in ("%Y-%m-%d", "%Y%m%d", "%d.%m.%Y", "%m/%d/%Y"):
            try:
                return datetime.strptime(s[:10], fmt)
            except (ValueError, IndexError):
                continue
        return None

    # -------------------------------------------------------------------- users
    #: The built-in superuser, which is not called the same thing everywhere.
    #: On-premise and managed SAP HANA ship `SYSTEM`. SAP HANA Cloud ships
    #: `DBADMIN` instead — and SAP's *essential* security task list for HANA
    #: Cloud says, in four words, "Deactivate the user DBADMIN."
    SUPERUSERS = {
        "SYSTEM": ("on-premise and managed SAP HANA",
                   "SAP HANA Security Guide — The SYSTEM User"),
        "DBADMIN": ("SAP HANA Cloud",
                    "SAP HANA Cloud, SAP HANA Database Security Guide — "
                    "Essential Security Tasks: Deactivate the DBADMIN User"),
    }

    def check_privileged_users(self):
        """CRITICAL: the built-in superuser should be deactivated once named
        administrator accounts exist (CIS SAP HANA).

        TWO ACCOUNTS, BECAUSE THERE ARE TWO DEPLOYMENTS, AND THIS CHECK KNEW ONE.

        It matched `SYSTEM` and nothing else. A customer running SAP HANA Cloud
        has no user called SYSTEM — theirs is `DBADMIN` — so the check walked the
        export, matched no row, and said nothing. Silence from this module reads
        as "the superuser is deactivated", which is the reassuring answer, about
        the one account SAP's own essential-task list tells them to turn off.

        That is this product's own failure mode: an absence of evidence rendered
        as evidence of absence. The fix is not cleverness, it is knowing the
        other name.
        """
        users = self.data.get("hana_db_users")
        if not users:
            return
        active: List[str] = []
        for row in users:
            name = str(row.get("USER_NAME", row.get("USER", row.get("NAME", "")))).strip().upper()
            if name not in self.SUPERUSERS or name in active:
                continue
            deactivated = row.get("USER_DEACTIVATED", row.get("DEACTIVATED",
                          row.get("IS_DEACTIVATED", row.get("ACTIVE", ""))))
            # ACTIVE column is inverted vs DEACTIVATED
            is_active = (self._truthy(row.get("ACTIVE", "")) if "ACTIVE" in row
                         else self._falsy(deactivated))
            if is_active:
                active.append(name)
        if not active:
            return
        # ONE finding, however many names matched. The aggregating invariant
        # (test_aggregating_module_ids_unique) is no formality here: the sample
        # export really does carry SYSTEM and DBADMIN side by side, and two
        # findings sharing HANADB-USER-001 would count one defect — "the
        # break-glass account is live" — twice in every score built on it.
        names = " and ".join(active)
        self.finding(
            check_id="HANADB-USER-001",
            title=("HANA %s superuser is still active" % names if len(active) == 1
                   else "HANA superusers %s are still active" % names),
            severity=self.SEVERITY_CRITICAL,
            category=self.CATEGORY,
            description=(
                "The built-in superuser is active: %s. It holds every system "
                "privilege available to the account and bypasses the role model; "
                "it should be deactivated once named administrator users exist, "
                "and used only for break-glass recovery. %s"
                % (names, " ".join(
                    "%s is the superuser shipped with %s." %
                    (n, self.SUPERUSERS[n][0]) for n in active))
            ),
            affected_items=["%s — status: active" % n for n in active],
            remediation=(
                "Create named administrator users with only the privileges they "
                "need, then deactivate the superuser (%s). "
                "Re-activate only for documented emergencies."
                % "; ".join("ALTER USER %s DEACTIVATE USER NOW" % n for n in active)
            ),
            references=(
                ["CIS SAP HANA Benchmark — Deactivate SYSTEM user"]
                + [self.SUPERUSERS[n][1] for n in active]
            ),
            # One defect — the break-glass account is live — whichever names carry
            # it. No qualifier: the check fires on exactly one state, so a qualifier
            # would add no discrimination while inheriting the export's spelling of
            # the ACTIVE/DEACTIVATED flag ("FALSE" vs "false" vs "0").
            affected_objects=[{"type": "hana_user", "name": n} for n in active],
            scope="object",
        )

    def check_setup_accounts(self):
        """HIGH: an installation account left active after the installation.

        XSA_ADMIN is created by the XS Advanced installation holding every
        controller role collection, and SAP's checklist says to deactivate it
        once named administrators exist. It is a separate check id from
        HANADB-USER-001 on purpose: that finding is about a break-glass account
        and its remediation says to keep it for emergencies, which is the wrong
        advice for an account with no emergency role.
        """
        users = self.data.get("hana_db_users")
        if not users:
            return
        live, objects = [], []
        for row in users:
            name = str(row.get("USER_NAME", row.get("USER", row.get("NAME", "")))).strip().upper()
            if name not in self.SETUP_ACCOUNTS:
                continue
            deactivated = row.get("USER_DEACTIVATED", row.get("DEACTIVATED",
                          row.get("IS_DEACTIVATED", row.get("ACTIVE", ""))))
            is_active = (self._truthy(row.get("ACTIVE", "")) if "ACTIVE" in row
                         else self._falsy(deactivated))
            if not is_active:
                continue
            origin, power = self.SETUP_ACCOUNTS[name]
            last = str(row.get("LAST_SUCCESSFUL_CONNECT", "") or "").strip()
            # "Never used" and "used last week" are different findings wearing
            # the same title, and the second one is the worse of the two.
            usage = ("last successful connect %s" % last if last
                     else "no successful connect recorded")
            live.append("%s — active; created by %s; %s; %s"
                        % (name, origin, power, usage))
            self._add_obj(objects, "hana_user", name)
        if not live:
            return
        self.finding(
            check_id="HANADB-USER-004",
            title="Installation account left active after setup",
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=(
                "%d account(s) created by an installation step are still "
                "active. SAP documents these as setup-only: they hold their "
                "platform's full administrative capability, they are not "
                "break-glass accounts, and they are meant to be deactivated "
                "once named administrators exist. An active one is a standing "
                "administrative account that nobody owns."
                % len(live)
            ),
            affected_items=live,
            remediation=(
                "1. Grant the capabilities still needed to named "
                "administrators — for XSA_ADMIN that is XS_AUTHORIZATION_ADMIN "
                "and XS_USER_ADMIN on a named account.\n"
                "2. Deactivate the setup account: ALTER USER <name> DEACTIVATE "
                "USER NOW.\n"
                "3. Under RISE the account sits on the SAP-operated database; "
                "raise a service request rather than issuing the ALTER USER."
            ),
            references=[
                "SAP HANA Security Checklists and Recommendations — "
                "Recommendations for XS Advanced",
            ],
            affected_objects=objects,
            scope="object",
        )

    def check_password_lifetime(self):
        """HIGH: non-technical DB users whose password lifetime check is disabled
        (password never expires)."""
        users = self.data.get("hana_db_users")
        if not users:
            return
        offenders = []
        objects: List[Dict[str, Any]] = []
        for row in users:
            name = str(row.get("USER_NAME", row.get("USER", row.get("NAME", "")))).strip()
            if not name or name.upper() in self.TECHNICAL_USERS or name.startswith("_SYS"):
                continue
            lifetime = row.get("IS_PASSWORD_LIFETIME_CHECK_ENABLED",
                       row.get("PASSWORD_LIFETIME_CHECK",
                       row.get("PASSWORD_LIFETIME_ENABLED", "")))
            if lifetime == "" or lifetime is None:
                continue
            if self._falsy(lifetime):
                offenders.append(f"{name} — password lifetime check: disabled")
                self._add_obj(objects, "hana_user", name)
        if offenders:
            self.finding(
                check_id="HANADB-USER-002",
                title="DB users with password lifetime check disabled",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} non-technical HANA user(s) have the password "
                    "lifetime check disabled, so their password never expires. Stale "
                    "static credentials increase the window for credential theft/reuse."
                ),
                affected_items=offenders,
                remediation=(
                    "Enable the password lifetime check for interactive users: "
                    "ALTER USER <user> ENABLE PASSWORD LIFETIME. "
                    "Reserve disabled lifetime for genuine technical users that use "
                    "certificate/SSO or securely-stored credentials."
                ),
                references=[
                    "CIS SAP HANA Benchmark — Password lifetime",
                    "SAP HANA Security Guide — Password Policy",
                ],
                affected_objects=objects,
                # One finding over the never-expiring-password population. Enabling the
                # lifetime check on one user must SHRINK this finding, not retire it and
                # raise a zero-age replacement — so the members stay out of identity.
                scope="aggregate",
            )

    def check_dormant_users(self):
        """MEDIUM: active DB users with no successful connect in N days."""
        users = self.data.get("hana_db_users")
        if not users:
            return
        threshold = self.get_config("hana_dormant_days", 90)
        now = datetime.now()
        dormant = []
        objects: List[Dict[str, Any]] = []
        for row in users:
            name = str(row.get("USER_NAME", row.get("USER", row.get("NAME", "")))).strip()
            if not name or name.upper() in self.TECHNICAL_USERS or name.startswith("_SYS"):
                continue
            deactivated = row.get("USER_DEACTIVATED", row.get("DEACTIVATED", ""))
            if self._truthy(deactivated):
                continue
            last = row.get("LAST_SUCCESSFUL_CONNECT", row.get("LAST_CONNECT",
                   row.get("LAST_LOGON", "")))
            parsed = self._parse_date(last)
            if last in ("", None) or str(last).strip() == "?":
                dormant.append(f"{name} — never connected")
                self._add_obj(objects, "hana_user", name)
            elif parsed and (now - parsed).days >= threshold:
                dormant.append(f"{name} — last connect {(now - parsed).days}d ago ({last})")
                self._add_obj(objects, "hana_user", name)
        if dormant:
            self.finding(
                check_id="HANADB-USER-003",
                title=f"Dormant HANA DB users (no logon in {threshold}+ days)",
                severity=self.SEVERITY_MEDIUM,
                category=self.CATEGORY,
                description=(
                    f"{len(dormant)} active DB user(s) have not connected in "
                    f"{threshold}+ days (or never). Unused accounts widen the attack "
                    "surface and are prime targets for takeover."
                ),
                affected_items=dormant,
                remediation=(
                    "Deactivate unused DB users (ALTER USER <user> DEACTIVATE USER NOW) "
                    "and drop them after a review period. Automate dormancy review."
                ),
                references=["CIS SAP HANA Benchmark — Unused users"],
                affected_objects=objects,
                # The canonical aggregate: "N dormant accounts" is about the check, not
                # about any one account. Deactivating one dormant user must not retire
                # the finding and reset its age. No qualifier carries the day count
                # either — it grows every run and would re-key the node daily.
                scope="aggregate",
            )

    # --------------------------------------------------------------- privileges
    def _resolution_entries(self, section: str) -> int:
        """How many rows the export carries for an ini SECTION, any key.

        `internal_hostname_resolution` and `system_replication_hostname_resolution`
        are sections whose KEYS are adapter IP addresses, so they can only be
        counted, never looked up by name.
        """
        wanted = section.lower()
        return sum(1 for r in (self.data.get("hana_parameters") or [])
                   if str(r.get("SECTION", "")).strip().lower() == wanted)

    def _param_rows(self, section: str, key: str = None):
        """Raw parameter rows for a section, optionally one key.

        Deliberately NOT `_param_index()`: that collapses to one value per key
        across every file, which is wrong for a section like [trace] that exists
        in indexserver.ini, nameserver.ini and xsengine.ini at once.
        """
        want_section = section.lower()
        want_key = key.lower() if key else None
        for row in (self.data.get("hana_parameters") or []):
            if str(row.get("SECTION", "")).strip().lower() != want_section:
                continue
            rkey = str(row.get("KEY", "")).strip()
            if want_key and rkey.lower() != want_key:
                continue
            yield (str(row.get("FILE_NAME", "")).strip(), rkey,
                   str(row.get("VALUE", "")).strip())

    def _iter_priv_rows(self):
        rows = self.data.get("hana_granted_privileges") or []
        for row in rows:
            grantee = str(row.get("GRANTEE", row.get("USER_NAME", row.get("GRANTEE_NAME", "")))).strip()
            gtype = str(row.get("GRANTEE_TYPE", row.get("TYPE", ""))).strip().upper()
            priv = str(row.get("PRIVILEGE", row.get("PRIVILEGE_NAME", row.get("SYSTEM_PRIVILEGE", "")))).strip().upper()
            obj = str(row.get("OBJECT_NAME", row.get("OBJECT", row.get("SCHEMA_NAME", "")))).strip()
            grantable = row.get("IS_GRANTABLE", row.get("GRANTABLE", row.get("WITH_ADMIN", "")))
            yield grantee, gtype, priv, obj, grantable

    def check_public_grants(self):
        """CRITICAL: sensitive privileges granted to PUBLIC (every user)."""
        if not self.data.get("hana_granted_privileges"):
            return
        offenders = []
        objects: List[Dict[str, Any]] = []
        for grantee, gtype, priv, obj, _ in self._iter_priv_rows():
            if grantee.upper() != "PUBLIC":
                continue
            if priv in self.HIGH_SYSTEM_PRIVS or priv == self.CP_ALL or "ADMIN" in priv:
                label = f"PUBLIC ← {priv}" + (f" ON {obj}" if obj else "")
                offenders.append(label)
                self._add_obj(objects, "hana_role", grantee)
                # OBJECT_NAME is a qualifier, not an object of its own: the export does
                # not say whether it names a schema, a procedure or a user, so typing it
                # would be a guess. It still belongs in identity — CATALOG READ on one
                # object is a different grant from the unrestricted system privilege.
                self._add_obj(objects, "hana_privilege", priv,
                              f"on={obj}" if obj else None)
        if offenders:
            self.finding(
                check_id="HANADB-PRIV-001",
                title="Sensitive privileges granted to PUBLIC",
                severity=self.SEVERITY_CRITICAL,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} sensitive privilege(s) are granted to the PUBLIC "
                    "role, which every database user (including technical and future "
                    "users) automatically holds. This gives all users administrative or "
                    "broad-data capability."
                ),
                affected_items=offenders,
                remediation=(
                    "Revoke administrative/sensitive privileges from PUBLIC and grant them "
                    "only through named roles to the specific users that require them: "
                    "REVOKE <privilege> FROM PUBLIC."
                ),
                references=[
                    "CIS SAP HANA Benchmark — Restrict PUBLIC role",
                    "SAP HANA Security Guide — The PUBLIC Role",
                ],
                affected_objects=objects,
                # One finding summarising every sensitive privilege PUBLIC holds.
                # Revoking one of them must shrink the finding rather than replace it,
                # so the privilege list is stored as members and excluded from identity.
                scope="aggregate",
            )

    def check_system_privileges(self):
        """HIGH: broad system privileges granted directly to users."""
        if not self.data.get("hana_granted_privileges"):
            return
        crit, high = [], []
        crit_objects: List[Dict[str, Any]] = []
        high_objects: List[Dict[str, Any]] = []
        crit_grants: List[Dict[str, Any]] = []
        high_grants: List[Dict[str, Any]] = []
        for grantee, gtype, priv, obj, _ in self._iter_priv_rows():
            gu = grantee.upper()
            if gu in ("PUBLIC",) or gu in self.TECHNICAL_USERS or gu.startswith("_SYS"):
                continue
            if gtype and gtype not in ("USER", ""):   # role grants handled elsewhere
                continue
            if priv in self.CRITICAL_SYSTEM_PRIVS:
                crit.append(f"{grantee} ← {priv}")
                # A grant is an edge: both ends become graph nodes, as in the
                # user -> profile modelling the identity tests use — and the
                # pairing is declared too, so the edge can actually be drawn.
                self._add_obj(crit_objects, "hana_user", grantee)
                self._add_obj(crit_objects, "hana_privilege", priv)
                self._add_grant(crit_grants, grantee, "hana_privilege", priv)
            elif priv in self.HIGH_SYSTEM_PRIVS:
                high.append(f"{grantee} ← {priv}")
                self._add_obj(high_objects, "hana_user", grantee)
                self._add_obj(high_objects, "hana_privilege", priv)
                self._add_grant(high_grants, grantee, "hana_privilege", priv)
        if crit:
            self.finding(
                check_id="HANADB-PRIV-002",
                title="Critical system privileges granted directly to users",
                severity=self.SEVERITY_CRITICAL,
                category=self.CATEGORY,
                description=(
                    f"{len(crit)} grant(s) of near-unrestricted system privileges "
                    "(DATA ADMIN, USER ADMIN, ROLE ADMIN, DEVELOPMENT, INIFILE ADMIN, "
                    "encryption/credential/trust admin) directly to individual users. "
                    "These bypass the role model and confer administrative control."
                ),
                affected_items=crit,
                remediation=(
                    "Revoke these system privileges from individual users and provision "
                    "them through a small number of reviewed, named admin roles under "
                    "least privilege. DATA ADMIN and DEVELOPMENT should be exceptional."
                ),
                references=[
                    "CIS SAP HANA Benchmark — System privileges",
                    "SAP HANA Security Guide — System Privileges",
                ],
                affected_objects=crit_objects,
                relations=crit_grants,
                # Every critical direct grant in the system rolls up into this ONE
                # finding. Revoking DATA ADMIN from one user while another keeps USER
                # ADMIN must leave the finding standing with its age intact, so the
                # grantee/privilege pairs are members rather than the subject.
                scope="aggregate",
            )
        if high:
            self.finding(
                check_id="HANADB-PRIV-003",
                title="Broad system privileges granted directly to users",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(high)} grant(s) of powerful system privileges (CATALOG READ, "
                    "BACKUP ADMIN, TRACE ADMIN, IMPORT/EXPORT, etc.) directly to users "
                    "rather than through roles — a least-privilege and reviewability gap."
                ),
                affected_items=high,
                remediation=(
                    "Move system-privilege grants into named roles and grant the roles; "
                    "review each direct grant for necessity."
                ),
                references=["SAP HANA Security Guide — System Privileges"],
                affected_objects=high_objects,
                relations=high_grants,
                # Same rollup as HANADB-PRIV-002, one severity band down.
                scope="aggregate",
            )

    # ------------------------------------------------- privileges held via roles
    def _role_members(self):
        """{ROLE: {grantee, ...}} from hana_granted_roles."""
        members = {}
        for row in (self.data.get("hana_granted_roles") or []):
            grantee = str(row.get("GRANTEE", row.get("USER_NAME", ""))).strip()
            role = str(row.get("ROLE_NAME", row.get("ROLE", ""))).strip()
            if grantee and role:
                members.setdefault(role.upper(), set()).add(grantee)
        return members

    def _effective_holders(self, role: str, members: dict, depth: int = 0):
        """Every grantee that reaches `role`, directly or through another role.

        Roles are granted to roles in HANA, so membership is a graph and not a
        list. `seen` is not tidiness — a role granted back to one of its own
        members is a cycle, and a cycle here would not return.
        """
        out, stack, seen = {}, [(role.upper(), [role])], set()
        while stack:
            current, chain = stack.pop()
            if current in seen or len(chain) > 8:
                continue
            seen.add(current)
            for grantee in members.get(current, ()):
                gu = grantee.upper()
                if gu in self.TECHNICAL_USERS or gu.startswith("_SYS"):
                    continue
                if gu in members:            # a role: keep walking outward
                    stack.append((gu, chain + [grantee]))
                    continue
                out.setdefault(grantee, chain + [grantee])
        return out

    def _direct_holdings(self):
        """{grantee: {privileges}} for USER grantees, from the privilege export."""
        held = {}
        for grantee, gtype, priv, _obj, _g in self._iter_priv_rows():
            gu = grantee.upper()
            if not gu or gu == "PUBLIC" or gu in self.TECHNICAL_USERS or gu.startswith("_SYS"):
                continue
            if gtype and gtype not in ("USER", ""):
                continue
            if priv:
                held.setdefault(grantee, set()).add(priv)
        return held

    def _role_holdings(self):
        """{ROLE: {privileges}} — the half of the export this module ignored."""
        held = {}
        for grantee, gtype, priv, _obj, _g in self._iter_priv_rows():
            if gtype not in ("ROLE",):
                continue
            gu = grantee.upper()
            if not gu or gu.startswith("_SYS"):
                continue
            # PUBLIC is a role and every user holds it, so resolving it would
            # name the whole user list here. HANADB-PRIV-001 already reports
            # that state, at CRITICAL, which is the right severity for it —
            # this check would only restate it one band lower.
            if gu == "PUBLIC":
                continue
            if priv:
                held.setdefault(grantee, set()).add(priv)
        return held

    def _effective_holdings(self):
        """{grantee: {privilege: path}} — direct grants AND grants via roles.

        SAP's own view for this is EFFECTIVE_PRIVILEGE_GRANTEES, which this
        product does not export. It is derivable from the two exports it does
        have, and deriving it is the difference between auditing an estate that
        ignores SAP's advice and auditing one that follows it.
        """
        members = self._role_members()
        effective = {}
        for grantee, privs in self._direct_holdings().items():
            for priv in privs:
                effective.setdefault(grantee, {}).setdefault(priv, [grantee])
        for role, privs in self._role_holdings().items():
            holders = self._effective_holders(role, members)
            for holder, chain in holders.items():
                for priv in privs:
                    # A direct grant already recorded wins: it is the shorter,
                    # more actionable path and the one PRIV-002 already reports.
                    effective.setdefault(holder, {}).setdefault(priv, list(reversed(chain)))
        return effective

    @staticmethod
    def _route(holdings: dict, priv: str) -> str:
        """How a grantee came to hold a privilege — for the display string.

        Named, because "USER ADMIN + ROLE ADMIN" is a different conversation
        depending on whether one arrived through a role somebody else owns.
        """
        chain = holdings.get(priv) or []
        if len(chain) <= 1:
            return "direct"
        return "via " + " ← ".join("role %s" % c for c in chain[1:])

    def check_role_held_privileges(self):
        """CRITICAL system privileges that reach users through role membership.

        THE MODULE DECLINED TO LOOK HERE, AND SAID SO. `check_system_privileges`
        carried the line

            if gtype and gtype not in ("USER", ""):   # role grants handled elsewhere

        and role grants were not handled elsewhere: `check_powerful_roles` reads
        `hana_granted_roles`, which is who holds which role, never which
        privileges a role holds. So every privilege granted to a role was
        invisible to this file.

        That is the wrong half to be blind to. SAP tells customers to grant
        through roles rather than to users, so the estates that follow the
        advice put DATA ADMIN, DEVELOPMENT and INIFILE ADMIN in exactly the
        place this module refused to read — and got a clean report for it,
        while an estate that granted the same privileges directly got a
        CRITICAL. The tool was scoring the shape of the grant, not the power.

        Granting through roles is NOT the defect and this finding does not say
        it is. What it reports is reach: who ends up holding a critical system
        privilege once role membership is resolved, which nobody could see
        before.
        """
        if not self.data.get("hana_granted_privileges"):
            return
        role_holdings = self._role_holdings()
        if not role_holdings:
            return
        members = self._role_members()
        paths, objects, orphan_roles = [], [], []
        for role, privs in sorted(role_holdings.items()):
            critical = sorted(privs & self.CRITICAL_SYSTEM_PRIVS)
            if not critical:
                continue
            holders = self._effective_holders(role, members)
            if not holders and "hana_granted_roles" not in self.data:
                # The role holds the privilege; the membership export is not
                # supplied, so WHO holds the role is not known. Saying "nobody"
                # here would be the false clean this check exists to end.
                #
                # `not in self.data`, NOT a falsy test: an export that was
                # supplied and came back empty is an answer — no role is granted
                # to anyone — while an export that was never supplied is a
                # question. A falsy test reads both as the question and puts an
                # "unknown holders" line on an estate that told us.
                orphan_roles.append("role %s ← %s (holders unknown: "
                                    "hana_granted_roles not supplied)"
                                    % (role, ", ".join(critical)))
                self._add_obj(objects, "hana_role", role)
                continue
            self._add_obj(objects, "hana_role", role)
            for priv in critical:
                self._add_obj(objects, "hana_privilege", priv)
            for holder, chain in sorted(holders.items()):
                trail = " ← ".join("role %s" % c if c.upper() in members else c
                                   for c in reversed(chain))
                paths.append("%s ← %s" % (trail, ", ".join(critical)))
                self._add_obj(objects, "hana_user", holder)
        if not paths and not orphan_roles:
            return
        items = paths + orphan_roles
        self.finding(
            check_id="HANADB-PRIV-007",
            title="Critical system privileges reach users through role membership",
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=(
                "%d effective grant(s) of near-unrestricted system privileges "
                "(DATA ADMIN, USER ADMIN, ROLE ADMIN, DEVELOPMENT, INIFILE "
                "ADMIN and the encryption/credential/trust administrators) that "
                "no user holds directly — each arrives through one or more "
                "roles. Granting through roles is SAP's own recommendation and "
                "is not the problem being reported. What is reported is reach: "
                "these accounts hold the privilege in practice, and a review "
                "that reads only direct grants does not see them."
                % len(items)
            ),
            affected_items=items,
            remediation=(
                "1. For each path, confirm the account still needs the "
                "privilege the role carries.\n"
                "2. Split broad admin roles so that a role granting DATA ADMIN "
                "is not also the role granting routine access.\n"
                "3. Verify against SAP's own resolution: SELECT * FROM "
                "\"PUBLIC\".\"EFFECTIVE_PRIVILEGE_GRANTEES\" WHERE "
                "PRIVILEGE = 'DATA ADMIN';"
            ),
            references=[
                "SAP HANA Security Checklists and Recommendations — "
                "Critical System Privileges",
                "SAP HANA Security Guide — System Privileges",
            ],
            affected_objects=objects,
            # One finding over the whole resolved graph. Removing one member from
            # one role must shrink it, not retire it and raise a new one.
            scope="aggregate",
        )

    def check_critical_privilege_combinations(self):
        """CRITICAL: privilege pairs SAP says must not meet on one grantee.

        Resolved through roles, because the pair is just as dangerous when the
        two halves arrive by different routes — and rather more likely to,
        since nobody granting one role is looking at what the other one holds.
        """
        if not self.data.get("hana_granted_privileges"):
            return
        effective = self._effective_holdings()
        if not effective:
            return
        offenders, objects = [], []
        for grantee, holdings in sorted(effective.items()):
            privs = set(holdings)
            for first, second, consequence in self.CRITICAL_PRIV_PAIRS:
                if first not in privs or second not in privs:
                    continue
                offenders.append(
                    "%s holds %s (%s) + %s (%s) — %s"
                    % (grantee, first, self._route(holdings, first),
                       second, self._route(holdings, second), consequence))
                self._add_obj(objects, "hana_user", grantee)
                self._add_obj(objects, "hana_privilege", first)
                self._add_obj(objects, "hana_privilege", second)
        if not offenders:
            return
        self.finding(
            check_id="HANADB-PRIV-008",
            title="Critical system privilege combinations held by one grantee",
            severity=self.SEVERITY_CRITICAL,
            category=self.CATEGORY,
            description=(
                "%d grantee/pair combination(s) that SAP's HANA Security "
                "Checklist names as critical. Each half of these pairs is "
                "ordinary enough on its own that a per-privilege review passes "
                "it; together they close a loop. USER ADMIN with ROLE ADMIN is "
                "self-service escalation to any privilege in the database, and "
                "AUDIT ADMIN with AUDIT OPERATOR is the ability to change what "
                "is recorded and then remove the record."
                % len(offenders)
            ),
            affected_items=offenders,
            remediation=(
                "Separate the pair. Move one half to a different account or "
                "role so that no single grantee holds both, and record the "
                "split as a segregation-of-duties control rather than a "
                "one-time revocation."
            ),
            references=[
                "SAP HANA Security Checklists and Recommendations — "
                "System Privileges: Critical Combinations",
            ],
            affected_objects=objects,
            scope="aggregate",
        )

    def check_system_info_dump_grants(self):
        """HIGH: EXECUTE on the full system info dump procedures.

        SAP's checklist singles these out because the dump they produce is not
        a diagnostic summary — it is configuration, trace content and query
        text written to a file on the database host, readable by whoever can
        reach that directory. The grant is an EXECUTE on an object, so none of
        the system-privilege checks in this file can see it.
        """
        if not self.data.get("hana_granted_privileges"):
            return
        offenders, objects = [], []
        for grantee, gtype, priv, obj, _g in self._iter_priv_rows():
            gu = grantee.upper()
            if not gu or gu in self.TECHNICAL_USERS or gu.startswith("_SYS"):
                continue
            if "FULL_SYSTEM_INFO_DUMP" not in obj.upper():
                continue
            if priv and priv != "EXECUTE":
                continue
            label = "%s%s ← EXECUTE ON %s" % (
                grantee, " (role)" if gtype == "ROLE" else "", obj)
            offenders.append(label)
            self._add_obj(objects,
                          "hana_role" if gtype == "ROLE" else "hana_user", grantee)
        if not offenders:
            return
        self.finding(
            check_id="HANADB-PRIV-009",
            title="Execute rights on the HANA full system info dump",
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=(
                "%d grantee(s) can run FULL_SYSTEM_INFO_DUMP_CREATE or "
                "FULL_SYSTEM_INFO_DUMP_RETRIEVE. The dump collects "
                "configuration, trace files and statement text into an archive "
                "on the database host; anyone who can create one and retrieve "
                "it obtains a broad extract of the system without holding any "
                "system privilege that a privilege review would flag."
                % len(offenders)
            ),
            affected_items=offenders,
            remediation=(
                "Revoke EXECUTE on SYS.FULL_SYSTEM_INFO_DUMP_CREATE and "
                "SYS.FULL_SYSTEM_INFO_DUMP_RETRIEVE from all but the support "
                "accounts that need them, and grant them for the duration of a "
                "support incident rather than permanently."
            ),
            references=[
                "SAP HANA Security Checklists and Recommendations — "
                "Recommendations for Support Users",
            ],
            affected_objects=objects,
            scope="aggregate",
        )

    def check_grantable_privileges(self):
        """MEDIUM: privileges granted WITH ADMIN/GRANT OPTION enable sprawl."""
        if not self.data.get("hana_granted_privileges"):
            return
        offenders = []
        objects: List[Dict[str, Any]] = []
        grants: List[Dict[str, Any]] = []
        for grantee, gtype, priv, obj, grantable in self._iter_priv_rows():
            gu = grantee.upper()
            if gu in self.TECHNICAL_USERS or gu.startswith("_SYS"):
                continue
            if self._truthy(grantable) and (priv in self.HIGH_SYSTEM_PRIVS or "ADMIN" in priv):
                offenders.append(f"{grantee} ← {priv} (WITH ADMIN/GRANT OPTION)")
                self._add_obj(objects, "hana_user", grantee)
                # No "grantable" qualifier: the delegation is what the CHECK is about,
                # and pinning it onto the node would fork DATA ADMIN into two graph
                # nodes that HANADB-PRIV-002 and this check could never share.
                self._add_obj(objects, "hana_privilege", priv)
                self._add_grant(grants, grantee, "hana_privilege", priv)
        if offenders:
            self.finding(
                check_id="HANADB-PRIV-004",
                title="Sensitive privileges granted WITH ADMIN OPTION",
                severity=self.SEVERITY_MEDIUM,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} sensitive privilege(s) are granted with the admin/"
                    "grant option, letting the grantee re-grant them to others. This "
                    "causes uncontrolled privilege propagation that is hard to audit."
                ),
                affected_items=offenders,
                remediation=(
                    "Re-grant without the admin option unless delegation is explicitly "
                    "required and governed. Regularly review WITH ADMIN OPTION grants."
                ),
                references=["SAP HANA Security Guide — Granting Privileges"],
                affected_objects=objects,
                relations=grants,
                # One finding over the delegated-grant population; re-granting one
                # privilege without the admin option must shrink it, not churn it.
                scope="aggregate",
            )

    def check_analytic_privilege_bypass(self):
        """CRITICAL: _SYS_BI_CP_ALL disables analytic-privilege data filtering."""
        offenders = []
        objects: List[Dict[str, Any]] = []
        for grantee, gtype, priv, obj, _ in self._iter_priv_rows():
            target = f"{priv} {obj}".upper()
            if self.CP_ALL in target or self.CP_ALL in grantee.upper():
                if grantee.upper() not in self.TECHNICAL_USERS:
                    offenders.append(f"{grantee} ← {self.CP_ALL}")
                    self._add_obj(objects, "hana_user", grantee)
                    self._add_obj(objects, "hana_privilege", self.CP_ALL)
        for row in (self.data.get("hana_granted_roles") or []):
            grantee = str(row.get("GRANTEE", row.get("USER_NAME", ""))).strip()
            role = str(row.get("ROLE_NAME", row.get("ROLE", ""))).strip().upper()
            if self.CP_ALL in role and grantee.upper() not in self.TECHNICAL_USERS:
                offenders.append(f"{grantee} ← role {role}")
                self._add_obj(objects, "hana_user", grantee)
                self._add_obj(objects, "hana_role", role)
        if offenders:
            self.finding(
                check_id="HANADB-PRIV-005",
                title="Analytic-privilege bypass (_SYS_BI_CP_ALL) granted",
                severity=self.SEVERITY_CRITICAL,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} grantee(s) hold _SYS_BI_CP_ALL. This built-in "
                    "structured (analytic) privilege turns off all analytic-privilege "
                    "row filtering in modeled calculation/analytic views — the grantee "
                    "can read all reporting data regardless of intended restrictions."
                ),
                affected_items=sorted(set(offenders)),
                remediation=(
                    "Revoke _SYS_BI_CP_ALL from users/roles and grant specific analytic "
                    "privileges that enforce the intended row/column restrictions."
                ),
                references=[
                    "CIS SAP HANA Benchmark — _SYS_BI_CP_ALL",
                    "SAP HANA Security Guide — Analytic Privileges",
                ],
                affected_objects=objects,
                # "N grantee(s) hold _SYS_BI_CP_ALL" is a population statement, and it
                # merges two sources (direct grants and role grants). Revoking it from
                # one grantee must shrink the finding, not raise a fresh one.
                scope="aggregate",
            )

    def check_powerful_roles(self):
        """HIGH: broadly powerful predefined roles granted to users."""
        roles = self.data.get("hana_granted_roles")
        if not roles:
            return
        offenders = []
        objects: List[Dict[str, Any]] = []
        # WHICH USER HOLDS WHICH ROLE, kept as well as flattened. The two ends
        # are in hand together on every iteration; without this the graph sees
        # three users and three roles and cannot tell which grant is which, so
        # the HANA half of the estate contributes no privilege edges at all.
        relations: List[Dict[str, Any]] = []
        for row in roles:
            grantee = str(row.get("GRANTEE", row.get("USER_NAME", ""))).strip()
            role = str(row.get("ROLE_NAME", row.get("ROLE", ""))).strip()
            if not grantee or not role:
                continue
            if grantee.upper() in self.TECHNICAL_USERS or grantee.startswith("_SYS"):
                continue
            ru = role.upper()
            if ru in self.POWERFUL_ROLES or ru.endswith("ADMIN") or "SUPPORT" in ru:
                offenders.append(f"{grantee} ← role {role}")
                self._add_obj(objects, "hana_user", grantee)
                self._add_obj(objects, "hana_role", role)
                relations.append(
                    {"from": {"type": "hana_user", "name": grantee},
                     "to": {"type": "hana_role", "name": role}})
        if offenders:
            self.finding(
                check_id="HANADB-ROLE-001",
                title="Powerful predefined roles granted to users",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} user grant(s) of broadly powerful roles "
                    "(CONTENT_ADMIN, MODELING, MONITORING, SAP_INTERNAL_HANA_SUPPORT, or "
                    "*ADMIN roles). SAP_INTERNAL_HANA_SUPPORT in particular exposes "
                    "internal system views and should only be granted temporarily to SAP."
                ),
                affected_items=offenders,
                remediation=(
                    "Grant these roles only to the minimum set of users and only when "
                    "required. Revoke SAP_INTERNAL_HANA_SUPPORT after any support case."
                ),
                references=[
                    "CIS SAP HANA Benchmark — SAP_INTERNAL_HANA_SUPPORT",
                    "SAP HANA Security Guide — Predefined Roles",
                ],
                affected_objects=objects,
                relations=relations,
                # One finding over every powerful-role grant. Revoking
                # SAP_INTERNAL_HANA_SUPPORT after a support case must shrink this
                # finding, leaving the remaining grants' age untouched.
                scope="aggregate",
            )

    # --------------------------------------------------------------- auditing
    def check_auditing_enabled(self):
        """CRITICAL: global auditing switched off."""
        idx = self._param_index()
        if not idx:
            return
        state = self._get_param(idx, "global_auditing_state", "auditing configuration")
        if state is None:
            # SILENCE WAS THE WRONG ANSWER HERE. SAP's own checklist says
            # auditing is DISABLED BY DEFAULT, so an export that carries no
            # global_auditing_state row is describing the insecure state, not an
            # unknown one — and returning quietly turned the check that reports
            # "no forensic trail at all" into a clean report. The parameter
            # export is supplied (`idx` is non-empty above), so this is an
            # absent setting rather than an absent source.
            self.finding(
                check_id="HANADB-AUDIT-005",
                title="HANA auditing state could not be read from the export",
                severity=self.SEVERITY_INFO,
                category=self.CATEGORY,
                description=(
                    "The supplied HANA parameter export carries no "
                    "[auditing configuration] global_auditing_state row. SAP's "
                    "HANA Security Checklist states that auditing is disabled by "
                    "default, so an unset value is very probably OFF rather than "
                    "unknown — but this product will not score it as a verdict "
                    "it did not read. Establish the value before treating the "
                    "absence of audit findings as evidence of an audit trail."
                ),
                affected_items=["[auditing configuration] global_auditing_state: "
                                "not present in the export"],
                remediation=(
                    "1. Run: SELECT * FROM \"PUBLIC\".\"M_INIFILE_CONTENTS\" "
                    "WHERE SECTION = 'auditing configuration' AND KEY = "
                    "'global_auditing_state';\n"
                    "2. If it returns nothing or false, auditing is off — enable "
                    "it and define audit policies.\n"
                    "3. Re-export hana_parameters.csv so the value is on record."
                ),
                references=["SAP HANA Security Checklists and Recommendations — "
                            "Recommendations for Auditing"],
                details={"degrades_coverage": True},
            )
            return
        if self._falsy(state):
            self.finding(
                check_id="HANADB-AUDIT-001",
                title="HANA database auditing is disabled",
                severity=self.SEVERITY_CRITICAL,
                category=self.CATEGORY,
                description=(
                    "global.ini [auditing configuration] global_auditing_state is not "
                    "'true'. With auditing off, privileged actions, grants, config "
                    "changes and failed logons are not recorded — there is no forensic "
                    "trail and no detection of misuse."
                ),
                affected_items=[f"global_auditing_state = {state}"],
                remediation=(
                    "Enable auditing: "
                    "ALTER SYSTEM ALTER CONFIGURATION ('global.ini','SYSTEM') "
                    "SET ('auditing configuration','global_auditing_state') = 'true' "
                    "WITH RECONFIGURE; then define audit policies for critical actions."
                ),
                references=[
                    "CIS SAP HANA Benchmark — Enable auditing",
                    "SAP HANA Security Guide — Auditing Activity",
                ],
                # One parameter, one defect. No qualifier: the check fires on any falsy
                # spelling ("false", "0", "off", empty), so pinning the exported value
                # would split one parameter into several identities and several nodes.
                affected_objects=[{"type": "parameter_name",
                                   "name": "global_auditing_state"}],
                scope="object",
            )

    def check_audit_trail_target(self):
        """HIGH: audit trail written to a tamperable CSV text file."""
        idx = self._param_index()
        if not idx:
            return
        offenders = []
        objects: List[Dict[str, Any]] = []
        for key in ("default_audit_trail_type", "emergency_audit_trail_type"):
            val = self._get_param(idx, key, "auditing configuration")
            if val and "CSVTEXTFILE" in str(val).upper():
                offenders.append(f"{key} = {val}")
                self._add_obj(objects, "parameter_name", key, val)
        if offenders:
            self.finding(
                check_id="HANADB-AUDIT-002",
                title="Audit trail written to CSV text file (tamperable)",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    "The audit trail target is CSVTEXTFILE. File-based audit trails can "
                    "be read or modified by anyone with OS/file access and are not "
                    "protected by the database, undermining audit integrity."
                ),
                affected_items=offenders,
                remediation=(
                    "Set the audit trail type to SYSLOGPROTOCOL (forwarded to a "
                    "protected SIEM) or, for local storage, the database audit table "
                    "(CSTABLE). Avoid CSVTEXTFILE in production."
                ),
                references=[
                    "CIS SAP HANA Benchmark — Audit trail target",
                    "SAP HANA Security Guide — Audit Trail Targets",
                ],
                affected_objects=objects,
                # Two parameters can name the same defect ("the audit trail is a text
                # file"). Aggregate so that fixing the default trail while the emergency
                # trail is still CSVTEXTFILE shrinks this finding instead of retiring it
                # and raising a zero-age clone for the leftover parameter.
                scope="aggregate",
            )

    def check_audit_policy_coverage(self):
        """HIGH: no active audit policy covering critical action groups."""
        policies = self.data.get("hana_audit_policies")
        if not policies:
            return
        critical_actions = {
            "GRANT": ["GRANT PRIVILEGE", "GRANT ROLE", "GRANT ANY", "GRANT STRUCTURED PRIVILEGE"],
            "REVOKE": ["REVOKE PRIVILEGE", "REVOKE ROLE", "REVOKE ANY"],
            "USER ADMIN": ["CREATE USER", "DROP USER", "ALTER USER"],
            "CONFIG": ["SYSTEM CONFIGURATION CHANGE", "SET SYSTEM LICENSE"],
            "CONNECT": ["CONNECT", "VALIDATE USER"],
        }
        covered = set()
        active_count = 0
        for row in policies:
            active = row.get("IS_AUDIT_POLICY_ACTIVE", row.get("ACTIVE",
                     row.get("IS_ENABLED", row.get("STATUS", ""))))
            if not (self._truthy(active) or str(active).strip().upper() == "ACTIVE"):
                continue
            active_count += 1
            actions = str(row.get("AUDIT_ACTION_NAME", row.get("ACTIONS",
                      row.get("AUDIT_ACTION", row.get("EVENT_ACTIONS", ""))))).upper()
            for group, needles in critical_actions.items():
                if any(n in actions for n in needles):
                    covered.add(group)
        missing = [g for g in critical_actions if g not in covered]
        if active_count == 0:
            self.finding(
                check_id="HANADB-AUDIT-003",
                title="No active HANA audit policies",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    "Auditing may be enabled globally, but no audit policy is active, so "
                    "nothing is actually recorded. Audit policies define which actions "
                    "are captured."
                ),
                affected_items=[f"{len(policies)} policy(ies) defined, 0 active"],
                remediation=(
                    "Activate audit policies covering privileged and security-relevant "
                    "actions (grants/revokes, user admin, configuration changes, "
                    "authentication)."
                ),
                references=["SAP HANA Security Guide — Audit Policies"],
                # No affected_objects: the defect is the ABSENCE of an active policy, so
                # there is no offending object to name. Listing the inactive policies
                # would make activating any one of them re-key the finding. Aggregate,
                # and therefore correctly identified by check_id alone.
                scope="aggregate",
            )
        elif missing:
            self.finding(
                check_id="HANADB-AUDIT-004",
                title="Audit policies do not cover critical action groups",
                severity=self.SEVERITY_MEDIUM,
                category=self.CATEGORY,
                description=(
                    f"Active audit policies do not cover: {', '.join(missing)}. "
                    "Privilege grants, user administration, configuration changes and "
                    "authentication are the highest-value events for detecting misuse."
                ),
                affected_items=[f"Uncovered action group: {g}" for g in missing],
                remediation=(
                    "Extend audit policies to include the missing critical action groups "
                    "(GRANT/REVOKE, CREATE/ALTER/DROP USER, SYSTEM CONFIGURATION, CONNECT)."
                ),
                references=["CIS SAP HANA Benchmark — Audit policy coverage"],
                # No affected_objects: the members here are this module's own action-
                # group labels (GRANT, REVOKE, CONNECT …), not objects that exist in the
                # system, and inventing a type for them would put fictional nodes in the
                # graph. Aggregate: covering one more group must shrink the finding.
                scope="aggregate",
            )

    # ------------------------------------------------------------- parameters
    def check_password_policy(self):
        """HIGH: weak HANA password-policy parameters."""
        idx = self._param_index()
        if not idx:
            return
        section = "password policy"
        issues = []
        objects: List[Dict[str, Any]] = []

        min_len = self._get_param(idx, "minimal_password_length", section)
        if min_len is not None:
            try:
                if int(str(min_len)) < 8:
                    issues.append(f"minimal_password_length = {min_len} (recommend ≥ 8)")
                    self._add_obj(objects, "parameter_name",
                                  "minimal_password_length", min_len)
            except ValueError:
                pass

        force_first = self._get_param(idx, "force_first_password_change", section)
        if force_first is not None and self._falsy(force_first):
            issues.append("force_first_password_change = false (initial passwords not forced to change)")
            self._add_obj(objects, "parameter_name",
                          "force_first_password_change", force_first)

        max_attempts = self._get_param(idx, "maximum_invalid_connect_attempts", section)
        if max_attempts is not None:
            try:
                if int(str(max_attempts)) > 6:
                    issues.append(f"maximum_invalid_connect_attempts = {max_attempts} (recommend ≤ 6)")
                    self._add_obj(objects, "parameter_name",
                                  "maximum_invalid_connect_attempts", max_attempts)
            except ValueError:
                pass

        lifetime = self._get_param(idx, "maximum_password_lifetime", section)
        if lifetime is not None:
            try:
                if int(str(lifetime)) > 365:
                    issues.append(f"maximum_password_lifetime = {lifetime}d (recommend ≤ 365)")
                    self._add_obj(objects, "parameter_name",
                                  "maximum_password_lifetime", lifetime)
            except ValueError:
                pass

        if issues:
            self.finding(
                check_id="HANADB-PARAM-001",
                title="Weak HANA password-policy parameters",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(issues)} HANA password-policy parameter(s) are weaker than "
                    "recommended, making DB passwords easier to guess or longer-lived "
                    "than they should be."
                ),
                affected_items=issues,
                remediation=(
                    "Harden [password policy] in indexserver.ini (tenant DB) / "
                    "nameserver.ini (system DB): "
                    "minimal_password_length ≥ 8, force_first_password_change = true, "
                    "maximum_invalid_connect_attempts ≤ 6, and a bounded "
                    "maximum_password_lifetime. Align with your enterprise password standard."
                ),
                references=[
                    "CIS SAP HANA Benchmark — Password policy",
                    "SAP HANA Security Guide — Password Policy Parameters",
                ],
                affected_objects=objects,
                # Up to four parameters roll up into ONE "weak password policy" finding.
                # Aggregate is what keeps the value in each qualifier safe: raising
                # minimal_password_length from 6 to 7 (still weak) must not retire the
                # finding and reset its age just because a member's value moved.
                scope="aggregate",
            )

    def check_error_disclosure(self):
        """MEDIUM: detailed error messages returned to clients (info disclosure)."""
        idx = self._param_index()
        if not idx:
            return
        val = self._get_param(idx, "detailed_error_on_connect", "password policy")
        if val is None:
            val = self._get_param(idx, "detailed_error_on_connect", None)
        if val is not None and self._truthy(val):
            self.finding(
                check_id="HANADB-PARAM-002",
                title="Detailed connect errors exposed to clients",
                severity=self.SEVERITY_MEDIUM,
                category=self.CATEGORY,
                description=(
                    "indexserver.ini [password policy] detailed_error_on_connect = true. Detailed "
                    "authentication error messages reveal whether a user exists, is "
                    "locked, or the password is wrong — aiding user enumeration and "
                    "targeted brute force."
                ),
                affected_items=[f"detailed_error_on_connect = {val}"],
                remediation=(
                    "Set detailed_error_on_connect = false in production so clients "
                    "receive only a generic authentication-failure message."
                ),
                references=[
                    "CIS SAP HANA Benchmark — detailed_error_on_connect",
                    "SAP HANA Security Guide — Error Disclosure",
                ],
                # One parameter, one defect. No qualifier: any truthy spelling fires the
                # check, so the exported value would fragment one parameter's identity.
                affected_objects=[{"type": "parameter_name",
                                   "name": "detailed_error_on_connect"}],
                scope="object",
            )

    def check_sql_tls_enforced(self):
        """HIGH: SQL/JDBC/ODBC connections not required to use TLS."""
        idx = self._param_index()
        if not idx:
            return
        enforce = self._get_param(idx, "sslenforce", "communication")
        if enforce is None:
            enforce = self._get_param(idx, "sslenforce", None)
        if enforce is not None and self._falsy(enforce):
            self.finding(
                check_id="HANADB-PARAM-003",
                title="TLS not enforced for HANA SQL connections",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    "global.ini [communication] sslenforce = false. SQL clients "
                    "(JDBC/ODBC and the application server) may connect to the HANA SQL "
                    "port without TLS, exposing credentials and query data to network "
                    "sniffing and man-in-the-middle attacks."
                ),
                affected_items=[f"sslenforce = {enforce}"],
                remediation=(
                    "Set [communication] sslenforce = true so only TLS-encrypted SQL "
                    "connections are accepted, and provision valid server certificates. "
                    "(This is separate from the ICM/HTTPS TLS covered by the crypto module.)"
                ),
                references=[
                    "CIS SAP HANA Benchmark — Enforce SSL for SQL",
                    "SAP HANA Security Guide — Secure Client Communication",
                ],
                # One parameter, one defect. No qualifier: any falsy spelling fires.
                affected_objects=[{"type": "parameter_name", "name": "sslenforce"}],
                scope="object",
            )

    # ---------------------------------------------------------------- recovery
    def check_log_mode(self):
        """HIGH: log_mode = overwrite disables point-in-time recovery."""
        idx = self._param_index()
        if not idx:
            return
        val = self._get_param(idx, "log_mode", "persistence")
        if val is None:
            val = self._get_param(idx, "log_mode", None)
        if val is not None and str(val).strip().lower() == "overwrite":
            self.finding(
                check_id="HANADB-PARAM-004",
                title="HANA log_mode = overwrite (no point-in-time recovery)",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    "global.ini [persistence] log_mode = overwrite. In this mode HANA "
                    "reuses redo-log segments after each savepoint instead of retaining "
                    "them, so no log backups are produced and the database cannot be "
                    "recovered to a point in time after the last complete data backup. "
                    "Any corruption, ransomware event, or erroneous mass change that "
                    "occurs after that backup is therefore unrecoverable, and the "
                    "recovery-point objective collapses to the age of the last full/delta "
                    "data backup. 'overwrite' is intended only for sandbox or bulk-loading "
                    "systems and must never be used on production or any system whose data "
                    "is subject to SOX/audit retention obligations."
                ),
                affected_items=[f"[persistence] log_mode = {val}"],
                remediation=(
                    "Set [persistence] log_mode = normal and restart the database. Take a "
                    "full data backup immediately afterwards — log backups only begin once "
                    "a data backup exists. Schedule automatic log backups (bound "
                    "log_backup_timeout_s) to a secure, encrypted target, verify that log "
                    "backups are actually being written, and perform a test recovery to "
                    "confirm the point-in-time recovery chain is intact. Ensure backup "
                    "encryption is enabled so the retained logs are protected at rest."
                ),
                references=[
                    "SAP HANA Administration Guide — Log Modes",
                    "SAP HANA Administration Guide — Backup and Recovery",
                ],
                # One parameter, one defect. No qualifier: the check fires on exactly one
                # value, compared case-insensitively, so carrying "overwrite" vs
                # "OVERWRITE" into identity would split the finding on export casing
                # alone while adding no discrimination.
                affected_objects=[{"type": "parameter_name", "name": "log_mode"}],
                scope="object",
            )

    def check_cross_database_access(self):
        """MEDIUM: MDC cross-database access enabled (tenant isolation weakened)."""
        idx = self._param_index()
        if not idx:
            return
        val = self._get_param(idx, "enabled", "cross_database_access", strict=True)
        if val is None:
            return
        if self._truthy(val):
            self.finding(
                check_id="HANADB-PARAM-005",
                title="HANA cross-database (MDC) access is enabled",
                severity=self.SEVERITY_MEDIUM,
                category=self.CATEGORY,
                description=(
                    "global.ini [cross_database_access] enabled = true on the system "
                    "database. In a multi-tenant (MDC) HANA system, enabling cross-database "
                    "access allows queries in one tenant database to read objects in another "
                    "tenant via associated remote users, weakening the isolation boundary "
                    "that is the main security rationale for tenant separation. If the set "
                    "of permitted target tenants (targets_for_<source_db_name>) is broad or "
                    "unmanaged, a "
                    "compromise or privilege escalation in a low-sensitivity tenant can be "
                    "pivoted into a high-sensitivity one, and data-residency/segregation "
                    "assumptions no longer hold. Access is scoped per source tenant via the "
                    "targets_for_<source_db_name> parameter (one-directional: it lists the "
                    "databases the named source tenant is allowed to read)."
                ),
                affected_items=[f"[cross_database_access] enabled = {val}"],
                remediation=(
                    "Disable cross-database access unless there is a documented business "
                    "requirement: [cross_database_access] enabled = false. Where it is "
                    "required, scope it explicitly with targets_for_<source_db_name> to the "
                    "minimum set of tenant pairs (e.g. targets_for_DB2 = DB1 to let DB2 read "
                    "DB1), restrict the associated remote users to least privilege, and "
                    "review the cross-tenant grants periodically."
                ),
                references=[
                    "SAP HANA Administration Guide — Cross-Database Access in MDC",
                    "SAP HANA Security Guide — Tenant Database Isolation",
                ],
                # One parameter, one defect. The key in M_INIFILE_CONTENTS is literally
                # "enabled", which is not an identity on its own — every ini section has
                # one — so the section narrows it. That is exactly what a qualifier is
                # for, and it is constant for this check, so identity stays stable.
                affected_objects=[{"type": "parameter_name", "name": "enabled",
                                   "qualifier": "section=cross_database_access"}],
                scope="object",
            )

    def check_debug_privileges(self):
        """HIGH: DEBUG / ATTACH DEBUGGER privileges expose runtime data."""
        if not self.data.get("hana_granted_privileges"):
            return
        offenders = []
        objects: List[Dict[str, Any]] = []
        grants: List[Dict[str, Any]] = []
        for grantee, gtype, priv, obj, _ in self._iter_priv_rows():
            gu = grantee.upper()
            if gu.startswith("_SYS") or gu == "SYS":
                continue
            if priv in ("DEBUG", "ATTACH DEBUGGER"):
                label = f"{grantee} ← {priv}" + (f" ON {obj}" if obj else "")
                offenders.append(label)
                self._add_obj(objects, "hana_user", grantee)
                # The debug target rides as a qualifier, not as its own object: the
                # export gives a bare OBJECT_NAME that may be a procedure ("DEBUG ON
                # ZFI_PAYMENT_RUN") or a user ("ATTACH DEBUGGER ON DBADMIN"), and there
                # is no field that says which — typing it would be a guess.
                self._add_obj(objects, "hana_privilege", priv,
                              f"on={obj}" if obj else None)
                self._add_grant(grants, grantee, "hana_privilege", priv,
                                f"on={obj}" if obj else None)
        if offenders:
            self.finding(
                check_id="HANADB-PRIV-006",
                title="Debug privileges (DEBUG / ATTACH DEBUGGER) granted to users",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} grant(s) of the DEBUG or ATTACH DEBUGGER privilege "
                    "were found. These privileges let a user attach the SQLScript debugger "
                    "to procedures or to another user's sessions, single-step through "
                    "server-side logic and inspect the live values of every variable and "
                    "intermediate result — including data the debugged code reads from "
                    "protected tables. ATTACH DEBUGGER in particular can expose the runtime "
                    "data of another user's session, bypassing analytic-privilege and "
                    "authorization filtering that would normally restrict what that data "
                    "consumer can see. On a production database these privileges are almost "
                    "never legitimate and are a strong candidate for both data exfiltration "
                    "and logic tampering."
                ),
                affected_items=offenders,
                remediation=(
                    "Revoke DEBUG and ATTACH DEBUGGER from all users on production: "
                    "REVOKE DEBUG ON <object> FROM <user>; and revoke ATTACH DEBUGGER "
                    "accordingly. Perform SQLScript debugging only in non-productive "
                    "systems that do not contain real business data. If a break-glass "
                    "debugging need arises in production, grant the privilege through a "
                    "firefighter/EAM session that is time-boxed, logged and reviewed, and "
                    "revoke it immediately afterwards."
                ),
                references=[
                    "SAP HANA Security Guide — Debugging Privileges",
                    "SAP HANA SQLScript Reference — Debugging",
                ],
                affected_objects=objects,
                relations=grants,
                # One finding over every debug grant found. Revoking DEBUG from one user
                # while another still holds ATTACH DEBUGGER must shrink this finding
                # rather than close it and open a fresh, zero-age one.
                scope="aggregate",
            )
    # ----------------------------------------------------- SAP Baseline NETCF-H
    def check_internal_listen_interface(self):
        """CRITICAL: HANA internal communication listens on every interface.

        SAP Security Baseline requirement NETCF-H, config store HDB_PARAMETER.
        """
        idx = self._param_index()
        if not idx:
            return
        val = self._get_param(idx, "listeninterface", "communication", strict=True)
        if val is None:
            return
        setting = str(val).strip().lower()
        # `.local` binds the internal services to loopback; `.internal` binds them
        # to the internal network defined by internal_hostname_resolution. Only
        # `.global` puts them on every interface, so anything else — including a
        # spelling this check does not know — is left alone rather than guessed at.
        if setting != ".global":
            return

        # A SECTION, NOT A KEY, and the difference made this line a lie.
        # `_get_param(idx, "internal_hostname_resolution", None)` looks up a KEY
        # of that name; in global.ini it is a SECTION whose keys are adapter IP
        # addresses. So the lookup returned None on every real export and the
        # supplementary line below was emitted unconditionally — asserting that
        # no internal network is defined on landscapes that define one.
        resolution = self._resolution_entries("internal_hostname_resolution")
        items = ["[communication] listeninterface = .global"]
        if not resolution:
            items.append("internal_hostname_resolution is not set, so no internal "
                         "network is defined to bind to instead")

        self.finding(
            check_id="HANADB-PARAM-006",
            title="HANA internal communication listens on all network interfaces",
            severity=self.SEVERITY_CRITICAL,
            category=self.CATEGORY,
            description=(
                "global.ini [communication] listeninterface = .global. HANA's "
                "internal service ports — the nameserver, indexserver, "
                "preprocessor, compileserver and the internal request channels "
                "— are bound to every network interface on the host rather "
                "than to loopback or to a dedicated internal network. Those "
                "channels carry inter-service traffic that is authenticated "
                "largely by the fact that it arrives on the internal network, so "
                "reaching them from outside the host means reaching the "
                "database's own control plane rather than its SQL port: the SQL "
                "authorization model and the audit policies that sit on it are "
                "not in that path at all. In a scale-out landscape .global is "
                "sometimes set to make the hosts reach one another and then left "
                "in place, which is why this is worth checking on a system that "
                "otherwise looks hardened."
            ),
            affected_items=items,
            remediation=(
                "Set [communication] listeninterface = .local on a single-host "
                "system, so the internal channels bind to loopback and are "
                "unreachable from the network. On a scale-out system set it to "
                ".internal and define the internal network with "
                "internal_hostname_resolution, so the channels bind only to the "
                "dedicated internal interface. Restart the database for the "
                "change to take effect, and confirm afterwards that the internal "
                "ports are no longer bound to an external address. Where .global "
                "genuinely cannot be avoided, firewall the internal port range to "
                "the other HANA hosts only."
            ),
            references=[
                "SAP Security Baseline — NETCF-H (HANA internal communication)",
                "SAP HANA Security Guide — Network and Communication Security",
                "SAP HANA Administration Guide — Configuring Internal Host Name Resolution",
            ],
            # One parameter, one defect. The section qualifies a key name generic
            # enough to recur, exactly as check_cross_database_access does.
            affected_objects=[{"type": "parameter_name", "name": "listeninterface",
                               "qualifier": "section=communication"}],
            scope="object",
        )

    # ---------------------------------------------------- SAP Baseline TRACES-H
    def check_sql_trace_results(self):
        """CRITICAL: SQL trace is recording result sets to a file.

        SAP Security Baseline requirement TRACES-H, config store HDB_PARAMETER.
        """
        idx = self._param_index()
        if not idx:
            return
        level = self._get_param(idx, "level", "sqltrace", strict=True)
        if level is None:
            # Some exports flatten the section into the key name. Match that
            # spelling too, but never a bare `level` — every ini section has
            # one, and reading an unrelated section's level as a trace level is
            # the kind of wrong answer this module must not produce.
            level = self._get_param(idx, "sql_trace_level", None)
        if level is None or str(level).strip().upper() != "ALL_WITH_RESULTS":
            return

        items = ["[sqltrace] level = ALL_WITH_RESULTS"]
        enabled = self._get_param(idx, "trace", "sqltrace", strict=True)
        if enabled is not None:
            items.append("[sqltrace] trace = %s" % enabled)
        user = self._get_param(idx, "user", "sqltrace", strict=True)
        if user is not None:
            items.append("[sqltrace] user = %s (whose statements are traced)" % user)

        self.finding(
            check_id="HANADB-TRACE-001",
            title="HANA SQL trace is set to record query results",
            severity=self.SEVERITY_CRITICAL,
            category=self.CATEGORY,
            description=(
                "indexserver.ini [sqltrace] level = ALL_WITH_RESULTS. At this "
                "level HANA writes not only the statements it executes but the "
                "rows they return into a plain trace file on the database host. "
                "Business data therefore leaves the database's access-control "
                "boundary entirely: the trace file is read through the "
                "filesystem, so the analytic privileges, the row-level "
                "restrictions and the audit policies that govern a SELECT do not "
                "apply to reading it, and anyone holding the operating-system "
                "account or a HANA trace-file privilege sees whatever the traced "
                "sessions saw. Where the traced tables carry personal data this "
                "also creates a copy outside every retention, masking and "
                "residency control the estate has. ALL_WITH_RESULTS exists for "
                "reproducing a defect under support supervision; it is "
                "frequently switched on for an incident and not switched off "
                "afterwards."
            ),
            affected_items=items,
            remediation=(
                "Set [sqltrace] trace = off, or reduce [sqltrace] level to "
                "NORMAL or ERROR, so results are no longer written. Delete the "
                "trace files already produced at this level and treat them as "
                "the data they contain — if the traced statements touched "
                "personal data, that is a disclosure to be assessed rather than "
                "a file to be tidied. Where SAP support asks for "
                "ALL_WITH_RESULTS, scope it with [sqltrace] user or object to "
                "the single session under investigation, agree an end time, and "
                "confirm it is off afterwards."
            ),
            references=[
                "SAP Security Baseline — TRACES-H (SQL trace level)",
                "SAP HANA Troubleshooting and Performance Analysis Guide — SQL Trace",
                "SAP HANA Security Guide — Trace and Dump Files",
            ],
            # The section qualifies `level`, which is far too generic to identify
            # on its own — the same reasoning as cross_database_access's `enabled`.
            affected_objects=[{"type": "parameter_name", "name": "level",
                               "qualifier": "section=sqltrace"}],
            scope="object",
        )

    # ---------------------------------------------------- SAP Baseline SECUPD-H
    # ----------------------------------------------------- parameters, continued
    #: Controls this module itself asserts, which a tenant administrator can
    #: undo unless they are on the system database's blocklist. Overridable,
    #: because an estate may legitimately manage a different set.
    TENANT_PROTECTED_PARAMS = (
        ("global_auditing_state", "HANADB-AUDIT-001"),
        ("default_audit_trail_type", "HANADB-AUDIT-002"),
        ("sslenforce", "HANADB-PARAM-003"),
        ("log_mode", "HANADB-PARAM-004"),
        ("listeninterface", "HANADB-PARAM-006"),
    )

    def check_replication_channel(self):
        """HIGH: the system replication channel is unrestricted or unencrypted.

        `[system_replication_communication] allowed_sender` is the allowlist of
        hosts permitted to open a replication channel. Unset, the internal
        replication port accepts a connection from anywhere that can route to
        it — and a replication peer receives the database.

        `enable_ssl` decides whether that channel is encrypted. The two belong
        in one finding because they are one control surface — who may take a
        copy of the database, and whether the copy travels in clear — and an
        auditor fixing one without the other has not secured the channel.

        SILENT WHEN REPLICATION IS NOT CONFIGURED, deliberately. Most systems
        have no replication and no reason to carry these parameters; firing on
        every one of them would be noise, and noise is how a real finding gets
        skimmed past. The check first establishes that this system replicates.
        """
        rows = self.data.get("hana_parameters")
        if not rows:
            return
        evidence = []
        for section in ("system_replication", "system_replication_communication",
                        "system_replication_hostname_resolution"):
            count = self._resolution_entries(section)
            if count:
                evidence.append("[%s]: %d parameter(s)" % (section, count))
        if not evidence:
            return          # no replication configured; nothing to allowlist
        faults, objects = [], []
        allowed = [v for _f, _k, v in
                   self._param_rows("system_replication_communication", "allowed_sender")
                   if v]
        if not allowed:
            faults.append("[system_replication_communication] allowed_sender: "
                          "not set — any host that can reach the replication "
                          "port may open a channel")
            objects.append({"type": "parameter_name", "name": "allowed_sender",
                            "qualifier": "system_replication_communication"})
        ssl = [v for _f, _k, v in
               self._param_rows("system_replication_communication", "enable_ssl")]
        if ssl and all(self._falsy(v) for v in ssl):
            faults.append("[system_replication_communication] enable_ssl = %s — "
                          "the replicated copy travels unencrypted" % ssl[0])
            objects.append({"type": "parameter_name", "name": "enable_ssl",
                            "qualifier": "system_replication_communication"})
        elif not ssl:
            # Not reported as disabled. The parameter is simply not in the
            # export, and this file does not turn an unread value into a verdict.
            faults.append("[system_replication_communication] enable_ssl: not in "
                          "the export — encryption of the channel not established")
        if len(faults) == 1 and faults[0].startswith(
                "[system_replication_communication] enable_ssl: not in"):
            return      # allowlist is set and the only open point is unread
        self.finding(
            check_id="HANADB-PARAM-007",
            title="System replication channel is not secured",
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=(
                "This system is configured for system replication and %d of the "
                "channel's controls is not in place. A replication peer receives "
                "a continuous copy of the whole database: allowed_sender is the "
                "allowlist deciding which hosts may become one, and enable_ssl "
                "decides whether the copy crosses the network in clear. Neither "
                "is governed by any privilege inside the database."
                % len(faults)
            ),
            affected_items=faults + ["replication is configured — " + e
                                     for e in evidence],
            remediation=(
                "1. Set allowed_sender to the replication partners' internal "
                "host names or addresses, comma-separated.\n"
                "2. Set enable_ssl = true and provision the replication "
                "certificates on both hosts.\n"
                "3. Keep replication traffic on a separate internal network "
                "and bind it there rather than on .global.\n"
                "4. Verify: SELECT * FROM \"PUBLIC\".\"M_INIFILE_CONTENTS\" "
                "WHERE SECTION = 'system_replication_communication';"
            ),
            references=[
                "SAP HANA Security Checklists and Recommendations — "
                "Recommendations for System Replication",
            ],
            affected_objects=objects,
            scope="aggregate",
        )

    def check_import_export_file_security(self):
        """HIGH: IMPORT/EXPORT may read and write outside the permitted paths.

        `[import_export] file_security` decides which directories a SQL IMPORT
        or EXPORT can touch. At its strictest the statements are confined to a
        configured path; relaxed, they reach the database host's file system
        with the privileges of the database process — which is a route out of
        the database that no privilege on any table controls.

        The check reports anything that is not the strict value rather than
        testing for one specific relaxed spelling, and quotes what it read.
        """
        rows = self.data.get("hana_parameters")
        if not rows:
            return
        observed = [(f, k, v) for f, k, v in
                    self._param_rows("import_export", "file_security") if v]
        if not observed:
            return
        weak = [(f, v) for f, _k, v in observed if v.strip().lower() != "high"]
        if not weak:
            return
        grantees = sorted({g for g, _t, p, _o, _x in self._iter_priv_rows()
                           if p in ("IMPORT", "EXPORT")
                           and g.upper() not in self.TECHNICAL_USERS
                           and not g.upper().startswith("_SYS")})
        items = ["%s [import_export] file_security = %s" % (f or "?", v)
                 for f, v in weak]
        if grantees:
            items.append("held by %d grantee(s) with IMPORT/EXPORT: %s"
                         % (len(grantees), ", ".join(grantees[:20])))
        else:
            # Not the same sentence as "nobody holds it": the privilege export
            # may simply not have been supplied, and this check does not know.
            items.append("grantees holding IMPORT/EXPORT: none found in the "
                         "supplied privilege export")
        self.finding(
            check_id="HANADB-PARAM-008",
            title="IMPORT/EXPORT file access is not restricted",
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=(
                "[import_export] file_security is not set to its strictest "
                "value, so SQL IMPORT and EXPORT statements are not confined "
                "to the configured import/export directory. A user holding "
                "IMPORT or EXPORT can then read and write files on the "
                "database host as the database process — a path out of the "
                "database that no table or schema privilege governs."
            ),
            affected_items=items,
            remediation=(
                "1. Set [import_export] file_security = high in indexserver.ini "
                "so IMPORT/EXPORT stay inside the configured path.\n"
                "2. Review who holds the IMPORT and EXPORT system privileges "
                "and revoke them where they are not needed.\n"
                "3. Under RISE this is SAP-operated configuration; raise a "
                "service request and verify the value afterwards."
            ),
            references=[
                "SAP HANA Security Checklists and Recommendations — "
                "Recommendations for File System Access",
            ],
            affected_objects=[{"type": "parameter_name", "name": "file_security",
                               "qualifier": "import_export"}],
            scope="object",
        )

    def check_trace_levels(self):
        """MEDIUM: a trace component left at DEBUG.

        Debug traces record statement text and parameter values, which is
        exactly the data the analytic-privilege and encryption controls exist
        to protect — written to a file on the host, in clear, readable by
        whoever can reach the trace directory. SAP's checklist says to switch
        debug tracing off after diagnosis, and it is routinely forgotten.

        `_param_rows`, NOT `_param_index`, because [trace] exists in
        indexserver.ini, nameserver.ini and xsengine.ini at once, and the index
        keeps one value per key name across every file — it would report one
        component and hide the rest.
        """
        rows = self.data.get("hana_parameters")
        if not rows:
            return
        debug = [(f, k, v) for f, k, v in self._param_rows("trace")
                 if v.strip().lower() == "debug"]
        if not debug:
            return
        items = ["%s [trace] %s = %s" % (f or "?", k, v) for f, k, v in debug]
        self.finding(
            check_id="HANADB-TRACE-002",
            title="HANA trace components are set to DEBUG",
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=(
                "%d trace component(s) are set to DEBUG. Debug traces record "
                "statement text and parameter values to files on the database "
                "host in clear text — the same business data that analytic "
                "privileges restrict and volume encryption protects at rest, "
                "written where neither control applies. Debug tracing is meant "
                "to be switched on for a diagnosis and off afterwards."
                % len(debug)
            ),
            affected_items=items,
            remediation=(
                "1. Reset each component to its default level: ALTER SYSTEM "
                "ALTER CONFIGURATION ('<file>', 'SYSTEM') UNSET "
                "('trace','<component>') WITH RECONFIGURE;\n"
                "2. Delete trace files written while DEBUG was active — they "
                "keep the data after the setting is reverted.\n"
                "3. Restrict the trace directory and the TRACE ADMIN privilege."
            ),
            references=[
                "SAP HANA Security Checklists and Recommendations — "
                "Recommendations for Trace and Dump Files",
            ],
            affected_objects=[{"type": "parameter_name", "name": k,
                               "qualifier": "trace"} for _f, k, _v in debug],
            scope="aggregate",
        )

    def check_tenant_parameter_blocklist(self):
        """HIGH: a tenant can change a control this scanner asserts.

        In a multi-tenant system, `multidb.ini` on the system database lists the
        parameters a tenant administrator may NOT change. Anything absent from
        that list is a control the tenant can switch off — including, if it is
        absent, the auditing, TLS and log-mode settings four other checks in
        this file report on. That makes this a meta-control: it decides whether
        those four findings mean anything.

        THE ABSENT CASE IS SILENT, and the reason is worth stating. An export
        with no multidb.ini rows is either a single-container system, where the
        control does not exist, or a multi-tenant system whose collector did not
        read the file — and nothing in a FILE_NAME/SECTION/KEY/VALUE export
        distinguishes the two. Firing on every single-container system to cover
        the second case would put a finding on the majority to describe a
        minority. The check therefore fires only where multidb.ini rows are
        present, which is where the answer is knowable.

        The blocklist's internal layout is matched by substring rather than by
        structure. [UNVERIFIED] against a real multi-tenant export: the file
        name is SAP's, the row format inside it is this file's assumption, and
        a substring match is the form that survives being wrong about it.
        """
        rows = self.data.get("hana_parameters")
        if not rows:
            return
        multidb = [r for r in rows
                   if "multidb" in str(r.get("FILE_NAME", "")).strip().lower()]
        if not multidb:
            return
        blob = " ".join(
            "%s %s %s" % (r.get("SECTION", ""), r.get("KEY", ""), r.get("VALUE", ""))
            for r in multidb).lower()
        protected = self.get_config("hana_tenant_protected_params",
                                    self.TENANT_PROTECTED_PARAMS)
        missing = [(p, cid) for p, cid in protected if p.lower() not in blob]
        if not missing:
            return
        self.finding(
            check_id="HANADB-PARAM-009",
            title="Tenant administrators can change controls this scan asserts",
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=(
                "This is a multi-tenant system, and %d of the parameters this "
                "scan reports on are not in the system database's multidb.ini "
                "blocklist. A tenant administrator can therefore change them "
                "from inside the tenant. Each one named below is asserted by "
                "another check in this report, and that check's verdict holds "
                "only for as long as nobody in the tenant reverses it."
                % len(missing)
            ),
            affected_items=[
                "%s — not blocklisted; asserted by %s" % (p, cid)
                for p, cid in missing
            ],
            remediation=(
                "1. Add each parameter to the configuration change blocklist in "
                "multidb.ini on the system database.\n"
                "2. Verify: SELECT * FROM \"PUBLIC\".\"M_INIFILE_CONTENTS\" "
                "WHERE FILE_NAME = 'multidb.ini';\n"
                "3. Under RISE, multidb.ini is system-database configuration "
                "and SAP's to change — raise a service request."
            ),
            references=[
                "SAP HANA Security Checklists and Recommendations — "
                "Recommendations for Tenant Databases",
            ],
            affected_objects=[{"type": "parameter_name", "name": p,
                               "qualifier": "multidb.ini blocklist"}
                              for p, _cid in missing],
            scope="aggregate",
        )

    def check_hana_maintenance_status(self):
        """CRITICAL: the installed HANA revision is out of security maintenance.

        SAP Security Baseline requirement SECUPD-H, config store HDB_VERSION.
        """
        installed = None
        for row in (self.data.get("hana_version") or []):
            if not isinstance(row, dict):
                continue
            keys = {str(k).strip().upper(): v for k, v in row.items()}
            name = str(keys.get("NAME", keys.get("PARAMETER", ""))).strip().upper()
            value = str(keys.get("VALUE", keys.get("VERSION", ""))).strip()
            if value and (not name or name in ("VERSION", "HDB_VERSION")):
                installed = value
                break
        if not installed:
            return

        parts = []
        for chunk in installed.split("."):
            digits = "".join(c for c in chunk if c.isdigit())
            if not digits:
                break
            parts.append(int(digits))
        if len(parts) < 3:
            # A revision this cannot order must not be reported as old. Silence is
            # the correct answer; sap_hotnews.py takes the same position.
            return
        line = (parts[0], parts[1], parts[2])

        maintained = sorted(self.HANA_MAINTAINED_LINES)
        if line >= maintained[0]:
            return
        oldest = maintained[0]
        oldest_name = self.HANA_MAINTAINED_LINES[oldest]
        oldest_text = "%s (%d.%d.%03d)" % (oldest_name, oldest[0], oldest[1], oldest[2])

        self.finding(
            check_id="HANADB-VER-001",
            title="HANA %s is below every security-maintained revision line" % installed,
            severity=self.SEVERITY_CRITICAL,
            category=self.CATEGORY,
            description=(
                "The database reports revision %s, which is below %s, the oldest "
                "line SAP still issues security corrections for. An "
                "out-of-maintenance HANA does not receive the fixes published on "
                "Patch Day, so a vulnerability disclosed from now on stays open "
                "on this system and no note can be applied to close it. That is "
                "a different statement from a missing individual note: the notes "
                "checked elsewhere in this scan have fixes that exist and have "
                "not been applied, while this one says the delivery channel "
                "itself has stopped. Under RISE the database is operated by SAP, "
                "so an out-of-maintenance revision is normally evidence of a "
                "deferred upgrade to be scheduled with SAP rather than a "
                "misconfiguration the customer can correct alone — but it is "
                "the customer who carries the exposure in the meantime."
                % (installed, oldest_text)
            ),
            affected_items=[
                "installed revision: %s" % installed,
                "oldest maintained line: %s" % oldest_text,
            ],
            remediation=(
                "Plan an upgrade to a currently-maintained SPS line with SAP. "
                "Under RISE raise it against the operations contract: the "
                "revision is SAP's to move, and the customer's obligation is to "
                "agree the maintenance window and run the regression test. "
                "Confirm the target line against SAP's HANA maintenance strategy "
                "at the time of planning rather than against this check, which "
                "knows only that the installed line is below all of them. Until "
                "the upgrade lands, treat the compensating controls as the real "
                "protection: network exposure of the SQL and internal ports, the "
                "privilege review, and the audit policy."
            ),
            references=[
                "SAP Security Baseline — SECUPD-H (HANA maintenance status)",
                "SAP Note 2378962 — SAP HANA 2.0 revision and maintenance strategy",
                "SAP HANA Platform — Release and Maintenance Strategy",
            ],
            # The revision is a property, not a subject — the same reasoning
            # BTP-CC-008 records for the Cloud Connector version. Carrying it into
            # identity would retire this finding on an upgrade that is still out of
            # maintenance, resetting the age of an exposure that has not moved.
            scope="aggregate",
        )
