# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
HANA Database Security Auditor
================================
Audits the SAP HANA database layer that sits underneath S/4HANA — the
privileged-access, audit and parameter surface that the application-layer
modules do not cover. (Encryption-at-rest of the HANA data/log volumes is
handled separately by the Cryptographic Posture module.)

Covers:
  - Privileged / standard DB users (SYSTEM deactivation, password lifetime, dormancy)
  - System privileges and the PUBLIC role (least privilege, grantable options)
  - Analytic-privilege bypass (_SYS_BI_CP_ALL)
  - Powerful predefined roles
  - Database auditing (enabled, trail target, critical action coverage)
  - Security-relevant HANA parameters (password policy, error disclosure, SQL TLS)

Data sources — and which of these view names SAP has actually published.

Two of the five are confirmed against the SAP HANA Cloud, SAP HANA Database
Security Guide (QRC 2/2026). Three are this file's own working knowledge, read
as fact for as long as they have existed. They are probably right; nobody has
shown that they are, and a view name a customer cannot query is a support call.
So they are marked, exactly as the GRC module's are:

  - hana_db_users.csv           → USERS                  [verified: User Types;
                                  CREATOR, CREATE_PROVIDER_TYPE and
                                  CREATE_PROVIDER_NAME are named columns]
  - hana_granted_privileges.csv → GRANTED_PRIVILEGES     [verified: named as the
                                  view that reports the granting user]
  - hana_granted_roles.csv      → GRANTED_ROLES          [UNVERIFIED]
  - hana_parameters.csv         → M_INIFILE_CONTENTS     [UNVERIFIED — but the
                                  *sections* are confirmed: `password policy` in
                                  indexserver.ini, `ldap` in global.ini]
  - hana_audit_policies.csv     → AUDIT_POLICIES         [UNVERIFIED — auditing
                                  via audit policies is confirmed, the view that
                                  lists them is not]

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

    # Analytic (structured) privilege that disables all analytic-privilege row
    # filtering in modeled views — effectively unrestricted reporting-data access.
    CP_ALL = "_SYS_BI_CP_ALL"

    # Predefined roles that carry broad administrative capability.
    POWERFUL_ROLES = {
        "CONTENT_ADMIN", "MODELING", "MONITORING", "SAP_INTERNAL_HANA_SUPPORT",
        "AFL__SYS_AFL_AFLPAL_EXECUTE",
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
        self.check_auditing_enabled()
        self.check_audit_trail_target()
        self.check_audit_policy_coverage()
        self.check_password_policy()
        self.check_error_disclosure()
        self.check_sql_tls_enforced()
        self.check_log_mode()
        self.check_cross_database_access()
        self.check_debug_privileges()
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
        for grantee, gtype, priv, obj, _ in self._iter_priv_rows():
            gu = grantee.upper()
            if gu in ("PUBLIC",) or gu in self.TECHNICAL_USERS or gu.startswith("_SYS"):
                continue
            if gtype and gtype not in ("USER", ""):   # role grants handled elsewhere
                continue
            if priv in self.CRITICAL_SYSTEM_PRIVS:
                crit.append(f"{grantee} ← {priv}")
                # A grant is an edge: both ends become graph nodes, as in the
                # user -> profile modelling the identity tests use.
                self._add_obj(crit_objects, "hana_user", grantee)
                self._add_obj(crit_objects, "hana_privilege", priv)
            elif priv in self.HIGH_SYSTEM_PRIVS:
                high.append(f"{grantee} ← {priv}")
                self._add_obj(high_objects, "hana_user", grantee)
                self._add_obj(high_objects, "hana_privilege", priv)
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
                # Same rollup as HANADB-PRIV-002, one severity band down.
                scope="aggregate",
            )

    def check_grantable_privileges(self):
        """MEDIUM: privileges granted WITH ADMIN/GRANT OPTION enable sprawl."""
        if not self.data.get("hana_granted_privileges"):
            return
        offenders = []
        objects: List[Dict[str, Any]] = []
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
                # One finding over every debug grant found. Revoking DEBUG from one user
                # while another still holds ATTACH DEBUGGER must shrink this finding
                # rather than close it and open a fresh, zero-age one.
                scope="aggregate",
            )
