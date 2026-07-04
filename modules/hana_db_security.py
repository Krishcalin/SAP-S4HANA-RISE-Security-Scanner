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

Data sources:
  - hana_db_users.csv          → SYS.USERS export (user master)
  - hana_granted_privileges.csv → GRANTED_PRIVILEGES / EFFECTIVE_PRIVILEGE_GRANTEES
  - hana_granted_roles.csv     → GRANTED_ROLES export
  - hana_parameters.csv        → M_INIFILE_CONTENTS (global.ini / indexserver.ini …)
  - hana_audit_policies.csv    → AUDIT_POLICIES export

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
        return self.findings

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _truthy(value: Any) -> bool:
        return str(value).strip().lower() in ("true", "1", "yes", "on", "enabled", "x")

    @staticmethod
    def _falsy(value: Any) -> bool:
        return str(value).strip().lower() in ("false", "0", "no", "off", "disabled", "", "none")

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

    def _get_param(self, idx: dict, key: str, section: str = None):
        key = key.lower()
        if section:
            section = section.lower()
            for keytuple, v in idx.items():
                if isinstance(keytuple, tuple) and keytuple[1] == section and keytuple[2] == key:
                    return v
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
    def check_privileged_users(self):
        """CRITICAL: the SYSTEM superuser should be deactivated once named
        administrator accounts exist (CIS SAP HANA)."""
        users = self.data.get("hana_db_users")
        if not users:
            return
        for row in users:
            name = str(row.get("USER_NAME", row.get("USER", row.get("NAME", "")))).strip().upper()
            if name != "SYSTEM":
                continue
            deactivated = row.get("USER_DEACTIVATED", row.get("DEACTIVATED",
                          row.get("IS_DEACTIVATED", row.get("ACTIVE", ""))))
            # ACTIVE column is inverted vs DEACTIVATED
            is_active = (self._truthy(row.get("ACTIVE", "")) if "ACTIVE" in row
                         else self._falsy(deactivated))
            if is_active:
                self.finding(
                    check_id="HANADB-USER-001",
                    title="HANA SYSTEM superuser is still active",
                    severity=self.SEVERITY_CRITICAL,
                    category=self.CATEGORY,
                    description=(
                        "The built-in SYSTEM user is active. SYSTEM holds every system "
                        "privilege and bypasses the role model; it should be deactivated "
                        "after named administrator users are created, and used only for "
                        "break-glass recovery."
                    ),
                    affected_items=["SYSTEM — status: active"],
                    remediation=(
                        "Create named administrator users with only the privileges they "
                        "need, then deactivate SYSTEM: "
                        "ALTER USER SYSTEM DEACTIVATE USER NOW. "
                        "Re-activate only for documented emergencies."
                    ),
                    references=[
                        "CIS SAP HANA Benchmark — Deactivate SYSTEM user",
                        "SAP HANA Security Guide — The SYSTEM User",
                    ],
                )
            return

    def check_password_lifetime(self):
        """HIGH: non-technical DB users whose password lifetime check is disabled
        (password never expires)."""
        users = self.data.get("hana_db_users")
        if not users:
            return
        offenders = []
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
            )

    def check_dormant_users(self):
        """MEDIUM: active DB users with no successful connect in N days."""
        users = self.data.get("hana_db_users")
        if not users:
            return
        threshold = self.get_config("hana_dormant_days", 90)
        now = datetime.now()
        dormant = []
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
            elif parsed and (now - parsed).days >= threshold:
                dormant.append(f"{name} — last connect {(now - parsed).days}d ago ({last})")
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
        for grantee, gtype, priv, obj, _ in self._iter_priv_rows():
            if grantee.upper() != "PUBLIC":
                continue
            if priv in self.HIGH_SYSTEM_PRIVS or priv == self.CP_ALL or "ADMIN" in priv:
                label = f"PUBLIC ← {priv}" + (f" ON {obj}" if obj else "")
                offenders.append(label)
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
            )

    def check_system_privileges(self):
        """HIGH: broad system privileges granted directly to users."""
        if not self.data.get("hana_granted_privileges"):
            return
        crit, high = [], []
        for grantee, gtype, priv, obj, _ in self._iter_priv_rows():
            gu = grantee.upper()
            if gu in ("PUBLIC",) or gu in self.TECHNICAL_USERS or gu.startswith("_SYS"):
                continue
            if gtype and gtype not in ("USER", ""):   # role grants handled elsewhere
                continue
            if priv in self.CRITICAL_SYSTEM_PRIVS:
                crit.append(f"{grantee} ← {priv}")
            elif priv in self.HIGH_SYSTEM_PRIVS:
                high.append(f"{grantee} ← {priv}")
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
            )

    def check_grantable_privileges(self):
        """MEDIUM: privileges granted WITH ADMIN/GRANT OPTION enable sprawl."""
        if not self.data.get("hana_granted_privileges"):
            return
        offenders = []
        for grantee, gtype, priv, obj, grantable in self._iter_priv_rows():
            gu = grantee.upper()
            if gu in self.TECHNICAL_USERS or gu.startswith("_SYS"):
                continue
            if self._truthy(grantable) and (priv in self.HIGH_SYSTEM_PRIVS or "ADMIN" in priv):
                offenders.append(f"{grantee} ← {priv} (WITH ADMIN/GRANT OPTION)")
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
            )

    def check_analytic_privilege_bypass(self):
        """CRITICAL: _SYS_BI_CP_ALL disables analytic-privilege data filtering."""
        offenders = []
        for grantee, gtype, priv, obj, _ in self._iter_priv_rows():
            target = f"{priv} {obj}".upper()
            if self.CP_ALL in target or self.CP_ALL in grantee.upper():
                if grantee.upper() not in self.TECHNICAL_USERS:
                    offenders.append(f"{grantee} ← {self.CP_ALL}")
        for row in (self.data.get("hana_granted_roles") or []):
            grantee = str(row.get("GRANTEE", row.get("USER_NAME", ""))).strip()
            role = str(row.get("ROLE_NAME", row.get("ROLE", ""))).strip().upper()
            if self.CP_ALL in role and grantee.upper() not in self.TECHNICAL_USERS:
                offenders.append(f"{grantee} ← role {role}")
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
            )

    def check_powerful_roles(self):
        """HIGH: broadly powerful predefined roles granted to users."""
        roles = self.data.get("hana_granted_roles")
        if not roles:
            return
        offenders = []
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
            )

    def check_audit_trail_target(self):
        """HIGH: audit trail written to a tamperable CSV text file."""
        idx = self._param_index()
        if not idx:
            return
        offenders = []
        for key in ("default_audit_trail_type", "emergency_audit_trail_type"):
            val = self._get_param(idx, key, "auditing configuration")
            if val and "CSVTEXTFILE" in str(val).upper():
                offenders.append(f"{key} = {val}")
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
            )

    # ------------------------------------------------------------- parameters
    def check_password_policy(self):
        """HIGH: weak HANA password-policy parameters."""
        idx = self._param_index()
        if not idx:
            return
        section = "password policy"
        issues = []

        min_len = self._get_param(idx, "minimal_password_length", section)
        if min_len is not None:
            try:
                if int(str(min_len)) < 8:
                    issues.append(f"minimal_password_length = {min_len} (recommend ≥ 8)")
            except ValueError:
                pass

        force_first = self._get_param(idx, "force_first_password_change", section)
        if force_first is not None and self._falsy(force_first):
            issues.append("force_first_password_change = false (initial passwords not forced to change)")

        max_attempts = self._get_param(idx, "maximum_invalid_connect_attempts", section)
        if max_attempts is not None:
            try:
                if int(str(max_attempts)) > 6:
                    issues.append(f"maximum_invalid_connect_attempts = {max_attempts} (recommend ≤ 6)")
            except ValueError:
                pass

        lifetime = self._get_param(idx, "maximum_password_lifetime", section)
        if lifetime is not None:
            try:
                if int(str(lifetime)) > 365:
                    issues.append(f"maximum_password_lifetime = {lifetime}d (recommend ≤ 365)")
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
            )
