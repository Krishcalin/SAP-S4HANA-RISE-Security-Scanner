"""
User & Authorization Auditor
=============================
Checks for:
  - SAP* and DDIC default user status
  - Users with SAP_ALL / SAP_NEW profiles
  - Dormant / never-logged-in accounts
  - Locked vs unlocked user ratios
  - Dialog users with critical authorizations
  - Service/system users with dialog logon type
  - Users with S_DEVELOP (debug/replace) in production
  - Excessive role assignments per user
"""

from typing import Dict, List, Any
from datetime import datetime, timedelta
from modules.base_auditor import BaseAuditor


class UserAuthAuditor(BaseAuditor):

    # Well-known default SAP users that should be locked/secured
    DEFAULT_USERS = {
        "SAP*": "Default superuser — must be locked in all clients",
        "DDIC": "Data dictionary user — lock in production, restrict to admin",
        "SAPCPIC": "CPI-C communication user — lock if unused",
        "EARLYWATCH": "EarlyWatch monitoring — lock if not actively used",
        "TMSADM": "Transport management — verify authorization scope",
    }

    # Profiles considered critical / overprivileged
    CRITICAL_PROFILES = ["SAP_ALL", "SAP_NEW", "S_A.SYSTEM"]

    # Authorization objects indicating high-privilege access
    CRITICAL_AUTH_OBJECTS = {
        "S_DEVELOP":    "Debug and code replacement in production",
        "S_ADMI_FCD":   "Admin functions (PADM = all admin privileges)",
        "S_BTCH_ADM":   "Batch admin across all clients",
        "S_RZL_ADM":    "System administration",
        "S_USER_GRP":   "User group admin with ACTVT=* (full user management)",
        "S_TABU_DIS":   "Table maintenance with AUTH='&NC&' (bypasses auth groups)",
    }

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_default_users()
        self.check_critical_profiles()
        self.check_dormant_accounts()
        self.check_user_type_mismatch()
        self.check_excessive_roles()
        self.check_critical_auth_objects()
        self.check_never_logged_in()
        self.check_password_not_changed()
        return self.findings

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _objects(pairs) -> List[Dict[str, Any]]:
        """Build de-duplicated affected-object dicts from (type, name) pairs.

        De-duplication keeps one graph node per real object: the SAP_ALL profile named
        in forty offending assignments is one node, not forty. A pair whose name is
        empty is dropped rather than given an invented placeholder — an export row with
        no BNAME names no user, and fabricating one would put a fictional node in the
        graph and, worse, let two nameless rows share an identity.
        """
        out: List[Dict[str, Any]] = []
        seen = set()
        for obj_type, name in pairs:
            n = "" if name is None else str(name).strip()
            if not n:
                continue
            key = (obj_type, n.upper())
            if key in seen:
                continue
            seen.add(key)
            out.append({"type": obj_type, "name": n})
        return out

    def check_default_users(self):
        """Check if default SAP users are properly secured."""
        users = self.data.get("users")
        if not users:
            return

        for row in users:
            uname = row.get("BNAME", row.get("USERNAME", "")).upper()
            lock_status = row.get("UFLAG", row.get("LOCK_STATUS", "0"))
            user_type = row.get("USTYP", row.get("USER_TYPE", ""))

            if uname in self.DEFAULT_USERS:
                # UFLAG = 0 means unlocked; anything > 0 generally means locked
                is_unlocked = str(lock_status) in ("0", "")
                if is_unlocked:
                    self.finding(
                        check_id="USR-001",
                        title=f"Default user {uname} is unlocked",
                        severity=self.SEVERITY_CRITICAL if uname in ("SAP*", "DDIC") else self.SEVERITY_HIGH,
                        category="User & Authorization",
                        description=(
                            f"The default SAP user '{uname}' is unlocked. "
                            f"{self.DEFAULT_USERS[uname]}. "
                            "Attackers routinely target default users with well-known passwords."
                        ),
                        affected_items=[uname],
                        # One finding per unlocked default user, so the user IS the
                        # defect and must sit in identity — otherwise the four USR-001
                        # rows collapse into one and three defects vanish from the
                        # report (see server/identity.py, OBJECT findings).
                        affected_objects=[{"type": "user", "name": uname}],
                        scope="object",
                        remediation=(
                            f"Lock user {uname} via SU01 or set UFLAG > 0. "
                            "Change password to a strong random value. "
                            "For SAP*, consider setting login/no_automatic_user_sapstar = 1."
                        ),
                        references=[
                            "SAP Note 1414256 — Secure default users",
                            "CIS SAP Benchmark Section 2.1"
                        ],
                    )

    def check_critical_profiles(self):
        """Check for users assigned SAP_ALL, SAP_NEW, S_A.SYSTEM."""
        profiles = self.data.get("profiles")
        if not profiles:
            # Fall back to checking in user_roles or users
            users = self.data.get("users") or []
            for row in users:
                prof = row.get("PROFILE", row.get("PROFILES", "")).upper()
                for crit in self.CRITICAL_PROFILES:
                    if crit in prof:
                        uname = row.get("BNAME", row.get("USERNAME", ""))
                        self.finding(
                            check_id="USR-002",
                            title=f"User {uname} has critical profile {crit}",
                            severity=self.SEVERITY_CRITICAL,
                            category="User & Authorization",
                            description=(
                                f"User '{uname}' is assigned the '{crit}' profile, "
                                "granting unrestricted system access. This violates "
                                "least-privilege and is a critical audit finding."
                            ),
                            affected_items=[f"{uname} → {crit}"],
                            # One finding per offending user-profile assignment, so
                            # both halves of the assignment belong to its identity:
                            # revoking SAP_ALL from one user must not touch another
                            # user's finding.
                            affected_objects=self._objects(
                                [("user", uname), ("profile", crit)]),
                            scope="object",
                            remediation=(
                                f"Remove {crit} from user {uname} via SU01/SU02. "
                                "Replace with role-based authorizations scoped to actual needs. "
                                "Document any temporary emergency assignments with expiry."
                            ),
                            references=[
                                "SAP Note 1698789 — Removal of SAP_ALL",
                                "CIS SAP Benchmark Section 2.3"
                            ],
                        )
            return

        affected = []
        object_pairs = []
        for row in profiles:
            profile = row.get("PROFILE", row.get("AGR_NAME", "")).upper()
            uname = row.get("BNAME", row.get("USERNAME", ""))
            for crit in self.CRITICAL_PROFILES:
                if crit == profile or crit in profile:
                    affected.append(f"{uname} → {profile}")
                    object_pairs.extend((("user", uname), ("profile", profile)))

        if affected:
            self.finding(
                check_id="USR-002",
                title=f"Users assigned critical profiles ({', '.join(self.CRITICAL_PROFILES)})",
                severity=self.SEVERITY_CRITICAL,
                category="User & Authorization",
                description=(
                    f"{len(affected)} user-profile assignment(s) found with critical profiles "
                    "that grant unrestricted system access."
                ),
                affected_items=affected,
                # This path rolls EVERY critical-profile assignment into one finding,
                # so its identity must exclude the membership: stripping SAP_ALL from
                # one of twelve users would otherwise retire this finding and raise a
                # brand-new one, resetting its age while eleven users stay exposed.
                # The users and profiles still ride along as graph nodes.
                affected_objects=self._objects(object_pairs),
                scope="aggregate",
                remediation=(
                    "Remove all SAP_ALL/SAP_NEW/S_A.SYSTEM assignments. "
                    "Implement proper role-based access control (RBAC). "
                    "Use emergency/firefighter procedures (e.g., SAP GRC) for break-glass scenarios."
                ),
                references=[
                    "SAP Note 1698789",
                    "CIS SAP Benchmark Section 2.3",
                ],
            )

    def check_dormant_accounts(self):
        """Flag accounts with no login in 90+ days."""
        users = self.data.get("users")
        if not users:
            return

        dormant_days = self.get_config("dormant_threshold_days", 90)
        dormant = []
        dormant_objs = []

        for row in users:
            uname = row.get("BNAME", row.get("USERNAME", ""))
            last_logon = row.get("TRDAT", row.get("LAST_LOGON", ""))
            lock_status = row.get("UFLAG", row.get("LOCK_STATUS", "0"))

            if str(lock_status) not in ("0", ""):
                continue  # already locked, skip

            if last_logon:
                try:
                    # Try common SAP date formats
                    for fmt in ("%Y%m%d", "%Y-%m-%d", "%d.%m.%Y", "%m/%d/%Y"):
                        try:
                            logon_date = datetime.strptime(last_logon, fmt)
                            break
                        except ValueError:
                            continue
                    else:
                        continue

                    days_inactive = (datetime.now() - logon_date).days
                    if days_inactive > dormant_days:
                        dormant.append(f"{uname} (last logon: {last_logon}, {days_inactive}d ago)")
                        dormant_objs.append(("user", uname))
                except Exception:
                    continue

        if dormant:
            self.finding(
                check_id="USR-003",
                title=f"Dormant accounts ({dormant_days}+ days inactive)",
                severity=self.SEVERITY_MEDIUM,
                category="User & Authorization",
                description=(
                    f"{len(dormant)} active (unlocked) user account(s) have not logged in "
                    f"for over {dormant_days} days. Dormant accounts increase attack surface."
                ),
                affected_items=dormant,
                # THE aggregate case from server/identity.py: "23 dormant accounts" is
                # about the check, not about any one account. Locking one dormant user
                # must shrink the list, not retire this finding and raise a fresh one
                # with its age reset to zero.
                affected_objects=self._objects(dormant_objs),
                scope="aggregate",
                remediation=(
                    "Review and lock dormant accounts. Implement automated dormant "
                    "account detection using SAP GRC or scheduled ABAP report RSUSR200. "
                    "Establish a policy for periodic user access reviews."
                ),
                references=["CIS SAP Benchmark Section 2.5"],
            )

    def check_user_type_mismatch(self):
        """Flag service/system accounts with dialog logon type."""
        users = self.data.get("users")
        if not users:
            return

        mismatched = []
        mismatched_objs = []
        for row in users:
            uname = row.get("BNAME", row.get("USERNAME", ""))
            user_type = row.get("USTYP", row.get("USER_TYPE", ""))

            # In SAP: A=Dialog, B=System, C=Communication, L=Reference, S=Service
            # Service/system accounts should not have type A (dialog)
            # Check naming conventions suggesting service accounts
            is_service_name = any(
                prefix in uname.upper()
                for prefix in ("SVC_", "RFC_", "BATCH_", "BG_", "INT_", "API_", "TECH_")
            )
            if is_service_name and str(user_type).upper() in ("A", "DIALOG", ""):
                mismatched.append(f"{uname} (type={user_type or 'Dialog'})")
                mismatched_objs.append(("user", uname))

        if mismatched:
            self.finding(
                check_id="USR-004",
                title="Service/technical accounts with dialog logon type",
                severity=self.SEVERITY_HIGH,
                category="User & Authorization",
                description=(
                    f"{len(mismatched)} account(s) appear to be service/technical users "
                    "but have dialog (interactive) logon capability. This allows "
                    "interactive logon with service credentials."
                ),
                affected_items=mismatched,
                # One finding rolling up every mis-typed service account, so identity
                # excludes the membership — converting one account to type S must not
                # restart the clock on the ones still wrong.
                affected_objects=self._objects(mismatched_objs),
                scope="aggregate",
                remediation=(
                    "Change user type to B (System), C (Communication), or S (Service) "
                    "as appropriate via SU01. Service accounts should never allow "
                    "dialog logon in production."
                ),
                references=["SAP Note 2175909"],
            )

    def check_excessive_roles(self):
        """Flag users with an excessive number of role assignments."""
        user_roles = self.data.get("user_roles")
        if not user_roles:
            return

        max_roles = self.get_config("max_roles_per_user", 30)
        role_counts: Dict[str, int] = {}

        for row in user_roles:
            uname = row.get("UNAME", row.get("BNAME", row.get("USERNAME", "")))
            role_counts[uname] = role_counts.get(uname, 0) + 1

        excessive = [
            f"{uname} ({count} roles)"
            for uname, count in role_counts.items()
            if count > max_roles
        ]

        if excessive:
            self.finding(
                check_id="USR-005",
                title=f"Users with excessive role assignments (>{max_roles})",
                severity=self.SEVERITY_MEDIUM,
                category="User & Authorization",
                description=(
                    f"{len(excessive)} user(s) have more than {max_roles} roles assigned. "
                    "Excessive roles often indicate role explosion or inadequate RBAC design."
                ),
                affected_items=excessive,
                # One finding summarising every over-provisioned user. The role COUNT is
                # deliberately not a qualifier: it moves every time somebody gains or
                # loses a role, which would churn the graph node without the defect
                # changing.
                affected_objects=self._objects(
                    ("user", uname) for uname, count in role_counts.items()
                    if count > max_roles
                ),
                scope="aggregate",
                remediation=(
                    "Review role assignments for consolidation opportunities. "
                    "Use composite/derived roles to reduce direct assignments. "
                    "Conduct a role mining exercise."
                ),
                references=["CIS SAP Benchmark Section 2.4"],
            )

    def check_critical_auth_objects(self):
        """Check for users with dangerous authorization object values."""
        auth_objects = self.data.get("auth_objects")
        if not auth_objects:
            return

        findings_map = {}
        users_map = {}
        for row in auth_objects:
            obj = row.get("OBJECT", row.get("AUTH_OBJECT", "")).upper()
            uname = row.get("UNAME", row.get("BNAME", row.get("USERNAME", "")))
            field_val = row.get("VALUE", row.get("AUTH_VALUE", ""))

            if obj in self.CRITICAL_AUTH_OBJECTS:
                # Flag wildcard or full-access values
                if field_val.strip() in ("*", "&NC&"):
                    key = obj
                    if key not in findings_map:
                        findings_map[key] = []
                        users_map[key] = []
                    findings_map[key].append(
                        f"{uname} → {obj} = {field_val}"
                    )
                    users_map[key].append(uname)

        for obj, affected in findings_map.items():
            self.finding(
                check_id="USR-006",
                title=f"Users with wildcard access on {obj}",
                severity=self.SEVERITY_HIGH,
                category="User & Authorization",
                description=(
                    f"{len(affected)} user(s) have unrestricted (wildcard) values for "
                    f"authorization object {obj}: {self.CRITICAL_AUTH_OBJECTS[obj]}."
                ),
                affected_items=affected,
                # One finding PER authorization object, naming every user that holds it
                # wide open: the defect is "S_DEVELOP is granted with a wildcard here",
                # and the user list is context that moves as people join and leave. So
                # the auth object is the SUBJECT and carries identity, while the users
                # ride along as members and as graph nodes. No qualifier on the subject:
                # this finding rolls up both offending values ("*" and "&NC&") for the
                # object, so pinning one of them would misdescribe it.
                subject=[{"type": "auth_object", "name": obj}],
                affected_objects=(
                    [{"type": "auth_object", "name": obj}]
                    + self._objects(("user", u) for u in users_map.get(obj, []))
                ),
                scope="object",
                remediation=(
                    f"Restrict {obj} field values to specific required entries. "
                    "Remove wildcard (*) authorizations and replace with "
                    "least-privilege values."
                ),
                references=["SAP Note 2077067", "CIS SAP Benchmark Section 3"],
            )

    def check_never_logged_in(self):
        """Flag active accounts that have never logged in."""
        users = self.data.get("users")
        if not users:
            return

        never_logged = []
        never_logged_objs = []
        for row in users:
            uname = row.get("BNAME", row.get("USERNAME", ""))
            last_logon = row.get("TRDAT", row.get("LAST_LOGON", ""))
            lock_status = row.get("UFLAG", row.get("LOCK_STATUS", "0"))
            created = row.get("ERDAT", row.get("CREATED_DATE", ""))

            is_unlocked = str(lock_status) in ("0", "")
            if is_unlocked and not last_logon:
                never_logged.append(f"{uname} (created: {created or 'unknown'})")
                never_logged_objs.append(("user", uname))

        if never_logged:
            self.finding(
                check_id="USR-007",
                title="Active accounts that have never logged in",
                severity=self.SEVERITY_LOW,
                category="User & Authorization",
                description=(
                    f"{len(never_logged)} unlocked account(s) have no recorded logon. "
                    "These may be orphaned provisioning artifacts or pre-staged accounts."
                ),
                affected_items=never_logged,
                # Same shape as USR-003: N never-used accounts rolled into ONE finding,
                # so identity stays on the check and deleting one account does not
                # re-raise the finding for the rest.
                affected_objects=self._objects(never_logged_objs),
                scope="aggregate",
                remediation=(
                    "Verify account necessity with business owners. "
                    "Lock or delete unused accounts."
                ),
                references=["CIS SAP Benchmark Section 2.5"],
            )

    def check_password_not_changed(self):
        """Flag users who haven't changed password in 180+ days."""
        users = self.data.get("users")
        if not users:
            return

        max_age = self.get_config("max_password_age_days", 180)
        stale = []
        stale_objs = []

        for row in users:
            uname = row.get("BNAME", row.get("USERNAME", ""))
            pw_date = row.get("PWDCHGDATE", row.get("PASSWORD_CHANGE_DATE", ""))
            lock_status = row.get("UFLAG", row.get("LOCK_STATUS", "0"))
            user_type = row.get("USTYP", row.get("USER_TYPE", "A"))

            if str(lock_status) not in ("0", ""):
                continue
            # Only check dialog users
            if str(user_type).upper() not in ("A", "DIALOG", ""):
                continue

            if pw_date:
                for fmt in ("%Y%m%d", "%Y-%m-%d", "%d.%m.%Y", "%m/%d/%Y"):
                    try:
                        pw_changed = datetime.strptime(pw_date, fmt)
                        days_old = (datetime.now() - pw_changed).days
                        if days_old > max_age:
                            stale.append(f"{uname} (password age: {days_old}d)")
                            stale_objs.append(("user", uname))
                        break
                    except ValueError:
                        continue

        if stale:
            self.finding(
                check_id="USR-008",
                title=f"Dialog users with stale passwords (>{max_age} days)",
                severity=self.SEVERITY_MEDIUM,
                category="User & Authorization",
                description=(
                    f"{len(stale)} dialog user(s) have not changed their password in "
                    f"over {max_age} days."
                ),
                affected_items=stale,
                # One finding covering every dialog user with an over-age password. The
                # age in days is deliberately not a qualifier — it advances every single
                # run, so it would re-key the node daily.
                affected_objects=self._objects(stale_objs),
                scope="aggregate",
                remediation=(
                    "Enforce password rotation via profile parameter "
                    "login/password_max_idle_initial and login/password_expiration_time. "
                    "Consider SSO/certificate-based auth to reduce password dependency."
                ),
                references=["SAP Note 1731549", "CIS SAP Benchmark Section 2.8"],
            )
