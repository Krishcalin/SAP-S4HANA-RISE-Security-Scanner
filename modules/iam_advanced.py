"""
Advanced Identity & Access Management Auditor
===============================================
Extended IAM checks beyond the base user/auth module:

  - Segregation of Duties (SoD) conflict detection
  - Emergency/firefighter access usage analysis
  - Role expiry enforcement validation
  - Cross-system identity consistency (S/4 ↔ BTP)
  - Privileged access review compliance
  - Role design quality (single roles vs composite)
  - Orphaned role assignments (roles without valid owners)
  - User group segmentation violations
  - Reference user misuse
  - Privilege escalation paths (indirect role chains)

Data sources:
  - sod_ruleset.json     → SoD conflict rule definitions
  - firefighter_log.csv  → Emergency access / firefighter usage log (GRC SPM)
  - role_expiry.csv      → Role assignments with validity dates (AGR_USERS)
  - btp_users.json       → BTP subaccount user/role collection export
  - role_details.csv     → Role metadata (owner, description, type)
  - access_reviews.csv   → Periodic access review completion records
  - user_groups.csv      → User group assignments (USGRP from USR02)
"""

from typing import Dict, List, Any, Set, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
from modules.base_auditor import BaseAuditor


class AdvancedIamAuditor(BaseAuditor):

    # ── Default SoD conflict rules ──────────────────────────────────
    # Each rule defines two sets of t-codes/auth objects that should
    # never be assigned to the same user simultaneously.
    # Users can override these via sod_ruleset.json.
    DEFAULT_SOD_RULES = [
        {
            "rule_id": "SOD-FIN-001",
            "name": "Vendor Master ↔ Payment Processing",
            "severity": "CRITICAL",
            "side_a": {
                "description": "Create/Modify Vendor Master",
                "tcodes": ["FK01", "FK02", "XK01", "XK02", "BP"],
                "auth_objects": ["F_LFA1_BUK"],
            },
            "side_b": {
                "description": "Process Vendor Payments",
                "tcodes": ["F110", "F-53", "F-58", "FBZP"],
                "auth_objects": ["F_BKPF_BUP"],
            },
        },
        {
            "rule_id": "SOD-FIN-002",
            "name": "Purchase Order ↔ Goods Receipt",
            "severity": "HIGH",
            "side_a": {
                "description": "Create/Release Purchase Orders",
                "tcodes": ["ME21N", "ME22N", "ME28", "ME29N"],
                "auth_objects": ["M_BEST_BSA"],
            },
            "side_b": {
                "description": "Post Goods Receipt",
                "tcodes": ["MIGO", "MB01", "MB0A"],
                "auth_objects": ["M_MSEG_BWA"],
            },
        },
        {
            "rule_id": "SOD-FIN-003",
            "name": "Journal Entry ↔ GL Account Master",
            "severity": "HIGH",
            "side_a": {
                "description": "Post Journal Entries",
                "tcodes": ["FB01", "FB50", "F-02", "BAPI_ACC_DOCUMENT_POST"],
                "auth_objects": ["F_BKPF_BUK"],
            },
            "side_b": {
                "description": "Maintain GL Account Master",
                "tcodes": ["FS00", "FSP0", "FSS0", "OB_GLACC01"],
                "auth_objects": ["F_SKA1_BUK"],
            },
        },
        {
            "rule_id": "SOD-FIN-004",
            "name": "Customer Master ↔ Sales Order / Billing",
            "severity": "HIGH",
            "side_a": {
                "description": "Create/Modify Customer Master",
                "tcodes": ["FD01", "FD02", "XD01", "XD02", "BP"],
                "auth_objects": ["F_KNA1_BUK"],
            },
            "side_b": {
                "description": "Create Sales Orders / Billing",
                "tcodes": ["VA01", "VA02", "VF01", "VF02"],
                "auth_objects": ["V_VBAK_AAT"],
            },
        },
        {
            "rule_id": "SOD-HR-001",
            "name": "HR Master Data ↔ Payroll Execution",
            "severity": "CRITICAL",
            "side_a": {
                "description": "Maintain HR Master Data",
                "tcodes": ["PA20", "PA30", "PA40"],
                "auth_objects": ["P_ORGIN"],
            },
            "side_b": {
                "description": "Execute Payroll",
                "tcodes": ["PC00_M99_RUN", "PC00_M10_CALC", "PU03"],
                "auth_objects": ["P_PYEVRUN"],
            },
        },
        {
            "rule_id": "SOD-SEC-001",
            "name": "User Administration ↔ Role Administration",
            "severity": "CRITICAL",
            "side_a": {
                "description": "User Account Management",
                "tcodes": ["SU01", "SU01D", "SU10"],
                "auth_objects": ["S_USER_GRP"],
            },
            "side_b": {
                "description": "Role/Profile Administration",
                "tcodes": ["PFCG", "SU02", "SU03"],
                "auth_objects": ["S_USER_AGR"],
            },
        },
        {
            "rule_id": "SOD-BASIS-001",
            "name": "Transport Management ↔ Development",
            "severity": "HIGH",
            "side_a": {
                "description": "Release/Import Transports",
                "tcodes": ["STMS", "SE09", "SE10"],
                "auth_objects": ["S_CTS_ADMI"],
            },
            "side_b": {
                "description": "ABAP Development",
                "tcodes": ["SE38", "SE80", "SE24", "SE37"],
                "auth_objects": ["S_DEVELOP"],
            },
        },
    ]

    # ── Firefighter / emergency access thresholds ───────────────────
    FF_MAX_DURATION_HOURS = 4
    FF_MAX_SESSIONS_PER_MONTH = 5
    FF_REQUIRE_REASON = True

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_sod_conflicts()
        self.check_firefighter_usage()
        self.check_role_expiry()
        self.check_cross_system_identity()
        self.check_access_review_compliance()
        self.check_role_design_quality()
        self.check_orphaned_roles()
        self.check_user_group_segmentation()
        self.check_reference_user_misuse()
        self.check_privilege_escalation_paths()
        return self.findings

    # ════════════════════════════════════════════════════════════════
    #  Affected-object construction
    # ════════════════════════════════════════════════════════════════

    @staticmethod
    def _objects(pairs) -> List[Dict[str, Any]]:
        """Build de-duplicated affected-object dicts from (type, name) pairs.

        De-duplication keeps one graph node per real object: a role named in forty
        offending assignments is one node with one edge set, not forty. A pair whose
        name is empty is dropped rather than given an invented placeholder — an export
        row with no UNAME names no user, and fabricating one would both put a fictional
        node in the graph and let two nameless rows share an identity.
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

    @classmethod
    def _row_objects(cls, rows) -> List[Dict[str, Any]]:
        """`_objects` over rows that each contribute several pairs.

        Checks that cap their display list (``affected_items=x[:50]``) slice the SAME
        rows here, so the structured objects describe exactly the evidence the report
        shows rather than a silently different subset.
        """
        return cls._objects(pair for row in rows for pair in row)

    # ════════════════════════════════════════════════════════════════
    #  SOD-*: Segregation of Duties Conflict Detection
    # ════════════════════════════════════════════════════════════════

    def _defer_to_ara(self) -> bool:
        """Should this coarse SoD check stand down in favour of the 'ara' module?

        The Access Risk Analysis module performs PERMISSION-level SoD from the
        AGR_1251 export (`role_auth_values.csv`) — object/field/activity precision
        that suppresses the display-only false positives this transaction-level
        check cannot avoid. Where both could speak, the deeper one should.

        TWO THINGS THIS GETS RIGHT THAT THE ORIGINAL DID NOT
        -----------------------------------------------------
        1. **Deferring on data presence alone was wrong.** `role_auth_values.csv`
           being loaded does not mean `ara` is RUNNING. `--modules iam` supplies
           exactly that data and never runs `ara`, so this check stood down in
           favour of a module that was not there and the run produced no SoD
           findings whatsoever. Now it only defers when `ara` is genuinely in the
           run; when the caller does not say, it keeps the historical behaviour
           rather than guessing.

        2. **A silent stand-down is indistinguishable from a clean bill of
           health.** Whenever this check does defer it now says so, as an INFO
           finding, so "no SoD findings here" can never be mistaken for "no SoD
           conflicts". That is the same discipline as the coverage manifest:
           absence must be stated, not implied.
        """
        if not self.data.get("role_auth_values"):
            return False                    # nothing deeper is possible; run.

        ara_running = self.module_is_running("ara")
        if ara_running is False:
            return False                    # ara was excluded; we are the only SoD.

        self.finding(
            check_id="IAM-SOD-DEFERRED",
            title="Transaction-level SoD deferred to permission-level analysis",
            severity=self.SEVERITY_INFO,
            category="Advanced IAM",
            description=(
                "Transaction-level Segregation of Duties analysis did not run here "
                "because the AGR_1251 authorization export (role_auth_values) is "
                "available and the Access Risk Analysis module performs the same "
                "analysis at permission level — matching on authorization object, "
                "field and activity rather than transaction code alone. That is "
                "strictly more precise and does not raise the display-only false "
                "positives this coarser check produces. "
                "SoD results for this run are the ARA-* findings."
            ),
            affected_items=["Advanced IAM SoD rules (IAM-SOD-*)"],
            remediation=(
                "No action. This records why one module is quiet so that an empty "
                "IAM-SOD-* result is not read as an absence of SoD conflicts. To "
                "run the coarser transaction-level check anyway, exclude the 'ara' "
                "module or omit the role_auth_values export."
            ),
            references=["SAP Security Baseline — Segregation of Duties"],
            scope="aggregate",
        )
        return True

    def check_sod_conflicts(self):
        """
        Detect SoD conflicts by checking if any user has t-codes or
        auth objects from both sides of a conflict rule.
        
        Accepts data from:
          - user_roles.csv (AGR_USERS: UNAME, AGR_NAME)
          - role_tcodes.csv (AGR_1251 mapping: AGR_NAME, TCODE or AUTH_OBJECT)
          - OR sod_matrix.csv (pre-computed: USERNAME, TCODE list)
          - OR sod_ruleset.json (custom rules overriding defaults)
        """
        if self._defer_to_ara():
            return

        # Load custom SoD rules if provided
        sod_ruleset = self.data.get("sod_ruleset")
        rules = sod_ruleset if isinstance(sod_ruleset, list) else self.DEFAULT_SOD_RULES

        # Strategy 1: Pre-computed SoD matrix (simplest for offline)
        sod_matrix = self.data.get("sod_matrix")
        if sod_matrix:
            self._check_sod_from_matrix(sod_matrix, rules)
            return

        # Strategy 2: Build user → tcode mapping from role assignments + role tcodes
        user_roles = self.data.get("user_roles")
        role_tcodes = self.data.get("role_tcodes")

        if user_roles and role_tcodes:
            self._check_sod_from_role_resolution(user_roles, role_tcodes, rules)
            return

        # Strategy 3: Use user_roles with role-name-based heuristic matching
        if user_roles:
            self._check_sod_from_role_names(user_roles, rules)
            return

        # No data available for SoD checking
        self.finding(
            check_id="IAM-SOD-000",
            title="Insufficient data for SoD conflict analysis",
            severity=self.SEVERITY_HIGH,
            category="Identity & Access Management",
            description=(
                "No SoD matrix, role-tcode mapping, or role assignment data was found. "
                "Cannot perform Segregation of Duties analysis. This is a critical "
                "audit gap — SoD violations are among the most exploited internal control weaknesses."
            ),
            # A missing-export finding names nothing: the defect is that no user, role
            # or t-code data reached the scanner at all. There is no object to point at,
            # so identity is (system, client, check) and no affected_objects are passed
            # — inventing one would fabricate a node that is not in any export.
            scope="aggregate",
            remediation=(
                "Export one of: (1) sod_matrix.csv with USERNAME, TCODES columns "
                "(from SUIM or GRC ARA), (2) user_roles.csv (AGR_USERS) + role_tcodes.csv "
                "(AGR_1251), or (3) Provide a pre-analyzed sod_ruleset.json from SAP GRC."
            ),
            references=["SAP GRC Access Risk Analysis", "ISACA ITGC — Segregation of Duties"],
        )

    def _check_sod_from_matrix(self, matrix: List[Dict], rules: List[Dict]):
        """Check SoD from a pre-computed user→tcode matrix."""
        for rule in rules:
            rule_id = rule["rule_id"]
            side_a_tcodes = set(t.upper() for t in rule["side_a"].get("tcodes", []))
            side_b_tcodes = set(t.upper() for t in rule["side_b"].get("tcodes", []))
            conflicts = []
            conflict_objs = []

            for row in matrix:
                user = row.get("USERNAME", row.get("BNAME", row.get("UNAME", "")))
                tcodes_raw = row.get("TCODES", row.get("TCODE_LIST", ""))
                user_tcodes = set(
                    t.strip().upper()
                    for t in tcodes_raw.replace(";", ",").split(",")
                    if t.strip()
                )

                has_a = user_tcodes & side_a_tcodes
                has_b = user_tcodes & side_b_tcodes

                if has_a and has_b:
                    conflicts.append(
                        f"{user} — [{rule['side_a']['description']}]: "
                        f"{', '.join(sorted(has_a))} ↔ "
                        f"[{rule['side_b']['description']}]: "
                        f"{', '.join(sorted(has_b))}"
                    )
                    # The conflicted USER is the offender; the t-codes are the two
                    # sides they actually hold, taken from the intersection with the
                    # export rather than from the rule definition.
                    conflict_objs.append(
                        [("user", user)]
                        + [("tcode", t) for t in sorted(has_a | has_b)]
                    )

            if conflicts:
                self.finding(
                    check_id=f"IAM-{rule_id}",
                    title=f"SoD Conflict: {rule['name']}",
                    severity=rule.get("severity", self.SEVERITY_HIGH),
                    category="Identity & Access Management",
                    description=(
                        f"{len(conflicts)} user(s) have access to both sides of this "
                        f"SoD conflict: '{rule['side_a']['description']}' AND "
                        f"'{rule['side_b']['description']}'. This violates separation "
                        "of duties and creates fraud/error risk."
                    ),
                    affected_items=conflicts,
                    # One finding per SoD RULE, rolling up every user that trips it, so
                    # identity must exclude the membership: remediating the first of
                    # eleven conflicted users would otherwise retire this finding and
                    # raise a new one with its age reset while ten conflicts remain.
                    # The users and the t-codes they hold still ride along as nodes.
                    affected_objects=self._row_objects(conflict_objs),
                    scope="aggregate",
                    remediation=(
                        f"Remove one side of the conflict for each affected user. "
                        f"If business requires both, implement mitigating controls: "
                        f"dual approval workflows, periodic reconciliation, or "
                        f"transaction-level monitoring via GRC Process Control."
                    ),
                    references=[
                        "SAP GRC Access Risk Analysis",
                        "ISACA COBIT — DSS05.04 Manage Identity and Logical Access",
                    ],
                )

    def _check_sod_from_role_resolution(self, user_roles: List[Dict],
                                         role_tcodes: List[Dict],
                                         rules: List[Dict]):
        """Resolve role→tcode mapping then check SoD."""
        # Build role → tcode set
        role_tcode_map: Dict[str, Set[str]] = defaultdict(set)
        for row in role_tcodes:
            role = row.get("AGR_NAME", row.get("ROLE", row.get("ROLE_NAME", ""))).upper()
            tcode = row.get("TCODE", row.get("LOW", row.get("OBJECT_VALUE", ""))).upper()
            auth_obj = row.get("AUTH_OBJECT", row.get("OBJECT", "")).upper()
            if tcode:
                role_tcode_map[role].add(tcode)
            if auth_obj:
                role_tcode_map[role].add(f"OBJ:{auth_obj}")

        # Build user → tcode set
        user_tcode_map: Dict[str, Set[str]] = defaultdict(set)
        for row in user_roles:
            user = row.get("UNAME", row.get("BNAME", row.get("USERNAME", ""))).upper()
            role = row.get("AGR_NAME", row.get("ROLE", row.get("ROLE_NAME", ""))).upper()
            user_tcode_map[user].update(role_tcode_map.get(role, set()))

        # Build synthetic matrix and check
        matrix = [
            {"USERNAME": user, "TCODES": ",".join(sorted(tcodes))}
            for user, tcodes in user_tcode_map.items()
        ]
        self._check_sod_from_matrix(matrix, rules)

    def _check_sod_from_role_names(self, user_roles: List[Dict], rules: List[Dict]):
        """
        Heuristic SoD check when we only have role names (no tcode resolution).
        Looks for role naming patterns that suggest conflicting access.
        """
        # Build user → role set
        user_role_map: Dict[str, Set[str]] = defaultdict(set)
        for row in user_roles:
            user = row.get("UNAME", row.get("BNAME", row.get("USERNAME", ""))).upper()
            role = row.get("AGR_NAME", row.get("ROLE", row.get("ROLE_NAME", ""))).upper()
            user_role_map[user].add(role)

        # Heuristic role-name conflict patterns
        heuristic_rules = [
            {
                "rule_id": "SOD-HEUR-001",
                "name": "Vendor Maintenance ↔ Payment Roles (heuristic)",
                "severity": "HIGH",
                "side_a_patterns": ["VENDOR", "FK01", "FK02", "XK0", "SUPPLIER", "LFA1"],
                "side_b_patterns": ["PAYMENT", "F110", "AP_PAY", "DISBURS", "F-53"],
            },
            {
                "rule_id": "SOD-HEUR-002",
                "name": "Purchasing ↔ Goods Receipt Roles (heuristic)",
                "severity": "HIGH",
                "side_a_patterns": ["PURCHAS", "PO_CREATE", "ME21", "ME22", "BUYER", "PROCUR"],
                "side_b_patterns": ["GR_POST", "GOODS_RECEIPT", "MIGO", "MB01", "WAREHOUSE"],
            },
            {
                "rule_id": "SOD-HEUR-003",
                "name": "User Admin ↔ Security Admin Roles (heuristic)",
                "severity": "CRITICAL",
                "side_a_patterns": ["USER_ADMIN", "SU01", "USER_MGMT", "IDM_ADMIN"],
                "side_b_patterns": ["ROLE_ADMIN", "PFCG", "AUTH_ADMIN", "SECURITY_ADMIN"],
            },
        ]

        for rule in heuristic_rules:
            conflicts = []
            conflict_objs = []
            for user, roles in user_role_map.items():
                role_str = " ".join(roles)
                has_a = any(p in role_str for p in rule["side_a_patterns"])
                has_b = any(p in role_str for p in rule["side_b_patterns"])

                if has_a and has_b:
                    matching_a = [r for r in roles if any(p in r for p in rule["side_a_patterns"])]
                    matching_b = [r for r in roles if any(p in r for p in rule["side_b_patterns"])]
                    conflicts.append(
                        f"{user} — Side A roles: {', '.join(matching_a[:3])} ↔ "
                        f"Side B roles: {', '.join(matching_b[:3])}"
                    )
                    # Full role lists, not the display list's first three: the display
                    # truncation is cosmetic, whereas every matched role is a real
                    # graph node the remediation has to touch.
                    conflict_objs.append(
                        [("user", user)]
                        + [("role", r) for r in matching_a + matching_b]
                    )

            if conflicts:
                self.finding(
                    check_id=f"IAM-{rule['rule_id']}",
                    title=f"Potential SoD Conflict: {rule['name']}",
                    severity=rule["severity"],
                    category="Identity & Access Management",
                    description=(
                        f"{len(conflicts)} user(s) have role assignments matching both "
                        f"sides of this SoD rule based on role naming patterns. "
                        f"Note: this is a heuristic check — provide role_tcodes.csv "
                        f"for precise t-code level analysis."
                    ),
                    affected_items=conflicts,
                    # Same shape as the matrix path: one finding per heuristic rule
                    # summarising every user that matches it, so the member list stays
                    # out of identity.
                    affected_objects=self._row_objects(conflict_objs),
                    scope="aggregate",
                    remediation=(
                        "Validate these conflicts using SUIM or SAP GRC Access Risk Analysis. "
                        "If confirmed, remove one side or implement mitigating controls."
                    ),
                    references=["SAP GRC Access Risk Analysis"],
                )

    # ════════════════════════════════════════════════════════════════
    #  IAM-FF-*: Emergency / Firefighter Access Analysis
    # ════════════════════════════════════════════════════════════════

    def check_firefighter_usage(self):
        """
        Analyze emergency/firefighter access logs for policy violations.
        Checks: excessive duration, high frequency, missing justification,
        unreviewed sessions, and self-approved usage.
        """
        ff_log = self.data.get("firefighter_log")
        if not ff_log:
            # Check if firefighter IDs exist but no log
            users = self.data.get("users") or []
            ff_users = [
                row.get("BNAME", row.get("USERNAME", ""))
                for row in users
                if any(p in row.get("BNAME", row.get("USERNAME", "")).upper()
                       for p in ("FF_", "FIRE", "EMERG", "BREAKGLASS", "EAM_"))
            ]
            if ff_users:
                self.finding(
                    check_id="IAM-FF-000",
                    title="Firefighter accounts detected but no usage log provided",
                    severity=self.SEVERITY_HIGH,
                    category="Identity & Access Management",
                    description=(
                        f"{len(ff_users)} account(s) with firefighter naming patterns "
                        "were found, but no firefighter usage log was provided. "
                        "Cannot verify proper use, session review, or justification compliance."
                    ),
                    affected_items=ff_users,
                    # One finding over the whole set of firefighter accounts found
                    # without a log. Deleting one such account does not supply the
                    # missing log, so it must not retire and re-raise this finding.
                    affected_objects=self._objects(("user", u) for u in ff_users),
                    scope="aggregate",
                    remediation=(
                        "Export firefighter usage logs from SAP GRC Superuser Privilege "
                        "Management (SPM) or equivalent. File: firefighter_log.csv with "
                        "columns: FF_USER, ACTUAL_USER, LOGIN_TIME, LOGOUT_TIME, "
                        "REASON, REVIEWED, REVIEWER."
                    ),
                    references=["SAP GRC SPM — Emergency Access Management"],
                )
            return

        max_duration = self.get_config("ff_max_duration_hours", self.FF_MAX_DURATION_HOURS)
        max_sessions = self.get_config("ff_max_sessions_per_month", self.FF_MAX_SESSIONS_PER_MONTH)

        long_sessions = []
        long_session_objs = []
        no_reason = []
        no_reason_objs = []
        unreviewed = []
        unreviewed_objs = []
        self_approved = []
        self_approved_objs = []
        user_session_counts: Dict[str, List] = defaultdict(list)

        for row in ff_log:
            ff_user = row.get("FF_USER", row.get("FIREFIGHTER_ID", row.get("FF_ID", "")))
            actual_user = row.get("ACTUAL_USER", row.get("REAL_USER", row.get("REQUESTOR", "")))
            login_time = row.get("LOGIN_TIME", row.get("START_TIME", row.get("SESSION_START", "")))
            logout_time = row.get("LOGOUT_TIME", row.get("END_TIME", row.get("SESSION_END", "")))
            reason = row.get("REASON", row.get("JUSTIFICATION", row.get("DESCRIPTION", "")))
            reviewed = row.get("REVIEWED", row.get("REVIEW_STATUS", row.get("APPROVED", "")))
            reviewer = row.get("REVIEWER", row.get("REVIEWED_BY", row.get("CONTROLLER", "")))

            session_label = f"{actual_user} as {ff_user} (login: {login_time})"
            # A session is not an SAP object; the two principals it names are. The login
            # timestamp is deliberately not a qualifier — it differs per session, so it
            # would split one firefighter ID into a new graph node on every use.
            session_objs = [("user", actual_user), ("user", ff_user)]

            # Check duration
            if login_time and logout_time:
                duration_hours = self._calc_duration_hours(login_time, logout_time)
                if duration_hours is not None and duration_hours > max_duration:
                    long_sessions.append(
                        f"{session_label} — duration: {duration_hours:.1f}h (max: {max_duration}h)"
                    )
                    long_session_objs.extend(session_objs)

            # Check justification
            if not reason or not reason.strip():
                no_reason.append(session_label)
                no_reason_objs.extend(session_objs)

            # Check review status
            if str(reviewed).upper() not in ("YES", "Y", "X", "1", "TRUE", "REVIEWED", "COMPLETE"):
                unreviewed.append(session_label)
                unreviewed_objs.extend(session_objs)

            # Check self-approval
            if reviewer and actual_user and reviewer.upper() == actual_user.upper():
                self_approved.append(f"{session_label} — reviewed by: {reviewer}")
                self_approved_objs.extend(session_objs)

            # Track frequency
            user_session_counts[actual_user.upper()].append(login_time)

        # Report findings
        if long_sessions:
            self.finding(
                check_id="IAM-FF-001",
                title=f"Firefighter sessions exceeding {max_duration}h duration",
                severity=self.SEVERITY_HIGH,
                category="Identity & Access Management",
                description=(
                    f"{len(long_sessions)} emergency access session(s) exceeded the "
                    f"maximum allowed duration of {max_duration} hours. Extended "
                    "firefighter sessions increase exposure to privileged access misuse."
                ),
                affected_items=long_sessions,
                # Every over-long session rolled into ONE finding. Sessions are historic
                # events that can never be "fixed" individually, so identity must stay
                # on the check or each new export would raise a brand-new finding.
                affected_objects=self._objects(long_session_objs),
                scope="aggregate",
                remediation=(
                    "Enforce automatic session timeout in GRC SPM configuration. "
                    "Investigate each extended session for unauthorized activity. "
                    f"Set maximum session duration to {max_duration} hours."
                ),
                references=["SAP GRC SPM — Session Duration Controls"],
            )

        if no_reason:
            self.finding(
                check_id="IAM-FF-002",
                title="Firefighter sessions without documented justification",
                severity=self.SEVERITY_HIGH,
                category="Identity & Access Management",
                description=(
                    f"{len(no_reason)} emergency access session(s) have no documented "
                    "reason/justification. Every firefighter session must have a "
                    "traceable business reason for audit compliance."
                ),
                affected_items=no_reason,
                # Aggregate for the same reason as IAM-FF-001: the members are past
                # sessions, and the defect is the missing reason-code control.
                affected_objects=self._objects(no_reason_objs),
                scope="aggregate",
                remediation=(
                    "Enable mandatory reason code in GRC SPM. "
                    "Retroactively document justification for existing sessions. "
                    "Implement workflow requiring incident/change ticket reference."
                ),
                references=["SOX / J-SOX — Emergency Access Documentation Requirements"],
            )

        if unreviewed:
            self.finding(
                check_id="IAM-FF-003",
                title="Firefighter sessions not reviewed by controller",
                severity=self.SEVERITY_CRITICAL,
                category="Identity & Access Management",
                description=(
                    f"{len(unreviewed)} emergency access session(s) have not been "
                    "reviewed. Unreviewed firefighter sessions represent a complete "
                    "breakdown of the compensating control framework."
                ),
                affected_items=unreviewed,
                # Aggregate: reviewing one outstanding session shortens the list but
                # does not close the control gap, so the finding keeps its identity.
                affected_objects=self._objects(unreviewed_objs),
                scope="aggregate",
                remediation=(
                    "Assign controllers to review all outstanding sessions immediately. "
                    "Configure automated email escalation for unreviewed sessions. "
                    "Set SLA: sessions must be reviewed within 48 hours of completion."
                ),
                references=[
                    "SAP GRC SPM — Controller Review Configuration",
                    "SOX Section 404 — Compensating Controls",
                ],
            )

        if self_approved:
            self.finding(
                check_id="IAM-FF-004",
                title="Firefighter sessions reviewed by the same user who initiated them",
                severity=self.SEVERITY_CRITICAL,
                category="Identity & Access Management",
                description=(
                    f"{len(self_approved)} emergency access session(s) were reviewed/approved "
                    "by the same person who used the firefighter ID. This is a "
                    "segregation of duties violation in the control process itself."
                ),
                affected_items=self_approved,
                # Aggregate over every self-approved session. The reviewer is the same
                # principal as the requestor by construction here, so naming it twice
                # would add no node.
                affected_objects=self._objects(self_approved_objs),
                scope="aggregate",
                remediation=(
                    "Enforce controller ≠ requestor rule in GRC SPM configuration. "
                    "Reassign controller responsibility to an independent reviewer. "
                    "Retroactively review all self-approved sessions for misuse."
                ),
                references=["SAP GRC SPM — Controller Assignment Best Practices"],
            )

        # Frequency analysis
        frequent_users = []
        frequent_user_objs = []
        for user, sessions in user_session_counts.items():
            if len(sessions) > max_sessions:
                frequent_users.append(
                    f"{user} — {len(sessions)} sessions (max: {max_sessions}/month)"
                )
                frequent_user_objs.append(("user", user))

        if frequent_users:
            self.finding(
                check_id="IAM-FF-005",
                title=f"Users with excessive firefighter usage (>{max_sessions} sessions)",
                severity=self.SEVERITY_MEDIUM,
                category="Identity & Access Management",
                description=(
                    f"{len(frequent_users)} user(s) have used emergency access more than "
                    f"{max_sessions} times. Frequent firefighter usage suggests the user "
                    "may need permanent role adjustments instead of emergency access."
                ),
                affected_items=frequent_users,
                # One finding listing every over-frequent user. The session COUNT is
                # not a qualifier: it climbs with each export, and would re-key the
                # node on every run.
                affected_objects=self._objects(frequent_user_objs),
                scope="aggregate",
                remediation=(
                    "Review each user's firefighter usage patterns. "
                    "If recurring access is needed, provision appropriate permanent roles "
                    "instead of relying on emergency access. "
                    "Update role design to cover legitimate recurring needs."
                ),
                references=["SAP GRC — Firefighter Usage Optimization"],
            )

    # ════════════════════════════════════════════════════════════════
    #  IAM-EXP-*: Role Expiry & Validity Enforcement
    # ════════════════════════════════════════════════════════════════

    def check_role_expiry(self):
        """
        Check role assignments for missing or expired validity dates.
        Uses role_expiry.csv or user_roles.csv with FROM_DAT/TO_DAT fields.
        """
        role_expiry = self.data.get("role_expiry")
        if not role_expiry:
            # Fall back to user_roles if it has date fields
            user_roles = self.data.get("user_roles") or []
            has_dates = any(
                row.get("TO_DAT", row.get("VALID_TO", row.get("END_DATE", "")))
                for row in user_roles
            )
            if has_dates:
                role_expiry = user_roles
            else:
                return  # No date data available

        no_expiry = []
        no_expiry_objs = []
        expired_active = []
        expired_active_objs = []
        long_validity = []
        long_validity_objs = []
        max_validity_days = self.get_config("max_role_validity_days", 365)

        for row in role_expiry:
            user = row.get("UNAME", row.get("BNAME", row.get("USERNAME", "")))
            role = row.get("AGR_NAME", row.get("ROLE", row.get("ROLE_NAME", "")))
            from_date = row.get("FROM_DAT", row.get("VALID_FROM", row.get("START_DATE", "")))
            to_date = row.get("TO_DAT", row.get("VALID_TO", row.get("END_DATE", "")))

            label = f"{user} → {role}"
            # A role ASSIGNMENT has no name of its own; the two ends of it do. Dates
            # stay out of the object names — they are exactly what remediation changes.
            row_objs = (("user", user), ("role", role))

            # No expiry date set
            if not to_date or to_date.strip() in ("", "99991231", "9999-12-31", "31.12.9999"):
                no_expiry.append(f"{label} (valid to: indefinite)")
                no_expiry_objs.append(row_objs)
                continue

            # Parse end date
            parsed_to = self._parse_date(to_date)
            if not parsed_to:
                continue

            now = datetime.now()

            # Already expired but still assigned
            if parsed_to < now:
                days_expired = (now - parsed_to).days
                expired_active.append(f"{label} (expired: {to_date}, {days_expired}d ago)")
                expired_active_objs.append(row_objs)
                continue

            # Excessively long validity
            parsed_from = self._parse_date(from_date) if from_date else now
            if parsed_from:
                validity_days = (parsed_to - parsed_from).days
                if validity_days > max_validity_days:
                    long_validity.append(
                        f"{label} (validity: {validity_days}d, max: {max_validity_days}d)"
                    )
                    long_validity_objs.append(row_objs)

        if no_expiry:
            self.finding(
                check_id="IAM-EXP-001",
                title="Role assignments without expiry dates",
                severity=self.SEVERITY_MEDIUM,
                category="Identity & Access Management",
                description=(
                    f"{len(no_expiry)} role assignment(s) have no expiration date set. "
                    "Indefinite role assignments bypass periodic access review enforcement "
                    "and create access accumulation risk."
                ),
                affected_items=no_expiry[:100],
                # One finding covering every open-ended assignment. Dating one of them
                # must not retire this finding and raise a fresh one — that would reset
                # its age every run and make MTTR permanently wrong. Same [:100] slice
                # as the display list so the nodes match the evidence shown.
                affected_objects=self._row_objects(no_expiry_objs[:100]),
                scope="aggregate",
                remediation=(
                    "Set validity end dates on all role assignments. "
                    "Implement a maximum validity period policy (e.g., 12 months). "
                    "Use SAP Identity Management or GRC ARM for automated expiry enforcement."
                ),
                references=["CIS SAP Benchmark — Role Validity Management"],
                details={"total_count": len(no_expiry)},
            )

        if expired_active:
            self.finding(
                check_id="IAM-EXP-002",
                title="Expired role assignments still present in user master",
                severity=self.SEVERITY_LOW,
                category="Identity & Access Management",
                description=(
                    f"{len(expired_active)} role assignment(s) have passed their validity "
                    "end date but are still assigned. While SAP enforces validity dates "
                    "at runtime, expired assignments should be cleaned up to maintain "
                    "an accurate access baseline."
                ),
                affected_items=expired_active[:50],
                # Aggregate over the stale-assignment backlog; same [:50] slice as the
                # display list.
                affected_objects=self._row_objects(expired_active_objs[:50]),
                scope="aggregate",
                remediation=(
                    "Run report PRGN_COMPRESS_TIMES to clean up expired role assignments. "
                    "Schedule periodic cleanup via SAP Identity Management."
                ),
                references=["SAP Note 1763498 — AGR_USERS Cleanup"],
                details={"total_count": len(expired_active)},
            )

        if long_validity:
            self.finding(
                check_id="IAM-EXP-003",
                title=f"Role assignments with excessive validity (>{max_validity_days}d)",
                severity=self.SEVERITY_MEDIUM,
                category="Identity & Access Management",
                description=(
                    f"{len(long_validity)} role assignment(s) have validity periods "
                    f"exceeding {max_validity_days} days. Long validity periods delay "
                    "access reviews and increase the window for privilege misuse."
                ),
                affected_items=long_validity[:50],
                # Aggregate over every over-long assignment; same [:50] slice as the
                # display list.
                affected_objects=self._row_objects(long_validity_objs[:50]),
                scope="aggregate",
                remediation=(
                    f"Reduce validity periods to {max_validity_days} days maximum. "
                    "Implement re-certification workflows for role renewals. "
                    "Exception: service/technical accounts may justify longer validity "
                    "with documented approval."
                ),
                references=["SOX/ITGC — Periodic Access Recertification"],
                details={"total_count": len(long_validity)},
            )

    # ════════════════════════════════════════════════════════════════
    #  IAM-XID-*: Cross-System Identity Consistency (S/4 ↔ BTP)
    # ════════════════════════════════════════════════════════════════

    def check_cross_system_identity(self):
        """
        Compare S/4HANA users with BTP subaccount users to identify
        orphaned accounts, privilege mismatches, and shadow access.
        """
        btp_users = self.data.get("btp_users")
        s4_users = self.data.get("users")

        if not btp_users or not s4_users:
            return  # Need both systems for comparison

        btp_user_list = btp_users if isinstance(btp_users, list) else \
            btp_users.get("users", btp_users.get("members", []))

        # Normalize to comparable identifiers (email or username)
        s4_identities = set()
        s4_user_details = {}
        for row in s4_users:
            uname = row.get("BNAME", row.get("USERNAME", "")).upper()
            email = row.get("SMTP_ADDR", row.get("EMAIL", "")).upper()
            s4_identities.add(uname)
            if email:
                s4_identities.add(email)
            s4_user_details[uname] = row
            if email:
                s4_user_details[email] = row

        btp_identities = set()
        btp_user_details = {}
        for user in btp_user_list:
            if not isinstance(user, dict):
                continue
            uid = user.get("userName", user.get("userId", user.get("email", ""))).upper()
            email = user.get("email", user.get("mail", "")).upper()
            btp_identities.add(uid)
            if email:
                btp_identities.add(email)
            btp_user_details[uid] = user
            if email:
                btp_user_details[email] = user

        # BTP users without S/4 counterpart
        btp_only = []
        btp_only_objs = []
        for user in btp_user_list:
            if not isinstance(user, dict):
                continue
            uid = user.get("userName", user.get("userId", user.get("email", ""))).upper()
            email = user.get("email", user.get("mail", "")).upper()
            roles = user.get("roleCollections", user.get("roles", []))

            if uid not in s4_identities and email not in s4_identities:
                role_str = ", ".join(roles[:3]) if isinstance(roles, list) else str(roles)
                btp_only.append(f"{uid} (roles: {role_str})")
                # Typed `user`, not a separate BTP type: this check exists precisely to
                # treat the S/4 and BTP user masters as ONE identity namespace, and it
                # already folds case (`uid` is upper-cased above) to compare them. A
                # second type here would split the very identity the check is matching.
                btp_only_objs.append(("user", uid))

        # S/4 locked users still active in BTP
        locked_but_active_btp = []
        locked_but_active_objs = []
        for row in s4_users:
            uname = row.get("BNAME", row.get("USERNAME", "")).upper()
            email = row.get("SMTP_ADDR", row.get("EMAIL", "")).upper()
            lock_status = row.get("UFLAG", row.get("LOCK_STATUS", "0"))
            is_locked = str(lock_status) not in ("0", "")

            if is_locked:
                if uname in btp_identities or email in btp_identities:
                    locked_but_active_btp.append(
                        f"{uname} — locked in S/4 but present in BTP"
                    )
                    locked_but_active_objs.append(("user", uname))

        # BTP admin role collections on unexpected users
        admin_patterns = ["SUBACCOUNT_ADMIN", "GLOBAL_ACCOUNT_ADMIN",
                          "SPACE_DEVELOPER", "SECURITY_ADMIN", "CONNECTIVITY_ADMIN",
                          "DESTINATION_ADMIN", "SUBACCOUNT_SERVICE_ADMIN"]

        btp_admins = []
        btp_admin_objs = []
        for user in btp_user_list:
            if not isinstance(user, dict):
                continue
            uid = user.get("userName", user.get("userId", ""))
            roles = user.get("roleCollections", user.get("roles", []))
            if isinstance(roles, list):
                admin_roles = [r for r in roles if any(
                    p in str(r).upper() for p in admin_patterns
                )]
                if admin_roles:
                    btp_admins.append(f"{uid} — {', '.join(str(r) for r in admin_roles[:4])}")
                    # Full admin_roles, not the display list's first four. Role
                    # collections use the case-sensitive `role_collection` type, which
                    # is what keeps a BTP "Subaccount_Admin" from being upper-cased and
                    # conflated with a PFCG role of the same spelling.
                    btp_admin_objs.append(
                        [("user", uid)]
                        + [("role_collection", str(r)) for r in admin_roles]
                    )

        if btp_only:
            self.finding(
                check_id="IAM-XID-001",
                title="BTP users without corresponding S/4HANA account",
                severity=self.SEVERITY_MEDIUM,
                category="Identity & Access Management",
                description=(
                    f"{len(btp_only)} BTP subaccount user(s) have no matching identity "
                    "in the S/4HANA user master. These may be orphaned accounts, "
                    "external consultants, or shadow access entries."
                ),
                affected_items=btp_only[:50],
                # One finding over the whole orphan set: deleting one BTP-only account
                # must shrink the list, not restart the clock on the rest. Same [:50]
                # slice as the display list.
                affected_objects=self._objects(btp_only_objs[:50]),
                scope="aggregate",
                remediation=(
                    "Review each BTP-only account for business justification. "
                    "Implement centralized identity governance spanning both S/4 and BTP "
                    "(e.g., SAP Cloud Identity Services with SCIM provisioning). "
                    "Remove orphaned accounts."
                ),
                references=["SAP BTP Security Guide — Identity Federation"],
                details={"total_count": len(btp_only)},
            )

        if locked_but_active_btp:
            self.finding(
                check_id="IAM-XID-002",
                title="S/4HANA locked users still active in BTP",
                severity=self.SEVERITY_HIGH,
                category="Identity & Access Management",
                description=(
                    f"{len(locked_but_active_btp)} user(s) are locked in S/4HANA but "
                    "still have active BTP subaccount access. This indicates incomplete "
                    "offboarding — the user may still access BTP services, APIs, and "
                    "potentially reach backend S/4 via API proxies."
                ),
                affected_items=locked_but_active_btp,
                # Aggregate: one finding for the incomplete-offboarding backlog, so
                # deprovisioning the first leaver does not re-raise it for the others.
                affected_objects=self._objects(locked_but_active_objs),
                scope="aggregate",
                remediation=(
                    "Implement synchronized deprovisioning across S/4 and BTP. "
                    "Use SAP Cloud Identity Services for centralized lifecycle management. "
                    "Immediately remove BTP access for all listed users."
                ),
                references=["SAP BTP — User Lifecycle Management"],
            )

        if btp_admins:
            self.finding(
                check_id="IAM-XID-003",
                title="BTP subaccount users with administrative role collections",
                severity=self.SEVERITY_HIGH,
                category="Identity & Access Management",
                description=(
                    f"{len(btp_admins)} BTP user(s) hold administrative role collections. "
                    "Administrative access in BTP allows configuration changes, "
                    "trust management, and service provisioning that can affect "
                    "the entire RISE landscape."
                ),
                affected_items=btp_admins,
                # Aggregate over every BTP admin holder; revoking one collection from
                # one user leaves the over-privileged population, and the finding.
                affected_objects=self._row_objects(btp_admin_objs),
                scope="aggregate",
                remediation=(
                    "Review all BTP admin assignments using principle of least privilege. "
                    "Separate Subaccount Admin from Security Admin roles. "
                    "Implement privileged access management for BTP admin actions. "
                    "Document each admin assignment with business justification."
                ),
                references=["SAP BTP Security Recommendations — Role Collections"],
            )

    # ════════════════════════════════════════════════════════════════
    #  IAM-REV-*: Access Review Compliance
    # ════════════════════════════════════════════════════════════════

    def check_access_review_compliance(self):
        """
        Check if periodic access reviews are being completed on schedule.
        Uses access_reviews.csv export from GRC ARM or manual tracking.
        """
        reviews = self.data.get("access_reviews")
        if not reviews:
            return

        review_cycle_days = self.get_config("access_review_cycle_days", 90)
        now = datetime.now()

        overdue = []
        incomplete = []
        no_reviewer = []

        for row in reviews:
            review_id = row.get("REVIEW_ID", row.get("CAMPAIGN_ID", row.get("ID", "")))
            review_name = row.get("REVIEW_NAME", row.get("CAMPAIGN_NAME", row.get("NAME", "")))
            due_date = row.get("DUE_DATE", row.get("DEADLINE", row.get("TARGET_DATE", "")))
            status = row.get("STATUS", row.get("REVIEW_STATUS", ""))
            completion = row.get("COMPLETION_PCT", row.get("PROGRESS", row.get("COMPLETED", "")))
            reviewer = row.get("REVIEWER", row.get("OWNER", row.get("RESPONSIBLE", "")))

            label = f"{review_name or review_id}"

            # Check overdue
            if due_date:
                parsed_due = self._parse_date(due_date)
                if parsed_due and parsed_due < now:
                    if status.upper() not in ("COMPLETED", "CLOSED", "DONE", "FINISHED"):
                        days_overdue = (now - parsed_due).days
                        overdue.append(f"{label} — due: {due_date}, {days_overdue}d overdue")

            # Check incomplete
            if completion:
                try:
                    pct = float(completion.replace("%", "").strip())
                    if pct < 100 and status.upper() in ("COMPLETED", "CLOSED", "DONE"):
                        incomplete.append(f"{label} — status: {status}, completion: {pct}%")
                except ValueError:
                    pass

            # Check missing reviewer
            if not reviewer or not reviewer.strip():
                no_reviewer.append(label)

        if overdue:
            self.finding(
                check_id="IAM-REV-001",
                title="Overdue access review campaigns",
                severity=self.SEVERITY_HIGH,
                category="Identity & Access Management",
                description=(
                    f"{len(overdue)} access review campaign(s) are past their due date "
                    "and not completed. Overdue reviews indicate a control gap in the "
                    "periodic access recertification process."
                ),
                affected_items=overdue,
                # Aggregate, and deliberately with no affected_objects: the members are
                # GRC review CAMPAIGNS, which are not SAP objects of any registered type
                # and have no presence in the attack-path graph. Naming the campaign
                # owner instead would put the reviewer in the graph as if they were the
                # defect, which they are not.
                scope="aggregate",
                remediation=(
                    "Escalate overdue reviews to management immediately. "
                    "Complete all outstanding reviews within 2 weeks. "
                    f"Enforce {review_cycle_days}-day review cycle with automated reminders."
                ),
                references=[
                    "SOX Section 404 — Periodic Access Recertification",
                    "SAP GRC Access Request Management",
                ],
            )

        if incomplete:
            self.finding(
                check_id="IAM-REV-002",
                title="Access reviews marked complete but with incomplete coverage",
                severity=self.SEVERITY_MEDIUM,
                category="Identity & Access Management",
                description=(
                    f"{len(incomplete)} review campaign(s) are marked as completed "
                    "but have less than 100% completion rate. Partial reviews leave "
                    "unvalidated access in place."
                ),
                affected_items=incomplete,
                # Aggregate over review campaigns — no registered object type, see
                # IAM-REV-001 above.
                scope="aggregate",
                remediation=(
                    "Reopen campaigns and ensure 100% review coverage. "
                    "Investigate why certain items were skipped. "
                    "Enforce completion rules in GRC ARM before allowing campaign closure."
                ),
                references=["SOX — Access Review Completeness Requirements"],
            )

        if no_reviewer:
            self.finding(
                check_id="IAM-REV-003",
                title="Access review campaigns without assigned reviewer",
                severity=self.SEVERITY_MEDIUM,
                category="Identity & Access Management",
                description=(
                    f"{len(no_reviewer)} review campaign(s) have no assigned reviewer/owner. "
                    "Unowned reviews will never be completed."
                ),
                affected_items=no_reviewer,
                # Aggregate over review campaigns — no registered object type, and by
                # definition no reviewer to name either. See IAM-REV-001 above.
                scope="aggregate",
                remediation=(
                    "Assign reviewers to all campaigns based on business process ownership. "
                    "Implement automatic reviewer assignment based on organizational structure."
                ),
                references=["SAP GRC ARM — Reviewer Assignment"],
            )

    # ════════════════════════════════════════════════════════════════
    #  IAM-ROLE-*: Role Design Quality
    # ════════════════════════════════════════════════════════════════

    def check_role_design_quality(self):
        """
        Analyze role metadata for design quality issues:
        roles without descriptions, single roles used as composites,
        roles without owners, and naming convention violations.
        """
        role_details = self.data.get("role_details")
        if not role_details:
            return

        no_description = []
        no_owner = []
        naming_violations = []
        empty_roles = []

        # Configurable naming convention pattern
        naming_prefixes = self.get_config("role_naming_prefixes", [
            "Z_", "Y_", "ZBC_", "ZFI_", "ZMM_", "ZSD_", "ZHR_", "ZPP_",
        ])

        for row in role_details:
            role_name = row.get("AGR_NAME", row.get("ROLE", row.get("ROLE_NAME", "")))
            description = row.get("TEXT", row.get("DESCRIPTION", row.get("AGR_TEXT", "")))
            owner = row.get("OWNER", row.get("RESPONSIBLE", row.get("CREATED_BY", "")))
            role_type = row.get("TYPE", row.get("ROLE_TYPE", ""))
            tcode_count = row.get("TCODE_COUNT", row.get("MENU_COUNT", ""))

            if not role_name:
                continue

            # Custom roles without description
            if role_name.startswith(("Z", "Y")):
                if not description or not description.strip():
                    no_description.append(role_name)

                # No owner
                if not owner or not owner.strip():
                    no_owner.append(role_name)

                # Empty roles (no tcodes/menu)
                if tcode_count:
                    try:
                        if int(tcode_count) == 0:
                            empty_roles.append(role_name)
                    except ValueError:
                        pass

            # Naming convention check for custom roles
            if role_name.startswith(("Z", "Y")):
                has_valid_prefix = any(role_name.upper().startswith(p) for p in naming_prefixes)
                if not has_valid_prefix and len(role_name) > 2:
                    naming_violations.append(role_name)

        if no_description:
            self.finding(
                check_id="IAM-ROLE-001",
                title="Custom roles without descriptions",
                severity=self.SEVERITY_LOW,
                category="Identity & Access Management",
                description=(
                    f"{len(no_description)} custom role(s) have no description text. "
                    "Undocumented roles cannot be effectively reviewed or maintained."
                ),
                affected_items=no_description[:50],
                # Aggregate: documenting one role does not document the rest, so the
                # member list stays out of identity. The display list here IS the role
                # names, so the same [:50] slice gives exactly matching nodes.
                affected_objects=self._objects(("role", r) for r in no_description[:50]),
                scope="aggregate",
                remediation=(
                    "Add meaningful descriptions to all custom roles via PFCG. "
                    "Include: business process, target user group, and approval reference."
                ),
                references=["SAP Security Best Practices — Role Documentation"],
                details={"total_count": len(no_description)},
            )

        if no_owner:
            self.finding(
                check_id="IAM-ROLE-002",
                title="Custom roles without designated owners",
                severity=self.SEVERITY_MEDIUM,
                category="Identity & Access Management",
                description=(
                    f"{len(no_owner)} custom role(s) have no designated owner. "
                    "Ownerless roles cannot be included in access review campaigns "
                    "and tend to accumulate unauthorized permissions over time."
                ),
                affected_items=no_owner[:50],
                # Aggregate over the ownerless-role population; same [:50] slice.
                affected_objects=self._objects(("role", r) for r in no_owner[:50]),
                scope="aggregate",
                remediation=(
                    "Assign business owners to all custom roles. "
                    "Use SAP GRC role ownership features or maintain a RACI matrix. "
                    "Owner should be the business process lead, not IT."
                ),
                references=["ISACA COBIT — Role Ownership and Accountability"],
                details={"total_count": len(no_owner)},
            )

        if empty_roles:
            self.finding(
                check_id="IAM-ROLE-003",
                title="Custom roles with no menu/transaction assignments",
                severity=self.SEVERITY_LOW,
                category="Identity & Access Management",
                description=(
                    f"{len(empty_roles)} custom role(s) have no transactions in their menu. "
                    "Empty roles may be leftover artifacts from role redesign projects."
                ),
                affected_items=empty_roles[:30],
                # Aggregate over the leftover empty roles; same [:30] slice.
                affected_objects=self._objects(("role", r) for r in empty_roles[:30]),
                scope="aggregate",
                remediation="Review and delete empty roles. Verify no users are assigned.",
                references=["SAP Note 1763498"],
                details={"total_count": len(empty_roles)},
            )

    # ════════════════════════════════════════════════════════════════
    #  IAM-ORPH-*: Orphaned Role Assignments
    # ════════════════════════════════════════════════════════════════

    def check_orphaned_roles(self):
        """
        Check for role assignments where the role no longer exists
        or is flagged for deletion.
        """
        user_roles = self.data.get("user_roles")
        role_details = self.data.get("role_details")

        if not user_roles or not role_details:
            return

        # Build set of valid role names
        valid_roles = set()
        for row in role_details:
            role = row.get("AGR_NAME", row.get("ROLE", row.get("ROLE_NAME", ""))).upper()
            if role:
                valid_roles.add(role)

        orphaned = []
        orphaned_objs = []
        for row in user_roles:
            user = row.get("UNAME", row.get("BNAME", row.get("USERNAME", "")))
            role = row.get("AGR_NAME", row.get("ROLE", row.get("ROLE_NAME", ""))).upper()
            if role and role not in valid_roles:
                orphaned.append(f"{user} → {role}")
                # The dangling role name is still a real node: it is what the AGR_USERS
                # row points at, and it is the thing the cleanup removes.
                orphaned_objs.append((("user", user), ("role", role)))

        if orphaned:
            self.finding(
                check_id="IAM-ORPH-001",
                title="Users assigned to non-existent or deleted roles",
                severity=self.SEVERITY_MEDIUM,
                category="Identity & Access Management",
                description=(
                    f"{len(orphaned)} user-role assignment(s) reference roles that "
                    "do not exist in the role catalog. These are orphaned assignments "
                    "from deleted roles that were not properly cleaned up."
                ),
                affected_items=orphaned[:50],
                # Aggregate over the orphaned-assignment backlog; same [:50] slice as
                # the display list.
                affected_objects=self._row_objects(orphaned_objs[:50]),
                scope="aggregate",
                remediation=(
                    "Remove orphaned role assignments via SU01 or mass cleanup. "
                    "Implement role deletion procedures that include assignment cleanup. "
                    "Run report PRGN_COMPRESS_TIMES periodically."
                ),
                references=["SAP Note 1763498"],
                details={"total_count": len(orphaned)},
            )

    # ════════════════════════════════════════════════════════════════
    #  IAM-USRGRP-*: User Group Segmentation
    # ════════════════════════════════════════════════════════════════

    def check_user_group_segmentation(self):
        """
        Validate user group assignments for proper segmentation.
        Flags users in default/generic groups and admins in regular groups.
        """
        user_groups = self.data.get("user_groups")
        if not user_groups:
            # Try to get from users data
            users = self.data.get("users") or []
            user_groups = [
                row for row in users
                if row.get("CLASS", row.get("USER_GROUP", row.get("USGRP", "")))
            ]
            if not user_groups:
                return

        default_group_users = []
        default_group_objs = []
        group_distribution: Dict[str, int] = defaultdict(int)

        for row in user_groups:
            user = row.get("BNAME", row.get("USERNAME", row.get("UNAME", "")))
            group = row.get("CLASS", row.get("USER_GROUP", row.get("USGRP", "")))

            if group:
                group_distribution[group] += 1

            # Users without a proper group assignment
            if not group or group.strip() in ("", "000", "DEFAULT", "SUPER"):
                lock_status = row.get("UFLAG", row.get("LOCK_STATUS", "0"))
                if str(lock_status) in ("0", ""):
                    default_group_users.append(f"{user} (group: {group or 'none'})")
                    # Only the user is named: the offending rows are exactly those with
                    # no group, or a placeholder group ("000"/"DEFAULT"/"SUPER"), so
                    # there is no real group object to point at.
                    default_group_objs.append(("user", user))

        if default_group_users:
            self.finding(
                check_id="IAM-USRGRP-001",
                title="Active users in default/unassigned user groups",
                severity=self.SEVERITY_LOW,
                category="Identity & Access Management",
                description=(
                    f"{len(default_group_users)} active user(s) are in the default or "
                    "unassigned user group. Proper user group segmentation enables "
                    "group-level access control via S_USER_GRP authorization object."
                ),
                affected_items=default_group_users[:30],
                # Aggregate: assigning one user a proper group does not segment the
                # rest. Same [:30] slice as the display list.
                affected_objects=self._objects(default_group_objs[:30]),
                scope="aggregate",
                remediation=(
                    "Assign all users to meaningful user groups reflecting their "
                    "organizational or functional role. Use user groups as an "
                    "additional authorization control layer in S_USER_GRP."
                ),
                references=["CIS SAP Benchmark — User Group Management"],
                details={"total_count": len(default_group_users)},
            )

    # ════════════════════════════════════════════════════════════════
    #  IAM-REF-*: Reference User Misuse
    # ════════════════════════════════════════════════════════════════

    def check_reference_user_misuse(self):
        """
        Detect dialog users assigned as reference users for other accounts.
        Reference users (type L) should be used, not regular dialog users.
        """
        users = self.data.get("users")
        if not users:
            return

        # Build set of reference user assignments
        ref_users_assigned = set()
        user_type_map = {}

        for row in users:
            uname = row.get("BNAME", row.get("USERNAME", "")).upper()
            user_type = row.get("USTYP", row.get("USER_TYPE", ""))
            ref_user = row.get("REF_USER", row.get("REFERENCE_USER", "")).upper()

            user_type_map[uname] = user_type

            if ref_user:
                ref_users_assigned.add(ref_user)

        # Flag dialog users being used as reference users
        misused = []
        misused_objs = []
        for ref_user in ref_users_assigned:
            user_type = user_type_map.get(ref_user, "")
            if str(user_type).upper() in ("A", "DIALOG"):
                misused.append(
                    f"{ref_user} (type: Dialog) — used as reference user for other accounts"
                )
                misused_objs.append(("user", ref_user))

        if misused:
            self.finding(
                check_id="IAM-REF-001",
                title="Dialog users used as reference users",
                severity=self.SEVERITY_HIGH,
                category="Identity & Access Management",
                description=(
                    f"{len(misused)} dialog user(s) are assigned as reference users for "
                    "other accounts. Reference users should be type L (Reference) only. "
                    "Using dialog users as reference users means changes to one user's "
                    "authorizations silently affect all dependent accounts."
                ),
                affected_items=misused,
                # Aggregate over every dialog account misused this way. Only the
                # reference users themselves are named — the check builds a set of
                # reference-user names and never keeps the dependent accounts, so
                # naming those would mean inventing data the check does not hold.
                affected_objects=self._objects(misused_objs),
                scope="aggregate",
                remediation=(
                    "Create dedicated type L (Reference) users for authorization inheritance. "
                    "Do not use active dialog accounts as reference users. "
                    "Audit all accounts that inherit from these reference users."
                ),
                references=["SAP Note 2191612 — Reference User Best Practices"],
            )

    # ════════════════════════════════════════════════════════════════
    #  IAM-PRIV-*: Privilege Escalation Path Detection
    # ════════════════════════════════════════════════════════════════

    def check_privilege_escalation_paths(self):
        """
        Detect indirect privilege escalation via:
        - Users who can modify roles they are assigned to
        - Users who can create/modify users in their own user group
        - Users who can assign roles to themselves
        """
        auth_objects = self.data.get("auth_objects")
        user_roles = self.data.get("user_roles")
        if not auth_objects:
            return

        # Build user → auth object mapping
        user_auths: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))
        for row in auth_objects:
            user = row.get("UNAME", row.get("BNAME", row.get("USERNAME", ""))).upper()
            obj = row.get("OBJECT", row.get("AUTH_OBJECT", "")).upper()
            field = row.get("FIELD", row.get("AUTH_FIELD", "")).upper()
            value = row.get("VALUE", row.get("AUTH_VALUE", "")).strip()
            user_auths[user][obj].add(value)

        escalation_paths = []
        escalation_objs = []

        for user, auth_map in user_auths.items():
            reasons = []
            triggered = []

            # Can modify roles (PFCG access) AND is assigned roles
            has_role_admin = "S_USER_AGR" in auth_map
            if has_role_admin and "*" in auth_map.get("S_USER_AGR", set()):
                reasons.append("can modify any role via PFCG (S_USER_AGR=*)")
                triggered.append("S_USER_AGR")

            # Can create/modify users (SU01 access) in any group
            has_user_admin = "S_USER_GRP" in auth_map
            if has_user_admin and "*" in auth_map.get("S_USER_GRP", set()):
                reasons.append("can manage any user via SU01 (S_USER_GRP=*)")
                triggered.append("S_USER_GRP")

            # Can assign profiles directly
            has_profile_admin = "S_USER_PRO" in auth_map
            if has_profile_admin and "*" in auth_map.get("S_USER_PRO", set()):
                reasons.append("can assign any profile (S_USER_PRO=*)")
                triggered.append("S_USER_PRO")

            if len(reasons) >= 2:
                escalation_paths.append(
                    f"{user} — {'; '.join(reasons)}"
                )
                # The user is the offender; the auth objects that combined to make the
                # path are the edges. Every one of these three names comes from the
                # export's OBJECT column, not from a list invented here.
                escalation_objs.append(
                    [("user", user)] + [("auth_object", o) for o in triggered]
                )

        if escalation_paths:
            self.finding(
                check_id="IAM-PRIV-001",
                title="Users with privilege escalation capability",
                severity=self.SEVERITY_CRITICAL,
                category="Identity & Access Management",
                description=(
                    f"{len(escalation_paths)} user(s) hold combinations of administrative "
                    "authorizations that enable self-escalation. These users can modify "
                    "their own access or create accounts with elevated privileges."
                ),
                affected_items=escalation_paths,
                # One finding rolling up every self-escalating user, so identity stays
                # on the check: splitting one user's administrative combination does
                # not remove the segregation gap for the others.
                affected_objects=self._row_objects(escalation_objs),
                scope="aggregate",
                remediation=(
                    "Separate user administration, role administration, and profile "
                    "administration across different individuals. No single user should "
                    "hold S_USER_GRP + S_USER_AGR + S_USER_PRO with full access. "
                    "Implement approval workflows for any changes to these objects."
                ),
                references=[
                    "CIS SAP Benchmark Section 3 — Authorization Object Segregation",
                    "ISACA — Privilege Escalation Prevention",
                ],
            )

    # ════════════════════════════════════════════════════════════════
    #  Utility Methods
    # ════════════════════════════════════════════════════════════════

    @staticmethod
    def _parse_date(date_str: str):
        """Try to parse a date string in common SAP formats."""
        if not date_str or not date_str.strip():
            return None
        for fmt in ("%Y%m%d", "%Y-%m-%d", "%d.%m.%Y", "%m/%d/%Y", "%d/%m/%Y"):
            try:
                return datetime.strptime(date_str.strip(), fmt)
            except ValueError:
                continue
        return None

    @staticmethod
    def _calc_duration_hours(start: str, end: str):
        """Calculate duration between two timestamp strings."""
        formats = [
            "%Y%m%d%H%M%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
            "%d.%m.%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%Y%m%d %H%M%S",
        ]
        start_dt = end_dt = None
        for fmt in formats:
            try:
                start_dt = datetime.strptime(start.strip(), fmt)
                break
            except ValueError:
                continue
        for fmt in formats:
            try:
                end_dt = datetime.strptime(end.strip(), fmt)
                break
            except ValueError:
                continue

        if start_dt and end_dt:
            delta = end_dt - start_dt
            return delta.total_seconds() / 3600
        return None
