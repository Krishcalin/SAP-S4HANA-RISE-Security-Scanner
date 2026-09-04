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
  - Identity federation hygiene and SCIM/provisioning de-provisioning (IAM-FED-*)
  - Disclosure of the federation checks an export could not support (IAM-FEDCOV-*)

Data sources:
  - sod_ruleset.json     → SoD conflict rule definitions
  - firefighter_log.csv  → Emergency access / firefighter usage log (GRC SPM)
  - role_expiry.csv      → Role assignments with validity dates (AGR_USERS)
  - btp_users.json       → BTP subaccount user/role collection export
  - btp_trust.json       → BTP subaccount trust configurations (IAM-FED-*)
  - comm_arrangements.json → Communication arrangements, read ONLY as evidence that
                             an identity-provisioning integration exists (IAM-FED-004)
  - ias_config.json      → IAS tenant config, likewise read only for provisioning
                           evidence (IAM-FED-004)
  - role_details.csv     → Role metadata (owner, description, type)
  - access_reviews.csv   → Periodic access review completion records
  - user_groups.csv      → User group assignments (USGRP from USR02)

────────────────────────────────────────────────────────────────────────────────
WHAT THE FEDERATION CHECKS ASSUME ABOUT `btp_trust.json`   (measured 2026-08-07)
────────────────────────────────────────────────────────────────────────────────
Only five fields are OBSERVED in this repository's own export fixture
(`sample_data/btp_trust.json`, the shape `docs/EXPORT_GUIDE.md` tells a customer to
produce):

    identityProvider, originKey, status, createShadowUsers, description

Everything else the checks below read — whether a trust is offered for interactive
user logon, which users of the IdP it admits, and when its certificate expires — is
a DOCUMENTED shape we accept if a tenant's export happens to carry it, not one we
have seen from a real tenant. Those field names are marked "UNVERIFIED:" at the
point of use.

The consequence is deliberate and is the conservative direction: a check whose field
is absent stays SILENT. It never reads "the export did not say" as "the trust is
unrestricted" or "the certificate has expired", because absence of evidence turning
into a finding is how a federation report becomes something nobody trusts.

SILENT ON THE FINDING, NOT SILENT ABOUT THE GAP
-----------------------------------------------
Silence on the FINDING is right; silence altogether is not, and that was the defect.
A report carrying no federation-admission and no certificate-expiry finding reads
exactly like a report that examined both and found them healthy — so two checks that
cannot fire on any export this product can currently load were being presented as
two clean results. Nothing to find and could not look must never look the same.

So when trust rows ARE present and none of them answers the attribute a check needs,
that check says so: `IAM-FEDCOV-002` and `IAM-FEDCOV-003`, INFO, naming the
attributes it looked for, what it therefore could not conclude, and how to produce an
export that carries them. This is the pattern
`snc_posture.check_family_not_assessable` establishes, and `server/enrich.py` carries
the same idea as its `not_assessable` remediation-owner state.

Two boundaries on that:

  * When `btp_trust` is absent ALTOGETHER these stay silent. A missing export is the
    coverage manifest's subject (`server/coverage.py`), which reports it once for the
    whole scan; restating it per check would bury the manifest in duplicates.
  * The coverage ids sit OUTSIDE the `IAM-FED-*` family on purpose. That prefix means
    "a defect was found in this customer's federation" and is filtered on as such —
    by the report, and by this feature's own test suite. "We could not look" is a
    defect in OUR evidence, not in their landscape, and counting it as a federation
    finding would inflate exactly the number a reader trusts.

WHAT IS DELIBERATELY NOT REPEATED HERE
--------------------------------------
`rise_btp_checks` already reports the SAP default IdP being active (RISE-001) and
shadow-user auto-creation per trust (RISE-002), and `btp_cloud_surface` already
reports the IAS tenant permitting local password logon alongside a corporate IdP
(BTP-IAS-005). None of those is restated. What none of them can see is the SHAPE of
the federation as a whole — how many independent ways in exist, whether the identity
lifecycle closes, and whether the trust's own certificate is about to strand it —
and that is what IAM-FED-* adds.
"""

from typing import Dict, List, Any, Optional, Set, Tuple
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

    # ── Federation / SCIM ───────────────────────────────────────────
    #: Days before a trust certificate expires at which it becomes a finding. Chosen
    #: to be longer than a normal change window, because renewing a federation
    #: certificate needs the IdP owner and the BTP owner in the same room.
    TRUST_CERT_WARNING_DAYS = 30

    #: Values that mean "everyone" where a restriction was expected. An EMPTY value is
    #: included only when the field is PRESENT — see `_logon_restriction`.
    FED_WILDCARDS = {"*", "ANY", "ALL", "ALL_USERS", "*@*", "*.*"}

    #: Where a trust row might state WHICH users of its identity provider may log on.
    #: Read by `_logon_restriction`, and quoted verbatim by IAM-FEDCOV-002 so that the
    #: customer is told what we actually looked for rather than a prose paraphrase of
    #: it that drifts the first time this tuple changes.
    #:
    #: UNVERIFIED: every name below. They are plausible/documented shapes; not one has
    #: been observed in an export this product can load, which is precisely why
    #: IAM-FEDCOV-002 exists.
    #:
    #: REVIEWED 2026-08-08 AND DELIBERATELY NOT WIDENED. No further name could be
    #: stood behind, and a wrong alias is worse than a short list in both directions at
    #: once: an attribute that says which email domains are ROUTED to this identity
    #: provider (home-realm discovery) looks exactly like an admission restriction and
    #: is not one, so reading it as one would report a properly scoped trust as
    #: restricted — silencing the check — while a genuinely wide-open trust carrying
    #: the same attribute would also go unreported. Padding this tuple to look thorough
    #: would convert a disclosed gap into an undisclosed false negative.
    FED_RESTRICTION_FIELDS: Tuple[str, ...] = (
        "userRestriction", "allowedUsers", "allowedUserDomains", "allowedDomains",
    )

    #: Where a trust row might carry the validity end of the certificate that signs its
    #: assertions. Read by `_trust_cert_expiry`, quoted by IAM-FEDCOV-003.
    #:
    #: UNVERIFIED: every name below, for the same reason as FED_RESTRICTION_FIELDS.
    #:
    #: REVIEWED 2026-08-08 AND DELIBERATELY NOT WIDENED. The expiry is a property of
    #: the certificate rather than of the trust, and the export shapes we have seen
    #: carry neither the certificate nor any date derived from it — so there is no
    #: further field name here to be confident about. Reading the validity out of a
    #: raw base64 X.509 attribute is the only way to answer this without guessing at a
    #: field name at all, and that is separate work, not an alias.
    FED_CERT_EXPIRY_FIELDS: Tuple[str, ...] = (
        "certificateExpiryDate", "certificateValidTo", "signingCertificateExpiry",
        "certificate_expiry", "certificateExpiry",
    )

    #: Word-level tokens in a communication-arrangement or IAS configuration name that
    #: evidence an identity-PROVISIONING integration rather than a business one.
    #: Matched on whole tokens, not substrings, so "SF_EMPLOYEE_SYNC" (HR master-data
    #: replication) is not mistaken for identity provisioning — it moves employee
    #: records, not the shadow users whose removal this check is about.
    FED_PROVISIONING_TOKENS = {"SCIM", "PROVISION", "PROVISIONING", "IPS", "IDM"}

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
        self.check_federation_logon_paths()
        self.check_federation_trust_restriction()
        self.check_federation_certificate_expiry()
        self.check_scim_deprovisioning()
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

    @staticmethod
    def _row_relations(rows) -> List[Dict[str, Any]]:
        """The same rows as `_row_objects`, keeping WHICH end goes with which.

        `_row_objects` flattens each row's two ends into one list, and the graph
        extractor then sees fifty users and fifty roles with no way to tell which
        assignment is which — so it declines to guess and the assignments produce
        no edges at all. The rows here are already pairs: `row_objs` is built as
        ``(("user", user), ("role", role))`` precisely because, as the comment
        there says, a role assignment has no name of its own and the two ends of
        it do.

        Slice the SAME rows the display list and `_row_objects` were given, for
        the same reason they slice together: edges that described assignments the
        report does not show would be evidence the reader cannot check.
        """
        out = []
        for row in rows:
            pairs = list(row)
            if len(pairs) != 2:
                continue          # only a two-ended row states a relationship
            (from_type, from_name), (to_type, to_name) = pairs
            if not from_name or not to_name:
                continue
            out.append({"from": {"type": from_type, "name": from_name},
                        "to": {"type": to_type, "name": to_name}})
        return out

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
                relations=self._row_relations(no_expiry_objs[:100]),
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
                relations=self._row_relations(expired_active_objs[:50]),
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
                relations=self._row_relations(long_validity_objs[:50]),
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
                # Typed `btp_user`, NOT `user`. The matching that unifies the two user
                # masters has already happened above, in Python, on normalised strings —
                # that is what produced this list. The GRAPH must keep the two apart: a
                # BTP identity and an ABAP user of the same name are different principals
                # reached by different means, and merging them into one node would hide
                # the on-prem/BTP crossing that the cloud-to-on-prem attack path exists
                # to show. `btp_user` is also cloud-scoped, so it is never stamped with
                # the ABAP SID of the system being scanned.
                btp_only_objs.append(("btp_user", uid))

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
        # One user to many collections, so `_row_relations` (which pairs the two
        # ends of a two-ended row) does not fit: each row here is a fan-out and
        # every arm of it is a real grant.
        btp_admin_rels: List[Dict[str, Any]] = []
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
                        [("btp_user", uid)]
                        + [("role_collection", str(r)) for r in admin_roles]
                    )
                    if uid:
                        btp_admin_rels.extend(
                            {"from": {"type": "btp_user", "name": uid},
                             "to": {"type": "role_collection", "name": str(r)}}
                            for r in admin_roles)

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
                relations=btp_admin_rels,
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
        overdue_objs = []
        incomplete_objs = []
        no_reviewer_objs = []

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
                        overdue_objs.append(("review_campaign", review_id or review_name))

            # Check incomplete
            if completion:
                try:
                    pct = float(completion.replace("%", "").strip())
                    if pct < 100 and status.upper() in ("COMPLETED", "CLOSED", "DONE"):
                        incomplete.append(f"{label} — status: {status}, completion: {pct}%")
                        incomplete_objs.append(
                            ("review_campaign", review_id or review_name))
                except ValueError:
                    pass

            # Check missing reviewer
            if not reviewer or not reviewer.strip():
                no_reviewer.append(label)
                no_reviewer_objs.append(("review_campaign", review_id or review_name))

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
                # The campaign IS the object — a GRC governance entity with its own id.
                # The REVIEWER deliberately is not: a person who has not completed a
                # review is not the defect, and naming them would put an individual in
                # the graph as though they were.
                #
                # Aggregate, so completing one campaign shrinks the member list without
                # retiring the finding and resetting the age of the rest.
                affected_objects=self._objects(overdue_objs),
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
                # Campaigns as objects, aggregate identity — see IAM-REV-001.
                affected_objects=self._objects(incomplete_objs),
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
                # The campaign is the object. There is by definition no reviewer to
                # name here — which is precisely the finding. See IAM-REV-001.
                affected_objects=self._objects(no_reviewer_objs),
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
    #  IAM-FED-*: Identity Federation & SCIM Provisioning
    # ════════════════════════════════════════════════════════════════

    _FED_TRUE = {"TRUE", "X", "YES", "Y", "1", "ACTIVE", "ENABLED", "ON"}
    _FED_FALSE = {"FALSE", "NO", "N", "0", "INACTIVE", "DISABLED", "OFF", "NONE"}

    @classmethod
    def _flag(cls, value: Any) -> Optional[bool]:
        """Read an export flag as True / False / None-for-"the export did not say".

        Tri-state on purpose. `bool(value)` is wrong twice over here: BTP writes trust
        status as either a JSON boolean or the string "inactive", and the string is
        TRUTHY, so a plain truth test reports a decommissioned trust as live. And a
        MISSING field is not a `False` — collapsing the two would let every check
        below fire on an export that simply does not carry the column, which is the
        one direction a federation finding must never be wrong in.
        """
        if value is None:
            return None
        if isinstance(value, bool):
            return value
        text = str(value).strip().upper()
        if not text:
            return None
        if text in cls._FED_TRUE:
            return True
        if text in cls._FED_FALSE:
            return False
        return None

    @staticmethod
    def _trust_rows(trust: Any) -> List[Dict[str, Any]]:
        """The trust configurations in a `btp_trust` export, whatever wraps them.

        Unwrapped exactly as `rise_btp_checks.check_btp_trust_config` unwraps them —
        a bare list, a `{"trusts": [...]}` envelope, or a single trust object — so the
        two modules always talk about the same rows. Non-dict entries are dropped
        rather than coerced: a stray string in the array names no trust, and inventing
        one would put a fictional node in the graph.
        """
        if not trust:
            return []
        if isinstance(trust, list):
            rows = trust
        elif isinstance(trust, dict):
            rows = trust.get("trusts", trust.get("trust_configurations"))
            if not isinstance(rows, list):
                rows = [trust]
        else:
            return []
        return [r for r in rows if isinstance(r, dict)]

    @staticmethod
    def _trust_key(row: Dict[str, Any]) -> str:
        """Name a trust by its originKey, falling back to the IdP display name.

        Identical to `rise_btp_checks._trust_name`, and identical ON PURPOSE: the
        origin is the technical key and `identityProvider` is an editable label, so
        keying on the origin makes RISE-001, RISE-002 and every IAM-FED-* finding
        point at ONE `idp_trust` node per trust. Diverging here would silently split
        one trust into two nodes and hide that the same trust carries several defects.
        """
        origin = row.get("originKey", row.get("origin", ""))
        idp = row.get("identityProvider", row.get("idp_name", row.get("name", "")))
        for candidate in (origin, idp):
            text = "" if candidate is None else str(candidate).strip()
            if text and text.lower() != "unknown":
                return text
        return ""

    @classmethod
    def _trust_admits_users(cls, row: Dict[str, Any]) -> bool:
        """Can a person interactively log on through this trust?

        Absence counts as YES, which inverts this module's usual rule, and the reason
        is that the default is not neutral here: a trust configuration EXISTS in order
        to authenticate people. The two fields below SUBTRACT from that — they say
        "decommissioned" or "not offered on the logon screen" — they do not grant it.
        Requiring positive evidence would make the whole check dormant on the only
        real-world export shape we have seen, which carries neither field.
        """
        if cls._flag(row.get("status", row.get("enabled", row.get("active")))) is False:
            return False
        # UNVERIFIED: `availableForUserLogon` is a documented BTP trust attribute we
        # have not observed in any export in this repository. Absent, it subtracts
        # nothing.
        logon = cls._flag(row.get("availableForUserLogon",
                                  row.get("available_for_user_logon")))
        return logon is not False

    @classmethod
    def _auto_creates_identities(cls, row: Dict[str, Any]) -> bool:
        """Does logging on through this trust MATERIALISE a BTP identity?

        This is the same field RISE-002 reports, read for a different question. RISE-002
        asks whether creation is automatic; IAM-FED-004 asks whether the identities so
        created are ever taken away again, which is a lifecycle question RISE-002 does
        not answer and cannot.
        """
        return cls._flag(row.get("createShadowUsers",
                                 row.get("auto_create_shadow_users"))) is True

    @classmethod
    def _logon_restriction(cls, row: Dict[str, Any]) -> Tuple[str, str]:
        """(the attribute that answered, its value) for "which IdP users may log on".

        The attribute NAME is returned rather than a bare present/absent flag, and ""
        means no attribute answered at all. Those two states mean different things and
        drive different outputs: an ABSENT attribute is an export that does not
        describe the restriction — silence on the finding, IAM-FEDCOV-002 on the gap —
        while an EMPTY one is a trust that admits everybody, which is IAM-FED-002.
        Returning the name also lets the coverage finding say what it read instead of
        what it hoped to read.

        A POPULATED attribute wins over a merely present one. Where an export carries
        two of these names — one empty, one naming a group — the empty one is the less
        informative reading and taking it would report a properly scoped trust as wide
        open. Under-claiming is the correct direction when the field names themselves
        are unverified.
        """
        answered = ""
        for field in cls.FED_RESTRICTION_FIELDS:
            if field not in row:
                continue
            answered = answered or field
            value = row[field]
            if isinstance(value, (list, tuple, set)):
                if value:
                    return field, ", ".join(str(v) for v in value)
            elif value not in (None, ""):
                return field, str(value)
        # Present but saying nothing: reported against the FIRST name that appeared, so
        # the finding quotes the attribute the export actually used.
        return answered, ""

    @classmethod
    def _trust_cert_expiry(cls, row: Dict[str, Any]) -> Tuple[str, str]:
        """(the attribute that answered, its raw value), or ("", "").

        Same shape and the same populated-wins rule as `_logon_restriction`, and here
        that rule is load-bearing rather than merely cautious: a row carrying
        ``certificateExpiryDate: ""`` alongside a populated ``certificateValidTo`` does
        tell us when the certificate lapses, and preferring the empty one would make
        IAM-FED-003 go quiet about a real expiry.

        A name that appeared but answered nothing still comes back, because "the export
        declared this attribute and left it blank" is a coverage gap and not a clean
        result.
        """
        answered = ""
        for field in cls.FED_CERT_EXPIRY_FIELDS:
            if field not in row:
                continue
            answered = answered or field
            value = row.get(field)
            if value not in (None, ""):
                return field, str(value).strip()
        return answered, ""

    @staticmethod
    def _tokens(*texts: Any) -> Set[str]:
        """Upper-case alphanumeric word tokens across several strings.

        Word-level, not substring: "PROVISION" as a substring matches nothing useful,
        whereas a substring search for "IPS" would match "SHIPS", "TIPS" and any
        arrangement whose name happens to contain those letters — and a FALSE piece of
        provisioning evidence silences IAM-FED-004, which is the dangerous direction.
        """
        out: Set[str] = set()
        for text in texts:
            if text in (None, ""):
                continue
            token = ""
            for ch in str(text).upper():
                if ch.isalnum():
                    token += ch
                elif token:
                    out.add(token)
                    token = ""
            if token:
                out.add(token)
        return out

    def _provisioning_evidence(self) -> List[str]:
        """Anything in the supplied exports that evidences automated user provisioning.

        This is EVIDENCE GATHERING, not detection: a customer whose SCIM provisioning
        is wired but who never exported the arrangement that carries it will still be
        told IAM-FED-004, and the finding says so in as many words. Reporting "we could
        not see it" is honest; reporting "it is not there" would not be.
        """
        evidence: List[str] = []

        for arr in self._arrangement_rows():
            name = arr.get("name", arr.get("arrangement_name", ""))
            scenario = arr.get("scenario_id", arr.get("communication_scenario", ""))
            if self._tokens(name, scenario) & self.FED_PROVISIONING_TOKENS:
                evidence.append(f"communication arrangement '{name}'")

        ias = self.data.get("ias_config")
        if isinstance(ias, dict):
            for field in ("provisioning", "userProvisioning", "scim", "scimProvisioning"):
                if field not in ias:
                    continue
                block = ias[field]
                if block in (None, "", {}, [], ()):
                    # A key that is present but carries nothing describes no integration.
                    # Reading it as evidence would SILENCE IAM-FED-004 — the direction
                    # this check must never be wrong in, because the customer is then
                    # told nothing at all about a lifecycle gap that is really there.
                    continue
                if isinstance(block, dict):
                    # A block that explicitly says it is switched off is the OPPOSITE
                    # of evidence, so it must not silence the finding.
                    if self._flag(block.get("enabled", block.get("active"))) is False:
                        continue
                    evidence.append(f"IAS '{field}' configuration")
                elif self._flag(block) is not False:
                    evidence.append(f"IAS '{field}' configuration")

        return evidence

    def _arrangement_rows(self) -> List[Dict[str, Any]]:
        """Communication arrangements, unwrapped as `rise_btp_checks` unwraps them."""
        comms = self.data.get("comm_arrangements")
        if not comms:
            return []
        if isinstance(comms, list):
            rows = comms
        elif isinstance(comms, dict):
            rows = comms.get("arrangements", comms.get("items", []))
        else:
            return []
        return [r for r in rows if isinstance(r, dict)]

    # ────────────────────────────────────────────────────────────────

    def check_federation_logon_paths(self):
        """IAM-FED-001 — how many independent ways in does this subaccount have?

        The assurance level of a federated subaccount is the MINIMUM over every trust
        that can authenticate a person, not the maximum. Conditional access, MFA and
        session policy live in the IdP, so a second live trust is a second policy
        engine — and an attacker only has to find the weaker one.

        This is NOT RISE-001. RISE-001 reports one specific trust (SAP's default IdP)
        and is silent when the second logon path is a legacy corporate SAML tenant, a
        partner IdP left behind after a migration, or a test IdP that was never
        removed — which are exactly the cases that survive an audit precisely because
        nothing names them.
        """
        rows = self._trust_rows(self.data.get("btp_trust"))
        if not rows:
            return

        paths = []
        path_objs = []
        seen: Set[str] = set()
        for row in rows:
            if not self._trust_admits_users(row):
                continue
            key = self._trust_key(row)
            if not key:
                continue
            # One row per trust, counted once. Exports get concatenated and hand-merged,
            # and a trust that appears twice is still ONE way in: counting it twice would
            # make the finding contradict itself — "2 trust configuration(s)" in the text
            # while `_objects` de-duplicates to a single node underneath — and send the
            # owner hunting for a second logon path that does not exist.
            if key.upper() in seen:
                continue
            seen.add(key.upper())
            idp = row.get("identityProvider", row.get("idp_name", ""))
            paths.append(f"{key}" + (f" ({idp})" if idp and str(idp) != key else ""))
            path_objs.append(("idp_trust", key))

        if len(paths) < 2:
            return

        self.finding(
            check_id="IAM-FED-001",
            title="Several identity providers can authenticate users into one subaccount",
            severity=self.SEVERITY_MEDIUM,
            category="Identity & Access Management",
            description=(
                f"{len(paths)} trust configuration(s) in this subaccount can "
                "interactively authenticate users. Every one of them is an independent "
                "policy engine: multi-factor enforcement, conditional access, session "
                "lifetime, and joiner/mover/leaver de-provisioning are all decided by "
                "the identity provider behind the trust, not by BTP. The effective "
                "assurance of the subaccount is therefore the weakest of these paths, "
                "not the strongest, and an attacker chooses which one to attack. "
                "Second logon paths are rarely deliberate — they are usually a legacy "
                "SAML tenant kept 'until the migration finishes', a partner IdP from a "
                "project that ended, or a test trust nobody removed. Each is listed "
                "below so the owner can confirm it is intended and carries the same "
                "controls as the primary corporate provider."
            ),
            affected_items=paths,
            # One finding ABOUT the set of logon paths: retiring one legacy trust must
            # shrink the member list rather than retire this finding and raise a new one
            # whose age starts at zero while the remaining paths are unchanged. The
            # trusts still ride along as `idp_trust` nodes, keyed on originKey so they
            # are the same nodes RISE-001/RISE-002 name.
            affected_objects=self._objects(path_objs),
            scope="aggregate",
            remediation=(
                "Confirm every trust listed is still required. Remove or set to "
                "inactive any trust left over from a migration, a pilot or an ended "
                "partner engagement (BTP Cockpit → Subaccount → Security → Trust "
                "Configuration). For each trust that must stay, verify at the identity "
                "provider that it enforces the same multi-factor and conditional-access "
                "policy as the primary corporate provider, and that it is included in "
                "the same joiner/mover/leaver process — a trust whose IdP does not "
                "de-provision leavers keeps access alive after the corporate account "
                "is closed."
            ),
            references=[
                "SAP BTP Security Guide — Trust Configuration",
                "SAP Security Baseline — Identity Federation",
            ],
            details={"logon_path_count": len(paths)},
        )

    def check_federation_trust_restriction(self):
        """IAM-FED-002 — a trust that admits every user of its identity provider.

        A trust is a statement about WHICH identities an IdP may assert, and a
        corporate IdP's population is routinely larger than the population that should
        reach a production SAP subaccount: contractors, service identities, guest and
        B2B accounts from directory federation. Left unrestricted, every one of them
        can authenticate — authorization then becomes the only control, and shadow-user
        auto-creation removes even the step where somebody notices a new account.

        Silent unless the export explicitly carries the restriction field and it is
        empty or a wildcard: see the module docstring on absence-of-evidence. Silent on
        the FINDING, that is — the trusts this could not read are collected as it goes
        and disclosed by IAM-FEDCOV-002 below.
        """
        # Gathered from the SAME loop that performs the check, deliberately: a coverage
        # statement assembled separately would drift from what the check actually
        # examined, and a coverage statement that overstates what was checked is worse
        # than none at all.
        #
        # Tallied per DISTINCT NAMED trust rather than per row, for two reasons that are
        # both "do not overstate coverage":
        #   * Exports get concatenated and hand-merged, and a trust that appears twice is
        #     still ONE trust — IAM-FED-001 de-duplicates for exactly this reason. A
        #     coverage finding saying "2 trust configurations" about one of them sends
        #     the owner looking for a second trust that does not exist.
        #   * A row this scan cannot NAME is neither assessed nor reportable as
        #     unassessed, so it must not be counted as either. Counting it only in the
        #     denominator made the finding claim it "did carry the attribute and was
        #     assessed", which is the precise sentence this check exists to avoid.
        assessed: List[str] = []
        unassessed: List[str] = []
        seen: Set[str] = set()

        for row in self._trust_rows(self.data.get("btp_trust")):
            if not self._trust_admits_users(row):
                # A trust that admits nobody needs no restriction, so this is not a gap
                # in the evidence — there is genuinely nothing to assess.
                continue
            field, value = self._logon_restriction(row)
            key = self._trust_key(row)
            # A row naming no trust is not listed: we cannot report "this trust was
            # not assessed" about a trust we cannot name, and inventing a label
            # would put a fictional trust in front of the reader. IAM-FED-001 drops
            # nameless rows for the same reason.
            if key and key.upper() not in seen:
                seen.add(key.upper())
                (assessed if field else unassessed).append(key)
            if not field:
                continue
            cleaned = value.strip()
            if cleaned and cleaned.upper() not in self.FED_WILDCARDS:
                continue

            if not key:
                continue
            idp = row.get("identityProvider", row.get("idp_name", key))
            stated = cleaned if cleaned else "(empty)"

            self.finding(
                check_id="IAM-FED-002",
                title=f"Trust configuration admits any user of the identity provider: {key}",
                severity=self.SEVERITY_HIGH,
                category="Identity & Access Management",
                description=(
                    f"Trust '{key}' ({idp}) carries no restriction on which users of "
                    f"its identity provider may log on — the restriction is "
                    f"'{stated}'. Every identity the provider will authenticate can "
                    "therefore reach this subaccount, including populations that were "
                    "never intended to: contractors, B2B guest accounts inherited "
                    "through directory federation, service identities, and accounts "
                    "in directory branches belonging to other business units. "
                    "Where the same trust also creates shadow users automatically, "
                    "there is no point at which a human sees a new principal appear."
                ),
                affected_items=[f"Trust: {key} — user restriction: {stated}"],
                # One finding per trust, matching how RISE-001/RISE-002 treat a trust
                # row: restricting trust A is its own change with its own approval and
                # leaves trust B exactly as it was, so the two must not share an
                # identity or one of them would vanish from the report.
                affected_objects=self._objects([("idp_trust", key)]),
                scope="object",
                remediation=(
                    "Restrict the trust to the population that is meant to reach this "
                    "subaccount. At the identity provider, scope the application/"
                    "assertion to a specific group or directory branch rather than to "
                    "all users; in IAS, use conditional authentication rules on the "
                    "corresponding application. Then re-export the trust configuration "
                    "and confirm the restriction is recorded. Where the trust also "
                    "auto-creates shadow users, restricting admission is the control "
                    "that stops unknown principals materialising."
                ),
                references=[
                    "SAP BTP Security Guide — Trust Configuration",
                    "SAP Security Baseline — Identity Federation",
                ],
            )

        self.check_trust_restriction_not_assessable(
            unassessed, len(assessed) + len(unassessed))

    def check_trust_restriction_not_assessable(self, unassessed: List[str],
                                               considered: int):
        """IAM-FEDCOV-002 — say that IAM-FED-002 could not run, and why.

        The defect this closes was not a wrong answer, it was no answer presented as a
        good one: IAM-FED-002 keys on attributes nobody has confirmed appear in a real
        export, so on every export the product can currently load it contributed
        nothing and said nothing, and a reader saw a federation section with no
        admission finding in it.

        Reported at INFO because it is a gap in OUR evidence and not a defect in the
        customer's landscape, and reported at all because the alternative is the most
        damaging thing this product can do.

        Called by `check_federation_trust_restriction` and NOT from `run_all_checks` —
        it reports the tally that check kept while it was looking. Wiring it into the
        runner as well would emit it twice, on a finding whose whole purpose is to be
        believed.
        """
        if not unassessed:
            return
        names = ", ".join(self.FED_RESTRICTION_FIELDS)
        # Written out singular/plural rather than with "(s)": this finding's whole job
        # is to be read and believed, and it is usually about one or two trusts.
        one = len(unassessed) == 1
        subject = ("One trust configuration" if one
                   else f"{len(unassessed)} trust configurations")
        clause = ("carries no attribute stating which users of its identity provider "
                  "it admits" if one else
                  "carry no attribute stating which users of their identity provider "
                  "they admit")
        self.finding(
            check_id="IAM-FEDCOV-002",
            title="Trust user admission could not be assessed from this export",
            severity=self.SEVERITY_INFO,
            category="Identity & Access Management",
            description=(
                f"{subject} in this subaccount can authenticate users interactively and "
                f"{clause} — under any of the attribute names this check reads "
                f"({names}). The question IAM-FED-002 exists to answer was therefore "
                f"not answered for {'it' if one else 'them'}. "
                "This is a gap in the evidence and not a verdict: a trust in this state "
                "may be scoped to a single named group, or may admit every contractor, "
                "B2B guest and service identity the provider will authenticate, and "
                "this scan cannot tell which. It is stated explicitly because the "
                "alternative — a federation section with no admission finding in it — "
                "reads as 'admission was checked and is fine', which is the one thing "
                "it does not mean."
                + (f" {considered - len(unassessed)} other trust configuration(s) in "
                   "this export did carry the attribute and were assessed."
                   if considered > len(unassessed) else "")
            ),
            affected_items=[f"Trust: {k} — no user-admission attribute in the export"
                            for k in unassessed],
            # No affected_objects, for the same reason the SNC family's own coverage
            # finding names none (`snc_posture.check_family_not_assessable`): the
            # defect is in the export, not in the trust. The trusts are named in
            # the display list so the owner knows which ones to go and check, but
            # hanging an "unassessed" node off them in the attack-path graph would
            # assert something about the trust that this finding explicitly declines
            # to assert.
            scope="aggregate",
            remediation=(
                "Two steps, and the second one matters whether or not the first works. "
                "First, re-export the trust configurations as the full objects the "
                "platform returns rather than a summarised subset (docs/EXPORT_GUIDE.md, "
                "btp_trust) and re-run the scan; the attribute names this check reads "
                "are listed in this finding's details, so if your export names the "
                "restriction differently that difference is a gap in this scanner and "
                "can be reported as one. Second — because no export shape we have seen "
                "carries it — verify the control directly with the identity-provider "
                "owner: confirm that the application or assertion issued to this "
                "subaccount is scoped to a named group or directory branch rather than "
                "to every user the provider will authenticate; in IAS, that is the "
                "conditional authentication rules on the corresponding application. "
                "Record that verification with this scan so the gap is closed by "
                "evidence rather than by silence."
            ),
            references=[
                "SAP BTP Security Guide — Trust Configuration",
                "SAP Security Baseline — Identity Federation",
            ],
            details={
                "unassessable_check": "IAM-FED-002",
                "attributes_looked_for": list(self.FED_RESTRICTION_FIELDS),
                "trusts_not_assessed": list(unassessed),
                # Distinct NAMED trusts that admit users — the population this check
                # could actually reach a per-trust conclusion about. Rows the scan
                # could not name are in neither this count nor `trusts_not_assessed`,
                # because a coverage figure that quietly absorbs them reports them as
                # assessed.
                "trusts_admitting_users": considered,
            },
        )

    def check_federation_certificate_expiry(self):
        """IAM-FED-003 — the certificate that holds the federation up.

        A federation signing certificate expires for everybody at once and without
        warning to end users, and the field workaround is depressingly consistent:
        re-enable the default or local identity provider "just until the certificate is
        renewed". That converts a certificate-management lapse into an authentication-
        assurance downgrade at precisely the moment nobody has time to review it, which
        is why this belongs in an identity report and not only in a monitoring alert.

        Silent unless the export carries an expiry date, and silent on a date it cannot
        parse — guessing a date would be inventing the evidence. Both silences are
        disclosed by IAM-FEDCOV-003 rather than left to look like a clean result.
        """
        rows = self._trust_rows(self.data.get("btp_trust"))
        if not rows:
            return

        # A baseline override arrives from hand-written JSON/YAML and is routinely typed
        # as a string ("90"). Comparing int <= str raises, and this method runs inside
        # run_all_checks(), so one mistyped baseline entry would take down every other
        # IAM check in the run. A value we cannot read as a number falls back to the
        # shipped default rather than silently disabling the check.
        try:
            warn_days = int(self.get_config("trust_cert_warning_days",
                                            self.TRUST_CERT_WARNING_DAYS))
        except (TypeError, ValueError):
            warn_days = self.TRUST_CERT_WARNING_DAYS

        # Compare CALENDAR DATES, not instants. `_parse_date` returns midnight, so
        # subtracting a mid-afternoon `datetime.now()` floors an extra day off every
        # answer: a certificate valid until 23:59 TODAY was reported as "expired 1
        # day(s) ago" at HIGH severity — stating as fact an outage that has not
        # happened. The field carries a date and no more, so a date is the only
        # precision we are entitled to claim.
        today = datetime.now().date()

        # Two distinct ways to be unassessable, kept apart because they take different
        # fixes: the export never mentioned an expiry, or it mentioned one and the value
        # is not a date. Both are "we could not look", and both were silent before.
        no_attribute: List[str] = []
        unreadable: List[str] = []
        seen: Set[str] = set()

        for row in rows:
            field, raw = self._trust_cert_expiry(row)
            key = self._trust_key(row)
            # ISO timestamps carry a time part the SAP date formats do not; drop it
            # rather than fail to parse and stay silent about a real expiry.
            parsed = self._parse_date(raw.split("T")[0].split(" ")[0]) if raw else None

            # Every row the check can NAME, exactly as the check below reads it — the
            # coverage statement must describe the same population, or it would claim
            # assessment of a trust the check would have reported on. Counted once per
            # distinct trust: a concatenated export listing one trust twice is still one
            # trust, and saying "2 trust configurations" about it sends the owner hunting
            # for a second one. A row naming no trust is not reported as an unassessed
            # trust and is not counted as an assessed one either — see IAM-FEDCOV-002.
            if key and key.upper() not in seen:
                seen.add(key.upper())
                if not field:
                    no_attribute.append(key)
                elif not parsed:
                    unreadable.append(f"{key} — {field} = {raw!r}")

            if not key or not field or not parsed:
                continue

            days = (parsed.date() - today).days
            if days < 0:
                severity, state = self.SEVERITY_HIGH, f"expired {abs(days)} day(s) ago"
            elif days <= warn_days:
                # "expires in 0 day(s)" is the date arithmetic showing through. The
                # certificate is good until the end of today, and that is what the
                # finding should say.
                severity = self.SEVERITY_MEDIUM
                state = "expires today" if days == 0 else f"expires in {days} day(s)"
            else:
                continue

            self.finding(
                check_id="IAM-FED-003",
                title=f"Identity federation certificate {state}: {key}",
                severity=severity,
                category="Identity & Access Management",
                description=(
                    f"The certificate on trust configuration '{key}' {state} "
                    f"(valid to {raw}). When a federation certificate lapses, single "
                    "sign-on fails for every user of that trust simultaneously and "
                    "without a graceful degradation path. The usual emergency response "
                    "— re-enabling the default or local identity provider so people can "
                    "work — reintroduces exactly the authentication bypass that "
                    "federating away from it was meant to close, and it is done under "
                    "outage pressure, without review, and frequently left in place "
                    "afterwards. Certificate renewal needs both the identity-provider "
                    "owner and the BTP subaccount owner, so it is scheduled work, not "
                    "something that can be absorbed on the day it fails."
                ),
                affected_items=[f"Trust: {key} — certificate valid to {raw} ({state})"],
                # Per trust, like IAM-FED-002 and RISE-001/002: each certificate is
                # renewed on its own with its own two owners, and collapsing several
                # expiring trusts into one finding would hide all but one of them.
                affected_objects=self._objects([("idp_trust", key)]),
                scope="object",
                remediation=(
                    "Renew the certificate with the identity-provider owner and upload "
                    "the new metadata to the subaccount trust configuration before the "
                    "current one lapses. Schedule renewals as recurring change work at "
                    f"least {warn_days} days ahead rather than on expiry, and add "
                    "certificate expiry to the landscape monitoring that already "
                    "watches the systems themselves. Do not plan to fall back to the "
                    "default identity provider during a renewal outage — if a "
                    "break-glass path is genuinely required, define it in advance with "
                    "multi-factor authentication, a named account list and an "
                    "expiry date."
                ),
                references=[
                    "SAP BTP Security Guide — Trust Configuration",
                    "SAP Security Baseline — Identity Federation",
                ],
                details={"days_to_expiry": days, "valid_to": raw},
            )

        self.check_certificate_expiry_not_assessable(no_attribute, unreadable,
                                                     len(seen))

    def check_certificate_expiry_not_assessable(self, no_attribute: List[str],
                                                unreadable: List[str],
                                                considered: int):
        """IAM-FEDCOV-003 — say that IAM-FED-003 could not run, and why.

        The same defect as IAM-FEDCOV-002 and with a sharper edge, because this check
        is the one a reader is most likely to take on trust: certificate expiry is the
        kind of thing people expect a scanner to watch, so a report that says nothing
        about it is read as "nothing is expiring". On every export this product can
        currently load, it said nothing because it could see nothing.

        The unreadable-value half is worth as much as the missing-attribute half. An
        export carrying ``certificateExpiryDate: "n/a"`` is a customer who tried to
        answer; declining to guess a date from it is right, and declining to mention
        that we declined is not.

        Called by `check_federation_certificate_expiry`, not from `run_all_checks`;
        see `check_trust_restriction_not_assessable`.
        """
        if not (no_attribute or unreadable):
            return

        clauses = []
        if no_attribute:
            clauses.append(
                f"{len(no_attribute)} carr{'ies' if len(no_attribute) == 1 else 'y'} no "
                "certificate-expiry attribute at all, under any of the attribute names "
                f"this check reads ({', '.join(self.FED_CERT_EXPIRY_FIELDS)})")
        if unreadable:
            clauses.append(
                f"{len(unreadable)} carr{'ies' if len(unreadable) == 1 else 'y'} "
                f"{'a value that is not a date' if len(unreadable) == 1 else 'values that are not dates'} "
                "this check can read, and a date will not be guessed from "
                f"{'it' if len(unreadable) == 1 else 'them'}")

        self.finding(
            check_id="IAM-FEDCOV-003",
            title="Identity federation certificate expiry could not be assessed "
                  "from this export",
            severity=self.SEVERITY_INFO,
            category="Identity & Access Management",
            description=(
                f"Of the {considered} trust configuration"
                f"{'' if considered == 1 else 's'} this scan could name in this "
                "export, "
                + " and ".join(clauses) + ". The expiry of the certificate that signs "
                "each federation listed below is therefore unknown to this scan. That "
                "is a gap in the evidence and not a verdict — the certificates may have "
                "years left, or may already have lapsed. It is stated because a certificate "
                "lapse takes single sign-on down for every user of the trust at once, "
                "the standing workaround is to re-enable the default or local identity "
                "provider under outage pressure, and a report that is silent about "
                "expiry is read as a report that checked it."
            ),
            affected_items=(
                [f"Trust: {k} — no certificate-expiry attribute in the export"
                 for k in no_attribute]
                + [f"Trust: {entry} — not a date this scan can read"
                   for entry in unreadable]
            ),
            # No affected_objects: the gap is in the export, not in the trust. See
            # `check_trust_restriction_not_assessable` for the reasoning.
            scope="aggregate",
            remediation=(
                "Re-export the trust configurations as the full objects the platform "
                "returns rather than a summarised subset (docs/EXPORT_GUIDE.md, "
                "btp_trust) and re-run the scan; this finding's details list the "
                "attribute names the check reads and the values it could not parse, so "
                "an export that names the expiry differently can be reported as a gap "
                "in this scanner. Meanwhile, do not wait for the scan to tell you: ask "
                "the identity-provider owner for the validity end of each trust's "
                "signing certificate and put those dates in the change calendar. "
                "Renewal needs the identity-provider owner and the subaccount owner "
                "together, so it is scheduled work — a certificate discovered on the day "
                "it lapses cannot be renewed on that day."
            ),
            references=[
                "SAP BTP Security Guide — Trust Configuration",
                "SAP Security Baseline — Identity Federation",
            ],
            details={
                "unassessable_check": "IAM-FED-003",
                "attributes_looked_for": list(self.FED_CERT_EXPIRY_FIELDS),
                "trusts_without_the_attribute": list(no_attribute),
                "trusts_with_an_unreadable_value": list(unreadable),
                # Distinct NAMED trusts examined, not the raw row count: duplicated rows
                # and rows this scan cannot name are excluded, so this number never
                # implies coverage of a trust nothing was concluded about.
                "trusts_in_export": considered,
            },
        )

    def check_scim_deprovisioning(self):
        """IAM-FED-004 — identities appear automatically; does anything remove them?

        THE classic federation failure in a federated SAP landscape, and the one
        every published BTP hardening checklist reaches for SCIM to answer.
        A trust with shadow-user creation enabled materialises a BTP principal — with
        whatever role collections a group mapping grants it — the first time somebody
        authenticates. Nothing in that flow runs in reverse. When HR processes a leaver
        and the corporate directory account is disabled, the BTP shadow user, its role
        collections and any long-lived tokens issued to it remain exactly as they were
        unless a provisioning integration (SAP Cloud Identity Services / IPS, or any
        SCIM client) is wired to de-provision them. The account stops being reachable
        through the corporate IdP and stays reachable through every other trust.

        This reports a GAP IN THE EVIDENCE, not a proven absence, and says so: a tenant
        that provisions correctly but did not export the arrangement carrying it will
        see this finding, and closing it is a matter of supplying that export. The
        alternative — staying silent because we cannot see the control — would let the
        commonest lifecycle failure in a federated landscape go unmentioned.
        """
        rows = self._trust_rows(self.data.get("btp_trust"))
        if not rows:
            return

        auto_trusts = []
        auto_objs = []
        for row in rows:
            if not self._auto_creates_identities(row):
                continue
            key = self._trust_key(row)
            if not key:
                continue
            auto_trusts.append(key)
            auto_objs.append(("idp_trust", key))

        if not auto_trusts:
            return  # identities are created deliberately; somebody owns each one.

        if self._provisioning_evidence():
            return

        self.finding(
            check_id="IAM-FED-004",
            title="Federated identities are auto-created with no evidence of de-provisioning",
            severity=self.SEVERITY_MEDIUM,
            category="Identity & Access Management",
            description=(
                f"{len(auto_trusts)} trust configuration(s) create a BTP identity "
                "automatically the first time a user authenticates, and nothing in the "
                "supplied exports evidences an automated provisioning integration "
                "(SAP Cloud Identity Services / Identity Provisioning, or any SCIM "
                "client) that would remove those identities again. Shadow-user "
                "creation is one-directional: disabling a person's account in the "
                "corporate directory does not delete the BTP principal it created, nor "
                "its role collections, nor tokens already issued to it. After an HR "
                "leaver event the identity therefore survives — invisible to the "
                "corporate directory that everyone reviews, and reachable through any "
                "trust or local credential that does not consult it. This is the "
                "commonest way a federated SAP landscape ends up with access that "
                "belongs to nobody. Note this reports what the exports could not show: "
                "if provisioning IS configured, the export that carries it was not "
                "supplied."
            ),
            affected_items=[f"Trust: {t} — shadow users created automatically"
                            for t in auto_trusts],
            # One finding about the lifecycle gap, listing the trusts that feed it.
            # Wiring de-provisioning is a single integration that closes the gap for
            # every trust at once, so per-trust findings would misdescribe the work.
            affected_objects=self._objects(auto_objs),
            scope="aggregate",
            remediation=(
                "Wire de-provisioning, then evidence it. Configure SAP Cloud Identity "
                "Services (Identity Provisioning) or another SCIM client to read the "
                "authoritative HR/directory source and to DELETE or deactivate BTP "
                "shadow users when the source identity is disabled — read-only "
                "provisioning that only creates is the failure this finding describes. "
                "Confirm the job runs on a schedule and that its failures alert "
                "somebody. Until it exists, reconcile BTP users against the corporate "
                "directory on the same cadence as your access reviews and remove "
                "identities with no active source record. Re-run the scan with the "
                "communication arrangement or IAS provisioning configuration included "
                "in the export so the control can be seen."
            ),
            references=[
                "SAP Cloud Identity Services — Identity Provisioning",
                "SAP BTP — User Lifecycle Management",
                "SAP Security Baseline — Identity Federation",
            ],
            details={"auto_creating_trusts": len(auto_trusts)},
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
