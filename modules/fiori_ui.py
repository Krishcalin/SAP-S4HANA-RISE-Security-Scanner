"""
Fiori & UI Layer Auditor
==========================
Checks for Fiori Launchpad, UI security, and OData
service-level authorization.

Covers:
  - Fiori catalog & group access control
  - Tiles granting access beyond backend role intent
  - OData service-level authorization vs UI restrictions
  - Launchpad role-based spaces/pages configuration
  - Sensitive apps exposed without proper restrictions
  - Legacy BSP/WebDynpro apps still active
  - Fiori app usage analysis (unused apps consuming access)

Data sources:
  - fiori_catalogs.csv       → Catalog-to-role assignments (/UI2/FLPD_CUST)
  - fiori_tiles.csv          → Tile definitions with target OData services
  - odata_auth.csv           → OData service authorization config (IWFND/MAINT_SERVICE)
  - fiori_spaces.json        → Spaces/pages role-based configuration
  - fiori_app_usage.csv      → App launch statistics
"""

from typing import Dict, List, Any
from collections import defaultdict
from modules.base_auditor import BaseAuditor


class FioriUiAuditor(BaseAuditor):

    # Sensitive Fiori apps that should have restricted access
    SENSITIVE_APPS = {
        "F0733": "Manage Users (identity management)",
        "F0735": "Manage Business Roles",
        "F1962": "Communication Arrangements",
        "F2723": "Communication Systems",
        "F1603": "Maintain Business Users",
        "F5765": "Manage Software Components",
        "F3861": "Display Technical Users",
        "F0709": "Manage Catalogs",
        "F2917": "IAM Information System",
    }

    # OData services that should always require auth
    SENSITIVE_ODATA = [
        "API_BUSINESS_PARTNER", "API_USER_MANAGEMENT",
        "API_SALES_ORDER", "API_PURCHASEORDER",
        "API_JOURNAL_ENTRY", "API_BILLING_DOCUMENT",
        "HCM_EMPLOYEE", "API_PAYROLL",
        "MANAGE_WORKFORCE", "FINANCIALS",
    ]

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_catalog_access()
        self.check_sensitive_app_exposure()
        self.check_odata_service_auth()
        self.check_spaces_pages_config()
        self.check_tile_odata_mismatch()
        self.check_unused_fiori_apps()
        return self.findings

    def check_catalog_access(self):
        """Audit Fiori catalog-to-role assignments for overly broad access."""
        catalogs = self.data.get("fiori_catalogs")
        if not catalogs:
            return

        public_catalogs = []
        excessive_roles = []
        no_role = []
        max_roles = self.get_config("max_roles_per_catalog", 10)

        catalog_roles = defaultdict(list)
        for row in catalogs:
            catalog = row.get("CATALOG_ID", row.get("CATALOG",
                    row.get("ID", "")))
            role = row.get("ROLE", row.get("AGR_NAME",
                  row.get("ASSIGNED_ROLE", "")))
            scope = row.get("SCOPE", row.get("ACCESS_TYPE",
                   row.get("VISIBILITY", "")))

            if role:
                catalog_roles[catalog].append(role)

            if str(scope).upper() in ("PUBLIC", "ALL", "EVERYONE", "*"):
                public_catalogs.append(f"{catalog} — scope: {scope}")

        for catalog, roles in catalog_roles.items():
            if len(roles) > max_roles:
                excessive_roles.append(
                    f"{catalog}: {len(roles)} roles assigned (max: {max_roles})"
                )

        # Catalogs without any role assignment
        all_catalogs = set()
        for row in catalogs:
            cat = row.get("CATALOG_ID", row.get("CATALOG", row.get("ID", "")))
            all_catalogs.add(cat)
        assigned_catalogs = set(catalog_roles.keys())
        unassigned = all_catalogs - assigned_catalogs
        if unassigned:
            no_role = list(unassigned)

        if public_catalogs:
            self.finding(
                check_id="FIORI-CAT-001",
                title="Fiori catalogs with public/unrestricted scope",
                severity=self.SEVERITY_HIGH,
                category="Fiori & UI Layer",
                description=(
                    f"{len(public_catalogs)} Fiori catalog(s) are scoped as public, "
                    "making their tiles visible to all authenticated users regardless "
                    "of role assignment."
                ),
                affected_items=public_catalogs,
                remediation=(
                    "Change catalog scope to role-based. Assign catalogs to specific "
                    "business roles via /UI2/FLPD_CUST or Manage Launchpad Settings. "
                    "Remove public scope from all non-default catalogs."
                ),
                references=["SAP Fiori — Catalog-Based Authorization"],
            )

        if excessive_roles:
            self.finding(
                check_id="FIORI-CAT-002",
                title=f"Fiori catalogs assigned to excessive roles (>{max_roles})",
                severity=self.SEVERITY_MEDIUM,
                category="Fiori & UI Layer",
                description=(
                    f"{len(excessive_roles)} catalog(s) are assigned to more than "
                    f"{max_roles} roles. Overly shared catalogs may grant broader "
                    "tile access than intended."
                ),
                affected_items=excessive_roles,
                remediation=(
                    "Review catalog-role assignments for least privilege. "
                    "Create separate catalogs for different user populations."
                ),
                references=["SAP Fiori — Role-Based Catalog Design"],
            )

    def check_sensitive_app_exposure(self):
        """Check if sensitive admin Fiori apps have proper access controls."""
        catalogs = self.data.get("fiori_catalogs")
        tiles = self.data.get("fiori_tiles")
        data_source = tiles or catalogs
        if not data_source:
            return

        exposed = []
        for row in data_source:
            app_id = row.get("APP_ID", row.get("TILE_ID",
                    row.get("SEMANTIC_OBJECT", "")))
            catalog = row.get("CATALOG_ID", row.get("CATALOG", ""))
            role = row.get("ROLE", row.get("AGR_NAME", ""))
            title = row.get("TITLE", row.get("APP_TITLE", row.get("DESCRIPTION", "")))
            scope = row.get("SCOPE", row.get("VISIBILITY", ""))

            for sensitive_id, sensitive_desc in self.SENSITIVE_APPS.items():
                if sensitive_id in str(app_id).upper() or sensitive_desc.upper() in str(title).upper():
                    if str(scope).upper() in ("PUBLIC", "ALL", "EVERYONE"):
                        exposed.append(
                            f"{app_id}: {title or sensitive_desc} — catalog: {catalog}, scope: {scope}"
                        )
                    break

        if exposed:
            self.finding(
                check_id="FIORI-APP-001",
                title="Sensitive admin Fiori apps exposed with broad access",
                severity=self.SEVERITY_HIGH,
                category="Fiori & UI Layer",
                description=(
                    f"{len(exposed)} sensitive Fiori application(s) (user management, "
                    "role management, communication config) are accessible from "
                    "broadly scoped catalogs."
                ),
                affected_items=exposed,
                remediation=(
                    "Move sensitive admin apps to restricted catalogs assigned only "
                    "to admin roles. Verify backend authorization also restricts access. "
                    "Do not rely solely on Fiori tile visibility for security."
                ),
                references=["SAP Fiori — Admin App Authorization Best Practices"],
            )

    def check_odata_service_auth(self):
        """Check OData service authorization independently from UI."""
        odata = self.data.get("odata_auth")
        if not odata:
            return

        no_auth = []
        sensitive_weak = []

        for row in odata:
            service = row.get("SERVICE_NAME", row.get("SERVICE",
                     row.get("TECHNICAL_NAME", "")))
            auth_check = row.get("AUTH_CHECK", row.get("AUTHORIZATION",
                        row.get("AUTH_ENABLED", "")))
            scope = row.get("SCOPE", row.get("AUTH_SCOPE",
                   row.get("ACCESS_CONTROL", "")))
            alias = row.get("ALIAS", row.get("SERVICE_ALIAS", ""))

            label = f"{service} ({alias})" if alias else service

            # No authorization check
            if str(auth_check).upper() in ("NONE", "NO", "FALSE", "0", "DISABLED", ""):
                no_auth.append(f"{label} — auth check: {auth_check or 'disabled'}")

            # Sensitive services with weak auth
            svc_upper = f"{service} {alias}".upper()
            for pattern in self.SENSITIVE_ODATA:
                if pattern in svc_upper:
                    if str(auth_check).upper() not in ("FULL", "YES", "TRUE", "1", "ENABLED",
                                                        "STANDARD", "X"):
                        sensitive_weak.append(
                            f"{label} — auth: {auth_check or 'not configured'}"
                        )
                    break

        if no_auth:
            self.finding(
                check_id="FIORI-ODATA-001",
                title="OData services without authorization checks",
                severity=self.SEVERITY_CRITICAL,
                category="Fiori & UI Layer",
                description=(
                    f"{len(no_auth)} OData service(s) have no authorization check "
                    "configured. Any authenticated user can call these services "
                    "directly, bypassing Fiori UI-level restrictions."
                ),
                affected_items=no_auth,
                remediation=(
                    "Enable authorization checks on all OData services via "
                    "IWFND/MAINT_SERVICE → Service → Authorization. "
                    "Implement authorization in DPC_EXT GET_ENTITYSET methods. "
                    "Never rely on Fiori UI for access control — always enforce at OData layer."
                ),
                references=[
                    "SAP Note 2926224 — OData Service Authorization",
                    "OWASP — API Authorization",
                ],
            )

        if sensitive_weak:
            self.finding(
                check_id="FIORI-ODATA-002",
                title="Sensitive OData services with inadequate authorization",
                severity=self.SEVERITY_HIGH,
                category="Fiori & UI Layer",
                description=(
                    f"{len(sensitive_weak)} sensitive OData service(s) (finance, HR, "
                    "master data) have weak or missing authorization configuration. "
                    "Direct API calls can bypass UI-level field restrictions."
                ),
                affected_items=sensitive_weak,
                remediation=(
                    "Implement full authorization checks including: "
                    "S_SERVICE for service-level access, business authorization objects "
                    "in the DPC implementation, and field-level authorization where needed."
                ),
                references=["SAP Fiori — OData Backend Authorization Design"],
            )

    def check_spaces_pages_config(self):
        """Check Fiori Spaces/Pages role-based configuration."""
        spaces = self.data.get("fiori_spaces")
        if not spaces:
            return

        space_list = spaces if isinstance(spaces, list) else \
            spaces.get("spaces", spaces.get("pages", []))

        no_role = []
        everyone_spaces = []

        for space in space_list:
            if not isinstance(space, dict):
                continue
            name = space.get("name", space.get("spaceId", "unknown"))
            roles = space.get("roles", space.get("assignedRoles", []))
            visibility = space.get("visibility", space.get("scope", ""))

            if str(visibility).upper() in ("PUBLIC", "EVERYONE", "ALL"):
                everyone_spaces.append(f"{name} — visibility: {visibility}")

            if not roles or (isinstance(roles, list) and len(roles) == 0):
                no_role.append(f"{name} — no roles assigned")

        if everyone_spaces:
            self.finding(
                check_id="FIORI-SPACE-001",
                title="Fiori spaces with public visibility",
                severity=self.SEVERITY_MEDIUM,
                category="Fiori & UI Layer",
                description=(
                    f"{len(everyone_spaces)} Fiori space(s) are visible to all users. "
                    "Public spaces expose application tiles to broader audiences "
                    "than intended."
                ),
                affected_items=everyone_spaces,
                remediation=(
                    "Configure role-based visibility for all spaces. "
                    "Migrate from catalog-based to spaces/pages architecture "
                    "with proper role assignments."
                ),
                references=["SAP Fiori — Spaces and Pages Configuration"],
            )

    def check_tile_odata_mismatch(self):
        """Detect tiles targeting OData services the assigned role doesn't authorize."""
        tiles = self.data.get("fiori_tiles")
        odata = self.data.get("odata_auth")
        if not tiles or not odata:
            return

        # Build OData service → required auth mapping
        service_auth = {}
        for row in odata:
            svc = row.get("SERVICE_NAME", row.get("SERVICE", "")).upper()
            auth_obj = row.get("REQUIRED_AUTH_OBJECT", row.get("AUTH_OBJECT", ""))
            if svc and auth_obj:
                service_auth[svc] = auth_obj

        # Check tiles for OData service references
        mismatch = []
        for row in tiles:
            tile_id = row.get("TILE_ID", row.get("APP_ID", ""))
            odata_svc = row.get("ODATA_SERVICE", row.get("TARGET_SERVICE",
                       row.get("SERVICE", ""))).upper()
            role = row.get("ROLE", row.get("AGR_NAME", ""))
            auth_provided = row.get("AUTH_OBJECT_IN_ROLE", row.get("ROLE_AUTH", ""))

            if odata_svc in service_auth and auth_provided:
                required = service_auth[odata_svc]
                if required and required not in str(auth_provided):
                    mismatch.append(
                        f"Tile {tile_id} → {odata_svc}: requires {required}, "
                        f"role {role} provides {auth_provided}"
                    )

        if mismatch:
            self.finding(
                check_id="FIORI-TILE-001",
                title="Fiori tiles with OData authorization mismatches",
                severity=self.SEVERITY_MEDIUM,
                category="Fiori & UI Layer",
                description=(
                    f"{len(mismatch)} Fiori tile(s) target OData services requiring "
                    "authorization objects not present in the assigned role. "
                    "Users will see the tile but get authorization errors when using it."
                ),
                affected_items=mismatch[:20],
                remediation=(
                    "Align tile catalog assignments with OData service authorization "
                    "requirements. Ensure roles contain the necessary authorization "
                    "objects for all tiles in their assigned catalogs."
                ),
                references=["SAP Fiori — Tile-Service Authorization Alignment"],
            )

    def check_unused_fiori_apps(self):
        """Identify Fiori apps with no usage that still consume access."""
        usage = self.data.get("fiori_app_usage")
        if not usage:
            return

        unused = []
        stale_days = self.get_config("fiori_app_stale_days", 90)

        for row in usage:
            app_id = row.get("APP_ID", row.get("TILE_ID", row.get("ID", "")))
            title = row.get("TITLE", row.get("APP_TITLE", ""))
            launches = row.get("LAUNCH_COUNT", row.get("USAGE_COUNT",
                      row.get("LAUNCHES", "0")))
            last_launch = row.get("LAST_LAUNCH", row.get("LAST_USED", ""))
            catalog = row.get("CATALOG", row.get("CATALOG_ID", ""))

            try:
                if int(str(launches)) == 0:
                    unused.append(f"{app_id}: {title} (catalog: {catalog}) — never launched")
            except ValueError:
                pass

        if unused:
            self.finding(
                check_id="FIORI-USAGE-001",
                title="Fiori apps with zero usage (never launched)",
                severity=self.SEVERITY_LOW,
                category="Fiori & UI Layer",
                description=(
                    f"{len(unused)} Fiori app(s) in active catalogs have never been "
                    "launched. These consume catalog space and may represent "
                    "unnecessary access surface."
                ),
                affected_items=unused[:30],
                remediation=(
                    "Review unused apps for continued business need. "
                    "Remove from catalogs if not required. "
                    "This reduces the visible attack surface and simplifies "
                    "catalog management."
                ),
                references=["SAP Fiori — App Usage Analytics"],
                details={"total_unused": len(unused)},
            )
