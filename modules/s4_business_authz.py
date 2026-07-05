"""
S/4HANA & Cloud Authorization Auditor
=======================================
The cloud-era authorization layer that sits between the classic ABAP checks and
BTP: S/4HANA business roles / catalogs / restrictions, CDS access-control,
OData V4, Cloud Connector principal propagation, and Cloud Foundry platform roles.

Covers:
  - Super-admin business-role templates (SAP_BR_ADMINISTRATOR …) in production
  - Business-role restriction fields left 'Unrestricted' (esp. Write)
  - Business roles bundling an excessive number of business catalogs
  - CDS views exposed with authorization checking disabled
  - OData V4 service groups published without matching authorization
  - Cloud Connector system mappings without principal propagation
  - Cloud Foundry Org Manager / Space Developer over-assignment
  - Birthright role collections auto-granted to all federated users

Data sources:
  - business_roles.csv             → business-role assignments (USER, BUSINESS_ROLE)
  - business_role_restrictions.csv → role restriction fields (ROLE, TYPE, ACCESS/VALUE)
  - business_role_catalogs.csv     → assigned business catalogs (ROLE, CATALOG)
  - cds_views.csv                  → CDS view auth annotations (VIEW, AUTH_CHECK, EXPOSED)
  - odata_v4_services.csv          → /IWFND/V4_ADMIN service groups
  - cloud_connector.json           → SCC system mappings (principalType)
  - cf_roles.csv                   → Cloud Foundry org/space role assignments
  - btp_role_collection_mappings.csv → role-collection → IdP-group mappings
"""

from typing import Dict, List, Any
from modules.base_auditor import BaseAuditor


class S4BusinessAuthzAuditor(BaseAuditor):

    CATEGORY = "S/4HANA & Cloud Authorization"

    # SAP-delivered broad-administrator business-role templates (initial-setup only).
    # SAP_BR_ADMINISTRATOR = system administrator; SAP_BR_ADMINISTRATOR_MDG = MDG-domain
    # administrator (broad within Master Data Governance). (SAP_BR_BPC_EXPERT is a powerful
    # *configuration* template, not an administrator, so it is intentionally NOT listed here.)
    SUPERADMIN_ROLES = {"SAP_BR_ADMINISTRATOR", "SAP_BR_ADMINISTRATOR_MDG"}
    # Restriction types where 'Unrestricted' is especially dangerous.
    SENSITIVE_RESTRICTIONS = {
        "COMPANY CODE", "COST CENTER", "CONTROLLING AREA", "SALES ORGANIZATION",
        "PROFIT CENTER", "PLANT", "PURCHASING ORGANIZATION", "WRITE", "VALUE HELP",
    }
    CF_PRIVILEGED_ROLES = {"ORG MANAGER", "SPACE MANAGER", "SPACE DEVELOPER",
                           "ORGMANAGER", "SPACEMANAGER", "SPACEDEVELOPER"}

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_superadmin_business_role()
        self.check_unrestricted_restrictions()
        self.check_catalog_sprawl()
        self.check_cds_auth_disabled()
        self.check_odata_v4_unprotected()
        self.check_cloud_connector_principal()
        self.check_cf_platform_roles()
        self.check_birthright_role_collection()
        return self.findings

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _get(row: dict, *names: str) -> str:
        low = {str(k).strip().upper(): v for k, v in row.items()}
        for n in names:
            v = low.get(n.upper())
            if v not in (None, ""):
                return str(v).strip()
        return ""

    @staticmethod
    def _rows(data) -> list:
        return [r for r in (data or []) if isinstance(r, dict)]

    # --------------------------------------------------------------------- checks
    def check_superadmin_business_role(self):
        rows = self.data.get("business_roles")
        if not rows:
            return
        offenders = []
        for row in self._rows(rows):
            role = self._get(row, "BUSINESS_ROLE", "ROLE", "AGR_NAME", "ROLE_ID").upper()
            user = self._get(row, "USER", "USER_ID", "BNAME", "USERNAME")
            if role in self.SUPERADMIN_ROLES:
                offenders.append(f"{user or '?'} ← {role}")
        if offenders:
            self.finding(
                check_id="S4AUTHZ-001",
                title="Super-admin business role template assigned in production",
                severity=self.SEVERITY_CRITICAL,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} assignment(s) of a super-admin business-role template "
                    "(SAP_BR_ADMINISTRATOR and siblings). SAP delivers these ONLY for initial "
                    "system setup; assigned to a business user they grant near-complete "
                    "administrative access to the S/4HANA system."
                ),
                affected_items=offenders,
                remediation=(
                    "Remove SAP_BR_ADMINISTRATOR* from business users. Build purpose-specific "
                    "administrator business roles with the minimum catalogs and restricted "
                    "values needed, under least privilege."
                ),
                references=["SAP KBA 3363028 — SAP_BR_ADMINISTRATOR is an initial-setup "
                            "template (not transportable)",
                            "SAP S/4HANA Cloud — Identity & Access Management"],
            )

    def check_unrestricted_restrictions(self):
        rows = self.data.get("business_role_restrictions")
        if not rows:
            return
        offenders = []
        for row in self._rows(rows):
            role = self._get(row, "ROLE", "BUSINESS_ROLE", "ROLE_ID")
            rtype = self._get(row, "RESTRICTION_TYPE", "TYPE", "FIELD", "RESTRICTION").upper()
            access = self._get(row, "ACCESS", "VALUE", "RESTRICTION_VALUE", "SETTING").upper()
            write = self._get(row, "WRITE", "WRITE_ACCESS").upper()
            unrestricted = access in ("UNRESTRICTED", "*", "ALL") or write == "UNRESTRICTED"
            if unrestricted and (rtype in self.SENSITIVE_RESTRICTIONS or "WRITE" in access or write):
                offenders.append(f"{role or '?'} — {rtype or 'restriction'}: Unrestricted")
        if offenders:
            self.finding(
                check_id="S4AUTHZ-002",
                title="Business-role restriction left 'Unrestricted'",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} business-role restriction field(s) on sensitive "
                    "restriction types (company code, cost/profit center, sales org, or generic "
                    "Write access) are set to 'Unrestricted' rather than scoped to specific "
                    "organizational values — the cloud equivalent of a '*' on an org level."
                ),
                affected_items=offenders,
                remediation=(
                    "Set explicit value ranges for each restriction type in the business role "
                    "(Maintain Business Roles → Restrictions); reserve 'Unrestricted' Write for "
                    "genuine cross-organization roles that are separately governed."
                ),
                references=["SAP S/4HANA Cloud — Business Role Restrictions"],
            )

    def check_catalog_sprawl(self):
        rows = self.data.get("business_role_catalogs")
        if not rows:
            return
        threshold = self.get_config("max_business_catalogs", 30)
        by_role: Dict[str, int] = {}
        for row in self._rows(rows):
            role = self._get(row, "ROLE", "BUSINESS_ROLE", "ROLE_ID")
            if role:
                by_role[role] = by_role.get(role, 0) + 1
        offenders = [f"{r} — {n} business catalogs" for r, n in by_role.items() if n > threshold]
        if offenders:
            self.finding(
                check_id="S4AUTHZ-003",
                title=f"Business role bundles more than {threshold} business catalogs",
                severity=self.SEVERITY_MEDIUM,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} business role(s) bundle more than {threshold} business "
                    "catalogs. Very broad, catalog-heavy roles over-provision access and make "
                    "segregation-of-duties review and recertification difficult."
                ),
                affected_items=offenders,
                remediation=(
                    "Split over-broad roles into smaller task-based business roles; review the "
                    "catalog list against the role's job function."
                ),
                references=["SAP S/4HANA Cloud — Business Role design best practices"],
            )

    def check_cds_auth_disabled(self):
        rows = self.data.get("cds_views")
        if not rows:
            return
        offenders = []
        for row in self._rows(rows):
            view = self._get(row, "VIEW", "CDS_VIEW", "NAME", "DDLNAME", "ENTITY")
            authchk = self._get(row, "AUTH_CHECK", "AUTHORIZATION_CHECK", "AUTHORIZATIONCHECK",
                                "ACCESSCONTROL").upper()
            exposed = self._get(row, "EXPOSED", "OData", "SERVICE", "RELEASED", "C1_CONTRACT")
            disabled = "NOT_REQUIRED" in authchk or "NOT_ALLOWED" in authchk or authchk in ("NONE", "FALSE")
            is_exposed = self._truthy(exposed) or exposed.upper() in ("X", "ODATA", "RELEASED", "TRUE")
            if disabled and (is_exposed or exposed == ""):
                offenders.append(f"{view or '?'} — @AccessControl.authorizationCheck: {authchk or 'disabled'}"
                                 + (" (exposed)" if is_exposed else ""))
        if offenders:
            self.finding(
                check_id="S4AUTHZ-004",
                title="CDS view exposes data with authorization checking disabled",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} CDS view(s) carry @AccessControl.authorizationCheck "
                    "#NOT_REQUIRED / #NOT_ALLOWED, so DCL access controls are not evaluated. If "
                    "the view is exposed (OData / service binding / released C1) this returns "
                    "data with no row-level authorization enforcement."
                ),
                affected_items=offenders,
                remediation=(
                    "Set @AccessControl.authorizationCheck: #CHECK (or #MANDATORY) and provide a "
                    "DCL access-control that enforces the intended restrictions, unless the view "
                    "is provably non-sensitive."
                ),
                references=["SAP Help — CDS Access Control (DCL) / @AccessControl.authorizationCheck"],
            )

    def check_odata_v4_unprotected(self):
        rows = self.data.get("odata_v4_services")
        if not rows:
            return
        offenders = []
        for row in self._rows(rows):
            grp = self._get(row, "SERVICE_GROUP", "SERVICEGROUP", "SERVICE", "NAME")
            published = self._get(row, "PUBLISHED", "STATUS", "STATE")
            alias = self._get(row, "SYSTEM_ALIAS", "ALIAS")
            auth = self._get(row, "AUTH", "AUTHORIZATION", "S_SERVICE", "PROTECTED")
            is_published = self._truthy(published) or published.upper() in ("PUBLISHED", "ACTIVE", "X")
            no_auth = auth == "" or auth.upper() in ("NONE", "NO", "0", "FALSE", "PUBLIC")
            if is_published and no_auth:
                offenders.append(f"{grp or '?'} (alias {alias or '?'}) — published, no S_SERVICE authorization")
        if offenders:
            self.finding(
                check_id="S4AUTHZ-005",
                title="OData V4 service group published without authorization",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} OData V4 service group(s) are published (/IWFND/V4_ADMIN) "
                    "with a productive system alias but no matching S_SERVICE authorization. "
                    "OData V4 is a common audit blind spot — a published, unauthorized service "
                    "group exposes its entity sets to any authenticated user."
                ),
                affected_items=offenders,
                remediation=(
                    "Restrict each published V4 service group with S_SERVICE and grant it only "
                    "through the business roles that need it; unpublish unused service groups."
                ),
                references=["SAP Help — OData V4 Service Groups (/IWFND/V4_ADMIN)"],
            )

    def check_cloud_connector_principal(self):
        cc = self.data.get("cloud_connector")
        if not cc:
            return
        mappings = []
        if isinstance(cc, dict):
            mappings = (cc.get("systemMappings") or cc.get("system_mappings")
                        or cc.get("mappings") or cc.get("backends") or [])
        elif isinstance(cc, list):
            mappings = cc
        offenders = []
        for m in mappings:
            if not isinstance(m, dict):
                continue
            backend = (m.get("virtualHost") or m.get("virtual_host") or m.get("backend")
                       or m.get("name") or "?")
            ptype = str(m.get("principalType") or m.get("principal_type")
                        or m.get("principalPropagation") or "").strip().lower()
            protocol = str(m.get("protocol") or m.get("type") or "").strip().lower()
            # flag only an EXPLICIT 'None' on an HTTP(S) mapping (absent = unknown, not flagged)
            if ("http" in protocol or protocol == "") and ptype in ("none", "no", "false"):
                offenders.append(f"{backend} — principalType: None (no principal propagation)")
        if offenders:
            self.finding(
                check_id="S4AUTHZ-006",
                title="Cloud Connector system mapping without principal propagation",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} Cloud Connector HTTPS system mapping(s) have Principal "
                    "Type 'None' instead of X.509 principal propagation. The connector then "
                    "reaches the S/4 backend as a shared technical user, losing end-user "
                    "attribution and letting any BTP app user act with that technical user's "
                    "authorizations."
                ),
                affected_items=offenders,
                remediation=(
                    "Configure X.509 principal propagation for HTTPS backend mappings so the "
                    "end user's identity flows to the backend, and remove any shared "
                    "technical-user fallback."
                ),
                references=["SAP Help — Cloud Connector Principal Propagation"],
            )

    def check_cf_platform_roles(self):
        rows = self.data.get("cf_roles")
        if not rows:
            return
        threshold = self.get_config("max_cf_privileged_users", 5)
        counts: Dict[str, list] = {}
        for row in self._rows(rows):
            user = self._get(row, "USER", "USERNAME", "USER_ID", "EMAIL")
            role = self._get(row, "ROLE", "ROLE_TYPE", "CF_ROLE").upper().replace("_", " ")
            scope = self._get(row, "SPACE", "ORG", "SCOPE", "ORGANIZATION")
            if role.replace(" ", "") in self.CF_PRIVILEGED_ROLES or role in self.CF_PRIVILEGED_ROLES:
                key = f"{role}"
                counts.setdefault(key, []).append(f"{user or '?'}@{scope or '?'}")
        offenders = []
        for role, users in counts.items():
            if len(users) > threshold:
                offenders.append(f"{role}: {len(users)} assignments (> {threshold})")
        if offenders:
            self.finding(
                check_id="S4AUTHZ-007",
                title="Cloud Foundry privileged platform role over-assigned",
                severity=self.SEVERITY_HIGH,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} Cloud Foundry platform role(s) (Org Manager / Space "
                    f"Manager / Space Developer) are assigned to more than {threshold} users. "
                    "Space Developer permits app deployment (code execution in the space); these "
                    "platform roles are separate from application role collections and are often "
                    "missed in access reviews."
                ),
                affected_items=offenders,
                remediation=(
                    "Reduce Org Manager / Space Developer to the minimum operators; use CI/CD "
                    "technical users for deployment rather than broad human Space Developer grants."
                ),
                references=["SAP BTP — Cloud Foundry Org & Space roles"],
            )

    def check_birthright_role_collection(self):
        rows = self.data.get("btp_role_collection_mappings")
        if not rows:
            return
        offenders = []
        for row in self._rows(rows):
            rc = self._get(row, "ROLE_COLLECTION", "ROLECOLLECTION", "COLLECTION", "NAME")
            group = self._get(row, "IDP_GROUP", "GROUP", "MAPPED_GROUP", "ATTRIBUTE_VALUE")
            gl = group.lower()
            if gl in ("default", "*", "all", "authenticated", "everyone") or "default" in gl or group == "*":
                offenders.append(f"{rc or '?'} ← IdP group '{group}' (auto-granted to all federated users)")
        if offenders:
            self.finding(
                check_id="S4AUTHZ-008",
                title="Birthright role collection auto-granted to all federated users",
                severity=self.SEVERITY_MEDIUM,
                category=self.CATEGORY,
                description=(
                    f"{len(offenders)} BTP role collection(s) are mapped to a 'Default' / "
                    "wildcard IdP group, so every user who authenticates via the corporate IdP "
                    "receives them automatically (birthright access). If the collection carries "
                    "more than baseline access this over-provisions the whole user base."
                ),
                affected_items=offenders,
                remediation=(
                    "Map role collections to specific IdP groups, not the Default group. Keep "
                    "only genuinely universal, low-privilege access as a default assignment."
                ),
                references=["SAP BTP — Role Collections & Trust Configuration (default groups)"],
            )

    @staticmethod
    def _truthy(v: Any) -> bool:
        return str(v).strip().lower() in ("1", "true", "yes", "on", "x")
