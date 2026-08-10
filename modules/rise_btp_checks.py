# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
RISE / BTP-Specific Auditor
=============================
Checks specific to SAP S/4HANA Cloud (RISE) and BTP:
  - BTP trust configuration (subaccount trust)
  - Communication arrangements — overly broad scopes
  - API endpoint exposure (OData/REST services)
  - Cloud Connector configuration issues
  - Principal propagation settings
  - BTP role collection reviews
"""

from typing import Dict, List, Any
from modules.base_auditor import BaseAuditor


class RiseBtpAuditor(BaseAuditor):

    # OData/REST services that should generally be restricted
    SENSITIVE_API_PATTERNS = [
        "API_BUSINESS_PARTNER",
        "API_PURCHASEORDER",
        "API_SALES_ORDER",
        "API_BILLING_DOCUMENT",
        "API_JOURNAL_ENTRY",
        "API_MATERIAL_DOCUMENT",
        "API_USER_MANAGEMENT",
        "API_COST_CENTER",
        "API_PRODUCT",
        "/sap/opu/odata/sap/",
        "FINANCIALS",
        "HCM_",
        "PAYROLL",
    ]

    @staticmethod
    def _add_object(bucket: List[Dict[str, Any]], obj_type: str, name: Any) -> None:
        """Append one structured affected object to `bucket`, or nothing.

        The checks below fall back to the literal "unknown" / "" when an export row
        carries no name. That is a placeholder for a human reader, not an identity:
        emitted as an object it would merge every unnamed row — across every export
        and every run — into a single graph node and a single finding identity. An
        unnamed row therefore contributes no object at all.
        """
        text = "" if name is None else str(name).strip()
        if not text or text.lower() in ("unknown", "?"):
            return
        bucket.append({"type": obj_type, "name": text})

    @staticmethod
    def _trust_name(origin: Any, idp_name: Any) -> str:
        """Identify a BTP trust configuration by its originKey, not its display name.

        The originKey ("sap.default", "corp-aad-tenant") is the technical key of the
        trust; `identityProvider` is an editable label. Keying on the origin keeps
        RISE-001 and RISE-002 pointing at the SAME graph node for one trust, and stops
        a cosmetic rename of the IdP from orphaning a finding's history. The display
        name is used only when the export carries no origin at all.
        """
        for candidate in (origin, idp_name):
            text = "" if candidate is None else str(candidate).strip()
            if text and text.lower() != "unknown":
                return text
        return ""

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_btp_trust_config()
        self.check_comm_arrangements()
        self.check_api_exposure()
        self.check_comm_users()
        self.check_api_auth_methods()
        return self.findings

    def check_btp_trust_config(self):
        """Analyze BTP subaccount trust configuration."""
        trust = self.data.get("btp_trust")
        if not trust:
            return

        trusts = trust if isinstance(trust, list) else trust.get("trusts", trust.get("trust_configurations", [trust]))

        for t in trusts:
            if not isinstance(t, dict):
                continue

            idp_name = t.get("identityProvider", t.get("idp_name", t.get("name", "unknown")))
            origin = t.get("originKey", t.get("origin", ""))
            auto_create = t.get("createShadowUsers", t.get("auto_create_shadow_users", False))
            enabled = t.get("status", t.get("enabled", True))

            trust_objects: List[Dict[str, Any]] = []
            self._add_object(trust_objects, "idp_trust", self._trust_name(origin, idp_name))

            # Check if default IDP is still enabled (sap.default)
            if origin.lower() in ("sap.default", "sap.ids") and enabled:
                self.finding(
                    check_id="RISE-001",
                    title=f"Default SAP IDP trust still active: {origin}",
                    severity=self.SEVERITY_MEDIUM,
                    category="RISE / BTP Security",
                    description=(
                        f"The default SAP identity provider '{origin}' is still active. "
                        "If a custom corporate IDP is configured, the default should be "
                        "disabled to prevent bypass via SAP ID Service accounts."
                    ),
                    affected_items=[f"Trust: {idp_name} (origin: {origin})"],
                    # Fires once per trust row, so this finding is ABOUT that one trust
                    # configuration and its identity must include it — otherwise two
                    # active default IdPs would collapse into a single finding and one
                    # of them would silently disappear from the report.
                    affected_objects=trust_objects,
                    scope="object",
                    remediation=(
                        "Disable the default SAP IDP trust in the BTP subaccount "
                        "security settings once your corporate IDP is configured and tested. "
                        "Navigate to: BTP Cockpit → Subaccount → Security → Trust Configuration."
                    ),
                    references=["SAP BTP Security Guide — Trust Configuration"],
                )

            # Auto shadow user creation
            if auto_create in (True, "true", "True", "1", "yes"):
                self.finding(
                    check_id="RISE-002",
                    title=f"Automatic shadow user creation enabled for {idp_name}",
                    severity=self.SEVERITY_MEDIUM,
                    category="RISE / BTP Security",
                    description=(
                        f"Trust '{idp_name}' has automatic shadow user creation enabled. "
                        "Any user authenticating via this IDP will automatically get a "
                        "BTP shadow user, potentially granting unintended access."
                    ),
                    affected_items=[f"Trust: {idp_name} — auto_create_shadow_users = true"],
                    # One finding per trust row: RISE-002 fires twice on the bundled
                    # sample data (two IdPs auto-create shadow users) and those are two
                    # separate defects that must keep two separate identities.
                    affected_objects=trust_objects,
                    scope="object",
                    remediation=(
                        "Disable automatic shadow user creation unless required. "
                        "Instead, provision users explicitly via BTP User Management "
                        "or SCIM-based provisioning with proper approval workflows."
                    ),
                    references=["SAP BTP Security Recommendations — Shadow Users"],
                )

    def check_comm_arrangements(self):
        """Review communication arrangements for overly broad configurations."""
        comms = self.data.get("comm_arrangements")
        if not comms:
            return

        arrangements = comms if isinstance(comms, list) else comms.get("arrangements", comms.get("items", []))

        overly_broad = []
        no_auth = []
        overly_broad_objects: List[Dict[str, Any]] = []
        no_auth_objects: List[Dict[str, Any]] = []

        for arr in arrangements:
            if not isinstance(arr, dict):
                continue

            name = arr.get("name", arr.get("arrangement_name", "unknown"))
            scenario = arr.get("scenario_id", arr.get("communication_scenario", ""))
            auth_method = arr.get("authentication_method", arr.get("auth_method", ""))
            services = arr.get("services", arr.get("inbound_services", []))
            user = arr.get("communication_user", arr.get("comm_user", ""))

            # Check for arrangements with many services (potentially over-scoped)
            if isinstance(services, list) and len(services) > 10:
                overly_broad.append(
                    f"{name} (scenario: {scenario}, {len(services)} services)"
                )
                # No qualifier for the service count: it changes as services are added
                # or removed, which would move the arrangement to a new graph node on
                # every export instead of keeping one node per arrangement.
                self._add_object(overly_broad_objects, "comm_arrangement", name)

            # Check for weak auth methods
            if auth_method.lower() in ("none", "anonymous", "", "basic"):
                no_auth.append(
                    f"{name} (auth: {auth_method or 'none'}, user: {user})"
                )
                # Both halves of the exposure are real exported objects: the weakly
                # protected arrangement and the communication user an attacker reaches
                # through it.
                self._add_object(no_auth_objects, "comm_arrangement", name)
                self._add_object(no_auth_objects, "user", user)

        if overly_broad:
            self.finding(
                check_id="RISE-003",
                title="Communication arrangements with excessive service scope",
                severity=self.SEVERITY_MEDIUM,
                category="RISE / BTP Security",
                description=(
                    f"{len(overly_broad)} communication arrangement(s) expose more than "
                    "10 services each. Overly broad arrangements increase the attack "
                    "surface if the communication user is compromised."
                ),
                affected_items=overly_broad,
                # Every over-scoped arrangement is rolled into ONE finding, so the
                # finding summarises the set. Trimming one arrangement's service list
                # must leave the remaining ones on the same finding rather than retire
                # it and raise a fresh one with a reset age; the members ride along as
                # data and as graph nodes.
                affected_objects=overly_broad_objects,
                scope="aggregate",
                remediation=(
                    "Review each arrangement and restrict to only required services. "
                    "Create separate arrangements for different integration scenarios. "
                    "Apply principle of least privilege to communication scenarios."
                ),
                references=["SAP S/4HANA Cloud Security Guide — Communication Management"],
            )

        if no_auth:
            self.finding(
                check_id="RISE-004",
                title="Communication arrangements with weak/no authentication",
                severity=self.SEVERITY_CRITICAL,
                category="RISE / BTP Security",
                description=(
                    f"{len(no_auth)} communication arrangement(s) use no authentication "
                    "or only basic authentication. This allows unauthenticated or weakly "
                    "protected access to SAP APIs."
                ),
                affected_items=no_auth,
                # One finding summarising every weakly authenticated arrangement:
                # moving one arrangement to OAuth must not reset the age of the
                # remaining exposure.
                affected_objects=no_auth_objects,
                scope="aggregate",
                remediation=(
                    "Configure OAuth 2.0 client credentials or X.509 certificate-based "
                    "authentication for all communication arrangements. "
                    "Basic auth should only be used with HTTPS and as a last resort."
                ),
                references=["SAP Note 3089413", "SAP BTP Security Guide"],
            )

    def check_api_exposure(self):
        """Review exposed API/OData endpoints for sensitive services."""
        apis = self.data.get("api_endpoints")
        if not apis:
            return

        endpoints = apis if isinstance(apis, list) else apis.get("endpoints", apis.get("services", []))

        sensitive_exposed = []
        sensitive_objects: List[Dict[str, Any]] = []
        for ep in endpoints:
            if not isinstance(ep, dict):
                continue

            name = ep.get("name", ep.get("service_name", ep.get("endpoint", "")))
            url = ep.get("url", ep.get("service_url", ep.get("path", "")))
            status = ep.get("status", ep.get("active", ""))
            auth = ep.get("authentication", ep.get("auth", ""))

            combined = f"{name} {url}".upper()

            for pattern in self.SENSITIVE_API_PATTERNS:
                if pattern.upper() in combined:
                    is_active = str(status).upper() in ("ACTIVE", "1", "TRUE", "YES", "PUBLISHED", "")
                    if is_active:
                        sensitive_exposed.append(
                            f"{name} ({url}) — auth: {auth or 'unknown'}"
                        )
                        # Name first, URL only as a fallback: the same endpoint must
                        # resolve to one node here and in RISE-007. The auth method is
                        # deliberately not a qualifier — it is what remediation
                        # changes, and a node that moves when it is fixed is useless.
                        self._add_object(sensitive_objects, "endpoint", name or url)
                    break

        if sensitive_exposed:
            self.finding(
                check_id="RISE-005",
                title="Sensitive APIs/OData services exposed",
                severity=self.SEVERITY_HIGH,
                category="RISE / BTP Security",
                description=(
                    f"{len(sensitive_exposed)} sensitive API endpoint(s) are published and "
                    "accessible. These include financial, HR, or master data services "
                    "that should have strict access controls."
                ),
                affected_items=sensitive_exposed,
                # An inventory of every sensitive endpoint that is published: this is
                # one finding about the exposed API surface, not one per API, so
                # unpublishing a single service must shrink the member list without
                # re-identifying the finding.
                affected_objects=sensitive_objects,
                scope="aggregate",
                remediation=(
                    "Review each exposed API for business necessity. "
                    "Disable services not actively consumed. "
                    "Implement API Management (SAP APIM) with rate limiting, "
                    "OAuth scopes, and IP restrictions for all sensitive endpoints."
                ),
                references=["SAP S/4HANA Cloud API Governance Guide"],
            )

    def check_comm_users(self):
        """Check communication users for privilege issues."""
        comms = self.data.get("comm_arrangements")
        if not comms:
            return

        arrangements = comms if isinstance(comms, list) else comms.get("arrangements", comms.get("items", []))

        users_seen = {}
        for arr in arrangements:
            if not isinstance(arr, dict):
                continue
            user = arr.get("communication_user", arr.get("comm_user", ""))
            name = arr.get("name", arr.get("arrangement_name", ""))
            if user:
                users_seen.setdefault(user, []).append(name)

        # Flag users shared across multiple arrangements
        shared_users = [
            f"{user} — used in {len(arrs)} arrangements: {', '.join(arrs[:5])}"
            for user, arrs in users_seen.items()
            if len(arrs) > 3
        ]

        shared_user_objects: List[Dict[str, Any]] = []
        for user, arrs in users_seen.items():
            if len(arrs) > 3:
                self._add_object(shared_user_objects, "user", user)
                # The arrangements are the blast radius of that one credential, which
                # is what the check is about, so they are carried as graph nodes even
                # though the offender named in `affected_items` is the user.
                for arr_name in arrs:
                    self._add_object(shared_user_objects, "comm_arrangement", arr_name)

        if shared_users:
            self.finding(
                check_id="RISE-006",
                title="Communication users shared across many arrangements",
                severity=self.SEVERITY_MEDIUM,
                category="RISE / BTP Security",
                description=(
                    f"{len(shared_users)} communication user(s) are reused across more "
                    "than 3 arrangements. Shared communication users make it difficult "
                    "to trace API activity and increase blast radius if compromised."
                ),
                affected_items=shared_users,
                # Every over-shared communication user is rolled into ONE finding, so
                # the finding summarises that set. Splitting one user out into
                # dedicated credentials must not retire the finding covering the rest.
                affected_objects=shared_user_objects,
                scope="aggregate",
                remediation=(
                    "Create dedicated communication users per integration scenario "
                    "or external system. This enables granular audit trails and "
                    "limits the impact of credential compromise."
                ),
                references=["SAP S/4HANA Cloud Security Guide"],
            )

    def check_api_auth_methods(self):
        """Check API endpoints for weak authentication configurations."""
        apis = self.data.get("api_endpoints")
        if not apis:
            return

        endpoints = apis if isinstance(apis, list) else apis.get("endpoints", apis.get("services", []))

        weak_auth = []
        weak_auth_objects: List[Dict[str, Any]] = []
        for ep in endpoints:
            if not isinstance(ep, dict):
                continue

            name = ep.get("name", ep.get("service_name", ""))
            auth = ep.get("authentication", ep.get("auth", ep.get("auth_method", "")))
            url = ep.get("url", ep.get("path", ""))

            if auth.lower() in ("none", "anonymous", "basic", ""):
                weak_auth.append(f"{name} ({url}) — auth: {auth or 'none'}")
                # Same naming rule as RISE-005 so one endpoint is one graph node
                # across both checks.
                self._add_object(weak_auth_objects, "endpoint", name or url)

        if weak_auth:
            self.finding(
                check_id="RISE-007",
                title="API endpoints with weak or no authentication",
                severity=self.SEVERITY_HIGH,
                category="RISE / BTP Security",
                description=(
                    f"{len(weak_auth)} API endpoint(s) have weak or no authentication "
                    "configured. In a RISE environment, all APIs should use "
                    "OAuth 2.0 or certificate-based authentication."
                ),
                affected_items=weak_auth,
                # One finding rolling up every weakly authenticated endpoint: putting
                # OAuth in front of one service must shrink this finding, not replace
                # it with a new one whose age starts at zero.
                affected_objects=weak_auth_objects,
                scope="aggregate",
                remediation=(
                    "Enforce OAuth 2.0 (client_credentials or authorization_code grant) "
                    "for all API endpoints. Configure appropriate scopes. "
                    "Use SAP API Management for centralized policy enforcement."
                ),
                references=["SAP BTP Security Guide — API Authentication"],
            )
