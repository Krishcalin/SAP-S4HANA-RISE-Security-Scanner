"""
Network & Integration Layer Auditor
======================================
Deep-dive into the integration plumbing between S/4HANA RISE,
BTP, and third-party systems.

Covers:
  - API Management policy enforcement (rate limiting, threat protection, TLS)
  - IDOC port security & partner profile exposure
  - Web service (SOAMANAGER) endpoint configuration
  - Webhook / callback endpoint security
  - RFC callback authorization (gateway reginfo/secinfo deep analysis)
  - Integration monitoring & alerting gaps
  - CPI advanced: adapter security, data store exposure, message logging
  - OAuth client/scope governance across integration landscape
  - Cross-system integration credential inventory
  - Middleware topology exposure (who-talks-to-whom graph)

Data sources:
  - apim_policies.json      → API Management proxy/policy config
  - idoc_ports.csv           → SM58/WE21 IDOC port configuration
  - idoc_partners.csv        → WE20 partner profile export
  - ws_endpoints.csv         → SOAMANAGER web service endpoint list
  - webhooks.json            → Registered webhook/callback endpoints
  - gw_secinfo.csv           → Gateway secinfo ACL rules
  - gw_reginfo.csv           → Gateway reginfo registration rules
  - integration_alerts.json  → Alert Notification / monitoring config
  - cpi_datastores.json      → CPI data store & variables
  - oauth_clients.json       → OAuth client registrations across landscape
  - integration_topology.json → System-to-system integration map
"""

from typing import Dict, List, Any, Set, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
from modules.base_auditor import BaseAuditor


class IntegrationLayerAuditor(BaseAuditor):

    # ── APIM policies that should be present on every proxy ──
    REQUIRED_APIM_POLICIES = {
        "spike_arrest":  "Rate limiting / spike arrest to prevent abuse",
        "quota":         "Usage quota enforcement",
        "verify_api_key": "API key verification for consumer identification",
        "oauth_v2":      "OAuth 2.0 token validation",
        "threat_protection": "JSON/XML threat protection (injection, XXE, oversize)",
        "cors":          "CORS policy to restrict cross-origin access",
    }

    # ── IDOC port types with security implications ──
    RISKY_IDOC_PORT_TYPES = {
        "TRFC": "Transactional RFC — verify SNC and authorization",
        "FILE": "File port — verify filesystem permissions and path restrictions",
        "HTTP": "HTTP port — verify HTTPS and authentication",
        "XML_HTTP": "XML-HTTP port — verify TLS and input validation",
    }

    # ── Web service endpoint security patterns ──
    WS_HIGH_RISK_PATTERNS = [
        "BAPI_USER",       # User management BAPIs exposed as WS
        "BAPI_COMPANYCODE", # Company code access
        "RFC_READ_TABLE",  # Arbitrary table read
        "RFC_SYSTEM_INFO", # System information disclosure
        "SXMB_",           # XI/PI message handling
        "BAPI_ACC_",       # Financial posting
        "BAPI_PAY",        # Payment processing
    ]

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_apim_proxy_policies()
        self.check_apim_tls_enforcement()
        self.check_apim_unprotected_proxies()
        self.check_idoc_port_security()
        self.check_idoc_partner_profiles()
        self.check_ws_endpoint_exposure()
        self.check_ws_authentication()
        self.check_webhook_security()
        self.check_gateway_secinfo()
        self.check_gateway_reginfo()
        self.check_integration_monitoring()
        self.check_cpi_datastores()
        self.check_oauth_client_governance()
        self.check_integration_topology()
        return self.findings

    # ════════════════════════════════════════════════════════════════
    #  INTG-APIM-*: API Management Policy Enforcement
    # ════════════════════════════════════════════════════════════════

    def check_apim_proxy_policies(self):
        """
        Verify API proxies have required security policies:
        rate limiting, threat protection, authentication, CORS.
        """
        apim = self.data.get("apim_policies")
        if not apim:
            return

        proxies = apim if isinstance(apim, list) else \
            apim.get("proxies", apim.get("apiProxies", apim.get("apis", [])))

        missing_policies = []
        no_auth_proxies = []

        for proxy in proxies:
            if not isinstance(proxy, dict):
                continue

            name = proxy.get("name", proxy.get("proxyName", proxy.get("apiName", "unknown")))
            policies = proxy.get("policies", proxy.get("appliedPolicies", []))
            base_path = proxy.get("basePath", proxy.get("path", ""))
            is_active = proxy.get("active", proxy.get("deployed", True))

            if not is_active or str(is_active).lower() in ("false", "0", "no"):
                continue

            # Normalize policy names
            if isinstance(policies, list):
                policy_names = set()
                for p in policies:
                    if isinstance(p, dict):
                        pname = p.get("name", p.get("policyName", p.get("type", ""))).lower()
                    else:
                        pname = str(p).lower()
                    policy_names.add(pname)
            elif isinstance(policies, str):
                policy_names = set(p.strip().lower() for p in policies.split(","))
            else:
                policy_names = set()

            # Check for missing required policies
            proxy_missing = []
            has_auth = False
            for req_key, req_desc in self.REQUIRED_APIM_POLICIES.items():
                key_lower = req_key.lower()
                # Check if any applied policy matches the required one
                found = any(key_lower in pn or pn in key_lower for pn in policy_names)
                if not found:
                    proxy_missing.append(req_key)
                if key_lower in ("oauth_v2", "verify_api_key"):
                    if found:
                        has_auth = True

            if proxy_missing:
                missing_policies.append(
                    f"{name} ({base_path}) — missing: {', '.join(proxy_missing)}"
                )

            if not has_auth:
                no_auth_proxies.append(f"{name} ({base_path}) — no authentication policy")

        if missing_policies:
            self.finding(
                check_id="INTG-APIM-001",
                title="API proxies missing required security policies",
                severity=self.SEVERITY_HIGH,
                category="Network & Integration Layer",
                description=(
                    f"{len(missing_policies)} API proxy/proxies are missing one or more "
                    "required security policies. Without rate limiting, threat protection, "
                    "and authentication, APIs are vulnerable to abuse, injection attacks, "
                    "and unauthorized access."
                ),
                affected_items=missing_policies,
                remediation=(
                    "Apply all required policies to every API proxy: "
                    "spike_arrest (rate limiting), threat_protection (JSON/XML injection), "
                    "oauth_v2 or verify_api_key (authentication), quota (usage limits), "
                    "and cors (cross-origin restriction). "
                    "Use API Management policy templates for consistent enforcement."
                ),
                references=[
                    "SAP API Management — Security Policy Best Practices",
                    "OWASP API Security Top 10",
                ],
            )

        if no_auth_proxies:
            self.finding(
                check_id="INTG-APIM-002",
                title="API proxies without authentication policies",
                severity=self.SEVERITY_CRITICAL,
                category="Network & Integration Layer",
                description=(
                    f"{len(no_auth_proxies)} API proxy/proxies have no authentication "
                    "policy (OAuth 2.0 or API key verification). Unauthenticated APIs "
                    "are fully exposed to any caller."
                ),
                affected_items=no_auth_proxies,
                remediation=(
                    "Add OAuth 2.0 token validation (OAuthV2 policy) or API key "
                    "verification (VerifyAPIKey policy) to every API proxy. "
                    "Prefer OAuth 2.0 for production APIs."
                ),
                references=["OWASP API Security — API2:2023 Broken Authentication"],
            )

    def check_apim_tls_enforcement(self):
        """Check if API proxies enforce TLS and reject HTTP."""
        apim = self.data.get("apim_policies")
        if not apim:
            return

        proxies = apim if isinstance(apim, list) else \
            apim.get("proxies", apim.get("apiProxies", []))

        http_allowed = []
        weak_tls = []

        for proxy in proxies:
            if not isinstance(proxy, dict):
                continue

            name = proxy.get("name", proxy.get("proxyName", "unknown"))
            tls_enforced = proxy.get("tlsEnforced", proxy.get("httpsOnly",
                          proxy.get("requireSSL", "")))
            tls_version = proxy.get("minTlsVersion", proxy.get("tlsVersion",
                         proxy.get("sslProtocol", "")))
            base_path = proxy.get("basePath", proxy.get("path", ""))

            if not tls_enforced or str(tls_enforced).lower() in ("false", "0", "no", ""):
                http_allowed.append(f"{name} ({base_path}) — HTTPS not enforced")

            if tls_version and str(tls_version) in ("1.0", "1.1", "TLSv1", "TLSv1.1"):
                weak_tls.append(
                    f"{name} ({base_path}) — min TLS: {tls_version} (should be 1.2+)"
                )

        if http_allowed:
            self.finding(
                check_id="INTG-APIM-003",
                title="API proxies allowing unencrypted HTTP traffic",
                severity=self.SEVERITY_HIGH,
                category="Network & Integration Layer",
                description=(
                    f"{len(http_allowed)} API proxy/proxies do not enforce HTTPS. "
                    "API traffic over HTTP exposes authentication tokens, business data, "
                    "and credentials to network interception."
                ),
                affected_items=http_allowed,
                remediation=(
                    "Enable HTTPS-only mode on all API proxies. "
                    "Configure virtual hosts to reject HTTP connections. "
                    "Redirect HTTP to HTTPS as a transitional measure."
                ),
                references=["SAP API Management — TLS Configuration"],
            )

        if weak_tls:
            self.finding(
                check_id="INTG-APIM-004",
                title="API proxies allowing deprecated TLS versions",
                severity=self.SEVERITY_HIGH,
                category="Network & Integration Layer",
                description=(
                    f"{len(weak_tls)} API proxy/proxies allow TLS 1.0 or 1.1, which "
                    "are deprecated and have known vulnerabilities (BEAST, POODLE)."
                ),
                affected_items=weak_tls,
                remediation=(
                    "Set minimum TLS version to 1.2 across all API proxies. "
                    "Prefer TLS 1.3 where client compatibility allows. "
                    "Disable TLS 1.0/1.1 at the API Management platform level."
                ),
                references=["NIST SP 800-52 Rev 2 — TLS Guidelines"],
            )

    def check_apim_unprotected_proxies(self):
        """Detect API proxies with no policies at all (pass-through)."""
        apim = self.data.get("apim_policies")
        if not apim:
            return

        proxies = apim if isinstance(apim, list) else \
            apim.get("proxies", apim.get("apiProxies", []))

        passthrough = []
        for proxy in proxies:
            if not isinstance(proxy, dict):
                continue

            name = proxy.get("name", proxy.get("proxyName", "unknown"))
            policies = proxy.get("policies", proxy.get("appliedPolicies", []))
            base_path = proxy.get("basePath", proxy.get("path", ""))
            target = proxy.get("target", proxy.get("targetUrl", ""))

            if not policies or (isinstance(policies, list) and len(policies) == 0):
                passthrough.append(f"{name} ({base_path}) → {target}")

        if passthrough:
            self.finding(
                check_id="INTG-APIM-005",
                title="API proxies operating in pass-through mode (zero policies)",
                severity=self.SEVERITY_CRITICAL,
                category="Network & Integration Layer",
                description=(
                    f"{len(passthrough)} API proxy/proxies have no policies applied. "
                    "These are pure pass-through proxies that provide no security value — "
                    "no authentication, no rate limiting, no threat protection."
                ),
                affected_items=passthrough,
                remediation=(
                    "Apply at minimum: authentication (OAuth/API key), rate limiting, "
                    "and threat protection policies. If the proxy is unused, undeploy it."
                ),
                references=["OWASP API Security Top 10"],
            )

    # ════════════════════════════════════════════════════════════════
    #  INTG-IDOC-*: IDOC Port & Partner Profile Security
    # ════════════════════════════════════════════════════════════════

    def check_idoc_port_security(self):
        """
        Audit IDOC port configurations (WE21):
        - File ports with insecure paths
        - HTTP/XML ports without TLS
        - RFC ports without SNC
        """
        ports = self.data.get("idoc_ports")
        if not ports:
            return

        insecure_ports = []
        file_port_risks = []

        for row in ports:
            port_name = row.get("PORT", row.get("PORT_NAME", row.get("PORTNAME", "")))
            port_type = row.get("PORT_TYPE", row.get("TYPE", row.get("PORTTYPE", "")))
            direction = row.get("DIRECTION", row.get("DIR", ""))
            host = row.get("HOST", row.get("RFCHOST", ""))
            path = row.get("FILE_PATH", row.get("PATH", row.get("DIRECTORY", "")))
            tls = row.get("TLS", row.get("SSL", row.get("HTTPS", "")))
            snc = row.get("SNC", row.get("SNC_MODE", ""))

            label = f"{port_name} (type: {port_type})"

            # HTTP/XML ports without TLS
            if port_type.upper() in ("HTTP", "XML_HTTP", "XML-HTTP"):
                if not tls or str(tls).lower() in ("0", "false", "no", ""):
                    insecure_ports.append(f"{label} — HTTP without TLS, host: {host}")

            # RFC ports without SNC
            if port_type.upper() in ("TRFC", "RFC"):
                if not snc or str(snc).lower() in ("0", "false", "no", ""):
                    insecure_ports.append(f"{label} — RFC without SNC, host: {host}")

            # File ports with risky paths
            if port_type.upper() == "FILE" and path:
                risky_path_patterns = ["/tmp", "/var/tmp", "\\temp", "C:\\temp",
                                       "/usr/sap", "/sapmnt"]
                if any(rp.lower() in path.lower() for rp in risky_path_patterns):
                    file_port_risks.append(f"{label} — path: {path}")

        if insecure_ports:
            self.finding(
                check_id="INTG-IDOC-001",
                title="IDOC ports without encryption (no TLS/SNC)",
                severity=self.SEVERITY_HIGH,
                category="Network & Integration Layer",
                description=(
                    f"{len(insecure_ports)} IDOC port(s) transmit data without encryption. "
                    "IDOC payloads often contain sensitive business data (orders, invoices, "
                    "HR records) that should be encrypted in transit."
                ),
                affected_items=insecure_ports,
                remediation=(
                    "Enable TLS on all HTTP/XML IDOC ports. "
                    "Enable SNC on all RFC-based IDOC ports. "
                    "Verify certificate validity on both ends."
                ),
                references=["SAP Note 2416093 — Secure RFC/IDOC Communication"],
            )

        if file_port_risks:
            self.finding(
                check_id="INTG-IDOC-002",
                title="IDOC file ports with insecure directory paths",
                severity=self.SEVERITY_MEDIUM,
                category="Network & Integration Layer",
                description=(
                    f"{len(file_port_risks)} IDOC file port(s) write to commonly accessible "
                    "or temporary directories. IDOCs written to insecure paths may be "
                    "readable by unauthorized OS users."
                ),
                affected_items=file_port_risks,
                remediation=(
                    "Use dedicated, access-controlled directories for IDOC file ports. "
                    "Set strict OS-level permissions (owner: sidadm, mode: 700). "
                    "Avoid /tmp, /var/tmp, or shared mount points."
                ),
                references=["SAP Security Guide — File System Permissions"],
            )

    def check_idoc_partner_profiles(self):
        """
        Audit IDOC partner profiles (WE20):
        - Partners with wildcard message types
        - Partners configured for sensitive IDOC types without restrictions
        """
        partners = self.data.get("idoc_partners")
        if not partners:
            return

        wildcard_partners = []
        sensitive_idoc_partners = []

        sensitive_idoc_types = [
            "HRMD_A",      # HR master data
            "PEXR2002",    # Payment order
            "FINSTA01",    # Bank statement
            "DEBMAS",      # Customer master
            "CREMAS",      # Vendor master
            "MATMAS",      # Material master
            "ACC_DOCUMENT", # Accounting document
            "ORDERS",      # Purchase/sales orders
            "WMMBXY",      # Goods movement
        ]

        for row in partners:
            partner = row.get("PARTNER", row.get("PARTNER_NO", row.get("PARTNR", "")))
            partner_type = row.get("PARTNER_TYPE", row.get("PARTYP", row.get("TYPE", "")))
            msg_type = row.get("MESSAGE_TYPE", row.get("MESTYP", row.get("IDOC_TYPE", "")))
            direction = row.get("DIRECTION", row.get("DIRECT", ""))
            port = row.get("PORT", row.get("RCVPOR", ""))

            label = f"Partner: {partner} ({partner_type})"

            if msg_type and msg_type.strip() in ("*", "", "ALL"):
                wildcard_partners.append(
                    f"{label} — message type: {msg_type or 'ALL'} (direction: {direction})"
                )

            if msg_type:
                for sensitive in sensitive_idoc_types:
                    if sensitive.upper() in msg_type.upper():
                        sensitive_idoc_partners.append(
                            f"{label} — {msg_type} via port {port} ({direction})"
                        )
                        break

        if wildcard_partners:
            self.finding(
                check_id="INTG-IDOC-003",
                title="IDOC partner profiles with wildcard message types",
                severity=self.SEVERITY_HIGH,
                category="Network & Integration Layer",
                description=(
                    f"{len(wildcard_partners)} partner profile(s) accept all IDOC message "
                    "types. This allows any IDOC type to be sent/received, bypassing "
                    "message-type-level authorization."
                ),
                affected_items=wildcard_partners,
                remediation=(
                    "Restrict each partner profile to specific message types required "
                    "for the business integration. Remove wildcard entries. "
                    "Document each message type assignment with business justification."
                ),
                references=["SAP IDOC — Partner Profile Authorization"],
            )

        if sensitive_idoc_partners:
            self.finding(
                check_id="INTG-IDOC-004",
                title="IDOC partner profiles configured for sensitive message types",
                severity=self.SEVERITY_MEDIUM,
                category="Network & Integration Layer",
                description=(
                    f"{len(sensitive_idoc_partners)} partner profile(s) handle sensitive "
                    "IDOC types (HR data, payments, financial postings, master data). "
                    "These require additional scrutiny for authorization and encryption."
                ),
                affected_items=sensitive_idoc_partners,
                remediation=(
                    "Ensure all sensitive IDOC types use encrypted transport (SNC/TLS). "
                    "Verify the receiving partner is authorized for the data classification. "
                    "Implement IDOC monitoring for sensitive message types."
                ),
                references=["SAP IDOC Security — Sensitive Data Handling"],
            )

    # ════════════════════════════════════════════════════════════════
    #  INTG-WS-*: Web Service (SOAMANAGER) Endpoint Security
    # ════════════════════════════════════════════════════════════════

    def check_ws_endpoint_exposure(self):
        """Audit web service endpoints for high-risk BAPI/RFC exposure."""
        ws = self.data.get("ws_endpoints")
        if not ws:
            return

        high_risk_exposed = []
        all_active = []

        for row in ws:
            name = row.get("SERVICE_NAME", row.get("NAME", row.get("ENDPOINT", "")))
            binding = row.get("BINDING", row.get("BINDING_NAME", ""))
            status = row.get("STATUS", row.get("ACTIVE", ""))
            auth = row.get("AUTHENTICATION", row.get("AUTH_TYPE", ""))
            transport = row.get("TRANSPORT_BINDING", row.get("PROTOCOL", ""))

            if str(status).upper() not in ("ACTIVE", "1", "TRUE", "YES", "X"):
                continue

            label = f"{name} (binding: {binding})"
            all_active.append(label)

            name_upper = name.upper()
            for pattern in self.WS_HIGH_RISK_PATTERNS:
                if pattern in name_upper:
                    high_risk_exposed.append(
                        f"{label} — auth: {auth or 'unknown'}, transport: {transport}"
                    )
                    break

        if high_risk_exposed:
            self.finding(
                check_id="INTG-WS-001",
                title="High-risk BAPIs/RFCs exposed as web services",
                severity=self.SEVERITY_HIGH,
                category="Network & Integration Layer",
                description=(
                    f"{len(high_risk_exposed)} active web service endpoint(s) expose "
                    "high-risk function modules (user management, arbitrary table reads, "
                    "financial postings). These can be exploited remotely if authentication "
                    "is weak."
                ),
                affected_items=high_risk_exposed,
                remediation=(
                    "Deactivate unnecessary web service endpoints via SOAMANAGER. "
                    "For required endpoints, enforce strong authentication (X.509 or OAuth). "
                    "Restrict access to specific consumer IP ranges. "
                    "Prefer OData/REST services with proper scope controls over raw BAPI WS."
                ),
                references=[
                    "SAP Note 1503579 — SOAMANAGER Security",
                    "OWASP — Web Service Security Cheat Sheet",
                ],
            )

        max_ws = self.get_config("max_active_ws_endpoints", 50)
        if len(all_active) > max_ws:
            self.finding(
                check_id="INTG-WS-002",
                title=f"Excessive active web service endpoints ({len(all_active)})",
                severity=self.SEVERITY_MEDIUM,
                category="Network & Integration Layer",
                description=(
                    f"{len(all_active)} web service endpoints are active (threshold: {max_ws}). "
                    "A large web service surface increases attack vectors and management complexity."
                ),
                affected_items=all_active[:30],
                remediation=(
                    "Review all active web service endpoints for continued business need. "
                    "Deactivate unused endpoints. Consolidate into modern OData/REST APIs."
                ),
                references=["SAP — Web Service Endpoint Governance"],
                details={"total_active": len(all_active)},
            )

    def check_ws_authentication(self):
        """Check web services for weak authentication methods."""
        ws = self.data.get("ws_endpoints")
        if not ws:
            return

        weak_auth = []
        for row in ws:
            name = row.get("SERVICE_NAME", row.get("NAME", ""))
            status = row.get("STATUS", row.get("ACTIVE", ""))
            auth = row.get("AUTHENTICATION", row.get("AUTH_TYPE", ""))
            transport = row.get("TRANSPORT_BINDING", row.get("PROTOCOL", ""))

            if str(status).upper() not in ("ACTIVE", "1", "TRUE", "YES", "X"):
                continue

            if auth and auth.upper() in ("NONE", "ANONYMOUS", "TRANSPORT", ""):
                weak_auth.append(
                    f"{name} — auth: {auth or 'none'}, transport: {transport}"
                )

        if weak_auth:
            self.finding(
                check_id="INTG-WS-003",
                title="Web service endpoints with weak/no authentication",
                severity=self.SEVERITY_CRITICAL,
                category="Network & Integration Layer",
                description=(
                    f"{len(weak_auth)} active web service endpoint(s) have no authentication "
                    "or rely only on transport-level security. Any network-reachable "
                    "caller can invoke these services."
                ),
                affected_items=weak_auth,
                remediation=(
                    "Configure message-level authentication (WS-Security with X.509 "
                    "certificates, SAML tokens, or username/password with TLS). "
                    "Never rely solely on transport-level (network) security."
                ),
                references=["SAP Note 1503579 — SOAMANAGER Authentication"],
            )

    # ════════════════════════════════════════════════════════════════
    #  INTG-WH-*: Webhook & Callback Endpoint Security
    # ════════════════════════════════════════════════════════════════

    def check_webhook_security(self):
        """
        Audit registered webhooks and callback URLs:
        - HTTP (non-HTTPS) callback URLs
        - Callbacks without signature verification
        - Callbacks to external/third-party domains
        - Stale/unused registrations
        """
        webhooks = self.data.get("webhooks")
        if not webhooks:
            return

        hook_list = webhooks if isinstance(webhooks, list) else \
            webhooks.get("webhooks", webhooks.get("callbacks",
            webhooks.get("subscriptions", [])))

        http_callbacks = []
        no_signature = []
        external_callbacks = []
        stale = []
        now = datetime.now()

        internal_patterns = self.get_config("internal_domain_patterns", [
            ".internal", ".corp", ".local", "localhost",
            "10.", "172.16.", "192.168.",
            ".hana.ondemand.com", ".cfapps.",
        ])

        for hook in hook_list:
            if not isinstance(hook, dict):
                continue

            name = hook.get("name", hook.get("event", hook.get("id", "unknown")))
            url = hook.get("url", hook.get("callbackUrl", hook.get("endpoint", "")))
            signature = hook.get("signatureVerification",
                       hook.get("hmac", hook.get("secret_configured", False)))
            created = hook.get("created", hook.get("registeredAt", ""))
            last_triggered = hook.get("lastTriggered", hook.get("lastCall", ""))
            status = hook.get("status", hook.get("active", ""))

            label = f"{name} → {url}"

            # HTTP without TLS
            if url and url.lower().startswith("http://"):
                http_callbacks.append(f"{label} — unencrypted HTTP")

            # No signature verification
            if not signature or str(signature).lower() in ("false", "0", "no", "none", ""):
                no_signature.append(f"{label} — no HMAC/signature validation")

            # External callback domains
            if url:
                is_internal = any(p in url.lower() for p in internal_patterns)
                if not is_internal:
                    external_callbacks.append(label)

            # Stale webhooks
            stale_days = self.get_config("webhook_stale_days", 180)
            ref_date = last_triggered or created
            if ref_date:
                parsed = self._parse_date_flexible(ref_date)
                if parsed and (now - parsed).days > stale_days:
                    stale.append(
                        f"{label} — last activity: {ref_date} "
                        f"({(now - parsed).days}d ago)"
                    )

        if http_callbacks:
            self.finding(
                check_id="INTG-WH-001",
                title="Webhook callbacks using unencrypted HTTP",
                severity=self.SEVERITY_HIGH,
                category="Network & Integration Layer",
                description=(
                    f"{len(http_callbacks)} webhook(s) send event payloads over plain HTTP. "
                    "Webhook payloads contain business event data and potentially "
                    "authentication tokens that can be intercepted."
                ),
                affected_items=http_callbacks,
                remediation=(
                    "Update all webhook callback URLs to use HTTPS. "
                    "Reject HTTP callback registrations at the platform level."
                ),
                references=["OWASP — Webhook Security Best Practices"],
            )

        if no_signature:
            self.finding(
                check_id="INTG-WH-002",
                title="Webhooks without signature/HMAC verification",
                severity=self.SEVERITY_HIGH,
                category="Network & Integration Layer",
                description=(
                    f"{len(no_signature)} webhook(s) do not use signature verification. "
                    "Without HMAC/signature validation, receivers cannot verify that "
                    "webhook payloads are authentic, enabling replay and spoofing attacks."
                ),
                affected_items=no_signature,
                remediation=(
                    "Configure HMAC (SHA-256) signature on all webhook registrations. "
                    "Receiving endpoints must validate the signature header before "
                    "processing the payload. Use a unique secret per registration."
                ),
                references=["OWASP — Webhook Signature Verification"],
            )

        if external_callbacks:
            self.finding(
                check_id="INTG-WH-003",
                title="Webhooks delivering events to external/third-party endpoints",
                severity=self.SEVERITY_MEDIUM,
                category="Network & Integration Layer",
                description=(
                    f"{len(external_callbacks)} webhook(s) deliver business events to "
                    "external endpoints outside the recognized corporate domain. "
                    "Verify these are authorized and data classification allows it."
                ),
                affected_items=external_callbacks,
                remediation=(
                    "Review each external webhook for business authorization. "
                    "Ensure data classification allows the event data to leave "
                    "the corporate boundary. Implement IP allowlisting on callback URLs."
                ),
                references=["Data Classification — Outbound Event Controls"],
            )

        if stale:
            self.finding(
                check_id="INTG-WH-004",
                title="Stale webhook registrations with no recent activity",
                severity=self.SEVERITY_LOW,
                category="Network & Integration Layer",
                description=(
                    f"{len(stale)} webhook registration(s) have not been triggered "
                    f"in over {self.get_config('webhook_stale_days', 180)} days. "
                    "Stale registrations may point to decommissioned consumers."
                ),
                affected_items=stale,
                remediation="Review and remove unused webhook registrations.",
                references=["Integration Governance — Webhook Lifecycle"],
            )

    # ════════════════════════════════════════════════════════════════
    #  INTG-GW-*: Gateway Security (secinfo/reginfo Deep Analysis)
    # ════════════════════════════════════════════════════════════════

    def check_gateway_secinfo(self):
        """
        Deep analysis of gateway secinfo rules:
        - Overly permissive rules (permit all)
        - Missing deny-all default rule
        - Rules allowing external program starts
        """
        secinfo = self.data.get("gw_secinfo")
        if not secinfo:
            return

        permit_all = []
        external_exec = []
        has_deny_default = False

        for row in secinfo:
            rule = row.get("RULE", row.get("ENTRY", row.get("LINE", "")))
            action = row.get("ACTION", "")
            program = row.get("PROGRAM", row.get("TP", ""))
            host = row.get("HOST", row.get("FROM_HOST", ""))
            user = row.get("USER", "")

            rule_text = rule or f"{action} {program} {host} {user}".strip()
            rule_upper = rule_text.upper()

            # Check for deny-all default
            if "DENY" in rule_upper and ("*" in rule_upper or "ALL" in rule_upper):
                has_deny_default = True

            # Permit all rules
            if "PERMIT" in rule_upper or action.upper() == "P":
                if ("*" in program or not program) and ("*" in host or not host):
                    permit_all.append(f"Rule: {rule_text}")

            # External program execution
            if "PERMIT" in rule_upper or action.upper() == "P":
                ext_indicators = ["SAPXPG", "TP_*", "/USR/", "/BIN/", "CMD", "PROGRAM"]
                if any(ind in rule_upper for ind in ext_indicators):
                    external_exec.append(f"Rule: {rule_text}")

        if permit_all:
            self.finding(
                check_id="INTG-GW-001",
                title="Gateway secinfo has overly permissive permit rules",
                severity=self.SEVERITY_CRITICAL,
                category="Network & Integration Layer",
                description=(
                    f"{len(permit_all)} secinfo rule(s) permit all programs from all hosts. "
                    "This effectively disables gateway program start authorization, "
                    "allowing remote program execution via the SAP gateway."
                ),
                affected_items=permit_all,
                remediation=(
                    "Replace wildcard permit rules with specific entries for each "
                    "required program/host combination. Follow SAP's recommended "
                    "secinfo configuration from SAP Note 1408081."
                ),
                references=[
                    "SAP Note 1408081 — Gateway Security",
                    "SAP Note 2776748 — Gateway ACL Hardening",
                ],
            )

        if not has_deny_default and secinfo:
            self.finding(
                check_id="INTG-GW-002",
                title="Gateway secinfo missing deny-all default rule",
                severity=self.SEVERITY_HIGH,
                category="Network & Integration Layer",
                description=(
                    "The gateway secinfo configuration does not contain a default "
                    "deny-all rule. Without explicit denial, undefined access may "
                    "be implicitly allowed depending on gateway configuration."
                ),
                affected_items=["secinfo — no deny-all default found"],
                remediation=(
                    "Add 'D *  *  *' (deny all) as the last rule in secinfo. "
                    "Then add specific permit rules above it for required access."
                ),
                references=["SAP Note 1408081 — Gateway Security Configuration"],
            )

        if external_exec:
            self.finding(
                check_id="INTG-GW-003",
                title="Gateway secinfo permits external program execution",
                severity=self.SEVERITY_HIGH,
                category="Network & Integration Layer",
                description=(
                    f"{len(external_exec)} secinfo rule(s) allow execution of external "
                    "programs (SAPXPG, OS commands) via the gateway. This can be "
                    "exploited for remote code execution."
                ),
                affected_items=external_exec,
                remediation=(
                    "Remove or restrict external program execution rules. "
                    "If SAPXPG is required, limit to specific programs and hosts. "
                    "Consider disabling gateway external program start entirely "
                    "if not needed (gw/rem_start = DISABLED)."
                ),
                references=["SAP Note 1408081", "CVE-2020-6207 — SAP Gateway RCE"],
            )

    def check_gateway_reginfo(self):
        """Deep analysis of gateway reginfo (RFC registration rules)."""
        reginfo = self.data.get("gw_reginfo")
        if not reginfo:
            return

        permit_all = []
        has_deny_default = False

        for row in reginfo:
            rule = row.get("RULE", row.get("ENTRY", row.get("LINE", "")))
            action = row.get("ACTION", "")
            tp = row.get("TP", row.get("PROGRAM", ""))
            host = row.get("HOST", row.get("FROM_HOST", ""))

            rule_text = rule or f"{action} {tp} {host}".strip()
            rule_upper = rule_text.upper()

            if "DENY" in rule_upper and "*" in rule_upper:
                has_deny_default = True

            if "PERMIT" in rule_upper or action.upper() == "P":
                if ("*" in tp or not tp) and ("*" in host or not host):
                    permit_all.append(f"Rule: {rule_text}")

        if permit_all:
            self.finding(
                check_id="INTG-GW-004",
                title="Gateway reginfo permits unrestricted RFC server registration",
                severity=self.SEVERITY_CRITICAL,
                category="Network & Integration Layer",
                description=(
                    f"{len(permit_all)} reginfo rule(s) allow any RFC program to register "
                    "from any host. An attacker can register a rogue RFC server to "
                    "intercept or inject RFC traffic."
                ),
                affected_items=permit_all,
                remediation=(
                    "Restrict reginfo to specific RFC server programs and source hosts. "
                    "Add a deny-all default rule. Only permit known integration servers."
                ),
                references=[
                    "SAP Note 1408081 — Gateway Registration Security",
                    "SAP Note 2776748",
                ],
            )

        if not has_deny_default and reginfo:
            self.finding(
                check_id="INTG-GW-005",
                title="Gateway reginfo missing deny-all default rule",
                severity=self.SEVERITY_HIGH,
                category="Network & Integration Layer",
                description=(
                    "The gateway reginfo does not have a default deny-all rule. "
                    "Without it, unrecognized RFC servers may be able to register."
                ),
                affected_items=["reginfo — no deny-all default found"],
                remediation="Add 'D *  *' as the last line in reginfo.",
                references=["SAP Note 1408081"],
            )

    # ════════════════════════════════════════════════════════════════
    #  INTG-MON-*: Integration Monitoring & Alerting
    # ════════════════════════════════════════════════════════════════

    def check_integration_monitoring(self):
        """
        Check if integration monitoring and alerting is properly configured:
        - Alert Notification Service configuration
        - Integration flow error alerting
        - Failed IDOC monitoring
        - SIEM integration for integration events
        """
        alerts = self.data.get("integration_alerts")
        if not alerts:
            return

        config = alerts if isinstance(alerts, dict) else {}
        if isinstance(alerts, list):
            config = {"rules": alerts}

        rules = config.get("rules", config.get("alertRules",
                config.get("conditions", [])))
        siem_configured = config.get("siemIntegration",
                         config.get("siem", config.get("logForwarding", False)))
        email_configured = config.get("emailNotification",
                          config.get("email", False))

        # Required alert categories
        required_alerts = {
            "iflow_error": "Integration flow runtime errors",
            "idoc_failure": "IDOC processing failures",
            "auth_failure": "Authentication/authorization failures on APIs",
            "cert_expiry": "Certificate expiration warnings",
            "rfc_error": "RFC communication failures",
            "quota_exceeded": "API quota/rate limit exceeded",
        }

        rule_names = set()
        for rule in rules:
            if isinstance(rule, dict):
                name = rule.get("name", rule.get("type", rule.get("category", ""))).lower()
            else:
                name = str(rule).lower()
            rule_names.add(name)

        missing_alerts = []
        for key, desc in required_alerts.items():
            found = any(key in rn or rn in key for rn in rule_names)
            if not found:
                missing_alerts.append(f"{key}: {desc}")

        if missing_alerts:
            self.finding(
                check_id="INTG-MON-001",
                title="Missing integration monitoring alert rules",
                severity=self.SEVERITY_HIGH,
                category="Network & Integration Layer",
                description=(
                    f"{len(missing_alerts)} required alert rule category/categories are "
                    "not configured. Without proper alerting, integration failures and "
                    "security events go undetected."
                ),
                affected_items=missing_alerts,
                remediation=(
                    "Configure alerts for all critical integration events using "
                    "SAP Alert Notification Service or equivalent. "
                    "At minimum: iFlow errors, IDOC failures, auth failures, "
                    "certificate expiry, RFC errors, and quota breaches."
                ),
                references=["SAP BTP Alert Notification Service — Configuration Guide"],
            )

        if not siem_configured or str(siem_configured).lower() in ("false", "0", "no", ""):
            self.finding(
                check_id="INTG-MON-002",
                title="Integration events not forwarded to SIEM",
                severity=self.SEVERITY_MEDIUM,
                category="Network & Integration Layer",
                description=(
                    "Integration monitoring events are not configured for SIEM forwarding. "
                    "Without SIEM integration, integration security events cannot be "
                    "correlated with other security data for incident detection."
                ),
                affected_items=["SIEM integration: not configured"],
                remediation=(
                    "Configure log forwarding from SAP Alert Notification Service "
                    "to your SIEM (Splunk, Sentinel, QRadar). "
                    "Include: CPI runtime logs, API Management access logs, "
                    "Event Mesh audit logs, and Cloud Connector logs."
                ),
                references=["SAP BTP — SIEM Integration with Alert Notification"],
            )

    # ════════════════════════════════════════════════════════════════
    #  INTG-CPI-*: CPI Advanced — Data Stores & Message Logging
    # ════════════════════════════════════════════════════════════════

    def check_cpi_datastores(self):
        """
        Audit CPI data stores and variables for security issues:
        - Data stores containing sensitive data without encryption tags
        - Global variables with credentials or tokens
        - Excessive data retention in data stores
        """
        cpi_ds = self.data.get("cpi_datastores")
        if not cpi_ds:
            return

        stores = cpi_ds if isinstance(cpi_ds, list) else \
            cpi_ds.get("dataStores", cpi_ds.get("stores", []))
        variables = cpi_ds if isinstance(cpi_ds, list) else \
            cpi_ds.get("variables", cpi_ds.get("globalVariables", []))

        sensitive_stores = []
        credential_vars = []
        large_stores = []

        sensitive_patterns = ["password", "token", "secret", "key", "credential",
                             "ssn", "bank", "salary", "payment", "credit_card",
                             "pii", "personal"]

        # Check data stores
        if isinstance(stores, list):
            for store in stores:
                if not isinstance(store, dict):
                    continue
                name = store.get("name", store.get("storeName", "unknown"))
                entry_count = store.get("entryCount", store.get("entries",
                             store.get("size", 0)))
                encrypted = store.get("encrypted", store.get("encryption", False))
                retention = store.get("retentionDays", store.get("ttl",
                           store.get("retention", "")))

                # Sensitive naming
                name_lower = name.lower()
                if any(p in name_lower for p in sensitive_patterns):
                    if not encrypted or str(encrypted).lower() in ("false", "0", "no"):
                        sensitive_stores.append(
                            f"{name} — entries: {entry_count}, encrypted: {encrypted}"
                        )

                # Large stores (potential data hoarding)
                max_entries = self.get_config("max_cpi_datastore_entries", 10000)
                try:
                    if int(str(entry_count)) > max_entries:
                        large_stores.append(
                            f"{name} — {entry_count} entries (max: {max_entries})"
                        )
                except (ValueError, TypeError):
                    pass

        # Check global variables
        if isinstance(variables, list):
            for var in variables:
                if not isinstance(var, dict):
                    continue
                name = var.get("name", var.get("variableName", "unknown"))
                value = var.get("value", var.get("content", ""))

                name_lower = name.lower()
                if any(p in name_lower for p in sensitive_patterns):
                    credential_vars.append(
                        f"Variable: {name} — may contain sensitive data"
                    )

        if sensitive_stores:
            self.finding(
                check_id="INTG-CPI-DS-001",
                title="CPI data stores with sensitive data names but no encryption",
                severity=self.SEVERITY_HIGH,
                category="Network & Integration Layer",
                description=(
                    f"{len(sensitive_stores)} CPI data store(s) have names suggesting "
                    "sensitive content but are not marked as encrypted. Data store "
                    "contents are accessible via CPI OData API."
                ),
                affected_items=sensitive_stores,
                remediation=(
                    "Enable encryption for all data stores containing sensitive data. "
                    "Use the CPI Security Material for credential storage instead. "
                    "Minimize data store retention periods."
                ),
                references=["SAP CPI — Data Store Security"],
            )

        if credential_vars:
            self.finding(
                check_id="INTG-CPI-DS-002",
                title="CPI global variables with potentially sensitive names",
                severity=self.SEVERITY_MEDIUM,
                category="Network & Integration Layer",
                description=(
                    f"{len(credential_vars)} CPI global variable(s) have names suggesting "
                    "they contain credentials, tokens, or personal data. Global variables "
                    "are not encrypted and are readable via management API."
                ),
                affected_items=credential_vars,
                remediation=(
                    "Move credentials to CPI Security Material (credential store). "
                    "Do not use global variables for secrets. "
                    "If PII must be stored, use encrypted data stores instead."
                ),
                references=["SAP CPI — Credential Management Best Practices"],
            )

        if large_stores:
            self.finding(
                check_id="INTG-CPI-DS-003",
                title="CPI data stores with excessive entries",
                severity=self.SEVERITY_LOW,
                category="Network & Integration Layer",
                description=(
                    f"{len(large_stores)} CPI data store(s) have more entries than the "
                    "configured threshold. Large data stores may indicate missing cleanup "
                    "logic, impacting performance and increasing data exposure risk."
                ),
                affected_items=large_stores,
                remediation=(
                    "Implement TTL (time-to-live) on data store entries. "
                    "Add cleanup logic to iFlows or use scheduled cleanup iFlows. "
                    "Review if data store usage is appropriate vs a proper database."
                ),
                references=["SAP CPI — Data Store Management"],
            )

    # ════════════════════════════════════════════════════════════════
    #  INTG-OAUTH-*: OAuth Client & Scope Governance
    # ════════════════════════════════════════════════════════════════

    def check_oauth_client_governance(self):
        """
        Audit OAuth client registrations across the integration landscape:
        - Clients with overly broad scopes
        - Clients with no scope restrictions
        - Stale/unused clients
        - Clients using deprecated grant types
        """
        oauth = self.data.get("oauth_clients")
        if not oauth:
            return

        clients = oauth if isinstance(oauth, list) else \
            oauth.get("clients", oauth.get("oauthClients", []))

        broad_scope = []
        deprecated_grants = []
        stale_clients = []
        now = datetime.now()

        for client in clients:
            if not isinstance(client, dict):
                continue

            client_id = client.get("clientId", client.get("client_id",
                       client.get("name", "unknown")))
            scopes = client.get("scopes", client.get("scope",
                    client.get("authorities", [])))
            grant_types = client.get("grantTypes", client.get("grant_types",
                         client.get("authorized_grant_types", [])))
            last_used = client.get("lastUsed", client.get("last_access",
                       client.get("lastTokenIssued", "")))
            created = client.get("created", client.get("createdAt", ""))

            scope_str = str(scopes).upper() if not isinstance(scopes, list) \
                       else " ".join(str(s).upper() for s in scopes)

            # Broad scopes
            admin_indicators = ["*", "ADMIN", "MANAGE_ALL", "FULL_ACCESS",
                               "UAA.ADMIN", "XSAPPNAME.ADMIN"]
            if any(ind in scope_str for ind in admin_indicators):
                broad_scope.append(
                    f"{client_id} — scopes: "
                    f"{scopes if isinstance(scopes, str) else ', '.join(str(s) for s in scopes[:5])}"
                )

            # Deprecated grant types
            if isinstance(grant_types, list):
                gt_str = " ".join(str(g).upper() for g in grant_types)
            else:
                gt_str = str(grant_types).upper()

            if any(d in gt_str for d in ["PASSWORD", "IMPLICIT"]):
                deprecated_grants.append(
                    f"{client_id} — grant types: {grant_types}"
                )

            # Stale clients
            ref_date = last_used or created
            stale_days = self.get_config("oauth_client_stale_days", 180)
            if ref_date:
                parsed = self._parse_date_flexible(ref_date)
                if parsed and (now - parsed).days > stale_days:
                    stale_clients.append(
                        f"{client_id} — last activity: {ref_date} "
                        f"({(now - parsed).days}d ago)"
                    )

        if broad_scope:
            self.finding(
                check_id="INTG-OAUTH-001",
                title="OAuth clients with admin-level or wildcard scopes",
                severity=self.SEVERITY_HIGH,
                category="Network & Integration Layer",
                description=(
                    f"{len(broad_scope)} OAuth client(s) have overly broad scope "
                    "assignments. Compromised client credentials with admin scopes "
                    "can lead to full platform takeover."
                ),
                affected_items=broad_scope,
                remediation=(
                    "Restrict OAuth client scopes to minimum required permissions. "
                    "Create separate clients for different integration scenarios "
                    "with narrow, purpose-specific scopes."
                ),
                references=["OAuth 2.0 Security Best Practices — RFC 6819"],
            )

        if deprecated_grants:
            self.finding(
                check_id="INTG-OAUTH-002",
                title="OAuth clients using deprecated grant types (password/implicit)",
                severity=self.SEVERITY_HIGH,
                category="Network & Integration Layer",
                description=(
                    f"{len(deprecated_grants)} OAuth client(s) use the password or implicit "
                    "grant types, which are deprecated in OAuth 2.1 due to security "
                    "risks (credential exposure, token leakage)."
                ),
                affected_items=deprecated_grants,
                remediation=(
                    "Migrate to client_credentials (for service-to-service) or "
                    "authorization_code with PKCE (for user-facing apps). "
                    "Remove password and implicit grant type configurations."
                ),
                references=[
                    "OAuth 2.1 Draft — Deprecated Grant Types",
                    "SAP BTP — OAuth Configuration Best Practices",
                ],
            )

        if stale_clients:
            self.finding(
                check_id="INTG-OAUTH-003",
                title=f"OAuth clients unused for {self.get_config('oauth_client_stale_days', 180)}+ days",
                severity=self.SEVERITY_MEDIUM,
                category="Network & Integration Layer",
                description=(
                    f"{len(stale_clients)} OAuth client(s) have not been used recently. "
                    "Stale clients represent unmonitored credential exposure."
                ),
                affected_items=stale_clients,
                remediation=(
                    "Review and delete unused OAuth clients. "
                    "Implement OAuth client lifecycle management with periodic reviews."
                ),
                references=["OAuth Client Governance — Credential Lifecycle"],
            )

    # ════════════════════════════════════════════════════════════════
    #  INTG-TOPO-*: Integration Topology Review
    # ════════════════════════════════════════════════════════════════

    def check_integration_topology(self):
        """
        Analyze the system-to-system integration topology:
        - Systems with excessive inbound/outbound connections
        - Single points of failure (hub systems)
        - Unencrypted connections in the topology
        - Connections to deprecated/EOL systems
        """
        topo = self.data.get("integration_topology")
        if not topo:
            return

        connections = topo if isinstance(topo, list) else \
            topo.get("connections", topo.get("integrations",
            topo.get("links", [])))

        # Build connection graph
        inbound_count: Dict[str, int] = defaultdict(int)
        outbound_count: Dict[str, int] = defaultdict(int)
        unencrypted = []
        deprecated_systems = []

        deprecated_indicators = self.get_config("deprecated_system_patterns", [
            "ECC", "R/3", "BW_3", "CRM_5", "SRM_7", "XI_7",
            "PI_7", "LEGACY", "OLD_", "DECOM",
        ])

        for conn in connections:
            if not isinstance(conn, dict):
                continue

            source = conn.get("source", conn.get("from", conn.get("sender", "")))
            target = conn.get("target", conn.get("to", conn.get("receiver", "")))
            protocol = conn.get("protocol", conn.get("type", conn.get("transport", "")))
            encrypted = conn.get("encrypted", conn.get("tls", conn.get("ssl", "")))
            status = conn.get("status", conn.get("active", ""))

            if str(status).upper() in ("INACTIVE", "DISABLED", "0", "FALSE"):
                continue

            inbound_count[target] += 1
            outbound_count[source] += 1

            # Unencrypted connections
            if encrypted is not None and str(encrypted).lower() in ("false", "0", "no"):
                unencrypted.append(f"{source} → {target} (protocol: {protocol})")
            elif protocol and protocol.upper() in ("HTTP", "RFC", "FTP", "SMTP"):
                if not encrypted or str(encrypted).lower() in ("", "unknown"):
                    unencrypted.append(
                        f"{source} → {target} (protocol: {protocol}, encryption: unknown)"
                    )

            # Deprecated systems
            for sys_name in (source, target):
                if any(d.upper() in sys_name.upper() for d in deprecated_indicators):
                    deprecated_systems.append(
                        f"{source} → {target} (system: {sys_name})"
                    )

        # Hub systems (excessive connections)
        max_connections = self.get_config("max_system_connections", 15)
        hub_systems = []
        all_counts = defaultdict(int)
        for sys_name, count in inbound_count.items():
            all_counts[sys_name] += count
        for sys_name, count in outbound_count.items():
            all_counts[sys_name] += count

        for sys_name, total in all_counts.items():
            if total > max_connections:
                hub_systems.append(
                    f"{sys_name} — {total} total connections "
                    f"(in: {inbound_count.get(sys_name, 0)}, "
                    f"out: {outbound_count.get(sys_name, 0)})"
                )

        if unencrypted:
            self.finding(
                check_id="INTG-TOPO-001",
                title="Integration connections without encryption",
                severity=self.SEVERITY_HIGH,
                category="Network & Integration Layer",
                description=(
                    f"{len(unencrypted)} integration connection(s) in the topology "
                    "do not use encryption or use protocols without verified TLS. "
                    "Business data traversing these connections is at risk of interception."
                ),
                affected_items=unencrypted,
                remediation=(
                    "Enable TLS/SNC on all integration connections. "
                    "Migrate FTP to SFTP, HTTP to HTTPS, and RFC to SNC-secured RFC. "
                    "Verify encryption status on all undetermined connections."
                ),
                references=["SAP Security Baseline — Encrypted Communications"],
            )

        if hub_systems:
            self.finding(
                check_id="INTG-TOPO-002",
                title="Integration hub systems with excessive connections",
                severity=self.SEVERITY_MEDIUM,
                category="Network & Integration Layer",
                description=(
                    f"{len(hub_systems)} system(s) have more than {max_connections} "
                    "integration connections. Highly connected systems are single points "
                    "of failure and high-value targets — a compromise affects all "
                    "connected systems."
                ),
                affected_items=hub_systems,
                remediation=(
                    "Review hub system security posture with extra scrutiny. "
                    "Consider distributing integrations via middleware (CPI/Event Mesh) "
                    "to reduce direct system-to-system dependencies. "
                    "Implement network segmentation around hub systems."
                ),
                references=["Integration Architecture — Hub Resilience"],
            )

        if deprecated_systems:
            # Deduplicate
            unique_deprecated = list(set(deprecated_systems))
            self.finding(
                check_id="INTG-TOPO-003",
                title="Integration connections to deprecated/legacy systems",
                severity=self.SEVERITY_MEDIUM,
                category="Network & Integration Layer",
                description=(
                    f"{len(unique_deprecated)} integration connection(s) involve systems "
                    "that appear to be deprecated or end-of-life based on naming patterns. "
                    "Legacy systems often have weaker security posture and may lack patches."
                ),
                affected_items=unique_deprecated[:30],
                remediation=(
                    "Validate each legacy system connection for business necessity. "
                    "Prioritize migration to supported systems. "
                    "For connections that must remain, ensure compensating controls: "
                    "encryption, monitoring, and network isolation."
                ),
                references=["SAP — System Decommissioning Security Checklist"],
                details={"total_deprecated": len(unique_deprecated)},
            )

    # ════════════════════════════════════════════════════════════════
    #  Utility Methods
    # ════════════════════════════════════════════════════════════════

    @staticmethod
    def _parse_date_flexible(date_str: str):
        """Parse date strings in multiple formats."""
        if not date_str or not str(date_str).strip():
            return None
        date_str = str(date_str).strip()
        for suffix in ("Z", "+00:00", "+0000"):
            if date_str.endswith(suffix):
                date_str = date_str[:-len(suffix)]
        if "T" in date_str:
            date_str = date_str.split("T")[0]
        for fmt in ("%Y-%m-%d", "%Y%m%d", "%d.%m.%Y", "%m/%d/%Y", "%d/%m/%Y"):
            try:
                return datetime.strptime(date_str[:10], fmt)
            except (ValueError, IndexError):
                continue
        return None
