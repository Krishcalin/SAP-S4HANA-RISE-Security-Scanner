"""
BTP & Cloud Attack Surface Auditor
=====================================
Deep-dive checks for the cloud-specific attack surface in
SAP S/4HANA RISE with BTP environments.

Covers:
  - Cloud Connector audit (exposed backends, ACLs, mTLS, stale configs)
  - BTP service binding secrets (rotation, scope, orphaned bindings)
  - BTP Destination service review (stored creds, proxy misconfig, stale)
  - Identity Authentication Service (IAS) policy review
  - BTP entitlement sprawl (unused entitled services)
  - Event Mesh topic authorization (publish/subscribe scope)
  - Cloud Integration (CPI) credential stores & iFlow security
  - Network isolation (Private Link / service endpoint config)
  - BTP subaccount governance (multi-environment consistency)
  - XSUAA vs IAS migration status
  - XSUAA token policy against SAP's published defaults (BTP-TOK-*)
  - Iframe embedding / clickjacking exposure of the login page (BTP-FRM-*)
  - Email as a cross-identity-provider join key (BTP-IDL-001)
  - Which subaccounts the audit-log export leaves unassessed (BTP-AUD-001)

Data sources:
  - cloud_connector.json    → SCC config export (backends, ACLs, certs)
  - btp_service_bindings.json → Service instance bindings
  - btp_destinations.json   → Destination service configuration
  - ias_config.json         → IAS application & policy config
  - btp_entitlements.json   → Subaccount entitlement/quota data
  - event_mesh.json         → Event Mesh queue/topic config
  - cpi_artifacts.json      → CPI iFlow and credential store data
  - btp_network.json        → Private Link / connectivity config
  - btp_subaccounts.json    → Multi-subaccount governance data
  - btp_security_settings.json → Token policy, iframe domains, email linking
  - btp_trust.json          → Active identity provider trusts (BTP-IDL-001)
  - btp_audit_log_records.json → Per-tenant logging evidence, via btp_import

The last three arrive through `modules/btp_import.py`, which normalises raw btp
CLI and API output and merges the settings onto the subaccounts they describe.
Those fields were ingested long before anything read them; see the section
"Subaccount security settings" below for why that was worse than not having them.
"""

from typing import Dict, List, Any, Set
from datetime import datetime, timedelta
from collections import defaultdict
from modules.base_auditor import BaseAuditor


def _norm_auth(value: Any) -> str:
    """An authentication-type name with its spelling normalised away.

    SAP writes these one way and hand-made exports write them another. The
    Destination service returns `BasicAuthentication`; a spreadsheet export or
    a hand-built fixture is as likely to say `BASIC_AUTHENTICATION`. Both name
    the same setting, and a check that recognised only one of them would be
    silent on whichever half of the estate it was not written against.
    """
    return "".join(ch for ch in str(value or "").upper() if ch.isalnum())


# ─────────────────────────────────────────────────────────────────────────────
#  Subaccount security settings — the numbers SAP publishes, not ones we chose
#
#  Every threshold below is quoted from SAP's own documentation of the SAP
#  Authorization and Trust Management service (XSUAA), section "Setting Token
#  Policy" [verified]. That matters more here than in most checks: a token
#  lifetime has no natural right answer, so a threshold this product invented
#  would be an opinion presented as a measurement. These are the vendor's.
#
#  Source: "Security Considerations for the SAP Authorization and Trust
#  Management Service", SAP BTP documentation.
# ─────────────────────────────────────────────────────────────────────────────

#: "Access tokens — Default: 43200 seconds (12 hours)."
_ACCESS_TOKEN_DEFAULT = 43200

#: "Refresh tokens — Default: 604800 seconds (7 days)."
_REFRESH_TOKEN_DEFAULT = 604800

#: "Keep token validity as short as possible, but not less than 30 minutes."
_TOKEN_VALIDITY_FLOOR = 1800

#: The fields `btp list security/settings` returns, as `btp_import` normalises
#: them. Presence of ANY of these is what makes a record a settings record.
_SETTINGS_FIELDS = ("accessTokenValidity", "refreshTokenValidity",
                    "iframeDomains", "iframeDomainsList", "customEmailDomains",
                    "treatUsersWithSameEmailAsSameUser")

#: The identity fields a subaccount can be named by, in the order `btp_import`
#: matches them. Kept in step with `btp_import._match_subaccount` deliberately:
#: if the two disagree, a settings record merged onto a subaccount there would
#: be read a SECOND time here as unattributed, and one subaccount's token policy
#: would be reported twice.
_SUBACCOUNT_KEYS = ("id", "subaccountId", "guid", "subdomain", "name",
                    "displayName")


class BtpCloudSurfaceAuditor(BaseAuditor):

    # ── Known high-risk backend resources exposed via Cloud Connector ──
    HIGH_RISK_BACKEND_PATHS = [
        "/sap/bc/soap/rfc",
        "/sap/bc/srt/rfc",
        "/sap/bc/gui/sap/its/webgui",
        "/sap/bc/webrfc",
        "/sap/opu/odata/sap",
        "/sap/bc/adt",     # ABAP Development Tools — code access
        "/sap/bc/bsp",
        "/sap/es5",
    ]

    # ── BTP services with security-critical entitlements ──
    SECURITY_CRITICAL_SERVICES = [
        "connectivity", "destination", "xsuaa", "identity",
        "auditlog", "malware-scanner", "credstore",
        "privatelink", "cloud-logging", "alert-notification",
    ]

    # ── CPI adapter types that require credential validation ──
    CPI_SENSITIVE_ADAPTERS = [
        "SFTP", "SOAP", "OData", "HTTP", "RFC", "JDBC",
        "LDAP", "Mail", "AS2", "IDOC", "SuccessFactors",
    ]

    @staticmethod
    def _add_object(bucket: List[Dict[str, Any]], obj_type: str,
                    name: Any, qualifier: Any = None) -> None:
        """Append one structured affected object to `bucket`, or nothing.

        The display strings built by the checks below fall back to the literal
        "unknown" when an export row carries no name. That is a placeholder for a
        human reader, not an identity: emitted as an object it would merge every
        unnamed row — across every export and every run — into one graph node and
        one finding identity. So an unnamed row contributes no object at all.

        `qualifier` carries the value that makes the object dangerous (a wildcard
        path, an admin scope, TrustAll=true). Dates and ages are deliberately never
        used as qualifiers: they change on every run, which would churn the node.
        """
        text = "" if name is None else str(name).strip()
        if not text or text.lower() == "unknown":
            return
        obj: Dict[str, Any] = {"type": obj_type, "name": text}
        qual = "" if qualifier is None else str(qualifier).strip()
        if qual:
            obj["qualifier"] = qual
        bucket.append(obj)

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_cloud_connector_backends()
        self.check_cloud_connector_acls()
        self.check_cloud_connector_certificates()
        self.check_cloud_connector_stale()
        self.check_service_binding_secrets()
        self.check_btp_destinations()
        self.check_ias_policies()
        self.check_ias_mfa()
        self.check_ias_password_policy()
        self.check_ias_idp_enforcement()
        self.check_cloud_connector_version()
        self.check_cloud_connector_ha()
        self.check_cloud_connector_audit()
        self.check_entitlement_sprawl()
        self.check_event_mesh_topics()
        self.check_cpi_credential_stores()
        self.check_cpi_iflow_security()
        self.check_network_isolation()
        self.check_subaccount_governance()
        self.check_xsuaa_migration()
        self.check_token_policy()
        self.check_iframe_domains()
        self.check_email_identity_linking()
        self.check_audit_log_coverage()
        return self.findings

    # ════════════════════════════════════════════════════════════════
    #  BTP-CC-*: Cloud Connector Audit
    # ════════════════════════════════════════════════════════════════

    def check_cloud_connector_backends(self):
        """
        Audit Cloud Connector exposed backend systems:
        - Too many backends exposed
        - High-risk paths accessible (WebGUI, RFC, ADT)
        - Wildcard resource mappings
        """
        cc_data = self.data.get("cloud_connector")
        if not cc_data:
            return

        backends = cc_data if isinstance(cc_data, list) else \
            cc_data.get("backends", cc_data.get("subaccountConfigurations",
            cc_data.get("systemMappings", [])))

        wildcard_mappings = []
        high_risk_exposed = []
        all_backends = []
        wildcard_objects: List[Dict[str, Any]] = []
        high_risk_objects: List[Dict[str, Any]] = []
        backend_objects: List[Dict[str, Any]] = []

        for backend in backends:
            if not isinstance(backend, dict):
                continue

            name = backend.get("name", backend.get("virtualHost",
                    backend.get("description", "unknown")))
            internal_host = backend.get("internalHost", backend.get("host",
                            backend.get("backendHost", "")))
            protocol = backend.get("protocol", backend.get("type", ""))
            resources = backend.get("resources", backend.get("paths",
                        backend.get("accessPolicy", [])))

            all_backends.append(f"{name} → {internal_host} ({protocol})")
            self._add_object(backend_objects, "cc_backend", name)

            if isinstance(resources, list):
                for res in resources:
                    if isinstance(res, dict):
                        path = res.get("path", res.get("url", res.get("resource", "")))
                        access = res.get("accessPolicy", res.get("access",
                                 res.get("enabled", "")))
                        exact_match = res.get("exactMatchOnly",
                                     res.get("exact", False))
                    elif isinstance(res, str):
                        path = res
                        access = "open"
                        exact_match = False
                    else:
                        continue

                    # Wildcard or root-level mapping
                    if path in ("/", "/*", "") or (not exact_match and path == "/sap"):
                        wildcard_mappings.append(
                            f"{name}: path='{path}' (exactMatch={exact_match}) "
                            f"→ {internal_host}"
                        )
                        self._add_object(
                            wildcard_objects, "cc_backend", name,
                            f"path={path}" if path else None,
                        )

                    # High-risk paths
                    for risky in self.HIGH_RISK_BACKEND_PATHS:
                        if risky.lower() in str(path).lower():
                            high_risk_exposed.append(
                                f"{name}: {path} → {internal_host}"
                            )
                            self._add_object(
                                high_risk_objects, "cc_backend", name,
                                f"path={path}" if path else None,
                            )
                            break

        if wildcard_mappings:
            self.finding(
                check_id="BTP-CC-001",
                title="Cloud Connector backends with wildcard resource mappings",
                severity=self.SEVERITY_CRITICAL,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(wildcard_mappings)} Cloud Connector backend mapping(s) use "
                    "wildcard or root-level paths without exact matching. This exposes "
                    "all backend resources through the tunnel, defeating the purpose "
                    "of granular access control."
                ),
                affected_items=wildcard_mappings,
                remediation=(
                    "Replace wildcard mappings with specific path prefixes. "
                    "Enable 'Exact Match Only' where possible. "
                    "Define individual resource entries for each API/service consumed. "
                    "Principle: expose the minimum surface required."
                ),
                references=[
                    "SAP BTP Cloud Connector Security Guide — Resource Access Control",
                    # A second reference here read "SAP Note 2Amazon3222800", a note
                    # number no customer could look up — the residue of a bad
                    # find/replace. It is removed rather than repaired: the correct
                    # number is not known, and inventing one would put a fabricated
                    # SAP identifier in a remediation. The guide above is real and
                    # findable, which is what a reference is for.
                ],
                affected_objects=wildcard_objects,
                # One finding summarising every wildcard mapping in the Cloud
                # Connector. Tightening one backend's mapping must leave the
                # remaining ones on the SAME finding rather than retiring it and
                # raising a fresh one with a reset age, so the members are carried
                # as data and kept out of the identity.
                scope="aggregate",
            )

        if high_risk_exposed:
            self.finding(
                check_id="BTP-CC-002",
                title="High-risk backend services exposed via Cloud Connector",
                severity=self.SEVERITY_HIGH,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(high_risk_exposed)} high-risk backend path(s) are accessible "
                    "through the Cloud Connector. These include WebGUI, SOAP/RFC bridges, "
                    "and ABAP Development Tools, which enable interactive access or "
                    "remote code execution from the cloud side."
                ),
                affected_items=high_risk_exposed,
                remediation=(
                    "Remove access to WebGUI, ADT, WebRFC, and SOAP RFC paths "
                    "unless explicitly required by cloud applications. "
                    "Restrict to specific OData/REST endpoints only. "
                    "Document business justification for each exposed resource."
                ),
                references=["SAP BTP Security Recommendations — Cloud Connector"],
                affected_objects=high_risk_objects,
                # Summary of every high-risk path exposed through the tunnel;
                # removing one exposure must not reset the finding's age.
                scope="aggregate",
            )

        # Too many backends
        max_backends = self.get_config("max_cc_backends", 20)
        if len(all_backends) > max_backends:
            self.finding(
                check_id="BTP-CC-003",
                title=f"Excessive Cloud Connector backend systems ({len(all_backends)})",
                severity=self.SEVERITY_MEDIUM,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(all_backends)} backend systems are configured in the Cloud "
                    f"Connector (threshold: {max_backends}). A large number of exposed "
                    "backends increases the attack surface and management complexity."
                ),
                affected_items=all_backends[:30],
                remediation=(
                    "Review all configured backends for active usage. "
                    "Remove backends for decommissioned or test systems. "
                    "Consider separate Cloud Connector instances for different "
                    "environments (dev/test/prod)."
                ),
                references=["SAP BTP Cloud Connector — Architecture Best Practices"],
                details={"total_backends": len(all_backends)},
                affected_objects=backend_objects,
                # A threshold finding about the POPULATION of backends, not about
                # any one of them. Decommissioning a single backend must keep this
                # one finding (with one fewer member) rather than raise a new one.
                scope="aggregate",
            )

    def check_cloud_connector_acls(self):
        """Check Cloud Connector access control list configuration."""
        cc_data = self.data.get("cloud_connector")
        if not cc_data:
            return

        acls = []
        if isinstance(cc_data, dict):
            acls = cc_data.get("accessControlLists", cc_data.get("acls",
                   cc_data.get("allowedSubaccounts", [])))

        # Check for overly permissive ACLs
        open_acls = []
        open_acl_objects: List[Dict[str, Any]] = []
        for acl in acls:
            if not isinstance(acl, dict):
                continue

            subaccount = acl.get("subaccount", acl.get("subaccountId", ""))
            allowed_hosts = acl.get("allowedHosts", acl.get("hosts",
                           acl.get("ipRestrictions", [])))
            enabled = acl.get("enabled", True)

            if not allowed_hosts or (isinstance(allowed_hosts, list) and
                any(h in ("*", "0.0.0.0/0", "any") for h in allowed_hosts)):
                if enabled in (True, "true", "True", 1, "1"):
                    open_acls.append(
                        f"Subaccount: {subaccount} — hosts: {allowed_hosts or 'unrestricted'}"
                    )
                    self._add_object(
                        open_acl_objects, "subaccount", subaccount,
                        f"allowedHosts={allowed_hosts}" if allowed_hosts else None,
                    )

        if open_acls:
            self.finding(
                check_id="BTP-CC-004",
                title="Cloud Connector with unrestricted access control lists",
                severity=self.SEVERITY_HIGH,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(open_acls)} Cloud Connector ACL(s) have no host restrictions. "
                    "Without IP-based ACLs, any authenticated BTP service can reach "
                    "the on-premise backend through the tunnel."
                ),
                affected_items=open_acls,
                remediation=(
                    "Configure IP-based restrictions in the Cloud Connector ACLs. "
                    "Only allow specific BTP runtime IPs or CIDR ranges. "
                    "Combine with principal propagation for user-level access control."
                ),
                references=["SAP BTP Cloud Connector — Access Control Configuration"],
                affected_objects=open_acl_objects,
                # Summary of every subaccount whose ACL is unrestricted; restricting
                # one of them must not retire this finding and reset its age.
                scope="aggregate",
            )

    def check_cloud_connector_certificates(self):
        """Check Cloud Connector TLS certificate health."""
        cc_data = self.data.get("cloud_connector")
        if not cc_data or not isinstance(cc_data, dict):
            return

        certs = cc_data.get("certificates", cc_data.get("tlsCertificates",
                cc_data.get("sslCerts", [])))

        expiring_soon = []
        weak_certs = []
        expiring_objects: List[Dict[str, Any]] = []
        weak_cert_objects: List[Dict[str, Any]] = []
        now = datetime.now()
        warning_days = self.get_config("cert_expiry_warning_days", 90)

        for cert in certs:
            if not isinstance(cert, dict):
                continue

            name = cert.get("name", cert.get("alias", cert.get("subject", "unknown")))
            expiry = cert.get("expiryDate", cert.get("validTo",
                    cert.get("notAfter", "")))
            key_size = cert.get("keySize", cert.get("key_length",
                      cert.get("bits", "")))
            algo = cert.get("algorithm", cert.get("signatureAlgorithm",
                   cert.get("keyAlgorithm", "")))

            # Check expiry
            if expiry:
                parsed = self._parse_date_flexible(expiry)
                if parsed:
                    days_remaining = (parsed - now).days
                    if days_remaining <= 0:
                        expiring_soon.append(
                            f"{name} — EXPIRED ({expiry}, {abs(days_remaining)}d ago)"
                        )
                        # No date qualifier: the days-remaining value changes on
                        # every run and would churn the certificate's node key.
                        self._add_object(expiring_objects, "certificate", name)
                    elif days_remaining <= warning_days:
                        expiring_soon.append(
                            f"{name} — expires in {days_remaining}d ({expiry})"
                        )
                        self._add_object(expiring_objects, "certificate", name)

            # Check weak key/algo
            if key_size:
                try:
                    if int(str(key_size)) < 2048:
                        weak_certs.append(
                            f"{name} — key size: {key_size} bits (min: 2048)"
                        )
                        self._add_object(weak_cert_objects, "certificate", name,
                                         f"keySize={key_size}")
                except ValueError:
                    pass

            if algo and any(w in str(algo).upper() for w in ("SHA1", "MD5", "SHA-1")):
                weak_certs.append(f"{name} — weak algorithm: {algo}")
                self._add_object(weak_cert_objects, "certificate", name,
                                 f"algorithm={algo}")

        if expiring_soon:
            self.finding(
                check_id="BTP-CC-005",
                title="Cloud Connector certificates expiring or expired",
                severity=self.SEVERITY_HIGH,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(expiring_soon)} certificate(s) are expired or expiring within "
                    f"{warning_days} days. Expired certificates will break the Cloud "
                    "Connector tunnel, causing integration outages."
                ),
                affected_items=expiring_soon,
                remediation=(
                    "Renew certificates before expiry. "
                    "Implement certificate monitoring with automated alerts. "
                    "Schedule renewal 30+ days before expiry to allow testing."
                ),
                references=["SAP BTP Cloud Connector — Certificate Management"],
                affected_objects=expiring_objects,
                # Summary of the expiring certificate population; renewing one must
                # not retire the finding covering the others.
                scope="aggregate",
            )

        if weak_certs:
            self.finding(
                check_id="BTP-CC-006",
                title="Cloud Connector certificates with weak cryptography",
                severity=self.SEVERITY_HIGH,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(weak_certs)} certificate(s) use weak key sizes (<2048 bits) "
                    "or deprecated algorithms (SHA-1, MD5). These are vulnerable to "
                    "cryptographic attacks."
                ),
                affected_items=weak_certs,
                remediation=(
                    "Replace with RSA 2048+ or EC P-256+ keys signed with SHA-256+. "
                    "Update all Cloud Connector system and CA certificates."
                ),
                references=["SAP Note 510007 — SSL/TLS Configuration"],
                affected_objects=weak_cert_objects,
                # Summary of every weak certificate; replacing one must not reset
                # the age of the finding that still covers the rest.
                scope="aggregate",
            )

    def check_cloud_connector_stale(self):
        """Check for stale/unused Cloud Connector backend configurations."""
        cc_data = self.data.get("cloud_connector")
        if not cc_data:
            return

        backends = cc_data if isinstance(cc_data, list) else \
            cc_data.get("backends", cc_data.get("systemMappings", []))

        stale_days = self.get_config("cc_stale_threshold_days", 90)
        stale = []
        stale_objects: List[Dict[str, Any]] = []
        now = datetime.now()

        for backend in backends:
            if not isinstance(backend, dict):
                continue

            name = backend.get("name", backend.get("virtualHost", "unknown"))
            last_used = backend.get("lastUsed", backend.get("lastAccess",
                       backend.get("lastConnectionTime", "")))
            status = backend.get("status", backend.get("state", ""))

            if last_used:
                parsed = self._parse_date_flexible(last_used)
                if parsed:
                    days_idle = (now - parsed).days
                    if days_idle > stale_days:
                        stale.append(
                            f"{name} — last used: {last_used} ({days_idle}d ago)"
                        )
                        # Idle days grow every run, so they are not a qualifier.
                        self._add_object(stale_objects, "cc_backend", name)
            elif status and str(status).upper() in ("DISABLED", "INACTIVE", "DISCONNECTED"):
                stale.append(f"{name} — status: {status}")
                self._add_object(stale_objects, "cc_backend", name,
                                 f"status={status}")

        if stale:
            self.finding(
                check_id="BTP-CC-007",
                title=f"Stale Cloud Connector backends ({stale_days}+ days unused)",
                severity=self.SEVERITY_MEDIUM,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(stale)} Cloud Connector backend(s) appear unused or inactive. "
                    "Stale configurations maintain unnecessary attack surface and "
                    "may point to decommissioned systems."
                ),
                affected_items=stale,
                remediation=(
                    "Remove unused backend configurations from Cloud Connector. "
                    "Implement periodic review of all configured backends. "
                    "Archive configuration before deletion for reference."
                ),
                references=["SAP BTP Cloud Connector — Lifecycle Management"],
                affected_objects=stale_objects,
                # Summary of the stale-backend population; deleting one backend must
                # leave the rest on the same finding.
                scope="aggregate",
            )

    @staticmethod
    def _ver_tuple(v):
        """Parse a dotted version like '2.16.2' into a comparable int tuple."""
        parts = []
        for chunk in str(v).strip().split("."):
            num = ""
            for ch in chunk:
                if ch.isdigit():
                    num += ch
                else:
                    break
            parts.append(int(num) if num else 0)
        return tuple(parts) if parts else (0,)

    def check_cloud_connector_version(self):
        """HIGH: Cloud Connector software version exposed to known CVEs / EOL."""
        cc_data = self.data.get("cloud_connector")
        if not isinstance(cc_data, dict):
            return
        version = cc_data.get("version", cc_data.get("sccVersion",
                 cc_data.get("softwareVersion")))
        if not version:
            return

        vt = self._ver_tuple(version)
        # CVE-2024-25642 (CWE-295, improper certificate validation, CVSS 7.4): SCC
        # trusts self-signed server certificates on outbound cloud connections, so
        # an attacker can impersonate the server and man-in-the-middle the tunnel.
        # It is a REGRESSION present only in 2.15.0–2.16.1; fixed in 2.16.2.
        cve_intro = (2, 15, 0)
        cve_fixed = (2, 16, 2)

        if cve_intro <= vt < cve_fixed:
            self.finding(
                check_id="BTP-CC-008",
                title=f"Cloud Connector {version} is vulnerable to CVE-2024-25642",
                severity=self.SEVERITY_HIGH,
                category="BTP Cloud Attack Surface",
                description=(
                    f"The SAP Cloud Connector reports software version {version}, which falls "
                    "in the 2.15.0–2.16.1 range affected by CVE-2024-25642 (CWE-295, improper "
                    "certificate validation, CVSS 7.4). In these versions the Cloud Connector "
                    "does not properly validate the server certificate on its outbound cloud "
                    "connections and will trust a self-signed / untrusted certificate, so an "
                    "attacker positioned on the network path can impersonate the genuine "
                    "endpoint and perform a man-in-the-middle attack, breaking the mutual "
                    "authentication and confidentiality/integrity of the tunnel (no privileges "
                    "or user interaction required; no availability impact). Because the Cloud "
                    "Connector sits at the trust boundary between the BTP tenant and the "
                    "on-premise/private network — it holds the system certificates and the "
                    "backend allow-list that reach into S/4HANA — a compromised tunnel is a "
                    "direct exposure of the internal landscape. The Cloud Connector is "
                    "customer-managed even in RISE, so patching it is the customer's "
                    "responsibility, and this flaw was introduced by a regression, so systems "
                    "that were patched to 2.15.x/2.16.0/2.16.1 are affected."
                ),
                affected_items=[f"Cloud Connector version: {version} (affected 2.15.0–2.16.1; fix: 2.16.2+)"],
                remediation=(
                    "Upgrade the Cloud Connector to at least 2.16.2 (ideally the latest patch "
                    "of the current line) to remediate CVE-2024-25642. Plan the upgrade using "
                    "the master/shadow high-availability pair so the tunnel is not "
                    "interrupted: upgrade the shadow, fail over, then upgrade the former "
                    "master. Subscribe to the SAP Cloud Connector release notes and treat SCC "
                    "patching as part of monthly SAP Security Patch Day handling. After "
                    "upgrade, confirm the reported version, re-establish the subaccount "
                    "tunnels, and re-validate the backend allow-list and certificates."
                ),
                references=[
                    "CVE-2024-25642 — SAP Cloud Connector improper certificate validation (CWE-295)",
                    "SAP Security Note 3424610",
                    "SAP BTP Cloud Connector — Release Notes and Upgrade",
                ],
                # No affected_objects: the Cloud Connector export carries a version
                # but no name, host or instance id, and inventing one would merge
                # every customer's SCC into a single node. The version itself is a
                # property, not a subject — putting it in the identity would retire
                # this finding and raise a new one on a 2.15.2 → 2.16.0 upgrade that
                # is still vulnerable, resetting the age of an unfixed defect. So the
                # singleton component is identified by (system, client, check_id).
                scope="aggregate",
            )
        elif vt < cve_intro:
            self.finding(
                check_id="BTP-CC-008",
                title=f"Cloud Connector {version} is an old, out-of-maintenance release",
                severity=self.SEVERITY_MEDIUM,
                category="BTP Cloud Attack Surface",
                description=(
                    f"The SAP Cloud Connector reports version {version}, which predates the "
                    "2.15 line and is well below any currently-supported baseline. This "
                    "specific version is not in the CVE-2024-25642 regression range (that flaw "
                    "was introduced in 2.15.0), but running such an old, out-of-maintenance "
                    "Cloud Connector means security fixes are no longer delivered for a "
                    "component that bridges BTP and the internal network, and it will be "
                    "missing numerous later hardening and vulnerability fixes."
                ),
                affected_items=[f"Cloud Connector version: {version}"],
                remediation=(
                    "Upgrade the Cloud Connector to a currently-supported release (2.16.2+) "
                    "and keep it patched via the HA master/shadow procedure. Treat SCC "
                    "patching as part of monthly SAP Security Patch Day handling."
                ),
                references=["SAP BTP Cloud Connector — Release Notes and Upgrade"],
                # Same singleton component, same reasoning as the branch above: the
                # export names no Cloud Connector instance, and the version is a
                # property rather than a subject.
                scope="aggregate",
            )

    # ----------------------------------------------------- SAP Baseline NETCF-P
    #: Where an export may carry the Cloud Connector's high-availability state.
    #: `isHaActive` is SAP's own name for it in the SCC_CONFIG configuration store,
    #: which is what the Baseline requirement reads; the rest are the spellings a
    #: hand-assembled export tends to use.
    _SCC_HA_KEYS = ("isHaActive", "haActive", "highAvailability", "ha_active")

    def check_cloud_connector_ha(self):
        """MEDIUM: the Cloud Connector runs without a shadow instance.

        SAP Security Baseline requirement NETCF-P, config store SCC_CONFIG.
        """
        cc = self.data.get("cloud_connector")
        if not isinstance(cc, dict):
            return
        raw = None
        for key in self._SCC_HA_KEYS:
            if key in cc:
                raw = cc[key]
                break
        if raw is None:
            # Absent is not false. An export that never carried the field would
            # otherwise make every customer fail a requirement on the strength of
            # a missing column, which is the failure mode this catalogue exists to
            # avoid — BTP-AUD-001 makes the same distinction for audit state.
            return
        if isinstance(raw, str):
            active = raw.strip().lower() in ("true", "yes", "on", "1", "active")
        else:
            active = bool(raw)
        if active:
            return

        backends = cc.get("backends") or []
        items = ["high availability is not active (no shadow Cloud Connector)"]
        if backends:
            items.append("%d backend system(s) reach the estate through this "
                         "single instance" % len(backends))

        self.finding(
            check_id="BTP-CC-009",
            title="Cloud Connector runs as a single instance with no shadow",
            severity=self.SEVERITY_MEDIUM,
            category="BTP Cloud Attack Surface",
            description=(
                "The Cloud Connector reports that high availability is not "
                "active, so there is no shadow instance to take the tunnel over. "
                "This is an availability control that SAP places in its Security "
                "Baseline, and the reason is that the alternatives to a planned "
                "failover are worse than the outage: with a single instance, "
                "patching the Cloud Connector costs a tunnel outage, so the "
                "patch gets deferred, and a component that bridges BTP to the "
                "on-premise network is exactly the one that must not fall "
                "behind. The same pressure drives the workarounds — a "
                "temporary direct route around the connector, a widened "
                "firewall rule for the duration — that outlive the incident "
                "and become the exposure. An unplanned failure has the same "
                "shape with less warning."
            ),
            affected_items=items,
            remediation=(
                "Install a second Cloud Connector as a shadow instance and pair "
                "it with the master, then verify a failover before relying on "
                "it. With the pair in place, upgrade by patching the shadow, "
                "failing over, and patching the former master, so Cloud "
                "Connector patching no longer needs a maintenance window and "
                "stops competing with the tunnel's availability."
            ),
            references=[
                "SAP Security Baseline — NETCF-P (SCC parameter isHaActive)",
                "SAP BTP Cloud Connector — Configuring High Availability",
            ],
            # Same singleton reasoning as BTP-CC-008: the export names no Cloud
            # Connector instance, and inventing one would merge every customer's
            # connector into a single node.
            scope="aggregate",
        )

    # ----------------------------------------------------- SAP Baseline AUDIT-P
    #: Cloud Connector audit levels, weakest first. SAP's own vocabulary.
    _SCC_AUDIT_LEVELS = ("off", "security", "all")

    def check_cloud_connector_audit(self):
        """HIGH: the Cloud Connector is not auditing.

        SAP Security Baseline requirement AUDIT-P, config store SCC_CONFIG.
        """
        cc = self.data.get("cloud_connector")
        if not isinstance(cc, dict):
            return
        raw = cc.get("auditLevel", cc.get("audit_level"))
        if raw is None:
            audit = cc.get("audit")
            if isinstance(audit, dict):
                raw = audit.get("level", audit.get("auditLevel"))
        if raw is None:
            return
        level = str(raw).strip().lower()
        if level not in self._SCC_AUDIT_LEVELS:
            # A level this check does not recognise is not evidence of anything.
            # Reporting it as "off" would be a guess about a customer's estate.
            return
        if level != "off":
            return

        self.finding(
            check_id="BTP-CC-010",
            title="Cloud Connector audit logging is switched off",
            severity=self.SEVERITY_HIGH,
            category="BTP Cloud Attack Surface",
            description=(
                "The Cloud Connector's audit level is Off, so it records "
                "neither the administrative changes made to it nor the requests "
                "that pass through it. Both halves matter and they are "
                "different losses. The administrative half means a change to "
                "the backend allow-list — the list that decides which "
                "on-premise systems and which paths BTP can reach at all — "
                "leaves no record of who widened it or when, which is the "
                "single most consequential configuration this component holds. "
                "The traffic half means that when a question is asked about "
                "what came through the tunnel, the answer has to be assembled "
                "from the backends' own logs, if they kept any; the connector "
                "sits at the trust boundary and is the one place the whole flow "
                "is visible. Neither gap is recoverable after the fact, because "
                "the records were never written."
            ),
            affected_items=["Cloud Connector audit level: %s" % raw],
            remediation=(
                "Set the Cloud Connector audit level to All in production, or "
                "to Security where the traffic volume makes All impractical — "
                "Security still records the configuration changes and the "
                "connection decisions, which is the half that cannot be "
                "reconstructed from anywhere else. Forward the audit files off "
                "the Cloud Connector host to the same destination as the rest of "
                "the estate's logs, so they survive the host and are reviewed "
                "with everything else, and confirm the retention matches the "
                "estate's standard."
            ),
            references=[
                "SAP Security Baseline — AUDIT-P (BTP audit settings)",
                "SAP BTP Cloud Connector — Audit Logging",
            ],
            # Singleton component, as BTP-CC-008 and BTP-CC-009.
            scope="aggregate",
        )

    # ════════════════════════════════════════════════════════════════
    #  BTP-SB-*: Service Binding Secrets
    # ════════════════════════════════════════════════════════════════

    def check_service_binding_secrets(self):
        """
        Audit BTP service instance bindings:
        - Overly broad scopes on service keys
        - Old / never-rotated bindings
        - Orphaned bindings (instance deleted but key remains)
        - Bindings with admin-level scopes
        """
        bindings = self.data.get("btp_service_bindings")
        if not bindings:
            return

        binding_list = bindings if isinstance(bindings, list) else \
            bindings.get("bindings", bindings.get("serviceBindings",
            bindings.get("items", [])))

        old_bindings = []
        admin_scopes = []
        orphaned = []
        no_rotation = []
        no_rotation_objects: List[Dict[str, Any]] = []
        admin_scope_objects: List[Dict[str, Any]] = []
        orphaned_objects: List[Dict[str, Any]] = []
        rotation_days = self.get_config("binding_rotation_max_days", 180)
        now = datetime.now()

        for binding in binding_list:
            if not isinstance(binding, dict):
                continue

            name = binding.get("name", binding.get("bindingName", "unknown"))
            service = binding.get("service", binding.get("serviceName",
                     binding.get("service_instance", "")))
            created = binding.get("created", binding.get("createdAt",
                     binding.get("creation_date", "")))
            last_rotated = binding.get("lastRotated", binding.get("rotatedAt",
                          binding.get("last_rotation", "")))
            scopes = binding.get("scopes", binding.get("authorities",
                    binding.get("scope", [])))
            instance_status = binding.get("instanceStatus",
                             binding.get("instance_state", ""))

            label = f"{name} (service: {service})"

            # Check age / rotation
            rotate_ref = last_rotated or created
            if rotate_ref:
                parsed = self._parse_date_flexible(rotate_ref)
                if parsed:
                    age_days = (now - parsed).days
                    if age_days > rotation_days:
                        no_rotation.append(
                            f"{label} — age: {age_days}d (max: {rotation_days}d), "
                            f"last rotated: {rotate_ref}"
                        )
                        # The service disambiguates two bindings that share a name;
                        # the age does not, and would churn the node every run.
                        self._add_object(
                            no_rotation_objects, "service_binding", name,
                            f"service={service}" if service else None,
                        )

            # Check admin-level scopes
            if isinstance(scopes, (list, str)):
                scope_str = str(scopes).upper()
                admin_indicators = [
                    "ADMIN", "MANAGE", "WRITE_ALL", "FULL_ACCESS",
                    "SUBACCOUNT_ADMIN", "*",
                ]
                if any(ind in scope_str for ind in admin_indicators):
                    admin_scopes.append(
                        f"{label} — scopes: {scopes if isinstance(scopes, str) else ', '.join(str(s) for s in scopes[:5])}"
                    )
                    # The granted scope is what makes this binding dangerous, so it
                    # qualifies the object: the same binding narrowed to read-only is
                    # a different defect from the same binding holding admin.
                    self._add_object(
                        admin_scope_objects, "service_binding", name,
                        f"scopes={scopes if isinstance(scopes, str) else ', '.join(str(s) for s in scopes[:5])}",
                    )

            # Orphaned bindings
            if instance_status and str(instance_status).upper() in (
                "DELETED", "FAILED", "ORPHANED", "DEPROVISIONED"
            ):
                orphaned.append(f"{label} — instance status: {instance_status}")
                self._add_object(orphaned_objects, "service_binding", name,
                                 f"instanceStatus={instance_status}")

        if no_rotation:
            self.finding(
                check_id="BTP-SB-001",
                title=f"Service bindings not rotated in {rotation_days}+ days",
                severity=self.SEVERITY_HIGH,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(no_rotation)} service binding(s) have not been rotated within "
                    f"the {rotation_days}-day policy. Stale credentials increase the "
                    "risk of undetected credential compromise."
                ),
                affected_items=no_rotation,
                remediation=(
                    "Rotate all service binding credentials on a regular schedule. "
                    f"Target: {rotation_days}-day maximum lifetime. "
                    "Use BTP Service Manager API for automated rotation. "
                    "Implement credential rotation pipelines in CI/CD."
                ),
                references=["SAP BTP Security Guide — Credential Lifecycle Management"],
                affected_objects=no_rotation_objects,
                # Summary of every over-age binding; rotating one must not retire the
                # finding that still covers the others.
                scope="aggregate",
            )

        if admin_scopes:
            self.finding(
                check_id="BTP-SB-002",
                title="Service bindings with admin-level scopes",
                severity=self.SEVERITY_HIGH,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(admin_scopes)} service binding(s) have administrative or "
                    "overly broad scopes. Compromised bindings with admin access can "
                    "lead to full service takeover."
                ),
                affected_items=admin_scopes,
                remediation=(
                    "Restrict service binding scopes to minimum required permissions. "
                    "Create separate bindings with different scope levels for "
                    "admin vs operational use. Review and narrow existing scopes."
                ),
                references=["SAP BTP — Service Key Scope Management"],
                affected_objects=admin_scope_objects,
                # Summary of every over-scoped binding; narrowing one must not reset
                # the age of the finding covering the rest.
                scope="aggregate",
            )

        if orphaned:
            self.finding(
                check_id="BTP-SB-003",
                title="Orphaned service bindings (deleted/failed instances)",
                severity=self.SEVERITY_MEDIUM,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(orphaned)} service binding(s) reference instances that are "
                    "deleted or in failed state. These orphaned credentials may still "
                    "be valid and represent unmanaged access."
                ),
                affected_items=orphaned,
                remediation=(
                    "Delete all orphaned service bindings. "
                    "Implement lifecycle hooks to clean up bindings when instances "
                    "are deprovisioned. Audit using BTP Service Manager API."
                ),
                references=["SAP BTP — Service Instance Lifecycle"],
                affected_objects=orphaned_objects,
                # Summary of the orphaned-binding population; deleting one must not
                # raise a brand-new finding for the remainder.
                scope="aggregate",
            )

    # ════════════════════════════════════════════════════════════════
    #  BTP-DST-*: Destination Service Review
    # ════════════════════════════════════════════════════════════════

    def check_btp_destinations(self):
        """
        Audit BTP Destination service configurations:
        - Destinations with stored credentials
        - Proxy type misconfigurations
        - Destinations to deprecated/decommissioned systems
        - Missing TLS verification
        """
        dests = self.data.get("btp_destinations")
        if not dests:
            return

        dest_list = dests if isinstance(dests, list) else \
            dests.get("destinations", dests.get("items", []))

        stored_creds = []
        no_tls_verify = []
        stale_dests = []
        proxy_issues = []
        stored_cred_objects: List[Dict[str, Any]] = []
        no_tls_objects: List[Dict[str, Any]] = []
        stale_dest_objects: List[Dict[str, Any]] = []
        proxy_objects: List[Dict[str, Any]] = []
        now = datetime.now()

        for dest in dest_list:
            if not isinstance(dest, dict):
                continue

            name = dest.get("Name", dest.get("name", dest.get("destinationName", "unknown")))
            url = dest.get("URL", dest.get("url", dest.get("host", "")))
            auth_type = dest.get("Authentication", dest.get("authentication",
                       dest.get("auth", "")))
            proxy_type = dest.get("ProxyType", dest.get("proxyType", ""))
            tls_verify = dest.get("TrustAll", dest.get("trustAll",
                        dest.get("skipSSLValidation", "")))
            last_modified = dest.get("lastModified", dest.get("modifiedAt", ""))
            user = dest.get("User", dest.get("user", ""))

            label = f"{name} → {url}"

            # Stored credentials.
            #
            # SPELLING IS NORMALISED BECAUSE THE LIVE API DISAGREES WITH THE
            # FIXTURE. The Destination service returns `BasicAuthentication`
            # and `OAuth2Password` — CamelCase, no separator. This comparison
            # was written against a hand-made sample that spelled them
            # `BASIC_AUTHENTICATION` and `OAUTH2_PASSWORD`, so it matched the
            # fixture, passed its tests, and would have matched nothing at all
            # the first time it was given a real export: a silent clean on the
            # most common destination misconfiguration there is. Found by
            # feeding it what the API actually returns.
            if _norm_auth(auth_type) in (
                "BASICAUTHENTICATION", "BASIC", "OAUTH2PASSWORD",
            ) and user:
                stored_creds.append(
                    f"{label} (auth: {auth_type}, user: {user})"
                )
                # The authentication type is the defect: the same destination on
                # OAuth client_credentials is not this finding.
                self._add_object(stored_cred_objects, "btp_destination", name,
                                 f"auth={auth_type}")

            # TLS verification disabled
            if str(tls_verify).lower() in ("true", "1", "yes"):
                no_tls_verify.append(f"{label} — TrustAll/SkipSSL = true")
                self._add_object(no_tls_objects, "btp_destination", name,
                                 f"TrustAll={tls_verify}")
                # The URL is the endpoint actually exposed to interception, and is
                # a graph node in its own right.
                self._add_object(no_tls_objects, "url", url)

            # Proxy type misconfig
            if proxy_type and url:
                is_internet_url = not any(
                    p in url.lower() for p in
                    ["10.", "172.16.", "192.168.", "localhost", ".internal", ".corp"]
                )
                if proxy_type.upper() == "ON_PREMISE" and is_internet_url:
                    proxy_issues.append(
                        f"{label} — ProxyType=OnPremise but URL appears external"
                    )
                    self._add_object(proxy_objects, "btp_destination", name,
                                     f"ProxyType={proxy_type}")
                    self._add_object(proxy_objects, "url", url)
                elif proxy_type.upper() == "INTERNET" and not is_internet_url:
                    proxy_issues.append(
                        f"{label} — ProxyType=Internet but URL appears on-premise"
                    )
                    self._add_object(proxy_objects, "btp_destination", name,
                                     f"ProxyType={proxy_type}")
                    self._add_object(proxy_objects, "url", url)

            # Stale destinations
            if last_modified:
                parsed = self._parse_date_flexible(last_modified)
                if parsed:
                    days_old = (now - parsed).days
                    stale_threshold = self.get_config("destination_stale_days", 365)
                    if days_old > stale_threshold:
                        stale_dests.append(
                            f"{label} — last modified: {last_modified} ({days_old}d ago)"
                        )
                        # No date qualifier — the age grows on every run.
                        self._add_object(stale_dest_objects, "btp_destination", name)

        if stored_creds:
            self.finding(
                check_id="BTP-DST-001",
                title="BTP destinations with stored credentials",
                severity=self.SEVERITY_HIGH,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(stored_creds)} BTP destination(s) store user credentials "
                    "(Basic Auth or OAuth Password grant). Stored credentials can be "
                    "read via the Destination Service API by any app bound to it."
                ),
                affected_items=stored_creds,
                remediation=(
                    "Migrate to OAuth2 client_credentials, SAMLAssertion, or "
                    "principal propagation flows. If Basic Auth is unavoidable, "
                    "use the Credential Store service for secret management."
                ),
                references=["SAP BTP Destination Service — Authentication Types"],
                affected_objects=stored_cred_objects,
                # Summary of every destination that stores a credential; migrating
                # one to OAuth must not retire the finding covering the rest.
                scope="aggregate",
            )

        if no_tls_verify:
            self.finding(
                check_id="BTP-DST-002",
                title="BTP destinations with TLS verification disabled",
                severity=self.SEVERITY_CRITICAL,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(no_tls_verify)} BTP destination(s) have TLS certificate "
                    "verification disabled (TrustAll=true). This makes connections "
                    "vulnerable to man-in-the-middle attacks."
                ),
                affected_items=no_tls_verify,
                remediation=(
                    "Enable TLS certificate verification on all destinations. "
                    "Upload the correct CA certificates to the destination's trust store. "
                    "Never use TrustAll=true in production environments."
                ),
                references=["SAP BTP Security Guide — Transport Layer Security"],
                affected_objects=no_tls_objects,
                # Summary of every TrustAll destination; fixing one must not reset
                # the age of the finding covering the others.
                scope="aggregate",
            )

        if proxy_issues:
            self.finding(
                check_id="BTP-DST-003",
                title="BTP destinations with proxy type mismatch",
                severity=self.SEVERITY_MEDIUM,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(proxy_issues)} BTP destination(s) have proxy type settings "
                    "that don't match their target URL. This may cause routing failures "
                    "or unintended exposure through the wrong network path."
                ),
                affected_items=proxy_issues,
                remediation=(
                    "Set ProxyType=OnPremise for backends accessible via Cloud Connector. "
                    "Set ProxyType=Internet for public/cloud endpoints. "
                    "Verify each destination's network routing path."
                ),
                references=["SAP BTP Destination Service — Proxy Configuration"],
                affected_objects=proxy_objects,
                # Summary of every proxy-type mismatch; correcting one destination
                # must leave the rest on the same finding.
                scope="aggregate",
            )

        if stale_dests:
            self.finding(
                check_id="BTP-DST-004",
                title="Stale BTP destinations (not modified in 365+ days)",
                severity=self.SEVERITY_LOW,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(stale_dests)} BTP destination(s) have not been modified in "
                    "over a year. They may point to decommissioned systems or contain "
                    "outdated credentials."
                ),
                affected_items=stale_dests,
                remediation=(
                    "Review all stale destinations for continued business need. "
                    "Delete unused destinations. Update credentials on active ones."
                ),
                references=["SAP BTP — Destination Lifecycle Management"],
                affected_objects=stale_dest_objects,
                # Summary of the stale-destination population; deleting one must not
                # raise a fresh finding for the remainder.
                scope="aggregate",
            )

    # ════════════════════════════════════════════════════════════════
    #  BTP-IAS-*: Identity Authentication Service
    # ════════════════════════════════════════════════════════════════

    def check_ias_policies(self):
        """
        Review IAS application and authentication policy configuration:
        - Applications without conditional authentication
        - Missing IP restrictions
        - Risk-based authentication not enabled
        """
        ias = self.data.get("ias_config")
        if not ias:
            return

        apps = ias if isinstance(ias, list) else \
            ias.get("applications", ias.get("apps", []))

        no_conditional = []
        no_ip_restrict = []
        no_risk_based = []
        no_conditional_objects: List[Dict[str, Any]] = []
        no_ip_objects: List[Dict[str, Any]] = []

        for app in apps:
            if not isinstance(app, dict):
                continue

            name = app.get("name", app.get("appName",
                   app.get("display_name", "unknown")))
            auth_rules = app.get("authenticationRules",
                        app.get("conditionalAuth",
                        app.get("authentication_policies", [])))
            ip_rules = app.get("ipRestrictions", app.get("ipRanges",
                      app.get("ip_filter", [])))
            risk_based = app.get("riskBasedAuth", app.get("riskBased",
                        app.get("risk_based_authentication", False)))
            app_type = app.get("type", app.get("appType", ""))

            # Skip system/technical apps
            if str(app_type).upper() in ("SYSTEM", "TECHNICAL", "BUNDLED"):
                continue

            label = f"{name} (type: {app_type or 'standard'})"

            if not auth_rules or (isinstance(auth_rules, list) and len(auth_rules) == 0):
                no_conditional.append(label)
                # No qualifier: the defect is the ABSENCE of a rule, so there is no
                # dangerous value to narrow the object with — and leaving it off lets
                # this app dedupe with the same app named by the other IAS checks.
                self._add_object(no_conditional_objects, "ias_application", name)

            if not ip_rules or (isinstance(ip_rules, list) and len(ip_rules) == 0):
                no_ip_restrict.append(label)
                self._add_object(no_ip_objects, "ias_application", name)

            if not risk_based or str(risk_based).lower() in ("false", "0", "no", "disabled"):
                no_risk_based.append(label)

        if no_conditional:
            self.finding(
                check_id="BTP-IAS-001",
                title="IAS applications without conditional authentication rules",
                severity=self.SEVERITY_MEDIUM,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(no_conditional)} IAS application(s) have no conditional "
                    "authentication policies. Without conditional auth, all users "
                    "authenticate via the same flow regardless of risk context."
                ),
                affected_items=no_conditional,
                remediation=(
                    "Configure conditional authentication rules in IAS for each "
                    "business-critical application. Define rules based on: "
                    "user group, IP range, authentication method, and identity provider. "
                    "Enforce stronger auth for admin or sensitive operations."
                ),
                references=["SAP IAS — Conditional Authentication"],
                affected_objects=no_conditional_objects,
                # Summary of every IAS application missing conditional auth;
                # configuring one must not retire the finding for the rest.
                scope="aggregate",
            )

        if no_ip_restrict:
            self.finding(
                check_id="BTP-IAS-002",
                title="IAS applications without IP-based access restrictions",
                severity=self.SEVERITY_MEDIUM,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(no_ip_restrict)} IAS application(s) have no IP restrictions "
                    "configured. Users can authenticate from any network location."
                ),
                affected_items=no_ip_restrict,
                remediation=(
                    "Configure allowed IP ranges for each application in IAS. "
                    "At minimum, restrict admin/backend applications to corporate "
                    "IP ranges. Use IAS conditional authentication for IP-based rules."
                ),
                references=["SAP IAS — IP Range Restrictions"],
                affected_objects=no_ip_objects,
                # Summary of every IAS application without IP restrictions; adding
                # a range to one must not reset the finding's age.
                scope="aggregate",
            )

    def check_ias_mfa(self):
        """Check IAS MFA enforcement across applications."""
        ias = self.data.get("ias_config")
        if not ias:
            return

        apps = ias if isinstance(ias, list) else \
            ias.get("applications", ias.get("apps", []))

        no_mfa = []
        no_mfa_objects: List[Dict[str, Any]] = []
        for app in apps:
            if not isinstance(app, dict):
                continue

            name = app.get("name", app.get("appName", "unknown"))
            mfa = app.get("mfaEnabled", app.get("twoFactorAuth",
                 app.get("multiFactorAuth",
                 app.get("mfa", ""))))
            app_type = app.get("type", app.get("appType", ""))

            if str(app_type).upper() in ("SYSTEM", "TECHNICAL", "BUNDLED"):
                continue

            if not mfa or str(mfa).lower() in ("false", "0", "no", "disabled", "none", ""):
                no_mfa.append(f"{name} (MFA: {mfa or 'not configured'})")
                self._add_object(no_mfa_objects, "ias_application", name)

        if no_mfa:
            self.finding(
                check_id="BTP-IAS-003",
                title="IAS applications without multi-factor authentication",
                severity=self.SEVERITY_HIGH,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(no_mfa)} IAS application(s) do not enforce multi-factor "
                    "authentication. Without MFA, compromised passwords provide "
                    "direct access to cloud applications."
                ),
                affected_items=no_mfa,
                remediation=(
                    "Enable TOTP-based MFA for all user-facing IAS applications. "
                    "At minimum, enforce MFA for admin and privileged access. "
                    "Configure IAS to require MFA as a second authentication factor."
                ),
                references=["SAP IAS — Multi-Factor Authentication Configuration"],
                affected_objects=no_mfa_objects,
                # Summary of every IAS application without MFA; enabling MFA on one
                # must not retire the finding that still covers the others.
                scope="aggregate",
            )

    def check_ias_password_policy(self):
        """HIGH/MEDIUM: weak IAS tenant password policy for local users."""
        ias = self.data.get("ias_config")
        if not isinstance(ias, dict):
            return
        policy = ias.get("passwordPolicy", ias.get("password_policy"))
        if not isinstance(policy, dict):
            return

        issues = []
        weak_len = False
        # Minimum length — distinguish an ABSENT field (not asserted) from an
        # explicit value; an explicit 0 (no minimum enforced) is the worst case.
        raw_len = policy.get("minLength", policy.get("minimumLength"))
        if raw_len is not None and str(raw_len) != "":
            try:
                min_len = int(raw_len)
            except (TypeError, ValueError):
                min_len = None
            if min_len is not None and min_len < 8:
                issues.append(f"minimum length = {min_len} (< 8)")
                weak_len = True
        # Account lockout after failed attempts — only evaluate when the field is
        # actually present (absence is not evidence of a missing lockout).
        lockout = policy.get("maxFailedAttempts", policy.get("lockoutThreshold",
                 policy.get("failedLogonAttempts")))
        if lockout not in (None, ""):
            try:
                lockout_n = int(lockout)
            except (TypeError, ValueError):
                lockout_n = None
            if lockout_n is not None and (lockout_n == 0 or lockout_n > 10):
                issues.append(f"account lockout threshold = {lockout}")
        # Complexity
        complexity = policy.get("requireComplexity", policy.get("complexityEnabled",
                    policy.get("requireMixedCase")))
        if complexity is not None and str(complexity).lower() in ("false", "0", "no", "disabled"):
            issues.append("password complexity not enforced")
        # Password expiry / max age — the genuine gap of IAS's built-in 'Standard'
        # policy vs 'Enterprise' (Standard already enforces length 8 / 3-of-4
        # complexity / 5-attempt lockout, so the tier alone is NOT a weakness).
        raw_age = policy.get("passwordExpiryDays", policy.get("maxPasswordAge"))
        if raw_age is not None and str(raw_age) != "":
            try:
                age = int(raw_age)
            except (TypeError, ValueError):
                age = None
            if age == 0:
                issues.append("password expiry = 0 (passwords never expire)")

        if issues:
            sev = self.SEVERITY_HIGH if weak_len else self.SEVERITY_MEDIUM
            self.finding(
                check_id="BTP-IAS-004",
                title="IAS password policy for local users is weak",
                severity=sev,
                category="BTP Cloud Attack Surface",
                description=(
                    "The SAP Cloud Identity Services (IAS) tenant password policy that "
                    "governs locally-stored user credentials falls below hardening "
                    "expectations in the specific dimensions listed under affected items "
                    "below. IAS local users are a frequent authentication fallback even in "
                    "landscapes that federate to a corporate IdP, and each such weakness "
                    "lowers the cost of password guessing and credential stuffing against "
                    "the identity provider that fronts the entire BTP account and, via "
                    "trust, the S/4HANA Fiori launchpad. Because IAS authenticates "
                    "administrators of the BTP cockpit itself, a weak local-user policy is "
                    "an account-wide exposure, not an application-local one. Note that IAS's "
                    "built-in 'Standard' policy already enforces minimum length 8, 3-of-4 "
                    "character complexity and lockout after 5 failed attempts; the main gap "
                    "versus the 'Enterprise' policy is password expiry/history, so only the "
                    "concretely-detected deviations below are reported (the policy tier name "
                    "alone is not treated as a finding)."
                ),
                affected_items=issues,
                remediation=(
                    "In the IAS admin console (Applications & Resources → Tenant Settings → "
                    "Password Policy) move the tenant to the 'Enterprise' password policy or "
                    "a custom policy that enforces: minimum length ≥ 8 (12+ for privileged "
                    "tenants), password complexity (mixed case, digits, special characters), "
                    "account lockout after ≤ 5–10 failed attempts, a bounded maximum "
                    "password age, and password-history reuse prevention. Where a corporate "
                    "IdP is available, prefer delegating authentication to it and disabling "
                    "local-user password logon entirely (see BTP-IAS-005) so this policy "
                    "governs only unavoidable break-glass accounts. Re-export and re-scan to "
                    "confirm the tightened values."
                ),
                references=[
                    "SAP Cloud Identity Services — Configure Password Policy",
                    "SAP BTP Security Recommendations — Identity Authentication",
                ],
                # No affected_objects: `issues` lists DIMENSIONS of one tenant-wide
                # policy (minimum length, lockout threshold), not objects. The export
                # carries no tenant name to hang them on, and the policy fields are
                # IAS settings — not SAP profile parameters — so naming them as
                # parameter objects would invent SAP identifiers that do not exist.
                # A tenant singleton is correctly identified by check_id alone.
                scope="aggregate",
            )

    def check_ias_idp_enforcement(self):
        """HIGH: corporate IdP configured but local password fallback still allowed."""
        ias = self.data.get("ias_config")
        if not isinstance(ias, dict):
            return
        idp = ias.get("corporateIdP", ias.get("corporateIdp", ias.get("corporate_idp")))
        if not isinstance(idp, dict):
            return

        enabled = idp.get("enabled", idp.get("configured"))
        if enabled is None or str(enabled).lower() in ("false", "0", "no"):
            return  # no corporate IdP configured -> this control does not apply

        enforced = idp.get("enforced", idp.get("enforce"))
        local_fallback = idp.get("localFallbackAllowed",
                        idp.get("allowLocalLogon", idp.get("passwordLogonAllowed")))

        reasons = []
        if enforced is not None and str(enforced).lower() in ("false", "0", "no"):
            reasons.append("corporate IdP configured but not enforced (users may pick local logon)")
        if local_fallback is not None and str(local_fallback).lower() in ("true", "1", "yes", "enabled"):
            reasons.append("local IAS password logon still permitted alongside corporate IdP")

        if reasons:
            self.finding(
                check_id="BTP-IAS-005",
                title="Corporate IdP not enforced — local password fallback allowed",
                severity=self.SEVERITY_HIGH,
                category="BTP Cloud Attack Surface",
                description=(
                    "A corporate identity provider is configured in IAS, but local IAS "
                    "password authentication has not been disabled/enforced away. This "
                    "leaves a parallel authentication path that bypasses the corporate "
                    "IdP's controls — conditional access, MFA, session policies, joiner/"
                    "mover/leaver deprovisioning and central logging. An attacker who "
                    "obtains or guesses a local IAS password (or targets a former employee "
                    "whose corporate account was disabled but whose IAS local user was not) "
                    "can authenticate to BTP and the trusting S/4HANA applications without "
                    "ever touching the corporate IdP, defeating the single-sign-on security "
                    "model the organisation believes is in force. Enforcement gaps of this "
                    "kind are a common root cause of 'we had MFA but the breach still "
                    "happened' incidents in federated SAP landscapes."
                ),
                affected_items=reasons,
                remediation=(
                    "Enforce the corporate IdP as the sole authenticating authority: in IAS, "
                    "set the corporate identity provider as default and disable local "
                    "password authentication for end users (Applications → Authentication & "
                    "Access → Identity Providers / Logon Alternatives). Retain at most a "
                    "small number of explicitly-documented break-glass local accounts, each "
                    "with MFA and monitoring. Verify that conditional-authentication rules "
                    "route every business application to the corporate IdP, and reconcile "
                    "IAS local users against the corporate directory to remove orphaned "
                    "accounts. Confirm no application still offers a 'log on with password' "
                    "alternative after the change."
                ),
                references=[
                    "SAP Cloud Identity Services — Corporate Identity Providers",
                    "SAP BTP Security Recommendations — Enforce Single Sign-On",
                ],
                # No affected_objects: `reasons` are enforcement gaps in the tenant's
                # single corporate-IdP trust, and the export names no identity
                # provider (only enabled/enforced/fallback flags and a protocol).
                # Fabricating a name would merge every tenant's IdP into one node.
                scope="aggregate",
            )

    # ════════════════════════════════════════════════════════════════
    #  BTP-ENT-*: Entitlement Sprawl
    # ════════════════════════════════════════════════════════════════

    def check_entitlement_sprawl(self):
        """
        Detect entitled but unused BTP services (dormant attack surface).
        """
        entitlements = self.data.get("btp_entitlements")
        if not entitlements:
            return

        entitled = entitlements if isinstance(entitlements, list) else \
            entitlements.get("entitlements", entitlements.get("services",
            entitlements.get("quotaAssignments", [])))

        unused_entitled = []
        security_unused = []
        unused_objects: List[Dict[str, Any]] = []
        security_unused_objects: List[Dict[str, Any]] = []

        for ent in entitled:
            if not isinstance(ent, dict):
                continue

            service = ent.get("serviceName", ent.get("service",
                    ent.get("name", "")))
            plan = ent.get("planName", ent.get("plan", ""))
            quota = ent.get("quota", ent.get("amount", 0))
            used = ent.get("used", ent.get("usage",
                  ent.get("instances_created", 0)))
            subaccount = ent.get("subaccount", ent.get("subaccountId", ""))

            try:
                quota_int = int(str(quota))
                used_int = int(str(used))
            except (ValueError, TypeError):
                continue

            if quota_int > 0 and used_int == 0:
                label = f"{service}/{plan} — entitled: {quota_int}, used: 0"
                if subaccount:
                    label += f" (subaccount: {subaccount})"
                unused_entitled.append(label)
                # The plan is part of what is entitled — the same service on a
                # different plan is a different entitlement.
                self._add_object(unused_objects, "btp_service", service,
                                 f"plan={plan}" if plan else None)
                self._add_object(unused_objects, "subaccount", subaccount)

                # Flag security-critical services that are entitled but unused
                if any(s in service.lower() for s in self.SECURITY_CRITICAL_SERVICES):
                    security_unused.append(label)
                    self._add_object(security_unused_objects, "btp_service", service,
                                     f"plan={plan}" if plan else None)
                    self._add_object(security_unused_objects, "subaccount", subaccount)

        if unused_entitled:
            self.finding(
                check_id="BTP-ENT-001",
                title="BTP services entitled but never provisioned",
                severity=self.SEVERITY_LOW,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(unused_entitled)} BTP service entitlement(s) have quota "
                    "allocated but zero instances provisioned. Unused entitlements "
                    "represent dormant capability that could be activated without "
                    "additional approval."
                ),
                affected_items=unused_entitled[:30],
                remediation=(
                    "Review and deallocate unused entitlements at the directory/global "
                    "account level. Implement entitlement governance with periodic "
                    "reviews of allocated vs consumed quotas."
                ),
                references=["SAP BTP — Entitlement and Quota Management"],
                details={"total_unused": len(unused_entitled)},
                # Summary of the unused-entitlement population. The display list is
                # truncated at 30 for readability; the objects are not, because they
                # are graph nodes rather than report text — and they stay out of the
                # identity so deallocating one quota does not reset the age.
                affected_objects=unused_objects,
                scope="aggregate",
            )

        if security_unused:
            self.finding(
                check_id="BTP-ENT-002",
                title="Security-critical BTP services entitled but not provisioned",
                severity=self.SEVERITY_MEDIUM,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(security_unused)} security-critical service(s) are entitled "
                    "but have no instances. These include audit logging, credential store, "
                    "and malware scanner — services that SHOULD be actively used."
                ),
                affected_items=security_unused,
                remediation=(
                    "Provision and configure security-critical services: "
                    "auditlog (for compliance), credstore (for secret management), "
                    "malware-scanner (for content scanning), and cloud-logging "
                    "(for SIEM integration)."
                ),
                references=["SAP BTP Security Recommendations — Essential Services"],
                affected_objects=security_unused_objects,
                # Summary of the security services left unprovisioned; provisioning
                # one must not retire the finding covering the others.
                scope="aggregate",
            )

    # ════════════════════════════════════════════════════════════════
    #  BTP-EM-*: Event Mesh Topic Authorization
    # ════════════════════════════════════════════════════════════════

    def check_event_mesh_topics(self):
        """
        Audit Event Mesh queue/topic configurations:
        - Overly broad topic subscriptions (wildcard patterns)
        - Queues without access control
        - Cross-namespace event exposure
        """
        em_data = self.data.get("event_mesh")
        if not em_data:
            return

        queues = em_data if isinstance(em_data, list) else \
            em_data.get("queues", em_data.get("subscriptions", []))

        wildcard_topics = []
        no_acl_queues = []
        cross_namespace = []
        wildcard_topic_objects: List[Dict[str, Any]] = []
        no_acl_objects: List[Dict[str, Any]] = []
        cross_namespace_objects: List[Dict[str, Any]] = []

        for queue in queues:
            if not isinstance(queue, dict):
                continue

            name = queue.get("name", queue.get("queueName", "unknown"))
            topics = queue.get("topics", queue.get("subscriptions",
                    queue.get("topicSubscriptions", [])))
            acl = queue.get("accessPolicy", queue.get("acl",
                 queue.get("permissions", "")))
            namespace = queue.get("namespace", queue.get("messageNamespace", ""))

            # Wildcard topic subscriptions
            if isinstance(topics, list):
                for topic in topics:
                    topic_str = str(topic)
                    if "*" in topic_str or ">" in topic_str or "#" in topic_str:
                        wildcard_topics.append(
                            f"Queue: {name} — topic: {topic_str}"
                        )
                        # The wildcard pattern is the defect: the same queue bound to
                        # one explicit topic is not this finding.
                        self._add_object(wildcard_topic_objects, "event_queue", name,
                                         f"topic={topic_str}")

                    # Cross-namespace subscriptions
                    if namespace and isinstance(topic, str):
                        topic_ns = topic.split("/")[0] if "/" in topic else ""
                        if topic_ns and topic_ns != namespace:
                            cross_namespace.append(
                                f"Queue: {name} — subscribes to foreign namespace: "
                                f"{topic_ns} (own: {namespace})"
                            )
                            self._add_object(cross_namespace_objects, "event_queue",
                                             name, f"foreignNamespace={topic_ns}")

            # No ACL defined
            if not acl or str(acl).upper() in ("NONE", "OPEN", "", "PUBLIC"):
                no_acl_queues.append(f"{name} — access policy: {acl or 'none'}")
                self._add_object(no_acl_objects, "event_queue", name,
                                 f"accessPolicy={acl}" if acl else None)

        if wildcard_topics:
            self.finding(
                check_id="BTP-EM-001",
                title="Event Mesh queues with wildcard topic subscriptions",
                severity=self.SEVERITY_HIGH,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(wildcard_topics)} Event Mesh queue(s) subscribe to wildcard "
                    "topic patterns. Wildcard subscriptions can capture events from "
                    "unintended business processes, leaking sensitive event data."
                ),
                affected_items=wildcard_topics,
                remediation=(
                    "Replace wildcard topic subscriptions with specific topic paths. "
                    "Follow the least-privilege principle for event consumption. "
                    "Use namespace-qualified topic paths for isolation."
                ),
                references=["SAP Event Mesh — Topic Authorization Best Practices"],
                affected_objects=wildcard_topic_objects,
                # Summary of every wildcard subscription; narrowing one queue must
                # not retire the finding covering the rest.
                scope="aggregate",
            )

        if no_acl_queues:
            self.finding(
                check_id="BTP-EM-002",
                title="Event Mesh queues without access control policies",
                severity=self.SEVERITY_HIGH,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(no_acl_queues)} Event Mesh queue(s) have no access control "
                    "policy defined. Any application with Event Mesh binding can "
                    "publish to or consume from these queues."
                ),
                affected_items=no_acl_queues,
                remediation=(
                    "Define explicit access control rules for each queue specifying "
                    "which client IDs can publish and consume. "
                    "Use Event Mesh management API to set queue-level permissions."
                ),
                references=["SAP Event Mesh — Queue Access Control"],
                affected_objects=no_acl_objects,
                # Summary of every queue without an access policy; adding one policy
                # must not reset the age of the finding covering the others.
                scope="aggregate",
            )

        if cross_namespace:
            self.finding(
                check_id="BTP-EM-003",
                title="Event Mesh queues subscribing to foreign namespaces",
                severity=self.SEVERITY_MEDIUM,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(cross_namespace)} queue(s) subscribe to topics in a different "
                    "namespace. Cross-namespace subscriptions may indicate unintended "
                    "event flow between separate business domains."
                ),
                affected_items=cross_namespace,
                remediation=(
                    "Verify cross-namespace subscriptions are intentional. "
                    "Document cross-domain event flows. "
                    "Use separate Event Mesh instances for isolated domains."
                ),
                references=["SAP Event Mesh — Namespace Isolation"],
                affected_objects=cross_namespace_objects,
                # Summary of every cross-namespace subscription; unsubscribing one
                # must leave the rest on the same finding.
                scope="aggregate",
            )

    # ════════════════════════════════════════════════════════════════
    #  BTP-CPI-*: Cloud Integration (CPI) Security
    # ════════════════════════════════════════════════════════════════

    def check_cpi_credential_stores(self):
        """
        Audit CPI credential store for security issues:
        - Credentials not using secure store (hardcoded in iFlow)
        - Old/never-rotated credentials
        - Overly broad credential access
        """
        cpi = self.data.get("cpi_artifacts")
        if not cpi:
            return

        credentials = cpi.get("credentials", cpi.get("securityMaterial",
                    cpi.get("credentialStore", [])))

        if not isinstance(credentials, list):
            return

        old_creds = []
        type_issues = []
        old_cred_objects: List[Dict[str, Any]] = []
        type_issue_objects: List[Dict[str, Any]] = []
        rotation_days = self.get_config("cpi_credential_rotation_days", 180)
        now = datetime.now()

        for cred in credentials:
            if not isinstance(cred, dict):
                continue

            name = cred.get("name", cred.get("alias", "unknown"))
            cred_type = cred.get("type", cred.get("kind", ""))
            deployed = cred.get("deployedOn", cred.get("lastModified",
                      cred.get("created", "")))
            owner = cred.get("deployedBy", cred.get("owner", ""))

            label = f"{name} (type: {cred_type})"

            # Age check
            if deployed:
                parsed = self._parse_date_flexible(deployed)
                if parsed:
                    age_days = (now - parsed).days
                    if age_days > rotation_days:
                        old_creds.append(
                            f"{label} — age: {age_days}d (deployed: {deployed})"
                        )
                        # Age is the defect but cannot qualify the object: it grows
                        # every run and would churn the node.
                        self._add_object(old_cred_objects, "cpi_credential", name)

            # Plain text or weak credential types
            if cred_type and cred_type.upper() in (
                "PLAIN_TEXT", "USER_CREDENTIAL", "BASIC"
            ):
                type_issues.append(
                    f"{label} — consider migrating to OAuth or certificate"
                )
                # Here the credential TYPE is exactly what makes it dangerous.
                self._add_object(type_issue_objects, "cpi_credential", name,
                                 f"type={cred_type}")

        if old_creds:
            self.finding(
                check_id="BTP-CPI-001",
                title=f"CPI credentials not rotated in {rotation_days}+ days",
                severity=self.SEVERITY_HIGH,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(old_creds)} CPI credential(s) have not been updated in over "
                    f"{rotation_days} days. Integration credentials should be rotated "
                    "regularly to limit exposure from credential compromise."
                ),
                affected_items=old_creds,
                remediation=(
                    "Rotate all CPI security material on a regular schedule. "
                    "Use the CPI Operations API for automated deployment. "
                    "Implement credential rotation as part of CI/CD pipelines."
                ),
                references=["SAP CPI — Security Material Management"],
                affected_objects=old_cred_objects,
                # Summary of every over-age credential; rotating one must not retire
                # the finding covering the others.
                scope="aggregate",
            )

        if type_issues:
            self.finding(
                check_id="BTP-CPI-002",
                title="CPI credentials using basic/plaintext authentication",
                severity=self.SEVERITY_MEDIUM,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(type_issues)} CPI credential(s) use basic username/password "
                    "or plaintext credentials. Modern integrations should use "
                    "OAuth 2.0, client certificates, or SAML assertions."
                ),
                affected_items=type_issues,
                remediation=(
                    "Migrate CPI credentials to OAuth 2.0 client credentials or "
                    "X.509 certificate-based authentication where supported. "
                    "Use the BTP Credential Store service for centralized secret management."
                ),
                references=["SAP CPI Security Best Practices"],
                affected_objects=type_issue_objects,
                # Summary of every basic/plaintext credential; migrating one must not
                # reset the age of the finding covering the rest.
                scope="aggregate",
            )

    def check_cpi_iflow_security(self):
        """Check iFlow configurations for security issues."""
        cpi = self.data.get("cpi_artifacts")
        if not cpi:
            return

        iflows = cpi.get("iflows", cpi.get("integrationFlows",
                cpi.get("artifacts", [])))

        if not isinstance(iflows, list):
            return

        hardcoded_creds = []
        no_auth_sender = []
        http_endpoints = []
        hardcoded_objects: List[Dict[str, Any]] = []
        no_auth_objects: List[Dict[str, Any]] = []
        http_endpoint_objects: List[Dict[str, Any]] = []

        for flow in iflows:
            if not isinstance(flow, dict):
                continue

            name = flow.get("name", flow.get("id", "unknown"))
            sender_auth = flow.get("senderAuth", flow.get("inboundAuth",
                         flow.get("senderAuthentication", "")))
            endpoints = flow.get("endpoints", flow.get("senderEndpoints", []))
            has_hardcoded = flow.get("hardcodedCredentials",
                           flow.get("embeddedCredentials", False))

            # Hardcoded credentials in iFlow
            if has_hardcoded in (True, "true", "True", "1", "yes"):
                hardcoded_creds.append(f"{name} — contains embedded credentials")
                self._add_object(hardcoded_objects, "iflow", name)

            # No sender authentication
            if sender_auth and str(sender_auth).upper() in (
                "NONE", "ANONYMOUS", "OPEN", ""
            ):
                no_auth_sender.append(
                    f"{name} — sender auth: {sender_auth or 'none'}"
                )
                # The configured sender auth is the dangerous value.
                self._add_object(no_auth_objects, "iflow", name,
                                 f"senderAuth={sender_auth}")

            # HTTP (non-HTTPS) endpoints
            if isinstance(endpoints, list):
                for ep in endpoints:
                    ep_str = str(ep).lower()
                    if ep_str.startswith("http://") and "localhost" not in ep_str:
                        http_endpoints.append(f"{name} — endpoint: {ep}")
                        self._add_object(http_endpoint_objects, "iflow", name)
                        # The plain-HTTP URL itself is the exposed thing; it is kept
                        # in its original case because a URL is case-bearing.
                        self._add_object(http_endpoint_objects, "url", ep)

        if hardcoded_creds:
            self.finding(
                check_id="BTP-CPI-003",
                title="CPI iFlows with hardcoded/embedded credentials",
                severity=self.SEVERITY_CRITICAL,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(hardcoded_creds)} iFlow(s) contain embedded credentials "
                    "rather than referencing the credential store. Hardcoded credentials "
                    "are visible in iFlow source, cannot be rotated independently, "
                    "and may leak through version history or exports."
                ),
                affected_items=hardcoded_creds,
                remediation=(
                    "Extract all credentials to CPI Security Material store. "
                    "Reference credentials via aliases in iFlow configuration. "
                    "Audit iFlow source for any remaining plaintext secrets."
                ),
                references=["SAP CPI — Security Material Externalization"],
                affected_objects=hardcoded_objects,
                # Summary of every iFlow carrying an embedded secret; externalising
                # one must not retire the finding covering the others.
                scope="aggregate",
            )

        if no_auth_sender:
            self.finding(
                check_id="BTP-CPI-004",
                title="CPI iFlows with no sender authentication",
                severity=self.SEVERITY_HIGH,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(no_auth_sender)} iFlow(s) accept inbound messages without "
                    "authentication. Unauthenticated senders can inject messages "
                    "into integration flows, potentially triggering business processes."
                ),
                affected_items=no_auth_sender,
                remediation=(
                    "Configure sender authentication on all inbound iFlow channels. "
                    "Use Client Certificate, OAuth, or Basic Auth at minimum. "
                    "Restrict sender access using role-based authorization."
                ),
                references=["SAP CPI — Sender Authentication Configuration"],
                affected_objects=no_auth_objects,
                # Summary of every unauthenticated inbound channel; securing one must
                # not reset the age of the finding covering the rest.
                scope="aggregate",
            )

        if http_endpoints:
            self.finding(
                check_id="BTP-CPI-005",
                title="CPI iFlows using unencrypted HTTP endpoints",
                severity=self.SEVERITY_HIGH,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(http_endpoints)} iFlow(s) reference plain HTTP (non-HTTPS) "
                    "endpoints. Data transmitted over HTTP is unencrypted and "
                    "vulnerable to interception."
                ),
                affected_items=http_endpoints,
                remediation=(
                    "Migrate all iFlow endpoints to HTTPS. "
                    "Configure proper TLS certificates for all external connections. "
                    "Remove any HTTP fallback configurations."
                ),
                references=["SAP CPI — Transport Layer Security"],
                affected_objects=http_endpoint_objects,
                # Summary of every plain-HTTP endpoint; moving one to HTTPS must not
                # retire the finding covering the others.
                scope="aggregate",
            )

    # ════════════════════════════════════════════════════════════════
    #  BTP-NET-*: Network Isolation
    # ════════════════════════════════════════════════════════════════

    def check_network_isolation(self):
        """
        Check Private Link / network isolation configurations.
        """
        net_data = self.data.get("btp_network")
        if not net_data:
            return

        configs = net_data if isinstance(net_data, list) else \
            net_data.get("endpoints", net_data.get("privateLinks",
            net_data.get("configurations", [])))

        public_endpoints = []
        no_private_link = []
        public_endpoint_objects: List[Dict[str, Any]] = []
        no_private_link_objects: List[Dict[str, Any]] = []

        for cfg in configs:
            if not isinstance(cfg, dict):
                continue

            service = cfg.get("service", cfg.get("serviceName", ""))
            endpoint_type = cfg.get("endpointType", cfg.get("type",
                           cfg.get("connectivity", "")))
            private_link = cfg.get("privateLink", cfg.get("privateLinkEnabled",
                          cfg.get("private_endpoint", False)))
            url = cfg.get("url", cfg.get("endpoint", ""))

            label = f"{service} ({url})"

            if str(endpoint_type).upper() in ("PUBLIC", "INTERNET") and service:
                public_endpoints.append(
                    f"{label} — endpoint: {endpoint_type}"
                )
                self._add_object(public_endpoint_objects, "btp_service", service,
                                 f"endpointType={endpoint_type}")
                self._add_object(public_endpoint_objects, "url", url)

            # Critical services without Private Link
            critical_for_pl = ["hana", "s4hana", "abap", "connectivity"]
            if any(c in service.lower() for c in critical_for_pl):
                if not private_link or str(private_link).lower() in (
                    "false", "0", "no", "disabled", ""
                ):
                    no_private_link.append(
                        f"{label} — Private Link: not configured"
                    )
                    # No qualifier: the defect is the absence of Private Link, so
                    # there is no value from the export to narrow the service with.
                    self._add_object(no_private_link_objects, "btp_service", service)
                    self._add_object(no_private_link_objects, "url", url)

        if public_endpoints:
            self.finding(
                check_id="BTP-NET-001",
                title="BTP services using public internet endpoints",
                severity=self.SEVERITY_MEDIUM,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(public_endpoints)} BTP service endpoint(s) are accessible "
                    "via the public internet. Public endpoints increase the attack "
                    "surface and exposure to DDoS and scanning attacks."
                ),
                affected_items=public_endpoints,
                remediation=(
                    "Where available, enable Private Link or private service endpoints. "
                    "Use API Management with IP allowlisting for public APIs. "
                    "Implement WAF/DDoS protection for internet-facing endpoints."
                ),
                references=["SAP BTP — Private Link Service"],
                affected_objects=public_endpoint_objects,
                # Summary of every publicly-reachable service endpoint; privatising
                # one must not retire the finding covering the rest.
                scope="aggregate",
            )

        if no_private_link:
            self.finding(
                check_id="BTP-NET-002",
                title="Critical BTP services without Private Link",
                severity=self.SEVERITY_HIGH,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(no_private_link)} critical service(s) do not use Private Link "
                    "connectivity. Traffic to these services traverses the public "
                    "internet, increasing exposure to interception and attacks."
                ),
                affected_items=no_private_link,
                remediation=(
                    "Enable SAP Private Link Service for HANA, S/4HANA, and "
                    "Connectivity service. This routes traffic through the cloud "
                    "provider's backbone, bypassing the public internet."
                ),
                references=[
                    "SAP BTP — Private Link Service Setup",
                    "SAP Note 3267858 — Private Link for RISE",
                ],
                affected_objects=no_private_link_objects,
                # Summary of every critical service still on public routing; enabling
                # Private Link for one must not reset the finding's age.
                scope="aggregate",
            )

    # ════════════════════════════════════════════════════════════════
    #  BTP-GOV-*: Subaccount Governance
    # ════════════════════════════════════════════════════════════════

    def check_subaccount_governance(self):
        """
        Check multi-subaccount governance:
        - Inconsistent security policies across subaccounts
        - Shadow subaccounts with weak controls
        - Missing audit log service in subaccounts
        """
        subaccounts = self.data.get("btp_subaccounts")
        if not subaccounts:
            return

        sa_list = subaccounts if isinstance(subaccounts, list) else \
            subaccounts.get("subaccounts", subaccounts.get("items", []))

        no_audit = []
        no_custom_idp = []
        inconsistent = []
        no_audit_objects: List[Dict[str, Any]] = []
        no_custom_idp_objects: List[Dict[str, Any]] = []

        for sa in sa_list:
            if not isinstance(sa, dict):
                continue

            name = sa.get("name", sa.get("displayName", "unknown"))
            sa_id = sa.get("id", sa.get("subaccountId", ""))
            region = sa.get("region", sa.get("dataCenter", ""))
            custom_idp = sa.get("customIdp", sa.get("identityProvider",
                        sa.get("trustConfiguration", "")))
            environment = sa.get("environment", sa.get("env", ""))

            label = f"{name} ({sa_id}, region: {region})"

            # Missing audit log — and ONLY when that is actually known. This read
            # `sa.get("auditLogEnabled", ..., False)`, so a subaccount whose
            # export never carried the field was reported as HIGH "no audit
            # logging" on the strength of a default argument. `_audit_state`
            # returns None for that case and BTP-AUD-001 reports it as
            # unassessed, which is what it is.
            if self._audit_state(sa) is False:
                no_audit.append(label)
                # The subaccount id is preferred over the display name: it is the
                # stable key, it survives a rename, and it is the same string the
                # Cloud Connector ACL check names, so both findings land on one node.
                self._add_object(no_audit_objects, "subaccount", sa_id or name)

            # Still using default IDP (no custom IDP configured)
            if not custom_idp or str(custom_idp).lower() in (
                "sap.default", "default", "", "sap.ids"
            ):
                no_custom_idp.append(label)
                self._add_object(no_custom_idp_objects, "subaccount", sa_id or name)

        if no_audit:
            self.finding(
                check_id="BTP-GOV-001",
                title="BTP subaccounts without audit logging",
                severity=self.SEVERITY_HIGH,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(no_audit)} BTP subaccount(s) do not have the audit log "
                    "service enabled. Without audit logging, security events and "
                    "configuration changes are not recorded."
                ),
                affected_items=no_audit,
                remediation=(
                    "Enable the Audit Log service in every BTP subaccount. "
                    "Configure audit log forwarding to your SIEM (Splunk, Sentinel). "
                    "Set retention periods to meet compliance requirements."
                ),
                references=["SAP BTP — Audit Log Service Configuration"],
                affected_objects=no_audit_objects,
                # Summary of every subaccount without audit logging; enabling it in
                # one must not retire the finding covering the others.
                scope="aggregate",
            )

        if no_custom_idp:
            self.finding(
                check_id="BTP-GOV-002",
                title="BTP subaccounts using default SAP IDP only",
                severity=self.SEVERITY_MEDIUM,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(no_custom_idp)} BTP subaccount(s) rely on the default SAP "
                    "ID Service without a custom corporate IDP. Users authenticate "
                    "with SAP IDs rather than corporate credentials, bypassing "
                    "centralized identity governance."
                ),
                affected_items=no_custom_idp,
                remediation=(
                    "Configure a custom IDP (corporate Azure AD, Okta, etc.) for "
                    "every subaccount. Use SAP IAS as the proxy IDP for consistent "
                    "policy enforcement across all subaccounts."
                ),
                references=["SAP BTP Security Guide — Identity Federation"],
                affected_objects=no_custom_idp_objects,
                # Summary of every subaccount still on the default SAP IDP;
                # federating one must not reset the age of the finding.
                scope="aggregate",
            )

    # ════════════════════════════════════════════════════════════════
    #  BTP-MIG-*: XSUAA vs IAS Migration
    # ════════════════════════════════════════════════════════════════

    def check_xsuaa_migration(self):
        """
        Check for applications still using deprecated XSUAA trust chains
        instead of SAP Cloud Identity Services (IAS).
        """
        ias = self.data.get("ias_config")
        if not ias:
            return

        if not isinstance(ias, dict):
            return

        apps = ias.get("applications", ias.get("apps", []))
        xsuaa_apps = []
        xsuaa_objects: List[Dict[str, Any]] = []

        for app in apps:
            if not isinstance(app, dict):
                continue

            name = app.get("name", app.get("appName", "unknown"))
            auth_type = app.get("authenticationType",
                       app.get("protocol", app.get("authType", "")))
            trust_type = app.get("trustType", app.get("idpType",
                        app.get("identityProviderType", "")))

            if str(auth_type).upper() in ("XSUAA", "XSUAA_ONLY") or \
               str(trust_type).upper() in ("XSUAA", "LEGACY"):
                xsuaa_apps.append(
                    f"{name} — auth: {auth_type}, trust: {trust_type}"
                )
                # The legacy trust chain is what makes the app a finding, so it
                # qualifies the object: the same app once migrated to IAS is not
                # the same defect.
                self._add_object(xsuaa_objects, "ias_application", name,
                                 f"auth={auth_type}, trust={trust_type}")

        if xsuaa_apps:
            self.finding(
                check_id="BTP-MIG-001",
                title="Applications still using XSUAA authentication (not migrated to IAS)",
                severity=self.SEVERITY_MEDIUM,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(xsuaa_apps)} application(s) still use XSUAA-based "
                    "authentication instead of SAP Cloud Identity Services (IAS). "
                    "XSUAA lacks advanced security features available in IAS "
                    "like conditional authentication, risk-based access, and "
                    "centralized policy management."
                ),
                affected_items=xsuaa_apps,
                remediation=(
                    "Migrate applications from XSUAA to IAS-based authentication. "
                    "Follow the SAP migration guide for establishing IAS trust. "
                    "Test thoroughly in non-production before cutover. "
                    "Priority: migrate admin and security-sensitive apps first."
                ),
                references=[
                    "SAP BTP — Migration from XSUAA to Identity Authentication",
                    "SAP Blog — Establishing Trust Between IAS and BTP",
                ],
                affected_objects=xsuaa_objects,
                # Summary of the un-migrated application population; migrating one
                # app must not retire the finding tracking the remaining backlog.
                scope="aggregate",
            )

    # ════════════════════════════════════════════════════════════════
    #  Subaccount security settings — reading what was already ingested
    #
    #  `btp_import` has normalised and merged these fields since it was
    #  written, and until now nothing read them. An ingested field with no
    #  consumer is worse than an absent one: the export guide asks a customer
    #  to run a command and send a file, the manifest confirms the file
    #  arrived, and the scan then says nothing about it. That reads as "we
    #  looked and found nothing wrong".
    # ════════════════════════════════════════════════════════════════

    @staticmethod
    def _subaccount_records(data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """The subaccount dicts inside whatever `btp_subaccounts` holds.

        The same three envelopes `btp_import._subaccount_list` unwraps, because
        these checks and that merge have to agree on what a subaccount is.
        """
        payload = data.get("btp_subaccounts")
        if isinstance(payload, list):
            return [r for r in payload if isinstance(r, dict)]
        if isinstance(payload, dict):
            for key in ("subaccounts", "items", "value"):
                found = payload.get(key)
                if isinstance(found, list):
                    return [r for r in found if isinstance(r, dict)]
        return []

    def _settings_scopes(self) -> List[Dict[str, Any]]:
        """Every subaccount security-settings record, counted exactly once.

        Two places hold the same fields. `btp_import._merge_settings` folds a
        `btp list security/settings` payload onto the subaccount it names, so an
        ATTRIBUTED record appears both on the subaccount and in the raw
        `btp_security_settings` list. Reading both would report one subaccount's
        token policy twice; reading only the raw list would lose the subaccount's
        name from every finding.

        So the subaccount wins, and a raw record is read only when it was never
        attributed to one. Those are still real measurements of a real
        subaccount and are not discarded — but they are labelled as
        unattributed, so the report never puts a subaccount's name against
        settings that might belong to a different one.
        """
        records = self._subaccount_records(self.data)
        known = set()
        for sa in records:
            for field in _SUBACCOUNT_KEYS:
                value = sa.get(field)
                if value not in (None, ""):
                    known.add(str(value).strip().lower())

        scopes: List[Dict[str, Any]] = []
        for sa in records:
            if not any(field in sa for field in _SETTINGS_FIELDS):
                continue
            sa_id = sa.get("id") or sa.get("subaccountId") or sa.get("guid") or ""
            name = sa.get("name") or sa.get("displayName") or ""
            if name and sa_id:
                label = "%s (%s)" % (name, sa_id)
            else:
                label = str(name or sa_id or "unnamed subaccount")
            scopes.append({"label": label, "name": str(sa_id or name),
                           "settings": sa, "attributed": True})

        raw = self.data.get("btp_security_settings")
        if not isinstance(raw, list):
            return scopes
        for row in raw:
            if not isinstance(row, dict):
                continue
            key = str(row.get("subaccount") or "").strip()
            if key and key.lower() in known:
                continue            # already read off the subaccount it merged onto
            if not key and len(records) == 1:
                continue            # merged onto the only subaccount there is
            scopes.append({
                "label": ("security settings for subaccount %s (no such "
                          "subaccount in this export)" % key) if key else
                         "security settings that name no subaccount",
                # No object name: an id nothing in the export corresponds to is
                # not a node, and "unattributed" as a name would merge every such
                # record in the estate into one.
                "name": "",
                "settings": row, "attributed": False})
        return scopes

    @staticmethod
    def _token_seconds(settings: Dict[str, Any], key: str):
        """The explicit token lifetime in seconds, or None for "not stated".

        None is not an error and not a zero — it means this subaccount sets no
        lifetime of its own, which leaves SAP's documented default in force.
        Three inputs reduce to it: the key is absent (the export never carried
        the field), the value is not a number, or the value is not positive.

        That last one is the load-bearing case. The cockpit and the Security
        Settings API write a non-positive sentinel where nothing has been set,
        and the exports seen here carry `-1`. Rather than hard-code a sentinel
        this product cannot cite, it takes the weaker and safer reading: a
        negative or zero number of seconds is not a lifetime under any
        interpretation, so it is treated as unset. If SAP ever gave `-1` some
        other meaning, this check would understate rather than fabricate.
        """
        if key not in settings:
            return None
        raw = settings[key]
        if isinstance(raw, bool):
            return None
        try:
            seconds = int(str(raw).strip())
        except (TypeError, ValueError):
            return None
        return seconds if seconds > 0 else None

    @staticmethod
    def _duration(seconds: int) -> str:
        """`43200 s (12 hours)` — the number and a human reading of it."""
        if seconds % 86400 == 0 and seconds >= 86400:
            unit, count = "day", seconds // 86400
        elif seconds % 3600 == 0 and seconds >= 3600:
            unit, count = "hour", seconds // 3600
        elif seconds % 60 == 0 and seconds >= 60:
            unit, count = "minute", seconds // 60
        else:
            return "%d s" % seconds
        return "%d s (%d %s%s)" % (seconds, count, unit, "" if count == 1 else "s")

    # ════════════════════════════════════════════════════════════════
    #  BTP-TOK-*: XSUAA token policy
    # ════════════════════════════════════════════════════════════════

    def check_token_policy(self):
        """Audit the subaccount-wide OAuth token lifetimes.

        SAP states the risk itself, and states it as the reason the setting
        exists: "increasing the token validity also means that if a malicious
        user manages to steal a token, that malicious user has access until the
        token expires."

        Three separate verdicts, because they call for three different actions:
        a lifetime relaxed past SAP's own default was chosen by somebody and can
        be un-chosen; a lifetime left at the default was never considered; and a
        lifetime under SAP's stated floor is a different mistake in the opposite
        direction.

        WHAT THIS CHECK CANNOT SEE, and every finding says so: the subaccount
        setting applies only to "service instances in the subaccount that
        haven't set a specific value in the application security descriptor
        (xs-security.json)". An individual application can override it in either
        direction, and no export in this product's reach carries those
        overrides. A clean result here is therefore a clean result about the
        subaccount default, not about every token the subaccount issues.
        """
        scopes = self._settings_scopes()
        if not scopes:
            return

        relaxed, relaxed_objects = [], []
        defaulted, defaulted_objects = [], []
        under_floor, under_floor_objects = [], []

        for scope in scopes:
            settings = scope["settings"]
            stated = [k for k in ("accessTokenValidity", "refreshTokenValidity")
                      if k in settings]
            if not stated:
                # The export carried settings but not these fields. Silence is
                # the only honest verdict: nothing was measured.
                continue

            pairs = (
                ("accessTokenValidity", "access token",
                 self._token_seconds(settings, "accessTokenValidity"),
                 _ACCESS_TOKEN_DEFAULT),
                ("refreshTokenValidity", "refresh token",
                 self._token_seconds(settings, "refreshTokenValidity"),
                 _REFRESH_TOKEN_DEFAULT),
            )

            over = ["%s %s — SAP default is %s"
                    % (what, self._duration(value), self._duration(default))
                    for _k, what, value, default in pairs
                    if value is not None and value > default]
            short = ["%s %s" % (what, self._duration(value))
                     for _k, what, value, _d in pairs
                     if value is not None and value < _TOKEN_VALIDITY_FLOOR]
            # `key in settings` is load-bearing, not defensive. Without it a
            # settings export trimmed to one of the two fields would be reported
            # as having left the OTHER at the SAP default — a claim about a field
            # that was never in the file, which is the same fabrication as
            # reading an absent auditLogEnabled as "logging is off", at a lower
            # severity. Only a field that is present and holds no positive
            # lifetime is evidence that no lifetime was set.
            #
            # Each one also names ITS OWN default: listing both whenever either
            # was unset would tell a subaccount that had set a 30-minute access
            # token that it was running on SAP's 12-hour one.
            unset = ["%s at %s" % (what, self._duration(default))
                     for key, what, value, default in pairs
                     if key in settings and value is None]

            if over:
                relaxed.append("%s — %s" % (scope["label"], "; ".join(over)))
                self._add_object(relaxed_objects, "subaccount", scope["name"],
                                 "; ".join(over))
            if short:
                under_floor.append("%s — %s" % (scope["label"], "; ".join(short)))
                self._add_object(under_floor_objects, "subaccount", scope["name"],
                                 "; ".join(short))
            if unset and not over:
                # Only when nothing was relaxed. A subaccount that lengthened its
                # access token and left the refresh token at the default belongs
                # in the finding about the change, not in the backlog one.
                defaulted.append("%s — left at the SAP default: %s"
                                 % (scope["label"], " and ".join(unset)))
                self._add_object(defaulted_objects, "subaccount", scope["name"],
                                 "token policy not set")

        override_caveat = (
            "Note: this is the subaccount-wide setting. It applies to service "
            "instances that do not set token-validity or refresh-token-validity "
            "in their own xs-security.json, and this scan cannot see those "
            "application-level overrides."
        )

        if relaxed:
            self.finding(
                check_id="BTP-TOK-001",
                title="OAuth token validity relaxed beyond the SAP default",
                severity=self.SEVERITY_HIGH,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(relaxed)} BTP subaccount(s) issue OAuth tokens that "
                    "stay valid longer than SAP's own documented default of "
                    f"{self._duration(_ACCESS_TOKEN_DEFAULT)} for access tokens "
                    f"and {self._duration(_REFRESH_TOKEN_DEFAULT)} for refresh "
                    "tokens. SAP's guidance on this setting: 'increasing the "
                    "token validity also means that if a malicious user manages "
                    "to steal a token, that malicious user has access until the "
                    "token expires.' A token lifted from a log, a browser "
                    "session, a CI variable or a bound application therefore "
                    "buys the holder that much unauthenticated access, and "
                    "revoking the user's credentials does not shorten it. "
                    "A relaxed lifetime is a deliberate change: the default had "
                    f"to be raised for this to be true. {override_caveat}"),
                affected_items=relaxed,
                remediation=(
                    "1. In the BTP cockpit, open Security > Settings > Token "
                    "Validity for each subaccount named, and record the current "
                    "values before changing them.\n"
                    "2. Identify why the lifetime was raised — it is usually one "
                    "integration that could not refresh — and fix that "
                    "integration to use the refresh flow.\n"
                    "3. Lower the access token validity to SAP's example value "
                    "of 1800 seconds and the refresh token validity to 43200 "
                    "seconds, or to the shortest values your integrations "
                    "tolerate.\n"
                    "4. Never set either below 1800 seconds: SAP states 'keep "
                    "token validity as short as possible, but not less than 30 "
                    "minutes'.\n"
                    "5. Check the bound applications' xs-security.json for "
                    "token-validity overrides, which this scan cannot see and "
                    "which take precedence over the subaccount value.\n"
                    "6. Re-run the scan to confirm the subaccount default is "
                    "back within the SAP baseline."),
                references=[
                    "SAP BTP — Configure Token Policy for SAP Authorization and "
                    "Trust Management Service",
                    "SAP BTP — Security Considerations for the SAP Authorization "
                    "and Trust Management Service (Setting Token Policy)",
                ],
                affected_objects=relaxed_objects,
                details={"access_token_default_seconds": _ACCESS_TOKEN_DEFAULT,
                         "refresh_token_default_seconds": _REFRESH_TOKEN_DEFAULT,
                         "application_overrides_not_visible": True},
                # Summary of every subaccount over the SAP default; tightening one
                # must not retire the finding covering the rest.
                scope="aggregate",
            )

        if defaulted:
            self.finding(
                check_id="BTP-TOK-002",
                title="OAuth token validity left at the SAP default (12 hours / 7 days)",
                severity=self.SEVERITY_LOW,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(defaulted)} BTP subaccount(s) set no token lifetime "
                    "of their own, so SAP's defaults apply: "
                    f"{self._duration(_ACCESS_TOKEN_DEFAULT)} for access tokens "
                    f"and {self._duration(_REFRESH_TOKEN_DEFAULT)} for refresh "
                    "tokens. This is not a misconfiguration — it is the shipped "
                    "state — but SAP's own recommendation for the setting is to "
                    "'keep token validity as short as possible, but not less "
                    "than 30 minutes', and a week-long refresh token in a "
                    "production subaccount is a long way from as short as "
                    "possible. It is raised at LOW severity for that reason: the "
                    "finding is that the decision was never made, not that a "
                    f"wrong one was. {override_caveat}"),
                affected_items=defaulted,
                remediation=(
                    "1. Decide a token policy per environment rather than per "
                    "subaccount ad hoc — production subaccounts warrant shorter "
                    "lifetimes than sandboxes.\n"
                    "2. In the BTP cockpit, Security > Settings > Token "
                    "Validity, set the access token validity toward SAP's "
                    "example of 1800 seconds and the refresh token validity "
                    "toward 43200 seconds.\n"
                    "3. Do not go below 1800 seconds for either.\n"
                    "4. Roll the change out to a non-production subaccount "
                    "first: a shortened refresh token surfaces any integration "
                    "that was silently relying on a long-lived one.\n"
                    "5. Record the chosen values in your BTP subaccount "
                    "provisioning blueprint so new subaccounts inherit them "
                    "instead of the defaults.\n"
                    "6. Re-run the scan to confirm each subaccount now states a "
                    "policy of its own."),
                references=[
                    "SAP BTP — Configure Token Policy for SAP Authorization and "
                    "Trust Management Service",
                ],
                affected_objects=defaulted_objects,
                details={"access_token_default_seconds": _ACCESS_TOKEN_DEFAULT,
                         "refresh_token_default_seconds": _REFRESH_TOKEN_DEFAULT,
                         "application_overrides_not_visible": True},
                # Summary of the subaccounts that never set a policy.
                scope="aggregate",
            )

        if under_floor:
            self.finding(
                check_id="BTP-TOK-003",
                title="OAuth token validity set below the 30-minute floor SAP states",
                severity=self.SEVERITY_LOW,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(under_floor)} BTP subaccount(s) set a token lifetime "
                    f"shorter than {self._duration(_TOKEN_VALIDITY_FLOOR)}, "
                    "against SAP's explicit instruction to 'keep token validity "
                    "as short as possible, but not less than 30 minutes'. This "
                    "is over-tightening rather than a weakness, and it is "
                    "reported because it does not fail safely: the SAP "
                    "Authorization and Trust Management service has its own "
                    "30-minute session timeout, after which it stops forwarding "
                    "logoff requests to the identity provider, and lifetimes "
                    "below that floor put the two out of step. The practical "
                    "result is users re-authenticating mid-task and "
                    "integrations failing intermittently — which is how a "
                    "well-intentioned tightening gets reverted to something "
                    f"longer than it started. {override_caveat}"),
                affected_items=under_floor,
                remediation=(
                    "1. Raise the affected token validity to at least 1800 "
                    "seconds in Security > Settings > Token Validity.\n"
                    "2. If the short lifetime was set to limit exposure for one "
                    "sensitive application, move that limit into the "
                    "application's own xs-security.json rather than applying it "
                    "to the whole subaccount.\n"
                    "3. Check whether users of this subaccount have been "
                    "reporting unexpected re-authentication, which confirms the "
                    "setting is the cause.\n"
                    "4. Re-run the scan to confirm the subaccount sits at or "
                    "above the floor."),
                references=[
                    "SAP BTP — Configure Token Policy for SAP Authorization and "
                    "Trust Management Service",
                    "SAP BTP — Security Considerations for the SAP Authorization "
                    "and Trust Management Service (Training Business Users How "
                    "to Handle Session Timeouts)",
                ],
                affected_objects=under_floor_objects,
                details={"floor_seconds": _TOKEN_VALIDITY_FLOOR},
                scope="aggregate",
            )

    # ════════════════════════════════════════════════════════════════
    #  BTP-FRM-*: iframe embedding / clickjacking exposure
    # ════════════════════════════════════════════════════════════════

    @staticmethod
    def _iframe_origins(settings: Dict[str, Any]) -> List[str]:
        """Every origin permitted to frame this subaccount's pages.

        Both spellings are read, and both have to be. `iframeDomains` is ONE
        string holding all of them — SAP's own Terraform provider documents it
        as "Enter as string. To provide multiple domains, separate them by
        spaces" — while `iframeDomainsList` is the newer list form of the same
        setting, which the provider recommends in its place. An export can carry
        either. Reading only one would report half the estates as having framing
        switched off when it is switched on.
        """
        origins: List[str] = []
        raw = settings.get("iframeDomains")
        if isinstance(raw, str):
            origins.extend(part for part in raw.split() if part)
        listed = settings.get("iframeDomainsList")
        if isinstance(listed, list):
            origins.extend(str(item).strip() for item in listed
                           if str(item or "").strip())

        seen, unique = set(), []
        for origin in origins:
            if origin not in seen:
                seen.add(origin)
                unique.append(origin)
        return unique

    @staticmethod
    def _origin_is_broad(origin: str) -> str:
        """Why this framing origin is worse than a named HTTPS host, or ``""``.

        Everything decided here is a property of the string itself, so nothing
        is looked up and nothing is assumed about the estate. Two properties
        matter. A wildcard that covers a whole domain space means the permitted
        framer is not a host at all, and SAP's guidance is that it has to be one
        you can vouch for: "Ensure that no attacker can add malicious web pages
        or Javascript to any of the hosts allowed to frame the applications."
        A plain-HTTP origin means the framing page can be rewritten in transit,
        so its trustworthiness is not a property anyone controls.

        `https://*.example.com` is NOT flagged. SAP documents exactly that form
        as legitimate, and a subdomain wildcard inside a domain the customer owns
        is a different thing from a wildcard over `*.com`.
        """
        text = str(origin or "").strip()
        if not text:
            return ""
        lowered = text.lower()
        host = lowered.split("://", 1)[-1].split("/", 1)[0].strip()
        if not host or host.strip("*.") == "":
            return "any origin may frame these pages"
        if host.startswith("*.") and host.count(".") <= 1:
            return "wildcard spans an entire top-level domain"
        if lowered.startswith("http://"):
            return "framing origin is plain HTTP and can be rewritten in transit"
        return ""

    def check_iframe_domains(self):
        """Audit which origins may embed the subaccount's pages in an iframe.

        SAP ships this closed: "By default, applications of the subaccount,
        including login pages of the SAP Authorization and Trust Management
        service can't be framed by other applications for security reasons."
        Configuring a trusted domain opens it, by sending a content security
        policy header that permits framing from that origin — and the page most
        worth framing is the login page.

        SAP lists the consequences: "Clickjacking attacks on the application as
        the URL of the application isn't visible", JavaScript-based cross-site
        scripting on older browsers, and a third-party-cookie dependency. The
        first is the one that matters here: a user typing corporate credentials
        into an invisible frame over an attacker's page cannot see the address
        bar that would tell them where the credentials are going.
        """
        scopes = self._settings_scopes()
        if not scopes:
            return

        broad, broad_objects = [], []
        enabled, enabled_objects = [], []

        for scope in scopes:
            settings = scope["settings"]
            if not any(k in settings for k in ("iframeDomains", "iframeDomainsList")):
                continue
            origins = self._iframe_origins(settings)
            if not origins:
                # Explicitly empty is the SAP default and the secure state. It is
                # a pass, and a pass is not a finding.
                continue

            offending = [(o, self._origin_is_broad(o)) for o in origins]
            wide = [(o, why) for o, why in offending if why]
            if wide:
                broad.append("%s — %s" % (scope["label"], "; ".join(
                    "%s (%s)" % (o, why) for o, why in wide)))
                self._add_object(broad_objects, "subaccount", scope["name"],
                                 "framing allowed from " +
                                 ", ".join(o for o, _w in wide))
            else:
                enabled.append("%s — framing allowed from: %s"
                               % (scope["label"], ", ".join(origins)))
                self._add_object(enabled_objects, "subaccount", scope["name"],
                                 "framing allowed from %d origin(s)" % len(origins))

        if broad:
            self.finding(
                check_id="BTP-FRM-001",
                title="Subaccount login pages may be framed by an unrestricted origin",
                severity=self.SEVERITY_HIGH,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(broad)} BTP subaccount(s) permit iframe embedding "
                    "from an origin that is not a specific HTTPS host — a "
                    "wildcard covering a whole domain space, or a plain-HTTP "
                    "origin. SAP disables framing by default precisely because "
                    "of this, and names clickjacking as the consequence: the "
                    "framed page's URL is not visible to the user. The page "
                    "worth framing is the SAP Authorization and Trust "
                    "Management service login page, so the attack is a "
                    "convincing overlay that harvests corporate credentials, or "
                    "an invisible frame that captures a click intended for "
                    "something else — a consent, an approval, a role "
                    "assignment. SAP's requirement for any permitted origin is "
                    "that 'no attacker can add malicious web pages or "
                    "Javascript' to it, which is a claim nobody can make about "
                    "a wildcard."),
                affected_items=broad,
                remediation=(
                    "1. In the BTP cockpit, open Security > Settings > Trusted "
                    "Domains for each subaccount named.\n"
                    "2. Remove the wildcard or plain-HTTP entry and replace it "
                    "with the specific HTTPS origins that genuinely embed these "
                    "pages.\n"
                    "3. If nothing embeds them, remove every entry and restore "
                    "the SAP default of no framing at all.\n"
                    "4. Where framing is genuinely required, prefer SAP's own "
                    "guidance and put the framing application on the same domain "
                    "using the SAP Custom Domain Service, which removes the need "
                    "for a trusted-domain entry entirely.\n"
                    "5. For each origin you keep, confirm with its owner that no "
                    "third party can publish content on that host — including "
                    "anything behind it if it is a reverse proxy.\n"
                    "6. Verify by loading the login page inside a test iframe on "
                    "a non-listed origin and confirming the browser refuses it.\n"
                    "7. Re-run the scan to confirm only specific HTTPS origins "
                    "remain."),
                references=[
                    "SAP BTP — Security Considerations for the SAP Authorization "
                    "and Trust Management Service (Implications of Using IFrames)",
                    "SAP BTP — Configure Trusted Domains for Multi-Environment "
                    "Subaccounts",
                    "W3C — Content Security Policy Level 2",
                ],
                affected_objects=broad_objects,
                scope="aggregate",
            )

        if enabled:
            self.finding(
                check_id="BTP-FRM-002",
                title="Iframe embedding enabled for the subaccount (SAP default is off)",
                severity=self.SEVERITY_MEDIUM,
                category="BTP Cloud Attack Surface",
                description=(
                    f"{len(enabled)} BTP subaccount(s) permit iframe embedding "
                    "from specific HTTPS origins. Every origin named is a "
                    "specific host, which is the supported way to configure "
                    "this — so this is a review item, not a defect. It is "
                    "reported because SAP ships framing disabled and each entry "
                    "moves part of the subaccount's security onto a host "
                    "outside it: SAP's stated requirement is to 'ensure that no "
                    "attacker can add malicious web pages or Javascript to any "
                    "of the hosts allowed to frame the applications', and that "
                    "'also includes hosts that act as reverse proxies, where an "
                    "attacker can put their content on a different host behind "
                    "the reverse proxy'. Trusted-domain lists outlive the "
                    "integration that justified them, and an entry for a "
                    "hostname the company no longer controls is a live "
                    "clickjacking path."),
                affected_items=enabled,
                remediation=(
                    "1. For each origin listed, identify the application that "
                    "embeds these pages and confirm the integration is still in "
                    "use.\n"
                    "2. Remove entries whose integration has been "
                    "decommissioned.\n"
                    "3. Confirm every retained hostname is still registered to "
                    "your organisation and that no third party can publish "
                    "content on it, including behind any reverse proxy.\n"
                    "4. Where the framing application could instead run on the "
                    "same domain via the SAP Custom Domain Service, migrate it "
                    "and drop the entry.\n"
                    "5. Add the trusted-domain list to your periodic subaccount "
                    "review so it is re-confirmed rather than inherited.\n"
                    "6. Re-run the scan to confirm the remaining list is the one "
                    "you intended."),
                references=[
                    "SAP BTP — Security Considerations for the SAP Authorization "
                    "and Trust Management Service (Implications of Using IFrames)",
                    "SAP BTP — Configure Trusted Domains for Multi-Environment "
                    "Subaccounts",
                ],
                affected_objects=enabled_objects,
                scope="aggregate",
            )

    # ════════════════════════════════════════════════════════════════
    #  BTP-IDL-*: email as a cross-identity-provider join key
    # ════════════════════════════════════════════════════════════════

    def _active_trusts(self) -> List[Dict[str, str]]:
        """The identity providers a `btp_trust` export shows as active.

        Unwrapped exactly as `rise_btp_checks.check_btp_trust_config` and
        `iam_advanced._trust_rows` unwrap it, and keyed on `originKey` for the
        same reason they are: the origin is the technical key and
        `identityProvider` is an editable label, so keying on the origin keeps
        every module pointing at one node per trust.
        """
        trust = self.data.get("btp_trust")
        if isinstance(trust, list):
            rows = trust
        elif isinstance(trust, dict):
            rows = trust.get("trusts", trust.get("trust_configurations"))
            if not isinstance(rows, list):
                rows = [trust]
        else:
            return []

        active = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            enabled = row.get("status", row.get("enabled", True))
            if str(enabled).strip().lower() in ("false", "0", "no", "off",
                                                "inactive", "disabled"):
                continue
            origin = str(row.get("originKey", row.get("origin", "")) or "").strip()
            name = str(row.get("identityProvider",
                               row.get("idp_name", row.get("name", ""))) or "").strip()
            if not origin and not name:
                continue
            active.append({"origin": origin, "name": name or origin})
        return active

    def check_email_identity_linking(self):
        """Audit email-based identity linking across identity providers.

        `treatUsersWithSameEmailAsSameUser` does what it says: SAP's own
        Terraform provider documents it as "If set to true, users with the same
        email are treated as same users." With ONE identity provider that is
        ordinary convenience. With more than one it makes the email address a
        join key BETWEEN identity providers, and the security of every account
        in the subaccount becomes the security of the weakest provider's
        account-creation process — because an account created there with a
        matching email address resolves to the same user.

        `customEmailDomains` is what bounds it. SAP's provider documents that
        field as "Set of domains that are allowed to be used for user
        authentication", so a populated list confines the linking to domains the
        customer named, and an empty one does not confine it at all. Both states
        are reported, at the same severity but with different text, because the
        remediation differs: one is a list to review, the other is a list to
        create.

        THE CONDITION IS DELIBERATELY NARROW. Linking is only reported when the
        export ACTUALLY SHOWS a second active trust. A subaccount whose trust
        configuration was not exported is not reported at all — there is no way
        to tell a single-provider subaccount from an unexported one, and
        guessing in either direction would be wrong.
        """
        scopes = self._settings_scopes()
        if not scopes:
            return

        trusts = self._active_trusts()
        if len(trusts) < 2:
            # One provider, or no trust export at all. Neither is a finding: with
            # one provider there is nothing to join across, and with no export
            # there is nothing to say. See the docstring.
            return

        linked, linked_objects = [], []
        for scope in scopes:
            settings = scope["settings"]
            if "treatUsersWithSameEmailAsSameUser" not in settings:
                continue
            value = settings["treatUsersWithSameEmailAsSameUser"]
            if isinstance(value, bool):
                on = value
            else:
                on = str(value).strip().lower() in ("true", "yes", "1", "on")
            if not on:
                continue

            domains = settings.get("customEmailDomains")
            domains = [str(d).strip() for d in domains
                       if str(d or "").strip()] if isinstance(domains, list) else []
            bound = ("bounded to %s" % ", ".join(domains) if domains
                     else "no custom email domains configured — unbounded")
            linked.append("%s — %s" % (scope["label"], bound))
            self._add_object(linked_objects, "subaccount", scope["name"],
                             "email identity linking across %d identity providers"
                             % len(trusts))

        if not linked:
            return

        idp_list = ", ".join(sorted(t["name"] for t in trusts))
        self.finding(
            check_id="BTP-IDL-001",
            title="Email address links identities across multiple identity providers",
            severity=self.SEVERITY_MEDIUM,
            category="BTP Cloud Attack Surface",
            description=(
                f"{len(linked)} BTP subaccount(s) treat users with the same "
                "email address as the same user, and this export shows "
                f"{len(trusts)} active identity provider trust(s): {idp_list}. "
                "The email address is therefore a join key between them, and "
                "an account created in any one of those providers with an "
                "email address matching an existing user resolves to that "
                "user's identity and role collections. The account-creation "
                "process of the weakest trusted provider becomes the "
                "account-creation process of the subaccount — which matters "
                "most where the SAP ID Service is still trusted alongside a "
                "corporate provider, because its accounts are self-registered "
                "and its email verification is not your process. Subaccounts "
                "with no custom email domain list bound the linking to nothing "
                "at all."),
            affected_items=linked,
            remediation=(
                "1. In Security > Trust Configuration, list the identity "
                "providers this subaccount trusts and remove any that are no "
                "longer required — in particular the default SAP ID Service "
                "where a corporate provider is in place.\n"
                "2. In Security > Settings, populate the custom email domains "
                "with the domains your organisation actually owns, so linking "
                "cannot occur on an address at a domain you do not control.\n"
                "3. For each remaining provider, confirm that email addresses "
                "are verified at account creation and cannot be self-asserted.\n"
                "4. If any trusted provider cannot guarantee that, turn off "
                "'treat users with the same email as the same user' for the "
                "subaccount and accept the duplicate shadow users instead.\n"
                "5. Review existing shadow users for the same email address "
                "appearing under more than one origin, which shows where "
                "linking has already happened.\n"
                "6. Re-run the scan to confirm the trust list and the email "
                "domain list are the ones you intended."),
            references=[
                "SAP BTP — Managing Security Settings",
                "SAP BTP — Managing Trust from SAP BTP to an SAP Cloud Identity "
                "Services Tenant",
            ],
            affected_objects=linked_objects,
            details={"active_trusts": [t["origin"] or t["name"] for t in trusts]},
            # Summary of every subaccount linking on email; fixing one subaccount
            # must not retire the finding covering the others.
            scope="aggregate",
        )

    # ════════════════════════════════════════════════════════════════
    #  BTP-AUD-*: what the audit-log export does and does not settle
    # ════════════════════════════════════════════════════════════════

    @staticmethod
    def _audit_state(sa: Dict[str, Any]):
        """True / False / None for one subaccount's audit-log enablement.

        None is the whole reason this helper exists. Three inputs produce it:
        the field is absent (`btp list accounts/subaccount` does not carry audit
        enablement at all), the field holds the `unknown` sentinel `btp_import`
        writes for a subaccount the audit-log export did not cover, or the field
        holds a string nothing can be made of.

        The code this replaced read all three as False and reported them as "does
        not have the audit log service enabled" — a HIGH finding manufactured out
        of a field that was never in the export. That is the exact failure this
        product is built to refuse, and it survived because the subaccount
        fixtures all happened to carry explicit booleans.
        """
        for key in ("auditLogEnabled", "hasAuditLog"):
            if key not in sa:
                continue
            value = sa[key]
            if isinstance(value, bool):
                return value
            text = str(value if value is not None else "").strip().lower()
            if text in ("true", "yes", "1", "on", "enabled"):
                return True
            if text in ("false", "no", "0", "off", "disabled"):
                return False
        return None

    def check_audit_log_coverage(self):
        """Report the subaccounts whose audit-log state nothing settled.

        BTP-GOV-001 names the subaccounts KNOWN to have no audit logging. This
        names the other group — the ones where neither export answered the
        question — because a subaccount that appears in neither finding reads as
        one that was checked and passed.

        `btp_import` already refuses to infer here: a subaccount missing from a
        scoped audit-log export is marked unknown rather than disabled, and that
        refusal is correct. But a refusal nobody is told about is
        indistinguishable from a pass. This finding is where the refusal becomes
        visible, and it carries `degrades_coverage` so `--gate` will not return a
        clean build on the strength of subaccounts that were never assessed.

        It also states what the audit-log export DID prove, from the summary
        `btp_import` builds. Deliberately not stated: retention. The span of an
        export is chosen by whoever ran the query, so reading a retention period
        out of it would be a measurement of the operator, not of the tenant.
        """
        records = self._subaccount_records(self.data)
        if not records:
            return

        unknown, unknown_objects = [], []
        evidenced = 0
        for sa in records:
            state = self._audit_state(sa)
            if state is True:
                evidenced += 1
                continue
            if state is False:
                continue                        # BTP-GOV-001 has this one
            sa_id = sa.get("id") or sa.get("subaccountId") or sa.get("guid") or ""
            name = sa.get("name") or sa.get("displayName") or ""
            region = sa.get("region") or sa.get("dataCenter") or ""
            label = "%s (%s)" % (name or "unnamed", sa_id or "no id")
            if region:
                label += ", region: %s" % region
            unknown.append(label)
            self._add_object(unknown_objects, "subaccount", sa_id or name)

        if not unknown:
            return

        audit = self.data.get("btp_audit_log")
        if isinstance(audit, dict) and audit.get("record_count"):
            tenants = audit.get("tenants") or []
            windows = sorted(
                "%s (%s records, %s to %s)"
                % (t.get("tenant") or "unnamed tenant", t.get("records", 0),
                   t.get("earliest") or "?", t.get("latest") or "?")
                for t in tenants if isinstance(t, dict))
            covered = (
                "An audit-log export was supplied and proves logging is running "
                "for %d tenant(s): %s. It says nothing about the subaccounts "
                "below, which it does not cover."
                % (len(tenants), "; ".join(windows) or "no tenant named"))
        else:
            covered = ("No audit-log export was supplied, so nothing in this "
                       "scan can confirm whether these subaccounts produce "
                       "audit records.")

        self.finding(
            check_id="BTP-AUD-001",
            title="Audit-log state could not be determined for some subaccounts",
            severity=self.SEVERITY_INFO,
            category="BTP Cloud Attack Surface",
            description=(
                f"{len(unknown)} of {len(records)} BTP subaccount(s) were NOT "
                "assessed for audit logging, because no export settles the "
                f"question for them ({evidenced} were confirmed as logging). "
                f"{covered} These subaccounts are absent from BTP-GOV-001 "
                "because they are unknown, not because they passed. Read this "
                "finding as the boundary of that check: a subaccount listed "
                "here may or may not be logging, and this scan is not evidence "
                "either way."),
            affected_items=unknown,
            remediation=(
                "1. For each subaccount listed, create an auditlog-management "
                "service instance and a service key if one does not exist.\n"
                "2. Retrieve records for each subaccount over a recent window "
                "and save them as btp_audit_log_records.json — see "
                "docs/EXPORT_GUIDE.md, 'Audit log records'.\n"
                "3. Alternatively, add an explicit auditLogEnabled field to "
                "your btp_subaccounts.json export if your own configuration "
                "management already records it.\n"
                "4. Re-run the scan; each subaccount will then appear as "
                "evidenced or in BTP-GOV-001, and no longer here.\n"
                "5. Treat any subaccount that stays here after a full export as "
                "a genuinely unmonitored one and investigate it directly in the "
                "cockpit."),
            references=[
                "SAP BTP — Audit Log Retrieval API",
                "SAP BTP Security Recommendations — audit logging",
            ],
            affected_objects=unknown_objects,
            details={"degrades_coverage": True,
                     "subaccounts_total": len(records),
                     "subaccounts_unassessed": len(unknown),
                     "subaccounts_evidenced": evidenced,
                     "retention_not_inferred": True},
            # A summary of what was not assessed; settling one subaccount must
            # shrink this finding rather than retire and re-raise it.
            scope="aggregate",
        )

    # ════════════════════════════════════════════════════════════════
    #  Utility Methods
    # ════════════════════════════════════════════════════════════════

    @staticmethod
    def _parse_date_flexible(date_str: str):
        """Parse date strings in many formats including ISO 8601."""
        if not date_str or not str(date_str).strip():
            return None

        date_str = str(date_str).strip()

        # Handle ISO 8601 with timezone
        for suffix in ("Z", "+00:00", "+0000"):
            if date_str.endswith(suffix):
                date_str = date_str[:-len(suffix)]

        # Try T-separated datetime first
        if "T" in date_str:
            date_str = date_str.split("T")[0] + " " + date_str.split("T")[1][:8]

        formats = [
            "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y%m%d",
            "%d.%m.%Y", "%m/%d/%Y", "%d/%m/%Y",
            "%Y-%m-%d %H:%M", "%d.%m.%Y %H:%M:%S",
        ]

        for fmt in formats:
            try:
                return datetime.strptime(date_str[:len(fmt)+4], fmt)
            except (ValueError, IndexError):
                continue
        return None
