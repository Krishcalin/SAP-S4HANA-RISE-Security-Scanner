"""
Network & Service Exposure Auditor
====================================
Checks for:
  - RFC destinations with stored credentials
  - RFC destinations pointing to external/untrusted systems
  - Insecure RFC connection types
  - Active ICF services that should be disabled
  - ICF services without authentication requirements
  - Open transports in production
  - Debug/replace flags on transports
"""

from typing import Dict, List, Any
from modules.base_auditor import BaseAuditor


class NetworkServiceAuditor(BaseAuditor):

    # ICF services that are commonly exploited and should be disabled unless needed
    HIGH_RISK_ICF_SERVICES = {
        "/sap/public/icman/ping": "ICM ping — information disclosure",
        "/sap/public/info": "System info page — reveals version/kernel details",
        "/sap/bc/soap/rfc": "SOAP RFC gateway — remote function execution",
        "/sap/bc/srt/rfc/sap": "SRT RFC — web service RFC bridge",
        "/sap/bc/gui/sap/its/webgui": "WebGUI — full SAP GUI in browser (high risk if public)",
        "/sap/bc/webrfc": "WebRFC — HTTP-to-RFC bridge",
        "/sap/bc/bsp/sap/it00": "ITS pages — legacy web interface",
        "/sap/bc/startpage": "Start page — may expose internal links",
        "/sap/public/icf_info/icr_groups": "ICF group info — service enumeration",
        "/sap/bc/webdynpro": "WebDynpro — may expose internal apps",
        "/sap/bc/soap/wsdl": "WSDL exposure — service definition enumeration",
    }

    # RFC types considered risky
    RISKY_RFC_TYPES = {
        "3": "RFC via TCP/IP (Type 3) — verify SNC encryption",
        "T": "TCP/IP Connection — potentially unencrypted",
        "W": "WebRFC/HTTP — verify HTTPS and auth",
    }

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_rfc_stored_credentials()
        self.check_rfc_external_destinations()
        self.check_rfc_insecure_types()
        self.check_icf_high_risk_services()
        self.check_icf_no_auth()
        self.check_open_transports()
        self.check_audit_log_config()
        return self.findings

    def check_rfc_stored_credentials(self):
        """Flag RFC destinations that store plaintext/fixed credentials."""
        rfc = self.data.get("rfc_destinations")
        if not rfc:
            return

        stored_creds = []
        for row in rfc:
            dest = row.get("RFCDEST", row.get("DESTINATION", ""))
            user = row.get("RFCUSER", row.get("USER", ""))
            auth_type = row.get("RFCAUTH", row.get("AUTH_TYPE", ""))

            # If a username is stored in the destination config
            if user and user.strip():
                stored_creds.append(
                    f"{dest} → user: {user} (auth type: {auth_type or 'stored'})"
                )

        if stored_creds:
            self.finding(
                check_id="NET-001",
                title="RFC destinations with stored credentials",
                severity=self.SEVERITY_HIGH,
                category="Network & Service Exposure",
                description=(
                    f"{len(stored_creds)} RFC destination(s) have stored user credentials. "
                    "Stored credentials in RFC destinations can be extracted and misused. "
                    "This is especially dangerous for destinations with privileged users."
                ),
                affected_items=stored_creds,
                remediation=(
                    "Replace stored credentials with: (1) Trusted RFC connections, "
                    "(2) SSO/certificate-based auth, or (3) SNC-secured connections. "
                    "If stored creds are required, ensure the RFC user has minimal privileges."
                ),
                references=[
                    "SAP Note 1480644",
                    "CIS SAP Benchmark Section 4.2",
                ],
            )

    def check_rfc_external_destinations(self):
        """Flag RFC destinations pointing to external/unknown hosts."""
        rfc = self.data.get("rfc_destinations")
        if not rfc:
            return

        external = []
        internal_patterns = self.get_config("internal_host_patterns", [
            "10.", "172.16.", "172.17.", "172.18.", "172.19.",
            "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
            "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
            "172.30.", "172.31.", "192.168.", "127.", "localhost",
        ])

        for row in rfc:
            dest = row.get("RFCDEST", row.get("DESTINATION", ""))
            host = row.get("RFCHOST", row.get("HOST", row.get("TARGET_HOST", "")))
            conn_type = row.get("RFCTYPE", row.get("CONN_TYPE", ""))

            if not host:
                continue

            is_internal = any(host.startswith(p) for p in internal_patterns)
            if not is_internal and host.strip():
                external.append(f"{dest} → {host} (type: {conn_type})")

        if external:
            self.finding(
                check_id="NET-002",
                title="RFC destinations to external/non-RFC hosts",
                severity=self.SEVERITY_MEDIUM,
                category="Network & Service Exposure",
                description=(
                    f"{len(external)} RFC destination(s) point to hosts outside "
                    "recognized internal IP ranges. Verify these are legitimate "
                    "and encrypted (SNC/TLS)."
                ),
                affected_items=external,
                remediation=(
                    "Review each external RFC destination for business justification. "
                    "Ensure SNC or TLS encryption is enabled. "
                    "Remove any destinations that are no longer needed."
                ),
                references=["SAP Note 1480644"],
            )

    def check_rfc_insecure_types(self):
        """Flag RFC destinations using potentially insecure connection types."""
        rfc = self.data.get("rfc_destinations")
        if not rfc:
            return

        insecure = []
        for row in rfc:
            dest = row.get("RFCDEST", row.get("DESTINATION", ""))
            conn_type = row.get("RFCTYPE", row.get("CONN_TYPE", ""))
            snc_mode = row.get("RFCSNC", row.get("SNC_MODE", row.get("SNC", "")))

            if conn_type in self.RISKY_RFC_TYPES:
                # Check if SNC is enabled for TCP/IP connections
                snc_enabled = str(snc_mode) in ("1", "ON", "TRUE", "YES")
                if not snc_enabled:
                    insecure.append(
                        f"{dest} (type: {conn_type}, SNC: disabled) — "
                        f"{self.RISKY_RFC_TYPES[conn_type]}"
                    )

        if insecure:
            self.finding(
                check_id="NET-003",
                title="RFC destinations without SNC encryption",
                severity=self.SEVERITY_HIGH,
                category="Network & Service Exposure",
                description=(
                    f"{len(insecure)} RFC destination(s) use connection types that "
                    "transmit data without SNC encryption. Credentials and data "
                    "may be interceptable."
                ),
                affected_items=insecure,
                remediation=(
                    "Enable SNC for all RFC destinations (type 3/T). "
                    "For HTTP connections (type W), ensure HTTPS is used. "
                    "Configure SNC with quality of protection 'integrity + encryption'."
                ),
                references=["SAP Note 2416093", "CIS SAP Benchmark Section 4.1"],
            )

    def check_icf_high_risk_services(self):
        """Flag active ICF services known to be high-risk."""
        icf = self.data.get("icf_services")
        if not icf:
            return

        active_risky = []
        for row in icf:
            service_path = row.get("ICF_NAME", row.get("SERVICE_PATH",
                            row.get("PATH", row.get("SERVICE", ""))))
            is_active = row.get("ICF_ACTIVE", row.get("ACTIVE", row.get("STATUS", "")))

            # Normalize
            if str(is_active).upper() in ("X", "1", "TRUE", "YES", "ACTIVE"):
                for risky_path, risk_desc in self.HIGH_RISK_ICF_SERVICES.items():
                    if risky_path.lower() in service_path.lower():
                        active_risky.append(f"{service_path} — {risk_desc}")

        if active_risky:
            self.finding(
                check_id="NET-004",
                title="High-risk ICF services are active",
                severity=self.SEVERITY_HIGH,
                category="Network & Service Exposure",
                description=(
                    f"{len(active_risky)} high-risk ICF service(s) are active. "
                    "These services can expose system information, enable remote "
                    "code execution, or provide attack surfaces if publicly accessible."
                ),
                affected_items=active_risky,
                remediation=(
                    "Deactivate unnecessary ICF services via SICF. "
                    "For required services, restrict access via ICF handler-level "
                    "authentication and IP filtering. Document business justification "
                    "for each active high-risk service."
                ),
                references=[
                    "SAP Note 1439348",
                    "CIS SAP Benchmark Section 5.1",
                ],
            )

    def check_icf_no_auth(self):
        """Flag ICF services configured without authentication."""
        icf = self.data.get("icf_services")
        if not icf:
            return

        no_auth = []
        for row in icf:
            service_path = row.get("ICF_NAME", row.get("SERVICE_PATH",
                            row.get("PATH", row.get("SERVICE", ""))))
            is_active = row.get("ICF_ACTIVE", row.get("ACTIVE", row.get("STATUS", "")))
            auth_required = row.get("AUTH_REQUIRED", row.get("AUTH",
                            row.get("AUTHENTICATION", "")))

            if str(is_active).upper() in ("X", "1", "TRUE", "YES", "ACTIVE"):
                if str(auth_required).upper() in ("N", "NO", "0", "FALSE", "NONE", "ANONYMOUS", ""):
                    # Skip /sap/public/* as these are intentionally public
                    if "/sap/public/" not in service_path.lower():
                        no_auth.append(service_path)

        if no_auth:
            self.finding(
                check_id="NET-005",
                title="Active ICF services without authentication",
                severity=self.SEVERITY_CRITICAL,
                category="Network & Service Exposure",
                description=(
                    f"{len(no_auth)} active ICF service(s) do not require authentication. "
                    "Anonymous access to SAP services can lead to data leakage and exploitation."
                ),
                affected_items=no_auth,
                remediation=(
                    "Enable authentication for all non-public ICF services. "
                    "Configure appropriate logon procedure (Basic, SSO, Certificate). "
                    "Review and restrict the ICF handler chain."
                ),
                references=["SAP Note 1439348", "CIS SAP Benchmark Section 5.2"],
            )

    def check_open_transports(self):
        """Flag open/unreleased transports in production — change management risk."""
        transports = self.data.get("transports")
        if not transports:
            return

        open_transports = []
        debug_transports = []

        for row in transports:
            tr_id = row.get("TRKORR", row.get("TRANSPORT", row.get("REQUEST", "")))
            status = row.get("TRSTATUS", row.get("STATUS", ""))
            tr_type = row.get("TRFUNCTION", row.get("TYPE", ""))
            owner = row.get("AS4USER", row.get("OWNER", ""))
            desc = row.get("AS4TEXT", row.get("DESCRIPTION", ""))

            # Status: D=Modifiable, L=Modifiable(protected), R=Released
            if str(status).upper() in ("D", "L", "MODIFIABLE"):
                open_transports.append(f"{tr_id} (owner: {owner}, desc: {desc[:60]})")

            # Check for debug/replace indicators
            desc_lower = desc.lower()
            if any(kw in desc_lower for kw in ("debug", "replace", "breakpoint", "hotfix direct")):
                debug_transports.append(f"{tr_id} — {desc[:80]}")

        if open_transports:
            self.finding(
                check_id="NET-006",
                title="Open/unreleased transports in production",
                severity=self.SEVERITY_MEDIUM,
                category="Change Management",
                description=(
                    f"{len(open_transports)} transport request(s) are still in modifiable "
                    "state. Open transports in production indicate potential "
                    "unauthorized changes or incomplete change management."
                ),
                affected_items=open_transports,
                remediation=(
                    "Review and release or delete all open transports in production. "
                    "Implement transport workflow controls to prevent direct changes. "
                    "Ensure TMS configuration enforces proper approval chain."
                ),
                references=["CIS SAP Benchmark Section 7.2"],
            )

        if debug_transports:
            self.finding(
                check_id="NET-007",
                title="Transports with debug/replace indicators",
                severity=self.SEVERITY_HIGH,
                category="Change Management",
                description=(
                    f"{len(debug_transports)} transport(s) have descriptions suggesting "
                    "debug or direct code replacement activities in production."
                ),
                affected_items=debug_transports,
                remediation=(
                    "Investigate each flagged transport for unauthorized code changes. "
                    "Disable ABAP debugging in production (rdisp/wpdbug_max_no = 0). "
                    "Restrict S_DEVELOP authorization object."
                ),
                references=["CIS SAP Benchmark Section 7.1"],
            )

    def check_audit_log_config(self):
        """Verify audit logging configuration (SM19 export)."""
        audit_cfg = self.data.get("audit_config")
        if not audit_cfg:
            return

        # Check if any audit filters are defined
        active_filters = [
            row for row in audit_cfg
            if str(row.get("ACTIVE", row.get("STATUS", ""))).upper()
            in ("X", "1", "TRUE", "YES", "ACTIVE")
        ]

        if not active_filters:
            self.finding(
                check_id="NET-008",
                title="No active security audit filters configured",
                severity=self.SEVERITY_CRITICAL,
                category="Audit Logging",
                description=(
                    "No active audit filters found in SM19 configuration. "
                    "Without audit filters, security-relevant events are not recorded."
                ),
                affected_items=["SM19 — 0 active filters"],
                remediation=(
                    "Configure SM19 audit filters for at least: "
                    "dialog logon failures, RFC logon events, transaction starts, "
                    "user master changes, authority check failures. "
                    "Enable both static and dynamic profiles."
                ),
                references=["SAP Note 2191612", "CIS SAP Benchmark Section 6.1"],
            )
