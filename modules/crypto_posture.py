"""
Cryptographic Posture Auditor
================================
Checks for encryption, certificate management, and
cryptographic configuration across S/4HANA and BTP.

Covers:
  - TLS configuration depth (cipher suites, protocol versions)
  - Certificate inventory & expiry management
  - SNC configuration and quality of protection
  - HANA encryption at rest
  - PSE (Personal Security Environment) health
  - CommonCryptoLib / SAP Crypto Library versioning
  - Key management & rotation policies
  - SSL/TLS trust store hygiene

Data sources:
  - tls_config.csv           → ICM TLS/SSL server configuration
  - certificate_inventory.csv → All system certificates (STRUST, SMICM)
  - snc_config.csv           → SNC configuration parameters
  - hana_encryption.json     → HANA encryption-at-rest settings
  - crypto_library.csv       → CommonCryptoLib/sapcryptolib version info
  - pse_inventory.csv        → PSE files and their status
  - key_management.json      → Key rotation and management config
"""

from typing import Dict, List, Any
from datetime import datetime
from modules.base_auditor import BaseAuditor


class CryptoPostureAuditor(BaseAuditor):

    WEAK_CIPHERS = [
        "RC4", "DES", "3DES", "NULL", "EXPORT", "anon",
        "MD5", "SHA1", "CBC3",
    ]

    STRONG_CIPHERS = [
        "AES_256_GCM", "AES_128_GCM", "CHACHA20_POLY1305",
        "ECDHE", "DHE",
    ]

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_tls_configuration()
        self.check_certificate_inventory()
        self.check_snc_configuration()
        self.check_hana_encryption()
        self.check_crypto_library_version()
        self.check_pse_health()
        self.check_key_management()
        return self.findings

    def check_tls_configuration(self):
        """Audit TLS/SSL configuration for protocol and cipher strength."""
        tls = self.data.get("tls_config")
        if not tls:
            return

        weak_protocols = []
        weak_ciphers_found = []
        no_hsts = []

        for row in tls:
            port = row.get("PORT", row.get("SERVICE_PORT", row.get("LISTENER", "")))
            protocol = row.get("PROTOCOL", row.get("SSL_PROTOCOL",
                      row.get("TLS_VERSION", "")))
            ciphers = row.get("CIPHERS", row.get("CIPHER_SUITE",
                     row.get("SSL_CIPHERS", "")))
            hsts = row.get("HSTS", row.get("STRICT_TRANSPORT", ""))
            name = row.get("NAME", row.get("SERVICE", f"Port {port}"))

            label = f"{name} (port: {port})"

            # Weak TLS versions
            if protocol:
                proto_upper = protocol.upper()
                if any(w in proto_upper for w in ["1.0", "1.1", "SSLV3", "SSLV2", "SSL3", "SSL2"]):
                    weak_protocols.append(
                        f"{label} — protocol: {protocol}"
                    )

            # Weak cipher suites
            if ciphers:
                cipher_upper = ciphers.upper()
                for wc in self.WEAK_CIPHERS:
                    if wc.upper() in cipher_upper:
                        weak_ciphers_found.append(
                            f"{label} — weak cipher: {wc} in suite"
                        )
                        break

            # Missing HSTS
            if not hsts or str(hsts).lower() in ("false", "0", "no", "disabled", ""):
                no_hsts.append(f"{label} — HSTS: not enabled")

        if weak_protocols:
            self.finding(
                check_id="CRYPTO-TLS-001",
                title="TLS endpoints allowing deprecated protocol versions",
                severity=self.SEVERITY_HIGH,
                category="Cryptographic Posture",
                description=(
                    f"{len(weak_protocols)} TLS endpoint(s) allow TLS 1.0, TLS 1.1, or SSLv3. "
                    "These have known vulnerabilities (BEAST, POODLE, etc.)."
                ),
                affected_items=weak_protocols,
                remediation=(
                    "Set minimum TLS version to 1.2 across all ICM ports. "
                    "Configure via icm/HTTPS/client_sni_* and ssl/ciphersuites. "
                    "Prefer TLS 1.3 where client compatibility allows."
                ),
                references=[
                    "SAP Note 510007 — SSL/TLS Configuration",
                    "NIST SP 800-52 Rev 2",
                ],
            )

        if weak_ciphers_found:
            self.finding(
                check_id="CRYPTO-TLS-002",
                title="TLS cipher suites include weak algorithms",
                severity=self.SEVERITY_HIGH,
                category="Cryptographic Posture",
                description=(
                    f"{len(weak_ciphers_found)} TLS endpoint(s) include weak cipher "
                    "algorithms (RC4, DES, 3DES, NULL, EXPORT, MD5-based). "
                    "These can be exploited for decryption or downgrade attacks."
                ),
                affected_items=weak_ciphers_found,
                remediation=(
                    "Configure ssl/ciphersuites to allow only strong ciphers: "
                    "AES-256-GCM, AES-128-GCM with ECDHE/DHE key exchange. "
                    "Remove all RC4, DES, 3DES, NULL, and EXPORT ciphers."
                ),
                references=["SAP Note 510007", "Mozilla TLS Configuration Guide"],
            )

        if no_hsts:
            self.finding(
                check_id="CRYPTO-TLS-003",
                title="HTTPS endpoints without HSTS (Strict Transport Security)",
                severity=self.SEVERITY_MEDIUM,
                category="Cryptographic Posture",
                description=(
                    f"{len(no_hsts)} HTTPS endpoint(s) do not send HSTS headers. "
                    "Without HSTS, users can be downgraded from HTTPS to HTTP "
                    "via SSL stripping attacks."
                ),
                affected_items=no_hsts,
                remediation=(
                    "Enable HSTS via ICM parameter icm/HTTP/hsts_header. "
                    "Set max-age to at least 31536000 (1 year). "
                    "Include includeSubDomains directive where appropriate."
                ),
                references=["SAP Note 2300507 — HSTS Configuration"],
            )

    def check_certificate_inventory(self):
        """Audit certificate inventory for expiry, weak keys, and management gaps."""
        certs = self.data.get("certificate_inventory")
        if not certs:
            return

        expired = []
        expiring_soon = []
        weak_keys = []
        self_signed_prod = []
        now = datetime.now()
        warning_days = self.get_config("cert_expiry_warning_days", 90)

        for row in certs:
            name = row.get("CERT_NAME", row.get("ALIAS", row.get("SUBJECT", "unknown")))
            expiry = row.get("VALID_TO", row.get("EXPIRY", row.get("NOT_AFTER", "")))
            key_size = row.get("KEY_SIZE", row.get("KEY_LENGTH", row.get("BITS", "")))
            algo = row.get("ALGORITHM", row.get("SIGNATURE_ALG", ""))
            issuer = row.get("ISSUER", row.get("ISSUED_BY", ""))
            purpose = row.get("PURPOSE", row.get("USAGE", row.get("PSE", "")))

            label = f"{name} (purpose: {purpose})" if purpose else name

            if expiry:
                parsed = self._parse_date(expiry)
                if parsed:
                    days_left = (parsed - now).days
                    if days_left <= 0:
                        expired.append(f"{label} — EXPIRED {abs(days_left)}d ago ({expiry})")
                    elif days_left <= warning_days:
                        expiring_soon.append(
                            f"{label} — expires in {days_left}d ({expiry})"
                        )

            if key_size:
                try:
                    if int(str(key_size)) < 2048:
                        weak_keys.append(f"{label} — key: {key_size} bits")
                except ValueError:
                    pass

            if algo and any(w in str(algo).upper() for w in ["SHA1", "MD5", "SHA-1"]):
                weak_keys.append(f"{label} — algorithm: {algo}")

            # Self-signed in production
            if issuer and name:
                issuer_upper = str(issuer).upper()
                name_upper = str(name).upper()
                if issuer_upper == name_upper or "SELF" in issuer_upper:
                    purpose_upper = str(purpose).upper()
                    if any(p in purpose_upper for p in ["PROD", "SSL", "HTTPS", "SNC", "SERVER"]):
                        self_signed_prod.append(f"{label} — issuer: self-signed")

        if expired:
            self.finding(
                check_id="CRYPTO-CERT-001",
                title="Expired certificates in system trust store",
                severity=self.SEVERITY_CRITICAL,
                category="Cryptographic Posture",
                description=(
                    f"{len(expired)} certificate(s) have expired. Expired certificates "
                    "cause TLS handshake failures, breaking HTTPS, SNC, and SSO."
                ),
                affected_items=expired,
                remediation=(
                    "Renew expired certificates immediately via STRUST. "
                    "Import updated CA certificates. Restart ICM after changes."
                ),
                references=["SAP Note 510007 — Certificate Management"],
            )

        if expiring_soon:
            self.finding(
                check_id="CRYPTO-CERT-002",
                title=f"Certificates expiring within {warning_days} days",
                severity=self.SEVERITY_HIGH,
                category="Cryptographic Posture",
                description=(
                    f"{len(expiring_soon)} certificate(s) are expiring within "
                    f"{warning_days} days. Proactive renewal avoids service disruptions."
                ),
                affected_items=expiring_soon,
                remediation=(
                    "Renew certificates at least 30 days before expiry. "
                    "Implement automated certificate monitoring and alerting."
                ),
                references=["SAP STRUST — Certificate Lifecycle"],
            )

        if weak_keys:
            self.finding(
                check_id="CRYPTO-CERT-003",
                title="Certificates with weak key sizes or algorithms",
                severity=self.SEVERITY_HIGH,
                category="Cryptographic Posture",
                description=(
                    f"{len(weak_keys)} certificate(s) use weak key sizes (<2048 bits) "
                    "or deprecated signature algorithms (SHA-1, MD5)."
                ),
                affected_items=weak_keys,
                remediation=(
                    "Replace with RSA 2048+ or ECDSA P-256+ keys, "
                    "signed with SHA-256 or stronger."
                ),
                references=["NIST SP 800-131A — Cryptographic Standards"],
            )

        if self_signed_prod:
            self.finding(
                check_id="CRYPTO-CERT-004",
                title="Self-signed certificates used in production context",
                severity=self.SEVERITY_MEDIUM,
                category="Cryptographic Posture",
                description=(
                    f"{len(self_signed_prod)} self-signed certificate(s) are used in "
                    "production contexts (HTTPS, SNC, SSL server). Self-signed certs "
                    "are not validated by standard trust chains, weakening TLS."
                ),
                affected_items=self_signed_prod,
                remediation=(
                    "Replace self-signed certificates with CA-issued certificates "
                    "from an internal PKI or public CA. "
                    "Self-signed certs are acceptable only for internal test environments."
                ),
                references=["SAP Security Guide — Certificate Best Practices"],
            )

    def check_snc_configuration(self):
        """Audit SNC (Secure Network Communications) configuration."""
        snc = self.data.get("snc_config")
        if not snc:
            # Check security_params for SNC parameters
            params = self.data.get("security_params") or []
            snc_params = {}
            for row in params:
                name = row.get("NAME", row.get("PARAMETER", "")).lower()
                value = row.get("VALUE", row.get("PARAM_VALUE", ""))
                if "snc" in name:
                    snc_params[name] = value

            if not snc_params:
                return

            # Check key SNC parameters
            snc_enabled = snc_params.get("snc/enable", "0")
            if str(snc_enabled) not in ("1", "TRUE", "YES"):
                self.finding(
                    check_id="CRYPTO-SNC-001",
                    title="SNC (Secure Network Communications) is disabled",
                    severity=self.SEVERITY_HIGH,
                    category="Cryptographic Posture",
                    description=(
                        "SNC is not enabled (snc/enable ≠ 1). Without SNC, "
                        "SAP GUI and RFC communication is unencrypted, exposing "
                        "credentials and business data on the network."
                    ),
                    affected_items=[f"snc/enable = {snc_enabled}"],
                    remediation=(
                        "Enable SNC by setting snc/enable = 1. "
                        "Configure snc/identity/as, snc/data_protection/min, "
                        "and snc/data_protection/max parameters. "
                        "Deploy SAP Crypto Library on all application servers."
                    ),
                    references=[
                        "SAP Note 460089 — SNC Configuration",
                        "CIS SAP Benchmark — SNC Requirements",
                    ],
                )

            qop = snc_params.get("snc/data_protection/min", "")
            if qop and str(qop) in ("1", "AUTHENTICATION_ONLY"):
                self.finding(
                    check_id="CRYPTO-SNC-002",
                    title="SNC quality of protection set to authentication only",
                    severity=self.SEVERITY_MEDIUM,
                    category="Cryptographic Posture",
                    description=(
                        "SNC minimum quality of protection is set to authentication "
                        "only (level 1). This verifies identity but does NOT encrypt "
                        "the data stream."
                    ),
                    affected_items=[f"snc/data_protection/min = {qop}"],
                    remediation=(
                        "Set snc/data_protection/min = 3 (privacy protection) "
                        "for full encryption. Level 2 (integrity) provides "
                        "tamper detection but not confidentiality."
                    ),
                    references=["SAP Note 460089 — SNC Quality of Protection Levels"],
                )
            return

        # Process dedicated SNC config export
        for row in snc:
            name = row.get("PARAMETER", row.get("NAME", ""))
            value = row.get("VALUE", "")
            if "enable" in name.lower() and str(value) not in ("1", "TRUE"):
                self.finding(
                    check_id="CRYPTO-SNC-001",
                    title="SNC is disabled",
                    severity=self.SEVERITY_HIGH,
                    category="Cryptographic Posture",
                    description="SNC is not enabled. RFC/GUI traffic is unencrypted.",
                    affected_items=[f"{name} = {value}"],
                    remediation="Enable SNC: set snc/enable = 1.",
                    references=["SAP Note 460089"],
                )

    def check_hana_encryption(self):
        """Check HANA encryption at rest and in transit."""
        hana = self.data.get("hana_encryption")
        if not hana:
            return

        config = hana if isinstance(hana, dict) else {}

        # Data volume encryption
        dve = config.get("dataVolumeEncryption", config.get("encryption_at_rest",
             config.get("volume_encryption", "")))
        if not dve or str(dve).lower() in ("false", "0", "no", "disabled"):
            self.finding(
                check_id="CRYPTO-HANA-001",
                title="HANA data volume encryption is disabled",
                severity=self.SEVERITY_HIGH,
                category="Cryptographic Posture",
                description=(
                    "HANA data volume encryption (encryption at rest) is not enabled. "
                    "Data stored on disk, including backups, is unencrypted and "
                    "vulnerable to physical media theft or unauthorized disk access."
                ),
                affected_items=["Data volume encryption: disabled"],
                remediation=(
                    "Enable HANA data volume encryption via "
                    "ALTER SYSTEM ENCRYPTION ON. "
                    "Configure with AES-256-CBC or AES-256-XTS. "
                    "Enable backup encryption separately."
                ),
                references=["SAP HANA Security Guide — Data Volume Encryption"],
            )

        # Log volume encryption
        log_enc = config.get("logVolumeEncryption", config.get("log_encryption", ""))
        if not log_enc or str(log_enc).lower() in ("false", "0", "no", "disabled"):
            self.finding(
                check_id="CRYPTO-HANA-002",
                title="HANA log volume encryption is disabled",
                severity=self.SEVERITY_MEDIUM,
                category="Cryptographic Posture",
                description=(
                    "HANA redo log encryption is not enabled. Transaction logs "
                    "contain complete change data and may expose sensitive records."
                ),
                affected_items=["Log volume encryption: disabled"],
                remediation="Enable log volume encryption alongside data volume encryption.",
                references=["SAP HANA Security Guide — Log Encryption"],
            )

        # Root key management
        root_key = config.get("rootKeyType", config.get("keyManagement",
                  config.get("key_source", "")))
        if root_key and str(root_key).upper() in ("INTERNAL", "DEFAULT", "LOCAL"):
            self.finding(
                check_id="CRYPTO-HANA-003",
                title="HANA encryption uses internal/default root key management",
                severity=self.SEVERITY_MEDIUM,
                category="Cryptographic Posture",
                description=(
                    "HANA encryption root keys are managed internally. For production, "
                    "an external key management solution (KMS) is recommended for "
                    "key separation and compliance."
                ),
                affected_items=[f"Root key management: {root_key}"],
                remediation=(
                    "Consider external key management via SAP Data Custodian or "
                    "cloud provider KMS (Azure Key Vault, AWS KMS). "
                    "This enables key separation from data."
                ),
                references=["SAP HANA — External Key Management"],
            )

    def check_crypto_library_version(self):
        """Check SAP Crypto Library / CommonCryptoLib version."""
        crypto = self.data.get("crypto_library")
        if not crypto:
            return

        for row in crypto:
            lib_name = row.get("LIBRARY", row.get("NAME",
                      row.get("COMPONENT", "")))
            version = row.get("VERSION", row.get("RELEASE", ""))
            patch = row.get("PATCH_LEVEL", row.get("PATCH", ""))
            path = row.get("PATH", row.get("LOCATION", ""))

            label = f"{lib_name} {version}" + (f" PL{patch}" if patch else "")

            # Check for very old versions (heuristic)
            if version:
                try:
                    major = int(str(version).split(".")[0])
                    if major < 8:
                        self.finding(
                            check_id="CRYPTO-LIB-001",
                            title=f"Outdated SAP Crypto Library: {label}",
                            severity=self.SEVERITY_HIGH,
                            category="Cryptographic Posture",
                            description=(
                                f"The SAP Crypto Library version ({label}) appears outdated. "
                                "Older versions may lack support for current TLS standards "
                                "and contain known vulnerabilities."
                            ),
                            affected_items=[f"{label} at {path}"],
                            remediation=(
                                "Update CommonCryptoLib to the latest version. "
                                "Download from SAP Software Center. "
                                "Verify compatibility with kernel version before upgrade."
                            ),
                            references=["SAP Note 1848999 — CommonCryptoLib Updates"],
                        )
                except (ValueError, IndexError):
                    pass

    def check_pse_health(self):
        """Check PSE (Personal Security Environment) file status."""
        pse = self.data.get("pse_inventory")
        if not pse:
            return

        issues = []
        now = datetime.now()

        for row in pse:
            pse_name = row.get("PSE_NAME", row.get("NAME",
                      row.get("PSE_FILE", "unknown")))
            status = row.get("STATUS", row.get("STATE", ""))
            cert_expiry = row.get("CERT_EXPIRY", row.get("VALID_TO", ""))
            pse_type = row.get("TYPE", row.get("PSE_TYPE", ""))

            label = f"{pse_name} ({pse_type})" if pse_type else pse_name

            if status and str(status).upper() in ("ERROR", "INVALID", "CORRUPTED", "EXPIRED"):
                issues.append(f"{label} — status: {status}")

            if cert_expiry:
                parsed = self._parse_date(cert_expiry)
                if parsed and (parsed - now).days <= 0:
                    issues.append(f"{label} — PSE certificate expired: {cert_expiry}")

        if issues:
            self.finding(
                check_id="CRYPTO-PSE-001",
                title="PSE files with errors or expired certificates",
                severity=self.SEVERITY_HIGH,
                category="Cryptographic Posture",
                description=(
                    f"{len(issues)} PSE file(s) have errors, are corrupted, or contain "
                    "expired certificates. PSEs are used for SSL/TLS, SNC, and SSO — "
                    "failures break encrypted communications."
                ),
                affected_items=issues,
                remediation=(
                    "Repair or recreate affected PSE files via STRUST. "
                    "Renew expired certificates within PSEs. "
                    "Verify PSE integrity after system copy or migration."
                ),
                references=["SAP STRUST — PSE Management"],
            )

    def check_key_management(self):
        """Audit key management and rotation policies."""
        km = self.data.get("key_management")
        if not km:
            return

        config = km if isinstance(km, dict) else {}
        issues = []

        rotation = config.get("keyRotationPolicy", config.get("rotation", ""))
        if not rotation or str(rotation).lower() in ("none", "manual", "disabled", ""):
            issues.append("Key rotation policy: not configured or manual-only")

        rotation_days = config.get("rotationIntervalDays", config.get("rotationPeriod", 0))
        max_rotation = self.get_config("max_key_rotation_days", 365)
        try:
            if int(str(rotation_days)) > max_rotation:
                issues.append(
                    f"Key rotation interval: {rotation_days}d (max: {max_rotation}d)"
                )
        except (ValueError, TypeError):
            pass

        backup = config.get("keyBackup", config.get("backupEnabled", ""))
        if not backup or str(backup).lower() in ("false", "0", "no"):
            issues.append("Encryption key backup: not configured")

        if issues:
            self.finding(
                check_id="CRYPTO-KEY-001",
                title="Key management policy gaps",
                severity=self.SEVERITY_MEDIUM,
                category="Cryptographic Posture",
                description=(
                    f"{len(issues)} key management gap(s) detected. Proper key "
                    "management is essential for maintaining encryption integrity "
                    "and enabling key recovery in disaster scenarios."
                ),
                affected_items=issues,
                remediation=(
                    "Implement automated key rotation with defined intervals. "
                    "Configure key backup/escrow for disaster recovery. "
                    "Document key management procedures and responsibilities."
                ),
                references=["NIST SP 800-57 — Key Management Recommendations"],
            )

    @staticmethod
    def _parse_date(date_str: str):
        if not date_str or not str(date_str).strip():
            return None
        date_str = str(date_str).strip()
        for suffix in ("Z", "+00:00"):
            if date_str.endswith(suffix):
                date_str = date_str[:-len(suffix)]
        if "T" in date_str:
            date_str = date_str.split("T")[0]
        for fmt in ("%Y-%m-%d", "%Y%m%d", "%d.%m.%Y", "%m/%d/%Y"):
            try:
                return datetime.strptime(date_str[:10], fmt)
            except (ValueError, IndexError):
                continue
        return None
