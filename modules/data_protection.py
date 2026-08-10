# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
Data Protection & Privacy Auditor
====================================
Checks for data protection and privacy compliance in
SAP S/4HANA RISE and BTP environments.

Covers:
  - Read Access Logging (RAL) configuration & coverage
  - Information Lifecycle Management (ILM) data retention
  - Data masking / anonymization in non-production systems
  - DPP toolkit configuration (GDPR/DPDP compliance)
  - Purpose of processing & consent management
  - Sensitive field logging & access auditing
  - Data residency & cross-border transfer controls
  - Personal data inventory & classification gaps
  - Data deletion / blocking compliance (right to erasure)
  - Non-production data protection

Data sources:
  - ral_config.csv           → Read Access Logging configuration (SRALMANAGER)
  - ral_log_channels.csv     → RAL log channel definitions
  - ilm_policies.json        → ILM retention/destruction rules
  - data_masking.json        → Non-prod data masking config
  - dpp_config.json          → Data Protection & Privacy toolkit config
  - purpose_of_processing.csv → Purpose assignments (GDPR Art.6)
  - sensitive_fields.csv     → Fields classified as PII/sensitive
  - data_residency.json      → Data residency & cross-border config
  - personal_data_inventory.csv → Personal data field inventory
  - deletion_requests.csv    → Data subject deletion/blocking requests
  - system_landscape.csv     → System landscape (prod/non-prod classification)
"""

from typing import Dict, List, Any, Set
from datetime import datetime, timedelta
from collections import defaultdict
from modules.base_auditor import BaseAuditor


class DataProtectionAuditor(BaseAuditor):

    # ── Fields considered highly sensitive (PII / financial) ──
    HIGHLY_SENSITIVE_FIELDS = {
        # HR / Personal
        "PERNR": "Personnel number",
        "NACHN": "Last name (HR)",
        "VORNA": "First name (HR)",
        "GBDAT": "Date of birth",
        "PERID": "Personal ID number",
        "ICNUM": "National ID / passport",
        "NATIO": "Nationality",
        "BANKN": "Bank account number",
        "BANKL": "Bank routing number",
        "IBAN": "IBAN",
        "SWIFT": "SWIFT/BIC code",
        "BETRG": "Salary/wage amount",
        "LGART": "Wage type",
        "GESCH": "Gender",
        "RACKY": "Ethnicity/race",
        "CONFG": "Religion",
        # Business Partner / Customer
        "SMTP_ADDR": "Email address",
        "TEL_NUMBER": "Phone number",
        "STRAS": "Street address",
        "PSTLZ": "Postal code",
        "NAME1": "Name line 1",
        "NAME2": "Name line 2",
        "STCD1": "Tax ID 1",
        "STCD2": "Tax ID 2",
        "KUNNR": "Customer number",
        "LIFNR": "Vendor number",
        # Financial
        "WRBTR": "Transaction amount",
        "DMBTR": "Local currency amount",
        "BELNR": "Document number",
        "HKONT": "GL account",
        "SAESSION_COOKIE": "Session identifiers",
    }

    # ── Tables containing personal data that should have RAL ──
    PERSONAL_DATA_TABLES = [
        "PA0000", "PA0001", "PA0002", "PA0003", "PA0006", "PA0008",
        "PA0009", "PA0021", "PA0077", "PA0105", "PA0185",
        "HRP1000", "HRP1001",
        "BUT000", "BUT020", "BUT021", "BUT050", "BUT100",
        "ADR2", "ADR3", "ADR6", "ADRC",
        "KNA1", "KNB1", "LFA1", "LFB1",
        "BSEG", "BKPF",
        "USR02", "USR21",
    ]

    # ── Regions with specific data protection regulations ──
    REGULATED_REGIONS = {
        "EU": "GDPR — General Data Protection Regulation",
        "EEA": "GDPR — European Economic Area",
        "UK": "UK GDPR / Data Protection Act 2018",
        "IN": "DPDP Act 2023 — Digital Personal Data Protection",
        "BR": "LGPD — Lei Geral de Proteção de Dados",
        "CA": "PIPEDA / Provincial privacy laws",
        "AU": "Privacy Act 1988 / APPs",
        "JP": "APPI — Act on Protection of Personal Information",
        "KR": "PIPA — Personal Information Protection Act",
        "CN": "PIPL — Personal Information Protection Law",
        "ZA": "POPIA — Protection of Personal Information Act",
        "SG": "PDPA — Personal Data Protection Act",
    }

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.check_ral_configuration()
        self.check_ral_coverage()
        self.check_ral_log_channels()
        self.check_ilm_retention_policies()
        self.check_ilm_missing_policies()
        self.check_data_masking_nonprod()
        self.check_dpp_toolkit()
        self.check_purpose_of_processing()
        self.check_sensitive_field_inventory()
        self.check_data_residency()
        self.check_deletion_requests()
        self.check_system_landscape_data_protection()
        return self.findings

    # ════════════════════════════════════════════════════════════════
    #  DPP-RAL-*: Read Access Logging
    # ════════════════════════════════════════════════════════════════

    def check_ral_configuration(self):
        """
        Verify Read Access Logging is enabled and configured.
        RAL records who read sensitive personal data — critical for
        GDPR Art.15 (right of access) and data breach forensics.
        """
        ral = self.data.get("ral_config")
        if not ral:
            # Check security_params for RAL-related parameters
            params = self.data.get("security_params") or []
            ral_param_found = False
            for row in params:
                name = row.get("NAME", row.get("PARAMETER", "")).lower()
                value = row.get("VALUE", row.get("PARAM_VALUE", ""))
                if "ral" in name or "read_access_log" in name:
                    ral_param_found = True
                    if str(value).lower() in ("0", "false", "no", "off", ""):
                        self.finding(
                            check_id="DPP-RAL-001",
                            title="Read Access Logging is disabled",
                            severity=self.SEVERITY_CRITICAL,
                            category="Data Protection & Privacy",
                            description=(
                                "Read Access Logging (RAL) is disabled at the system level. "
                                "Without RAL, there is no audit trail of who accessed sensitive "
                                "personal data — a fundamental GDPR/DPDP compliance requirement."
                            ),
                            affected_items=[f"Parameter: {name} = {value}"],
                            # One profile parameter is the whole defect, so the parameter
                            # IS the subject. No qualifier: the check fires on any of
                            # 0/false/no/off/empty, so pinning the exported spelling would
                            # retire and re-raise this finding on a cosmetic value change
                            # that fixes nothing.
                            affected_objects=[{"type": "parameter_name", "name": name}],
                            scope="object",
                            remediation=(
                                "Enable RAL via transaction SRALMANAGER. "
                                "Configure logging for all personal data access channels: "
                                "Dynpro, Web Dynpro, OData, RFC, and report outputs. "
                                "Ensure log storage is sized for retention requirements."
                            ),
                            references=[
                                "SAP Note 2089022 — Read Access Logging",
                                "GDPR Article 15 — Right of Access",
                                "DPDP Act 2023 Section 11 — Right to Information",
                            ],
                        )
                        return

            if not ral_param_found:
                self.finding(
                    check_id="DPP-RAL-001",
                    title="Read Access Logging configuration not found",
                    severity=self.SEVERITY_HIGH,
                    category="Data Protection & Privacy",
                    description=(
                        "No RAL configuration data was found. Cannot verify whether "
                        "Read Access Logging is enabled and properly configured."
                    ),
                    remediation=(
                        "Export RAL configuration from SRALMANAGER or provide "
                        "ral_config.csv with RAL channel and purpose definitions."
                    ),
                    references=["SAP Note 2089022 — Read Access Logging"],
                    # An ABSENCE of evidence: neither a RAL export nor a RAL-related
                    # profile parameter exists, so there is nothing in the data to name.
                    # Identified by (system, client, check_id) alone — correctly coarse.
                    scope="aggregate",
                )
            return

        # Analyze RAL config entries
        enabled_configs = []
        disabled_configs = []
        disabled_objects = []

        for row in ral:
            config_name = row.get("CONFIG_NAME", row.get("NAME",
                         row.get("LOG_DOMAIN", "")))
            status = row.get("STATUS", row.get("ACTIVE",
                    row.get("ENABLED", "")))
            channel = row.get("CHANNEL", row.get("LOG_CHANNEL", ""))
            purpose = row.get("PURPOSE", row.get("LOG_PURPOSE", ""))

            if str(status).upper() in ("ACTIVE", "1", "TRUE", "YES", "X"):
                enabled_configs.append(f"{config_name} (channel: {channel})")
            else:
                disabled_configs.append(f"{config_name} (channel: {channel})")
                # The RAL configuration (log domain) is the config entry that has to be
                # activated in SRALMANAGER. A row that names no configuration contributes
                # its display string only — no placeholder node is invented for it. The
                # channel is left off the node so one RAL configuration stays one node
                # across its per-channel rows.
                if config_name and str(config_name).strip():
                    disabled_objects.append({"type": "ral_config", "name": config_name})

        if not enabled_configs:
            self.finding(
                check_id="DPP-RAL-001",
                title="Read Access Logging has no active configurations",
                severity=self.SEVERITY_CRITICAL,
                category="Data Protection & Privacy",
                description=(
                    "RAL is configured but no active logging rules were found. "
                    "Personal data read access is not being recorded."
                ),
                affected_items=disabled_configs[:10] if disabled_configs else ["No RAL configs found"],
                affected_objects=disabled_objects,
                # One finding summarising the whole inactive RAL configuration set:
                # activating one configuration must shrink this finding, not retire it
                # and raise a fresh one with a reset age.
                scope="aggregate",
                remediation=(
                    "Activate RAL configurations for all personal data domains. "
                    "Configure via SRALMANAGER with appropriate log purposes."
                ),
                references=[
                    "SAP Note 2089022",
                    "GDPR Article 15",
                ],
            )

    def check_ral_coverage(self):
        """Check if RAL covers all personal data access channels."""
        ral = self.data.get("ral_config")
        if not ral:
            return

        configured_channels = set()
        for row in ral:
            channel = row.get("CHANNEL", row.get("LOG_CHANNEL", "")).upper()
            status = row.get("STATUS", row.get("ACTIVE", ""))
            if str(status).upper() in ("ACTIVE", "1", "TRUE", "YES", "X"):
                configured_channels.add(channel)

        required_channels = {
            "DYNPRO": "SAP GUI screen access",
            "WEBDYNPRO": "Web Dynpro / Fiori UI access",
            "ODATA": "OData API access (Fiori apps, external APIs)",
            "RFC": "Remote Function Call access",
            "ALV": "ALV report output / list displays",
        }

        missing = []
        for ch, desc in required_channels.items():
            found = any(ch in cc for cc in configured_channels)
            if not found:
                missing.append(f"{ch}: {desc}")

        if missing:
            self.finding(
                check_id="DPP-RAL-002",
                title="Read Access Logging missing coverage for key channels",
                severity=self.SEVERITY_HIGH,
                category="Data Protection & Privacy",
                description=(
                    f"{len(missing)} data access channel(s) are not covered by RAL. "
                    "Personal data accessed through these channels goes unlogged."
                ),
                affected_items=missing,
                # Aggregate, and deliberately WITHOUT affected_objects. The members are the
                # required channel KINDS from this module's own constant list, and the
                # defect is precisely that no RAL rule exists for them — the missing rules
                # are absent from the export by definition, so there is no object in the
                # data to name. Covering one channel must also not reset the finding's age.
                scope="aggregate",
                remediation=(
                    "Configure RAL rules for all listed channels in SRALMANAGER. "
                    "OData is especially critical as Fiori apps use it exclusively. "
                    "RFC channel is needed to capture BAPI-based data reads."
                ),
                references=["SAP Note 2089022 — RAL Channel Configuration"],
            )

    def check_ral_log_channels(self):
        """Check RAL log channel storage and retention."""
        channels = self.data.get("ral_log_channels")
        if not channels:
            return

        short_retention = []
        short_retention_objects = []
        no_archiving = []
        min_retention_days = self.get_config("ral_min_retention_days", 365)

        for row in channels:
            name = row.get("CHANNEL_NAME", row.get("NAME", ""))
            retention = row.get("RETENTION_DAYS", row.get("RETENTION",
                       row.get("TTL", "")))
            archiving = row.get("ARCHIVING", row.get("ARCHIVE_ENABLED", ""))
            storage = row.get("STORAGE_TYPE", row.get("STORAGE", ""))

            if retention:
                try:
                    ret_days = int(str(retention))
                    if ret_days < min_retention_days:
                        short_retention.append(
                            f"{name} — retention: {ret_days}d (min: {min_retention_days}d)"
                        )
                        # The RAL log channel is the config entry whose retention is
                        # remediated. No qualifier: the retention figure is exactly what
                        # changes when this is fixed, so pinning it would spawn a new node
                        # every time the value is tuned. Unnamed rows are skipped.
                        if name and str(name).strip():
                            short_retention_objects.append(
                                {"type": "ral_channel", "name": name})
                except ValueError:
                    pass

            if not archiving or str(archiving).lower() in ("false", "0", "no", ""):
                no_archiving.append(f"{name} — archiving: not configured")

        if short_retention:
            self.finding(
                check_id="DPP-RAL-003",
                title=f"RAL log channels with retention below {min_retention_days} days",
                severity=self.SEVERITY_MEDIUM,
                category="Data Protection & Privacy",
                description=(
                    f"{len(short_retention)} RAL log channel(s) have retention periods "
                    f"shorter than {min_retention_days} days. Regulatory requirements "
                    "may mandate longer retention for data access audit trails."
                ),
                affected_items=short_retention,
                affected_objects=short_retention_objects,
                # One finding over every under-retained channel: lengthening retention on
                # one channel must shrink the member list, not reset the finding's age.
                scope="aggregate",
                remediation=(
                    f"Increase RAL log retention to at least {min_retention_days} days. "
                    "Configure archiving for long-term storage compliance. "
                    "Verify retention aligns with GDPR Art.5(1)(e) storage limitation principle."
                ),
                references=["GDPR Article 5(1)(e) — Storage Limitation"],
            )

    # ════════════════════════════════════════════════════════════════
    #  DPP-ILM-*: Information Lifecycle Management
    # ════════════════════════════════════════════════════════════════

    def check_ilm_retention_policies(self):
        """
        Audit ILM retention and destruction policies:
        - Policies with excessively long retention
        - Policies without end-of-purpose triggers
        - Policies with manual-only destruction
        """
        ilm = self.data.get("ilm_policies")
        if not ilm:
            return

        policies = ilm if isinstance(ilm, list) else \
            ilm.get("policies", ilm.get("retentionRules", []))

        long_retention = []
        no_auto_destroy = []
        no_end_purpose = []
        long_retention_objects = []
        no_auto_destroy_objects = []
        no_end_purpose_objects = []
        max_retention_years = self.get_config("max_retention_years", 10)

        for pol in policies:
            if not isinstance(pol, dict):
                continue

            name = pol.get("name", pol.get("policyName", pol.get("rule", "unknown")))
            data_object = pol.get("dataObject", pol.get("object",
                         pol.get("table", "")))
            retention = pol.get("retentionPeriod", pol.get("retention",
                       pol.get("duration", "")))
            destruction = pol.get("destructionMethod", pol.get("destruction",
                         pol.get("endAction", "")))
            end_purpose = pol.get("endOfPurpose", pol.get("purposeExpiry",
                         pol.get("legalBasis", "")))
            unit = pol.get("unit", pol.get("retentionUnit", "YEARS"))

            label = f"{name} (object: {data_object})"

            # Objects for this policy row. The ILM POLICY is the config entry at fault;
            # the retained TABLE is a real object too, and the policy->table edge is what
            # makes the ILM coverage question answerable in the graph. `name` above falls
            # back to the display placeholder "unknown", so identity is taken from the raw
            # export instead: a row that named no policy contributes no node rather than a
            # fabricated one.
            raw_name = pol.get("name") or pol.get("policyName") or pol.get("rule") or ""
            pol_objects = []
            if str(raw_name).strip():
                pol_objects.append({"type": "ilm_policy", "name": raw_name})
            if data_object and str(data_object).strip():
                pol_objects.append({"type": "table", "name": data_object})

            # Excessive retention
            if retention:
                try:
                    ret_val = int(str(retention))
                    if unit.upper() in ("YEARS", "Y") and ret_val > max_retention_years:
                        long_retention.append(
                            f"{label} — retention: {ret_val} years (max: {max_retention_years})"
                        )
                        long_retention_objects.extend(pol_objects)
                    elif unit.upper() in ("DAYS", "D") and ret_val > max_retention_years * 365:
                        long_retention.append(
                            f"{label} — retention: {ret_val} days (max: {max_retention_years * 365})"
                        )
                        long_retention_objects.extend(pol_objects)
                except ValueError:
                    pass

            # No automatic destruction
            if destruction and str(destruction).upper() in (
                "MANUAL", "NONE", "REVIEW", ""
            ):
                no_auto_destroy.append(
                    f"{label} — destruction: {destruction or 'not configured'}"
                )
                no_auto_destroy_objects.extend(pol_objects)

            # No end-of-purpose definition
            if not end_purpose or str(end_purpose).strip() == "":
                no_end_purpose.append(label)
                no_end_purpose_objects.extend(pol_objects)

        if long_retention:
            self.finding(
                check_id="DPP-ILM-001",
                title=f"ILM policies with retention exceeding {max_retention_years} years",
                severity=self.SEVERITY_MEDIUM,
                category="Data Protection & Privacy",
                description=(
                    f"{len(long_retention)} ILM retention policy/policies exceed "
                    f"{max_retention_years} years. GDPR/DPDP requires data to be stored "
                    "only as long as necessary for the processing purpose."
                ),
                affected_items=long_retention,
                affected_objects=long_retention_objects,
                # One finding rolling up every over-retaining policy: shortening one
                # policy's retention must shrink this finding, not retire it and raise a
                # fresh one whose age starts at zero.
                scope="aggregate",
                remediation=(
                    "Review retention periods against business and legal requirements. "
                    "Reduce to minimum necessary. Document legal basis for any "
                    "retention exceeding standard periods."
                ),
                references=[
                    "GDPR Article 5(1)(e) — Storage Limitation",
                    "DPDP Act 2023 Section 8(7) — Data Retention",
                ],
            )

        if no_auto_destroy:
            self.finding(
                check_id="DPP-ILM-002",
                title="ILM policies without automatic data destruction",
                severity=self.SEVERITY_MEDIUM,
                category="Data Protection & Privacy",
                description=(
                    f"{len(no_auto_destroy)} ILM policy/policies rely on manual destruction "
                    "or have no destruction method configured. Manual processes are "
                    "unreliable and frequently result in data hoarding."
                ),
                affected_items=no_auto_destroy,
                affected_objects=no_auto_destroy_objects,
                # Aggregate over the manual-destruction policy set — same reasoning.
                scope="aggregate",
                remediation=(
                    "Configure automatic destruction workflows in ILM. "
                    "Use SAP ILM destruction cockpit for scheduled execution. "
                    "Implement approval workflows for destruction of regulated data."
                ),
                references=["SAP ILM — Data Destruction Configuration"],
            )

        if no_end_purpose:
            self.finding(
                check_id="DPP-ILM-003",
                title="ILM policies without end-of-purpose definitions",
                severity=self.SEVERITY_HIGH,
                category="Data Protection & Privacy",
                description=(
                    f"{len(no_end_purpose)} ILM policy/policies have no end-of-purpose "
                    "trigger defined. Without this, there is no mechanism to determine "
                    "when data should transition to blocking or deletion."
                ),
                affected_items=no_end_purpose,
                affected_objects=no_end_purpose_objects,
                # Aggregate over the policies missing an end-of-purpose trigger —
                # defining one policy's trigger must not restart the finding's clock.
                scope="aggregate",
                remediation=(
                    "Define end-of-purpose conditions for every ILM policy: "
                    "business transaction completion, contract termination, "
                    "employment end, or explicit time-based trigger. "
                    "Map to GDPR Article 6 legal basis for processing."
                ),
                references=[
                    "GDPR Article 17 — Right to Erasure",
                    "SAP ILM — End of Purpose Configuration",
                ],
            )

    def check_ilm_missing_policies(self):
        """Check for personal data tables without ILM policies."""
        ilm = self.data.get("ilm_policies")
        if not ilm:
            return

        policies = ilm if isinstance(ilm, list) else \
            ilm.get("policies", ilm.get("retentionRules", []))

        covered_objects = set()
        for pol in policies:
            if isinstance(pol, dict):
                obj = pol.get("dataObject", pol.get("object",
                     pol.get("table", ""))).upper()
                if obj:
                    covered_objects.add(obj)

        uncovered = []
        for table in self.PERSONAL_DATA_TABLES:
            if table.upper() not in covered_objects:
                uncovered.append(table)

        if uncovered:
            self.finding(
                check_id="DPP-ILM-004",
                title="Personal data tables without ILM retention policies",
                severity=self.SEVERITY_HIGH,
                category="Data Protection & Privacy",
                description=(
                    f"{len(uncovered)} table(s) known to contain personal data have no "
                    "ILM retention policy. Data in these tables will be retained "
                    "indefinitely, violating data minimization principles."
                ),
                affected_items=uncovered,
                # The uncovered TABLES are real SAP objects (this module's personal-data
                # table list), so they become graph nodes and connect this gap to the ILM
                # policies that do exist. Aggregate: creating a policy for one table must
                # shrink the finding rather than replace it with a zero-age clone.
                affected_objects=[{"type": "table", "name": t} for t in uncovered],
                scope="aggregate",
                remediation=(
                    "Create ILM retention policies for all listed tables. "
                    "Use SAP's standard ILM objects where available. "
                    "For custom tables, define custom ILM objects in transaction IRMPOL."
                ),
                references=[
                    "SAP ILM — Standard Retention Objects",
                    "GDPR Article 5(1)(c) — Data Minimisation",
                ],
            )

    # ════════════════════════════════════════════════════════════════
    #  DPP-MASK-*: Data Masking in Non-Production
    # ════════════════════════════════════════════════════════════════

    def check_data_masking_nonprod(self):
        """
        Verify that non-production system copies have data masking/anonymization.
        """
        masking = self.data.get("data_masking")
        landscape = self.data.get("system_landscape")

        if masking:
            configs = masking if isinstance(masking, list) else \
                masking.get("configurations", masking.get("rules", []))

            no_pii_masking = []
            no_pii_masking_objects = []
            disabled = []

            for cfg in configs:
                if not isinstance(cfg, dict):
                    continue

                name = cfg.get("name", cfg.get("system", "unknown"))
                system_type = cfg.get("systemType", cfg.get("type",
                             cfg.get("environment", "")))
                pii_masked = cfg.get("piiMasked", cfg.get("anonymized",
                            cfg.get("maskingEnabled", False)))
                status = cfg.get("status", cfg.get("active", ""))

                if str(system_type).upper() in ("DEV", "DEVELOPMENT", "QA",
                    "QUALITY", "TEST", "SANDBOX", "SBX", "TRAINING"):

                    if not pii_masked or str(pii_masked).lower() in (
                        "false", "0", "no", ""
                    ):
                        no_pii_masking.append(
                            f"{name} (type: {system_type}) — PII masking: not enabled"
                        )
                        # The unmasked SYSTEM is the object. `name` above falls back to
                        # the display placeholder "unknown", so the node is taken from the
                        # raw export and a config that names no system contributes none.
                        # The name is NOT also stamped as the object's `system` field:
                        # fingerprint_finding reads objs[0].system even for an aggregate,
                        # which would let the member list leak into this finding's identity.
                        raw_name = cfg.get("name") or cfg.get("system") or ""
                        if str(raw_name).strip():
                            no_pii_masking_objects.append(
                                {"type": "system", "name": raw_name})

                    if status and str(status).upper() in ("DISABLED", "INACTIVE"):
                        disabled.append(f"{name} — masking status: {status}")

            if no_pii_masking:
                self.finding(
                    check_id="DPP-MASK-001",
                    title="Non-production systems without PII data masking",
                    severity=self.SEVERITY_CRITICAL,
                    category="Data Protection & Privacy",
                    description=(
                        f"{len(no_pii_masking)} non-production system(s) do not have PII "
                        "masking/anonymization enabled. Production data copies in dev/test "
                        "systems expose personal data to broader user populations with "
                        "weaker access controls."
                    ),
                    affected_items=no_pii_masking,
                    affected_objects=no_pii_masking_objects,
                    # One finding over the whole unmasked non-production population:
                    # masking one system must shrink it, not reset its age.
                    scope="aggregate",
                    remediation=(
                        "Implement data masking for all non-production system copies. "
                        "Use SAP Data Privacy Integration (DPI), SAP Test Data Migration "
                        "Server (TDMS), or third-party tools (e.g., Informatica TDM). "
                        "Mask: names, addresses, phone numbers, bank details, "
                        "tax IDs, and all fields classified as PII."
                    ),
                    references=[
                        "GDPR Article 32 — Security of Processing",
                        "SAP TDMS — Test Data Migration Server",
                    ],
                )

        # Also check system landscape for systems without masking config
        if landscape:
            nonprod_systems = []
            nonprod_objects = []
            for row in landscape:
                sid = row.get("SID", row.get("SYSTEM", row.get("SYSTEM_ID", "")))
                env_type = row.get("ENVIRONMENT", row.get("TYPE",
                          row.get("SYSTEM_TYPE", "")))
                has_masking = row.get("DATA_MASKING", row.get("ANONYMIZED",
                             row.get("MASKED", "")))
                is_prod_copy = row.get("PROD_COPY", row.get("IS_COPY",
                              row.get("SOURCE_PROD", "")))

                if str(env_type).upper() in ("DEV", "DEVELOPMENT", "QA",
                    "QUALITY", "TEST", "SANDBOX", "SBX", "TRAINING"):
                    if str(is_prod_copy).upper() in ("YES", "TRUE", "1", "X"):
                        if not has_masking or str(has_masking).lower() in (
                            "false", "0", "no", ""
                        ):
                            nonprod_systems.append(
                                f"{sid} (env: {env_type}) — production copy without masking"
                            )
                            # The SID from the landscape export is the object. Rows with
                            # no SID are display-only. As above, the SID is not stamped as
                            # the object's `system` field: for an aggregate that would put
                            # objs[0] — a member — into the finding's identity.
                            if sid and str(sid).strip():
                                nonprod_objects.append({"type": "system", "name": sid})

            if nonprod_systems:
                self.finding(
                    check_id="DPP-MASK-002",
                    title="Non-production systems identified as production copies without masking",
                    severity=self.SEVERITY_CRITICAL,
                    category="Data Protection & Privacy",
                    description=(
                        f"{len(nonprod_systems)} non-production system(s) are flagged as "
                        "copies of production but have no data masking. These contain "
                        "full production personal data accessible to development teams."
                    ),
                    affected_items=nonprod_systems,
                    affected_objects=nonprod_objects,
                    # Aggregate over the unmasked production-copy population — masking
                    # one copy must not retire the finding and restart its clock.
                    scope="aggregate",
                    remediation=(
                        "Immediately schedule data masking runs for all production copies. "
                        "Implement a policy requiring masking within 48 hours of system copy. "
                        "Block production copy requests without approved masking plans."
                    ),
                    references=[
                        "GDPR Article 25 — Data Protection by Design",
                        "SAP Note 2667054 — Data Scrambling in System Copies",
                    ],
                )

    # ════════════════════════════════════════════════════════════════
    #  DPP-TOOLKIT-*: DPP Toolkit Configuration
    # ════════════════════════════════════════════════════════════════

    def check_dpp_toolkit(self):
        """
        Review SAP Data Protection & Privacy toolkit configuration:
        - Change of purpose (GDPR Art.6 compliance)
        - Information report (Art.15 — right of access)
        - Deletion report (Art.17 — right to erasure)
        - Blocking/unblocking (end-of-purpose)
        """
        dpp = self.data.get("dpp_config")
        if not dpp:
            return

        config = dpp if isinstance(dpp, dict) else {}

        required_features = {
            "informationReport": "GDPR Art.15 — Right of Access / Data Subject Report",
            "deletionReport": "GDPR Art.17 — Right to Erasure / Deletion Report",
            "changeOfPurpose": "GDPR Art.6 — Change of Purpose Management",
            "dataBlocking": "End-of-Purpose — Data Blocking Mechanism",
            "consentManagement": "GDPR Art.7 — Consent Recording & Withdrawal",
            "dataBreachNotification": "GDPR Art.33/34 — Breach Notification Support",
        }

        unconfigured = []
        for feature, desc in required_features.items():
            val = config.get(feature, config.get(feature.lower(), ""))
            if not val or str(val).lower() in ("false", "0", "no", "disabled", ""):
                unconfigured.append(f"{feature}: {desc}")

        if unconfigured:
            self.finding(
                check_id="DPP-TOOLKIT-001",
                title="DPP toolkit features not configured",
                severity=self.SEVERITY_HIGH,
                category="Data Protection & Privacy",
                description=(
                    f"{len(unconfigured)} DPP toolkit feature(s) are not enabled. "
                    "These features are required for GDPR/DPDP compliance to support "
                    "data subject rights and regulatory obligations."
                ),
                affected_items=unconfigured,
                # Aggregate, and deliberately WITHOUT affected_objects. The members are
                # toolkit CAPABILITY FLAGS from this module's own constant list, not named
                # SAP objects, and the defect is that they are switched off. Typing them
                # as `parameter_name` would be a lie (they are not profile parameters) and
                # would upper-case case-bearing keys such as "informationReport".
                scope="aggregate",
                remediation=(
                    "Configure all DPP toolkit features in the S/4HANA system. "
                    "Use Fiori apps: 'Information Report', 'Deletion Report', "
                    "'Change of Purpose', and 'Data Blocking/Unblocking'. "
                    "Ensure integration with your consent management platform."
                ),
                references=[
                    "SAP S/4HANA — Data Protection & Privacy Toolkit",
                    "GDPR Articles 6, 7, 15, 17, 33, 34",
                    "DPDP Act 2023 Sections 6, 8, 11, 12, 13",
                ],
            )

    # ════════════════════════════════════════════════════════════════
    #  DPP-POP-*: Purpose of Processing
    # ════════════════════════════════════════════════════════════════

    def check_purpose_of_processing(self):
        """
        Audit purpose-of-processing assignments:
        - Personal data processed without assigned purpose
        - Expired purposes still active
        - Missing legal basis documentation
        """
        pop = self.data.get("purpose_of_processing")
        if not pop:
            return

        no_legal_basis = []
        expired = []
        no_legal_basis_objects = []
        expired_objects = []
        now = datetime.now()

        for row in pop:
            purpose = row.get("PURPOSE", row.get("PURPOSE_ID",
                    row.get("PURPOSE_NAME", "")))
            legal_basis = row.get("LEGAL_BASIS", row.get("BASIS",
                         row.get("GDPR_ARTICLE", "")))
            expiry = row.get("EXPIRY_DATE", row.get("VALID_TO",
                    row.get("END_DATE", "")))
            data_categories = row.get("DATA_CATEGORIES", row.get("CATEGORIES",
                             row.get("FIELDS", "")))
            status = row.get("STATUS", row.get("ACTIVE", ""))

            label = f"Purpose: {purpose}"

            # The purpose-of-processing entry is the config object at fault. Neither the
            # legal basis nor the expiry date qualifies it: both are the values being
            # remediated, so pinning them would re-node the purpose on every correction.
            purpose_obj = ({"type": "processing_purpose", "name": purpose}
                           if purpose and str(purpose).strip() else None)

            if not legal_basis or legal_basis.strip() == "":
                no_legal_basis.append(f"{label} — legal basis: not documented")
                if purpose_obj:
                    no_legal_basis_objects.append(purpose_obj)

            if expiry:
                parsed = self._parse_date_flexible(expiry)
                if parsed and parsed < now:
                    if str(status).upper() not in ("EXPIRED", "CLOSED", "INACTIVE"):
                        expired.append(
                            f"{label} — expired: {expiry}, status: {status or 'active'}"
                        )
                        if purpose_obj:
                            expired_objects.append(purpose_obj)

        if no_legal_basis:
            self.finding(
                check_id="DPP-POP-001",
                title="Purposes of processing without documented legal basis",
                severity=self.SEVERITY_HIGH,
                category="Data Protection & Privacy",
                description=(
                    f"{len(no_legal_basis)} purpose-of-processing definition(s) lack a "
                    "documented legal basis (GDPR Art.6). Every processing activity "
                    "must have a lawful basis: consent, contract, legal obligation, "
                    "vital interest, public task, or legitimate interest."
                ),
                affected_items=no_legal_basis,
                affected_objects=no_legal_basis_objects,
                # One finding over every purpose lacking a legal basis: documenting one
                # purpose must shrink the finding, not raise a zero-age replacement.
                scope="aggregate",
                remediation=(
                    "Document the legal basis for every purpose of processing. "
                    "Map to GDPR Art.6(1)(a-f) or DPDP Act Section 4. "
                    "Record in the S/4HANA DPP toolkit and your ROPA."
                ),
                references=[
                    "GDPR Article 6 — Lawfulness of Processing",
                    "DPDP Act 2023 Section 4 — Grounds for Processing",
                ],
            )

        if expired:
            self.finding(
                check_id="DPP-POP-002",
                title="Expired purposes of processing still active",
                severity=self.SEVERITY_MEDIUM,
                category="Data Protection & Privacy",
                description=(
                    f"{len(expired)} purpose(s) have passed their expiry date but are "
                    "still active. Data processed under expired purposes lacks lawful "
                    "basis and should be blocked or deleted."
                ),
                affected_items=expired,
                affected_objects=expired_objects,
                # Aggregate over the expired-but-active purpose set — same reasoning.
                scope="aggregate",
                remediation=(
                    "Deactivate expired purposes and trigger end-of-purpose data blocking. "
                    "Review affected data for deletion eligibility. "
                    "Update ROPA (Record of Processing Activities)."
                ),
                references=["GDPR Article 5(1)(b) — Purpose Limitation"],
            )

    # ════════════════════════════════════════════════════════════════
    #  DPP-FIELD-*: Sensitive Field Inventory & Classification
    # ════════════════════════════════════════════════════════════════

    def check_sensitive_field_inventory(self):
        """
        Audit the personal data field inventory for coverage gaps:
        - Known sensitive fields missing from classification
        - Fields classified but without protection measures
        """
        inventory = self.data.get("personal_data_inventory")
        sensitive_fields = self.data.get("sensitive_fields")

        if inventory:
            inv_list = inventory if isinstance(inventory, list) else []

            # Check classified fields
            no_protection = []
            no_ral = []
            no_ral_objects = []
            no_protection_objects = []

            for row in inv_list:
                field = row.get("FIELD_NAME", row.get("FIELD",
                       row.get("COLUMN", "")))
                table = row.get("TABLE_NAME", row.get("TABLE", ""))
                classification = row.get("CLASSIFICATION", row.get("DATA_CLASS",
                                row.get("SENSITIVITY", "")))
                ral_enabled = row.get("RAL_ENABLED", row.get("RAL",
                             row.get("ACCESS_LOGGING", "")))
                masked = row.get("MASKED_IN_NONPROD", row.get("MASKED",
                        row.get("ANONYMIZED", "")))

                label = f"{table}.{field}" if table else field

                # The object is the TABLE, narrowed by the column: a bare field name is
                # not locatable (NAME1 exists in many tables), so a row with no table
                # contributes its display string only. The classification is left off the
                # qualifier — re-classifying a field must not create a second node for it.
                field_obj = None
                if table and str(table).strip():
                    field_obj = {"type": "table", "name": table}
                    if field and str(field).strip():
                        field_obj["qualifier"] = f"field={str(field).strip()}"

                if classification and classification.upper() in (
                    "PII", "SENSITIVE", "PERSONAL", "SPECIAL_CATEGORY",
                    "HIGH", "CONFIDENTIAL"
                ):
                    if not ral_enabled or str(ral_enabled).lower() in (
                        "false", "0", "no", ""
                    ):
                        no_ral.append(f"{label} (class: {classification})")
                        if field_obj:
                            no_ral_objects.append(field_obj)

                    if not masked or str(masked).lower() in (
                        "false", "0", "no", ""
                    ):
                        no_protection.append(
                            f"{label} (class: {classification}) — not masked in non-prod"
                        )
                        if field_obj:
                            no_protection_objects.append(field_obj)

            if no_ral:
                self.finding(
                    check_id="DPP-FIELD-001",
                    title="Sensitive classified fields without Read Access Logging",
                    severity=self.SEVERITY_HIGH,
                    category="Data Protection & Privacy",
                    description=(
                        f"{len(no_ral)} field(s) classified as PII/sensitive do not have "
                        "Read Access Logging enabled. Access to these fields is unaudited."
                    ),
                    affected_items=no_ral[:50],
                    affected_objects=no_ral_objects,
                    # One finding over the unlogged-field population: enabling RAL on one
                    # field must shrink it rather than reset its age. The object list is
                    # not truncated with the display list — identity is unaffected either
                    # way and the graph should see every field.
                    scope="aggregate",
                    remediation=(
                        "Enable RAL for all PII-classified fields via SRALMANAGER. "
                        "Create RAL log purposes matching the field's processing purpose."
                    ),
                    references=["SAP Note 2089022 — Field-Level RAL Configuration"],
                    details={"total_count": len(no_ral)},
                )

            if no_protection:
                self.finding(
                    check_id="DPP-FIELD-002",
                    title="Sensitive fields not masked in non-production",
                    severity=self.SEVERITY_MEDIUM,
                    category="Data Protection & Privacy",
                    description=(
                        f"{len(no_protection)} PII field(s) are classified as sensitive "
                        "but are not included in non-production masking rules."
                    ),
                    affected_items=no_protection[:50],
                    affected_objects=no_protection_objects,
                    # Aggregate over the unmasked-field population — same reasoning.
                    scope="aggregate",
                    remediation=(
                        "Add all PII-classified fields to the data masking rule set. "
                        "Apply masking during system copy refresh cycles."
                    ),
                    references=["GDPR Article 32 — Pseudonymisation & Encryption"],
                    details={"total_count": len(no_protection)},
                )

        # Check for known sensitive fields missing from inventory entirely
        if sensitive_fields:
            classified_fields = set()
            for row in sensitive_fields:
                field = row.get("FIELD_NAME", row.get("FIELD",
                       row.get("COLUMN", ""))).upper()
                if field:
                    classified_fields.add(field)

            missing_from_inventory = []
            for field, desc in self.HIGHLY_SENSITIVE_FIELDS.items():
                if field.upper() not in classified_fields:
                    missing_from_inventory.append(f"{field}: {desc}")

            if missing_from_inventory:
                self.finding(
                    check_id="DPP-FIELD-003",
                    title="Known sensitive fields missing from data classification inventory",
                    severity=self.SEVERITY_MEDIUM,
                    category="Data Protection & Privacy",
                    description=(
                        f"{len(missing_from_inventory)} commonly sensitive SAP field(s) "
                        "are not present in the data classification inventory. "
                        "Unclassified sensitive fields may lack proper protection."
                    ),
                    affected_items=missing_from_inventory[:30],
                    # Aggregate, and deliberately WITHOUT affected_objects. The members are
                    # bare DDIC field names from this module's constant checklist with no
                    # owning table in the data — NAME1 alone is not a locatable object, and
                    # naming a table for it would be invention. (Contrast DPP-ILM-004,
                    # where each uncovered member IS one concrete table.)
                    scope="aggregate",
                    remediation=(
                        "Add all listed fields to the personal data classification inventory. "
                        "Assign appropriate data classification levels. "
                        "Use SAP's Data Privacy Integration (DPI) for automated discovery."
                    ),
                    references=["SAP DPI — Personal Data Discovery & Classification"],
                    details={"total_missing": len(missing_from_inventory)},
                )

    # ════════════════════════════════════════════════════════════════
    #  DPP-RES-*: Data Residency & Cross-Border Transfers
    # ════════════════════════════════════════════════════════════════

    def check_data_residency(self):
        """
        Check data residency and cross-border transfer configurations.
        """
        residency = self.data.get("data_residency")
        if not residency:
            return

        config = residency if isinstance(residency, dict) else {}
        if isinstance(residency, list):
            config = {"transfers": residency}

        transfers = config.get("transfers", config.get("crossBorder",
                   config.get("dataFlows", [])))
        primary_region = config.get("primaryRegion", config.get("dataCenter",
                        config.get("homeRegion", "")))

        no_adequacy = []
        no_safeguard = []
        sensitive_transfers = []
        no_safeguard_objects = []
        sensitive_transfer_objects = []

        for transfer in transfers:
            if not isinstance(transfer, dict):
                continue

            name = transfer.get("name", transfer.get("flow", "unknown"))
            source_region = transfer.get("sourceRegion", transfer.get("from", ""))
            dest_region = transfer.get("destRegion", transfer.get("to",
                         transfer.get("destination", "")))
            adequacy = transfer.get("adequacyDecision", transfer.get("adequacy", ""))
            safeguard = transfer.get("safeguard", transfer.get("transferMechanism",
                       transfer.get("legal_mechanism", "")))
            data_types = transfer.get("dataTypes", transfer.get("categories", []))
            has_dpia = transfer.get("dpiaCompleted", transfer.get("dpia", ""))

            label = f"{name}: {source_region} → {dest_region}"

            # The named transfer flow is the config entry at fault. `name` above falls
            # back to the display placeholder "unknown", so the node is taken from the raw
            # export and an unnamed flow contributes no node. The flow name already
            # carries its route, and the safeguard is the setting being remediated, so
            # neither is used as a qualifier — that keeps one flow one node across
            # DPP-RES-001 and DPP-RES-002.
            raw_name = transfer.get("name") or transfer.get("flow") or ""
            transfer_obj = ({"type": "data_transfer", "name": raw_name}
                            if str(raw_name).strip() else None)

            # Check for transfers without adequacy decision or safeguards
            if not adequacy or str(adequacy).lower() in ("false", "0", "no", "none", ""):
                if not safeguard or str(safeguard).lower() in ("none", "", "unknown"):
                    no_safeguard.append(
                        f"{label} — no adequacy decision or transfer safeguard"
                    )
                    if transfer_obj:
                        no_safeguard_objects.append(transfer_obj)
                elif str(safeguard).upper() not in (
                    "SCC", "STANDARD_CONTRACTUAL_CLAUSES", "BCR",
                    "BINDING_CORPORATE_RULES", "CONSENT",
                    "ADEQUACY", "DEROGATION"
                ):
                    no_adequacy.append(
                        f"{label} — safeguard: {safeguard} (verify validity)"
                    )

            # Sensitive data categories in cross-border transfers
            if isinstance(data_types, list):
                sensitive_cats = [d for d in data_types if any(
                    s in str(d).upper() for s in
                    ["HEALTH", "BIOMETRIC", "GENETIC", "RACIAL", "ETHNIC",
                     "POLITICAL", "RELIGIOUS", "UNION", "SEXUAL", "CRIMINAL"]
                )]
                if sensitive_cats:
                    sensitive_transfers.append(
                        f"{label} — special categories: {', '.join(sensitive_cats)}"
                    )
                    if transfer_obj:
                        sensitive_transfer_objects.append(transfer_obj)

        if no_safeguard:
            self.finding(
                check_id="DPP-RES-001",
                title="Cross-border data transfers without legal safeguards",
                severity=self.SEVERITY_CRITICAL,
                category="Data Protection & Privacy",
                description=(
                    f"{len(no_safeguard)} cross-border data transfer(s) have neither an "
                    "adequacy decision nor an appropriate safeguard mechanism. "
                    "Under GDPR Chapter V, transfers to third countries require "
                    "specific legal basis."
                ),
                affected_items=no_safeguard,
                affected_objects=no_safeguard_objects,
                # One finding over every unsafeguarded flow: putting SCCs in place for one
                # flow must shrink this finding, not raise a zero-age replacement.
                scope="aggregate",
                remediation=(
                    "Implement appropriate transfer mechanisms for each cross-border flow: "
                    "Standard Contractual Clauses (SCCs), Binding Corporate Rules (BCRs), "
                    "or rely on an adequacy decision. Complete a Transfer Impact Assessment "
                    "for each destination country."
                ),
                references=[
                    "GDPR Articles 44-49 — Transfer of Personal Data to Third Countries",
                    "DPDP Act 2023 Section 16 — Transfer Outside India",
                ],
            )

        if sensitive_transfers:
            self.finding(
                check_id="DPP-RES-002",
                title="Special category personal data in cross-border transfers",
                severity=self.SEVERITY_HIGH,
                category="Data Protection & Privacy",
                description=(
                    f"{len(sensitive_transfers)} cross-border transfer(s) involve special "
                    "category data (health, biometric, genetic, racial/ethnic, etc.). "
                    "These require additional safeguards under GDPR Art.9."
                ),
                affected_items=sensitive_transfers,
                affected_objects=sensitive_transfer_objects,
                # Aggregate over the special-category transfer set — same reasoning.
                scope="aggregate",
                remediation=(
                    "Conduct a Data Protection Impact Assessment (DPIA) for each "
                    "transfer involving special category data. Ensure explicit consent "
                    "or specific legal basis under Art.9(2). Implement supplementary "
                    "technical measures (encryption, pseudonymization)."
                ),
                references=[
                    "GDPR Article 9 — Special Categories of Personal Data",
                    "GDPR Article 35 — Data Protection Impact Assessment",
                ],
            )

    # ════════════════════════════════════════════════════════════════
    #  DPP-DEL-*: Data Deletion & Blocking Requests
    # ════════════════════════════════════════════════════════════════

    def check_deletion_requests(self):
        """
        Audit data subject deletion/blocking request compliance:
        - Overdue requests
        - Incomplete deletions
        - Requests without documentation
        """
        requests = self.data.get("deletion_requests")
        if not requests:
            return

        overdue = []
        incomplete = []
        undocumented = []
        overdue_objects = []
        incomplete_objects = []
        undocumented_objects = []
        now = datetime.now()
        sla_days = self.get_config("deletion_sla_days", 30)

        for row in requests:
            req_id = row.get("REQUEST_ID", row.get("ID", row.get("TICKET", "")))
            subject = row.get("DATA_SUBJECT", row.get("SUBJECT",
                    row.get("PERSON", "")))
            req_type = row.get("REQUEST_TYPE", row.get("TYPE",
                      row.get("ACTION", "")))
            received = row.get("RECEIVED_DATE", row.get("CREATED",
                      row.get("REQUEST_DATE", "")))
            completed = row.get("COMPLETED_DATE", row.get("CLOSED",
                       row.get("COMPLETION_DATE", "")))
            status = row.get("STATUS", row.get("STATE", ""))
            documentation = row.get("DOCUMENTATION", row.get("NOTES",
                           row.get("JUSTIFICATION", "")))

            label = f"Request {req_id} ({req_type}, subject: {subject})"

            # The request itself is the object; a row with no request id is display-only.
            # The DATA SUBJECT is deliberately NOT named: these are pseudonymised natural
            # persons, not SAP principals, and turning a privacy finding's data subjects
            # into permanent graph nodes would put personal data into the very inventory
            # the check exists to protect. Status/age are not qualifiers either — they are
            # what changes as the request is worked.
            req_obj = ({"type": "dsar_request", "name": req_id}
                       if req_id and str(req_id).strip() else None)

            # Overdue
            if received and str(status).upper() not in (
                "COMPLETED", "CLOSED", "DONE"
            ):
                parsed = self._parse_date_flexible(received)
                if parsed:
                    days_open = (now - parsed).days
                    if days_open > sla_days:
                        overdue.append(
                            f"{label} — open {days_open}d (SLA: {sla_days}d), "
                            f"status: {status or 'open'}"
                        )
                        if req_obj:
                            overdue_objects.append(req_obj)

            # Completed but incomplete
            if str(status).upper() in ("COMPLETED", "CLOSED", "DONE"):
                completion_pct = row.get("COMPLETION_PCT",
                                row.get("PROGRESS", "100"))
                try:
                    if float(str(completion_pct).replace("%", "")) < 100:
                        incomplete.append(
                            f"{label} — status: {status}, completion: {completion_pct}%"
                        )
                        if req_obj:
                            incomplete_objects.append(req_obj)
                except ValueError:
                    pass

            # Missing documentation
            if not documentation or not str(documentation).strip():
                undocumented.append(
                    f"{label} — no documentation/justification recorded"
                )
                if req_obj:
                    undocumented_objects.append(req_obj)

        if overdue:
            self.finding(
                check_id="DPP-DEL-001",
                title=f"Data subject requests overdue (>{sla_days} day SLA)",
                severity=self.SEVERITY_CRITICAL,
                category="Data Protection & Privacy",
                description=(
                    f"{len(overdue)} data subject request(s) have exceeded the "
                    f"{sla_days}-day SLA. GDPR Art.12(3) requires response within "
                    "one month. Overdue requests expose the organization to "
                    "regulatory enforcement."
                ),
                affected_items=overdue,
                affected_objects=overdue_objects,
                # One finding over the overdue backlog: closing one request must shrink
                # this finding, not retire it and raise a fresh one whose age is zero —
                # which is exactly the SLA metric this check feeds.
                scope="aggregate",
                remediation=(
                    "Process all overdue requests immediately. "
                    "Communicate delays to data subjects with justification. "
                    "Implement automated SLA tracking and escalation workflows."
                ),
                references=[
                    "GDPR Article 12(3) — Response Time Limits",
                    "DPDP Act 2023 Section 12 — Right of Grievance Redressal",
                ],
            )

        if incomplete:
            self.finding(
                check_id="DPP-DEL-002",
                title="Data subject requests marked complete but incomplete",
                severity=self.SEVERITY_HIGH,
                category="Data Protection & Privacy",
                description=(
                    f"{len(incomplete)} request(s) are marked as completed but have "
                    "less than 100% completion. Partial deletions leave residual "
                    "personal data in the system."
                ),
                affected_items=incomplete,
                affected_objects=incomplete_objects,
                # Aggregate over the partially-completed request set — same reasoning.
                scope="aggregate",
                remediation=(
                    "Reopen and complete all partially processed requests. "
                    "Verify deletion across all systems (S/4, BTP, archives, backups). "
                    "Use SAP DPP Deletion Report to confirm completeness."
                ),
                references=["GDPR Article 17 — Right to Erasure"],
            )

        if undocumented:
            self.finding(
                check_id="DPP-DEL-003",
                title="Data subject requests without documentation",
                severity=self.SEVERITY_MEDIUM,
                category="Data Protection & Privacy",
                description=(
                    f"{len(undocumented)} request(s) have no documentation or "
                    "justification recorded. Every data subject request must be "
                    "documented for accountability purposes."
                ),
                affected_items=undocumented[:30],
                affected_objects=undocumented_objects,
                # Aggregate over the undocumented request set — documenting one request
                # must not restart the finding's clock.
                scope="aggregate",
                remediation=(
                    "Document all data subject requests with: identity verification, "
                    "scope of request, actions taken, any exemptions applied, "
                    "and completion confirmation. Retain documentation per policy."
                ),
                references=[
                    "GDPR Article 5(2) — Accountability Principle",
                    "DPDP Act 2023 Section 8(8) — Records of Processing",
                ],
                details={"total_count": len(undocumented)},
            )

    # ════════════════════════════════════════════════════════════════
    #  DPP-LAND-*: System Landscape Data Protection
    # ════════════════════════════════════════════════════════════════

    def check_system_landscape_data_protection(self):
        """Check system landscape for data protection configuration gaps."""
        landscape = self.data.get("system_landscape")
        if not landscape:
            return

        no_classification = []
        no_classification_objects = []
        prod_with_open_access = []

        for row in landscape:
            sid = row.get("SID", row.get("SYSTEM", row.get("SYSTEM_ID", "")))
            env_type = row.get("ENVIRONMENT", row.get("TYPE", ""))
            data_class = row.get("DATA_CLASSIFICATION", row.get("CLASSIFICATION",
                        row.get("DATA_CLASS", "")))
            access_policy = row.get("ACCESS_POLICY", row.get("ACCESS_CONTROL", ""))
            contains_prod_data = row.get("CONTAINS_PROD_DATA",
                                row.get("HAS_PROD_DATA", ""))

            label = f"{sid} (env: {env_type})"

            if not data_class or data_class.strip() == "":
                no_classification.append(label)
                # The unclassified SYSTEM is the object. As in DPP-MASK-002 the SID is not
                # stamped as the object's `system` field, because for an aggregate that
                # would pull a member (objs[0]) into the finding's identity.
                if sid and str(sid).strip():
                    no_classification_objects.append({"type": "system", "name": sid})

            if str(env_type).upper() in ("PROD", "PRODUCTION"):
                if access_policy and access_policy.upper() in (
                    "OPEN", "UNRESTRICTED", "ALL"
                ):
                    prod_with_open_access.append(
                        f"{label} — access policy: {access_policy}"
                    )

        if no_classification:
            self.finding(
                check_id="DPP-LAND-001",
                title="Systems without data classification assignment",
                severity=self.SEVERITY_MEDIUM,
                category="Data Protection & Privacy",
                description=(
                    f"{len(no_classification)} system(s) in the landscape have no data "
                    "classification level assigned. Without classification, appropriate "
                    "protection measures cannot be determined."
                ),
                affected_items=no_classification,
                affected_objects=no_classification_objects,
                # One finding over every unclassified system: classifying one system must
                # shrink this finding rather than replace it with a zero-age clone.
                scope="aggregate",
                remediation=(
                    "Assign data classification levels to all systems: "
                    "Public, Internal, Confidential, or Restricted. "
                    "Classification drives access control, encryption, "
                    "and monitoring requirements."
                ),
                references=["ISO 27001 — Information Classification"],
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
