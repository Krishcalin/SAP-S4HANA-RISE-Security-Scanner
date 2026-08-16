"""Which logical sources an ECC 6.0 EHP8 fixture holds, and why.

FIXED BEFORE THE MEASUREMENT RAN. Phase 1 exists to falsify the estimate that
"fourteen of the thirty modules run on an ECC export with no code change". A
fixture assembled after seeing the number, or tuned until the number matched,
would measure nothing at all. So the three tiers below are decided on grounds of
what an ECC estate HAS and what a Basis team can EXPORT — never on which modules
they would light up.
"""

# ── Tier B: cannot exist on ECC. Architectural, not friction. ──────────────
#    These are the deliberate absences the plan asks for.
CANNOT_EXIST_ON_ECC = {
    # HANA — ECC 6.0 EHP8 in the field is overwhelmingly AnyDB (Oracle, Db2,
    # SQL Server, ASE). This fixture is Oracle.
    "hana_db_users", "hana_granted_privileges", "hana_granted_roles",
    "hana_parameters", "hana_audit_policies", "hana_encryption",
    # Fiori — the launchpad is an S/4 and NetWeaver Gateway concern.
    "fiori_catalogs", "fiori_tiles", "fiori_spaces", "fiori_app_usage",
    # BTP and the cloud surface — no subaccount, no CPI, no Cloud Connector.
    "btp_users", "btp_subaccounts", "btp_trust", "btp_destinations",
    "btp_entitlements", "btp_service_bindings", "btp_security_settings",
    "btp_audit_log_records", "btp_network", "btp_role_collection_mappings",
    "cf_roles", "cloud_connector", "cpi_artifacts", "cpi_datastores",
    "event_mesh", "apim_policies", "ias_config", "comm_arrangements",
    "integration_alerts", "integration_topology",
    # CDS and OData v4 — ABAP CDS is 7.4+ tooling that ECC estates rarely carry,
    # and OData v4 services are an S/4 concern.
    "cds_views", "odata_v4_services", "odata_auth",
    # S/4 business roles. ECC uses PFCG roles, which ARE in the fixture; business
    # roles are a distinct S/4 object and would be a fabrication here.
    "business_roles", "business_role_catalogs", "business_role_restrictions",
    # SAP Gateway OData catalogue. Gateway is optional on ECC and this fixture
    # deliberately does not have it — see the ICF connector's own findings on how
    # often the catalogue is simply absent.
    "api_endpoints",
}

# ── Tier C: could exist, but only if the customer bought or configured it. ──
#    Left out of the base fixture and measured separately, because whether these
#    are present is a fact about the CUSTOMER, not about ECC.
OPTIONAL_TOOLING = {
    # SAP GRC Access Control — a separately licensed product.
    "grac_access_requests", "grac_firefighter_log", "grac_firefighter_owners",
    "grac_mitigating_controls", "grac_sod_risks", "grac_sod_violations",
    "ara_ruleset", "sod_ruleset", "sod_matrix", "mitigating_controls",
    "firefighter_log", "access_reviews", "role_expiry", "su24_proposals",
    # ILM / data-protection tooling. Read Access Logging is 7.4+ so an EHP8
    # system CAN run it; most do not.
    "ilm_policies", "dpp_config", "purpose_of_processing", "data_residency",
    "personal_data_inventory", "deletion_requests", "sensitive_fields",
    "data_masking", "ral_config", "ral_log_channels",
    # Operational documents rather than system exports.
    "incident_response", "siem_config", "log_retention", "recovery_tests",
    "backup_catalog",
    # Finance configuration — plausible for an SOX-scoped review, absent from a
    # Basis-led security export. BKPF document headers are the same call: an
    # ECC system certainly HAS them, but they are a finance extract rather
    # than anything a Basis-led security export would contain.
    "posting_periods", "tolerance_groups", "dual_control_fields",
    "doc_change_rules", "fi_number_ranges", "fi_documents",
    # GRC job-execution stamps live on the separately-licensed GRC box, like
    # every other grac_* source above.
    "grac_job_log",
    # Miscellaneous integration surfaces a Basis team would not routinely export.
    "webhooks", "ws_endpoints", "oauth_clients", "key_management",
}
