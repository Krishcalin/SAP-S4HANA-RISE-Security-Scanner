# Export source reference

<!-- GENERATED FILE — DO NOT EDIT BY HAND.
     Produced by tools/build_export_reference.py from the code itself.
     Change the loader or the modules, then regenerate:
       python -m tools.build_export_reference -->

Every logical source the scanner can read, what it enables, and whether
[`EXPORT_GUIDE.md`](EXPORT_GUIDE.md) tells you how to produce it.

**128 logical sources.** 66 have a written procedure in the export
guide; **62 do not yet** — those rows name the files the loader will
accept, so a source you already have to hand can be supplied today, but the
step-by-step extraction has not been verified and is deliberately not guessed.

Omitting a source is always safe. The checks behind it do not run, and the
coverage manifest counts it as *not supplied* rather than passing it off as
clean — see chapter 13 of the architecture guide.


| Source | Files the loader accepts | Feeds | Procedure |
|---|---|---|---|
| `access_reviews` | `access_reviews.csv`, `arm_reviews.csv` | `iam_advanced` | documented |
| `api_endpoints` | `api_endpoints.json`, `odata_services.json` | `rise_btp_checks` | documented |
| `apim_policies` | `apim_policies.json`, `api_proxies.json` | `integration_layer` | **not yet written** |
| `applied_notes` | `applied_notes.csv`, `snote_status.csv`, `implemented_notes.csv` | `sap_hotnews` | documented |
| `ara_ruleset` | `ara_ruleset.json`, `sod_ruleset_custom.json` | `access_risk_analysis` | documented |
| `audit_config` | `audit_config.csv`, `sm19.csv` | `log_monitoring`, `log_review`, `network_services` | documented |
| `auth_objects` | `auth_objects.csv` | `code_transport`, `iam_advanced`, `user_auth_audit` | **not yet written** |
| `background_job_steps` | `background_job_steps.csv`, `tbtcp.csv`, `job_steps.csv` | `basis_job_command` | documented |
| `background_jobs` | `background_jobs.csv`, `tbtco.csv`, `sm37_jobs.csv` | `basis_job_command`, `resilience_posture` | documented |
| `backup_catalog` | `backup_catalog.csv`, `backups.csv`, `db13.csv`, `backup_history.csv` | `resilience_posture` | documented |
| `btp_audit_log_records` | `btp_audit_log_records.json`, `auditlogrecords.json`, `audit_log_records.json` | — | documented |
| `btp_destinations` | `btp_destinations.json`, `destinations.json` | `btp_cloud_surface` | **not yet written** |
| `btp_entitlements` | `btp_entitlements.json`, `entitlements.json` | `btp_cloud_surface` | **not yet written** |
| `btp_network` | `btp_network.json`, `private_link.json` | `btp_cloud_surface` | **not yet written** |
| `btp_role_collection_mappings` | `btp_role_collection_mappings.csv`, `role_collection_groups.csv`, `btp_role_collections.json`, `security_role_collection.json` | `cap_xsuaa`, `s4_business_authz` | documented |
| `btp_security_settings` | `btp_security_settings.json`, `security_settings.json` | `btp_cloud_surface` | documented |
| `btp_service_bindings` | `btp_service_bindings.json`, `service_bindings.json` | `btp_cloud_surface` | **not yet written** |
| `btp_subaccounts` | `btp_subaccounts.json`, `subaccounts.json`, `btp_accounts_subaccount.json`, `accounts_subaccount.json` | `btp_cloud_surface` | documented |
| `btp_trust` | `btp_trust.json` | `btp_cloud_surface`, `iam_advanced`, `rise_btp_checks` | documented |
| `btp_users` | `btp_users.json` | `iam_advanced` | documented |
| `business_role_catalogs` | `business_role_catalogs.csv` | `s4_business_authz` | **not yet written** |
| `business_role_restrictions` | `business_role_restrictions.csv` | `s4_business_authz` | **not yet written** |
| `business_roles` | `business_roles.csv`, `business_role_users.csv` | `s4_business_authz` | **not yet written** |
| `cds_views` | `cds_views.csv`, `cds_access_control.csv` | `s4_business_authz` | **not yet written** |
| `certificate_inventory` | `certificate_inventory.csv`, `strust_certs.csv` | `crypto_posture` | **not yet written** |
| `cf_roles` | `cf_roles.csv`, `cf_org_space_roles.csv` | `s4_business_authz` | **not yet written** |
| `change_document_items` | `change_document_items.csv`, `cdpos.csv` | `master_data_changes` | documented |
| `change_documents` | `change_documents.csv`, `cdhdr.csv` | `code_transport`, `master_data_changes` | documented |
| `client_settings` | `client_settings.csv`, `scc4.csv` | `code_transport`, `ecs_config_items`, `log_review` | documented |
| `cloud_connector` | `cloud_connector.json`, `scc_config.json`, `cloud_connector_configuration.json`, `scc_api_configuration.json` | `btp_cloud_surface`, `s4_business_authz` | documented |
| `code_inventory` | `code_inventory.csv`, `custom_objects.csv` | `atc_import`, `code_inventory_report`, `code_transport` | documented |
| `comm_arrangements` | `comm_arrangements.json`, `comm_arr.json` | `iam_advanced`, `rise_btp_checks` | documented |
| `cpi_artifacts` | `cpi_artifacts.json`, `cpi_security.json` | `btp_cloud_surface` | **not yet written** |
| `cpi_datastores` | `cpi_datastores.json`, `cpi_variables.json` | `integration_layer` | **not yet written** |
| `crypto_library` | `crypto_library.csv`, `commoncryptolib.csv` | `crypto_posture` | **not yet written** |
| `custom_code_scan` | `custom_code_scan.csv`, `atc_results.csv`, `code_inspector.csv` | `atc_import`, `code_transport` | **not yet written** |
| `data_masking` | `data_masking.json`, `masking_config.json` | `data_protection` | **not yet written** |
| `data_residency` | `data_residency.json`, `cross_border.json` | `data_protection` | **not yet written** |
| `deletion_requests` | `deletion_requests.csv`, `dsar_requests.csv` | `data_protection` | **not yet written** |
| `dev_access_prod` | `dev_access_prod.csv` | `code_transport` | **not yet written** |
| `doc_change_rules` | `doc_change_rules.csv`, `tbaer.csv`, `ob32.csv` | `financial_controls` | documented |
| `dpp_config` | `dpp_config.json`, `dpp_toolkit.json` | `data_protection` | **not yet written** |
| `dual_control_fields` | `dual_control_fields.csv`, `t055f.csv`, `sensitive_fi_fields.csv` | `financial_controls` | documented |
| `event_mesh` | `event_mesh.json`, `em_config.json` | `btp_cloud_surface` | **not yet written** |
| `ext_os_commands` | `ext_os_commands.csv`, `sxpgcostab.csv`, `sm69_commands.csv` | `basis_job_command` | documented |
| `ext_os_commands_sap` | `ext_os_commands_sap.csv`, `sxpgcotabe.csv` | `basis_job_command` | **not yet written** · not obtainable in RISE |
| `fi_documents` | `fi_documents.csv`, `bkpf.csv` | `financial_controls` | documented |
| `fi_number_ranges` | `fi_number_ranges.csv`, `tnro.csv`, `number_ranges.csv` | `financial_controls` | documented |
| `fiori_app_usage` | `fiori_app_usage.csv`, `app_usage.csv` | `fiori_ui` | **not yet written** |
| `fiori_catalogs` | `fiori_catalogs.csv`, `flpd_catalogs.csv` | `fiori_ui` | **not yet written** |
| `fiori_spaces` | `fiori_spaces.json`, `spaces_pages.json` | `fiori_ui` | **not yet written** |
| `fiori_tiles` | `fiori_tiles.csv`, `flpd_tiles.csv` | `fiori_ui` | **not yet written** |
| `firefighter_log` | `firefighter_log.csv`, `ff_log.csv`, `spm_log.csv` | `iam_advanced` | documented |
| `grac_access_requests` | `grac_access_requests.csv`, `gracreq.csv` | `grc_access_control` | documented |
| `grac_firefighter_log` | `grac_firefighter_log.csv`, `gracfflog.csv` | `grc_access_control` | documented |
| `grac_firefighter_owners` | `grac_firefighter_owners.csv`, `gracffowner.csv` | `grc_access_control` | documented |
| `grac_job_log` | `grac_job_log.csv`, `gractaskexecstmp.csv`, `grac_sync_jobs.csv` | `grc_access_control` | documented |
| `grac_mitigating_controls` | `grac_mitigating_controls.csv`, `gracmitcnt.csv` | `grc_access_control` | documented |
| `grac_sod_risks` | `grac_sod_risks.csv`, `gracsodrisk.csv` | `grc_access_control` | documented |
| `grac_sod_violations` | `grac_sod_violations.csv`, `gracuserprmvl.csv` | `grc_access_control` | documented |
| `gw_reginfo` | `gw_reginfo.csv`, `reginfo.csv` | `integration_layer` | documented · not obtainable in RISE |
| `gw_secinfo` | `gw_secinfo.csv`, `secinfo.csv` | `integration_layer` | documented · not obtainable in RISE |
| `hana_audit_policies` | `hana_audit_policies.csv`, `audit_policies.csv` | `hana_db_security` | documented |
| `hana_db_users` | `hana_db_users.csv`, `sys_users.csv` | `hana_db_security` | documented |
| `hana_encryption` | `hana_encryption.json` | `crypto_posture` | documented |
| `hana_granted_privileges` | `hana_granted_privileges.csv`, `granted_privileges.csv` | `hana_db_security` | documented |
| `hana_granted_roles` | `hana_granted_roles.csv`, `granted_roles.csv` | `hana_db_security` | documented |
| `hana_parameters` | `hana_parameters.csv`, `m_inifile_contents.csv`, `hana_ini.csv` | `crypto_posture`, `hana_db_security`, `resilience_posture` | documented |
| `ias_config` | `ias_config.json`, `ias_applications.json` | `btp_cloud_surface`, `iam_advanced` | **not yet written** |
| `icf_services` | `icf_services.csv`, `sicf.csv`, `icf_nodes.csv` | `network_services` | documented |
| `idoc_partners` | `idoc_partners.csv`, `we20.csv` | `integration_layer` | **not yet written** |
| `idoc_ports` | `idoc_ports.csv`, `we21.csv` | `integration_layer` | **not yet written** |
| `ilm_policies` | `ilm_policies.json`, `ilm_retention.json` | `data_protection` | **not yet written** |
| `incident_response` | `incident_response.json`, `ir_config.json` | `log_monitoring` | **not yet written** |
| `integration_alerts` | `integration_alerts.json`, `alert_config.json` | `integration_layer` | **not yet written** |
| `integration_topology` | `integration_topology.json`, `system_map.json` | `integration_layer` | **not yet written** |
| `key_management` | `key_management.json` | `crypto_posture` | documented |
| `log_retention` | `log_retention.json` | `log_monitoring` | **not yet written** |
| `logon_events` | `logon_events.csv`, `logon_stats.csv` | `log_monitoring`, `log_review` | **not yet written** |
| `mitigating_controls` | `mitigating_controls.csv`, `mitigations.csv`, `grc_mitigations.csv` | `access_risk_analysis` | documented |
| `ms_acl` | `ms_acl.csv`, `ms_acl_info.csv`, `msacl.csv` | `system_trust` | documented · not obtainable in RISE |
| `oauth_clients` | `oauth_clients.json`, `xsuaa_clients.json` | `integration_layer` | **not yet written** |
| `odata_auth` | `odata_auth.csv`, `iwfnd_auth.csv` | `fiori_ui` | documented |
| `odata_v4_services` | `odata_v4_services.csv`, `iwfnd_v4.csv` | `s4_business_authz` | **not yet written** |
| `personal_data_inventory` | `personal_data_inventory.csv`, `pdi.csv` | `data_protection` | **not yet written** |
| `posting_periods` | `posting_periods.csv`, `t001b.csv`, `ob52.csv` | `financial_controls` | documented |
| `profiles` | `profiles.csv`, `usr04.csv` | `basis_job_command`, `log_review`, `user_auth_audit` | documented |
| `pse_inventory` | `pse_inventory.csv`, `strust_pse.csv` | `crypto_posture` | **not yet written** |
| `purpose_of_processing` | `purpose_of_processing.csv`, `pop_config.csv` | `data_protection` | **not yet written** |
| `ral_config` | `ral_config.csv`, `sralmanager.csv` | `data_protection` | **not yet written** |
| `ral_log_channels` | `ral_log_channels.csv` | `data_protection` | **not yet written** |
| `recovery_tests` | `recovery_tests.csv`, `dr_tests.csv`, `restore_tests.csv` | `resilience_posture` | documented |
| `rfc_destinations` | `rfc_destinations.csv`, `sm59.csv`, `rfcdes.csv` | `network_services`, `system_trust` | documented |
| `rfc_trust` | `rfc_trust.csv`, `rfcsysacl.csv`, `trusted_systems.csv` | `system_trust` | **not yet written** |
| `role_auth_values` | `role_auth_values.csv`, `role_authorizations.csv`, `agr1251_values.csv` | `abap_authorizations`, `access_risk_analysis`, `iam_advanced`, `role_governance`, `sap_hotnews` | documented |
| `role_details` | `role_details.csv`, `agr_define.csv` | `iam_advanced`, `role_governance` | documented |
| `role_expiry` | `role_expiry.csv`, `agr_users_validity.csv` | `iam_advanced` | documented |
| `role_profiles` | `role_profiles.csv`, `agr_1016.csv` | `role_governance` | **not yet written** |
| `role_tcodes` | `role_tcodes.csv`, `agr_1251.csv` | `iam_advanced` | documented |
| `sap_modifications` | `sap_modifications.csv`, `se95.csv`, `modifications.csv` | `code_transport` | **not yet written** |
| `sap_security_notes` | `sap_security_notes.json`, `hotnews_catalog.json` | `sap_hotnews` | documented |
| `saprouttab` | `saprouttab.csv`, `route_permission.csv` | `system_trust` | **not yet written** · not obtainable in RISE |
| `security_audit_log` | `security_audit_log.csv`, `sm19_filters.csv` | `log_monitoring`, `log_review` | documented |
| `security_params` | `security_params.csv`, `rsparam.csv`, `profile_params.csv` | `abap_authorizations`, `baseline_params`, `crypto_posture`, `data_protection`, `log_monitoring`, `security_params`, `snc_posture`, `system_trust` | documented |
| `sensitive_fields` | `sensitive_fields.csv`, `pii_fields.csv` | `data_protection` | **not yet written** |
| `siem_config` | `siem_config.json` | `log_monitoring` | **not yet written** |
| `snc_config` | `snc_config.csv` | `crypto_posture` | **not yet written** |
| `sod_matrix` | `sod_matrix.csv` | `iam_advanced` | documented |
| `sod_ruleset` | `sod_ruleset.json` | `iam_advanced` | documented |
| `standard_users` | `standard_users.csv`, `rsusr003.csv`, `default_users.csv` | `log_review`, `system_trust` | documented |
| `su24_proposals` | `su24_proposals.csv`, `usobt_c.csv`, `su24.csv` | `role_governance` | **not yet written** |
| `system_change` | `system_change.csv`, `se06.csv`, `system_change_option.csv` | `code_transport` | **not yet written** |
| `system_component` | `system_component.csv`, `cvers.csv`, `component_versions.csv` | `sap_hotnews` | documented |
| `system_landscape` | `system_landscape.csv`, `landscape.csv` | `data_protection` | **not yet written** |
| `table_auth_groups` | `table_auth_groups.csv`, `table_authorization_groups.csv`, `se54.csv` | — | documented |
| `table_logging` | `table_logging.csv`, `dd09l.csv` | `log_monitoring` | documented |
| `tls_config` | `tls_config.csv`, `icm_ssl.csv` | `crypto_posture` | **not yet written** |
| `tolerance_groups` | `tolerance_groups.csv`, `t043t.csv`, `oba4.csv` | `financial_controls` | documented |
| `transport_history` | `transport_history.csv`, `stms_log.csv`, `import_history.csv` | `code_transport` | **not yet written** |
| `transport_routes` | `transport_routes.csv`, `tms_routes.csv` | `code_transport` | **not yet written** |
| `transports` | `transports.csv`, `se09.csv` | `network_services` | **not yet written** |
| `user_groups` | `user_groups.csv` | `iam_advanced` | **not yet written** |
| `user_roles` | `user_roles.csv`, `agr_users.csv` | `abap_authorizations`, `access_risk_analysis`, `iam_advanced`, `role_governance`, `user_auth_audit` | documented |
| `users` | `users.csv` | `basis_job_command`, `iam_advanced`, `user_auth_audit` | documented |
| `vendor_bank` | `vendor_bank.csv`, `but0bk.csv`, `lfbk.csv` | `vendor_master` | **not yet written** |
| `vendor_master` | `vendor_master.csv`, `but000.csv`, `lfa1.csv` | `vendor_master` | **not yet written** |
| `webhooks` | `webhooks.json`, `callbacks.json` | `integration_layer` | **not yet written** |
| `ws_endpoints` | `ws_endpoints.csv`, `soamanager.csv` | `integration_layer` | **not yet written** |

## What “not yet written” means

The scanner will read the file if you supply it under one of the names above. What is missing is a verified procedure for producing it — which transaction, which selection, which columns. Those are not guessed here: a wrong transaction code in an export guide costs a customer an afternoon and costs the product its credibility.
