"""
Data Loader Module
==================
Reads exported SAP configuration data from CSV and JSON files.

Expected file naming convention in the data directory:
  - users.csv          → USR02/USR04 user master export
  - user_roles.csv     → AGR_USERS role assignments
  - profiles.csv       → USR04 profile assignments
  - auth_objects.csv   → Authorization object details
  - security_params.csv → RSPARAM / profile parameter export (RZ10/RZ11)
  - rfc_destinations.csv → SM59 RFC destination export
  - icf_services.csv   → SICF service tree export
  - transports.csv     → SE09/STMS transport list
  - audit_config.csv   → SM19 audit log configuration
  - btp_trust.json     → BTP trust configuration export
  - comm_arrangements.json → Communication arrangement export
  - api_endpoints.json → Exposed API/OData service catalog

All files are optional — the scanner will only run checks
for which data is available.

SAP CLOUD ALM CSA EXPORTS
-------------------------
A directory may instead (or additionally) contain SAP Cloud ALM Configuration &
Security Analysis store exports, named after the store: `ABAP_INSTANCE_PAHI.csv`,
`STANDARD_USERS.csv`, `SICF_SERVICES.csv` and so on. Those are translated into the
same logical sources by `modules/cloudalm_import.py` after the filename pass, and
they fill only sources a named file did not already supply — a file named in
FILE_MAP always wins, so nothing about the existing convention changes.

See `docs/EXPORT_GUIDE.md` for how a customer obtains the export, including the
caveat about whether Cloud ALM's API returns raw store values at all.

BTP ADMINISTRATIVE EXPORTS
--------------------------
Several BTP logical sources accept EITHER a hand-made file in our own shape or the
raw output of SAP's own BTP tooling — the `btp` CLI, the customer-hosted Cloud
Connector configuration API, and auditlog-management records. Those raw shapes are
translated after loading by `modules/btp_import.py`, which recognises each by its
own field names and leaves anything it does not recognise untouched, so a
hand-made export keeps behaving exactly as before. Again see `docs/EXPORT_GUIDE.md`
for the exact commands.
"""

import csv
import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional

from modules import btp_import
from modules import cloudalm_import


class DataLoader:
    """Load and normalize exported SAP configuration data."""

    # Mapping of logical names to expected filenames
    FILE_MAP = {
        "users":             ["users.csv"],
        "user_roles":        ["user_roles.csv", "agr_users.csv"],
        "profiles":          ["profiles.csv", "usr04.csv"],
        "auth_objects":      ["auth_objects.csv"],
        "security_params":   ["security_params.csv", "rsparam.csv", "profile_params.csv"],
        "rfc_destinations":  ["rfc_destinations.csv", "sm59.csv", "rfcdes.csv"],
        "icf_services":      ["icf_services.csv", "sicf.csv", "icf_nodes.csv"],
        "transports":        ["transports.csv", "se09.csv"],
        "audit_config":      ["audit_config.csv", "sm19.csv"],
        "btp_trust":         ["btp_trust.json"],
        "comm_arrangements": ["comm_arrangements.json", "comm_arr.json"],
        "api_endpoints":     ["api_endpoints.json", "odata_services.json"],
        # Advanced IAM data sources
        "sod_matrix":        ["sod_matrix.csv"],
        "sod_ruleset":       ["sod_ruleset.json"],
        "role_tcodes":       ["role_tcodes.csv", "agr_1251.csv"],
        "firefighter_log":   ["firefighter_log.csv", "ff_log.csv", "spm_log.csv"],
        "role_expiry":       ["role_expiry.csv", "agr_users_validity.csv"],
        "btp_users":         ["btp_users.json"],
        "role_details":      ["role_details.csv", "agr_define.csv"],
        "access_reviews":    ["access_reviews.csv", "arm_reviews.csv"],
        "user_groups":       ["user_groups.csv"],
        # GRC Access Control (native GRAC* exports from the GRC AC ABAP system)
        "grac_firefighter_log":     ["grac_firefighter_log.csv", "gracfflog.csv"],
        "grac_firefighter_owners":  ["grac_firefighter_owners.csv", "gracffowner.csv"],
        "grac_access_requests":     ["grac_access_requests.csv", "gracreq.csv"],
        "grac_sod_violations":      ["grac_sod_violations.csv", "gracuserprmvl.csv"],
        "grac_mitigating_controls": ["grac_mitigating_controls.csv", "gracmitcnt.csv"],
        "grac_sod_risks":           ["grac_sod_risks.csv", "gracsodrisk.csv"],
        # Role Design & Governance (PFCG build-quality)
        "su24_proposals":           ["su24_proposals.csv", "usobt_c.csv", "su24.csv"],
        "role_profiles":            ["role_profiles.csv", "agr_1016.csv"],
        # Financial Controls (SOX FI/CO application configuration)
        "posting_periods":          ["posting_periods.csv", "t001b.csv", "ob52.csv"],
        "tolerance_groups":         ["tolerance_groups.csv", "t043t.csv", "oba4.csv"],
        "dual_control_fields":      ["dual_control_fields.csv", "t055f.csv", "sensitive_fi_fields.csv"],
        "doc_change_rules":         ["doc_change_rules.csv", "tbaer.csv", "ob32.csv"],
        "fi_number_ranges":         ["fi_number_ranges.csv", "tnro.csv", "number_ranges.csv"],
        # BTP Cloud Attack Surface data sources
        #
        # The trailing filenames on cloud_connector / btp_subaccounts are the raw
        # output of SAP's own BTP tooling rather than our shape; modules/btp_import.py
        # translates them after loading. A file in our own shape is listed FIRST and
        # therefore always wins.
        "cloud_connector":      ["cloud_connector.json", "scc_config.json",
                                 "cloud_connector_configuration.json",
                                 "scc_api_configuration.json"],
        "btp_service_bindings": ["btp_service_bindings.json", "service_bindings.json"],
        "btp_destinations":     ["btp_destinations.json", "destinations.json"],
        "ias_config":           ["ias_config.json", "ias_applications.json"],
        "btp_entitlements":     ["btp_entitlements.json", "entitlements.json"],
        "event_mesh":           ["event_mesh.json", "em_config.json"],
        "cpi_artifacts":        ["cpi_artifacts.json", "cpi_security.json"],
        "btp_network":          ["btp_network.json", "private_link.json"],
        "btp_subaccounts":      ["btp_subaccounts.json", "subaccounts.json",
                                 "btp_accounts_subaccount.json",
                                 "accounts_subaccount.json"],
        # `btp --format json list security/settings` — subaccount security settings.
        # Folded onto the subaccount they describe by modules/btp_import.py.
        "btp_security_settings": ["btp_security_settings.json", "security_settings.json"],
        # auditlog-management records from /auditlog/v2/auditlogrecords. Summarised
        # into per-tenant evidence; the records themselves never reach a report.
        "btp_audit_log_records": ["btp_audit_log_records.json", "auditlogrecords.json",
                                  "audit_log_records.json"],
        # Network & Integration Layer data sources
        "apim_policies":        ["apim_policies.json", "api_proxies.json"],
        "idoc_ports":           ["idoc_ports.csv", "we21.csv"],
        "idoc_partners":        ["idoc_partners.csv", "we20.csv"],
        "ws_endpoints":         ["ws_endpoints.csv", "soamanager.csv"],
        "webhooks":             ["webhooks.json", "callbacks.json"],
        "gw_secinfo":           ["gw_secinfo.csv", "secinfo.csv"],
        "gw_reginfo":           ["gw_reginfo.csv", "reginfo.csv"],
        "ms_acl":               ["ms_acl.csv", "ms_acl_info.csv", "msacl.csv"],
        "system_change":        ["system_change.csv", "se06.csv", "system_change_option.csv"],
        "integration_alerts":   ["integration_alerts.json", "alert_config.json"],
        "cpi_datastores":       ["cpi_datastores.json", "cpi_variables.json"],
        "oauth_clients":        ["oauth_clients.json", "xsuaa_clients.json"],
        "integration_topology": ["integration_topology.json", "system_map.json"],
        # Data Protection & Privacy data sources
        "ral_config":              ["ral_config.csv", "sralmanager.csv"],
        "ral_log_channels":        ["ral_log_channels.csv"],
        "ilm_policies":            ["ilm_policies.json", "ilm_retention.json"],
        "data_masking":            ["data_masking.json", "masking_config.json"],
        "dpp_config":              ["dpp_config.json", "dpp_toolkit.json"],
        "purpose_of_processing":   ["purpose_of_processing.csv", "pop_config.csv"],
        "sensitive_fields":        ["sensitive_fields.csv", "pii_fields.csv"],
        "data_residency":          ["data_residency.json", "cross_border.json"],
        "personal_data_inventory": ["personal_data_inventory.csv", "pdi.csv"],
        "deletion_requests":       ["deletion_requests.csv", "dsar_requests.csv"],
        "system_landscape":        ["system_landscape.csv", "landscape.csv"],
        # Code & Transport Security data sources
        "custom_code_scan":        ["custom_code_scan.csv", "atc_results.csv", "code_inspector.csv"],
        "transport_routes":        ["transport_routes.csv", "tms_routes.csv"],
        "transport_history":       ["transport_history.csv", "stms_log.csv", "import_history.csv"],
        "client_settings":         ["client_settings.csv", "scc4.csv"],
        "change_documents":        ["change_documents.csv", "cdhdr.csv"],
        "code_inventory":          ["code_inventory.csv", "custom_objects.csv"],
        "sap_modifications":       ["sap_modifications.csv", "se95.csv", "modifications.csv"],
        "dev_access_prod":         ["dev_access_prod.csv"],
        # Logging, Monitoring & IR data sources
        "security_audit_log":      ["security_audit_log.csv", "sm19_filters.csv"],
        "siem_config":             ["siem_config.json"],
        "log_retention":           ["log_retention.json"],
        "incident_response":       ["incident_response.json", "ir_config.json"],
        "table_logging":           ["table_logging.csv", "dd09l.csv"],
        "logon_events":            ["logon_events.csv", "logon_stats.csv"],
        # Fiori & UI Layer data sources
        "fiori_catalogs":          ["fiori_catalogs.csv", "flpd_catalogs.csv"],
        "fiori_tiles":             ["fiori_tiles.csv", "flpd_tiles.csv"],
        "odata_auth":              ["odata_auth.csv", "iwfnd_auth.csv"],
        "fiori_spaces":            ["fiori_spaces.json", "spaces_pages.json"],
        "fiori_app_usage":         ["fiori_app_usage.csv", "app_usage.csv"],
        # Cryptographic Posture data sources
        "tls_config":              ["tls_config.csv", "icm_ssl.csv"],
        "certificate_inventory":   ["certificate_inventory.csv", "strust_certs.csv"],
        "snc_config":              ["snc_config.csv"],
        "hana_encryption":         ["hana_encryption.json"],
        "crypto_library":          ["crypto_library.csv", "commoncryptolib.csv"],
        "pse_inventory":           ["pse_inventory.csv", "strust_pse.csv"],
        "key_management":          ["key_management.json"],
        # HANA Database Security data sources
        "hana_db_users":           ["hana_db_users.csv", "sys_users.csv"],
        "hana_granted_privileges": ["hana_granted_privileges.csv", "granted_privileges.csv"],
        "hana_granted_roles":      ["hana_granted_roles.csv", "granted_roles.csv"],
        "hana_parameters":         ["hana_parameters.csv", "m_inifile_contents.csv", "hana_ini.csv"],
        "hana_audit_policies":     ["hana_audit_policies.csv", "audit_policies.csv"],
        # SAP Security Notes / HotNews data sources
        "applied_notes":           ["applied_notes.csv", "snote_status.csv", "implemented_notes.csv"],
        "sap_security_notes":      ["sap_security_notes.json", "hotnews_catalog.json"],
        # ABAP Authorization & Critical Access data sources
        "role_auth_values":        ["role_auth_values.csv", "role_authorizations.csv", "agr1251_values.csv"],
        # System Trust & Standard Users data sources
        "rfc_trust":               ["rfc_trust.csv", "rfcsysacl.csv", "trusted_systems.csv"],
        "standard_users":          ["standard_users.csv", "rsusr003.csv", "default_users.csv"],
        "saprouttab":              ["saprouttab.csv", "route_permission.csv"],
        # (Security Baseline Parameters reuses security_params.csv)
        # S/4HANA & Cloud Authorization data sources
        "business_roles":              ["business_roles.csv", "business_role_users.csv"],
        "business_role_restrictions":  ["business_role_restrictions.csv"],
        "business_role_catalogs":      ["business_role_catalogs.csv"],
        "cds_views":                   ["cds_views.csv", "cds_access_control.csv"],
        "odata_v4_services":           ["odata_v4_services.csv", "iwfnd_v4.csv"],
        "cf_roles":                    ["cf_roles.csv", "cf_org_space_roles.csv"],
        # The .json alias is `btp --format json list security/role-collection`,
        # translated to these rows by modules/btp_import.py.
        "btp_role_collection_mappings": ["btp_role_collection_mappings.csv",
                                         "role_collection_groups.csv",
                                         "btp_role_collections.json",
                                         "security_role_collection.json"],
        # Access Risk Analysis (SoD) data sources
        # (reuses role_auth_values.csv [AGR_1251] + user_roles.csv [AGR_USERS])
        "mitigating_controls":         ["mitigating_controls.csv", "mitigations.csv", "grc_mitigations.csv"],
        "ara_ruleset":                 ["ara_ruleset.json", "sod_ruleset_custom.json"],
        # Basis Jobs & External OS Commands data sources
        # (reuses users.csv [USR02] + profiles.csv [USR04] to resolve privileged step users)
        "ext_os_commands":             ["ext_os_commands.csv", "sxpgcostab.csv", "sm69_commands.csv"],
        "ext_os_commands_sap":         ["ext_os_commands_sap.csv", "sxpgcotabe.csv"],
        "background_jobs":             ["background_jobs.csv", "tbtco.csv", "sm37_jobs.csv"],
        "background_job_steps":        ["background_job_steps.csv", "tbtcp.csv", "job_steps.csv"],
    }

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self._data: Dict[str, Any] = {}
        #: One entry per Cloud ALM CSA store file found — including the ones we
        #: recognise and deliberately refuse to translate. Empty for a directory
        #: that holds no store exports, which is every native export directory.
        self.cloudalm_report: List[Dict[str, Any]] = []
        #: What modules/btp_import.py translated, one note per source. Empty for a
        #: directory holding no BTP administrative exports.
        self.btp_import_notes: List[str] = []
        #: Real filenames the FILE_MAP pass claimed. Only these are withheld from
        #: the Cloud ALM pass, so a store file is neither double-counted nor
        #: silently withheld.
        self._consumed_files: set = set()
        #: Lazily built `lowercased filename -> real filename` index.
        self._dir_entries: Optional[Dict[str, str]] = None

    def load_all(self) -> Dict[str, Any]:
        """Load all available data files and return unified data dict."""
        for logical_name, filenames in self.FILE_MAP.items():
            for fname in filenames:
                fpath = self._resolve(fname)
                if fpath is not None:
                    print(f"    Loading {fpath.name}...")
                    self._consumed_files.add(fpath.name)
                    if fname.endswith(".csv"):
                        self._data[logical_name] = self._load_csv(fpath)
                    elif fname.endswith(".json"):
                        self._data[logical_name] = self._load_json(fpath)
                    break  # Use first matching file
            else:
                self._data[logical_name] = None

        self._load_cloudalm_stores()

        # Translate any BTP administrative exports into our shapes. Runs
        # unconditionally: every translator recognises its own payload by field
        # name and returns "not mine" for anything else, so a directory holding
        # only hand-made exports comes out of here unchanged.
        self.btp_import_notes = btp_import.apply(self._data)
        for note in self.btp_import_notes:
            print(f"    {note}")

        loaded = [k for k, v in self._data.items() if v is not None]
        missing = [k for k, v in self._data.items() if v is None]
        print(f"    Loaded: {', '.join(loaded) if loaded else 'none'}")
        if missing:
            print(f"    Not found (skipping): {', '.join(missing)}")

        return self._data

    # ------------------------------------------------------------------ #
    #  SAP Cloud ALM CSA store exports                                    #
    # ------------------------------------------------------------------ #
    def _entries(self) -> Dict[str, str]:
        """`lowercased filename -> real filename` for the data directory."""
        if self._dir_entries is None:
            entries: Dict[str, str] = {}
            try:
                for entry in sorted(self.data_dir.iterdir()):
                    if entry.is_file():
                        entries.setdefault(entry.name.lower(), entry.name)
            except OSError:
                pass
            self._dir_entries = entries
        return self._dir_entries

    def _resolve(self, fname: str) -> Optional[Path]:
        """Find `fname` on disk, or None. Case-insensitive, with one exception.

        Three Cloud ALM store names collide with our own filenames —
        `STANDARD_USERS`, `GW_SECINFO`, `GW_REGINFO`. On Windows the filesystem is
        case-insensitive, so `STANDARD_USERS.csv` satisfied a bare
        `(data_dir / "standard_users.csv").exists()` and the FILE_MAP pass ate the
        store export raw, untranslated; on Linux the same directory went to the
        importer. One directory, two products, decided by the host OS.

        So an exact filename match always wins — a customer who literally named the
        file `standard_users.csv` gets the native path — and a differently-cased
        match is refused when the real name is a translatable store, leaving it to
        the Cloud ALM pass.
        """
        real = self._entries().get(fname.lower())
        if real is None:
            return None
        if real != fname and cloudalm_import.store_for_filename(real) in \
                cloudalm_import.STORE_TARGETS:
            return None
        return self.data_dir / real

    def _load_cloudalm_stores(self) -> None:
        """Fill logical sources from Cloud ALM CSA store exports.

        Runs AFTER the filename pass and fills only what is still missing: a file
        named in FILE_MAP always wins. A CSA export is an additional way to supply
        a source, never a redefinition of the existing one.
        """
        translated, report = cloudalm_import.load_cloudalm(
            self.data_dir,
            csv_reader=self._load_csv,
            json_reader=self._load_json,
            skip_files=self._consumed_files,
        )
        self.cloudalm_report = report
        if not report:
            return

        print("    SAP Cloud ALM CSA store export detected:")
        for line in cloudalm_import.summarise(report):
            print(f"      {line}")

        for logical_name, rows in sorted(translated.items()):
            if not rows:
                continue
            if self._data.get(logical_name) is not None:
                # The customer supplied both. The named file is the more specific
                # statement of intent, and silently preferring the store export
                # would change what a check sees without saying so.
                print(f"      [note] {logical_name} already loaded from a named "
                      f"file — Cloud ALM rows not used")
                continue
            self._data[logical_name] = rows
            print(f"      {logical_name}: {len(rows)} row(s) from Cloud ALM")

        for entry in report:
            if entry.get("undecoded_client_codes"):
                print("      [warn] CLIENTS change options arrived as raw codes we "
                      "do not decode; client-change checks will not fire on them: "
                      + "; ".join(entry["undecoded_client_codes"]))
            if entry.get("unrecognised_values"):
                print(f"      [warn] {entry.get('store')}: values passed through "
                      f"untranslated: "
                      + ", ".join(sorted(set(entry["unrecognised_values"]))[:8]))

    def _load_csv(self, path: Path) -> List[Dict[str, str]]:
        """Load a CSV file into a list of dicts with normalized headers."""
        rows = []
        try:
            # Try to detect delimiter
            with open(path, "r", encoding="utf-8-sig") as f:
                sample = f.read(4096)
                f.seek(0)

                # Detect delimiter
                if "\t" in sample and sample.count("\t") > sample.count(","):
                    delimiter = "\t"
                elif ";" in sample and sample.count(";") > sample.count(","):
                    delimiter = ";"
                elif "|" in sample and sample.count("|") > sample.count(","):
                    delimiter = "|"
                else:
                    delimiter = ","

                reader = csv.DictReader(f, delimiter=delimiter)
                for row in reader:
                    # Normalize keys: strip whitespace, uppercase
                    normalized = {
                        k.strip().upper().replace(" ", "_"): v.strip()
                        for k, v in row.items() if k
                    }
                    rows.append(normalized)
        except Exception as e:
            print(f"    [WARN] Failed to load {path}: {e}")
        return rows

    def _load_json(self, path: Path) -> Any:
        """Load a JSON file."""
        try:
            with open(path, "r", encoding="utf-8-sig") as f:
                return json.load(f)
        except Exception as e:
            print(f"    [WARN] Failed to load {path}: {e}")
            return None
