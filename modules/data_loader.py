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
"""

import csv
import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional


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
        # BTP Cloud Attack Surface data sources
        "cloud_connector":      ["cloud_connector.json", "scc_config.json"],
        "btp_service_bindings": ["btp_service_bindings.json", "service_bindings.json"],
        "btp_destinations":     ["btp_destinations.json", "destinations.json"],
        "ias_config":           ["ias_config.json", "ias_applications.json"],
        "btp_entitlements":     ["btp_entitlements.json", "entitlements.json"],
        "event_mesh":           ["event_mesh.json", "em_config.json"],
        "cpi_artifacts":        ["cpi_artifacts.json", "cpi_security.json"],
        "btp_network":          ["btp_network.json", "private_link.json"],
        "btp_subaccounts":      ["btp_subaccounts.json", "subaccounts.json"],
        # Network & Integration Layer data sources
        "apim_policies":        ["apim_policies.json", "api_proxies.json"],
        "idoc_ports":           ["idoc_ports.csv", "we21.csv"],
        "idoc_partners":        ["idoc_partners.csv", "we20.csv"],
        "ws_endpoints":         ["ws_endpoints.csv", "soamanager.csv"],
        "webhooks":             ["webhooks.json", "callbacks.json"],
        "gw_secinfo":           ["gw_secinfo.csv", "secinfo.csv"],
        "gw_reginfo":           ["gw_reginfo.csv", "reginfo.csv"],
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
    }

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self._data: Dict[str, Any] = {}

    def load_all(self) -> Dict[str, Any]:
        """Load all available data files and return unified data dict."""
        for logical_name, filenames in self.FILE_MAP.items():
            for fname in filenames:
                fpath = self.data_dir / fname
                if fpath.exists():
                    print(f"    Loading {fname}...")
                    if fname.endswith(".csv"):
                        self._data[logical_name] = self._load_csv(fpath)
                    elif fname.endswith(".json"):
                        self._data[logical_name] = self._load_json(fpath)
                    break  # Use first matching file
            else:
                self._data[logical_name] = None

        loaded = [k for k, v in self._data.items() if v is not None]
        missing = [k for k, v in self._data.items() if v is None]
        print(f"    Loaded: {', '.join(loaded) if loaded else 'none'}")
        if missing:
            print(f"    Not found (skipping): {', '.join(missing)}")

        return self._data

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
