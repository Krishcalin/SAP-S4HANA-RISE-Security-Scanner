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

TABLE -> AUTHORIZATION GROUP EXTRACT
------------------------------------
`table_auth_groups` (TDDAT-shaped: one row per table or view that carries an
authorization group) is the one source here that is read as COMPLETE. A table
ABSENT from it is read as "no authorization group assigned", because that is what
absence means in an unfiltered extract — and it is the defect
`modules/ecs_config_items.py` exists to catch, so reading it the other way would
let that defect pass silently on every system.

An extract restricted to a namespace or to an object list therefore over-reports,
and it must be taken without a filter. Where the rows themselves prove a filter was
applied the module declines to judge the objects the extract never mentions and
discloses them as a coverage gap instead; where they cannot prove it, every finding
that rests on absence says so in its own text. Neither the loader nor the module can
turn a filtered extract into a complete one.

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
import io
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
        # TOBJ: the CATALOGUE of authorization objects this release
        # defines. Deliberately separate from `auth_objects` above, which
        # existing consumers read as per-USER grants (UNAME/OBJECT/VALUE).
        # Object definitions are static SAP content rather than a customer
        # setting, which is why the collector does not produce this and it
        # is optional everywhere.
        "auth_object_catalogue":
                             ["auth_object_catalogue.csv",
                              "auth_object_catalog.csv", "tobj.csv"],
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
        "grac_job_log":             ["grac_job_log.csv", "gractaskexecstmp.csv",
                                     "grac_sync_jobs.csv"],
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
        # The installed software components and their releases — the CVERS table,
        # which SPAM/SAINT shows as "Component version". This is what lets a check
        # say "this applies from SAP_BASIS 7.40" instead of firing on a release
        # where the thing it looks for cannot exist. See BaseAuditor.release_gate.
        "system_component":        ["system_component.csv", "cvers.csv",
                                    "component_versions.csv"],
        # Code & Transport Security data sources
        "custom_code_scan":        ["custom_code_scan.csv", "atc_results.csv", "code_inspector.csv"],
        "transport_routes":        ["transport_routes.csv", "tms_routes.csv"],
        "transport_history":       ["transport_history.csv", "stms_log.csv", "import_history.csv"],
        "client_settings":         ["client_settings.csv", "scc4.csv"],
        "change_documents":        ["change_documents.csv", "cdhdr.csv"],
        "change_document_items":   ["change_document_items.csv", "cdpos.csv"],
        # SAP Cloud ALM CSA RESULTS — the verdict half of the Cloud ALM path.
        # Store exports go through cloudalm_import.py and feed our own checks;
        # a results export carries SAP's compliance verdicts instead and is read
        # by cloudalm_verdicts.py as SAP's findings, not ours.
        "csa_findings":            ["csa_findings.csv", "csa_verdicts.csv",
                                    "csa_compliance.csv"],
        # HANA revision. The counterpart of sap_kernel for the database half:
        # SAP's note policies read HDB_VERSION in 30 check items, and without it
        # 18 notes cannot be answered from any other export.
        "hana_version":            ["hana_version.csv", "hdb_version.csv",
                                    "m_database.csv"],
        # Kernel release and patch level. Small file, large consequence: SAP's
        # own note policies use SAP_KERNEL in 602 check items, and without it 62
        # notes cannot be answered at all.
        "sap_kernel":              ["sap_kernel.csv", "kernel_version.csv",
                                    "disp_work.csv"],
        # REGUH — what the payment program actually paid, and into which account.
        # The other half of MDC-BANK-001: a bank change is a register entry, a
        # payment into the changed account is an incident.
        "payment_runs":            ["payment_runs.csv", "reguh.csv"],
        "fi_documents":            ["fi_documents.csv", "bkpf.csv"],
        "vendor_master":           ["vendor_master.csv", "but000.csv", "lfa1.csv"],
        "vendor_bank":             ["vendor_bank.csv", "but0bk.csv", "lfbk.csv"],
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
        # UNIFIED CONNECTIVITY. The ABAP-layer view of remote-callable exposure,
        # and in RISE the ONLY one: secinfo/reginfo are OS files the customer
        # cannot reach. RISE_SECURITY_MODEL section 7.1 ranks this first among the
        # checks to add, and section 3 has carried "Gap in our ingest" against it
        # since it was written.
        # THE INTERNET-FACING INSTANCE'S OWN PROFILE. Separate from
        # security_params because a Web Dispatcher is a separate instance;
        # SAP splits them the same way (2ADISCL reads ABAP_INSTANCE_PAHI,
        # 2ODISCL reads Parameters) and merging them would give one finding
        # for two components with no way to tell which was exposed.
        "webdisp_params":          ["webdisp_params.csv", "webdisp_profile.csv",
                                    "web_dispatcher_params.csv", "sapwebdisp_pfl.csv"],
        "ucon_rfc_state":          ["ucon_rfc_state.csv", "ucon_rfc.csv",
                                    "uconcockpit.csv", "ucon_phase_tool.csv"],
        # The HTTP half, whose config store ABAP_UCON_HTTP_WHITE_LIST comes from
        # SAP's own Apache-2.0 policy XML and which no logical source consumed.
        "ucon_http_allowlist":     ["ucon_http_allowlist.csv", "http_whitelist.csv",
                                    "abap_ucon_http_white_list.csv"],
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
        # Table/view -> authorization group, TDDAT-shaped. The OBJECT side of
        # S_TABU_DIS, read by modules/ecs_config_items.py.
        #
        # THE COLUMN VOCABULARY LIVES IN THAT MODULE AND NOWHERE ELSE. Its docstring
        # lists the accepted headers and `_cell` matches them case-insensitively
        # against whatever `_load_csv` produced. A second list here would be a second
        # vocabulary, and a header only one side knows reads as an EMPTY CELL — which
        # turns a correctly grouped table into "no authorization group assigned" and
        # reports a compliant system as exposing every password hash it holds.
        #
        # THE EXTRACT MUST BE UNFILTERED — see the section in this module's docstring.
        #
        # `tddat.csv` is deliberately NOT an alias, even though TDDAT is the table the
        # extract comes from and the convention everywhere else in this map would ask
        # for it. TDDAT is also a Cloud ALM CSA store name, and `_resolve` withholds a
        # differently-cased match only for stores we TRANSLATE — TDDAT is in
        # cloudalm_import.UNMAPPED_STORES, so the alias would let this pass eat a CSA
        # `TDDAT.csv` raw. That would drop the "recognised, not translated" line which
        # is currently the only thing said about that store, and claim a store whose
        # completeness nobody has established — for a source where an object the
        # extract omits is reported as unprotected. Mapping that store belongs in
        # modules/cloudalm_import.py, which owns the translation and the reason.
        "table_auth_groups":       ["table_auth_groups.csv",
                                    "table_authorization_groups.csv", "se54.csv"],
        # Resilience & recovery evidence (modules/resilience_posture.py). Without
        # these keys the module loads nothing and EIGHT of its nine checks are
        # unreachable — it ships dead, exactly as the two ECS table checks did
        # before `table_auth_groups` above was added. A module whose input has no
        # loader key is not "conservative", it is absent.
        "backup_catalog":          ["backup_catalog.csv", "backups.csv",
                                    "db13.csv", "backup_history.csv"],
        "recovery_tests":          ["recovery_tests.csv", "dr_tests.csv",
                                    "restore_tests.csv"],
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
        #: Files present in the directory that no loader path claimed. Populated
        #: by load_all; a caller that wants to put them in front of a reader
        #: (the coverage manifest does) reads them from here.
        self.unrecognised_files: list = []
        #: filename -> the decode error. A file the customer SUPPLIED and we
        #: could not read, which is a third state: not "absent", not "empty".
        #: Reported as a finding rather than only counted as missing, because
        #: the customer believes they sent it.
        self.unreadable_sources: Dict[str, str] = {}
        #: The logical source names behind those files, so a reader can say
        #: which checks lost their input rather than which file was malformed.
        self.unreadable_logical_names: set = set()
        #: filename -> the encoding that finally decoded it, when it was not the
        #: first choice. cp1252 never raises, so reaching it may mean the text
        #: decoded into mojibake rather than correctly - worth surfacing, and
        #: not the same class of problem as a file that failed outright.
        self.fallback_encodings: Dict[str, str] = {}
        #: Names the CALLER knows about and we should not call unrecognised —
        #: the --config baseline and the --output report both live wherever the
        #: operator put them, which is often beside the exports. The loader
        #: cannot know those names; the composition root can, and passes them.
        self._disregard: set = set()
        #: Lazily built `lowercased filename -> real filename` index.
        self._dir_entries: Optional[Dict[str, str]] = None

    def disregard(self, *names: str) -> "DataLoader":
        """Declare files the caller already accounts for. Chainable."""
        for name in names:
            if name:
                self._disregard.add(Path(name).name.lower())
        return self

    def evidence_manifest(self) -> List[Dict[str, Any]]:
        """SHA-256, size, row count and mtime of every file this loader consumed.

        The requirement this answers, in the SRS documents' own words: "keep
        raw extract hash ... supports audit replay and defensible results." A
        finding challenged months later is re-checkable because the report
        names exactly which bytes produced it — same files, same hashes, same
        findings; a hash that no longer matches means the evidence changed
        after the scan, which is an answer rather than a failure.

        Hashes are computed at call time from the files as they sit in the
        data directory, so call it in the same run that loaded them — which
        is what sap_scanner.py does when it builds scan_meta."""
        import datetime as _dt
        import hashlib as _hashlib
        base = Path(self.data_dir)
        alias_to_logical = {n.lower(): logical
                            for logical, names in self.FILE_MAP.items()
                            for n in names}
        out: List[Dict[str, Any]] = []
        for name in sorted(self._consumed_files, key=str.lower):
            real = (self._entries() or {}).get(name.lower(), name)
            path = base / real
            if not path.is_file():
                continue
            digest = _hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    digest.update(chunk)
            rows = None
            logical = alias_to_logical.get(name.lower())
            if logical is not None and isinstance(self._data.get(logical), list):
                rows = len(self._data[logical])
            st = path.stat()
            out.append({
                "file": real,
                "sha256": digest.hexdigest(),
                "bytes": st.st_size,
                "rows": rows,
                "modified": _dt.datetime.fromtimestamp(st.st_mtime)
                            .strftime("%Y-%m-%d %H:%M:%S"),
            })
        return out

    # ── source directories ──────────────────────────────────────────────────
    #
    # WHY THESE ARE DISCOVERED RATHER THAN NAMED. `abap_source_dir` and
    # `cap_project_dir` are DIRECTORIES, not tabular exports, so they are absent
    # from FILE_MAP and were set only by the CLI flags --abap-src and --cap-src.
    # `server/ingest.py` calls `load_all()` and sets neither, so an uploaded
    # bundle could not reach `abap_sast` or `cap_xsuaa` at all: 136 `ABAP-*` check
    # ids and the CAP set were published in the catalogue and unreachable through
    # the console. Discovering them here fixes both entry points at once, and the
    # CLI still wins because it assigns after `load_all()` returns.
    #
    # NAME-PREFERRED, CONTENT-VERIFIED, WITH A CONTENT FALLBACK. A conventional
    # directory name is what a customer can be told to use, so it is tried first —
    # but it is only accepted if the directory actually holds the file type, since
    # a bundle with an empty `src/` must not turn into "asked to look, could not"
    # and arm the release gate. Where no conventional name matches, the shallowest
    # directory that genuinely holds the sources is used, which is what an unpacked
    # abapGit repository looks like when somebody drops it in whole.
    #
    # THE DATA ROOT IS NEVER THE ANSWER. Pointing a scanner at the bundle root
    # would make it walk every CSV and count them in `unscanned_by_suffix`, turning
    # a coverage figure into noise about files that were never source.

    #: Directory names a customer may reasonably use, in preference order.
    ABAP_SOURCE_DIRS = ("abap_src", "abap_source", "abap", "src")
    CAP_PROJECT_DIRS = ("cap_project", "cap", "mta", "app")

    #: What has to be inside for the name to be believed.
    _ABAP_GLOBS = ("*.abap", "*.abp", "*.asddls", "*.acds")
    _CAP_GLOBS = ("xs-security.json", "*.cds")

    #: How deep to look. An unpacked abapGit export puts sources two levels below
    #: its own root, and a bundle adds one; beyond that a match is more likely to
    #: be an accident than an export.
    _SOURCE_SCAN_DEPTH = 4

    @staticmethod
    def _holds(directory, globs) -> bool:
        for pattern in globs:
            for match in directory.rglob(pattern):
                if match.is_file():
                    return True
        return False

    def _discover_directory(self, names, globs):
        """The directory holding this kind of source, or None."""
        if not self.data_dir.is_dir():
            return None

        # 1. a conventional name, believed only if it holds the files.
        for name in names:
            candidate = self.data_dir / name
            if candidate.is_dir() and self._holds(candidate, globs):
                return candidate

        # 2. otherwise the shallowest directory that genuinely holds them.
        best, best_depth = None, None
        for pattern in globs:
            for match in self.data_dir.rglob(pattern):
                if not match.is_file():
                    continue
                parent = match.parent
                try:
                    depth = len(parent.relative_to(self.data_dir).parts)
                except ValueError:                       # pragma: no cover
                    continue
                # Never the bundle root: a scanner pointed there walks every CSV
                # and counts them as unscanned, which is noise rather than
                # coverage. A loose source file at the top level is not a project.
                if depth == 0 or depth > self._SOURCE_SCAN_DEPTH:
                    continue
                if best_depth is None or depth < best_depth:
                    best, best_depth = parent, depth
        return best

    def _load_source_directories(self) -> None:
        abap = self._discover_directory(self.ABAP_SOURCE_DIRS, self._ABAP_GLOBS)
        if abap is not None:
            self._data["abap_source_dir"] = str(abap)
            print(f"    ABAP source directory: {abap.name}/")
        cap = self._discover_directory(self.CAP_PROJECT_DIRS, self._CAP_GLOBS)
        if cap is not None:
            self._data["cap_project_dir"] = str(cap)
            print(f"    CAP project directory: {cap.name}/")

    def load_all(self) -> Dict[str, Any]:
        """Load all available data files and return unified data dict."""
        for logical_name, filenames in self.FILE_MAP.items():
            for fname in filenames:
                fpath = self._resolve(fname)
                if fpath is not None:
                    print(f"    Loading {fpath.name}...")
                    self._consumed_files.add(fpath.name)
                    if fname.endswith(".csv"):
                        loaded = self._load_csv(fpath)
                        # None (not []) when the file could not be decoded, so
                        # every "was this supplied?" test in the codebase gets
                        # the honest answer without needing to know about
                        # encodings.
                        self._data[logical_name] = loaded
                        if loaded is None:
                            self.unreadable_logical_names.add(logical_name)
                    elif fname.endswith(".json"):
                        self._data[logical_name] = self._load_json(fpath)
                        if self._data[logical_name] is None and \
                                fpath.name in self.unreadable_sources:
                            self.unreadable_logical_names.add(logical_name)
                    break  # Use first matching file
            else:
                self._data[logical_name] = None

        self._load_source_directories()
        self._load_completeness()


        self._load_crq_parameters()
        self._load_cloudalm_stores()

        # Translate any BTP administrative exports into our shapes. Runs
        # unconditionally: every translator recognises its own payload by field
        # name and returns "not mine" for anything else, so a directory holding
        # only hand-made exports comes out of here unchanged.
        self.btp_import_notes = btp_import.apply(self._data)
        for note in self.btp_import_notes:
            print(f"    {note}")

        # A FILE THAT IS PRESENT AND UNRECOGNISED IS NOT A MISSING FILE.
        #
        # The customer exported it, named it something the loader does not know,
        # and will read "not supplied" in the coverage manifest for a source that
        # is sitting in the directory. One typo, or `Users.CSV` from a system that
        # exports differently, and the whole account list silently does not
        # participate — reported accurately as absent, and unactionable, because
        # nothing tells them the file was there.
        #
        # So the loader names them. Every path that claims a file records it in
        # `_consumed_files`, which makes the leftovers derivable rather than
        # guessed at.
        self.unrecognised_files = sorted(
            name for name in self._entries().values()
            if self._looks_like_an_unread_export(name))

        # A FILE WE RECOGNISE AND DID NOT APPLY IS A THIRD THING, and lumping it
        # in with the unknown names made the warning above fire on our own
        # shipped sample directory. `sample_data/baseline.json` is there to be
        # passed to --config; a first run without that flag printed "1 file(s)
        # ... were not recognised", about a file this product wrote, on the very
        # first command in the README. A warning whose first appearance is a
        # false one teaches the reader to scroll past it, which costs more than
        # the misnamed export it exists to catch.
        #
        # So it gets its own line, and that line is more useful than the one it
        # replaced: it names the flag that would have applied the file.
        self.unapplied_files = sorted(
            (name, self._WELL_KNOWN_UNAPPLIED[name.lower()])
            for name in self._entries().values()
            if name.lower() in self._WELL_KNOWN_UNAPPLIED
            and name not in self._consumed_files
            and name.lower() not in self._disregard)

        # Handed to the auditors so the report can name a supplied-but-unreadable
        # export. Set before the summary below so `loaded`/`missing` see it.
        self._data[self.UNREADABLE_KEY] = {
            "files": dict(self.unreadable_sources),
            "sources": sorted(self.unreadable_logical_names),
            "fallback_encodings": dict(self.fallback_encodings),
        } if (self.unreadable_sources or self.fallback_encodings) else None

        loaded = [k for k, v in self._data.items() if v is not None]
        missing = [k for k, v in self._data.items() if v is None]
        print(f"    Loaded: {', '.join(loaded) if loaded else 'none'}")
        if self.unreadable_sources:
            print(f"    [WARN] {len(self.unreadable_sources)} supplied file(s) "
                  f"could not be decoded and are counted as NOT supplied: "
                  + ", ".join(sorted(self.unreadable_sources)))
        if self.fallback_encodings:
            print(f"    [NOTE] {len(self.fallback_encodings)} file(s) decoded "
                  f"only via a fallback encoding; check them for mojibake: "
                  + ", ".join("%s (%s)" % kv
                              for kv in sorted(self.fallback_encodings.items())))
        if missing:
            print(f"    Not found (skipping): {', '.join(missing)}")
        for name, flag in self.unapplied_files:
            print(f"    [NOTE] {name} is present but was not applied. "
                  f"Pass {flag} {name} to use it.")
        if self.unrecognised_files:
            shown = ", ".join(self.unrecognised_files[:10])
            more = (" and %d more" % (len(self.unrecognised_files) - 10)
                    if len(self.unrecognised_files) > 10 else "")
            print(f"    [WARN] {len(self.unrecognised_files)} file(s) in the "
                  f"directory were not recognised and have been ignored: "
                  f"{shown}{more}")
            print(f"           Check the name against docs/EXPORT_SOURCES.md — "
                  f"a misnamed export reads as 'not supplied'.")

        return self._data

    #: Where a customer, or a connector, DECLARES that an export is the whole
    #: thing. Read into the data dict under a key that is deliberately not a
    #: logical source, so it never appears in the coverage manifest as something
    #: the customer forgot to send.
    COMPLETENESS_FILE = "export_completeness.json"
    COMPLETENESS_KEY = "_export_completeness"
    #: Where the supplied-but-unreadable record is handed to the auditors.
    UNREADABLE_KEY = "_unreadable_sources"

    #: The customer's own financial figures, for the FAIR quantification. Same
    #: convention as the completeness declaration above and for the same reason:
    #: a key that is NOT a logical source, so a customer who has never heard of
    #: CRQ is never told they forgot to export something.
    CRQ_PARAMETERS_FILE = "crq_parameters.json"
    CRQ_PARAMETERS_KEY = "_crq_parameters"

    def _load_completeness(self) -> None:
        """Read the declaration that an export is complete.

        WHY THIS FILE EXISTS AT ALL
        For most sources, absence of a row means nothing: the export may simply
        not have included it. `security_params` is the sharpest case — the export
        guide offers RZ11, which returns ONE parameter at a time, as an equal
        route to RSPARAM, so a parameter missing from the file may be unset or may
        just not have been asked for. Those are opposite facts and the file cannot
        tell them apart.

        That ambiguity is why absent parameters are disclosed rather than judged.
        This is the input that resolves it: where somebody states that a source is
        the COMPLETE list, absence within it becomes a real observation — the
        setting is not there — and can be judged.

        IT IS A DECLARATION, NOT A PROOF, AND MUST NEVER BE PRESENTED AS ONE.
        Nothing here verifies that an export really is complete; a customer can
        assert it wrongly and a connector can assert it about a system that
        answered partially. So every finding that rests on this says so in its own
        text and names the declaration, which is what makes a wrong declaration
        diagnosable instead of merely wrong.

        WHY A SEPARATE FILE rather than a column or a marker row: a column repeats
        the same claim on every row and lets rows disagree; a marker row is
        indistinguishable from data to anything that does not know about it. A
        sidecar leaves the exports themselves untouched, which keeps the
        connector's output byte-identical in shape to a hand-made one — the
        property decision D2 rests on.
        """
        path = self._resolve(self.COMPLETENESS_FILE)
        if path is None:
            # ABSENT MEANS UNKNOWN, never "incomplete" and never "complete".
            # Defaulting either way would decide the question the file exists to
            # answer, for every customer who has not heard of it.
            self._data[self.COMPLETENESS_KEY] = None
            return
        payload = self._load_json(path)
        self._consumed_files.add(path.name)
        if not isinstance(payload, dict):
            print(f"    [WARN] {path.name} is not an object; ignoring it. "
                  f"Completeness stays unknown.")
            self._data[self.COMPLETENESS_KEY] = None
            return
        declared = payload.get("complete_sources")
        if not isinstance(declared, list):
            print(f"    [WARN] {path.name} has no 'complete_sources' list; "
                  f"ignoring it. Completeness stays unknown.")
            self._data[self.COMPLETENESS_KEY] = None
            return
        self._data[self.COMPLETENESS_KEY] = payload
        names = ", ".join(str(s) for s in declared) or "none"
        print(f"    Declared complete: {names}  (from {path.name})")


    def _load_crq_parameters(self) -> None:
        """Read the customer's financial figures, if they supplied any.

        WHY A FILE, AND WHY THIS ONE
        The console stores these in PostgreSQL; the offline scanner has no
        database, so the figures arrive the way everything else does in offline
        mode — as a file in the data directory. `export_completeness.json` set
        that precedent and this follows it exactly rather than inventing a second
        convention.

        ABSENT MEANS THE CUSTOMER HAS NOT PRICED THEIR BUSINESS. It does NOT mean
        zero, and it must never be quietly replaced by the catalogue's
        illustrative company — which is precisely what the offline report did
        before this existed: it printed a $1bn manufacturer's losses under the
        customer's name, to the cent, with nothing on the page saying so.
        """
        path = self._resolve(self.CRQ_PARAMETERS_FILE)
        if path is None:
            self._data[self.CRQ_PARAMETERS_KEY] = None
            return
        payload = self._load_json(path)
        self._consumed_files.add(path.name)
        if not isinstance(payload, dict):
            print(f"    [WARN] {path.name} is not an object; ignoring it. "
                  f"Loss figures stay unpriced.")
            self._data[self.CRQ_PARAMETERS_KEY] = None
            return
        answers = payload.get("answers")
        if not isinstance(answers, dict) or not answers:
            print(f"    [WARN] {path.name} has no 'answers' object; ignoring it. "
                  f"Loss figures stay unpriced.")
            self._data[self.CRQ_PARAMETERS_KEY] = None
            return
        self._data[self.CRQ_PARAMETERS_KEY] = payload
        revision = payload.get("revision") or payload.get("as_of") or "unversioned"
        print(f"    CRQ figures supplied: {len(answers)} answer(s), "
              f"revision {revision}  (from {path.name})")

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

    #: Extensions an export arrives in. Anything else in the directory is not a
    #: candidate for "you misnamed this", so listing it would be noise — and a
    #: warning that cries wolf is one the reader learns to scroll past, which is
    #: the failure this warning exists to prevent.
    _EXPORT_SUFFIXES = (".csv", ".json")

    #: Files this product itself writes into, or reads from, an export directory.
    #: A report or a scenario export sitting beside the exports is expected.
    _OUR_OWN = (".crq.json",)

    #: Filenames this product knows, that only take effect behind a flag. Present
    #: without the flag they are neither loaded nor misnamed, so they are neither
    #: "not supplied" nor "not recognised" — they are the third thing, and the
    #: useful sentence names the flag rather than the file.
    _WELL_KNOWN_UNAPPLIED = {"baseline.json": "--config"}

    def _looks_like_an_unread_export(self, name: str) -> bool:
        """Is this a file a customer plausibly meant us to read, and we did not?"""
        if name in self._consumed_files:
            return False
        lowered = name.lower()
        if not lowered.endswith(self._EXPORT_SUFFIXES):
            return False
        if lowered.endswith(self._OUR_OWN):
            return False
        if lowered in self._disregard:
            return False
        if lowered in self._WELL_KNOWN_UNAPPLIED:
            return False           # reported separately, and more usefully
        return True

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

    #: Encodings tried in order when there is no byte-order mark, and what each
    #: one is here for. UTF-8 first because it is what a modern export and every
    #: fixture in this repository uses. cp1252 last because it decodes ANY byte
    #: sequence without raising - it is the fallback of last resort and never a
    #: detection, which is why using it is recorded rather than passed over.
    FALLBACK_ENCODINGS = ("utf-8", "cp1252")

    #: Byte-order marks, longest first: the UTF-8 BOM does not collide with the
    #: UTF-16 ones, but UTF-32's begins with the UTF-16LE mark, so order matters.
    BOMS = ((b"\x00\x00\xfe\xff", "utf-32"), (b"\xff\xfe\x00\x00", "utf-32"),
            (b"\xef\xbb\xbf", "utf-8-sig"),
            (b"\xfe\xff", "utf-16"), (b"\xff\xfe", "utf-16"))

    def _read_text(self, path: Path) -> str:
        """Decode a file the way SAP actually writes them.

        WHY THIS IS NOT JUST `encoding="utf-8-sig"`
        -------------------------------------------
        It was, and two of the most ordinary real-world exports failed on it,
        silently:

          UTF-16LE with a BOM   what SAP GUI writes for a list download or a
                                spreadsheet export on Windows
          latin-1 / cp1252      what a German-language system produces the
                                moment a name carries an umlaut

        Both raised UnicodeDecodeError, which was caught, printed as one WARN
        line among a hundred and thirty sources, and turned into an EMPTY list.
        An empty list is indistinguishable from an export with nothing in it, so
        the scan carried on and reported over a fraction of the estate. That is
        the same "we could not look, rendered as we looked and saw nothing"
        failure this codebase exists to prevent, sitting at the front door.

        A byte-order mark is a fact, so it is honoured first. After that the
        order is a preference, not a detection: cp1252 decodes any byte sequence
        at all and will never raise, so reaching it means the text may be
        mojibake rather than correct. That is recorded in `fallback_encodings`
        and reported, because a silently wrong decode is worse than a loud one.
        """
        raw = path.read_bytes()
        for mark, encoding in self.BOMS:
            if raw.startswith(mark):
                return raw.decode(encoding)
        for encoding in self.FALLBACK_ENCODINGS:
            try:
                text = raw.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                continue
            if encoding != self.FALLBACK_ENCODINGS[0]:
                self.fallback_encodings[path.name] = encoding
            return text
        raise UnicodeDecodeError(
            "unknown", raw, 0, 1,
            "no supported encoding decoded this file (tried a byte-order mark, "
            + ", ".join(self.FALLBACK_ENCODINGS) + ")")

    def _load_csv(self, path: Path) -> List[Dict[str, str]]:
        """Load a CSV file into a list of dicts with normalized headers."""
        rows = []
        try:
            # Try to detect delimiter
            with io.StringIO(self._read_text(path)) as f:
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
                    # Normalize keys: strip whitespace, uppercase.
                    #
                    # A SHORT ROW IS A MISSING CELL, NOT A BROKEN FILE. DictReader
                    # fills an absent trailing field with None, `None.strip()` raised
                    # out of this loop, and the `except` below then returned the rows
                    # read SO FAR — a silently TRUNCATED extract with nothing but a
                    # WARN line on stdout to say so.
                    #
                    # Every source paid for that, but `table_auth_groups` pays worst:
                    # it is the one source read as COMPLETE, so every row lost after
                    # the truncation point reads as "this table has no authorization
                    # group" and a correctly configured system is told at HIGH that
                    # every password hash it holds is readable. One trailing empty
                    # field dropped by a spreadsheet round-trip was enough.
                    #
                    # An absent cell is an empty cell — that is what the file says.
                    # A LONG ROW IS AN UNQUOTED DELIMITER, NOT AN EXTRA COLUMN.
                    #
                    # `if k` below drops csv.DictReader's overflow key — the None
                    # key it uses when a row has MORE fields than headers — and
                    # that is where an unquoted delimiter inside a value lands.
                    # SAP profile values routinely contain commas:
                    #
                    #   icm/HTTP/admin_0,PREFIX=/sap/admin,CLIENTHOST=10.0.0.1
                    #
                    # arrived as VALUE='PREFIX=/sap/admin' with the CLIENTHOST
                    # restriction discarded, and webdisp_security then reported a
                    # correctly restricted admin handler as unrestricted at HIGH.
                    # The module has its own recovery for exactly this and could
                    # never fire, because the loader had already thrown the pieces
                    # away one layer earlier.
                    #
                    # Rejoined with the delimiter that split it, which is lossless
                    # and reverses the exact operation. A file with genuinely more
                    # columns than headers gets them concatenated into its last
                    # field — visible and wrong, rather than invisible and wrong.
                    overflow = row.get(None)
                    normalized = {
                        k.strip().upper().replace(" ", "_"): (v or "").strip()
                        for k, v in row.items() if k
                    }
                    if overflow and normalized:
                        parts = overflow if isinstance(overflow, (list, tuple)) \
                            else [overflow]
                        extra = delimiter.join(str(p) for p in parts if p is not None)
                        if extra:
                            last = list(normalized)[-1]
                            normalized[last] = (
                                f"{normalized[last]}{delimiter}{extra}".strip()
                                if normalized[last] else extra.strip())
                            self._long_rows = getattr(self, "_long_rows", 0) + 1
                    rows.append(normalized)
        except Exception as e:
            print(f"    [WARN] Failed to load {path}: {e}")
            # RECORDED, and the caller turns this into `None` rather than an
            # empty list. An empty list means "supplied, and it held nothing";
            # None means "not supplied". Neither is true here - the customer DID
            # supply it and we could not read it - which is why it is also named
            # in a finding rather than only counted as absent.
            self.unreadable_sources[path.name] = str(e)
            return None
        return rows

    def _load_json(self, path: Path) -> Any:
        """Load a JSON file."""
        try:
            return json.loads(self._read_text(path))
        except Exception as e:
            print(f"    [WARN] Failed to load {path}: {e}")
            self.unreadable_sources[path.name] = str(e)
            return None
