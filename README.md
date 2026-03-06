<p align="center">
  <img src="docs/banner.svg" alt="SAP S/4HANA RISE Security Scanner" width="800"/>
</p>

<p align="center">
  <strong>An offline security audit tool for SAP S/4HANA RISE and BTP environments</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.8+"/>
  <img src="https://img.shields.io/badge/dependencies-zero-brightgreen?style=flat-square" alt="Zero Dependencies"/>
  <img src="https://img.shields.io/badge/license-MIT-orange?style=flat-square" alt="MIT License"/>
  <img src="https://img.shields.io/badge/SAP-S%2F4HANA%20RISE-0FAAFF?style=flat-square&logo=sap&logoColor=white" alt="SAP S/4HANA"/>
  <img src="https://img.shields.io/badge/checks-141%2B-red?style=flat-square" alt="123+ Checks"/>
</p>

---

## Overview

**SAP S/4HANA RISE Security Scanner** analyzes exported SAP configuration data (CSV/JSON) and produces an interactive HTML dashboard with findings, severity ratings, and actionable remediation guidance.

- **No direct system connection required** — ideal for RISE environments with restricted RFC access
- **Zero external dependencies** — runs on Python 3.8+ stdlib only
- **141+ security checks across 8 audit modules
- **CIS SAP Benchmark aligned** — checks mapped to industry-standard baselines

---

## Audit Modules

| Module | Checks | Focus |
|--------|--------|-------|
| 🔐 **User & Authorization** | USR-001→008 | Default users, SAP_ALL, dormant accounts, service accounts |
| 🛡️ **Advanced IAM** | IAM-SOD/FF/EXP/XID/REV/ROLE/PRIV (28) | SoD conflicts, firefighter access, role lifecycle, cross-system identity |
| ⚙️ **Security Parameters** | PARAM-* (25+) | Password policy, login security, RFC, gateway, TLS, audit logging |
| 🌐 **Network & Services** | NET-001→008 | RFC destinations, ICF services, transports, audit config |
| ☁️ **RISE / BTP Core** | RISE-001→007 | Trust config, comm arrangements, API exposure |
| 🔥 **BTP Cloud Attack Surface** | BTP-CC/SB/DST/IAS/ENT/EM/CPI/NET/GOV/MIG (29) | Cloud Connector, service bindings, destinations, IAS, Event Mesh, CPI, network isolation |
| 🔗 **Network & Integration Layer** | INTG-APIM/IDOC/WS/WH/GW/MON/CPI/OAUTH/TOPO (27) | API Management, IDOC ports, web services, webhooks, gateway ACLs, OAuth, topology |
| 🔏 **Data Protection & Privacy** | DPP-RAL/ILM/MASK/TOOLKIT/POP/FIELD/RES/DEL/LAND (18) | Read Access Logging, ILM retention, data masking, GDPR/DPDP toolkit, data residency |

<details>
<summary><strong>🛡️ Advanced IAM — Full Check List</strong></summary>

### Segregation of Duties (IAM-SOD-*)
| Check | Description | Severity |
|-------|-------------|----------|
| IAM-SOD-FIN-001 | SoD: Vendor Master ↔ Payment Processing | CRITICAL |
| IAM-SOD-FIN-002 | SoD: Purchase Order ↔ Goods Receipt | HIGH |
| IAM-SOD-FIN-003 | SoD: Journal Entry ↔ GL Account Master | HIGH |
| IAM-SOD-FIN-004 | SoD: Customer Master ↔ Sales Order / Billing | HIGH |
| IAM-SOD-HR-001 | SoD: HR Master Data ↔ Payroll Execution | CRITICAL |
| IAM-SOD-SEC-001 | SoD: User Administration ↔ Role Administration | CRITICAL |
| IAM-SOD-BASIS-001 | SoD: Transport Management ↔ Development | HIGH |

SoD checks support three data strategies: pre-computed matrix (`sod_matrix.csv`), role resolution (`user_roles.csv` + `role_tcodes.csv`), or heuristic role-name matching.

### Firefighter / Emergency Access (IAM-FF-*)
| Check | Description | Severity |
|-------|-------------|----------|
| IAM-FF-001 | Sessions exceeding max duration (default: 4h) | HIGH |
| IAM-FF-002 | Sessions without documented justification | HIGH |
| IAM-FF-003 | Sessions not reviewed by controller | CRITICAL |
| IAM-FF-004 | Sessions self-approved (reviewer = requestor) | CRITICAL |
| IAM-FF-005 | Users with excessive firefighter usage frequency | MEDIUM |

### Role Expiry & Validity (IAM-EXP-*)
| Check | Description | Severity |
|-------|-------------|----------|
| IAM-EXP-001 | Role assignments without expiry dates (indefinite) | MEDIUM |
| IAM-EXP-002 | Expired role assignments still present in user master | LOW |
| IAM-EXP-003 | Role assignments with excessive validity periods | MEDIUM |

### Cross-System Identity (IAM-XID-*)
| Check | Description | Severity |
|-------|-------------|----------|
| IAM-XID-001 | BTP users without corresponding S/4HANA account | MEDIUM |
| IAM-XID-002 | S/4HANA locked users still active in BTP (incomplete offboarding) | HIGH |
| IAM-XID-003 | BTP users with administrative role collections | HIGH |

### Access Review Compliance (IAM-REV-*)
| Check | Description | Severity |
|-------|-------------|----------|
| IAM-REV-001 | Overdue access review campaigns | HIGH |
| IAM-REV-002 | Reviews marked complete but with incomplete coverage | MEDIUM |
| IAM-REV-003 | Reviews without assigned reviewer | MEDIUM |

### Role Design Quality (IAM-ROLE-*)
| Check | Description | Severity |
|-------|-------------|----------|
| IAM-ROLE-001 | Custom roles without descriptions | LOW |
| IAM-ROLE-002 | Custom roles without designated owners | MEDIUM |
| IAM-ROLE-003 | Empty roles with no menu/transaction assignments | LOW |

### Other IAM Checks
| Check | Description | Severity |
|-------|-------------|----------|
| IAM-ORPH-001 | Users assigned to non-existent/deleted roles | MEDIUM |
| IAM-USRGRP-001 | Active users in default/unassigned user groups | LOW |
| IAM-REF-001 | Dialog users misused as reference users | HIGH |
| IAM-PRIV-001 | Users with privilege escalation capability (self-escalation paths) | CRITICAL |

</details>

<details>
<summary><strong>🔥 BTP Cloud Attack Surface — Full Check List</strong></summary>

### Cloud Connector (BTP-CC-*)
| Check | Description | Severity |
|-------|-------------|----------|
| BTP-CC-001 | Wildcard resource mappings on backends | CRITICAL |
| BTP-CC-002 | High-risk paths exposed (WebGUI, ADT, SOAP RFC) | HIGH |
| BTP-CC-003 | Excessive number of backend systems | MEDIUM |
| BTP-CC-004 | Unrestricted access control lists | HIGH |
| BTP-CC-005 | Certificates expiring or expired | HIGH |
| BTP-CC-006 | Certificates with weak cryptography (SHA-1, <2048 bit) | HIGH |
| BTP-CC-007 | Stale/unused backend configurations | MEDIUM |

### Service Bindings (BTP-SB-*)
| Check | Description | Severity |
|-------|-------------|----------|
| BTP-SB-001 | Bindings not rotated in 180+ days | HIGH |
| BTP-SB-002 | Bindings with admin-level scopes | HIGH |
| BTP-SB-003 | Orphaned bindings (deleted instances) | MEDIUM |

### Destination Service (BTP-DST-*)
| Check | Description | Severity |
|-------|-------------|----------|
| BTP-DST-001 | Destinations with stored credentials | HIGH |
| BTP-DST-002 | Destinations with TLS verification disabled | CRITICAL |
| BTP-DST-003 | Proxy type mismatch (Internet vs OnPremise) | MEDIUM |
| BTP-DST-004 | Stale destinations (365+ days unmodified) | LOW |

### Identity Authentication Service (BTP-IAS-*)
| Check | Description | Severity |
|-------|-------------|----------|
| BTP-IAS-001 | Apps without conditional authentication rules | MEDIUM |
| BTP-IAS-002 | Apps without IP-based restrictions | MEDIUM |
| BTP-IAS-003 | Apps without multi-factor authentication | HIGH |

### Entitlement Governance (BTP-ENT-*)
| Check | Description | Severity |
|-------|-------------|----------|
| BTP-ENT-001 | Services entitled but never provisioned | LOW |
| BTP-ENT-002 | Security services entitled but unused (audit, credstore) | MEDIUM |

### Event Mesh (BTP-EM-*)
| Check | Description | Severity |
|-------|-------------|----------|
| BTP-EM-001 | Queues with wildcard topic subscriptions | HIGH |
| BTP-EM-002 | Queues without access control policies | HIGH |
| BTP-EM-003 | Cross-namespace event subscriptions | MEDIUM |

### Cloud Integration / CPI (BTP-CPI-*)
| Check | Description | Severity |
|-------|-------------|----------|
| BTP-CPI-001 | Credentials not rotated in 180+ days | HIGH |
| BTP-CPI-002 | Credentials using basic/plaintext auth | MEDIUM |
| BTP-CPI-003 | iFlows with hardcoded/embedded credentials | CRITICAL |
| BTP-CPI-004 | iFlows with no sender authentication | HIGH |
| BTP-CPI-005 | iFlows using unencrypted HTTP endpoints | HIGH |

### Network Isolation (BTP-NET-*)
| Check | Description | Severity |
|-------|-------------|----------|
| BTP-NET-001 | Services using public internet endpoints | MEDIUM |
| BTP-NET-002 | Critical services without Private Link | HIGH |

### Subaccount Governance (BTP-GOV-*)
| Check | Description | Severity |
|-------|-------------|----------|
| BTP-GOV-001 | Subaccounts without audit logging | HIGH |
| BTP-GOV-002 | Subaccounts using default SAP IDP only | MEDIUM |

### XSUAA Migration (BTP-MIG-*)
| Check | Description | Severity |
|-------|-------------|----------|
| BTP-MIG-001 | Apps still using XSUAA (not migrated to IAS) | MEDIUM |

</details>

<details>
<summary><strong>🔗 Network & Integration Layer — Full Check List</strong></summary>

### API Management (INTG-APIM-*)
| Check | Description | Severity |
|-------|-------------|----------|
| INTG-APIM-001 | API proxies missing required security policies | HIGH |
| INTG-APIM-002 | API proxies without authentication policies | CRITICAL |
| INTG-APIM-003 | API proxies allowing unencrypted HTTP | HIGH |
| INTG-APIM-004 | API proxies allowing deprecated TLS versions | HIGH |
| INTG-APIM-005 | API proxies in pass-through mode (zero policies) | CRITICAL |

### IDOC Port & Partner Security (INTG-IDOC-*)
| Check | Description | Severity |
|-------|-------------|----------|
| INTG-IDOC-001 | IDOC ports without encryption (TLS/SNC) | HIGH |
| INTG-IDOC-002 | IDOC file ports with insecure directories | MEDIUM |
| INTG-IDOC-003 | IDOC partners with wildcard message types | HIGH |
| INTG-IDOC-004 | IDOC partners handling sensitive message types | MEDIUM |

### Web Services / SOAMANAGER (INTG-WS-*)
| Check | Description | Severity |
|-------|-------------|----------|
| INTG-WS-001 | High-risk BAPIs/RFCs exposed as web services | HIGH |
| INTG-WS-002 | Excessive active web service endpoints | MEDIUM |
| INTG-WS-003 | Web services with weak/no authentication | CRITICAL |

### Webhook & Callback Security (INTG-WH-*)
| Check | Description | Severity |
|-------|-------------|----------|
| INTG-WH-001 | Webhook callbacks using unencrypted HTTP | HIGH |
| INTG-WH-002 | Webhooks without HMAC signature verification | HIGH |
| INTG-WH-003 | Webhooks delivering to external endpoints | MEDIUM |
| INTG-WH-004 | Stale webhook registrations | LOW |

### Gateway ACL Deep Analysis (INTG-GW-*)
| Check | Description | Severity |
|-------|-------------|----------|
| INTG-GW-001 | Secinfo with overly permissive permit rules | CRITICAL |
| INTG-GW-002 | Secinfo missing deny-all default rule | HIGH |
| INTG-GW-003 | Secinfo permits external program execution | HIGH |
| INTG-GW-004 | Reginfo permits unrestricted RFC registration | CRITICAL |
| INTG-GW-005 | Reginfo missing deny-all default rule | HIGH |

### Integration Monitoring (INTG-MON-*)
| Check | Description | Severity |
|-------|-------------|----------|
| INTG-MON-001 | Missing integration monitoring alert rules | HIGH |
| INTG-MON-002 | Integration events not forwarded to SIEM | MEDIUM |

### CPI Data Stores (INTG-CPI-DS-*)
| Check | Description | Severity |
|-------|-------------|----------|
| INTG-CPI-DS-001 | Data stores with sensitive names, no encryption | HIGH |
| INTG-CPI-DS-002 | Global variables with potentially sensitive names | MEDIUM |
| INTG-CPI-DS-003 | Data stores with excessive entries | LOW |

### OAuth Client Governance (INTG-OAUTH-*)
| Check | Description | Severity |
|-------|-------------|----------|
| INTG-OAUTH-001 | OAuth clients with admin/wildcard scopes | HIGH |
| INTG-OAUTH-002 | OAuth clients using deprecated grant types | HIGH |
| INTG-OAUTH-003 | OAuth clients unused for 180+ days | MEDIUM |

### Integration Topology (INTG-TOPO-*)
| Check | Description | Severity |
|-------|-------------|----------|
| INTG-TOPO-001 | Integration connections without encryption | HIGH |
| INTG-TOPO-002 | Hub systems with excessive connections | MEDIUM |
| INTG-TOPO-003 | Connections to deprecated/legacy systems | MEDIUM |

</details>

<details>
<summary><strong>🔏 Data Protection & Privacy — Full Check List (NEW)</strong></summary>

### Read Access Logging (DPP-RAL-*)
| Check | Description | Severity |
|-------|-------------|----------|
| DPP-RAL-001 | RAL disabled or no active configurations | CRITICAL |
| DPP-RAL-002 | RAL missing coverage for key channels (OData, RFC, ALV) | HIGH |
| DPP-RAL-003 | RAL log channels with insufficient retention | MEDIUM |

### Information Lifecycle Management (DPP-ILM-*)
| Check | Description | Severity |
|-------|-------------|----------|
| DPP-ILM-001 | Retention policies exceeding maximum period | MEDIUM |
| DPP-ILM-002 | Policies without automatic data destruction | MEDIUM |
| DPP-ILM-003 | Policies without end-of-purpose definitions | HIGH |
| DPP-ILM-004 | Personal data tables without ILM retention policies | HIGH |

### Data Masking — Non-Production (DPP-MASK-*)
| Check | Description | Severity |
|-------|-------------|----------|
| DPP-MASK-001 | Non-production systems without PII data masking | CRITICAL |
| DPP-MASK-002 | Production copies in non-prod without masking | CRITICAL |

### DPP Toolkit (DPP-TOOLKIT-*)
| Check | Description | Severity |
|-------|-------------|----------|
| DPP-TOOLKIT-001 | DPP toolkit features not configured (deletion report, consent, breach notification) | HIGH |

### Purpose of Processing (DPP-POP-*)
| Check | Description | Severity |
|-------|-------------|----------|
| DPP-POP-001 | Purposes without documented legal basis (GDPR Art.6) | HIGH |
| DPP-POP-002 | Expired purposes still active | MEDIUM |

### Sensitive Field Inventory (DPP-FIELD-*)
| Check | Description | Severity |
|-------|-------------|----------|
| DPP-FIELD-001 | PII fields without Read Access Logging | HIGH |
| DPP-FIELD-002 | Sensitive fields not masked in non-production | MEDIUM |
| DPP-FIELD-003 | Known sensitive SAP fields missing from classification inventory | MEDIUM |

### Data Residency & Cross-Border (DPP-RES-*)
| Check | Description | Severity |
|-------|-------------|----------|
| DPP-RES-001 | Cross-border transfers without legal safeguards (SCCs/BCRs) | CRITICAL |
| DPP-RES-002 | Special category data in cross-border transfers | HIGH |

### Data Subject Requests (DPP-DEL-*)
| Check | Description | Severity |
|-------|-------------|----------|
| DPP-DEL-001 | Data subject requests overdue (>30 day SLA) | CRITICAL |
| DPP-DEL-002 | Requests marked complete but incomplete | HIGH |
| DPP-DEL-003 | Requests without documentation | MEDIUM |

### System Landscape (DPP-LAND-*)
| Check | Description | Severity |
|-------|-------------|----------|
| DPP-LAND-001 | Systems without data classification assignment | MEDIUM |

</details>

---

## Quick Start

```bash
git clone https://github.com/Krishcalin/SAP-S4HANA-RISE-Security-Scanner.git
cd SAP-S4HANA-RISE-Security-Scanner

# Run against sample data (included)
python sap_scanner.py --data-dir ./sample_data --output report.html

# Run specific modules
python sap_scanner.py --data-dir ./exports --modules btpcloud iam
python sap_scanner.py --data-dir ./exports --modules intglayer network

# Filter by severity
python sap_scanner.py --data-dir ./exports --severity HIGH

# Custom thresholds
python sap_scanner.py --data-dir ./exports --config baseline.json
```

### Available Modules

```
users     — User & Authorization (USR-*)
iam       — Advanced IAM (IAM-*)
params    — Security Parameters (PARAM-*)
network   — Network & Service Exposure (NET-*)
rise      — RISE / BTP Core (RISE-*)
btpcloud  — BTP Cloud Attack Surface (BTP-*)
intglayer — Network & Integration Layer (INTG-*)
dataprot  — Data Protection & Privacy (DPP-*)
all       — Run everything (default)
```

---

## Data Sources

All files are optional — the scanner runs only checks for which data is available. See [`docs/EXPORT_GUIDE.md`](docs/EXPORT_GUIDE.md) for detailed export instructions.

<details>
<summary><strong>📋 Core & IAM data files</strong></summary>

| File | Source | Description |
|------|--------|-------------|
| `users.csv` | RSUSR002 / SU01 | User master data (BNAME, USTYP, UFLAG, TRDAT, etc.) |
| `profiles.csv` | SU02 / USR04 | Profile assignments |
| `user_roles.csv` | AGR_USERS | Role assignments |
| `auth_objects.csv` | SUIM | Authorization object values |
| `security_params.csv` | RSPARAM / RZ11 | Profile parameter values |
| `rfc_destinations.csv` | SM59 | RFC destination configs |
| `icf_services.csv` | SICF | ICF service tree |
| `audit_config.csv` | SM19 | Audit log filter config |
| `transports.csv` | SE09 / STMS | Transport requests |
| `sod_matrix.csv` | SUIM / GRC ARA | Pre-computed user→tcode mapping |
| `role_tcodes.csv` | AGR_1251 | Role→tcode mapping |
| `sod_ruleset.json` | Custom | Custom SoD rule definitions |
| `firefighter_log.csv` | GRC SPM | Emergency access usage log |
| `role_expiry.csv` | AGR_USERS validity | Role assignments with dates |
| `role_details.csv` | AGR_DEFINE | Role metadata (owner, description) |
| `access_reviews.csv` | GRC ARM | Access review campaign data |
| `user_groups.csv` | USR02 | User group assignments |

</details>

<details>
<summary><strong>📋 BTP / RISE data files</strong></summary>

| File | Source | Description |
|------|--------|-------------|
| `btp_trust.json` | BTP Cockpit → Trust Config | Trust configurations |
| `comm_arrangements.json` | Fiori "Communication Arrangements" | Communication setups |
| `api_endpoints.json` | OData service catalog | Published API endpoints |
| `btp_users.json` | BTP Cockpit → Users | BTP user & role collections |
| `cloud_connector.json` | SCC Admin UI | Backends, ACLs, certificates |
| `btp_service_bindings.json` | BTP Service Manager API | Service bindings |
| `btp_destinations.json` | Destination Service API | Destination configs |
| `ias_config.json` | IAS Admin Console | Application & policy config |
| `btp_entitlements.json` | BTP Cockpit / CLI | Entitlement quotas & usage |
| `event_mesh.json` | Event Mesh Management API | Queue/topic configs |
| `cpi_artifacts.json` | CPI Operations API | Credentials & iFlow metadata |
| `btp_network.json` | BTP Cockpit | Private Link / network config |
| `btp_subaccounts.json` | BTP Cockpit / CLI | Multi-subaccount governance |

</details>

<details>
<summary><strong>📋 Integration Layer data files</strong></summary>

| File | Source | Description |
|------|--------|-------------|
| `apim_policies.json` | API Management admin | Proxy & policy configurations |
| `idoc_ports.csv` | WE21 | IDOC port configurations |
| `idoc_partners.csv` | WE20 | IDOC partner profiles |
| `ws_endpoints.csv` | SOAMANAGER | Web service endpoints |
| `webhooks.json` | Event / webhook registry | Callback registrations |
| `gw_secinfo.csv` | Gateway secinfo file | Program start ACL rules |
| `gw_reginfo.csv` | Gateway reginfo file | RFC registration ACL rules |
| `integration_alerts.json` | Alert Notification Service | Monitoring alert config |
| `cpi_datastores.json` | CPI Operations API | Data stores & global variables |
| `oauth_clients.json` | XSUAA / IAS admin | OAuth client registrations |
| `integration_topology.json` | Manual / discovery tool | System-to-system connection map |

</details>

<details>
<summary><strong>📋 Data Protection & Privacy data files</strong></summary>

| File | Source | Description |
|------|--------|-------------|
| `ral_config.csv` | SRALMANAGER | RAL configuration & active rules |
| `ral_log_channels.csv` | SRALMANAGER | RAL log channel retention settings |
| `ilm_policies.json` | IRMPOL / ILM Cockpit | ILM retention & destruction rules |
| `data_masking.json` | TDMS / DPI config | Non-production masking configuration |
| `dpp_config.json` | DPP Toolkit Fiori apps | DPP feature enablement status |
| `purpose_of_processing.csv` | ROPA / DPP config | Purpose definitions with legal basis |
| `sensitive_fields.csv` | Data classification inventory | PII field classification & protection status |
| `data_residency.json` | Data governance / legal | Cross-border transfer configurations |
| `personal_data_inventory.csv` | DPI / manual inventory | Personal data field-level inventory |
| `deletion_requests.csv` | DSAR tracking system | Data subject request log |
| `system_landscape.csv` | System landscape inventory | System classification & data protection status |

</details>

---

## Custom Baseline

Override default thresholds by creating a JSON config file:

```json
{
    "dormant_threshold_days": 60,
    "max_roles_per_user": 20,
    "max_password_age_days": 60,
    "max_role_validity_days": 365,
    "ff_max_duration_hours": 4,
    "ff_max_sessions_per_month": 5,
    "access_review_cycle_days": 90,
    "binding_rotation_max_days": 180,
    "cpi_credential_rotation_days": 180,
    "cert_expiry_warning_days": 90,
    "max_cc_backends": 20,
    "destination_stale_days": 365,
    "max_active_ws_endpoints": 50,
    "webhook_stale_days": 180,
    "oauth_client_stale_days": 180,
    "max_cpi_datastore_entries": 10000,
    "max_system_connections": 15,
    "ral_min_retention_days": 365,
    "max_retention_years": 10,
    "deletion_sla_days": 30
}
```

---

## Project Structure

```
SAP-S4HANA-RISE-Security-Scanner/
├── sap_scanner.py                  # Main entry point & CLI
├── modules/
│   ├── base_auditor.py             # Base class
│   ├── data_loader.py              # CSV/JSON loader (40+ file types)
│   ├── user_auth_audit.py          # USR-* checks
│   ├── iam_advanced.py             # IAM-* checks (SoD, firefighter, role lifecycle)
│   ├── security_params.py          # PARAM-* checks
│   ├── network_services.py         # NET-* checks
│   ├── rise_btp_checks.py          # RISE-* checks
│   ├── btp_cloud_surface.py        # BTP-* checks
│   ├── integration_layer.py        # INTG-* checks
│   ├── data_protection.py          # DPP-* checks (NEW)
│   └── report_generator.py         # HTML dashboard
├── sample_data/                    # 45+ demo files
├── docs/
│   ├── banner.svg
│   ├── EXPORT_GUIDE.md
│   └── CHECKS_REFERENCE.md
├── .gitignore
├── LICENSE
├── CONTRIBUTING.md
└── README.md
```

---

## Roadmap

- [x] Core security parameter validation
- [x] User & authorization auditing
- [x] Network & service exposure checks
- [x] RISE/BTP-specific checks
- [x] Segregation of Duties (SoD) detection
- [x] Emergency/firefighter access analysis
- [x] Role lifecycle & cross-system identity
- [x] Privilege escalation path detection
- [x] Access review compliance checks
- [x] Cloud Connector audit
- [x] BTP service binding & destination review
- [x] IAS policy & MFA enforcement
- [x] Event Mesh topic authorization
- [x] CPI credential & iFlow security
- [x] Network isolation / Private Link
- [x] Multi-subaccount governance
- [x] XSUAA → IAS migration status
- [x] API Management policy enforcement
- [x] IDOC port & partner profile security
- [x] Web service (SOAMANAGER) endpoint audit
- [x] Webhook & callback endpoint security
- [x] Gateway secinfo/reginfo deep analysis
- [x] Integration monitoring & alerting gaps
- [x] OAuth client & scope governance
- [x] Integration topology analysis
- [x] Read Access Logging (RAL) configuration & coverage
- [x] Information Lifecycle Management (ILM) retention policies
- [x] Non-production data masking / anonymization
- [x] GDPR/DPDP toolkit configuration (DPP)
- [x] Purpose of processing & legal basis compliance
- [x] Sensitive field inventory & classification
- [x] Cross-border data transfer controls
- [x] Data subject request (DSAR) compliance
- [ ] Custom ABAP code security scanning
- [ ] Fiori catalog/tile authorization review
- [ ] Cryptographic posture assessment
- [ ] Scan comparison mode (diff two scans)
- [ ] CI/CD integration with exit codes

---

## Requirements

**Python 3.8+** — No external packages required.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Disclaimer

This tool is for **authorized security assessments only**. The scanner performs offline analysis of exported data and does not connect to or modify any SAP system.

## License

MIT License — see [LICENSE](LICENSE).
