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
  <img src="https://img.shields.io/badge/checks-123%2B-red?style=flat-square" alt="96+ Checks"/>
</p>

---

## Overview

**SAP S/4HANA RISE Security Scanner** analyzes exported SAP configuration data (CSV/JSON) and produces an interactive HTML dashboard with findings, severity ratings, and actionable remediation guidance.

- **No direct system connection required** — ideal for RISE environments with restricted RFC access
- **Zero external dependencies** — runs on Python 3.8+ stdlib only
- **123+ security checks across 7 audit modules
- **CIS SAP Benchmark aligned** — checks mapped to industry-standard baselines

---

## Audit Modules

| Module | Checks | Focus |
|--------|--------|-------|
| 🔐 **User & Authorization** | USR-001→008 | Default users, SAP_ALL, dormant accounts, service accounts |
| 🛡️ **Advanced IAM** | IAM-SOD/FF/EXP/XID/REV/ROLE/PRIV | SoD conflicts, firefighter access, role lifecycle, cross-system identity |
| ⚙️ **Security Parameters** | PARAM-* (25+) | Password policy, login security, RFC, gateway, TLS, audit logging |
| 🌐 **Network & Services** | NET-001→008 | RFC destinations, ICF services, transports, audit config |
| ☁️ **RISE / BTP Core** | RISE-001→007 | Trust config, comm arrangements, API exposure |
| 🔥 **BTP Cloud Attack Surface** | BTP-CC/SB/DST/IAS/ENT/EM/CPI/NET/GOV/MIG (29) | Cloud Connector, service bindings, destinations, IAS, Event Mesh, CPI, network isolation |
| 🔗 **Network & Integration Layer** | INTG-APIM/IDOC/WS/WH/GW/MON/CPI/OAUTH/TOPO (27) | API Management, IDOC ports, web services, webhooks, gateway ACLs, OAuth, topology |

<details>
<summary><strong>🔥 BTP Cloud Attack Surface — Full Check List (NEW)</strong></summary>

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
<summary><strong>🔗 Network & Integration Layer — Full Check List (NEW)</strong></summary>

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

---

## Quick Start

```bash
git clone https://github.com/Krishcalin/SAP-S4HANA-RISE-Security-Scanner.git
cd SAP-S4HANA-RISE-Security-Scanner

# Run against sample data (included)
python sap_scanner.py --data-dir ./sample_data --output report.html

# Run specific modules
python sap_scanner.py --data-dir ./exports --modules btpcloud iam
python sap_scanner.py --data-dir ./exports --modules users params network

# Filter by severity
python sap_scanner.py --data-dir ./exports --severity HIGH

# Custom thresholds
python sap_scanner.py --data-dir ./exports --config baseline.json
```

### Available Modules

```
users     — User & Authorization (USR-*)
params    — Security Parameters (PARAM-*)
network   — Network & Service Exposure (NET-*)
rise      — RISE / BTP Core (RISE-*)
iam       — Advanced IAM (IAM-*)
btpcloud  — BTP Cloud Attack Surface (BTP-*)
intglayer — Network & Integration Layer (INTG-*)
all       — Run everything (default)
```

---

## Data Sources

All files are optional — the scanner runs only checks for which data is available. See [`docs/EXPORT_GUIDE.md`](docs/EXPORT_GUIDE.md) for detailed export instructions.

<details>
<summary><strong>📋 BTP Cloud Attack Surface data files (NEW)</strong></summary>

| File | Source | Description |
|------|--------|-------------|
| `cloud_connector.json` | SCC Admin UI export | Backends, ACLs, certificates |
| `btp_service_bindings.json` | BTP Service Manager API | Service instance bindings |
| `btp_destinations.json` | BTP Destination Service API | Destination configurations |
| `ias_config.json` | IAS Admin Console | Application & policy config |
| `btp_entitlements.json` | BTP Cockpit / CLI | Entitlement quotas & usage |
| `event_mesh.json` | Event Mesh Management API | Queue/topic configurations |
| `cpi_artifacts.json` | CPI Operations API | Credentials & iFlow metadata |
| `btp_network.json` | BTP Cockpit | Private Link / network config |
| `btp_subaccounts.json` | BTP Cockpit / CLI | Multi-subaccount governance |

</details>

---

## Custom Baseline

```json
{
    "dormant_threshold_days": 60,
    "max_roles_per_user": 20,
    "ff_max_duration_hours": 4,
    "ff_max_sessions_per_month": 5,
    "binding_rotation_max_days": 180,
    "cpi_credential_rotation_days": 180,
    "cert_expiry_warning_days": 90,
    "max_cc_backends": 20,
    "destination_stale_days": 365
}
```

---

## Project Structure

```
SAP-S4HANA-RISE-Security-Scanner/
├── sap_scanner.py                  # Main entry point & CLI
├── modules/
│   ├── base_auditor.py             # Base class
│   ├── data_loader.py              # CSV/JSON loader (30+ file types)
│   ├── user_auth_audit.py          # USR-* checks
│   ├── iam_advanced.py             # IAM-* checks (SoD, firefighter, etc.)
│   ├── security_params.py          # PARAM-* checks
│   ├── network_services.py         # NET-* checks
│   ├── rise_btp_checks.py          # RISE-* checks
│   ├── btp_cloud_surface.py        # BTP-* checks
│   ├── integration_layer.py        # INTG-* checks (NEW)
│   └── report_generator.py         # HTML dashboard
├── sample_data/                    # 25+ demo files
├── docs/
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
- [x] Cloud Connector audit
- [x] BTP service binding & destination review
- [x] IAS policy & MFA enforcement
- [x] Event Mesh topic authorization
- [x] CPI credential & iFlow security
- [x] Network isolation / Private Link
- [x] Multi-subaccount governance
- [x] XSUAA → IAS migration status
- [ ] Data protection & privacy (RAL, ILM)
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
