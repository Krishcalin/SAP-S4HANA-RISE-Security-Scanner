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
  <img src="https://img.shields.io/badge/CIS-Benchmark%20Aligned-yellow?style=flat-square" alt="CIS Benchmark"/>
</p>

---

## Overview

**SAP S/4HANA RISE Security Scanner** analyzes exported SAP configuration data (CSV/JSON) and produces an interactive HTML dashboard with findings, severity ratings, and actionable remediation guidance.

- **No direct system connection required** — ideal for RISE environments with restricted RFC access
- **Zero external dependencies** — runs on Python 3.8+ stdlib only
- **CIS SAP Benchmark aligned** — checks mapped to industry-standard baselines
- **43+ security checks** across 4 audit domains

<p align="center">
  <img src="docs/screenshot_dashboard.png" alt="Dashboard Screenshot" width="750"/>
</p>

---

## Audit Modules

### 🔐 User & Authorization (`USR-001` → `USR-008`)
| Check | Description | Severity |
|-------|-------------|----------|
| USR-001 | Default users (SAP*, DDIC, SAPCPIC) unlocked | CRITICAL |
| USR-002 | Users assigned SAP_ALL / SAP_NEW / S_A.SYSTEM | CRITICAL |
| USR-003 | Dormant accounts (90+ days inactive) | MEDIUM |
| USR-004 | Service accounts with dialog logon type | HIGH |
| USR-005 | Excessive role assignments per user | MEDIUM |
| USR-006 | Wildcard auth object values (S_DEVELOP, S_TABU_DIS) | HIGH |
| USR-007 | Active accounts that never logged in | LOW |
| USR-008 | Dialog users with stale passwords (180+ days) | MEDIUM |

### ⚙️ Security Parameters (`PARAM-*`)
25+ profile parameters validated against the CIS SAP S/4HANA benchmark:
- **Password Policy** — min length, complexity, expiration, history
- **Login Security** — lockout thresholds, SAP* auto-logon, multi-session
- **RFC Security** — `rfc/reject_insecure_logon`, old ticket format
- **Gateway Security** — `gw/sec_info` and `gw/reg_info` configuration
- **Transport Security** — ICM TLS settings, cipher suites
- **Audit Logging** — `rsau/enable`, `rec/client` table logging
- **Development Controls** — debug work processes in production

### 🌐 Network & Service Exposure (`NET-001` → `NET-008`)
| Check | Description | Severity |
|-------|-------------|----------|
| NET-001 | RFC destinations with stored credentials | HIGH |
| NET-002 | RFC destinations to external/unknown hosts | MEDIUM |
| NET-003 | RFC destinations without SNC encryption | HIGH |
| NET-004 | High-risk ICF services active (11 patterns) | HIGH |
| NET-005 | Active ICF services without authentication | CRITICAL |
| NET-006 | Open/unreleased transports in production | MEDIUM |
| NET-007 | Transports with debug/replace indicators | HIGH |
| NET-008 | No active security audit filters (SM19) | CRITICAL |

### ☁️ RISE / BTP-Specific (`RISE-001` → `RISE-007`)
| Check | Description | Severity |
|-------|-------------|----------|
| RISE-001 | Default SAP IDP trust still active | MEDIUM |
| RISE-002 | Automatic shadow user creation enabled | MEDIUM |
| RISE-003 | Communication arrangements with excessive service scope | MEDIUM |
| RISE-004 | Communication arrangements with weak/no auth | CRITICAL |
| RISE-005 | Sensitive APIs exposed (finance, HR, master data) | HIGH |
| RISE-006 | Communication users shared across arrangements | MEDIUM |
| RISE-007 | API endpoints with weak/no authentication | HIGH |

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/Krishcalin/SAP-S4HANA-RISE-Security-Scanner.git
cd SAP-S4HANA-RISE-Security-Scanner

# Run against sample data (included)
python sap_scanner.py --data-dir ./sample_data --output report.html

# Open the report
open report.html        # macOS
xdg-open report.html    # Linux
start report.html       # Windows
```

### CLI Options

```
usage: sap_scanner.py [-h] --data-dir DATA_DIR [--output OUTPUT]
                      [--severity {CRITICAL,HIGH,MEDIUM,LOW,ALL}]
                      [--modules {users,params,network,rise,all} ...]
                      [--config CONFIG]

Options:
  --data-dir   Directory containing exported SAP config files (required)
  --output     Output HTML report filename (default: sap_security_report.html)
  --severity   Minimum severity filter (default: ALL)
  --modules    Specific modules to run (default: all)
  --config     Path to custom baseline JSON overrides
```

### Examples

```bash
# Run only user and parameter checks
python sap_scanner.py --data-dir ./exports --modules users params

# Critical and High findings only
python sap_scanner.py --data-dir ./exports --severity HIGH

# Custom baseline thresholds
python sap_scanner.py --data-dir ./exports --config my_baseline.json
```

---

## Exporting Data from SAP

<details>
<summary><strong>📋 Click to expand — Full export guide for each data source</strong></summary>

### Users (`users.csv`)
**Source:** Report `RSUSR002` or `SU01` user list export
```
Required fields: BNAME, USTYP, UFLAG, TRDAT, ERDAT, PWDCHGDATE
```

### Profiles (`profiles.csv`)
**Source:** `SU02` or table `USR04`
```
Required fields: BNAME, PROFILE
```

### User Roles (`user_roles.csv`) — *Optional*
**Source:** Table `AGR_USERS`
```
Required fields: UNAME, AGR_NAME
```

### Auth Objects (`auth_objects.csv`) — *Optional*
**Source:** `SUIM` → Users by Authorization Object
```
Required fields: UNAME, OBJECT, VALUE
```

### Security Parameters (`security_params.csv`)
**Source:** Report `RSPARAM` or `RZ11` export
```
Required fields: NAME, VALUE
```

### RFC Destinations (`rfc_destinations.csv`)
**Source:** `SM59` export
```
Required fields: RFCDEST, RFCTYPE, RFCHOST, RFCUSER, RFCSNC
```

### ICF Services (`icf_services.csv`)
**Source:** `SICF` service tree export
```
Required fields: ICF_NAME, ICF_ACTIVE, AUTH_REQUIRED
```

### Transports (`transports.csv`) — *Optional*
**Source:** `SE09` or `STMS`
```
Required fields: TRKORR, TRSTATUS, AS4USER, AS4TEXT
```

### Audit Config (`audit_config.csv`)
**Source:** `SM19` filter configuration
```
Required fields: FILTER_NAME, ACTIVE, EVENT_CLASS
```

### BTP Trust (`btp_trust.json`)
**Source:** BTP Cockpit → Subaccount → Security → Trust Configuration

### Communication Arrangements (`comm_arrangements.json`)
**Source:** Fiori app "Communication Arrangements" or via API

### API Endpoints (`api_endpoints.json`)
**Source:** Fiori app "Communication Scenarios" or OData catalog

</details>

---

## Custom Baseline

Override default thresholds by creating a JSON config file:

```json
{
    "dormant_threshold_days": 60,
    "max_roles_per_user": 20,
    "max_password_age_days": 60,
    "internal_host_patterns": [
        "10.", "172.16.", "192.168.", "mycompany.corp"
    ]
}
```

Pass it with `--config`:
```bash
python sap_scanner.py --data-dir ./exports --config baseline.json
```

See [`sample_data/baseline.json`](sample_data/baseline.json) for a complete example.

---

## Project Structure

```
SAP-S4HANA-RISE-Security-Scanner/
├── sap_scanner.py              # Main entry point & CLI
├── modules/
│   ├── __init__.py
│   ├── base_auditor.py         # Base class with finding/severity utilities
│   ├── data_loader.py          # CSV/JSON loader with auto-detection
│   ├── user_auth_audit.py      # User & authorization checks
│   ├── security_params.py      # Profile parameter baseline validation
│   ├── network_services.py     # RFC, ICF, transport, audit log checks
│   ├── rise_btp_checks.py      # RISE/BTP-specific checks
│   └── report_generator.py     # HTML dashboard generator
├── sample_data/                # Demo data + sample report
│   ├── users.csv
│   ├── profiles.csv
│   ├── security_params.csv
│   ├── rfc_destinations.csv
│   ├── icf_services.csv
│   ├── audit_config.csv
│   ├── btp_trust.json
│   ├── comm_arrangements.json
│   ├── api_endpoints.json
│   ├── baseline.json
│   └── sample_report.html
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

## HTML Report Features

- **Risk Score** — Weighted composite score (0–100) with visual ring gauge
- **Severity Summary** — Count cards for CRITICAL / HIGH / MEDIUM / LOW
- **Category Breakdown** — Horizontal bar chart of findings per audit domain
- **Interactive Findings** — Expandable cards with description, affected items, remediation, and SAP Note references
- **Severity Filter** — Client-side filter buttons to focus on specific severities
- **Print-Friendly** — Auto-expands all findings when printing (`Ctrl+P`)

---

## Requirements

- **Python 3.8+**
- **No external packages** — uses only Python standard library (`csv`, `json`, `html`, `argparse`, `datetime`, `pathlib`)

---

## Roadmap

- [ ] JSON/CSV export alongside HTML report
- [ ] ABAP code scanner for custom code vulnerabilities
- [ ] SAP GRC integration for automated role analysis
- [ ] PyRFC live-scan module (optional, for non-RISE systems)
- [ ] Comparison mode — diff two scans over time
- [ ] CI/CD integration with exit codes based on findings

---

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Disclaimer

This tool is for **authorized security assessments only**. Always obtain proper authorization before auditing SAP systems. The scanner performs offline analysis of exported data and does not connect to or modify any SAP system.

---

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.
