<p align="center">
  <img src="docs/banner.svg" alt="SAP S/4HANA RISE Security Scanner" width="800"/>
</p>

<p align="center">
  <strong>An offline security audit tool for SAP S/4HANA RISE and BTP environments</strong>
</p>

<p align="center">
  <a href="https://github.com/Krishcalin/SAP-S4HANA-RISE-Security-Scanner/actions/workflows/tests.yml"><img src="https://github.com/Krishcalin/SAP-S4HANA-RISE-Security-Scanner/actions/workflows/tests.yml/badge.svg" alt="tests"/></a>
  <img src="https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.8+"/>
  <img src="https://img.shields.io/badge/dependencies-zero-brightgreen?style=flat-square" alt="Zero Dependencies"/>
  <img src="https://img.shields.io/badge/license-MIT-orange?style=flat-square" alt="MIT License"/>
  <img src="https://img.shields.io/badge/SAP-S%2F4HANA%20RISE-0FAAFF?style=flat-square&logo=sap&logoColor=white" alt="SAP S/4HANA"/>
  <img src="https://img.shields.io/badge/checks-278%2B-red?style=flat-square" alt="278+ Checks"/>
</p>

---

## Overview

**SAP S/4HANA RISE Security Scanner** analyzes exported SAP configuration data (CSV/JSON) and produces an interactive HTML dashboard with findings, severity ratings, and actionable remediation guidance.

- **No direct system connection required** — offline & agentless; ideal for RISE environments with restricted RFC access
- **Zero external dependencies** — runs on Python 3.8+ stdlib only
- **278+ security checks across 19 audit modules** — from ABAP authorizations and HANA DB to BTP/Cloud and permission-level Segregation of Duties
- **Standards-aligned** — mapped to the CIS SAP Benchmark, DSAG best-practice guide, and the SAP Security Baseline

**Pipeline:** &nbsp;`LOAD` CSV/JSON exports → `MODULES` (19 auditors) → `CHECKS` (278+ rules) → `RANK` by severity → interactive `REPORT` (HTML dashboard).

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
| 💻 **Code & Transport Security** | CODE-INJ/STMT/ATC/TMS/CLIENT/CHG/DEV/MOD/DEAD (21) | SQL injection, hardcoded creds, ATC findings, transport workflow, client config, SAP mods |
| 📊 **Logging, Monitoring & IR** | LOG-AUD/SIEM/RET/TBL/LOGON/IR (11) | Audit log config, SIEM integration, log retention, table logging, brute-force detection |
| 🖥️ **Fiori & UI Layer** | FIORI-CAT/APP/ODATA/SPACE/TILE/USAGE (8) | Catalog access, OData backend auth, sensitive app exposure, spaces/pages config |
| 🔑 **Cryptographic Posture** | CRYPTO-TLS/CERT/SNC/HANA/LIB/PSE/KEY (13) | TLS config, certificate health, SNC, HANA encryption, crypto library, key management |
| 🗄️ **HANA Database Security** | HANADB-USER/PRIV/ROLE/AUDIT/PARAM (15) | Privileged DB users (SYSTEM, password lifetime, dormancy), PUBLIC & system-privilege grants, _SYS_BI_CP_ALL analytic bypass, DB auditing, HANA security parameters |
| 📰 **SAP Security Notes / HotNews** | HOTNEWS-000→004 (5) | Missing HotNews (Priority 1) & High (Priority 2) SAP Security Notes since 2020, actively-exploited (CISA KEV) unpatched CVEs, partially-implemented notes — diffed from your SNOTE export against a curated, verified catalog |
| 🔓 **ABAP Authorization & Critical Access** | AUTH-001→015 (15) | Role-content analysis from AGR_1251: Debug&Replace (runtime auth bypass), trusted-RFC impersonation (S_RFCACL), OS command/file access (S_LOG_COM/S_DATASET), authorization forging (S_USER_AUT), broad S_RFC, generic table maintenance (S_TABU_*), run-any-report (S_PROGRAM), batch impersonation, and sensitive Basis transactions — attributed to the users who hold each role |
| 🔗 **System Trust & Standard Users** | TRUST-001→008, STDUSR-001→003 (11) | Trusted/trusting RFC (inbound trust from a lower tier, self-trust, unmigrated 2020 method, trusted destination with a fixed user), SAProuter wildcard routes, message-server port separation, UCON RFC allowlist, gateway proxy ACL — plus standard users (SAP* kernel auto-logon, default passwords, unlocked SAP*/DDIC/SAPCPIC/EARLYWATCH/TMSADM) |
| 🧱 **Security Baseline Parameters** | BASELINE-001→010 (10) | SAP Security Baseline / DSAG / CIS profile parameters the other modules don't cover: RFC authorization engine (auth/rfc_authority_check, auth/no_check_in_some_cases), SNC insecure-connection fallback, SAP GUI Scripting, weak legacy password hashes (downwards compatibility), sapstartsrv / Host-Agent web methods, gateway ACL mode, SSO ticket & session-cookie transport, ICM security log & error disclosure |
| 🧩 **S/4HANA & Cloud Authorization** | S4AUTHZ-001→008 (8) | The cloud-era authorization layer: super-admin business-role templates (SAP_BR_ADMINISTRATOR*), business-role restrictions left 'Unrestricted', business-catalog sprawl, CDS views with @AccessControl.authorizationCheck disabled, published OData V4 service groups without S_SERVICE, Cloud Connector system mappings without principal propagation, over-assigned Cloud Foundry Org Manager / Space Developer, and birthright role collections mapped to the Default IdP group |
| ⚖️ **Access Risk Analysis (SoD)** | ARA-* (27 risks + user score) | GRC-style **offline Segregation-of-Duties** from AGR_1251 + AGR_USERS. Resolves each user's transactions **and** authorization object/field/activity across all roles, then evaluates a verified ruleset at the **permission level** (so display-only access is not a false positive): 25 SoD conflicts across Procure-to-Pay, Order-to-Cash, Record-to-Report, Hire-to-Retire and Basis/Security, plus 2 HR critical accesses. Honours documented **mitigating controls** (with expiry) and produces a **per-user risk profile**. Extensible via a custom ruleset JSON. (Supersedes the coarse transaction-level SoD in Advanced IAM, which now defers to this module when AGR_1251 is available.) |

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
<summary><strong>🔏 Data Protection & Privacy — Full Check List</strong></summary>

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

<details>
<summary><strong>💻 Code & Transport Security — Full Check List</strong></summary>

### Code Injection / SQL Injection (CODE-INJ-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CODE-INJ-001 | SQL injection patterns in custom code (dynamic WHERE, EXEC SQL) | CRITICAL |
| CODE-INJ-002 | Custom code missing authority checks | HIGH |
| CODE-INJ-003 | Hardcoded credentials in ABAP source | CRITICAL |

### Dangerous Statements (CODE-STMT-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CODE-STMT-001 | Dangerous ABAP statements (CALL 'SYSTEM', GENERATE, INSERT REPORT) | HIGH |

### ATC / Code Inspector (CODE-ATC-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CODE-ATC-001 | Unresolved critical ATC findings | CRITICAL |
| CODE-ATC-002 | Unresolved high-severity ATC findings | HIGH |

### Transport Management (CODE-TMS-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CODE-TMS-001 | Transport routes allow direct dev→prod delivery | CRITICAL |
| CODE-TMS-002 | Production imports without approval | HIGH |
| CODE-TMS-003 | Same user releasing and importing (SoD violation) | HIGH |
| CODE-TMS-004 | Transport imports outside change windows (weekends) | MEDIUM |
| CODE-TMS-005 | Transports imported directly from dev to prod | CRITICAL |

### Client Configuration (CODE-CLIENT-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CODE-CLIENT-001 | Production client allows changes (not locked) | CRITICAL |

### Change Documents (CODE-CHG-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CODE-CHG-001 | Critical object types without change documents | MEDIUM |
| CODE-CHG-002 | Change documents with empty/system user attribution | MEDIUM |

### Development Access (CODE-DEV-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CODE-DEV-001 | Users with S_DEVELOP modify/create in production | HIGH |

### SAP Modifications (CODE-MOD-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CODE-MOD-001 | Unregistered SAP standard modifications | MEDIUM |
| CODE-MOD-002 | Modifications to security-critical standard programs | CRITICAL |
| CODE-MOD-003 | Stale modifications (5+ years old) | LOW |

### Dead Code (CODE-DEAD-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CODE-DEAD-001 | Excessive unreferenced custom code | MEDIUM |
| CODE-DEAD-002 | Custom code objects without designated owner | LOW |

</details>

<details>
<summary><strong>📊 Logging, Monitoring & IR — Full Check List</strong></summary>

### Security Audit Log (LOG-AUD-*)
| Check | Description | Severity |
|-------|-------------|----------|
| LOG-AUD-001 | Security Audit Log disabled or no active filters | CRITICAL |
| LOG-AUD-002 | No static audit profile configured (lost on restart) | HIGH |
| LOG-AUD-003 | Audit log missing coverage for required event types | HIGH |

### SIEM Integration (LOG-SIEM-*)
| Check | Description | Severity |
|-------|-------------|----------|
| LOG-SIEM-001 | No SIEM integration or SIEM disabled | HIGH |
| LOG-SIEM-002 | SIEM missing critical log source forwarding | MEDIUM |

### Log Retention (LOG-RET-*)
| Check | Description | Severity |
|-------|-------------|----------|
| LOG-RET-001 | Log retention below minimum (365 days) | MEDIUM |
| LOG-RET-002 | Security logs without archiving | LOW |

### Table Logging (LOG-TBL-*)
| Check | Description | Severity |
|-------|-------------|----------|
| LOG-TBL-001 | Critical tables without change logging | HIGH |

### Logon Analysis (LOG-LOGON-*)
| Check | Description | Severity |
|-------|-------------|----------|
| LOG-LOGON-001 | Potential brute-force attack patterns | CRITICAL |
| LOG-LOGON-002 | Accounts with excessive logon failures | MEDIUM |

### Incident Response (LOG-IR-*)
| Check | Description | Severity |
|-------|-------------|----------|
| LOG-IR-001 | Incident response readiness gaps | MEDIUM |

</details>

<details>
<summary><strong>🖥️ Fiori & UI Layer — Full Check List</strong></summary>

### Catalog Access (FIORI-CAT-*)
| Check | Description | Severity |
|-------|-------------|----------|
| FIORI-CAT-001 | Catalogs with public/unrestricted scope | HIGH |
| FIORI-CAT-002 | Catalogs assigned to excessive roles | MEDIUM |

### App Exposure (FIORI-APP-*)
| Check | Description | Severity |
|-------|-------------|----------|
| FIORI-APP-001 | Sensitive admin apps exposed with broad access | HIGH |

### OData Authorization (FIORI-ODATA-*)
| Check | Description | Severity |
|-------|-------------|----------|
| FIORI-ODATA-001 | OData services without authorization checks | CRITICAL |
| FIORI-ODATA-002 | Sensitive OData services with inadequate auth | HIGH |

### Spaces & Pages (FIORI-SPACE-*)
| Check | Description | Severity |
|-------|-------------|----------|
| FIORI-SPACE-001 | Spaces with public visibility | MEDIUM |

### Tile-Service Alignment (FIORI-TILE-*)
| Check | Description | Severity |
|-------|-------------|----------|
| FIORI-TILE-001 | Tiles with OData authorization mismatches | MEDIUM |

### App Usage (FIORI-USAGE-*)
| Check | Description | Severity |
|-------|-------------|----------|
| FIORI-USAGE-001 | Apps with zero usage (never launched) | LOW |

</details>

<details>
<summary><strong>🔑 Cryptographic Posture — Full Check List</strong></summary>

### TLS Configuration (CRYPTO-TLS-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CRYPTO-TLS-001 | TLS endpoints allowing deprecated protocols (1.0/1.1/SSLv3) | HIGH |
| CRYPTO-TLS-002 | Cipher suites include weak algorithms (RC4, DES, 3DES) | HIGH |
| CRYPTO-TLS-003 | HTTPS without HSTS headers | MEDIUM |

### Certificate Management (CRYPTO-CERT-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CRYPTO-CERT-001 | Expired certificates in trust store | CRITICAL |
| CRYPTO-CERT-002 | Certificates expiring within warning window | HIGH |
| CRYPTO-CERT-003 | Certificates with weak keys/algorithms | HIGH |
| CRYPTO-CERT-004 | Self-signed certificates in production | MEDIUM |

### SNC (CRYPTO-SNC-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CRYPTO-SNC-001 | SNC (Secure Network Communications) disabled | HIGH |
| CRYPTO-SNC-002 | SNC quality set to authentication only (no encryption) | MEDIUM |

### HANA Encryption (CRYPTO-HANA-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CRYPTO-HANA-001 | HANA data volume encryption disabled | HIGH |
| CRYPTO-HANA-002 | HANA log volume encryption disabled | MEDIUM |
| CRYPTO-HANA-003 | HANA using internal/default key management | MEDIUM |

### Crypto Library (CRYPTO-LIB-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CRYPTO-LIB-001 | Outdated SAP Crypto Library version | HIGH |

### PSE Health (CRYPTO-PSE-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CRYPTO-PSE-001 | PSE files with errors or expired certificates | HIGH |

### Key Management (CRYPTO-KEY-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CRYPTO-KEY-001 | Key management policy gaps (rotation, backup) | MEDIUM |

</details>

<details>
<summary><strong>🗄️ HANA Database Security — Full Check List</strong></summary>

### Privileged DB Users (HANADB-USER-*)
| Check | Description | Severity |
|-------|-------------|----------|
| HANADB-USER-001 | HANA SYSTEM superuser is still active | CRITICAL |
| HANADB-USER-002 | DB users with password-lifetime check disabled | HIGH |
| HANADB-USER-003 | Dormant HANA DB users (no logon in N+ days) | MEDIUM |

### Privilege Grants (HANADB-PRIV-*)
| Check | Description | Severity |
|-------|-------------|----------|
| HANADB-PRIV-001 | Sensitive privileges granted to PUBLIC | CRITICAL |
| HANADB-PRIV-002 | Critical system privileges granted directly to users | CRITICAL |
| HANADB-PRIV-003 | Broad system privileges granted directly to users | HIGH |
| HANADB-PRIV-004 | Sensitive privileges granted WITH ADMIN OPTION | MEDIUM |
| HANADB-PRIV-005 | Analytic-privilege bypass (`_SYS_BI_CP_ALL`) granted | CRITICAL |

### Roles & Auditing (HANADB-ROLE-* / HANADB-AUDIT-*)
| Check | Description | Severity |
|-------|-------------|----------|
| HANADB-ROLE-001 | Powerful predefined roles granted to users | HIGH |
| HANADB-AUDIT-001 | HANA database auditing is disabled | CRITICAL |
| HANADB-AUDIT-002 | Audit trail written to a CSV text file (tamperable) | HIGH |
| HANADB-AUDIT-003 | No active HANA audit policies | HIGH |
| HANADB-AUDIT-004 | Audit policies do not cover critical action groups | MEDIUM |

### Security Parameters (HANADB-PARAM-*)
| Check | Description | Severity |
|-------|-------------|----------|
| HANADB-PARAM-001 | Weak HANA password-policy parameters | HIGH |
| HANADB-PARAM-002 | Detailed connect errors exposed to clients | MEDIUM |
| HANADB-PARAM-003 | TLS not enforced for HANA SQL connections | HIGH |

*Distinct from Cryptographic Posture's `CRYPTO-HANA-*` (encryption-at-rest); this module covers users, privileges, auditing and ini parameters.*

</details>

<details>
<summary><strong>📰 SAP Security Notes / HotNews — Full Check List</strong></summary>

| Check | Description | Severity |
|-------|-------------|----------|
| HOTNEWS-000 | SAP Note implementation status not provided (no SNOTE export) | MEDIUM |
| HOTNEWS-001 | Missing HotNews (Priority 1) SAP Security Notes | CRITICAL |
| HOTNEWS-002 | Missing High-priority (Priority 2) SAP Security Notes | HIGH |
| HOTNEWS-003 | Missing notes for actively-exploited SAP vulnerabilities (CISA KEV) | CRITICAL |
| HOTNEWS-004 | Critical SAP Notes only partially implemented | HIGH |

Diffs your `applied_notes.csv` (SNOTE export) against a **built-in, verified catalog** of major SAP Security Notes since 2020 — including RECON (CVE-2020-6287), ICMAD (CVE-2022-22536), and the 2025 NetWeaver VC RCE (CVE-2025-31324). Note matching is leading-zero-insensitive; not-yet-implemented statuses fail safe to "missing". Extensible via an optional `sap_security_notes.json`.

</details>

<details>
<summary><strong>🔓 ABAP Authorization & Critical Access — Full Check List</strong></summary>

Role-content analysis of the **AGR_1251** export (role → object → field → value), attributing each risky role to the users who hold it.

| Check | Description | Severity |
|-------|-------------|----------|
| AUTH-001 | Debug & Replace authorization (runtime authorization bypass) | CRITICAL |
| AUTH-002 | Trusted-RFC logon as any user (S_RFCACL wildcard) | CRITICAL |
| AUTH-003 | Unrestricted external OS-command execution (S_LOG_COM) | CRITICAL |
| AUTH-004 | Authorization forging via role-content control objects (S_USER_AUT) | CRITICAL |
| AUTH-005 | Role allows starting any transaction (S_TCODE = *) | CRITICAL |
| AUTH-006 | Broad RFC authorization (S_RFC RFC_NAME = *) | HIGH |
| AUTH-007 | Generic table write via S_TABU_NAM (TABLE = *) | HIGH |
| AUTH-008 | Generic table maintenance via S_TABU_DIS (all / no auth group) | HIGH |
| AUTH-009 | Cross-client table maintenance (S_TABU_CLI) | HIGH |
| AUTH-010 | Arbitrary OS file access from ABAP (S_DATASET) | HIGH |
| AUTH-011 | Run-any-report authorization (S_PROGRAM) | HIGH |
| AUTH-012 | Background-job impersonation (S_BTCH_NAM BTCUNAME = *) | HIGH |
| AUTH-013 | Sensitive Basis / administration transactions in roles | HIGH |
| AUTH-014 | ABAP development change access (S_DEVELOP create/change) | HIGH |
| AUTH-015 | Global authorization-object disabling is active | MEDIUM |

</details>

<details>
<summary><strong>🔗 System Trust & Standard Users — Full Check List</strong></summary>

### Standard / Default Users (STDUSR-*)
| Check | Description | Severity |
|-------|-------------|----------|
| STDUSR-001 | SAP* kernel emergency-user auto-logon enabled | CRITICAL |
| STDUSR-002 | Standard users still have SAP default passwords | CRITICAL |
| STDUSR-003 | Standard users not locked (SAP*/DDIC/SAPCPIC/EARLYWATCH/TMSADM) | HIGH |

### System Trust (TRUST-*)
| Check | Description | Severity |
|-------|-------------|----------|
| TRUST-001 | Inbound trusted-RFC relationships (verify tier) | HIGH/MEDIUM |
| TRUST-002 | RFC self-trust enabled | HIGH |
| TRUST-003 | Trust not migrated to current security method | HIGH |
| TRUST-004 | Trusted RFC destination with a fixed logon user | HIGH |
| TRUST-005 | SAProuter route table allows wildcard host/port | HIGH |
| TRUST-006 | Message-server internal/external separation weak | HIGH |
| TRUST-007 | UCON RFC allowlist not active | HIGH |
| TRUST-008 | RFC Gateway proxy ACL (gw/prxy_info) not configured | MEDIUM |

</details>

<details>
<summary><strong>🧱 Security Baseline Parameters — Full Check List</strong></summary>

SAP Security Baseline / DSAG / CIS profile parameters the other modules don't cover (from `security_params.csv`).

| Check | Description | Severity |
|-------|-------------|----------|
| BASELINE-001 | RFC authorization check disabled (auth/rfc_authority_check = 0) | HIGH |
| BASELINE-002 | Profile-generator auth checks not active (auth/no_check_in_some_cases) | HIGH |
| BASELINE-003 | SNC accepts insecure (unencrypted) connections | HIGH |
| BASELINE-004 | SAP GUI Scripting enabled server-side (sapgui/user_scripting) | HIGH |
| BASELINE-005 | Weak legacy password hashes retained (downwards compatibility) | HIGH |
| BASELINE-006 | sapstartsrv / Host Agent web methods not protected | HIGH |
| BASELINE-007 | RFC Gateway default ACL not enforced (gw/acl_mode) | MEDIUM |
| BASELINE-008 | SSO ticket / session-cookie transport not hardened | MEDIUM |
| BASELINE-009 | Web-tier logging / error disclosure weak (ICM security log) | MEDIUM |
| BASELINE-010 | Existing passwords not forced to current policy | MEDIUM |

</details>

<details>
<summary><strong>🧩 S/4HANA & Cloud Authorization — Full Check List</strong></summary>

| Check | Description | Severity |
|-------|-------------|----------|
| S4AUTHZ-001 | Super-admin business-role template assigned in production (SAP_BR_ADMINISTRATOR*) | CRITICAL |
| S4AUTHZ-002 | Business-role restriction left 'Unrestricted' | HIGH |
| S4AUTHZ-003 | Business role bundles more than 30 business catalogs | MEDIUM |
| S4AUTHZ-004 | CDS view exposes data with authorization checking disabled | HIGH |
| S4AUTHZ-005 | OData V4 service group published without authorization | HIGH |
| S4AUTHZ-006 | Cloud Connector system mapping without principal propagation | HIGH |
| S4AUTHZ-007 | Cloud Foundry privileged platform role over-assigned | HIGH |
| S4AUTHZ-008 | Birthright role collection auto-granted to all federated users | MEDIUM |

</details>

<details>
<summary><strong>⚖️ Access Risk Analysis (SoD) — Full Risk List</strong></summary>

GRC-style **offline, permission-level** Segregation of Duties from AGR_1251 + AGR_USERS. Each risk resolves the user's transaction codes **and** authorization object/field/activity across all roles; a conflict fires only when the *maintain* activity is held (display-only access is not a false positive). Documented mitigating controls (with expiry) suppress a user/risk and are reported as residual.

### Segregation-of-Duties conflicts (25)
| Risk | Conflict | Severity |
|------|----------|----------|
| ARA-P2P-01 | Maintain Vendor Master ↔ Process/Execute Vendor Payment | CRITICAL |
| ARA-P2P-02 | Maintain Vendor Bank Details ↔ Run Automatic Payment Program | CRITICAL |
| ARA-P2P-03 | Create/Change Purchase Order ↔ Release Purchase Order | HIGH |
| ARA-P2P-04 | Create Purchase Order ↔ Post Goods Receipt | HIGH |
| ARA-P2P-05 | Create Purchase Order ↔ Post Vendor Invoice (MIRO) | HIGH |
| ARA-P2P-06 | Maintain Vendor Master ↔ Post AP (Non-PO) Vendor Invoice | CRITICAL |
| ARA-O2C-01 | Maintain Customer Master ↔ Create Sales Order | HIGH |
| ARA-O2C-02 | Maintain Customer Credit Limit ↔ Release Credit-Blocked Order | HIGH |
| ARA-O2C-03 | Post/Clear Incoming Customer Payments ↔ Maintain Customer Master | CRITICAL |
| ARA-O2C-04 | Maintain Pricing/Condition Records ↔ Create Sales Order | HIGH |
| ARA-O2C-05 | Post Billing Document ↔ Maintain Customer Master | HIGH |
| ARA-O2C-06 | Create Sales Order ↔ Release Own Credit-Blocked Order | HIGH |
| ARA-R2R-01 | Maintain G/L Account Master ↔ Post Journal Entries | CRITICAL |
| ARA-R2R-02 | Maintain G/L Account Master ↔ Open/Close Posting Periods | HIGH |
| ARA-R2R-03 | Enter/Park ↔ Post Journal Entries (four-eyes bypass) | HIGH |
| ARA-R2R-04 | Maintain Exchange Rates ↔ Post Journal Entries | HIGH |
| ARA-R2R-05 | Open/Close Posting Periods ↔ Post Journal Entries | HIGH |
| ARA-H2R-01 | Maintain HR Master Data ↔ Execute Payroll Run | CRITICAL |
| ARA-H2R-02 | Maintain Employee Bank Details ↔ Run Payroll / Generate Payments | CRITICAL |
| ARA-H2R-03 | Maintain Personnel Actions (Hire/Terminate) ↔ Maintain Time Data | HIGH |
| ARA-H2R-04 | Execute Payroll Run ↔ Post Payroll Results to Accounting | HIGH |
| ARA-BASIS-01 | User Administration ↔ Authorization/Profile Administration | CRITICAL |
| ARA-BASIS-02 | Maintain Role ↔ Assign Role to User | HIGH |
| ARA-BASIS-03 | ABAP Development ↔ Transport Release/Import to Production | HIGH |
| ARA-BASIS-04 | Maintain Table Data ↔ Administer Security Audit Log | HIGH |

### Critical access + risk profile
| Risk | Description | Severity |
|------|-------------|----------|
| ARA-CA-04 | Change Payroll Status / Delete Payroll Results (PU03/PU01) | HIGH |
| ARA-CP-05 | Maintain Own HR Master Data (P_PERNR PSIGN=I) | HIGH |
| ARA-SCORE-001 | Users concentrating ≥2 unmitigated access risks (severity-weighted) | HIGH/MEDIUM |

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
codetrans — Code & Transport Security (CODE-*)
logmon    — Logging, Monitoring & IR (LOG-*)
fiori     — Fiori & UI Layer (FIORI-*)
crypto    — Cryptographic Posture (CRYPTO-*)
hanadb    — HANA Database Security (HANADB-*)
hotnews   — SAP Security Notes / HotNews (HOTNEWS-*)
authz     — ABAP Authorization & Critical Access (AUTH-*)
systrust  — System Trust & Standard Users (TRUST-*, STDUSR-*)
baseline  — Security Baseline Parameters (BASELINE-*)
s4authz   — S/4HANA & Cloud Authorization (S4AUTHZ-*)
ara       — Access Risk Analysis / offline SoD (ARA-*)
all       — Run everything (default)
```

Examples with the newer modules:

```bash
# Offline Segregation-of-Duties + ABAP critical-access review
python sap_scanner.py --data-dir ./exports --modules ara authz

# HANA DB hardening + missing SAP Security Notes
python sap_scanner.py --data-dir ./exports --modules hanadb hotnews

# System trust, standard users, and Security Baseline parameters
python sap_scanner.py --data-dir ./exports --modules systrust baseline
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

<details>
<summary><strong>📋 Code, Transport & Change data files</strong></summary>

| File | Source | Description |
|------|--------|-------------|
| `custom_code_scan.csv` | ATC / Code Inspector / SCI | Static-analysis findings for custom ABAP |
| `code_inventory.csv` | Custom object inventory | Z/Y objects, owner, last-used |
| `transport_routes.csv` | STMS (transport routes) | TMS route/layer definitions |
| `transport_history.csv` | STMS import history | Import log per system (who/when) |
| `client_settings.csv` | SCC4 | Client role & change options |
| `change_documents.csv` | CDHDR | Change-document header records |
| `sap_modifications.csv` | SE95 / SPAU | Modifications to SAP standard objects |
| `dev_access_prod.csv` | SUIM / user-auth export | Developer access present in production |

</details>

<details>
<summary><strong>📋 Logging, Monitoring & IR data files</strong></summary>

| File | Source | Description |
|------|--------|-------------|
| `security_audit_log.csv` | SM19 / RSAU_CONFIG | Security Audit Log filters & status |
| `table_logging.csv` | DD09L | Table technical settings (change logging flag) |
| `logon_events.csv` | Logon statistics / SM20 | Logon success/failure counts per user |
| `siem_config.json` | SIEM / log-forwarding config | SIEM integration & forwarded sources |
| `log_retention.json` | Log housekeeping config | Retention & archiving settings |
| `incident_response.json` | IR readiness inventory | Incident-response process readiness |

</details>

<details>
<summary><strong>📋 Fiori & UI data files</strong></summary>

| File | Source | Description |
|------|--------|-------------|
| `fiori_catalogs.csv` | Launchpad Designer (FLPD) | Fiori catalogs & assigned roles |
| `fiori_tiles.csv` | Launchpad Designer | Tiles → target-mapping / OData service |
| `odata_auth.csv` | /IWFND/MAINT_SERVICE | OData services & authorization status |
| `fiori_spaces.json` | Spaces & Pages | Space/page visibility & role config |
| `fiori_app_usage.csv` | Usage statistics (ST03N / FLP) | App launch counts |

</details>

<details>
<summary><strong>📋 Cryptographic Posture data files</strong></summary>

| File | Source | Description |
|------|--------|-------------|
| `tls_config.csv` | ICM / Web Dispatcher SSL config | TLS protocols & cipher suites per endpoint |
| `certificate_inventory.csv` | STRUST | Certificate inventory (expiry, key size, algorithm) |
| `snc_config.csv` | RZ11 (snc/*) | SNC enablement & quality of protection |
| `hana_encryption.json` | HANA encryption config | Data/log volume encryption & key management |
| `crypto_library.csv` | CommonCryptoLib version export | SAP Crypto Library version |
| `pse_inventory.csv` | STRUST (PSE list) | PSE files & health |
| `key_management.json` | Key-management policy inventory | Rotation / backup policy status |

</details>

<details>
<summary><strong>📋 HANA Database Security data files</strong></summary>

| File | Source | Description |
|------|--------|-------------|
| `hana_db_users.csv` | HANA `SYS.USERS` | DB users (SYSTEM active, password lifetime, last connect) |
| `hana_granted_privileges.csv` | `GRANTED_PRIVILEGES` | System/object/analytic privileges & grantee (incl. PUBLIC) |
| `hana_granted_roles.csv` | `GRANTED_ROLES` | Role grants (predefined powerful roles) |
| `hana_parameters.csv` | `M_INIFILE_CONTENTS` | HANA ini parameters (password policy, TLS, error verbosity) |
| `hana_audit_policies.csv` | `AUDIT_POLICIES` | Audit policy status & covered action groups |

</details>

<details>
<summary><strong>📋 Authorization, Trust & Security-Notes data files</strong></summary>

| File | Source | Description |
|------|--------|-------------|
| `role_auth_values.csv` | AGR_1251 | Role → object/field/LOW/HIGH values (drives ABAP Authz **and** Access Risk Analysis) |
| `rfc_trust.csv` | RFCSYSACL / SMT1 | Trusted/trusting RFC relationships |
| `standard_users.csv` | RSUSR003 | Standard/default users: lock status & default-password flag |
| `saprouttab.csv` | SAProuter route table | Route permission (P/S) rules |
| `applied_notes.csv` | SNOTE / SNADM export | Implemented SAP Notes (diffed against the HotNews catalog) |
| `sap_security_notes.json` | *Optional* | Custom HotNews catalog to extend/override the built-in one |

</details>

<details>
<summary><strong>📋 S/4HANA & Cloud Authorization data files</strong></summary>

| File | Source | Description |
|------|--------|-------------|
| `business_roles.csv` | Maintain Business Roles | User ↔ business-role assignments |
| `business_role_restrictions.csv` | Business-role restrictions | Restriction fields & 'Unrestricted' access |
| `business_role_catalogs.csv` | Business-role catalogs | Business catalogs per role (sprawl) |
| `cds_views.csv` | CDS metadata / repository | `@AccessControl.authorizationCheck` per view |
| `odata_v4_services.csv` | /IWFND/V4_ADMIN | Published OData V4 service groups & authorization |
| `cf_roles.csv` | Cloud Foundry (cf CLI) | CF org/space platform-role assignments |
| `btp_role_collection_mappings.csv` | BTP Cockpit (Trust → Role Collections) | Role-collection → IdP-group mappings |

</details>

<details>
<summary><strong>📋 Access Risk Analysis (SoD) data files</strong></summary>

| File | Source | Description |
|------|--------|-------------|
| `role_auth_values.csv` | AGR_1251 | Per-role authorization object/field/value (shared with ABAP Authz) |
| `user_roles.csv` | AGR_USERS | User ↔ role assignments (shared with IAM) |
| `mitigating_controls.csv` | *Optional* (GRC / manual) | `USER, RISK_ID, CONTROL_ID, VALID_TO` — suppresses a mitigated risk |
| `ara_ruleset.json` | *Optional* | Custom SoD risks that extend/override the built-in 27-risk ruleset |

*Security Baseline Parameters (`baseline`) reuses `security_params.csv`; it needs no additional export.*

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
    "deletion_sla_days": 30,
    "hana_dormant_days": 90,
    "max_business_catalogs": 30,
    "max_cf_privileged_users": 5,
    "ara_user_risk_threshold": 2
}
```

Access Risk Analysis can also be driven by a **custom SoD ruleset** — drop an `ara_ruleset.json` into your `--data-dir` to extend or override the built-in 27-risk ruleset (entries matching a built-in `risk_id` override it; new ids are added).

---

## Project Structure

```
SAP-S4HANA-RISE-Security-Scanner/
├── sap_scanner.py                  # Main entry point & CLI orchestrator
├── modules/
│   ├── base_auditor.py             # BaseAuditor: finding()/get_config() + severity constants
│   ├── data_loader.py              # CSV/JSON loader (auto-delimiter, header normalize; 90+ file types)
│   ├── report_generator.py         # Interactive HTML dashboard (XSS-safe, weighted risk score)
│   ├── user_auth_audit.py          # USR-*            User & Authorization
│   ├── iam_advanced.py             # IAM-*            Advanced IAM (SoD, firefighter, role lifecycle)
│   ├── security_params.py          # PARAM-*          Security Parameters
│   ├── network_services.py         # NET-*            Network & Service Exposure
│   ├── rise_btp_checks.py          # RISE-*           RISE / BTP Core
│   ├── btp_cloud_surface.py        # BTP-*            BTP Cloud Attack Surface
│   ├── integration_layer.py        # INTG-*           Network & Integration Layer
│   ├── data_protection.py          # DPP-*            Data Protection & Privacy
│   ├── code_transport.py           # CODE-*           Code & Transport Security
│   ├── log_monitoring.py           # LOG-*            Logging, Monitoring & IR
│   ├── fiori_ui.py                 # FIORI-*          Fiori & UI Layer
│   ├── crypto_posture.py           # CRYPTO-*         Cryptographic Posture
│   ├── hana_db_security.py         # HANADB-*         HANA Database Security
│   ├── sap_hotnews.py              # HOTNEWS-*        SAP Security Notes / HotNews
│   ├── abap_authorizations.py      # AUTH-*           ABAP Authorization & Critical Access
│   ├── system_trust.py             # TRUST-*/STDUSR-* System Trust & Standard Users
│   ├── baseline_params.py          # BASELINE-*       Security Baseline Parameters
│   ├── s4_business_authz.py        # S4AUTHZ-*        S/4HANA & Cloud Authorization
│   └── access_risk_analysis.py     # ARA-*            Access Risk Analysis (offline SoD)
├── sample_data/                    # 90 crafted demo exports (trigger every check)
├── tests/
│   ├── conftest.py                 # pytest fixtures (DataLoader over sample_data)
│   └── test_scanner.py             # per-module + full-pipeline + CLI tests
├── docs/
│   ├── banner.svg                  # README banner
│   ├── EXPORT_GUIDE.md             # how to export each data file from SAP
│   └── CHECKS_REFERENCE.md         # complete per-check reference
├── .github/workflows/tests.yml     # CI: pytest matrix (Python 3.8–3.12) + scanner smoke run
├── requirements-dev.txt            # dev-only dependency: pytest
├── CLAUDE.md                       # contributor / AI-assistant guidance
├── CONTRIBUTING.md
├── .gitignore
├── LICENSE
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
- [x] Custom ABAP code security scanning (SQL injection, hardcoded creds, dangerous statements)
- [x] ATC/code inspector finding analysis
- [x] Transport workflow enforcement (approval, SoD, route integrity)
- [x] Client configuration security (SCC4)
- [x] SAP standard modification auditing
- [x] Dead/unreferenced custom code detection
- [x] Security Audit Log (SM20/SM21) configuration & coverage
- [x] SIEM integration & log forwarding validation
- [x] Log retention & archiving compliance
- [x] Table logging for critical tables
- [x] Logon anomaly / brute-force detection
- [x] Incident response readiness assessment
- [x] Fiori catalog/tile authorization review
- [x] OData service-level authorization audit
- [x] Fiori spaces/pages role-based configuration
- [x] TLS configuration depth (protocols, ciphers, HSTS)
- [x] Certificate inventory & expiry management
- [x] SNC configuration & quality of protection
- [x] HANA encryption at rest & log encryption
- [x] CommonCryptoLib version auditing
- [x] PSE health & key management policies
- [x] HANA database security (privileged DB users, PUBLIC & system-privilege grants, DB auditing, ini parameters)
- [x] SAP Security Notes / HotNews gap analysis (missing P1/P2 notes since 2020, CISA-KEV exploited CVEs)
- [x] ABAP authorization & critical-access analysis (AGR_1251 role content: Debug&Replace, S_RFCACL, S_TABU_*, S_PROGRAM, …)
- [x] System trust & standard users (trusted RFC, SAProuter, message server, SAP*/DDIC/default passwords)
- [x] SAP Security Baseline profile parameters (auth engine, SNC fallback, GUI scripting, gateway ACL, ICM log)
- [x] S/4HANA & cloud authorization (business roles, CDS auth-check, OData V4, Cloud Connector principal propagation, CF roles)
- [x] Offline permission-level Segregation of Duties / Access Risk Analysis (GRC-style ruleset, mitigating controls, user risk score)
- [ ] Scan comparison mode (diff two scans)
- [ ] CI/CD integration with exit codes
- [ ] PDF report export

---

## Requirements

**Python 3.8+** — No external packages required to run the scanner.

## Testing

The scanner has a `pytest` suite that runs every audit module against the bundled
`sample_data` (crafted to trigger each check) and validates the full pipeline —
no SAP system needed. It checks that each module fires, handles empty input
without crashing, honours the finding contract (field types / severities — this
catches bugs like a description accidentally being a tuple), has no cross-module
check-id collisions, renders the HTML report, and runs end-to-end via the CLI.

```bash
python -m pip install -r requirements-dev.txt   # just pytest
python -m pytest -q
```

CI (GitHub Actions, `.github/workflows/tests.yml`) runs the suite on Python
3.8–3.12 plus a full `sap_scanner.py` smoke run on every push and pull request.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Disclaimer

This tool is for **authorized security assessments only**. The scanner performs offline analysis of exported data and does not connect to or modify any SAP system.

## License

MIT License — see [LICENSE](LICENSE).
