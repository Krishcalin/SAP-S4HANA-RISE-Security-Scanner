# Check reference

<!-- GENERATED FILE — DO NOT EDIT BY HAND.
     Produced by tools/build_checks_reference.py from the code itself.
     CI re-runs the generator and fails if this file disagrees, so an edit
     here is reverted by the next build rather than merged. Change the
     check, then regenerate:  python -m tools.build_checks_reference -->

**365** check ids are written as literals in `modules/`, across **30** modules. A further **255** are built at runtime from shipped rule tables, giving **620** in total.

## What this file does not claim

**42 of the 365 titles and 15 of the severities are not fixed.** A title is often an f-string naming the object it found, and a severity is often conditional on what was found — a locked account and an unlocked one are the same check at different severities.

Those are rendered as *varies*, with the template where one can be shown. They are **not** resolved to one example. The previous hand-written version of this file froze one branch as fact and ended up carrying eleven wrong titles and four wrong severities; a generator repeating that mistake would carry a machine's authority while doing it.

A check's **identity** is its id. Severity is a judgement about a particular finding and is not part of it.

## Checks by module

### `abap_authorizations` — 16 checks

| Check | Severity | Title |
|---|---|---|
| `AUTH-001` | CRITICAL | Debug & Replace authorization (runtime authorization bypass) |
| `AUTH-002` | CRITICAL | Trusted-RFC logon as any user (S_RFCACL wildcard) |
| `AUTH-003` | CRITICAL | Unrestricted external OS-command execution (S_LOG_COM) |
| `AUTH-004` | CRITICAL | Authorization forging via role-content control objects |
| `AUTH-005` | CRITICAL | Role allows starting any transaction (S_TCODE = *) |
| `AUTH-006` | HIGH | Broad RFC authorization (S_RFC RFC_NAME = *) |
| `AUTH-007` | HIGH | Generic table write via S_TABU_NAM (TABLE = *) |
| `AUTH-008` | HIGH | Generic table maintenance via S_TABU_DIS (all / no auth group) |
| `AUTH-009` | HIGH | Cross-client table maintenance (S_TABU_CLI) |
| `AUTH-010` | HIGH | Arbitrary OS file access from ABAP (S_DATASET) |
| `AUTH-011` | HIGH | Run-any-report authorization (S_PROGRAM) |
| `AUTH-012` | HIGH | Background-job impersonation (S_BTCH_NAM BTCUNAME = *) |
| `AUTH-013` | HIGH | Sensitive Basis / administration transactions in roles |
| `AUTH-014` | HIGH | ABAP development change access (S_DEVELOP create/change) |
| `AUTH-015` | MEDIUM | Global authorization-object disabling is active |
| `AUTH-016` | HIGH | Unrestricted destination authorization (S_ICF ICF_FIELD=DEST, ICF_VALUE=*) |

### `abap_sast` — 5 checks

Category: Code & Transport Security

| Check | Severity | Title |
|---|---|---|
| `ABAP-COV-001` | *varies* | ABAP source scan was requested but the source path is not readable |
| `ABAP-COV-002` | *varies* | ABAP source scan read no source files |
| `ABAP-COV-003` | *varies* | Some source files could not be read and were not scanned |
| `ABAP-LEX-001` | INFO | Source the scanner could not lex reliably |
| `ABAP-NOSEC-001` | INFO | Findings suppressed by #NOSEC markers in source |

### `access_risk_analysis` — 1 check

| Check | Severity | Title |
|---|---|---|
| `ARA-SCORE-001` | *varies* — HIGH or MEDIUM | Users concentrating multiple access risks (SoD risk profile) |

### `atc_import` — 2 checks

Category: Code & Transport Security

| Check | Severity | Title |
|---|---|---|
| `ATC-GOV-001` | HIGH | Custom code security scanning is not evidenced |
| `ATC-GOV-002` | INFO | ATC export rows not classified as security findings |

### `baseline_params` — 14 checks

| Check | Severity | Title |
|---|---|---|
| `BASELINE-000` | INFO | No profile parameter export — baseline parameters not assessed |
| `BASELINE-001` | HIGH | RFC authorization check disabled (auth/rfc_authority_check) |
| `BASELINE-002` | HIGH | Profile-generator authorization checks not active (auth/no_check_in_some_cases) |
| `BASELINE-003` | HIGH | SNC accepts insecure (unencrypted) connections |
| `BASELINE-004` | HIGH | SAP GUI Scripting enabled server-side (sapgui/user_scripting) |
| `BASELINE-005` | HIGH | Weak legacy password hashes retained (login/password_downwards_compatibility) |
| `BASELINE-006` | HIGH | sapstartsrv / Host Agent web methods not protected (service/protectedwebmethods) |
| `BASELINE-007` | MEDIUM | RFC Gateway default ACL not enforced (gw/acl_mode) |
| `BASELINE-008` | MEDIUM | SSO ticket / session-cookie transport not hardened |
| `BASELINE-009` | MEDIUM | Web-tier logging / error disclosure weak (ICM) |
| `BASELINE-010` | MEDIUM | Existing passwords not forced to current policy (login/password_compliance_to_current_policy) |
| `BASELINE-011` | *varies* | Weak password hash algorithm (login/password_hash_algorithm) |
| `BASELINE-012` | HIGH | RFC callback protection not enforced (rfc/callback_security_method) |
| `BASELINE-SNC-DEFERRED` | INFO | SNC insecure-fallback parameters deferred to the SNC family model |

### `basis_job_command` — 11 checks

| Check | Severity | Title |
|---|---|---|
| `JOBCMD-CMD-001` | CRITICAL | External OS command wraps a shell / interpreter |
| `JOBCMD-CMD-002` | HIGH | External OS command allows runtime additional parameters (ADDPAR) |
| `JOBCMD-CMD-003` | HIGH | External OS command resolves to an unqualified or writable path |
| `JOBCMD-CMD-004` | MEDIUM | Destructive / exfiltration OS command defined as a standing command |
| `JOBCMD-CMD-005` | LOW | External OS command not bound to a specific operating system |
| `JOBCMD-JOB-001` | CRITICAL | Armed background job runs under SAP*/DDIC or a SAP_ALL step user |
| `JOBCMD-JOB-002` | HIGH | Background job step executes an external OS command / program |
| `JOBCMD-JOB-003` | HIGH | Job runs RSBDCOS0 or unreviewed custom code under a privileged user |
| `JOBCMD-JOB-004` | MEDIUM | Armed job step user is deleted, locked, expired, or a dialog user |
| `JOBCMD-JOB-005` | MEDIUM | Background job step user differs from scheduler (identity borrowing) |
| `JOBCMD-JOB-001B` | HIGH | Armed background job runs under a standard/technical step user |

### `btp_cloud_surface` — 35 checks

Category: BTP Cloud Attack Surface

| Check | Severity | Title |
|---|---|---|
| `BTP-CC-001` | CRITICAL | Cloud Connector backends with wildcard resource mappings |
| `BTP-CC-002` | HIGH | High-risk backend services exposed via Cloud Connector |
| `BTP-CC-003` | MEDIUM | *varies* — Excessive Cloud Connector backend systems (…) |
| `BTP-CC-004` | HIGH | Cloud Connector with unrestricted access control lists |
| `BTP-CC-005` | HIGH | Cloud Connector certificates expiring or expired |
| `BTP-CC-006` | HIGH | Cloud Connector certificates with weak cryptography |
| `BTP-CC-007` | MEDIUM | *varies* — Stale Cloud Connector backends (…+ days unused) |
| `BTP-CC-008` | *varies* — MEDIUM | *varies* — Cloud Connector … is vulnerable to CVE-2024-25642 |
| `BTP-CPI-001` | HIGH | *varies* — CPI credentials not rotated in …+ days |
| `BTP-CPI-002` | MEDIUM | CPI credentials using basic/plaintext authentication |
| `BTP-CPI-003` | CRITICAL | CPI iFlows with hardcoded/embedded credentials |
| `BTP-CPI-004` | HIGH | CPI iFlows with no sender authentication |
| `BTP-CPI-005` | HIGH | CPI iFlows using unencrypted HTTP endpoints |
| `BTP-DST-001` | HIGH | BTP destinations with stored credentials |
| `BTP-DST-002` | CRITICAL | BTP destinations with TLS verification disabled |
| `BTP-DST-003` | MEDIUM | BTP destinations with proxy type mismatch |
| `BTP-DST-004` | LOW | Stale BTP destinations (not modified in 365+ days) |
| `BTP-EM-001` | HIGH | Event Mesh queues with wildcard topic subscriptions |
| `BTP-EM-002` | HIGH | Event Mesh queues without access control policies |
| `BTP-EM-003` | MEDIUM | Event Mesh queues subscribing to foreign namespaces |
| `BTP-ENT-001` | LOW | BTP services entitled but never provisioned |
| `BTP-ENT-002` | MEDIUM | Security-critical BTP services entitled but not provisioned |
| `BTP-GOV-001` | HIGH | BTP subaccounts without audit logging |
| `BTP-GOV-002` | MEDIUM | BTP subaccounts using default SAP IDP only |
| `BTP-IAS-001` | MEDIUM | IAS applications without conditional authentication rules |
| `BTP-IAS-002` | MEDIUM | IAS applications without IP-based access restrictions |
| `BTP-IAS-003` | HIGH | IAS applications without multi-factor authentication |
| `BTP-IAS-004` | *varies* | IAS password policy for local users is weak |
| `BTP-IAS-005` | HIGH | Corporate IdP not enforced — local password fallback allowed |
| `BTP-MIG-001` | MEDIUM | Applications still using XSUAA authentication (not migrated to IAS) |
| `BTP-NET-001` | MEDIUM | BTP services using public internet endpoints |
| `BTP-NET-002` | HIGH | Critical BTP services without Private Link |
| `BTP-SB-001` | HIGH | *varies* — Service bindings not rotated in …+ days |
| `BTP-SB-002` | HIGH | Service bindings with admin-level scopes |
| `BTP-SB-003` | MEDIUM | Orphaned service bindings (deleted/failed instances) |

### `code_inventory_report` — 5 checks

| Check | Severity | Title |
|---|---|---|
| `CODE-INV-001` | INFO | Custom-code estate inventory |
| `CODE-INV-002` | LOW | Custom code that nothing reaches is still installed |
| `CODE-INV-003` | INFO | Custom code with no recent recorded execution |
| `CODE-INV-004` | INFO | Custom code whose reachability could not be determined |
| `CODE-INV-005` | INFO | Custom-code inventory carries no usable execution data |

### `code_transport` — 22 checks

Category: Code & Transport Security

| Check | Severity | Title |
|---|---|---|
| `CODE-ATC-001` | CRITICAL | *varies* — Unresolved critical ATC findings (…) |
| `CODE-ATC-002` | HIGH | *varies* — Unresolved high-severity ATC findings (…) |
| `CODE-CHG-001` | MEDIUM | Critical object types without change documents |
| `CODE-CHG-002` | MEDIUM | Change documents with empty or system user attribution |
| `CODE-CLIENT-001` | CRITICAL | Production client allows changes (not locked) |
| `CODE-DEAD-001` | MEDIUM | *varies* — Excessive unreferenced custom code (… objects) |
| `CODE-DEAD-002` | LOW | Custom code objects without designated owner |
| `CODE-DEV-001` | HIGH | *varies* — Users with development access in production |
| `CODE-INJ-001` | CRITICAL | SQL injection patterns detected in custom code |
| `CODE-INJ-002` | HIGH | Custom code missing authority checks |
| `CODE-INJ-003` | CRITICAL | Hardcoded credentials detected in custom code |
| `CODE-MOD-001` | MEDIUM | Unregistered SAP standard modifications |
| `CODE-MOD-002` | CRITICAL | Modifications to SAP security-critical standard programs |
| `CODE-MOD-003` | LOW | Stale SAP modifications (5+ years old) |
| `CODE-STMT-001` | HIGH | *varies* — Dangerous ABAP statement: … |
| `CODE-SYSCHG-001` | CRITICAL | SE06 global system change option is 'Modifiable' (production changeable) |
| `CODE-SYSCHG-002` | HIGH | Individual namespaces / software components left modifiable in production |
| `CODE-TMS-001` | CRITICAL | Transport routes allow direct dev-to-production delivery |
| `CODE-TMS-002` | HIGH | Production transport imports without approval |
| `CODE-TMS-003` | HIGH | Transports released and imported by the same user |
| `CODE-TMS-004` | MEDIUM | Transport imports outside normal change windows (weekends) |
| `CODE-TMS-005` | CRITICAL | Transports imported into production directly from development |

### `crypto_posture` — 18 checks

Category: Cryptographic Posture

| Check | Severity | Title |
|---|---|---|
| `CRYPTO-CERT-001` | CRITICAL | Expired certificates in system trust store |
| `CRYPTO-CERT-002` | HIGH | *varies* — Certificates expiring within … days |
| `CRYPTO-CERT-003` | HIGH | Certificates with weak key sizes or algorithms |
| `CRYPTO-CERT-004` | MEDIUM | Self-signed certificates used in production context |
| `CRYPTO-HANA-001` | HIGH | HANA data volume encryption is disabled |
| `CRYPTO-HANA-002` | MEDIUM | HANA log volume encryption is disabled |
| `CRYPTO-HANA-003` | MEDIUM | HANA encryption uses internal/default root key management |
| `CRYPTO-HANA-004` | HIGH | HANA backup encryption is disabled |
| `CRYPTO-HANA-005` | HIGH | HANA system replication is not TLS-encrypted |
| `CRYPTO-KEY-001` | MEDIUM | Key management policy gaps |
| `CRYPTO-LIB-001` | HIGH | *varies* — Outdated SAP Crypto Library: … |
| `CRYPTO-PSE-001` | HIGH | PSE files with errors or expired certificates |
| `CRYPTO-SNC-001` | HIGH | *varies* — SNC (Secure Network Communications) is disabled |
| `CRYPTO-SNC-002` | MEDIUM | SNC quality of protection set to authentication only |
| `CRYPTO-SNC-DEFERRED` | INFO | SNC parameter checks deferred to the SNC family model |
| `CRYPTO-TLS-001` | HIGH | TLS endpoints allowing deprecated protocol versions |
| `CRYPTO-TLS-002` | HIGH | TLS cipher suites include weak algorithms |
| `CRYPTO-TLS-003` | MEDIUM | HTTPS endpoints without HSTS (Strict Transport Security) |

### `data_protection` — 21 checks

Category: Data Protection & Privacy

| Check | Severity | Title |
|---|---|---|
| `DPP-DEL-001` | CRITICAL | *varies* — Data subject requests overdue (>… day SLA) |
| `DPP-DEL-002` | HIGH | Data subject requests marked complete but incomplete |
| `DPP-DEL-003` | MEDIUM | Data subject requests without documentation |
| `DPP-FIELD-001` | HIGH | Sensitive classified fields without Read Access Logging |
| `DPP-FIELD-002` | MEDIUM | Sensitive fields not masked in non-production |
| `DPP-FIELD-003` | MEDIUM | Known sensitive fields missing from data classification inventory |
| `DPP-ILM-001` | MEDIUM | *varies* — ILM policies with retention exceeding … years |
| `DPP-ILM-002` | MEDIUM | ILM policies without automatic data destruction |
| `DPP-ILM-003` | HIGH | ILM policies without end-of-purpose definitions |
| `DPP-ILM-004` | HIGH | Personal data tables without ILM retention policies |
| `DPP-LAND-001` | MEDIUM | Systems without data classification assignment |
| `DPP-MASK-001` | CRITICAL | Non-production systems without PII data masking |
| `DPP-MASK-002` | CRITICAL | Non-production systems identified as production copies without masking |
| `DPP-POP-001` | HIGH | Purposes of processing without documented legal basis |
| `DPP-POP-002` | MEDIUM | Expired purposes of processing still active |
| `DPP-RAL-001` | *varies* — HIGH | *varies* — Read Access Logging has no active configurations |
| `DPP-RAL-002` | HIGH | Read Access Logging missing coverage for key channels |
| `DPP-RAL-003` | MEDIUM | *varies* — RAL log channels with retention below … days |
| `DPP-RES-001` | CRITICAL | Cross-border data transfers without legal safeguards |
| `DPP-RES-002` | HIGH | Special category personal data in cross-border transfers |
| `DPP-TOOLKIT-001` | HIGH | DPP toolkit features not configured |

### `ecs_config_items` — 5 checks

Category: ABAP Authorization & Critical Access, Cryptographic Posture, Security Audit Log Review, System Trust & Standard Users

| Check | Severity | Title |
|---|---|---|
| `AUTH-ECS-000` | INFO | Table authorization group assignments could not be assessed from this export |
| `AUTH-ECS-001` | HIGH | Password-hash tables are not protected by authorization group SPWD |
| `CRYPTO-ECS-001` | HIGH | Database PSE table SSF_PSE_D is not protected by authorization group SPSE |
| `LREV-ECS-001` | HIGH | Security Audit Log filters are bound to named users rather than all users |
| `STDUSR-ECS-001` | MEDIUM | Obsolete standard client(s) still present in the system |

### `financial_controls` — 6 checks

| Check | Severity | Title |
|---|---|---|
| `FIN-DOC-001` | HIGH | Payment-relevant document fields may be changed after posting/clearing |
| `FIN-NR-001` | MEDIUM | Financial document number ranges are buffered (completeness gaps) |
| `FIN-PP-001` | HIGH | Posting periods open too wide with no authorization-group control |
| `FIN-SF-001` | HIGH | Payment-relevant master-data fields are not under dual control (T055F) |
| `FIN-TOL-001` | HIGH | FI tolerance groups have effectively unlimited posting limits |
| `FIN-TOL-002` | MEDIUM | No FI tolerance groups defined (no posting limits) |

### `fiori_ui` — 8 checks

Category: Fiori & UI Layer

| Check | Severity | Title |
|---|---|---|
| `FIORI-APP-001` | HIGH | Sensitive admin Fiori apps exposed with broad access |
| `FIORI-CAT-001` | HIGH | Fiori catalogs with public/unrestricted scope |
| `FIORI-CAT-002` | MEDIUM | *varies* — Fiori catalogs assigned to excessive roles (>…) |
| `FIORI-ODATA-001` | CRITICAL | OData services without authorization checks |
| `FIORI-ODATA-002` | HIGH | Sensitive OData services with inadequate authorization |
| `FIORI-SPACE-001` | MEDIUM | Fiori spaces with public visibility |
| `FIORI-TILE-001` | MEDIUM | Fiori tiles with OData authorization mismatches |
| `FIORI-USAGE-001` | LOW | Fiori apps with zero usage (never launched) |

### `grc_access_control` — 13 checks

| Check | Severity | Title |
|---|---|---|
| `GRC-ARA-001` | HIGH | Users carry open SoD violations with no active mitigating control |
| `GRC-ARM-001` | HIGH | Access provisioned without an approver (workflow bypass) |
| `GRC-ARM-002` | MEDIUM | Access provisioned without a risk (SoD) analysis |
| `GRC-ARM-001B` | HIGH | Access request self-approved / self-provisioned |
| `GRC-FF-001` | HIGH | Firefighter (emergency-access) sessions used without a documented reason |
| `GRC-FF-002` | HIGH | Firefighter IDs without an assigned owner and controller |
| `GRC-FF-001B` | HIGH | Firefighter session logs not reviewed / approved |
| `GRC-FF-002B` | HIGH | Firefighter owner also acts as controller (self-monitoring) |
| `GRC-FF-002C` | MEDIUM | Firefighter log review / delivery disabled |
| `GRC-MIT-001` | MEDIUM | Mitigating controls are expired, owner-less or unmonitored |
| `GRC-RS-001` | HIGH | Critical SoD risks are disabled in the rule set |
| `GRC-RS-002` | MEDIUM | SoD risks without an assigned risk owner |
| `GRC-RS-003` | MEDIUM | SoD rule set appears incomplete / never tailored |

### `hana_db_security` — 19 checks

| Check | Severity | Title |
|---|---|---|
| `HANADB-AUDIT-001` | CRITICAL | HANA database auditing is disabled |
| `HANADB-AUDIT-002` | HIGH | Audit trail written to CSV text file (tamperable) |
| `HANADB-AUDIT-003` | HIGH | No active HANA audit policies |
| `HANADB-AUDIT-004` | MEDIUM | Audit policies do not cover critical action groups |
| `HANADB-PARAM-001` | HIGH | Weak HANA password-policy parameters |
| `HANADB-PARAM-002` | MEDIUM | Detailed connect errors exposed to clients |
| `HANADB-PARAM-003` | HIGH | TLS not enforced for HANA SQL connections |
| `HANADB-PARAM-004` | HIGH | HANA log_mode = overwrite (no point-in-time recovery) |
| `HANADB-PARAM-005` | MEDIUM | HANA cross-database (MDC) access is enabled |
| `HANADB-PRIV-001` | CRITICAL | Sensitive privileges granted to PUBLIC |
| `HANADB-PRIV-002` | CRITICAL | Critical system privileges granted directly to users |
| `HANADB-PRIV-003` | HIGH | Broad system privileges granted directly to users |
| `HANADB-PRIV-004` | MEDIUM | Sensitive privileges granted WITH ADMIN OPTION |
| `HANADB-PRIV-005` | CRITICAL | Analytic-privilege bypass (_SYS_BI_CP_ALL) granted |
| `HANADB-PRIV-006` | HIGH | Debug privileges (DEBUG / ATTACH DEBUGGER) granted to users |
| `HANADB-ROLE-001` | HIGH | Powerful predefined roles granted to users |
| `HANADB-USER-001` | CRITICAL | *varies* |
| `HANADB-USER-002` | HIGH | DB users with password lifetime check disabled |
| `HANADB-USER-003` | MEDIUM | *varies* — Dormant HANA DB users (no logon in …+ days) |

### `iam_advanced` — 30 checks

Category: Advanced IAM, Identity & Access Management

| Check | Severity | Title |
|---|---|---|
| `IAM-EXP-001` | MEDIUM | Role assignments without expiry dates |
| `IAM-EXP-002` | LOW | Expired role assignments still present in user master |
| `IAM-EXP-003` | MEDIUM | *varies* — Role assignments with excessive validity (>…d) |
| `IAM-FED-001` | MEDIUM | Several identity providers can authenticate users into one subaccount |
| `IAM-FED-002` | HIGH | *varies* — Trust configuration admits any user of the identity provider: … |
| `IAM-FED-003` | *varies* | *varies* — Identity federation certificate …: … |
| `IAM-FED-004` | MEDIUM | Federated identities are auto-created with no evidence of de-provisioning |
| `IAM-FEDCOV-002` | INFO | Trust user admission could not be assessed from this export |
| `IAM-FEDCOV-003` | INFO | Identity federation certificate expiry could not be assessed from this export |
| `IAM-FF-000` | HIGH | Firefighter accounts detected but no usage log provided |
| `IAM-FF-001` | HIGH | *varies* — Firefighter sessions exceeding …h duration |
| `IAM-FF-002` | HIGH | Firefighter sessions without documented justification |
| `IAM-FF-003` | CRITICAL | Firefighter sessions not reviewed by controller |
| `IAM-FF-004` | CRITICAL | Firefighter sessions reviewed by the same user who initiated them |
| `IAM-FF-005` | MEDIUM | *varies* — Users with excessive firefighter usage (>… sessions) |
| `IAM-ORPH-001` | MEDIUM | Users assigned to non-existent or deleted roles |
| `IAM-PRIV-001` | CRITICAL | Users with privilege escalation capability |
| `IAM-REF-001` | HIGH | Dialog users used as reference users |
| `IAM-REV-001` | HIGH | Overdue access review campaigns |
| `IAM-REV-002` | MEDIUM | Access reviews marked complete but with incomplete coverage |
| `IAM-REV-003` | MEDIUM | Access review campaigns without assigned reviewer |
| `IAM-ROLE-001` | LOW | Custom roles without descriptions |
| `IAM-ROLE-002` | MEDIUM | Custom roles without designated owners |
| `IAM-ROLE-003` | LOW | Custom roles with no menu/transaction assignments |
| `IAM-SOD-000` | HIGH | Insufficient data for SoD conflict analysis |
| `IAM-SOD-DEFERRED` | INFO | Transaction-level SoD deferred to permission-level analysis |
| `IAM-USRGRP-001` | LOW | Active users in default/unassigned user groups |
| `IAM-XID-001` | MEDIUM | BTP users without corresponding S/4HANA account |
| `IAM-XID-002` | HIGH | S/4HANA locked users still active in BTP |
| `IAM-XID-003` | HIGH | BTP subaccount users with administrative role collections |

### `integration_layer` — 32 checks

Category: Network & Integration Layer

| Check | Severity | Title |
|---|---|---|
| `INTG-APIM-001` | HIGH | API proxies missing required security policies |
| `INTG-APIM-002` | CRITICAL | API proxies without authentication policies |
| `INTG-APIM-003` | HIGH | API proxies allowing unencrypted HTTP traffic |
| `INTG-APIM-004` | HIGH | API proxies allowing deprecated TLS versions |
| `INTG-APIM-005` | CRITICAL | API proxies operating in pass-through mode (zero policies) |
| `INTG-CPI-DS-001` | HIGH | CPI data stores with sensitive data names but no encryption |
| `INTG-CPI-DS-002` | MEDIUM | CPI global variables with potentially sensitive names |
| `INTG-CPI-DS-003` | LOW | CPI data stores with excessive entries |
| `INTG-GW-001` | CRITICAL | Gateway secinfo has overly permissive permit rules |
| `INTG-GW-002` | HIGH | Gateway secinfo missing deny-all default rule |
| `INTG-GW-003` | HIGH | Gateway secinfo permits external program execution |
| `INTG-GW-004` | CRITICAL | Gateway reginfo permits unrestricted RFC server registration |
| `INTG-GW-005` | HIGH | Gateway reginfo missing deny-all default rule |
| `INTG-IDOC-001` | HIGH | IDOC ports without encryption (no TLS/SNC) |
| `INTG-IDOC-002` | MEDIUM | IDOC file ports with insecure directory paths |
| `INTG-IDOC-003` | HIGH | IDOC partner profiles with wildcard message types |
| `INTG-IDOC-004` | MEDIUM | IDOC partner profiles configured for sensitive message types |
| `INTG-MON-001` | HIGH | Missing integration monitoring alert rules |
| `INTG-MON-002` | MEDIUM | Integration events not forwarded to SIEM |
| `INTG-OAUTH-001` | HIGH | OAuth clients with admin-level or wildcard scopes |
| `INTG-OAUTH-002` | HIGH | OAuth clients using deprecated grant types (password/implicit) |
| `INTG-OAUTH-003` | MEDIUM | *varies* — OAuth clients unused for …+ days |
| `INTG-TOPO-001` | HIGH | Integration connections without encryption |
| `INTG-TOPO-002` | MEDIUM | Integration hub systems with excessive connections |
| `INTG-TOPO-003` | MEDIUM | Integration connections to deprecated/legacy systems |
| `INTG-WH-001` | HIGH | Webhook callbacks using unencrypted HTTP |
| `INTG-WH-002` | HIGH | Webhooks without signature/HMAC verification |
| `INTG-WH-003` | MEDIUM | Webhooks delivering events to external/third-party endpoints |
| `INTG-WH-004` | LOW | Stale webhook registrations with no recent activity |
| `INTG-WS-001` | HIGH | High-risk BAPIs/RFCs exposed as web services |
| `INTG-WS-002` | MEDIUM | *varies* — Excessive active web service endpoints (…) |
| `INTG-WS-003` | CRITICAL | Web service endpoints with weak/no authentication |

### `log_monitoring` — 14 checks

Category: Logging, Monitoring & IR

| Check | Severity | Title |
|---|---|---|
| `LOG-AUD-001` | *varies* — HIGH | *varies* — Security Audit Log has no active filters |
| `LOG-AUD-002` | HIGH | No static audit profile configured |
| `LOG-AUD-003` | HIGH | Security Audit Log missing event coverage |
| `LOG-AUD-010` | HIGH | Security Audit Log is not enabled (rsau/enable = 0) |
| `LOG-AUD-011` | MEDIUM | Security Audit Log integrity protection not active (rsau/integrity = 0) |
| `LOG-IR-001` | MEDIUM | Incident response readiness gaps |
| `LOG-LOGON-001` | CRITICAL | Potential brute-force attack patterns detected |
| `LOG-LOGON-002` | MEDIUM | Accounts with excessive logon failures |
| `LOG-RET-001` | MEDIUM | *varies* — Log retention below …-day minimum |
| `LOG-RET-002` | LOW | Security logs without archiving configured |
| `LOG-SIEM-001` | HIGH | *varies* — No SIEM integration configuration found |
| `LOG-SIEM-002` | MEDIUM | SIEM missing critical log source forwarding |
| `LOG-TBL-001` | HIGH | Critical tables without change logging enabled |
| `LOG-TBL-010` | HIGH | Table change logging master switch off (rec/client not set) |

### `log_review` — 15 checks

| Check | Severity | Title |
|---|---|---|
| `LREV-FLT-001` | HIGH | *varies* |
| `LREV-FLT-002` | HIGH | Audit filters do not cover every client in the system |
| `LREV-FLT-003` | MEDIUM | Event class recorded only by a dynamic filter — coverage is lost at restart |
| `LREV-PAT-001` | HIGH | Privileged dialog logons outside business hours in the reviewed window |
| `LREV-PAT-002` | CRITICAL | Failed logon run followed by a successful logon in the reviewed window |
| `LREV-PAT-003` | HIGH | SAP-delivered default accounts were active in the reviewed window |
| `LREV-PAT-004` | HIGH | Debug activity recorded in the reviewed window |
| `LREV-PAT-005` | MEDIUM | High-volume direct table access in the reviewed window |
| `LREV-PAT-006` | CRITICAL | The audit configuration itself was changed during the reviewed window |
| `LREV-PAT-007` | MEDIUM | Privileged logons from terminals that barely appear in the reviewed window |
| `LREV-SRC-001` | MEDIUM | No Security Audit Log event extract supplied — no window could be reviewed |
| `LREV-SRC-002` | MEDIUM | Audit log extract carries no usable event timestamp |
| `LREV-SRC-003` | MEDIUM | Audit filter configuration not supplied alongside the event extract |
| `LREV-WIN-001` | LOW | Reviewed window is too short to be representative |
| `LREV-WIN-002` | HIGH | *varies* |

### `network_services` — 8 checks

Category: Audit Logging, Change Management, Network & Service Exposure

| Check | Severity | Title |
|---|---|---|
| `NET-001` | HIGH | RFC destinations with stored credentials |
| `NET-002` | MEDIUM | RFC destinations to external/non-RFC hosts |
| `NET-003` | HIGH | RFC destinations without SNC encryption |
| `NET-004` | HIGH | High-risk ICF services are active |
| `NET-005` | CRITICAL | Active ICF services without authentication |
| `NET-006` | MEDIUM | Open/unreleased transports in production |
| `NET-007` | HIGH | Transports with debug/replace indicators |
| `NET-008` | CRITICAL | No active security audit filters configured |

### `resilience_posture` — 9 checks

| Check | Severity | Title |
|---|---|---|
| `RES-BCK-001` | HIGH | No recent successful full data backup recorded in the supplied catalogue |
| `RES-BCK-002` | MEDIUM | Backup runs are failing repeatedly despite a recorded success |
| `RES-BCK-003` | HIGH | No successful log backup recorded, so no point-in-time recovery evidence |
| `RES-BCK-004` | INFO | Backup recency could not be assessed from the supplied catalogue |
| `RES-DR-001` | MEDIUM | Recovery test evidence is missing, failed or stale |
| `RES-DR-002` | INFO | Backup evidence supplied without any recovery-test evidence |
| `RES-DR-003` | MEDIUM | Recorded recovery test did not meet its stated RTO / RPO target |
| `RES-EVD-001` | INFO | Part of the resilience evidence could not be read by this scan |
| `RES-JOB-001` | MEDIUM | Recovery-relevant background job recorded as aborted |

### `rise_btp_checks` — 7 checks

Category: RISE / BTP Security

| Check | Severity | Title |
|---|---|---|
| `RISE-001` | MEDIUM | *varies* — Default SAP IDP trust still active: … |
| `RISE-002` | MEDIUM | *varies* — Automatic shadow user creation enabled for … |
| `RISE-003` | MEDIUM | Communication arrangements with excessive service scope |
| `RISE-004` | CRITICAL | Communication arrangements with weak/no authentication |
| `RISE-005` | HIGH | Sensitive APIs/OData services exposed |
| `RISE-006` | MEDIUM | Communication users shared across many arrangements |
| `RISE-007` | HIGH | API endpoints with weak or no authentication |

### `role_governance` — 3 checks

| Check | Severity | Title |
|---|---|---|
| `RG-DRV-001` | MEDIUM | Derived roles have authorizations that drifted from their parent |
| `RG-GEN-001` | MEDIUM | *varies* — Roles with no generated authorization profile are assigned to users or Roles with no generated authorization profile |
| `RG-SU24-001` | MEDIUM | Custom transactions without maintained SU24 authorization proposals |

### `s4_business_authz` — 8 checks

| Check | Severity | Title |
|---|---|---|
| `S4AUTHZ-001` | CRITICAL | Super-admin business role template assigned in production |
| `S4AUTHZ-002` | HIGH | Business-role restriction left 'Unrestricted' |
| `S4AUTHZ-003` | MEDIUM | *varies* — Business role bundles more than … business catalogs |
| `S4AUTHZ-004` | HIGH | CDS view exposes data with authorization checking disabled |
| `S4AUTHZ-005` | HIGH | OData V4 service group published without authorization |
| `S4AUTHZ-006` | HIGH | Cloud Connector system mapping without principal propagation |
| `S4AUTHZ-007` | HIGH | Cloud Foundry privileged platform role over-assigned |
| `S4AUTHZ-008` | MEDIUM | Birthright role collection auto-granted to all federated users |

### `sap_hotnews` — 6 checks

| Check | Severity | Title |
|---|---|---|
| `HOTNEWS-000` | MEDIUM | SAP Note implementation status not provided |
| `HOTNEWS-001` | CRITICAL | Missing HotNews (Priority 1) SAP Security Notes |
| `HOTNEWS-002` | HIGH | Missing High-priority SAP Security Notes |
| `HOTNEWS-003` | CRITICAL | Missing notes for actively-exploited SAP vulnerabilities |
| `HOTNEWS-004` | HIGH | Critical SAP Notes only partially implemented |
| `HOTNEWS-COVERAGE` | INFO | SAP note check ran against a curated subset, not the full patch history |

### `security_params` — 3 checks

Category: Security Parameters

| Check | Severity | Title |
|---|---|---|
| `PARAM-000` | HIGH | No security parameters data available |
| `PARAM-MISSING` | HIGH | Critical security parameters not found in export |
| `PARAM-MISSING-OTHER` | INFO | Further security parameters not found in export |

### `snc_posture` — 7 checks

| Check | Severity | Title |
|---|---|---|
| `CRYPTO-SNCECS-000` | INFO | SNC posture could not be assessed from this export |
| `CRYPTO-SNCECS-001` | HIGH | SNC is not enabled, so the mandated ECS SNC baseline is not in force |
| `CRYPTO-SNCECS-002` | MEDIUM | SNC connection-acceptance parameters deviate from the ECS baseline |
| `CRYPTO-SNCECS-003` | *varies* | SNC protection level deviates from the ECS baseline |
| `CRYPTO-SNCECS-004` | MEDIUM | SNC protection-level parameters contradict each other |
| `CRYPTO-SNCECS-005` | MEDIUM | SNC identity is not consistent with the ECS baseline |
| `CRYPTO-SNCECS-006` | MEDIUM | SNC GSS-API library is not the one the ECS baseline mandates |

### `system_trust` — 12 checks

| Check | Severity | Title |
|---|---|---|
| `STDUSR-001` | CRITICAL | SAP* kernel emergency-user auto-logon is enabled |
| `STDUSR-002` | CRITICAL | Standard users still have SAP default passwords |
| `STDUSR-003` | HIGH | Standard users not locked |
| `TRUST-001` | *varies* — HIGH or MEDIUM | Inbound trusted-RFC relationships (verify no trust from a lower tier) |
| `TRUST-002` | HIGH | RFC self-trust enabled |
| `TRUST-003` | HIGH | Trusted-RFC relationships not migrated to the current security method |
| `TRUST-004` | HIGH | Trusted RFC destination configured with a fixed logon user |
| `TRUST-005` | HIGH | SAProuter route table allows wildcard target host/port |
| `TRUST-006` | HIGH | Message-server internal/external separation weak |
| `TRUST-007` | HIGH | UCON RFC allowlist is not active |
| `TRUST-008` | MEDIUM | RFC Gateway proxy ACL (gw/prxy_info) not configured |
| `TRUST-010` | HIGH | Message-server ACL permits any host to register (rogue app server) |

### `user_auth_audit` — 10 checks

Category: User & Authorization

| Check | Severity | Title |
|---|---|---|
| `USR-001` | *varies* — CRITICAL or HIGH | *varies* — Default user … is unlocked |
| `USR-002` | CRITICAL | *varies* — Users assigned critical profiles (…) |
| `USR-003` | MEDIUM | *varies* — Dormant accounts (…+ days inactive) |
| `USR-004` | HIGH | Service/technical accounts with dialog logon type |
| `USR-005` | MEDIUM | *varies* — Users with excessive role assignments (>…) |
| `USR-006` | HIGH | *varies* — Users with wildcard access on … |
| `USR-007` | LOW | Active accounts that have never logged in |
| `USR-008` | MEDIUM | *varies* — Dialog users with stale passwords (>… days) |
| `USR-009` | *varies* — HIGH or MEDIUM | DDIC is a dialog user on an ECS-managed system |
| `USR-010` | *varies* — HIGH or LOW | EARLYWATCH still exists on an ECS-managed system |

## Runtime check families

These ids are constructed per entry in a shipped table, so the catalogue grows with the table and not with the code.

### `PARAM-<parameter name>` — 78

Source: `modules/security_params.py — BASELINE + ECS_RULES`

Examples: `abap/ext_debugging_possible`, `auth/check/calltransaction`, `auth/no_check_in_some_cases`, `auth/object_disabling_active`, `auth/rfc_authority_check`, `dbs/dba/ccms_maintenance`

One id per judged profile parameter. `PARAM-000`, `PARAM-MISSING` and `PARAM-MISSING-OTHER` are fixed ids and appear in the literal table above.

### `ABAP-<rule id>` — 133

Source: `modules/abap_sast.py — ALL_ABAP_SAST_RULES (118) + ALL_JS_RULES (7) + ALL_BTP_CONFIG_RULES (8)`

Examples: `ABAP-AMDP-001`, `ABAP-AMDP-002`, `ABAP-AMDP-003`, `ABAP-AMDP-004`, `ABAP-AMDP-005`, `ABAP-AUTH-001`

Custom-code scan rules. All three tables emit into the same `ABAP-` namespace: ABAP/UI5, JavaScript, and BTP descriptors.

### `ARA-<risk id>` — 27

Source: `modules/access_risk_analysis.py — RULESET`

Examples: `{'risk_id': 'BASIS-01', 'name': 'User Administration vs Authorization/Profile Administration', 'process': 'BASIS-SEC', 'risk_type': 'SOD', 'severity': 'CRITICAL', 'rationale': 'A single user who administers user master records (create users, reset passwords, assign roles/profiles) AND defines what roles/profiles grant (build authorizations) can grant themselves unlimited access with no four-eyes control. Foundational Basis privilege-escalation SoD.', 'functions': [{'name': 'User Administration (create/change users, assign roles & profiles)', 'actions': ['SU01', 'SU10', 'SU12'], 'permissions': [{'object': 'S_USER_GRP', 'field': 'ACTVT', 'values': ['01', '02']}, {'object': 'S_USER_AGR', 'field': 'ACTVT', 'values': ['22']}, {'object': 'S_USER_PRO', 'field': 'ACTVT', 'values': ['22']}]}, {'name': 'Authorization & Profile Administration (define role/profile content)', 'actions': ['PFCG', 'SU02', 'SU03', 'SU24'], 'permissions': [{'object': 'S_USER_AGR', 'field': 'ACTVT', 'values': ['01', '02']}, {'object': 'S_USER_AUT', 'field': 'ACTVT', 'values': ['01', '02']}, {'object': 'S_USER_PRO', 'field': 'ACTVT', 'values': ['01', '02']}]}], 'references': ['SAP Help S_USER_GRP (CLASS/ACTVT)', 'SAP KBA 2658656', 'SAP Help S_USER_AGR (ACTVT 01/02/22)', 'authorizationexperts.com s_user_agr']}`, `{'risk_id': 'BASIS-02', 'name': 'Maintain Role vs Assign Role to User', 'process': 'BASIS-SEC', 'risk_type': 'SOD', 'severity': 'HIGH', 'rationale': 'The person who BUILDS a role (its transactions and authorization values) must not be the person who ASSIGNS it to users. Combined, a user could insert powerful access into a role and assign it to their own account, bypassing role-owner approval. Build-vs-assign split at role granularity.', 'functions': [{'name': 'Maintain Role Content (build role menu & authorizations)', 'actions': ['PFCG'], 'permissions': [{'object': 'S_USER_AGR', 'field': 'ACTVT', 'values': ['01', '02']}, {'object': 'S_USER_TCD', 'field': 'TCD', 'values': ['*']}]}, {'name': 'Assign Role to User', 'actions': ['SU01', 'SU10', 'PFCG', 'PFUD'], 'permissions': [{'object': 'S_USER_AGR', 'field': 'ACTVT', 'values': ['22']}, {'object': 'S_USER_GRP', 'field': 'ACTVT', 'values': ['22']}]}], 'references': ['SAP Help / authorizationexperts.com S_USER_AGR (01/02 vs 22)', 'SAP Help S_USER_TCD (TCD)', 'SAP Help S_USER_SAS']}`, `{'risk_id': 'BASIS-03', 'name': 'ABAP Development vs Transport Release/Import to Production', 'process': 'BASIS-SEC', 'risk_type': 'SOD', 'severity': 'HIGH', 'rationale': 'A developer who writes/changes ABAP AND releases their own transports and imports them into production defeats change-management four-eyes control, moving untested or malicious code (backdoors) into PRD unreviewed.', 'functions': [{'name': 'Develop / Maintain ABAP Repository Objects', 'actions': ['SE38', 'SE80', 'SE24', 'SE37', 'SE11'], 'permissions': [{'object': 'S_DEVELOP', 'field': 'ACTVT', 'values': ['01', '02']}]}, {'name': 'Release & Import Transport Requests to Production', 'actions': ['SE09', 'SE10', 'SE01', 'STMS'], 'permissions': [{'object': 'S_TRANSPRT', 'field': 'ACTVT', 'values': ['43']}, {'object': 'S_CTS_ADMI', 'field': 'CTS_ADMFCT', 'values': ['IMPA', 'IMPS']}]}], 'references': ['SAP Help S_DEVELOP; SAP Note 65968', 'authorizationexperts.com s_transprt (ACTVT 43)', 'SAP Help S_CTS_ADMI (IMPA/IMPS)']}`, `{'risk_id': 'BASIS-04', 'name': 'Maintain Table Data vs Administer Security Audit Log', 'process': 'BASIS-SEC', 'risk_type': 'SOD', 'severity': 'HIGH', 'rationale': 'A user who directly changes sensitive table contents AND configures/deactivates the logging that records those changes (Security Audit Log via SM19/RSAU_CONFIG) can make and then conceal fraudulent changes. Separating data maintenance from audit administration preserves an untampered trail.', 'functions': [{'name': 'Maintain Table Contents Directly', 'actions': ['SM30', 'SM31', 'SM34', 'SE16N'], 'permissions': [{'object': 'S_TABU_DIS', 'field': 'ACTVT', 'values': ['02']}, {'object': 'S_TABU_NAM', 'field': 'ACTVT', 'values': ['02']}]}, {'name': 'Administer Security Audit Log / Change Logging', 'actions': ['SM19', 'RSAU_CONFIG'], 'permissions': [{'object': 'S_ADMI_FCD', 'field': 'S_ADMI_FCD', 'values': ['AUDA']}]}], 'references': ['SAP Help S_TABU_DIS / S_TABU_NAM', 'SAP Help Configuring the Security Audit Log (SM19/RSAU_CONFIG)', 'SAP community S_ADMI_FCD AUDA/AUDD']}`, `{'risk_id': 'CA-04', 'name': 'Change Payroll Status / Delete Payroll Results', 'process': 'H2R', 'risk_type': 'CRITICAL_ACTION', 'severity': 'HIGH', 'rationale': 'PU03 edits the Payroll Status infotype (IT0003) — unlock a personnel number, reset accounted-to/earliest-retro date and correction flags — while PU01 deletes the current payroll result. Together they re-open a closed/locked period, wipe a result and recalculate, defeating payroll locking and enabling undetected manipulation.', 'functions': [{'name': 'Manipulate Payroll Status / Results', 'actions': ['PU03', 'PU01'], 'permissions': [{'object': 'P_ORGIN', 'field': 'INFTY', 'values': ['0003']}, {'object': 'P_PCLX', 'field': 'AUTHC', 'values': ['U']}]}], 'references': ['SAP community IT0003 payroll status (PU03)', 'dan852 PU01 delete current result', 'authorizationexperts.com p_pclx (RELID/AUTHC=U)']}`, `{'risk_id': 'CP-05', 'name': 'Maintain Own HR Master Data (P_PERNR PSIGN=I)', 'process': 'H2R', 'risk_type': 'CRITICAL_PERMISSION', 'severity': 'HIGH', 'rationale': "P_PERNR (Personnel Number Check) with PSIGN='I' (own personnel number) at write level lets a user maintain their OWN pay-relevant infotypes (Basic Pay 0008, Bank Details 0009) — self-service pay manipulation. When the PERNR main switch is active (OOAC, AUTSW/PERNR), P_PERNR overrides P_ORGIN; PSIGN='I' with write AUTHC is the exact self-maintenance grant. Best practice PSIGN='E' (exclude own record) for pay-relevant infotypes.", 'functions': [{'name': 'Maintain Own Personnel Master Data', 'actions': ['PA30', 'PA40'], 'permissions': [{'object': 'P_PERNR', 'field': 'PSIGN', 'values': ['I']}, {'object': 'P_PERNR', 'field': 'AUTHC', 'values': ['W', 'E', 'S', '*']}]}], 'references': ['SAP Help P_PERNR', 'SAP Help P_PERNR PSIGN I/E, main switch OOAC (AUTSW/PERNR)']}`

Segregation-of-duties and critical-access risks, extendable by a customer's own `ara_ruleset.json`.

### `ATC-<family>` — 10

Source: `modules/atc_import.py — FAMILIES`

Examples: `SQLI`, `CINJ`, `CMDI`, `AUTHCHK`, `PATH`, `XSS`

ABAP Test Cockpit finding families, imported from an ATC export.

### `IAM-<sod rule>` — 7

Source: `modules/iam_advanced.py — DEFAULT_SOD_RULES`

Examples: `{'rule_id': 'SOD-BASIS-001', 'name': 'Transport Management ↔ Development', 'severity': 'HIGH', 'side_a': {'description': 'Release/Import Transports', 'tcodes': ['STMS', 'SE09', 'SE10'], 'auth_objects': ['S_CTS_ADMI']}, 'side_b': {'description': 'ABAP Development', 'tcodes': ['SE38', 'SE80', 'SE24', 'SE37'], 'auth_objects': ['S_DEVELOP']}}`, `{'rule_id': 'SOD-FIN-001', 'name': 'Vendor Master ↔ Payment Processing', 'severity': 'CRITICAL', 'side_a': {'description': 'Create/Modify Vendor Master', 'tcodes': ['FK01', 'FK02', 'XK01', 'XK02', 'BP'], 'auth_objects': ['F_LFA1_BUK']}, 'side_b': {'description': 'Process Vendor Payments', 'tcodes': ['F110', 'F-53', 'F-58', 'FBZP'], 'auth_objects': ['F_BKPF_BUP']}}`, `{'rule_id': 'SOD-FIN-002', 'name': 'Purchase Order ↔ Goods Receipt', 'severity': 'HIGH', 'side_a': {'description': 'Create/Release Purchase Orders', 'tcodes': ['ME21N', 'ME22N', 'ME28', 'ME29N'], 'auth_objects': ['M_BEST_BSA']}, 'side_b': {'description': 'Post Goods Receipt', 'tcodes': ['MIGO', 'MB01', 'MB0A'], 'auth_objects': ['M_MSEG_BWA']}}`, `{'rule_id': 'SOD-FIN-003', 'name': 'Journal Entry ↔ GL Account Master', 'severity': 'HIGH', 'side_a': {'description': 'Post Journal Entries', 'tcodes': ['FB01', 'FB50', 'F-02', 'BAPI_ACC_DOCUMENT_POST'], 'auth_objects': ['F_BKPF_BUK']}, 'side_b': {'description': 'Maintain GL Account Master', 'tcodes': ['FS00', 'FSP0', 'FSS0', 'OB_GLACC01'], 'auth_objects': ['F_SKA1_BUK']}}`, `{'rule_id': 'SOD-FIN-004', 'name': 'Customer Master ↔ Sales Order / Billing', 'severity': 'HIGH', 'side_a': {'description': 'Create/Modify Customer Master', 'tcodes': ['FD01', 'FD02', 'XD01', 'XD02', 'BP'], 'auth_objects': ['F_KNA1_BUK']}, 'side_b': {'description': 'Create Sales Orders / Billing', 'tcodes': ['VA01', 'VA02', 'VF01', 'VF02'], 'auth_objects': ['V_VBAK_AAT']}}`, `{'rule_id': 'SOD-HR-001', 'name': 'HR Master Data ↔ Payroll Execution', 'severity': 'CRITICAL', 'side_a': {'description': 'Maintain HR Master Data', 'tcodes': ['PA20', 'PA30', 'PA40'], 'auth_objects': ['P_ORGIN']}, 'side_b': {'description': 'Execute Payroll', 'tcodes': ['PC00_M99_RUN', 'PC00_M10_CALC', 'PU03'], 'auth_objects': ['P_PYEVRUN']}}`

Conflicting-duty pairs.

---

Generated by `tools/build_checks_reference.py`. Run `python -m tools.build_checks_reference` after changing a check.
