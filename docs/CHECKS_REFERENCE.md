# Check reference

<!-- GENERATED FILE — DO NOT EDIT BY HAND.
     Produced by tools/build_checks_reference.py from the code itself.
     CI re-runs the generator and fails if this file disagrees, so an edit
     here is reverted by the next build rather than merged. Change the
     check, then regenerate:  python -m tools.build_checks_reference -->

**463** check ids are written as literals in `modules/`, across **38** modules. A further **344** are built at runtime from shipped rule tables, giving **807** in total.

Each check is published with **what it reads** and **which SAP Security Baseline requirement it answers** — the two things that make a catalogue auditable rather than a number. A competitor publishing a count and no itemised list is making a claim; this is a claim somebody else can check.

## What this file does not claim

**62 of the 463 titles and 30 of the severities are not fixed.** A title is often an f-string naming the object it found, and a severity is often conditional on what was found — a locked account and an unlocked one are the same check at different severities.

Those are rendered as *varies*, with the template where one can be shown. They are **not** resolved to one example. The previous hand-written version of this file froze one branch as fact and ended up carrying eleven wrong titles and four wrong severities; a generator repeating that mistake would carry a machine's authority while doing it.

A check's **identity** is its id. Severity is a judgement about a particular finding and is not part of it.

## Coverage of SAP's published Baseline

Every check below carries the SAP Security Baseline requirement it answers, where one exists. This is the roll-up, and it reports **three numbers rather than one percentage**, because a single percentage hides the interesting part.

- **28 of 28** requirements that are IN SCOPE for this product are addressed by at least one check here.
- **10 of 38** published requirements are out of scope, because they are for a stack this product does not read. They are named below, not dropped: the denominator has to be honest in both directions, and a reader comparing 28 against 38 has no way to know that.
- **0** in-scope requirements are not addressed at all. They are listed below rather than summarised away.
- **535 of 807** checks answer no Baseline requirement — **which is not a failure.** Segregation of duties, GRC, financial controls, the attack-path content and the RISE-specific checks have no Baseline equivalent, and that is where this product goes beyond it.

> ⚠️ These are CHECK ITEMS in the CSA policies, not the 'control points' counted in the Baseline document — the widely-quoted 214 (69/92/53) is that other unit. The two do not reconcile; do not publish a percentage of one against the other.

Baseline version: **v2.4**.

### Published requirements this catalogue does not address

**In scope, and not addressed: none.** Every requirement SAP publishes for a stack this product reads is answered by at least one check. That is a statement about coverage of the requirement, not about depth against it — SAP's requirements carry 351 check items between them and this product does not claim to reproduce each one.

**Out of scope.** These are not gaps but a scope decision, and it is not one more work here would reverse. By technology: **10** Java. SAP NetWeaver AS Java is a separate stack from the ABAP server S/4HANA runs on. This product reads no Java export and ships no Java check, so these requirements are out of its scope rather than unmet by it.

| Requirement | Tier | Technology | Title |
|---|---|---|---|
| `AUDIT-J` | EXTENDED | Java | Enable XML Hardener |
| `CRITAU-J` | STANDARD | Java | Role SAP_J2EE_ADMIN must not be assigned to users other than standard users |
| `DISCL-J` | STANDARD | Java | Disclosure of unnecessary information about versions or from errors |
| `MSGSRV-J` | CRITICAL | Java | File with access control list for message server |
| `NOTEST-J` | CRITICAL | Java | InvokerServlet globally enabled |
| `PWDPOL-J` | CRITICAL | Java | Minimum Password Length |
| `RFCGW-J` | CRITICAL | Java | Path-like value for ms/acl_info (message server access control list) |
| `SECUPD-J` | CRITICAL | Java | Last detected Update older than 1 year |
| `SESS-J` | STANDARD | Java | SystemCookiesDataProtection |
| `SSO-J` | EXTENDED | Java | Send SAP logon ticket only via HTTPS |

## Checks by module

### `abap_authorizations` — 16 checks

Reads: `role_auth_values`, `security_params`, `user_roles` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `AUTH-001` | CRITICAL | Debug & Replace authorization (runtime authorization bypass) | `CRITAU-A` |
| `AUTH-002` | CRITICAL | Trusted-RFC logon as any user (S_RFCACL wildcard) | `CRITAU-A` |
| `AUTH-003` | CRITICAL | Unrestricted external OS-command execution (S_LOG_COM) | `CRITAU-A` |
| `AUTH-004` | CRITICAL | Authorization forging via role-content control objects | `CRITAU-A` |
| `AUTH-005` | CRITICAL | Role allows starting any transaction (S_TCODE = *) | `CRITAU-A` |
| `AUTH-006` | HIGH | Broad RFC authorization (S_RFC RFC_NAME = *) | `CRITAU-A` |
| `AUTH-007` | HIGH | Generic table write via S_TABU_NAM (TABLE = *) | `CRITAU-A` |
| `AUTH-008` | HIGH | Generic table maintenance via S_TABU_DIS (all / no auth group) | `CRITAU-A` |
| `AUTH-009` | HIGH | Cross-client table maintenance (S_TABU_CLI) | `CRITAU-A` |
| `AUTH-010` | HIGH | Arbitrary OS file access from ABAP (S_DATASET) | `CRITAU-A` |
| `AUTH-011` | HIGH | Run-any-report authorization (S_PROGRAM) | `CRITAU-A` |
| `AUTH-012` | HIGH | Background-job impersonation (S_BTCH_NAM BTCUNAME = *) | `CRITAU-A` |
| `AUTH-013` | HIGH | Sensitive Basis / administration transactions in roles | `CRITAU-A` |
| `AUTH-014` | HIGH | ABAP development change access (S_DEVELOP create/change) | `CRITAU-A` |
| `AUTH-015` | MEDIUM | Global authorization-object disabling is active | `CRITAU-A` |
| `AUTH-016` | HIGH | Unrestricted destination authorization (S_ICF ICF_FIELD=DEST, ICF_VALUE=*) | `CRITAU-A` |

### `abap_sast` — 8 checks

Category: Code & Transport Security

Reads: `abap_source_dir` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `ABAP-COV-001` | *varies* | ABAP source scan was requested but the source path is not readable | — |
| `ABAP-COV-002` | *varies* | ABAP source scan read no source files | — |
| `ABAP-COV-003` | *varies* | Some source files could not be read and were not scanned | — |
| `ABAP-COV-004` | *varies* | Files in languages this scanner does not read were not examined | — |
| `ABAP-COV-005` | *varies* | No CDS access-control artefact was found, so view protection was not assessed | — |
| `ABAP-COV-006` | *varies* | Views without an access-control role whose exposure could not be established | — |
| `ABAP-LEX-001` | INFO | Source the scanner could not lex reliably | — |
| `ABAP-NOSEC-001` | INFO | Findings suppressed by #NOSEC markers in source | — |

### `access_risk_analysis` — 4 checks

Reads: `ara_ruleset`, `change_documents`, `fiori_tiles`, `mitigating_controls`, `odata_auth`, `role_auth_values`, `user_roles` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `ARA-DIDDO-001` | HIGH | *varies* | `CRITAU-A` |
| `ARA-SCORE-001` | *varies* — HIGH or MEDIUM | Users concentrating multiple access risks (SoD risk profile) | `CRITAU-A` |
| `MITIG-001` | *varies* — LOW or MEDIUM | *varies* | — |
| `MITIG-002` | HIGH | *varies* | — |

### `atc_import` — 2 checks

Category: Code & Transport Security

Reads: `code_inventory`, `custom_code_scan` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `ATC-GOV-001` | HIGH | Custom code security scanning is not evidenced | — |
| `ATC-GOV-002` | INFO | ATC export rows not classified as security findings | — |

### `baseline_params` — 14 checks

Reads: `security_params` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `BASELINE-000` | INFO | No profile parameter export — baseline parameters not assessed | — |
| `BASELINE-001` | HIGH | RFC authorization check disabled (auth/rfc_authority_check) | — |
| `BASELINE-002` | HIGH | Profile-generator authorization checks not active (auth/no_check_in_some_cases) | — |
| `BASELINE-003` | HIGH | SNC accepts insecure (unencrypted) connections | `NETENC-A` |
| `BASELINE-004` | HIGH | SAP GUI Scripting enabled server-side (sapgui/user_scripting) | `SCRIPT-A` |
| `BASELINE-005` | HIGH | Weak legacy password hashes retained (login/password_downwards_compatibility) | — |
| `BASELINE-006` | HIGH | sapstartsrv / Host Agent web methods not protected (service/protectedwebmethods) | — |
| `BASELINE-007` | MEDIUM | RFC Gateway default ACL not enforced (gw/acl_mode) | — |
| `BASELINE-008` | MEDIUM | SSO ticket / session-cookie transport not hardened | `SSO-A` |
| `BASELINE-009` | MEDIUM | Web-tier logging / error disclosure weak (ICM) | `DISCL-A` |
| `BASELINE-010` | MEDIUM | Existing passwords not forced to current policy (login/password_compliance_to_current_policy) | — |
| `BASELINE-011` | *varies* | Weak password hash algorithm (login/password_hash_algorithm) | — |
| `BASELINE-012` | HIGH | RFC callback protection not enforced (rfc/callback_security_method) | — |
| `BASELINE-SNC-DEFERRED` | INFO | SNC insecure-fallback parameters deferred to the SNC family model | — |

### `basis_job_command` — 11 checks

Reads: `background_job_steps`, `background_jobs`, `ext_os_commands`, `ext_os_commands_sap`, `profiles`, `users` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `JOBCMD-CMD-001` | CRITICAL | External OS command wraps a shell / interpreter | — |
| `JOBCMD-CMD-002` | HIGH | External OS command allows runtime additional parameters (ADDPAR) | — |
| `JOBCMD-CMD-003` | HIGH | External OS command resolves to an unqualified or writable path | — |
| `JOBCMD-CMD-004` | MEDIUM | Destructive / exfiltration OS command defined as a standing command | — |
| `JOBCMD-CMD-005` | LOW | External OS command not bound to a specific operating system | — |
| `JOBCMD-JOB-001` | CRITICAL | Armed background job runs under SAP*/DDIC or a SAP_ALL step user | — |
| `JOBCMD-JOB-002` | HIGH | Background job step executes an external OS command / program | — |
| `JOBCMD-JOB-003` | HIGH | Job runs RSBDCOS0 or unreviewed custom code under a privileged user | — |
| `JOBCMD-JOB-004` | MEDIUM | Armed job step user is deleted, locked, expired, or a dialog user | — |
| `JOBCMD-JOB-005` | MEDIUM | Background job step user differs from scheduler (identity borrowing) | — |
| `JOBCMD-JOB-001B` | HIGH | Armed background job runs under a standard/technical step user | — |

### `btp_cloud_surface` — 44 checks

Category: BTP Cloud Attack Surface

Reads: `btp_destinations`, `btp_entitlements`, `btp_network`, `btp_security_settings`, `btp_service_bindings`, `btp_subaccounts`, `btp_trust`, `cloud_connector`, `cpi_artifacts`, `event_mesh`, `ias_config` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `BTP-AUD-001` | INFO | Audit-log state could not be determined for some subaccounts | — |
| `BTP-CC-001` | CRITICAL | Cloud Connector backends with wildcard resource mappings | — |
| `BTP-CC-002` | HIGH | High-risk backend services exposed via Cloud Connector | — |
| `BTP-CC-003` | MEDIUM | *varies* — Excessive Cloud Connector backend systems (…) | — |
| `BTP-CC-004` | HIGH | Cloud Connector with unrestricted access control lists | — |
| `BTP-CC-005` | HIGH | Cloud Connector certificates expiring or expired | — |
| `BTP-CC-006` | HIGH | Cloud Connector certificates with weak cryptography | — |
| `BTP-CC-007` | MEDIUM | *varies* — Stale Cloud Connector backends (…+ days unused) | — |
| `BTP-CC-008` | *varies* — MEDIUM | *varies* — Cloud Connector … is vulnerable to CVE-2024-25642 | `SECUPD-P` |
| `BTP-CC-009` | MEDIUM | Cloud Connector runs as a single instance with no shadow | `NETCF-P` |
| `BTP-CC-010` | HIGH | Cloud Connector audit logging is switched off | `AUDIT-P` |
| `BTP-CPI-001` | HIGH | *varies* — CPI credentials not rotated in …+ days | — |
| `BTP-CPI-002` | MEDIUM | CPI credentials using basic/plaintext authentication | — |
| `BTP-CPI-003` | CRITICAL | CPI iFlows with hardcoded/embedded credentials | — |
| `BTP-CPI-004` | HIGH | CPI iFlows with no sender authentication | — |
| `BTP-CPI-005` | HIGH | CPI iFlows using unencrypted HTTP endpoints | — |
| `BTP-DST-001` | HIGH | BTP destinations with stored credentials | — |
| `BTP-DST-002` | CRITICAL | BTP destinations with TLS verification disabled | — |
| `BTP-DST-003` | MEDIUM | BTP destinations with proxy type mismatch | — |
| `BTP-DST-004` | LOW | Stale BTP destinations (not modified in 365+ days) | — |
| `BTP-EM-001` | HIGH | Event Mesh queues with wildcard topic subscriptions | — |
| `BTP-EM-002` | HIGH | Event Mesh queues without access control policies | — |
| `BTP-EM-003` | MEDIUM | Event Mesh queues subscribing to foreign namespaces | — |
| `BTP-ENT-001` | LOW | BTP services entitled but never provisioned | — |
| `BTP-ENT-002` | MEDIUM | Security-critical BTP services entitled but not provisioned | — |
| `BTP-FRM-001` | HIGH | Subaccount login pages may be framed by an unrestricted origin | — |
| `BTP-FRM-002` | MEDIUM | Iframe embedding enabled for the subaccount (SAP default is off) | — |
| `BTP-GOV-001` | HIGH | BTP subaccounts without audit logging | — |
| `BTP-GOV-002` | MEDIUM | BTP subaccounts using default SAP IDP only | — |
| `BTP-IAS-001` | MEDIUM | IAS applications without conditional authentication rules | — |
| `BTP-IAS-002` | MEDIUM | IAS applications without IP-based access restrictions | — |
| `BTP-IAS-003` | HIGH | IAS applications without multi-factor authentication | — |
| `BTP-IAS-004` | *varies* | IAS password policy for local users is weak | — |
| `BTP-IAS-005` | HIGH | Corporate IdP not enforced — local password fallback allowed | — |
| `BTP-IDL-001` | MEDIUM | Email address links identities across multiple identity providers | — |
| `BTP-MIG-001` | MEDIUM | Applications still using XSUAA authentication (not migrated to IAS) | — |
| `BTP-NET-001` | MEDIUM | BTP services using public internet endpoints | — |
| `BTP-NET-002` | HIGH | Critical BTP services without Private Link | — |
| `BTP-SB-001` | HIGH | *varies* — Service bindings not rotated in …+ days | — |
| `BTP-SB-002` | HIGH | Service bindings with admin-level scopes | — |
| `BTP-SB-003` | MEDIUM | Orphaned service bindings (deleted/failed instances) | — |
| `BTP-TOK-001` | HIGH | OAuth token validity relaxed beyond the SAP default | — |
| `BTP-TOK-002` | LOW | OAuth token validity left at the SAP default (12 hours / 7 days) | — |
| `BTP-TOK-003` | LOW | OAuth token validity set below the 30-minute floor SAP states | — |

### `cap_xsuaa` — 15 checks

Reads: `btp_role_collection_mappings`, `cap_project_dir` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `CAPX-ATTR-001` | MEDIUM | Attribute-based restriction declared but not enforced (valueRequired=false) | — |
| `CAPX-AUTH-001` | MEDIUM | Application accepts every authority granted to it, without naming them | — |
| `CAPX-CDS-001` | HIGH | CAP service exposed with no access control | — |
| `CAPX-CDS-002` | HIGH | @restrict privilege grants to every user (no `to` given) | — |
| `CAPX-CDS-003` | MEDIUM | CDS model enforces a role no security descriptor grants | — |
| `CAPX-CDS-004` | HIGH | Restricted entity reachable by $expand from a service that does not require its role | — |
| `CAPX-CDS-005` | MEDIUM | Personal or sensitive element exposed by a projection that excludes nothing | — |
| `CAPX-CRED-001` | MEDIUM | Application requests an instance secret, which cannot be rotated | — |
| `CAPX-GRAPH-001` | HIGH | Broken reference in the XSUAA authorization chain | — |
| `CAPX-GRAPH-002` | HIGH | Application scopes are granted to every federated user by birthright | — |
| `CAPX-GRAPH-003` | MEDIUM | Role template that no role collection can deliver | — |
| `CAPX-SCOPE-001` | MEDIUM | Application scope granted directly to another application | — |
| `CAPX-TEN-001` | MEDIUM | Application uses the shared tenant mode (one client secret everywhere) | — |
| `CAPX-TOK-001` | HIGH | Application overrides the subaccount token policy | — |
| `CAPX-URI-001` | HIGH | OAuth redirect URI is broader than a specific host | — |

### `cloudalm_verdicts` — 4 checks

Reads: `csa_findings` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `CSA-COV-001` | INFO | A CSA export was supplied but no result could be read from it | — |
| `CSA-SAP-001` | *varies* | SAP Cloud ALM CSA reports these policies as not compliant | — |
| `CSA-SAP-002` | INFO | SAP Cloud ALM CSA could not evaluate these policies | — |
| `CSA-SAP-003` | LOW | CSA results name policies the vendored baseline catalogue does not know | — |

### `code_inventory_report` — 5 checks

Reads: `code_inventory` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `CODE-INV-001` | INFO | Custom-code estate inventory | — |
| `CODE-INV-002` | LOW | Custom code that nothing reaches is still installed | — |
| `CODE-INV-003` | INFO | Custom code with no recent recorded execution | — |
| `CODE-INV-004` | INFO | Custom code whose reachability could not be determined | — |
| `CODE-INV-005` | INFO | Custom-code inventory carries no usable execution data | — |

### `code_transport` — 22 checks

Category: Code & Transport Security

Reads: `auth_objects`, `change_documents`, `client_settings`, `code_inventory`, `custom_code_scan`, `dev_access_prod`, `sap_modifications`, `system_change`, `transport_history`, `transport_routes` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `CODE-ATC-001` | CRITICAL | *varies* — Unresolved critical ATC findings (…) | — |
| `CODE-ATC-002` | HIGH | *varies* — Unresolved high-severity ATC findings (…) | — |
| `CODE-CHG-001` | MEDIUM | Critical object types without change documents | — |
| `CODE-CHG-002` | MEDIUM | Change documents with empty or system user attribution | — |
| `CODE-CLIENT-001` | CRITICAL | Production client allows changes (not locked) | `CHANGE-A` |
| `CODE-DEAD-001` | MEDIUM | *varies* — Excessive unreferenced custom code (… objects) | — |
| `CODE-DEAD-002` | LOW | Custom code objects without designated owner | — |
| `CODE-DEV-001` | HIGH | *varies* — Users with development access in production | — |
| `CODE-INJ-001` | CRITICAL | SQL injection patterns detected in custom code | — |
| `CODE-INJ-002` | HIGH | Custom code missing authority checks | — |
| `CODE-INJ-003` | CRITICAL | Hardcoded credentials detected in custom code | — |
| `CODE-MOD-001` | MEDIUM | Unregistered SAP standard modifications | — |
| `CODE-MOD-002` | CRITICAL | Modifications to SAP security-critical standard programs | — |
| `CODE-MOD-003` | LOW | Stale SAP modifications (5+ years old) | — |
| `CODE-STMT-001` | HIGH | *varies* — Dangerous ABAP statement: … | — |
| `CODE-SYSCHG-001` | CRITICAL | SE06 global system change option is 'Modifiable' (production changeable) | `CHANGE-A` |
| `CODE-SYSCHG-002` | HIGH | Individual namespaces / software components left modifiable in production | `CHANGE-A` |
| `CODE-TMS-001` | CRITICAL | Transport routes allow direct dev-to-production delivery | `CHANGE-A` |
| `CODE-TMS-002` | HIGH | Production transport imports without approval | `CHANGE-A` |
| `CODE-TMS-003` | HIGH | Transports released and imported by the same user | `CHANGE-A` |
| `CODE-TMS-004` | MEDIUM | Transport imports outside normal change windows (weekends) | `CHANGE-A` |
| `CODE-TMS-005` | CRITICAL | Transports imported into production directly from development | `CHANGE-A` |

### `crypto_posture` — 19 checks

Category: Cryptographic Posture

Reads: `certificate_inventory`, `crypto_library`, `hana_encryption`, `hana_parameters`, `key_management`, `pse_inventory`, `security_params`, `snc_config`, `tls_config` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `CRYPTO-CERT-001` | CRITICAL | Expired certificates in system trust store | `NETENC-A` |
| `CRYPTO-CERT-002` | HIGH | *varies* — Certificates expiring within … days | `NETENC-A` |
| `CRYPTO-CERT-003` | HIGH | Certificates with weak key sizes or algorithms | `NETENC-A` |
| `CRYPTO-CERT-004` | MEDIUM | Self-signed certificates used in production context | `NETENC-A` |
| `CRYPTO-HANA-001` | HIGH | HANA data volume encryption is disabled | `NETENC-A` |
| `CRYPTO-HANA-002` | MEDIUM | HANA log volume encryption is disabled | `NETENC-A` |
| `CRYPTO-HANA-003` | MEDIUM | HANA encryption uses internal/default root key management | `NETENC-A` |
| `CRYPTO-HANA-004` | HIGH | HANA backup encryption is disabled | `NETENC-A` |
| `CRYPTO-HANA-005` | HIGH | HANA system replication is not TLS-encrypted | `NETENC-A` |
| `CRYPTO-HANA-006` | INFO | Encryption at rest is operated by SAP on this deployment | `NETENC-A` |
| `CRYPTO-KEY-001` | MEDIUM | Key management policy gaps | `NETENC-A` |
| `CRYPTO-LIB-001` | HIGH | *varies* — Outdated SAP Crypto Library: … | `NETENC-A` |
| `CRYPTO-PSE-001` | HIGH | PSE files with errors or expired certificates | `NETENC-A` |
| `CRYPTO-SNC-001` | HIGH | *varies* — SNC (Secure Network Communications) is disabled | `NETENC-A` |
| `CRYPTO-SNC-002` | MEDIUM | SNC quality of protection set to authentication only | `NETENC-A` |
| `CRYPTO-SNC-DEFERRED` | INFO | SNC parameter checks deferred to the SNC family model | `NETENC-A` |
| `CRYPTO-TLS-001` | HIGH | TLS endpoints allowing deprecated protocol versions | `NETENC-A` |
| `CRYPTO-TLS-002` | HIGH | TLS cipher suites include weak algorithms | `NETENC-A` |
| `CRYPTO-TLS-003` | MEDIUM | HTTPS endpoints without HSTS (Strict Transport Security) | `NETENC-A` |

### `data_protection` — 21 checks

Category: Data Protection & Privacy

Reads: `data_masking`, `data_residency`, `deletion_requests`, `dpp_config`, `ilm_policies`, `personal_data_inventory`, `purpose_of_processing`, `ral_config`, `ral_log_channels`, `security_params`, `sensitive_fields`, `system_landscape` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `DPP-DEL-001` | CRITICAL | *varies* — Data subject requests overdue (>… day SLA) | — |
| `DPP-DEL-002` | HIGH | Data subject requests marked complete but incomplete | — |
| `DPP-DEL-003` | MEDIUM | Data subject requests without documentation | — |
| `DPP-FIELD-001` | HIGH | Sensitive classified fields without Read Access Logging | — |
| `DPP-FIELD-002` | MEDIUM | Sensitive fields not masked in non-production | — |
| `DPP-FIELD-003` | MEDIUM | Known sensitive fields missing from data classification inventory | — |
| `DPP-ILM-001` | MEDIUM | *varies* — ILM policies with retention exceeding … years | — |
| `DPP-ILM-002` | MEDIUM | ILM policies without automatic data destruction | — |
| `DPP-ILM-003` | HIGH | ILM policies without end-of-purpose definitions | — |
| `DPP-ILM-004` | HIGH | Personal data tables without ILM retention policies | — |
| `DPP-LAND-001` | MEDIUM | Systems without data classification assignment | — |
| `DPP-MASK-001` | CRITICAL | Non-production systems without PII data masking | — |
| `DPP-MASK-002` | CRITICAL | Non-production systems identified as production copies without masking | — |
| `DPP-POP-001` | HIGH | Purposes of processing without documented legal basis | — |
| `DPP-POP-002` | MEDIUM | Expired purposes of processing still active | — |
| `DPP-RAL-001` | *varies* — HIGH | *varies* — Read Access Logging has no active configurations | — |
| `DPP-RAL-002` | HIGH | Read Access Logging missing coverage for key channels | — |
| `DPP-RAL-003` | MEDIUM | *varies* — RAL log channels with retention below … days | — |
| `DPP-RES-001` | CRITICAL | Cross-border data transfers without legal safeguards | — |
| `DPP-RES-002` | HIGH | Special category personal data in cross-border transfers | — |
| `DPP-TOOLKIT-001` | HIGH | DPP toolkit features not configured | — |

### `ecs_config_items` — 5 checks

Category: ABAP Authorization & Critical Access, Cryptographic Posture, Security Audit Log Review, System Trust & Standard Users

Reads: `audit_config`, `client_settings`, `security_audit_log`, `table_auth_groups` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `AUTH-ECS-000` | INFO | Table authorization group assignments could not be assessed from this export | `CRITAU-A` |
| `AUTH-ECS-001` | HIGH | Password-hash tables are not protected by authorization group SPWD | `CRITAU-A` |
| `CRYPTO-ECS-001` | HIGH | Database PSE table SSF_PSE_D is not protected by authorization group SPSE | `NETENC-A` |
| `LREV-ECS-001` | HIGH | Security Audit Log filters are bound to named users rather than all users | — |
| `STDUSR-ECS-001` | MEDIUM | Obsolete standard client(s) still present in the system | `STDUSR-A` |

### `export_integrity` — 2 checks

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `EXPORT-001` | HIGH | *varies* | — |
| `EXPORT-002` | LOW | *varies* | — |

### `financial_controls` — 9 checks

Reads: `doc_change_rules`, `dual_control_fields`, `fi_documents`, `fi_number_ranges`, `posting_periods`, `tolerance_groups` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `FIN-DOC-001` | HIGH | Payment-relevant document fields may be changed after posting/clearing | — |
| `FIN-EVD-001` | MEDIUM | Postings back-dated beyond the entry-lag threshold | — |
| `FIN-EVD-002` | LOW | FI documents entered on weekends | — |
| `FIN-EVD-003` | MEDIUM | Reversal rate above threshold in the FI document sample | — |
| `FIN-NR-001` | MEDIUM | Financial document number ranges are buffered (completeness gaps) | — |
| `FIN-PP-001` | HIGH | Posting periods open too wide with no authorization-group control | — |
| `FIN-SF-001` | HIGH | Payment-relevant master-data fields are not under dual control (T055F) | — |
| `FIN-TOL-001` | HIGH | FI tolerance groups have effectively unlimited posting limits | — |
| `FIN-TOL-002` | MEDIUM | No FI tolerance groups defined (no posting limits) | — |

### `fiori_ui` — 8 checks

Category: Fiori & UI Layer

Reads: `fiori_app_usage`, `fiori_catalogs`, `fiori_spaces`, `fiori_tiles`, `odata_auth` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `FIORI-APP-001` | HIGH | Sensitive admin Fiori apps exposed with broad access | — |
| `FIORI-CAT-001` | HIGH | Fiori catalogs with public/unrestricted scope | — |
| `FIORI-CAT-002` | MEDIUM | *varies* — Fiori catalogs assigned to excessive roles (>…) | — |
| `FIORI-ODATA-001` | CRITICAL | OData services without authorization checks | — |
| `FIORI-ODATA-002` | HIGH | Sensitive OData services with inadequate authorization | — |
| `FIORI-SPACE-001` | MEDIUM | Fiori spaces with public visibility | — |
| `FIORI-TILE-001` | MEDIUM | Fiori tiles with OData authorization mismatches | — |
| `FIORI-USAGE-001` | LOW | Fiori apps with zero usage (never launched) | — |

### `grc_access_control` — 17 checks

Reads: `grac_access_requests`, `grac_firefighter_log`, `grac_firefighter_owners`, `grac_job_log`, `grac_mitigating_controls`, `grac_sod_risks`, `grac_sod_violations` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `GRC-ARA-001` | HIGH | Users carry open SoD violations with no active mitigating control | — |
| `GRC-ARM-001` | HIGH | Access provisioned without an approver (workflow bypass) | — |
| `GRC-ARM-002` | MEDIUM | Access provisioned without a risk (SoD) analysis | — |
| `GRC-ARM-001B` | HIGH | Access request self-approved / self-provisioned | — |
| `GRC-FF-001` | HIGH | Firefighter (emergency-access) sessions used without a documented reason | — |
| `GRC-FF-002` | HIGH | Firefighter IDs without an assigned owner and controller | — |
| `GRC-FF-003` | HIGH | Firefighter sessions without an active assignment | — |
| `GRC-FF-004` | HIGH | Firefighter ID used by its own owner or controller | — |
| `GRC-FF-001B` | HIGH | Firefighter session logs not reviewed / approved | — |
| `GRC-FF-002B` | HIGH | Firefighter owner also acts as controller (self-monitoring) | — |
| `GRC-FF-002C` | MEDIUM | Firefighter log review / delivery disabled | — |
| `GRC-MIT-001` | MEDIUM | Mitigating controls are expired, owner-less or unmonitored | — |
| `GRC-RS-001` | HIGH | Critical SoD risks are disabled in the rule set | — |
| `GRC-RS-002` | MEDIUM | SoD risks without an assigned risk owner | — |
| `GRC-RS-003` | MEDIUM | SoD rule set appears incomplete / never tailored | — |
| `GRC-SYNC-001` | MEDIUM | GRC synchronisation jobs are behind — every export here inherits the gap | — |
| `GRC-SYNC-002` | LOW | GRC job-log export contains no recognisable synchronisation job | — |

### `hana_db_security` — 31 checks

Reads: `hana_audit_policies`, `hana_db_users`, `hana_granted_privileges`, `hana_granted_roles`, `hana_parameters`, `hana_version` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `HANADB-AUDIT-001` | CRITICAL | HANA database auditing is disabled | `AUDIT-H` |
| `HANADB-AUDIT-002` | HIGH | Audit trail written to CSV text file (tamperable) | `AUDIT-H` |
| `HANADB-AUDIT-003` | HIGH | No active HANA audit policies | `AUDIT-H` |
| `HANADB-AUDIT-004` | MEDIUM | Audit policies do not cover critical action groups | `AUDIT-H` |
| `HANADB-AUDIT-005` | INFO | HANA auditing state could not be read from the export | `AUDIT-H` |
| `HANADB-PARAM-001` | HIGH | Weak HANA password-policy parameters | `PWDPOL-H` |
| `HANADB-PARAM-002` | MEDIUM | Detailed connect errors exposed to clients | — |
| `HANADB-PARAM-003` | HIGH | TLS not enforced for HANA SQL connections | — |
| `HANADB-PARAM-004` | HIGH | HANA log_mode = overwrite (no point-in-time recovery) | — |
| `HANADB-PARAM-005` | MEDIUM | HANA cross-database (MDC) access is enabled | — |
| `HANADB-PARAM-006` | CRITICAL | HANA internal communication listens on all network interfaces | `NETCF-H` |
| `HANADB-PARAM-007` | HIGH | System replication channel is not secured | — |
| `HANADB-PARAM-008` | HIGH | IMPORT/EXPORT file access is not restricted | — |
| `HANADB-PARAM-009` | HIGH | Tenant administrators can change controls this scan asserts | — |
| `HANADB-PRIV-001` | CRITICAL | Sensitive privileges granted to PUBLIC | `CRITAU-H` |
| `HANADB-PRIV-002` | CRITICAL | Critical system privileges granted directly to users | `CRITAU-H` |
| `HANADB-PRIV-003` | HIGH | Broad system privileges granted directly to users | `CRITAU-H` |
| `HANADB-PRIV-004` | MEDIUM | Sensitive privileges granted WITH ADMIN OPTION | `CRITAU-H` |
| `HANADB-PRIV-005` | CRITICAL | Analytic-privilege bypass (_SYS_BI_CP_ALL) granted | `CRITAU-H` |
| `HANADB-PRIV-006` | HIGH | Debug privileges (DEBUG / ATTACH DEBUGGER) granted to users | `CRITAU-H` |
| `HANADB-PRIV-007` | HIGH | Critical system privileges reach users through role membership | `CRITAU-H` |
| `HANADB-PRIV-008` | CRITICAL | Critical system privilege combinations held by one grantee | `CRITAU-H` |
| `HANADB-PRIV-009` | HIGH | Execute rights on the HANA full system info dump | `CRITAU-H` |
| `HANADB-ROLE-001` | HIGH | Powerful predefined roles granted to users | — |
| `HANADB-TRACE-001` | CRITICAL | HANA SQL trace is set to record query results | `TRACES-H` |
| `HANADB-TRACE-002` | MEDIUM | HANA trace components are set to DEBUG | `TRACES-H` |
| `HANADB-USER-001` | CRITICAL | *varies* | `STDUSR-H` |
| `HANADB-USER-002` | HIGH | DB users with password lifetime check disabled | `STDUSR-H` |
| `HANADB-USER-003` | MEDIUM | *varies* — Dormant HANA DB users (no logon in …+ days) | `STDUSR-H` |
| `HANADB-USER-004` | HIGH | Installation account left active after setup | `STDUSR-H` |
| `HANADB-VER-001` | CRITICAL | *varies* | `SECUPD-H` |

### `iam_advanced` — 30 checks

Category: Advanced IAM, Identity & Access Management

Reads: `access_reviews`, `auth_objects`, `btp_trust`, `btp_users`, `comm_arrangements`, `firefighter_log`, `ias_config`, `role_auth_values`, `role_details`, `role_expiry`, `role_tcodes`, `sod_matrix`, `sod_ruleset`, `user_groups`, `user_roles`, `users` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `IAM-EXP-001` | MEDIUM | Role assignments without expiry dates | — |
| `IAM-EXP-002` | LOW | Expired role assignments still present in user master | — |
| `IAM-EXP-003` | MEDIUM | *varies* — Role assignments with excessive validity (>…d) | — |
| `IAM-FED-001` | MEDIUM | Several identity providers can authenticate users into one subaccount | — |
| `IAM-FED-002` | HIGH | *varies* — Trust configuration admits any user of the identity provider: … | — |
| `IAM-FED-003` | *varies* | *varies* — Identity federation certificate …: … | — |
| `IAM-FED-004` | MEDIUM | Federated identities are auto-created with no evidence of de-provisioning | — |
| `IAM-FEDCOV-002` | INFO | Trust user admission could not be assessed from this export | — |
| `IAM-FEDCOV-003` | INFO | Identity federation certificate expiry could not be assessed from this export | — |
| `IAM-FF-000` | HIGH | Firefighter accounts detected but no usage log provided | — |
| `IAM-FF-001` | HIGH | *varies* — Firefighter sessions exceeding …h duration | — |
| `IAM-FF-002` | HIGH | Firefighter sessions without documented justification | — |
| `IAM-FF-003` | CRITICAL | Firefighter sessions not reviewed by controller | — |
| `IAM-FF-004` | CRITICAL | Firefighter sessions reviewed by the same user who initiated them | — |
| `IAM-FF-005` | MEDIUM | *varies* — Users with excessive firefighter usage (>… sessions) | — |
| `IAM-ORPH-001` | MEDIUM | Users assigned to non-existent or deleted roles | — |
| `IAM-PRIV-001` | CRITICAL | Users with privilege escalation capability | — |
| `IAM-REF-001` | HIGH | Dialog users used as reference users | — |
| `IAM-REV-001` | HIGH | Overdue access review campaigns | — |
| `IAM-REV-002` | MEDIUM | Access reviews marked complete but with incomplete coverage | — |
| `IAM-REV-003` | MEDIUM | Access review campaigns without assigned reviewer | — |
| `IAM-ROLE-001` | LOW | Custom roles without descriptions | — |
| `IAM-ROLE-002` | MEDIUM | Custom roles without designated owners | — |
| `IAM-ROLE-003` | LOW | Custom roles with no menu/transaction assignments | — |
| `IAM-SOD-000` | HIGH | Insufficient data for SoD conflict analysis | — |
| `IAM-SOD-DEFERRED` | INFO | Transaction-level SoD deferred to permission-level analysis | — |
| `IAM-USRGRP-001` | LOW | Active users in default/unassigned user groups | — |
| `IAM-XID-001` | MEDIUM | BTP users without corresponding S/4HANA account | — |
| `IAM-XID-002` | HIGH | S/4HANA locked users still active in BTP | — |
| `IAM-XID-003` | HIGH | BTP subaccount users with administrative role collections | — |

### `integration_layer` — 32 checks

Category: Network & Integration Layer

Reads: `apim_policies`, `cpi_datastores`, `gw_reginfo`, `gw_secinfo`, `idoc_partners`, `idoc_ports`, `integration_alerts`, `integration_topology`, `oauth_clients`, `webhooks`, `ws_endpoints` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `INTG-APIM-001` | HIGH | API proxies missing required security policies | — |
| `INTG-APIM-002` | CRITICAL | API proxies without authentication policies | — |
| `INTG-APIM-003` | HIGH | API proxies allowing unencrypted HTTP traffic | — |
| `INTG-APIM-004` | HIGH | API proxies allowing deprecated TLS versions | — |
| `INTG-APIM-005` | CRITICAL | API proxies operating in pass-through mode (zero policies) | — |
| `INTG-CPI-DS-001` | HIGH | CPI data stores with sensitive data names but no encryption | — |
| `INTG-CPI-DS-002` | MEDIUM | CPI global variables with potentially sensitive names | — |
| `INTG-CPI-DS-003` | LOW | CPI data stores with excessive entries | — |
| `INTG-GW-001` | CRITICAL | Gateway secinfo has overly permissive permit rules | `RFCGW-A` |
| `INTG-GW-002` | HIGH | Gateway secinfo missing deny-all default rule | `RFCGW-A` |
| `INTG-GW-003` | HIGH | Gateway secinfo permits external program execution | `RFCGW-A` |
| `INTG-GW-004` | CRITICAL | Gateway reginfo permits unrestricted RFC server registration | `RFCGW-A` |
| `INTG-GW-005` | HIGH | Gateway reginfo missing deny-all default rule | `RFCGW-A` |
| `INTG-IDOC-001` | HIGH | IDOC ports without encryption (no TLS/SNC) | — |
| `INTG-IDOC-002` | MEDIUM | IDOC file ports with insecure directory paths | — |
| `INTG-IDOC-003` | HIGH | IDOC partner profiles with wildcard message types | — |
| `INTG-IDOC-004` | MEDIUM | IDOC partner profiles configured for sensitive message types | — |
| `INTG-MON-001` | HIGH | Missing integration monitoring alert rules | — |
| `INTG-MON-002` | MEDIUM | Integration events not forwarded to SIEM | — |
| `INTG-OAUTH-001` | HIGH | OAuth clients with admin-level or wildcard scopes | — |
| `INTG-OAUTH-002` | HIGH | OAuth clients using deprecated grant types (password/implicit) | — |
| `INTG-OAUTH-003` | MEDIUM | *varies* — OAuth clients unused for …+ days | — |
| `INTG-TOPO-001` | HIGH | Integration connections without encryption | — |
| `INTG-TOPO-002` | MEDIUM | Integration hub systems with excessive connections | — |
| `INTG-TOPO-003` | MEDIUM | Integration connections to deprecated/legacy systems | — |
| `INTG-WH-001` | HIGH | Webhook callbacks using unencrypted HTTP | — |
| `INTG-WH-002` | HIGH | Webhooks without signature/HMAC verification | — |
| `INTG-WH-003` | MEDIUM | Webhooks delivering events to external/third-party endpoints | — |
| `INTG-WH-004` | LOW | Stale webhook registrations with no recent activity | — |
| `INTG-WS-001` | HIGH | High-risk BAPIs/RFCs exposed as web services | — |
| `INTG-WS-002` | MEDIUM | *varies* — Excessive active web service endpoints (…) | — |
| `INTG-WS-003` | CRITICAL | Web service endpoints with weak/no authentication | — |

### `log_monitoring` — 14 checks

Category: Logging, Monitoring & IR

Reads: `audit_config`, `incident_response`, `log_retention`, `logon_events`, `security_audit_log`, `security_params`, `siem_config`, `table_logging` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `LOG-AUD-001` | *varies* — HIGH | *varies* — Security Audit Log has no active filters | `AUDIT-A` |
| `LOG-AUD-002` | HIGH | No static audit profile configured | `AUDIT-A` |
| `LOG-AUD-003` | HIGH | Security Audit Log missing event coverage | `AUDIT-A` |
| `LOG-AUD-010` | HIGH | Security Audit Log is not enabled (rsau/enable = 0) | `AUDIT-A` |
| `LOG-AUD-011` | MEDIUM | Security Audit Log integrity protection not active (rsau/integrity = 0) | `AUDIT-A` |
| `LOG-IR-001` | MEDIUM | Incident response readiness gaps | — |
| `LOG-LOGON-001` | CRITICAL | Potential brute-force attack patterns detected | — |
| `LOG-LOGON-002` | MEDIUM | Accounts with excessive logon failures | — |
| `LOG-RET-001` | MEDIUM | *varies* — Log retention below …-day minimum | — |
| `LOG-RET-002` | LOW | Security logs without archiving configured | — |
| `LOG-SIEM-001` | HIGH | *varies* — No SIEM integration configuration found | — |
| `LOG-SIEM-002` | MEDIUM | SIEM missing critical log source forwarding | — |
| `LOG-TBL-001` | HIGH | Critical tables without change logging enabled | — |
| `LOG-TBL-010` | HIGH | Table change logging master switch off (rec/client not set) | — |

### `log_review` — 15 checks

Reads: `audit_config`, `client_settings`, `logon_events`, `profiles`, `security_audit_log`, `standard_users` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `LREV-FLT-001` | HIGH | *varies* | — |
| `LREV-FLT-002` | HIGH | Audit filters do not cover every client in the system | — |
| `LREV-FLT-003` | MEDIUM | Event class recorded only by a dynamic filter — coverage is lost at restart | — |
| `LREV-PAT-001` | HIGH | Privileged dialog logons outside business hours in the reviewed window | — |
| `LREV-PAT-002` | CRITICAL | Failed logon run followed by a successful logon in the reviewed window | — |
| `LREV-PAT-003` | HIGH | SAP-delivered default accounts were active in the reviewed window | — |
| `LREV-PAT-004` | HIGH | Debug activity recorded in the reviewed window | — |
| `LREV-PAT-005` | MEDIUM | High-volume direct table access in the reviewed window | — |
| `LREV-PAT-006` | CRITICAL | The audit configuration itself was changed during the reviewed window | — |
| `LREV-PAT-007` | MEDIUM | Privileged logons from terminals that barely appear in the reviewed window | — |
| `LREV-SRC-001` | MEDIUM | No Security Audit Log event extract supplied — no window could be reviewed | — |
| `LREV-SRC-002` | MEDIUM | Audit log extract carries no usable event timestamp | — |
| `LREV-SRC-003` | MEDIUM | Audit filter configuration not supplied alongside the event extract | — |
| `LREV-WIN-001` | LOW | Reviewed window is too short to be representative | — |
| `LREV-WIN-002` | HIGH | *varies* | — |

### `master_data_changes` — 5 checks

Reads: `change_document_items`, `change_documents`, `payment_runs` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `MDC-BANK-001` | HIGH | Vendor / customer / business-partner bank details were changed | — |
| `MDC-DIRECT-001` | HIGH | Master data changed through direct table maintenance | — |
| `MDC-EVD-001` | LOW | Change-document items were supplied without before/after values | — |
| `MDC-PAY-001` | CRITICAL | A payment left into a bank account that had just been changed | — |
| `MDC-PAY-002` | INFO | Bank changes found, but no payment-run export to check them against | — |

### `network_services` — 8 checks

Category: Audit Logging, Change Management, Network & Service Exposure

Reads: `audit_config`, `icf_services`, `rfc_destinations`, `transports` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `NET-001` | HIGH | RFC destinations with stored credentials | `NETCF-A` |
| `NET-002` | MEDIUM | RFC destinations to external/non-RFC hosts | `NETCF-A` |
| `NET-003` | HIGH | RFC destinations without SNC encryption | `NETCF-A` |
| `NET-004` | HIGH | High-risk ICF services are active | `NETCF-A` |
| `NET-005` | CRITICAL | Active ICF services without authentication | `NETCF-A` |
| `NET-006` | MEDIUM | Open/unreleased transports in production | `NETCF-A` |
| `NET-007` | HIGH | Transports with debug/replace indicators | `NETCF-A` |
| `NET-008` | CRITICAL | No active security audit filters configured | `NETCF-A` |

### `resilience_posture` — 9 checks

Reads: `background_jobs`, `backup_catalog`, `hana_parameters`, `recovery_tests` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `RES-BCK-001` | HIGH | No recent successful full data backup recorded in the supplied catalogue | — |
| `RES-BCK-002` | MEDIUM | Backup runs are failing repeatedly despite a recorded success | — |
| `RES-BCK-003` | HIGH | No successful log backup recorded, so no point-in-time recovery evidence | — |
| `RES-BCK-004` | INFO | Backup recency could not be assessed from the supplied catalogue | — |
| `RES-DR-001` | MEDIUM | Recovery test evidence is missing, failed or stale | — |
| `RES-DR-002` | INFO | Backup evidence supplied without any recovery-test evidence | — |
| `RES-DR-003` | MEDIUM | Recorded recovery test did not meet its stated RTO / RPO target | — |
| `RES-EVD-001` | INFO | Part of the resilience evidence could not be read by this scan | — |
| `RES-JOB-001` | MEDIUM | Recovery-relevant background job recorded as aborted | — |

### `rise_btp_checks` — 7 checks

Category: RISE / BTP Security

Reads: `api_endpoints`, `btp_trust`, `comm_arrangements` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `RISE-001` | MEDIUM | *varies* — Default SAP IDP trust still active: … | — |
| `RISE-002` | MEDIUM | *varies* — Automatic shadow user creation enabled for … | — |
| `RISE-003` | MEDIUM | Communication arrangements with excessive service scope | — |
| `RISE-004` | CRITICAL | Communication arrangements with weak/no authentication | — |
| `RISE-005` | HIGH | Sensitive APIs/OData services exposed | — |
| `RISE-006` | MEDIUM | Communication users shared across many arrangements | — |
| `RISE-007` | HIGH | API endpoints with weak or no authentication | — |

### `role_governance` — 3 checks

Reads: `role_auth_values`, `role_details`, `role_profiles`, `su24_proposals`, `user_roles` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `RG-DRV-001` | MEDIUM | Derived roles have authorizations that drifted from their parent | — |
| `RG-GEN-001` | MEDIUM | *varies* — Roles with no generated authorization profile are assigned to users or Roles with no generated authorization profile | — |
| `RG-SU24-001` | MEDIUM | Custom transactions without maintained SU24 authorization proposals | — |

### `ruleset_coverage` — 11 checks

Reads: `role_auth_values` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `SODCOV-000` | *varies* | *varies* | — |
| `SODCOV-001` | *varies* | *varies* | — |
| `SODCOV-002` | *varies* — INFO or MEDIUM | *varies* | — |
| `SODCOV-003` | MEDIUM | *varies* | — |
| `SODCOV-004` | MEDIUM | SoD ruleset coverage could not be measured | — |
| `SODCOV-005` | HIGH | *varies* | — |
| `SODCOV-006` | *varies* | *varies* | — |
| `SODCOV-007` | *varies* — HIGH or MEDIUM | *varies* | — |
| `SODCOV-008` | *varies* — CRITICAL or HIGH | *varies* | — |
| `SODCOV-009` | MEDIUM | *varies* | — |
| `SODCOV-010` | *varies* — INFO or MEDIUM | *varies* | — |

### `s4_business_authz` — 8 checks

Reads: `btp_role_collection_mappings`, `business_role_catalogs`, `business_role_restrictions`, `business_roles`, `cds_views`, `cf_roles`, `cloud_connector`, `odata_v4_services` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `S4AUTHZ-001` | CRITICAL | Super-admin business role template assigned in production | — |
| `S4AUTHZ-002` | HIGH | Business-role restriction left 'Unrestricted' | — |
| `S4AUTHZ-003` | MEDIUM | *varies* — Business role bundles more than … business catalogs | — |
| `S4AUTHZ-004` | HIGH | CDS view exposes data with authorization checking disabled | — |
| `S4AUTHZ-005` | HIGH | OData V4 service group published without authorization | — |
| `S4AUTHZ-006` | HIGH | Cloud Connector system mapping without principal propagation | — |
| `S4AUTHZ-007` | HIGH | Cloud Foundry privileged platform role over-assigned | — |
| `S4AUTHZ-008` | MEDIUM | Birthright role collection auto-granted to all federated users | — |

### `sap_hotnews` — 16 checks

Reads: `applied_notes`, `hana_version`, `role_auth_values`, `sap_security_notes`, `system_component` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `HOTNEWS-000` | MEDIUM | SAP Note implementation status not provided | `SECUPD-A` |
| `HOTNEWS-001` | CRITICAL | Missing HotNews (Priority 1) SAP Security Notes | `SECUPD-A` |
| `HOTNEWS-002` | HIGH | Missing High-priority SAP Security Notes | `SECUPD-A` |
| `HOTNEWS-003` | CRITICAL | Missing notes for actively-exploited SAP vulnerabilities | `SECUPD-A` |
| `HOTNEWS-004` | HIGH | Critical SAP Notes only partially implemented | `SECUPD-A` |
| `HOTNEWS-005` | INFO | Catalogue notes this system's export can neither confirm nor deny | `SECUPD-A` |
| `HOTNEWS-006` | CRITICAL | Installed release is inside the affected range of an unpatched note | `SECUPD-A` |
| `HOTNEWS-007` | HIGH | Unpatched notes exploitable without any credentials | `SECUPD-A` |
| `HOTNEWS-008` | INFO | Installed release is not in the published affected list (verify before deprioritising) | `SECUPD-A` |
| `HOTNEWS-009` | HIGH | Note not implemented and its published workaround is not in place either | `SECUPD-A` |
| `HOTNEWS-010` | INFO | Exposure could not be established for some notes | `SECUPD-A` |
| `HOTNEWS-011` | LOW | Note facts differ between this catalogue and SAP's published record | `SECUPD-A` |
| `HOTNEWS-012` | HIGH | SAP-published HotNews notes absent from the applied-notes export | `SECUPD-A` |
| `HOTNEWS-013` | *varies* — CRITICAL or HIGH | Installed component is below the support package that fixes an unpatched note | `SECUPD-A` |
| `HOTNEWS-014` | *varies* — CRITICAL or HIGH | Note recorded as applied, but the fix it needs is not installed | `SECUPD-A` |
| `HOTNEWS-COVERAGE` | INFO | SAP note check ran against a curated subset, not the full patch history | `SECUPD-A` |

### `security_params` — 7 checks

Category: Password Policy, Security Parameters

Reads: `password_hashes`, `security_params`, `security_policies`, `users` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `PARAM-000` | HIGH | No security parameters data available | — |
| `PARAM-MISSING` | HIGH | Critical security parameters not found in export | — |
| `PARAM-MISSING-OTHER` | INFO | Further security parameters not found in export | — |
| `PWDHASH-001` | HIGH | Downward-compatible password hashes still present | `PWDPOL-A` |
| `SECPOL-001` | HIGH | Security policies weaken the instance password parameters | `PWDPOL-A` |
| `SECPOL-002` | INFO | Security policies are in use but were not exported | `PWDPOL-A` |
| `SECPOL-003` | INFO | Security-policy attributes this scan did not assess | `PWDPOL-A` |

### `snc_posture` — 7 checks

Reads: `security_params` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `CRYPTO-SNCECS-000` | INFO | SNC posture could not be assessed from this export | `NETENC-A` |
| `CRYPTO-SNCECS-001` | HIGH | SNC is not enabled, so the mandated ECS SNC baseline is not in force | `NETENC-A` |
| `CRYPTO-SNCECS-002` | MEDIUM | SNC connection-acceptance parameters deviate from the ECS baseline | `NETENC-A` |
| `CRYPTO-SNCECS-003` | *varies* | SNC protection level deviates from the ECS baseline | `NETENC-A` |
| `CRYPTO-SNCECS-004` | MEDIUM | SNC protection-level parameters contradict each other | `NETENC-A` |
| `CRYPTO-SNCECS-005` | MEDIUM | SNC identity is not consistent with the ECS baseline | `NETENC-A` |
| `CRYPTO-SNCECS-006` | MEDIUM | SNC GSS-API library is not the one the ECS baseline mandates | `NETENC-A` |

### `system_trust` — 15 checks

Reads: `client_settings`, `ms_acl`, `rfc_destinations`, `rfc_trust`, `saprouttab`, `security_params`, `standard_users` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `OBSCNT-001` | MEDIUM | Obsolete client 066 still exists | `OBSCNT-A` |
| `OBSCNT-002` | LOW | Template client 001 still exists | `OBSCNT-A` |
| `STDUSR-001` | CRITICAL | SAP* kernel emergency-user auto-logon is enabled | `STDUSR-A` |
| `STDUSR-002` | CRITICAL | Standard users still have SAP default passwords | `STDUSR-A` |
| `STDUSR-003` | HIGH | Standard users not locked | `STDUSR-A` |
| `STDUSR-COV-001` | INFO | *varies* | `STDUSR-A` |
| `TRUST-001` | *varies* — HIGH or MEDIUM | Inbound trusted-RFC relationships (verify no trust from a lower tier) | `RFCGW-A` |
| `TRUST-002` | HIGH | RFC self-trust enabled | `RFCGW-A` |
| `TRUST-003` | HIGH | Trusted-RFC relationships not migrated to the current security method | `RFCGW-A` |
| `TRUST-004` | HIGH | Trusted RFC destination configured with a fixed logon user | `RFCGW-A` |
| `TRUST-005` | HIGH | SAProuter route table allows wildcard target host/port | `RFCGW-A` |
| `TRUST-006` | HIGH | Message-server internal/external separation weak | `MSGSRV-A` |
| `TRUST-007` | HIGH | UCON RFC allowlist is not active | `RFCGW-A` |
| `TRUST-008` | MEDIUM | RFC Gateway proxy ACL (gw/prxy_info) not configured | `RFCGW-A` |
| `TRUST-010` | HIGH | Message-server ACL permits any host to register (rogue app server) | `MSGSRV-A` |

### `ucon_exposure` — 5 checks

Reads: `gw_reginfo`, `gw_secinfo`, `ucon_http_allowlist`, `ucon_rfc_state` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `UCON-001` | *varies* — HIGH or MEDIUM | *varies* — UCON RFC scenario is still recording for … function module(s) | — |
| `UCON-002` | MEDIUM | *varies* — … externally callable function module(s) were never called | — |
| `UCON-003` | HIGH | *varies* — … is callable from outside the system | — |
| `UCON-004` | MEDIUM | The UCON HTTP allowlist was supplied and is empty | — |
| `UCON-COV-001` | INFO | No UCON data was supplied, so remote-callable exposure was not assessed | — |

### `user_auth_audit` — 10 checks

Category: User & Authorization

Reads: `auth_objects`, `profiles`, `user_roles`, `users` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `USR-001` | *varies* — CRITICAL or HIGH | *varies* — Default user … is unlocked | `STDUSR-A` |
| `USR-002` | CRITICAL | *varies* — Users assigned critical profiles (…) | `STDUSR-A` |
| `USR-003` | MEDIUM | *varies* — Dormant accounts (…+ days inactive) | `STDUSR-A` |
| `USR-004` | HIGH | Service/technical accounts with dialog logon type | `STDUSR-A` |
| `USR-005` | MEDIUM | *varies* — Users with excessive role assignments (>…) | `STDUSR-A` |
| `USR-006` | HIGH | *varies* — Users with wildcard access on … | `STDUSR-A` |
| `USR-007` | LOW | Active accounts that have never logged in | `STDUSR-A` |
| `USR-008` | MEDIUM | *varies* — Dialog users with stale passwords (>… days) | `STDUSR-A` |
| `USR-009` | *varies* — HIGH or MEDIUM | DDIC is a dialog user on an ECS-managed system | `STDUSR-A` |
| `USR-010` | *varies* — HIGH or LOW | EARLYWATCH still exists on an ECS-managed system | — |

### `vendor_master` — 3 checks

Reads: `vendor_bank`, `vendor_master` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `VBM-BANK-001` | HIGH | One bank account is shared by several business partners | — |
| `VBM-DATA-001` | LOW | Bank export contains no account numbers, so no account can be compared | — |
| `VBM-SOLE-001` | MEDIUM | Payment-relevant partners created and last changed by the same person | — |

### `webdisp_security` — 1 check

Reads: `webdisp_params` — the sources the MODULE consumes; an individual check below reads some subset of them.

| Check | Severity | Title | SAP Baseline |
|---|---|---|---|
| `WDISP-COV-001` | INFO | No Web Dispatcher profile was supplied, so the internet-facing instance was not assessed | — |

## Runtime check families

These ids are constructed per entry in a shipped table, so the catalogue grows with the table and not with the code.

### `WDISP-<nnn>` — 14

Source: `data/webdisp_baseline.json — rules`

SAP Baseline: `DISCL-O`, `NETENC-O`

Examples: `WDISP-001`, `WDISP-002`, `WDISP-003`, `WDISP-004`, `WDISP-005`, `WDISP-006`

Transcribed from SAP's WEBDISP_ALL baseline policies (2ODISCL, 2ONETENC). `WDISP-COV-001` is a fixed id and appears in the literal table.

### `PARAM-<parameter name>` — 79

Source: `modules/security_params.py — BASELINE + ECS_RULES`

SAP Baseline: `CHANGE-A`, `FILE-A`, `NETCF-A`, `NETENC-A`, `PWDPOL-A`, `RFCGW-A`, `SCRIPT-A`, `USRCTR-A` — 68 of 79 answer none, which for this family is expected rather than a gap.

Examples: `PARAM-abap/ext_debugging_possible`, `PARAM-abap/path_normalization`, `PARAM-auth/check/calltransaction`, `PARAM-auth/no_check_in_some_cases`, `PARAM-auth/object_disabling_active`, `PARAM-auth/rfc_authority_check`

One id per judged profile parameter. `PARAM-000`, `PARAM-MISSING` and `PARAM-MISSING-OTHER` are fixed ids and appear in the literal table.

### `ABAP-<rule id>` — 135

Source: `modules/abap_sast.py — ALL_ABAP_SAST_RULES (118) + ALL_JS_RULES (7) + ALL_BTP_CONFIG_RULES (8) + CROSS_ARTIFACT_RULES (3)`

Examples: `ABAP-AMDP-001`, `ABAP-AMDP-002`, `ABAP-AMDP-003`, `ABAP-AMDP-004`, `ABAP-AMDP-005`, `ABAP-AUTH-001`

Custom-code scan rules. All four tables emit into the same `ABAP-` namespace: ABAP/UI5, JavaScript, BTP descriptors, and the cross-artefact checks, which carry no pattern because the finding is the ABSENCE of an artefact.

### `ARA-<risk id>` — 99

Source: `modules/access_risk_analysis.py — RULESET`

SAP Baseline: `CRITAU-A`

Examples: `ARA-BASIS-01`, `ARA-BASIS-02`, `ARA-BASIS-03`, `ARA-BASIS-04`, `ARA-BASIS-05`, `ARA-BASIS-06`

Segregation-of-duties and critical-access risks, extendable by a customer's own `ara_ruleset.json`.

### `ATC-<family>` — 10

Source: `modules/atc_import.py — FAMILIES`

Examples: `ATC-AUTHCHK`, `ATC-CINJ`, `ATC-CMDI`, `ATC-CRED`, `ATC-CRYP`, `ATC-INFO`

ABAP Test Cockpit finding families, imported from an ATC export.

### `IAM-<sod rule>` — 7

Source: `modules/iam_advanced.py — DEFAULT_SOD_RULES`

Examples: `IAM-SOD-BASIS-001`, `IAM-SOD-FIN-001`, `IAM-SOD-FIN-002`, `IAM-SOD-FIN-003`, `IAM-SOD-FIN-004`, `IAM-SOD-HR-001`

Conflicting-duty pairs.

---

Generated by `tools/build_checks_reference.py`. Run `python -m tools.build_checks_reference` after changing a check.
