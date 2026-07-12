# Security Checks Reference

Complete reference for all checks performed by the scanner.

---

## User & Authorization (USR-*)

| ID | Title | Severity | Data Source |
|----|-------|----------|-------------|
| USR-001 | Default users unlocked | CRITICAL/HIGH | users.csv |
| USR-002 | Critical profile assignments (SAP_ALL) | CRITICAL | profiles.csv |
| USR-003 | Dormant accounts (90+ days) | MEDIUM | users.csv |
| USR-004 | Service accounts with dialog logon | HIGH | users.csv |
| USR-005 | Excessive role assignments | MEDIUM | user_roles.csv |
| USR-006 | Wildcard authorization values | HIGH | auth_objects.csv |
| USR-007 | Never-logged-in accounts | LOW | users.csv |
| USR-008 | Stale passwords (180+ days) | MEDIUM | users.csv |

---

## Advanced IAM — SoD Conflicts (IAM-SOD-*)

| ID | Title | Severity | Data Source |
|----|-------|----------|-------------|
| IAM-SOD-FIN-001 | Vendor Master ↔ Payment Processing | CRITICAL | sod_matrix.csv |
| IAM-SOD-FIN-002 | Purchase Order ↔ Goods Receipt | HIGH | sod_matrix.csv |
| IAM-SOD-FIN-003 | Journal Entry ↔ GL Account Master | HIGH | sod_matrix.csv |
| IAM-SOD-FIN-004 | Customer Master ↔ Sales/Billing | HIGH | sod_matrix.csv |
| IAM-SOD-HR-001 | HR Master Data ↔ Payroll | CRITICAL | sod_matrix.csv |
| IAM-SOD-SEC-001 | User Admin ↔ Role Admin | CRITICAL | sod_matrix.csv |
| IAM-SOD-BASIS-001 | Transport Mgmt ↔ Development | HIGH | sod_matrix.csv |

SoD checks support three data strategies:
1. **Pre-computed matrix** (`sod_matrix.csv`) — simplest, one row per user with all t-codes
2. **Role resolution** (`user_roles.csv` + `role_tcodes.csv`) — scanner resolves user→role→tcode chain
3. **Heuristic** (`user_roles.csv` only) — role-name pattern matching (less precise)

---

## Advanced IAM — Firefighter / Emergency Access (IAM-FF-*)

| ID | Title | Severity | Config Key |
|----|-------|----------|------------|
| IAM-FF-001 | Sessions exceeding max duration | HIGH | `ff_max_duration_hours` (default: 4) |
| IAM-FF-002 | Sessions without justification | HIGH | — |
| IAM-FF-003 | Sessions not reviewed by controller | CRITICAL | — |
| IAM-FF-004 | Sessions self-approved | CRITICAL | — |
| IAM-FF-005 | Users with excessive usage frequency | MEDIUM | `ff_max_sessions_per_month` (default: 5) |

---

## Advanced IAM — Role Lifecycle (IAM-EXP-*, IAM-ROLE-*, IAM-ORPH-*)

| ID | Title | Severity | Config Key |
|----|-------|----------|------------|
| IAM-EXP-001 | Role assignments without expiry dates | MEDIUM | — |
| IAM-EXP-002 | Expired assignments still present | LOW | — |
| IAM-EXP-003 | Excessive validity periods | MEDIUM | `max_role_validity_days` (default: 365) |
| IAM-ROLE-001 | Custom roles without descriptions | LOW | — |
| IAM-ROLE-002 | Custom roles without owners | MEDIUM | — |
| IAM-ROLE-003 | Empty roles (no transactions) | LOW | — |
| IAM-ORPH-001 | Assignments to deleted roles | MEDIUM | — |

---

## Advanced IAM — Cross-System & Privilege (IAM-XID-*, IAM-*)

| ID | Title | Severity | Data Source |
|----|-------|----------|-------------|
| IAM-XID-001 | BTP users without S/4 counterpart | MEDIUM | btp_users.json + users.csv |
| IAM-XID-002 | S/4 locked users active in BTP | HIGH | btp_users.json + users.csv |
| IAM-XID-003 | BTP admin role collection holders | HIGH | btp_users.json |
| IAM-REV-001 | Overdue access review campaigns | HIGH | access_reviews.csv |
| IAM-REV-002 | Incomplete reviews marked done | MEDIUM | access_reviews.csv |
| IAM-REV-003 | Reviews without assigned reviewer | MEDIUM | access_reviews.csv |
| IAM-USRGRP-001 | Users in default user groups | LOW | users.csv / user_groups.csv |
| IAM-REF-001 | Dialog users as reference users | HIGH | users.csv |
| IAM-PRIV-001 | Privilege escalation paths | CRITICAL | auth_objects.csv |

---

## Security Parameters (PARAM-*)

25+ parameters checked. See `modules/security_params.py` for the full baseline with expected values, operators, and CIS references.

---

## Network & Services (NET-*)

| ID | Title | Severity | Data Source |
|----|-------|----------|-------------|
| NET-001 | RFC stored credentials | HIGH | rfc_destinations.csv |
| NET-002 | External RFC destinations | MEDIUM | rfc_destinations.csv |
| NET-003 | RFC without SNC | HIGH | rfc_destinations.csv |
| NET-004 | High-risk ICF services active | HIGH | icf_services.csv |
| NET-005 | ICF without authentication | CRITICAL | icf_services.csv |
| NET-006 | Open transports in production | MEDIUM | transports.csv |
| NET-007 | Debug/replace transports | HIGH | transports.csv |
| NET-008 | No active audit filters | CRITICAL | audit_config.csv |

---

## RISE / BTP (RISE-*)

| ID | Title | Severity | Data Source |
|----|-------|----------|-------------|
| RISE-001 | Default SAP IDP active | MEDIUM | btp_trust.json |
| RISE-002 | Shadow user auto-creation | MEDIUM | btp_trust.json |
| RISE-003 | Over-scoped comm arrangements | MEDIUM | comm_arrangements.json |
| RISE-004 | Weak auth on comm arrangements | CRITICAL | comm_arrangements.json |
| RISE-005 | Sensitive APIs exposed | HIGH | api_endpoints.json |
| RISE-006 | Shared communication users | MEDIUM | comm_arrangements.json |
| RISE-007 | API weak authentication | HIGH | api_endpoints.json |

---

## HANA Database Security (HANADB-*)

The database layer beneath S/4HANA — privileged access, auditing and security
parameters. Aligned to the CIS SAP HANA Benchmark and the SAP HANA Security Guide.
(Encryption-at-rest of the HANA data/log volumes is covered by CRYPTO-HANA-*.)

| ID | Title | Severity | Data Source |
|----|-------|----------|-------------|
| HANADB-USER-001 | HANA SYSTEM superuser still active | CRITICAL | hana_db_users.csv |
| HANADB-USER-002 | DB users with password lifetime check disabled | HIGH | hana_db_users.csv |
| HANADB-USER-003 | Dormant HANA DB users (90+ days) | MEDIUM | hana_db_users.csv |
| HANADB-PRIV-001 | Sensitive privileges granted to PUBLIC | CRITICAL | hana_granted_privileges.csv |
| HANADB-PRIV-002 | Critical system privileges granted directly to users | CRITICAL | hana_granted_privileges.csv |
| HANADB-PRIV-003 | Broad system privileges granted directly to users | HIGH | hana_granted_privileges.csv |
| HANADB-PRIV-004 | Sensitive privileges granted WITH ADMIN/GRANT OPTION | MEDIUM | hana_granted_privileges.csv |
| HANADB-PRIV-005 | Analytic-privilege bypass (_SYS_BI_CP_ALL) granted | CRITICAL | hana_granted_privileges.csv / hana_granted_roles.csv |
| HANADB-ROLE-001 | Powerful predefined roles granted to users | HIGH | hana_granted_roles.csv |
| HANADB-AUDIT-001 | HANA database auditing disabled | CRITICAL | hana_parameters.csv |
| HANADB-AUDIT-002 | Audit trail written to CSV text file (tamperable) | HIGH | hana_parameters.csv |
| HANADB-AUDIT-003 | No active HANA audit policies | HIGH | hana_audit_policies.csv |
| HANADB-AUDIT-004 | Audit policies miss critical action groups | MEDIUM | hana_audit_policies.csv |
| HANADB-PARAM-001 | Weak HANA password-policy parameters | HIGH | hana_parameters.csv |
| HANADB-PARAM-002 | Detailed connect errors exposed to clients | MEDIUM | hana_parameters.csv |
| HANADB-PARAM-003 | TLS not enforced for HANA SQL connections | HIGH | hana_parameters.csv |
| HANADB-PARAM-004 | log_mode = overwrite (no point-in-time recovery) | HIGH | hana_parameters.csv |
| HANADB-PARAM-005 | Cross-database (MDC) access enabled | MEDIUM | hana_parameters.csv |
| HANADB-PRIV-006 | DEBUG / ATTACH DEBUGGER privileges granted (runtime data exposure) | HIGH | hana_granted_privileges.csv |

Data sources (all optional; the check runs only if the file is present):
`hana_db_users.csv` (SYS.USERS export), `hana_granted_privileges.csv`
(GRANTED_PRIVILEGES), `hana_granted_roles.csv` (GRANTED_ROLES),
`hana_parameters.csv` (M_INIFILE_CONTENTS), `hana_audit_policies.csv` (AUDIT_POLICIES).

---

## SAP Security Notes / HotNews (HOTNEWS-*)

Flags missing critical SAP Security Notes by diffing the system's implemented
notes (SNOTE export) against a **curated, verified catalog** of the highest-impact
HotNews (Priority 1, CVSS 9.0-10.0) and High (Priority 2) notes released since 2020
— RECON (CVE-2020-6287), ICMAD (CVE-2022-22536), the NetWeaver Visual Composer RCEs
(incl. the actively-exploited CVE-2025-31324), Solution Manager auth bypass, and
more. Every catalog entry (note ↔ CVE ↔ CVSS ↔ component ↔ date ↔ exploited) was
verified against SAP Security Patch Day / NVD / CISA KEV. The catalog is a
high-signal subset, not exhaustive; supply `sap_security_notes.json` to add the
HotNews/High notes for your specific product versions and the module merges them.

| ID | Title | Severity | Data Source |
|----|-------|----------|-------------|
| HOTNEWS-000 | SAP Note implementation status not provided | MEDIUM | (fires when applied_notes absent) |
| HOTNEWS-001 | Missing HotNews (Priority 1) SAP Security Notes | CRITICAL | applied_notes.csv |
| HOTNEWS-002 | Missing High-priority SAP Security Notes | HIGH | applied_notes.csv |
| HOTNEWS-003 | Missing notes for actively-exploited vulnerabilities (CISA KEV) | CRITICAL | applied_notes.csv |
| HOTNEWS-004 | Critical SAP Notes only partially implemented | HIGH | applied_notes.csv |

Data sources: `applied_notes.csv` (SNOTE / SAP Note implementation status export:
columns NOTE, STATUS [, TITLE]); `sap_security_notes.json` (optional catalog to
merge — list of `{note, cve, cvss, priority, component, released, exploited, title}`).

---

## ABAP Authorization & Critical Access (AUTH-*)

Evaluates the **content** of ABAP roles at the authorization-object / field / value
level — the deep analysis a flat user-value scan cannot do — by parsing an
`AGR_1251` export and attributing each risky role to its holders (`AGR_USERS`).
Grounded in the SAP Security Baseline, DSAG audit guidelines, and SAP Notes
65968 / 1416085 / 1481950.

| ID | Title | Severity | Object / condition |
|----|-------|----------|--------------------|
| AUTH-001 | Debug & Replace (runtime authorization bypass) | CRITICAL | S_DEVELOP OBJTYPE=DEBUG + ACTVT=02 |
| AUTH-002 | Trusted-RFC logon as any user | CRITICAL | S_RFCACL RFC_USER/RFC_SYSID=* (RFC_EQUSER≠Y) |
| AUTH-003 | Unrestricted external OS-command execution | CRITICAL | S_LOG_COM COMMAND=* + HOST=* |
| AUTH-004 | Authorization forging via role-content objects | CRITICAL | S_USER_AUT/S_USER_TCD/S_USER_VAL wildcard |
| AUTH-005 | Role allows starting any transaction | CRITICAL | S_TCODE TCD=* |
| AUTH-006 | Broad RFC authorization | HIGH | S_RFC RFC_NAME=* |
| AUTH-007 | Generic table write via S_TABU_NAM | HIGH | S_TABU_NAM TABLE=* + ACTVT=02 |
| AUTH-008 | Generic table maintenance via S_TABU_DIS | HIGH | S_TABU_DIS DICBERCLS=*/&NC& + ACTVT=02 |
| AUTH-009 | Cross-client table maintenance | HIGH | S_TABU_CLI CLIIDMAINT=X |
| AUTH-010 | Arbitrary OS file access from ABAP | HIGH | S_DATASET FILENAME=* + PROGRAM=* |
| AUTH-011 | Run-any-report authorization | HIGH | S_PROGRAM P_ACTION=SUBMIT + P_GROUP=*/blank |
| AUTH-012 | Background-job impersonation | HIGH | S_BTCH_NAM BTCUNAME=* |
| AUTH-013 | Sensitive Basis / administration transactions in roles | HIGH | S_TCODE TCD ∈ critical-tcode catalog |
| AUTH-014 | ABAP development change access | HIGH | S_DEVELOP ACTVT 01/02 on non-DEBUG object types |
| AUTH-015 | Global authorization-object disabling active | MEDIUM | auth/object_disabling_active = Y |
| AUTH-016 | Unrestricted destination authorization | HIGH | S_ICF ICF_FIELD=DEST + ICF_VALUE=* (SM59 auth-group value) |

Data sources: `role_auth_values.csv` (AGR_1251: AGR_NAME, OBJECT, AUTH, FIELD, LOW,
HIGH [, DELETED]); `user_roles.csv` (AGR_USERS, for holder attribution);
`security_params.csv` (for AUTH-015). Runs only if `role_auth_values.csv` is present.

---

## System Trust & Standard Users (TRUST-* / STDUSR-*)

The landscape trust / connectivity surface (lateral-movement paths between SAP
systems) and the standard/default accounts. Grounded in the SAP Security Baseline
and SAP Notes 128447 / 3089413 / 3157268 / 1421005 / 910918 / 2383.

| ID | Title | Severity | Source / condition |
|----|-------|----------|--------------------|
| STDUSR-001 | SAP* kernel emergency-user auto-logon enabled | CRITICAL | login/no_automatic_user_sapstar = 0 |
| STDUSR-002 | Standard users still have SAP default passwords | CRITICAL | RSUSR003 default-password flag |
| STDUSR-003 | Standard users not locked | HIGH | RSUSR003 lock status |
| TRUST-001 | Inbound trusted-RFC relationships (verify tier) | HIGH/MEDIUM | RFCSYSACL (trusted SID, non-prod prefix) |
| TRUST-002 | RFC self-trust enabled | HIGH | rfc/selftrust = 1 or self-SID trust |
| TRUST-003 | Trust not migrated to current security method | HIGH | rfc/allowoldticket4tt = yes / unmigrated RFCSYSACL |
| TRUST-004 | Trusted RFC destination with a fixed logon user | HIGH | RFCDES trusted + fixed RFCUSER |
| TRUST-005 | SAProuter route table allows wildcard host/port | HIGH | saprouttab P/S wildcard rule |
| TRUST-006 | Message-server internal/external separation weak | HIGH | rdisp/msserv_internal = 0 / ms/monitor ≠ 0 |
| TRUST-007 | UCON RFC allowlist not active | HIGH | ucon/rfc/active ≠ 1 |
| TRUST-008 | RFC Gateway proxy ACL (gw/prxy_info) not configured | MEDIUM | gw/prxy_info empty (and gw/acl_mode_proxy ≠ 1) |

Data sources: `security_params.csv` (profile parameters), `rfc_trust.csv`
(RFCSYSACL / SMT1 export), `standard_users.csv` (RSUSR003 export),
`saprouttab.csv` (SAProuter route table), `rfc_destinations.csv` (SM59, for TRUST-004).

---

## Security Baseline Parameters (BASELINE-*)

Profile parameters from the **SAP Security Baseline Template / DSAG / CIS** that the
other modules do not already cover — the authorization engine, SNC insecure fallback,
GUI scripting, weak legacy password hashes, sapstartsrv web methods, the RFC gateway
ACL mode, SSO ticket/cookie transport, and the ICM security log / error disclosure.
(Password length/complexity/expiry live in Security Parameters; `snc/enable` and data
encryption in Cryptographic Posture; the message server and `gw/prxy_info` in System
Trust; `auth/object_disabling_active` in ABAP Authorization — deliberately not repeated.)

| ID | Title | Severity | Source / condition |
|----|-------|----------|--------------------|
| BASELINE-001 | RFC authorization check disabled | HIGH | auth/rfc_authority_check = 0 (harden to 9) |
| BASELINE-002 | Profile-generator auth checks not active | HIGH | auth/no_check_in_some_cases = N (baseline requires Y) |
| BASELINE-003 | SNC accepts insecure (unencrypted) connections | HIGH | snc/accept_insecure_rfc\|gui\|cpic\|r3int_rfc = 1 or U |
| BASELINE-004 | SAP GUI Scripting enabled server-side | HIGH | sapgui/user_scripting = TRUE |
| BASELINE-005 | Weak legacy password hashes retained | HIGH | login/password_downwards_compatibility > 0 |
| BASELINE-006 | sapstartsrv / Host Agent web methods not protected | HIGH | service/protectedwebmethods not SDEFAULT/ALL |
| BASELINE-007 | RFC Gateway default ACL not enforced | MEDIUM | gw/acl_mode = 0 (10KBLAZE misconfig class; CISA AA19-122A) |
| BASELINE-008 | SSO ticket / session-cookie transport not hardened | MEDIUM | login/ticket_only_by_https = 0 / icf/set_HTTPonly_flag_on_cookies ≠ 0 / login/ticket_only_to_host = 0 |
| BASELINE-009 | Web-tier logging / error disclosure weak (ICM) | MEDIUM | icm/security_log LEVEL < 3 / is/HTTP/show_detailed_errors = TRUE |
| BASELINE-010 | Existing passwords not forced to current policy | MEDIUM | login/password_compliance_to_current_policy = 0 |
| BASELINE-011 | Weak password hash algorithm | HIGH/MEDIUM | login/password_hash_algorithm uses iSSHA-1/MD5 or iterations < 10000 |

Data source: `security_params.csv` (RSPARAM / RZ11 profile parameter export). The
module self-skips when no parameter export is present.

---

## S/4HANA & Cloud Authorization (S4AUTHZ-*)

The cloud-era authorization layer between the classic ABAP checks and BTP:
S/4HANA business roles / catalogs / restrictions, CDS access-control, OData V4,
Cloud Connector principal propagation, and Cloud Foundry platform roles. Each check
self-skips when its data source is absent.

| ID | Title | Severity | Source / condition |
|----|-------|----------|--------------------|
| S4AUTHZ-001 | Super-admin business role template assigned in production | CRITICAL | business_roles: SAP_BR_ADMINISTRATOR / _MDG assigned to a business user |
| S4AUTHZ-002 | Business-role restriction left 'Unrestricted' | HIGH | business_role_restrictions: sensitive type or Write = Unrestricted |
| S4AUTHZ-003 | Business role bundles more than 30 business catalogs | MEDIUM | business_role_catalogs: catalog count per role > threshold (default 30) |
| S4AUTHZ-004 | CDS view exposes data with authorization checking disabled | HIGH | cds_views: @AccessControl.authorizationCheck #NOT_REQUIRED / #NOT_ALLOWED and exposed |
| S4AUTHZ-005 | OData V4 service group published without authorization | HIGH | odata_v4_services: published (/IWFND/V4_ADMIN) + no S_SERVICE |
| S4AUTHZ-006 | Cloud Connector system mapping without principal propagation | HIGH | cloud_connector: HTTP(S) mapping principalType = None |
| S4AUTHZ-007 | Cloud Foundry privileged platform role over-assigned | HIGH | cf_roles: Org Manager / Space Manager / Space Developer > threshold (default 5) |
| S4AUTHZ-008 | Birthright role collection auto-granted to all federated users | MEDIUM | btp_role_collection_mappings: role collection mapped to Default / wildcard IdP group |

Data sources: `business_roles.csv`, `business_role_restrictions.csv`,
`business_role_catalogs.csv`, `cds_views.csv`, `odata_v4_services.csv`,
`cloud_connector.json` (SCC system mappings), `cf_roles.csv`,
`btp_role_collection_mappings.csv`.

---

## Access Risk Analysis — Segregation of Duties (ARA-*)

GRC-style **offline** Access Risk Analysis. For each user, the module resolves — across
all assigned roles — the transaction codes (S_TCODE) **and** the authorization
object/field/value combinations held, from the AGR_1251 export, then evaluates a verified
ruleset at the **permission level**. A conflict fires only when a user holds the maintaining
**activity** (ACTVT 01/02, HR AUTHC W/E/S, release 43, …) — not mere display (ACTVT 03 /
AUTHC R,M) — which removes the display-only false positives a transaction-level check
produces. Each risk = one finding id `ARA-<risk_id>`; there is one aggregate `ARA-SCORE-001`
user risk profile. Documented mitigating controls (with validity dates) suppress the
matching user/risk and are reported as *residual*. When AGR_USERS is absent the analysis
runs per role (a single role that already contains both functions).

**Segregation-of-Duties conflicts (SOD, 25 risks):**

| ID | Conflict | Severity |
|----|----------|----------|
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

**Critical single-function access (H2R, 2 risks) + risk profile:**

| ID | Risk | Severity |
|----|------|----------|
| ARA-CA-04 | Change Payroll Status / Delete Payroll Results (PU03/PU01) | HIGH |
| ARA-CP-05 | Maintain Own HR Master Data (P_PERNR PSIGN=I) | HIGH |
| ARA-SCORE-001 | Users concentrating ≥2 unmitigated access risks (severity-weighted) | HIGH/MEDIUM |

Data sources: `role_auth_values.csv` (AGR_1251), `user_roles.csv` (AGR_USERS),
`mitigating_controls.csv` (optional: USER, RISK_ID, CONTROL_ID, VALID_TO),
`ara_ruleset.json` (optional: custom risks that extend/override the built-in ruleset).
The ruleset was built and web-verified against SAP authorization-object documentation and
standard GRC/vendor rulesets; single-object critical actions already covered role-side by
the ABAP Authorization module (debug-replace, S_RFCACL, table maintenance, OS command,
run-any-report) and SAP_ALL (User module) are intentionally not duplicated here.

---

## Basis Jobs & OS Commands (JOBCMD-*)

The realised **host-command-execution** and background-processing surface — where an SAP
misconfiguration becomes operating-system code execution or batch privilege escalation.
It inspects the actual command catalog (SM69 / SXPGCOSTAB) and the actual armed jobs
(TBTCO/TBTCP), complementing the ABAP Authorization module, which covers who is *authorized*
to run commands / set a foreign step user (S_LOG_COM, S_BTCH_NAM). Only *armed* jobs
(STATUS scheduled/released/ready/active) are evaluated.

| ID | Title | Severity | Source / condition |
|----|-------|----------|--------------------|
| JOBCMD-CMD-001 | External OS command wraps a shell / interpreter | CRITICAL | SXPGCOSTAB OPCOMMAND basename in {sh,bash,cmd,powershell,python,…} or shell metacharacter in OPCOMMAND/PARAMETERS |
| JOBCMD-CMD-002 | External OS command allows runtime additional parameters | HIGH | SXPGCOSTAB ADDPAR truthy (X) |
| JOBCMD-CMD-003 | External OS command on an unqualified or writable path | HIGH | OPCOMMAND bare name (PATH hijack) / relative / /tmp,/var/tmp,%TEMP%,C:\Users… |
| JOBCMD-CMD-004 | Destructive / exfiltration command defined | MEDIUM | OPCOMMAND basename in {rm,dd,format,curl,wget,nc,scp,reg,certutil,…} |
| JOBCMD-CMD-005 | External OS command not bound to a specific OS | LOW | OPSYSTEM blank / ANYOS / * |
| JOBCMD-JOB-001 | Armed job runs under SAP*/DDIC or a SAP_ALL step user | CRITICAL | TBTCP/TBTCO AUTHCKNAM = SAP*/DDIC or a SAP_ALL/SAP_NEW holder (via profiles) |
| JOBCMD-JOB-001B | Armed job runs under a standard/technical step user | HIGH | AUTHCKNAM in {SAPCPIC,EARLYWATCH,TMSADM} |
| JOBCMD-JOB-002 | Job step executes an external OS command / program | HIGH | TBTCP XPGFLAG external / EXTCMD / XPGPROG populated |
| JOBCMD-JOB-003 | Job runs RSBDCOS0 or unreviewed custom code under a privileged user | HIGH | PROGNAME=RSBDCOS0 (SM69 bypass) or Z/Y report under a privileged step user |
| JOBCMD-JOB-004 | Armed job step user is deleted / locked / expired / dialog | MEDIUM | AUTHCKNAM absent from USR02, or UFLAG locked / GLTGB past / USTYP dialog |
| JOBCMD-JOB-005 | Job step user differs from scheduler (identity borrowing) | MEDIUM | AUTHCKNAM ≠ SDLUNAME and AUTHCKNAM is a privileged/standard user |

Data sources: `ext_os_commands.csv` (SXPGCOSTAB), `ext_os_commands_sap.csv` (SXPGCOTABE,
optional), `background_jobs.csv` (TBTCO), `background_job_steps.csv` (TBTCP); reuses
`users.csv` (USR02) and `profiles.csv` (USR04) to resolve privileged step users.

---

## Cryptographic Posture — HANA at-rest & transport (CRYPTO-HANA-*)

The HANA data-at-rest and internal-transport encryption subgroup of the Cryptographic
Posture module (which also covers ICM/TLS, certificates, SNC, crypto library and PSE).
Aligned to the SAP HANA Security Guide. Backup encryption is keyed independently of
volume encryption, and system-replication is evaluated on the **effective** (highest
inifile-layer) value.

| ID | Title | Severity | Data Source |
|----|-------|----------|-------------|
| CRYPTO-HANA-001 | HANA data volume encryption disabled | HIGH | hana_encryption.json |
| CRYPTO-HANA-002 | HANA log volume encryption disabled | MEDIUM | hana_encryption.json |
| CRYPTO-HANA-003 | HANA encryption uses internal/default root-key management | MEDIUM | hana_encryption.json |
| CRYPTO-HANA-004 | HANA backup encryption disabled | HIGH | hana_encryption.json |
| CRYPTO-HANA-005 | HANA system replication not TLS-encrypted | HIGH | hana_parameters.csv (`[system_replication_communication] enable_ssl`; fires only when present) |

---

## BTP Cloud — Identity & Cloud Connector (BTP-IAS-* / BTP-CC-*)

The identity and connectivity subgroup of the BTP Cloud Attack Surface module. IAS
password/IdP checks apply to the SAP Cloud Identity Services tenant; the Cloud
Connector is customer-managed even under RISE, so its version currency is the
customer's responsibility.

| ID | Title | Severity | Data Source |
|----|-------|----------|-------------|
| BTP-IAS-001/002/003 | IAS conditional-auth / IP restriction / MFA gaps | MEDIUM–HIGH | ias_config.json |
| BTP-IAS-004 | Weak IAS password policy for local users | HIGH/MEDIUM | ias_config.json (`passwordPolicy`) |
| BTP-IAS-005 | Corporate IdP configured but not enforced (local password fallback) | HIGH | ias_config.json (`corporateIdP`) |
| BTP-CC-008 | Cloud Connector version vulnerable to CVE-2024-25642 (CWE-295, 2.15.0–2.16.1) or out-of-maintenance | HIGH/MEDIUM | cloud_connector.json (`version`) |

(The module additionally covers Cloud Connector backends/ACLs/certs/staleness (BTP-CC-001…007),
service bindings, destinations, entitlements, Event Mesh, CPI, network isolation, governance,
and XSUAA→IAS migration — see `modules/btp_cloud_surface.py`.)

---

## GRC Access Control (GRC-*)

The **SAP GRC Access Control** process layer — Emergency Access Management (Firefighter),
Access Request Management, GRC-native SoD, mitigating controls and ruleset governance.
This is the control *process* (who reviews, who approves, is risk analysis run), distinct
from the permission-level SoD computed in Access Risk Analysis (ARA-*).

| ID | Title | Severity | Data Source |
|----|-------|----------|-------------|
| GRC-FF-001 | Firefighter usage without owner/controller log review | HIGH | grac_firefighter_log.csv |
| GRC-FF-001B | Firefighter sessions with no reason/activity captured | MEDIUM | grac_firefighter_log.csv |
| GRC-FF-002 | Firefighter ID owned by (or usable by) the same person | HIGH | grac_firefighter_owners.csv |
| GRC-FF-002B | Firefighter IDs without an assigned owner/controller | HIGH | grac_firefighter_owners.csv |
| GRC-FF-002C | Firefighter access outside a controlled session | MEDIUM | grac_firefighter_log.csv |
| GRC-ARM-001 | Access requests provisioned without SoD risk analysis | HIGH | grac_access_requests.csv |
| GRC-ARM-001B | Access requests auto-approved / no approver | HIGH | grac_access_requests.csv |
| GRC-ARM-002 | Access requests approved despite open risks | HIGH | grac_access_requests.csv |
| GRC-ARA-001 | Open GRC SoD violations past remediation SLA | HIGH | grac_sod_violations.csv |
| GRC-MIT-001 | Mitigating controls without a monitor or past validity | MEDIUM | grac_mitigating_controls.csv |
| GRC-RS-001 | SoD risks with blank/invalid criticality level | MEDIUM | grac_sod_risks.csv |
| GRC-RS-002 | Critical SoD risks in the ruleset (inventory/attention) | INFO/MEDIUM | grac_sod_risks.csv |
| GRC-RS-003 | SoD ruleset not maintained / stale | MEDIUM | grac_sod_risks.csv |

Data sources (all optional; module self-skips per check): `grac_firefighter_log.csv`,
`grac_firefighter_owners.csv`, `grac_access_requests.csv`, `grac_sod_violations.csv`,
`grac_mitigating_controls.csv`, `grac_sod_risks.csv` (GRC AC exports).

---

## Role Design & Governance (RG-*)

Role-build hygiene from the PFCG role tables — the defects that make roles either
over-entitled or inert.

| ID | Title | Severity | Data Source |
|----|-------|----------|-------------|
| RG-SU24-001 | Custom Z*/Y* transactions with unmaintained SU24 proposals | MEDIUM | su24_proposals.csv |
| RG-GEN-001 | Roles whose authorization profiles were never generated | HIGH | role_profiles.csv (AGR_1016) |
| RG-DRV-001 | Derived roles whose authorization values drifted from the parent | MEDIUM | role_details.csv + role_auth_values.csv |

---

## Financial Controls — SOX ITGC (FIN-*)

SOX IT general controls at the FI configuration level — posting periods, tolerances,
payment dual-control, document-change rules and number-range integrity. Grounded in
standard SAP FI customizing tables.

| ID | Title | Severity | Data Source |
|----|-------|----------|-------------|
| FIN-PP-001 | Posting-period variant left wide open | HIGH | posting_periods.csv (T001B) |
| FIN-TOL-001 | Posting tolerance group unlimited or unset | HIGH | tolerance_groups.csv (T043T) |
| FIN-TOL-002 | Excessive per-document / per-open-item tolerance | MEDIUM | tolerance_groups.csv (T043T) |
| FIN-SF-001 | Payment-relevant master fields not under dual control | HIGH | dual_control_fields.csv (T055F) |
| FIN-DOC-001 | Document-change rules allow post-posting edits to bank/payment fields | HIGH | doc_change_rules.csv (TBAER) |
| FIN-NR-001 | FI accounting-document number ranges main-memory buffered | MEDIUM | fi_number_ranges.csv (TNRO) |
