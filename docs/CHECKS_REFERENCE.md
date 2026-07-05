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
