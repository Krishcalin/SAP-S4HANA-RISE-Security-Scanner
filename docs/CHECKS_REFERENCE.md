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
