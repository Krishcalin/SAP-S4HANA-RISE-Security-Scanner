# Security Checks Reference

Complete reference for all checks performed by the SAP S/4HANA RISE Security Scanner.

---

## User & Authorization Audit

### USR-001: Default Users Unlocked
- **Severity:** CRITICAL (SAP*, DDIC) / HIGH (others)
- **Data:** `users.csv`
- **Logic:** Checks if SAP*, DDIC, SAPCPIC, EARLYWATCH, TMSADM have UFLAG = 0
- **Baseline:** SAP Note 1414256, CIS SAP Benchmark 2.1

### USR-002: Critical Profile Assignments
- **Severity:** CRITICAL
- **Data:** `profiles.csv` or `users.csv`
- **Logic:** Flags any user assigned SAP_ALL, SAP_NEW, or S_A.SYSTEM
- **Baseline:** SAP Note 1698789, CIS SAP Benchmark 2.3

### USR-003: Dormant Accounts
- **Severity:** MEDIUM
- **Data:** `users.csv`
- **Logic:** Active users with last logon > 90 days ago (configurable)
- **Config:** `dormant_threshold_days` (default: 90)

### USR-004: Service Account Type Mismatch
- **Severity:** HIGH
- **Data:** `users.csv`
- **Logic:** Accounts with service naming prefixes (SVC_, RFC_, BATCH_, etc.) that have dialog (type A) logon
- **Baseline:** SAP Note 2175909

### USR-005: Excessive Role Assignments
- **Severity:** MEDIUM
- **Data:** `user_roles.csv`
- **Logic:** Users with more than 30 roles (configurable)
- **Config:** `max_roles_per_user` (default: 30)

### USR-006: Wildcard Authorization Values
- **Severity:** HIGH
- **Data:** `auth_objects.csv`
- **Logic:** Users with VALUE = * or &NC& on S_DEVELOP, S_ADMI_FCD, S_BTCH_ADM, S_RZL_ADM, S_USER_GRP, S_TABU_DIS
- **Baseline:** SAP Note 2077067, CIS SAP Benchmark 3

### USR-007: Never-Logged-In Accounts
- **Severity:** LOW
- **Data:** `users.csv`
- **Logic:** Active (unlocked) users with no recorded logon date

### USR-008: Stale Passwords
- **Severity:** MEDIUM
- **Data:** `users.csv`
- **Logic:** Dialog users with password age > 180 days (configurable)
- **Config:** `max_password_age_days` (default: 180)

---

## Security Parameters

All parameter checks follow the pattern: compare exported value against baseline using an operator (==, >=, <=, !=).

### Password Policy Parameters
| Parameter | Expected | Op | Severity | CIS Ref |
|-----------|----------|-----|----------|---------|
| login/min_password_lng | >= 8 | >= | HIGH | 1.1.1 |
| login/min_password_digits | >= 1 | >= | MEDIUM | 1.1.2 |
| login/min_password_letters | >= 1 | >= | MEDIUM | 1.1.3 |
| login/min_password_specials | >= 1 | >= | MEDIUM | 1.1.4 |
| login/password_expiration_time | <= 90 | <= | MEDIUM | 1.1.6 |
| login/password_max_idle_initial | <= 14 | <= | MEDIUM | 1.1.7 |
| login/password_history_size | >= 5 | >= | LOW | 1.1.8 |

### Login Security Parameters
| Parameter | Expected | Op | Severity | CIS Ref |
|-----------|----------|-----|----------|---------|
| login/fails_to_session_end | <= 3 | <= | HIGH | 1.2.1 |
| login/fails_to_user_lock | <= 5 | <= | HIGH | 1.2.2 |
| login/no_automatic_user_sapstar | == 1 | == | CRITICAL | 1.2.5 |
| login/disable_multi_gui_login | == 1 | == | LOW | 1.2.6 |

### RFC Security Parameters
| Parameter | Expected | Op | Severity |
|-----------|----------|-----|----------|
| rfc/reject_insecure_logon | == 1 | == | HIGH |
| rfc/reject_insecure_logon_data | == 1 | == | HIGH |
| rfc/allowoldticket4tt | == 0 | == | MEDIUM |

### Gateway Security Parameters
| Parameter | Expected | Op | Severity | CIS Ref |
|-----------|----------|-----|----------|---------|
| gw/sec_info | != (empty) | != | CRITICAL | 3.1 |
| gw/reg_info | != (empty) | != | CRITICAL | 3.2 |
| gw/reg_no_conn_info | >= 255 | >= | HIGH | — |

### Transport Security Parameters
| Parameter | Expected | Op | Severity |
|-----------|----------|-----|----------|
| icm/HTTPS/verify_client | >= 1 | >= | HIGH |
| ssl/ciphersuites | != (empty) | != | HIGH |

### Audit & Development Parameters
| Parameter | Expected | Op | Severity | CIS Ref |
|-----------|----------|-----|----------|---------|
| rsau/enable | == 1 | == | CRITICAL | 6.1 |
| rec/client | != (empty) | != | HIGH | 6.2 |
| rdisp/wpdbug_max_no | == 0 | == | HIGH | 7.1 |

### PARAM-MISSING: Critical Parameters Not in Export
- **Severity:** HIGH
- **Logic:** Any CRITICAL or HIGH parameter not found in the exported data

---

## Network & Service Exposure

### NET-001: RFC Stored Credentials
- **Severity:** HIGH
- **Logic:** RFC destinations with a non-empty RFCUSER field

### NET-002: External RFC Destinations
- **Severity:** MEDIUM
- **Logic:** RFC destinations with hosts outside recognized internal IP ranges
- **Config:** `internal_host_patterns`

### NET-003: RFC Without SNC
- **Severity:** HIGH
- **Logic:** Type 3/T/W RFC destinations with SNC disabled

### NET-004: High-Risk ICF Services Active
- **Severity:** HIGH
- **Logic:** 11 known high-risk service paths checked against active ICF services

### NET-005: ICF Services Without Authentication
- **Severity:** CRITICAL
- **Logic:** Active ICF services (excluding /sap/public/*) with no auth requirement

### NET-006: Open Transports in Production
- **Severity:** MEDIUM
- **Logic:** Transports with status D or L (modifiable)

### NET-007: Debug/Replace Transport Indicators
- **Severity:** HIGH
- **Logic:** Transports with descriptions containing debug/replace keywords

### NET-008: No Active Audit Filters
- **Severity:** CRITICAL
- **Logic:** Zero active filters found in SM19 export

---

## RISE / BTP-Specific

### RISE-001: Default SAP IDP Active
- **Severity:** MEDIUM
- **Logic:** Trust entry with origin sap.default or sap.ids still enabled

### RISE-002: Shadow User Auto-Creation
- **Severity:** MEDIUM
- **Logic:** Trust entries with createShadowUsers = true

### RISE-003: Over-Scoped Communication Arrangements
- **Severity:** MEDIUM
- **Logic:** Arrangements exposing > 10 services

### RISE-004: Weak Auth on Communication Arrangements
- **Severity:** CRITICAL
- **Logic:** Arrangements with auth_method = none, anonymous, or basic

### RISE-005: Sensitive APIs Exposed
- **Severity:** HIGH
- **Logic:** Active API endpoints matching sensitive patterns (finance, HR, master data)

### RISE-006: Shared Communication Users
- **Severity:** MEDIUM
- **Logic:** Communication users reused across > 3 arrangements

### RISE-007: API Weak Authentication
- **Severity:** HIGH
- **Logic:** API endpoints with auth = none, anonymous, or basic
