# SAP Data Export Guide

Step-by-step instructions for exporting the configuration data needed by the scanner.

---

## Core Data Exports

### Users (`users.csv`)
**Transaction:** `SU01` or Report `RSUSR002`  
**Table:** `USR02`

```
Required: BNAME, USTYP, UFLAG, TRDAT, ERDAT, PWDCHGDATE
Optional: CLASS (user group), SMTP_ADDR (email), REF_USER
```

Quick: `SA38 → RSUSR002 → Execute → Export`

### Profiles (`profiles.csv`)
**Table:** `USR04`
```
Required: BNAME, PROFILE
```

### Security Parameters (`security_params.csv`)
**Report:** `RSPARAM` or **Transaction:** `RZ11`
```
Required: NAME, VALUE
```

### RFC Destinations (`rfc_destinations.csv`)
**Transaction:** `SM59` | **Table:** `RFCDES`
```
Required: RFCDEST, RFCTYPE, RFCHOST, RFCUSER, RFCSNC
```

### ICF Services (`icf_services.csv`)
**Transaction:** `SICF`
```
Required: ICF_NAME, ICF_ACTIVE, AUTH_REQUIRED
```

### Audit Config (`audit_config.csv`)
**Transaction:** `SM19`
```
Required: FILTER_NAME, ACTIVE, EVENT_CLASS
```

---

## Advanced IAM Data Exports

### SoD Matrix (`sod_matrix.csv`)
**Source:** SUIM → Users by Transaction or SAP GRC Access Risk Analysis export

```
Required: USERNAME, TCODES (comma-separated list of t-codes per user)
```

**Alternative:** Export `role_tcodes.csv` from table `AGR_1251` (role→tcode mapping) and `user_roles.csv` from `AGR_USERS`. The scanner will resolve user→tcode automatically.

### Role-TCode Mapping (`role_tcodes.csv`)
**Table:** `AGR_1251`
```
Required: AGR_NAME, TCODE
Optional: AUTH_OBJECT
```

### Custom SoD Rules (`sod_ruleset.json`)
Override default SoD rules with your own. Format:
```json
[
  {
    "rule_id": "SOD-CUSTOM-001",
    "name": "My Custom Rule",
    "severity": "HIGH",
    "side_a": {
      "description": "Activity A",
      "tcodes": ["TCODE1", "TCODE2"]
    },
    "side_b": {
      "description": "Activity B",
      "tcodes": ["TCODE3", "TCODE4"]
    }
  }
]
```

### Firefighter Log (`firefighter_log.csv`)
**Source:** SAP GRC Superuser Privilege Management (SPM) log export

```
Required: FF_USER, ACTUAL_USER, LOGIN_TIME, LOGOUT_TIME, REASON, REVIEWED, REVIEWER
```

Timestamp format: `YYYY-MM-DD HH:MM:SS`

### Role Expiry (`role_expiry.csv`)
**Table:** `AGR_USERS` with validity dates

```
Required: UNAME, AGR_NAME, FROM_DAT, TO_DAT
```

Note: `99991231` or `9999-12-31` is treated as "no expiry"

### User Roles (`user_roles.csv`)
**Table:** `AGR_USERS`
```
Required: UNAME, AGR_NAME
```

### Role Details (`role_details.csv`)
**Table:** `AGR_DEFINE` + `AGR_TEXTS`
```
Required: AGR_NAME
Optional: TEXT (description), OWNER, TYPE, TCODE_COUNT
```

### Access Reviews (`access_reviews.csv`)
**Source:** SAP GRC Access Request Management or manual tracking

```
Required: REVIEW_ID, REVIEW_NAME, DUE_DATE, STATUS, COMPLETION_PCT, REVIEWER
```

---

## BTP / RISE Exports

### BTP Trust Config (`btp_trust.json`)
**Source:** BTP Cockpit → Subaccount → Security → Trust Configuration

```bash
btp list security/trust --subaccount <id> --format json > btp_trust.json
```

### BTP Users (`btp_users.json`)
**Source:** BTP Cockpit → Subaccount → Users, or BTP CLI

```json
{
  "users": [
    {"userName": "user@email.com", "email": "user@email.com", "roleCollections": ["Role1", "Role2"]}
  ]
}
```

### Communication Arrangements (`comm_arrangements.json`)
**Source:** Fiori app "Communication Arrangements" (F1962)

### API Endpoints (`api_endpoints.json`)
**Source:** OData service catalog or Communication Scenarios app

---

## Tips

- **Export from production** — always scan production configuration
- **Anonymize before sharing** — replace real usernames with pseudonyms for external review
- **Delimiter auto-detection** — the scanner handles comma, semicolon, tab, and pipe delimiters
- **All files optional** — the scanner runs only checks for which data is available
