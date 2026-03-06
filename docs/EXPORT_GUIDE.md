# SAP Data Export Guide

Step-by-step instructions for exporting the configuration data needed by the scanner.

## Prerequisites

- SAP GUI access or Fiori Launchpad access to the target S/4HANA system
- Authorization for the relevant transactions (SU01, RZ11, SM59, SICF, etc.)
- For BTP exports: BTP Cockpit access with Security Administrator role

## Export Methods

### Method 1: SAP GUI Transaction Exports

Each transaction below has a list/table view that can be exported to CSV:
1. Navigate to the transaction
2. Execute the report/display the list
3. Use `System → List → Save → Local File → Spreadsheet (CSV)`

### Method 2: SE16/SE16N Table Exports

For direct table access:
1. Go to `SE16N`
2. Enter the table name
3. Execute and export results

### Method 3: ABAP Report Output

Some data is best extracted via standard reports:
1. Go to `SA38` (ABAP Editor - Execute)
2. Enter the report name
3. Configure selection parameters
4. Execute and export

---

## Data Sources

### 1. Users — `users.csv`

**Transaction:** `SU01` (User Maintenance) or Report `RSUSR002`

**SE16N Table:** `USR02`

| Export Field | Table Field | Description |
|-------------|-------------|-------------|
| BNAME | USR02-BNAME | Username |
| USTYP | USR02-USTYP | User type (A=Dialog, B=System, C=Comm, S=Service) |
| UFLAG | USR02-UFLAG | Lock status (0=unlocked) |
| TRDAT | USR02-TRDAT | Last logon date |
| ERDAT | USR02-ERDAT | Creation date |
| PWDCHGDATE | USR02-PWDCHGDATE | Last password change |

**Quick method:**
```
SA38 → RSUSR002 → Execute with all users → Export
```

### 2. Profiles — `profiles.csv`

**SE16N Table:** `USR04`

| Export Field | Table Field | Description |
|-------------|-------------|-------------|
| BNAME | USR04-BNAME | Username |
| PROFILE | USR04-PROFN | Profile name |

### 3. Security Parameters — `security_params.csv`

**Transaction:** `RZ11` or Report `RSPARAM`

**Quick method:**
```
SA38 → RSPARAM → Execute → Export full list
```

| Export Field | Description |
|-------------|-------------|
| NAME | Parameter name (e.g., login/min_password_lng) |
| VALUE | Current active value |

### 4. RFC Destinations — `rfc_destinations.csv`

**Transaction:** `SM59`

**SE16N Table:** `RFCDES`

| Export Field | Table Field | Description |
|-------------|-------------|-------------|
| RFCDEST | RFCDES-RFCDEST | Destination name |
| RFCTYPE | RFCDES-RFCTYPE | Connection type (3, T, W, etc.) |
| RFCHOST | RFCDES-RFCHOST | Target hostname/IP |
| RFCUSER | RFCDES-RFCUSER | Stored username (if any) |
| RFCSNC | RFCDES-RFCSNC | SNC enabled flag |

### 5. ICF Services — `icf_services.csv`

**Transaction:** `SICF`

Navigate the service tree and export. Focus on `/sap/bc/*` and `/sap/public/*` subtrees.

| Export Field | Description |
|-------------|-------------|
| ICF_NAME | Full service path |
| ICF_ACTIVE | Active flag (X = active) |
| AUTH_REQUIRED | Whether authentication is required |

### 6. Audit Configuration — `audit_config.csv`

**Transaction:** `SM19`

| Export Field | Description |
|-------------|-------------|
| FILTER_NAME | Audit filter name |
| ACTIVE | Filter active status |
| EVENT_CLASS | Event class being audited |

### 7. BTP Trust Configuration — `btp_trust.json`

**Source:** SAP BTP Cockpit

1. Navigate to your subaccount
2. Go to **Security → Trust Configuration**
3. Note down each trust entry's properties
4. Create JSON manually or use BTP CLI:

```bash
btp list security/trust --subaccount <subaccount-id> --format json > btp_trust.json
```

### 8. Communication Arrangements — `comm_arrangements.json`

**Source:** Fiori app "Communication Arrangements" or API

In S/4HANA Cloud, export from:
- Fiori app: **Communication Arrangements** (F1962)
- Or via API: `GET /sap/opu/odata/sap/MANAGE_COMM_ARRANGEMENTS_SRV`

### 9. API Endpoints — `api_endpoints.json`

**Source:** Fiori app "Communication Scenarios" or service catalog

Export the list of published OData/REST services with their authentication settings.

---

## Tips

- **Anonymize before sharing** — replace real usernames with pseudonyms if exporting for external review
- **Export from production** — always scan production configuration (not dev/QA)
- **Regular exports** — schedule monthly exports to track configuration drift
- **Delimiter detection** — the scanner auto-detects CSV delimiters (comma, semicolon, tab, pipe)
