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
Optional: HANDLER_CLASS
```

> **`HANDLER_CLASS` is worth the extra column.** It is the ABAP class that serves
> the node, and it is the one field that connects a *code* finding to the *outside
> world*. With it, a SQL injection inside a class published on an unauthenticated
> ICF node is identifiable as internet-reachable and ranks accordingly; without
> it, the same finding can only be ranked on whether anything in the estate
> references the object at all. In SICF the value is on the node's *Handler List*
> tab. Supplying it is what upgrades this product's reachability answer for custom
> code from "referenced somewhere" to "reachable from outside".

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

### OData Authorizations (`odata_auth.csv`)
```
Required: SERVICE_NAME, AUTH_CHECK
Optional: ALIAS, SCOPE, REQUIRED_AUTH_OBJECT, IMPL_CLASS
```

> **`IMPL_CLASS` is the OData half of the same link as `HANDLER_CLASS` above** —
> the Data Provider Class behind the service. It is what lets a code finding in a
> DPC method be identified as sitting behind a published, possibly
> unauthenticated, OData service. Without it, custom code exposed exclusively
> through OData looks no different from code nothing calls.

---

## Making custom-code findings rankable

Three exports decide whether a code finding can be told apart from every other
code finding. Supply what you can; each one is independently useful.

| Export | Column | What it buys |
|---|---|---|
| `code_inventory.csv` | `REFERENCED`, `LAST_USED` | **Available today.** Separates live code from dead code. A CRITICAL injection in a referenced, recently-run program ranks P1; the identical one in a program nothing references and that has never run ranks P3. |
| `icf_services.csv` | `HANDLER_CLASS` | Upgrades "referenced somewhere" to "reachable from outside" for web-exposed code. |
| `odata_auth.csv` | `IMPL_CLASS` | The same, for code reached only through OData. |

Without any of them every code finding is ranked on severity alone, which is how a
custom-code report becomes a list nobody works top-down. The tool says
`reachability: unknown` in that case rather than guessing in either direction.

## BTP Administrative Exports — the fully automatable set

BTP is the mirror image of the ABAP stack: **you** control it, and SAP publishes a CLI
and documented APIs for it. Everything in this section can be scripted end to end —
no SAP ticket, no transport, no ECS involvement. It is the one part of a RISE
landscape where evidence collection can be complete.

The scanner reads the **files these tools produce**. It holds no connection to SAP and
performs no API calls of its own; you run the commands, you keep the output, and the
importer (`modules/btp_import.py`) translates it. Where a command's exact output shape
is not certain the importer accepts several and skips what it does not recognise, so
an extra wrapper or a renamed field degrades one record rather than the export.

### 1. Subaccounts (`btp_accounts_subaccount.json`)

```bash
btp login --url https://cli.btp.cloud.sap --subdomain <global-account-subdomain>
btp --format json list accounts/subaccount > btp_accounts_subaccount.json
```

Returns the Accounts Service subaccount list — `guid`, `technicalName`, `displayName`,
`region`, `subdomain`, `state`, `usedForProduction`, `createdDate`, `modifiedDate`.

> **What this file does NOT contain:** audit-log enablement and the environment type
> (Cloud Foundry / Kyma). The scanner does not infer either. A subaccount whose
> audit-log state nothing tells us is reported as **unknown**, not as "audit logging
> disabled" — see files 2 and 4 below for the exports that do settle it.

### 2. Subaccount security settings (`btp_security_settings.json`)

```bash
btp target --subaccount <subaccount-id>
btp --format json list security/settings > btp_security_settings.json
```

Returns the subaccount's security settings: `defaultIdentityProvider`,
`treatUsersWithSameEmailAsSameUser`, `accessTokenValidity`, `refreshTokenValidity`,
`iframeDomains` / `iframeDomainsList`, `customEmailDomains`. This is what settles
whether a subaccount still logs on through the default SAP ID service.

> **Run it once per subaccount.** The command reports on the subaccount you are
> currently targeted at, and the output is not guaranteed to repeat that subaccount's
> id. If you have more than one subaccount, add the id yourself so the settings can be
> attributed — either wrap the objects in an array, each with a `"subaccount": "<guid>"`
> key, or key them by guid:
>
> ```json
> {"a1b2c3d4-…-0001": { … settings … }, "a1b2c3d4-…-0002": { … settings … }}
> ```
>
> A settings payload that names no subaccount is attributed only when exactly one
> subaccount is known; otherwise it is kept but attached to nothing, because guessing
> would put one subaccount's identity provider onto another's finding.

### 3. Role collections (`btp_role_collections.json`)

```bash
btp target --subaccount <subaccount-id>
btp --format json list security/role-collection > btp_role_collections.json
```

Returns the subaccount's role collections. The **detailed** form additionally carries
`roleReferences`, `userReferences`, `groupReferences` and `attributeReferences`; it is
`groupReferences` / `attributeReferences` that reveal *birthright* access — a
collection mapped to the `Default` group is granted to every federated user
automatically. If your CLI's list verb returns names only, fetch the detail per
collection and concatenate them into a JSON array:

```bash
for rc in $(btp --format json list security/role-collection | jq -r '.[].name'); do
  btp --format json get security/role-collection "$rc"
done | jq -s '.' > btp_role_collections.json
```

A collection with no references is recorded as *no mapping observed* — never as
"mapped to nothing", because the list verb may simply not return the references.

### 4. Audit log records (`btp_audit_log_records.json`)

Retrieved from the **auditlog-management** service instance in the subaccount. Create
the instance and a service key, fetch a token from the key's `uaa` block, then:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://auditlog-management.cfapps.<region>.hana.ondemand.com/auditlog/v2/auditlogrecords?time_from=2026-07-01T00:00:00Z" \
  > btp_audit_log_records.json
```

The exact host comes from the service key, not from this guide. Pages are followed
with the `handle` the response carries; concatenating several pages into one array is
fine, and so is leaving each page's `{"handle": …, "records": […]}` wrapper in place.

> **What the scanner takes from this file, and what it deliberately does not.**
> It takes one fact — *this tenant is producing audit records* — which is what turns
> a subaccount's audit-log state from **unknown** into evidenced. Only a per-tenant
> count and date range are kept; the records themselves, which are personal data,
> never reach a report.
>
> It does **not** derive retention from the file. The span of records in an export is
> chosen by whoever ran the query, so reading "90 days of retention" out of a 90-day
> pull would be a fabricated measurement. And a subaccount missing from the export is
> not marked as lacking audit logging — an export scoped to one subaccount says
> nothing about the others.

### 5. Cloud Connector configuration (`cloud_connector_configuration.json`)

The Cloud Connector runs on **your** infrastructure, so you can query it directly. It
is also the network door into the RISE system, which makes it the highest-value file
in this section.

```bash
SCC=https://<cloud-connector-host>:8443
AUTH='-u <scc-admin-user>:<password>'

curl -s $AUTH $SCC/api/v1/configuration/connector/version
curl -s $AUTH $SCC/api/v1/configuration/subaccounts
curl -s $AUTH $SCC/api/v1/configuration/subaccounts/<regionHost>/<subaccount>/systemMappings
curl -s $AUTH $SCC/api/v1/configuration/subaccounts/<regionHost>/<subaccount>/systemMappings/<virtualHost>:<virtualPort>/resources
```

Save the responses into **one** JSON file. Any of these layouts is accepted:

```json
{
  "/api/v1/configuration/connector/version": {"version": "2.16.2"},
  "/api/v1/configuration/subaccounts": [ … ],
  "/api/v1/configuration/subaccounts/cf.eu10.hana.ondemand.com/<guid>/systemMappings": [ … ]
}
```

```json
{"version": "2.16.2", "systemMappings": [ … ], "certificates": [ … ]}
```

The `resources` array is easiest to keep **inside** each system mapping. A separately
curled resource list carries no backend of its own, so it can only be attributed when
there is exactly one system mapping — with several it is dropped rather than attached
to the wrong backend.

What the scanner reads from this file: the connector version (CVE and maintenance
state), each system mapping's virtual/internal host, protocol and
`authenticationMode` (principal propagation), each mapping's resource paths (wildcard
and high-risk exposure such as WebGUI, ADT and the SOAP/RFC bridges), and any
certificate expiry it carries.

> **Not derived from this file:** per-subaccount allowed-host ACLs (the configuration
> API exposes no such list — the Cloud Connector's access control *is* its system
> mappings plus their resources), and "last used" for a backend (`creationDate` is a
> different fact and is not read as one).

### Which checks these files feed

| File | Checks it makes possible |
|---|---|
| `btp_accounts_subaccount.json` | `BTP-GOV-001`, `BTP-GOV-002` (with files 2 and 4) |
| `btp_security_settings.json` | `BTP-GOV-002` |
| `btp_role_collections.json` | `S4AUTHZ-008` (birthright role collections) |
| `btp_audit_log_records.json` | `BTP-GOV-001` (evidence that logging is on) |
| `cloud_connector_configuration.json` | `BTP-CC-001` … `BTP-CC-008`, `S4AUTHZ-006` |

Hand-made files in the scanner's own shape (`cloud_connector.json`,
`btp_subaccounts.json`, `btp_role_collection_mappings.csv`) keep working exactly as
before and take precedence: the translators recognise raw tooling output by its own
field names and leave anything else untouched.

---

## SAP Cloud ALM — Configuration & Security Analysis (CSA) exports

SAP Cloud ALM is included with a RISE subscription through Enterprise Support at no
extra fee, and in most tenants it is already collecting ABAP configuration stores.
That makes it the cheapest ingestion path after plain file upload: no ABAP
transport, no RFC user, no agent, nothing to install. See
`docs/RISE_SECURITY_MODEL.md` §5 and §7.3.

If your tenant has CSA switched on, you can feed this scanner from it. Drop the
store exports into a directory and scan it as you would any other export directory:

```bash
python sap_scanner.py --data-dir ./my_csa_export --output report.html
```

A worked example ships in [`sample_data_cloudalm/`](../sample_data_cloudalm).

### ⚠️ Read this first — the caveat that scopes this whole path

**We could not confirm whether Cloud ALM's API returns raw configuration-store
values or only SAP's own policy compliance verdicts.** It is recorded as an open
question in `docs/RISE_SECURITY_MODEL.md` §8, and it is unresolved because we hold
no Cloud ALM tenant to test against.

**This importer covers the raw-export path only.** It reads store rows — parameter
names and values, user names and lock flags, ICF paths and their activation state.
If what your tenant gives you is a list of SAP policy results ("1ASTDUSR:
non-compliant"), this importer cannot use it, and no amount of configuration will
change that: a verdict is not the configuration it was computed from.

Nothing here connects to Cloud ALM, to SAP, or to anything else. **It reads files
you exported.** There is no live API client, deliberately: one we cannot exercise
would be a capability claim we could not stand behind.

### Obtaining the export

In Cloud ALM, open **Configuration & Security Analysis** and export the
configuration stores for the managed ABAP system you want scanned. The export
control and its exact position differ between Cloud ALM releases, so rather than
print a click path we have not verified, here is what the scanner needs:

- **One file per configuration store**, CSV or JSON.
- **Named after the store** — `ABAP_INSTANCE_PAHI.csv`, `STANDARD_USERS.csv`. A
  `CSA_` / `CALM_` prefix and a trailing SID, instance number or date are fine:
  `CSA_ABAP_INSTANCE_PAHI_PRD_00.csv` resolves to the same store.
- **One header row** naming the columns. Delimiter is auto-detected (comma,
  semicolon, tab, pipe).
- **JSON** may be a bare list of row objects or an OData `{"value": [...]}`
  envelope — saving a response body straight to disk works.

The store names are SAP's own, from the policies SAP publishes at
[`SAP-samples/frun-csa-policies-best-practices`](https://github.com/SAP-samples/frun-csa-policies-best-practices)
(Apache-2.0). `data/sap_baseline_requirements.json` lists which stores each of
SAP's baseline requirements reads.

### Stores the scanner translates

| Store | Becomes | Column names accepted (SAP's spelling first where we have it) |
|---|---|---|
| `ABAP_INSTANCE_PAHI` | `security_params` | `PARAMETER` \| `PARAMETER_NAME` \| `PARAM` \| `NAME`, and `VALUE` \| `PARAMETER_VALUE` \| `PARAM_VALUE` \| `CURRENT_VALUE` |
| `STANDARD_USERS` | `standard_users` | `USERNAME` \| `USER` \| `BNAME`, `CLIENT` \| `MANDT`, `DEFAULT_PASSWORD` \| `PASSWORD_STATUS` \| `PWD_STATUS`, `LOCKED` \| `LOCK_STATUS` \| `UFLAG`, `USER_TYPE` \| `USTYP` |
| `AUTH_PROFILE_USER` | `profiles` | `PROFILE`, `USERNAME`, `USER_TYPE`, `STATUS` |
| `SICF_SERVICES` | `icf_services` | `PATH` \| `ICF_NAME` \| `URL` \| `NAME`, `ACTIVE` \| `ICF_ACTIVE` \| `STATUS`, `AUTH_REQUIRED` \| `AUTHENTICATION` \| `AUTH` |
| `GW_SECINFO` | `gw_secinfo` | `RULE` \| `LINE` \| `ENTRY`, or structured `ACCESS`/`ACTION` + `TP` + `HOST` + `USER` |
| `GW_REGINFO` | `gw_reginfo` | as above, without `USER` |
| `AUDIT_CONFIGURATION_SLOT` | `audit_config` | `SLOT`, `FILTER_NAME` \| `SLOT_NAME` \| `NAME`, `ACTIVE`, `EVENT_CLASS` \| `CLASS`, `CLIENT` |
| `CLIENTS` | `client_settings` | `MANDT` \| `CLIENT`, `CCCATEGORY` \| `ROLE`, `CCCORACTIV`, `CCNOCLIIND`, `CCCOPYLOCK` |
| `MS_SECINFO` | `ms_acl` | `HOST` + `SERVICE`, or `LINE` \| `RULE` |

Column names match case-insensitively and spaces become underscores, so
`Parameter Name` resolves the same as `PARAMETER_NAME`. SAP's published policies
name the stores but not every column, and the header you actually get depends on
the export route — so each field is resolved through the alias list above rather
than against one assumed spelling. **Those aliases are the spellings we accept,
not a claim about SAP's schema.**

**Two ACLs worth calling out.** `secinfo` and `reginfo` are filesystem files on the
application server, which a RISE customer cannot reach — `RISE_SECURITY_MODEL.md`
§3 lists them, and the message server ACL, as structurally unavailable. As CSA
configuration stores they *are* reachable, so this path closes that gap rather than
restating it.

### Stores the scanner deliberately does not translate

They are recognised, listed in the scan output with the reason, and skipped:

| Store | Why not |
|---|---|
| `AUDIT_CONFIGURATION` | Global audit settings, not filter slots. Mixing them into `audit_config` would inflate the filter count and turn *"no audit filters configured"* into a pass. `AUDIT_CONFIGURATION_SLOT` is translated instead. |
| `Parameters`, `http`, `servlet_jsp`, `com.sap.security.core.ume.service`, `AUTH_ROLE_USER` | **Java** AS / Web Dispatcher stores. SAP's Java stack has a store literally named `Parameters`; translating it into `security_params` would score Java settings against ABAP profile-parameter thresholds. |
| `HDB_*` | HANA. Technical HANA configuration is SAP-operated under RISE (§4). |
| `AUTH_COMB_USER`, `AUTH_COMB_ROLE` | SAP's critical-authorisation *combination* content. Our checks read `AGR_1251` authorisation values, and we could not confirm whether these stores carry the rules or the matches. |
| `AUTH_SECURITY_POLICY` | Per-client security policies. Their attribute names are not the instance profile parameters `security_params` holds; merging them would score a policy attribute against a parameter threshold. |
| `GLOBAL`, `SAP_KERNEL`, `COMP_LEVEL`, `TRANSPORT_TOOL`, `TDDAT`, `ABAP_UCON_HTTP_WHITE_LIST`, `ABAP_SACF_INFO`, `USER_PASSWD_HASH_USAGE` | No logical source consumes them yet. UCON in particular is a known ingest gap (§7.1), not a translation problem. |

### Known limitations

- **`users.csv` still has to come from `RSUSR002`.** No CSA store in SAP's baseline
  policies carries a full `USR02` user master. `AUTH_PROFILE_USER` holds only users
  who hold a profile, and feeding that partial population to checks that compute
  rates over the user master — dormancy, password age, never-logged-on — would make
  every one of them silently understate. So it fills `profiles` and nothing else.
- **Raw `T000` change codes are not decoded.** If your `CLIENTS` export gives the
  change options as single-character codes rather than text, the scanner does not
  guess their meaning: a wrong decode either invents a CRITICAL *"production client
  is modifiable"* finding or clears a real one. The codes appear in the scan output
  as undecoded, and the client-change check does not fire on them. Cross-check in
  `SCC4`.
- **Standard-user coverage is only as wide as the clients in the export.** The
  clients actually present are recorded, because "compliant in the clients we saw"
  must never render as "compliant" (§3.1).
- **Values we do not recognise are passed through, not guessed.** An unrecognised
  activation token is reported rather than assumed to mean "inactive" — assuming
  would clear an exposed service with nothing anywhere saying so.

### Mixing CSA and native exports

You can put both in one directory. **A file named in the loader's own convention
always wins**; store exports fill only what is still missing. Dropping
`ABAP_INSTANCE_PAHI.csv` next to an existing `security_params.csv` changes nothing,
and the scan output says so per source.

One consequence worth knowing: three store names collide with our filenames
(`STANDARD_USERS`, `GW_SECINFO`, `GW_REGINFO`). Case decides — `standard_users.csv`
is the native export, `STANDARD_USERS.csv` is the CSA store — on Windows too, where
the filesystem itself cannot tell them apart.

---

## Tips

- **Export from production** — always scan production configuration
- **Anonymize before sharing** — replace real usernames with pseudonyms for external review
- **Delimiter auto-detection** — the scanner handles comma, semicolon, tab, and pipe delimiters
- **All files optional** — the scanner runs only checks for which data is available
