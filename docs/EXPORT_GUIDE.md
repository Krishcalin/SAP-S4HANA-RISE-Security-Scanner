# SAP Data Export Guide

Step-by-step instructions for exporting the configuration data needed by the scanner.

---


## Connected mode: the RFC collector (optional)

`python -m collect sapcontrol` and `python -m collect icf` need no SDK and should
be your first choice. Sixteen logical sources are beyond them — users, profiles,
roles, authorisation values, RFC destinations, client settings, background jobs
and change documents — and those need RFC.

```bash
export SAPNWRFC_HOME=/opt/nwrfcsdk          # you supply this; see below
export LD_LIBRARY_PATH=$SAPNWRFC_HOME/lib   # Linux: the .so loads its siblings

python -m collect rfc --list-sources        # what it produces; no connection made
python -m collect rfc --host p01.acme.internal --instance 00 \
                      --client 100 --user MONITOR --probe-only
python -m collect rfc --host p01.acme.internal --instance 00 \
                      --client 100 --user MONITOR --out ./extract
python sap_scanner.py --data-dir ./extract
```

**You supply the SDK.** The SAP NetWeaver RFC SDK is downloaded from SAP under
your own S-user licence and cannot be redistributed, so this product does not
ship it and the container image does not contain it. That is the whole reason
this collector is optional and out-of-process.

**No Python binding is installed.** PyRFC was archived in May 2026 and its PyPI
releases yanked; this collector calls the SDK directly through `ctypes`, which is
part of the standard library. There is nothing to `pip install`.

**Read-only, enforced before the network.** Three function modules are permitted —
`RFC_READ_TABLE`, `RFC_SYSTEM_INFO`, `RFCPING` — and the allowlist is checked
before any handle is opened. RFC exposes every remote-enabled function module in
the system, including ones that change user master records and execute ABAP, so
this is enforced in the transport rather than trusted to callers.

**Bound the big tables.** `AGR_1251` (authorisation values) and `CDHDR` (change
documents) are unbounded on a production system. Always pass `--where`, and
`--row-limit` while you are testing:

```bash
python -m collect rfc ... --only change_documents --where "UDATE GE '20260101'"
python -m collect rfc ... --only role_auth_values --row-limit 50000
```

**The minimum authorisation** the RFC user needs is `S_RFC` for the function group
that contains `RFC_READ_TABLE` (`SDTX`), plus `S_TABU_DIS`/`S_TABU_NAM` read access
to the tables listed by `--list-sources`. Granting more than that is not required
and should not be done for a read-only collection.

**What it still cannot reach**, and which the export guide's manual routes remain
the answer for: gateway ACL files (`gw/sec_info`, `gw/reg_info` are files on the
application server, not tables), audit-log configuration, TMS transport routes,
and table authorisation groups. `--list-sources` prints the current list with a
reason for each.


## Every source, including the ones this guide does not cover

This guide gives a verified, step-by-step procedure for the sources a first scan
needs. The scanner reads **123** logical sources in total, and the remaining ones
have no written procedure yet.

[**`EXPORT_SOURCES.md`**](EXPORT_SOURCES.md) lists all 123 — the filenames the
loader accepts, which checks each one feeds, and whether a procedure exists. It
is generated from the code, so a source cannot be added to the scanner without
appearing there.

If you already hold one of those files, supply it: the scanner will read it under
any of the listed names. What is missing is the extraction procedure, and those
are not guessed — a wrong transaction code in an export guide costs you an
afternoon.

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

> ⚠️ **`HANDLER_CLASS` IS NOT READ BY ANYTHING TODAY. Supply it only if you want to.**
> The paragraph below describes what it is *for*, and that design is still the
> intention — but no module currently consumes the column, and
> `modules/reachability.py` says so in its own docstring ("no handler class").
> Asking for a column and then ignoring it wastes somebody's afternoon in SICF, so
> the honest position is stated here rather than left to be discovered.
>
> **What it would be worth.** It is the ABAP class that serves
> the node, and it is the one field that connects a *code* finding to the *outside
> world*. With it, a SQL injection inside a class published on an unauthenticated
> ICF node is identifiable as internet-reachable and ranks accordingly; without
> it, the same finding can only be ranked on whether anything in the estate
> references the object at all. In SICF the value is on the node's *Handler List*
> tab. Supplying it is what upgrades this product's reachability answer for custom
> code from "referenced somewhere" to "reachable from outside".

### Installed components (`system_component.csv`)
**Transaction:** `SPAM` / `SAINT` (Component version) · **Table:** `CVERS` ·
also **System > Status > Component information**
```
Required: COMPONENT, RELEASE
Optional: SP_LEVEL, DESCRIPTION
```

> **What it unlocks.** A check that looks for something introduced in a particular
> release has three possible relationships to your system: it applies, it cannot
> apply, or nobody can tell. Without this file only the third is available, and a
> check that cannot tell whether it applies did not examine your system — so its
> silence is not a pass, and the release gate is held open to say so.
>
> Example rows: `SAP_BASIS,750,0018` · `SAP_APPL,618,0012` · `S4CORE,105,0002`.

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

**Send the WHOLE object — do not trim it to the fields you think are interesting.**
Two checks depend on attributes that may or may not be present depending on your
platform version: which users a trust admits, and when its signing certificate
expires. If neither is in your export, the scanner tells you so explicitly
(`IAM-FEDCOV-002` / `IAM-FEDCOV-003`) rather than reporting a clean result it did
not earn — but those two controls then have to be verified by hand with whoever
owns the identity provider. A trimmed export turns a checkable control into a
manual one.

### Table Authorization Groups (`table_auth_groups.csv`)
**Source:** SE54 → Assign Authorization Group, or a download of table `TDDAT`

Also accepted: `table_authorization_groups.csv`, `se54.csv`

| Column (any of) | Meaning |
|---|---|
| `TABNAME` · `TABLE` · `TABLE_NAME` · `OBJECT` · `OBJECT_NAME` · `VIEWNAME` | Table or view |
| `CCLASS` · `AUTH_GROUP` · `AUTHGROUP` · `AUTHORIZATION_GROUP` · `AUTH_GRP` · `DICBERCLS` · `BRGRU` | Authorization group |

**This extract must be UNFILTERED.** A table that is absent is read as *"no
authorization group assigned"*, because that is what absence means in a complete
extract — and that is the entire finding for the password-hash tables SAP Note
3250501 requires behind group `SPWD`. If you can only supply a namespace-filtered
extract (Z* only, say), the scanner detects the provable cases and downgrades them
to a coverage gap rather than an accusation, but it cannot detect every filtering,
so send everything if you can.

### Backup Catalog (`backup_catalog.csv`)
**Source:** DB13 / DBACOCKPIT backup history, or your backup tool's own export

Also accepted: `backups.csv`, `db13.csv`, `backup_history.csv`

Feeds the resilience checks (`RES-BCK-*`). Include the run timestamp, the outcome,
and the backup type where your tool records it — the checks distinguish "no full
data backup exists" from "backups exist that I could not classify by type", and the
second is a coverage statement rather than a finding.

### Recovery Tests (`recovery_tests.csv`)
**Source:** whatever records your DR and restore exercises — a register, a ticket
export, a spreadsheet

Also accepted: `dr_tests.csv`, `restore_tests.csv`

Feeds `RES-DR-*`. **What this can and cannot tell you:** the scanner reads exported
configuration, so it verifies that recovery is *evidenced and scheduled*. It never
verifies that a restore works. No offline tool can.

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

> ⚠️ **`IMPL_CLASS` IS NOT READ BY ANYTHING TODAY EITHER** — same position as
> `HANDLER_CLASS` above, and the same reason for saying so plainly.
>
> **What it would be worth.** It is the OData half of the same link —
> the Data Provider Class behind the service. It is what lets a code finding in a
> DPC method be identified as sitting behind a published, possibly
> unauthenticated, OData service. Without it, custom code exposed exclusively
> through OData looks no different from code nothing calls.

---

---

## SAP GRC Access Control exports (the `grcac` module)

These six sources feed `modules/grc_access_control.py`. They come out of a
**separate SAP GRC Access Control system**, not out of the ABAP system the other
exports come from, which is why they are the last set to be written and why they
are optional: omit them and the GRC checks do not run, exactly as chapter 13
describes.

> ⚠️ **THE GRC REPOSITORY IS A SYNCHRONISED COPY, AND A STALE SYNC LOOKS LIKE
> GOOD NEWS.** Every table below is populated by a background job on the GRC
> box, not written live. If `GRAC_SPM_LOG_SYNC` has not run, the firefighter log
> export comes out short or empty — and "no privileged sessions" is the single
> most reassuring thing this product can be told. Before exporting, confirm the
> synchronisation jobs have run recently, under `SPRO` → *Governance, Risk and
> Compliance* → *Access Control* → *Synchronization Jobs*:
>
> | Job | Transaction | SAP's recommended frequency |
> |---|---|---|
> | Authorization Synch | `GRAC_AUTH_SYNC` | weekly |
> | Repository Object Synch | `GRAC_REP_OBJ_SYNC` | daily |
> | Action Usage Synch | `GRAC_ACT_USAGE_SYNC` | daily |
> | Role Usage Synch | `GRAC_ROLE_USAGE_SYNC` | daily |
> | Firefighter Log Synch | `GRAC_SPM_LOG_SYNC` | daily |
> | Firefighter Workflow Synch | `GRAC_SPM_WF_SYNC` | daily |
>
> Record the date each job last ran alongside the export. A finding built on a
> three-week-old sync is a finding about three weeks ago.

**Read-only is enough.** SAP delivers `SAP_GRAC_DISPLAY_ALL` for display-only
access to GRC master and application data; it is the role SAP itself names for
read-only remote support. Nobody needs a maintenance role to produce these files.

**Finding the transaction for anything below**: `SE93`, search `GRAC*`.

### Firefighter session log (`grac_firefighter_log.csv`, `gracfflog.csv`)
**Table:** `GRACFFLOG`  |  **Report:** *Consolidated Log Report*, under Emergency
Access Management → Reports (`NWBC`). The report's *Update Firefighter Log*
button runs `GRAC_SPM_LOG_SYNC_UPDATE`, which is the same collection the daily
job performs — press it before exporting if the job's timing is uncertain.

```
Required: FFID (or FIREFIGHTER_ID), FF_USER (or USER), REASON_CODE, STATUS
Optional: LOGON_TIME (or LOGON_DATE), CONTROLLER, LOG_REVIEWED
```
The module reads a session as unreviewed when `STATUS` is absent, so an export
that drops the column reports every session as unreviewed rather than as clean.

*What decides whether this export can exist at all*: configuration parameter
`4000` selects ID-based (`1`) or role-based (`2`) firefighting, and parameters
`4003`–`4006` decide which logs are collected at all (change log, system log,
audit log, O/S command log). If those are unset, the log is thin for a reason
that has nothing to do with how the estate is used — note it on the export.

### Firefighter ID owners and controllers (`grac_firefighter_owners.csv`)
**Route:** `NWBC` → Access Control → Emergency Access Management → owner and
controller maintenance. **Authorization object:** `GRAC_FFOWN` (fields
`GRAC_OWN_T` owner type, `GRAC_USER`, `GRAC_SYSID`).
*Table name not verified* — export from the maintenance screen, not `SE16`.

```
Required: FFID (or FIREFIGHTER_ID), FF_OWNER (or OWNER), FF_CONTROLLER (or CONTROLLER)
Optional: VALID_TO, NOTIFY_BY_EMAIL
```
> Configuration parameter `5033` decides whether firefighters may exist with **no
> controller at all** (SAP ships it permissive). Where it is on, a blank
> controller column is a real configuration state and not a broken export —
> which is the difference between a finding and a data-quality note.

### Access requests (`grac_access_requests.csv`, `gracreq.csv`)
**Table:** `GRACREQ`, with request detail across `GRACREQUSER`,
`GRACREQOWNER`, `GRACREQPROVITEM` and `GRACREQPROVLOG`. **Authorization
object:** `GRAC_REQ`.

```
Required: REQ_ID (or REQUEST_ID / REQNO), REQUESTOR, PROVISIONED_USER, STATUS
Optional: APPROVER, RISK_ANALYSIS_DONE, PROV_STATUS
```
`RISK_ANALYSIS_DONE` is the column worth chasing: configuration parameter `1071`
decides whether risk analysis runs automatically on submission at all, so its
absence across every row may mean the control is off rather than that the export
is short.

### SoD violations (`grac_sod_violations.csv`)
**Route:** Batch risk analysis (`GRAC_BATCH_RA`, monitored with
`GRACRABATCH_MONITOR`), then export the violation report. Related stored data:
`GRACSODUSERROLE`, `GRACSODREVIEW`; spooled analytics land in `GRACSODREPDATA`
(column `REPCONTENT`) when configuration parameter `1053` is set to `D`.

```
Required: USER_ID (or USER / BNAME), RISK_ID
Optional: MITIGATION_ID, MIT_VALID_TO, RISK_LEVEL
```
> **`MIT_VALID_TO` decides whether a mitigation counts.** The module treats an
> expired or undated mitigation as no mitigation, deliberately. Parameter `1011`
> sets the default mitigation lifetime (SAP ships 365 days), so a control
> assigned and forgotten a year ago is exactly the case this column exists to
> expose. Export it.
>
> Two parameters change what the analysis even contains, and both belong in the
> export note: `1031` excludes critical roles and profiles by default, and `1030`
> excludes already-mitigated risks by default. A violation list produced with the
> defaults is narrower than the estate.

### Mitigating controls (`grac_mitigating_controls.csv`)
**Route:** `NWBC` → Access Control → mitigating control maintenance; the
*Invalid Mitigating Controls* report lists assignments whose risk no longer
exists. **Authorization object:** `GRAC_MITC` (fields `GRAC_MITC` control id,
`GRAC_OUNIT`). *Table name not verified.*

```
Required: CONTROL_ID (or MITIGATION_ID), CONTROL_OWNER (or OWNER), MONITOR
Optional: MONITOR_FREQUENCY, VALID_TO
```

### SoD risks and rule set (`grac_sod_risks.csv`)
**Route:** `NWBC` → Access Control → access risk maintenance. **Authorization
object:** `GRAC_RISK`, whose fields name the columns exactly: `GRAC_RISK` (risk
id), `GRAC_RLVL` (risk level), `GRAC_RSET` (rule set id), `GRAC_RTYPE` (risk
type), `GRAC_BPROC` (business process). *Table name not verified.*

```
Required: RISK_ID, RISK_LEVEL, STATUS
Optional: RISK_OWNER, RISK_TYPE, RULE_SET
```

### Which rule set you are being measured against (`ara_ruleset.json`)
SAP delivers its SoD rule content as **BC sets**, activated at installation.
Which ones are active is what your violation counts mean:

`GRAC_RA_RULESET_COMMON`, `..._SAP_R3`, `..._SAP_BASIS`, `..._SAP_HR`,
`..._SAP_NHR`, `..._SAP_CRM`, `..._SAP_SRM`, `..._SAP_APO`, `..._SAP_ECCS`,
`..._S4HANA_ALL`, and the non-SAP sets `..._JDE`, `..._ORACLE`, `..._PSOFT`.

Export the active rule set with its id and version. SAP Note **986996** explains
the delivered risk-analysis and remediation rules and is the reference for what
each rule means. A customer-written rule set is the other legitimate answer —
name it, and the finding text will say the analysis was run against yours.

---

## Basis background jobs and OS commands

### Background jobs (`background_jobs.csv`, `sm37_jobs.csv`, `tbtco.csv`)
**Transaction:** `SM37`. Select by job name, user name, status and time period,
then export the overview list.

```
Required: JOBNAME, SDLUNAME (or the "Job CreatedBy" column), STATUS
Optional: STRTDATE, STRTTIME, PERIODIC
```
The overview carries job name, created-by, status, start date, start time,
duration and delay — filter on **user name** rather than job name when you want
everything a given account schedules, which is the question the module asks.

### Background job steps (`background_job_steps.csv`, `job_steps.csv`, `tbtcp.csv`)
**Transaction:** `SM37` → select the job → **Step** → *Step List Overview*.

```
Required: JOBNAME, PROGRAM (the "Program name/command" column)
Optional: AUTHCKNAM (the step "User"), TYPE (Prog. type), PARAMETER, LANGUAGE
```
> **The step user is the whole point of this export.** A job's *step* runs under
> an authorisation user that need not be the account that scheduled it, so a
> low-privileged scheduler can run a step as a privileged one. The overview shows
> the program and the user side by side; export both columns or the check cannot
> be made.

### External OS commands (`ext_os_commands.csv`, `sm69_commands.csv`)
**Execution transaction:** `SM49`. Where SAP GRC Emergency Access Management is
in use, configuration parameter `4006` makes it collect the O/S command log
(table `GRACOSCMDLOG`) covering commands created, changed or executed — which is
the audit trail for this surface rather than the command definitions themselves.
*The definition-maintenance transaction and table are not verified here; export
the command list from your Basis team's own documented route and say which.*

```
Required: NAME (command name), OPSYSTEM, OPCOMMAND
Optional: PARAMETERS, ADDITIONAL_PARAMETERS_ALLOWED
```

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

Nothing in the scanner connects to Cloud ALM, to SAP, or to anything else. **It reads
files.** Those files have three possible producers and it cannot tell them apart:
you, using the commands in this guide; SAP's own tooling; or a `collect/`
connector you run against a system you authorise (decision D2).

There is still no live API client *inside* the scanner or the server, deliberately:
one we cannot exercise would be a capability claim we could not stand behind. A
connector is a separate, optional program that produces an export — never a second
ingestion path.

**Connected mode does not make an export unnecessary.** Some surfaces are reachable
only over RFC, which this product declines (decision D3), and those remain
export-only. A connected run that silently omits them would be the same
"we could not look, so we said nothing" failure the release gate now refuses.

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

### Telling the scanner an export is complete (`export_completeness.json`)

**Optional, and it changes what a missing row means.**

For most of this guide, a row that isn't in your export means nothing — the
scanner can't tell whether the setting is absent from the *system* or absent from
the *export*. Profile parameters are the sharpest case: `RSPARAM` lists every
parameter, but `RZ11` returns one at a time, and both are offered above. So a
parameter missing from `security_params.csv` is genuinely ambiguous, and the
scanner reports it as a gap rather than judging it.

If you know your export is the **complete** list, say so:

```json
{
  "complete_sources": ["security_params"],
  "declared_by": "basis-team@example.com",
  "declared_at": "2026-08-11",
  "method": "RSPARAM, full list, no name filter"
}
```

Save it as `export_completeness.json` beside your CSVs. With it in place, a
parameter absent from a listed source is treated as **not set** — a real finding
against the baseline — rather than listed as something we couldn't see.

| without it | with it |
|---|---|
| `PARAM-MISSING` / `PARAM-MISSING-OTHER` name the parameters as coverage gaps | each absent parameter gets a real finding: *"Parameter X is not set"* |
| the release gate is held open by degraded coverage | the gate judges on the findings themselves |

**Three things to be clear about:**

- **It is a declaration, not a proof.** Nothing verifies it. Every finding built
  on it says so in its own text and names this file, so if the declaration is
  wrong the finding is traceable to it rather than merely wrong.
- **Undoing it is one step.** Delete the file, re-run, and every finding that
  rested on it goes back to being a coverage disclosure.
- **`python -m collect sapcontrol` writes it for you**, because it genuinely
  knows: it asks the instance for *every* parameter rather than a list of names.
  If that read was partial for any reason, delete the file.

Only list a source you are sure about. Declaring completeness you don't have
converts honest gaps into confident accusations — which is the failure mode this
whole product is built to avoid, arriving through the front door.

### Database coverage is HANA only — the other engines are declined, not pending

Decision D6, `docs/DECISIONS.md`. Stated here because this is where you would look
for it, and because silence about a gap reads as coverage.

`modules/hana_db_security.py` audits **SAP HANA**. It does not audit **Oracle,
IBM Db2, Microsoft SQL Server or SAP ASE**, and there is no partial or best-effort
coverage of them: no privileged-account check, no audit-policy check, no
encryption-at-rest check. If your ECC or NetWeaver system runs on one of those,
its database layer is **unscanned**, and nothing in a MonitorRisk report should be
read as a statement about it.

This is a scope decision, not a backlog item. HANA alone is 55 KB of engine-specific
logic; the other four are four more of those, and a shallow common core presented as
"database security" would imply a depth that is not there. If it is ever revisited it
will be as a deliberately scoped common core — privileged accounts, audit, encryption
at rest — costed as four modules and named as a common core, never as one module and
never as parity.

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

## Connected mode — letting MonitorRisk produce part of the export for you

Decision D2/D3/D4, `docs/DECISIONS.md`. Everything above assumes **you** produce
the files. On an estate where you can reach the system over the network — ECC and
on-premise NetWeaver typically, RISE typically not — MonitorRisk can produce some
of them itself.

**The scanner still does not connect to anything.** `collect/` is a separate,
optional program, run by you, that writes the same files this guide describes. The
scanner reads a directory; it cannot tell whether you filled it or a connector
did. That is the whole design, and it is why connected mode inherits every test
the offline path already has.

```bash
# 1a. Profile parameters, from the instance's SAP start service.
python -m collect sapcontrol --host ecc-prod.example.com --instance 00 \
                             --user SAPADM --out ./extract

# 1b. The ICF surface — which endpoints are active and which are UNAUTHENTICATED.
python -m collect icf --host ecc-prod.example.com --user SAPADM --out ./extract

# 2. Scan what they wrote, exactly as if you had exported it by hand.
python sap_scanner.py --data-dir ./extract
```

Both collectors write into the same directory and both are recorded in
`collection_manifest.json` — the manifest accumulates rather than being replaced,
so a directory built from two collections has a record describing two.

### The two collectors

**`sapcontrol`** speaks to the SAP start service over its SOAP interface on port
`5<NN>14` (HTTPS) or `5<NN>13` (HTTP) — instance `00` is `50014`/`50013`. No SAP
SDK is involved and no ABAP-side component is installed.

**`icf`** probes a short, fixed list of documented ICF paths over HTTP(S) and, if
you supply credentials, reads the SAP Gateway OData catalogue.

| | collects | cannot collect |
|---|---|---|
| `sapcontrol` | `security_params.csv` — the instance's profile parameters, the input for the Security Parameters and Baseline modules. Plus instance topology and the process list. | 14 logical sources |
| `icf` | `icf_services.csv` — which endpoints are active and **which answer with no authentication at all**. Plus `api_endpoints.json` from the Gateway catalogue. | 16 logical sources |

**Neither reaches users, roles, profiles or authorisations.** There is no
standard, pre-built OData service on ECC exposing `USR02` or `AGR_USERS`, and
Gateway exposes only the services an administrator has activated. Those sources
live inside the ABAP stack, are reachable over RFC or by an interactive export,
and this product declines RFC (decision D3). **A connected collection is partial
by construction** — the export sections above are still how you get the rest.

### The ICF probe is deliberately anonymous

Every ICF request is sent **without credentials**, and that is the entire point of
the `AUTH_REQUIRED` column. Sending a credential would turn a `401` into a `200`
and record an authentication-protected service as one needing none — inverting
the finding. The status code is the whole observation:

| answer | recorded as |
|---|---|
| `404` / `503` | not active here |
| `401` / `403` | active, authentication required |
| `302` to a logon page | active, authentication required — the redirect is **not** followed |
| `200` | **active and unauthenticated** ← the finding |
| no answer at all | unknown, never "absent" — a firewall is not a clean estate |

`--user` is used *only* to read the Gateway catalogue, never for the probe.

**This is an audit of known endpoints, not a scan.** The path list is short,
fixed and reviewed, each entry carrying a stated reason. It does not enumerate,
guess, fuzz or follow links: authorising a configuration review is not authorising
a web crawl of your production application server. Use `--delay` if your
dispatcher rate-limits.

One documented limitation carried into the manifest: the Gateway catalogue **does
not list OData V4 services**, so `api_endpoints.json` covers V2 only.

Every run writes `collection_manifest.json` next to the data, listing exactly what
it obtained, what failed, and what is not reachable at all. Read it. A directory
with four files in it and no statement about the fortieth is indistinguishable
from a complete export, and that ambiguity is the failure this product exists to
refuse — treat any check depending on an uncollected source as **unknown**, never
as clean.

### Credentials, TLS, and what it will refuse to do

- **There is no `--password` flag and there will not be.** An argument is visible
  in `ps` output and in shell history on a shared administrative host. The
  password is prompted on a TTY, read from a pipe, or taken from
  `SAPCONTROL_PASSWORD`.
- **TLS is verified by default.** `--insecure` exists because many instances
  present a self-signed certificate, but it is recorded in the manifest — an
  unverified connection is a caveat on the evidence, not a detail of the plumbing.
  `--ca-file` is the better answer for a self-signed estate.
- **It is read-only, and that is enforced rather than promised.** The same service
  and the same port also offer `Start`, `Stop`, `Restart` and OS command
  execution. The collector carries an allowlist of read operations that the
  transport checks *before any byte reaches the network*, so no typo and no future
  caller can stop a production instance.

### Try it without connecting to anything

```bash
python -m collect sapcontrol --host <host> --instance 00 --probe-only
```

Reports what the endpoint advertises and whether it answers **without
credentials**, collects nothing and writes nothing. Worth running first: an
instance that answers an unauthenticated caller is exposing an interface that can
also stop it, which is governed by the profile parameter
`service/protectedwebmethods` (see SAP Note 927637 and SAP Note 1439348).

## Tips

- **Export from production** — always scan production configuration
- **Anonymize before sharing** — replace real usernames with pseudonyms for external review
- **Delimiter auto-detection** — the scanner handles comma, semicolon, tab, and pipe delimiters
- **All files optional** — the scanner runs only checks for which data is available
