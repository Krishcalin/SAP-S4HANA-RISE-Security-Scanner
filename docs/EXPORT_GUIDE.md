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

These seven sources feed `modules/grc_access_control.py`. They come out of a
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
> Record the date each job last ran alongside the export — or better, export
> the stamp table itself (*Synchronisation job log*, below) and the scanner
> dates every family and flags the stale ones (`GRC-SYNC-001`) mechanically. A
> finding built on a three-week-old sync is a finding about three weeks ago.

**Read-only is enough.** SAP delivers `SAP_GRAC_DISPLAY_ALL` for display-only
access to GRC master and application data; it is the role SAP itself names for
read-only remote support. Nobody needs a maintenance role to produce these files.

**Finding the transaction for anything below**: `SE93`, search `GRAC*`.

### Synchronisation job log (`grac_job_log.csv`, `gractaskexecstmp.csv`)
**Table:** `GRACTASKEXECSTMP` — executed background jobs with last-run stamps
[corroborated — community SE80 table catalogue, not an SAP document; confirm
in `SE11` before scripting]. **Route:** `SE16` on that table, or `SM37` job
selection filtered to `GRAC_*`, exported to spreadsheet.

```
Required: TASK (or JOB / JOB_NAME / JOBNAME / PROGRAM),
          LAST_RUN (or EXEC_DATE / EXEC_TIMESTAMP / TIMESTAMP / END_DATE)
```

The scanner recognises synchronisation families by name (anything containing
`SYNC`), takes the latest run of each, and raises `GRC-SYNC-001` for every
family more than seven days behind — SAP's own recommended frequencies are
daily for five of the six families and weekly for the authorisation sync. A
family with no parseable run date is reported as "no recorded execution",
which is the fail-safe reading.

> This export dates the evidence itself. Every other file in this section is
> a synchronised copy, and the job table above can only ask you to check the
> sync by hand; this file lets the scanner do it and put the answer in the
> report next to the findings that depend on it.

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
`4003`–`4006` decide which logs are collected at all (change log `GRACCHANGELOG`, system log `GRACSYSTEMLOG`, audit log
`GRACAUDITLOG`, O/S command log `GRACOSCMDLOG`; action usage lands in
`GRACACTUSAGE` — table names corroborated by the community catalogues). If those are unset, the log is thin for a reason
that has nothing to do with how the estate is used — note it on the export.

### Firefighter ID owners and controllers (`grac_firefighter_owners.csv`)
**Route:** `NWBC` → Access Control → Emergency Access Management → owner and
controller maintenance. **Authorization object:** `GRAC_FFOWN` (fields
`GRAC_OWN_T` owner type, `GRAC_USER`, `GRAC_SYSID`).
*Table names corroborated, not verified*: two independent community
catalogues list `GRACFFOWNER` and `GRACFFOBJECT`, and spell the controller
table differently between them — `GRACFFCNTL` in one, `GRACFFCTRL` in the
other. That disagreement is the shift-between-support-packs warning
demonstrating itself in the sources. Confirm the spelling in `SE11` before
scripting an extraction — the maintenance-screen export needs none of that.

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
`GRACREQOWNER`, `GRACREQPROVITEM` and `GRACREQPROVLOG`; the approval trail
itself lives in the MSMP workflow runtime — `GRFNMWRTINST`, `GRFNMWRTAPPR`
(the approvals), `GRFNMWRTDATLG`, `GRFNMWRTMSGLG` [corroborated] — worth
exporting when the question is WHO approved, not just whether. **Authorization
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
**Table:** `GRACUSERPRMVL` — user-level violations, verified twice over: SAP's
technical-table catalogue (SAP Note 2388483) lists it under *GRC violations*,
and SAP Note 2270608 names it in its title. The loader accepts
`gracuserprmvl.csv` directly. The same catalogue row names a role-level
sibling, `GRACROLEPRMVL`; this product reads user-level violations only.
**Route:** Batch risk analysis (`GRAC_BATCH_RA`, monitored with
`GRACRABATCH_MONITOR`), then export the violation report. Related stored data:
`GRACSODUSERROLE`, `GRACSODREVIEW`; spooled analytics land in `GRACSODREPDATA`
(with `GRACSODREPINDEX` and `GRACSODREPSTATUS`, column `REPCONTENT`) when
configuration parameter `1053` is set to `D`.

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
`GRAC_OUNIT`). *The flat-table guess is CONTRADICTED*: the same community
catalogue that corroborates other names here indicates the control MASTER
record — owner, monitor, validity, exactly the columns below — lives in the
GRC entity/hierarchy framework, not in a flat `GRAC` table (the flat
`GRACMIT*` tables hold user/role/profile ASSIGNMENTS). `GRACMITCNT` may
exist; the data this file needs is not simply in it. The NWBC export is not a
fallback route. It is the route. The ASSIGNMENT-level tables are flat and
corroborated — `GRACMITUSER` (user) and `GRACMITROLE` (role); the control
MASTER is what is not.

```
Required: CONTROL_ID (or MITIGATION_ID), CONTROL_OWNER (or OWNER), MONITOR
Optional: MONITOR_FREQUENCY, VALID_TO
```

### SoD risks and rule set (`grac_sod_risks.csv`)
**Route:** `NWBC` → Access Control → access risk maintenance. **Authorization
object:** `GRAC_RISK`, whose fields name the columns exactly: `GRAC_RISK` (risk
id), `GRAC_RLVL` (risk level), `GRAC_RSET` (rule set id), `GRAC_RTYPE` (risk
type), `GRAC_BPROC` (business process). *Table names corroborated, not verified*:
the community catalogue lists `GRACSODRISK` (with `GRACSODRISKT` texts) and
`GRACRULESET`, and names `GRACSODRISKOWN` as the risk-to-owner assignment —
so an export whose `RISK_OWNER` column comes back empty may simply have been
taken from the risk table alone. Confirm in `SE11` before scripting; the
NWBC export sidesteps the question. The catalogue also names the
rule-generation siblings `GRACSODRISKFUNC` (risk-to-function), `GRACORGRULE`
and `GRACACTRULE` [corroborated] — the org-rule table is where org-scope
conflicts come from.

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

---

---

## ABAP change and audit logging

Two sources that decide whether the `log_monitoring` and `log_review` audit
checks run. They share the failure mode this product exists to name: each is a
*configuration* whose absence silently produces an empty *log*, and an empty
log reads as good news.

### Security audit log configuration (`security_audit_log.csv`, `sm19_filters.csv`)
**Transaction:** `RSAU_CONFIG` — the kernel-based Security Audit Log
configuration as of NetWeaver 7.50, with `RSAU_ADMIN` administering the log and
its database store (tables `RSAU_BUF_DATA` and `RSAU_LOG`). On older systems
the classic configuration transaction is `SM19`, the same one the
`audit_config` export records. SAP Note **2191612** is the FAQ for the 7.50+
log; SAP Note **3137004** covers archiving and deleting the database trail.

Export the filter list — each filter with its activation state and event
selection:

```
Required: ACTIVE (or STATUS), EVENT_CLASS (or EVENT_TYPE / FILTER_EVENT)
Optional: PROFILE_TYPE (the module matches STATIC / DYNAMIC), DESCRIPTION
```

> **A filter list is not a log.** These checks read whether auditing is
> *configured*: active filters, event coverage. An estate with no active
> filters produces no audit events at all, and "no security events" is the most
> reassuring sentence a review can be handed. That is why the export is the
> configuration, and why an empty one is a finding rather than a pass.

### Table change logging (`table_logging.csv`, `dd09l.csv`)
**Per-table flag:** the *Log Changes* setting in a table's technical settings
(`SE11` / `SE13`). **The log it produces:** table `DBTABLOG`, displayed with
transaction `SCU3`, retained long-term via archiving objects `BC_DBLOGS` and
`S_AUT_LTXT`. All of that is verified against SAP's Data Management Guide
(ch. 5.8) and SAP Note 2388483. *The loader also accepts `dd09l.csv` — DD09L is
where working knowledge says the flag lives, but that table name is not
verified in these documents; export the flag list from `SE11`/`SE13` or your
own audit tooling, and say which.*

```
Required: TABNAME (or TABLE_NAME / TABLE), LOGGING (or LOG_ENABLED / LOG_FLAG)
```

> **The flag alone logs nothing.** SAP writes a change record only when BOTH
> conditions hold: the table's *Log Changes* flag is set AND the profile
> parameter `rec/client` permits it — `OFF` never logs, `nnn[,mmm…]` logs the
> listed clients (at most ten), `ALL` logs every client, and the value must be
> consistent across all application servers. A flagged table on a system with
> `rec/client = OFF` writes no `DBTABLOG` rows, and the empty history it leaves
> is indistinguishable from "nobody changed anything". Record `rec/client` —
> it is already in your `security_params.csv` — alongside this export.

---

## FI customizing exports (the `fincontrols` module)

Five exports, five IMG transactions, five standard Customizing tables that
have carried these settings for decades. This is the configuration half of
the financial-controls pair — the evidence half (BKPF document headers) is
documented in the next section, and each check here names what its evidence
twin would show.

**Read-only is enough for all five**: display access to the IMG activity, or
`SE16` display on the table.

### Posting periods (`posting_periods.csv`, `t001b.csv`, `ob52.csv`)
**Transaction:** `OB52` — maintains posting-period variants in `T001B`
(view `V_T001B`). **Route:** read the OB52 screen into the CSV, or `SE16` on
`T001B` unfiltered.

```
Required: VARIANT (or BUKRS / PERIOD_VARIANT), ACCOUNT_TYPE (or KOART),
          FROM_PERIOD / TO_PERIOD (or FRPE1 / TOPE1),
          FROM_YEAR / TO_YEAR (or FRYE1 / TOYE1)
Optional: AUTH_GROUP (or BRGRU) — export it; it is the point
```

Export EVERY row: all account types (`+` is the all-types row) and all
period intervals. The second interval is the special-period range where the
authorization group belongs — a wide-open first interval with no `BRGRU` on
any row is exactly what FIN-PP-001 exists to catch, and `9999` as a to-year
reads as "open into the far future", which it is.

### Tolerance groups (`tolerance_groups.csv`, `t043t.csv`, `oba4.csv`)
**Transaction:** `OBA4` — FI tolerance groups for users, stored in `T043T`
(user assignments in `OB57`).

```
Required: GROUP (or TOLERANZ — blank IS the default group),
          AMOUNT_PER_DOC (or MAX_AMOUNT)
Optional: CURRENCY, AMOUNT_PER_OPEN_ITEM
```

> **Supply this file even when it is empty.** An empty export is evidence —
> "no tolerance groups are defined, so no posting limit exists" — and raises
> its own finding (FIN-TOL-002) instead of silently skipping the check. The
> blank-key group is the default every unassigned user falls into; do not
> filter it out. Amounts are parsed locale-tolerantly (`1,234.56` and
> `1.234,56` both work), so export in whatever format the GUI gives you.

### Sensitive fields for dual control (`dual_control_fields.csv`, `t055f.csv`, `sensitive_fi_fields.csv`)
**Transactions:** `FK08` (vendor) / `FD08` (customer) define which
master-data fields are dual-control sensitive; storage is `T055F`.
**Route:** read the FK08/FD08 field list, or `SE16` on `T055F`.

```
Required: FIELD (or FIELDNAME / FELDNAME) — plain ("BANKN") or
          table-qualified ("LFBK-BANKN"); both are accepted
Optional: TABLE, ACCOUNT_TYPE
```

The check tests COVERAGE, not presence: an export that exists but contains
no payment-relevant field (`BANKN`, `BANKL`, `BANKS`, `IBAN`, `BVTYP`,
`ZWELS`, `HBKID`) raises FIN-SF-001, because a dual-control list that skips
the bank fields protects everything except the fraud path. The runtime twin
is the change-document register (MDC-BANK-001): this export says whether a
second person HAD to confirm; that register shows the changes that went
through.

### Document change rules (`doc_change_rules.csv`, `tbaer.csv`, `ob32.csv`)
**Transaction:** `OB32` — document change rules, stored in `TBAER`.

```
Required: FIELD (or FELDNAME), CHANGE_ALLOWED (or CHANGEABLE / AENDERBAR)
Optional: ACCOUNT_TYPE (or KOART), AFTER_POSTING (or POSTED),
          AFTER_CLEARING (or CLEARED)
```

> **Do not feed raw TBAER columns into this file.** The raw `XAUSZ` flag
> means the OPPOSITE of what it looks like — `X` = *not* changeable after
> clearing — and a contract built on a negative flag would invert somewhere
> between `SE16` and the CSV. The loader therefore takes INTERPRETED,
> positive columns: `CHANGE_ALLOWED` = the rule permits the change,
> `AFTER_POSTING` / `AFTER_CLEARING` = it permits it even then. Read the
> rules off the OB32 screen (which displays them positively) or transform
> deliberately, and say which on the export note.

### FI number ranges (`fi_number_ranges.csv`, `tnro.csv`, `number_ranges.csv`)
**Transaction:** `SNRO` — number-range object maintenance; the buffering
flag lives in `TNRO`. **Route:** `SNRO` on `RF_BELEG` (and `FI_BELEG` /
`RF_BELEG_M` where present), or `SE16` on `TNRO`.

```
Required: OBJECT (or NROBJ), BUFFERING (or PUFFER / BUFFER_TYPE)
Optional: NO_BUFFER (inverse flag, if that is what your export carries)
```

Every non-blank buffer code counts — `X` (main memory), `L` (local), `P`
(parallel-local) and `S` all discard numbers on restart and break the
sequential-completeness assertion over FI documents. Only the ACCOUNTING
document objects are assessed: master-data ranges (`DEBITOR`, `KREDITOR`)
gap legitimately per SAP Note 62077, and SD/CO document ranges carry no FI
completeness assertion — the module deliberately ignores them, so export
everything and let it filter. Interval contents (`NRIV`) are not needed.

---

## Master-data change and posting evidence (the `mdchange` + `fincontrols` modules)

The sections above export CONFIGURATION. These two sources export EVIDENCE —
what actually happened — and each pairs with a configuration check that says
what should have been possible. FIN-SF-001 reports whether vendor bank fields
are under dual control; the change-document items show the bank changes that
went through. FIN-PP-001 reports whether posting periods stand open; the FI
document headers show the back-dating that happened anyway.

### Change-document items (`change_document_items.csv`, `cdpos.csv`)
**Tables:** `CDHDR` (headers — already exported above as
`change_documents.csv`) and `CDPOS` (items, with `VALUE_OLD` / `VALUE_NEW`).
Both are core data-dictionary tables, stable across releases. **Route:** `SE16`
on `CDPOS`, filtered by `TABNAME` to the payment-relevant tables the module
reads — `LFBK`, `KNBK`, `BUT0BK`, `TIBAN` — or unfiltered for a date-bounded
change-number range. Export the matching `CDHDR` range too: item rows carry no
user or date, and the join runs over `CHANGENR`.

```
CDPOS: OBJECTCLAS, OBJECTID, CHANGENR, TABNAME, FNAME,
       VALUE_OLD, VALUE_NEW, CHNGIND
```

> **Bank account values in this export are sensitive by definition.** Findings
> mask everything but the last four characters, but the CSV itself is the
> unmasked original — handle it like the payment data it is.

### FI document headers (`fi_documents.csv`, `bkpf.csv`)
**Table:** `BKPF` — accounting document HEADERS only. **Route:** `SE16` on
`BKPF` for the audit window (filter on `CPUDT`, the entry date), every company
code in scope. Headers are enough for the evidence checks; no line items and
no amounts leave the system.

```
Required: BUKRS, BELNR, GJAHR, BUDAT, CPUDT
Optional: BLART, USNAM, TCODE, STBLG (reversal document), BSTAT
```

> Amount-level checks (postings above tolerance limits) would need line items
> (`ACDOCA` / `BSEG`) and are deliberately not part of this export: the
> header-only file keeps monetary data out of the audit bundle while still
> answering when a document was posted versus when it was entered, who entered
> it, and whether it was reversed.

---

## SAP Security Notes exports (the sap_hotnews module)

The module ships its own curated catalogue of high-impact notes (through
2025-08), so only ONE export from the system is required; the second file is
an optional catalogue extension, not a system export.

### Applied notes (`applied_notes.csv`, `snote_status.csv`, `implemented_notes.csv`)
**Route (preferred):** System Recommendations — in SAP Solution Manager 7.2 or
SAP Cloud ALM — filtered to security notes for the audited system, exported to
spreadsheet. Preferred because it also tracks KERNEL-delivered fixes (the
CommonCryptoLib note 3340576 ships as a kernel/CCL patch, not an SNOTE
correction instruction) that a pure SNOTE worklist cannot represent.
**Route (alternative):** transaction `SNOTE` (Note Assistant) — export the
note worklist with implementation status. SAP Note **2342391** describes how
security notes are accessed and consumed.

```
Required: NOTE (or SAP_NOTE / NOTE_NUMBER / NUMBER),
          STATUS (or IMPLEMENTATION_STATUS / PROCESSING_STATUS)
Optional: TITLE, VERSION
```

Status vocabulary: "Completely implemented", "Obsolete", "Not relevant" and
"Cannot be implemented" count as addressed; "Incompletely implemented" is
surfaced as its own finding; "Can be implemented" / "New" / "Downloaded" count
as NOT applied. Note numbers may arrive zero-padded (`0002934135`) — the
module normalises them.

> **Absence is treated as missing, on purpose.** A note that never appears in
> the export — never downloaded, never evaluated — is counted as missing, not
> skipped. The reassuring reading ("SNOTE has never heard of it, so it must
> not apply") is exactly the reading this product refuses to make. If a note
> genuinely does not apply, SNOTE says so once it has been evaluated
> ("Cannot be implemented", "Obsolete"), and that status is honoured. No
> table name is claimed for this export: the SNOTE worklist store is
> internal, and the two UI routes above are the documented ways out.

Record the export date alongside the file: an export taken before the last
patch cycle understates the estate in the safe direction, but one taken from
a System Recommendations run that has not been refreshed can overstate it.

### Security-notes catalogue extension (`sap_security_notes.json`, `hotnews_catalog.json`)
**Not a system export.** The built-in catalogue is curated through 2025-08;
this OPTIONAL file extends or corrects it. Source: SAP ONE Support Launchpad →
My Security Notes (S-user required), filtered to HotNews / High. Notes newer
than the built-in cut-off — for example the Feb-2026 HotNews the operator
reference lists (note 3747367 / CVE-2026-44747), once confirmed in the
Launchpad — belong here:

```json
[{"note": "3747367", "cve": "CVE-2026-44747", "priority": "HotNews",
  "component": "NetWeaver AS ABAP", "released": "2026-02",
  "applies_to": "abap"}]
```

Merge semantics: entries override the built-in catalogue key-by-key and never
blank a curated field by omission (an entry without `exploited` keeps the
built-in flag). `applies_to` values other than `abap` (`java`, `bi`, `btp`,
`solman`) move an entry into the adjacent-systems disclosure instead of the
missing-notes findings; an entry that does not say defaults to `abap` — the
fail-safe direction is a false alarm on this system, never a silent pass.

## SAP HANA database exports (the `hana_db_security` module)

Five sources, from the database underneath S/4HANA rather than from the ABAP
stack. They are the last exports most people produce and the first ones a
database-layer finding depends on.

> ⚠️ **WHICH HANA YOU ARE ON DECIDES WHICH OF THESE EXIST.** SAP HANA Cloud runs
> a shared-responsibility model. You own users, authorisation, auditing, masking
> and anonymisation. SAP owns secure operation, encryption and system auditing —
> and you have **no operating-system access, no file-system access, and no access
> to the system database**, only your tenant.
>
> That is not a limitation to work around, it is an answer. Where SAP holds the
> control, the honest state is *not applicable*, not *not assessed*, and this
> product will say so if you tell it which deployment you are on. Say it.

**The superuser has two names, and only one of them is `SYSTEM`.** On-premise and
managed HANA ship `SYSTEM`. SAP HANA Cloud ships **`DBADMIN`** — and SAP's list
of *essential* security tasks, the five things to do after creating an instance,
includes "Deactivate the user DBADMIN" as item four. Both names are checked.

### Database users (`hana_db_users.csv`, `sys_users.csv`)
**System view:** `USERS` — verified. SAP names it as the view carrying `CREATOR`
(the user is technically created by `SYS`) and `CREATE_PROVIDER_TYPE` /
`CREATE_PROVIDER_NAME` (which identity provider created the user, where one did).
Restricted users — those without the `PUBLIC` role or authorisation for their own
schema — are identified here too.

```
Required: USER_NAME, IS_DEACTIVATED (or DEACTIVATED / USER_DEACTIVATED / ACTIVE)
Optional: IS_PASSWORD_LIFETIME_CHECK_ENABLED, LAST_SUCCESSFUL_CONNECT,
          CREATOR, CREATE_PROVIDER_TYPE, CREATE_PROVIDER_NAME, USER_MODE
```
`ACTIVE` is read inverted against `DEACTIVATED`, so either spelling works — but
export one of them. Without a status column every account reads as active.

**Password policy is per user group, not per system.** A group's initial policy
is a copy of the default (`password policy` section of `indexserver.ini`) and can
then diverge. To see what is actually in force for one account rather than what
the system default says:

```sql
SELECT * FROM "PUBLIC"."M_EFFECTIVE_PASSWORD_POLICY" WHERE USER_NAME = '<user>';
```

Worth exporting alongside: `USERGROUPS`, `USERGROUP_PARAMETERS` and
`USERGROUP_CONNECT_RESTRICTIONS` — all named system views. Connect restrictions
limit a group to an IP range, an application or an authentication method, and a
user connects only if at least one restriction allows it. A group with none is a
different posture from a group with one that permits everything.

### Granted privileges (`hana_granted_privileges.csv`, `granted_privileges.csv`)
**System view:** `GRANTED_PRIVILEGES` — verified.

```
Required: GRANTEE, PRIVILEGE
Optional: IS_GRANTABLE, OBJECT_TYPE, SCHEMA_NAME, OBJECT_NAME, GRANTOR
```
> **`GRANTOR` can be structurally missing, and that is not an export error.**
> When a privilege is granted with the `USING GROUP` option, SAP states plainly
> that you can no longer determine which user performed the grant from this view
> — the grant is attributed to the user group principal instead. SAP's own answer
> is to audit `GRANT` and `REVOKE` operations. So a blank grantor column may mean
> the estate uses group-principal granting, not that the export is short. Note
> which, on the export.

### Granted roles (`hana_granted_roles.csv`, `granted_roles.csv`)
**Route:** the **Role Assignment** app of SAP HANA Cloud Central is the tool SAP
names for granting roles to database users; export the assignments from there.
*The system view name `GRANTED_ROLES` is this product's assumption and is not
verified in the security guide* — use the app, or your own documented route, and
say which you used.

```
Required: GRANTEE (or USER_NAME), ROLE_NAME (or ROLE)
Optional: GRANTOR, IS_GRANTABLE
```
The two role names this export exists to find are `_SYS_BI_CP_ALL`, which
bypasses analytic privileges entirely, and any role granting `USER ADMIN`. Note
that on HANA Cloud, `DBADMIN` is deliberately **not** granted `USER ADMIN` — so
finding it granted to somebody is a change from the delivered state.

### Security parameters (`hana_parameters.csv`, `m_inifile_contents.csv`)
*The view name `M_INIFILE_CONTENTS` is unverified here.* The **sections** are
confirmed: `password policy` in `indexserver.ini`, and `ldap` in `global.ini`.

The LDAP TLS parameters and their SAP-documented defaults, which are worth
exporting whether or not you use LDAP, because the defaults are the finding:

| Parameter | Default | Reads as |
|---|---|---|
| `sslMinProtocolVersion` | `TLS12` | minimum accepted TLS version |
| `sslMaxProtocolVersion` | `MAX` (internally `TLS12`) | maximum accepted |
| `sslCipherSuites` | `PFS:HIGH::EC_HIGH:+EC_OPT` | permitted ciphers |
| `timeout` | `0` | **no timeout at all** |

One more export that needs no view name at all, because SAP gives the statement:

```sql
SELECT * FROM M_CUSTOMIZABLE_FUNCTIONALITIES WHERE IS_ENABLED = 'FALSE';
```
That lists the features SAP has disabled on your instance — import/export on the
server, and operational features SAP takes responsibility for. **You cannot
enable what SAP has disabled**, so a check against one of those features is
answered by this list rather than by a finding.

### Audit policies (`hana_audit_policies.csv`, `audit_policies.csv`)
**Route:** auditing configuration in SAP HANA Cloud Central / SAP HANA Cockpit.
*The view name `AUDIT_POLICIES` is unverified here*; that audit policies are the
mechanism, and that creating them is an **essential** post-installation task, is
confirmed.

```
Required: AUDIT_POLICY_NAME, IS_AUDIT_POLICY_ACTIVE (or IS_ENABLED / ACTIVE / STATUS)
Optional: AUDIT_ACTION_NAME (or ACTIONS / EVENT_ACTIONS), AUDIT_TRAIL_TYPE, LEVEL
```
> **The audit-trail-target check does not apply to HANA Cloud.** On HANA Cloud
> the trail is *always* written to a database table local to the database, to
> keep it private to that database — a file-system target is not reachable, and
> neither is the file system. On-premise, `CSVTEXTFILE` remains a real and
> serious misconfiguration. Same check, two deployments, two meanings.
>
> SAP also runs its **own** audit policies on customer systems for central
> security monitoring. Those are designed to give SAP no insight into your
> business data, and you can write your own policies to monitor what SAP-owned
> database users do. If you see policies you did not create, that is why.

### Encryption and key management (`hana_encryption.json`, `key_management.json`)
On **SAP HANA Cloud** this is short and worth being exact about: data volumes,
log volumes and backups are encrypted, and **it is not possible to disable
encryption**. There is no setting to export and no finding to raise. Record the
deployment and that is the whole answer.

The one customer-controlled dimension is the root key. HANA encryption root keys
can additionally be secured with the external **SAP Data Custodian Key Management
Service (KMS)**. Whether you use it is a real posture question:

```
hana_encryption.json  {"deployment": "hana_cloud", "data_at_rest": "enforced_by_sap",
                       "can_be_disabled": false}
key_management.json   {"root_key_protection": "sap_managed" | "customer_kms",
                       "kms": "sap_data_custodian" | null}
```
On-premise HANA is the opposite case — there encryption *is* yours to configure,
it can be off, and the export has to carry the real state.

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
`iframeDomains` / `iframeDomainsList`, `customEmailDomains`. This settles whether a
subaccount still logs on through the default SAP ID service, and it is the only
source for four further checks: the OAuth token lifetimes against SAP's published
defaults (`BTP-TOK-*`), which origins may embed the login page in an iframe
(`BTP-FRM-*`), and — read together with `btp_trust.json` — whether an email address
links identities across identity providers (`BTP-IDL-001`).

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
>
> **Those subaccounts are named rather than dropped.** `BTP-AUD-001` lists every
> subaccount whose audit-log state neither this file nor the subaccount export
> settles, and carries `degrades_coverage` so `--gate` will not return a clean build
> on the strength of them. A subaccount that appears in neither `BTP-GOV-001` nor
> `BTP-AUD-001` is one this scan positively confirmed is logging.

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
| `btp_accounts_subaccount.json` | `BTP-GOV-001`, `BTP-GOV-002` (with files 2 and 4), `BTP-AUD-001` |
| `btp_security_settings.json` | `BTP-GOV-002`, `BTP-TOK-001…003` (token policy), `BTP-FRM-001/002` (iframe embedding), `BTP-IDL-001` (with `btp_trust.json`) |
| `btp_role_collections.json` | `S4AUTHZ-008` (birthright role collections) |
| `btp_audit_log_records.json` | `BTP-GOV-001` (evidence that logging is on), `BTP-AUD-001` (which subaccounts it leaves unsettled) |
| `cloud_connector_configuration.json` | `BTP-CC-001` … `BTP-CC-008`, `S4AUTHZ-006` |

Hand-made files in the scanner's own shape (`cloud_connector.json`,
`btp_subaccounts.json`, `btp_role_collection_mappings.csv`) keep working exactly as
before and take precedence: the translators recognise raw tooling output by its own
field names and leave anything else untouched.

---

## The CAP project itself (the `capxsuaa` module)

This one is not an export. It is the application's own source tree, and it is
supplied with a path rather than a file:

```bash
python sap_scanner.py --data-dir ./export --cap-src /path/to/cap-project
```

Point `--cap-src` at the **project root** — the directory holding `srv/`, `db/` and
the `mta.yaml` or `package.json`. `node_modules/`, `gen/`, `dist/` and the other
build directories are skipped, so pointing at a working checkout is fine and no
cleaning step is needed.

**Why a source tree at all, when everything else here is an export.** Several
authorization facts exist only at design time and appear in no runtime export
anywhere:

| Fact | Where it lives | Nothing else can see it because |
|---|---|---|
| A wildcard OAuth redirect URI | `xs-security.json` | The subaccount shows the client, not its redirect list |
| An application-level token lifetime | `xs-security.json` | It **overrides** the subaccount policy `BTP-TOK-*` measures |
| A scope granted to another application | `xs-security.json` | It is held by an app, so it is in no role collection |
| A CAP service with no access control | `srv/*.cds` | The deployed service looks identical either way |
| Which scopes a role collection delivers | both | The subaccount export carries counts, not the chain |

The last row is the one worth supplying both halves for. Export
`btp_role_collections.json` (file 3 above, in its **detailed** form) alongside the
project, and `CAPX-GRAPH-002` can follow the whole chain — scope → role-template →
role-collection → IdP group — and tell you which application privileges every
federated user holds by birthright. Neither side answers that alone: the descriptor
knows what a collection grants and not who has it; the subaccount knows who has it
and not what it grants.

> **Two parsers, two confidence levels, and the report says which.**
> `xs-security.json` is JSON, so those findings quote values that are literally in
> the file. The CDS model is read **lexically** — this product is offline and
> stdlib-only, so there is no CDS compiler here to ask. That is enough to find a
> service nobody protected and it is **not** enough to prove a service *is*
> protected, so the CDS checks only ever report what they positively found, and
> `CAPX-COV-001` lists every construct the parser could not resolve. If it could not
> read something, it says so rather than passing over it.

Annotations applied from a separate file (`annotate CatalogService with …`, the
usual CAP layout) are resolved to their target, so keeping restrictions in
`annotations.cds` works as expected.

### Which checks this makes possible

| Input | Checks |
|---|---|
| `xs-security.json` | `CAPX-GRAPH-001` (broken chain), `CAPX-SCOPE-001`, `CAPX-AUTH-001`, `CAPX-ATTR-001`, `CAPX-TOK-001`, `CAPX-URI-001`, `CAPX-CRED-001`, `CAPX-TEN-001` |
| `srv/**/*.cds`, `db/**/*.cds` | `CAPX-CDS-001` (unprotected service), `CAPX-CDS-002` (privilege with no audience) |
| both together | `CAPX-CDS-003` (model enforces a role no descriptor grants) |
| both **plus** `btp_role_collections.json` | `CAPX-GRAPH-002` (who holds the scopes), `CAPX-GRAPH-003` (undeliverable role template) |

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
