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

The scanner reads **128** logical sources. All of them now have a procedure: the
sections up to *SAP Cloud ALM* cover what a first scan needs, and
[*The remaining sources*](#the-remaining-sources) below covers the rest.

[**`EXPORT_SOURCES.md`**](EXPORT_SOURCES.md) lists all 128 — the filenames the
loader accepts, which checks each one feeds, and whether a procedure exists. It is
generated from the code, so a source cannot be added to the scanner without
appearing there, and it will show up as undocumented until somebody writes the
procedure.

Not every procedure is equally attested, and the ones that are not say so. A route
marked *not verified for this guide* is the one the scanner's own module was
written against, recorded so you have somewhere to start rather than nowhere —
check it before you build a job around it. Nothing is guessed: a wrong transaction
code in an export guide costs you an afternoon.

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

### Payment runs (`payment_runs.csv`, `reguh.csv`)
**Table:** `REGUH` — the payment program's settlement data, one row per payee per
run, carrying **the bank account the payment actually went to**. **Route:** `SE16`
on `REGUH` for the same window as the change documents, every paying company code
in scope. *The field list below is corroborated from this product's own module and
the payment-program data model rather than verified against SAP's published data
dictionary — confirm the column names in `SE11` before you script the extract.*

```
Required: LIFNR or KUNNR or EMPFG (payee), ZBNKN (payee bank account),
          ZALDT or LAUFD (payment / run date)
Strongly recommended: XVORL (proposal flag), LAUFI (run id), ZBUKR (company code),
          VBLNR (payment document), RWBTR + WAERS (amount and currency)
```

**Export `XVORL` and do not filter on it yourself.** It is the proposal flag: a
proposal run is what the payment program *intends* to pay and can still be edited
or deleted before the run proper. The scanner drops proposal rows, so counting one
as a payment would report money that never moved — but a row with **no** proposal
column at all is kept, because the absence of the flag is not evidence that the
row is a proposal.

**Match the window to `change_documents.csv`.** This export exists for one
correlation: `MDC-PAY-001` matches `VALUE_NEW` on a bank-account field in CDPOS
against `ZBNKN` here, and reports where a payment left into an account that had
just been changed. The match is on the account number itself, not on "a payment to
that partner around the same time" — which is why the two exports have to cover
the same period or the correlation has nothing to join. Thirty days is the default
window; `payment_correlation_days` changes it.

If you supply the change documents and not this file, the scanner does not go
quiet about it: `MDC-PAY-002` records that bank changes were found and the one
test that separates a routine update from a diversion was not run.

> **This file contains payment data.** Bank accounts and amounts are masked to
> the last four characters in every finding, but the CSV itself is not — handle
> and retain it as the payment record it is, alongside `vendor_bank.csv`.

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
**Not a system export.** The built-in catalogue is swept systematically through
2025-08, with later notes added individually; this OPTIONAL file extends or
corrects it. Source: SAP ONE Support Launchpad → My Security Notes (S-user
required), filtered to HotNews / High. Any note newer than the sweep, or any
correction to a built-in entry, belongs here:

```json
[{"note": "3812004", "cve": "CVE-2026-51230", "cvss": 9.8, "priority": "HotNews",
  "component": "NetWeaver AS ABAP", "released": "2026-09",
  "exploited": false, "applies_to": "abap",
  "title": "…"}]
```

> **You may not need an S-user for the identifying fields.** SAP is a CVE
> Numbering Authority, so its advisories reach the NVD feed directly with
> `sourceIdentifier: cna@sap.com` and a reference to `me.sap.com/notes/<note>` —
> which is SAP itself binding the note number to the CVE, publicly. That covers
> `note`, `cve`, `cvss`, `component`, `released` and `title`. The Launchpad is
> genuinely required for the rest: note text, affected support-package levels and
> correction instructions.
>
> Note **3747367 / CVE-2026-44747** (NetWeaver AS ABAP kernel, CVSS 9.9) is the
> worked example and is now **built in** — added from the SAP CNA record, not
> from the Launchpad. It also arrived here dated Feb 2026 in an operator
> reference; SAP published it on **14 July 2026**. Prefer the CNA record over a
> summary when the two disagree about a date.

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
| `srv/**/*.cds`, `db/**/*.cds` | `CAPX-CDS-001` (unprotected service), `CAPX-CDS-002` (privilege with no audience), `CAPX-CDS-004` (restricted entity reachable by `$expand`), `CAPX-CDS-005` (personal element carried into a projection) |
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
| `GLOBAL`, `SAP_KERNEL`, `COMP_LEVEL`, `TRANSPORT_TOOL`, `TDDAT`, `ABAP_SACF_INFO`, `USER_PASSWD_HASH_USAGE` | No logical source consumes them yet. `ABAP_UCON_HTTP_WHITE_LIST` left this list when `ucon_http_allowlist` was added — it now translates. |

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

### CSA compliance results (`csa_findings.csv`) — the other kind of CSA export

Everything above concerns a **configuration-store** export: rows that are the
settings themselves, which the store importer turns into inputs this product's own
checks read. Some tenants can only produce the **results** instead — one row per
policy per system, saying whether SAP's own check passed.

Supply those as `csa_findings.csv`. Also accepted: `csa_verdicts.csv`,
`csa_compliance.csv`

| Column (any of) | Meaning |
|---|---|
| `POLICY` · `POLICY_ID` · `CHECK_ID` · `RULE_ID` | SAP's policy identifier, e.g. `2AAUDIT` |
| `SYSTEM` · `SID` · `TARGET_SYSTEM` · `MANAGED_OBJECT` | the system assessed |
| `STATUS` · `RESULT` · `COMPLIANCE` · `RATING` | the verdict |
| `CHECK_ITEM` · `DESCRIPTION` · `TITLE` | the item, where the export names one |
| `DATE` · `COLLECTED_ON` · `LAST_RUN` | when it was collected |

```
POLICY,SYSTEM,STATUS
2AAUDIT,PRD,NON-COMPLIANT
1ACHANGE,PRD,NOT ASSESSED
```

> **These become SAP's findings, not this product's.** They were produced by SAP's
> rules against SAP's own collection, and a verdict carries no parameter value,
> user or table row — so there is nothing here to re-check and nothing is claimed
> to have been. `CSA-SAP-001` reports them, labelled throughout, at **SAP's own
> priority tier** rather than a severity this product invented. Policy identifiers
> resolve against the SAP Security Baseline catalogue vendored from SAP's published
> policies, so each line carries SAP's requirement and tier.

**`NOT ASSESSED` is not a pass.** Statuses meaning the policy could not be
evaluated are reported separately by `CSA-SAP-002` and mark coverage as degraded:
a system compliant on everything CSA *could* evaluate is not a system compliant.
Export those rows rather than filtering to failures.

**Supply the store export as well if your tenant produces one.** The two are
complementary, not alternatives: the store export yields the value, this yields
the verdict. Where both are present you will see two views of one problem rather
than two problems.

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

---

# The remaining sources

The sections above cover what a first scan needs. What follows covers the rest of
the catalogue, so that every source the scanner reads has somewhere to send you.

**Two things to know before you use them.**

**Where the route came from.** Each procedure names the transaction, table or API
the scanner's own module was written against — that mapping lives in the module
header and is the reason the column names below are what they are. A route marked
*"not verified for this guide — confirm before you build a job around it"* is one
that has not been checked against a primary SAP source. It is written down rather
than left out so you have somewhere to start, and marked so you do not mistake it
for a checked fact. Nothing here is invented: where neither the module nor a
primary source names a route, the entry says so plainly.

**Some of these are not exports at all.** A dozen sources are *declarative*: there
is no SAP transaction behind them because the thing being audited is a decision
your organisation made, not a setting SAP stores. Whether personal data is masked
in the QA system, which log types you retain and for how long, whether an incident
runbook exists — SAP does not know any of that. Those files you write, once, and
keep beside the export. Each one is marked **declarative** and gives the exact key
names the check reads. Writing one is not busywork: it converts an assumption
nobody has stated into a control somebody can review, and the scanner will tell
you when it drifts.

Omitting any of these is always safe. The checks behind them do not run, and the
coverage manifest counts the source as *not supplied* rather than passing it off
as clean.

---

## ABAP authorization detail (the `rolegov`, `iam` and `users` modules)

### Authorization object values per user (`auth_objects.csv`)
**Source:** `SUIM` → *User* → *Users by Complex Selection Criteria* → *By
Authorization Values*, or the same data from your own role-explosion job. One row
per user × authorization object × field × value. *The node path shifts slightly
between releases; the report is the one that selects users by authorization
object, field and value.*

| Column (any of) | Meaning |
|---|---|
| `UNAME` · `BNAME` · `USERNAME` | User ID |
| `OBJECT` · `AUTH_OBJECT` | Authorization object (`S_DEVELOP`, `S_TABU_DIS`, …) |
| `FIELD` · `AUTH_FIELD` | Field within the object (`ACTVT`, `DEVCLASS`, …) |
| `VALUE` · `AUTH_VALUE` | Value or range held |
| `ACTIVITY` · `ACTVT` | Activity, where you export it as its own column |
| `TCODE` · `TRANSACTION` | Transaction, where the row is transaction-scoped |

This is the *effective* authorization — after role composition, not the role
definition. `role_auth_values.csv` (AGR_1251) is the role side and answers a
different question; supplying both lets the SoD analysis work at permission level.

An export limited to a handful of objects is fine and common. It bounds what the
checks can say, and the coverage manifest records the source as supplied, so state
the filter in your own notes — the scanner cannot see that `S_TABU_DIS` was left
out of the extract rather than held by nobody.

### User groups (`user_groups.csv`)
**Source:** `SU10` or `SUIM`, or a download of `USR02` — the group for the
authorization check is `USR02-CLASS`.

| Column (any of) | Meaning |
|---|---|
| `BNAME` · `UNAME` · `USERNAME` | User ID |
| `CLASS` · `USGRP` · `USER_GROUP` | User group for authorization check |
| `UFLAG` · `LOCK_STATUS` | Lock status, if you have it |

Segmentation is the point: `S_USER_GRP` is what stops a user administrator in one
group from resetting passwords in another. A system where every user sits in the
same group — or in none — has a user-administration boundary that exists on the
org chart and nowhere else.

### Generated role profiles (`role_profiles.csv`, `agr_1016.csv`)
**Source:** `SE16` on `AGR_1016`.

Also accepted: `agr_1016.csv`

| Column (any of) | Meaning |
|---|---|
| `AGR_NAME` · `ROLE` · `ROLE_NAME` | Role |
| `PROFILE` · `PROFILE_NAME` · `GENERATED_PROFILE` · `PROFN` | Generated authorization profile |
| `GENERATED` · `STATUS` · `GEN_STATUS` | Generation status, if your extract carries it |

**Export every role, including the ones with no profile.** A blank profile is the
finding: the role was maintained in PFCG and never generated, so it grants nothing
at runtime while continuing to appear in every access review as though it did. A
row that is absent cannot be told apart from a role that was filtered out, so an
extract of only the roles that *have* profiles reports nothing at all.

### SU24 authorization proposals (`su24_proposals.csv`, `usobt_c.csv`)
**Source:** `SU24`, or `SE16` on `USOBX_C` (check indicators) joined to `USOBT_C`
(proposed values). The check indicator is `USOBX_C-OKFLAG`.

Also accepted: `usobt_c.csv`, `su24.csv`

| Column (any of) | Meaning |
|---|---|
| `TCODE` · `TRANSACTION` · `TCD` · `NAME` | Transaction |
| `CHECK_INDICATOR` · `CHECK_IND` · `OKFLAG` · `MODE` | Check indicator (`CM` / `C` / `N` / `U`) |
| `PROPOSAL` · `MAINTAINED` | Whether a value proposal exists |

`U` — *unmaintained* — is what this is for. PFCG builds a role from the proposals,
so a transaction whose proposal was never maintained produces a role that either
under-authorises (and gets fixed by someone adding a manual full authorization) or
was never checked at all. After an upgrade, run `SU25` step 2 before you export,
or the extract shows the pre-upgrade picture.

---

## Change control and custom code (the `codetrans` module)

### System change option (`system_change.csv`, `se06.csv`)
**Source:** `SE06` → *System Change Option* (also reachable from `SE03`). Export
the global setting and the per-software-component and per-namespace rows.

**SAP's own vocabulary for this, and the values to expect.** The Focused Run
baseline policy reads it from a configuration store named `GLOBAL`, as
`NAME = 'GLOBAL_SETTING'` with `VALUE = 'NOT MODIFIABLE'` for a system that is
locked. Those are the names and the literal value SAP uses, so an export written
as `NAME,VALUE` rows in that shape needs no translation — the loader accepts
`NAME` and `VALUE` directly. Anything else your extract can produce is accepted
under the aliases below.

Also accepted: `se06.csv`, `system_change_option.csv`

| Column (any of) | Meaning |
|---|---|
| `SCOPE` · `OBJECT` · `NAMESPACE` · `COMPONENT` · `NAME` | What the row governs — global, a software component, or a namespace |
| `SETTING` · `MODIFIABLE` · `VALUE` · `SETTING_VALUE` · `CHANGEABILITY` · `STATUS` · `EDTFLAG` | Modifiable / not modifiable |

This is the second and **independent** lock beside the SCC4 client setting, which
is why it is worth its own export: a client can be closed while the system is
globally modifiable, and repository objects can then be changed in production
regardless of what SCC4 says. The underlying ABAP table is not named here and
does not need to be: the export comes from the SE06 screen, and the field
vocabulary above is SAP's own.

### Open transport requests (`transports.csv`, `se09.csv`)
**Source:** `SE09` / `SE10` — the Transport Organizer. Table route: `E070`
(header) joined to `E07T` (description).

| Column (any of) | Meaning |
|---|---|
| `TRKORR` · `TRANSPORT` · `REQUEST` | Request number |
| `TRSTATUS` · `STATUS` | Release status, exported as-is |
| `TRFUNCTION` · `TYPE` | Request type |
| `AS4USER` · `OWNER` | Owner |
| `AS4TEXT` · `DESCRIPTION` | Short text |

Export `TRSTATUS` unchanged rather than translating it — the scanner reads SAP's
own codes, and a translated column ("open", "done") loses the distinction between
a request that is merely modifiable and one that is protected against release.

Taken **in production**. An open request in a development system is a working
day; an open request in production is a change that entered outside the transport
path, and the whole point of the check is which system it was found in.

### Transport routes (`transport_routes.csv`, `tms_routes.csv`)
**Source:** `STMS` → *Overview* → *Transport Routes*.

| Column (any of) | Meaning |
|---|---|
| `TYPE` · `ROUTE_TYPE` | Consolidation or delivery route |
| `SOURCE` · `FROM_SYSTEM` · `SOURCE_SID` | Source system |
| `TARGET` · `TO_SYSTEM` · `TARGET_SID` | Target system |

Export the whole domain, not the routes touching one system. The finding is about
the *shape* of the landscape — a delivery route that reaches production without
passing through QA is only visible when both legs are in the same file.

### Transport import history (`transport_history.csv`, `stms_log.csv`)
**Source:** `STMS` → *Import Overview* → select the system → *Import History*.

Also accepted: `stms_log.csv`, `import_history.csv`

| Column (any of) | Meaning |
|---|---|
| `TRKORR` · `TRANSPORT` · `REQUEST` | Request number |
| `RELEASED_BY` · `RELEASER` · `AS4USER` | Who released it |
| `IMPORTED_BY` · `IMPORTER` · `IMPORT_USER` | Who imported it |
| `APPROVAL` · `APPROVED_BY` · `APPROVER` | Who approved it |
| `IMPORT_DATE` · `IMPORT_TIME` · `TRDATE` | When it was imported |
| `TARGET` · `TARGET_SYSTEM` | Where it went |
| `SOURCE` · `SOURCE_SYSTEM` · `ORIGIN` | Where it came from |

**The approval column will usually not be in the STMS export.** STMS records who
released and who imported; approval lives in ChaRM, ServiceNow or whatever your
change process runs on. Join it in if you can — a transport released and imported
by the same person is the four-eyes finding, and without the approval column the
check can only say that no third party appears, not that none existed.

### SAP standard modifications (`sap_modifications.csv`, `se95.csv`)
**Source:** `SE95` — the Modification Browser.

Also accepted: `se95.csv`, `modifications.csv`

| Column (any of) | Meaning |
|---|---|
| `OBJECT` · `OBJECT_NAME` · `PROGRAM` | Modified SAP object |
| `TYPE` · `MOD_TYPE` | Modification type |
| `REGISTERED` · `SAP_NOTE` · `CORRECTION` | Registration key or the note it implements |
| `MOD_DATE` · `DATE` · `CHANGED_ON` | When |
| `MODIFIED_BY` · `CHANGED_BY` · `USER` | By whom |
| `REASON` · `DESCRIPTION` | Why |

A modification made under a note correction is routine. One with no note and no
reason is both a security question and an upgrade liability, and the two are the
same finding because the mechanism is the same: SAP ships a fix, the modification
adjustment reverses it, and nobody notices until the next scan.

### Development authorization in production (`dev_access_prod.csv`)
**Source:** the same extract as `auth_objects.csv`, **taken in the production
system**, filtered to the development authorizations — `S_DEVELOP`, and the users
who can reach `SE38`, `SE80`, `SE37`, `SE24`.

| Column (any of) | Meaning |
|---|---|
| `USERNAME` · `UNAME` · `BNAME` | User ID |
| `TCODE` · `TRANSACTION` | Transaction |
| `AUTH_OBJECT` · `OBJECT` | Authorization object |
| `FIELD` · `AUTH_FIELD` | Field |
| `VALUE` · `AUTH_VALUE` · `ACTIVITY` · `ACTVT` | Value held |

Supplying `auth_objects.csv` from production alone is enough — this file exists so
you can supply the narrower extract when a full authorization dump from production
is not something your change process will allow.

### ATC / Code Inspector results (`custom_code_scan.csv`, `atc_results.csv`)
**Source:** `ATC` — run the security variant and export the result list. Code
Inspector (`SCI`) output is accepted in the same shape.

Also accepted: `atc_results.csv`, `code_inspector.csv`

| Column (any of) | Meaning |
|---|---|
| `OBJECT_NAME` · `OBJECT` · `PROGRAM` · `REPORT` · `INCLUDE` · `CLASS` | The object |
| `OBJECT_TYPE` · `TYPE` · `OBJTYPE` | Object type |
| `FINDING_TYPE` · `CHECK` · `CHECK_TITLE` · `CHECK_ID` · `MESSAGE_ID` · `MSG_ID` | Which check fired |
| `DESCRIPTION` · `MESSAGE` · `MESSAGE_TEXT` · `TEXT` | The message |
| `LINE` · `LINE_NUMBER` · `LINE_NO` · `ROW` | Line |
| `SEVERITY` · `PRIORITY` | Priority as ATC reported it |
| `STATUS` · `STATE` · `EXEMPTION` | Exemption / suppression state |

**You may not need this file.** MonitorRisk carries its own ABAP scanner — point
`--code-src` at a source export and it applies its own rules directly. This source
is for importing an ATC run you already have, so that findings your team has
already triaged appear beside the rest rather than being re-litigated.

Export **exemptions along with findings**. An ATC run with every finding exempted
and an ATC run with no findings look identical once the exemptions are dropped,
and they are not the same system.

---

## Cryptography and transport security (the `crypto` module)

### ICM TLS configuration (`tls_config.csv`, `icm_ssl.csv`)
**Source:** `SMICM` → *Goto* → *Services*, which lists each active port with its
protocol. Cipher configuration comes from the profile parameters (`RZ11`), which
you may already be supplying as `security_params.csv`.

| Column (any of) | Meaning |
|---|---|
| `PORT` · `SERVICE_PORT` | Port |
| `NAME` · `SERVICE` · `LISTENER` | Service name |
| `PROTOCOL` · `SSL_PROTOCOL` · `TLS_VERSION` | Protocol / version offered |
| `CIPHERS` · `CIPHER_SUITE` · `SSL_CIPHERS` | Cipher suite string |
| `HSTS` · `STRICT_TRANSPORT` | HSTS, where configured |

Export the services as configured, including the ones you believe are internal.
"Internal" is a statement about the network, and the check is about the endpoint;
where both are true the finding costs you one line of justification, and where
only one is true it is the finding.

### Certificate inventory (`certificate_inventory.csv`, `strust_certs.csv`)
**Source:** `STRUST` — every PSE's own certificate and its trust list. `SMICM`
shows the ones the web dispatcher presents.

| Column (any of) | Meaning |
|---|---|
| `CERT_NAME` · `ALIAS` · `SUBJECT` | Certificate subject or alias |
| `VALID_TO` · `EXPIRY` · `NOT_AFTER` | Expiry date |
| `KEY_SIZE` · `KEY_LENGTH` · `BITS` | Key length |
| `ALGORITHM` · `SIGNATURE_ALG` | Signature algorithm |
| `ISSUER` · `ISSUED_BY` | Issuer |
| `PURPOSE` · `USAGE` · `PSE` | Which PSE / what it is for |

Include expired certificates rather than filtering them out. An expired
certificate still sitting in a trust list is a different finding from one that was
removed, and only the export can tell the two apart.

### PSE inventory (`pse_inventory.csv`, `strust_pse.csv`)
**Source:** `STRUST` — the PSE list in the left-hand tree.

| Column (any of) | Meaning |
|---|---|
| `PSE_NAME` · `NAME` · `PSE_FILE` | PSE (`SAPSSLS.pse`, `SAPSSLA.pse`, …) |
| `TYPE` · `PSE_TYPE` | PSE type |
| `STATUS` · `STATE` | Status as STRUST reports it |
| `CERT_EXPIRY` · `VALID_TO` | Expiry of the PSE's own certificate |

### CommonCryptoLib version (`crypto_library.csv`, `commoncryptolib.csv`)
**Source:** the version your kernel reports. *The exact invocation differs by
kernel release and is not verified for this guide — use the one your Basis team
documents, and note which you used.*

| Column (any of) | Meaning |
|---|---|
| `LIBRARY` · `NAME` · `COMPONENT` | Library name |
| `VERSION` · `RELEASE` | Version |
| `PATCH_LEVEL` · `PATCH` | Patch level |
| `PATH` · `LOCATION` | Where it is loaded from |

One row is enough. The path matters more than it looks: a system running a
CommonCryptoLib from outside the kernel directory is patched on a schedule nobody
is tracking.

### Kernel release and patch level (`sap_kernel.csv`)
**Source:** the kernel's own version report — `disp+work -v` at the OS, or
*System* → *Status* → *Other kernel information* in the SAP GUI. Two rows are
enough. *The exact invocation differs by kernel release and is not verified for
this guide; use the one your Basis team documents.*

Also accepted: `kernel_version.csv`, `disp_work.csv`

| Column (any of) | Meaning |
|---|---|
| `NAME` · `PARAMETER` | `KERN_REL` and `KERN_PATCHLEVEL` |
| `VALUE` | the release (`753_REL`, `793_REL`) and the patch level (`1518`) |

```
NAME,VALUE
KERN_REL,793_REL
KERN_PATCHLEVEL,0410
```

**The smallest file in this guide, and one of the most consequential.** SAP's own
note policies consult the kernel in 602 check items, and 62 security notes cannot
be answered from any other export — including kernel notes at CVSS 9.9. This
source was once measured as unlocking a single note and left unbuilt on that
basis; the measurement was taken against a 43-note catalogue rather than against
SAP's published record, and the denominator was wrong.

Take it from the **same instance** the rest of the export came from. A landscape
running several application servers can carry different kernel patch levels on
each, and a finding attributed to the wrong host sends somebody to patch a
machine that was already current.

### HANA revision (`hana_version.csv`)
**Source:** the database's own version, from `M_DATABASE`:

```sql
SELECT VERSION FROM M_DATABASE;
```

Also accepted: `hdb_version.csv`, `m_database.csv`

| Column (any of) | Meaning |
|---|---|
| `VERSION` | the full revision string, e.g. `2.00.073.00.1745...` |
| `NAME` + `VALUE` | the SAP config-store shape: `NAME` is `VERSION` |

```
NAME,VALUE
VERSION,2.00.073.00.1745910275
```

**Export the WHOLE string, not the SPS.** SAP publishes note fixes at revision
granularity — note 2424173 is fixed in `1.00.122.07`, not "SPS12" — so a value
truncated to `2.00.073` cannot be compared against a fix at `2.00.073.00.17`, and
the check reports the note as undetermined rather than guessing.

**The counterpart of `sap_kernel.csv`, for the database half.** SAP's own note
policies read the HANA revision in 30 check items, and 18 notes could be answered
from no other export. Supplying it lets `HOTNEWS-013` state a determination — *"HANA
is at revision 1.00.122.00; the fix is in 1.00.122.07"* — instead of listing the
note as unassessed.

Take it from the **same database** the rest of the export describes. A scale-out
or MDC landscape has one revision per system, and a finding attributed to the
wrong tenant sends somebody to patch a database that was already current.

### SNC parameters (`snc_config.csv`)
**Source:** `RZ11` — the `snc/*` profile parameters. If you are already supplying
`security_params.csv` you can skip this file; the check falls back to it.

| Column (any of) | Meaning |
|---|---|
| `PARAMETER` · `NAME` | Parameter name (`snc/enable`, `snc/data_protection/min`, …) |
| `VALUE` · `PARAM_VALUE` | Current value |

Export the **current** value, not the profile value. A parameter changed
dynamically and never written back to the profile is correct today and wrong after
the next restart, and that gap is worth seeing.

---

## Web Dispatcher (the `webdisp` module)

**Why this is a separate file from `security_params.csv`.** The Web Dispatcher is a
separate instance with its own profile, and it is the internet-facing one. SAP draws
the same line: policy `2ADISCL` reads the ABAP instance's `ABAP_INSTANCE_PAHI` store
while `2ODISCL` reads the dispatcher's `Parameters` store, because they describe two
components. Merging them here would produce one finding for two instances with no way
to tell which was exposed.

### Web Dispatcher profile (`webdisp_params.csv`)
**Source:** the Web Dispatcher instance profile — the `sapwebdisp.pfl` file, or
`Profile Parameters` in the dispatcher's own admin UI. Export as a two-column
`NAME,VALUE` list.

Also accepted: `webdisp_profile.csv`, `web_dispatcher_params.csv`, `sapwebdisp_pfl.csv`

| Column (any of) | Meaning |
|---|---|
| `NAME` · `PARAMETER` · `PARAMETER_NAME` · `PARAM` · `PNAME` | The profile parameter |
| `VALUE` · `PARAMETER_VALUE` · `PVALUE` · `CURRENT_VALUE` | Its value, whole |

⚠️ **Quote any value containing a comma.** Web Dispatcher values routinely do —
`PROT=HTTP,PORT=8000,TIMEOUT=60` is ONE value, not three. An unquoted line produces
more fields than headers, and a naive reader keeps only the part before the first
comma. That is not a cosmetic problem: `icm/HTTP/admin_0,PREFIX=/x,CLIENTHOST=10.0.0.1`
would lose the `CLIENTHOST` restriction and the scan would report a correctly
restricted admin handler as exposed. This scanner rejoins the overflow so the
unquoted form still produces the right verdict, but quoting it is what makes the file
correct CSV for everything else that reads it:

```csv
NAME,VALUE
icm/server_port_0,"PROT=HTTPS,PORT=8443,TIMEOUT=60"
icm/HTTP/admin_0,"PREFIX=/sap/admin,CLIENTHOST=10.0.0.1,PORT=8443"
is/HTTP/show_server_header,FALSE
```

**What is checked, and by whose rules.** Fourteen checks transcribed from SAP's own
Apache-2.0 baseline policies for the `WEBDISP_ALL` stack — `2ODISCL` (information
disclosure) and `2ONETENC` (network encryption), v2.4. Every finding carries the SAP
check id and the verbatim predicate it came from, so a disagreement is with SAP's
rule rather than ours. Two of SAP's check items are deliberately not implemented and
`data/webdisp_baseline.json` records why.

**An unset parameter is not a finding.** A profile lists what was SET; an unset one
takes SAP's default, which no export reveals. The single exception is the HTTPS
listener check, because "no `icm/server_port_*` serves HTTPS anywhere in this profile"
is a statement the profile does make.

**Under RISE, this is usually SAP's to supply.** SAP operates the Web Dispatcher in a
RISE tenant, so the profile comes through a service request rather than an export you
can run — the coverage manifest classifies the source `ticket` for that reason. A
customer running their own dispatcher in front of the tenant owns it outright, and
for them every finding here is directly actionable.

---

## Unified Connectivity (the `ucon` module)

**Why this section matters more in RISE than anywhere else.** The gateway ACL files
`secinfo` and `reginfo` are filesystem artifacts on the application server, and a
RISE customer contractually never gets OS access — `RISE_SECURITY_MODEL.md` §3
lists them as structurally unavailable. UCON is the ABAP-layer equivalent, the
Roles & Responsibilities put business-client UCON configuration with the customer,
and it is reached from a transaction they already have. Without it, a RISE scan can
say nothing at all about which function modules are callable from outside.

`TRUST-007` already tells you to start the UCON RFC scenario in the Logging phase.
This is the export of what that recording produced.

### UCON RFC scenario state (`ucon_rfc_state.csv`)
**Source:** `UCONCOCKPIT` — UCON RFC scenario, function-module list. Export the list
view.

Also accepted: `ucon_rfc.csv`, `uconcockpit.csv`, `ucon_phase_tool.csv`

| Column (any of) | Meaning |
|---|---|
| `FUNCNAME` · `FUNCTION` · `FUNCTION_MODULE` · `RFM` · `FMODULE` | The remote-enabled function module |
| `AREA` · `FUNCGROUP` · `FUNCTION_GROUP` · `GROUP` | Its function group |
| `PHASE` · `UCON_PHASE` · `STATUS` | Logging / Evaluation / Final. Only *Final* enforces |
| `CA` · `DEFAULT_CA` · `IN_DEFAULT_CA` · `ASSEMBLY` · `COMM_ASSEMBLY` | Whether it is in the default Communication Assembly, i.e. externally callable |
| `CALLED` · `CALL_COUNT` · `COUNT` · `EXTERNAL_CALLS` · `CALLS` | External calls recorded during the logging window |
| `LAST_CALL` · `LASTCALL` · `LAST_CALLED` · `LAST_CALL_DATE` | When it was last called from outside |

**The call-count column is the valuable one.** With it, `UCON-002` reports the
function modules that are externally callable and were never actually called —
remote attack surface that costs nothing to remove. Without it the check stays
silent rather than assuming zero, because an absent column is not evidence of
silence.

**Export a window long enough to be honest.** A function used only at period end
looks unused in a two-week recording. The finding says so, but the fix is a longer
window, not a shorter conclusion.

⚠️ **Column names are the spellings we accept, not a claim about SAP's schema.**
UCONCOCKPIT's list view varies by release and language, and no SAP-primary source
consulted for this guide publishes a table name for the RFC scenario — so no table
name is asserted here. Match your export's headers against the aliases above and
rename if none fit.

### UCON HTTP allowlist (`ucon_http_allowlist.csv`)
**Source:** `UCONCOCKPIT` — HTTP allowlist. The underlying table is
`HTTP_WHITELIST`, delivered with **SAP Note 2573569**.

Also accepted: `http_whitelist.csv`, `abap_ucon_http_white_list.csv`

Any column layout is accepted — the check reads whether the allowlist has entries
at all, because an empty allowlist leaves every activated ICF service reachable by
anything that can reach the HTTP port. This is the logical source for the
`ABAP_UCON_HTTP_WHITE_LIST` configuration store that SAP's own baseline policies
name and that nothing consumed until now.

---

## System trust and routing (the `systrust` module)

### Trusted-RFC inbound relationships (`rfc_trust.csv`, `rfcsysacl.csv`)
**Source:** `SMT1` — *Trusted Systems*, or `SE16` on `RFCSYSACL`.

Also accepted: `rfcsysacl.csv`, `trusted_systems.csv`

| Column (any of) | Meaning |
|---|---|
| `RFCTRUSTSY` · `RFCSYSID` · `TRUSTED_SID` · `TRUSTED_SYSTEM` · `RFC_TRUSTSY` · `SID` | The system that is trusted to log on here |

Take it **in the system that is being trusted into** — the direction is the whole
finding. A production system that trusts a development system means any dialog
user in development can arrive in production as themselves; the reverse is
ordinary. Set `local_system_sid` in the scan configuration so the system's own SID
is not reported as trusting itself.

### SAProuter route permission table (`saprouttab.csv`)
**Source:** the `saprouttab` file on the SAProuter host. Supply it as-is — one
route-permission line per row — or split it into columns if that is easier.

Also accepted: `route_permission.csv`

| Column (any of) | Meaning |
|---|---|
| `LINE` · `RULE` · `ENTRY` | The whole route-permission line, unsplit |
| `ACTION` · `TYPE` | `P` / `S` / `D` |
| `SOURCE` · `SOURCE_HOST` · `SRC` · `FROM` | Source host |
| `DEST` · `DEST_HOST` · `TARGET` · `TO` | Destination host |
| `PORT` · `DEST_PORT` · `SERVICE` | Destination port |

The unsplit form is preferred, because a wildcard is easier to see in the original
line than in a column somebody has already interpreted. Include comment lines if
your extract carries them; they are ignored, and leaving them in keeps the line
numbers matching the file on the host.

---

## The ABAP integration surface (the `intglayer` module)

### IDoc ports (`idoc_ports.csv`, `we21.csv`)
**Source:** `WE21` — port definitions.

| Column (any of) | Meaning |
|---|---|
| `PORT` · `PORT_NAME` · `PORTNAME` | Port name |
| `PORT_TYPE` · `TYPE` · `PORTTYPE` | File, tRFC, XML, ABAP-PI, … |
| `DIRECTION` · `DIR` | Inbound / outbound |
| `HOST` · `RFCHOST` | Target host, for RFC ports |
| `FILE_PATH` · `PATH` · `DIRECTORY` | Directory, for file ports |
| `TLS` · `SSL` · `HTTPS` | Whether transport is encrypted |
| `SNC` · `SNC_MODE` | SNC status |

A file port writing to a directory the application server shares with anything
else is an IDoc anyone on that host can read or forge; an RFC port without SNC is
business documents on the wire. Both are only visible if the path and the SNC
column survive the export, so keep them.

### IDoc partner profiles (`idoc_partners.csv`, `we20.csv`)
**Source:** `WE20` — partner profiles.

| Column (any of) | Meaning |
|---|---|
| `PARTNER` · `PARTNER_NO` · `PARTNR` | Partner number |
| `PARTNER_TYPE` · `PARTYP` · `TYPE` | Partner type (`LS`, `KU`, `LI`, …) |
| `MESSAGE_TYPE` · `MESTYP` · `IDOC_TYPE` | Message type |
| `DIRECTION` · `DIRECT` | Inbound / outbound |
| `PORT` · `RCVPOR` | Port used |

Export inbound and outbound together. The interesting case is an inbound profile
for a message type that posts documents, bound to a partner nobody recognises —
and you can only see that the partner is unrecognised when the whole list is in
one place.

### Web service endpoints (`ws_endpoints.csv`, `soamanager.csv`)
**Source:** `SOAMANAGER` → *Web Service Configuration*. Export the service
definitions with their bindings.

| Column (any of) | Meaning |
|---|---|
| `SERVICE_NAME` · `NAME` · `ENDPOINT` | Service |
| `BINDING` · `BINDING_NAME` | Binding |
| `STATUS` · `ACTIVE` | Whether the binding is active |
| `AUTHENTICATION` · `AUTH_TYPE` | Authentication method configured |
| `TRANSPORT_BINDING` · `PROTOCOL` | Transport (HTTP / HTTPS) |

The check is looking for two things that read very differently on screen and
identically to an attacker: a binding that accepts basic authentication over
plain HTTP, and an active binding in front of a service that wraps a BAPI or
remote-enabled function module. Export inactive bindings too — an inactive
binding is a control, and the scan should be able to see that you applied it.

### SAP-delivered external OS commands (`ext_os_commands_sap.csv`, `sxpgcotabe.csv`)
**Source:** the SAP-delivered external command set, the counterpart of the
customer commands documented above under *External OS commands*. *The table is
recorded in the scanner's module as `SXPGCOTABE`, and neither that nor the
maintenance route is verified for this guide — export from your Basis team's own
documented route and say which.*

```
Required: NAME (command name), OPSYSTEM, OPCOMMAND
Optional: PARAMETERS, ADDITIONAL_PARAMETERS_ALLOWED
```

Optional in every sense: supply it only if you want the SAP-delivered commands
audited alongside your own. The customer command list matters more, because that
is where a command with `ADDITIONAL_PARAMETERS_ALLOWED` set turns `SM49` execution
authorization into a shell.

---

## Fiori launchpad (the `fiori` module)

### Catalogs (`fiori_catalogs.csv`, `flpd_catalogs.csv`)
**Source:** `/UI2/FLPD_CUST` — the Launchpad Designer — or your launchpad content
export. One row per catalog × role assignment.

| Column (any of) | Meaning |
|---|---|
| `CATALOG_ID` · `CATALOG` · `ID` | Catalog |
| `ROLE` · `AGR_NAME` · `ASSIGNED_ROLE` | Role the catalog is assigned to |
| `SCOPE` · `ACCESS_TYPE` · `VISIBILITY` | Assignment scope, where you have it |

### Tiles (`fiori_tiles.csv`, `flpd_tiles.csv`)
**Source:** `/UI2/FLPD_CUST`, same export, tile level.

| Column (any of) | Meaning |
|---|---|
| `TILE_ID` · `APP_ID` · `ID` | Tile / application |
| `TITLE` · `APP_TITLE` · `DESCRIPTION` | Title |
| `CATALOG_ID` · `CATALOG` | Catalog it belongs to |
| `ROLE` · `AGR_NAME` | Role |
| `SEMANTIC_OBJECT` | Semantic object |
| `SERVICE_NAME` · `ODATA_SERVICE` · `SERVICE` · `TARGET_SERVICE` | OData service the tile calls |

Supply `odata_auth.csv` as well if you can. On their own the tiles say what is on
somebody's home page; joined to the OData authorizations they answer the question
worth asking, which is whether the role that shows the tile also authorises the
service behind it. A tile that launches and then fails is a nuisance. A service
authorised for a role that shows no tile is the finding — the app is hidden, not
protected, and any client that knows the URL reaches it.

### Spaces and pages (`fiori_spaces.json`)
**Source:** the launchpad *Manage Launchpad Spaces* and *Manage Launchpad Pages*
apps. *The export route is not verified for this guide* — SAP publishes no
machine-readable documentation repository for the ABAP front-end server's
launchpad, and the Work Zone documentation that does exist describes a different
product with a different content model.

If spaces and pages are not in use — many landscapes still run the classic
catalog-and-group model — omit this file. `fiori_catalogs.csv` and
`fiori_tiles.csv` answer the same access question for that model.

Also accepted: `spaces_pages.json`

```json
{"spaces": [
  {"spaceId": "ZSPACE_FIN", "name": "Finance",
   "roles": ["SAP_BR_AP_ACCOUNTANT"], "visibility": "role-based",
   "pages": [{"id": "ZPAGE_AP", "name": "Payables"}]}
]}
```

`roles` / `assignedRoles` is what the check reads. A space with an empty role list
is visible to everyone the launchpad serves, which is the spaces-and-pages version
of the catalog finding above.

### App launch statistics (`fiori_app_usage.csv`)
**Source:** your launchpad usage analytics. *No verified route is recorded for
this one, and it is the weakest entry in this guide.* The module was written
against a launch-count extract; where that comes from differs by release, by
whether the launchpad runs on the ABAP front-end server or on Work Zone, and by
whether usage collection was ever switched on at all — which in most landscapes
it was not.

**Skip it unless you already have the data.** Every other Fiori source answers a
question about configuration, which is always available; this one answers a
question about behaviour, which is only available if somebody turned on
collection months ago. If your team has a usage report, export it in the shape
below and note where it came from. If not, the check simply does not run, and
that costs you one finding about unused app assignments rather than anything
about the security of what IS used.

| Column (any of) | Meaning |
|---|---|
| `APP_ID` · `TILE_ID` · `ID` | Application |
| `TITLE` · `APP_TITLE` | Title |
| `LAUNCH_COUNT` · `USAGE_COUNT` · `LAUNCHES` | Times launched in the window |
| `LAST_LAUNCH` · `LAST_USED` | Last launch |
| `CATALOG` · `CATALOG_ID` | Catalog |

**Say what window it covers.** Zero launches over a quarter is an access grant
nobody needs; zero launches over a fortnight is a holiday. The scanner cannot see
the window, so record it beside the file — the finding it produces is only as good
as that number.

---

## S/4HANA business authorization (the `s4authz` module)

These five sources describe the S/4HANA authorization layer that sits above the
classic authorization objects: business roles, the restrictions that scope them,
the catalogs they carry, and the CDS views and OData services they ultimately
expose.

> **You may already have most of this, under other names.** In S/4HANA
> on-premise and RISE private edition the business role IS a PFCG role, so the
> assignment data is the same `AGR_USERS` extract this guide already documents as
> [`user_roles.csv`](#user-roles-user_rolescsv) — supply that and the assignment
> question is answered without producing anything new. What the files below add
> is the layer PFCG does not model as a role: the restriction fields, the catalog
> assignments, and the CDS and OData surface they reach. In the public cloud
> edition there is no PFCG and the *Maintain Business Roles* app is the source
> for all of them.
>
> Every route in this section is marked *not verified for this guide* for the
> same reason: SAP publishes no machine-readable documentation repository for the
> S/4HANA application layer the way it does for BTP and the Integration Suite, so
> these were written from the consuming module rather than checked against a
> primary source. The COLUMN NAMES are exact — they are extracted from the code —
> and it is only the extraction route that is unconfirmed.

### Business role assignments (`business_roles.csv`)
**Source:** `PFCG` in S/4HANA on-premise and RISE private edition, where business
roles are PFCG roles and the assignment is `AGR_USERS`; the *Maintain Business
Roles* app in the public cloud edition. *Not verified for this guide — and if you
are on-premise or private cloud, `user_roles.csv` already carries this.*

Also accepted: `business_role_users.csv`

| Column (any of) | Meaning |
|---|---|
| `USER` · `USER_ID` · `BNAME` · `USERNAME` | User |
| `BUSINESS_ROLE` · `ROLE` · `AGR_NAME` · `ROLE_ID` | Business role |

One row per assignment. The check looks for the business-role equivalent of
`SAP_ALL` — a single role that carries the whole application surface — and for how
many people hold it, so an extract limited to a department answers a smaller
question than it appears to.

### Business role restrictions (`business_role_restrictions.csv`)
**Source:** the restriction maintenance behind the business role — organisational
and value restrictions per restriction type. *Not verified for this guide.*

| Column (any of) | Meaning |
|---|---|
| `ROLE` · `BUSINESS_ROLE` · `ROLE_ID` | Business role |
| `RESTRICTION_TYPE` · `TYPE` | Restriction type |
| `FIELD` · `RESTRICTION` | Restricted field |
| `VALUE` · `RESTRICTION_VALUE` · `ACCESS` · `SETTING` | Value, or the unrestricted marker |
| `WRITE` · `WRITE_ACCESS` | Whether the restriction covers write as well as read |

**Export the unrestricted rows.** A restriction set to *unrestricted* is the
finding, and it is not the same as a restriction that is absent: the first is a
decision somebody made in the maintenance screen, the second may just be a row
your extract dropped. Keep whatever marker your export uses for it rather than
converting it to a blank.

### Business catalogs per role (`business_role_catalogs.csv`)
**Source:** the catalog assignment of each business role. *Not verified for this
guide.*

| Column (any of) | Meaning |
|---|---|
| `ROLE` · `BUSINESS_ROLE` · `ROLE_ID` | Business role |

Catalog sprawl is a count, not a judgement: a role carrying dozens of catalogs is
not wrong, it is unreviewable, and the check reports the roles nobody could
sensibly attest to in an access review.

### CDS view exposure (`cds_views.csv`)
**Source:** the `@AccessControl.authorizationCheck` annotation and the exposure
state of each CDS view, from ADT or from your own report over the DDL sources.
*Not verified for this guide* — SAP documents what the annotation MEANS, but not
a supported way to export its value across a repository.

**Prefer `--code-src` if you can.** Given the ABAP sources, MonitorRisk reads the
DDL and the DCL directly and cross-references them, which answers a strictly
stronger question than this column can: it distinguishes an exposed view with no
access-control role at all from one whose role exists and grants everything, and
it finds the RAP behaviour definitions that authorise an operation but never an
instance. This file exists for landscapes where a source export is not available
and somebody can run a report over the annotations instead.

Also accepted: `cds_access_control.csv`

| Column (any of) | Meaning |
|---|---|
| `VIEW` · `CDS_VIEW` · `DDLNAME` · `ENTITY` · `NAME` | View |
| `EXPOSED` · `OData` · `SERVICE` | Whether it is exposed as a service |
| `RELEASED` · `C1_CONTRACT` | Release contract, where you have it |
| `AUTH_CHECK` · `AUTHORIZATION_CHECK` · `AUTHORIZATIONCHECK` · `ACCESSCONTROL` | The authorization-check annotation |

**You may not need this file.** If you can supply the ABAP sources instead —
`--code-src` pointed at a repository export — MonitorRisk reads the DDL and the
DCL directly and cross-references them, which is a stronger answer than an
annotation column: it can tell an exposed view with no access-control role at all
from one whose role exists and grants everything.

### OData V4 service groups (`odata_v4_services.csv`, `iwfnd_v4.csv`)
**Source:** `/IWFND/V4_ADMIN` — the Gateway V4 service administration. The V2
services belong in `odata_auth.csv` (`/IWFND/MAINT_SERVICE`) and are documented
separately.

| Column (any of) | Meaning |
|---|---|
| `SERVICE_GROUP` · `SERVICEGROUP` | Service group |
| `SERVICE` · `NAME` | Service |
| `PUBLISHED` · `STATUS` · `STATE` | Publication state |
| `SYSTEM_ALIAS` · `ALIAS` | System alias |
| `AUTH` · `AUTHORIZATION` · `S_SERVICE` · `PROTECTED` | Whether an `S_SERVICE` authorization guards it |

A published V4 service group with no `S_SERVICE` check is reachable by any
authenticated caller who can construct the URL, and unlike a Fiori tile there is
nothing on a screen to suggest it exists.

### Cloud Foundry org and space roles (`cf_roles.csv`)
**Source:** the Cloud Foundry CLI.

```bash
cf curl /v3/roles?include=user,organization,space > cf_roles.json
```

Convert to CSV, or export from `cf org-users` / `cf space-users` per org and
space. Also accepted: `cf_org_space_roles.csv`

| Column (any of) | Meaning |
|---|---|
| `USER` · `USERNAME` · `USER_ID` · `EMAIL` | User |
| `ORG` · `ORGANIZATION` | Organization |
| `SPACE` | Space |
| `ROLE` · `ROLE_TYPE` · `CF_ROLE` | Role (`OrgManager`, `SpaceDeveloper`, …) |
| `SCOPE` | Org-level or space-level |

`SpaceDeveloper` in the production space is deploy authority over the running
application, which is a larger grant than most of the business roles it sits
beside — and it is administered in a different console by a different team, which
is exactly why it is worth pulling into the same report.

---

## BTP platform surface (the `btpcloud` module)

The five BTP files documented earlier — subaccounts, security settings, role
collections, audit log records, Cloud Connector — are the ones with a verified
`btp` CLI verb behind them. The six below are the rest of the subaccount's
surface. Two have a documented API path; the others are cockpit exports, and they
are marked so you know which is which.

### Destinations (`btp_destinations.json`)
**Source:** the Destination service's own API, path
`/destination-configuration/v1/subaccountDestinations`, reached at the hostname
inside a Destination service key. **MonitorRisk will fetch this for you:**

```bash
python -m collect btp --service-key ./destination-key.json --out ./extract
python sap_scanner.py --data-dir ./extract
```

The service key is the file you download from the BTP cockpit when you create a
service key for the Destination service instance; the client secret stays inside
it and never reaches the command line. Or call the path yourself and save the
response. Also accepted: `destinations.json`

Either an array of destinations, or the service's own envelope:

```json
[{"Name": "S4_BACKEND", "URL": "https://s4.example.com",
  "Authentication": "BasicAuthentication", "ProxyType": "OnPremise",
  "TrustAll": "false", "User": "RFC_USER"}]
```

Keys read: `Name`, `URL`, `Authentication`, `ProxyType`, `TrustAll` (also
`skipSSLValidation`), `User`, `lastModified`.

`TrustAll: "true"` is the one to look for. It disables certificate validation on
the connection between the platform and your backend, which turns a TLS link into
an encrypted link to whoever is on the path — and it is set, routinely, to get a
destination working against a self-signed certificate and then never unset.

### Entitlements (`btp_entitlements.json`)
**Source:** the `btp` CLI.

```bash
btp --format json list accounts/entitlement > btp_entitlements.json
```

SAP documents this verb as *"Get all the entitlements and quota assignments for a
global account, directories, and subaccounts"*, so one call covers the whole
account rather than one subaccount at a time. It runs against the global account
you are logged into unless you narrow it first with `btp target`. The cockpit
route is *Entitlements* → *Entity Assignments* if you would rather export by hand.

Also accepted: `entitlements.json`

```json
{"entitlements": [
  {"serviceName": "hana-cloud", "planName": "hana", "subaccount": "<guid>",
   "quota": 2, "used": 0}
]}
```

Keys read: `entitlements` / `services` / `quotaAssignments`, then `serviceName` /
`service` / `name`, `planName` / `plan`, `quota` / `amount`, `used` / `usage` /
`instances_created`, `subaccount` / `subaccountId`.

Include the **used** figure, or the check has nothing to work with. An entitlement
with quota and no instances is a service anybody with the right role can spin up
in a subaccount nobody is watching — dormant attack surface that costs nothing and
appears on no inventory. Without `used`, an unspent entitlement and a fully
consumed one look the same.

### Service instance bindings (`btp_service_bindings.json`)
**Source:** the `btp` CLI.

```bash
btp target --subaccount <subaccount-id>
btp --format json list services/binding > btp_service_bindings.json
```

SAP documents this verb as *"List all service bindings associated with the current
subaccount"* — so unlike the entitlement call it is per subaccount, and `btp
target` decides which one. `btp get services/binding` returns one binding in full
where the list form is too thin. Where the instances live in a Cloud Foundry space
you can equally use `cf curl /v3/service_credential_bindings`, and the cockpit
route is *Instances and Subscriptions*.

Also accepted: `service_bindings.json`

Keys read: `bindings` / `serviceBindings` / `items`, then `name` / `bindingName`,
`service` / `serviceName` / `service_instance`, `created` / `createdAt` /
`creation_date`, `lastRotated` / `rotatedAt` / `last_rotation`, `scopes` /
`authorities` / `scope`, `instanceStatus` / `instance_state`.

`lastRotated` is the field that matters and the one most often missing. A binding
carries a credential; a binding created three years ago and never rotated is a
credential three years old, held by whatever application still has the environment
variable. If your export cannot produce a rotation timestamp, say so rather than
supplying the creation date in its place — the check reports "no rotation evidence"
differently from "rotated three years ago", and the second is a claim.

### Private Link and network isolation (`btp_network.json`)
**Source:** SAP Private Link is consumed as **ordinary service instances**, so it
is listed like any other service in the subaccount:

```bash
btp target --subaccount <subaccount-id>
btp --format json list services/instance > instances.json
```

Or `cf services` in the Cloud Foundry space. SAP's own documentation settles that
these are service instances rather than a separate object: creating them needs the
**Space Developer** role in the space, they carry service keys and bindings, and
the guide notes that *"service keys for SAP Private Link service instances in
Cloud Foundry do not include the hostname of the connected resource, only the
private IP address"*.

*What is not verified for this guide is the service offering name to filter on* —
select the Private Link instances by the offering your subaccount is entitled to
and say which. The cockpit route is the Private Link service's own instance list.

Also accepted: `private_link.json`

```json
{"endpoints": [
  {"service": "hana-cloud", "endpointType": "public",
   "privateLink": false, "url": "https://…"}
]}
```

Keys read: `endpoints` / `privateLinks` / `configurations` / `connectivity`, then
`service` / `serviceName`, `endpointType` / `type`, `privateLink` /
`privateLinkEnabled` / `private_endpoint`, `url` / `endpoint`.

### Identity Authentication configuration (`ias_config.json`)
**Source:** the **Application Configurations API**, which SAP publishes on the SAP
Business Accelerator Hub as `SCI_Application_Directory`; or the IAS Administration
Console — *Applications & Resources* for the application list and their
authentication policies, and the tenant's own password policy.

> **The two do not return the same list, by design.** SAP: *"the Application
> Configurations API may return a higher number of applications than those
> displayed in the administration console. Some applications are used for internal
> purposes and are not shown in the admin console."* So an API export will name
> applications an administrator has never seen. That is not an error and they
> should not be filtered out — an internal application with a weak authentication
> policy is still an authentication path into the tenant. Say which route you used,
> because a console export that is missing them is not the same evidence.

Also accepted: `ias_applications.json`

```json
{"applications": [
  {"name": "S4 Fiori", "type": "SAP", "mfaEnabled": true,
   "authenticationRules": [...], "ipRestrictions": ["10.0.0.0/8"],
   "riskBasedAuth": true, "authenticationType": "saml2"}],
 "passwordPolicy": {"minLength": 12, "maxFailedAttempts": 5,
                    "requireComplexity": true, "passwordExpiryDays": 180},
 "corporateIdP": {"enabled": true, "enforced": true,
                  "localFallbackAllowed": false}}
```

Three blocks, three different checks, and they are worth supplying together:
`applications` drives the MFA and conditional-authentication checks,
`passwordPolicy` the local-user policy check, and `corporateIdP` the one that
matters most — a corporate identity provider that is configured but not
*enforced*, with local password logon still allowed, means every conditional
access rule your IdP applies can be walked around by anyone who knows the local
password. `enforced` and `localFallbackAllowed` are the two keys that settle it.

`authenticationType` / `trustType` also feeds the XSUAA-trust check: applications
still on the older trust chain are named so the migration has a list.

### Cloud Integration artifacts (`cpi_artifacts.json`)
**Source:** Cloud Integration's OData API, whose service root SAP documents as
`https://<host address>/api/v1/` — on an Edge Integration Cell,
`https://<host address>/location/<runtime location id>/api/v1/`. The resources
this file is built from:

| Resource | What it gives you |
|---|---|
| `IntegrationRuntimeArtifacts` | the deployed content — *"read, deploy, and undeploy integration content"*, and the error information for each |
| `IntegrationDesigntimeArtifacts` | the iFlows themselves, and their configurations |

An API client needs the **`MonitoringDataRead`** role template, and inbound HTTP
access has to be set up for it first — that is the step people miss, and it fails
as a 401 that reads like a wrong password. Example requests are on the SAP
Business Accelerator Hub under *Integration Content*.

The **credential store** is the other half and does not come from the same place:
the tenant keystore and certificates have their own *Security Content* OData API
on the Hub, and the deployed user-credential artifacts are listed in *Monitor* →
*Manage Security* → *Security Material*. *The API resource for listing deployed
user credentials is not verified for this guide* — export that half from the
Monitor screen and say so.

Also accepted: `cpi_security.json`

```json
{"credentials": [
  {"name": "S4_USER", "type": "User Credentials",
   "deployedOn": "2023-02-11", "deployedBy": "P000123"}],
 "iflows": [
  {"name": "OrderReplication", "senderAuth": "None",
   "endpoints": ["/http/orders"], "hardcodedCredentials": false}]}
```

Keys read: `credentials` / `securityMaterial` / `credentialStore` with `name` /
`alias`, `type` / `kind`, `deployedOn` / `created` / `lastModified`, `deployedBy`
/ `owner`; and `iflows` / `integrationFlows` / `artifacts` with `name` / `id`,
`senderAuth` / `inboundAuth` / `senderAuthentication`, `endpoints` /
`senderEndpoints`, `hardcodedCredentials` / `embeddedCredentials`.

The credential store is the interesting half. Deployment metadata is what makes it
auditable: a credential deployed by somebody who left, or deployed once and never
touched, is a standing password nobody owns.

### Event Mesh (`event_mesh.json`)
**Source:** the Event Mesh queue and topic configuration for the subaccount. *No
verified export route is recorded for this one.*

Also accepted: `em_config.json`

```json
{"queues": [
  {"name": "orders.inbound", "accessPolicy": "…",
   "topics": ["ns/orders/*"], "subscriptions": [...]}]}
```

Keys read: `queues` with `name` / `queueName`, `topics` / `topicSubscriptions`,
`accessPolicy` / `acl` / `permissions`, `namespace` / `messageNamespace`.

---

## The cloud integration surface (the `intglayer` module, cloud half)

Four of these six are **declarative**: there is no single system that knows your
integration topology or which webhooks you have registered across three vendors.
That is the reason they are worth writing down.

### API Management proxies and policies (`apim_policies.json`)
**Source:** API Management's own public APIs, reached through the
**`apiportal-apiaccess`** service plan. Create a service instance on that plan and
generate a service key; SAP's own description is that the plan "offers external
applications the ability to access the public APIs of the SAP Integration Suite
API Management capability… to perform CRUD operations on API Management features
like API proxies or products", and that it is "especially useful when integrating
API Management with a CI/CD process". The service key carries the application
`url`, `clientId`, `clientSecret` and `tokenUrl`; exchange those for a bearer
token and call the proxy and policy endpoints, which are documented on the SAP
Business Accelerator Hub.

Exporting by hand from the API portal produces the same rows if you would rather
not create an instance.

Also accepted: `api_proxies.json`

```json
{"proxies": [
  {"name": "OrderAPI", "basePath": "/orders", "deployed": true,
   "policies": ["VerifyAPIKey", "Quota"],
   "tlsEnforced": true, "minTlsVersion": "TLSv1.2",
   "target": "https://s4.example.com/sap/opu/odata/…"}]}
```

Keys read: `proxies` / `apiProxies` / `apis` with `name` / `proxyName` /
`apiName`, `basePath` / `path`, `policies` / `appliedPolicies`, `active` /
`deployed`, `target` / `targetUrl`, `tlsEnforced` / `httpsOnly` / `requireSSL`,
`minTlsVersion` / `tlsVersion` / `sslProtocol`.

A proxy with an empty policy list is a pass-through: API Management is in the path
adding a hostname and nothing else, while the architecture diagram shows a
gateway. Export proxies with no policies rather than filtering them out — they are
the finding.

### OAuth client registrations (`oauth_clients.json`)
**Source:** two `btp` CLI lists, because "OAuth client" covers two different
things in a BTP subaccount and both are worth having:

```bash
btp target --subaccount <subaccount-id>
# 1. the application clients — one XSUAA service instance per application
btp --format json list services/instance > instances.json
btp --format json list services/binding  > bindings.json
# 2. the API credentials that call the Authorization and Trust Management APIs
btp --format json list security/api-credential > api_credentials.json
```

SAP documents the second as managing "API credentials, which enable you to access
the REST APIs of the SAP Authorization and Trust Management service" — a separate
population from the application clients, administered separately, and the one
nobody reviews. Merge whichever you have into the shape below.

Also accepted: `xsuaa_clients.json`

```json
{"clients": [
  {"clientId": "sb-orderapp!t1234", "scopes": ["uaa.resource"],
   "grantTypes": ["client_credentials"],
   "created": "2022-06-01", "lastUsed": "2026-07-30"}]}
```

Keys read: `clients` / `oauthClients` with `clientId` / `client_id` / `name`,
`scopes` / `scope` / `authorities`, `grantTypes` / `grant_types` /
`authorized_grant_types`, `created` / `createdAt`, `lastUsed` / `last_access` /
`lastTokenIssued`.

`lastUsed` is what turns this from an inventory into a control. A
`client_credentials` client that has issued no token in a year is a live
credential with no owner and no purpose, and it will not appear in any user access
review because it is not a user.

### CPI data stores and variables (`cpi_datastores.json`)
**Source:** the same Cloud Integration OData API as above, service root
`https://<host address>/api/v1/`, resource `DataStores`. SAP's own example request
is the one worth starting from:

```http
GET /DataStores?overdueonly=true
```

`overdueonly=true` narrows it to stores holding messages past their retention,
which is the sharp end of this check; drop the parameter for the full inventory,
which is what the scanner wants. The cockpit route is *Monitor* → *Manage Stores*.

Also accepted: `cpi_variables.json`

```json
{"dataStores": [{"name": "OrderStage", "entryCount": 14200,
                 "encrypted": false, "retentionDays": 0}],
 "variables":  [{"name": "lastRunToken", "value": "…"}]}
```

Keys read: `dataStores` / `stores` with `name` / `storeName`, `entryCount` /
`entries` / `size`, `encrypted` / `encryption`, `retentionDays` / `ttl` /
`retention`; and `variables` / `globalVariables` with `name` / `variableName`,
`value` / `content`.

A data store is a queue that has stopped being a queue: unencrypted, no retention,
and holding a year of business documents that were only ever meant to be in
transit. The entry count and the retention setting together are the finding.

### Registered webhooks (`webhooks.json`) — **declarative**
**Source:** you. There is no one system that holds this; webhooks get registered
in whichever application needed one, and the point of writing them down is that
nobody currently can list them.

Also accepted: `callbacks.json`

```json
{"webhooks": [
  {"name": "order-created", "url": "https://hooks.example.com/…",
   "event": "OrderCreated", "signatureVerification": true,
   "active": true, "created": "2025-03-02", "lastTriggered": "2026-08-10"}]}
```

Keys read: `webhooks` / `callbacks` / `subscriptions` with `name` / `id`, `url` /
`callbackUrl` / `endpoint`, `event`, `signatureVerification` / `hmac` /
`secret_configured`, `status` / `active`, `created` / `registeredAt`,
`lastTriggered` / `lastCall`.

`signatureVerification` is the one that matters: a webhook receiver that does not
verify a signature will act on anything that arrives at the URL, and the URL is in
the configuration of every system that calls it.

### Integration topology (`integration_topology.json`) — **declarative**
**Source:** you, or your architecture repository if it is machine-readable.

Also accepted: `system_map.json`

```json
{"connections": [
  {"source": "S4P", "target": "CRM-SaaS", "protocol": "https",
   "encrypted": true, "status": "active"}]}
```

Keys read: `connections` / `integrations` / `links` with `source` / `from` /
`sender`, `target` / `to` / `receiver`, `protocol` / `type` / `transport`,
`encrypted` / `tls` / `ssl`, `status` / `active`.

Worth the hour it takes. Every other integration check in this product examines
one endpoint at a time; this is the only source that says which systems are meant
to be talking at all, so it is the only one that can show a connection nobody
would defend if asked.

### Integration alerting (`integration_alerts.json`) — **declarative**
**Source:** you, describing how integration failures reach a human.

Also accepted: `alert_config.json`

```json
{"rules": [{"name": "iflow-failure", "type": "error", "category": "runtime"}],
 "siemIntegration": true, "emailNotification": true, "logForwarding": true}
```

Keys read: `rules` / `alertRules` / `conditions` with `name`, `type`, `category`;
and the top-level `siemIntegration` / `siem`, `emailNotification` / `email`,
`logForwarding`.

An integration layer with no alerting is not a monitoring gap, it is a security
gap: a failing iFlow that nobody is told about is a business process that has
quietly stopped, and a *succeeding* iFlow doing the wrong thing is one nobody will
notice for a quarter.

---

## Data protection and privacy (the `dataprot` module)

Three of these come out of SAP. The rest are **declarative** — the classification
of which fields hold personal data, which systems hold production copies, what
legal basis each processing purpose runs on. SAP stores none of that, because none
of it is a setting; it is the register your data-protection officer either has or
does not. Writing it down here means the scanner can hold it against what the
system is actually configured to do, which is the only way a paper register and a
running system ever get compared.

### Read Access Logging configuration (`ral_config.csv`, `sralmanager.csv`)
**Source:** `SRALMANAGER` — Read Access Logging Manager. Export the configurations
with their log purposes and channels.

| Column (any of) | Meaning |
|---|---|
| `CONFIG_NAME` · `NAME` | RAL configuration |
| `STATUS` · `ACTIVE` · `ENABLED` | Whether it is switched on |
| `CHANNEL` · `LOG_CHANNEL` | Channel (Dynpro, Web Dynpro, RFC, Web Service, Gateway) |
| `PURPOSE` · `LOG_PURPOSE` · `LOG_DOMAIN` | Log purpose |

RAL is the only thing in an ABAP system that records who *read* personal data —
the change documents cover writes and nothing else. Its coverage is per channel,
so export every channel including the ones with no configuration: a RAL setup that
covers the Dynpro screens and not the OData services logs the way people used to
reach the data and not the way they reach it now.

If you are already supplying `security_params.csv`, the check falls back to it for
the master switch — but the channel detail only exists here.

### RAL log channels (`ral_log_channels.csv`)
**Source:** `SRALMANAGER` — the channel configuration, with storage and retention.

| Column (any of) | Meaning |
|---|---|
| `CHANNEL_NAME` · `NAME` | Channel |
| `RETENTION_DAYS` · `RETENTION` · `TTL` | Retention |
| `ARCHIVING` · `ARCHIVE_ENABLED` | Whether records are archived |
| `STORAGE_TYPE` · `STORAGE` | Where records are kept |

A read-access log with a short retention is a control that satisfies an auditor on
the day of the audit and answers no question afterwards. The retention needs to
outlast the time it takes to discover a breach, which is the number the check
compares it against.

### ILM retention policies (`ilm_policies.json`)
**Source:** `IRMPOL` — Information Lifecycle Management policy maintenance.

Also accepted: `ilm_retention.json`

```json
{"policies": [
  {"name": "FI_DOCS", "dataObject": "FI_ACCTIT", "retentionPeriod": 10,
   "unit": "YEAR", "destructionMethod": "DELETE",
   "endOfPurpose": true, "legalBasis": "HGB §257"}]}
```

Keys read: `policies` / `retentionRules` with `name` / `policyName`, `dataObject` /
`object` / `table`, `retentionPeriod` / `retention` / `duration`, `unit` /
`retentionUnit`, `destructionMethod` / `destruction` / `endAction`, `endOfPurpose`
/ `purposeExpiry`, `legalBasis`.

Export the policies for the personal-data objects even where retention is
indefinite. "No policy" and "policy with no end" are different findings: the first
is an oversight, the second is a decision somebody can be asked to justify.

### Personal data field inventory (`personal_data_inventory.csv`) — **declarative**
**Source:** your data-protection register. Where you already run RAL or the
Information Retrieval Framework, seed it from those and correct by hand.

Also accepted: `pdi.csv`

| Column (any of) | Meaning |
|---|---|
| `TABLE_NAME` · `TABLE` | Table |
| `FIELD_NAME` · `FIELD` · `COLUMN` | Field |
| `CLASSIFICATION` · `DATA_CLASS` · `SENSITIVITY` | Classification |
| `RAL_ENABLED` · `RAL` · `ACCESS_LOGGING` | Whether read access is logged |
| `MASKED_IN_NONPROD` · `MASKED` · `ANONYMIZED` | Whether it is masked in copies |

The two right-hand columns are what makes this more than a spreadsheet. They are
claims about the system, and the scanner holds them against `ral_config.csv` and
`data_masking.json` — so a field marked *RAL enabled* in a system where RAL covers
no channel becomes a finding rather than a reassurance.

### Sensitive field classification (`sensitive_fields.csv`) — **declarative**
**Source:** you. Same shape as the inventory above and read by the same check;
supply whichever your organisation already maintains, or both.

Also accepted: `pii_fields.csv`

### Purpose of processing (`purpose_of_processing.csv`) — **declarative**
**Source:** your Article 30 record of processing activities. Where purposes are
already modelled in ILM, export from there and extend.

Also accepted: `pop_config.csv`

| Column (any of) | Meaning |
|---|---|
| `PURPOSE` · `PURPOSE_ID` · `PURPOSE_NAME` | Purpose |
| `LEGAL_BASIS` · `BASIS` · `GDPR_ARTICLE` | Legal basis |
| `EXPIRY_DATE` · `VALID_TO` · `END_DATE` | When the purpose ends |
| `DATA_CATEGORIES` · `CATEGORIES` · `FIELDS` | Categories covered |
| `STATUS` · `ACTIVE` | Whether it is current |

A purpose past its expiry date with data still live is the end-of-purpose finding,
and it is the one nobody discovers on their own, because nothing in the system
raises an event when a legal basis lapses.

### Deletion and DSAR requests (`deletion_requests.csv`) — **declarative**
**Source:** your data-subject request process — the ticket queue, not SAP.

Also accepted: `dsar_requests.csv`

| Column (any of) | Meaning |
|---|---|
| `REQUEST_ID` · `ID` · `TICKET` | Request |
| `DATA_SUBJECT` · `SUBJECT` · `PERSON` | Subject, however you reference them |
| `REQUEST_TYPE` · `TYPE` · `ACTION` | Erasure, blocking, access |
| `RECEIVED_DATE` · `CREATED` · `REQUEST_DATE` | Received |
| `COMPLETED_DATE` · `CLOSED` · `COMPLETION_DATE` | Completed |
| `STATUS` · `STATE` | Status |
| `DOCUMENTATION` · `NOTES` · `JUSTIFICATION` | Evidence of what was done |

**Reference data subjects rather than naming them.** A ticket number is enough for
the check, which measures elapsed time against the statutory deadline; a name puts
a data subject into a security report, which is the one place a privacy control
should never create a new copy of them.

### Non-production data masking (`data_masking.json`) — **declarative**
**Source:** you, describing which non-production systems hold masked data.

Also accepted: `masking_config.json`

```json
{"configurations": [
  {"name": "S4Q", "systemType": "QA", "piiMasked": true,
   "status": "active", "anonymized": true}]}
```

Keys read: `configurations` / `rules` with `name` / `system`, `systemType` /
`type`, `piiMasked` / `maskingEnabled` / `anonymized`, `status` / `active`.

Read together with `system_landscape.csv`: a system classified as a production
copy with no masking configuration is the finding, and it is the most common one
in this family, because a system refresh copies the data and nobody re-runs the
masking job afterwards.

### Data residency and cross-border transfer (`data_residency.json`) — **declarative**
**Source:** you, describing where data sits and where it moves.

Also accepted: `cross_border.json`

```json
{"primaryRegion": "eu10",
 "transfers": [
   {"name": "analytics-feed", "sourceRegion": "eu10", "destRegion": "us10",
    "adequacyDecision": false, "safeguard": "SCC",
    "dataTypes": ["customer"], "dpiaCompleted": true}]}
```

Keys read: `primaryRegion` / `homeRegion` / `dataCenter`, and `transfers` /
`dataFlows` / `flow` with `name`, `sourceRegion` / `from`, `destRegion` / `to` /
`destination`, `adequacyDecision` / `adequacy`, `safeguard` / `transferMechanism`
/ `legal_mechanism`, `dataTypes` / `categories`, `dpiaCompleted` / `dpia`.

The check is looking for a transfer with neither an adequacy decision nor a
safeguard recorded — a data flow that exists in the architecture and not in the
compliance file. Include the transfers you believe are fine; that is what makes
the absence of the others meaningful.

### DPP toolkit configuration (`dpp_config.json`) — **declarative**
**Source:** you, recording which of SAP's data-protection capabilities are
actually configured in this system.

Also accepted: `dpp_toolkit.json`

Six keys, all read at the top level, each either a truthy value or absent:

```json
{"informationReport": true, "deletionReport": true, "changeOfPurpose": true,
 "dataBlocking": true, "consentManagement": false,
 "dataBreachNotification": true}
```

| Key | What it stands for |
|---|---|
| `informationReport` | GDPR Art.15 — right of access / data subject report |
| `deletionReport` | GDPR Art.17 — right to erasure |
| `changeOfPurpose` | GDPR Art.6 — change of purpose management |
| `dataBlocking` | End-of-purpose blocking |
| `consentManagement` | GDPR Art.7 — consent recording and withdrawal |
| `dataBreachNotification` | GDPR Art.33/34 — breach notification support |

`false` and absent are treated the same, deliberately: this file is a set of
claims, and a claim you did not make is not a claim the scanner will make for you.

### System landscape classification (`system_landscape.csv`) — **declarative**
**Source:** you, or your SLD / LMDB if it carries the classification.

Also accepted: `landscape.csv`

| Column (any of) | Meaning |
|---|---|
| `SID` · `SYSTEM` · `SYSTEM_ID` | System |
| `ENVIRONMENT` · `TYPE` · `SYSTEM_TYPE` | Production, QA, development, sandbox |
| `DATA_CLASSIFICATION` · `CLASSIFICATION` · `DATA_CLASS` | Highest classification held |
| `CONTAINS_PROD_DATA` · `HAS_PROD_DATA` · `IS_COPY` · `SOURCE_PROD` | Whether it holds a production copy |
| `ACCESS_POLICY` · `ACCESS_CONTROL` | Access policy applied |

`CONTAINS_PROD_DATA` is the column the rest of the family hangs on. A sandbox
holding a production copy is a production system with development access and no
change control, and nothing inside that sandbox knows it.

---

## Logging, SIEM and incident response (the `logmon` module)

### SIEM connector configuration (`siem_config.json`) — **declarative**
**Source:** you, describing how SAP logs reach your SIEM.

```json
{"enabled": true, "connector": "sapetd-splunk", "lastSync": "2026-08-14",
 "logSources": ["security_audit_log", "system_log", "change_documents"]}
```

Keys read: `enabled` / `active`, `connector` / `type`, `lastSync` / `lastForward`,
`logSources` / `sources`.

`logSources` is the half that finds things. Almost every landscape forwards the
security audit log; far fewer forward change documents or the table change log,
and an attacker who knows which is which knows exactly which trail is watched.

### Log retention policy (`log_retention.json`) — **declarative**
**Source:** you, per log type.

```json
{"policies": [
  {"logType": "security_audit_log", "retentionDays": 365, "archiving": true},
  {"logType": "change_documents",   "retentionDays": 2555, "archiving": true}]}
```

Keys read: `policies` / `retentionRules` with `logType` / `name`, `retentionDays`
/ `retention`, `archiving` / `archiveEnabled`.

The `logreview` module holds this against the audit-log window you actually
exported, so a policy promising a year against an export covering a fortnight
becomes a discrepancy rather than a comfort.

### Logon event counters (`logon_events.csv`)
**Source:** aggregate per-user logon counts for the window — derived from your
security audit log export, or from the workload statistics. *No single verified
route is recorded; whichever you use, keep the window consistent with the audit
log you supply.*

Also accepted: `logon_stats.csv`

| Column (any of) | Meaning |
|---|---|
| `USERNAME` · `BNAME` · `USER` | User |
| `COUNT` · `OCCURRENCES` | Number of events in the window |
| `EVENT` · `TYPE` · `LOGON_TYPE` | Success or failure, and how they logged on |

Aggregates only. This file is deliberately not the event stream — it feeds the
failed-logon-count checks, and the run-of-failures-then-a-success analysis reads
the audit log itself. Keep failures and successes as separate rows rather than
netting them: a hundred failures and one success is the pattern, and a single row
saying 101 hides it.

### Incident response readiness (`incident_response.json`) — **declarative**
**Source:** you. Six keys, each truthy or absent:

```json
{"runbook": "https://wiki/…/sap-ir", "contacts": "secops@example.com",
 "escalation": true, "forensicAccess": true,
 "backupVerification": "monthly", "drillSchedule": "2026-11"}
```

| Key | What it stands for |
|---|---|
| `runbook` | Incident response runbook or playbook exists |
| `contacts` | Emergency security contact list is maintained |
| `escalation` | Escalation matrix is defined |
| `forensicAccess` | Forensic access procedure is documented |
| `backupVerification` | Log backup verification is scheduled |
| `drillSchedule` | Tabletop or drill schedule exists |

The value can be a URL, a date, a team name — anything truthy. The check is
control existence, not content: it cannot read your runbook and does not pretend
to, and it says so in the finding.

---

## Vendor and payment master data (the `vendormaster` module)

Two exports, and together they answer the ghost-vendor question: is there a bank
account that several suppliers share, and is there a supplier whose payment
details were created and last changed by the same person with nobody else
involved.

### Business partner / vendor master (`vendor_master.csv`)
**Source:** `SE16` on `BUT000` (business partner) in S/4HANA, or `LFA1` (vendor
master) in a classic or converted system. `KNA1` for customers, if you audit
those too.

Also accepted: `but000.csv`, `lfa1.csv`

| Column (any of) | Meaning |
|---|---|
| `PARTNER` · `LIFNR` · `KUNNR` · `PARTNER_ID` · `VENDOR` | Partner or vendor number |
| `NAME1` · `NAME` · `PARTNER_NAME` · `MC_NAME1` | Name |
| `XBLCK` · `SPERR` · `BLOCKED` | Posting block |
| `LOEVM` · `XDELE` · `DELETED` · `DELETE_FLAG` | Deletion flag |
| `NOT_RELEASED` · `UNRELEASED` | Not-released marker, where you have it |
| `CRDAT` · `ERDAT` · `CREATED_ON` | Created on |
| `CRUSR` · `ERNAM` · `CREATED_BY` | Created by |
| `CHDAT` · `AEDAT` · `CHANGED_ON` | Last changed on |
| `CHUSR` · `AENAM` · `CHANGED_BY` | Last changed by |

The four audit columns are the ones people leave out and the ones the analysis
runs on. Without created-by and changed-by there is no four-eyes question to ask,
and the check will say so rather than reporting a clean result.

### Bank details (`vendor_bank.csv`)
**Source:** `SE16` on `BUT0BK` (business partner bank details) or `LFBK` (vendor
bank details). `KNBK` for customers.

Also accepted: `but0bk.csv`, `lfbk.csv`

| Column (any of) | Meaning |
|---|---|
| `PARTNER` · `LIFNR` · `KUNNR` · `PARTNER_ID` · `VENDOR` | Partner the account belongs to |
| `BANKS` · `BANK_COUNTRY` · `COUNTRY` | Bank country key |
| `BANKL` · `BANK_KEY` · `BANK_NUMBER` | Bank key |
| `BANKN` · `ACCOUNT` · `ACCOUNT_NUMBER` | Account number |
| `IBAN` | IBAN, where held |

**Account numbers never leave this product in full.** They are masked to the last
four characters everywhere they appear — findings, reports, exports, the console.
They are needed unmasked *on the way in* because the whole analysis is a match
between partners, and two accounts masked to `••••4321` are not evidence that they
are the same account.

If your change process will not release account numbers at all, supply the file
without them. The scanner detects that specific case and reports it as an export
quality gap — the analysis did not run — rather than as an absence of shared
accounts. That distinction is the entire reason the check exists in that shape:
a payment-fraud analysis that silently reports nothing is worse than one that says
it could not run.

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
