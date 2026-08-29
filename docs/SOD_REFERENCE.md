# SAP Segregation of Duties — a vendor-neutral reference

Built 2026-08-29 from SAP's own primary documentation, PCAOB standards, COSO,
ISACA and SEC filings. Companion to [`COMPETITOR_PATHLOCK.md`](COMPETITOR_PATHLOCK.md),
which measures a competitor against this yardstick.

Labels: `verified` (primary source, quoted) · `asserted` (credible secondary) ·
`inferred` (synthesis, evidence named).

Primary sources: **SAP Access Control 12.0 SP31 Application Help** and
**Administrator Guide** (SAP's PDF builds — `help.sap.com` HTML is a JS shell
that returns only a title to any fetcher) · **PCAOB AS 2201, AS 1105, Staff
Audit Practice Alert No. 11** · **COSO 2013** · **ISACA Glossary** · **SEC EDGAR**.

---

## 1. Three findings that should change what we build

### 1.1 SAP's own bias is to OVER-report — and it is the opposite of the market's

`verified` — SAP AC 12.0 SP31 §8.2.1.1, **Caution**:

> *"If you create organizational rules incorrectly, you could potentially filter
> out too much. By filtering out too much, you cannot identify possible control
> concerns with your access. **From a control perspective, it is much better to
> over-report (causing false positives) rather than under-report (causing false
> negatives).**"*

Every competitor sells noise reduction. Pathlock's stated differentiator is
*"reduce false positives"*. **SAP explicitly warns against optimising that
axis.**

`inferred` — the defensible claim is not fewer findings. It is **precision with
recall**: remove a flagged conflict only when the engine can *name the org field
and value* that makes execution impossible, and say so on the row. That is a
different product from one that quietly suppresses.

### 1.2 Ruleset COVERAGE is measurable, and nobody publishes it

`verified` — SAP ships three reports that measure what a ruleset **cannot see**:

| Report | SAP's description |
|---|---|
| **List Actions in Roles But Not in Rules** | *"lists all the actions that are in roles but are not part of the rule library"* |
| **List Permissions in Roles But Not in Rules** | *"lists all the permissions that are in roles but are not part of the rule library"* |
| **Embedded Action Calls in Programs of SAP Systems** | *"identifies embedded transaction calls in custom programs"* |

SAP shipping these is SAP conceding the gap exists.

`inferred` — **this is the answer to "36 risks against their 207."** Breadth is
a number anyone can inflate; **coverage is a number almost nobody computes and
no vendor publishes.** A conflict report is only as trustworthy as the fraction
of the estate its ruleset can see. Computing that fraction — and printing it
beside every SoD result — is a differentiator available to us today, on data we
already parse (`AGR_1251`, `role_auth_values`, `custom_code_scan`).

### 1.3 Ruleset validation is a genuine gap in published guidance

`verified` — the standards chain that *compels* validation exists:

- **AS 1105.10** — the auditor must *"test the accuracy and completeness of the
  information, or test the controls over"* it, and *"evaluate whether the
  information is sufficiently precise and detailed."*
- **PCAOB SAPA 11 p.26** — a named inspection failure is not testing *"**the
  logic of the queries (or parameters) used to extract data**"*.
- **AS 2201 ¶.B30** — benchmarking is unavailable for controls dependent on
  *"the related files, tables, data, and parameters."*

`inferred` — **the SoD ruleset *is* the query logic and the parameters.** So
AS 1105.10 obliges someone to validate it, ¶.B30 forbids benchmarking it away
— and no published source describes how anyone actually does this. SAP itself
calls rule sets *"arbitrary definitions"* (§8.2.2.1).

That is the most defensible place to claim differentiated methodology: not a
bigger rulebook, but **a rulebook that carries its own evidence**.

---

## 2. The canonical model — with the correction everyone gets wrong

`verified` — SAP's definition (§8.3): *"An access risk is one or more actions or
permissions that, when available to a single user (or single role, profile, or
HR Object), creates the potential for fraud or unintentional errors."*

Three risk types, SAP's words: **Segregation of Duties** (≥2 functions) ·
**Critical Action** (1 function) · **Critical Permission** (*"certain permissions
(authorization objects) that are considered critical on their own"*).

```
Rule Set  (container; risks assigned TO rule sets, many-to-many)
  └─ Access Risk    4-char ID · Type · Level · Business Process · Owner
       ├─ Function  ─ Action      = tcode / Fiori app / OData service
       │             └─ Permission = auth object + field + value,
       │                             ATTACHED TO AN ACTION
       └─ Function  (≥2 for SoD)
                    ↓ GRAC_GENERATE_RULES
            Generated Rules — the Cartesian product actually evaluated
```

**The correction: Permission is not a sibling of Action. It hangs off one.**

`verified` — §8.2.2.2.1.1: *"The Permissions screen appears, displaying the
permissions (authorization objects) **for all of the actions that have been
added to the function**."* And the **Caution**: *"This screen allows you to
further restrict the access defined in the permission object. **You cannot
expand the access or reconfigure the permission object.**"*

`inferred` — permission maintenance is **monotonically narrowing**, and the
proposal set comes from **SU24**. Therefore the ruleset's permission layer is
downstream of SU24 quality: a badly maintained SU24 silently caps what a ruleset
can even express. Our own ruleset, which states object/field/value directly and
does not inherit from SU24, is *structurally* free of that ceiling — worth
saying out loud.

### The combinatorics are brutal and bounded

`verified` — SAP's own example (§8.2.1.3): a risk with functions of 21, 46 and
34 actions across three systems *"translates to **98,532 distinct rules**
(21x46x34x3)"*. Maximum **1,679,615** rules per risk — which is 36⁴−1, a 4-char
base-36 ID space, and is reachable by three functions of ~120 actions on one
system.

⚠️ `verified` — **a defect in SAP's own documentation**: the preceding example
says two functions × five actions × two systems = *"20 distinct rules"*. Under
SAP's own multiplicative model that is 50. Build against the model, not the 20.

---

## 3. Why object level matters — the worked case

`verified` — the objects behind PO maintenance: `M_BEST_BSA` (document type,
`BSART`) · `M_BEST_EKG` (purchasing group) · `M_BEST_EKO` (purchasing org) ·
`M_BEST_WRK` (plant, `WERKS`) · `M_BEST_LGO` (storage location). `ACTVT`:
`01` create · `02` change · `03` display · `06` delete. `S_TCODE` is only a
*start* authorization.

Risk: *Create PO* ∧ *Post Goods Receipt* (`ME21N` ∧ `MIGO`).

| User | `S_TCODE` | `M_BEST_WRK` | GR plant | Verdict |
|---|---|---|---|---|
| A | both | `ACTVT=03`, `WERKS=*` | `01`/`1000` | **False positive** — display only |
| B | both | `ACTVT=01`, `WERKS=1000` | `01`/`2000` | **False positive** — disjoint plants |
| C | both | `ACTVT=01`, `WERKS=1000` | `01`/`1000` | **True positive** |

Action-level analysis flags all three identically. B is the org-level case: the
fraud path needs the *same* plant, and "remediating" B strips access that was
never a risk.

**Two failure directions, and the second is worse.** False positives come from
transactions present without authority. **False negatives** come from authority
present without the transaction — reachable via `SE16`/`SM30`/`SE38`, a custom
`Z` transaction, a parameter transaction, a Fiori app, an OData service, a
background job step under another user, or an RFC destination with stored
credentials. None appears in `S_TCODE`.

---

## 4. The hard problems, ranked by how much they invalidate a report

### 4.1 Fiori and S/4HANA — the largest structural gap in current tooling

`verified` — SAP's scope table: Fiori **Catalog** `[FCAT]` has **no standard
ruleset**. And `asserted` from an SAP-authored blog, the critical asymmetry:

> *"**The SAP Fiori APP[FAPP] will not have any permissions. The permissions are
> associated with Service[SVC].** If you only add SAP Fiori APP in the action's
> tabs, the permission tab will be empty."*

- FAPP vs FAPP → **action-level risk only**
- SVC vs SVC → action **and** permission level
- FAPP+SVC → granular, but *"you need to **manually copy and paste** the
  permission of the Service"*

`inferred` — **Fiori-app-level SoD reproduces transaction-code-level SoD's
weakness, one abstraction layer up.** Doing it properly means resolving
app → OData service → back-end authorization objects. Start authorization
objects: `S_SERVICE` (field `SRV_NAME`) for OData, `S_START` for Web Dynpro.
Tile visibility ≠ authorization — removing a tile leaves the endpoint callable.

`inferred` — a GRC 12.0 install that never activated `GRAC_RA_RULESET_S4HANA_ALL`
and never added the second connector **reports SoD on S/4HANA while blind to
every Fiori-initiated action.** One of the most common causes of a green report.

### 4.2 Generic table access defeats transaction-keyed rules entirely

`verified` — `S_TABU_DIS` (fields `DICBERCLS`, `ACTVT`; groups in `TDDAT`) and
`S_TABU_NAM` (fields `TABLE`, `ACTVT`). SAP Note **1541577** is titled *"Impact
of S_TABU_NAM in Risk Analysis and Remediation"* — **SAP conceding the object
breaks existing rulesets.**

`asserted` (two independent practitioners) — the two objects are evaluated as a
logical **OR**. `inferred`: a ruleset modelling only one misses everything
granted via the other.

**Worked bypass:** the rule *Maintain Vendor ∧ Post Invoice* is `FK02 ∧ FB60`.
A user with `SE16` + `S_TABU_DIS ACTVT=02, DICBERCLS=*` edits `LFA1`/`LFBK`
directly — the "maintain vendor" half **without ever holding `FK01`/`FK02`**.
The rule never fires.

`asserted` — `&NC&` is the fallback group for unclassified tables, so **every
custom `Z*` table lands there**; one `DICBERCLS=&NC&` grant exposes the whole
custom data model. Group `MA` alone holds *"more than six hundred tables."*

### 4.3 Technical identities carry the other half of the conflict

`verified` — *"By default, a job runs under the authorizations of the user who
scheduled it"*, but `S_BTCH_NAM` (field `BTCUNAME`) lets a step run **as someone
else**. SAP: *"You should give this authorization to the batch administrator
only."*

`inferred` — a clerk with `FB60`, `SM36` and `S_BTCH_NAM BTCUNAME=BATCH_FI`
(where `BATCH_FI` holds `F110`) posts the invoice and schedules the payment.
**User-level SoD sees the two halves in two identities and reports nothing.**

`verified` — `S_RFCACL` is deliberately **excluded from `SAP_ALL`**, and SAP
warns *"individual users might be misused as anonymous users to perform actions
in the target system."* An SM59 destination with stored credentials is a
privilege capsule: the caller needs only `S_RFC`.

`verified` — **reference users** are a user-master attribute, CUA-propagated.
`inferred` — **their authorizations are not role assignments**, so any engine
building its picture from `AGR_USERS` alone misses them entirely.

### 4.4 The four analysis levels give four different answers

`verified` — GRC ships **User / Role / Profile / HR Object** level as separate
reports, crossed with **Action / Permission / Critical Action / Critical
Permission / Critical Role-Profile**, three views and four formats.

`inferred` — they cannot agree by construction. **Role level cannot see a
conflict formed by combining two clean roles, which is the normal shape of a
real violation.** It is favoured because it is cheap and produces smaller
numbers — which is also why it is the level most often quoted to auditors.
**Reporting one level and calling it "the SoD position" is the failure.**

`inferred` — **mitigation at role level masks user-level conflicts**: attach one
control to a role and every current *and future* holder reads as mitigated.

### 4.5 The report is silently filtered by whoever ran it

⚠️ `verified` — nearly every SAP AC report carries this note verbatim:

> *"**Report Details** — The application displays only objects that you are
> authorized to see. For example… you may only see the data related to North
> America, if you are only authorized to see North America."*

`inferred` — **a SoD conflict report is silently scoped by the running user's
own authorizations.** Two people run "the same report" and get different
populations, and neither report says so. In SAP AC, *who ran it* is a
**completeness** attribute, not merely provenance. This is a first-order IPE
finding, stated by the vendor.

### 4.6 Custom code has no authorization guarantee

`verified` — SAP: *"**It is therefore the programmer's responsibility** to check
that every user who can call the program is also authorized"* and *"in ABAP
programs, **SQL Statements do not trigger authorization checks in the database
system.** Thus, Open SQL and Native SQL statements allow unrestricted access to
all database tables."*

`inferred` — `ZPO_CREATE` calling `BAPI_PO_CREATE1` with no `AUTHORITY-CHECK`
defeats both the action-level rule (wrong tcode) and the permission-level rule
(object never checked).

### 4.7 SU24 amplifies both error directions

`verified` — `SU24` maintains `USOBT_C`/`USOBX_C`; *"Only these customer default
authorization values are applied when PFCG is used."* And ⚠️ *"**The system
overwrites tables USOBT_C and USOBX_C when it executes step 1** [of SU25], and
the values that you maintained in the last release are lost."*

`inferred` — check indicator set to "no check" → false negative while the
transaction still works. Over-broad proposals (`*` in `ACTVT` or an org field) →
false positives *and* a real unintended capability. SU24 unmaintained for `Z*`
→ the same custom transaction carries different object sets in different roles.

---

## 5. Critical access is a different analysis, not half a conflict

`verified` — SAP's distinguishing sentence: *"This is different from segregation
of duties risks in that **the person only needs to have access to a single
function**."*

| | SoD | Critical access |
|---|---|---|
| Predicate | ∃ a ∈ Fn₁, b ∈ Fn₂ with intersecting org scope | ∃ a ∈ Fn₁ |
| Remediation | Split duties | Remove, or wrap in monitored emergency access |
| Mitigation | Detective control over the specific pair | Usually **not mitigable** |
| Org rules | Applicable, often necessary | **Mostly inapplicable** |

`inferred` — **debug-replace, `SAP_ALL` and generic table write grant both
halves of *every* conflict simultaneously**, without appearing in `S_TCODE` for
any business transaction. Modelling them as SoD legs understates them by an
order of magnitude.

`verified` — SAP's own critical-access catalogue (EarlyWatch Alert – Security):
`SAP_ALL` holders · **`S_DEVELOP` with `ACTVT=02` and `OBJTYPE=DEBUG`** ·
users who can change/display all tables via `SE16`/`SE16N`/`SE17` *"(or any
corresponding parameter transaction)"* · users who can start all reports · RFC
administrators · default passwords on standard users.

`verified` — debug-replace semantics: `S_DEVELOP` + `OBJTYPE=DEBUG` +
**`ACTVT=02`** = *"This activity allows editing values of variables in the ABAP
debugger."* `inferred` — the `/h` + `sy-subrc` flip happens **after** the
`AUTHORITY-CHECK` has run, so no authorization object, org level or SoD rule can
constrain it.

`verified` — **Critical Roles and Critical Profiles are a third mechanism**
because `SAP_ALL` is a *profile, not a role*. Analysis driven off `AGR_USERS`
misses it entirely.

---

## 6. Mitigating controls — the word does not mean what practitioners think

`verified` — **PCAOB AS 2201 ¶.68**: *"**To have a mitigating effect, the
compensating control should operate at a level of precision that would prevent
or detect a misstatement that could be material.**"* Exhaustive term counts over
AS 2201: "compensating" **2** (both in ¶.68), "mitigating" **1**,
"complementary" **0**.

`verified` — the **ISACA Glossary has no entry for "mitigating control."**
COSO's phrase is *"alternative control activities."*

| Term | Home | Denotes |
|---|---|---|
| **Compensating control** | PCAOB, ISACA | A control **credited in the severity evaluation**; must be tested |
| **Mitigating control** | **SAP GRC product vocabulary** | A row in a table linked to a risk ID and an assignment |
| **Alternative control activity** | COSO | What management designs when SoD is impractical |

**A SAP "mitigating control" is a row; a "compensating control" is an audit
conclusion. Nothing makes the former produce the latter.**

`verified` — SAP's model: controls assign to **users, roles, profiles or HR
objects**, with **Valid From / Valid To**, monitors and approvers. Six
assignment objects, including **User/Role for Organization Rules**.

⚠️ `verified` — **`GRAC_MITIGATE` appears zero times** in SAP's 274-page
Application Help. Do not cite it as a transaction code.

⚠️ `verified` — the **Invalid Mitigation Monitors checkbox is off by default**:
*"If you do not select this checkbox, the report shows the Control ID Status. It
will not show the Monitor Status."* A shop running these reports without ticking
it sees green Control IDs while the monitors are expired, deleted or locked.

`verified` — the rubber stamp ships as configuration: MSMP settings
**`Approve Despite Risk`** and **`Risk Analysis Mandatory`**.

`verified` — the circularity, from **Blount International's FY2014 10-K**:
*"**Many of the Company's mitigating and compensating controls… rely on
information produced and maintained within the SAP system, and therefore such
controls were also ineffective due to the pervasive impact of ineffective
ITGCs.**"* A compensating control whose evidence is an SAP report inherits that
report's IPE problem.

---

## 7. What auditors actually require

`verified` — **AS 2201 ¶.64**, the single most important sentence for this work:

> *"**The severity of a deficiency does not depend on whether a misstatement
> actually has occurred** but rather on whether there is a reasonable
> possibility that the company's controls will fail to prevent or detect a
> misstatement."*

`verified` — the empirical proof, **Paragon Offshore Q1 2015 10-Q**: SAP SoD
material weakness where *"**This control deficiency did not result in any
adjustments** to the consolidated financial statements… However, the deficiency
could result in misstatements."*

`verified` — **AS 2201 ¶.69's four indicators of material weakness are: senior-
management fraud, restatement, auditor-identified material misstatement,
ineffective audit-committee oversight. None is an SoD conflict.** SoD reaches
material weakness through ¶.63 likelihood/magnitude and the ¶.70 prudent-official
test — not the indicator list. Do not claim otherwise.

`verified` — sign-off is not evidence, stated in 2013 and **restated verbatim in
December 2023**: *"Verifying that a review was signed off provides little or no
evidence by itself about the control's effectiveness."*

Evidence an auditor asks for maps to named SAP artefacts — Access Rule Summary
and Detail Reports, User to Role Relationship, the four Risk Violation reports
*with their flag settings recorded*, Mitigated Object Report, **User/Role Level
Invalid Mitigations with the monitor box ticked**, UAR and SoD Review History,
Requests with Conflicts and Mitigations, the Firefighter log set, PFCG Change
History, and the three coverage-gap reports in §1.2.

---

## 8. What could not be established

- **SAP publishes no ruleset counts.** Not in the Application Help, the
  Administrator Guide, the product page or any reachable KBA. The widely-quoted
  **206 risks / 198 functions / 14 processes** comes from **one** practitioner
  analysis and could not be corroborated. Do not present it as an SAP figure.
- **SAP Note bodies** are login-gated. Notes cited *by SAP's own public docs*
  and therefore verified-by-citation: 65968, 101146, 987031, 1481950, 1541577,
  2655122, 2975653, 3226223, 3430610, 3469294, 3458015.
- **GRC ruleset table names** (`GRACSODRISK`, `GRACFUNC`, `GRACFUNCACT`,
  `GRACFUNCPRM`) are consistent across practitioner sources but unconfirmed from
  an SAP-hosted page.
- **No published guidance exists on SoD ruleset validation or benchmarking**, or
  on whether external auditors accept, test or substitute a client's ruleset.
  The standards logic compelling validation is established; actual practice is
  undocumented. **This is the gap §1.3 proposes to occupy.**
- **No formal standards distinction between "compensating" and "mitigating"** —
  confirmed absent from AS 2201, COSO's Executive Summary and the ISACA
  glossary. COBIT 2019 and ISACA's ITAF were not searched.
- **No delivered SAP SoD content for S/4HANA Cloud Public Edition.**
  `GRAC_RA_RULESET_S4HANA_ALL` is explicitly on-premise. Do not assert one
  exists.
- ISACA/IIA audit programs, Big Four methodology papers and academic sources
  were largely unreachable; the web-search budget was exhausted. A genuine gap,
  not a null result.
