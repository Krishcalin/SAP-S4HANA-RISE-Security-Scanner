# RISE with SAP — Security Model, and What an Offline Scanner Can Actually Reach

**Status:** research synthesis, 2026-08-05, after an adversarial verification pass. Sourced
primarily from SAP's own contract and support documents. Every claim carries its source; claims
resting on third-party summaries are labelled and must not be repeated as fact.

**Why this document exists.** The product is being pivoted to a client-server platform for
S/4HANA Cloud Private Edition (PCE) customers. Every scoping decision — which checks are worth
running, which findings are actionable, what the remediation text should even *say* — depends on
where SAP's contractual responsibility line sits. This is that line, read from the documents
rather than from vendor marketing.

**Evidence labels.**

| Label | Meaning |
|---|---|
| **[SAP-primary]** | Read from an SAP-published document or SAP-maintained repository |
| **[SAP-named]** | Named inside an SAP document; the artifact itself was not read (login-gated Notes) |
| **[vendor]** | A competitor's or consultancy's assertion. Signal, not fact. |
| **[unverified]** | We saw the string but could not confirm the specific claim — do not ship |

---

## 0. ⚠️ Read this before citing any line-item ID

An adversarial verification pass downloaded the R&R PDFs and **proved that the line-item ID column
drifts against the description and category columns during text extraction.**

Hard proof: in the tailored v3-2025 text, one row extracts as
`BASIC 1.2.16 | Define and implement security concept for application | Excluded Tasks` — but
`BASIC_1.2.16` is *"Provide access to client 000"* in the PCE document. The next extracts as
`BASIC_1.2.21 | Analyze the SAP system and identify relevant SAP security notes`, a different task
again.

> **The task descriptions and the categories are correct as text. The ID-to-task pairing is an
> extraction artifact.**
>
> Every `BASIC_*`, `INFRA_*`, `HANA_*`, `TO_NWABAP_*` and `CAS_*` identifier in this document is
> **UNVERIFIED as a pairing** and must be confirmed by eye against the rendered PDF before it
> appears in any customer-facing artifact or is used to tag a check. Two IDs cited in earlier
> research are absent from v7-2026 entirely: `TO_NWABAP_1.1.19` and `BASIC_1.2.30`.
>
> This matters because the obvious next move — tagging each of our 819 checks with the R&R task
> it discharges, so the report answers *"why am I paying you when I pay SAP?"* with SAP's own
> classification — is a **good idea executed on unsafe data.** Do it, after eye-verification.
> Shipping wrong contract citations is precisely the SAP-identifier credibility failure this
> project has already suffered once.

**Second correction: two different contracts were conflated.** This document draws on both
**S/4HANA Cloud Private Edition (PCE)** and the **tailored option**, and they use *different
category vocabularies* — verified by counting: PCE v7-2026 contains "Packaged Services" 205 times
and "available at additional charge" once; tailored v3-2025 contains "Packaged Services" **zero**
times and "CAS available at additional charge" 316 times.

> **The five-category model below is PCE vocabulary and does not transfer.** Any responsibility
> matrix we ship must be **tenant-configurable**, not hard-coded.

---

## 1. What RISE is, and Private vs Public edition

RISE with SAP is a subscription bundle: the S/4HANA licence, infrastructure in an SAP data centre
or on a hyperscaler, and SAP-operated technical managed services, sold as one contract. The
security-relevant question is not what is in the bundle but **which layer the customer still
touches.**

| Dimension | S/4HANA Cloud **Private** Edition (PCE) | S/4HANA Cloud **Public** Edition |
|---|---|---|
| Tenancy | Single-tenant | Multi-tenant |
| Classic ABAP / modifications | Retained — customer may develop ABAP add-ons and modifications | Not available; extensions are BTP-side only |
| Upgrade control | Deferrable | Mandatory, twice yearly |
| Custom code security | Customer's, with an explicit SLA carve-out in the Supplement | Largely moot — little classic custom code exists |
| Security Audit Log configuration | Customer-owned | Reduced to "Application Logs" on the customer side |
| Application change management | Customer-owned | Largely SAP-side |
| OS / infrastructure hardening | SAP's | SAP's, **plus** more of the platform layer |
| **Consequence for us** | **Large customer-owned surface. This is the product.** | **Little for a config scanner to say. Out of scope.** |

The split is drawn from an SAP-authored shared-responsibility deck (pp. 13–14), which lists
customer scope for RISE Private as including Application User Identity Management, Authentication
and Authorisation Management, Roles / User Groups / Access Control, Customer Data Ownership,
Compliance, **Application Security Audit Logging (SAL)**, Integration and Extensions, **Custom
Applications Development**, Configuration of Customer Business Processes, and Application Change
Management. For GROW (Public) the customer list is narrower and SAP additionally owns "Hardening
and Patching Operating Systems" and "Securing the infrastructure, operating systems, and
networking, and applications". **[SAP-primary]**
`https://assets.dm.ux.sap.com/webinars/sap-user-groups-k4u/pdfs/240215_shared_responsibility_in_sap_s4hana_cloud.pdf`

> **Scoping decision.** Every scoping and marketing statement must say **S/4HANA Cloud Private
> Edition (and SAP ERP, PCE)** explicitly, and the tool should say so in its own output. A report
> that silently assumes PCE and is run against a Public Edition tenant is mostly noise.

**Caveat we could not close:** no task-level Roles & Responsibilities document exists publicly for
Public Edition. The comparison rests on SAP's deck plus secondary commentary.

---

## 2. The shared responsibility matrix as published

### 2.1 The authoritative artifact

SAP publishes a **Roles and Responsibilities ("R&R")** catalogue as the Documentation of record,
versioned roughly quarterly, at
`https://assets.cdn.sap.com/agreements/product-policy/hec/roles-responsibilities/`. SAP states the
PDF is the Documentation of record and that non-PDF renderings "shall not be considered
Documentation." **[SAP-primary]**

| Version read | Pages | Note |
|---|---|---|
| v7-2021, v3-2022 | — | key clauses unchanged from 2021 |
| tailored option v3-2025 | 59 | ~1,423 numbered task rows |
| **PCE v7-2026** | 56 | 2026 edition drops the "RISE with" prefix; also covers SAP Business Data Cloud |

**It is not a RACI.** It is a five-category service catalogue **[SAP-primary]**:

| Category | Meaning |
|---|---|
| **Standard Services** | SAP performs it, covered by the subscription fee |
| **Optional Services** | SAP only, extra fee, must be contracted |
| **Additional Service** | SAP only, one-off, extra fee |
| **Packaged Services** | *The customer performs it* — unless they buy the package from SAP |
| **Excluded Tasks** | Only the customer can do it; excluded from every SAP service tier |

Counts, independently re-verified:

| Document | Excluded Tasks | CAS at additional charge | Standard | Optional |
|---|---|---|---|---|
| tailored v3-2025 | ~195 | 316 ✓ | ~515 | ~84 |
| **PCE v7-2026** | **146 ✓** | — ("Packaged Services" ×205) | — | — |

Catch-all clause: *"All tasks and work efforts not purchased by customer or not provided [by] SAP
as part of the standard service but applicable to customer and its Computing Environment are the
responsibility of customer."* **[SAP-primary]**

> **Design consequence.** Our responsibility tag must be **four-state**, not binary: customer-owned
> (Excluded) · customer-owned-unless-purchased (Packaged) · SAP-with-customer-request (Standard but
> ticket-driven) · SAP-only. A binary customer/SAP flag misrepresents the Packaged category — which
> is exactly where SAP's own paid competitors to us sit.

### 2.2 The matrix

"Customer can act" is the column that decides how a finding renders.

| Domain / task, as worded in the R&R | Category | **Customer can act?** | ID (pairing [unverified]) |
|---|---|---|---|
| Create and maintain OS users and groups | Standard | **No** — *"Service provider access only, no privileged access to operating system by customer"* | INFRA_1.6.01 |
| Assist customers with tasks where OS access is required | Standard | **No** — *"Customers will not get OS access to managed servers within cloud"* | BASIC_1.1.14 |
| Configure OS parameters; troubleshoot OS; monitor system log and file systems | Standard | **No** | INFRA_1.6.05 / .06 |
| Maintain application / system profile parameters — static and dynamic | Standard | **Read-only → ticket.** SAP adjusts "by customer request except for certain standardized settings required to maintain system stability or security" | BASIC_1.1.16 |
| Maintain user profiles, roles, authorizations, passwords **in client 000** | Standard | **No** | BASIC_1.2.15 |
| Provide access to client 000 for customer | Standard | **Negotiated** — *"Restricted, predefined profile only; limited set of users provided; service provided on request only"* | BASIC_1.2.16 |
| Administer users (create / change / delete / lock / unlock) | Packaged | **Yes** | BASIC_1.2.18 |
| Administer roles — role creation and role change | Packaged | **Yes** | BASIC_1.2.18A |
| Definition, maintenance, review and audit of roles, profiles, authorizations | Packaged / CAS | **Yes** | BASIC_1.2.17 |
| Customer-specific Security Audit Log analysis | Packaged / CAS | **Yes** | BASIC_1.2.19 |
| Provide audit log information to customers | Standard | **Negotiated — wording differs between document variants; see §6.1** | BASIC_1.2.21 |
| Analyze the SAP system and identify relevant SAP security notes | Standard in one variant, Packaged in the other | **Varies — check the customer's contract** | BASIC_1.2.20 |
| Implement SAP Security Notes — Basis / ABAP related | Standard | **No** (SAP does it) — but only *"without manual activities"* | BASIC_1.2.27 |
| Implement relevant SAP Security Notes — Application related | Packaged / CAS | **Negotiated** — *"Testing of implemented Notes is Customer's responsibility"* | BASIC_1.2.28 |
| Update Global Change parameters (SE06) and default system settings (SCC4) | Standard | **No → ticket** | BASIC_1.2.26_AE |
| Configure SAP-delivered UCON CA for client 000 | Standard | **Yes for business clients** — *"Customer owns the configuration of UCON (via T-code UCONCOCKPIT) from Business Client"*; the SAP-delivered allowlist needs a service request | BASIC_1.2.37 |
| Review and optimize customer code | **Excluded** | **Yes — only the customer** | BASIC_1.7.08 |
| Define and implement security concept for application | **Excluded** | **Yes — only the customer.** SAP does not do this at any tier | BASIC_1.2.22 |
| Single Sign-On design and implementation | **Excluded** | **Yes — only the customer** | BASIC_1.2.24 / .25 |
| Enable LogServ (infrastructure + application logging service) | Optional (paid) | **Negotiated — costs money** | BASIC_1.2.33 |
| LogServ activities on customer SIEM; activities within customer SIEM / SOC | **Excluded** | **Yes — only the customer.** SAP excludes correlation-rule creation, alert tuning, incident response, threat hunting, offence monitoring | BASIC_1.2.34 / .36 |
| Enable RAVEN within SAP-delivered systems | Optional (paid) | **Negotiated** — SAP's own security monitoring / vulnerability assessment service; telemetry lands in SAP's portal | BASIC_1.2.35 |
| Application Security Monitoring; SoD check and risk report; regular security audits; Security for Interface (RFC hardening) | Packaged / CAS | **Yes, or pay SAP** — SAP competing directly in our footprint | BASIC_1.2.31 / .32, CAS_2.2.01 / .03 / .04 / .05 |
| Transfer and release of transport orders; execute transports | Packaged / CAS | **Yes** | TO_NWABAP_1.5.02 / .03 |
| Testing and acceptance of object changes | **Excluded** | **Yes — only the customer** | TO_NWABAP_1.5.09 |
| Transport domain, transport directory, initial TMS setup and routes | Standard | **No** — "limited to a default setup" | TO_NWABAP_1.5.10 / .15_AE |
| Deactivate critical ICF services in the ABAP instance | Standard | **No → ticket** | TO_NWABAP_1.1.32 |
| HANA user / role / permission management — **technical and administration** users | Standard | **No** | HANA_1.1.19 |
| HANA user / role / permission management — **non-technical** users | Packaged | **Yes** — *"Customer has ownership and responsibility for SAP HANA role CUST_USER_ROLE_ADMIN"* | HANA_1.1.18 |
| HANA technical configuration parameters; encryption at rest; software updates; backups | Standard | **No** | HANA_1.1.08 and related |
| Implementation of patches for system software at OS level, e.g. SAP kernel | Standard | **No** | BASIC_1.5.06 |
| Install new entities (add-ons, content packages) after handover | Standard | **Negotiated** — *"Contractual Change Request required in case of changed managed service scope or increased infrastructure consumption"* | BASIC_1.5.13 |
| Homogeneous system copy / refresh | Standard | **N/A** — *"Does not include activities such as data masking, scrambling etc."* | BASIC_1.3.10B and related |

### 2.3 The one claim that is fully solid

*"Customers will not get OS access to managed servers within cloud"* and *"no privileged access to
operating system by customer"* appear **verbatim in both** the PCE v7-2026 and the tailored v3-2025
PDFs, and in the earlier 2021 and 2022 editions. Stable across document versions and contract
variants. **[SAP-primary]**

This is the load-bearing fact of our architecture and it is safe to state without hedging.

### 2.4 SAP's own monitoring of S/4HANA covers client 000 only

The SAP-authored shared-responsibility deck, "Security Monitoring & Forensics" row for RISE
Private, lists under SAP: maintain 24x7 security monitoring, collect and correlate platform logs,
define security use cases for automatic alerting, maintain the SIEM platform — *followed by*
**"Monitoring in S/4 HANA is limited to client 000."** The customer side of the same row reads:
*"Responsible for reviewing security audit logs such as technical user level logins and retrieval
of such logs via API"* and *"Review of logs such as Change documents, Read access logs,
Authorization trace logs, SAP support user request logs."* **[SAP-primary — deck p.19]**

Client 000 holds no business data and no business users. Every productive client — where the data,
the users and the fraud risk live — sits outside SAP's monitoring.

Label the evidence class honestly: an **SAP-authored slide deck marked Public, not contract text.**
Strong and citable. Not a clause.

> **Consequence.** The scanner must be **client-aware**. Findings are reported per client; client
> 000 findings are de-prioritised and marked provider-owned.

### 2.5 The customer is structurally read-only on profile parameters

SAP is responsible for executing parameter maintenance "as it can have an impact on system
performance and availability", providing recommendations and adjusting "by customer request except
for certain standardized settings required to maintain system stability or security."
**[SAP-primary]** Independently, SAP KBA **3460793**, *"[ECS] Cannot modify Default Profile in
transaction (RZ10) in Business Clients"*, documents the symptoms *"Client 100 lacks authorization
to execute this action. Changes cannot be saved"* and *"Could not store profile data in database"*,
scoped to ECS / RISE PCE. **[SAP-primary — KBA preview]**

> **This is the product insight.** In RISE the customer can *see* a bad parameter and cannot fix
> it. Remediation is a ticket to SAP.
>
> 1. Parameter findings must render as **"raise with SAP"** with pre-drafted ticket text naming
>    the parameter, current value and target value — never as "change this".
> 2. The mitigation journey needs a **third state** between open and closed:
>    **`submitted_to_provider`**. Without it, every parameter finding sits open forever and the
>    burndown chart lies.

### 2.6 Security patching is customer-initiated by contract

Supplement §3.3.3: *"Customer is responsible for requesting and coordinating with SAP the
application of security patches (all security patches with priorities 'critical,' 'high,' 'medium,'
or 'low') by way of a service request ticket. Such patches will be applied during Scheduled
Downtime or other Agreed Downtime."* **[SAP-primary]**

This sits in visible tension with §3.3.1, in which SAP performs monthly scheduled maintenance
"including OS security patch levels, database and application patches". SAP does not reconcile the
two.

Note implementation of Very High / High notes is conditional on the customer having agreed to a
standard change process — *"Customers who do not agree to a standard change process will be
informed about available security notes but implementation and transport need to be extra triggered
via ad hoc service request."* Testing is always the customer's. **[SAP-primary — wording]**

> **Consequence.** Note *identification* may already be covered, so "we find your missing notes" is
> a weak pitch. The defensible ground is **verifying the note actually took effect**, including its
> manual configuration steps. Remediation text must say *"raise a service request"*, never *"apply
> the note"*. Ask once whether the standard change process is signed and change the wording.

### 2.7 Third-party ABAP add-ons must go through SAP

Installing new entities — add-ons and content packages — after handover carries the remark that a
**contractual Change Request is required** where managed-service scope or infrastructure
consumption changes. The R&R also contains a third-party-solutions section stating such solutions
are not included in the baseline service, require an additional SKU and/or contract, and that
"technical and operational compatibility of every 3rd Party Solution with SAP has to be
individually checked by the customer", with install / configure / monitor / update / troubleshoot
of unmanaged ABAP add-ons marked as Excluded Tasks. **[SAP-primary — wording; section and row
numbers omitted deliberately, they are extraction-derived]**

> **Consequence.** "Nothing is installed in your SAP system" is a **first-class differentiator, not
> a footnote.** It also argues permanently against ever adding an ABAP agent to our own roadmap.

### 2.8 Where SAP's material is vague — say so, do not invent certainty

1. **Application security concept.** One row reads "Define and implement security concept for
   application — Excluded Tasks"; the row beside it reads "Define and implement application and
   infrastructure security concept — Standard Services". SAP does not explain the difference.
2. **Patching.** §3.3.1 versus §3.3.3, above.
3. **Scope is negotiated.** The R&R disclaims fixed scope: it is "a catalog of services", "the
   relevance and necessity of each individual task or service will be unique to each customer's
   Computing Environment", availability "may be limited for sandbox or other test environments",
   "Infrastructure related services may be different depending on deployed infrastructure platform
   (e.g. Hyperscaler)", and customers must confirm scope with an SAP Cloud Architect Advisor,
   Client Delivery Manager or the Private Cloud customer centre. **[SAP-primary]**

> **Product consequence.** Two customers on PCE can have different splits depending on which
> Packaged / Optional services they bought (CAS, LogServ, RAVEN) and which hyperscaler they run on.
> Make the responsibility mapping **per-tenant configurable**, and carry a plain-English caveat in
> the report that responsibility is contract-dependent. That caveat is a credibility asset with
> auditors, not a weakness.

---

## 3. What evidence a RISE customer can actually produce

**This table is the upload surface of the client-server product.** One row per data source our
loader consumes today.

**Reachable** legend: **Yes** = customer self-serves · **Read-only** = can export, cannot remediate
· **Partial** = obtainable but incomplete or mixed-ownership · **Ticket** = needs an SAP service
request · **No** = structurally unavailable.

| Data source (loader key) | How the customer produces it | Reachable | What blocks them |
|---|---|---|---|
| **Users** `users.csv` (`USR02`) | `SU01`; report `RSUSR002`; `SE16`/`SE16N` list download | **Yes** | Nothing. User administration is customer-owned in business clients. |
| **Profiles** `profiles.csv` (`USR04`) | `SE16` on `USR04`; `SUIM` | **Yes** | Nothing |
| **User→role** `user_roles.csv` (`AGR_USERS`) | `SE16` on `AGR_USERS`; `SUIM` | **Yes** | Nothing |
| **Role content** `role_auth_values.csv` / `role_tcodes.csv` (`AGR_1251`) | `SE16` on `AGR_1251`; `PFCG` per role | **Yes** | Volume only. **Our richest customer-owned source.** |
| **Role metadata** `role_details.csv` (`AGR_DEFINE`+`AGR_TEXTS`), `role_profiles.csv` (`AGR_1016`), `role_expiry.csv` | `SE16` | **Yes** | Nothing |
| **SU24 proposals** `su24_proposals.csv` (`USOBT_C`) | `SE16`; `SU24` | **Yes** | Nothing |
| **Standard users** `standard_users.csv` | Report **`RSUSR003`** | **Partial** | Cross-client by nature; client 000 access is restricted and on-request, so a customer may only evidence productive clients. **See §3.1.** |
| **Profile parameters** `security_params.csv` | Report `RSPARAM` / `RSPFPAR`; `RZ11` per parameter; `TU02` for change history | **Read-only** | SAP executes parameter maintenance; KBA 3460793 documents the customer unable to save in `RZ10` (§2.5) |
| **RFC destinations** `rfc_destinations.csv` (`SM59`/`RFCDES`) | `SM59`; or `SE16` on `RFCDES` | **Yes, mixed ownership** | Export contains SAP-managed technical/monitoring destinations the customer must not touch. **See §3.2.** |
| **RFC trust** `rfc_trust.csv` | `SE16`; trust-relationship display | **Yes** | Nothing |
| **ICF services** `icf_services.csv` | `SICF` | **Yes (read) / Ticket (fix)** | Deactivating critical ICF services appears as an SAP Standard task — the finding is real, the fix is a ticket |
| **UCON** `ucon_rfc_state.csv`, `ucon_http_allowlist.csv` | `UCONCOCKPIT` — RFC scenario function-module list; HTTP allowlist | **Yes** | Nothing. The R&R explicitly puts business-client UCON configuration with the customer. **Ingested since `modules/ucon_exposure.py`** — the gap this row carried is closed. |
| **Background jobs** `background_jobs.csv` / `_steps` (`TBTCO`/`TBTCP`) | `SM37`; `SE16` | **Yes** | Whether the customer's role includes job administration was not verified on a live tenant |
| **External OS commands** `ext_os_commands.csv` (`SM69`) | `SM69`; `SE16` on the command tables | **Yes (read)** | Definitions are ABAP-visible even though execution is at OS level. High value — see §4. |
| **Audit log configuration** `audit_config.csv` / `security_audit_log.csv` | **`RSAU_CONFIG`** (replaced `SM19` from SAP_BASIS 7.50 SP03); read via **`RSAU_READ_LOG`**; admin via **`RSAU_ADMIN`** | **Yes** | Nothing. **Disproportionately valuable in RISE** — see §4 and §6.1. |
| **Client settings** `client_settings.csv` (`T000`/`SCC4`); **system change** `system_change.csv` (`SE06`) | `SCC4`, `SE06`, `SE16` on `T000` | **Read Yes / Fix Ticket** | Global change and default system settings are SAP-executed |
| **Transports** `transport_history.csv`, `transport_routes.csv` | `STMS`; `SE09`/`SE10` | **Yes** | Transport domain, directory and TMS default setup are SAP's; content and routes are customer-side |
| **Custom code** `custom_code_scan.csv`, `code_inventory.csv`, `sap_modifications.csv` | ATC / Code Vulnerability Analyzer result export; `SE95` for modifications | **Yes** | Contractually 100% customer. Supplement §3.5: customer responsible for testing and resolving "security vulnerabilities or other conflicts"; "The SLA and Support Schedule shall not apply to any Customer ABAP Add-ons." **[SAP-primary]** |
| **Applied notes** `applied_notes.csv` | `SNOTE` status export; component and support-package levels | **Yes** | The note *catalogue* is behind SAP for Me — we can ship age/coverage logic, not live note data |
| **Table logging** `table_logging.csv` (`DD09L`) | `SE16` | **Yes** | Nothing |
| **Change documents** `change_documents.csv` (`CDHDR`) | `SE16` | **Yes** | Volume |
| **Fiori** `fiori_catalogs` / `_tiles` / `_spaces` / `odata_auth` / `_app_usage` | Launchpad designer exports; OData service catalogue | **Yes** | Nothing |
| **Business roles / CDS / OData v4 / CF roles** (`s4_business_authz` inputs) | S/4HANA business-role apps; service catalogue; `btp` CLI for CF roles | **Yes** | Nothing |
| **FI configuration** — posting periods, tolerance groups, dual control, doc change rules, number ranges | `SE16` on the customizing tables; the corresponding config transactions | **Yes** | Nothing. Pure application customizing. |
| **Read Access Logging / ILM / masking / residency** (`data_protection` inputs) | RAL configuration display; ILM policy export; the project's loader already accepts an `sralmanager.csv` alias for RAL config | **Yes** | Nothing structural |
| **Gateway ACLs** `gw_secinfo.csv` / `gw_reginfo.csv` | **Filesystem files** on the app server | **No (as files) / Partial (via `SMGW`)** | `secinfo`/`reginfo` are OS artifacts and the customer has no OS access. Re-source from the ABAP gateway monitor or accept the gap. |
| **Message server ACL** `ms_acl.csv`; **SAProuter** `saprouttab.csv` | OS-level files | **No** | Same OS constraint |
| **TLS / SNC / crypto library / PSE / certificates** | `SMICM`; `STRUST` for certificates and PSEs; crypto library is kernel-level | **Partial** | Certificate and PSE inventory reachable; ICM/SNC parameters and the crypto library are SAP-operated |
| **HANA parameters / encryption / audit policies** | HANA SQL system views | **Mostly No** | Technical HANA configuration is SAP's. Whether a `CUST_USER_ROLE_ADMIN` holder can read parameter system views **was not verified — test on a design-partner tenant.** |
| **HANA users / granted roles / privileges** | HANA SQL under `CUST_USER_ROLE_ADMIN` | **Partial** | Scoped to non-technical users; technical and admin users are SAP's |
| **BTP** — subaccounts, trust, destinations, role collections, entitlements, service bindings, Cloud Connector, CPI, IAS, Event Mesh, APIM | `btp` CLI (`btp list security/settings`, `btp get security/role-collection`); Authorization & Trust Management REST APIs; Cloud Connector `/api/v1/configuration`; audit log via `auditlog-management` at `/auditlog/v2/auditlogrecords` | **Yes — fully automatable** | Nothing. **The one area with real APIs and no SAP involvement.** **[SAP-primary]** |
| **GRC** `grac_*` | SAP GRC Access Control export | **Only if they own GRC** | GRC AC / Cloud Identity Access Governance are separate purchases, not part of RISE |
| **Infrastructure / OS / DB logs** | — | **No** | Routine access requires the paid **SAP LogServ** option. Microsoft's documentation states that in SAP RISE/ECS environments infrastructure and operating system logs "are owned and managed by SAP, and aren't accessible through the standard SAP application connector", and that a purchase order for LogServ must be completed. **[SAP-primary — Microsoft Learn]** |

### 3.1 Cross-client checks must not silently pass on partial data

Standard-user hygiene is cross-client by nature: `SAP*`/`DDIC`/`SAPCPIC` default passwords in *all*
clients, `TMSADM` existing only in 000, `EARLYWATCH`, client 066 removal. SAP's own baseline policy
`1ASTDUSR` checks exactly these, plus `login/no_automatic_user_sapstar='1'` and SUPER group
assignment. **[SAP-primary]**

In RISE a customer may only be able to evidence productive clients. **The importer must accept a
per-client scope declaration, and the report must distinguish "compliant in the clients we saw"
from "compliant."** Silently passing a cross-client check on partial data is a defect an auditor
can catch, and it is the kind that ends an engagement.

> **CLOSED** — `modules/client_scope.py` + `STDUSR-COV-001`. The scope is MEASURED rather than
> declared wherever `client_settings` (T000) was supplied: T000 names the clients that exist, the
> standard-user export names the clients we looked at, and the difference is the gap. A declared
> scope (`--clients 000,100`) stands in only where T000 is absent, and with neither the well-known
> clients 000/001/066 are the floor — every scope reports its `basis` so a measured one is
> distinguishable from an assumed one. `STDUSR-002` and `STDUSR-003` now carry the clients they
> were computed over, and `STDUSR-COV-001` arms the coverage gate when the scope is partial. On the
> bundled sample this fires: the standard-user export covers 000/001/066 while T000 lists
> 000/100/200/300, so the PRODUCTION client was the one nobody had looked at.

### 3.2 RFC destinations carry mixed ownership

An `SM59` export in RISE contains SAP-managed monitoring destinations. Flagging one as a customer
misconfiguration wastes their time and damages credibility on the first report. We need an
**ownership classification pass** — SAP-managed vs customer-managed, driven by naming pattern and
target host, confirmed once by the customer and persisted across scans. In the attack-path graph
these destinations still appear as edges (they are real trust relationships) but labelled
provider-controlled.

### 3.3 Adopt SAP's schema instead of inventing one

SAP maintains **`SAP-samples/frun-csa-policies-best-practices`** on GitHub under **Apache-2.0**
(header: "Copyright (c) 2020 SAP SE or an SAP affiliate company") — **260 XML policy files**: 97
baseline policies under `BaselinePolicies/SOS` (ABAP_ALL, HANA_ALL, JAVA_ALL, BTP_ALL, WEBDISP_ALL),
133 ABAP security-note policies organised by patch day, 23 HANA, plus `MiscPolicies` and an XSD
schema. Each policy is `<targetsystem>` → `<configstore>` → `<checkitem>` with SQL-style
compliant / non-compliant predicates. **[SAP-primary]**

| Policy file | Config stores referenced | Sample checks |
|---|---|---|
| `1APWDPOL.xml` | `ABAP_INSTANCE_PAHI`, `AUTH_SECURITY_POLICY` | `login/min_password_lng >= 0008` (as `lpad(VALUE,4,'0')`), `login/password_max_idle_initial`, `login/password_downwards_compatibility`; per-client `MIN_PASSWORD_LENGTH`, `MAX_PASSWORD_IDLE_INITIAL` |
| `1ARFCGW.xml` | `GW_SECINFO`, `GW_REGINFO`, `ABAP_INSTANCE_PAHI` | `gw/sec_info`, `gw/reg_info`, `gw/reg_no_conn_info`, `gw/acl_mode='1'`, `gw/monitor='1'`, `gw/sim_mode='0'` |
| `1ASTDUSR.xml` | `STANDARD_USERS`, `ABAP_INSTANCE_PAHI` | SAP\*, DDIC, SAPCPIC, TMSADM, EARLYWATCH status; SUPER group; `login/no_automatic_user_sapstar='1'` |
| `1ACRITA_CSTO.xml` | `AUTH_PROFILE_USER` (`PROFILE`, `USERNAME`, `USER_TYPE`, `STATUS`), `AUTH_PROFILE_USER_CHANGE_DOC` (`USER`, `ACTION`, `PROFILE`, `MODIFIED_BY`, `CD_HIST_DATE`) | `SAP_ALL` holders; recent `SAP_ALL` grants. Check IDs `CRITAU-A_a.1`, `CRITAU-A_a.2` |
| `2AAUDIT.xml` | `AUDIT_CONFIGURATION`, `AUDIT_CONFIGURATION_SLOT`, `ABAP_INSTANCE_PAHI` | `rsau/enable=1`, `rsau/integrity=1`, `rsau/log_peer_address=1`, `rsau/user_selection=1`, minimum 10 filter slots |
| `2ANETCF.xml` | `SICF_SERVICES`, `ABAP_UCON_HTTP_WHITE_LIST` | 27 checks deactivating services (webrfc, IDoc/IDoc_XML, bsp_veri, certmap, certreq, echo, sample paths) |

Check items carry `[p1-CRITICAL]` / `[p2-STANDARD]` tags. A `not_found="positive"` attribute
controls how *absent* data is rated — a real semantic that naive scanners get wrong.

**Three payoffs from adopting these names as our canonical import schema:**

1. Any customer already running Focused Run or Cloud ALM can hand us data in a shape we understand.
2. Our findings map **1:1 onto SAP's own baseline requirement IDs** (`PWDPOL-A`, `RFCGW-A`,
   `CRITAU-A`, `STDUSR-A`…), far more defensible in an audit than house-brand control names.
3. It is free, versioned, Apache-2.0 content we can **diff in CI on every release** rather than
   hand-maintaining — and SAP updates the note policies every patch day.

This directly mitigates this project's known failure mode: hand-authoring check content risks
inventing parameter names, note numbers and thresholds; deriving them from an SAP-authored
predicate does not.

**Where SAP's baseline is thin.** `BTP_ALL` in v2.4 contains **four** policy files against roughly
**29** for `ABAP_ALL`, and its network policy checks a single Cloud Connector `isHaActive`
parameter — no checks for subaccount security settings, destinations or trust configuration. BTP is
where the customer has full control and full API access and where SAP's free content is nearly
empty. **Mirror SAP's baseline for ABAP; spend our own check-writing effort on BTP.**

### 3.4 The SAP Security Baseline Template — free, anonymous, versioned

The ZIP at `support.sap.com/content/dam/.../Security_Baseline_Template_V2.zip` returns HTTP 200 to
an **unauthenticated** request (99,336,484 bytes; 545 entries; versions V2.0–V2.6 including point
releases V2.4.1 and V2.5.1). Current is **V2.6, 95 pages, dated 11-Jul-2025.** **[SAP-primary]**

Requirement IDs are `<mnemonic>-<technology>` where technology is **A**=ABAP AS, **J**=Java AS,
**H**=HANA, **O**=Other (Web Dispatcher, SAPGUI), **P**=BTP Platform. The 27 families: AUDIT,
AUTHASSIGN, CHANGE, CRITAU, DISCL, FEATAC, FILE, IDPROV, MSGSRV, NETCF, NETENC, NOTEST, OBSCNT,
PWDPOL, RFCGW, SCRIPT, SECSTO, SECUPD, SELFRG, SESS, SSO, STDUSR, TRACES, TRUST, USRCHAR, USRCTR,
USRTYP. Each requirement is marked **[Critical]**, **[Standard]** or **[Extended]**; SAP states the
Critical tier aligns with the EarlyWatch Alert Security chapter and with the Security Optimization
Service checks that drive an overall red rating.

Each version ships a `Configuration_Validation_Template` folder with importable transports,
`Target_System_*.dat` files named after check IDs, and customizing CSVs including
**`AUTH_COMB_CHECK_ROLE.csv` and `AUTH_COMB_CHECK_USER.csv`** — SAP's own critical-authorisation
combination lists, already in CSV, the exact format our loader reads.

> ⚠️ **Version trap.** The older public DAM link serves **V1.9**, which uses a *completely
> different* ID scheme (`I-1`…`I-13`, `C-1`/`C-2`, `S-1`…`S-10`, `O-1`…`O-8`, `X-1`). Anything
> mapped against V1.9 IDs will not line up with V2.6. Use V2.6 and **pin the baseline version in
> the product**, as we would a CIS benchmark version. The archive's `change_marker` PDFs are a
> free, precise diff of what SAP added between versions.

---

## 4. Scoping our 23 modules against RISE

> **The table below is the scoping AS IT WAS REASONED, on 2026-08-05, when there were
> 23 modules. There are now 38.** It is kept because the *justifications* are the
> value here — each verdict is argued from §2 and §3 of this document, and that
> reasoning does not expire when a module is added.
>
> **The live verdict for every module is `RISE_MODULE_SCOPE` in
> [`modules/coverage.py`](../modules/coverage.py)**, which the scanner actually
> reads. Where this table and that map disagree, the map is right. Do not
> re-derive a verdict from this table for a module added after the date above —
> derive it from §2 and §3 and record it in the map.
>
> The map carries 36 of the 38. The two it does not are `export_integrity` and
> `ruleset_coverage`, and they are left out on purpose: the first asks whether the
> customer's own export files could be read, the second asks how much of the
> estate our own segregation-of-duties ruleset can see. Neither audits the SAP
> system, so neither has a contractual owner to record. `tests/test_rise_module_scope.py`
> holds that split — every other auditor must have a verdict, and a new module
> either gets one or has to argue in writing that it belongs with those two.

Verdicts: **IN SCOPE** (customer-owned and actionable) · **PARTIAL / SPLIT** (mixed ownership, or
read-only) · **OUT** (SAP-operated; suppress or mark not-applicable) · **INFORMATIONAL** (real
finding, no customer action).

| # | Module | Primary inputs | RISE verdict | Justification from §2 |
|---|---|---|---|---|
| 1 | `user_auth_audit` | users, profiles, user_roles, auth_objects | **IN SCOPE** | User administration in business clients is Packaged/customer |
| 2 | `security_params` | security_params | **PARTIAL — read-only** | Parameter maintenance is SAP-executed; customer reads via `RSPARAM`, cannot save in `RZ10` (§2.5). Render as *ticket-to-SAP*. |
| 3 | `network_services` | icf_services, rfc_destinations, transports, audit_config | **PARTIAL** | ICF readable but deactivation is an SAP task; RFC destinations mixed-ownership (§3.2); audit config fully customer |
| 4 | `rise_btp_checks` | btp_trust, comm_arrangements, api_endpoints | **IN SCOPE** | BTP is customer-owned outright with published APIs |
| 5 | `iam_advanced` | role content, SoD, firefighter, reviews, expiry | **IN SCOPE — promote** | Roles and authorizations are the cleanest, highest-value customer-owned domain |
| 6 | `btp_cloud_surface` | subaccounts, destinations, entitlements, Cloud Connector, CPI, IAS | **IN SCOPE — flagship** | The only module automatable end-to-end with no SAP ticket, transport or ECS involvement |
| 7 | `integration_layer` | gw_secinfo/reginfo, IDoc, WS, OAuth, webhooks, APIM, CPI, topology | **SPLIT** | Gateway ACL **files** are OS artifacts → **OUT** in RISE; IDoc / WS / OAuth / webhook / CPI configuration → **IN SCOPE**. Never blend these into one finding. |
| 8 | `data_protection` | RAL config, ILM, masking, DPP, residency, sensitive fields | **IN SCOPE** | Application and process layer; read-access-logging and data-protection configuration are customer-owned |
| 9 | `code_transport` | client_settings, system_change, transports, custom code, modifications | **SPLIT** | `SE06`/`SCC4` → **ticket-to-SAP**; transport routes and content, custom code, modifications → **IN SCOPE** (Excluded Tasks = only the customer) |
| 10 | `log_monitoring` | audit_config, SAL, siem_config, retention, table logging, logon events | **IN SCOPE — promote** | SAL configuration is customer-owned and SAP does not routinely hand over log content. Proving the log is correctly configured *is* the customer's substitute evidence. |
| 11 | `fiori_ui` | catalogs, tiles, spaces, OData auth, app usage | **IN SCOPE** | Application layer; new S/4HANA attack surface with no legacy predecessor |
| 12 | `crypto_posture` | TLS, certs, SNC, crypto library, PSE, HANA encryption, key mgmt | **PARTIAL** | Certificate and PSE inventory reachable; ICM/SNC parameters, crypto library version and HANA encryption are SAP-operated → **INFORMATIONAL** |
| 13 | `hana_db_security` | HANA users, roles, privileges, parameters, audit policies | **MOSTLY OUT** | Technical HANA config, technical users, encryption and patching are SAP's. Only the **non-technical user / role / privilege** half is plausibly reachable via `CUST_USER_ROLE_ADMIN`, and that is **unverified on a live tenant**. Design for graceful degradation, not a wall of "unknown". |
| 14 | `sap_hotnews` | applied_notes, note catalogue | **IN SCOPE (identify) / ticket (fix)** | Exposure and testing remain the customer's even where SAP implements |
| 15 | `abap_authorizations` | role_auth_values, user_roles, security_params | **IN SCOPE** | Authorization content is customer-owned |
| 16 | `system_trust` | rfc_trust, ms_acl, saprouttab, standard_users, rfc_destinations | **SPLIT** | RFC trust and standard users → **IN SCOPE**; message server ACL and SAProuter route table → **OUT** (OS-level) |
| 17 | `grc_access_control` | GRAC exports | **IN SCOPE, conditional** | Customer-owned *if they own GRC* — but GRC AC / IAG are separate purchases not included in RISE. Skip cleanly when absent. |
| 18 | `role_governance` | role details, profiles, SU24 | **IN SCOPE** | Role design is customer-owned |
| 19 | `financial_controls` | posting periods, tolerance groups, dual control, doc change rules, number ranges | **IN SCOPE** | Pure application customizing — the least ambiguous customer ownership in the whole tool |
| 20 | `baseline_params` | security_params | **PARTIAL — read-only, strategically central** | Same read-only constraint as #2, but this is the module that scores against SAP's *mandatory* ECS hardening. Highest-value RISE report section despite being unfixable by the customer. |
| 21 | `s4_business_authz` | business roles, catalogs, restrictions, CDS, OData v4, CF roles | **IN SCOPE** | The S/4HANA business-role model is customer-owned |
| 22 | `access_risk_analysis` | SoD over role content, mitigating controls | **IN SCOPE — promote** | SAP sells SoD checking as a paid package, which validates the category and prices the alternative |
| 23 | `basis_job_command` | background jobs, job steps, external OS commands, users | **IN SCOPE — underrated** | Job and `SM69` command definitions are ABAP-visible. In a system where the customer has **no OS access**, an external OS command definition is a documented ABAP→OS bridge — a genuine attack-path edge worth surfacing prominently. |

**Rollup: 15 IN SCOPE · 7 PARTIAL/SPLIT · 1 mostly OUT.** Four of the PARTIAL/SPLIT modules carry
genuinely unreachable components (gateway ACL files, message server ACL, SAProuter route table,
HANA technical configuration), and two more (`security_params`, `baseline_params`) are fully
readable but entirely unfixable by the customer.

**Nothing needs deleting — but roughly a third of the tool needs re-labelling rather than running
unchanged.**

### 4.1 How to present findings a customer cannot act on

Three failure modes to avoid: reporting an SAP-owned setting as a customer failure; reporting it as
"unknown"; and hiding it so the report looks thinner than the risk.

The fix is a **remediation-owner dimension on every finding**, rendered differently:

| Class | Badge | Remediation text pattern | Severity treatment |
|---|---|---|---|
| **Customer-fixable** | *Yours to fix* | Concrete action plus transaction or table | Full severity; counts toward the score |
| **Ticket-to-SAP** | *Raise with SAP* | Pre-drafted service-request text: system, client, parameter, current value, target value, and the SAP requirement it derives from | Full severity, counted separately — time-to-fix depends on SAP's queue, so the FAIR remediation-effort model must differ |
| **Provider-owned** | *SAP's under RISE* | "No customer action. Shown for completeness and for your auditor." | Informational; excluded from the score |
| **Not assessable** | *Out of reach in RISE* | State the reason: "requires OS access, which RISE customers do not have" | Excluded from the score, but listed so the coverage map stays honest |

Two supporting requirements follow:

- **A deployment-mode switch (on-prem / RISE PCE)** that re-tags every finding's remediation owner
  and re-weights severity by fixability. Shipping the on-prem view into a RISE account is precisely
  the "report full of unactionable findings" failure this exercise exists to prevent.
- **A third mitigation state — `submitted_to_provider`** — between open and closed (§2.5).

---

## 5. What SAP already provides natively — overlap or complement

The honest scoping section. Ignoring it produces a pitch that dies in the first technical
evaluation.

| SAP capability | Included in RISE? | Verdict for us |
|---|---|---|
| **SAP Cloud ALM — Configuration & Security Analysis (CSA)** | **Yes, no extra fee** via Enterprise Support **[SAP-primary, ALM FAQ]** | **DIRECT OVERLAP — do not compete on collection.** SAP's own page names S/4HANA Cloud Private Edition support and lists config stores covering RFC destinations by type, standard users, `SAP_ALL` holders, security policy, audit log, UCON, Code Vulnerability Analyzer status, kernel, trusted systems, HTTP allowlists, plus the `SECREC_INDEX`/`SECREC_STATUS` compliance convention and a documented OData Analytics API. That is essentially our ABAP surface, free, for our exact target systems. **Make it an ingestion path.** ⚠️ *"Daily" collection is a secondary-source claim — the word does not appear on SAP's CSA content page. Do not state frequency as SAP-documented.* |
| **SAP Focused Run** | **No — separately licensed**, explicitly not in any SAP maintenance agreement **[SAP-primary, ALM FAQ]** | **COMPLEMENT — and our wedge.** The richest free policy content (the 260 GitHub CSA policies) *runs on Focused Run*, which most RISE customers do not own. We can execute SAP's own baseline policies against exported config for everyone who never buys it. |
| **SAP Solution Manager** | **Not licensed for RISE at all** **[SAP-primary, ALM FAQ]**; 7.2 mainstream maintenance reported to end 2027 **[secondary — do not quote the date to customers]** | **COMPLEMENT.** Customers with existing Configuration Validation setups will need a replacement — a migration window. |
| **EarlyWatch Alert (EWA)** | **Yes, free, weekly**, covered by the maintenance agreement | **PARTIAL OVERLAP.** Its security card genuinely covers default standard-user passwords, gateway and message-server security, weak password policy, software outdated beyond note support, `SAP_ALL` / debug-replace / change-all-tables holders, HANA `DATA ADMIN`, and audit log inactive or written to an insecure target. **[SAP-primary]** Weaknesses to beat: weekly; a **fixed, non-tunable** list (SAP's own material tells customers wanting their own policy to use Focused Run or Solution Manager); no history-based mitigation tracking; delivered as a document with no machine-readable export we could find; and the Security card requires a specific S-user authorization security teams frequently do not hold. **Not a data source.** |
| **Security Optimization Service (SOS)** | Free guided self-service | **CLOSEST ANALOGUE — know it to sell against it.** Point-in-time, no persistence, no trend, no quantification, no workflow, S-user gated. *"SOS tells you once; we track whether it got fixed"* is the comparison. |
| **Configuration & Security Analytics (Focused Run)** | Licensed separately | **SAP HANDS US THE POSITIONING.** SAP's own expert-portal page states that, like the complete CSA application, it *"is not meant to be an audit-proof tool by itself, and moving towards such more advanced use cases likely requires integration with software products designed for managing compliance."* **[SAP-primary]** `https://support.sap.com/en/alm/sap-focused-run/expert-portal/configuration-and-security-analytics.html` — SAP supplies the checks and states plainly that turning them into audit-grade compliance requires dedicated software. That is the layer we sell. It also sets the minimum bar for our exception workflow: policy, check ID, validity window, due date, ticket reference. |
| **Code Vulnerability Analyzer (CVA)** | **Fee-free only inside a purchased BTP ABAP Environment entitlement** — *not* free for RISE PCE generally **[corrected 2026-08-07]** | **REVISED — see [`CVA_MERGE_PLAN.md`](CVA_MERGE_PLAN.md).** Consuming the outcome is still the *first* move: an ATC/CVA export costs nothing and its findings are SAP's, so they carry no false positives. But the prior instruction ("DO NOT BUILD ABAP SOURCE SCANNING") rested on a licensing claim that is wrong, and on a "Cloud ALM CVA status store" for which no evidence could be found — treat that as **[unverified]** until an S-user confirms it. Customers without the entitlement have no CVA at all. What we build is not a better pattern matcher — SAP's is mature and ours is not — but the one thing an in-system ATC add-on structurally cannot do: run **offline over an abapGit export**, and join a code finding against the exposure surface (`code_inventory`, ICF, OData, Fiori) to say whether the defect is **reachable**. |
| **Enterprise Threat Detection (ETD)** | **No — paid add-on or SAP-run managed service** | **ORTHOGONAL, NOT A GAP.** Runtime log-based detection versus static posture from exports. Never build log streaming; that is a funded SAP product with a 24x7 SOC behind it. Position as complementary: our findings say which systems most deserve ETD coverage. |
| **GRC Access Control / Cloud Identity Access Governance** | Separate purchases | **REAL GAP, scoped carefully.** Neither Cloud ALM CSA nor EWA does SoD, and many mid-market RISE customers hold neither GRC product. Sane scope is **critical access and toxic-combination detection**, seeded from SAP's own `AUTH_COMB_CHECK_*` CSVs and the CRITAU / AUTHASSIGN baseline families — not full SoD governance against entrenched incumbents. |
| **SAP Security Baseline Template** | Free, anonymous download | **INGEST IT** (§3.4). The rubric every SAP auditor recognises. |
| **SAP Trust Center certifications** (ISO 27001/27017/27018, SOC 1 ISAE 3402, SOC 2, C5, TISAX…) | Yes | **DO NOT BUILD PLATFORM ATTESTATION FEATURES.** The useful inverse framing: *SAP's SOC 2 covers SAP's controls, not your ABAP parameters or your role assignments.* Sharper than any control-mapping table, and it pre-empts the "we already have a SOC 2" objection. |

### 5.1 The one thing nothing in the RISE-native stack does

Across Cloud ALM CSA, Focused Run CSA, EarlyWatch Alert, the Security Baseline Template and the
Security Optimization Service, the output model is uniformly **per-check compliant / non-compliant,
change-versus-previous-snapshot, and red/yellow ratings**. No SAP page reviewed describes
correlating findings into exploitation chains, computing financial loss exposure, or tracking
remediation of a specific finding across successive scans as a first-class object. The closest
artifacts are Focused Run's time-boxed exemptions — which SAP itself characterises as supporting a
basic manual process — and EWA's week-over-week alert recalculation.

State this as **our analysis across five reviewed products**, not as an SAP claim.

> **Strategic consequence.** Treat "more checks" as low-value work — SAP gives us 260 policies free.
> Treat **"what the checks mean together, in money, over time"** as the entire moat.

---

## 6. The practitioner reality

### 6.1 Is "we cannot get security visibility into our own RISE system" evidenced, or an assumption?

**Evidenced — but not as strongly as we have been saying it, and one document variant matters.**

What is solid:

- **Infrastructure, OS and DB logs are genuinely withheld.** Microsoft's documentation states that
  in SAP RISE/ECS environments infrastructure and operating system logs are owned and managed by
  SAP and are not accessible through the standard SAP application connector, and that a purchase
  order for **SAP LogServ** must be completed before that integration can be used.
  **[SAP-primary — learn.microsoft.com]**
- **SAP explicitly excludes doing anything with those logs in the customer's SIEM.** The R&R marks
  LogServ activities on the customer SIEM, and activities within the customer SIEM/SOC (integration,
  correlation-rule creation, alert tuning, incident response, threat hunting, dashboard
  customisation), as **Excluded Tasks**. **[SAP-primary]**
- **SAP's S/4HANA security monitoring is limited to client 000** (§2.4). **[SAP-primary — deck]**
- **A practitioner-authored SAP PRESS piece**, co-written by a practising SAP cybersecurity manager
  and a vendor CTO, states RISE logging and monitoring capabilities "are still not mature yet",
  causing hesitation in regulated industries, and that customers lose direct access to client 000,
  OS, database and cloud infrastructure layers. **[vendor-adjacent, but practitioner]**

What we must stop over-claiming:

> ⚠️ The strongest quote we had — *"By request only to support incident investigations, but not on
> a regular basis e.g. to monitor administrative activities"* — appears in the **tailored option
> v3-2025** document and is **absent from the PCE v7-2026 document** (zero occurrences). The 2026
> PCE text for the corresponding audit-log row instead carries remarks referencing SAP Note
> **3137004** and states that **"Record in Database"** is the default and **only supported** audit
> recording target, with File System **not permitted**. So *"routine security visibility is
> withheld by the contracted service level"* describes a different — possibly superseded — contract
> variant. **Re-verify against the customer's own contract version before this enters any pitch.**

The honest formulation, defensible from SAP documents and sufficient: *application-layer security
evidence in RISE is the customer's to produce; infrastructure-layer evidence is withheld unless
purchased; and SAP's own monitoring of the application does not extend past client 000.*

**A RISE-specific check rule falls out of the 2026 PCE text:** our SAL checks must assert the
**database recording target and flag File System as unsupported in RISE**, not as a generic best
practice. An on-prem-derived checklist gets this wrong. Separately, SAP KBA **3723614** ("Audit log
retention in Private Cloud Services") describes a symptom of short on-system SAL availability — the
body is login-gated, so we know the concern exists but not the numbers. That short retention is what
makes *"is SAL configured correctly, and is it being exported anywhere?"* a high-value finding.

### 6.2 Recurring gaps practitioners report

These cluster tightly across independent sources — subject to the sourcing caveat in §6.4.

1. **Legacy ECC roles lifted into S/4HANA without redesign**, carrying forward over-privilege and
   SoD conflicts because the move is run as an infrastructure project rather than a security
   redesign. The most frequently named failure in every source reviewed. Maps directly onto the
   attack-path graph: over-privileged role → sensitive app → financially relevant data.
2. **Custom ABAP carried forward unreviewed.** Contractually 100% the customer's, with an explicit
   SLA carve-out. **[SAP-primary — Supplement §3.5]**
3. **Configuration drift away from the mandatory baseline** — named as a distinct failure mode by
   four independent sources. This is the argument for repeat scanning *specifically*: a one-shot
   assessment is a consulting deliverable; drift detection is a subscription.
4. **Audit log configured but never analysed.**
5. **RFC destinations with stored credentials bridging tiers.** Dev-to-production trust with a
   stored privileged user is the classic SAP path and is purely a configuration finding. SAP itself
   prices RFC module hardening as a separate paid package, corroborating that the problem is real
   and unserved.
6. **Unmasked production data in non-production copies.** Corroborated from SAP's side: the
   homogeneous system copy tasks carry the remark *"Does not include activities such as data
   masking, scrambling etc."*, and ABAP customers get up to twelve refreshes per SID per contract
   year included. **[SAP-primary]** The condition is common, not exotic — a high-severity default
   check with an unusually strong citation.

### 6.3 The demand signal

SAPinsider's RISE with SAP 2025 benchmark reports that among organisations already live on RISE,
**62%** follow the shared responsibility model rigorously and **32%** acknowledge they do not;
**30%** of those still exploring are unaware the model exists; and **only 33% of live customers
regularly audit for mandatory compliance requirements**. Confirmed at the SAPinsider article.
**[secondary — SAPinsider]**

⚠️ The **methodology is not confirmed** — sample size and field dates are not stated in the article
we read, and the full report is registration-gated. Cite the percentages with the source named; do
not assert the sample.

A competitor separately reports 100% of RISE systems non-compliant with at least one mandatory
requirement at ~77% average compliance. That is a **vendor's self-reported figure from its own
customer base**. Use it as a talk-track if at all; never cite it as fact — citing it lends them
credibility. The better move: once we have a handful of RISE scans, publish our own measured
distribution.

### 6.4 A caveat on the whole practitioner literature

Substantive RISE-security content comes almost entirely from the four vendors selling into this gap,
plus outlets carrying vendor sponsorship. Genuinely independent customer voice — DSAG working-group
material, SAP Community threads, LinkedIn — was largely unreachable behind 403s and registration
walls. Where vendor claims could be checked against SAP's own contract text, they held up. Where
they could not, figures diverge wildly.

Two hard consequences:

- **Do not build our claims on vendor statistics.** A technically literate SAP buyer reads those
  vendors too and will discount us for repeating their marketing.
- **One specific prohibition.** The widely repeated claim that penetration-testing a RISE system
  requires a formal request **six weeks** in advance via a **named SAP support component** comes
  from a **single competitor's page that cites no SAP document, note or policy.** Make only the
  general claim — *active testing in RISE is gated by SAP approval and scoped away from SAP-managed
  layers; we require none, because we send no packets* — and **never quote the six weeks or the
  component string.** For the "nothing installed" argument, cite the add-on / change-request clause
  in §2.7 instead; it is SAP's own text.

---

## 7. What this means for the product

### 7.1 Checks to add

| Priority | Check family | Why |
|---|---|---|
| ~~1~~ **DONE** | **UCON state** (`UCONCOCKPIT`) — `modules/ucon_exposure.py`, four checks. `UCON-002` reports function modules in the default Communication Assembly with zero recorded external calls, which is the exposure-without-use finding this row was asking for; `UCON-COV-001` arms the coverage gate when no UCON export arrives, because with the gateway ACLs unreachable too the product would otherwise be silent on remote-callable exposure. |
| **1** | **SAL recording target = database**, File System flagged as not permitted in RISE; filter-slot count; event-class coverage; retention; whether logs are exported anywhere | RISE-specific rule an on-prem checklist gets wrong. Cheap, fully offline, and it is what makes any retrospective-review story credible. |
| **1** | **Log-source health** as a check class — is the audit log actually capturing what the customer believes | Pure configuration, high value, and the customer cannot get it from SAP. |
| **2** | **Support-package age against the 24-month window** — SAP delivers fixes for high / very-high notes only for support packages shipped in the last 24 months | Computable from exported component levels alone. A compounding, unpatchable exposure and an excellent FAIR input. **[SAP-primary]** |
| **2** | **Non-production client is an unmasked production copy** — client settings and change options inconsistent with a client holding real business data | SAP contractually refreshes production into non-production and explicitly does not mask it. |
| **2** | **BTP audit log on the free 90-day default retention**, and custom applications not writing to the audit log because the premium plan is absent | SAP documents the 90-day default, the premium plan requirement and the support-ticket process for extension. Cheap, checkable, credibility-establishing. **[SAP-primary]** |
| **2** | **ATC / CVA enabled and running**, wired into the transport release path, exemptions not granted without approval | Control-existence assurance, not code scanning. Cloud ALM already exposes a CVA status store. |
| **3** | **Critical authorisation combinations** seeded from SAP's own `AUTH_COMB_CHECK_ROLE.csv` / `AUTH_COMB_CHECK_USER.csv` | SAP-authored content, already CSV, licence-clean. Feeds the attack-path graph without claiming to replace GRC. |
| **3** | **External OS command definitions** (`SM69`) treated as an ABAP→OS bridge | In a system where the customer has no OS access, this is a documented escalation path and a genuine graph edge. |

### 7.2 Checks to re-scope or demote

- **`hana_db_security`** — split into a user / role / privilege half (plausibly reachable) and a
  parameter / encryption / audit-target half (SAP-owned). Mark the latter *not assessable in RISE*
  rather than emitting "unknown". Validate the reachable half on a design-partner tenant before
  promising it.
- **`integration_layer`** — separate gateway ACL **file** checks (unreachable) from ABAP-layer
  interface checks (reachable). Never blend them into one finding.
- **`crypto_posture`** — demote ICM/SNC parameters, crypto library version and HANA encryption to
  *provider-owned / informational*; keep certificate and PSE inventory customer-actionable.
- **`system_trust`** — keep RFC trust and standard users; mark message server ACL and the SAProuter
  route table out of reach in RISE.
- **`code_transport`** — `SE06`/`SCC4` findings become *ticket-to-SAP*. Reporting "production client
  is modifiable" as a customer action item is **wrong** in RISE.
- **`security_params` / `baseline_params`** — all findings become *ticket-to-SAP* with pre-drafted
  request text. Keep full severity; change the remediation model and the effort assumption.
- **`grc_access_control`** — skip cleanly and visibly when GRAC data is absent, since most RISE
  customers do not own GRC.

### 7.3 Export and upload formats to support, in priority order

1. **File upload (universal).** Manual `SE16`/`SE16N`/`SUIM`/`RSPARAM`/`RSUSR003`/`RSAU_CONFIG`
   exports. Works everywhere, needs nothing from SAP, no approval, no window. **This is v1.**
2. **SAP Cloud ALM CSA export / API.** Already switched on and pre-wired in most RISE tenants; no
   ABAP transport, no RFC user, no agent — it removes the biggest adoption objection.
   ⚠️ **Open question that gates this:** whether the CSA API returns **raw config-store values** or
   **only policy compliance verdicts.** If the latter, we are constrained to SAP's checks rather
   than our own. Resolve against the live API before committing roadmap.
3. **BTP collectors (fully automatable).** `btp` CLI output for subaccount settings, trust and role
   collections; the `auditlog-management` API honouring `handle` pagination and the documented
   per-token rate limits; Cloud Connector `/api/v1/configuration` for ACLs and mapped backends.
   Cloud Connector deserves particular attention — it is the network door into the RISE system and
   sits entirely on the customer's side of the line.
4. **Focused Run / Solution Manager Configuration Validation exports** — only the largest estates.

**Deliberately not on the roadmap:** an EarlyWatch Alert importer (Word/PDF only — treat EWA as a
cross-check to reconcile against, not a data source), ABAP source scanning, any log-streaming or
real-time capability, and an in-system ABAP agent of our own.

**Canonical internal schema:** normalise everything into SAP's config-store shapes (§3.3), with a
mapping layer from our field names to store field names, so one check body can consume either a
Cloud ALM pull or a hand-made CSV.

### 7.4 How the report and console must change

- **Deployment-mode switch** (on-prem / RISE PCE) driving remediation owner and severity weighting.
- **Four-state responsibility badge** on every finding (§4.1), plus per-tenant configuration of
  which SAP packages (CAS, LogServ, RAVEN) the customer holds.
- **Client-aware reporting** with a per-client scope declaration; "compliant in the clients we saw"
  must never render as "compliant."
- **Owning-team dimension** on every check (Basis / Authorizations / Development / Integration /
  Data Protection / Identity) as a first-class filter and scorecard axis. This makes hundreds of
  findings consumable and gives repeat-scan tracking a natural assignment model — findings route to
  a team, not a person.
- **Findings expressed in SAP Security Baseline v2.6 requirement IDs and tiers** (`PWDPOL-A`,
  `RFCGW-A`, `CRITAU-A`… / Critical, Standard, Extended) so output can go to an auditor without
  translation. Pin the baseline version in the product; treat re-basing as routine maintenance.
- **A distinct diff category for "requirement changed" versus "system changed"** across repeat
  scans. The baseline archive's `change_marker` PDFs make this computable, and nobody else appears
  to separate the two.
- **A "yours under RISE / SAP's under RISE" tag** on every finding. That single tag turns the report
  from a scan dump into a governance artifact, and it is the argument that justifies buying anything
  at all in a RISE tenant.

---

## 8. Open questions that block specific decisions

| Question | Blocks | How to resolve |
|---|---|---|
| Does Cloud ALM CSA's API return raw store values or only compliance verdicts? | Whether ingestion path #2 unlocks our checks or only SAP's | Test against the live API |
| Can a `CUST_USER_ROLE_ADMIN` holder read HANA parameter system views? | Whether `hana_db_security` degrades gracefully or is dead in RISE | Design-partner tenant |
| Does a RISE customer's standard authorization set actually include `SE16`/`SE16N` in productive clients, and `SM37`/`SM69`? | The entire manual-export path | Design-partner tenant. Contractual responsibility implies yes; role content is a separate question. |
| What is actually in Notes 3250501 / 3480723 / 3381209? | Any coverage claim against mandatory ECS hardening | A customer or partner with SAP for Me |
| Which R&R line-item IDs pair with which tasks? | The check→contract-clause mapping in §7.4 | Eye-verify against the rendered PDF |
| How much of our parameter surface does Cloud ALM already give away free? | The core commercial question in the plan | Enumerate SAP's delivered CSA content |
| Which SAP packages does a given tenant hold (CAS, LogServ, RAVEN)? | Per-finding ownership | Per-tenant configuration; unanswerable from public sources |

---

## 9. Verification status

An adversarial pass re-checked every load-bearing claim against primary sources.

### Survived fully intact

| Claim | How it was confirmed |
|---|---|
| **"No OS access in RISE"** | **Verbatim in BOTH PDFs** — appears in v7-2026 (PCE) *and* v3-2025 (tailored), and in the 2021/2022 editions. **The one load-bearing RISE claim that survives completely.** |
| **Notes 3250501 (ABAP), 3480723 (HANA), 3381209 (Java), 2926224** | Named with exact titles in **SAP's own Security Baseline v2.6 §3.6**. No longer rest on vendor blogs. **Numbers safe to cite; contents are not.** |
| **Baseline Template ZIP downloads anonymously** | HTTP 200, exact byte count **99,336,484**; 545 entries; V2.0–V2.6; v2.6 PDF = 95 pages, 11-Jul-2025 |
| **Baseline taxonomy** | 27 requirement families confirmed by extraction; three-tier scheme real (54 `[Critical]`, 105 `[Standard]`, 57 `[Extended]` occurrences) |
| **GitHub `frun-csa-policies-best-practices`** | Apache-2.0, SAP-maintained. `1ACRITA_CSTO.xml` read raw: config stores and field lists **exactly** as in §3.3; check IDs `CRITAU-A_a.1` / `CRITAU-A_a.2` |
| **Cloud ALM CSA supports S/4HANA PCE** | SAP's own page (via curl; WebFetch gets 403), including the RFC destination, `SAP_ALL`, standard user, security policy, audit log, UCON, CVA, kernel, trusted-system and HTTP-allowlist stores |
| **SAPinsider benchmark percentages** | 33% regularly audit; 62% follow the model rigorously — confirmed at source. Methodology gated. |
| **Cloud ALM included / Focused Run separately licensed** | Confirmed; a second authoritative URL exists at `support.sap.com/en/alm/usage-rights.html` |

### SAP KBA-vs-Note triage (all ten identifiers probed)

- **HTTP 200 — public preview available:** `3480723`, `2253549`, `3137004`, `3460793`, `3351928`,
  `3723614`
- **HTTP 404 — these are SAP *Notes*, not KBAs; login-only:** `3250501`, `3381209`, `2926224`,
  `863362`

Operationally useful: it tells you exactly which identifiers a customer can self-serve a preview
for, and which require SAP for Me.

### Still unverified — do not ship

- **Every R&R line-item ID pairing** (§0)
- **`BC-OP-RC-ECS`** — the alleged SAP support component for pen-test requests. Single competitor
  source, no SAP document cited. **Do not use.**
- **SAP Note `863362`** (EWA security check documentation) — 404 on the public KBA endpoint; sourced
  only from a 2022 SAP deck
- **The ECS hardening control counts** — "81 parameters + 17 settings", "150+ controls". Vendor-
  sourced only; the note bodies are login-gated. **No coverage percentage against a parameter list
  nobody on the team has read.**
- **`ECS` vs `GCO`** — SAP has renamed Enterprise Cloud Services to **Global Cloud Operations** in
  at least the live `3480723` KBA title, while Baseline v2.6 (Jul 2025) still says ECS. Both were
  right at their time. **Check which naming is current before publishing**, or it dates us.
- **Solution Manager 7.2 end-of-maintenance dates** — secondary sources only.

### Could not reach

`community.sap.com` (403 throughout — blocked SAP's own RISE cybersecurity FAQ and
shared-security-responsibility posts); `help.sap.com` (JavaScript shell — blocked the Cloud ALM CSA
API reference, the single most important open question); the full SAPinsider benchmark report
(registration); SAP's Secure Operations Map PDF (403); SAP for Me KBA bodies; and the DSAG S/4HANA
Prüfleitfaden (confirmed to exist, ~335 pages, German-only, based on on-premise and Public Cloud
releases — someone German-reading should review it before we claim DSAG alignment).

### Access is perishable

`support.sap.com` now returns 403 to automated fetches for the ALM FAQ, ALM usage-rights and CSA
expert-portal pages, though curl with a browser UA still works for some and the DAM ZIP downloads
fine. **Treat any single successful fetch as perishable and archive what you retrieve.**
