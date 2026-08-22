<p align="center">
  <img src="assets/monitorrisk-logo.png" alt="MonitorRisk — SAP Threat, Vulnerability, Governance &amp; Risk Quantification" width="620"/>
</p>

<p align="center">
  <strong>Agentless security auditing for SAP S/4HANA RISE, ECS, ECC and BTP</strong><br/>
  <sub>Offline by default · optional read-only connectors · nothing ever installed in the SAP system · no RFC user · nothing is ever written back</sub>
</p>

<p align="center">
  <a href="https://github.com/Krishcalin/SAP-S4HANA-RISE-Security-Scanner/actions/workflows/tests.yml"><img src="https://github.com/Krishcalin/SAP-S4HANA-RISE-Security-Scanner/actions/workflows/tests.yml/badge.svg" alt="tests"/></a>
  <img src="https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.8+"/>
  <img src="https://img.shields.io/badge/CLI-stdlib%20only-brightgreen?style=flat-square" alt="CLI: stdlib only"/>
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="MIT licensed"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/SAP%20Note%203250501-92%2F92%20parameters-0FAAFF?style=flat-square&logo=sap&logoColor=white" alt="SAP Note 3250501: 92/92"/>
  <img src="https://img.shields.io/badge/checks-709%20across%2036%20modules-red?style=flat-square" alt="709 checks, 36 modules"/>
  <img src="https://img.shields.io/badge/custom%20code-133%20ABAP%2FJS%2FBTP%20rules%20%2B%20taint-8A2BE2?style=flat-square" alt="133 static-analysis rules with taint analysis"/>
  <img src="https://img.shields.io/badge/reports-HTML%20%C2%B7%20PDF%20%C2%B7%20PPTX-555?style=flat-square" alt="HTML · PDF · PPTX Reports"/>
  <img src="https://img.shields.io/badge/server-FastAPI%20%2B%20PostgreSQL%2016-336791?style=flat-square&logo=postgresql&logoColor=white" alt="Server: FastAPI + PostgreSQL 16"/>
</p>

---

> ### 🔓 Open source, MIT licensed
>
> Read it, run it, fork it, change it, self-host it, build it into your own
> product, commercial or otherwise. No permission needed and none to ask for.
>
> The only condition MIT sets is that the copyright and permission notice travel
> with substantial portions of the software. That notice lives once, in
> **[LICENSE](LICENSE)** — there are no per-file headers to preserve.
>
> **One carve-out, and it is not ours to waive:**
> `data/sap_baseline_requirements.json` is derived from SAP's own published CSA
> policies under **Apache-2.0, Copyright (c) 2020 SAP SE**. That attribution is
> required by SAP's licence and stays. See
> **[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)**.
>
> **Contributions welcome** · **[CONTRIBUTING.md](CONTRIBUTING.md)** · Reporting a
> vulnerability? **[SECURITY.md](SECURITY.md)**

---

## Contents

- **[System Architecture](docs/ARCHITECTURE.md)** &nbsp;<sub>plain-language guide · 35 chapters · **confidential**</sub>
- **[Overview](#overview)**
- **[Server mode — quick start](#server-mode--quick-start)**
- **[Connected mode](#connected-mode)**
  - [What the server adds over the CLI](#what-the-server-adds-over-the-cli)
- **[Audit Modules](#audit-modules)** &nbsp;<sub>36 modules · 80 documented families</sub>
  <details><summary><sub>expand by family</sub></summary>

  - **Identity & Access** &nbsp; [Segregation of Duties](#segregation-of-duties-iam-sod-) · [Firefighter / Emergency Access](#firefighter--emergency-access-iam-ff-) · [Role Expiry & Validity](#role-expiry--validity-iam-exp-) · [Cross-System Identity](#cross-system-identity-iam-xid-) · [Access Review Compliance](#access-review-compliance-iam-rev-) · [Role Design Quality](#role-design-quality-iam-role-)
  - **Identity & Access (cont.)** &nbsp; [Other IAM Checks](#other-iam-checks) · [Critical access + risk profile](#critical-access--risk-profile)
  - **BTP / Cloud** &nbsp; [Cloud Connector](#cloud-connector-btp-cc-) · [Service Bindings](#service-bindings-btp-sb-) · [Destination Service](#destination-service-btp-dst-) · [Identity Authentication Service](#identity-authentication-service-btp-ias-) · [Entitlement Governance](#entitlement-governance-btp-ent-) · [Event Mesh](#event-mesh-btp-em-) · [Cloud Integration / CPI](#cloud-integration--cpi-btp-cpi-) · [Network Isolation](#network-isolation-btp-net-) · [Subaccount Governance](#subaccount-governance-btp-gov-) · [Audit-Log Coverage](#audit-log-coverage-btp-aud-) · [Token Policy](#token-policy-btp-tok-) · [Iframe Embedding / Clickjacking](#iframe-embedding--clickjacking-btp-frm-) · [Identity Linking](#identity-linking-btp-idl-) · [XSUAA Migration](#xsuaa-migration-btp-mig-)
  - **Integration Layer** &nbsp; [API Management](#api-management-intg-apim-) · [IDOC Port & Partner Security](#idoc-port--partner-security-intg-idoc-) · [Web Services / SOAMANAGER](#web-services--soamanager-intg-ws-) · [Webhook & Callback Security](#webhook--callback-security-intg-wh-) · [Gateway ACL Deep Analysis](#gateway-acl-deep-analysis-intg-gw-) · [Integration Monitoring](#integration-monitoring-intg-mon-) · [CPI Data Stores](#cpi-data-stores-intg-cpi-ds-) · [OAuth Client Governance](#oauth-client-governance-intg-oauth-) · [Integration Topology](#integration-topology-intg-topo-)
  - **Data Protection & Privacy** &nbsp; [Read Access Logging](#read-access-logging-dpp-ral-) · [Information Lifecycle Management](#information-lifecycle-management-dpp-ilm-) · [Data Masking — Non-Production](#data-masking--non-production-dpp-mask-) · [DPP Toolkit](#dpp-toolkit-dpp-toolkit-) · [Purpose of Processing](#purpose-of-processing-dpp-pop-) · [Sensitive Field Inventory](#sensitive-field-inventory-dpp-field-) · [Data Residency & Cross-Border](#data-residency--cross-border-dpp-res-) · [Data Subject Requests](#data-subject-requests-dpp-del-) · [System Landscape](#system-landscape-dpp-land-)
  - **Code & Transport** &nbsp; [Code Injection / SQL Injection](#code-injection--sql-injection-code-inj-) · [Dangerous Statements](#dangerous-statements-code-stmt-) · [ATC / Code Inspector](#atc--code-inspector-code-atc-) · [Transport Management](#transport-management-code-tms-) · [Client Configuration](#client-configuration-code-client-) · [Change Documents](#change-documents-code-chg-) · [Development Access](#development-access-code-dev-) · [SAP Modifications](#sap-modifications-code-mod-) · [Dead Code](#dead-code-code-dead-)
  - **Logging & Monitoring** &nbsp; [Security Audit Log](#security-audit-log-log-aud-) · [SIEM Integration](#siem-integration-log-siem-) · [Log Retention](#log-retention-log-ret-) · [Table Logging](#table-logging-log-tbl-) · [Logon Analysis](#logon-analysis-log-logon-) · [Incident Response](#incident-response-log-ir-)
  - **Fiori / UI** &nbsp; [Catalog Access](#catalog-access-fiori-cat-) · [App Exposure](#app-exposure-fiori-app-) · [OData Authorization](#odata-authorization-fiori-odata-) · [Spaces & Pages](#spaces--pages-fiori-space-) · [Tile-Service Alignment](#tile-service-alignment-fiori-tile-) · [App Usage](#app-usage-fiori-usage-)
  - **Cryptography** &nbsp; [TLS Configuration](#tls-configuration-crypto-tls-) · [Certificate Management](#certificate-management-crypto-cert-) · [SNC](#snc-crypto-snc-) · [HANA Encryption](#hana-encryption-crypto-hana-) · [Crypto Library](#crypto-library-crypto-lib-) · [PSE Health](#pse-health-crypto-pse-) · [Key Management](#key-management-crypto-key-)
  - **HANA Database** &nbsp; [Privileged DB Users](#privileged-db-users-hanadb-user-) · [Privilege Grants](#privilege-grants-hanadb-priv-) · [Roles & Auditing](#roles--auditing-hanadb-role---hanadb-audit-) · [Security Parameters](#security-parameters-hanadb-param-)
  - **Standard Users** &nbsp; [Standard / Default Users](#standard--default-users-stdusr-)
  - **System Trust** &nbsp; [System Trust](#system-trust-trust-)
  - **Access Risk Analysis** &nbsp; [Segregation-of-Duties conflicts](#segregation-of-duties-conflicts-25)
  - **CAP & XSUAA** &nbsp; [The Authorization Chain](#the-authorization-chain-capx-graph-) · [The CDS Model](#the-cds-model-capx-cds-) · [Security Descriptor Configuration](#security-descriptor-configuration-capx-)
  - **Basis Jobs & OS Commands** &nbsp; [External OS-command definitions (JOBCMD-CMD-*) — from SM69 / SXPGCOSTAB](#external-os-command-definitions-jobcmd-cmd---from-sm69--sxpgcostab) · [Background jobs & step users (JOBCMD-JOB-*) — from TBTCO / TBTCP](#background-jobs--step-users-jobcmd-job---from-tbtco--tbtcp)

  </details>
- **[Quick Start](#quick-start)**
  - [Available Modules](#available-modules) &nbsp;<sub>all 33 keys</sub>
- **[Release Gate](#release-gate)** &nbsp;<sub>exit 0 · 1 · 2</sub>
- **[Reports](#reports)** &nbsp;<sub>4 sections</sub>
  <details><summary><sub>expand</sub></summary>

  - [Risk prioritization (P1–P4)](#risk-prioritization-p1p4)
  - [Compliance mapping](#compliance-mapping)
  - [Detailed findings — knowledge base](#detailed-findings--knowledge-base)
  - [Cyber-risk quantification — FAIR *(optional, `--crq`)*](#cyber-risk-quantification--fair-optional---crq)

  </details>
- **[Data Sources](#data-sources)**
- **[Custom Baseline](#custom-baseline)**
- **[Project Structure](#project-structure)**
- **[Roadmap](#roadmap)**
- **[Requirements](#requirements)**
- **[Testing](#testing)**
- **[Contributing](#contributing)**
- **[Disclaimer](#disclaimer)**
- **[License](#license)**

### Deeper documentation

| Document | What it covers |
|---|---|
| [**`docs/ARCHITECTURE.md`**](docs/ARCHITECTURE.md) <br><sub>**Confidential** · not published. Renders here on GitHub; [`ARCHITECTURE.html`](docs/ARCHITECTURE.html) is the same document styled for print and offline reading, generated from the same source.</sub> | How the system is put together and why, explained from first principles for readers who are not software engineers. Seven parts and 35 chapters: the problem RISE creates, the trust boundary, the seven-stage pipeline, the thirty inspectors, what to fix first, risk in money terms, and a full chapter on what the product cannot do. Start here. |
| [`docs/EXPORT_GUIDE.md`](docs/EXPORT_GUIDE.md) | How to produce the exports this tool reads |
| [`docs/EXPORT_SOURCES.md`](docs/EXPORT_SOURCES.md) | Every one of the 128 logical sources, what it feeds, and which checks it unlocks — all 128 now have a written procedure in the export guide |
| [`docs/CHECKS_REFERENCE.md`](docs/CHECKS_REFERENCE.md) | Per-check reference |
| [`docs/RELEASE_GATE.md`](docs/RELEASE_GATE.md) | Using the scanner as a CI gate — adoption order and policy |
| [`docs/RISE_SECURITY_MODEL.md`](docs/RISE_SECURITY_MODEL.md) | Who can actually fix what in RISE, and why it decides the finding text |
| [`docs/CVA_ENGINE_IMPROVEMENT_PLAN.md`](docs/CVA_ENGINE_IMPROVEMENT_PLAN.md) | The ABAP scanner's engine: what shipped, what was declined, what is unverified |
| [`docs/COMPETITIVE_ANALYSIS.md`](docs/COMPETITIVE_ANALYSIS.md) | Where this sits against Onapsis, SecurityBridge and SAP's own tooling |
| [`docs/PIVOT_PLAN.md`](docs/PIVOT_PLAN.md) · [`docs/BUILD_ROADMAP.md`](docs/BUILD_ROADMAP.md) | Product direction and build history |

---

<sub>[↑ Contents](#contents)</sub>

## Overview

**SAP S/4HANA RISE Security Scanner** analyzes exported SAP configuration data (CSV/JSON) and reports findings, severity ratings, risk prioritization, compliance mapping and actionable remediation.

It runs in **two modes that share one scanner core**:

| | **CLI** *(stdlib only)* | **Server** *(client-server)* |
|---|---|---|
| Input | `--data-dir` of exports | Browser upload, or the same directory |
| Output | HTML · PDF · PPTX | Interactive web console + JSON API |
| State | Single-shot, stateless | PostgreSQL — findings persist across uploads |
| Use it for | Air-gapped review, one-off assessment | Continuous tracking of the **mitigation journey** |

- **No direct system connection required** — offline & agentless by default. Nothing is ever installed in the SAP system and no RFC user is created, in either mode.
- **Connected mode is optional and separately invoked.** `python -m collect …` reads from a system you authorise and writes the same export files the offline path consumes — read-only, enforced in the transport rather than promised. The scanner itself still connects to nothing. See [Connected mode](#connected-mode). In RISE, third-party ABAP add-ons are an Excluded Task requiring an additional SKU and a multi-week evaluation; an export bundle needs none of that.
- **709 security checks across 36 audit modules** — ABAP authorizations, HANA DB, BTP/Cloud, GRC Access Control, SOX financial-config controls, permission-level Segregation of Duties, and a custom-code scanner. Precisely: **400** check IDs are written as literals and **664** exist once the five runtime-generated families (profile parameters, ABAP rules, SoD risks, ATC families, conflicting-duty pairs) resolve against their shipped rulesets.
- **Findings map to OWASP and ASVS, with the basis stated** — every finding carries `owasp.basis`, which is `cwe` where OWASP's own published CWE list settles the category, `family` where this product makes a curated judgement (with the reasoning recorded), or `null` where no honest mapping exists. **616 of 673** checks map; the remaining 57 are declared, not swept into A05 — RISE shared-responsibility findings are about a contract, SOX financial-configuration controls are about a different framework, and backup/DR is about availability. A scanner whose every check mapped cleanly to the Top 10 would either be a web-application scanner or be overstating itself. **CVSS vectors are attached to CVEs only** — taken from the SAP CNA record — and never invented for a configuration finding, which has no attack vector to describe.
- **Complete against SAP's mandatory ECS baseline** — **92 of 92** profile parameters from **SAP Note 3250501** (the hardening requirements SAP makes mandatory for AS ABAP in Enterprise Cloud Services), plus its configuration half. Every value is read from a recorded extract of the note, never hand-typed, because a transcription typo tells a customer they are compliant when they are not.
- **Deployment-aware** — `--deployment-mode` decides what *compliant* means. `snc/accept_insecure_gui = 1` is **SAP's own mandated value** in ECS, `rfc/callback_security_method = 1` is a **documented exception** SAP permits (the ECS standard is `3`), and an unlocked `DDIC` is explicitly not required to be locked. All three are findings on classic on-premise ABAP. A RISE-specific scanner that flags SAP's own baseline is confidently wrong on every compliant system.
- **Custom code (CVA)** — **133 rules dispatched by file type** (118 ABAP/CDS/RAP, 7 JavaScript/UI5, 8 BTP descriptor) over a statement-level lexer with intra-procedural taint analysis, so a finding is graded `confirmed` / `tentative` / `pattern-only` rather than asserted. ABAP statements end at a period and span lines; matching them one line at a time loses real injections and invents false ones.
- **A release gate, not just a report** — `--gate` exits non-zero when a change would make things worse, so the scanner can sit in a pipeline. Judges the *delta* against a baseline, scopes to the objects a transport touches, never blocks on a finding the customer cannot fix, and **never fails open**: degraded coverage is "could not assess", never "pass".
- **Stable finding identity** — every finding is fingerprinted from the concrete SAP objects it names, so it matches itself across re-uploads. That is what makes remediation tracking, aging and MTTR possible rather than approximate.
- **Risk-prioritized (P1–P4)** — ranked by severity × exploitability × exposure × privilege, with the contributing factors shown. Works on findings CVSS cannot score at all.
- **Compliance mapping** — **ISO/IEC 27001:2022, NIST SP 800-53 Rev 5, NIST CSF 2.0, CIS Controls v8, DORA (EU 2022/2554), TISAX/VDA ISA, SOC 2, SOX/ITGC, EU GDPR**. DORA is mapped to named requirement areas, not article numbers: an auditor reading a citation expects the sub-paragraph to say what we imply it says.
- **Cyber-risk quantification (FAIR)** — a dollar-denominated Annualised Loss Exposure and loss-exceedance curve from a bundled Monte-Carlo engine, so the board sees financial risk rather than a severity count. On the CLI via `--crq`; in the server it runs on **every** scan and lands on the dashboard. Priced on the complete, unfiltered finding set — the input count is stored beside the figure, so a display filter can never move the number — with the unattributed count disclosed rather than hidden.
- **RISE-aware** — findings carry a remediation owner. In RISE a customer can *see* a bad profile parameter and cannot change it, so those findings render as a pre-drafted service request to SAP, never as "change this".
- **Standards-aligned** — CIS SAP Benchmark, DSAG best-practice guide, SAP Security Baseline

**Pipeline:** &nbsp;`LOAD` CSV/JSON exports → `MODULES` (36 auditors) → `CHECKS` (~709 rules) → `RANK` by severity & P1–P4 priority → `MAP` to compliance frameworks → *(optional)* `QUANTIFY` FAIR loss exposure ($) → `REPORT` (HTML · PDF · PPTX) **or** `STORE` (PostgreSQL → web console, run-over-run diff, graph nodes).

> **A note on dependencies.** The CLI still runs on the Python standard library alone — the HTML, PDF and PPTX engines are all hand-built. The **server tier** deliberately ends that rule: a browser console and a durable finding store cannot be built on the stdlib. The discipline that replaces it is a **single-digit runtime dependency count** (currently 4 — Jinja2 left with the server-rendered console on 2026-08-09), no ORM and no graph database. The console is a **React + TypeScript SPA** built at build time and served as static files by the same FastAPI process at `/` — so it costs build-time tooling, not a runtime dependency and not a second service. The deployment is still one app container plus one PostgreSQL. See [`docs/PIVOT_PLAN.md`](docs/PIVOT_PLAN.md).

---

<sub>[↑ Contents](#contents)</sub>

## Server mode — quick start

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"   # paste into SESSION_SECRET
docker compose up -d --build

docker compose exec app python -m server.cli init-db
docker compose exec app python -m server.cli create-user admin admin --generate
docker compose exec app python -m server.cli add-landscape "Acme Production" --mode rise_pce
# An ABAP system, or a SaaS tenant (SuccessFactors, Concur, IAS, a BTP subaccount):
#   … add-system  "Acme Production" PRD 100 --tier prod
#   … add-tenant  "Acme Production" successfactors acme-sf-prod --tier prod
```

Open <http://127.0.0.1:8000> and sign in — the console is branded **MonitorRisk**.
`--generate` prints a password to the terminal, so it
now lives in scrollback and in `docker compose logs` — the console therefore holds that account
at **Your account** until it is replaced. Every JSON endpoint stays closed until then — the
console shell is a static bundle, so the gate is enforced on the **data**, not on the page, and
therefore cannot be scripted around.

After that, passwords are managed from inside the console: **Your account** (the role chip, top
right) changes your own — the current password is required even though you are already signed
in, because a stolen session should not be enough to take an account over permanently. Admins
also get a user list there, where a reset *mints* a new password rather than setting a chosen
one. Either way, every other session for that account is signed out; that is the point of
changing a password that may have leaked.

Locked out of every admin account, the way back in is from the host — where whoever runs the
container already has the database anyway:

```bash
docker compose exec app python -m server.cli set-password admin --generate
```

Then upload an export bundle. The scan runs automatically and the findings land in the console.

Scanning without a browser — the air-gapped path:

```bash
python -m server.cli scan "Acme Production" ./exports --sid PRD --client 100
python -m server.cli runs

# Send queued notifications to an ITSM endpoint. Credentials come from
# ITSM_WEBHOOK_URL and ITSM_WEBHOOK_TOKEN in the environment, never from argv.
python -m server.cli notify

# A READ-ONLY MCP surface on stdio, scoped to one console account. Nothing it
# exposes changes anything, and there is no unscoped mode.
python -m server.cli mcp auditor
```

The estate is also exportable as a document from the store rather than from a
single scan — `GET /api/export/report.pdf` and `.pptx`, scoped to whatever the
caller may see, carrying the state, assignment and due dates a scan does not
have.

**The whole deployment is one app container and one PostgreSQL.** That is deliberate: it is the
product's clearest structural advantage, and a third service would forfeit it.

### What the server adds over the CLI

- **Mitigation journey** — re-upload the same exports over time; each finding is classified
  *new · persisting · resolved · regressed · unexamined*, with age, assignee, due date and MTTR. A finding
  that comes back re-opens the **same row** with its history intact rather than appearing as new.
  *Unexamined* is the fifth because it has to be: a run that could not observe a finding leaves it
  open and says so, rather than reporting a remediation that never happened.
- **Coverage manifest** — *"you supplied 105 of 135 sources; 10 modules ran with incomplete
  input; 1 source is not obtainable in RISE at all."* Without it a partial upload produces a
  clean-looking report over a fraction of the estate.
- **Risk acceptance with expiry**, false-positive disputes with a mandatory reason, and a
  `submitted_to_provider` state for work handed to SAP under RISE.
- **Graph nodes** — the SAP objects named by findings are materialised as typed nodes, the
  substrate for the attack-path view.
- **RBAC with per-system row scoping**, session auth, and an append-only audit log.
- **Twelve security domains** — the findings re-expressed in the vocabulary an SAP security
  buyer already uses, so an RFP checklist matches line for line. Each domain states **two**
  things that are easy to confuse: what this product can *ever* see there, and what this scan
  found. Four of the twelve name continuous activities we do not perform, and say so on the
  tile rather than in a footnote; the one we do not cover at all shows a dash, never a zero.
  `/domains`, `/domains/{id}`, and a `?domain=` filter on the triage queue.
- **JSON API** rendering from the same query layer as the console, including a
  `changes since run N` endpoint.

---


<sub>[↑ Contents](#contents)</sub>

## Connected mode

Everything above assumes **you** produce the export. On an estate you can reach
over the network — ECC and on-premise NetWeaver typically, RISE typically not —
MonitorRisk can produce part of it itself.

**The scanner still connects to nothing.** `collect/` is a separate, optional
program that writes the same files the offline path reads. The scanner cannot tell
which produced them, and that is the design: connected mode inherits the offline
path's entire test suite.

```bash
# Profile parameters, from the instance's SAP start service (sapstartsrv).
python -m collect sapcontrol --host ecc-prod.example.com --instance 00                              --user SAPADM --out ./extract

# The ICF surface — which endpoints are active, and which answer UNAUTHENTICATED.
python -m collect icf --host ecc-prod.example.com --out ./extract

# Users, roles, authorisations and RFC destinations — the surfaces HTTPS cannot
# reach. Optional: needs the SAP NetWeaver RFC SDK, which you supply under your
# own licence. No Python binding is installed; the SDK is called via ctypes.
python -m collect rfc --host ecc-prod.example.com --instance 00 \
                      --client 100 --user MONITOR --out ./extract

# Then scan it, exactly as if you had exported it by hand.
python sap_scanner.py --data-dir ./extract
```

| | |
|---|---|
| **No SDK, no add-on** | sapstartsrv SOAP on `5<NN>14`, and plain HTTPS. `collect/` is stdlib-only, so a customer running it installs nothing. |
| **Read-only, enforced** | The same service also offers `Start`, `Stop`, `Restart` and OS command execution. An allowlist is checked *before any byte reaches the network*. |
| **No `--password`** | A credential in argv is visible in `ps` and in shell history. Prompted, piped, or `SAPCONTROL_PASSWORD`. |
| **Partial by construction** | Users, roles and authorisations are RFC-only, and RFC is declined ([decision D3](docs/DECISIONS.md)). Every run writes a manifest naming what it could not reach. |

`--probe-only` reports what an endpoint exposes — including whether it answers
with **no credentials at all** — and collects nothing. Worth running first.

Full detail, including the `export_completeness.json` declaration that lets an
absent parameter be judged rather than merely disclosed, is in
**[docs/EXPORT_GUIDE.md](docs/EXPORT_GUIDE.md)**.

## Audit Modules

| Module | Checks | Focus |
|--------|--------|-------|
| 🔐 **User & Authorization** | USR-001→010 (10) | Default users, SAP_ALL, dormant accounts, service accounts |
| 🛡️ **Advanced IAM** | IAM-SOD/FF/EXP/XID/REV/ROLE/FED/PRIV (30) | SoD conflicts, firefighter access, role lifecycle, cross-system identity |
| ⚙️ **Security Parameters** | PARAM-&lt;parameter&gt; (78 parameters) | Password policy, login security, RFC, gateway, TLS, audit logging |
| 🌐 **Network & Services** | NET-001→008 | RFC destinations, ICF services, transports, audit config |
| ☁️ **RISE / BTP Core** | RISE-001→007 | Trust config, comm arrangements, API exposure |
| 🔥 **BTP Cloud Attack Surface** | BTP-CC/SB/DST/IAS/ENT/EM/CPI/NET/GOV/MIG (35) | Cloud Connector (incl. version/CVE-2024-25642), service bindings, destinations, IAS (incl. password policy & corporate-IdP enforcement), Event Mesh, CPI, network isolation |
| 🔗 **Network & Integration Layer** | INTG-APIM/IDOC/WS/WH/GW/MON/CPI/OAUTH/TOPO (32) | API Management, IDOC ports, web services, webhooks, gateway ACLs, OAuth, topology |
| 🔏 **Data Protection & Privacy** | DPP-RAL/ILM/MASK/TOOLKIT/POP/FIELD/RES/DEL/LAND (21) | Read Access Logging, ILM retention, data masking, GDPR/DPDP toolkit, data residency |
| 💻 **Code & Transport Security** | CODE-INJ/STMT/ATC/TMS/CLIENT/CHG/DEV/MOD/DEAD (21) | SQL injection, hardcoded creds, ATC findings, transport workflow, client config, SAP mods |
| 📊 **Logging, Monitoring & IR** | LOG-AUD/SIEM/RET/TBL/LOGON/IR (14) | Audit log config, SIEM integration, log retention, table logging, brute-force detection |
| 🖥️ **Fiori & UI Layer** | FIORI-CAT/APP/ODATA/SPACE/TILE/USAGE (8) | Catalog access, OData backend auth, sensitive app exposure, spaces/pages config |
| 🔑 **Cryptographic Posture** | CRYPTO-TLS/CERT/SNC/HANA/LIB/PSE/KEY (18) | TLS config, certificate health, SNC, HANA encryption at rest (data/log/**backup**), **system-replication TLS**, crypto library, key management |
| 🗄️ **HANA Database Security** | HANADB-USER/PRIV/ROLE/AUDIT/PARAM (19) | Privileged DB users (SYSTEM, password lifetime, dormancy), PUBLIC & system-privilege grants, _SYS_BI_CP_ALL analytic bypass, **DEBUG/ATTACH DEBUGGER** grants, DB auditing, HANA security parameters incl. **log_mode/PITR** and **MDC cross-database access** |
| 📰 **SAP Security Notes / HotNews** | HOTNEWS-000→013 (14) | Missing HotNews (Priority 1) & High (Priority 2) SAP Security Notes, actively-exploited (CISA KEV) unpatched CVEs, partially-implemented notes, release-exposure and workaround analysis — diffed from your SNOTE export against **SAP’s own published patch-day record**: 1,732 notes across 154 patch days, derived from `SAP-samples/frun-csa-policies-best-practices` (Apache-2.0) rather than typed by hand. Includes a self-audit (HOTNEWS-011) that reports where this product’s curated facts differ from SAP’s published ones, without adjudicating — the two publish different CVSS scores for the same CVE. |
| 🔓 **ABAP Authorization & Critical Access** | AUTH-001→016 (16) | Role-content analysis from AGR_1251: Debug&Replace (runtime auth bypass), trusted-RFC impersonation (S_RFCACL), OS command/file access (S_LOG_COM/S_DATASET), authorization forging (S_USER_AUT), broad S_RFC, generic table maintenance (S_TABU_*), run-any-report (S_PROGRAM), batch impersonation, unrestricted destination authorization (S_ICF DEST=*), and sensitive Basis transactions — attributed to the users who hold each role |
| 🔗 **System Trust & Standard Users** | TRUST-001→008 + TRUST-010, STDUSR-001→003 (12) | Trusted/trusting RFC (inbound trust from a lower tier, self-trust, unmigrated 2020 method, trusted destination with a fixed user), SAProuter wildcard routes, message-server port separation, UCON RFC allowlist, gateway proxy ACL — plus standard users (SAP* kernel auto-logon, default passwords, unlocked SAP*/DDIC/SAPCPIC/EARLYWATCH/TMSADM) |
| 🧱 **Security Baseline Parameters** | BASELINE-001→012 + BASELINE-SNC-DEFERRED (13) | SAP Security Baseline / DSAG / CIS profile parameters the other modules don't cover: RFC authorization engine (auth/rfc_authority_check, auth/no_check_in_some_cases), SNC insecure-connection fallback, SAP GUI Scripting, weak legacy password hashes (downwards compatibility) and weak password hash algorithm (login/password_hash_algorithm), sapstartsrv / Host-Agent web methods, gateway ACL mode, SSO ticket & session-cookie transport, ICM security log & error disclosure |
| 🧩 **S/4HANA & Cloud Authorization** | S4AUTHZ-001→008 (8) | The cloud-era authorization layer: super-admin business-role templates (SAP_BR_ADMINISTRATOR*), business-role restrictions left 'Unrestricted', business-catalog sprawl, CDS views with @AccessControl.authorizationCheck disabled, published OData V4 service groups without S_SERVICE, Cloud Connector system mappings without principal propagation, over-assigned Cloud Foundry Org Manager / Space Developer, and birthright role collections mapped to the Default IdP group |
| ☁️ **SAP Cloud ALM CSA Results** | CSA-SAP/COV (4) | SAP’s own Configuration & Security Analysis verdicts, imported and reported **as SAP’s** — supplied as `csa_findings.csv`. Cloud ALM is included with every RISE subscription and needs no transport, RFC user or agent. Policy ids resolve against the SAP Security Baseline catalogue this product vendors from SAP’s published policies, so each result carries SAP’s requirement and priority tier; severity is **SAP’s tier**, never a ranking of ours, because a verdict arrives without the value that produced it. `NOT ASSESSED` is kept apart from `NON-COMPLIANT` and degrades coverage. The complementary path — raw configuration-store exports that feed this product’s own checks — is `modules/cloudalm_import.py`. |
| 🧬 **CAP & XSUAA Application Security** | CAPX-CDS/GRAPH/SCOPE/AUTH/ATTR/TOK/URI/CRED/TEN (15) | The application as **written**, not as deployed — supplied with `--cap-src`. Follows the chain that decides who can call what: scope ← role-template ← role-collection ← IdP group. Reads `xs-security.json` exactly (broken references in the chain, scopes granted to other applications, `$ACCEPT_GRANTED_AUTHORITIES`, `valueRequired:false` attributes that build unrestricted roles, token lifetimes that **override** the subaccount policy `BTP-TOK-*` cannot see, wildcard OAuth redirect URIs, unrotatable instance secrets, shared tenant mode) and the CDS model lexically (services with no `@requires`/`@restrict`, `@restrict` privileges with no `to:` — which SAP documents as granting to *every* user — roles the model enforces that no descriptor grants, restricted entities a single `$expand` reaches from a service that never demanded their role — CAP evaluates authorization "only on the target entity of the request" — and personal-data elements a projection carries into a service, since CAP supports no property-level authorization at all). Joined to `btp_role_collections.json` it answers the question an auditor actually asks: which application scopes does every federated user already hold. |
| ⚖️ **Access Risk Analysis (SoD)** | ARA-* (27 risks + user score) | GRC-style **offline Segregation-of-Duties** from AGR_1251 + AGR_USERS. Resolves each user's transactions **and** authorization object/field/activity across all roles, then evaluates a verified ruleset at the **permission level** (so display-only access is not a false positive): 25 SoD conflicts across Procure-to-Pay, Order-to-Cash, Record-to-Report, Hire-to-Retire and Basis/Security, plus 2 HR critical accesses. Honours documented **mitigating controls** (with expiry) and produces a **per-user risk profile**. Extensible via a custom ruleset JSON. (Supersedes the coarse transaction-level SoD in Advanced IAM, which now defers to this module when AGR_1251 is available.) |
| ⚙️ **Basis Jobs & OS Commands** | JOBCMD-CMD/JOB-* (11) | The realised **host-command-execution** surface: external OS-command definitions (SM69 / SXPGCOSTAB) that wrap a shell/interpreter, allow runtime argument injection (ADDPAR), resolve to an unqualified/user-writable path, or wrap a destructive/exfil utility — plus armed background jobs (TBTCO/TBTCP) whose step user (AUTHCKNAM) is SAP*/DDIC/SAP_ALL, that shell out to an OS command/program, that run RSBDCOS0 (SM69-allowlist bypass) or unreviewed custom code, whose step user is deleted/locked/dialog, or differs from the scheduler (identity borrowing). Reuses `users`/`profiles` to resolve privileged step users. Complements the ABAP Authorization module (which covers who *can* act) with what is *actually* defined and scheduled. |
| 🚨 **GRC Access Control** | GRC-FF/ARM/ARA/MIT/RS (13) | The **SAP GRC Access Control** process layer (not just configuration): Emergency Access Management / Firefighter usage without owner review, self-owned firefighter IDs, uncontrolled Firefighter logon; Access Request Management approvals bypassing SoD risk analysis, auto-provisioned requests, missing risk analysis; GRC-native SoD violations left open past SLA; mitigating controls without a monitor or past validity; and SoD-ruleset governance (blank/critical risk levels, ruleset currency). |
| 👔 **Role Design & Governance** | RG-SU24/GEN/DRV (3) | Role-build hygiene: custom Z*/Y* transactions with unmaintained SU24 authorization proposals (default-check gaps), roles whose profiles were never generated (AGR_1016) so the authorizations are inert, and derived roles whose authorization values have **drifted** from their parent (org-level fields excepted) — a common source of silent over-entitlement. |
| 💰 **Financial Controls (SOX)** | FIN-PP/TOL/SF/DOC/NR (6) | SOX ITGC / FI configuration controls: posting-period variants left wide open (T001B), unlimited or unset posting tolerance groups (T043T), payment-relevant fields not under dual-control / four-eyes (T055F), document-change rules allowing post-posting edits to bank/payment fields (TBAER), and FI accounting-document number ranges main-memory buffered (TNRO) — which breaks gap-free, audit-defensible document numbering. |
| 🧾 **ATC / CVA Import** | ATC-* | SAP's **own** ATC / Code Vulnerability Analyzer results, ingested rather than re-derived. Where the customer already licenses CVA, its findings are authoritative and duplicating them would only disagree with SAP about SAP's own tool. |
| 🔎 **Security Audit Log Review** | LREV-FLT/PAT/RET/* (15) | Retrospective SM20 review — what the audit log *actually recorded*, as opposed to how it is configured. Configuration says what should be captured; this says what was. |
| 🔒 **SNC Posture** | CRYPTO-SNCECS-* (7) | The **18 SNC / IGS parameters of SAP Note 3250501 as one model, not 18 comparisons.** With `snc/enable = 0` every `accept_insecure_*` setting is moot, so ten independent findings would report ten problems where the truth is one. Also checks the relationships the note itself states: `igs/snc/name` must match `snc/identity/as`, `igs/snc/library` must match `snc/gssapi_lib`, and `data_protection/min` may not exceed `max`. Critically, `snc/accept_insecure_gui = 1` and `snc/only_encrypted_rfc = 0` are the **ECS standard** — flagging them would flag every compliant RISE system. |
| 📜 **ECS Mandatory Configuration** | AUTH-ECS / CRYPTO-ECS / STDUSR-ECS / LREV-ECS (5) | The **configuration half** of Note 3250501 — the items that are not profile parameters: password-hash tables behind authorization group SPWD, `SSF_PSE_D` behind SPSE, unused clients, and Security Audit Log filter coverage. Every one of the note's 18 items is accounted for in a disposition table naming who owns it, so a future note version that adds a nineteenth breaks the build rather than the report. |
| 🧬 **Custom Code (CVA)** | ABAP-* (133 rules) | Our own **ABAP / CDS / RAP scanner** over an abapGit offline export — the one route ABAP source leaves a RISE PCE system. Statement-level lexing (ABAP statements end at a period and routinely span five lines; matching line-by-line both loses real injections and invents false ones), a mode-stack that handles string templates and their embedded expressions, SQLScript lexing for AMDP bodies, and intra-procedural taint analysis that grades each finding `confirmed` / `tentative` / `pattern-only`. Where the customer has SAP's own CVA, `atc` ingests those results instead. |
| 📦 **Custom-Code Inventory** | CODE-INV-001→005 (5) | The estate picture rather than its defects: object counts by type, code nothing references (dead-code removal reduces attack surface), code that has not run in a year, and — kept deliberately separate — code whose reachability is **unknown**. Unknown is not unreachable. |
| 🔁 **Resilience & Recovery** | RES-BCK/DR/EVD/JOB (9) | Ransomware readiness from what an export can actually evidence: backup recency and failure posture, DR-test records, recovery objectives. Scrupulously scoped — this verifies that resilience is **configured**, never that a restore works. |

<details>
<summary><strong>🛡️ Advanced IAM — Full Check List</strong></summary>

### Segregation of Duties (IAM-SOD-*)
| Check | Description | Severity |
|-------|-------------|----------|
| IAM-SOD-FIN-001 | SoD: Vendor Master ↔ Payment Processing | CRITICAL |
| IAM-SOD-FIN-002 | SoD: Purchase Order ↔ Goods Receipt | HIGH |
| IAM-SOD-FIN-003 | SoD: Journal Entry ↔ GL Account Master | HIGH |
| IAM-SOD-FIN-004 | SoD: Customer Master ↔ Sales Order / Billing | HIGH |
| IAM-SOD-HR-001 | SoD: HR Master Data ↔ Payroll Execution | CRITICAL |
| IAM-SOD-SEC-001 | SoD: User Administration ↔ Role Administration | CRITICAL |
| IAM-SOD-BASIS-001 | SoD: Transport Management ↔ Development | HIGH |

SoD checks support three data strategies: pre-computed matrix (`sod_matrix.csv`), role resolution (`user_roles.csv` + `role_tcodes.csv`), or heuristic role-name matching.

### Firefighter / Emergency Access (IAM-FF-*)
| Check | Description | Severity |
|-------|-------------|----------|
| IAM-FF-001 | Sessions exceeding max duration (default: 4h) | HIGH |
| IAM-FF-002 | Sessions without documented justification | HIGH |
| IAM-FF-003 | Sessions not reviewed by controller | CRITICAL |
| IAM-FF-004 | Sessions self-approved (reviewer = requestor) | CRITICAL |
| IAM-FF-005 | Users with excessive firefighter usage frequency | MEDIUM |

### Role Expiry & Validity (IAM-EXP-*)
| Check | Description | Severity |
|-------|-------------|----------|
| IAM-EXP-001 | Role assignments without expiry dates (indefinite) | MEDIUM |
| IAM-EXP-002 | Expired role assignments still present in user master | LOW |
| IAM-EXP-003 | Role assignments with excessive validity periods | MEDIUM |

### Cross-System Identity (IAM-XID-*)
| Check | Description | Severity |
|-------|-------------|----------|
| IAM-XID-001 | BTP users without corresponding S/4HANA account | MEDIUM |
| IAM-XID-002 | S/4HANA locked users still active in BTP (incomplete offboarding) | HIGH |
| IAM-XID-003 | BTP users with administrative role collections | HIGH |

### Access Review Compliance (IAM-REV-*)
| Check | Description | Severity |
|-------|-------------|----------|
| IAM-REV-001 | Overdue access review campaigns | HIGH |
| IAM-REV-002 | Reviews marked complete but with incomplete coverage | MEDIUM |
| IAM-REV-003 | Reviews without assigned reviewer | MEDIUM |

### Role Design Quality (IAM-ROLE-*)
| Check | Description | Severity |
|-------|-------------|----------|
| IAM-ROLE-001 | Custom roles without descriptions | LOW |
| IAM-ROLE-002 | Custom roles without designated owners | MEDIUM |
| IAM-ROLE-003 | Empty roles with no menu/transaction assignments | LOW |

### Other IAM Checks
| Check | Description | Severity |
|-------|-------------|----------|
| IAM-ORPH-001 | Users assigned to non-existent/deleted roles | MEDIUM |
| IAM-USRGRP-001 | Active users in default/unassigned user groups | LOW |
| IAM-REF-001 | Dialog users misused as reference users | HIGH |
| IAM-PRIV-001 | Users with privilege escalation capability (self-escalation paths) | CRITICAL |

</details>

<details>
<summary><strong>🔥 BTP Cloud Attack Surface — Full Check List</strong></summary>

### Cloud Connector (BTP-CC-*)
| Check | Description | Severity |
|-------|-------------|----------|
| BTP-CC-001 | Wildcard resource mappings on backends | CRITICAL |
| BTP-CC-002 | High-risk paths exposed (WebGUI, ADT, SOAP RFC) | HIGH |
| BTP-CC-003 | Excessive number of backend systems | MEDIUM |
| BTP-CC-004 | Unrestricted access control lists | HIGH |
| BTP-CC-005 | Certificates expiring or expired | HIGH |
| BTP-CC-006 | Certificates with weak cryptography (SHA-1, <2048 bit) | HIGH |
| BTP-CC-007 | Stale/unused backend configurations | MEDIUM |
| BTP-CC-008 | Cloud Connector version vulnerable to CVE-2024-25642 (improper cert validation / MITM, regression 2.15.0–2.16.1) or out-of-maintenance | HIGH/MEDIUM |

### Service Bindings (BTP-SB-*)
| Check | Description | Severity |
|-------|-------------|----------|
| BTP-SB-001 | Bindings not rotated in 180+ days | HIGH |
| BTP-SB-002 | Bindings with admin-level scopes | HIGH |
| BTP-SB-003 | Orphaned bindings (deleted instances) | MEDIUM |

### Destination Service (BTP-DST-*)
| Check | Description | Severity |
|-------|-------------|----------|
| BTP-DST-001 | Destinations with stored credentials | HIGH |
| BTP-DST-002 | Destinations with TLS verification disabled | CRITICAL |
| BTP-DST-003 | Proxy type mismatch (Internet vs OnPremise) | MEDIUM |
| BTP-DST-004 | Stale destinations (365+ days unmodified) | LOW |

### Identity Authentication Service (BTP-IAS-*)
| Check | Description | Severity |
|-------|-------------|----------|
| BTP-IAS-001 | Apps without conditional authentication rules | MEDIUM |
| BTP-IAS-002 | Apps without IP-based restrictions | MEDIUM |
| BTP-IAS-003 | Apps without multi-factor authentication | HIGH |
| BTP-IAS-004 | IAS password policy for local users is weak (length/complexity/lockout) | HIGH/MEDIUM |
| BTP-IAS-005 | Corporate IdP not enforced — local password fallback allowed | HIGH |

### Entitlement Governance (BTP-ENT-*)
| Check | Description | Severity |
|-------|-------------|----------|
| BTP-ENT-001 | Services entitled but never provisioned | LOW |
| BTP-ENT-002 | Security services entitled but unused (audit, credstore) | MEDIUM |

### Event Mesh (BTP-EM-*)
| Check | Description | Severity |
|-------|-------------|----------|
| BTP-EM-001 | Queues with wildcard topic subscriptions | HIGH |
| BTP-EM-002 | Queues without access control policies | HIGH |
| BTP-EM-003 | Cross-namespace event subscriptions | MEDIUM |

### Cloud Integration / CPI (BTP-CPI-*)
| Check | Description | Severity |
|-------|-------------|----------|
| BTP-CPI-001 | Credentials not rotated in 180+ days | HIGH |
| BTP-CPI-002 | Credentials using basic/plaintext auth | MEDIUM |
| BTP-CPI-003 | iFlows with hardcoded/embedded credentials | CRITICAL |
| BTP-CPI-004 | iFlows with no sender authentication | HIGH |
| BTP-CPI-005 | iFlows using unencrypted HTTP endpoints | HIGH |

### Network Isolation (BTP-NET-*)
| Check | Description | Severity |
|-------|-------------|----------|
| BTP-NET-001 | Services using public internet endpoints | MEDIUM |
| BTP-NET-002 | Critical services without Private Link | HIGH |

### Subaccount Governance (BTP-GOV-*)
| Check | Description | Severity |
|-------|-------------|----------|
| BTP-GOV-001 | Subaccounts without audit logging | HIGH |
| BTP-GOV-002 | Subaccounts using default SAP IDP only | MEDIUM |

### Audit-Log Coverage (BTP-AUD-*)
| Check | Description | Severity |
|-------|-------------|----------|
| BTP-AUD-001 | Subaccounts whose audit-log state no export settles | INFO |

### Token Policy (BTP-TOK-*)
| Check | Description | Severity |
|-------|-------------|----------|
| BTP-TOK-001 | Token validity relaxed beyond the SAP default (12 h / 7 d) | HIGH |
| BTP-TOK-002 | Token validity left at the SAP default | LOW |
| BTP-TOK-003 | Token validity below the 30-minute floor SAP states | LOW |

### Iframe Embedding / Clickjacking (BTP-FRM-*)
| Check | Description | Severity |
|-------|-------------|----------|
| BTP-FRM-001 | Login pages framable from a wildcard or plain-HTTP origin | HIGH |
| BTP-FRM-002 | Iframe embedding enabled (SAP ships it disabled) | MEDIUM |

### Identity Linking (BTP-IDL-*)
| Check | Description | Severity |
|-------|-------------|----------|
| BTP-IDL-001 | Email links identities across multiple identity providers | MEDIUM |

### XSUAA Migration (BTP-MIG-*)
| Check | Description | Severity |
|-------|-------------|----------|
| BTP-MIG-001 | Apps still using XSUAA (not migrated to IAS) | MEDIUM |

## CAP & XSUAA Application Security (`--cap-src`)

The application as written, from its own source tree. Design-time facts that
appear in no runtime export.

### The Authorization Chain (CAPX-GRAPH-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CAPX-GRAPH-001 | Broken reference in the scope ← role-template ← role-collection chain | HIGH |
| CAPX-GRAPH-002 | Application scopes granted to every federated user by birthright | HIGH |
| CAPX-GRAPH-003 | Role template no role collection can deliver | MEDIUM |

### The CDS Model (CAPX-CDS-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CAPX-CDS-001 | CAP service exposed with no access control | HIGH |
| CAPX-CDS-002 | `@restrict` privilege with no `to:` — grants to every user | HIGH |
| CAPX-CDS-003 | Model enforces a role no security descriptor grants | MEDIUM |
| CAPX-CDS-004 | Restricted entity reachable by `$expand` from a service that does not require its role | HIGH |
| CAPX-CDS-005 | Personal or sensitive element exposed by a projection that excludes nothing | MEDIUM |

### Security Descriptor Configuration (CAPX-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CAPX-TOK-001 | Application overrides the subaccount token policy | HIGH |
| CAPX-URI-001 | OAuth redirect URI broader than a specific host | HIGH |
| CAPX-SCOPE-001 | Scope granted directly to another application | MEDIUM |
| CAPX-AUTH-001 | `$ACCEPT_GRANTED_AUTHORITIES` — accepts every grant, unnamed | MEDIUM |
| CAPX-ATTR-001 | `valueRequired:false` builds an unrestricted role | MEDIUM |
| CAPX-CRED-001 | Instance secret requested, which cannot be rotated | MEDIUM |
| CAPX-TEN-001 | Shared tenant mode — one client secret in every subaccount | MEDIUM |
| CAPX-COV-001 | Parts of the project could not be read | INFO |

</details>

<details>
<summary><strong>🔗 Network & Integration Layer — Full Check List</strong></summary>

### API Management (INTG-APIM-*)
| Check | Description | Severity |
|-------|-------------|----------|
| INTG-APIM-001 | API proxies missing required security policies | HIGH |
| INTG-APIM-002 | API proxies without authentication policies | CRITICAL |
| INTG-APIM-003 | API proxies allowing unencrypted HTTP | HIGH |
| INTG-APIM-004 | API proxies allowing deprecated TLS versions | HIGH |
| INTG-APIM-005 | API proxies in pass-through mode (zero policies) | CRITICAL |

### IDOC Port & Partner Security (INTG-IDOC-*)
| Check | Description | Severity |
|-------|-------------|----------|
| INTG-IDOC-001 | IDOC ports without encryption (TLS/SNC) | HIGH |
| INTG-IDOC-002 | IDOC file ports with insecure directories | MEDIUM |
| INTG-IDOC-003 | IDOC partners with wildcard message types | HIGH |
| INTG-IDOC-004 | IDOC partners handling sensitive message types | MEDIUM |

### Web Services / SOAMANAGER (INTG-WS-*)
| Check | Description | Severity |
|-------|-------------|----------|
| INTG-WS-001 | High-risk BAPIs/RFCs exposed as web services | HIGH |
| INTG-WS-002 | Excessive active web service endpoints | MEDIUM |
| INTG-WS-003 | Web services with weak/no authentication | CRITICAL |

### Webhook & Callback Security (INTG-WH-*)
| Check | Description | Severity |
|-------|-------------|----------|
| INTG-WH-001 | Webhook callbacks using unencrypted HTTP | HIGH |
| INTG-WH-002 | Webhooks without HMAC signature verification | HIGH |
| INTG-WH-003 | Webhooks delivering to external endpoints | MEDIUM |
| INTG-WH-004 | Stale webhook registrations | LOW |

### Gateway ACL Deep Analysis (INTG-GW-*)
| Check | Description | Severity |
|-------|-------------|----------|
| INTG-GW-001 | Secinfo with overly permissive permit rules | CRITICAL |
| INTG-GW-002 | Secinfo missing deny-all default rule | HIGH |
| INTG-GW-003 | Secinfo permits external program execution | HIGH |
| INTG-GW-004 | Reginfo permits unrestricted RFC registration | CRITICAL |
| INTG-GW-005 | Reginfo missing deny-all default rule | HIGH |

### Integration Monitoring (INTG-MON-*)
| Check | Description | Severity |
|-------|-------------|----------|
| INTG-MON-001 | Missing integration monitoring alert rules | HIGH |
| INTG-MON-002 | Integration events not forwarded to SIEM | MEDIUM |

### CPI Data Stores (INTG-CPI-DS-*)
| Check | Description | Severity |
|-------|-------------|----------|
| INTG-CPI-DS-001 | Data stores with sensitive names, no encryption | HIGH |
| INTG-CPI-DS-002 | Global variables with potentially sensitive names | MEDIUM |
| INTG-CPI-DS-003 | Data stores with excessive entries | LOW |

### OAuth Client Governance (INTG-OAUTH-*)
| Check | Description | Severity |
|-------|-------------|----------|
| INTG-OAUTH-001 | OAuth clients with admin/wildcard scopes | HIGH |
| INTG-OAUTH-002 | OAuth clients using deprecated grant types | HIGH |
| INTG-OAUTH-003 | OAuth clients unused for 180+ days | MEDIUM |

### Integration Topology (INTG-TOPO-*)
| Check | Description | Severity |
|-------|-------------|----------|
| INTG-TOPO-001 | Integration connections without encryption | HIGH |
| INTG-TOPO-002 | Hub systems with excessive connections | MEDIUM |
| INTG-TOPO-003 | Connections to deprecated/legacy systems | MEDIUM |

</details>

<details>
<summary><strong>🔏 Data Protection & Privacy — Full Check List</strong></summary>

### Read Access Logging (DPP-RAL-*)
| Check | Description | Severity |
|-------|-------------|----------|
| DPP-RAL-001 | RAL disabled or no active configurations | CRITICAL |
| DPP-RAL-002 | RAL missing coverage for key channels (OData, RFC, ALV) | HIGH |
| DPP-RAL-003 | RAL log channels with insufficient retention | MEDIUM |

### Information Lifecycle Management (DPP-ILM-*)
| Check | Description | Severity |
|-------|-------------|----------|
| DPP-ILM-001 | Retention policies exceeding maximum period | MEDIUM |
| DPP-ILM-002 | Policies without automatic data destruction | MEDIUM |
| DPP-ILM-003 | Policies without end-of-purpose definitions | HIGH |
| DPP-ILM-004 | Personal data tables without ILM retention policies | HIGH |

### Data Masking — Non-Production (DPP-MASK-*)
| Check | Description | Severity |
|-------|-------------|----------|
| DPP-MASK-001 | Non-production systems without PII data masking | CRITICAL |
| DPP-MASK-002 | Production copies in non-prod without masking | CRITICAL |

### DPP Toolkit (DPP-TOOLKIT-*)
| Check | Description | Severity |
|-------|-------------|----------|
| DPP-TOOLKIT-001 | DPP toolkit features not configured (deletion report, consent, breach notification) | HIGH |

### Purpose of Processing (DPP-POP-*)
| Check | Description | Severity |
|-------|-------------|----------|
| DPP-POP-001 | Purposes without documented legal basis (GDPR Art.6) | HIGH |
| DPP-POP-002 | Expired purposes still active | MEDIUM |

### Sensitive Field Inventory (DPP-FIELD-*)
| Check | Description | Severity |
|-------|-------------|----------|
| DPP-FIELD-001 | PII fields without Read Access Logging | HIGH |
| DPP-FIELD-002 | Sensitive fields not masked in non-production | MEDIUM |
| DPP-FIELD-003 | Known sensitive SAP fields missing from classification inventory | MEDIUM |

### Data Residency & Cross-Border (DPP-RES-*)
| Check | Description | Severity |
|-------|-------------|----------|
| DPP-RES-001 | Cross-border transfers without legal safeguards (SCCs/BCRs) | CRITICAL |
| DPP-RES-002 | Special category data in cross-border transfers | HIGH |

### Data Subject Requests (DPP-DEL-*)
| Check | Description | Severity |
|-------|-------------|----------|
| DPP-DEL-001 | Data subject requests overdue (>30 day SLA) | CRITICAL |
| DPP-DEL-002 | Requests marked complete but incomplete | HIGH |
| DPP-DEL-003 | Requests without documentation | MEDIUM |

### System Landscape (DPP-LAND-*)
| Check | Description | Severity |
|-------|-------------|----------|
| DPP-LAND-001 | Systems without data classification assignment | MEDIUM |

</details>

<details>
<summary><strong>💻 Code & Transport Security — Full Check List</strong></summary>

### Code Injection / SQL Injection (CODE-INJ-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CODE-INJ-001 | SQL injection patterns in custom code (dynamic WHERE, EXEC SQL) | CRITICAL |
| CODE-INJ-002 | Custom code missing authority checks | HIGH |
| CODE-INJ-003 | Hardcoded credentials in ABAP source | CRITICAL |

### Dangerous Statements (CODE-STMT-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CODE-STMT-001 | Dangerous ABAP statements (CALL 'SYSTEM', GENERATE, INSERT REPORT) | HIGH |

### ATC / Code Inspector (CODE-ATC-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CODE-ATC-001 | Unresolved critical ATC findings | CRITICAL |
| CODE-ATC-002 | Unresolved high-severity ATC findings | HIGH |

### Transport Management (CODE-TMS-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CODE-TMS-001 | Transport routes allow direct dev→prod delivery | CRITICAL |
| CODE-TMS-002 | Production imports without approval | HIGH |
| CODE-TMS-003 | Same user releasing and importing (SoD violation) | HIGH |
| CODE-TMS-004 | Transport imports outside change windows (weekends) | MEDIUM |
| CODE-TMS-005 | Transports imported directly from dev to prod | CRITICAL |

### Client Configuration (CODE-CLIENT-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CODE-CLIENT-001 | Production client allows changes (not locked) | CRITICAL |

### Change Documents (CODE-CHG-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CODE-CHG-001 | Critical object types without change documents | MEDIUM |
| CODE-CHG-002 | Change documents with empty/system user attribution | MEDIUM |

### Development Access (CODE-DEV-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CODE-DEV-001 | Users with S_DEVELOP modify/create in production | HIGH |

### SAP Modifications (CODE-MOD-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CODE-MOD-001 | Unregistered SAP standard modifications | MEDIUM |
| CODE-MOD-002 | Modifications to security-critical standard programs | CRITICAL |
| CODE-MOD-003 | Stale modifications (5+ years old) | LOW |

### Dead Code (CODE-DEAD-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CODE-DEAD-001 | Excessive unreferenced custom code | MEDIUM |
| CODE-DEAD-002 | Custom code objects without designated owner | LOW |

</details>

<details>
<summary><strong>📊 Logging, Monitoring & IR — Full Check List</strong></summary>

### Security Audit Log (LOG-AUD-*)
| Check | Description | Severity |
|-------|-------------|----------|
| LOG-AUD-001 | Security Audit Log disabled or no active filters | CRITICAL |
| LOG-AUD-002 | No static audit profile configured (lost on restart) | HIGH |
| LOG-AUD-003 | Audit log missing coverage for required event types | HIGH |

### SIEM Integration (LOG-SIEM-*)
| Check | Description | Severity |
|-------|-------------|----------|
| LOG-SIEM-001 | No SIEM integration or SIEM disabled | HIGH |
| LOG-SIEM-002 | SIEM missing critical log source forwarding | MEDIUM |

### Log Retention (LOG-RET-*)
| Check | Description | Severity |
|-------|-------------|----------|
| LOG-RET-001 | Log retention below minimum (365 days) | MEDIUM |
| LOG-RET-002 | Security logs without archiving | LOW |

### Table Logging (LOG-TBL-*)
| Check | Description | Severity |
|-------|-------------|----------|
| LOG-TBL-001 | Critical tables without change logging | HIGH |

### Logon Analysis (LOG-LOGON-*)
| Check | Description | Severity |
|-------|-------------|----------|
| LOG-LOGON-001 | Potential brute-force attack patterns | CRITICAL |
| LOG-LOGON-002 | Accounts with excessive logon failures | MEDIUM |

### Incident Response (LOG-IR-*)
| Check | Description | Severity |
|-------|-------------|----------|
| LOG-IR-001 | Incident response readiness gaps | MEDIUM |

</details>

<details>
<summary><strong>🖥️ Fiori & UI Layer — Full Check List</strong></summary>

### Catalog Access (FIORI-CAT-*)
| Check | Description | Severity |
|-------|-------------|----------|
| FIORI-CAT-001 | Catalogs with public/unrestricted scope | HIGH |
| FIORI-CAT-002 | Catalogs assigned to excessive roles | MEDIUM |

### App Exposure (FIORI-APP-*)
| Check | Description | Severity |
|-------|-------------|----------|
| FIORI-APP-001 | Sensitive admin apps exposed with broad access | HIGH |

### OData Authorization (FIORI-ODATA-*)
| Check | Description | Severity |
|-------|-------------|----------|
| FIORI-ODATA-001 | OData services without authorization checks | CRITICAL |
| FIORI-ODATA-002 | Sensitive OData services with inadequate auth | HIGH |

### Spaces & Pages (FIORI-SPACE-*)
| Check | Description | Severity |
|-------|-------------|----------|
| FIORI-SPACE-001 | Spaces with public visibility | MEDIUM |

### Tile-Service Alignment (FIORI-TILE-*)
| Check | Description | Severity |
|-------|-------------|----------|
| FIORI-TILE-001 | Tiles with OData authorization mismatches | MEDIUM |

### App Usage (FIORI-USAGE-*)
| Check | Description | Severity |
|-------|-------------|----------|
| FIORI-USAGE-001 | Apps with zero usage (never launched) | LOW |

</details>

<details>
<summary><strong>🔑 Cryptographic Posture — Full Check List</strong></summary>

### TLS Configuration (CRYPTO-TLS-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CRYPTO-TLS-001 | TLS endpoints allowing deprecated protocols (1.0/1.1/SSLv3) | HIGH |
| CRYPTO-TLS-002 | Cipher suites include weak algorithms (RC4, DES, 3DES) | HIGH |
| CRYPTO-TLS-003 | HTTPS without HSTS headers | MEDIUM |

### Certificate Management (CRYPTO-CERT-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CRYPTO-CERT-001 | Expired certificates in trust store | CRITICAL |
| CRYPTO-CERT-002 | Certificates expiring within warning window | HIGH |
| CRYPTO-CERT-003 | Certificates with weak keys/algorithms | HIGH |
| CRYPTO-CERT-004 | Self-signed certificates in production | MEDIUM |

### SNC (CRYPTO-SNC-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CRYPTO-SNC-001 | SNC (Secure Network Communications) disabled | HIGH |
| CRYPTO-SNC-002 | SNC quality set to authentication only (no encryption) | MEDIUM |

### HANA Encryption (CRYPTO-HANA-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CRYPTO-HANA-001 | HANA data volume encryption disabled | HIGH |
| CRYPTO-HANA-002 | HANA log volume encryption disabled | MEDIUM |
| CRYPTO-HANA-003 | HANA using internal/default key management | MEDIUM |
| CRYPTO-HANA-004 | HANA backup encryption is disabled | HIGH |
| CRYPTO-HANA-005 | HANA system replication is not TLS-encrypted | HIGH |

### Crypto Library (CRYPTO-LIB-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CRYPTO-LIB-001 | Outdated SAP Crypto Library version | HIGH |

### PSE Health (CRYPTO-PSE-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CRYPTO-PSE-001 | PSE files with errors or expired certificates | HIGH |

### Key Management (CRYPTO-KEY-*)
| Check | Description | Severity |
|-------|-------------|----------|
| CRYPTO-KEY-001 | Key management policy gaps (rotation, backup) | MEDIUM |

</details>

<details>
<summary><strong>🗄️ HANA Database Security — Full Check List</strong></summary>

### Privileged DB Users (HANADB-USER-*)
| Check | Description | Severity |
|-------|-------------|----------|
| HANADB-USER-001 | HANA SYSTEM superuser is still active | CRITICAL |
| HANADB-USER-002 | DB users with password-lifetime check disabled | HIGH |
| HANADB-USER-003 | Dormant HANA DB users (no logon in N+ days) | MEDIUM |

### Privilege Grants (HANADB-PRIV-*)
| Check | Description | Severity |
|-------|-------------|----------|
| HANADB-PRIV-001 | Sensitive privileges granted to PUBLIC | CRITICAL |
| HANADB-PRIV-002 | Critical system privileges granted directly to users | CRITICAL |
| HANADB-PRIV-003 | Broad system privileges granted directly to users | HIGH |
| HANADB-PRIV-004 | Sensitive privileges granted WITH ADMIN OPTION | MEDIUM |
| HANADB-PRIV-005 | Analytic-privilege bypass (`_SYS_BI_CP_ALL`) granted | CRITICAL |
| HANADB-PRIV-006 | Debug privileges (DEBUG / ATTACH DEBUGGER) granted to users | HIGH |

### Roles & Auditing (HANADB-ROLE-* / HANADB-AUDIT-*)
| Check | Description | Severity |
|-------|-------------|----------|
| HANADB-ROLE-001 | Powerful predefined roles granted to users | HIGH |
| HANADB-AUDIT-001 | HANA database auditing is disabled | CRITICAL |
| HANADB-AUDIT-002 | Audit trail written to a CSV text file (tamperable) | HIGH |
| HANADB-AUDIT-003 | No active HANA audit policies | HIGH |
| HANADB-AUDIT-004 | Audit policies do not cover critical action groups | MEDIUM |

### Security Parameters (HANADB-PARAM-*)
| Check | Description | Severity |
|-------|-------------|----------|
| HANADB-PARAM-001 | Weak HANA password-policy parameters | HIGH |
| HANADB-PARAM-002 | Detailed connect errors exposed to clients | MEDIUM |
| HANADB-PARAM-003 | TLS not enforced for HANA SQL connections | HIGH |
| HANADB-PARAM-004 | `log_mode = overwrite` — no point-in-time recovery | HIGH |
| HANADB-PARAM-005 | Cross-database (MDC) access is enabled | MEDIUM |

*Distinct from Cryptographic Posture's `CRYPTO-HANA-*` (encryption-at-rest); this module covers users, privileges, auditing and ini parameters.*

</details>

<details>
<summary><strong>📰 SAP Security Notes / HotNews — Full Check List</strong></summary>

| Check | Description | Severity |
|-------|-------------|----------|
| HOTNEWS-000 | SAP Note implementation status not provided (no SNOTE export) | MEDIUM |
| HOTNEWS-001 | Missing HotNews (Priority 1) SAP Security Notes | CRITICAL |
| HOTNEWS-002 | Missing High-priority (Priority 2) SAP Security Notes | HIGH |
| HOTNEWS-003 | Missing notes for actively-exploited SAP vulnerabilities (CISA KEV) | CRITICAL |
| HOTNEWS-004 | Critical SAP Notes only partially implemented | HIGH |
| HOTNEWS-005 | Catalogue notes this system's export can neither confirm nor deny | INFO |
| HOTNEWS-006 | Installed release is inside the affected range of an unpatched note | CRITICAL |
| HOTNEWS-007 | Unpatched notes exploitable without any credentials | HIGH |
| HOTNEWS-008 | Unpatched note with a documented workaround not applied | HIGH |
| HOTNEWS-009 | Workaround applied but the note itself is still missing | MEDIUM |
| HOTNEWS-010 | Exposure could not be established for some notes | INFO |
| HOTNEWS-011 | Note facts differ between this catalogue and SAP's published record | LOW |
| HOTNEWS-012 | SAP-published HotNews notes absent from the applied-notes export (applicability undetermined) | HIGH |
| HOTNEWS-013 | Installed component, kernel or HANA revision is below the level that fixes an unpatched note | CRITICAL |

Diffs your `applied_notes.csv` (SNOTE export) against two catalogues. The first is a curated set of major notes since 2020 — RECON (CVE-2020-6287), ICMAD (CVE-2022-22536), the 2025 NetWeaver VC RCE (CVE-2025-31324) — carrying exploitation evidence, affected-release ranges and documented workarounds. The second is **SAP's own published record**: `data/sap_notes_catalogue.json`, generated from `SAP-samples/frun-csa-policies-best-practices` (Apache-2.0) and holding 1,732 notes across 154 patch days from 2016-01, with SAP's own declaration of which notes each policy does *not* check.

Note matching is leading-zero-insensitive; not-yet-implemented statuses fail safe to "missing". **HOTNEWS-013 is a determination, not a worklist**: SAP publishes the level carrying each fix — a support package (note 3772411 → SAP_BASIS 750 at SP 0037, 752 at 0019, 753 at 0017), a kernel patch level, or a HANA revision (note 2424173 → 1.00.122.07) — your `system_component.csv`, `sap_kernel.csv` and `hana_version.csv` say what is installed, and the arithmetic between them is the only part this product contributes. SAP's SQL is neither executed nor reproduced. HOTNEWS-012 keeps what that could not settle — an installed release SAP's list does not mention, an affected range expressed in a form this product declines to interpret, or no component export at all — and says which. HOTNEWS-011 compares the two catalogues and reports differences **without adjudicating**: NVD and SAP as CNA publish different base scores for the same CVE (8.8 vs 9.9 for CVE-2021-38176, differing on Scope), and for CVE-2022-41204 SAP's policy header differs from SAP's own CNA record. Extensible via an optional `sap_security_notes.json`.

</details>

<details>
<summary><strong>🔓 ABAP Authorization & Critical Access — Full Check List</strong></summary>

Role-content analysis of the **AGR_1251** export (role → object → field → value), attributing each risky role to the users who hold it.

| Check | Description | Severity |
|-------|-------------|----------|
| AUTH-001 | Debug & Replace authorization (runtime authorization bypass) | CRITICAL |
| AUTH-002 | Trusted-RFC logon as any user (S_RFCACL wildcard) | CRITICAL |
| AUTH-003 | Unrestricted external OS-command execution (S_LOG_COM) | CRITICAL |
| AUTH-004 | Authorization forging via role-content control objects (S_USER_AUT) | CRITICAL |
| AUTH-005 | Role allows starting any transaction (S_TCODE = *) | CRITICAL |
| AUTH-006 | Broad RFC authorization (S_RFC RFC_NAME = *) | HIGH |
| AUTH-007 | Generic table write via S_TABU_NAM (TABLE = *) | HIGH |
| AUTH-008 | Generic table maintenance via S_TABU_DIS (all / no auth group) | HIGH |
| AUTH-009 | Cross-client table maintenance (S_TABU_CLI) | HIGH |
| AUTH-010 | Arbitrary OS file access from ABAP (S_DATASET) | HIGH |
| AUTH-011 | Run-any-report authorization (S_PROGRAM) | HIGH |
| AUTH-012 | Background-job impersonation (S_BTCH_NAM BTCUNAME = *) | HIGH |
| AUTH-013 | Sensitive Basis / administration transactions in roles | HIGH |
| AUTH-014 | ABAP development change access (S_DEVELOP create/change) | HIGH |
| AUTH-015 | Global authorization-object disabling is active | MEDIUM |
| AUTH-016 | Unrestricted destination authorization (S_ICF ICF_FIELD=DEST, ICF_VALUE=*) | HIGH |

</details>

<details>
<summary><strong>🔗 System Trust & Standard Users — Full Check List</strong></summary>

### Standard / Default Users (STDUSR-*)
| Check | Description | Severity |
|-------|-------------|----------|
| STDUSR-001 | SAP* kernel emergency-user auto-logon enabled | CRITICAL |
| STDUSR-002 | Standard users still have SAP default passwords | CRITICAL |
| STDUSR-003 | Standard users not locked (SAP*/DDIC/SAPCPIC/EARLYWATCH/TMSADM) | HIGH |

### System Trust (TRUST-*)
| Check | Description | Severity |
|-------|-------------|----------|
| TRUST-001 | Inbound trusted-RFC relationships (verify tier) | HIGH/MEDIUM |
| TRUST-002 | RFC self-trust enabled | HIGH |
| TRUST-003 | Trust not migrated to current security method | HIGH |
| TRUST-004 | Trusted RFC destination with a fixed logon user | HIGH |
| TRUST-005 | SAProuter route table allows wildcard host/port | HIGH |
| TRUST-006 | Message-server internal/external separation weak | HIGH |
| TRUST-007 | UCON RFC allowlist not active | HIGH |
| TRUST-008 | RFC Gateway proxy ACL (gw/prxy_info) not configured | MEDIUM |

</details>

<details>
<summary><strong>🧱 Security Baseline Parameters — Full Check List</strong></summary>

SAP Security Baseline / DSAG / CIS profile parameters the other modules don't cover (from `security_params.csv`).

| Check | Description | Severity |
|-------|-------------|----------|
| BASELINE-001 | RFC authorization check disabled (auth/rfc_authority_check = 0) | HIGH |
| BASELINE-002 | Profile-generator auth checks not active (auth/no_check_in_some_cases) | HIGH |
| BASELINE-003 | SNC accepts insecure (unencrypted) connections | HIGH |
| BASELINE-004 | SAP GUI Scripting enabled server-side (sapgui/user_scripting) | HIGH |
| BASELINE-005 | Weak legacy password hashes retained (downwards compatibility) | HIGH |
| BASELINE-006 | sapstartsrv / Host Agent web methods not protected | HIGH |
| BASELINE-007 | RFC Gateway default ACL not enforced (gw/acl_mode) | MEDIUM |
| BASELINE-008 | SSO ticket / session-cookie transport not hardened | MEDIUM |
| BASELINE-009 | Web-tier logging / error disclosure weak (ICM security log) | MEDIUM |
| BASELINE-010 | Existing passwords not forced to current policy | MEDIUM |
| BASELINE-011 | Weak password hash algorithm (login/password_hash_algorithm) | HIGH |

</details>

<details>
<summary><strong>🧩 S/4HANA & Cloud Authorization — Full Check List</strong></summary>

| Check | Description | Severity |
|-------|-------------|----------|
| S4AUTHZ-001 | Super-admin business-role template assigned in production (SAP_BR_ADMINISTRATOR*) | CRITICAL |
| S4AUTHZ-002 | Business-role restriction left 'Unrestricted' | HIGH |
| S4AUTHZ-003 | Business role bundles more than 30 business catalogs | MEDIUM |
| S4AUTHZ-004 | CDS view exposes data with authorization checking disabled | HIGH |
| S4AUTHZ-005 | OData V4 service group published without authorization | HIGH |
| S4AUTHZ-006 | Cloud Connector system mapping without principal propagation | HIGH |
| S4AUTHZ-007 | Cloud Foundry privileged platform role over-assigned | HIGH |
| S4AUTHZ-008 | Birthright role collection auto-granted to all federated users | MEDIUM |

</details>

<details>
<summary><strong>⚖️ Access Risk Analysis (SoD) — Full Risk List</strong></summary>

GRC-style **offline, permission-level** Segregation of Duties from AGR_1251 + AGR_USERS. Each risk resolves the user's transaction codes **and** authorization object/field/activity across all roles; a conflict fires only when the *maintain* activity is held (display-only access is not a false positive). Documented mitigating controls (with expiry) suppress a user/risk and are reported as residual.

### Segregation-of-Duties conflicts (25)
| Risk | Conflict | Severity |
|------|----------|----------|
| ARA-P2P-01 | Maintain Vendor Master ↔ Process/Execute Vendor Payment | CRITICAL |
| ARA-P2P-02 | Maintain Vendor Bank Details ↔ Run Automatic Payment Program | CRITICAL |
| ARA-P2P-03 | Create/Change Purchase Order ↔ Release Purchase Order | HIGH |
| ARA-P2P-04 | Create Purchase Order ↔ Post Goods Receipt | HIGH |
| ARA-P2P-05 | Create Purchase Order ↔ Post Vendor Invoice (MIRO) | HIGH |
| ARA-P2P-06 | Maintain Vendor Master ↔ Post AP (Non-PO) Vendor Invoice | CRITICAL |
| ARA-O2C-01 | Maintain Customer Master ↔ Create Sales Order | HIGH |
| ARA-O2C-02 | Maintain Customer Credit Limit ↔ Release Credit-Blocked Order | HIGH |
| ARA-O2C-03 | Post/Clear Incoming Customer Payments ↔ Maintain Customer Master | CRITICAL |
| ARA-O2C-04 | Maintain Pricing/Condition Records ↔ Create Sales Order | HIGH |
| ARA-O2C-05 | Post Billing Document ↔ Maintain Customer Master | HIGH |
| ARA-O2C-06 | Create Sales Order ↔ Release Own Credit-Blocked Order | HIGH |
| ARA-R2R-01 | Maintain G/L Account Master ↔ Post Journal Entries | CRITICAL |
| ARA-R2R-02 | Maintain G/L Account Master ↔ Open/Close Posting Periods | HIGH |
| ARA-R2R-03 | Enter/Park ↔ Post Journal Entries (four-eyes bypass) | HIGH |
| ARA-R2R-04 | Maintain Exchange Rates ↔ Post Journal Entries | HIGH |
| ARA-R2R-05 | Open/Close Posting Periods ↔ Post Journal Entries | HIGH |
| ARA-H2R-01 | Maintain HR Master Data ↔ Execute Payroll Run | CRITICAL |
| ARA-H2R-02 | Maintain Employee Bank Details ↔ Run Payroll / Generate Payments | CRITICAL |
| ARA-H2R-03 | Maintain Personnel Actions (Hire/Terminate) ↔ Maintain Time Data | HIGH |
| ARA-H2R-04 | Execute Payroll Run ↔ Post Payroll Results to Accounting | HIGH |
| ARA-BASIS-01 | User Administration ↔ Authorization/Profile Administration | CRITICAL |
| ARA-BASIS-02 | Maintain Role ↔ Assign Role to User | HIGH |
| ARA-BASIS-03 | ABAP Development ↔ Transport Release/Import to Production | HIGH |
| ARA-BASIS-04 | Maintain Table Data ↔ Administer Security Audit Log | HIGH |

### Critical access + risk profile
| Risk | Description | Severity |
|------|-------------|----------|
| ARA-CA-04 | Change Payroll Status / Delete Payroll Results (PU03/PU01) | HIGH |
| ARA-CP-05 | Maintain Own HR Master Data (P_PERNR PSIGN=I) | HIGH |
| ARA-SCORE-001 | Users concentrating ≥2 unmitigated access risks (severity-weighted) | HIGH/MEDIUM |

</details>

<details>
<summary><strong>⚙️ Basis Jobs & OS Commands — Full Check List</strong></summary>

### External OS-command definitions (JOBCMD-CMD-*) — from SM69 / SXPGCOSTAB
| Check | Description | Severity |
|-------|-------------|----------|
| JOBCMD-CMD-001 | External OS command wraps a shell/interpreter or embeds shell metacharacters | CRITICAL |
| JOBCMD-CMD-002 | External OS command allows runtime additional parameters (ADDPAR = X) | HIGH |
| JOBCMD-CMD-003 | External OS command resolves to an unqualified (PATH-hijack) or user-writable path | HIGH |
| JOBCMD-CMD-004 | Destructive / exfiltration utility defined as a standing command (rm/dd/curl/nc/…) | MEDIUM |
| JOBCMD-CMD-005 | External OS command not bound to a specific operating system | LOW |

### Background jobs & step users (JOBCMD-JOB-*) — from TBTCO / TBTCP
| Check | Description | Severity |
|-------|-------------|----------|
| JOBCMD-JOB-001 | Armed job runs under SAP*/DDIC or a SAP_ALL step user | CRITICAL |
| JOBCMD-JOB-001B | Armed job runs under a standard/technical step user (SAPCPIC/EARLYWATCH/TMSADM) | HIGH |
| JOBCMD-JOB-002 | Job step executes an external OS command / program | HIGH |
| JOBCMD-JOB-003 | Job runs RSBDCOS0 (SM69-allowlist bypass) or unreviewed custom code under a privileged user | HIGH |
| JOBCMD-JOB-004 | Armed job step user is deleted, locked, expired, or a dialog user | MEDIUM |
| JOBCMD-JOB-005 | Job step user differs from scheduler (identity borrowing) | MEDIUM |

Only *armed* jobs (STATUS scheduled/released/ready/active) are evaluated; finished/cancelled jobs are out of scope. Complements the ABAP Authorization module (`authz`), which covers who is *authorized* to run commands / set a foreign step user (S_LOG_COM, S_BTCH_NAM) — this module reports the *actual* command catalog and the *actual* scheduled jobs.

</details>

---


<sub>[↑ Contents](#contents)</sub>

## Quick Start

```bash
git clone https://github.com/Krishcalin/SAP-S4HANA-RISE-Security-Scanner.git
cd SAP-S4HANA-RISE-Security-Scanner

# Run against sample data (included)
python sap_scanner.py --data-dir ./sample_data --output report.html

# Generate the detailed PDF hand-over report, the PPTX deck, or several at once
python sap_scanner.py --data-dir ./exports --output report.pdf  --format pdf
python sap_scanner.py --data-dir ./exports --output report.html --format both   # HTML + PDF
python sap_scanner.py --data-dir ./exports --output report.pptx --format pptx    # one slide per finding
python sap_scanner.py --data-dir ./exports --output report.pptx --format pptx --pptx-mode summary  # short exec deck
python sap_scanner.py --data-dir ./exports --output report.html --format all     # HTML + PDF + PPTX

# Run specific modules
python sap_scanner.py --data-dir ./exports --modules btpcloud iam
python sap_scanner.py --data-dir ./exports --modules intglayer network

# Filter by severity
python sap_scanner.py --data-dir ./exports --severity HIGH

# Custom thresholds
python sap_scanner.py --data-dir ./exports --config baseline.json

# Cyber-risk quantification (FAIR): embed a dollar-denominated loss exposure in the report
python sap_scanner.py --data-dir ./exports --output report.html --format both --crq \
    --crq-revenue 2000000000 --crq-industry manufacturing --crq-org-name "Acme Manufacturing"

# Tell the scanner which estate this is — it changes what "compliant" means (see below)
python sap_scanner.py --data-dir ./exports --deployment-mode rise_pce
# modes: on_prem · rise_pce · rise_tailored · rise_ecc  (ECC running inside RISE)

# Scan custom ABAP from an abapGit offline export (the `cva` module)
python sap_scanner.py --data-dir ./exports --abap-src ./abapgit_export --modules cva

# Scan a CAP project's own source — xs-security.json and the CDS model (the `capxsuaa` module)
python sap_scanner.py --data-dir ./exports --cap-src ./bookshop --modules capxsuaa

# Use it as a release gate in CI — exits 0 pass / 1 blocked / 2 could not assess
python sap_scanner.py --data-dir ./exports --gate-write-baseline gate-baseline.json   # once
python sap_scanner.py --data-dir ./exports --gate --gate-baseline gate-baseline.json  # every build
```

### Available Modules

```
users     — User & Authorization (USR-*)
iam       — Advanced IAM (IAM-*)
params    — Security Parameters (PARAM-*)
network   — Network & Service Exposure (NET-*)
rise      — RISE / BTP Core (RISE-*)
btpcloud  — BTP Cloud Attack Surface (BTP-*)
intglayer — Network & Integration Layer (INTG-*)
dataprot  — Data Protection & Privacy (DPP-*)
codetrans — Code & Transport Security (CODE-*)
logmon    — Logging, Monitoring & IR (LOG-*)
fiori     — Fiori & UI Layer (FIORI-*)
crypto    — Cryptographic Posture (CRYPTO-*)
hanadb    — HANA Database Security (HANADB-*)
hotnews   — SAP Security Notes / HotNews (HOTNEWS-*)
authz     — ABAP Authorization & Critical Access (AUTH-*)
systrust  — System Trust & Standard Users (TRUST-*, STDUSR-*)
baseline  — Security Baseline Parameters (BASELINE-*)
s4authz   — S/4HANA & Cloud Authorization (S4AUTHZ-*)
ara       — Access Risk Analysis / offline SoD (ARA-*)
jobcmd    — Basis Jobs & OS Commands (JOBCMD-*)
grcac     — GRC Access Control (GRC-*)
rolegov   — Role Design & Governance (RG-*)
fincontrols — Financial Controls / SOX (FIN-*)
atc       — SAP ATC / CVA result import (ATC-*)
cva       — Custom-code ABAP/CDS/RAP scanner (ABAP-*)   ← needs --abap-src
capxsuaa  — CAP & XSUAA application security (CAPX-*)   ← needs --cap-src
logreview — Security Audit Log retrospective review (LREV-*)
codeinv   — Custom-code inventory & dead code (CODE-INV-*)
resilience— Backup / DR / recovery posture (RES-*)
snc       — SNC posture as one model (CRYPTO-SNCECS-*)
ecsconfig — ECS mandatory configuration, Note 3250501 (…-ECS-*)
all       — Run everything (default)
```

That is the complete list — all 33 keys, matching `--modules` exactly.

Examples with the newer modules:

```bash
# Offline Segregation-of-Duties + ABAP critical-access review
python sap_scanner.py --data-dir ./exports --modules ara authz

# HANA DB hardening + missing SAP Security Notes
python sap_scanner.py --data-dir ./exports --modules hanadb hotnews

# System trust, standard users, and Security Baseline parameters
python sap_scanner.py --data-dir ./exports --modules systrust baseline
```

---


<sub>[↑ Contents](#contents)</sub>

## Release Gate

`--gate` turns the scanner from something that *reports* into something that **decides**, so it can sit in a pipeline. Full adoption guidance is in [`docs/RELEASE_GATE.md`](docs/RELEASE_GATE.md).

| Exit | Meaning |
|:---:|---|
| **0** | Pass — nothing in scope got worse |
| **1** | Blocked — the policy was violated |
| **2** | Could not assess — coverage was degraded, so no verdict is claimed |

```bash
# 1. Record where you are today. Runs a full scan and writes a report as well.
python sap_scanner.py --data-dir ./exports --gate-write-baseline gate-baseline.json

# 2. Enforce on every build.
python sap_scanner.py --data-dir ./exports --gate --gate-baseline gate-baseline.json

# Optional: scope to the objects a transport actually touches, and emit machine-readable output
python sap_scanner.py --data-dir ./exports --gate --gate-baseline gate-baseline.json \
    --gate-scope transport-objects.json --gate-policy gate-policy.json --gate-json gate.json
```

Four rules, each drawn from a specific way gates get switched off in practice:

- **Judge the delta, not the backlog.** A gate that fails on pre-existing findings is disabled in a week.
- **Judge only what the transport touches.** `--gate-scope` narrows the verdict to the objects under change. The file may be a JSON list, a JSON object with an `objects` list, or one object name per line with `#` comments. A scope file naming nothing is **refused** (`exit 2`, cannot-assess) rather than obeyed — narrowing the gate to nothing would pass every build.
- **Never block on what the customer cannot fix.** In RISE, a `ticket_to_sap` finding is not the developer's to resolve, and failing their build for it teaches them to bypass the gate.
- **Never fail open.** Degraded coverage is exit **2**, never a pass — an unassessable build must not look like a clean one.

> One thing worth knowing before you wire it up: `--gate-write-baseline` is evaluated **before** `--gate`, so passing both in one command writes the baseline and skips evaluation. An empty finding set no longer returns **pass** on its own — the gate is told how many checks executed, and "nothing failed" is only a result when that number is greater than zero.

---


<sub>[↑ Contents](#contents)</sub>

## Reports

Choose the output with `--format html` (default), `pdf`, `pptx`, `both` (html+pdf), or `all` (html+pdf+pptx). The output path's extension is respected; companion files are written alongside it. All three engines are **pure standard library** — no `python-pptx`, no `reportlab`.

| Format | Best for | Contents |
|--------|----------|----------|
| **HTML** | Interactive triage | Clean, light-themed dashboard (MonitorRisk + SAP branding) with an overall risk score, the P1–P4 priority queue, severity/category breakdown, a compliance-mapping panel, a live severity filter, and collapsible findings — each with its detailed risk narrative and step-by-step remediation. Single self-contained file (logos embedded as data URIs). |
| **PDF** | Formal hand-over to the SAP Basis / security team | A multi-page assessment report ordered **cover → risk-priority queue (P1–P4) → findings-by-area → compliance mapping → per-finding detail pages** (fix-first order), each with the affected objects, a detailed **Security Risk** explanation, a numbered step-by-step **Remediation** procedure, and references. Running header/footer, page numbers, confidentiality banner. Built with a **pure-standard-library PDF engine**. |
| **PPTX** | Presenting findings in a meeting / to leadership | A PowerPoint deck. `--pptx-mode full` (default) = title, executive summary, priority queue, findings-by-area, recommended actions, a compliance snapshot + one slide per framework, then **one slide per finding** (fix-first, ~300+ slides) with severity/priority chips, exploit tags, and a summarized Security Risk + High-Level Mitigation. `--pptx-mode summary` = a short executive-only deck. Built with a **pure-standard-library OOXML/PPTX engine**. |

### Risk prioritization (P1–P4)

Findings are ranked **P1 (fix now) → P4 (backlog)** by combining severity with exploitability (actively-exploited / CISA-KEV, HotNews), internet/exposure, and privilege. The reports lead with this queue and order the detailed findings fix-first, so the highest-leverage work is unmistakable.

### Compliance mapping

Every category is mapped to control frameworks and rendered as a per-framework panel (flagged controls with severity counts) in the HTML and PDF, and as dedicated slides in the PPTX deck. **Nine frameworks**: **ISO/IEC 27001:2022** (Annex A), **NIST CSF 2.0**, **NIST SP 800-53 Rev 5**, **DORA** (Regulation (EU) 2022/2554), **CIS Controls v8**, **TISAX / VDA ISA**, **SOC 2** (Trust Services Criteria), **SOX / ITGC**, and **EU GDPR**. All control IDs are verified against the published frameworks. DORA and SOX/ITGC are mapped to named requirement areas rather than clause numbers — DORA publishes articles this product has not verified clause by clause, and ITGC publishes no numbered catalogue at all. An auditor reading a citation expects the sub-paragraph to say what we imply it says.

### The twelve security domains

The same findings, arranged in the vocabulary the SAP security market talks in, so a reader
holding an RFP checklist can match them line for line. It appears on the dashboard, on
`/domains` and `/domains/{id}` in the console, as a `?domain=` filter on the triage queue, and
as one slide in the PPTX deck — all from one module (`modules/domains.py`), because a screen
and a slide that sort the same findings by two copies of the same rules eventually disagree.
The HTML and PDF reports deliberately carry **no** domain section: they are the long-form
hand-over documents and are kept simple.

Every domain carries **two facts that are not the same question**:

| | |
|---|---|
| **Reach** | What this product can *ever* see in that domain. A property of the product, fixed, identical for every customer. |
| **State** | What *this* scan found: findings · no findings · export not supplied · not assessed. |

That separation is the point. This is an offline, point-in-time **configuration** assessment,
and four of the twelve domains name **continuous** activities — event monitoring, interface
traffic, user behaviour, exploit protection. Twelve tiles each showing a number would assert
twelve capabilities and four of them would be false, so the limit is printed beside the count
rather than left to a footnote:

| Domain | Reach | What that means here |
|---|---|---|
| Baselining and Benchmarking | fully assessed | |
| Access and Authorization | fully assessed | |
| Identity Security | fully assessed | |
| Violation Management | fully assessed | SoD at permission level |
| Custom Code Security | fully assessed | 133 rules over the ABAP/UI5 you export. **Not** SAP's Code Vulnerability Analyzer, which is a separately licensed SAP product — so the tile does not carry that name |
| Security & Compliance Monitoring | partly assessed | point-in-time, and there is no compliance score |
| Patch and Hotnews Management | partly assessed | a curated subset of high-impact Notes, with its size and cut-off stated |
| Comprehensive Transport Security | partly assessed | the route and change control, not transport payloads |
| Suspicious User Behaviour | partly assessed | a pattern library run **retrospectively** over the log window you export — not behavioural analytics, not live |
| Security Event Monitoring | configuration only | whether the audit log *could* have recorded the answer. We do not monitor events |
| Interface Traffic Monitoring | configuration only | destinations, gateway ACLs, exposed services. We do not see traffic |
| Exploit and 0-Day Protection | **not covered** | a runtime capability needing an agent; we hold no connection. Prints a dash, never a zero |

Membership is a strict partition — every finding lands in exactly one domain, so the tiles add
up to the corpus rather than exceeding it. Findings the vocabulary has no word for (BTP,
RISE shared-responsibility, resilience) are **listed with the reason** rather than dropped.
There is no score, no percentage and no maturity rating: we see your findings, not your
control environment.

### Detailed findings — knowledge base

Every finding is rendered with an in-depth **Security Risk** explanation (what the weakness is, the concrete attack/abuse scenario, and the business/compliance impact) and a **numbered, step-by-step remediation procedure** naming the exact SAP transactions, reports, IMG paths, parameters and tables to change, how to verify the fix, and rollout cautions. This content lives in a bundled knowledge base (`data/finding_details.json`) keyed by check-id (with family-prefix fallback); where an entry is absent, the report falls back to the finding's own description and remediation, so the report is always complete.

### Cyber-risk quantification — FAIR *(optional, `--crq`)*

Run with `--crq` to translate the technical findings into **financial risk** using the [FAIR](https://www.fairinstitute.org/) (Factor Analysis of Information Risk) model and a Monte-Carlo simulation. The report gains a **Financial Risk Exposure** section: the expected annual loss (mean ALE), the **1-in-10 bad year (ALE P90)**, a **loss-exceedance curve**, a per-scenario breakdown, and the **dollar amount reducible by remediation** (as-is posture vs. a fully-hardened target).

How it stays methodologically honest:

- **A finding is not a risk.** Findings are treated as *evidence that shifts the FAIR factors* of a small set of scoped SAP loss scenarios (internet-facing RCE→ransomware, SoD/financial-controls→payment fraud, privileged/standard-user takeover, HANA data exfiltration→GDPR breach, interface/integration→lateral movement) — never assigned their own dollar figure and summed.
- **Calibration is range-selection, not arithmetic on CVSS.** The worst open *prevention* finding selects a Resistance-Strength band; the scanner's existing `exposed`/`exploited` signals select the Contact-Frequency and Probability-of-Action bands. Logging/monitoring gaps aren't a scenario — they set a **dwell-time loss multiplier** (weak detection ⇒ longer dwell ⇒ larger loss, per FAIR-CAM).
- **Correct aggregation.** The portfolio ALE is the element-wise Monte-Carlo sum of the independent per-scenario loss distributions — *never* a sum of percentiles.
- **Report filters never move a claim about the estate.** `--severity` decides what is LISTED, never what was found. The FAIR figure, the risk-posture score, the NIST CSF roll-up, the FAIR-CAM control map and the compliance mapping are all computed on the **complete** finding set; the finding tables, severity cards and P1–P4 queue obey the filter, which is what the flag is for. Where the two disagree the report says so, in print and on the deck's title slide. *(This was FAIR-only until 2026-08-14: on `--severity HIGH` a CSF Category with real MEDIUM findings rendered the green “no findings” chip, and the headline posture moved from 100/100 Critical to 50/100 High with no change in the data.)*
- **The posture score is a density, and it can go down.** It is `worst severity per check ÷ checks that actually ran`, rescaled so that **100** would mean every check that ran found a *critical*; **40**, a high; **16**, a medium; **4**, a low. The bands are the severity weights, not round numbers, and every report prints that anchor beside the figure together with **how many checks it was computed over**. Closing findings **moves it**. If no coverage manifest can be built, the report prints **“Not scored”** rather than a number. *(Until 2026-08-14 it was `min(100, crit×25 + high×10 + …)` — on the bundled sample data that total is 3693, so it printed 100 and stayed at 100 no matter how much was remediated. Reports from before that date are on the old scale and are not comparable.)*
- **Every check is countable before it fails.** A check id is written three ways — a `check_id="X"` keyword, passed positionally to an emitter wrapper (`_emit("AUTH-001", …)`), or composed at runtime from a shipped rule table (`PARAM-` + a parameter name). The coverage derivation used to read only the first, so **78 of the 333** ids a real scan emits were invisible until one failed. A denominator that learns of a check by being failed by it is a tally of failures, and it meant *discovering more problems lowered the score* — 120 new findings moved the bundled sample from 38 to 29 with nothing remediated. `coverage.all_check_ids()` now unions all three readers, and the reference generator shares the same definitions rather than keeping a second copy.
- **What the score does *not* promise.** It is a mean over the assessed portion, and no mean is immune to subsetting: removing a check whose severity is above the estate’s own average pulls the average down, so withholding an export can still nudge it. That is arithmetic (`new < old ⟺ w > Σw/A`), not an implementation gap, and a standalone offline report has no prior run to hold the denominator against. What **is** eliminated is the large, systematic version: a module that ran on partial input is no longer credited with the checks it never got to run, no single check contributes more than once however many objects it fires on, and the denominator no longer grows only on failure. Measured by removing each of the 108 bundled exports in turn — **61 of 108** removals lowered the score before those fixes, by up to 4 points; **3 of 108** do now, by 1–2. The residue is why the scope sentence is printed next to the number and why the coverage section comes before the findings: the condition is stated rather than assumed away.
- **Honest by construction.** Loss magnitudes are **priced from figures you supply** in `crq_parameters.json`; without them **no currency total is presented as your exposure** — the shipped catalogue is calibrated to an illustrative $1bn manufacturer and printing its losses under your name would be a fabrication. The report says which components came from your answers and which went unpriced, and the scenario input is exported alongside as `*.crq.json`.

The Monte-Carlo engine is **bundled** (`modules/crq_engine.py`, standard library only), so `--crq` produces an actual number on a plain checkout. It is deliberately **last** in the lookup order, so `--crq-engine`, the `CRQ_ENGINE` env var and a sibling [Cyber-Risk-Quantification](https://github.com/Krishcalin/Cyber-Risk-Quantification) checkout all still take precedence. If no engine resolves at all, the scanner still exports the `*.crq.json` scenario input so you can quantify it standalone — there is **no hard dependency** on the sibling repo.

> The engine was bundled because the sibling repo is absent from a normal checkout, so `--crq` used to degrade silently to "inputs exported, not simulated" and produce no figure at all.

| Flag | Purpose |
|------|---------|
| `--crq` | Enable FAIR quantification; write `<output>.crq.json` and embed the ALE + loss-exceedance curve in the HTML/PDF report |
| `--crq-revenue` | Organization annual revenue (USD) for the loss scaling (default: illustrative $1B) |
| `--crq-industry` | Industry **label** printed on the report. It scales nothing — there is no industry multiplier in the engine and there never has been (`financial_services`, `healthcare`, `technology`, `retail`, `manufacturing`, `government`, `energy`, `education`) |
| `--crq-org-name` | Organization name shown in the report |
| `--crq-sims` | Monte-Carlo iterations per scenario (default: 10000) |
| `--crq-engine` | Explicit path to `crq_engine.py` (overrides auto-detect / `CRQ_ENGINE`) |

---


<sub>[↑ Contents](#contents)</sub>

## Data Sources

All files are optional — the scanner runs only checks for which data is available. See [`docs/EXPORT_GUIDE.md`](docs/EXPORT_GUIDE.md) for detailed export instructions.

<details>
<summary><strong>📋 Core & IAM data files</strong></summary>

| File | Source | Description |
|------|--------|-------------|
| `users.csv` | RSUSR002 / SU01 | User master data (BNAME, USTYP, UFLAG, TRDAT, etc.) |
| `profiles.csv` | SU02 / USR04 | Profile assignments |
| `user_roles.csv` | AGR_USERS | Role assignments |
| `auth_objects.csv` | SUIM | Authorization object values |
| `security_params.csv` | RSPARAM / RZ11 | Profile parameter values |
| `rfc_destinations.csv` | SM59 | RFC destination configs |
| `icf_services.csv` | SICF | ICF service tree |
| `audit_config.csv` | SM19 | Audit log filter config |
| `transports.csv` | SE09 / STMS | Transport requests |
| `sod_matrix.csv` | SUIM / GRC ARA | Pre-computed user→tcode mapping |
| `role_tcodes.csv` | AGR_1251 | Role→tcode mapping |
| `sod_ruleset.json` | Custom | Custom SoD rule definitions |
| `firefighter_log.csv` | GRC SPM | Emergency access usage log |
| `role_expiry.csv` | AGR_USERS validity | Role assignments with dates |
| `role_details.csv` | AGR_DEFINE | Role metadata (owner, description) |
| `access_reviews.csv` | GRC ARM | Access review campaign data |
| `user_groups.csv` | USR02 | User group assignments |

</details>

<details>
<summary><strong>📋 BTP / RISE data files</strong></summary>

| File | Source | Description |
|------|--------|-------------|
| `btp_trust.json` | BTP Cockpit → Trust Config | Trust configurations |
| `comm_arrangements.json` | Fiori "Communication Arrangements" | Communication setups |
| `api_endpoints.json` | OData service catalog | Published API endpoints |
| `btp_users.json` | BTP Cockpit → Users | BTP user & role collections |
| `cloud_connector.json` | SCC Admin UI | Backends, ACLs, certificates |
| `btp_service_bindings.json` | BTP Service Manager API | Service bindings |
| `btp_destinations.json` | Destination Service API | Destination configs |
| `ias_config.json` | IAS Admin Console | Application & policy config |
| `btp_entitlements.json` | BTP Cockpit / CLI | Entitlement quotas & usage |
| `event_mesh.json` | Event Mesh Management API | Queue/topic configs |
| `cpi_artifacts.json` | CPI Operations API | Credentials & iFlow metadata |
| `btp_network.json` | BTP Cockpit | Private Link / network config |
| `btp_subaccounts.json` | BTP Cockpit / CLI | Multi-subaccount governance |

</details>

<details>
<summary><strong>📋 Integration Layer data files</strong></summary>

| File | Source | Description |
|------|--------|-------------|
| `apim_policies.json` | API Management admin | Proxy & policy configurations |
| `idoc_ports.csv` | WE21 | IDOC port configurations |
| `idoc_partners.csv` | WE20 | IDOC partner profiles |
| `ws_endpoints.csv` | SOAMANAGER | Web service endpoints |
| `webhooks.json` | Event / webhook registry | Callback registrations |
| `gw_secinfo.csv` | Gateway secinfo file | Program start ACL rules |
| `gw_reginfo.csv` | Gateway reginfo file | RFC registration ACL rules |
| `integration_alerts.json` | Alert Notification Service | Monitoring alert config |
| `cpi_datastores.json` | CPI Operations API | Data stores & global variables |
| `oauth_clients.json` | XSUAA / IAS admin | OAuth client registrations |
| `integration_topology.json` | Manual / discovery tool | System-to-system connection map |

</details>

<details>
<summary><strong>📋 Data Protection & Privacy data files</strong></summary>

| File | Source | Description |
|------|--------|-------------|
| `ral_config.csv` | SRALMANAGER | RAL configuration & active rules |
| `ral_log_channels.csv` | SRALMANAGER | RAL log channel retention settings |
| `ilm_policies.json` | IRMPOL / ILM Cockpit | ILM retention & destruction rules |
| `data_masking.json` | TDMS / DPI config | Non-production masking configuration |
| `dpp_config.json` | DPP Toolkit Fiori apps | DPP feature enablement status |
| `purpose_of_processing.csv` | ROPA / DPP config | Purpose definitions with legal basis |
| `sensitive_fields.csv` | Data classification inventory | PII field classification & protection status |
| `data_residency.json` | Data governance / legal | Cross-border transfer configurations |
| `personal_data_inventory.csv` | DPI / manual inventory | Personal data field-level inventory |
| `deletion_requests.csv` | DSAR tracking system | Data subject request log |
| `system_landscape.csv` | System landscape inventory | System classification & data protection status |

</details>

<details>
<summary><strong>📋 Code, Transport & Change data files</strong></summary>

| File | Source | Description |
|------|--------|-------------|
| `custom_code_scan.csv` | ATC / Code Inspector / SCI | Static-analysis findings for custom ABAP |
| `code_inventory.csv` | Custom object inventory | Z/Y objects, owner, last-used |
| `transport_routes.csv` | STMS (transport routes) | TMS route/layer definitions |
| `transport_history.csv` | STMS import history | Import log per system (who/when) |
| `client_settings.csv` | SCC4 | Client role & change options |
| `change_documents.csv` | CDHDR | Change-document header records |
| `sap_modifications.csv` | SE95 / SPAU | Modifications to SAP standard objects |
| `dev_access_prod.csv` | SUIM / user-auth export | Developer access present in production |

</details>

<details>
<summary><strong>📋 Logging, Monitoring & IR data files</strong></summary>

| File | Source | Description |
|------|--------|-------------|
| `security_audit_log.csv` | SM19 / RSAU_CONFIG | Security Audit Log filters & status |
| `table_logging.csv` | DD09L | Table technical settings (change logging flag) |
| `logon_events.csv` | Logon statistics / SM20 | Logon success/failure counts per user |
| `siem_config.json` | SIEM / log-forwarding config | SIEM integration & forwarded sources |
| `log_retention.json` | Log housekeeping config | Retention & archiving settings |
| `incident_response.json` | IR readiness inventory | Incident-response process readiness |

</details>

<details>
<summary><strong>📋 Fiori & UI data files</strong></summary>

| File | Source | Description |
|------|--------|-------------|
| `fiori_catalogs.csv` | Launchpad Designer (FLPD) | Fiori catalogs & assigned roles |
| `fiori_tiles.csv` | Launchpad Designer | Tiles → target-mapping / OData service |
| `odata_auth.csv` | /IWFND/MAINT_SERVICE | OData services & authorization status |
| `fiori_spaces.json` | Spaces & Pages | Space/page visibility & role config |
| `fiori_app_usage.csv` | Usage statistics (ST03N / FLP) | App launch counts |

</details>

<details>
<summary><strong>📋 Cryptographic Posture data files</strong></summary>

| File | Source | Description |
|------|--------|-------------|
| `tls_config.csv` | ICM / Web Dispatcher SSL config | TLS protocols & cipher suites per endpoint |
| `certificate_inventory.csv` | STRUST | Certificate inventory (expiry, key size, algorithm) |
| `snc_config.csv` | RZ11 (snc/*) | SNC enablement & quality of protection |
| `hana_encryption.json` | HANA encryption config | Data/log volume encryption & key management |
| `crypto_library.csv` | CommonCryptoLib version export | SAP Crypto Library version |
| `pse_inventory.csv` | STRUST (PSE list) | PSE files & health |
| `key_management.json` | Key-management policy inventory | Rotation / backup policy status |

</details>

<details>
<summary><strong>📋 HANA Database Security data files</strong></summary>

| File | Source | Description |
|------|--------|-------------|
| `hana_db_users.csv` | HANA `SYS.USERS` | DB users (SYSTEM active, password lifetime, last connect) |
| `hana_granted_privileges.csv` | `GRANTED_PRIVILEGES` | System/object/analytic privileges & grantee (incl. PUBLIC) |
| `hana_granted_roles.csv` | `GRANTED_ROLES` | Role grants (predefined powerful roles) |
| `hana_parameters.csv` | `M_INIFILE_CONTENTS` | HANA ini parameters (password policy, TLS, error verbosity) |
| `hana_audit_policies.csv` | `AUDIT_POLICIES` | Audit policy status & covered action groups |

</details>

<details>
<summary><strong>📋 Authorization, Trust & Security-Notes data files</strong></summary>

| File | Source | Description |
|------|--------|-------------|
| `role_auth_values.csv` | AGR_1251 | Role → object/field/LOW/HIGH values (drives ABAP Authz **and** Access Risk Analysis) |
| `rfc_trust.csv` | RFCSYSACL / SMT1 | Trusted/trusting RFC relationships |
| `standard_users.csv` | RSUSR003 | Standard/default users: lock status & default-password flag |
| `saprouttab.csv` | SAProuter route table | Route permission (P/S) rules |
| `applied_notes.csv` | SNOTE / SNADM export | Implemented SAP Notes (diffed against the HotNews catalog) |
| `sap_security_notes.json` | *Optional* | Custom HotNews catalog to extend/override the built-in one |

</details>

<details>
<summary><strong>📋 S/4HANA & Cloud Authorization data files</strong></summary>

| File | Source | Description |
|------|--------|-------------|
| `business_roles.csv` | Maintain Business Roles | User ↔ business-role assignments |
| `business_role_restrictions.csv` | Business-role restrictions | Restriction fields & 'Unrestricted' access |
| `business_role_catalogs.csv` | Business-role catalogs | Business catalogs per role (sprawl) |
| `cds_views.csv` | CDS metadata / repository | `@AccessControl.authorizationCheck` per view |
| `odata_v4_services.csv` | /IWFND/V4_ADMIN | Published OData V4 service groups & authorization |
| `cf_roles.csv` | Cloud Foundry (cf CLI) | CF org/space platform-role assignments |
| `btp_role_collection_mappings.csv` | BTP Cockpit (Trust → Role Collections) | Role-collection → IdP-group mappings |

</details>

<details>
<summary><strong>📋 Access Risk Analysis (SoD) data files</strong></summary>

| File | Source | Description |
|------|--------|-------------|
| `role_auth_values.csv` | AGR_1251 | Per-role authorization object/field/value (shared with ABAP Authz) |
| `user_roles.csv` | AGR_USERS | User ↔ role assignments (shared with IAM) |
| `mitigating_controls.csv` | *Optional* (GRC / manual) | `USER, RISK_ID, CONTROL_ID, VALID_TO` — suppresses a mitigated risk |
| `ara_ruleset.json` | *Optional* | Custom SoD risks that extend/override the built-in 27-risk ruleset |

*Security Baseline Parameters (`baseline`) reuses `security_params.csv`; it needs no additional export.*

</details>

<details>
<summary><strong>📋 Basis Jobs & OS Commands data files</strong></summary>

| File | Source | Description |
|------|--------|-------------|
| `ext_os_commands.csv` | SM69 / table SXPGCOSTAB | Customer external OS commands: `NAME, OPSYSTEM, OPCOMMAND, PARAMETERS, ADDPAR` |
| `ext_os_commands_sap.csv` | table SXPGCOTABE | *Optional* — SAP-delivered logical commands (to diff against) |
| `background_jobs.csv` | SM37 / table TBTCO | Job header: `JOBNAME, JOBCOUNT, STATUS, SDLUNAME, AUTHCKNAM` (export STATUS in P/S/Y/R — armed jobs) |
| `background_job_steps.csv` | table TBTCP | Job steps: `JOBNAME, JOBCOUNT, STEPCOUNT, PROGNAME, XPGFLAG, EXTCMD, XPGPROG, AUTHCKNAM` |

Reuses `users.csv` (USR02) and `profiles.csv` (USR04) to resolve whether a job step user is SAP*/DDIC or a SAP_ALL holder, locked, expired or a dialog account.

</details>

---


<sub>[↑ Contents](#contents)</sub>

## Custom Baseline

Override default thresholds by creating a JSON config file:

```json
{
    "dormant_threshold_days": 60,
    "max_roles_per_user": 20,
    "max_password_age_days": 60,
    "max_role_validity_days": 365,
    "ff_max_duration_hours": 4,
    "ff_max_sessions_per_month": 5,
    "access_review_cycle_days": 90,
    "binding_rotation_max_days": 180,
    "cpi_credential_rotation_days": 180,
    "cert_expiry_warning_days": 90,
    "max_cc_backends": 20,
    "destination_stale_days": 365,
    "max_active_ws_endpoints": 50,
    "webhook_stale_days": 180,
    "oauth_client_stale_days": 180,
    "max_cpi_datastore_entries": 10000,
    "max_system_connections": 15,
    "ral_min_retention_days": 365,
    "max_retention_years": 10,
    "deletion_sla_days": 30,
    "hana_dormant_days": 90,
    "max_business_catalogs": 30,
    "max_cf_privileged_users": 5,
    "ara_user_risk_threshold": 2
}
```

Access Risk Analysis can also be driven by a **custom SoD ruleset** — drop an `ara_ruleset.json` into your `--data-dir` to extend or override the built-in 27-risk ruleset (entries matching a built-in `risk_id` override it; new ids are added).

---


<sub>[↑ Contents](#contents)</sub>

## Project Structure

```
SAP-S4HANA-RISE-Security-Scanner/
├── sap_scanner.py                  # Main entry point & CLI orchestrator
├── collect/                        # CONNECTED MODE — optional, out-of-process, stdlib-only
│   ├── __main__.py                 # python -m collect sapcontrol | icf
│   ├── sapcontrol.py               # profile parameters over the sapstartsrv SOAP interface
│   ├── icf.py                      # ICF surface probe + SAP Gateway OData catalogue
│   ├── soap.py / web.py            # minimal SOAP and GET-only HTTP, read-only by construction
│   └── extract.py                  # writes the same export files the offline path reads
├── modules/
│   ├── base_auditor.py             # BaseAuditor: finding()/get_config() + severity constants
│   ├── data_loader.py              # CSV/JSON loader (auto-delimiter, header normalize; 128 logical sources)
│   ├── report_generator.py         # Interactive HTML dashboard (light theme, XSS-safe, weighted risk score, compliance panel)
│   ├── pdf_report.py               # Multi-page PDF report (cover → priority → categories → compliance → fix-first findings)
│   ├── pdf_writer.py               # Dependency-free PDF engine (standard-14 fonts, wrapping, tables)
│   ├── pptx_report.py              # PPTX deck composer (exec summary, compliance, one slide per finding)
│   ├── pptx_writer.py              # Dependency-free OOXML/PPTX engine (slides, shapes, text, images)
│   ├── compliance_mapping.py       # Category → framework control mapping (ISO/NIST/CIS/TISAX/SOC 2/GDPR)
│   ├── risk_prioritizer.py         # P1–P4 risk prioritizer (severity × exploitability × exposure × privilege)
│   ├── fair_adapter.py             # FAIR CRQ adapter (--crq): findings → SAP loss scenarios → $ ALE via crq_engine
│   ├── finding_kb.py               # Findings knowledge base loader (detailed risk + remediation)
│   ├── user_auth_audit.py          # USR-*            User & Authorization
│   ├── iam_advanced.py             # IAM-*            Advanced IAM (SoD, firefighter, role lifecycle)
│   ├── security_params.py          # PARAM-*          Security Parameters
│   ├── network_services.py         # NET-*            Network & Service Exposure
│   ├── rise_btp_checks.py          # RISE-*           RISE / BTP Core
│   ├── btp_cloud_surface.py        # BTP-*            BTP Cloud Attack Surface
│   ├── integration_layer.py        # INTG-*           Network & Integration Layer
│   ├── data_protection.py          # DPP-*            Data Protection & Privacy
│   ├── code_transport.py           # CODE-*           Code & Transport Security
│   ├── log_monitoring.py           # LOG-*            Logging, Monitoring & IR
│   ├── fiori_ui.py                 # FIORI-*          Fiori & UI Layer
│   ├── crypto_posture.py           # CRYPTO-*         Cryptographic Posture
│   ├── hana_db_security.py         # HANADB-*         HANA Database Security
│   ├── sap_hotnews.py              # HOTNEWS-*        SAP Security Notes / HotNews
│   ├── abap_authorizations.py      # AUTH-*           ABAP Authorization & Critical Access
│   ├── system_trust.py             # TRUST-*/STDUSR-* System Trust & Standard Users
│   ├── baseline_params.py          # BASELINE-*       Security Baseline Parameters
│   ├── s4_business_authz.py        # S4AUTHZ-*        S/4HANA & Cloud Authorization
│   ├── access_risk_analysis.py     # ARA-*            Access Risk Analysis (offline SoD)
│   ├── basis_job_command.py        # JOBCMD-*         Basis Jobs & External OS Commands
│   ├── grc_access_control.py       # GRC-*            GRC Access Control (EAM/ARM/SoD governance)
│   ├── role_governance.py          # RG-*             Role Design & Governance (SU24/profile-gen/derived drift)
│   ├── financial_controls.py       # FIN-*            Financial Controls (SOX ITGC / FI config)
│   ├── atc_import.py               # ATC-*            SAP's own ATC/CVA results, ingested not re-derived
│   ├── log_review.py               # LREV-*           Retrospective SM20 audit-log review
│   ├── code_inventory_report.py    # CODE-INV-*       Custom-code estate: dead, dormant, unknown
│   ├── resilience_posture.py       # RES-*            Backup / DR / recovery posture
│   ├── snc_posture.py              # CRYPTO-SNCECS-*  The SNC family modelled as ONE thing, not 18
│   ├── ecs_config_items.py         # *-ECS-*          The configuration half of SAP Note 3250501
│   ├── abap_sast.py                # ABAP-*           The CVA engine: lexer + taint analysis
│   ├── abap_sast_rules.py          # 89 vendored ABAP rules + 7 JS/UI5 + 8 BTP descriptor
│   ├── abap_sast_extra.py          # 29 MonitorRisk-authored ABAP rules
│   ├── reachability.py             # Call-graph reachability for the custom-code inventory
│   ├── ecs_baseline.py             # The SINGLE ECS oracle — is_compliant() returns True/False/None
│   ├── release_gate.py             # --gate: the delta verdict and its 0/1/2 exit codes
│   ├── btp_import.py               # BTP export normalisation
│   ├── cloudalm_import.py          # SAP Cloud ALM export normalisation
│   └── crq_engine.py               # FAIR Monte-Carlo engine (stdlib; bundled, overridable)
│   #   50 files in all: 30 emit findings, 20 are rule tables, loaders and report writers
├── server/                         # Client-server tier (FastAPI + PostgreSQL 16)
│   ├── identity.py                 # Finding fingerprints + AffectedObject — the load-bearing module
│   ├── schema.sql                  # 20 tables: systems, runs, findings, lifecycle, graph, CRQ, RBAC
│   ├── db.py                       # psycopg pool, row scoping (one place), audit log
│   ├── auth.py                     # PBKDF2 passwords, sessions, ranked roles, per-system scope
│   ├── queries.py                  # The query layer — every read the JSON API serves
│   ├── enrich.py                   # Priority tier, owning team, RISE remediation owner, SLA
│   ├── analytics.py                # MTTR, burndown, aging, trajectory, scorecards
│   ├── graph.py                    # Attack paths: instantiation, cuts, choke points, closure
│   ├── crq.py                      # FAIR quantification per run (portfolio + 5 scenarios)
│   ├── coverage.py                 # Per-upload coverage manifest (module→source map is derived)
│   ├── ingest.py                   # upload → parse → scan → store → run-over-run diff
│   ├── app.py                      # JSON API, uploads, background scans, and the SPA mount (last)
│   ├── cli.py                      # Admin CLI + the air-gapped `scan` path
│   ├── config.py                   # Env-only settings; no defaults for secrets
│   ├── api_auth.py                 # /api/auth/* + /api/account/* — the only sign-in surface
│   ├── sapcontent.py               # SAP's published Security Baseline policies → our control vocabulary
│   ├── prose.py                    # steps()/paragraphs() — the reference the TypeScript port matches
│   ├── checkdocs.py                # What a check IS: assembles catalogue + KB + Baseline + paths
│   ├── migrations.py               # Data migrations SQL cannot express (a fingerprint is a hash)
│   ├── static/                     # Brand assets, mounted at /static, deliberately unauthenticated
│   └── spa/                        # Compiled console (build output, gitignored)
├── frontend/                       # React + TypeScript console — built by Vite into server/spa/
│   ├── src/routes/                 # One screen per file — 22 routes incl. checks, requirements, chokepoints
│   ├── src/api/client.ts           # Typed API client — the only place fetch() is called
│   ├── src/lib/ui.ts               # The stat tile, in one place (it had drifted into four)
│   ├── src/components/             # AppShell, Sidebar, TopBar, AuthGate, Login
│   │                               # + Donut, Meter, Refs (check/requirement links), CrqCharts
│   └── package.json                # react, react-dom, react-router, lucide-react (+ vite/ts/tailwind)
├── assets/                         # MonitorRisk + SAP logos (embedded in reports as data URIs)
├── sample_data/                    # 107 crafted demo exports
├── sample_data_cloudalm/           # SAP Cloud ALM export fixture (same-fingerprint proof)
├── tools/                          # build_brand_assets.py, build_abap_rules.py, add_code_kb_entries.py
├── data/
│   ├── finding_details.json        # Knowledge base: 380 entries — detailed risk + remediation per check
│   ├── fair_scenarios.json         # FAIR catalog: 5 SAP loss scenarios + factor/loss ranges (--crq)
│   ├── attack_paths.json           # 13 SAP attack-path templates (content, not code)
│   ├── ecs_hardening_3250501.json  # SAP Note 3250501: 92 parameters + 18 config items, facts only
│   └── sap_baseline_requirements.json  # Derived from SAP's published CSA policies; CI fails on drift
├── tests/                          # 4,015 tests across 123 files
│   ├── conftest.py                 # pytest fixtures (DataLoader over sample_data)
│   ├── test_scanner.py             # per-module + full-pipeline + CLI tests
│   ├── test_identity.py            # fingerprint semantics, against the REAL sample_data
│   ├── test_release_gate.py        # the 0/1/2 verdicts, end to end
│   ├── test_spa_mount.py           # the SPA mount path and vite `base` cannot drift apart
│   └── test_integration_*.py       # end-to-end against a real PostgreSQL (skip without DB_DSN)
├── docs/
│   ├── EXPORT_GUIDE.md             # how to export each data file from SAP
│   ├── CHECKS_REFERENCE.md         # per-check reference (GENERATED; CI fails on drift)
│   ├── RELEASE_GATE.md             # using the scanner as a CI gate
│   ├── CVA_ENGINE_IMPROVEMENT_PLAN.md  # the ABAP engine: shipped / declined / unverified
│   ├── PIVOT_PLAN.md               # Architecture + 6 phases, with rationale
│   ├── BUILD_ROADMAP.md            # Execution view: status, dependencies, exit criteria
│   ├── COMPETITIVE_ANALYSIS.md     # Onapsis, market, attack-path design spec
│   ├── COMPETITOR_SECURITYBRIDGE.md
│   └── RISE_SECURITY_MODEL.md      # SAP's contractual line; what a RISE customer can export
├── Dockerfile                      # Two stages: node:22-alpine builds the SPA → python:3.12-slim
├── docker-compose.yml              # app + PostgreSQL 16 — the entire deployment
├── .env.example                    # Template; `.env` itself is gitignored
├── requirements.txt                # 4 server-tier runtime deps (the CLI needs none)
├── .github/workflows/tests.yml     # CI: 5 jobs — cli · purity · sap-content · brand-assets · server
├── requirements-dev.txt            # dev-only dependency: pytest
├── CLAUDE.md                       # contributor / AI-assistant guidance
├── CONTRIBUTING.md
├── .gitignore
├── LICENSE
└── README.md
```

---


<sub>[↑ Contents](#contents)</sub>

## Roadmap

- [x] Core security parameter validation
- [x] User & authorization auditing
- [x] Network & service exposure checks
- [x] RISE/BTP-specific checks
- [x] Segregation of Duties (SoD) detection
- [x] Emergency/firefighter access analysis
- [x] Role lifecycle & cross-system identity
- [x] Privilege escalation path detection
- [x] Access review compliance checks
- [x] Cloud Connector audit
- [x] BTP service binding & destination review
- [x] IAS policy & MFA enforcement
- [x] Event Mesh topic authorization
- [x] CPI credential & iFlow security
- [x] Network isolation / Private Link
- [x] Multi-subaccount governance
- [x] XSUAA → IAS migration status
- [x] API Management policy enforcement
- [x] IDOC port & partner profile security
- [x] Web service (SOAMANAGER) endpoint audit
- [x] Webhook & callback endpoint security
- [x] Gateway secinfo/reginfo deep analysis
- [x] Integration monitoring & alerting gaps
- [x] OAuth client & scope governance
- [x] Integration topology analysis
- [x] Read Access Logging (RAL) configuration & coverage
- [x] Information Lifecycle Management (ILM) retention policies
- [x] Non-production data masking / anonymization
- [x] GDPR/DPDP toolkit configuration (DPP)
- [x] Purpose of processing & legal basis compliance
- [x] Sensitive field inventory & classification
- [x] Cross-border data transfer controls
- [x] Data subject request (DSAR) compliance
- [x] Custom ABAP code security scanning (SQL injection, hardcoded creds, dangerous statements)
- [x] ATC/code inspector finding analysis
- [x] Transport workflow enforcement (approval, SoD, route integrity)
- [x] Client configuration security (SCC4)
- [x] SAP standard modification auditing
- [x] Dead/unreferenced custom code detection
- [x] Security Audit Log (SM20/SM21) configuration & coverage
- [x] SIEM integration & log forwarding validation
- [x] Log retention & archiving compliance
- [x] Table logging for critical tables
- [x] Logon anomaly / brute-force detection
- [x] Incident response readiness assessment
- [x] Fiori catalog/tile authorization review
- [x] OData service-level authorization audit
- [x] Fiori spaces/pages role-based configuration
- [x] TLS configuration depth (protocols, ciphers, HSTS)
- [x] Certificate inventory & expiry management
- [x] SNC configuration & quality of protection
- [x] HANA encryption at rest & log encryption
- [x] CommonCryptoLib version auditing
- [x] PSE health & key management policies
- [x] HANA database security (privileged DB users, PUBLIC & system-privilege grants, DB auditing, ini parameters)
- [x] SAP Security Notes / HotNews gap analysis (missing P1/P2 notes since 2020, CISA-KEV exploited CVEs)
- [x] ABAP authorization & critical-access analysis (AGR_1251 role content: Debug&Replace, S_RFCACL, S_TABU_*, S_PROGRAM, …)
- [x] System trust & standard users (trusted RFC, SAProuter, message server, SAP*/DDIC/default passwords)
- [x] SAP Security Baseline profile parameters (auth engine, SNC fallback, GUI scripting, gateway ACL, ICM log)
- [x] S/4HANA & cloud authorization (business roles, CDS auth-check, OData V4, Cloud Connector principal propagation, CF roles)
- [x] Offline permission-level Segregation of Duties / Access Risk Analysis (GRC-style ruleset, mitigating controls, user risk score)
- [x] Basis background jobs & external OS-command hardening (SM69/SXPGCOSTAB shell-wrap/ADDPAR/path, TBTCO/TBTCP privileged step users, RSBDCOS0)
- [x] GRC Access Control process layer (EAM/firefighter, access-request workflow, SoD governance)
- [x] Role design & governance (SU24 proposals, profile generation, derived-role drift)
- [x] SOX ITGC / FI financial-config controls (posting periods, tolerances, dual control, number ranges)
- [x] Detailed PDF hand-over report + per-finding risk/remediation knowledge base
- [x] Risk prioritization (P1–P4: severity × exploitability × exposure × privilege)
- [x] Compliance mapping (ISO 27001:2022, NIST CSF 2.0, CIS v8, TISAX/VDA ISA, SOC 2, SOX/ITGC, GDPR)
- [x] PowerPoint (PPTX) deck export — executive summary + one slide per finding
- [x] Cyber-risk quantification — FAIR loss exposure ($ ALE + loss-exceedance curve, `--crq`)
- [x] Scan comparison mode (diff two scans) — run-over-run diff in the console, `GET /api/runs/{id}/diff` and `GET /api/findings/changes`
- [x] CI/CD integration with exit codes — `--gate`, exit 0/1/2, see [Release Gate](#release-gate)
- [x] Client-server tier: PostgreSQL persistence, RBAC with per-system row scoping, audit log
- [x] Twelve security domains — the buyer's own vocabulary, each stating what we can see there as well as what we found (`/domains`, `?domain=` on the queue, deck slide)
- [x] Attack-path graph — templates instantiated from co-existing findings, with cuts and choke points
- [x] SAP Note 3250501 — 92 of 92 mandatory ECS profile parameters, plus the configuration half
- [x] Custom-code scanner (CVA) — 133 rules, statement lexer, intra-procedural taint analysis
- [x] React + TypeScript console, compiled at build time and served by the same FastAPI process
- [x] SAP's published Security Baseline policies adopted as the control vocabulary (CI fails on drift)
- [x] Generate `docs/CHECKS_REFERENCE.md` from the code and fail CI on drift
- [ ] Sample fixtures for `resilience`, `ecsconfig` and `cva` so they fire on the bundled `sample_data`

---

<sub>[↑ Contents](#contents)</sub>

## Requirements

| | Needs |
|---|---|
| **CLI scanner** | **Python 3.8+** and nothing else. No external packages — the HTML, PDF and PPTX engines are all hand-built, and a CI job walks the AST of `modules/` and `sap_scanner.py` to keep it that way. |
| **Server** | Python 3.12, **PostgreSQL 16**, and the four packages in `requirements.txt` (FastAPI, uvicorn, psycopg, python-multipart). `DB_DSN` and `SESSION_SECRET` have no defaults and must be set. |
| **Building the console** | **Node 22 + npm**, at build time only. `docker compose up --build` does this for you inside the image's first stage; nothing JavaScript runs at runtime. |
| **Running the tests** | `pytest`, plus the runtime dependencies and `httpx` — see [Testing](#testing). |

If you check the repo out and start the server **without building the console**, that is a defined state rather than a crash: the API keeps working and every console URL answers **503** with a message telling you to run `npm run build` in `frontend/`.

<sub>[↑ Contents](#contents)</sub>

## Testing

About **4,015 tests** across 123 files, plus 83 vitest tests over the console. The suite runs every audit module against the bundled
`sample_data` (crafted to trigger each check) and validates the full pipeline —
no SAP system needed. It checks that each module fires, handles empty input
without crashing, honours the finding contract (field types / severities — this
catches bugs like a description accidentally being a tuple), has no cross-module
check-id collisions, renders the HTML report, and runs end-to-end via the CLI.

```bash
python -m pip install -r requirements.txt -r requirements-dev.txt httpx
python -m pytest -q
```

`requirements-dev.txt` on its own is **not** enough: it contains only `pytest`, and the
server-tier suites import `psycopg` / `starlette` at module level, which aborts collection
rather than skipping. `httpx` is in neither file but Starlette's `TestClient` will not
construct without it.

**Nine suites need a real PostgreSQL** and skip without `DB_DSN` — the journey, the analytics,
the HTTP layer and all of the RBAC coverage. The journey is implemented in SQL, so a mocked
database proves the Python is self-consistent and proves nothing about whether it works:

```bash
docker run -d --name sapsec-test-db -e POSTGRES_USER=sapsec -e POSTGRES_PASSWORD=sapsec \
    -e POSTGRES_DB=sapsec -p 55433:5432 postgres:16
DB_DSN=postgresql://sapsec:sapsec@localhost:55433/sapsec \
SESSION_SECRET=$(python -c "import secrets;print(secrets.token_urlsafe(48))") \
    python -m pytest -q
```

CI (GitHub Actions, `.github/workflows/tests.yml`) runs **seven jobs** on every push and pull request:

| Job | What it proves |
|---|---|
| `cli` | The suite passes on Python **3.8–3.12** with *only* pytest installed, plus a full `sap_scanner.py` smoke run — so a third-party import into the scanner core fails the build |
| `purity` | Walks the AST of `modules/` and `sap_scanner.py` and rejects any non-stdlib import — the charter enforced mechanically rather than remembered |
| `sap-content` | Re-derives `data/sap_baseline_requirements.json` from SAP's published policy repository and fails on drift; the coverage page is measured against that catalogue, so a stale copy misreports coverage |
| `brand-assets` | Re-derives `server/static/*` from the master artwork and fails if the committed files drift |
| `image` | Builds the runtime image, scans it for known vulnerabilities, and proves it **runs as a non-root user** on a **read-only** root filesystem under the compose hardening — the evidence a customer's security team asks for first |
| `schema-upgrade` | Builds a database from the **previous** `schema.sql`, puts rows in it, applies the current one three times, and proves the rows survived and the constraints actually moved — the upgrade path, exercised rather than assumed |
| `server` | The full suite against **PostgreSQL 16**, schema applied **twice** (idempotency is the upgrade path), a scan seeded *before* pytest so data-dependent suites actually execute, a guard that **fails the build if more than one test skips**, and `npm test` — the console's own render tests |

That last guard is load-bearing. Before it existed, `pytest -q` ran the database-backed suites,
they skipped for want of `DB_DSN`, and the job went green having verified none of the journey,
none of the analytics and none of the HTTP layer. A suite that silently skips is worse than one
that does not exist, because it *looks* verified.

[`docs/CHECKS_REFERENCE.md`](docs/CHECKS_REFERENCE.md) is **generated** from the code by
`tools/build_checks_reference.py`, and CI re-runs the generator and fails on any difference — so
it cannot fall behind the modules. It is the one document in this repository that is checked
against the source on every push, which makes it the one to trust when a count here and a count
there disagree. It also states plainly what it does *not* claim: 40 of the 364 titles and 15 of
the severities vary at runtime and are rendered as *varies* rather than frozen to one example.

*(This paragraph used to open "is the least current file in the repo" and then explain why it
could not fall behind — a half-applied edit that survived long enough to warn readers away from
the most current document in the project.)*

<sub>[↑ Contents](#contents)</sub>

## Contributing

**Contributions are welcome** — the project is MIT and open to outside work. Bug reports, corrections to SAP facts, and false positive/negative reports are especially valuable, because a wrong SAP fact is worse here than a missing feature. See [CONTRIBUTING.md](CONTRIBUTING.md).

Found a vulnerability **in this tool**? Do not open an issue — see [SECURITY.md](SECURITY.md).

<sub>[↑ Contents](#contents)</sub>

## Disclaimer

This tool is for **authorized security assessments only**.

The scanner itself performs **offline analysis of exported data** and never connects to
anything. Connected mode is an optional, separately-invoked collector (`collect/`) that
reads from a system you authorise and writes the same export files the offline path
consumes; the scanner cannot tell which produced them.

**Nothing in this product ever writes to an SAP system, in either mode.** Every connector
is read-only, and there is no remediation, provisioning or transport path — by design, not
by omission. See `docs/DECISIONS.md` (D2, D3) for the reasoning and its limits.

<sub>[↑ Contents](#contents)</sub>

## License

**[MIT](LICENSE).** Use it, change it, ship it, sell it. The only condition is
that the copyright notice and permission notice travel with substantial portions
of the software, which is the whole of what MIT asks.

MIT is a copyright licence, so it names a holder: Copyright (c) 2026
Krishnendu De. That notice lives once, in [LICENSE](LICENSE), rather than at the
top of every file.

**Third-party terms are untouched by this**, and cannot be otherwise. Exactly one
component is third-party: `data/sap_baseline_requirements.json`, derived from
SAP-samples/frun-csa-policies-best-practices under **Apache-2.0, Copyright (c)
2020 SAP SE or an SAP affiliate company**. Its notice is required by that licence
and stays. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) — it is part of
the release, not documentation, because the Dockerfile redistributes some of what
it lists.

Questions: krishnendu.de@hotmail.com
