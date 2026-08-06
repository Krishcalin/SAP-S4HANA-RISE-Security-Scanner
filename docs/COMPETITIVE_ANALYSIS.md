# Competitive Analysis — Onapsis, SecurityBridge, and the SAP Security Market

**Status:** research output, 2026-08-05. Produced by two multi-agent research passes plus **two**
adversarial verification passes, which between them downgraded or corrected sixteen claims.

**Companion documents:** [`RISE_SECURITY_MODEL.md`](RISE_SECURITY_MODEL.md) ·
[`COMPETITOR_SECURITYBRIDGE.md`](COMPETITOR_SECURITYBRIDGE.md) — a fuller dossier that supersedes
§3 below wherever the two differ · [`PIVOT_PLAN.md`](PIVOT_PLAN.md)

**Rules observed throughout.** No vendor text, code or images are reproduced — capabilities are
described by what they *do*. Claims are labelled `verified` (read from a primary source),
`asserted` (vendor marketing, no published catalogue) or `inferred` (absence of evidence across
named sources). **Absence of a capability in a competitor's public material is never stated as
proof of absence** — both Onapsis's and SecurityBridge's product documentation is
login-gated.

---

## 1. Executive summary

Three conclusions drive the product plan.

**1. Our headline pivot feature is table stakes, not a differentiator.** "Track the mitigation
journey across repeat uploads" is already shipped by both incumbents and claimed by the free
tool in our exact niche. Onapsis Security Advisor ships posture-over-time, trended response
metrics, average remediation speed and backlog trajectory; SecurityBridge's Security Roadmap
ranks by risk *and* resolution complexity, routes work by responsibility area, integrates
Jira/ServiceNow, guards against regression and supports documented risk acceptance; and
offlinesec.com — free — explicitly markets tracking "how quickly notes are implemented and how
configuration issues evolve month to month". **We must build it to be credible. We cannot sell
on it.**

**2. Two lanes are genuinely open, and one of them is closing.** No public evidence of a
config-derived attack-path graph at Onapsis (their integrator-published data model has **no
edge or relationship entity at all** — a vulnerability points at exactly one asset), and none of
financial risk quantification at either vendor. **FAIR/monetary quantification is the cleanest
open lane and we already have the engine.** The graph lane is contested: SecurityBridge's
research director released **SAPMAP** in 2026, framed as "SAP's BloodHound moment", and an OWASP
project already renders an SAP inter-system connection graph. We are entering a category, not
inventing one.

**3. The offline-export architecture is validated by SAP's own contract — and it is a narrower
wedge than it looks.** Every documented Onapsis deployment requires live connectivity plus
customer-hosted infrastructure; SecurityBridge is an ABAP add-on, which in RISE is an Excluded
Task requiring an additional SKU and multi-week evaluation. But Onapsis already sells the "I
can't give you access" objection-handler (Business Risk Illustration — no install, no
production access, no customer credentials), and offlinesec is free on the same export model.
**Our defensible claim is narrow and must be stated precisely: credentialed-grade depth with
zero connectivity, zero installed infrastructure, zero credentials handed over, and zero vendor
egress.**

---

## 2. Onapsis

### 2.1 Portfolio

Four platform modules — **Assess** (vulnerability management), **Defend** (threat detection),
**Control / Control Central** (code + transport security), **Security Advisor** (AI posture
guidance) — plus **Comply** as a paid add-on requiring an Assess licence, two premium add-ons
(Threat Intel Center, Network Detection Rule Pack), and stack-specific SKUs (Assess Baseline,
Assess for BTP, Assess for SuccessFactors, Onapsis for Oracle EBS). Newest: **Agentic Gateway**
(17 Mar 2026), an MCP server exposing SAP risk data to Copilot/Claude/Gemini/ChatGPT —
explicitly in **preview with no GA date**.

### 2.2 Deployment — the concrete contrast

`verified`, quoted exactly from the Assess datasheet landing page:

| Component | Spec |
|---|---|
| Console | HD 200 GB · CPUs 8 cores (2+ GHz), 16 recommended · RAM 16 GB |
| Sensors | HD 200 GB · CPUs 8 cores (2+ GHz), 16 recommended · RAM 16 GB |
| SaaS Connector | Ubuntu 20.04 · CPUs 1 · RAM 1 GB |

Shipped as pre-built OVAs (VMware, KVM, Hyper-V, AWS, Azure, GCP). **Even SaaS requires a
customer-hosted connector inside the network.** "Agentless" means no agent on the SAP host — it
still holds live credentialed sessions over SAP's proprietary RFC and DIAG protocols. **Defend
goes further and installs SAP-certified add-ons into the ABAP and Java stacks.**

> Quote the spec; never say "heavy" in the abstract. And note the corollary: if our own
> deployment needs more than one modest container, we forfeit the only structural advantage we
> have.

⚠️ **Downgraded by verification.** Do *not* assert that Assess requires no transport. The one
readable deployment account describes deploying pointers across multiple SAP systems (ECC, BW,
GTS, GRC) "necessitating transport configurations".

### 2.3 The data model — the closest thing to a published spec for what we are building

Onapsis publishes no product documentation. Its **integrator** does. Brinqa's connector docs
enumerate the GraphQL field names (`verified`, and the best technical artifact in the entire
research):

- **Asset** — id, name, **sid**, type, stack, asset_role_type, components[].ip,
  **business_value**, status, snc.status, snc.protection_mode, discovered_on, last_scanned,
  owner_id, detection_status, **tags[].name**, categories
- **Vulnerability (an occurrence)** — id, okb_id, **state**, asset.id, **first_occurrence_date**,
  **last_detected_date**, last_scan_date, **days_unresolved**, **unresolved_since**,
  **assignee.name**, **due_date**, **acceptance**{accepted_by, due_date, from, reason},
  **last_transition**{date, **expired_acceptance**}, **transitioned_by**, scope, scope_type,
  parent_path, last_module_output
- **Vulnerability Definition** — keyed on `okb_id`; name, cve, risk, description, solution,
  business_impact, category, full CVSS v3 block (vector, base, temporal, AV/AC/PR/UI/CI/II/AI,
  severity, E/RL/RC), source.public_exploit, sap_notes_links
- **Note** — first-class entity: id, name, priority, cvss_score, latest_release_date, note_url,
  asset.id, asset.sid, **implementation_status**, related_vulnerability.id

Auth: API key → `POST /api/v1/token` → Bearer; reads via `POST /graphql`.
**Delta sync explicitly absent** — *"Each sync is a full sync… accepts a sync token but does not
apply it as an incremental filter."*

> **Three things to take directly.**
> 1. **The definition/occurrence split is the answer to our `check_id` collision problem.**
>    Fingerprint on `(system, check_id, normalized_affected_object)`; `check_id` becomes a
>    foreign key into a definition table.
> 2. **Copy the acceptance block wholesale** — accepted_by, reason, from, due_date, and an
>    `expired_acceptance` boolean. A risk acceptance that silently never expires is itself an
>    audit finding.
> 3. **Their no-delta-sync limitation is a gift.** We will already compute run-over-run diffs,
>    so a "changes since run N" endpoint is nearly free and is something their integrators
>    explicitly cannot get.

### 2.4 Scoring, and the opening it creates

`verified`, verbatim: *"we will consider only the Base Score, and CVSS score or simply score
means CVSS Base Score, where CVSS means CVSS version 3.1."* They concede in the same post that
CVSS does not apply to many SAP findings at all — their example is disabled logging — and that
"not all systems are the same, and some bear more criticality than others."

> Our `risk_prioritizer.py` produces explainable P1–P4 with named factors (actively-exploited
> +25, HotNews note +14, known privileged path +14, exposed surface +12, plus a CVSS bump), a
> rationale string, and a KEV-analog floor. **It works on findings that have no CVSS at all —
> which by the incumbent's own admission is a large share of SAP findings.** Lead with
> explainability; keep the factor list visible in the UI.

### 2.5 The single strongest quote we have

Onapsis's own documented method for tracking remediation over time (`verified`, verbatim):

> *"One way to use the CVSS as a progress indicator is to periodically export the Assess PDF
> Report and monitor the Lowest, Average and Highest CVSS score decreasing to 0 as the issue
> occurrences are remediated."*

Real longitudinal analytics only reached GA at the **end of Q2 2026**, and they live in
**Security Advisor — a different product surface from Assess**, which is precisely the
fragmentation their own customers complain about.

> **Two lessons.** The metric vocabulary buyers now expect is fixed: *average remediation speed,
> backlog trajectory, technical debt, exposure trend* — use those words. And they shipped
> trending as a bolt-on rather than in the console where findings are worked. **Do not copy that
> mistake:** our journey view sits on the same finding rows the SAP team is triaging.

### 2.6 What they have that we should not fight

| Capability | Numbers (`verified` where quoted) | Our stance |
|---|---|---|
| **SAP Endorsed App**, premium certified for S/4HANA and RISE, on SAP Store | Only SAP security platform with this status | Cannot be bought in any realistic timeframe. Compensate: cite real SAP Notes / CIS SAP / DSAG / Security Baseline on every finding (295 of 296 sample findings already do), publish the check catalogue openly, and reframe — **"nothing to certify because nothing is installed."** |
| **SAP Security Baseline coverage** | 100% of in-scope control points: **69 Critical + 92 Standard + 53 Extended = 214**; only 27 published control points out of scope | **This is the yardstick they chose. Build our coverage mapping against it.** We currently make no baseline claim at all. |
| **Control** — custom code | *"over 600 industry-leading test cases across six primary categories"* (Security, Compliance, Performance, Robustness, Maintainability, DLP); inline in Eclipse/VS Code/BAS; Transport Guard blocks risky transports in TMS/cTMS | **Do not compete on ABAP SAST.** We have 22 metadata checks and an offline tool can never block a transport. |
| **Defend** — runtime detection | 2,000+ rules (their own pages also say 2,500+), 24 pre-configured alarms | No analogue. Never imply one. |
| **SAP Notes Command Center** | Centralises patching; *validates patches including manual configuration steps and workarounds* | Our weakest area meets their newest investment. See §5. |
| **Security Advisor** | Peer benchmarking "against hundreds of other organizations in the Onapsis community"; coverage-gap view; trended response metrics | Peer benchmarking is structurally closed to us until we have a customer base — **do not promise it.** Benchmark the customer against themselves over time and against the SAP baseline. |

### 2.7 What is genuinely absent (`inferred` — phrase carefully)

- **No attack-path / blast-radius graph.** Independently checked across the Security Advisor
  product page, the Q1 2026 release, the Q2 2026 release, the Assess datasheet, every release
  note Sept 2025 → Q2 2026, and the Brinqa schema — **which exposes no relationship or edge
  entity at all.** Their P4CHAINS work is *published threat research*, not a customer-landscape
  view. Because their schema has no edge concept, this is not something they can add as a widget.
- **No financial risk quantification of any kind.** No ALE, SLE, loss scenario, Monte Carlo or
  currency output anywhere. `business_impact` is a prose field on the definition. The only
  dollar figures they publish are ROI/labour-savings — the cost of the tool's absence, not the
  risk of the finding.

> State both as *"no public evidence across N named sources"*, never as *"they do not have it."*

### 2.8 Reviewer criticism — useful as design requirements, unusable as citations

⚠️ **Verification downgraded this hard.** The readable evidence is **one** PeerSpot reviewer.
Everything attributed to Gartner Peer Insights and G2 came from search-engine summaries of pages
that return HTTP 403. The specific complaints — *cannot stop a running scan*, *a failing asset
yields no error detail in console or backend log*, *high false positives*, *slow assessments* —
**must not appear in any competitive document as attributed fact.** They remain excellent
internal design requirements:

1. **Cancellable, resumable jobs with visible progress.** A 23-module run must move off the
   request path.
2. **Per-module, per-file error capture surfaced in operator language.** LogOcean's
   degrade-never-drop rule and `/health` `degraded[]` array is the pattern.
3. **An explicit per-upload coverage manifest.** *"You supplied 41 of 117 sources; 12 modules ran
   degraded; 63 checks did not execute."* Our current silent self-skip on a missing file is the
   **same class of invisible failure** — and worse in our case, because it produces a
   clean-looking report. **This is a correctness defect, not a missing feature.**

One verified detail worth designing against: the PeerSpot reviewer wrote batch scripts and
re-posted to SharePoint because **only one login ID could access the tool**, making per-audience
interactive reporting impossible. Design reporting as **permission-scoped durable URLs**, not
file production.

### 2.9 Commercials

No public price list, **no trial, no free tier**. One verifiable datapoint: a Government of
Canada contract via reseller RHEA INC., **CAD $272,952.19**, 24 Jul 2020 – 23 Jul 2021. Treat it
as a single dated public-sector figure including margin, not a list price — but it establishes a
six-figure annual budget line and suggests the mid-market is underserved. Aggregated review
scores put **dashboards/reporting (3.5/5) and pricing transparency (3.1/5)** as their weakest
attributes against strong compliance (4.6) and accuracy (4.1).

---

## 3. SecurityBridge

### 3.1 Architecture — the mirror image of Onapsis

An **SAP-certified ABAP add-on whose entire UI lives inside SAP** as a SAPUI5/Fiori-style
application, not a standalone console. That one fact explains both its strengths (fast deploy,
no extra infrastructure, native to Basis teams) and its reviewer complaints (overwhelming, steep
learning curve, and specifically *"the management dashboard is not usable to build management
reporting"*).

They market **"no data to export to an outside platform"** as a virtue. **This is the sharpest
objection our architecture will face** and it needs a prepared answer, not an improvised one.

### 3.2 Scale and content

| Claim | Kind |
|---|---|
| "SecurityBridge Standard Baseline" of **550+ configuration checks**, "twice as much as the SAP Security Baseline" | `asserted` — **no itemised control list exists publicly in any format** |
| **900+** out-of-the-box use cases; "hundreds" of threat-detection patterns; "100+ listeners, identification patterns and signatures" | `asserted`, no catalogue |
| ~~Seven core components~~ → **13 modules** on the current platform overview | ⚠️ **the "seven components" solution brief is SUPERSEDED — see §3.2a** |
| **CRIS** (Mar 2026) — scores 8 Areas of Responsibility 0–100%, with in-product anonymised peer benchmarking across thousands of production systems, refreshed 6-monthly. Published bands: <50% risky, 51–60% acceptable, 61–80% good, >80% great; "most new customers start at 30–40%" | `verified` (methodology not published) |
| Published AoR scores: Operating System 100%, Development/Code 77%, Integration 77%, Identity & Access 73%, Authorizations 68%, Data Protection 65%, SAP Basis 58% | `verified`; the 8th area is not named publicly |
| **8,000+** SAP systems protected (up from 5,000+ in 2024); PE-backed by Bregal Unternehmerkapital; CEO Jesper Zerlang since Jan 2026 | `verified` |

> **The honest comparison is 323 published-and-auditable vs 550 asserted-and-unverifiable.**
> Publishing our full check catalogue — ID, what it reads, which standard clause it satisfies —
> converts a perceived count deficit into a transparency advantage **no incumbent currently
> offers**. It is the cheapest positioning move available to us.
>
> **Two extra pieces of ammunition, both verified.** First: their own **Buyer's Guide to SAP
> Security** (13 pp, retrieved) contains **zero numeric capability claims** — no 550, no 900,
> no 8,000. Their buyer-facing document avoids the numbers their press releases use. Fair to
> raise when a prospect quotes them. Second: the "twice the SAP Security Baseline" comparison
> is **comparing unlike units** — SAP's actual v2.6 baseline is 27 requirement families / ~55
> family-technology IDs / 54 `[Critical]` markers, and is **not structured as ~275 discrete
> checks** at all.

### 3.2a Six modules the first research pass missed entirely

⚠️ **Correction from verification.** The widely-cited "seven core components" comes from a
superseded solution brief. **The current platform overview names 13 modules.** Not previously
counted: **Privileged Access Management**, **Identity Protection**, **Data Loss Prevention**,
**Forensic Analysis (HyperLogging)**, **TrustBroker**, and **Vulnerability Management** as a
distinct module (plus Security Dashboard and Security Roadmap).

This materially changes the competitive picture:

- **PAM** (verified): self-service elevation instead of standing "god-mode" authorisations,
  admins act under named accounts, **auto-activates HyperLogging for the privileged session** and
  auto-decommissions privileges on session close or expiry, recording activity before, during and
  after. A runtime in-system capability an offline scanner structurally cannot match — and it
  **materially weakens** the rival allegation that SecurityBridge does no critical-access analysis,
  which the first pass had flagged as a testable hypothesis.
- **Data Loss Prevention**: application-native DLP inside SAP — who is downloading what data —
  combining detection with preventative enforcement. Another structural impossibility for an
  export-based tool.

> **Concede both explicitly rather than being surprised by them in an evaluation.** They are in
> categories we are not competing in, but citing the seven-component brief signals stale research.

Their Buyer's Guide also names seven "Top SAP Security Use Cases" — Real-Time Threat Detection,
Patch Management Automation, Compliance Automation, Vulnerability Management, Custom Code
Security, Incident Response, Identify the Attack Surface — plus an "Essential Capabilities" list
including PAM and DLP. **That is a ready-made RFP checklist structure and worth reading as one.**

### 3.3 Two mechanics worth copying outright

**Areas of Responsibility.** Checks are pre-clustered by owning SAP team specifically "to help
distributing their mitigation within the SAP team". This is what makes 550 checks consumable
rather than a wall. Tag every one of our checks with an owning-team dimension (Basis /
Authorizations / Development / Integration / Data Protection / Identity), make it a first-class
filter and scorecard axis, and use it as the assignment model — findings route to a **team**,
not a person.

**Per-domain percentage scoring.** Computable from a single offline export and it is the number
an exec repeats. Ship it alongside the FAIR figure. The peer benchmark is not reachable at
launch — but design the schema so cross-tenant anonymised aggregation is *possible* later;
retrofitting that is painful.

### 3.4 The retrospective-detection opening

Microsoft's (now deprecated) Sentinel connector documentation reveals the architecture: the ABAP
add-on **writes normalised CEF event files to the SAP application server filesystem** (documented
sample path `/usr/sap/tmp/sb_events/*.cef`) and a SIEM agent tails them.

> **The intelligence is in the pattern library, not in privileged live access to the kernel.**
> If a client can export the Security Audit Log for a date range — and they can, it is a standard
> extract — we can run pattern analysis over it offline and report what happened during that
> window.
>
> This is a **new product category for us that costs no live connection**, and it gives repeat
> scans a second axis of change beyond configuration drift. Be scrupulous with the wording:
> *"retrospective detection over the exported window"*, **never** *"monitoring."*
>
> Prerequisite and cheap: **log-source health checks** — is the Security Audit Log active, what
> filter profile, what retention, which event classes. It is a pure configuration check, fully
> offline-doable, and it is what makes the retrospective story credible: we can tell a client
> their audit log was not capturing what they thought it was.

### 3.5 SAPMAP — the graph lane is contested

`marketing` (the tool itself is invitation-only; I could not obtain it).

SecurityBridge's Director of Security Research (Joris van de Vis) released **SAPMAP** on
**15 July 2026**, explicitly framed as **"SAP's BloodHound moment"** — mapping attack paths across
a landscape's trust relationships in **both directions across the on-prem/BTP boundary**, tied to
**16 business-impact scenarios** (named examples: salary theft, vendor bank fraud, production
sabotage, customer data breaches). Vendor-stated: **72 CVEs, 1,817 automated tests, 7 weaponized
exploits** including CVE-2025-31324. It is **not part of the commercial product** — it is an
open-source research tool under OWASP CBAS, invitation-only with a broader public release planned.

*Verification note: all of the above figures were confirmed exactly at the press release — but it
**is** a press release, not documentation. **Its ingestion method (live connection vs export) is
still unknown**, which is exactly what determines whether it competes with an offline tool at all.
No public OWASP CBAS repository was found.*

Separately, the **OWASP SAP Threat Modeling Builder** already exists: a Python/Flask tool that
takes credentials for multiple SAP systems, discovers inter-SAP connections, and renders both an
interactive graph and a filterable table — specifically flagging **prod↔non-prod links and
stored passwords**.

> **Two openings survive, and we should aim at both.**
> 1. Both tools **connect to systems** to scan. Our premise is offline export analysis — the
>    only thing that works in a RISE tenant where the customer owns neither the OS nor the
>    network, and where pen-testing needs six weeks' notice and an NDA.
> 2. **Neither claims longitudinal tracking of path closure across repeat assessments.** That is
>    our mitigation-journey feature expressed in its strongest possible unit.
>
> Also note the framing convergence: SAPMAP uses **16 business-impact scenarios**, not "critical
> severity". Our FAIR adapter already makes exactly that move with 5 scoped SAP loss scenarios.
> **Merge them — path targets should *be* the FAIR scenarios.**

### 3.6 Where SecurityBridge is ahead, and where it is not

**Ahead:** Security Roadmap (mature remediation tracking with regression guards and documented
risk acceptance), CRIS scoring + peer benchmarking, real-time detection, in-system code scanning
wired to Code Inspector / ATC, broad SIEM/ITSM integrations (Fetch Events API — JSON/XML,
time-filtered, basic auth, port 8000), and a research operation that is their strongest genuine
moat — verbatim CVE and SAP Note identifiers for seven 0-days patched in Q1 2026 alone, plus
"Virtual Patching" that detects execution of vulnerable ABAP programs during the remediation
window.

**Not ahead:** **no financial risk quantification** — their only money-facing artifact is a
Business Case Calculator computing the ROI of *buying the tool*. No public developer portal or
API reference. And a rival's comparison alleges both they and Onapsis leave gaps in SoD /
access-risk analysis for S/4HANA business users — vendor-biased, but a testable hypothesis that
matches what we found independently about Onapsis.

**RISE-specific wedge they hand us:** SecurityBridge itself argues that RISE's default security
monitoring *"primarily covers client 000"* while productive clients remain the customer's
responsibility. SAP's own deck says the same thing (see `RISE_SECURITY_MODEL.md` §2.2). When a
competitor and the vendor agree, the point is safe to make.

---

## 4. The rest of the field

| Vendor | Model | Relevance |
|---|---|---|
| **offlinesec.com** | **Free.** Manual table export **and** an automated Connector doing RFC extraction with SSO/SNC or user/password. Explicitly markets the mitigation journey: *"Run the tool regularly to monitor your security posture over time — track how quickly notes are implemented and how configuration issues evolve month to month."* | **A bigger threat than first assessed.** The free incumbent in our exact niche already claims offline collection **and** progress tracking. Our remaining ground is narrower and must be stated precisely: **fully self-hosted with zero vendor egress** (offlinesec uploads pseudonymised data to their servers and returns an Excel file), multi-system landscape lifecycle as a system of record, the config-derived graph, and FAIR. |
| **Layer Seven** | ABAP add-on installed via SAINT, positioned for RISE/ECS | Claims "5,000+ vulnerability checks / 1,200+ threat patterns / 300+ code checks" — `asserted`, no catalogue |
| **Pathlock / SAST, Saviynt, SailPoint, One Identity, SAP GRC** | Access-governance incumbents | See §4.1 — this is the comparison set if we lead with ARA |
| **Protect4S** | ~2,000 checks `asserted`; Connection Map | Connection-centric, not identity-and-privilege |
| **MTC Skopos** | Offline Rust SoD engine, flat-rate pricing | Direct competitor to our ARA module |
| **ERPScan** | Named in KuppingerCole vendors-to-watch | Appeared as a prior evaluation in the one readable Onapsis deployment account |

### 4.1 The analyst frame changes the comparison set

**KuppingerCole Leadership Compass "SAP Access Control and Security"**, Martin Kuppinger,
25 March 2026 (report ID LC81035; body is gated):

- **Overall Leaders:** Pathlock, SAP, Saviynt, SailPoint, One Identity
- **Rated:** CERPASS, Nagarro, Nexis, Pointsharp, ROIABLE, **SecurityBridge**, Werth IT
- **Vendors to Watch (not rated):** **Onapsis**, Layer Seven, Protect4S, ERPScan

> **If we lead with ARA/SoD — our strongest asset — our comparison set is Pathlock and SAP GRC,
> not Onapsis.** That is a materially different pitch with a different objection set. Choose
> deliberately which frame each deal is fought in.

---

## 5. Our position, measured

### 5.1 Genuinely strong

- **Access Risk Analysis** (`modules/access_risk_analysis.py`, 55 KB) — a real offline GRC-style
  SoD engine. 27 risks in the ruleset (25 SoD, 1 critical action, 1 critical permission) across
  P2P / O2C / R2R / H2R / Basis. Resolves user → role → `AGR_1251` object/field/activity and
  matches at **permission level** (the function requires the tcode **and** the auth object
  values), which is what suppresses display-only false positives. Honours mitigating controls
  **with expiry dates**. Accepts a custom ruleset JSON.

  > **Onapsis explicitly cedes this ground.** They position GRC/IAG as owning SoD and themselves
  > as *"the underlying technical layer"* those tools have a blind spot in. No shipped SoD
  > ruleset, no permission-level matching claim, no mitigating-controls-with-expiry claim
  > anywhere public. **This is the sharpest differentiator we own.**
  >
  > It is also the exact SAP analogue of AWS Security Hub's **"effective permissions"** — *"the
  > permissions a principal actually has after evaluating its identity-based policies together
  > with the resource-based policies"* — which we can claim truthfully today.

- **ABAP authorization content analysis** (`modules/abap_authorizations.py`) — 16 checks parsing
  an `AGR_1251` export at object/field/LOW-HIGH level and **attributing each role finding to the
  users holding it**: Debug-and-Replace, `S_RFCACL` trusted-RFC impersonation, `S_LOG_COM` /
  `S_DATASET`, `S_USER_AUT` authorization forging, `S_TCODE '*'`, broad `S_RFC`, generic and
  cross-client `S_TABU_*`, `S_PROGRAM`, batch impersonation, `S_ICF DEST='*'`, plus a 40-entry
  sensitive-Basis-transaction catalogue.

- **FAIR quantification** (`modules/fair_adapter.py` + `data/fair_scenarios.json`) — 5 scoped SAP
  loss scenarios. **Calibration is range-selection, never arithmetic on CVSS.** Logging findings
  are not a scenario — they set a dwell-time multiplier on dwell-sensitive loss components only.
  Portfolio ALE is an **element-wise Monte-Carlo sum, never a sum of percentiles**. FAIR always
  runs on the **unfiltered** finding set so a display filter cannot move the dollar figure. It
  discloses an **unrouted** count.

  > Two of those disciplines become sales-defensible claims, and the unrouted count is what
  > separates this from vendor hand-waving. **A buyer with a risk function will test exactly
  > that.**

- **Explainable prioritisation** (`risk_prioritizer.py`) — P1–P4 with `factors[]` and a rationale
  string, four named boosts, a KEV-analog floor, and SLA windows (24–72h / 7d / 30d / next cycle).
  Works where CVSS does not apply.

- **Breadth of input** — 117 logical sources / 242 accepted filenames, tolerant parsing (BOM-safe,
  delimiter auto-detect, missing file → check self-skips).

- **Citation discipline** — 295 of 296 sample findings carry real references. **Protect this; it
  is a sales asset.**

### 5.2 Genuinely weak

| Gap | Measured | Consequence |
|---|---|---|
| **SAP Notes / patch coverage** | `modules/sap_hotnews.py` ships a curated catalogue of **11 notes** and can emit **at most 5 findings**. No note-to-version applicability, no support-package reasoning, no CVE/KEV/EPSS feed. | **Most buyer-visible weakness.** A documented Onapsis audit example returned 144 missing notes on one ABAP system. **Reframe around *verification that the note took effect*, not catalogue volume** — note identification is already free from SAP. The free `NotesPolicies/ABAP` folder (133 policies by patch day) in SAP's Apache-2.0 repo is ready-made content. |
| **No persistence or identity model** | No database, no `scan_run`, no SAP system entity. `scan_meta` = `{scan_time, data_directory, modules_run, severity_filter}`. SID, client, tier, release, kernel level, BTP subaccount, tenant captured **nowhere**. | Two uploads from different systems are indistinguishable. **Blocks everything else.** |
| **No stable finding identity** | `check_id` is **not unique within a run** — verified collisions on `sample_data`: `USR-001` ×4, `CODE-STMT-001` ×4, `RISE-002` ×2. `affected_items` is free text (`"MM_CLERK_01 -> SAP_ALL"`); `details` populated on only 82 of 296 findings and is schema-free. | **The mitigation journey is currently impossible** — no finding can be matched across runs. Also blocks the graph: every node would be a string. |
| **Parameter baseline depth** | `security_params.BASELINE` = 22 entries + `PARAM-MISSING` = 23. The mandatory ECS ABAP note is reported by third parties at ~81 parameters + 17 settings (contradicted by other sources). | The concrete coverage gap on the one checklist a RISE auditor asks about. |
| **Silent partial-data success** | A missing file loads as `None` and its checks self-skip silently → a partial upload produces a **clean-looking report**. | **A correctness defect a buyer can catch in a POC.** The coverage manifest is required, not optional. |
| **Dead code path** | `modules/iam_advanced.py:185` returns early and emits **nothing** whenever `role_auth_values.csv` is present — its 7 documented SoD rules are dead on any complete export (ARA takes over). | Fix or document. |
| **One documented overstatement** | README claims `PARAM-* (25+)`; code holds 23. | **Fix first.** A buyer who catches one inflated number discounts every other number we give them. Docs are otherwise *conservative* vs code (integration_layer 27 documented / 32 declared; data_protection 18/21; log_monitoring 11/14; code_transport 21/22; system_trust 11/12). |

### 5.3 Scope out, explicitly and first

Being crisp about these buys credibility for the claims we can defend:

- **Real-time threat detection / incident response** — needs an in-system agent and event-time
  execution. Structurally impossible offline.
- **Transport gating** — a write-path, inline capability.
- **ABAP source SAST** — SAP gives PCE customers CVA free via remote ATC on BTP, running where
  the code lives.
- **Peer benchmarking** — fiction with a handful of customers. Benchmark the customer against
  themselves and against the SAP baseline.
- **BusinessObjects, SuccessFactors** — API-only and offline-hostile. Decline rather than fake.
- **Check-count comparisons** — nobody publishes a catalogue; we lose an unverifiable-number war
  even when we are deeper. Compare **depth per domain**, and publish our catalogue.

---

## 6. Designing the graph — build to the readable specs

Wiz's product documentation is behind a login (`docs.wiz.io` → 403). **Microsoft's and AWS's are
public**, and they document the same pattern in far more detail. Treat Wiz's blogs as the
*vocabulary a buyer will use* ("toxic combination", "blast radius", "crown jewels", "effective
exposure") and Microsoft/AWS as **the specification to build to**.

### 6.1 The most reusable finding in the entire research

Microsoft's documented attack-path UX **does not lead with a graph**:

- **Overview tab** — attack paths over time, **top 5 choke points**, top 5 attack path scenarios,
  top targets, top entry points
- **Attack paths list** — filterable by risk level, asset type, **remediation status**, time frame
- **Choke points view** — nodes where multiple paths converge, flagged as high-risk bottlenecks
- **The graph appears only after selecting one path.** Node detail is *text* — MITRE ATT&CK
  tactics/techniques, risk factors, recommendations.
- Resolved paths take up to 24 hours to disappear → **paths are stored entities with a lifecycle,
  not query results**

> This answers "how do we avoid a hairball" and **saves us the riskiest engineering in the pivot**.
> No graph layout engine, no canvas library, no client-side pathfinding. A server-rendered ranked
> list, a per-path table, and a small SVG of 6–10 nodes matches both documented incumbents and
> fits a Jinja2 stack.
>
> It also hands us the mitigation-journey UI for free: *"attack paths over time"* + a
> remediation-status filter **is** the run-over-run diff, expressed as a screen.

### 6.2 The "one change that breaks it" mechanic

Microsoft splits remediation into **"Recommendations — that mitigate the attack path"** vs
**"Additional recommendations — that reduce exploitation risks, but don't mitigate the attack
path."**

> Non-magical and directly implementable: every edge must know whether removing it disconnects
> the path. In our model each edge maps to a `check_id`, so **mitigating = edges on every variant
> of the path (a cut)**, **additional = edges on some variants**. Our 323-entry
> `finding_details.json` then supplies step-by-step fix text for the cut edge at **zero extra
> content cost** — the KB becomes path-aware for free.

### 6.3 Also worth taking

- **AWS's six-trait taxonomy** — Assumability, Impact, Misconfiguration, Reachability, Sensitive
  Data, Vulnerability. Tractable, and it maps cleanly onto SAP: Assumability → trusted RFC /
  stored-credential destination / firefighter ID; Impact → role blast radius (users holding it);
  Misconfiguration → our parameter checks; Reachability → ICF/gateway/message-server/BTP exposure;
  Sensitive Data → HANA schemas, HR/FI tables, RAL scope; Vulnerability → SAP Notes/CVE.
- **The collapsed intermediate node** (AWS collapses a whole network route into one expandable
  node) — our analogue: collapse SAProuter → gateway → dispatcher into one hop.
- **The parallel tabular path view** — a table of *step, object, why this step works* is what a
  Basis reviewer pastes into a change ticket, and it renders from SQL with no graph library.
- **"Attack paths: 3" as a column on the findings grid** — one more factor in
  `risk_prioritizer.py`, no redesign, outsized demo effect.
- **Microsoft's lifecycle columns** — Owner, Status (unassigned / on time / overdue) — a good
  schema shortlist to copy rather than invent.
- **Microsoft explicitly blesses a short or empty path list**: *"You may see an empty Attack Path
  page, as attack paths now focus on real, externally driven and exploitable threats rather than
  broad scenarios."* **Permission to ship three high-confidence paths instead of three hundred.
  A short list is the feature.**
- **Edge provenance.** Wiz distinguishes *configured* from *observed* (runtime) edges. Our offline
  analogue is real and derivable: configured (an `RFCDES` entry exists) vs **used** (the
  destination appears in an exported gateway/SM20 log, or the role's holders show recent logons in
  `USR02`). *"This trust relationship was actually used in the last 90 days"* would be a genuine
  differentiator.
- **Confidence must be explicit.** Wiz validates exposure with an external scanner; we can never
  validate. Every reachability edge carries *"derived from configuration export, not validated"*
  and the UI says so. A buyer who has seen Wiz **will** ask "did you actually reach it?" — the
  answer must be prepared.
- **Don't buy a graph database.** Wiz runs Neptune at "hundreds of billions of relationships". A
  single SAP landscape is tens of systems, thousands of roles, tens of thousands of user-role
  edges — six or seven orders of magnitude below. **Recursive CTEs in PostgreSQL 16 are
  comfortable**, and a graph DB would break the deployment-simplicity advantage that is our whole
  wedge.

### 6.4 Six concrete SAP paths, every hop grounded in a check we already run

| # | Path | Chokepoint (the one cut) |
|---|---|---|
| **1** | **Lower-tier trust pivot** — DEV(nonprod) → RFC destination with stored credentials → trust relationship into PRD → role with wildcard `S_RFCACL` → technical user → `SAP_ALL` → PRD. Checks: NET-001/003, TRUST-001/002/003/004, AUTH-002, USR-001/002, STDUSR-002 | **The `S_RFCACL` wildcard in one role** — remove it and every DEV→PRD trust path dies at once |
| **2** | **Callback inversion** — PRD's own *outbound* destination to a weaker system becomes the *inbound* route; the callback runs in the production user's context. Checks: NET-001/002/003, AUTH-006, TRUST-007 | UCON RFC allowlist (TRUST-007), then per-destination callback allowlists, then `rfc/callback_security_method=3` and `auth/rfc_authority_check=6` — **⚠️ open item: confirm those two parameters are in our 23-entry baseline; if not, this path has an unasserted chokepoint** |
| **3** | **Transport-borne code** — developer in DEV → `S_DEVELOP` → transport request → direct DEV→PRD route → import without approval → arbitrary ABAP in PRD. Checks: CODE-DEV-001, AUTH-001/014, CODE-TMS-001..005, CODE-CLIENT-001, CODE-SYSCHG-001/002, CODE-STMT-001, CODE-INJ-002, CODE-CHG-001/002 | The transport route (CODE-TMS-001) or four-eyes on release/import (CODE-TMS-003). **Note: CODE-TMS-003 is a *governance* rule, not a technical vulnerability, yet it is a genuine cut edge — our path model must allow process controls to be edges, which CNAPP-derived designs do not.** |
| **4** | **Exposed surface → OS → database** — internet → SAProuter wildcard / open message-server ACL / permissive `secinfo`/`reginfo` / unauthenticated ICF → `S_LOG_COM` or `S_DATASET` → HANA. Checks: TRUST-005/006/008/010, INTG-GW-001..005, NET-004/005, INTG-WS-001/003, AUTH-003/010/011, HANADB-* | The deny-all default in `reginfo`/`secinfo` (INTG-GW-002/005) severs the gateway branch; deactivating one ICF node severs the web branch |
| **5** | **Cloud-to-on-prem (the RISE path)** — IAS without MFA → BTP subaccount → destination with stored credentials / admin-scoped binding / iFlow with hardcoded credentials → Cloud Connector wildcard mapping → on-prem ABAP user. Checks: BTP-IAS-001..005, BTP-DST-001/002, BTP-SB-001/002, BTP-CPI-003/004, BTP-CC-001/002/004/008, INTG-OAUTH-001/002 | **Cloud Connector wildcard resource mapping (BTP-CC-001)** — narrowing one mapping cuts every path through that backend |
| **6** | **Business-impact path — no exploit at all** — user → roles → effective permission set → SoD risk → P2P → the payment run. Plus expired mitigating controls, firefighter gaps, financial customizing, logging blind spots | One role's permission-level grant, or one mitigating control's expiry date |
| **7** | **The ABAP→OS bridge (RISE-specific, and underrated)** — an `SM69` external OS command definition plus a background job that invokes it. In a system where the customer contractually has **no OS access at all**, a customer-visible ABAP object that executes OS commands is a documented bridge across the exact boundary SAP's contract draws. Module: `basis_job_command` (11 checks), plus `AUTH-003` (`S_LOG_COM`) | The command definition itself, or the `S_LOG_COM` grant that reaches it |

Path 4 is the one to lead with for a CISO who thinks in Wiz terms. **Path 6 is the one a cloud
CNAPP cannot express at all** — in SAP the crown jewel is not a bucket of PII, it is a business
transaction — and it is where our FAIR engine already routes SAP-FRAUD-02. **Make the FAIR
scenario the graph's target node: the path ends at a dollar figure, which is the only slide a CFO
reads.**

Path 1 is **the demo**: it requires zero new checks, only structured affected objects and a system
identity. Today those ten findings are scattered across four modules and four severity bands in a
296-row report; as a path they are **one CRITICAL item with one recommended fix**.

Two entry-point classes are **CISA-cited rather than asserted** — advisory AA19-122A (10KBLAZE:
gateway `gw/acl_mode`, `secinfo`, message server `ms/acl_info`, `rdisp/msserv` split, SAProuter)
and **CVE-2025-31324** (SAP NetWeaver Visual Composer unauthenticated RCE, CVSS 10.0, added to
CISA KEV 15 May 2025). A CISA advisory is the most buyer-proof citation available for an SAP entry
point.

> ⚠️ `CVE-2026-31431` surfaced in one fetch of the SAPMAP page and **could not be verified**.
> **Do not use it** until confirmed against cve.org or SAP directly.

### 6.5 Path 4 exposes a modelling gap we must close

An ICF service exposed only on an internal VLAN and one reachable from the internet are **the same
finding today**. We cannot validate reachability offline — so let the customer **declare exposure
zones per system at upload time**. A small input that upgrades every path in this class.

---

## 7. What this means for positioning, in one page

**Do not say:** "we're easier to deploy" (Assess Baseline claims scan-within-hours zero-footprint
SaaS) · "we track remediation over time" (both incumbents ship it; the free tool claims it) ·
"we have 323 checks" (nobody publishes a catalogue; volume wars are unwinnable) · "Onapsis doesn't
have X" (their docs are gated; state absence of evidence) · any false-positive percentage
(unfalsifiable, and reviewers will contradict whatever we claim).

**Do say:**

1. **"Nothing is installed in your SAP system."** In RISE, third-party ABAP add-ons are Excluded
   Tasks requiring an additional SKU and a multi-week evaluation. Every agent competitor must clear
   that. We need a file upload.
2. **"No connection, no credentials, no open port, no vendor egress."** Fully self-hosted —
   distinguishing us from offlinesec, which returns an Excel file from *their* servers.
3. **"Credentialed-grade depth without credentials."** Onapsis's own no-access offering (BRI) is
   unauthenticated black-box reconnaissance — it structurally cannot read `AGR_1251` role content,
   `RSPARAM` values, SoD conflicts or HANA privilege grants.
4. **"SAP monitors client 000. Your business clients are yours."** SAP's own words.
5. **"Every finding shows the source file, the parsed rows and the rule that fired."** Compete on
   *auditability*, not on a false-positive rate — a Basis lead can dispute a finding in ten seconds.
6. **"Every priority shows its factors — including for findings CVSS cannot score."** Their own
   post concedes CVSS does not apply to a large share of SAP findings.
7. **"A dollar figure the finance function can test."** Unfiltered input, element-wise Monte Carlo,
   a disclosed unrouted count. Neither incumbent has any monetary output.
8. **"Published check catalogue."** 323 auditable vs 550 asserted. Structurally hard for a
   gated-documentation incumbent to match.
9. **"This path was severed on 12 Sep when the `S_RFCACL` wildcard was removed from
   ZBASIS_SUPPORT."** A sentence no incumbent's PDF can produce.

**Mirror their land motion:** Onapsis's only self-serve entry is a sales-led engagement, and there
is no trial or free tier anywhere in this market. A tool a prospect can run against their own
exports **with no vendor contact at all** is a genuinely differentiated top of funnel.

---

## 8. Confidence and blind spots

**Verified against primary sources:** the Assess hardware spec, the Brinqa data model, the CVSS
base-score-only policy, the PDF-export remediation-tracking quote, the SAP R&R contract rows, the
SAP Security Baseline 214 control points, Microsoft's and AWS's attack-path UX, the KuppingerCole
positioning, SAP's Apache-2.0 policy repository, and SAP's "monitoring is limited to client 000".

**Could not be reached — and this bounds every negative claim:**

- Onapsis Defenders Community and Customer Portal (MFA/Salesforce-gated) — **the real module and
  check catalogue, admin guides and full release notes live there.** Biggest single blind spot.
- All `go.onapsis.com` gated PDFs — architecture diagrams, port/protocol tables, capability-table
  footnotes unseen.
- G2, Gartner Peer Insights, TrustRadius — all HTTP 403. **Reviewer sentiment rests on one
  readable reviewer.**
- `docs.wiz.io` — 403. Every Wiz graph detail here is from blogs and partner pages, never product
  docs.
- SAPMAP itself — invitation-only. UI, node/edge model and the 16 scenario definitions unseen; the
  72-CVE / 1,817-test / 7-exploit figures are vendor-stated.
- SAP Notes 3250501 / 3480723 / 3381209 and the Security Baseline Template body — S-user gated.
  **Only notes 2253549 and 3137004 were verified first-hand.**
- Onapsis pricing, editions, licensing metric, SaaS data residency for scanned SAP data, console
  RBAC/SSO details, and the SAP authorizations their scan account requires — none public.
- **Whether an unadvertised Onapsis offline/air-gapped ingest mode exists.** Phrase our claim
  positively: *"every documented Onapsis deployment requires live connectivity plus
  customer-hosted infrastructure."*

**Explicitly flagged as unverified or corrected by the verification passes:** the Business Risk
Illustration "under two hours / complimentary" figures (not supported by the cited URL) · the "Age
of Issues" tracker (press-release claim, absent from the current product page) · Comply "14
policies" (2023 source, may be stale) · Onapsis Assess "requires no transport" (**do not assert**)
· all vendor check counts on all sides · SecurityBridge's "seven core components" (superseded;
13 modules now) · the Fortinet FortiSOAR connector (community-authored and non-certified, **not**
vendor API documentation — though the conclusion that their public API surface is events-only is
strengthened by that) · the Interface Traffic Monitor capability specifics (a feature-bullet
marketing page, no datasheet).

**Identifiers that must not ship without checking:**

- **`CVE-2026-31431`** — surfaced in one fetch of the SAPMAP page, appears nowhere in the
  research. **Do not use.**
- **The SecurityBridge Q1 2026 zero-day set** — `CVE-2026-0491`, `-0498`, `-24322`, `-0486`,
  `-24313`, `-23681`, `-24326` and SAP Notes `3697979`, `3694242`, `3705882`, `3691645`,
  `3707930`, `3680416`, `3678009`. **None were verified.** They come from a vendor blog. Check
  every one against SAP or NVD before it appears anywhere.
- **`BC-OP-RC-ECS`** — alleged SAP support component for RISE pen-test requests. Single
  competitor source citing no SAP document. **Do not use.**
- **All SAP R&R line-item IDs** as currently paired — the ID column drifts against the
  description column in PDF text extraction, and the same ID maps to different tasks across the
  PCE and tailored documents. See `RISE_SECURITY_MODEL.md` §0.
