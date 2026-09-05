# Pivot Plan — Offline CLI → Client-Server SAP Security Platform

> ## ⚠️ Status note — 2026-08-12
>
> Read the phase lists below as a **record of what was planned**, not of what is
> outstanding. A great deal has shipped since they were written, and this document
> has not been rewritten phase by phase:
>
> - **38 audit modules** (these documents say 23), 819 check ids, 139 logical sources.
> - **Connected mode exists** — `collect/` with four read-only collectors:
>   `sapcontrol` (sapstartsrv SOAP), `icf` (HTTP service surface + OData
>   catalogue), `rfc` (users, roles, authorisations) and `btp` (platform REST
>   APIs + Cloud Connector). It was the *last* phase in the coverage plan and
>   was built early.
> - **The ECC axis is measured, not estimated**: 13 of 38 auditors produce
>   identical findings on an ECC export, and 25 produce something. Re-measured
>   2026-09-05. See [ECC_COVERAGE.md](ECC_COVERAGE.md).
> - **Release gating, the tenant model and the schema-upgrade CI job have all
>   landed.** See [DECISIONS.md](DECISIONS.md) for D1–D8 and what each one changed.
>
> Where a phase below is marked "PASSED" with numbers, treat those numbers as a
> dated measurement taken when that phase closed — they are records, and several
> have since moved.

---

**Status:** proposal, 2026-08-05. **Not started. Requires sign-off before any code is written.**

Companion documents: [`COMPETITIVE_ANALYSIS.md`](COMPETITIVE_ANALYSIS.md) ·
[`RISE_SECURITY_MODEL.md`](RISE_SECURITY_MODEL.md) ·
[`COMPETITOR_EMBEDDED_INCUMBENT.md`](COMPETITOR_EMBEDDED_INCUMBENT.md)

---

## 0. The target, restated

SAP offline exports uploaded through a browser → PostgreSQL backend (Linux/Docker) → scanners
run automatically on upload → findings, remediation and FAIR CRQ values stored → an SAP team
works results in a professional interactive web console. Repeat uploads of the same exports over
time track the **mitigation journey**. Plus a **Wiz-style attack-path and risk-quantification
graph view**.

---

## 1. The one thing that must be decided first

**Three roadmap items are the same schema change, and doing them in the wrong order means
migrating twice.**

The finding contract today (`modules/base_auditor.py`) emits:

```python
finding(check_id, title, severity, category, description,
        affected_items,   # list of DISPLAY STRINGS: "MM_CLERK_01 -> SAP_ALL"
        remediation, references, details)   # details: schema-free, present on 82 of 296
```

Measured consequences:

- `check_id` is **not unique within a single run** — verified collisions on `sample_data`:
  `USR-001` ×4, `CODE-STMT-001` ×4, `RISE-002` ×2.
- Nothing fingerprints **which object** is at fault — `affected_items` is free text.
- `scan_meta` carries only `{scan_time, data_directory, modules_run, severity_filter}` — no SID,
  client, tier, release, kernel level, BTP subaccount or tenant anywhere.

So:

| Feature the user asked for | Blocked by |
|---|---|
| Mitigation journey across repeat uploads | No stable finding identity → nothing matches across runs; every re-upload reports everything as new |
| Multi-system landscape console | No SAP system entity → two uploads from different systems are indistinguishable |
| Attack-path graph | Free-text affected items → **every node would be a string** |

**One change fixes all three:** emit **structured affected objects** alongside the display string.

```python
affected_objects = [
    {"type": "user",        "system": "PRD", "client": "100", "name": "MM_CLERK_01"},
    {"type": "profile",     "system": "PRD", "client": "100", "name": "SAP_ALL"},
    {"type": "destination", "system": "DEV", "client": "200", "name": "PRD_TRUSTED",
     "qualifier": "type=3"},
]
```

From which:

- **Graph nodes** are extractable (`type` + `system` + `client` + `name` is a node key)
- **Finding fingerprint** is deterministic: `sha256(tenant, system_id, client, check_id,
  canonical(affected_objects))`
- **Mitigation journey** becomes computable — the same defect on the same object matches itself
  across runs

> **This is the first slice, and nothing else should be built before it.** The graph is not a
> later phase sitting on top of the database — **it dictates the database.**

### Migration approach

`affected_items` stays as the display string (every report renderer consumes it). Add
`affected_objects` as a parallel, optional field. Modules are converted incrementally; a module
that has not been converted yet contributes findings that carry no graph nodes and fall back to
a weaker fingerprint (`system_id + check_id + hash(affected_items)`), which is **still stable**
as long as the display string is stable. Convert the 8 graph-relevant modules first
(`system_trust`, `abap_authorizations`, `network_services`, `access_risk_analysis`,
`btp_cloud_surface`, `integration_layer`, `code_transport`, `hana_db_security`).

---

## 2. Architecture

### 2.1 Stack — and the charter change it forces

The project's founding rule was **zero external dependencies, stdlib only, no
`requirements.txt` by design**. A Postgres backend and a web tier ends that. This is a
deliberate, one-way decision and should be recorded as such.

**Proposed stack — deliberately the same as LogOcean/SIEM-Lite**, which is the in-house
precedent and already runs this exact shape in production:

| Layer | Choice | Why |
|---|---|---|
| Web | **FastAPI** | Already proven in LogOcean (85 routes) |
| Templates | **Jinja2**, server-rendered, one stylesheet, **no client framework** | Matches Microsoft's and AWS's own attack-path UX (§6.1 of the competitive analysis) — the graph is 6–10 nodes in an SVG, not a canvas.<br>**Superseded 2026-08-09.** The 13 templates were replaced by a React + TypeScript SPA (`frontend/`), compiled by Vite at build time into `server/spa/` and served by the same FastAPI process at `/`. The reasoning above held: what changed is that a triage queue with live filtering, bulk selection and polling wants client state, not that the SVG needed a canvas. Still one container, still no chart library, and the runtime dependency count went **down** when jinja2 left. |
| DB | **PostgreSQL 16, single instance**, not published to the host | Recursive CTEs are ample for SAP-scale graphs; a graph DB would be an unforced dependency and would break the deployment-simplicity wedge |
| Driver | **psycopg** | Precedent |
| Deploy | **One `docker compose`** — app + Postgres | If we need more than one modest container we forfeit our only structural advantage over an 8-core/16 GB/200 GB console + sensor pair |
| Scanner core | **The existing 30 modules, unchanged in logic** | They are the product. Only the contract and the I/O boundary change |

Target: keep the runtime dependency count in single digits, as LogOcean does (7).

### 2.2 What is reused from LogOcean rather than reinvented

Practically every client-server mechanic already exists there in working form:

- **Ingest** — `ingest_batches` row per upload with content-SHA duplicate detection that
  *informs rather than blocks*; one caller-owned transaction with rollback → mark-error →
  reraise; chunked writes
- **Degrade-never-drop** — an enrichment/module failure degrades the row and surfaces on
  `/health`; it never discards the batch. **This is the direct answer to the "no error detail
  for a failing asset" complaint.**
- **Stamp + backfill staleness** — `*_meta` fingerprints measured against the **live** ruleset,
  never a stored one. Directly applicable to stored graph paths: when the path ruleset changes,
  stored paths are stale and the console must say so.
- **Content packs** — versioned install/uninstall with conflicts and problems. This is how the
  SAP baseline policies, the note catalogue and the ARA ruleset ship.
- **RBAC** — ranked roles + `audit_log`. Needs a **fourth axis**: which systems a principal may
  see.
- **The query-compiler pattern** (LOQL) — parameterized SQL, pure compile, no `eval`, no string
  interpolation. It is the **single un-bypassable place to inject the per-system row filter**,
  and it is the safe substrate if we ever expose an MCP/agent read surface.
- Server-side sessions, notify channels + dispatcher (for "new CRITICAL finding" alerts).

### 2.3 Data model

Five layers. The middle one is the part that does not exist today in either repo.

```
tenant
  └── landscape                     (a customer's SAP estate)
        └── sap_system              SID, client, tier(prod/qa/dev/sandbox), product,
                                    release, kernel patch level, BTP subaccount,
                                    criticality, owner, tags[], exposure_zone
              └── scan_run          upload → parse → scan → derive; content-sha,
                                    coverage manifest, module status, R&R version pinned
                    ├── finding_occurrence
                    └── graph: node / edge / path / path_edge / path_finding
```

**The definition/occurrence split** (taken from the incumbent's own published schema):

| `check_definition` — the catalogue | `finding_occurrence` — per run, per system, per object |
|---|---|
| `check_id` (PK), title, category, default severity, module, owning **team**, SAP Baseline requirement ID, framework mappings, references, risk narrative + remediation (from `finding_details.json`), CVE/CVSS where applicable | `fingerprint`, `check_id` (FK), `scan_run_id`, `system_id`, `client`, `affected_objects` (jsonb), computed severity + P-tier + `factors[]`, **lifecycle** |

**Lifecycle columns** — the platform incumbent's occupancy of this space is the minimum credible set, plus one
addition RISE forces:

```
state              open | submitted_to_provider | mitigated | accepted | false_positive | resolved
responsibility     customer | customer_unless_purchased | sap_on_request | sap_only
remediation_owner  customer_fixable | ticket_to_sap | provider_owned | not_assessable
assignee, owning_team, due_date
first_seen_run, last_seen_run, first_seen_at, last_detected_at, days_open
acceptance{accepted_by, reason, from, due_date, expired}
transitioned_by, last_transition_at
provider_ticket_ref
```

**`remediation_owner` is a separate axis from `responsibility`**, and it is what the UI renders:

| Class | Badge | Remediation text | Scoring |
|---|---|---|---|
| `customer_fixable` | *Yours to fix* | Concrete action + transaction/table | Full severity, counts toward the score |
| `ticket_to_sap` | *Raise with SAP* | Pre-drafted service-request text: system, client, parameter, current value, target value, and the SAP requirement it derives from | Full severity, **counted separately** — time-to-fix depends on SAP's queue, so FAIR's remediation-effort model must differ |
| `provider_owned` | *SAP's under RISE* | "No customer action. Shown for completeness and for your auditor." | Informational, excluded from score |
| `not_assessable` | *Out of reach in RISE* | State the reason — "requires OS access, which RISE customers do not have" | Excluded from score, **but listed** so the coverage map stays honest |

> Three failure modes this prevents: reporting an SAP-owned setting as a customer failure;
> reporting it as "unknown"; and hiding it so the report looks thinner than the risk.

> **`submitted_to_provider` is not optional.** In RISE the customer can see a bad profile
> parameter and **cannot fix it** — remediation is a ticket to SAP ECS (SAP KBA 3460793). Without
> this state every parameter finding sits open forever and the burndown chart lies.
>
> **`responsibility` is four-state, not binary.** A binary customer/SAP flag misrepresents the
> Packaged Services category — which is exactly where SAP's own paid competitors to us sit.
>
> ⚠️ **But it must be tenant-configurable, not hard-coded.** Verification established that the
> four-state vocabulary is **PCE-specific** — the tailored-option contract uses "CAS available at
> additional charge" and the string "Packaged Services" appears in it zero times. SAP's own R&R
> disclaims fixed scope, and the effective split depends on the Order Form and purchased
> packages. **And do not tag checks to R&R line-item IDs** — the ID-to-task pairing is unverified
> (`RISE_SECURITY_MODEL.md` §0). Tag to the *task description*, not the identifier.

**Graph tables**, with the columns that make the journey work:

```
node        (system_id, type, client, name, qualifier)  + finding_count, criticality
edge        from_node, to_node, type, direction, attributes(jsonb), check_id,
            provenance(configured|used), confidence, owner(customer|sap)
path        template_id, entry_node, target_node (→ a FAIR scenario), severity,
            first_seen, last_seen, closed_at, closed_by_edge
path_edge   path_id, edge_id, is_cut   -- is_cut drives mitigate-vs-additional
path_finding path_id, fingerprint
```

> `path.closed_by_edge` **is the product**: *"this path was severed on 12 Sep when the
> `S_RFCACL` wildcard was removed from ZBASIS_SUPPORT"* is a sentence no incumbent's PDF can
> produce.

### 2.4 Two invariants worth writing down now

1. **One console, one finding table, one severity scale, one lifecycle.** Parameter checks,
   authorization findings, SoD risks, HANA, BTP, code/transport and note gaps all in the same
   queue with the same filters. Our scanner already does this by accident — all 23 auditors emit
   the same dict. **Preserve it in the database; resist per-module tables.** The incumbent's own
   customers say they cannot get this.
2. **Everything the console shows is available via the API**, because both render from the same
   query layer. One pure analytics function, many renderings.

---

## 3. Phasing

Six phases. **Phase 1 is a hard prerequisite for everything else.** Phases 4–6 can reorder.

### Phase 1 — Identity, persistence, ingest *(the blocker)*

- `affected_objects` contract change + conversion of the 8 graph-relevant modules
- Fingerprint function + **unit test proving the `sample_data` collisions are resolved**
  (`USR-001` ×4 → 4 distinct fingerprints)
- Schema: tenant / landscape / sap_system / scan_run / check_definition / finding_occurrence
- Docker compose (app + Postgres 16); FastAPI skeleton; RBAC with the per-system row filter in
  the query layer **from day one** (retrofitting row scoping is painful, and the incumbent only
  shipped it in Q1 2026 — arriving with it is competitive, not late)
- Upload → parse → scan → store, as a **cancellable, resumable background job with visible
  progress**. A 23-module run must not sit on the request path.
- **Coverage manifest per upload** — *"you supplied 41 of 117 sources; 12 modules ran degraded;
  63 checks did not execute."*

> The manifest is **not a feature, it is a defect fix.** Today a missing file loads as `None`,
> its checks self-skip silently, and a partial upload produces a **clean-looking report**. A
> buyer catches that in a POC.

- **A deployment-mode switch (on-prem / RISE PCE)** that re-tags every finding's
  `remediation_owner` and re-weights severity by fixability

> Shipping the on-prem view into a RISE account produces a report full of unactionable findings —
> the exact failure this research exists to prevent. Per the module scoping in
> `RISE_SECURITY_MODEL.md` §4: **15 modules IN SCOPE · 7 PARTIAL/SPLIT · 1 mostly OUT.** Nothing
> needs deleting, but **roughly a third of the tool needs re-labelling rather than running
> unchanged** — and three modules must never blend reachable and unreachable components into one
> finding (`integration_layer`: gateway ACL *files* are OS artifacts; `code_transport`:
> `SE06`/`SCC4` are ticket-to-SAP; `system_trust`: message-server ACL and SAProuter route table
> are OS-level).

**Also in Phase 1, because they are cheap and one is a credibility fix:**
- Correct the README `PARAM-* (25+)` overstatement (code has 23)
- Fix or document the dead path at `modules/iam_advanced.py:185`
- Tag every check with an **owning team** (Basis / Authorizations / Development / Integration /
  Data Protection / Identity), a **responsibility** state and a **remediation owner**
- ⚠️ **Do not** tag checks to SAP R&R line-item IDs. Tagging each check with the contract task it
  discharges is a good idea — it answers *"why am I paying you when I pay SAP?"* with SAP's own
  classification — but the ID-to-task pairings are unverified (`RISE_SECURITY_MODEL.md` §0). Tag
  to the **task description**; add IDs only after eye-verification against the rendered PDF.

**Exit test:** upload the same export bundle twice; every finding matches itself; the second run
reports zero new.

### Phase 2 — The console and the mitigation journey

- Finding queue: filters (system, client, tier, tag, team, severity, P-tier, state,
  responsibility), saved views, **permission-scoped durable URLs per audience** — Basis worklist,
  auditor evidence view, executive view — *not* file production
- Run-over-run diff: **new / persisting / resolved / regressed**, aging, MTTR by severity and by
  module, burndown by P-tier
- Lifecycle: assignment, due dates, risk acceptance **with expiry**, false-positive with a
  required reason (so disputed findings become tuning data, not noise)
- The trend view sits **on the same finding rows the team is triaging** — not on a separate
  executive tab. That fragmentation is the incumbent's architectural mistake.
- Per-domain % score by Area of Responsibility (computable from one export; it is the number an
  exec repeats)
- Metric vocabulary buyers now expect: *average remediation speed, backlog trajectory, technical
  debt, exposure trend*

> Deliver this to be **credible**, not to differentiate — both incumbents shipped it and the free
> tool claims it.

### Phase 3 — FAIR on the front page

- Portfolio ALE on the landing dashboard next to the finding counts; the 5 scoped scenarios as a
  board view; **the unrouted count carried into the UI**
- Preserve the two disciplines that make it defensible: FAIR runs on the **unfiltered** finding
  set; portfolio ALE is an **element-wise Monte-Carlo sum**
- Add system **criticality** as a legitimate calibration input — a prod system's exposure band
  should not equal a sandbox's

> **The cleanest open lane.** Neither incumbent has any monetary risk output at all; their
> "business impact" is a prose field. Promote it from a `--crq` flag to a headline.

### Phase 4 — The graph

Build to the **readable** specs (Microsoft, AWS), not to Wiz's gated docs.

- Node/edge extraction as a layer over the existing `DataLoader` — **not a new ingest**
- Path templates as **versioned content**, not code — start with the **six paths in
  §6.4 of the competitive analysis**, every hop already grounded in a check we run
- Landing screen is **a ranked path list with a remediation-status column plus a choke-point
  tab** — the graph renders only inside one selected path
- **Mitigate vs additional** recommendations, driven by `path_edge.is_cut`; the 323-entry
  remediation KB becomes path-aware for free
- Chokepoint ranking: a `GROUP BY` over `path_edge` — *"remove this wildcard: closes 14 paths,
  affects 3 roles and 41 users, removes 2 of 5 paths to the payment run"*
- Path targets **are** the FAIR scenarios — the path ends at a dollar figure
- **Every reachability edge carries "derived from configuration export, not validated"** and the
  UI says so. A buyer who has seen Wiz will ask.
- Customer declares **exposure zones per system** at upload — a small input that upgrades every
  path in the internet-facing class
- **A short list is the feature.** Microsoft explicitly blesses an empty attack-path page.

**Two open items to close during this phase:** confirm `rfc/callback_security_method` and
`auth/rfc_authority_check` are in our 23-entry parameter baseline (Path 2's chokepoint is
currently unasserted if not); and build the **RFC destination ownership classification pass**
(SAP-managed vs customer-managed) so we do not flag SAP's own monitoring destinations as customer
misconfigurations on the first report.

### Phase 5 — Content: adopt SAP's own catalogue

- Importer for `SAP-samples/frun-csa-policies-best-practices` (**Apache-2.0, 260 XML policies**)
  → our check model; adopt SAP's config-store and field names as the **canonical import schema**
- Map every check to its **SAP Security Baseline requirement ID** (`PWDPOL-A`, `RFCGW-A`,
  `CRITAU-A`…) and publish coverage against the **214 in-scope control points** — the yardstick
  the incumbent itself chose
- CI job that **diffs the SAP repo and the Baseline Template ZIP on every release** (no login
  wall) — free version currency, and the direct mitigation for this project's known
  invented-identifier failure mode
- Rebuild the **SAP Notes module** around the free `NotesPolicies/ABAP` folder (133 policies by
  patch day), reframed around **verifying the note took effect** rather than catalogue volume —
  note *identification* is already free from SAP
- Add the **SOX/ITGC** framework mapping (the number-one SAP audit driver; we already load the
  FI/SOX customizing sources) and an **SAP ECS mandatory hardening** framework
- **Publish the full check catalogue** as a public artifact: 323 auditable vs 550 asserted

> ⚠️ **Do not publish any coverage percentage against SAP Note 3250501 until someone with an
> S-user reads it.** Third-party control counts contradict each other (81+17 vs 150+ vs 120+).

### Phase 6 — Reach

- **SAP Cloud ALM CSA** as an ingestion path (already switched on in most RISE tenants; no
  transport, no RFC user, no agent; daily refresh turns repeat scanning into an automatic trend).
  *Verify first:* whether its API returns raw store values or only compliance verdicts.
- **BTP collectors** — fully automatable, customer-owned, real APIs: `btp` CLI output, the
  `auditlog-management` service, Cloud Connector `/api/v1/configuration`
- **Retrospective threat review** over an exported Security Audit Log window — a new category
  that costs no live connection. Prerequisite: **log-source health checks**. Wording discipline:
  *"retrospective detection over the exported window"*, never *"monitoring."*
- ITSM outbound webhook + stored external ticket reference (start here, not with a ServiceNow app)
- A read-only MCP surface over the query layer — a thin layer once the schema exists, and our
  323-entry remediation KB is exactly the grounding corpus such an interface needs

---

## 4. Explicit non-goals

Being crisp about these buys credibility for what we do claim:

- Real-time threat detection and automated incident response
- Transport gating / any write path into SAP
- ~~ABAP source SAST~~ — **moved in scope 2026-08-07** (`docs/CVA_MERGE_PLAN.md`); the "CVA free for PCE" premise was wrong
- Peer benchmarking (fiction without a customer base — benchmark against the SAP baseline and
  against the customer's own history)
- BusinessObjects
- ~~SuccessFactors~~ — **moved in scope** (decision D1, `docs/DECISIONS.md`), qualified:
  offline-first, security surface only
- Any ABAP agent or add-on, ever — it would forfeit the entire wedge
- Competing on check counts

---

## 5. Risks

| Risk | Mitigation |
|---|---|
| **Schema migrated twice** because the graph was treated as a later phase | Phase 1 lands the `affected_objects` contract before any UI work |
| **"SAP Cloud ALM already does this"** | SAP's own docs: CSA *"is not meant to be an audit-proof tool by itself"*. Never compete on collection; make CSA an input |
| **"the embedded incumbent already has its estate-graph feature"** | True, and it connects to systems. Our angle is offline + **path closure over time**, which neither its estate-graph feature nor the OWASP tool claims |
| **"a free offline scanner is free and does this"** | It uploads pseudonymised data to *their* servers. Ours is fully self-hosted, zero vendor egress, with landscape lifecycle, the graph and FAIR |
| **"No data leaves SAP with an add-on"** (the embedded incumbent's marketed virtue) | Self-hosted deployment; nothing egresses to us either. Prepare this answer, do not improvise it |
| **An inflated number is caught** | Fix the README `25+` claim in Phase 1. Docs are otherwise conservative vs code — keep them that way |
| **A fabricated SAP identifier ships** | Phase 5's SAP-sourced content importer is the structural fix. Until then, every note number carries "as cited by [source]". **`CVE-2026-31431` is unverified — do not use it.** |
| Ending the stdlib-only charter | One-way decision, recorded here. Single-digit dependency count as the discipline that replaces it |

---

## 6. Decisions needed before Phase 1 starts

1. **Confirm the charter change** — Postgres + web tier ends stdlib-only. One-way.
2. **Confirm the stack** — FastAPI + Jinja2 + psycopg + PostgreSQL 16, single compose file,
   mirroring LogOcean. (Alternative worth naming only to dismiss it: adding a graph database.)
   *Answered yes; the Jinja half was later superseded — see the stack table in §3. The graph
   database was dismissed and stayed dismissed.*
3. **Confirm the sequencing** — identity contract first, console second, FAIR third, graph
   fourth. The temptation is to build the graph early because it demos well; doing so means
   migrating the schema twice.
4. **Multi-tenant or single-tenant per deployment?** Affects the RBAC row filter and whether
   cross-tenant anonymised benchmarking is ever possible. Cheap now, painful to retrofit.
5. **Does the existing CLI stay?** Recommendation: yes — as the ingest-side collector and for
   air-gapped assessment, with the server as the system of record.
