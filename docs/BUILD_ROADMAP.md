# Build Roadmap — Execution Plan

**Companion to [`PIVOT_PLAN.md`](PIVOT_PLAN.md)**, which carries the *rationale*. This is the
*execution* view: what is built, what is next, what each phase depends on, and how each one is
proved done.

**Decisions locked 2026-08-05.**

| Decision | Choice |
|---|---|
| Charter | Stdlib-only rule **ends**. One-way. Replaced by a single-digit runtime dependency count |
| Stack | FastAPI · Jinja2 · psycopg · PostgreSQL 16 · one `docker compose` |
| Tenancy | **Single-tenant per deployment.** No `tenant_id`; the `landscape` level preserves the option |

**Rules that apply to every phase:**
1. No phase is "done" until its exit criterion passes against a **real PostgreSQL**, not a mock.
2. Never fabricate an SAP identifier. Note numbers, auth objects, parameter names and R&R
   line-item IDs are verified or they do not ship.
3. Every claim about a competitor is `verified` / `asserted` / `inferred`, never bare.

---

## Phase 1 — Identity, persistence, ingest ✅ **COMPLETE**

The blocker. Three roadmap items were the same schema change, and doing them in the wrong order
meant migrating twice.

| Component | File | Status |
|---|---|---|
| Fingerprint + `AffectedObject` | `server/identity.py` | ✅ |
| Extended finding contract | `modules/base_auditor.py` | ✅ |
| Schema — 18 tables, 17 indexes | `server/schema.sql` | ✅ |
| Pool, row scoping, audit | `server/db.py` | ✅ |
| RBAC, PBKDF2, sessions | `server/auth.py` | ✅ |
| Query layer (one layer, many renderings) | `server/queries.py` | ✅ |
| Coverage manifest | `server/coverage.py` | ✅ |
| Ingest + run-over-run diff + rebase | `server/ingest.py` | ✅ |
| FastAPI app, upload, cancellable jobs | `server/app.py` | ✅ |
| Console templates | `server/templates/` | ✅ |
| Admin/air-gapped CLI | `server/cli.py` | ✅ |
| Deployment | `Dockerfile`, `docker-compose.yml` | ✅ |
| Module conversion to structured objects | 8 graph-relevant modules | 🔄 in progress |

### Exit criterion — **PASSED**

> Upload the same export bundle twice; every finding matches itself; zero new.

```
tests/test_identity.py           31 passed
tests/test_integration_ingest.py 10 passed   (real PostgreSQL 16)
full unit suite                 198 passed, 1 skipped
```

Measured on the bundled `sample_data`: **296 findings, 204 graph nodes, 105 of 117 logical
sources supplied.** The three collisions that blocked the pivot now resolve —
`USR-001` 4→4 distinct, `CODE-STMT-001` 4→4, `RISE-002` 2→2.

### Two defects found and fixed during the build

**1. Silent partial-upload success.** A missing export loaded as `None` and its checks
self-skipped with nothing saying so, producing a clean-looking report over a fraction of the
estate. Fixed by the coverage manifest, which is recorded per run and rendered on the run page.

**2. Converting a module orphaned its findings' history.** Caught live: a module was converted
between two scans of a *byte-identical* bundle and `BTP-DST-001` churned new+resolved, because
its identity moved from display-string to structured-object basis. In production a customer
tracking a defect for six months would lose its age, assignee and risk acceptance the day we
shipped an improvement to that check. Fixed by `_rebase` in `server/ingest.py`, which carries
history across an identity-basis change — but **only when unambiguous**. If several open
findings for a check could be the match, it does nothing and reports them as new, because
attaching one defect's history to another is worse than losing it.

### Also landed
- `remediation_owner` — four classes, so a RISE customer is never told to change a setting only
  SAP can change
- `submitted_to_provider` lifecycle state with a mandatory ticket reference
- Deployment-mode switch (`on_prem` / `rise_pce` / `rise_tailored`) per landscape
- Row scoping in one place; an empty explicit scope means **nothing**, not everything
- Degrade-never-drop: a failing module is recorded with its traceback and the run continues

---

## Phase 2 — Console and the mitigation journey ✅ **COMPLETE**

**Built to be credible, not to differentiate** — both incumbents ship this and the free tool in
our niche claims it.

| Component | File | Status |
|---|---|---|
| Priority, team, RISE ownership, SLA windows | `server/enrich.py` | ✅ |
| MTTR · burndown · aging · trajectory · scorecards | `server/analytics.py` | ✅ |
| Trend screen | `server/templates/trend.html` | ✅ |
| Saved views + permission-scoped durable URLs | `queries.py`, `/v/{slug}` | ✅ |
| Assignment, due dates, bulk transitions | `queries.py`, `app.py` | ✅ |
| Notifications on new CRITICAL + regressions | `ingest.queue_notifications` | ✅ |
| `risk_prioritizer.py` wired into ingest | `server/ingest.py` | ✅ |
| `finding_kb.py` (323 entries) into the catalogue | `server/ingest.py` | ✅ |
| Schema v2: `saved_view`, `notification`, SLA columns | `server/schema.sql` | ✅ |

### Exit criterion — **PASSED**

> Answer *"what changed since last month, who owns it, and is it getting better"* without
> exporting anything.

```
unit                       213 passed, 1 skipped
integration + HTTP          43 passed   (real PostgreSQL 16)
                           ---
                           256 tests
```

Measured on `sample_data` in a RISE landscape: **P1 26 · P2 32 · P3 169 · P4 69**;
**31 findings routed to `ticket_to_sap`**; 253 of 292 checks KB-backed; **227 due dates**, which
is exactly 296 − 69 because P4 deliberately carries no clock.

### Decisions worth keeping

- **Priority outranks severity in the queue.** The tier already folds in exploitability, exposure
  and privilege, so sorting by raw severity would put an unreachable CRITICAL above an
  actively-exploited HIGH.
- **Provider-bound work is a separate series everywhere.** A finding a RISE customer cannot fix
  sits open until SAP acts; rolling it into the same MTTR or overdue count measures the wrong
  organisation. `ticket_to_sap` also gets a longer SLA window for the same reason.
- **MTTR counts only findings actually resolved.** Including still-open ones as "time so far"
  makes MTTR *fall* whenever a burst of new findings arrives — exactly backwards.
- **Burndown is per run, not per calendar day.** The backlog only changes when a scan observes
  it; a daily series over weekly scans draws six flat days and one cliff, implying activity on
  days nothing was measured.
- **Counts of resolved occurrences, never an average severity.** A mean that falls because a
  batch of LOW findings arrived would report progress where none happened.
- **The domain score is over checks that ran**, not the whole catalogue — otherwise supplying
  fewer exports improves the score.
- **Saved views store filters, never rows**, so a shared link re-runs under the caller's own row
  scope and can never widen access.
- **Bulk actions are deliberately not all-or-nothing** — apply what can move, report what could
  not and why.
- **The scanner never overwrites a human's assignment**, and the SLA clock only restarts when the
  tier actually moves; recomputing the due date every run would mean nothing could ever be overdue.

### Three defects found during the build

**1. Every page in the console was broken.** `TemplateResponse(name, context)` is the legacy
Starlette signature — the current one takes `request` first, so the old form passed the context
dict where the template name belongs. Imports succeeded, templates parsed, and the query layer
was covered by integration tests; not one page could render. Only an HTTP request exposed it, so
`tests/test_http_console.py` now asserts every route returns 200 against a real database.

**2. The documented upgrade path was broken.** `CREATE OR REPLACE VIEW` cannot change a view's
column list, and `finding_effective` selected `f.*` — so the first `ALTER TABLE finding` made
re-running `schema.sql` fail with *"cannot change name of view column"*. The view was removed
rather than nursed: nothing used it, both its derivations are computed inline in `queries.py`,
and an unused view that breaks migrations is strictly negative. Schema idempotency is now proven
by re-running it twice.

**3. Eight checks belonged to nobody.** The team table carried `S4AUTH-` against the scanner's
actual `S4AUTHZ-` prefix, so those findings routed to `unassigned` and would never have appeared
on any team's worklist. Nothing failed — the work was silently orphaned. A test now asserts every
check the scanner emits routes to a team, because a prefix table mis-matches quietly.

---

---

## Phase 3 — FAIR on the front page ✅ **COMPLETE**

**The cleanest open lane** — neither incumbent has any monetary output at all.

| Component | File | Status |
|---|---|---|
| FAIR run per scan, persisted to `crq_result` | `server/crq.py` | ✅ |
| **The Monte-Carlo engine itself** | `modules/crq_engine.py` | ✅ (see below) |
| `/risk` board view — portfolio, scenarios, exposure over time | `templates/risk.html` | ✅ |
| ALE tile on the landing dashboard | `templates/dashboard.html` | ✅ |
| Unrouted count carried into the UI | both views | ✅ |
| System criticality as a calibration input | `crq.landscape_exposure_weight` | ✅ |
| `/api/risk` | `server/app.py` | ✅ |

### The engine did not exist

`fair_adapter.py` builds calibrated scenario inputs and hands them to an engine it locates on
disk — historically a sibling repository. **That repository is not present and never has been**,
so `--crq` had always degraded to *"scenario inputs exported, not simulated"*. The product's
headline differentiator produced no number.

`modules/crq_engine.py` is that engine: Open FAIR, BetaPERT three-point sampling, Poisson event
counts, conditional secondary loss, seeded for reproducibility. Standard library only, because
`modules/` is stdlib-only by charter and CI now enforces it. It is **last** in
`_ENGINE_CANDIDATES`, so an explicit `--crq-engine` path, `CRQ_ENGINE`, or an external sibling
engine all still win — bundling must not silently change results for anyone who already has one.

### The bug that made the number wrong

First implementation resolved vulnerability as a plain `TC > RS` comparison — defensible FAIR
theory in the abstract, and **measurably wrong for this catalogue**. `data/fair_scenarios.json`
documents the function it was calibrated against:

```
Vulnerability = clamp((TC - RS + 50) / 100, 0, 1)
```

with bands tuned so `hardened` lands ~0.3–0.4 and `CRITICAL` ~0.8–0.85 against threat
capabilities of ~50–72. Under binary comparison the hardened band (68/82/95) is barely reachable
by threat capability (55/72/85), so vulnerability collapsed to ~0 and the model reported that
**remediating everything drives residual risk to exactly $0** — the first number a risk
professional would challenge. Corrected, and pinned by tests that fail if the engine and the
bands ever drift apart.

### Exit criterion — **PASSED**

Measured on `sample_data`, 10,000 simulations:

```
portfolio        P50 $27.2M    P90 $80.8M
reducible                      $73.0M
residual                        $7.8M    (~10% — non-zero, as it must be)
priced on        296 findings (the complete set)   unrouted 0

SAP-RCE-01   $67.6M   18 findings   exploited · exposed
SAP-DATA-04  $22.8M   50 findings   exposed
SAP-PRIV-03  $21.8M  124 findings   exposed
SAP-INTF-05  $10.9M   67 findings   exposed
SAP-FRAUD-02  $1.9M   24 findings   exposed
```

Disciplines preserved and asserted in tests: FAIR runs on the **unfiltered** finding set (the
input count is stored on every row and checked against the scan), the portfolio is an
**element-wise Monte-Carlo sum** rather than a sum of percentiles, the **unrouted count is
disclosed**, and identical input yields an identical figure — a currency number that drifts
between runs is indistinguishable from a real change in exposure.

---

## Continuous integration ✅ **COMPLETE**

Three jobs in `.github/workflows/tests.yml`:

- **`cli`** — Python 3.8–3.12, installs *only* pytest. If anyone imports a third-party package
  into the scanner core it fails here rather than at a customer who installed nothing.
- **`purity`** — walks the AST of `modules/` and `sap_scanner.py` and fails on any non-stdlib
  import. "`modules/` stays stdlib-only" lived only in CLAUDE.md, and a rule that lives only in
  a document erodes.
- **`server`** — PostgreSQL 16 service container, applies `schema.sql` **twice** (idempotency is
  the documented upgrade path, and it has broken once), runs the full suite, and renders every
  console page end to end.

**The load-bearing part is the skip guard.** Before it, `pytest -q` ran the DB-backed suites,
they skipped for want of `DB_DSN`, and the job went green having verified none of the journey,
none of the analytics and none of the HTTP layer. That is how a bug breaking *every page in the
console* reached main. Exactly one skip is expected and accounted for; more fails the build.

---

## Phase 4 — The attack-path graph

**Depends on:** Phase 1 (nodes already materialise). Build to the **readable** specs — Microsoft
and AWS — not to Wiz's gated docs.

- [ ] Edge extraction over the existing `DataLoader`, not a new ingest
- [ ] Path templates as **versioned content, not code** — the six paths in
      `COMPETITIVE_ANALYSIS.md` §6.4, plus path 7 (the `SM69` ABAP→OS bridge)
- [ ] Landing screen = ranked path **list** with a remediation-status column, plus a choke-point
      tab. The graph renders only inside one selected path
- [ ] `is_cut` drives **mitigate vs additional** recommendations; the 323-entry KB becomes
      path-aware for free
- [ ] Chokepoint ranking — a `GROUP BY` over `path_edge`
- [ ] Path targets **are** the FAIR scenarios, so a path ends at a currency figure
- [ ] Every reachability edge carries *"derived from configuration export, not validated"* and
      the UI says so
- [ ] Customer-declared **exposure zones** per system
- [ ] `used` vs `configured` edge provenance from logon/gateway data
- [ ] Ruleset fingerprint + staleness banner when stored paths predate a ruleset change

**Open items to close here:** confirm `rfc/callback_security_method` and
`auth/rfc_authority_check` are in the 23-entry parameter baseline (path 2's chokepoint is
unasserted if not); build the RFC destination **ownership classification** so SAP-managed
monitoring destinations are not flagged as customer misconfigurations.

**Exit:** *"remove this wildcard: closes 14 paths, affects 3 roles and 41 users, removes 2 of 5
paths to the payment run"* — and, after a fix, `closed_by_edge` produces a sentence no
incumbent's PDF can. **A short list is the feature**; Microsoft explicitly blesses an empty
attack-path page.

---

## Phase 5 — Content: adopt SAP's own catalogue

**Depends on:** Phase 1. The structural fix for the invented-identifier failure mode.

- [ ] Importer for `SAP-samples/frun-csa-policies-best-practices` (Apache-2.0, 260 XML policies)
- [ ] Adopt SAP's config-store and field names as the **canonical import schema**
- [ ] Map every check to its SAP Security Baseline requirement ID; publish coverage against the
      **214 in-scope control points** — the yardstick the incumbent itself chose
- [ ] CI job diffing the SAP repo and the Baseline ZIP each release (no login wall). The
      `change_marker` PDFs give a precise inter-version diff
- [ ] Rebuild the SAP Notes module on `NotesPolicies/ABAP` (133 policies by patch day), reframed
      around **verifying the note took effect** — identification is already free from SAP
- [ ] SOX/ITGC framework mapping; "SAP ECS mandatory hardening" framework
- [ ] Populate `owning_team` and `responsibility` across the catalogue
- [ ] **Publish the check catalogue** — 323 auditable vs 550 asserted

⚠️ **No coverage percentage against SAP Note 3250501 until someone with an S-user reads it.**
Third-party counts contradict each other (81+17 vs 150+ vs 120+). Tag checks to R&R *task
descriptions*, never line-item IDs — the pairings are unverified.

**Exit:** every check traces to an SAP-authored predicate or a verified citation, and the
catalogue refreshes from SAP in CI rather than by hand.

---

## Phase 6 — Reach

- [ ] **SAP Cloud ALM CSA** ingestion — already switched on in most RISE tenants; no transport,
      no RFC user, no agent. *Verify first:* whether its API returns raw store values or only
      compliance verdicts. That determines whether it unlocks our 350 checks or only SAP's
- [ ] **BTP collectors** — `btp` CLI output, `auditlog-management`
      (`/auditlog/v2/auditlogrecords`, handle pagination, 4–8 req/s), Cloud Connector
      `/api/v1/configuration`. The one area automatable end-to-end
- [ ] **Retrospective threat review** over an exported Security Audit Log window. Prerequisite:
      log-source health checks. Wording discipline: *"retrospective detection over the exported
      window"*, **never** *"monitoring"*
- [ ] ITSM outbound webhook + stored ticket reference (not a ServiceNow app)
- [ ] Read-only MCP surface over the query layer
- [ ] PDF/PPTX export driven from SQL rather than an in-memory list

---

## Non-goals — decline these explicitly

Being crisp buys credibility for what we do claim.

| Not building | Why |
|---|---|
| Real-time threat detection / incident response | Needs an in-system agent and event-time execution |
| Transport gating | A write path into SAP |
| ABAP source SAST | SAP gives PCE customers CVA free via remote ATC on BTP |
| Peer benchmarking | Fiction without a customer base. Benchmark against the SAP baseline and the customer's own history |
| BusinessObjects, SuccessFactors | API-only and offline-hostile |
| **Any ABAP agent or add-on, ever** | Forfeits the entire wedge |
| Check-count comparisons | Nobody publishes a catalogue; unwinnable even when we are deeper |
| A graph database | Recursive CTEs are ample at SAP scale; a third service kills the deployment advantage |

---

## Standing risks

| Risk | Mitigation |
|---|---|
| Schema migrated twice | Phase 1 landed the contract before any UI work ✅ |
| Converting a module orphans history | `_rebase`, with a deliberate refusal to guess ✅ |
| "SAP Cloud ALM already does this" | SAP's own words: CSA *"is not meant to be an audit-proof tool by itself"*. Never compete on collection |
| "SecurityBridge has SAPMAP" | True, and it connects to systems. Our angle is offline + **path closure over time**, which neither SAPMAP nor the OWASP tool claims |
| "offlinesec is free" | It uploads pseudonymised data to *their* servers. Ours is fully self-hosted, zero vendor egress |
| "No data leaves SAP with an add-on" | Self-hosted; nothing egresses to us either. Prepare this answer, do not improvise it |
| A fabricated SAP identifier ships | Phase 5's SAP-sourced importer is the structural fix. Until then every note number carries "as cited by [source]" |
| Deployment grows past one compose file | That *is* the advantage. Treat a third service as a design failure |

---

## Module conversion ✅ **COMPLETE — all 23**

Every auditor now emits structured `affected_objects`. Measured on `sample_data`:

```
296 findings  ->  296 distinct fingerprints   (0 collisions, 0 unconverted)
basis:  objects 56 · check_only 240 · display 0
620 graph nodes   64 object types, all registered, registries disjoint
```

**`display` basis is now zero.** Every finding is either structurally identified by the SAP
objects it names, or honestly labelled an aggregate. The weaker display-string fallback is no
longer relied on anywhere — it remains only as a safety net for a module nobody has converted.

The high `check_only` count is correct, not a shortfall: most checks roll every offender into
one finding, and an aggregate is honestly identified by check and system. Forcing a `subject`
onto those would change the label the console shows without changing the guarantee behind it.

Re-verified end to end after conversion: scanning the same bundle twice still gives
`new 0 · persisting 296 · resolved 0`.

---

## Immediate next actions

1. ~~Fix the dead SoD path~~ ✅ **DONE.** The deferral was correct in intent — `ara` does SoD at
   permission level, which is strictly better — but keyed on the wrong condition and said
   nothing. It stood down whenever `role_auth_values.csv` was *loaded*, which is not the same as
   `ara` *running*: `--modules iam` supplies that export and never runs `ara`, so SoD analysis
   silently produced **nothing** and an empty result read as "no SoD conflicts".
   `BaseAuditor` now carries a `run_context`, so the module defers only when the deeper module is
   genuinely in the run, and **says so** with an INFO finding when it does. A caller that
   supplies no context keeps the historical behaviour rather than having it changed underneath
   it. Measured: `--modules iam` went from **0 SoD findings to 7**.
2. ~~Review two conversion judgement calls~~ ✅ **DONE**, and reviewing them found a defect
   neither report mentioned.

   **BTP identities.** The defence — "the check exists to treat the S/4 and BTP user masters as
   one identity namespace" — describes the *matching*, which happens in Python before objects
   are built. The graph is a different question, and typing them `user` had a concrete cost:
   `extract_nodes` stamps the run's SID onto anything that does not name its own system, so a
   BTP subaccount role became **`role_collection:Subaccount_Admin@PRD`** — a cloud entity filed
   under an on-premise ABAP SID — and a BTP `JSMITH` would have merged with an ABAP `JSMITH`
   into one node. That erases the exact boundary the cloud-to-on-prem attack path exists to
   show. Fixed with a `btp_user` type and a `_CLOUD_SCOPED_TYPES` set that is never stamped with
   the ABAP SID. Case-insensitive despite being email addresses: RFC 5321 makes the local part
   case-sensitive in theory, nothing treats it so in practice, and the module already folds case
   to compare — splitting on it would make one person two nodes.

   **GRC access reviews.** Half right. Naming the *reviewer* would indeed put a person in the
   graph as though they were the defect — that instinct was correct and is preserved. But a
   review campaign is a real governance object with its own id, and it was being discarded as
   free text. Campaigns are now `review_campaign` objects; the finding stays **aggregate**, so
   closing one overdue review shrinks the member list without retiring the finding and
   restarting the clock on the rest.

3. Begin Phase 4 — the attack-path graph. The node substrate is in place: **626 typed nodes**
   from real exports, with cloud and on-premise identities correctly separated.

**Done:** README `PARAM-* (25+)` overstatement corrected to 23. CI now has three jobs including
a stdlib-purity gate and a skip guard.
