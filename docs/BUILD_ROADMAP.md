# Build Roadmap — Execution Plan

> ## ⚠️ Status note — 2026-08-12
>
> Read the phase lists below as a **record of what was planned**, not of what is
> outstanding. A great deal has shipped since they were written, and this document
> has not been rewritten phase by phase:
>
> - **34 audit modules** (these documents say 23), 685 check ids, 132 logical sources.
>   The forward lists in Phases 5 and 6 have since been reconciled item by item
>   against the shipped code — they had drifted in the direction that is easy to
>   miss, understating the product, so a reader would have set out to rebuild
>   things that already existed.
> - **Connected mode exists** — `collect/` with four read-only collectors:
>   `sapcontrol` (sapstartsrv SOAP), `icf` (HTTP service surface + OData
>   catalogue), `rfc` (users, roles, authorisations) and `btp` (platform REST
>   APIs + Cloud Connector). It was the *last* phase in the coverage plan and
>   was built early.
> - **The ECC axis is measured, not estimated**: 15 of 33 auditors produce
>   identical findings on an ECC export, and 22 produce something. See
>   [ECC_COVERAGE.md](ECC_COVERAGE.md).
> - **Release gating, the tenant model and the schema-upgrade CI job have all
>   landed.** See [DECISIONS.md](DECISIONS.md) for D1–D8 and what each one changed.
>
> Where a phase below is marked "PASSED" with numbers, treat those numbers as a
> dated measurement taken when that phase closed — they are records, and several
> have since moved.

---

**Companion to [`PIVOT_PLAN.md`](PIVOT_PLAN.md)**, which carries the *rationale*. This is the
*execution* view: what is built, what is next, what each phase depends on, and how each one is
proved done.

**Decisions locked 2026-08-05.**

| Decision | Choice |
|---|---|
| Charter | Stdlib-only rule **ends**. One-way. Replaced by a single-digit runtime dependency count |
| Stack | FastAPI · Jinja2 · psycopg · PostgreSQL 16 · one `docker compose` <br>*(Jinja2 superseded 2026-08-09: the console is a React + TypeScript SPA compiled at build time and served by the same FastAPI process. Still one `docker compose`; the runtime dependency count went 5 → 4.)* |
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
| Schema — 28 tables, 17 indexes | `server/schema.sql` | ✅ |
| Pool, row scoping, audit | `server/db.py` | ✅ |
| RBAC, PBKDF2, sessions | `server/auth.py` | ✅ |
| Query layer (one layer, many renderings) | `server/queries.py` | ✅ |
| Coverage manifest | `server/coverage.py` | ✅ |
| Ingest + run-over-run diff + rebase | `server/ingest.py` | ✅ |
| FastAPI app, upload, cancellable jobs | `server/app.py` | ✅ |
| Console templates | `server/templates/` | ✅ *(retired 2026-08-09 → `frontend/`)* |
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

Measured on the bundled `sample_data`: **296 findings, 204 graph nodes, 106 of 123 logical
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
| Trend screen | `server/templates/trend.html` | ✅ *(now `frontend/src/routes/Trend.tsx`)* |
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
| `/risk` board view — portfolio, scenarios, exposure over time | `frontend/src/routes/Risk.tsx` | ✅ |
| ALE tile on the landing dashboard | `frontend/src/routes/Dashboard.tsx` | ✅ |
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

## Phase 4 — The attack-path graph ✅ **COMPLETE**

| Component | File | Status |
|---|---|---|
| Path templates as **content, not code** | `data/attack_paths.json` (7 paths) | ✅ |
| Instantiation, cuts, chokepoints, closure | `server/graph.py` | ✅ |
| `/paths` ranked list + choke-point table | `frontend/src/routes/Paths.tsx` | ✅ |
| Per-path detail, SVG, mitigate-vs-additional | `frontend/src/routes/PathDetail.tsx` | ✅ |
| Ruleset fingerprint + staleness banner | `graph.ruleset_fingerprint` | ✅ |
| RFC destination ownership classification | `enrich.classify_destination_owner` | ✅ |
| `rfc/callback_security_method` (path 2's cut) | `BASELINE-011` | ✅ |
| `/api/paths` | `server/app.py` | ✅ |

### Exit criterion — **PASSED**

All 7 templates instantiate on `sample_data`, and closure works end to end. Removing the
external OS command definitions resolved 5 findings and **severed SAPPATH-07**, with the path
row and its `first_seen` kept intact:

```
SEVERED:  SAPPATH-07  ABAP to operating system bridge — severed 06 Aug 2026, first seen 06 Aug
```

SAPPATH-04 correctly stayed open: its "OS command execution reachable" hop also cites
`AUTH-003`, which still holds. One cut of a multi-check hop does not sever it while other
checks still evidence that hop.

Choke-point ranking already earns its place — `JOBCMD-CMD-001/2/3` each cut **two** paths,
because they are cuts of both SAPPATH-04 and SAPPATH-07.

### Design decisions

- **Templates, not free traversal.** Free traversal over a graph this dense yields hundreds of
  "paths", nearly all noise. Microsoft's own documentation says an empty attack-path page is
  correct, because paths should focus on real exploitable threats. **A short list is the
  feature.** Adding a path is a data change, never a code change.
- **Every hop cites checks that already exist**, so a path can never claim more than the scanner
  actually detected. A test fails if a *required* hop cites no check any module emits — such a
  path would silently never instantiate, and a missing path is invisible in a way a wrong one
  is not.
- **Cuts need no algorithm.** A hop marked `cut` appears on every variant of its path, so
  closing it disconnects the path; everything else only reduces exploitability. That is the
  whole mitigate-vs-additional split.
- **A path is a stored row with a lifecycle**, not a query re-run on each page load. That is
  what makes *"severed on 6 August"* expressible at all, and what lets a returning path re-open
  as the **same** path rather than a new one.
- **Identity is (template, systems)** — never the findings. Evidence churns as individual
  defects are fixed and re-found; folding that into identity would retire and re-raise the path
  continuously, the same mistake aggregate findings avoid.
- **An accepted risk does NOT close a path.** A risk acceptance is a decision to tolerate a
  defect, not evidence it is gone, and an attacker is unmoved by paperwork. A *mitigated*
  finding does close it, because a compensating control genuinely interrupts the step.
- **Every path says it was not validated.** We hold no connection and never will, so
  `derived_from_config` is stored on the path and repeated in the UI. A buyer who has seen Wiz
  will ask "did you actually reach it?" — the answer has to be prepared, not improvised.
- **A path ends at a FAIR scenario**, so it terminates in a currency figure rather than a
  severity word. A test fails on a dangling scenario id.
- **Process controls can be cuts.** Four-eyes separation on transport release is a governance
  rule, not a technical vulnerability, and it is still a genuine cut — a path model that could
  not express that would miss it.

### RFC destination ownership

`SAPOSS`, `SM_*`, `SAPNET*` and SAP's support domains are classified as SAP-operated in RISE, so
their findings do not arrive as customer misconfigurations. Deliberately conservative: it only
downgrades when **every** destination named is SAP's (a finding spanning both is still real work),
customer integrations on SAP-branded SaaS — Ariba, SuccessFactors — stay the customer's, and the
classification is labelled a **naming heuristic to confirm once per landscape**, not a fact SAP
publishes. A wrong "SAP's problem" hides a real finding, which is worse than an extra one to
dismiss.

---

## Phase 4 — original scope (for reference)

**Depends on:** Phase 1 (nodes already materialise). Build to the **readable** specs — Microsoft
and AWS — not to Wiz's gated docs.

> **RECONCILED against the shipped code**, and this list had drifted furthest of
> the three. Six of these ten were already built when it was audited; two more
> were half-built with only the surfacing missing. What follows is the real state.

- [x] Edge extraction over the existing `DataLoader`, not a new ingest —
      **SHIPPED.** `graph_edge` had been defined since the schema landed, with a
      `provenance` column and a comment about never validating reachability, and
      nothing had ever written a row into it: the graph held nodes and no
      relationships. `server/edges.py` derives them from findings that name both
      ends, `data/graph_edges.json` holds the rules as CONTENT, and
      `store_graph_edges` writes them beside the nodes. The pairing rule is the
      design: a finding lists its objects flat, so an edge is emitted only where
      one side is a singleton — cross-producting would fabricate relationships
      and parsing the display string would resurrect the retired `display` basis.
      Findings where both sides are plural are declined AND COUNTED
- [x] Path templates as **versioned content, not code** — **ALREADY SHIPPED.**
      `data/attack_paths.json`, 7 templates; `server/graph.py`: "adding a path is a
      data change, never a code change". Original text follows:
      * — the six paths in
      `COMPETITIVE_ANALYSIS.md` §6.4, plus path 7 (the `SM69` ABAP→OS bridge)
- [x] Landing screen — **SHIPPED; this entry was wrong.** `frontend/src/routes/Paths.tsx`
      renders the ranked path list, the four summary cards and the full choke-point
      table — severs count coloured by CONSEQUENCE rather than by the finding's own
      tier, linked check id, FAIR scenarios, ownership badge, state pill and an
      explained empty state. Routed at `App.tsx` `/paths`. What was actually missing
      was any TEST, which is how this entry came to disagree with the code:
      nothing failed when the claim went stale and nothing would have failed if the
      rendering went away. `Paths.test.tsx` now guards it. Original: * with a remediation-status column, plus a choke-point
      tab. The graph renders only inside one selected path
- [x] `is_cut` drives **mitigate vs additional** — **ALREADY SHIPPED**, in the
      path hops and their cut semantics:
      * recommendations; the 323-entry KB becomes
      path-aware for free
- [x] Chokepoint ranking — **ALREADY SHIPPED, differently**: `graph.chokepoints()`
      groups over `attack_path.detail->'hops'` rather than `attack_path_edge`, and
      works. Original text: *
- [x] Path targets **are** the FAIR scenarios — **ALREADY SHIPPED**: every template
      carries `fair_scenario`, so a path ends at a currency figure. Original: *, so a path ends at a currency figure
- [x] Every reachability edge carries the derived-from-config statement —
      **SHIPPED**: paths carried it already; every edge now writes
      `confidence='derived_from_config'`, tested. Original: * and
      the UI says so
- [x] Customer-declared **exposure zones** per system — **ALREADY SHIPPED**:
      `exposure_zone` on the system record, settable from the console and the CLI.
      Original: *
- [x] `used` vs `configured` edge provenance from logon/gateway data —
      **SHIPPED, and narrower than the heading suggests.** An edge FROM a user is
      written `used` when the logon export shows that user logging on
      successfully in the window; everything else stays `configured`. The claim is
      deliberately weak: a logon proves the ACCOUNT is live, not that it invoked
      this role or destination, and no configuration export could show the latter.
      Worth having anyway — a dormant account holding SAP_ALL and a live one
      holding it are different risks. Only the SCAN path can settle it, because it
      holds the sources; an uploaded report carries findings alone, so its edges
      stay `configured` and `provenance_evidence` is None to record that nobody
      looked rather than that nothing is used. Gateway data is NOT used: no
      gateway log is a documented source today. Chokepoint ranking does not prefer
      `used` edges either — `graph.chokepoints()` ranks findings by cut hops in
      `attack_path` and never reads `graph_edge`.
      **The catch worth carrying forward**: a low `used` count has three causes —
      no logon export, an export covering none of the users holding edges, and an
      export covering them and finding them quiet — and only the third says
      anything about the landscape. The sample corpus is the SECOND case (its
      logon export and its role assignments name disjoint users), so the counts
      `users_on_edges` / `users_in_logon_export` /
      `users_absent_from_logon_export` are reported alongside, and the CLI names
      which case it hit. Without them the product would have reported a fully
      dormant estate off two exports that never overlapped. Original: *
- [x] Ruleset fingerprint + staleness — **SHIPPED; this entry was wrong too.**
      `graph.ruleset_fingerprint()` stamps every path, `path_summary` counts the ones
      whose fingerprint differs from the current ruleset, and `Paths.tsx` renders the
      banner — with the remedy, because a warning with no remedy is one the reader
      learns to skip, and NOT on the healthy case, because a banner that always shows
      is how the real one gets ignored. Guarded three ways in `Paths.test.tsx`
      including the absence case. Original: *

**Open items to close here:** confirm `rfc/callback_security_method` and
`auth/rfc_authority_check` are in the 23-entry parameter baseline (path 2's chokepoint is
unasserted if not); build the RFC destination **ownership classification** so SAP-managed
monitoring destinations are not flagged as customer misconfigurations.

**Exit:** *"remove this wildcard: closes 14 paths, affects 3 roles and 41 users, removes 2 of 5
paths to the payment run"* — and, after a fix, `closed_by_edge` produces a sentence no
incumbent's PDF can. **A short list is the feature**; Microsoft explicitly blesses an empty
attack-path page.

---

## Phase 5 — Content: adopt SAP's own catalogue ✅ **COMPLETE**

| Component | File | Status |
|---|---|---|
| Parser for SAP's Apache-2.0 CSA policies | `server/sapcontent.py` | ✅ |
| Derived requirement catalogue (vendored) | `data/sap_baseline_requirements.json` | ✅ |
| Check → SAP requirement mapping | `sapcontent.CHECK_TO_REQUIREMENT` | ✅ |
| `/coverage` — the published catalogue **and its gaps** | `frontend/src/routes/Coverage.tsx` | ✅ |
| CI job re-derives from SAP and fails on drift | `.github/workflows/tests.yml` | ✅ |
| `rebuild-sap-catalogue` CLI command | `server/cli.py` | ✅ |
| Static check-id collision guard | `tests/test_check_id_uniqueness.py` | ✅ |

### Measured against SAP's real files

Parsed from **58 policy files** actually fetched from
`SAP-samples/frun-csa-policies-best-practices`:

```
38 requirement families · 351 check items · CRITICAL 97 / STANDARD 175 / EXTENDED 79
we cover 17 of 38 · 162 of our checks go beyond the Baseline entirely
uncovered by stack: Java 10 · ABAP 4 · HANA 3 · BTP 2 · Other 2
```

**Ten of the 21 gaps are NetWeaver Java**, which this tool deliberately does not cover. The
`/coverage` page publishes that rather than hiding it — a coverage page that lists only what
you cover is marketing; one that lists what you do not is evidence.

### A number we deliberately do not publish

The research reported the SAP Security Baseline as **214 in-scope control points**
(69/92/53) — the yardstick the incumbent chose. Parsing SAP's published policies gives
**351 check items across 38 families** (97/175/79). **These are different units** and do not
reconcile: a "control point" in the Baseline document is not a `checkitem` in the CSA
policies. The catalogue carries that warning inline, and no percentage is published against
214. The earlier instruction — *no coverage claim against SAP Note 3250501 until someone with
an S-user reads it* — also still stands.

### Three defects found while building it

**A check-id collision I introduced.** `BASELINE-011` was already taken by the password-hash
check when I used it for the new RFC-callback check. My `grep | tail -5` had not shown it.
Renumbered to `BASELINE-012`, and there is now a static guard — the runtime suite could never
have caught it, because the two fire on different conditions and `sample_data` triggers only
one.

**A parser bug that would have flattered us.** SAP uses *both* separators after the
technology letter — `CRITAU-A_a.1` and `NETENC-O.a.1` — so accepting only the underscore
silently dropped `NETENC-O`, `OBSCNT-A` and `SECUPD-H`. That shrinks the published
denominator and makes coverage look **better** than it is, which is the one direction an
error here must never go.

**An untiered requirement.** `SECUPD-A` carries no priority tag at all in SAP's own files.
It is recorded as `None` and rendered "untiered" rather than assigned a tier — inventing one
for SAP's content would be exactly the fabrication this project forbids.

---

## Phase 5 — original scope (for reference)

**Depends on:** Phase 1. The structural fix for the invented-identifier failure mode.

> **RECONCILED against the shipped code.** This list had drifted, and in the
> direction that is easy to miss: it UNDERSTATED the product. Somebody reading it
> would have set out to build things that exist. Each item below now says what
> shipped, where it lives, and what it deliberately did not do.

- [x] Importer for `SAP-samples/frun-csa-policies-best-practices` (Apache-2.0, 261 XML
      policies) — **SHIPPED, both halves.** `server/sapcontent.py` parses
      `BaselinePolicies` into `data/sap_baseline_requirements.json` (38 requirements,
      58 policies); `tools/build_sap_notes_catalogue.py` parses `NotesPolicies` into
      `data/sap_notes_catalogue.json` (1,732 notes, 154 patch days from 2016-01).
      Two generators because their consumers differ — the baseline feeds the server's
      coverage page, the notes feed `modules/sap_hotnews.py`, and `modules/` may not
      import from `server/`
- [~] Adopt SAP's config-store and field names as the **canonical import schema** —
      **PARTIAL, and probably as far as this should go.** `modules/cloudalm_import.py`
      keys on SAP's store names; `CONFIGSTORE_SOURCES` in the notes generator maps every
      store SAP's note policies read to the export that answers it; `system_change`
      documents SAP's own `GLOBAL` / `NAME='GLOBAL_SETTING'` / `VALUE='NOT MODIFIABLE'`
      vocabulary. What did NOT happen is renaming our logical sources to SAP's store
      names, and that was right: a customer's file is named for what they exported, not
      for what Focused Run calls it
- [~] Map every check to its SAP Security Baseline requirement ID; ~~publish coverage
      against the **214 in-scope control points**~~ — **PARTIAL, AND HALF OF IT
      DECLINED.** `server/sapcontent.requirement_for()` maps 208 of 685 checks to a
      Baseline requirement, covering 17 of the 38 SAP publishes. The remaining 477 are
      mostly things the Baseline does not describe at all — financial controls, vendor
      master integrity, resilience — so "map EVERY check" is not a target so much as a
      category error. **The 214 figure is refused outright**: parsing SAP's published
      v2.4 policies yields 351 check items across 38 families, a different unit that
      does not reconcile with the widely-quoted 214 control points (69/92/53). Publishing
      a percentage against it would be a fabricated denominator. See the warning in
      `server/sapcontent.py`
- [~] CI job diffing the SAP repo and the Baseline ZIP each release (no login wall) —
      **PARTIAL.** The `sap-content` job clones SAP's policy repository on every run and
      re-derives BOTH catalogues, failing on any drift, which is the half that needed no
      login. The Baseline ZIP and its `change_marker` PDFs are still untouched
- [x] Rebuild the SAP Notes module on `NotesPolicies/ABAP` (133 policies by patch day),
      reframed around **verifying the note took effect** — **SHIPPED, and the reframing
      is the part that matters.** `HOTNEWS-012` lists SAP-published HotNews notes absent
      from the applied-notes export; `HOTNEWS-013` goes further and states a
      DETERMINATION — the installed component, kernel or HANA revision is below the level
      SAP publishes as carrying the fix, with the evidence in the finding. That is
      "verifying the note took effect" as far as an offline export can reach it
- [x] SOX/ITGC framework mapping; "SAP ECS mandatory hardening" framework —
      **SHIPPED, as two things rather than one.** Only the first is a framework in
      this product's sense. Every entry in `ComplianceMapper.FRAMEWORKS` is a
      theme-to-control map; SAP Note 3250501 is 92 named parameters with a mandated
      value each, and its question is "is this parameter what SAP requires", one
      parameter at a time. Forcing it into a theme table would lose the parameter —
      which IS the control — and report a domain score where the note gives a list.

      **SOX/ITGC** is a ninth framework on the DORA pattern: the four IT
      general-control domains (APD / PC / PD / CO), with **no clause numbers
      claimed**, because unlike ISO 27001 or NIST 800-53 ITGC publishes no single
      catalogue — the domains are an audit convention and every firm numbers its own
      testing programme. Six themes are deliberately left unmapped, on this file's
      own rule that a defensible gap beats indefensible coverage.

      **ECS hardening** is `ecs_baseline.compliance()`, a roll-up beside the
      frameworks. Four outcomes, not two: compliant, deviating, ABSENT FROM THE
      EXPORT, and governed-but-no-opinion — and the rate is over what was ASSESSED,
      never over the 92 mandated, or an export covering 25 of them reports the other
      67 as failures. Empty outside ECS/RISE: scoring an on-premise estate against a
      contract it is not under is the confidently-wrong reporting that module exists
      to prevent.
- [x] Populate `owning_team` and `responsibility` across the catalogue — **SHIPPED,
      with one half narrower than the heading.** `owning_team` is derived for every
      check from `rise_ownership.TEAM_BY_PREFIX` and stored on `check_definition`.
      Responsibility is `remediation_owner` — customer_fixable / ticket_to_sap /
      provider_owned / not_assessable — derived per finding from SAP's published
      Roles & Responsibilities, and it now reaches BOTH products: it moved out of
      `server/enrich.py` into `modules/rise_ownership.py` so the offline scanner
      stamps it too, and `modules/report_generator.py` renders a badge on every
      finding plus a "who fixes what" split above them. Rendered in RISE only —
      on premise every finding is the customer's and a badge on all of them
      trains the reader to ignore badges. What is NOT done is curation: the
      values are derived from check-ID prefixes and a destination-naming
      heuristic, not reviewed check by check, and the heuristic half says so in
      the report footer.
- [x] **Publish the check catalogue** — **SHIPPED, and this entry had misread its own
      source.** "323 auditable vs 550 asserted" is not a split within OUR checks. All
      three sources — `COMPETITIVE_ANALYSIS.md` §3.2, `COMPETITOR_SECURITYBRIDGE.md`,
      `PIVOT_PLAN.md` — say 323 is OUR count (published-and-auditable, because we publish
      the catalogue) and 550 is a COMPETITOR's (asserted-and-unverifiable, because no
      itemised list exists publicly). It is a comparison between two products. Read as an
      internal taxonomy it sent the plan toward an `evidence_basis` attribute nobody had
      asked for.

      What the sources actually ask for is the catalogue published with "ID, what it
      reads, which standard clause it satisfies". Two of those three were missing and
      both were derivable: `docs/CHECKS_REFERENCE.md` now carries a per-module **Reads**
      line (module granularity, labelled as such — the per-check subset is recorded
      nowhere) and a **SAP Baseline** column per check, plus a roll-up reporting three
      numbers rather than one percentage, and the unaddressed requirements listed rather
      than summarised away.

      **Publishing it immediately found a bug of exactly the kind publication is for.**
      `PWDPOL-A` — minimum password length, CRITICAL — rendered as "not addressed" while
      this product has always checked `login/min_password_lng`. The mapping was the prefix
      `PARAM-PWD`, and every id in that family is `PARAM-<parameter name>`, so it had
      matched none of the 81 for its whole life. Nothing published the result, so nothing
      contradicted it. Replaced by a mapping derived from SAP's own requirement titles:
      209 → 233 checks mapped, 17 → 21 of 38 requirements covered.

✅ **SATISFIED, 2026-08-07.** A customer supplied SAP Note 3250501 v46 (released
2026-05-15) from their own S-user. It is recorded as facts in
`data/ecs_hardening_3250501.json` and coverage is **92 of 92 parameters** plus the
configuration half. Reading it also found four values we had WRONG — three in the
dangerous direction, e.g. we required `login/min_password_lng >= 8` where SAP
mandates `>= 15`, so a customer could have been told their password policy was
clean and then failed an ECS audit on it. The instruction was right to exist.

The same bar still applies to the notes we have NOT read: claim nothing about
3480723 (HANA) or 3381209 (Java) until someone reads them.
Third-party counts contradict each other (81+17 vs 150+ vs 120+). Tag checks to R&R *task
descriptions*, never line-item IDs — the pairings are unverified.

**Exit:** every check traces to an SAP-authored predicate or a verified citation, and the
catalogue refreshes from SAP in CI rather than by hand.

---

## Phase 6 — Reach ✅ **COMPLETE (file-based half)**

| Component | File | Status |
|---|---|---|
| Cloud ALM CSA export importer | `modules/cloudalm_import.py` | ✅ |
| BTP CLI / Cloud Connector / audit-log importers | `modules/btp_import.py` | ✅ |
| Retrospective Security Audit Log review | `modules/log_review.py` (`logreview`) | ✅ |
| Export guidance for all three | `docs/EXPORT_GUIDE.md` | ✅ |

**2,365 tests collected** (401 unit, 64 against real PostgreSQL 16) — *measured when this
phase closed; the suite stands at 3,253 today.*

### Deliberately NOT built: live API clients *inside the product*

> **Amended by decision D2 (`docs/DECISIONS.md`).** The prohibition below stands for
> everything under `server/` and `modules/`, and is superseded only in one specific form:
> connectors may exist **out of process**, under `collect/`, and their only output is a file
> the offline path already reads. This is recorded as a **reversal** of a considered
> decision — a BTP live-OAuth scanner was removed from this codebase on exactly these
> grounds — and not as the resumption of something merely unfinished.
>
> The original objection is answered rather than waived. "One we cannot exercise" was about
> a client whose failures would be invisible inside a product that could not reach a system;
> a collector that writes a file is exercised against a recorded fixture, and its output is
> validated by the same loader that validates a customer's own export.

No Cloud ALM OData client, no BTP `auditlog-management` client, no live Cloud Connector
polling **within the scanner or the server**. They cannot be verified in this environment, and
shipping unverifiable network code would be a capability claim we cannot stand behind. Every
importer reads **files** — produced by the customer using documented SAP tooling, by SAP's own
tooling, or (now) by a `collect/` connector the customer runs against a system they authorise.
`docs/EXPORT_GUIDE.md` gives the exact commands.

Also stated honestly in the module docstring: the research could **not** confirm whether Cloud
ALM's API returns raw store values or only SAP's own policy verdicts. The importer covers the
raw-export path; if the API returns only verdicts, that path is narrower than it looks.

### A CRITICAL false negative found and fixed

The Cloud ALM agent reported — but did not fix — a latent defect it had tripped over. Verified
and fixed here, because it is the entry-point hop of attack path 4:

`INTG-GW-001` (CRITICAL, "secinfo overly permissive permit rules") detected permit-all only via
the literal word `PERMIT` or a structured `ACTION` column. Real gateway ACL lines use a leading
`P`, and our own `sample_data/gw_secinfo.csv` contains

```
P TP=* HOST=* USER=*
```

— any program, from any host, as any user: **exactly the 10KBLAZE condition CISA AA19-122A
describes.** The check did not fire. Nor did `INTG-GW-004`, its reginfo twin.

Behind it sat the opposite bug: the operands were read from columns a rule-only export does not
have, leaving them empty, and the wildcard test treated empty as wildcard. Had the action test
ever matched, **every** permit rule would have been flagged, including the specific ones. Both
are fixed by a real ACL parser; the specific rules correctly stay quiet and only the
all-wildcard rule is flagged.

### Two smaller things

**A cross-platform loader bug**, found and fixed by the Cloud ALM agent. Three CSA store names
collide with our own filenames (`STANDARD_USERS`, `GW_SECINFO`, `GW_REGINFO`). On Windows the
filesystem is case-insensitive, so `STANDARD_USERS.csv` satisfied a lookup for
`standard_users.csv` and the store export was read **raw and untranslated** — `UFLAG=64` then
reads as *unlocked*, silently passing a CRITICAL check. One export produced two different
products depending on the host OS.

**The ID collision had a second victim.** Renumbering `BASELINE-011`→`BASELINE-012` made
SAPPATH-02's required cut stop resolving — revealing that the path had been instantiating on
the *password-hash* finding all along, because the template cited the colliding id.
`rfc/callback_security_method` is now in the sample data (and its CSA twin, kept in step) so
the cut is genuinely evidenced.

---

## Phase 6 — original scope (for reference)

> **RECONCILED against the shipped code**, same as Phase 5 above.

- [x] **SAP Cloud ALM CSA** ingestion — **SHIPPED, both paths, and the precondition was
      answered by making it moot.** *Verify first* could NOT be satisfied: SAP's
      `cloud-alm-setup-admin-guide` carries no CSA content, `SAP-samples/cloud-alm-api-examples`
      publishes projects, tasks, process authoring, requirements, testing and analytics
      and nothing for configuration and security analysis, and the Business Accelerator
      Hub is a JavaScript application this product cannot read. Settling it needs a live
      tenant. So both shapes are handled instead: `modules/cloudalm_import.py` translates
      RAW STORE exports into the logical sources our own checks read, and
      `modules/cloudalm_verdicts.py` reads a RESULTS export as SAP's verdicts — labelled
      as SAP's throughout, severity taken from SAP's own Baseline tier, with "could not
      evaluate" kept apart from "failed". Whichever the tenant can produce, one of the
      two reads it
- [x] **BTP collectors** — **SHIPPED** as `collect/btp.py`: destinations, subaccounts,
      `auditlog-management` (`/auditlog/v2/auditlogrecords`) and the Cloud Connector
      `/api/v1/configuration`, all read-only behind a path allowlist checked before a
      request is built. Out of process under `collect/`, per Decision D2 — the objection
      recorded below was to a network client inside the stdlib-only boundary, and that
      still stands in that form
- [x] **Retrospective threat review** over an exported Security Audit Log window —
      **SHIPPED** as `modules/log_review.py` (`--modules logreview`), 15 checks: a pattern
      library (`LREV-PAT-001..007`), filter-coverage checks (`LREV-FLT-*`), window
      checks (`LREV-WIN-*`) and the stated prerequisite, log-source health, as
      `LREV-SRC-001..003`. The wording discipline is enforced in the module's own
      docstring rather than left to whoever writes the next datasheet: it is a
      retrospective review over an exported window, and no finding, title or description
      derived from it may imply monitoring, detection, real-time or streaming
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
| ABAP source SAST | ~~SAP gives PCE customers CVA free~~ — **wrong; corrected 2026-08-07.** CVA is fee-free only inside a purchased BTP ABAP Environment entitlement. Now in scope: see `docs/CVA_MERGE_PLAN.md` |
| Peer benchmarking | Fiction without a customer base. Benchmark against the SAP baseline and the customer's own history |
| BusinessObjects | Shrinking estate, separate authorisation model, no comparable API story |
| ~~SuccessFactors~~ | **In scope as of D1**, qualified: offline-first, security surface only. The "API-only" half of the old objection is answered by `collect/` (D2); the "is enough of it *security* configuration" half is still **inferred** and offline stays the default so it keeps being tested |
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

3. ~~Begin Phase 4 — the attack-path graph~~ ✅ **DONE.** The core shipped; the
   heading above records it. The node substrate that made it possible was **626
   typed nodes** from real exports, with cloud and on-premise identities correctly
   separated. What remains is the DEPTH rather than the core — path templates as
   versioned content, choke-point ranking, exposure zones, `used` vs `configured`
   edge provenance — and every item in that list has since shipped. The Phase 4
   forward list above is the current record; this paragraph is kept for the
   history and should not be read as an open worklist.

**Done:** README `PARAM-* (25+)` overstatement corrected to 23. CI now has six jobs including
a stdlib-purity gate and a skip guard.
