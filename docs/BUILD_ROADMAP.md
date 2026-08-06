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

## Phase 2 — Console and the mitigation journey

**Depends on:** Phase 1. **Build to be credible, not to differentiate** — both incumbents ship
this and the free tool in our niche claims it.

- [ ] Saved views + **permission-scoped durable URLs** per audience (Basis worklist, auditor
      evidence view, executive view). Reporting is read access, not file production
- [ ] Trend screen: MTTR by severity and by module, backlog trajectory, burndown by P-tier,
      technical-debt accumulation
- [ ] Aging view and SLA breach tiles from the existing P1–P4 windows
- [ ] Per-domain % score by Area of Responsibility — computable from one export, and the number
      an exec repeats
- [ ] Assignment, due dates, bulk transition
- [ ] Wire `risk_prioritizer.py` into ingest so `priority_tier` / `priority_factors` populate
- [ ] Wire `finding_kb.py` (323 entries) into `check_definition`
- [ ] Notification on new CRITICAL findings

**Exit:** a user can answer *"what changed since last month, who owns it, and is it getting
better"* without exporting anything. The trend view sits on the same rows being triaged — not on
a separate executive tab, which is the incumbent's architectural mistake.

---

## Phase 3 — FAIR on the front page

**Depends on:** Phase 2. **The cleanest open lane** — neither incumbent has any monetary output.

- [ ] Wire `fair_adapter.py` into ingest; persist to `crq_result`
- [ ] Portfolio ALE on the landing dashboard beside the finding counts
- [ ] The 5 scoped scenarios as a board view
- [ ] Carry the **unrouted count** into the UI — disclosing what the model did not price is what
      separates this from hand-waving, and a buyer with a risk function will test it
- [ ] Add system `criticality` as a calibration input
- [ ] Differentiate remediation effort for `ticket_to_sap` findings — time-to-fix depends on
      SAP's queue, not the customer's

**Exit:** the dashboard shows a currency figure that survives a hostile question about method.
Preserve both disciplines already in the code: FAIR runs on the **unfiltered** finding set, and
portfolio ALE is an **element-wise Monte-Carlo sum**, never a sum of percentiles.

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

## Immediate next actions

1. Finish converting the remaining modules to structured `affected_objects` (in flight)
2. Fix the README `PARAM-* (25+)` overstatement — code has 23. A buyer who catches one inflated
   number discounts every other number we give them
3. Fix or document the dead path at `modules/iam_advanced.py:185` — it returns early and emits
   nothing whenever `role_auth_values.csv` is present
4. Add CI: unit suite on every push, integration suite against a PostgreSQL service container
5. Begin Phase 2
