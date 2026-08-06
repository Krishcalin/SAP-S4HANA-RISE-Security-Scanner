# CLAUDE.md — SAP S/4HANA RISE Security Scanner

Guidance for Claude Code (and humans) working in this repository.

## What this is

An **offline SAP S/4HANA RISE + BTP security config-review tool**, in two modes over one
scanner core:

1. **CLI** (`sap_scanner.py`) — reads exports from a `--data-dir`, runs the auditor modules,
   writes **HTML / PDF / PPTX**. Single-shot and stateless.
2. **Server** (`server/`) — the same modules behind a browser console backed by
   **PostgreSQL 16**. Uploads are scanned automatically, findings persist, and re-uploads over
   time track the **mitigation journey**.

No live system / RFC connection is needed in either mode — ideal for RISE, where the customer
contractually has no OS access and a third-party ABAP add-on is an Excluded Task.

### ⚠️ The charter changed (2026-08-05) — read this before adding a dependency

The founding rule was *zero external dependencies, stdlib only*. That rule **ended when the
product became client-server**, deliberately and one-way. It has NOT been relaxed everywhere:

- **`modules/` and `sap_scanner.py` remain standard library only.** The HTML, PDF and PPTX
  engines are hand-built. Do **not** add `reportlab` / `python-pptx` / `pandas`.
- **`server/` may use the five pinned runtime dependencies** in `requirements.txt` (FastAPI,
  uvicorn, Jinja2, psycopg, python-multipart) and nothing else without a decision.
- The discipline replacing "zero deps" is a **single-digit runtime dependency count**. Also
  deliberately absent, and to stay absent: an **ORM** (SQL is hand-written and reviewed), a
  **graph database** (recursive CTEs are ample at SAP landscape scale), and a **client-side
  framework** (pages are server-rendered).
- The deployment is **one app container + one PostgreSQL**. A third service is a design
  failure, not a feature — it forfeits the product's clearest structural advantage over
  competitors that need a console VM plus sensors.

Background and the full plan: [`docs/PIVOT_PLAN.md`](docs/PIVOT_PLAN.md),
[`docs/BUILD_ROADMAP.md`](docs/BUILD_ROADMAP.md).
- **~300+ checks across 23 audit modules** (keep the README badge/count and
  `docs/CHECKS_REFERENCE.md` in sync when you add checks).
- CIS SAP / DSAG-aligned; findings cite real SAP Notes / SAP Security Baseline / CIS.
- **Flow** (illustrated by `docs/banner.svg`): `sap_scanner.py` **LOADs** the exports
  (`DataLoader`) → runs the 23 auditor **MODULES** → each emits severity-ranked findings
  (**CHECKS** → **RANK**) → a **REPORT** is written. When you add a module, refresh
  `docs/banner.svg`'s module/check counts too.
- **Reports** (`--format html|pdf|pptx|both|all`, `--pptx-mode full|summary`):
  `report_generator.py` (light-themed HTML dashboard, PhalanxCyber + SAP branding),
  `pdf_report.py` (multi-page hand-over PDF on the stdlib `pdf_writer.py` engine), and
  `pptx_report.py` (PowerPoint deck on the stdlib `pptx_writer.py` OOXML engine — one slide
  per finding in `full` mode). **All three engines are pure standard library** — do not add
  `reportlab` / `python-pptx`. The HTML and PDF are ordered *priority queue → categories →
  compliance mapping → fix-first findings*; `risk_prioritizer.py` computes the P1–P4 order and
  `compliance_mapping.py` maps categories to ISO 27001:2022 / NIST CSF 2.0 / CIS v8 / TISAX /
  SOC 2 / GDPR controls. Each finding renders its detailed **Security Risk** narrative +
  step-by-step **Remediation** from the findings knowledge base (`finding_kb.py` loading
  `data/finding_details.json`, keyed by check-id with family-prefix fallback), falling back
  to the finding's own `description`/`remediation` when no KB entry exists. When you add
  checks, add matching KB entries so the hand-over report stays detailed. Report logos live in
  `assets/` and are embedded as base64 data URIs so reports stay self-contained/offline.

## Run it

```bash
python sap_scanner.py --data-dir ./sample_data --output report.html            # all modules
python sap_scanner.py --data-dir ./sample_data --output report.html --modules hanadb authz
python sap_scanner.py --data-dir ./exports --output report.html --severity HIGH  # min severity
python sap_scanner.py --data-dir ./sample_data --output report.pdf  --format pdf   # PDF hand-over
python sap_scanner.py --data-dir ./sample_data --output report.pptx --format pptx  # PPTX deck (full)
python sap_scanner.py --data-dir ./sample_data --output report.html --format all   # HTML + PDF + PPTX
python sap_scanner.py --data-dir ./sample_data --output report.html --format both --crq \
    --crq-revenue 2000000000 --crq-industry manufacturing --crq-org-name "Acme Mfg"   # + FAIR $ loss exposure
```

⚠️ **Windows console gotcha:** `banner()` prints box-drawing characters (`╔═╗`) that crash
on the default cp1252 console. Always run with `PYTHONIOENCODING=utf-8` on Windows
(`PYTHONIOENCODING=utf-8 python sap_scanner.py …`). (Pre-existing; fine on UTF-8 terminals.)

### Server mode

```bash
cp .env.example .env          # then set SESSION_SECRET (>=32 chars) and POSTGRES_PASSWORD
docker compose up -d --build
docker compose exec app python -m server.cli init-db
docker compose exec app python -m server.cli create-user admin admin
docker compose exec app python -m server.cli add-landscape "Acme Prod" --mode rise_pce

# scan without a browser (air-gapped path)
python -m server.cli scan "Acme Prod" ./sample_data --sid PRD --client 100
python -m server.cli runs
```

`DB_DSN` and `SESSION_SECRET` have **no defaults** — a deployment that forgets them must fail
at startup rather than silently run on a value published in this repo.

## Architecture

- **`sap_scanner.py`** — CLI entry / orchestrator. Parses args, loads data via `DataLoader`,
  runs each selected auditor, severity-filters, and calls `ReportGenerator`. Each module is
  invoked in its own `if "<key>" in run_modules:` block.
- **`modules/base_auditor.py`** — `BaseAuditor`. Subclass it; implement
  `run_all_checks() -> list[findings]`. Create findings with:
  `self.finding(check_id, title, severity, category, description, affected_items=[],
  remediation="", references=[], details={}, affected_objects=[], subject=[], scope=None,
  system=None, client=None)`. Severity constants: `SEVERITY_CRITICAL/HIGH/MEDIUM/LOW/INFO`.
  `self.get_config(key, default)` reads baseline overrides (from `--config baseline.json`).

  **The identity kwargs are not optional extras — get them wrong and the mitigation journey
  breaks.** Read the `finding()` docstring and `server/identity.py` before touching a module.
  - `affected_objects=[{"type","name","system"?,"client"?,"qualifier"?}]` — the concrete SAP
    objects. Display strings alone cannot be graph nodes and cannot identify a finding.
  - `scope="object"` — the finding is ABOUT the named object(s); identity includes them. Four
    unlocked default users must be four findings, not one.
  - `scope="aggregate"` — the finding SUMMARISES a set ("23 dormant accounts"). Identity
    excludes the members; otherwise dismissing one member retires the finding and raises a new
    one, resetting its age **every run**. Still pass the objects — they become graph nodes.
  - `subject=[…]` — for a finding that is about ONE thing but names several ("role Z_ADMIN
    grants SAP_ALL to 41 users"): the role is identity, the users are members.
  - Types must be registered in `_UPPERCASE_TYPES` or `_CASE_SENSITIVE_TYPES` in
    `server/identity.py`, never both. Case-bearing things (ICF paths, URLs, BTP entities,
    schemas) are case-**sensitive**; SAP identifiers are not.
  - **A cloud object must also be registered in `_CLOUD_SCOPED_TYPES`.** `extract_nodes`
    stamps the run's SID onto anything that does not name its own system — right for ABAP
    objects, wrong for BTP ones. Unregistered, a BTP subaccount role became
    `role_collection:Subaccount_Admin@PRD`, filing a cloud entity under an on-premise SID, and
    a BTP `JSMITH` merged with an ABAP `JSMITH` into one node. That erases the very boundary
    the cloud-to-on-prem attack path exists to show, so **`btp_user` is deliberately distinct
    from `user`** even though the cross-system check matches them: the matching happens in
    Python and reports its result; the graph must still keep the two principals apart.
  - **Do not reach for `subject` just to make `fingerprint_basis` read `objects`.** A genuine
    aggregate is honestly `check_only`; the console presents `objects` as "structural, survives
    rewording", so mislabelling it is a claim the data does not support.
- **`modules/data_loader.py`** — `DataLoader.FILE_MAP` maps a logical data-source name to a
  list of candidate filenames. CSV → list of dicts with **headers normalized to
  UPPERCASE, spaces→underscores** and values stripped; JSON → the parsed object. Missing
  files load as `None`, so checks self-skip when their data is absent.
- **`modules/report_generator.py`** — light-themed HTML dashboard. Uses `html.escape`
  (XSS-safe) and a weighted risk score; renders the P1–P4 priority queue and the
  compliance-mapping panel. Consumes the standard `finding()` dict plus optional
  `priorities` (from `risk_prioritizer.py`). `pdf_report.py` / `pptx_report.py` consume the
  same inputs so all three formats stay consistent.
- **Report-side helpers (not auditors):** `risk_prioritizer.py` (P1–P4 tiering),
  `compliance_mapping.py` (category → framework controls), `pdf_writer.py` / `pptx_writer.py`
  (stdlib PDF / OOXML engines). Keep these in sync when a new **category** is introduced — add
  it to `compliance_mapping.CATEGORY_THEMES` so its findings map to controls.
- **`modules/fair_adapter.py` + `data/fair_scenarios.json`** — optional FAIR cyber-risk
  quantification (`--crq`). The adapter maps findings onto **5 scoped SAP loss scenarios**,
  calibrates the FAIR factor ranges, emits the sibling CRQ engine's scenario JSON, and (if
  `crq_engine.py` is locatable) runs the Monte Carlo to embed a $ ALE + loss-exceedance curve
  in the HTML/PDF. **Invariants to preserve when you touch this** (all covered by
  `tests/test_fair_adapter.py`):
  - *A finding is not a risk.* Findings are **evidence that shifts a scenario's factors**;
    never give a finding its own ALE and sum them. The portfolio ALE is the **element-wise
    Monte-Carlo sum** of per-scenario draws — **never a sum of percentiles**.
  - *Calibration is range-selection, not arithmetic on CVSS/ordinals.* Worst open prevention
    finding → Resistance-Strength band; `exposed`/`exploited` (RiskPrioritizer's own flags) →
    Contact-Frequency / Probability-of-Action bands. Logging/monitoring findings are **not** a
    scenario — they set a **dwell-time loss multiplier** on the dwell-sensitive loss components.
  - *Report filters must not move the number.* FAIR always runs on the **complete** finding set
    (`fair_findings` captured before the `--severity` display filter).
  - *No hard dependency on the sibling repo.* If the engine isn't found, still export the
    `*.crq.json` and degrade gracefully (summary = None).
  - *Routing lives in the catalog.* When you add a **new module**, add its `check_id` prefix (or
    category) to the right scenario's `routing` in `fair_scenarios.json`, else its findings fall
    to the `SAP-PRIV-03` fallback and the report discloses the `unrouted` count. Routing is
    prefix-first, then exact-category — so category strings must match the module's emitted
    `category` **byte-for-byte**.
  - **Loss ranges are modelled estimates from public benchmarks, not measurements** — cite real
    sources in the catalog's `sources[]`, and keep the report's "modelled estimate" disclaimer.
- **`modules/crq_engine.py`** — the FAIR Monte-Carlo engine, bundled. It exists because the
  sibling repo `fair_adapter` looks for is not present in a normal checkout, so `--crq` silently
  degraded to "inputs exported, not simulated" and produced no number at all. It is **last** in
  `_ENGINE_CANDIDATES`, so `--crq-engine`, `CRQ_ENGINE` and an external sibling engine all still
  take precedence.
  - ⚠️ **The vulnerability function is not a free choice.** `data/fair_scenarios.json` documents
    it — `clamp((TC - RS + 50) / 100, 0, 1)` — and its resistance-strength bands are calibrated
    to it (`hardened` ~0.3–0.4, `CRITICAL` ~0.8–0.85 against TC ~50–72). A plain `TC > RS`
    comparison is defensible FAIR theory and **wrong for this catalogue**: the hardened band is
    barely reachable, vulnerability collapses to ~0, and the model claims remediating everything
    drives residual risk to exactly $0. If the function ever changes, **re-calibrate the bands in
    the same commit** — `tests/test_crq_engine.py` fails if they drift apart.
  - Other invariants with tests: frequency is Poisson (a 0.3 expected frequency means "usually
    zero, sometimes one", not "0.3 of an incident"), secondary loss is **conditional** on
    escalation rather than applied to every event, and identical input yields an identical figure
    — a currency number that drifts between runs is indistinguishable from a real change in
    exposure and makes the trend chart worthless.

### The server tier (`server/`)

| file | role |
|---|---|
| `identity.py` | **The load-bearing module.** `AffectedObject`, normalization, `compute_fingerprint`, `extract_nodes`. Read its docstring before changing anything about finding identity. |
| `schema.sql` | 20 tables. Single-tenant (no `tenant_id`); `landscape` preserves the option. Idempotent — re-running it upgrades an existing deployment. |
| `db.py` | psycopg pool, `scope_clause` (**the one place** row scoping is expressed), `audit`. |
| `auth.py` | PBKDF2 passwords, sessions, ranked roles, per-system scope. |
| `queries.py` | Every read of findings/runs/systems, plus assignment, bulk actions and saved views. HTML pages and the JSON API call the same functions — that is what keeps "everything the console shows is in the API" structural. |
| `enrich.py` | Priority tier, owning team, **remediation owner** and SLA window. The team map is a prefix table; the ownership map is deployment-mode dependent. |
| `analytics.py` | The mitigation journey: MTTR, burndown, aging, backlog trajectory, team and domain scorecards. |
| `crq.py` | FAIR quantification per run — portfolio ALE, the 5 scoped scenarios, the unrouted count, and system criticality as a calibration input. |
| `coverage.py` | The per-upload manifest. Module→source mapping is **derived from source at import**, never hand-maintained, so it cannot drift. |
| `ingest.py` | upload → parse → scan → enrich → store → diff → notify. Holds `store_run` (the journey), `_rebase` and `queue_notifications`. |
| `app.py` | FastAPI. Uploads, cancellable background scans, saved-view redirects, `/health`. |
| `cli.py` | Admin + the air-gapped `scan` path. |
| `templates/` | Jinja2, server-rendered, one stylesheet, no client framework. |

**Invariants to preserve in the server tier:**
- *A finding row is never deleted.* "Resolved" is the **absence of an observation in the latest
  run**. That is what lets a regression re-open the same row with its age and assignee intact.
- *Degrade, never drop.* A module that raises is recorded with its traceback and the run
  continues. Losing 22 modules because the 23rd hit a bad row is far worse than an incomplete
  run that says it is incomplete.
- *An empty explicit row scope means NOTHING, not everything.* `scope_clause([])` returns
  `FALSE`. Returning `TRUE` would hand a deliberately-restricted user the whole estate.
- *Coverage is recorded, not implied.* A missing export loads as `None` and its checks
  self-skip; without the manifest a partial upload produces a clean-looking report. This is a
  correctness defect, not a missing feature.
- *`_rebase` must refuse to guess.* Converting a module changes its findings' fingerprints;
  `_rebase` carries history across that only when exactly one candidate matches. Attaching one
  defect's history to another is worse than losing it.
- *`remediation_owner` is four-state* (`customer_fixable` / `ticket_to_sap` / `provider_owned`
  / `not_assessable`). In RISE the customer can see a bad parameter and cannot fix it, so a
  report that says "change this" is unactionable noise.
- *Never add an R&R line-item ID column.* Tagging checks to the SAP contract task they
  discharge is a good idea, but the published PDFs' ID-to-task pairings drift under text
  extraction and are **unverified**. Tag to the task description. See
  `docs/RISE_SECURITY_MODEL.md` §0.
- *The scanner owns severity and priority; a HUMAN owns the assignee.* A re-scan must never
  quietly undo somebody's assignment, and the SLA clock restarts only when the tier actually
  moves — recomputing the due date every run would mean nothing could ever be overdue.
- *Provider-bound work is a separate series in every metric.* A finding a RISE customer cannot
  fix sits open until SAP acts. Rolling `ticket_to_sap` into the customer's MTTR or overdue
  count measures the wrong organisation, which is why it also carries a longer SLA window.
- *Count resolved occurrences, never average a severity.* A mean that falls because a batch of
  LOW findings arrived reports progress where none happened. Likewise MTTR counts only findings
  actually **resolved**: including still-open ones as "time so far" makes it fall whenever new
  findings arrive, which is exactly backwards.
- *A saved view stores FILTERS, never rows*, and the filter keys are an allowlist. Opening a
  shared link re-runs the query under the caller's own row scope, so it can never widen access.

**Two traps this tier has already fallen into — do not re-introduce them:**
- *`CREATE OR REPLACE VIEW` over `SELECT f.*` breaks the upgrade path.* A view's column list
  cannot change, so the first `ALTER TABLE` that adds a column makes re-running `schema.sql`
  fail. If a view is ever wanted, enumerate its columns and `DROP` before recreating.
- *`TemplateResponse` takes `request` FIRST* in current Starlette. The legacy
  `(name, context)` form passes the context dict as the template name and breaks every page —
  while imports succeed and templates parse. `tests/test_http_console.py` exists because that
  is only catchable over HTTP.

### The 23 modules (module key → class → focus)

| key | module | focus |
|---|---|---|
| `users` | user_auth_audit | default users, SAP_ALL, dormant, service accounts, wildcard values |
| `iam` | iam_advanced | SoD, firefighter, role lifecycle, cross-system identity |
| `params` | security_params | password/login/RFC/gateway/TLS/audit profile parameters |
| `network` | network_services | RFC destinations, ICF, transports, audit config |
| `rise` | rise_btp_checks | BTP trust/IdP, comm arrangements, API exposure |
| `btpcloud` | btp_cloud_surface | Cloud Connector, service bindings, destinations, IAS, CPI, network |
| `intglayer` | integration_layer | APIM, IDoc, web services, webhooks, gateway ACLs, OAuth |
| `dataprot` | data_protection | RAL, ILM, masking, GDPR/DPDP, residency |
| `codetrans` | code_transport | ABAP SQLi, ATC, transports, client config, SAP mods |
| `logmon` | log_monitoring | Security Audit Log, SIEM, retention, table logging |
| `fiori` | fiori_ui | catalog access, OData backend auth, spaces/tiles |
| `crypto` | crypto_posture | TLS, certs, SNC, **HANA encryption-at-rest** (data/log/**backup**), **system-replication TLS**, PSE, keys |
| `hanadb` | hana_db_security | HANA DB users/privileges/roles/audit/parameters (not encryption); **log_mode/PITR, MDC cross-DB, DEBUG privileges** |
| `hotnews` | sap_hotnews | missing critical SAP Security Notes since 2020 |
| `authz` | abap_authorizations | AGR_1251 role-content: critical auth objects & transactions |
| `systrust` | system_trust | trusted RFC, SAProuter, msg server, UCON, SAP*/default passwords |
| `baseline` | baseline_params | SAP Security Baseline profile params: auth engine, SNC fallback, GUI scripting, weak hashes, sapstartsrv, gateway ACL, SSO cookies, ICM log |
| `s4authz` | s4_business_authz | S/4HANA business roles/catalogs/restrictions, CDS auth-check, OData V4, Cloud Connector principal propagation, CF platform roles, birthright role collections |
| `ara` | access_risk_analysis | offline GRC-style **permission-level SoD** from AGR_1251+AGR_USERS: 27-risk ruleset (P2P/O2C/R2R/H2R/Basis), mitigating controls, per-user risk score; iam SoD defers to it when role_auth_values present |
| `jobcmd` | basis_job_command | **host-command-execution surface**: SM69/SXPGCOSTAB external cmds (shell-wrap/ADDPAR/path/danger-verb) + TBTCO/TBTCP armed job step users (SAP*/DDIC/SAP_ALL, RSBDCOS0, external steps, deleted/dialog, identity-borrow); reuses users/profiles |
| `grcac` | grc_access_control | **GRC Access Control**: EAM/Firefighter usage+ownership, ARM access-request workflow, GRC-native SoD violations, mitigating controls, SoD ruleset governance |
| `rolegov` | role_governance | **role design**: SU24 proposal hygiene for custom tcodes, ungenerated profiles (AGR_1016), derived-role authorization-value drift vs parent |
| `fincontrols` | financial_controls | **SOX ITGC / FI config**: posting-period controls (T001B), tolerance groups (T043T), payment dual-control (T055F), document-change rules (TBAER), FI number-range buffering (TNRO) |

## Adding a new module (the recipe)

1. **`modules/<name>.py`** — `class <Name>Auditor(BaseAuditor)`, with a `run_all_checks()`
   that calls check methods. Each check: `rows = self.data.get("<source>")`; guard
   `if not rows: return`; iterate with **tolerant column access**
   (`row.get("A", row.get("B", ""))`); collect offenders; `self.finding(...)`. Check IDs are
   `MODULE-SUBAREA-NNN` (e.g. `HANADB-PRIV-001`, `AUTH-002`, `TRUST-005`). Always cite **real**
   references (SAP Note / CIS SAP / DSAG / SAP Security Baseline).
   **Pass `affected_objects` and `scope` on every finding** — names taken from the data, never
   invented; omit the object rather than fabricating a placeholder when a row lacks the field.
   `server/coverage.py` derives your module's data sources by scanning for
   `self.data.get("…")`, so the coverage manifest picks the module up automatically.
2. **`sap_scanner.py`** — add the import, add the module key to the `--modules` `choices`
   list, add it to the `"all"` expansion list, and add an `if "<key>" in run_modules:` run block.
3. **`modules/data_loader.py`** — add the new data source(s) to `FILE_MAP`.
4. **`sample_data/`** — add crafted-bad sample files so the module produces findings on the
   bundled `sample_data` run (and verify a benign row does NOT fire).
5. **Docs** — bump the README badge + "N+ checks across M modules" line, add a README module-
   table row, and add a section to `docs/CHECKS_REFERENCE.md`.
6. **Reports** — add a `data/finding_details.json` KB entry per new check (detailed risk +
   step-by-step remediation) so the PDF/PPTX hand-over stays detailed, and if the module
   introduces a **new category** string, add it to `compliance_mapping.CATEGORY_THEMES` so its
   findings map to framework controls.
7. **Smoke test end-to-end** (see below), then commit.

## Conventions & gotchas (learned the hard way)

- **Never fabricate SAP identifiers.** SAP Note numbers, CVEs, authorization objects/fields
  (`S_DEVELOP`/`OBJTYPE`/`ACTVT`), and profile parameter names must be **verified against SAP
  Help / SAP Security Baseline / CIS SAP / DSAG** before shipping. Past verification passes
  caught wrong SAP Note numbers (`2408073`, `1852424`) and misattributed auth logic. When
  unsure of a specific SAP Note number, prefer a generic "SAP Security Baseline" reference.
- **Run the FULL scanner, not just `run_all_checks()`.** A direct `run_all_checks()` smoke
  test does not exercise `report_generator`. A trailing comma in `description=( "…", )` makes
  the value a **tuple**, which passes the findings test but crashes `html.escape` in the HTML
  report. Always finish with a full `PYTHONIOENCODING=utf-8 python sap_scanner.py --data-dir
  ./sample_data …` run.
- **String false-positive/negative traps.** Substring tests bite: `"lock" in "unlocked"` is
  `True`; `"default" in "No default"` is `True`. Use `startswith` / exact tokens and guard
  negations.
- **Fire only on present-and-risky.** Parameter checks should key on a parameter being
  *present with a risky value*, not merely absent from the export (absence ≠ secure/insecure).
- **A module may defer to a deeper sibling, but never on data presence alone, and never
  silently.** `iam` defers its transaction-level SoD to `ara`'s permission-level analysis — but
  the condition must be *"is `ara` actually running"* (`self.module_is_running("ara")`), not
  *"is `ara`'s input loaded"*. Those differ: `--modules iam` loads `role_auth_values.csv` without
  running `ara`, and the original condition made SoD analysis produce **nothing** while looking
  like a clean result. When a check does stand down it must emit an INFO finding saying so —
  same discipline as the coverage manifest: **absence is stated, never implied**. Callers pass
  `run_context={"modules": …}`; a module given no context keeps its historical behaviour rather
  than guessing.
- **CSV header normalization:** the loader upper-cases headers and replaces spaces with `_`,
  so match `row.get("USER_NAME")` etc. Values are stripped but keep their case.
- **Tests + CI exist** (`tests/`, `.github/workflows/tests.yml`, `requirements-dev.txt`). Run
  `python -m pytest -q` (no SAP system needed). The suite runs every module over `sample_data`
  and validates the finding contract, cross-module id collisions, the report render, and a CLI
  end-to-end run. **When you add a module:** it is picked up automatically by the parametrized
  tests via the `MODULES` list in `tests/test_scanner.py` — add your class there, and add a set
  of key check ids to `EXPECTED_CHECKS` so a regression that stops your checks firing is caught.
  Module tests stay stdlib + `pytest`-only; type hints stay `typing`-based (`List`/`Dict`/
  `Optional`, not `list[...]`/`X | Y`) for the 3.8–3.12 matrix.
- **Three suites need a real PostgreSQL and SKIP without `DB_DSN`** —
  `test_integration_ingest.py` (the journey), `test_integration_journey.py` (analytics, saved
  views, bulk actions) and `test_http_console.py` (every route returns 200). The journey is
  implemented in SQL, so a mocked database proves the Python is self-consistent and proves
  nothing about whether it works. Run them:
  ```bash
  docker run -d --name sapsec-test-db -e POSTGRES_USER=sapsec -e POSTGRES_PASSWORD=sapsec \
      -e POSTGRES_DB=sapsec -p 55433:5432 postgres:16
  DB_DSN=postgresql://sapsec:sapsec@localhost:55433/sapsec \
  SESSION_SECRET=$(python -c "import secrets;print(secrets.token_urlsafe(48))") \
      python -m pytest tests/test_integration_ingest.py \
                       tests/test_integration_journey.py \
                       tests/test_http_console.py -q
  ```
- **The Phase-1 exit criterion is a test, and it must stay green:** scan the same bundle twice
  and get `new 0 · persisting N · resolved 0`. If it ever fails, finding identity has broken
  and every re-upload will report the whole estate as newly broken.
- **CI has three jobs, and the skip guard is load-bearing.** `cli` (3.8–3.12, pytest only, so a
  third-party import into the scanner core fails the build), `purity` (walks the AST of
  `modules/` and rejects any non-stdlib import), and `server` (PostgreSQL 16, applies the schema
  **twice** because idempotency is the upgrade path and it has broken once). The `server` job
  **fails if more than one test skips** — before that guard, `pytest -q` ran the DB-backed
  suites, they skipped for want of `DB_DSN`, and the job went green having verified nothing.
- **`tests/test_identity.py` runs against the REAL `sample_data`, not fixtures**, and asserts
  the `check_id` collisions still exist before asserting they resolve. If the sample data ever
  stops colliding, the test fails loudly rather than silently proving less.

## Product direction

The tool is being taken from an offline assessment CLI to a commercial-grade platform. The
competitive and contractual research behind that is in `docs/`, and it is evidence-based —
claims are labelled `verified` / `asserted` / `inferred`, and two adversarial verification
passes corrected sixteen of them.

| doc | what it settles |
|---|---|
| [`PIVOT_PLAN.md`](docs/PIVOT_PLAN.md) | Architecture and the six phases, with rationale |
| [`BUILD_ROADMAP.md`](docs/BUILD_ROADMAP.md) | Execution view: status, dependencies, exit criteria, non-goals |
| [`COMPETITIVE_ANALYSIS.md`](docs/COMPETITIVE_ANALYSIS.md) | Onapsis, the market, and the attack-path design spec |
| [`COMPETITOR_SECURITYBRIDGE.md`](docs/COMPETITOR_SECURITYBRIDGE.md) | SecurityBridge dossier |
| [`RISE_SECURITY_MODEL.md`](docs/RISE_SECURITY_MODEL.md) | Where SAP's contractual line sits; what a RISE customer can actually export |

**Things that would be a mistake to build** (each is argued in the docs): real-time threat
detection, transport gating, ABAP source SAST (SAP gives RISE customers CVA free), peer
benchmarking (fiction without a customer base), BusinessObjects/SuccessFactors, an ABAP agent
of any kind, and check-count comparisons.

**Do not repeat these overclaims:** the mitigation journey is *table stakes*, not a
differentiator — both incumbents ship it. The genuinely open lane is monetary risk
quantification. And absence of a capability in a competitor's public material is stated as
"no public evidence across N named sources", never as proof of absence.

## Git / commits

- Remote: `https://github.com/Krishcalin/SAP-S4HANA-RISE-Security-Scanner`.
- **Commit style: plain, descriptive conventional messages with NO co-author trailer** —
  match the existing history (e.g. `Adding <X> module — <summary> (N new checks)`).
- Flow: branch → commit → `git fetch` → ff-merge to `main` → push. Keep new modules additive.
