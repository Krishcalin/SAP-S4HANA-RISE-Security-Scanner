# CLAUDE.md — SAP S/4HANA RISE Security Scanner

Guidance for Claude Code (and humans) working in this repository.

## What this is

An **offline SAP S/4HANA RISE + BTP security config-review tool**. It reads exported
SAP configuration (CSV / JSON) from a `--data-dir`, runs a set of auditor modules, and
produces an interactive **HTML report** with findings, severity ratings and remediation.
No live system / RFC connection is needed — ideal for RISE environments with restricted
access.

- **Zero external dependencies** — Python 3.8+ standard library only. Do **not** add
  third-party packages (no `requirements.txt` / `pyproject.toml` by design).
- **~278+ checks across 19 audit modules** (keep the README badge/count and
  `docs/CHECKS_REFERENCE.md` in sync when you add checks).
- CIS SAP / DSAG-aligned; findings cite real SAP Notes / SAP Security Baseline / CIS.
- **Flow** (illustrated by `docs/banner.svg`): `sap_scanner.py` **LOADs** the exports
  (`DataLoader`) → runs the 19 auditor **MODULES** → each emits severity-ranked findings
  (**CHECKS** → **RANK**) → a **REPORT** is written. When you add a module, refresh
  `docs/banner.svg`'s module/check counts too.
- **Reports** (`--format html|pdf|both`): `report_generator.py` (HTML dashboard) and
  `pdf_report.py` (multi-page hand-over PDF, on the stdlib `pdf_writer.py` engine — no
  third-party PDF lib). Both render each finding's detailed **Security Risk** narrative +
  step-by-step **Remediation** from the findings knowledge base (`finding_kb.py` loading
  `data/finding_details.json`, keyed by check-id with family-prefix fallback), falling back
  to the finding's own `description`/`remediation` when no KB entry exists. When you add
  checks, add matching KB entries so the hand-over report stays detailed.

## Run it

```bash
python sap_scanner.py --data-dir ./sample_data --output report.html            # all modules
python sap_scanner.py --data-dir ./sample_data --output report.html --modules hanadb authz
python sap_scanner.py --data-dir ./exports --output report.html --severity HIGH  # min severity
```

⚠️ **Windows console gotcha:** `banner()` prints box-drawing characters (`╔═╗`) that crash
on the default cp1252 console. Always run with `PYTHONIOENCODING=utf-8` on Windows
(`PYTHONIOENCODING=utf-8 python sap_scanner.py …`). (Pre-existing; fine on UTF-8 terminals.)

## Architecture

- **`sap_scanner.py`** — CLI entry / orchestrator. Parses args, loads data via `DataLoader`,
  runs each selected auditor, severity-filters, and calls `ReportGenerator`. Each module is
  invoked in its own `if "<key>" in run_modules:` block.
- **`modules/base_auditor.py`** — `BaseAuditor`. Subclass it; implement
  `run_all_checks() -> list[findings]`. Create findings with:
  `self.finding(check_id, title, severity, category, description, affected_items=[],
  remediation="", references=[], details={})`. Severity constants:
  `SEVERITY_CRITICAL/HIGH/MEDIUM/LOW/INFO`. `self.get_config(key, default)` reads
  baseline overrides (from `--config baseline.json`).
- **`modules/data_loader.py`** — `DataLoader.FILE_MAP` maps a logical data-source name to a
  list of candidate filenames. CSV → list of dicts with **headers normalized to
  UPPERCASE, spaces→underscores** and values stripped; JSON → the parsed object. Missing
  files load as `None`, so checks self-skip when their data is absent.
- **`modules/report_generator.py`** — HTML dashboard. Uses `html.escape` (XSS-safe) and a
  weighted risk score. Consumes the standard `finding()` dict.

### The 19 modules (module key → class → focus)

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
| `crypto` | crypto_posture | TLS, certs, SNC, **HANA encryption-at-rest**, PSE, keys |
| `hanadb` | hana_db_security | HANA DB users/privileges/roles/audit/parameters (not encryption) |
| `hotnews` | sap_hotnews | missing critical SAP Security Notes since 2020 |
| `authz` | abap_authorizations | AGR_1251 role-content: critical auth objects & transactions |
| `systrust` | system_trust | trusted RFC, SAProuter, msg server, UCON, SAP*/default passwords |
| `baseline` | baseline_params | SAP Security Baseline profile params: auth engine, SNC fallback, GUI scripting, weak hashes, sapstartsrv, gateway ACL, SSO cookies, ICM log |
| `s4authz` | s4_business_authz | S/4HANA business roles/catalogs/restrictions, CDS auth-check, OData V4, Cloud Connector principal propagation, CF platform roles, birthright role collections |
| `ara` | access_risk_analysis | offline GRC-style **permission-level SoD** from AGR_1251+AGR_USERS: 27-risk ruleset (P2P/O2C/R2R/H2R/Basis), mitigating controls, per-user risk score; iam SoD defers to it when role_auth_values present |

## Adding a new module (the recipe)

1. **`modules/<name>.py`** — `class <Name>Auditor(BaseAuditor)`, with a `run_all_checks()`
   that calls check methods. Each check: `rows = self.data.get("<source>")`; guard
   `if not rows: return`; iterate with **tolerant column access**
   (`row.get("A", row.get("B", ""))`); collect offenders; `self.finding(...)`. Check IDs are
   `MODULE-SUBAREA-NNN` (e.g. `HANADB-PRIV-001`, `AUTH-002`, `TRUST-005`). Always cite **real**
   references (SAP Note / CIS SAP / DSAG / SAP Security Baseline).
2. **`sap_scanner.py`** — add the import, add the module key to the `--modules` `choices`
   list, add it to the `"all"` expansion list, and add an `if "<key>" in run_modules:` run block.
3. **`modules/data_loader.py`** — add the new data source(s) to `FILE_MAP`.
4. **`sample_data/`** — add crafted-bad sample files so the module produces findings on the
   bundled `sample_data` run (and verify a benign row does NOT fire).
5. **Docs** — bump the README badge + "N+ checks across M modules" line, add a README module-
   table row, and add a section to `docs/CHECKS_REFERENCE.md`.
6. **Smoke test end-to-end** (see below), then commit.

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
- **CSV header normalization:** the loader upper-cases headers and replaces spaces with `_`,
  so match `row.get("USER_NAME")` etc. Values are stripped but keep their case.
- **Tests + CI exist** (`tests/`, `.github/workflows/tests.yml`, `requirements-dev.txt`). Run
  `python -m pytest -q` (stdlib + pytest only; no SAP system needed). The suite runs every
  module over `sample_data` and validates the finding contract, cross-module id collisions, the
  report render, and a CLI end-to-end run. **When you add a module:** it is picked up
  automatically by the parametrized tests via the `MODULES` list in `tests/test_scanner.py` —
  add your class there, and add a set of key check ids to `EXPECTED_CHECKS` so a regression that
  stops your checks firing is caught. Keep tests stdlib + `pytest`-only. CI matrix is Python
  3.8–3.12; keep type hints `typing`-based (`List`/`Dict`/`Optional`, not `list[...]`/`X | Y`).

## Git / commits

- Remote: `https://github.com/Krishcalin/SAP-S4HANA-RISE-Security-Scanner`.
- **Commit style: plain, descriptive conventional messages with NO co-author trailer** —
  match the existing history (e.g. `Adding <X> module — <summary> (N new checks)`).
- Flow: branch → commit → `git fetch` → ff-merge to `main` → push. Keep new modules additive.
