# ECC coverage, measured

**Phase 1 of the platform-coverage plan.** It ships no feature. Its only job is to
find out whether the estimate the rest of the plan rests on — *"fourteen of the
thirty modules run on an ECC export with no code change at all"* — survives
contact with a real fixture, cheaply, before ten to fifteen days are spent on
Phase 3.

## The answer

**It survives, exactly.** Fourteen of the thirty auditors produce findings on the
ECC fixture that are **identical** to what they produce on the full sample.

| | of 30 |
|---|---:|
| identical to the full sample — *"runs with no code change"* | **14** |
| produce findings, but fewer than with full data | 6 |
| **produce findings at all** | **20** |
| cannot exist on ECC (no HANA, Fiori, BTP, CDS, S/4 business roles) | 5 |
| optional tooling — could run if the customer exports it (GRC, FI config) | 2 |
| no file inputs (`abap_sast` reads `--abap-src`) | 1 |
| silent even with full data | 2 |

The estimate is confirmed on its own terms and the number is not the whole story,
so two more are published beside it. **20 of 30** produce something useful — the
six "partial" modules are degraded and still worth running. And by the strictest
reading, only **9** are `complete` on data presence alone. Which number is right
depends on what "runs" is taken to mean, and this table exists so that nobody has
to guess.

## How the fixture was decided, and when

The tiers were fixed in `tests/ecc_fixture_tiers.py` **before the measurement was
run**, on grounds of what an ECC estate HAS and what a Basis team can EXPORT —
never on which modules they would light up. A fixture assembled after seeing the
number, or tuned until the number matched, would measure nothing.

- **Tier A — in the fixture (38 sources).** What a realistic ECC 6.0 EHP8 Basis
  and security export contains.
- **Tier B — cannot exist (37 sources).** HANA (this system is AnyDB), Fiori,
  BTP and the whole cloud surface, ABAP CDS, S/4 business roles, the Gateway
  OData catalogue. These are architectural absences, not export friction.
- **Tier C — optional tooling (38 sources).** GRC Access Control, ILM and
  data-protection tooling, SIEM and operational documents, FI configuration.
  Whether these exist is a fact about the **customer**, not about ECC — so they
  are excluded from the base measurement rather than assumed either way.

Nine Tier-A sources have no file in `sample_data/` at all and so are absent from
the fixture too: `auth_objects`, `dev_access_prod`, `ext_os_commands_sap`,
`role_tcodes`, `sap_security_notes`, `snc_config`, `table_auth_groups`,
`transports`, `user_groups`. **The measurement therefore understates ECC coverage
slightly**, and that is stated rather than corrected by hand — inventing SAP
content to flatter a number is the one thing this exercise must not do.

## What the measurement found on the way

Phase 1 was supposed to produce no code change. It produced two, because the
measurement could not be trusted until they were made.

**Four of thirty auditors were invisible to the coverage manifest.** Not
"unknown", not "skipped" — absent. `user_auth_audit`, `ecs_config_items`,
`code_inventory_report` and `abap_sast` all read their data through an accessor,
a class constant, or `(self.data or {}).get(...)`, and `module_sources()` only
recognised a literal `self.data.get("name")`. So the report whose entire purpose
is to say what was and was not covered said **nothing at all** about the module
that audits users, profiles and roles. Fixed by parsing the accessor pattern, and
by mapping every auditor rather than only those with a recognised read.

**A module with no file inputs was reported as `skipped`.** `abap_sast` reads an
unpacked abapGit directory given with `--abap-src`, which is not one of the
loader's logical sources. Calling that "skipped" tells a customer they forgot an
export that does not exist. It is now `no_file_inputs`.

One near-miss worth recording: the accessor analysis initially collected `"DDIC"`
— a standard SAP user name passed to a data-reading helper — and turned it into a
required source no customer could ever supply, which would have made
`user_auth_audit` read as permanently degraded. Requirements are now filtered
against what the loader actually knows. Over-reporting is the more dangerous
direction: it manufactures coverage gaps that are not real, and a manifest that
cries wolf gets ignored.

## Reproducing it

```bash
python -m tests.measure_ecc_coverage sample_data_ecc   # the ECC fixture
python -m tests.measure_ecc_coverage sample_data       # the full-data control
```

The control matters. Without it, "this module produced 6 findings" says nothing
about whether 6 is all of them.

## The per-module table

| module | status | ECC | full | verdict |
|---|---|---:|---:|---|
| `security_params` | complete | 34 | 34 | **identical to full sample** |
| `abap_authorizations` | complete | 16 | 16 | **identical to full sample** |
| `atc_import` | complete | 12 | 12 | **identical to full sample** |
| `baseline_params` | complete | 12 | 12 | **identical to full sample** |
| `system_trust` | complete | 12 | 12 | **identical to full sample** |
| `log_review` | complete | 5 | 5 | **identical to full sample** |
| `code_inventory_report` | complete | 3 | 3 | **identical to full sample** |
| `snc_posture` | complete | 1 | 1 | **identical to full sample** |
| `ecs_config_items` | complete | 0 | 0 | silent on both |
| `code_transport` | degraded | 22 | 22 | **identical to full sample** |
| `basis_job_command` | degraded | 11 | 11 | **identical to full sample** |
| `integration_layer` | degraded | 9 | 30 | partial — 9 of 30 |
| `user_auth_audit` | degraded | 9 | 9 | **identical to full sample** |
| `crypto_posture` | degraded | 7 | 13 | partial — 7 of 13 |
| `log_monitoring` | degraded | 7 | 10 | partial — 7 of 10 |
| `access_risk_analysis` | degraded | 6 | 6 | **identical to full sample** |
| `iam_advanced` | degraded | 6 | 22 | partial — 6 of 22 |
| `network_services` | degraded | 6 | 6 | **identical to full sample** |
| `sap_hotnews` | degraded | 4 | 4 | **identical to full sample** |
| `data_protection` | degraded | 3 | 18 | partial — 3 of 18 |
| `role_governance` | degraded | 2 | 3 | partial — 2 of 3 |
| `resilience_posture` | degraded | 0 | 0 | silent on both |
| `abap_sast` | no_file_inputs | 0 | 0 | no file inputs (needs --abap-src) |
| `btp_cloud_surface` | skipped | 0 | 32 | **cannot exist on ECC** |
| `financial_controls` | skipped | 0 | 5 | optional tooling — ECC could, if exported |
| `fiori_ui` | skipped | 0 | 6 | **cannot exist on ECC** |
| `grc_access_control` | skipped | 0 | 13 | optional tooling — ECC could, if exported |
| `hana_db_security` | skipped | 0 | 18 | **cannot exist on ECC** |
| `rise_btp_checks` | skipped | 0 | 8 | **cannot exist on ECC** |
| `s4_business_authz` | skipped | 0 | 8 | **cannot exist on ECC** |
