# ECC coverage, measured

**Phase 1 of the platform-coverage plan.** It ships no feature. Its only job is to
find out whether the estimate the rest of the plan rests on — *"fourteen of the
thirty modules run on an ECC export with no code change at all"* — survives
contact with a real fixture, cheaply, before ten to fifteen days are spent on
Phase 3.

## The answer

**It survived, exactly.** When this was first measured, fourteen of the thirty
auditors produced findings on the ECC fixture **identical** to what they produced
on the full sample — the estimate the plan rested on, confirmed on its own terms.

**The number has since moved to fourteen of thirty-three, and neither move was
the estimate being wrong.** The product grew, in two different ways.

Two auditors were added that ECC *can* feed — `master_data_changes` and
`vendor_master` — and with them ECC-native sources the original fixture had no
reason to carry: vendor master and bank details (`LFA1` / `LFBK`) and
change-document items (`CDPOS`, whose header table `CDHDR` was in the fixture
from the start, making its absence arbitrary rather than considered). Both are
things an ECC 6.0 estate genuinely has and a Basis team can genuinely export, so
both are Tier A, and `vendor_master` runs on ECC exactly as it runs on S/4.

A third, `cap_xsuaa`, was added that ECC **cannot** feed at any effort: it reads a
CAP project's `xs-security.json` and CDS model, which are BTP artefacts that do
not exist in an ECC estate. It moves the denominator without moving the
numerator, which is why the headline ratio changed while nothing about ECC did.
That is the honest way for this number to move, and it is worth stating plainly:
adding modules an ECC customer can never use makes this figure look worse without
making their scan worse.

A fourth change moved it the other way, and downward was the improvement.
`ucon_exposure` is NOT in the identical set, and the reason is the fixture rather than
the product: `sample_data_ecc` carries no UCON export, so the module returns its
coverage finding there and its full check set on the S/4 sample. Adding UCON files to the
ECC fixture would assert that ECC estates generally have UCON configured, which was
not verified against SAP-primary material — so that estimate stands and this
paragraph records why rather than the fixture implying an answer.

`sap_hotnews` left the identical set when its exposure checks began comparing the
installed component release against the affected-version lists SAP publishes with
each CVE. The ECC fixture is SAP_BASIS 750 with no S4CORE; the full sample is 755
with S4CORE 105 — so the two systems now receive different answers, which is the
correct outcome and was not previously possible. A module that returns the same
findings whatever release it is pointed at is "identical to the full sample" for
the least interesting reason available.

The estimate was conservative, not mistaken.

| | of 34 |
|---|---:|
| identical to the full sample — *"runs with no code change"* | **15** |
| produce findings, but fewer than with full data | 7 |
| **produce findings at all** | **22** |
| cannot exist on ECC (no HANA, Fiori, BTP, CDS, S/4 business roles) | 6 |
| optional tooling — could run if the customer exports it (GRC, FI config) | 2 |
| no file inputs (`abap_sast` reads `--abap-src`) | 1 |
| silent even with full data | 2 |

The number is not the whole story, so two more are published beside it. **25** of
34** produce something useful — the seven "partial" modules are degraded and
still worth running. Which number is right depends on what "runs" is taken to
mean, and this table exists so that nobody has to guess. The per-module table
below is regenerated from the measurement rather than maintained by hand, because
the first version of it had already drifted from the code by the time a second
module was added.

## How the fixture was decided, and when

The tiers were fixed in `tests/ecc_fixture_tiers.py` **before the measurement was
run**, on grounds of what an ECC estate HAS and what a Basis team can EXPORT —
never on which modules they would light up. A fixture assembled after seeing the
number, or tuned until the number matched, would measure nothing.

- **Tier A — in the fixture (39 sources).** What a realistic ECC 6.0 EHP8 Basis
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
| `security_params` | complete | 35 | 35 | **identical to full sample** |
| `code_transport` | degraded | 22 | 22 | **identical to full sample** |
| `abap_authorizations` | complete | 16 | 16 | **identical to full sample** |
| `atc_import` | complete | 12 | 12 | **identical to full sample** |
| `baseline_params` | complete | 12 | 12 | **identical to full sample** |
| `system_trust` | complete | 12 | 12 | **identical to full sample** |
| `basis_job_command` | degraded | 11 | 11 | **identical to full sample** |
| `sap_hotnews` | degraded | 10 | 9 | more on ECC (10 vs 9) — extra findings are coverage disclosures |
| `integration_layer` | degraded | 9 | 30 | partial — 9 of 30 |
| `user_auth_audit` | degraded | 9 | 9 | **identical to full sample** |
| `access_risk_analysis` | degraded | 7 | 7 | **identical to full sample** |
| `crypto_posture` | degraded | 7 | 13 | partial — 7 of 13 |
| `log_monitoring` | degraded | 7 | 10 | partial — 7 of 10 |
| `iam_advanced` | degraded | 6 | 22 | partial — 6 of 22 |
| `network_services` | degraded | 6 | 6 | **identical to full sample** |
| `log_review` | complete | 5 | 5 | **identical to full sample** |
| `code_inventory_report` | complete | 3 | 3 | **identical to full sample** |
| `data_protection` | degraded | 3 | 18 | partial — 3 of 18 |
| `role_governance` | degraded | 2 | 3 | partial — 2 of 3 |
| `vendor_master` | complete | 2 | 2 | **identical to full sample** |
| `master_data_changes` | complete | 1 | 2 | partial — 1 of 2 |
| `snc_posture` | complete | 1 | 1 | **identical to full sample** |
| `abap_sast` | not_requested | 0 | 0 | no file inputs (needs `--abap-src`) |
| `btp_cloud_surface` | skipped | 0 | 32 | **cannot exist on ECC** |
| `cap_xsuaa` | skipped | 0 | 0 | silent on both |
| `ecs_config_items` | complete | 0 | 0 | silent on both |
| `financial_controls` | skipped | 0 | 8 | optional tooling — ECC could, if exported |
| `fiori_ui` | skipped | 0 | 6 | **cannot exist on ECC** |
| `grc_access_control` | skipped | 0 | 16 | optional tooling — ECC could, if exported |
| `hana_db_security` | skipped | 0 | 18 | **cannot exist on ECC** |
| `resilience_posture` | degraded | 0 | 0 | silent on both |
| `rise_btp_checks` | skipped | 0 | 8 | **cannot exist on ECC** |
| `s4_business_authz` | skipped | 0 | 8 | **cannot exist on ECC** |


## 2026-08-29 — `ruleset_coverage` added, parity moved 14 → 15

`modules/ruleset_coverage.py` measures what fraction of an estate's granted
transactions and authorization objects the SoD ruleset can name. It reads
`role_auth_values` (AGR_1251) and nothing else, and AGR_1251 is identical on ECC
and S/4HANA — so the module is **ECC-identical by construction**, not by
coincidence, and needed no ECC-specific handling.

Parity is therefore **15 of 34** identical and **25 of 34** producing something.
Recorded here rather than left to move quietly, per the guard in
`tests/test_ecc_coverage.py`.
