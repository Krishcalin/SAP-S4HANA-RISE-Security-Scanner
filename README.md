<p align="center">
  <img src="assets/monitorrisk-logo.png" alt="MonitorRisk — SAP Threat, Vulnerability, Governance &amp; Risk Quantification" width="620"/>
</p>

<p align="center">
  <strong>Security auditing for SAP S/4HANA RISE, ECS, ECC and BTP</strong><br/>
  <sub>Reads exported files · nothing installed in SAP · no RFC user · nothing written back</sub>
</p>

<p align="center">
  <a href="https://github.com/Krishcalin/SAP-S4HANA-RISE-Security-Scanner/actions/workflows/tests.yml"><img src="https://github.com/Krishcalin/SAP-S4HANA-RISE-Security-Scanner/actions/workflows/tests.yml/badge.svg" alt="tests"/></a>
  <img src="https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.8+"/>
  <img src="https://img.shields.io/badge/checks-794%20in%2038%20modules-red?style=flat-square" alt="794 checks in 38 modules"/>
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="MIT licensed"/>
</p>

---

## The SAP Security Tool

MonitorRisk is an open source SAP Security Tool which someone can use to assess the effectiveness of the security controls within an SAP RISE Private or Public cloud environment. This is a solution built as a client server architecture using Python3, FastAPI, React, PostgreSQL16, TypeScript. You export configuration data out of your SAP systems as CSV and JSON files.
This reads those files and tells you what is wrong, how bad it is, who can fix
it, and what it might cost you.

You can extra the file in an offline fashion or in a connected way. Nothing is installed in the SAP system, no
RFC user is created, and nothing is ever written back. That is deliberate: in a
RISE contract a third-party ABAP add-on is an excluded task needing a separate
SKU and a long evaluation, and a folder of exports needs none of it.

There is an optional collector that can fetch those exports for you from a
system you authorise. It is read-only, it is a separate command you have to run
on purpose, and the scanner itself still connects to nothing.

**Start here:** [System Architecture](docs/ARCHITECTURE.md) — a plain-language
guide with no SAP background assumed.

---

## Try it

Sample data is included, so this works on a fresh checkout with nothing set up:

```bash
python sap_scanner.py --data-dir sample_data --format html --output report.html
```

Open `report.html`. That is the whole tool.

---

## Two ways to run it

Both use the same scanner underneath.

| | **CLI** | **Server** |
|---|---|---|
| You give it | A folder of exports | The same files, uploaded in a browser |
| You get back | HTML, PDF or PowerPoint | A web console and a JSON API |
| It remembers | Nothing — one run, one report | Everything, in PostgreSQL |
| Use it for | A one-off review, or an air-gapped site | Tracking whether things actually get fixed |

The CLI needs Python and nothing else. The server needs PostgreSQL and four
Python packages.

---

## What it checks

**794 checks across 38 modules.** Every one is listed, with what it reads and
which SAP baseline requirement it answers, in
**[docs/CHECKS_REFERENCE.md](docs/CHECKS_REFERENCE.md)** — a file generated from
the code, so it cannot drift from what actually runs.

The areas covered:

- **Users and authorisations** — who has what, including permission-level
  segregation of duties against a ruleset of 99 conflicting-duty rules
- **Profile parameters** — all 92 of the 92 parameters SAP makes mandatory for
  Enterprise Cloud Services in Note 3250501
- **HANA database** — privileges, auditing, encryption, parameters
- **BTP and cloud** — Cloud Connector, destinations, IAS, entitlements, CPI
- **Interfaces** — RFC, web services, IDoc, gateway ACLs, OAuth clients
- **Custom ABAP code** — 133 static-analysis rules with taint tracking
- **Financial controls** — the SOX-relevant configuration in FI
- **Patching, logging, encryption, transports, backup and recovery**

Findings are mapped to ISO 27001, NIST 800-53, NIST CSF, CIS Controls, DORA,
TISAX, SOC 2, SOX and GDPR.

---

## What you feed it

136 different export sources, all of them files a Basis or security team can
produce with standard SAP transactions.

- **[docs/EXPORT_GUIDE.md](docs/EXPORT_GUIDE.md)** — how to produce each one
- **[docs/EXPORT_SOURCES.md](docs/EXPORT_SOURCES.md)** — the full catalogue

You do not need all of them. Give it what you have; it reports what it could
not assess rather than quietly scoring you on a subset.

---

## Common options

| | |
|---|---|
| `--format html \| pdf \| pptx \| all` | What to produce |
| `--severity CRITICAL \| HIGH \| …` | What to list. It never changes what was *found* — the scores and the money are always computed on everything |
| `--modules iam,hanadb,…` | Run only some of them. `--modules all` is the default |
| `--deployment-mode on_prem \| rise_pce \| rise_tailored \| rise_ecc` | Decides what counts as compliant. Get this right or a RISE system looks broken |
| `--config FILE` | Your own thresholds, merged over the shipped baseline |
| `--abap-src DIR` | Scan custom ABAP from an abapGit offline export |
| `--cap-src DIR` | Scan a CAP project's `xs-security.json` and CDS model |
| `--crq` | Put a money figure on it — see below |
| `--gate` | Use it as a release gate — see below |

### Fetching the exports for you

If you would rather not export by hand, a separate read-only collector can do it
from a system you authorise. It writes the same files, and the scanner still
connects to nothing:

```bash
python -m collect sapcontrol --host … --out exports/   # profile parameters, topology
python -m collect icf        --url  … --out exports/   # which endpoints answer, and to whom
python -m collect btp        --subaccount … --out exports/
python -m collect rfc        --host … --out exports/   # needs SAP's NetWeaver RFC SDK, your licence
```

Details in [docs/EXPORT_GUIDE.md](docs/EXPORT_GUIDE.md).

### Putting a money figure on it

```bash
python sap_scanner.py --data-dir exports/ --crq --crq-inputs crq_parameters.json
```

`crq_parameters.json` holds your own figures — what an hour of downtime costs,
how many personal records you hold, how often SAP here is actually probed.
What it prices, and what it refuses to price without them, is under
[What it will not tell you](#what-it-will-not-tell-you).

---

## Server mode

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"   # paste into SESSION_SECRET
docker compose up -d --build

docker compose exec app python -m server.cli init-db
docker compose exec app python -m server.cli create-user admin admin --generate
```

Open <http://localhost:8000> and sign in. Upload an export bundle and the scan
runs on upload.

The deployment is **one application container and one PostgreSQL**. If it ever
needs a third service, the main advantage over connected competitors — which
want a console VM plus sensor VMs — is gone.

What the console adds over the CLI: findings that persist across uploads so you
can see what got fixed and what came back, an attack-path graph, a dashboard
with the financial figure on it, role-based access, an audit log, and a
read-only MCP interface for asking questions of the data.

**It says what it takes to close a scenario, not just what is worst.** A single
finding almost never severs a whole scenario — a real estate has four to six
independent routes to each — so the console computes the smallest *set* of
fixes that leaves one with no route at all, and prices that. On the bundled
sample: three fixes close the $13.2M ransomware scenario, two close the payment
fraud one, twenty-one close all five. The answer is exact rather than
approximate, and a scenario with a route no fix can sever is reported as
unclosable rather than handed a plan that ignores it.

**The worklist is ordered by money, not by severity.** The graph knows which
findings sit on the one hop that severs a path; the FAIR model knows what the
scenario at the end of that path is worth. Join them and the first line reads
*"close this and $4M of annual exposure has no route left"*. A figure appears
only where the fix closes **every** open path to a scenario — anywhere else the
row says how many of how many routes it cuts and shows no number, because a
fraction of a scenario's exposure is a quantity this model does not compute.

---

## Reports

The HTML report is the working document. The PDF is the hand-over artefact. The
PowerPoint deck is for the steering committee. All three are generated by
hand-built engines, which is why the CLI needs no packages.

---

## Use it as a release gate

`--gate` makes the scanner exit non-zero when a change makes things worse, so it
can sit in a build pipeline. Three exit codes, and the third is the point:

| | |
|---|---|
| `0` | passed |
| `1` | blocked — this change makes things worse |
| `2` | **could not assess** — the exports were too thin to judge |

```bash
# Record where you are today
python sap_scanner.py --data-dir exports/ --gate --gate-write-baseline baseline.json

# Then enforce on every build
python sap_scanner.py --data-dir exports/ --gate --gate-baseline baseline.json
```

It judges the change, not the estate, so an old problem does not block a new
build. It never blocks on something the customer is not allowed to fix. And it
**never fails open** — if coverage got thinner than the baseline, or a check did
not run at all, the answer is "could not assess", never "pass".

That comparison is the reason the gate is usable. Real exports are always
incomplete somewhere, so a gate that blocked on any gap would answer "could not
assess" forever and get switched off. Gaps the baseline recorded are reported and
let through; a check that could see less than it could last time stops the build
and is named.

---

## What it will not tell you

Most of the distinctive work in this product is in refusing to say things it
cannot support. A clean result and an unasked question look identical on a page.

- **No money figure without your figures.** The bundled loss catalogue describes
  an illustrative $1bn manufacturer. Printing that company's losses under your
  name would be a fabrication, so without your own numbers the report prices
  nothing.
- **No annual figure without your attack rate.** Annual loss is frequency times
  magnitude. Supply what a breach costs you and it prices the cost per event;
  supply how often SAP here is actually probed and it annualises. Half the
  calculation gets you half the answer, clearly labelled.
- **When the model and the customer disagree, the estate decides.** If the
  model expects more loss events than the organisation has seen, the report
  says which side is more likely to be wrong — from the logging and
  monitoring findings the scan already produced. With the Security Audit Log
  switched off it says the silence is a statement about the monitoring rather
  than about the attacker; with logging in good order it says the modelled
  frequency is the more likely error. Neither verdict moves the number: it is
  a disclosure, not a correction.
- **"How many incidents have you had?" cannot set the frequency.** An
  organisation with no logging answers zero, truthfully, and would be told it
  was the safest — by a tool whose own findings say its logging is off.
- **CVSS scores appear on CVEs only**, taken from SAP's own record. A
  configuration finding has no attack vector to describe, so none is invented.
- **Not every finding maps to OWASP**, and the ones that do not are named. A
  scanner whose every check mapped to the Top 10 would be a web-application
  scanner or would be overstating itself.
- **Custom-code findings are graded** `confirmed`, `tentative` or
  `pattern-only`, depending on whether data flow was actually traced.
- **What "compliant" means depends on the deployment.** Several settings SAP
  itself mandates in ECS are findings on classic on-premise. `--deployment-mode`
  decides which rules apply; a RISE scanner that flags SAP's own baseline is
  confidently wrong on every compliant system.
- **In RISE you often cannot fix it yourself.** Those findings come with the
  service request already written — the system, the setting, the current and
  required values and the SAP note they come from — rather than an instruction
  to make a change the contract does not let you make. One request per system
  rather than one per setting, because forty-seven tickets is not a remediation
  plan. Where the export did not carry a value, the draft asks SAP to confirm
  it instead of stating a change with a blank in it.
- **There is no industry multiplier.** `--crq-industry` sets a label on the
  report and scales nothing.

---

## Requirements

| | Needs |
|---|---|
| **CLI** | Python 3.8+ and nothing else. A CI job walks the source to keep it that way. |
| **Server** | Python 3.12, PostgreSQL 16, and the four packages in `requirements.txt`. `DB_DSN` and `SESSION_SECRET` have no defaults. |
| **Building the console** | Node 22 and npm, at build time only. `docker compose up --build` does it for you. |
| **Tests** | `pytest`, the runtime packages, and `httpx`. |

Starting the server without building the console is a defined state, not a
crash: the API works and console URLs answer 503 with instructions.

---

## Testing

About 4,500 tests, plus vitest tests over the console. They run every module
against the bundled `sample_data`, which is crafted to trigger each check, and
exercise the whole pipeline. No SAP system needed.

```bash
python -m pip install -r requirements.txt -r requirements-dev.txt httpx
python -m pytest -q
```

Some suites need a real PostgreSQL and skip without `DB_DSN`. The mitigation
journey is written in SQL, so a mocked database would prove the Python is
self-consistent and prove nothing about whether it works:

```bash
docker run -d --name sapsec-test-db -e POSTGRES_USER=sapsec -e POSTGRES_PASSWORD=sapsec \
    -e POSTGRES_DB=sapsec -p 55433:5432 postgres:16
DB_DSN=postgresql://sapsec:sapsec@localhost:55433/sapsec \
SESSION_SECRET=$(python -c "import secrets;print(secrets.token_urlsafe(48))") \
    python -m pytest -q
```

---

## More documentation

| | |
|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | How it all works, in plain language |
| [CHECKS_REFERENCE.md](docs/CHECKS_REFERENCE.md) | Every check, generated from the code |
| [EXPORT_GUIDE.md](docs/EXPORT_GUIDE.md) | How to produce the exports |
| [EXPORT_SOURCES.md](docs/EXPORT_SOURCES.md) | The full source catalogue |
| [RELEASE_GATE.md](docs/RELEASE_GATE.md) | Adopting the gate without blocking everyone |
| [SOD_REFERENCE.md](docs/SOD_REFERENCE.md) | The segregation-of-duties ruleset |
| [RISE_SECURITY_MODEL.md](docs/RISE_SECURITY_MODEL.md) | Who is responsible for what under RISE |
| [DECISIONS.md](docs/DECISIONS.md) | Choices made, and why |
| [PIVOT_PLAN.md](docs/PIVOT_PLAN.md) | Where this is going |

---

## Licence

MIT. Read it, run it, fork it, change it, self-host it, sell it. No permission
needed. The notice lives once, in [LICENSE](LICENSE) — there are no per-file
headers to preserve.

One carve-out that is not ours to waive:
`data/sap_baseline_requirements.json` derives from SAP's own published policies
under Apache-2.0, Copyright (c) 2020 SAP SE. That attribution stays. See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Contributions welcome — [CONTRIBUTING.md](CONTRIBUTING.md). Reporting a
vulnerability — [SECURITY.md](SECURITY.md).

---

## Disclaimer

This is an auditing tool. It reports what your exports show. It is not a
substitute for a penetration test, a formal audit, or SAP's own support
channels, and a clean report is not a guarantee that a system is secure. Run it
only against systems you are authorised to assess.
