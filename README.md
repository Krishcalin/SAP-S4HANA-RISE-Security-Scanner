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
  <img src="https://img.shields.io/badge/checks-819%20in%2038%20modules-red?style=flat-square" alt="819 checks in 38 modules"/>
  <img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="MIT licensed"/>
</p>

---

## The SAP Security Tool

MonitorRisk checks how well the security controls in an SAP estate are actually
holding — RISE private or public cloud, classic on-premise, ECC or BTP.

You export configuration out of your SAP systems as CSV and JSON files. It reads
those files and tells you what is wrong, how bad it is, who is allowed to fix it,
what the fix is, and what the problem might cost you.

Nothing is installed in SAP, no RFC user is created, and nothing is ever written
back. That is a deliberate choice rather than a limitation: under a RISE contract
a third-party ABAP add-on is an excluded task needing its own SKU and a long
evaluation, and a folder of exports needs none of that.

If exporting by hand is a nuisance, an optional collector can fetch the files for
you from a system you authorise. It is read-only, you run it deliberately as a
separate command, and the scanner itself still connects to nothing.

It is open source, MIT licensed, and built as a client-server application in
Python, FastAPI, React and PostgreSQL — though the command line needs none of
that.

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

**819 checks across 38 modules.** Every one is listed, with what it reads and
which SAP baseline requirement it answers, in
**[docs/CHECKS_REFERENCE.md](docs/CHECKS_REFERENCE.md)** — a file generated from
the code, so it cannot drift from what actually runs.

The areas covered:

- **Users and authorisations** — who has what, including permission-level
  segregation of duties against a ruleset of 99 conflicting-duty rules
- **Profile parameters** — every one of the 92 parameters SAP makes mandatory
  for Enterprise Cloud Services in Note 3250501
- **HANA database** — privileges, auditing, encryption, parameters
- **BTP and cloud** — Cloud Connector, destinations, IAS, entitlements, CPI
- **Interfaces** — RFC, web services, IDoc, gateway ACLs, OAuth clients
- **Custom ABAP code** — 135 static-analysis rules with taint tracking
- **Financial controls** — the SOX-relevant configuration in FI
- **Patching, logging, encryption, transports, backup and recovery**

Findings are mapped to ISO 27001, NIST 800-53, NIST CSF, CIS Controls, DORA,
TISAX, SOC 2, SOX, GDPR and **NERC CIP** — the last for a utility, cited at
standard and requirement (`CIP-007 R2`) rather than at part level, because a
part-level citation nobody has verified line by line is the coverage that
collapses on the first auditor question. An SAP system is very often not a BES
Cyber System at all; that determination is CIP-002's, and the customer's.

---

## What you feed it

139 different export sources, all of them files a Basis or security team can
produce with standard SAP transactions.

- **[docs/EXPORT_GUIDE.md](docs/EXPORT_GUIDE.md)** — how to produce each one
- **[docs/EXPORT_SOURCES.md](docs/EXPORT_SOURCES.md)** — the full catalogue

You do not need all of them. Give it what you have; it reports what it could
not assess rather than quietly scoring you on a subset.

It also tells you which missing export is worth producing next, because "supplied
119 of 139 sources" is true and useless on its own. Each scan ends with something
you can act on:

```
next: Supply btp_security_settings, audit_config, client_settings —
      16 more check(s) would run. The other 15 missing source(s) would add 17 more.
```

Sources your contract does not let you produce are named separately rather than
recommended, so nobody spends a week chasing a file RISE will never give them.

The console shows the same ranking on the run page, as a table.

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

**It says why a finding ranks where it does.** The tier is not a bare badge — the
finding page lists the evidence behind it and what each piece was worth, so "this
is P1" can be argued with. One of those pieces is whether anyone is actually
using the account: a logon export turns "SAP_ALL is assigned" into "SAP_ALL is
assigned to someone who signed in this week", which is a different problem from
the same privilege sitting on a dormant account. Evidence of use raises priority
and never lowers it — a thirty-day window is one break-glass procedure away from
being wrong, and a firefighter account is dormant by design.

**It writes the change, where the change is exactly known.** A profile parameter
comes with the line to put in RZ10 and the current value to roll back to; a HANA
grant comes with the `REVOKE` and the `GRANT` that undoes it. Per system, those
are bundled into one artefact for one change window rather than one fragment per
finding. It refuses more than it writes — nothing for a setting SAP owns under
the contract, nothing where the baseline states a rule rather than a value,
nothing for a grant whose object the export does not identify — and it says how
many findings it could not write a change for, so 39 changes are never mistaken
for a complete remedy.

**It says whether anybody outside can reach the vulnerable line.** A code scanner
reads ABAP and tells you a statement is dangerous. It cannot tell you who can get
to it, because it sees the code and not the estate around it. This holds both. If
you add two optional columns to exports you already produce — the handler class
on an ICF node, the implementation class behind an OData service — a finding
comes back with the route:

```
/sap/bc/z_vendor_report          ICF node, active, no authentication
  → ZCL_TREE_CALLER              the class serving it
     → drive                     zcl_tree_caller.clas.abap:20
        → by_public_tainted      zcl_tree_worker.clas.abap:35
           → SELECT … WHERE (iv_where)
```

That is a different finding from the same statement in a class only a nightly job
touches, and it ranks accordingly. Without the columns it says so and claims
nothing: no route found is reported as unknown, never as safe, because a dynamic
call resolves to no edge and the endpoint list is only as complete as what you
exported.

**It says which export to go and get next.** The run page lists what each module
could not read, and then orders it. On one partial upload, supplying the user
list on its own would let 21 more checks run and `saprouttab` would let one — so
you know which trip to Basis is worth making. Two numbers are kept apart: what a
file unlocks by itself, and what still waits on a second file that is also
missing. Adding them together would promise for one upload what takes two.
Sources your contract does not let you produce are listed as the reason a gap
exists, not as a job for someone.

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

About 5,600 tests, plus vitest tests over the console. They run every module
against the bundled `sample_data` and exercise the whole pipeline. No SAP system
needed.

`sample_data` is a realistic estate, not a fixture built to trip every check, and
plenty of the catalogue stays correctly silent on it. That matters, because a
check that is correctly silent and a check that could never fire look identical
unless somebody measures. So the suite records which check ids actually produce a
finding anywhere in it, and publishes the count in
[docs/CHECK_FIRING.md](docs/CHECK_FIRING.md) — currently 819 of 819.

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
