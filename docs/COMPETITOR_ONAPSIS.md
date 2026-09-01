# Onapsis — what they ship that we do not, measured

Researched 2026-09-01 against primary sources (vendor release blogs, datasheets,
press releases). Claims are labelled `verified` (read on a vendor page, with the
capability phrase quoted), `asserted` (vendor marketing with nothing behind it)
or `inferred` (reasoning, with the evidence named). Absence is written as "no
public evidence across N named sources", never as "they do not have it".

**This supersedes §2 of [`COMPETITIVE_ANALYSIS.md`](COMPETITIVE_ANALYSIS.md)**,
which anonymised Onapsis as "the platform incumbent" and was written 2026-08-05.
Two of its findings about **us** are now out of date, and are corrected in §3.

**Read with** [`COMPETITOR_PATHLOCK.md`](COMPETITOR_PATHLOCK.md) — Pathlock, not
Onapsis, is the vendor that ships financial risk quantification as a line item.

---

## 1. What Onapsis shipped since the last dossier

`verified` — Onapsis publishes quarterly release notes, which is the most
enumerable source any of these vendors offers.

| Release | Capability | Module |
|---|---|---|
| Q1 2026 | Granular user roles; segmented visibility restricting users to specific SAP assets or business units | Assess |
| Q1 2026 | Editable baseline policies for custom vulnerability scans | Assess |
| Q1 2026 | **Rapid Controls** for over-privileged users — deploy a compensating monitoring control on a privileged account with one click | Assess + Defend |
| Q1 2026 | Event tuning — mute lower-priority activity (e.g. known-safe activity on dev systems) | Defend |
| Q1 2026 | **SAP cTMS integration** — scans ABAP Cloud transports in the import queue and blocks critical findings before deployment | Control |
| Q2 2026 | Rapid Controls phase 3 — extends one-click compensating controls to **misconfigurations** | Assess + Defend |
| Q2 2026 | SAP Web Dispatcher monitoring for unauthorised access and lateral entry, in real time | Defend |
| Q2 2026 | Behavioural anomaly trending — "a high-level view of shifting activity patterns" exposing configuration drift | Defend |
| Q2 2026 | Automated workflow notifications — approvers alerted by email/mobile on new TMS requests | Control |
| Q2 2026 | Long-term performance reporting — multi-month remediation speed, backlog trajectory, risk exposure trend | Security Advisor |
| Q2 2026 | Findings API — export Git repository scan data to external analytics | Security Advisor |
| Mar 2026 | **Agentic Gateway** — an MCP server exposing SAP risk data to Copilot, Claude, Gemini, ChatGPT | Platform |

**The Agentic Gateway is still `preview` with no GA date**, six months after
announcement — `verified` on the press release, which invites customers to
demonstrations rather than to use it.

---

## 2. The gaps worth closing, in order

Each is measured against what we actually ship today, not against memory.

### 2.1 Note validation that checks the manual step — the strongest opportunity

Onapsis's flagship patch claim is the **SAP Notes Command Center**, and the part
they sell hardest is that it "automatically validates that all patches —
including manual configurations and workarounds — were applied correctly"
(`verified`). They quote a customer reducing patch-validation time 65%
(`asserted` — a vendor case study).

**Why this is ours to take rather than theirs.** A great many SAP Security Notes
are not only a kernel or support-package delivery: they require a profile
parameter set, an authorisation object restricted, a service disabled. SNOTE
records that the *note* was implemented. It cannot record that the *manual step*
was carried out. So "applied" and "effective" are different claims, and only one
of them is in the export.

We already run 500+ configuration checks. We are therefore in an unusually good
position to answer the second question — and it is exactly the shape of every
other distinction this product makes: *implemented* is not *effective*, the way
*reached the end* is not *understood* and *no findings* is not *clean*.

**Today** `modules/sap_hotnews.py` compares applied notes against a curated
catalogue of 43 high-impact notes and is scrupulous about what it cannot judge
(`HOTNEWS-005` for adjacent components, `HOTNEWS-010` for notes it cannot assess
against installed releases). What it does **not** do is link a note to the
configuration check that proves its manual step landed.

**Build:** a `manual_step` field on catalogue entries naming the check id that
verifies it, and a finding for *note recorded as applied, manual step not
carried out*. Even a dozen notes wired this way is a claim no offline competitor
makes.

### 2.2 State the baseline claim in the unit a buyer compares

Onapsis publishes **214 in-scope SAP Security Baseline control points** — 69
Critical, 92 Standard, 53 Extended (`verified`). It is the yardstick they chose,
and a buyer will hold both products to it.

⚠️ **`COMPETITIVE_ANALYSIS.md` §2.6 says "we currently make no baseline claim at
all". That is out of date.** We ship `data/sap_baseline_requirements.json`,
findings carry `baseline_req_id`, and `/api/requirements/{id}` has a screen
behind it.

Measured today: **38 requirement families — 18 Critical, 16 Standard, 3 Extended
— naming 104 control points between them.** Roughly half of Onapsis's in-scope
figure, weighted towards Critical, which is the right half to have first.

**Build:** publish the figure the way they do, in control points, with the tier
split — and generate it from the data file so it cannot drift, the way
`docs/CHECK_FIRING.md` already works. Cheap, and it converts an existing
strength into a comparable number.

### 2.3 Two compliance frameworks we do not map

We map SOX, GDPR, NIST CSF, NIST 800-53, ISO 27001, SOC 2 and CIS. Onapsis's
Comply packs add **NERC CIP** and **PCI DSS** (`verified` on the Assess
datasheet).

NERC CIP is the one to take. This product already carries OT and plant-floor
content, and a utility running SAP is precisely the buyer for whom CIP-003/-005
/-007 map onto exactly the parameter, patch and account checks we already run.

### 2.4 Compensating controls — the guidance, not the deployment

**Rapid Controls** is Onapsis's most repeated 2026 theme: one click deploys a
monitoring control for a finding you cannot fix today. The deployment half is
closed to us and should stay closed — it is a write path into SAP, which
`BUILD_ROADMAP.md` lists as a non-goal.

The *guidance* half is not closed, and it fits RISE unusually well: a customer
who cannot change the setting themselves is exactly the customer who needs to
know what to watch instead. We already draft the service request for those
findings (`server/servicerequest.py`); the natural companion is *"until SAP
applies this, monitor X"* — an audit-log filter, a specific `RAL` condition, a
role to review.

### 2.5 Customer-defined checks

Onapsis lets users "create custom policies" and define custom vulnerability
checks (`verified`). Our checks are Python modules; a customer cannot add one.
`baseline.json` tunes four thresholds — dormant days, max roles per user,
password age, internal host patterns — which is a real but much smaller thing.

`inferred`: a data-driven check format (a parameter, an expected value, a
severity, a citation) would cover a large fraction of what customers actually
want to add, without opening the door to arbitrary code in a security tool.

### 2.6 The queue that drains by hand

Onapsis ships ITSM ticket creation (`verified`). We queue notifications for new
CRITICALs and regressions and deliver them only when somebody runs
`python -m server.cli notify` on a cron they wrote themselves; `delivery_error`
is documented in `server/webhook.py` as "what an operator reads" and the only
reader is that module. This is a smaller gap than it looks — the webhook exists
— but the queue is invisible and unscheduled.

---

## 3. What not to fight, and why

| Theirs | Why we should not |
|---|---|
| **Defend** — real-time detection, 2,000+ rules, Web Dispatcher monitoring, behavioural anomaly trending | Needs an in-system agent and event-time execution. Already a declared non-goal; never imply an analogue |
| **Control** — 600+ ABAP test cases, TMS and cTMS transport blocking | Blocking a transport is a write path into SAP. An offline tool cannot do it, and should not claim to |
| **Peer benchmarking** ("against hundreds of organizations in the Onapsis community") | Structurally closed until we have a customer base. Benchmark against the SAP baseline and the customer's own history |
| **SAP Endorsed App / premium certification** | Not purchasable in a realistic timeframe. The counter is the true one: nothing to certify, because nothing is installed |
| **Multi-stack breadth** — BusinessObjects, Oracle EBS | BusinessObjects is a declared non-goal; Oracle EBS is a separate product in this workspace |

---

## 4. Where we are ahead, and the evidence

Stated as "no public evidence across N named sources", per the rule at the top.

- **Attack-path and choke-point analysis.** No public evidence across the Assess
  datasheet, the Q1 2026 and Q2 2026 release notes, the Agentic Gateway press
  release, and the integrator's GraphQL schema — **which exposes no relationship
  or edge entity at all**. Their published attack-chain work is threat research,
  not a customer-landscape view. We ship choke points, severing sets, and the
  smallest set of fixes that closes a scenario.
- **Financial risk quantification.** No public evidence across the same sources:
  no ALE, no loss exceedance, no Monte Carlo, no currency output. The dollar
  figures on their site are market context (downtime costs, exploit prices), not
  per-finding output. We ship FAIR with a calibrated frequency model and refuse
  to print a figure without the customer's own numbers.
- **MCP.** Theirs was announced March 2026 and remains preview with no GA date.
  Ours is in `server/mcp.py`, read-only by construction, and works.
- **Deployment.** Their console and each sensor want 8 cores and 16 GB, and even
  the SaaS option needs a customer-hosted connector inside the network
  (`verified`, quoted from the Assess datasheet). We are one compose file. If
  our deployment ever needs a third service we forfeit the only structural
  advantage we have.
- **An open catalogue.** They publish numbers and never a list.

---

## 5. Recommended order

1. **Note validation with the manual step** (§2.1) — their flagship claim, our
   existing strength, and nobody else offline can make it.
2. **Publish the baseline figure in control points** (§2.2) — hours of work, and
   it makes an existing strength comparable.
3. **NERC CIP mapping** (§2.3) — one framework, high relevance to the utility
   buyer this product already serves.
4. **Compensating-control guidance** (§2.4) — pairs with the service request
   that already exists.
5. **Customer-defined checks, data-driven** (§2.5) — the largest of these, and
   the one most likely to grow scope.

Sources: Onapsis Q1 2026 and Q2 2026 release blogs, the Assess and Defend
datasheets, the Agentic Gateway press release, and the SAP Notes Command Center
platform update — all fetched 2026-09-01.
