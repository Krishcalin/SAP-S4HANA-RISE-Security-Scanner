# Pathlock — the competitor that was not in the file

Researched 2026-08-29 by six parallel agents against primary sources. Claims are
labelled `verified` (read in a primary source, quoted), `asserted` (vendor
marketing with nothing behind it) or `inferred` (reasoning, with the evidence
named). Absence is written as "no public evidence across N named sources",
never as proof.

**Read this before `COMPETITIVE_ANALYSIS.md`.** That document analyses two
vendors, and Pathlock is neither of them. Three of its load-bearing claims do
not survive contact with this one.

---

## 1. What this research falsifies

### 1.1 "The monetary lane is open" — FALSE as a market statement

`COMPETITIVE_ANALYSIS.md` and `BUILD_ROADMAP.md` both say it:

> *"FAIR/monetary quantification is the cleanest open lane and we already have
> the engine."*
> *"The cleanest open lane — neither incumbent has any monetary output at all."*

That was true of the two vendors named. It is false of the market. Pathlock
ships **Risk Quantification** as a named CCM module, and SAP sells the OEM
edition itself:

> `verified` — *"Risk Quantification — Quantify the material impact of
> violations by analyzing 100% of transactions in real time, from purchase
> orders to invoices and payments."* — pathlock.com/products/continuous-controls-monitoring/
>
> `verified` — *"**Associate a dollar value with access risk violations** so you
> can prioritize remediation efforts"* — sap.com, Access Violation Management
>
> `verified` — *"Violation Management by Greenlight enables you to assess the
> **financial exposure** business processes and transactions have on the
> organization"* — help.sap.com, SAP Solution Extensions

**But the two numbers answer different questions, and that is the real finding.**

| | Pathlock Risk Quantification | Our FAIR engine |
|---|---|---|
| Method | Sums PO / invoice / payment values that **actually flowed** through a conflicted path | Monte Carlo over loss event frequency × magnitude → ALE |
| Nature | Deterministic, **realised** | Probabilistic, **expected** |
| Vocabulary | "financial exposure", "material impact" (SOX materiality) | ALE, value at risk |
| Requires | **Live transaction data** | Customer-supplied loss figures only |
| Answers | "How much money went through this hole?" | "What should we expect to lose?" |

`verified` — a sweep of pathlock.com's whole content index via its WordPress
REST API found **no product-page occurrence of "value at risk"**, and no
evidence anywhere of probability, frequency, confidence intervals or Monte
Carlo. Their quantification is a sum, not a forecast.

**Correct restatement:** the lane is occupied by a method that requires
continuous access to financial document flow — which a RISE customer on offline
exports cannot grant. Theirs is better *evidence*; ours is available without
live system access. Do not claim the lane is empty. Claim the two answers are
different and say which question we answer.

### 1.2 "RISE forbids ABAP-resident competitors" — FALSE

`verified` — *"SAP Integration and Certification Center (SAP ICC) has certified
that the integration software for Pathlock Native Cyber Security and GRC Suite
and Application Profiler are **SAP-certified for clean core with RISE with
SAP**"* — 21 May 2026, pathlock.com news + PRNewswire + SAPinsider.

And SAP's own FAQ for S/4HANA Cloud Private Edition:

> `verified` — *"I have **add-ons** to SAP S/4HANA and integrations with
> third-party software. Will they still work after I switch to SAP S/4HANA
> Cloud Private Edition? … **Yes, almost any software that currently works with
> SAP S/4HANA will continue to work**."*

SAP Readiness Check explicitly models "Certified Third-Party Software" against a
Private Edition target, citing SAP Note 2214409. **Certified partner add-ons are
an established, SAP-sanctioned path into RISE.** Any pitch built on "they cannot
do RISE" collapses the moment a customer reads the press release.

### 1.3 The wedge that survives, and it is better

Certification removes the **architectural** objection. It does not remove the
**operational** one. `inferred`, from SAP's ECS operating model plus 1.2:

In ECS, SAP controls the transport path and the customer cannot self-install. A
certified add-on in RISE still implies:

1. an SAP-approved add-on import via service request;
2. an SAP change window;
3. **upgrade-time gating — SUM blocks a conversion on an incompatible add-on**;
4. a three-way support triangle: customer / Pathlock / SAP.

A read-only, zero-footprint tool removes all four. That is the honest wedge.

Two facts sharpen it. `verified`: Pathlock's entire RISE presence is **one press
release** — no deployment page, no datasheet, no ECS installation guidance.
And KuppingerCole calls Pathlock Native **"(legacy)"** while it is precisely the
product SAP certified for RISE. That tension is unresolved.

---

## 2. There is no such thing as "Pathlock's architecture"

Pathlock is nine companies in two roll-ups that merged in 2022. The product is
four loosely-coupled pillars, and **the SAP collection mechanism differs by
line**. Any sentence of the form "Pathlock connects to SAP via X" is wrong
unless scoped.

| Line | Origin | Mechanism | Label |
|---|---|---|---|
| **Native / CAC** | SAST SOLUTIONS (akquinet) | **ABAP add-on inside SAP**, own namespace, via SAP change management | `verified` |
| **Greenlight AVM** | Greenlight, SAP OEM | ABAP add-on via SPAM/PAT (components `GLT`, `GLTGRC`) + a NetWeaver **Java** component | `verified` |
| **CSI Authorization Auditor** | CSI tools | **External .NET**, scheduled snapshots into its own DB — no ABAP at all | `verified` |
| **Pathlock Cloud / Nexus** | Greenlight/Appsian | SaaS connectors; **wire protocol never published anywhere** | `verified` (as a gap) |

> `verified` — *"Pathlock SAST ist als **mandantenfähiges SAP Add-on**
> konzipiert und **vollständig in ABAP entwickelt** … **Betrieb in einem eigenen
> Namensraum**"* — rz10.de (independent German technical review)
>
> `verified` — *"They are provided as part of the **Pathlock Native Platform
> (legacy)**, which are the SAP-focused components utilizing an **ABAP-native
> architecture** … delivered on-premises, using SAP-native interfaces."*
> — KuppingerCole Executive View 81246

`inferred`, high confidence: their Transport Control module *blocks transports at
TMS release* and Code Scanning *extends SAP ATC*. Neither is achievable from
outside the ABAP stack.

**The namespace exists but its string is published nowhere.** `GLT`/`GLTGRC` are
Greenlight **software components**, not namespaces — never render them as
`/GLT/`. `/SAST/` is plausible and **unconfirmed**; the search is polluted
because `SAST` is both the generic acronym for static analysis and a real SAP
transaction code. Do not invent one.

`verified`, and the hardest evidence in the study — the actual SAST job ads,
recovered from archive snapshots and posted under Pathlock ownership:

> *"**Produktentwicklung in ABAP** und ggf. UI5 für unsere Software"* ·
> *"Mehrjährige Berufserfahrung in der **Software-Produktentwicklung mit SAP
> ABAP-OO**"* · *"Kenntnisse in der **ALV- und Dialogprogrammierung**"*
> — *SAP ABAP / Fiori Entwickler (m/w/d) Inhouse*, Hamburg/Dortmund, 2023,
> footer: *"Pathlock Deutschland c/o akquinet enterprise solutions GmbH"*

Those are **product developers, not consultants**. `inferred`: the ABAP product
engineering centre of gravity has since moved to India — a `Product Developer -
SAP ABAP` role in Bangalore/Chandigarh/Pune (2023), while the German site's
developer roles vanished by mid-2024 and today's careers page carries no
listings at all. The cloud half of the stack is **.NET and Java**, not ABAP.

⚠️ **`mandantenfähig` means SAP client-capable, not SaaS multi-tenant.** Do not
conflate the two when reading their German material.

`verified`, and it sharpens §1.3: **"RISE with SAP" and "Clean Core" return zero
hits across Pathlock's own SAST product pages** — technology/sap,
cybersecurity-application-controls, and use-cases/erp-and-cloud-migrations. The
certification is real and dated May 2026; the product material has not caught up
with it.

### The marketing line, read precisely

> `verified` — *"Pathlock delivers Identity Governance, GRC and Cybersecurity
> that **never touch your SAP Core**"*

This is true in SAP's clean-core sense — a registered-namespace add-on is not a
modification — and it **enumerates IGA, GRC and Cybersecurity while omitting
Dynamic Access Control**, which is by design an in-system ABAP add-on. It is
precise, not sloppy. It also reads to a buyer as "no code in my system", which
is a different claim. That gap is our opening, and we must state it accurately
or we lose the argument to someone who has read the page.

`verified`, from their own UK G-Cloud filing: **"Requires a local server to
deploy a software agent on."** Pathlock Cloud is not fully agentless either.

---

## 3. The SoD engine — they are ahead, and pretending otherwise is useless

### Granularity: parity, not differentiation

The clearest statement found anywhere is from their own product demo, pulled
from the Wistia caption API:

> `verified` — *"Fine grain means that we go below the top level of the
> application's security permission structure and down multiple levels. For
> example, **in SAP, this means building rule sets at the transaction
> authorization object, field, and field value level, not at the role level.**
> For Oracle, this is building rule sets for menus and functions and not at the
> responsibility level."*

Independently corroborated: *"Fine-grained permissions are supported down to the
authorization objects and the field level"* (KuppingerCole EV 81239). Their own
brief describes a rule distinguishing view-only from change — `ACTVT 03` vs `02`.

**Permission-level analysis is the entry ticket, not our differentiator.**

### Ruleset breadth: they are 4–6× larger

| Ruleset | Published count | Ours |
|---|---|---|
| SAP ECC | **over 207 SoD** + ~20 sensitive access | — |
| SAP S/4HANA | **over 137 SoD** + ~20 sensitive access | **36 risks** (34 SoD + 2 critical) |
| S/4HANA Public Cloud | over 80 SoD + over 119 sensitive access | — |
| Oracle EBS | over 200 risks | n/a |
| Oracle ERP Cloud | over 100 SoD + over 220 sensitive access | n/a |
| Dynamics 365 F&O | over 100 SoD + 30+ sensitive access | n/a |

All `verified` from pathlock.com/integrations/ pages. Ours: 36 risks, 70
functions, 131 permission predicates, 126 tcodes, 62 authorization objects,
10 processes.

### The cross-application story has a measured limit

`verified` — the risk data model, from the same demo transcript: *"If this was a
cross application risk, this first group would be comprised of the detailed
activities of the first application and the second group would be comprised of
the activities of the second application."* One risk = N function groups, each
bound to one application, each holding that application's native objects.

**But `verified` by scraping all 71 connector pages: 48 advertise SoD analysis
and only 9 advertise fine-grained permission extraction** — SAP ERP/S4, S/4
Public Cloud, Ariba, Business One, SuccessFactors, Oracle EBS, Oracle Fusion,
PeopleSoft, Dynamics F&O. Workday, Salesforce, NetSuite, Coupa and JD Edwards do
not. Independently spot-checked and confirmed.

`inferred`: a cross-app risk pairing SAP (object+field) with Workday (security
group) is only as precise as its weakest side. "One ruleset enforced everywhere"
is true of the *rule*, not the *resolution* — the same false-positive problem
they criticise IGA vendors for, reappearing at the edge of their connector
estate. KuppingerCole says the quiet part: *"For non-SAP solutions, the
long-standing experience regarding best practice role models, critical access
rule sets, and SoD role sets is still lacking at most vendors."*

### "CAN DO" vs "DID DO" is their organising concept

Not a feature — the spine. Usage data feeds SoD prioritisation, simulation,
remediation and access reviews, and drives named engines: **Conflict Resolver,
RoleAdvisor, RoleReplacer, RoleSplitter, Activity Remover**, each grounded in
actual usage, each able to write the fix back to the ERP.

`verified`, Protiviti (independent): *"AVM-RA provides the ability to automate
the 'did-do' analysis … The recent updates to AVM have provided the capability
to mine target applications for SoD transactions for all users … This can allow
the AVM results to **test SoD rulesets for gaps or validate GRC reporting for
false negatives**."*

That last clause is a product that audits somebody else's ruleset. So is the
acquired CSI Authorization Auditor: *"Because transaction code access and
authorization access is checked separately, this module can **verify the
completeness of SAP GRC rule sets**."*

### Mitigating controls carry a full lifecycle

`verified`, from the certifications demo: the mitigation record shows *"the date,
the approvers, reasons, and **mitigated until** date, as well as the source and
any references"*, and risk/control revalidation is a first-class campaign type.

---

## 4. Commercial — the price list contradicts the pitch

Pathlock publishes no pricing. Its own UK entity (Grey Monarch Ltd) filed an
itemised list to the **G-Cloud 14 Digital Marketplace**. `verified`.

Licensing metric: *"the number of systems that you have connected … and the
number of users within those systems."*

**AAG / CCM for SAP — per month, by user band**

| | ≤1,000 | ≤3,000 | ≤5,000 | ≤10,000 |
|---|---|---|---|---|
| AAG Core (1st system incl.) | £3,000 | £5,500 | £7,000 | £10,000 |
| CCM for SAP | £3,000 | £5,500 | £7,000 | £10,000 |
| **each** additional Tier-1 connector | £1,500 | £2,750 | £3,500 | £5,000 |
| **each** additional Tier-2 connector | £750 | £1,375 | £1,750 | £2,500 |

Onboarding **£5,000 per instance per product**. 12-month minimum. Support
08:00–18:00 Mon–Fri; **out-of-hours £10/day extra**. Offboarding is **CSV or
Excel export only**.

`inferred` — **the structure is the story.** Cost scales with connector count,
which is exactly the multi-application breadth they market on. A 5,000-user
estate wanting SAP + Oracle + Entra + AD reaches £7,000 + (3 × £3,500) =
**£17,500/month ≈ £210k/year for AAG alone**, before CCM, before CAC, before
onboarding. The pitch and the price list pull in opposite directions.

Separately published list tiers: Free $0 · Essential **$7,500/yr** ·
Professional **$15,000/yr** · Advanced **$30,000/yr**.

---

## 5. Their evidence base is thinner than their position

| Source | Rating | Reviews |
|---|---|---|
| Gartner Peer Insights (all markets) | 4.6 | **123** across 6 markets |
| G2 | 4.5 | **12** |
| TrustRadius | 8.6/10 | 7 ratings, **1 displayed** (incentivised, 1–10 employees) |
| Capterra / PeerSpot / GetApp / SourceForge | — | **0 each** |

`inferred`, three readings: **34 of 123 Gartner reviews (28%) are for
Appsian-heritage products**, not Pathlock Cloud; the 4.6 composite is lifted by
six 1–3-review 5.0 ratings in categories like *Hybrid Mesh Firewall*; and 123
reviews against a claimed 1,400 customers is thin.

**The customer count is not citable.** `verified`, all live: 1,200 (May 2022) →
1,400 (Sept 2022) → 1,400 (Jan 2026) — and **today two live pages say "1,300+"
and "1,400+" simultaneously.** It has not moved in over three years.

**No public evidence, across 14 named review sources, on the two things that
matter most in an SoD tool: ruleset quality / false-positive rates, and
performance at scale.** Their product documentation is entirely customer-gated
(GitBook behind email or Okta SSO; 36 doc URLs located, none readable), so
nobody outside their customer base can verify the engine.

### The ratings are vendor-solicited; the dislikes are the reliable part

`verified` — 7 of 8 Gartner review records carry `reviewIncentiveCode: 2`, and
the page's own strings expose vendor-controlled campaigns: *"**The vendor has
opted to not incentivize reviewers** of companies less than $50M in revenue."*
Two of the eight share a date. `inferred`: treat 4.5–4.7 as soft. The free-text
dislikes are the evidence.

One reviewer disowns their own rating's subject:

> `verified` — *"**This belongs rather to the SAST SUITE.** Pathlock Suite will
> follow soon in our S4 environment, means most comments refer to an older
> product version."* — 4★, Feb 2025, Manager Basis Solutions, manufacturing

And the acquired **Appsian line is rated higher (4.7, n=21) than the Pathlock
flagship (4.5, n=65)** — with an ERP access product filed under *Hybrid Mesh
Firewall*. Three brand identities still transacting separately in Gartner's
catalogue four years after the merger.

### The sharpest single finding: they sell SAP IDM replacement, and the IDM connector reportedly does not work

`verified` — two independent reviewers, different roles, industries and revenue
bands, same defect:

> *"**Connection to SAP IDM not feasible**"* — 3★, Feb 2025, Senior Consultant
> Information Security, retail, $1–3B
>
> *"Since the implementation, the **direct SAP IDM connection is unfortunately
> not working. It seems that there is no current documentation available.**"*
> — 5★, Feb 2025, IT Security & Risk associate, consumer goods, $10–30B

`verified` — meanwhile **SAP IDM end-of-life migration is an explicit Pathlock
go-to-market motion**, with its own campaign page and blog, positioning Pathlock
Cloud as the migration target.

`inferred`: this is the most checkable weakness found in the entire study. It is
a named capability, marketed as a campaign, contradicted by two of the eight
readable customer reviews. Anyone evaluating them should demand a reference
running that connector in production.

Other verified themes (n=8 reviews read in full): initial setup complex (2),
documentation split (1 neg / 1 pos), roadmap opacity and ineffective escalation
(1), legacy SAP GUI look-and-feel in acquired modules (1), recurring upgrade
cost (1). Support is genuinely **split** — positive on the Appsian/PeopleSoft
side, negative on the SAP side.

> `verified` — *"Lack of transparency in product roadmap … Lack of timely issue
> resolution and support from Vendor … Escalation Matrix not effective most of
> the times."* — 3★, Jul 2026, IT Manager, healthcare, $3–10B

**A quote we deliberately do not use.** A researcher surfaced a damaging Reddit
comment ("I would personally stay away from them"). Three checks failed: the
permalink resolved to a different comment by a different author, the account
404s, and a search returned nothing. It came from an archive API that now blocks
agents. It is excluded. If it resurfaces in anyone's notes, it is unverified.

`verified`: **brand fragmentation is live four years on** — sast-solutions.com,
csi-tools.com, appsiansecurity.com and greymonarch.com all resolve as separate
maintained sites. csi-tools.com's own nav reads *"Pathlock Cloud: The Successor
of CSI tools"* — that customer base faces a forced migration with no published
EOL date. CEO changed January 2026 with no departure statement.

---

## 6. Analyst standing — read the tier, not the logo

| Body | Placement |
|---|---|
| KuppingerCole LC81035 SAP Access Control | **Overall Leader** |
| KuppingerCole LC81036 Business Application Risk | **Overall Leader** |
| KuppingerCole LC81005 Identity & Access Governance | **Overall Leader** |
| KuppingerCole LC80864 **pure IGA** | Innovation/Market Leader — **not Overall** |
| Gartner Market Guide for IGA (Oct 2025) | **Representative Vendor** — inclusion, not a rating |
| Gartner Market Guide for SAM Tools (Jan 2026) | **Representative Vendor** |
| Gartner Hype Cycle for Cyber-Risk Mgmt 2025 | **Sample Vendor** |

`inferred`, load-bearing: **Pathlock has no Gartner Magic Quadrant placement.**
"Gartner-recognized" here means a list, not an assessment. Their real credential
is KuppingerCole, where it is genuine and recent.

No public evidence of any **Forrester Wave** naming Pathlock, across ten named
sources — blocked sources and an exhausted search budget, not proof.

---

## 7. Where this leaves the competitive map

**Onapsis and SecurityBridge are not Pathlock's peers.**
`verified`: SecurityBridge has **zero occurrences of "segregation of duties" or
"SoD"** across its product line. Onapsis has no SoD, access-request,
certification or role-design product, is only "Vendor to Watch" in
KuppingerCole's SAP compass, and is **absent entirely** from the
cross-application one.

**The overlap is asymmetric and runs against Onapsis.** Pathlock sells SAP
vulnerability scanning (4,000+ checks), threat detection (1,500+ signatures) and
code/transport scanning as *priced line items* — into Onapsis's category.
Onapsis does not sell into Pathlock's.

**Saviynt is Pathlock's most direct functional competitor**, matching or beating
it in all four KuppingerCole compasses.

`verified`, from enumerating their full 1,709-URL sitemap: **Pathlock publishes
comparison content against exactly one competitor family — SAP.** Zero pages
named against Onapsis, SecurityBridge, Saviynt, Fastpath, Soterion or Xiting.
Their public competitive strategy is displacement of SAP's own stack.

### SAP GRC Access Control is not end-of-life, and Pathlock says so honestly

`verified`, SAP's own community blog citing SAP Note 3326989: mainstream
maintenance for Access Control 12.0 **to end-2027, extended to 2030**. SAP is
publicly rebutting competitor FUD: *"Let's set the record straight: SAP Access
Control and GRC solutions for SAP are **NOT end-of-life**!"*

**Pathlock's own content on this is accurate.** It states the dates correctly,
never claims EOL, and credits SAP: *"For organizations whose critical processes
live almost entirely inside SAP … this is a reasonable path."* The FUD comes
from third-party SEO sites, not from them. Do not repeat the EOL claim.

Their sharpest true argument, which we should expect to meet:

> `verified` — *"SAP GRC for HANA modernizes the technology stack, not the
> governance architecture. **SoD analysis stops at the application boundary.**"*

---

## 8. What we could not establish

1. The ABAP **namespace string** — confirmed to exist, published nowhere.
2. The **wire protocol** between Pathlock Cloud and on-prem SAP. Never stated.
   Notably their Solution Architect job ad lists "REST, DB, LDAP" and never
   mentions RFC or JCo.
3. **Required SAP connection-user privileges.** The AVM Security Guide was
   retrieved in full and grepped for `S_RFC`, `S_TABU_DIS`, `S_DEVELOP`,
   `SAP_ALL` — zero hits. No delivered PFCG role name found anywhere.
4. **Data residency, hosting region, sub-processors, SOC 2 / ISO 27001.** The
   Trust Center is a Vanta-hosted JS shell serving no readable content. This is
   a first-order procurement question and is publicly unanswered.
5. **Any ruleset quality or scale benchmark** (§5).
6. Whether **"the only solution endorsed by SAP"** is true. It is a *different,
   lower* badge than the SAP Endorsed App tier Onapsis claims exclusivity in.
   Do not conflate or repeat either exclusivity claim.
7. Whether **Pathlock Native is being sunset** — KuppingerCole calls it
   "(legacy)"; SAP certified it for RISE in May 2026. Unresolved.
8. Company revenue, headcount and valuation. Only disclaimed estimates exist,
   and they contradict the documented $200M raise.

---

## 9. Positioning consequences

1. **Rewrite the monetary claim.** Not "the lane is open" — "we answer the
   forward-looking question without live transaction access; they answer the
   backward-looking one and need it."
2. **Delete any RISE-forbids-add-ons argument.** Replace with the four
   operational frictions in §1.3, which are true and checkable.
3. **Stop treating permission-level SoD as a differentiator.** It is table
   stakes. But do **not** answer 36-against-207 by racing on breadth — see
   [`SOD_REFERENCE.md`](SOD_REFERENCE.md) §1, which found the better answer:

   * **SAP's own documented bias is to OVER-report.** `verified`, AC 12.0
     §8.2.1.1: *"From a control perspective, it is much better to over-report
     (causing false positives) rather than under-report (causing false
     negatives)."* Pathlock's stated differentiator is reducing false
     positives. **They are competing on the axis SAP explicitly warns against
     optimising.** The defensible claim is precision *with* recall — suppress a
     conflict only when the engine can name the org field and value that makes
     execution impossible, and print that reason on the row.
   * **Ruleset COVERAGE is measurable and nobody publishes it.** SAP ships
     three reports that measure what a ruleset cannot see — actions in roles
     but not in rules, permissions in roles but not in rules, and embedded
     transaction calls in custom programs. A conflict report is only as
     trustworthy as the fraction of the estate its ruleset can see. Computing
     that fraction from data we already parse (`AGR_1251`, `role_auth_values`,
     `custom_code_scan`) and printing it beside every result is available to us
     now, and **no vendor publishes a coverage number, including Pathlock**
     (§5: no public evidence on ruleset quality or false-positive rates across
     14 named sources).
   * **Ruleset validation is a gap in published guidance.** AS 1105.10 obliges
     testing the query logic; PCAOB SAPA 11 names failure to test it as an
     inspection finding; AS 2201 ¶.B30 forbids benchmarking it away. The SoD
     ruleset *is* that query logic — and no source describes how anyone
     validates one. A rulebook that carries its own evidence is a product
     nobody else is selling.
4. **The offline-export model remains genuinely differentiated**, but on
   operational grounds: no transport, no add-on, no upgrade gating, no support
   triangle. Not on "they cannot do it".
5. **Their weakest flank is evidence, not capability**: gated documentation, a
   thin review corpus, no published false-positive or scale data, and an
   unciteable customer count. A product that publishes its ruleset, its
   provenance and its limits competes on exactly the axis they cannot.
