# Competitor Dossier — SecurityBridge

**Status:** research synthesis, 2026-08-05, after an adversarial verification pass.

**How to read this.** SecurityBridge publishes numbers and never a catalogue. Almost every
capability claim about them traces to a marketing page, a solution brief, or a press release —
there is **no public documentation portal, no admin manual and no API reference anywhere**. That is
itself a finding (§6). Labels used below:

| Label | Meaning |
|---|---|
| **[evidence]** | A documented module list, manual, datasheet table, release note, screenshot or third-party integration doc |
| **[claim]** | A vendor assertion on a marketing page or press release — real signal, unverified content |
| **[second-hand]** | Reached only through search snippets; the page itself returned 403 |

**Standing prohibitions for anything customer-facing:**

- **Do not repeat SecurityBridge's Q1 2026 zero-day CVE or SAP Note identifiers.** They come from a
  vendor blog and **none were verified against SAP or NVD.** Wrong SAP identifiers have burned this
  project before.
- **Do not describe them as having "seven core components."** That framing comes from an older
  solution brief and is superseded — their current platform overview names **13 modules**. Using it
  signals stale research.
- **Do not treat "550 checks" or "900 use cases" as capability.** They are claims (§1.2).

---

## 1. What SecurityBridge is

An SAP-certified **ABAP add-on** that runs security analysis inside the SAP system, with a
SAPUI5/Fiori-style interface rendered by the SAP system itself. It supports ABAP NetWeaver,
S/4HANA and other SAP cloud solutions, requires no additional hardware, and executes its analysis
in-system. Microsoft's connector documentation independently describes it as an SAP-certified
add-on. **[evidence — solution brief + Microsoft Learn]**

Company context: CEO Jesper Zerlang since 1 January 2026 (previously chairman), founders moved into
evangelism and customer-facing strategy; backed by funds advised by Bregal Unternehmerkapital;
public statements put it at **8,000+ SAP systems protected**, up from a 5,000+ milestone in 2024.
**[claim — press]** This is a funded, scaling incumbent with a growth mandate, not a stagnant
target. SAPMAP and CRIS shipped within five months of each other — expect continued roadmap pace.

### 1.1 Module portfolio

The current platform overview names **13 modules**. Evidenced modules, grouped by what they do:

| Module | What it does | Reachable by an offline scanner? |
|---|---|---|
| **Security & Compliance Management** | Measures system state against a "Standard Baseline"; metrics normalised at system level | **Yes — this is our category** |
| **Vulnerability Management** | Findings pre-clustered by "Area of Responsibility" so they route to the owning SAP team | **Yes** |
| **Patch Management** | Identifies missing SAP Security Notes, their prerequisites, relevance and system-specific impact | **Yes (applicability by component/SP level)** |
| **Code Vulnerability Analysis** | ABAP static analysis; runs inside SAP with no source extraction | **Yes in principle — but see §5.3** |
| **Transport Security** | Checks new custom development at the transport layer | **Partly** |
| **Interface Traffic Monitor** | Interactive landscape communication map from RFC/UCON data; flags obsolete interfaces and "tier-up" traffic from lower systems into production | **Partly — configuration yes, observed traffic no** |
| **Real-time Threat Detection** | Scans security-relevant SAP logs against activity patterns; validates log-source health and alerts when a source is switched off | **No — structurally** |
| **Automated Incident Response** | Triggers automation off events, forwards to enterprise ITSM | **No — structurally** |
| **Privileged Access Management** | Self-service elevation instead of standing god-mode authorisations; admins act under named accounts; auto-activates session logging and auto-decommissions privileges on session close | **No — structurally** |
| **Data Loss Prevention** | Application-native visibility into who is downloading what data, with preventative enforcement | **No — structurally** |
| **Forensic Analysis (HyperLogging)** | Deep session recording of activity before, during and after privileged access | **No — structurally** |
| **Identity Protection** | Identity-layer controls | **Unknown — thin public detail** |
| **TrustBroker** | SSO / trust brokering | **Out of our category** |
| **Security Dashboard** / **Security Roadmap** | Presentation and remediation-sequencing layers | **Yes — see §4** |

PAM, DLP, Forensic Analysis, Identity Protection and TrustBroker are **whole categories we are not
competing in**. Concede them explicitly rather than being surprised in an evaluation. Note also
that PAM materially weakens a rival vendor's public allegation that SecurityBridge does no critical
access analysis.

### 1.2 The numbers, and why they are not capability

| Number | Status |
|---|---|
| **"550+ checks", "twice the SAP Security Baseline"** | Verbatim on their CRIS page and launch release. **[claim]** We searched their site, SAP Store, solution briefs, whitepapers and press for an itemised control list and found **none** — not a table, not an appendix, not a datasheet. The count is asserted everywhere and enumerated nowhere. |
| **"900+ out-of-the-box use cases"** | Circulates via the SAP Store listing and secondary coverage. **[claim]** Never reconciled against the 550 figure in any public source. |
| **"Hundreds of threat-detection patterns", "100+ listeners, identification patterns and signatures"** | **[claim]** No catalogue published. |
| **"Twice the SAP Security Baseline"** | The implied ~275 baseline figure is unverified in both directions. We now hold the actual SAP baseline (v2.6: 27 requirement families, ~55 requirement-technology IDs, 54 `[Critical]` markers) and **it is not structured as ~275 discrete checks** — so the 2× comparison is comparing unlike units. |
| **Their own Buyer's Guide contains ZERO numeric capability claims** | Retrieved and read (10.6 MB, 13 pages). No 550, no 900, no 8,000. **[evidence]** Their own buyer-facing document avoids the numbers their press releases use. |

> **Positioning consequence.** The honest comparison is **~323 published-and-auditable vs 550
> asserted-and-unverifiable.** Publishing our full check catalogue — ID, what it reads, which
> standard clause it satisfies — converts a perceived count deficit into a transparency advantage
> no incumbent currently offers. It is the cheapest positioning move available to us.
>
> When a prospect quotes 550 at us, the fair and effective response is to ask what it counts. They
> cannot answer that from any public source either.

---

## 2. The deployment model, and what it implies

This single architectural fact explains most of their strengths and most of their complaints.

| | **SecurityBridge — in-system ABAP add-on** | **Us — offline export ingestion** |
|---|---|---|
| Where it runs | Inside the SAP system, analysis executed in-system | Outside entirely; reads exported CSV/JSON |
| UI | SAPUI5/Fiori inside SAP, under SAP's authorization model | Browser console with its own database and identity layer |
| Install cost | Transport into production, change-approval cycle, Basis buy-in, ongoing add-on version management | A file upload |
| Access to runtime state | **Full** — live logs, sessions, execution events | **None** |
| Access when SAP is unavailable | None | **Full** |
| Non-SAP-literate stakeholders | Must learn an SAP transaction | Native audience |

### 2.1 Where their model genuinely wins — say this plainly

- **Runtime truth.** Anything that requires observing execution — threat detection, privileged
  session recording, DLP enforcement, execution of vulnerable programs — is available to them and
  is structurally unavailable to us. Not a feature gap; a physics gap.
- **Developer-inline scanning.** Their code analyser hooks into the ABAP workbench, Eclipse-based
  ABAP tooling, SAP Code Inspector and the ABAP Test Cockpit, so scans run as part of coding. We
  cannot be in that loop.
- **Continuous, agent-driven freshness.** They see the system continuously; we see a snapshot the
  customer chose to export.
- **Native idiom for Basis teams.** They look like SAP because they are in SAP.

### 2.2 Where our model genuinely wins — and it is not small

- **Deployable where an add-on cannot go.** Audit engagements, pre-acquisition diligence, air-gapped
  review, and RISE tenants where the customer will not or contractually cannot install third-party
  ABAP. In RISE, installing new entities after handover carries a **contractual Change Request**
  requirement, and install/configure/monitor/update of unmanaged ABAP add-ons sit as Excluded Tasks
  — SAP's own text, cited in `RISE_SECURITY_MODEL.md` §2.7. **[SAP-primary]**
- **Time-to-first-report.** Ours is measured in the time to produce an export. Theirs includes a
  transport and an approval cycle. Reviewers independently flag that because the product is not
  agentless, implementation effort should not be underestimated. **[second-hand — G2 summaries]**
- **No approval, no window, no rules of engagement.** We send no packets to the SAP system.
- **Survives losing SAP access.** The console, the history and the evidence live outside SAP.
- **Serves the buyer who actually inherited the accountability.** In RISE that is the security/GRC
  owner, not the Basis team — and they often do not hold the SAP access an in-system tool assumes.

> **Positioning line:** *zero footprint — nothing installed, nothing to approve, works on an export
> someone emails you.* And accept openly that we lose every deal where continuous in-system
> monitoring is the actual requirement.

---

## 3. Capability matrix

**STRUCTURALLY BEHIND** = requires in-system or real-time presence we do not have by design.

| Capability | Verdict | Evidence, one line |
|---|---|---|
| **Financial risk quantification (FAIR)** | **WIN** | Their only money-facing artifact is a Business Case Calculator that computes ROI of *buying the tool* from labour days saved — not the monetary risk of findings. No monetary loss exposure appears on their compliance, roadmap or CRIS pages. **[evidence]** |
| **Published, auditable check catalogue** | **WIN** | Their 550 is asserted and never enumerated anywhere public; their own Buyer's Guide carries no numbers at all. **[evidence]** |
| **Public product documentation** | **WIN** | No documentation portal, admin guide or API reference exists; support sits behind a Jira Service Desk login. **[evidence]** |
| **Board-grade exportable reporting** | **WIN** | Reviewers state the management dashboard is not usable for building management reporting. Our HTML/PDF/**PPTX** output answers this directly. **[second-hand — G2 summaries]** |
| **Deployability in RISE / audit / diligence contexts** | **WIN** | §2.2 — their add-on needs a transport and change request; we need a file. |
| **Findings/compliance REST API** | **WIN (probable)** | The only documented API surface we could find is event retrieval. See §6 for the caveat. |
| **Configuration & compliance assessment** | **PARITY (contested)** | Same category, same data. They claim 2× our check count and cannot show it; we can show ours. |
| **Compliance framework mapping** | **PARITY** | They name GDPR, NIS2, SOX, FDA, NIST, PCI DSS, ISO 27000, CIS, SWIFT CSCF, MITRE ATT&CK and ISACA. **[claim]** Table stakes: its absence loses deals, its presence wins none. Build it as a mapping layer over the catalogue so adding a framework is a data exercise. |
| **Patch/note applicability** | **PARITY** | Their method is not disclosed; component and support-package comparison is computable offline. Their "does the note touch objects in use" refinement needs usage data we do not have. |
| **Repeat-scan remediation tracking** | **BEHIND** | Their Security Roadmap is mature: ranks findings by risk **and resolution complexity**, sequences lowest-hanging fruit first, distributes work by responsibility area, integrates Jira and ServiceNow, guards against reopening closed gaps, supports documented risk acceptance, and trends compliance rating over time per area. **[claim, but detailed and consistent]** **This is table stakes, not one of our differentiators.** |
| **Per-domain scoring + peer benchmarking (CRIS)** | **BEHIND** | Eight Areas of Responsibility scored 0–100% with published bands (<50% risky, 51–60% acceptable, 61–80% good, >80% great; "most new customers start at 30–40%"), plus anonymised cross-customer benchmarking refreshed periodically. **[claim + press]** The per-domain % is reproducible offline today; **peer benchmarking needs an installed base we do not have.** |
| **Landscape interface/topology map** | **BEHIND** | Interface Traffic Monitor draws nodes and edges and already names tier-up lateral movement. **[claim — the page is marketing with no configuration, architecture or performance detail]** |
| **Attack-path graph** | **BEHIND (narrative), contested (product)** | Their research director released **SAPMAP** in July 2026 — press-reported as 72 CVEs, 1,817 automated tests, 7 weaponised exploits and 16 business-impact scenarios, mapping on-prem SAP and BTP across the trust boundary. **[evidence — press release, not documentation]** It is an invitation-only OWASP CBAS research tool, **not the commercial product**: no console, no repeat-scan tracking, no reporting. **They have claimed the narrative; the productised graph is still open.** |
| **SAP vulnerability research** | **BEHIND — structurally, and we should not try** | Their lab has SAP-acknowledged standing as a top-3 reporting source and a track record of 0-day discovery. **[claim — SAP's own credits page returned 403, so the ranking rests on their press release]** Original research needs a lab, an SAP disclosure relationship and years. |
| **SIEM integration** | **BEHIND** | Named integrations across Splunk, Sentinel, QRadar, ArcSight, FortiSIEM, Elastic, LogRhythm, Exabeam, Sumo Logic, Google SecOps, Rapid7, plus ServiceNow and Jira. **[claim]** Depends on live log streaming, which we do not do. |
| **Real-time threat detection** | **STRUCTURALLY BEHIND** | Requires a persistent in-system agent and event-time execution. |
| **Automated incident response** | **STRUCTURALLY BEHIND** | Same. |
| **Privileged Access Management** | **STRUCTURALLY BEHIND** | Session-time elevation, recording and decommissioning. |
| **Data Loss Prevention** | **STRUCTURALLY BEHIND** | Requires runtime interception of downloads. |
| **Forensic session recording (HyperLogging)** | **STRUCTURALLY BEHIND** | Runtime capture. |
| **"Virtual Patching"** — detecting execution of vulnerable ABAP programs during the remediation window | **STRUCTURALLY BEHIND** | **[claim — their own research updates]** This is the honest answer to "do they track exploitability or just presence": for their own discoveries they detect attempted exploitation at runtime. We cannot. |
| **Developer-inline ABAP scanning** | **STRUCTURALLY BEHIND** | Runs in SE38/SE80/Eclipse and enhances the ABAP Test Cockpit. |

### 3.1 The one structural loss that is only partial

Their threat-detection substrate is **exportable**. Microsoft's (now deprecated and archived)
Sentinel connector documentation shows the architecture: the ABAP add-on writes normalised CEF
event files to the SAP application server filesystem — documented sample path `/usr/sap/tmp/sb_events/*.cef`,
filenames like `AED_20211129164544.cef` — and a Sentinel agent tails that directory into a
`SecurityBridgeLogs_CL` custom table. Developed against SecurityBridge Application Platform 7.4.0.
**[evidence — Microsoft Learn, verified verbatim]**

The intelligence lives in the pattern library, not in privileged access to the SAP kernel. So:

- **Real-time monitoring is off the table for us. Permanently.**
- **Retrospective analysis over an exported Security Audit Log window is not.** If a client can
  export the SAL for a date range — a standard extract — we can run pattern analysis offline and
  report what happened during that window.

> **Wording discipline:** *"retrospective review over the exported window."* **Never "monitoring."**
> Claiming real-time detection would be caught in the first technical evaluation and would cost the
> deal. This converts a structural loss into a partial win and gives repeat scans a second axis of
> change beyond configuration drift.

Adjacent and cheap: **log-source health** is a pure configuration check — is the audit log active,
what filter profile, what retention, which event classes. Their threat-detection material claims
the same capability. Ours costs nothing extra and makes the retrospective story credible.

---

## 4. UX and reporting patterns worth learning from

### 4.1 Copy these

| Pattern | Why it works |
|---|---|
| **Findings pre-clustered by Area of Responsibility** — published areas include Operating System, Development/Code Vulnerability, Integration, Identity and Access, Authorizations, Data Protection, SAP Basis | This is what makes 550 findings consumable instead of a wall. Nearly free for us to copy: tag every check with an owning team, make it a first-class filter and scorecard axis, and let repeat-scan tracking assign to a team rather than a person. |
| **Per-domain 0–100% scoring with published interpretation bands** | It is the number an executive repeats. Computable from a single offline export — ship it alongside the FAIR quantification. |
| **Resolution complexity as a first-class sort dimension alongside severity** | "Lowest-hanging fruit first" is a better remediation sequence than severity alone. |
| **Documented risk acceptance** with justification and expiry | Turns "we're not fixing this" into an auditable record instead of an open finding forever. |
| **Alerts dragged into an "incident basket" to become an incident** | The primitive is right even if the mechanic isn't ours: **cluster related findings into one remediation item** rather than presenting hundreds of atomic rows. This is the direct antidote to the "overwhelming" complaint. |
| **Their code-finding schema: vulnerability type, severity, object, authorization, package, RFC-enabled flag, changed-by** | Two lessons. The **RFC-enabled flag is a reachability signal** — a missing authority check in an RFC-callable module is a remote attack path, and that flag is exactly the edge type an attack-path graph needs. **Changed-by** turns a finding into an assignable item. Both are cheap fields that make findings actionable rather than merely enumerated. |
| **Landscape overview: per-system finding counts with last-scan timestamps across dev/QA/prod** | Simple, and immediately legible to anyone running a multi-system estate. |
| **Translating SAP-native identifiers into analyst-readable events with assigned severity** | Any export we build should do the same. |
| **Mapping attack paths to named business-impact scenarios** (salary theft, vendor bank fraud, production sabotage, customer data breach) | *"This path leads to vendor bank-detail fraud"* lands with a CFO in a way *"privilege escalation via RFC trust"* never will — and it is the natural input to a FAIR model. Steal the framing. |
| **A free public SAP Note advisory portal** — browsable without login, exposing per advisory the Note ID, CVE, CVSS, affected stack, patch month/year and description | A lead-generation asset built from data SAP already publishes, and it makes them the monthly reference point. Decide deliberately whether to compete on this surface, but do not be surprised when a prospect's first instinct on any note question is a competitor's portal. |

### 4.2 Design against these

Reviewer complaints, all **[second-hand]** — G2 and Gartner Peer Insights both returned 403 to
direct fetching, so this is search-snippet paraphrase, not quotation, from a narrow base (no
PeerSpot or TrustRadius profile found).

| Complaint | Design requirement it implies |
|---|---|
| "The management dashboard is not usable to build management reporting" | **Our sharpest opening**, and it lands on an existing strength. Make board-ready, exportable, editable executive output a headline feature, not a footnote. Design a deliberate **executive view separate from the analyst view.** |
| The interface is not user-friendly and feels overwhelming; the multitude of functions is a lot initially | An **opinionated default view with a small number of headline metrics**, not a configurable-everything dashboard. |
| Clearer prioritisation of the most important security metrics would be desirable | Rank and cluster by default; do not make the user build the priority. |
| Level of detail in some areas is sometimes too deep | **Progressive disclosure** — summary first, evidence on demand. |
| Steep learning curve during initial setup and feature configuration | Our onboarding is a file upload; keep it that way and measure time-to-first-report. |
| Because the product is not agentless, implementation effort should not be underestimated | Lead with "nothing installed." |
| Billing shows inconsistencies | **Transparent, simple, published pricing** — unusually easy for a challenger and disproportionately effective. |
| Users want better testing before newer versions ship | Boring reliability is a differentiator against a fast-moving incumbent. |

Market framing to be aware of: third-party comparison data rates SecurityBridge **easier to use and
stronger on roadmap** than Onapsis, while Onapsis is preferred on "meets business needs" and
"easier to do business with". **[second-hand]** So **entering on usability alone collides head-on
with their strongest claim.** The stronger wedge is the pairing the market is not offering —
business-language risk output plus an independent console — rather than "easier to use", which is
taken and hard to prove pre-sale.

---

## 5. Where we can win, argued from evidence

### 5.1 The clean lanes

1. **Financial risk quantification.** Genuinely absent from the incumbent, whose only money language
   is vendor-serving ROI. Quantify the risk of the customer's findings, not the ROI of our software.
   That reaches the CFO and the audit committee, and it is a different and more credible
   conversation. Pair it with the attack path so a path terminates in a currency figure.
2. **Deployment access.** §2.2. Every agent-based competitor must clear a change request, an
   SAP-approved transport and ongoing add-on maintenance inside a system the customer does not fully
   control. We need a file upload. Cite SAP's own add-on clause, not a competitor's pen-test claim.
3. **Radical transparency on check content.** Publish the catalogue. Nobody else in this market
   does, and the incumbent structurally cannot without giving away its asserted advantage.
4. **Public documentation.** A readable public manual and API reference is a trust and evaluation
   advantage, shortens prospects' security review, and makes the product discoverable to
   practitioners who cannot get past a demo-request form.
5. **A findings/compliance API.** Their documented API surface appears to be event retrieval only.
   A clean, documented REST API over findings, scan history and remediation state is cheap for a
   client-server product and is a real gap.
6. **Executive and auditor reporting as named personas.** Directly answers their loudest reviewer
   complaint, and "audit evidence pack" is a sellable outcome in its own right — ITGC evidence
   gathering is otherwise manual screenshot work.
7. **RISE shared-responsibility framing.** Tag every finding *yours under RISE* vs *SAP's under
   RISE*. No incumbent surfaced in this research presents findings organised by ownership, and it is
   what makes a report actionable for a RISE customer. See `RISE_SECURITY_MODEL.md` §4.1.

### 5.2 Traceability as a moat we can actually hold

We have no research lab and cannot compete on original SAP vulnerability discovery. That constraint
becomes an asset if we lean into it: **every check cites a published source — SAP Notes, the SAP
Security Baseline, DSAG, CIS — or it does not ship.** Given this project's history of shipping wrong
SAP Note numbers, a hard traceability rule is both the right engineering discipline and the right
market story. SAP's own Apache-2.0 policy repository makes it cheap (see `RISE_SECURITY_MODEL.md`
§3.3).

### 5.3 Two things to stop believing

- **The attack-path graph is not the moat.** SecurityBridge's research director has claimed the
  narrative publicly, and if SAPMAP goes public with a documented taxonomy, adopting it is cheaper
  and more credible than inventing our own. **The moat is offline-export ingestion plus repeat-scan
  mitigation tracking** — which SAPMAP does not do. What is still defensible in the graph is
  **chaining** (entry point → escalation → business impact) and terminating a path in a currency
  figure, not "we visualise the landscape", which they already do.
- **Repeat-scan tracking is not a differentiator.** It is parity work. To reach parity we need, at
  minimum: finding state carried across scans with regression detection, effort/complexity as a
  first-class sort dimension, assignment by responsibility area, a risk-acceptance record with
  justification and expiry, and per-area trend lines. Shipping less than that is a **visible
  deficit**.

### 5.4 A benchmark worth adopting instead of arguing about 550

Their compliance material states the **DSAG audit guideline** contains 250+ checks and that
solutions such as theirs come preconfigured with all of them. **[claim]** It is the only externally
defined, countable check corpus named anywhere in their material, and it is what an auditor actually
asks for in the DACH market.

Mapping our checks to DSAG clauses (and to SAP Security Baseline v2.6 requirement IDs) and
publishing the coverage percentage gives a **third-party-anchored completeness claim** without ever
arguing about their unverifiable 550. **Do this before adding new checks — coverage-mapped is worth
more than count-inflated.** Caveat: the DSAG S/4HANA Prüfleitfaden is ~335 pages, German-only, and
based on on-premise and Public Cloud releases; someone German-reading must review it before we claim
alignment.

---

## 6. What we do not know, and what would resolve it

| Unknown | Why it matters | What would resolve it |
|---|---|---|
| **The 550 baseline check contents** | We cannot assess real overlap or make a defensible coverage comparison | Nothing public exists. Only a customer, a partner or a competitive bake-off would reveal it. |
| **Whether a findings/compliance API exists** | Our "API gap" WIN rests on absence of evidence. The Fortinet connector we relied on is explicitly **community-authored and non-certified**, and documents exactly one operation (Fetch Events, port 8000, basic auth, JSON/XML, time-filtered) | A customer with the product, or any vendor-published API reference appearing |
| **Screen-level UX** — dashboard layout, drill-down from system → finding → fix, assignment and status workflow | The weakest-evidenced part of this dossier; described from text sources only | Watch their demo videos and webinar recordings (not done); a live demo |
| **Independent practitioner assessment** — deployment effort, false-positive rates, real limitations | All reviewer evidence here is **second-hand search snippets**; G2 and Gartner Peer Insights both 403'd, no PeerSpot or TrustRadius profile exists | Direct access to the review platforms; reference calls |
| **Pricing and licensing** | We cannot position on price | Nothing public. They publish a business-case calculator, not a price list. |
| **SAPMAP's ingestion method** (live connection vs export) and whether it will be productised | Determines whether it competes with an offline tool at all | Invitation-only; watch the OWASP CBAS project for a public release |
| **The eighth CRIS Area of Responsibility** | Minor, but the full taxonomy would be useful to mirror | The full CRIS report is demo-gated; seven of eight leaked into blogs and press. An independent German trade write-up gives a partly conflicting category framing we could not reconcile. |
| **Detection content update cadence** | Would tell us how fast their pattern library moves | No published SLA or frequency; sources say only "continually added" and shipped alongside patch-day releases |
| **MITRE ATT&CK technique-level coverage** | They name ATT&CK as a supported framework; no coverage matrix is published | Nothing public |
| **The event/alert taxonomy in their CEF Configuration Guide** | The most promising primary source for their actual detection content | The PDF downloads but is image-encoded and not text-extractable |

### 6.1 Sources that could not be reached at all

- **No SecurityBridge documentation portal, admin guide or API reference exists** — unusually, there
  is no `docs.<vendor>` equivalent indexed. Everything technical comes from solution briefs,
  marketing pages, blogs or third-party integration docs.
- **G2 and Gartner Peer Insights** — HTTP 403 on every product and comparison URL tried. All review
  content here is search-engine summary; ratings and counts are second-hand and complaint wording is
  paraphrase, not quotation. Note also that the SAP security software category carries very small
  review counts for both vendors, so those star ratings are statistically weak.
- **SAP Store listing** — JavaScript-rendered, returned only a page shell. Could not confirm
  certification wording, supported versions, licensing, or the 900-use-cases claim at its primary
  source.
- **SAP.com partner product pages** and **SAP's official Credits for Security Researchers page** —
  HTTP 403. The top-3 research-lab ranking therefore rests on SecurityBridge's own press release.
- **The full CRIS report** — demo-request gated.
- **Their CEF Configuration Guide and NIST CSF alignment whitepaper** — downloaded but image-encoded;
  no text extractable.
- **A competitor's SecurityBridge transition guide** — 404. No adversarial technical teardown of
  SecurityBridge obtained from any source. (Their Onapsis-transition equivalent does exist as a
  published series and is worth reading for the evaluation criteria it uses, even though it is
  competitor-authored.)
- **A rival vendor's 20-criterion comparison table** alleging both SecurityBridge and Onapsis lack
  SoD/access-risk analysis for S/4HANA business users and neither covers database and OS layer
  monitoring: the source is a direct competitor to both and structures the table so only its own
  product passes. **Treat every cell as a hypothesis.** Its real value is the 20-criterion list
  itself, which buyers in this market recognise — use it to structure our battlecard. Note the SoD
  allegation is now doubtful given their PAM module (§1.1).
