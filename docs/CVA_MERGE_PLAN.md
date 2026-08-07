# Merging the Code Vulnerability Analyzer into MonitorRisk

**Status:** proposed, not started · **Date:** 2026-08-07
**Source repo:** `SAP-Code-Vulnerability-Analyzer` v1.9.0 (`abap_scanner.py`, 3,421 lines)
**Target:** this repository

Evidence labels follow `RISE_SECURITY_MODEL.md`: **[measured]** = we ran it and
recorded the output · **[read]** = read from the source code of either repo ·
**[SAP-primary]** = read from an SAP-published document · **[unverified]** = do not ship.

---

## 0. Two corrections to what this repository already says

Both matter before anything else, because the existing docs would send this work
in the wrong direction.

**`RISE_SECURITY_MODEL.md:490` is wrong, in a way that argues *for* this merge.**
It says "**DO NOT BUILD ABAP SOURCE SCANNING**" on the grounds that SAP's own Code
Vulnerability Analyzer is "Free for PCE". That premise does not hold: SAP's CVA is
fee-free only *inside a purchased BTP ABAP Environment entitlement*, not for RISE
PCE customers generally. The same line proposes a fallback — "Cloud ALM already
exposes a CVA status store" — for which no supporting evidence could be found;
treat it as **[unverified]** until someone with an S-user confirms it. The
instruction rests on a false premise and should be revised, not obeyed.

**ABAP source *is* obtainable under RISE PCE.** The customer keeps the ABAP
application layer and SAP GUI, and abapGit's **offline ZIP export** produces a
serialized repository on the customer's laptop with no OS access, no outbound
network from the SAP system, and no SAP ticket. gCTS is ticket-gated; transport
files are OS artifacts and therefore out of reach; SAPlink is obsolete; `REPOSRC`
is compressed so a table read yields nothing. **[read]** Offline ZIP is the input
story — one mechanism, and it survives RISE.

---

## 1. The decision

**Merge the rule corpus and the taint engine. Drop the BTP half, the grade and the
reporting. Gate it on precision. And build the reachability join, or do not build
the engine at all.**

The Code Vulnerability Analyzer is not a SAST engine today; it is a line-oriented
regex grep over ABAP text with an opt-in taint pass bolted on. That is not a reason
to reject it — it is a reason to be precise about what is being acquired. What
comes across is *content and two algorithms*: the rule dicts, `_block_scan`, and
`TaintAnalyzer`. The corpus maps close to 1:1 onto SAP's own CVA category taxonomy,
so the *shape* of the coverage is right even where the implementation is shallow.

**The differentiator is not the scanner.** Pattern parity with SAP's CVA is not
winnable and not worth chasing: Onapsis (ex-Virtual Forge CodeProfiler),
SecurityBridge and Fortify all ship global interprocedural flow analysis, and this
is intra-procedural and path-insensitive. Two claims are defensible instead.

1. **Offline, over an export.** Every competitor — and SAP's own CVA — runs as an
   in-system ATC add-on. None of them can be pointed at an abapGit ZIP on an
   assessor's laptop.
2. **The reachability join, which is the real prize.** MonitorRisk already holds
   `role_tcodes`, `icf_services`, `api_endpoints` / `odata_auth`,
   `rfc_destinations` and `fiori_tiles`. Joining an ABAP object name against those
   answers a question SAP's CVA *structurally cannot*, because it sees code and not
   the exposure surface: **is this SQL injection reachable?** The same defect
   behind a published ICF node and in a program with no transaction code and no
   ICF node are not the same finding, and only this product holds both halves.

**Conditional recommendation.** If the reachability work (Phase 4) will not be
funded, the recommendation inverts: **do not merge the engine at all.** Do Phase 1
— a proper ATC / Code Inspector importer into the `custom_code_scan` reader that
already exists — and stop. The engine without the join is a noisier, less accurate
re-implementation of a tool SAP already ships.

### The measurements that drove this

Every number below was produced by running the scanner, not by reading it.

**Rule arithmetic, corrected by executing the module.** The headline "110" is wrong
in both directions. `ALL_ABAP_SAST_RULES` is **89** ABAP-source rules; plus **7**
`ABAP-JS-*` and **8** `ABAP-BTP-*` deployment-descriptor rules = **104** static
rules. `all_known_rules()` returns **134** only because it adds the 30-entry
`BTP_API_CHECKS` live-network table, which is being dropped. Severity split:
17 CRITICAL / 46 HIGH / 22 MEDIUM / 4 LOW. **8** rules carry a taint sink; **1**
carries a multi-line block check. **Budget against 89 + 7 + 8, not 110 or 134.** **[measured]**

| Observation | Evidence |
|---|---|
| 89 findings from 6 small sample files; 67 rules fired | **[measured]** |
| Of 104 static rules, **1** has multi-line context; **8** can be taint-refined; taint is **off by default** | **[read]** |
| 50 lines of deliberately *secure, idiomatic* ABAP → **4 findings**, two of them HIGH because the substring `des` appears inside `lv_modes` and `lt_codes` | **[measured]** |
| A dynamic `WHERE (lv_where)` split across lines the way real ABAP is formatted → **zero findings** | **[measured]** |
| The taint pass **silently deletes a genuine injection** when the sanitizer sits in an `IF` branch — the walk is path-insensitive | **[measured]** |
| The A–F grade is computed *after* CLI filters, so one unchanged file scores B, A/93 or A/100 depending only on flags | **[measured]** |
| Throughput ~5,600–6,700 lines/sec, ~5 MB heap → ~3 min for a million-line estate. `--data-flow` is O(files × findings) and does not hold up | **[measured]** |
| The scanner does **not read real abapGit output**: `.ddls.asddls`, `.dcls.asdcls`, `.bdef.asbdef` and every `.xml` metadata sidecar are silently skipped | **[measured]** |

The false-positive and the false-negative example are the same defect seen twice:
the analysis unit is a *line of text*, and ABAP is not written one statement per
line. That is the thing Phase 2 exists to fix.

---

## 2. What comes across, and what does not

| CVA subsystem | Verdict | Replaced by |
|---|---|---|
| 89 ABAP-source rules + 7 `ABAP-JS-*` | **MERGE** — this is the capability | — |
| `TaintAnalyzer` + `_block_scan` | **MERGE** — the only subsystem with no host analogue | — |
| 8 `ABAP-BTP-*` descriptor rules (`xs-security.json`, `xs-app.json`, `mta.yaml`) | **MERGE, after dedup** | — (genuinely net-new; see warning below) |
| `AbapBtpScanner` + 30 `BTP_API_CHECKS` + `import requests` | **DROP, loudly** | `modules/btp_cloud_surface.py`, `rise_btp_checks.py`, `btp_import.py` |
| `SAP_VULNERABLE_PACKAGES` (hardcoded CVEs / Note numbers) | **DROP** | `modules/sap_hotnews.py` owns note/CVE knowledge and has a customer-override path; keeping it also double-counts against the KEV floor in `risk_prioritizer.py` |
| `_ReportMixin` HTML/JSON reporting | **DROP** | `report_generator.py`, `pdf_report.py`, `pptx_report.py` |
| A–F security grade | **DROP** | `risk_prioritizer.py` (P1–P4) + `crq_engine.py` (FAIR $) |
| `CATEGORY_TO_OWASP` as a taxonomy | **DROP; keep `cwe` as a field** | `compliance_mapping.py` — `"Code & Transport Security"` is already a `CATEGORY_THEMES` key, so emitting that category inherits the frameworks for free. Two taxonomies in one product will drift |
| `Finding` + `fingerprint()` + baseline file | **REWRITE** | `base_auditor.finding()` + `server/identity.py`; a baseline becomes a bulk transition to `accepted` with an expiry — auditable and expiring, strictly better than a fingerprint file |
| Scan profiles / `RuleSelector` | **REWRITE** | host `--modules` + `--severity` |
| SARIF 2.1.0 output | **DEFER** | Keep the `cwe` field so the option stays open; the CI-gate buyer is a different product (§6) |
| `#NOSEC` inline suppression | **KEEP THE READ, DROP THE DELETE** | See below |

**`#NOSEC` must not delete.** As written it removes the finding before it ever
reaches the server — the same failure class that `server/coverage.py` exists to
prevent, a clean-looking report over a fraction of the estate. Read the marker,
**emit the finding** with `details.suppressed_by_source_marker = true`, count it in
coverage, and let the server's existing dismissal workflow — which has an audit
trail and an expiry — own the decision.

**Descriptor-rule warning.** `ABAP-BTP-001` and `-002` each have duplicate regex
forms. Under host identity a double emission with the same check_id and subject
fingerprints *identically*, so one of the two findings **silently disappears**.
Dedup before merging. The always-firing `-006` needs rewriting or dropping.

**`CODE-INJ-001/002/003` and `CODE-STMT-001` stay.** They are a different evidence
source (an ATC export) for the same defect class. Verified: no template in
`data/attack_paths.json` cites them, so they could be retired safely — but there is
no reason to. **Precedence rule:** when both an ATC export and our engine are
present, both fire and neither is suppressed; the ABAP auditor writes
`details.also_reported_by_atc` on any object appearing in both, and the methodology
section discloses it.

### Why the BTP scanner must go

Three independent reasons converge, and dropping it resolves all three at once.

1. **It is a live OAuth client** against SAP endpoints. `modules/btp_import.py`
   considered and rejected exactly this, in writing: *"no live connection to SAP
   anywhere in this product."* **[read]**
2. **It is redundant and shallower.** Roughly three quarters of its 30 checks are
   already covered; `BTP-IAS-004` alone is a strict superset of all four
   `ABAP-BTP-PWD-*` rules, using the same lockout threshold while additionally
   distinguishing an absent field from a bad one. **[read]**
3. **It carries the only non-stdlib import.** `abap_scanner.py:45` has a
   try-guarded `import requests`, used solely by BTP mode. The host's purity job
   walks the AST, so the guard does not save it — it fails CI on day one. **[measured]**

Nine of its predicates are worth keeping as *new branches inside existing host
checks* — notably three that read `accessTokenValidity` / `refreshTokenValidity`,
which `btp_import.py` already ingests and no check currently reads. **[read]**

---

## 3. Identity — smaller than feared

This looked like the hard problem and is not, because the CVA already solved it.

A code finding is about a *location*, and line numbers move. If the line enters the
fingerprint, inserting one comment at the top of a program re-fingerprints every
finding below it, and `identity._rebase` provably cannot rescue that — it only
fires when exactly one candidate exists.

The CVA's own `fingerprint()` is already deliberately line-number-independent:

```python
sha1(f"{rule_id}|{basename}|{normalized_line_content}")
```

Its whitespace normalization is **byte-identical** to `identity.py`'s. **[read]**
So the mapping needs **no change to `identity.py` at all**:

- `subject` = the ABAP object (program / class / include) — a real, durable SAP object
- `AffectedObject.qualifier` = the normalized offending source line
- `scope` = `"object"`, `fingerprint_basis` = `objects`

Verified against the real 89-finding set. **[measured]**

**Stated failure modes**, because they are real:
- Two *identical* lines in one object collide into one finding. Acceptable: the
  remediation is the same edit.
- A variable rename re-fingerprints the finding, resetting its age. Unavoidable
  without an AST; a rename is also a genuine code change.
- Moving a method between includes changes `basename` and so changes identity.

**Volume control uses the existing contract, not a new one.** Taint-*confirmed*
findings become per-location `scope="object"` findings. Pattern-only findings —
which is all but the 8 that carry a taint sink — become `scope="aggregate"`, one finding per
(rule × ABAP object) naming its occurrences as members. That is what `aggregate`
already means in this codebase, and it collapses the volume problem without
inventing a fingerprint basis.

---

## 4. Phased plan

Each phase ships something usable. No phase builds foundations for six weeks.

### Phase 1 — Ingest what SAP's own tools already produce
Extend `modules/code_transport.py`, which already parses `custom_code_scan.csv`
(`OBJECT_NAME`, `FINDING_TYPE`, `LINE`, `SEVERITY`) but only keyword-matches its
description text in `CODE-INJ-001/002/003` and `CODE-STMT-001`. **[read]**
Turn ATC / Code Inspector / SAP CVA exports into first-class findings.

> **Exit:** an ATC export with *n* security findings produces *n* findings with
> stable identity across two runs, and a customer who already owns SAP CVA gets
> value from this module without our scanner running at all.

*Ships first because it has zero false positives — the findings are SAP's.*

### Phase 2 — Make the scanner read real ABAP
Two defects, both measured, both blocking:
statement-level analysis instead of line-level (ABAP statements end at `.`, not at
`\n`), and the abapGit extension set (`.asddls`, `.asdcls`, `.asbdef`, `.xml`
sidecars).

> **Exit:** a multi-line dynamic `WHERE` is detected; `lv_modes` does not fire a
> crypto rule; a real abapGit offline ZIP export scans with zero silently-skipped
> source files.

### Phase 3 — Land it in `modules/` as an auditor
Drop the BTP scanner, `_ReportMixin` and the grade. Implement the `BaseAuditor`
contract. Keep the 134 → 104 `ABAP-*` IDs **unchanged** — they are a published
contract, appearing in SARIF `ruleId`s, in customer baseline files, and inside
customer ABAP source as `#NOSEC ABAP-SQLI-001` comments. **[read]** Rename only
`ABAP-AUTH-*`, which reads confusingly beside the host's unrelated `AUTH-*`.

Registration touches ~21 edit sites, not the 7 in `CLAUDE.md`'s recipe — it omits
`server/ingest.py` `AUDITORS`, `enrich.TEAM_BY_PREFIX` and
`coverage.RISE_MODULE_SCOPE`, all of which **fail silently**. **[read]**
Three CI gates glob `modules/*.py` non-recursively and a subpackage would evade
them; fix the globs in this phase.

> **Exit:** `python sap_scanner.py --modules cva` runs; the purity job passes; no
> check_id collides; `team_for()` returns a real team for every `ABAP-*` id;
> `--dry-run` lists the module.

### Phase 4 — The reachability join. **This is the differentiator.**
Join the ABAP object name against `role_tcodes` / AGR_1251, `icf_services`,
`api_endpoints` / `odata_auth`, `rfc_destinations` and `fiori_tiles`. Add a fourth
signal, `reachable`, to `RiskPrioritizer`, and let **that** — not a keyword in a
rule description — drive `exposed`. The prioritiser's design rule that a signal may
only ever *raise* priority makes this naturally conservative.

Add one attack path: an `ABAP-CMDI-*` finding as a `cut=true` hop under
`SAP-RCE-01`, using only the existing node/edge vocabulary.

**Named limit:** path hops match on `check_id` alone, so a `tentative` finding
instantiates a path exactly like a `confirmed` one. Either add an optional
hop-level `min_confidence` predicate — which changes `graph.instantiate()` and
`_open_findings_by_check`, and therefore alters `ruleset_fingerprint`, so it is
*not* a pure content change — or accept coarse matching for code hops. Splitting
confirmed/tentative into separate check_ids would double the catalogue and is worse.

> **Gating question, to settle before Phase 2 ships, not before Phase 4 starts:**
> is there a reliable **transaction-code → program** signal in what the host
> already ingests? `role_tcodes` gives tcode → role. If tcode → program is not
> obtainable, this needs a new logical source and `docs/EXPORT_GUIDE.md` work.
> The business case rests on this; find out early.

> **Exit:** an `ABAP-CMDI-*` finding in a program reachable from a published ICF
> node tiers **P1**; the identical finding in an unreferenced program tiers **P4**;
> both facts appear as named entries in the finding's factor list with their point
> values; the new path instantiates on sample data and `tests/test_graph_paths.py`
> passes.

### Phase 5 — Trust model: confidence, aggregation, suppression
Taint on by default for the 8 rules that support it. Aggregate scoping per §3.
`#NOSEC` honoured and surfaced. A per-finding `confidence` column
(`confirmed` / `tentative` / `pattern-only`) — it varies per occurrence, so it
cannot live on `check_definition`.

> **Exit:** a 200k-line estate produces a finding count an analyst will actually
> work; every finding states the evidence class it rests on; the FAIR figure moves
> by less than 10% when pattern-only findings are excluded.

### Phase 6 — Server tier and console
Almost no schema change is needed: `finding_observation.details jsonb` already
exists, is already populated by `ingest.py` from the auditor's `details` dict, and
is rendered by **no template** — dead storage that is exactly the right home for a
snippet and a taint trace, both of which are properties of a *particular run*.
**[read]** Two genuinely new columns: `check_definition.cwe` (the table has `cve`
and `cvss` but no `cwe`, and every CVA finding carries one) and the per-finding
`confidence` from Phase 4.

Render the source→sink trace on `finding_detail.html`. The trace is the CVA's best
output and there is nothing like it in the product:

```
line 10  source  lv_where = request->get_form_field( 'q' ).
line 11  sink    SELECT * FROM mara WHERE (lv_where) INTO TABLE @DATA(lt1).
```

> **Exit:** a taint-confirmed finding renders its trace; a code finding shows its
> snippet; the KB cost lands at ~14 family entries + ~20 per-rule overrides rather
> than 134, because `FindingKB.lookup` already does prefix fallback. **[read]**

### Phase 7 — Close the verified coverage gaps
Six zero-coverage classes confirmed by grep: **EXEC SQL** (native SQL), **AMDP /
SQLScript**, **CDS DCL access control** (despite the scanner already reading
`.ddls.abap`/`.dcls.abap`), **ABAP Cloud / RAP**, **XXE**, **SSRF**, and
**TEST-SEAM** backdoors. **[read]**

Build **AMDP first** — SAP's own keyword documentation states no test tool exists
for it, which makes it the one place this module can be genuinely ahead rather
than behind. **[SAP-primary]**

> **Exit:** each new family has a positive and a negative test fixture, and the
> negative fixture produces zero findings.

---

## 5. Risk register

**1 — False positives poison the dollar figure.** *Highest.* FAIR is priced on the
**unfiltered** finding set by design, so noise inflates Annualised Loss Exposure,
and the board number is the product's most exposed claim. Two HIGHs from the
substring `des` is not hypothetical. **[measured]**
→ Phase 4 before any customer sees a code finding: aggregate scoping,
confidence-banding, and exclude pattern-only findings from CRQ pricing until a
human confirms them.

**2 — An English word in a rule description silently inflates the dollar figure.**
`risk_prioritizer.py:142` sets `exposed = bool(cat in _EXPOSURE_CATEGORIES or
_EXPOSURE_KW.search(text))`, and `_EXPOSURE_KW` (`:52`) matches
`internet|external|publicly|exposed|…` **over free text**. CVA rule descriptions
are written in exactly that vocabulary. So a code finding gets an exposure boost —
raising its P-tier and its FAIR contribution — because of a word in its own prose,
with no reference to whether the code is reachable by anyone. **[read]** This is
fabricated quantification in a customer deliverable, and it is invisible.
→ Exclude code-finding description text from `_EXPOSURE_KW` in Phase 3. Drive
`exposed` from the Phase 4 reachability join, or leave it false. This is the second
reason Phase 4 is not optional.

**3 — Volume.** Existing scans produce ~300 findings; a real custom-code estate
could produce thousands. At risk: the P1–P4 queue, the PDF report, ingest time,
the console.
→ Aggregate scoping (§3) is the primary control; measure ingest on a synthetic
100k-line estate before Phase 5.

**4 — Suppression is inadequate for code.** The host's only tool is `accepted`
with an expiry. Code has thousands of legitimately-suppressed findings that should
stay suppressed permanently.
→ `#NOSEC` in source is the right primitive: the suppression lives next to the
code, in the customer's VCS, reviewed like code.

**5 — CI fails on day one.** The `requests` import; non-recursive `modules/*.py`
globs; `team_for()` returning `unassigned` for every `ABAP-*` id. **[read]**
→ All three are Phase 3 exit criteria.

**6 — `--data-flow` does not scale.** O(files × findings). **[measured]**
→ Bound it per object; taint only the 8 rules that use it.

**7 — Competitive honesty.** Onapsis (ex-Virtual Forge CodeProfiler),
SecurityBridge and Fortify all ship **global interprocedural** data- and
control-flow analysis. This is intra-procedural and will stay that way. **[read]**
→ Do not claim parity. Claim the thing that is true and that they cannot do:
offline, pre-ATC, over an export, with no connection to the SAP system.

---

## 6. What I would not do

- **Not** merge the BTP scanner. It is a live API client in an offline product.
- **Not** build an ABAP parser or AST. Statement-level splitting (Phase 2) gets
  most of the accuracy for a fraction of the cost; a real front end is a
  multi-month project that would not close the interprocedural gap anyway.
- **Not** claim interprocedural analysis, or a security "grade".
- **Not** rename the `ABAP-*` rule IDs. They are already in customer source code.
- **Not** preserve the source repo's git history in this one. Vendor the file with
  a provenance header and archive the standalone repo; a 3,400-line single file
  with its own CI and LICENSE is not worth a subtree merge.

---

## 7. Open questions

1. **Positioning.** SAP's CVA is fee-free only within a purchased BTP ABAP
   Environment entitlement. How many target customers actually have it? That
   number decides whether Phase 2 is the priority or Phase 1 is the whole product.
2. Does Cloud ALM expose a CVA/ATC status store? **[unverified]** — needs an S-user.
3. Has any real abapGit export been scanned? No. Same gap as the rest of the
   product: nothing here has met a genuine SAP artifact yet.
