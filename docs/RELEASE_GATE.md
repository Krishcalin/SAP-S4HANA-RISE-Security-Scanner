# Release Gate

Turns the scanner from something that reports into something that decides.

A scanner tells you what is wrong. A gate refuses the change that would make it
worse — which is the only mechanism that stops a backlog growing, and it is the
difference between an audit artefact and a control an auditor will accept.

Exit codes follow CI convention:

| Code | Meaning |
|:----:|---------|
| `0` | Pass — ship it |
| `1` | Policy violated — findings are holding this release |
| `2` | **Could not assess** — the scan cannot support a pass |

---

## Adopt it in this order

Skipping step 1 is how gates get switched off in week one.

### 1. Establish the baseline

```bash
python sap_scanner.py --data-dir ./exports --abap-src ./abapgit_export \
    --cap-src ./cap-project \
    --gate-write-baseline gate-baseline.json
```

This records the estate's current findings as **accepted**. Commit the file. Without
it, every existing finding counts as new and the first pipeline run fails on a
change that introduced none of them.

### 2. Run in warn-only mode for a sprint

```json
{ "warn_only": true }
```

```bash
python sap_scanner.py --data-dir ./exports --abap-src ./abapgit_export \
    --cap-src ./cap-project \
    --gate --gate-policy gate-policy.json --gate-baseline gate-baseline.json
```

Everything is evaluated and reported exactly as it will be when enforced, but the
exit code is always `0`. Use the time to confirm the baseline is right and that the
gate is not blocking on anything absurd.

### 3. Enforce

Drop `warn_only`. Optionally scope to the transport:

```bash
python sap_scanner.py --data-dir ./exports --abap-src ./abapgit_export \
    --cap-src ./cap-project \
    --gate --gate-policy gate-policy.json \
    --gate-baseline gate-baseline.json \
    --gate-scope transport-K900123.txt \
    --gate-json gate-result.json
```

`--gate-scope` takes one SAP object name per line (`#` comments allowed) — the
objects the transport contains.

---

## What blocks, by default

A finding must be **all** of these to hold a release:

- **New** — not in the baseline
- **In scope** — on an object the transport touches, if `--gate-scope` is given
- **CRITICAL or HIGH** — `max_new` decides; unlisted severities are not gated
- **Evidenced** — `confirmed` or `tentative`. `pattern-only` never blocks
- **Customer-fixable** — or of unknown ownership
- **Not exempt** — `exempt_checks` is for risks accepted through the dismissal
  workflow, which has an audit trail and an expiry (unlike a `#NOSEC` in source)

### Why `pattern-only` does not block

That evidence class is the population Tier 2 of the CVA engine plan was about:
rules that matched correct code. A finding with no data-flow evidence behind it is
not a safe thing to stop a release with. It is still reported and still counted; it
just does not get to hold the build.

### Why ownership matters

In RISE a real finding may be the provider's to remediate, or may need an SAP
ticket. Blocking a customer's transport on `provider_owned` or `ticket_to_sap` is a
demand they cannot satisfy at any effort, and it is the fastest route to the gate
being bypassed permanently. The four-state `remediation_owner` model is what lets
the gate be strict *because* it is fair.

Ownership is assigned server-side. The offline CLI has no ownership data, so
everything reads as unknown there — and **unknown blocks**, because unknown is not
a licence to ship. Use `exempt_checks` offline.

> There is **no server-side gate**, and this paragraph used to imply one. `server/`
> does not import `release_gate` and exposes no gate route; the gate is CLI-only by
> design, because it belongs in somebody else's pipeline rather than behind a login.
> `CLAUDE.md` states this correctly and this document did not.

---

## It never fails open

If coverage was degraded, the answer is `2` — never `0`.

Degraded coverage is reported as a FINDING rather than a side channel, so the gate
reads the same evidence a human would. It no longer keys on one check id: any
finding carrying `details["degrades_coverage"]` arms the fail-closed path, so a
coverage check written later arms the gate the day it is written rather than the
day somebody remembers to teach the gate its id.

The findings that carry it today:

<!-- BEGIN GENERATED: degraded-coverage findings -->

| check | module | what could not be looked at |
|---|---|---|
| `ABAP-COV-001` | `abap_sast` | `--abap-src` names a path that is not a directory — the scan never ran |
| `ABAP-COV-002` | `abap_sast` | the source tree held no file the scanner recognises |
| `ABAP-COV-003` | `abap_sast` | files that could not be read were skipped |
| `ABAP-COV-004` | `abap_sast` | source files were present in a language this scanner has no rules for |
| `ABAP-COV-005` | `abap_sast` | no CDS access-control artefact in the tree, so view protection was not assessed |
| `ABAP-COV-006` | `abap_sast` | roleless views whose exposure could not be established |
| `ABAP-LEX-001` | `abap_sast` | the lexer lost its place in a source file |
| `BASELINE-000` | `baseline_params` | no profile parameter export, so eighteen parameters went unjudged |
| `BTP-AUD-001` | `btp_cloud_surface` | subaccounts whose audit-log state no supplied export settles |
| `CAPX-COV-001` | `cap_xsuaa` | `--cap-src` unreadable, or a descriptor or CDS construct that would not parse |
| `CSA-COV-001` | `cloudalm_verdicts` | a CSA results export was supplied and no row in it named a policy |
| `CSA-SAP-002` | `cloudalm_verdicts` | SAP Cloud ALM could not evaluate some policies, so its silence on them is not a pass |
| `MDC-PAY-002` | `master_data_changes` | bank changes were found and no payment-run export was supplied, so whether any were paid was never tested |
| `HOTNEWS-010` | `sap_hotnews` | exposure could not be established against the installed releases |
| `HOTNEWS-COVERAGE` | `sap_hotnews` | the note catalogue is a curated subset, not the full patch history |
| `PARAM-MISSING-OTHER` | `security_params` | parameters absent from an export nobody declared complete |
| `STDUSR-COV-001` | `system_trust` | **undescribed** — add it to DESCRIPTIONS in tools/build_gate_reference.py |
| `UCON-COV-001` | `ucon_exposure` | **undescribed** — add it to DESCRIPTIONS in tools/build_gate_reference.py |
| `VBM-DATA-001` | `vendor_master` | the vendor / bank master export carried no usable rows |
| `WDISP-COV-001` | `webdisp_security` | **undescribed** — add it to DESCRIPTIONS in tools/build_gate_reference.py |
| `<CHECK>-COVERAGE` | any | a release-gated check could not determine whether it applied |

> **This table is generated** by `python -m tools.build_gate_reference`,
> which reads `details["degrades_coverage"]` out of the modules —
> including the ids that reach it through a `_coverage` helper and never
> appear beside the flag. It used to say it was derived while being
> maintained by hand, which is how `ABAP-COV-004` and then `MDC-PAY-002`
> came to be missing from it.
>
> The gate itself was never wrong either time: it reads the flag on the
> finding and does not know these ids, which is exactly the property the
> paragraph above describes. Only the documentation drifted — and this is
> the document somebody reads before wiring the gate into CI, so a table
> that silently omits a check is how a reader concludes their pipeline is
> covered when it is not.
<!-- END GENERATED: degraded-coverage findings -->

An unreadable or misspelled policy is also `2`: a typo in a config file must not
quietly disarm the gate. **A scan that read nothing at all is `2` as well** — zero
findings from an empty directory used to be exit `0`, which is the same lie as a
mis-lexed file and arrived by a shorter route.

A mis-lexed file that yields a green pipeline is the single worst outcome this
feature can produce. It is indistinguishable from clean code, and it is a lie told
automatically, on every build, until somebody notices.

Set `block_on_degraded_coverage: false` only if you are content with that.

---

## Policy reference

Supplied JSON is **merged over** the defaults, so a policy naming one key cannot
silently switch the others off. An unrecognised key is an error, not a shrug — a
misspelled key that is ignored is a policy the operator believes is in force and
is not.

| Key | Default | Meaning |
|---|---|---|
| `max_new` | `{"CRITICAL": 0, "HIGH": 0}` | Max new findings per severity. Absent severity = not gated |
| `blocking_confidence` | `["confirmed", "tentative", null]` | Evidence classes allowed to block. `null` covers non-ABAP modules, which carry no evidence class |
| `blocking_owners` | `["customer_fixable", null]` | Ownership states that may block |
| `exempt_checks` | `[]` | Check ids or id prefixes that never block |
| `block_on_degraded_coverage` | `true` | Degraded scan → exit 2 |
| `warn_only` | `false` | Evaluate and report, always exit 0 |

---

## Notes

`--severity` is a **display** option and does not affect the gate. A control whose
verdict moves because somebody narrowed a report is not a control — the same
reasoning that keeps the FAIR figure priced on the unfiltered set.

Finding identity is the subject and its qualifier, **never the line number**, matching
`server/identity.py`. Adding four blank lines above a finding does not make it new,
so unrelated edits do not re-block.

`modules/release_gate.py` is stdlib-only, asserted by a test — it runs in someone
else's pipeline, which is exactly where a dependency hurts.
