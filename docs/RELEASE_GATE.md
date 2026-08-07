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
    --gate --gate-policy gate-policy.json --gate-baseline gate-baseline.json
```

Everything is evaluated and reported exactly as it will be when enforced, but the
exit code is always `0`. Use the time to confirm the baseline is right and that the
gate is not blocking on anything absurd.

### 3. Enforce

Drop `warn_only`. Optionally scope to the transport:

```bash
python sap_scanner.py --data-dir ./exports --abap-src ./abapgit_export \
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
a licence to ship. Use `exempt_checks` offline, or run the gate against the server.

---

## It never fails open

If coverage was degraded, the answer is `2` — never `0`.

The ABAP scanner reports lost lexer state as an `ABAP-LEX-001` finding, and the gate
reads that same evidence rather than a side channel. An unreadable or misspelled
policy is also `2`: a typo in a config file must not quietly disarm the gate.

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
