# Decisions D1–D8

The eight decisions the platform-coverage plan reserved for the owner, answered.

**The brief that settled them:** *MonitorRisk must run in both offline mode and
online connected mode within an SAP instance.* That sentence does most of the
work below. It reverses the plan's recommendation on D2, reframes D3, and raises
the bar on D4 — and it leaves D1, D5, D6, D7 and D8 where the plan put them.

Each decision names the sites that change. Where a decision rests on something
this repository has not verified against a primary source, it says so; the
grading convention is the plan's own — **verified** (fetched and read),
**asserted** (claimed, not re-checked here), **inferred** (reasoning).

---

## The shape the brief implies

"Offline **and** connected" could be built two ways, and only one of them
survives contact with this codebase's charter.

The tempting one is a live client inside the product: `modules/` grows an HTTP
path, findings come either from a file or from a socket, and every module learns
two ways to get its input. That doubles the state space of every check, puts
network I/O behind a stdlib-only boundary, and makes the offline path — the thing
customers actually buy — the less-tested of the two.

The one taken here keeps a single ingestion path and moves the network outside
it:

```
online   SAP instance ──HTTPS──> collect/ ──writes──> extract files ──> DataLoader ──> modules/
offline  customer's own export ─────────────────────> extract files ──> DataLoader ──> modules/
```

A connector is a **third producer of an artefact that already exists**, beside
the customer's manual export and SAP's own tooling. Both modes converge before
the first check runs, so connected mode inherits every test the offline path
already has, and `modules/` never learns that a network exists.

This is what makes "both modes" affordable rather than a second product.

---

## D1 — Does SuccessFactors leave the non-goals list?

**Decided: yes, qualified. Split the row.** SuccessFactors moves in scope as
*offline-first, security surface only*. BusinessObjects stays declined.

Two sites list them together with one reason, *"API-only and offline-hostile"*:
[`docs/BUILD_ROADMAP.md:538`](BUILD_ROADMAP.md), and
[`docs/COMPETITIVE_ANALYSIS.md:465`](COMPETITIVE_ANALYSIS.md). Two more name them
in passing: `CLAUDE.md:784` and `docs/PIVOT_PLAN.md:367`.

The stated reason is **rebutted, not deleted**. Half of it was always about
access rather than surface, and connected mode answers that half directly:
SuccessFactors exposes OData and SCIM over HTTPS, so a `collect/` connector can
produce the extract the customer would otherwise assemble by hand. The other
half — whether enough of the surface is *security configuration* rather than
business configuration — is unchanged and still **inferred**. Offline stays the
default so that premise keeps being tested rather than assumed away.

BusinessObjects stays out on its own merits: a shrinking estate with a different
authorisation model, and no comparable API story.

> If a real SuccessFactors export shows the security surface is thinner than
> assumed, this decision should be revisited, not quietly carried.

## D2 — Does "no live API client" end?

**Decided: yes — in the out-of-process form, and recorded as a reversal.**

This is the brief's central consequence. Five sites state the prohibition, and
one of them matters more than the rest: a BTP live-OAuth scanner was **removed**
from this codebase on exactly these grounds
([`docs/CVA_MERGE_PLAN.md:404`](CVA_MERGE_PLAN.md)). Re-introducing the
capability is a reversal of a considered decision, not a resumption of something
merely unfinished, and it is recorded here as one.

What replaces the prohibition:

> **No live connector inside the product.** Connectors are an optional,
> out-of-process collector in `collect/`, whose only output is a file the
> offline path already reads. `server/` and `modules/` never import it, and
> deleting the directory leaves every test passing and the image building.

The distinction is not a technicality. The original objection —
[`docs/EXPORT_GUIDE.md`](EXPORT_GUIDE.md) (the *no live API client* passage), *"one we cannot exercise"* — was
about a client whose failures would be invisible and untestable inside a product
that could not reach a system. A collector that writes a file can be exercised
against a recorded fixture, and its output is validated by the same loader that
validates a customer's export.

Sites to amend: `docs/BUILD_ROADMAP.md:460`, `docs/EXPORT_GUIDE.md:440`,
`modules/btp_import.py:22`, `modules/abap_sast_rules.py:29`,
`docs/CVA_MERGE_PLAN.md:160` and `:404`, and `README.md:1640` — which currently
tells users the tool "does not connect to or modify any SAP system". The
*modify* half stays true and absolute. The *connect* half becomes conditional
and must say so.

`CLAUDE.md`'s *"no live connection is needed in either mode"* survives
unchanged — **needed** stays exactly true, and that is the property worth
keeping.

> **Built.** `collect/` exists, is stdlib-only, is covered by the `purity` CI job,
> and `tests/test_collect.py` asserts that nothing in `server/` or `modules/`
> imports it and that `sap_scanner.py` has grown no `--connect` flag. The first
> connector speaks sapstartsrv over SOAP; see D3 for what that reaches.

## D3 — Is RFC declined permanently?

**Decided: RFC is declined. Connected mode is delivered over HTTPS instead.**

These are two different questions that the plan's framing risked merging, and
the brief only requires an answer to the second.

Declining RFC rests on one architectural fact that needs no external
verification: the SAP NetWeaver RFC SDK cannot be redistributed inside the
image, so a customer would need an S-user and a mounted SDK before the container
starts. That destroys the one-container property — and it would do so for *every*
user, including the majority who only ever scan offline.

The plan's supporting claim — that PyRFC was archived and its PyPI releases
yanked — remains **asserted** here, not re-verified. The decision does not depend
on it, and should not be written up as if it did.

What connected mode uses instead, all over HTTP(S):

| surface | transport | feeds |
|---|---|---|
| Profile / instance parameters | SAPControl SOAP web service | `security_params`, `baseline_params` |
| Users, roles, authorisations | **RFC only** — see the Since-built note below | `user_auth_audit`, `s4_business_authz` |
| Landscape configuration | SolMan / Focused Run CCDB | multi-system ingest |
| SaaS tenants | vendor REST / SCIM | the Phase 6–7 modules |

**Named rather than absorbed:** some surfaces are genuinely RFC-only, and
connected mode will not reach them. Those stay export-only, and the export guide
must say which they are. "Connected mode" must never be allowed to imply
"complete without an export" — that is the same silent-coverage failure the
release gate now refuses.

> **Built, for the first row of that table.** `python -m collect sapcontrol`
> reaches an ABAP instance's profile parameters over the sapstartsrv SOAP
> interface — no SDK, no ABAP component, no dependency — and writes
> `security_params.csv` in the shape the offline loader already reads. Verified
> end to end: collect → load → scan → findings, with the scanner unable to tell
> the result from a hand-made export.
>
> **The RFC-only remainder is now written down**, which D3 required before
> connected mode could be called documentable: 14 logical sources, listed in
> `collect/extract.py` as `SAPCONTROL_CANNOT_REACH`, restated in every run's
> `collection_manifest.json`, and tabulated in the export guide. `partial` is
> hard-coded `true` in that manifest and is not a field any caller can set,
> because a connected collection is partial by construction rather than by
> circumstance.
>
> The endpoint is also *itself* a security observation: `--probe-only` reports
> whether the instance answers a read with no credentials at all, which is
> governed by `service/protectedwebmethods` (SAP Note 927637, SAP Note 1439348 —
> cited as pointers, not quoted).
>
> **Second connector: `python -m collect icf`.** Probes a fixed list of documented
> ICF paths and writes `icf_services.csv`, plus the Gateway OData catalogue as
> `api_endpoints.json`. The probe is deliberately anonymous — a credential would
> turn a 401 into a 200 and record a protected service as open — and redirects are
> recorded rather than followed for the same reason.
>
> **It does NOT reach users and roles, and that corrects an earlier claim in this
> document's own history.** This connector was scoped as "the one that gets users
> and roles". There is no standard pre-built OData service on ECC exposing
> `USR02` or `AGR_USERS`, and Gateway exposes only what an administrator
> activated. Those four sources head `ICF_CANNOT_REACH` in `collect/extract.py`
> and a test asserts they stay there, so a future edit cannot quietly start
> claiming otherwise.
>
> The manifest accumulates across collectors rather than being overwritten: a
> directory built from two collections now has a record describing two, which the
> first draft got wrong.

> **Since built — and the asserted claim is now verified.**
>
> **PyRFC is archived and yanked.** The repository was archived on 28 May 2026 and
> the PyPI releases carry a yank reason of "No longer supported", so `pip install
> pyrfc` fails without an exact version pin. SAP discontinued it for want of a
> maintainer with access to the SDK source, and discontinued the Node.js and other
> bindings at the same time — SAP has exited RFC language bindings, not just the
> Python one. There is no official replacement. This decision recorded that claim
> as **asserted**; it is now **verified**, and it is worse than it read.
>
> **The decision holds, and an RFC collector was still built** — because the two
> are not in conflict. What D3 declined was making RFC a REQUIREMENT: an SDK the
> image cannot carry, mounted before the container starts, for every user
> including the majority who only scan offline. `collect/rfc.py` is not that. It is
> optional, out-of-process and customer-installed, exactly like the other two
> collectors, and the image is byte-identical whether or not it exists.
>
> **It depends on no binding at all.** Building the most sensitive collector in a
> security product on an archived, yanked package that will never receive another
> patch is not a trade worth making, so the SDK is bound directly through `ctypes`
> — standard library. The dependency count does not move and there is no upstream
> left to rot.
>
> **What the customer still supplies is unchanged:** the SDK itself, under their
> own S-user licence. That fact is what this decision rests on and nothing about
> it has changed. It has simply moved from being a precondition for everyone to a
> precondition for the customers who want the sixteen sources HTTPS cannot reach.
>
> **The table above said ICF reaches users, roles and authorisations. It does
> not** — `users`, `profiles`, `roles` and `role_profiles` head `ICF_CANNOT_REACH`
> in `collect/extract.py`, and D3's own built-note said so while the table went
> uncorrected. That row is fixed above.
>
> **An RFC connection is not a complete export either.** `collect/rfc_tables.py`
> declares six sources it still cannot produce — gateway ACL files, audit-log
> configuration, TMS routes and others — with a reason for each, and the manifest
> reports them the way the other collectors report theirs.

## D4 — Does the four-dependency rule extend to `collect/`?

**Decided: the rule binds `server/` and `modules/`. `collect/` is separate — and
targets stdlib-only anyway.**

The plan's recommendation was that `collect/` carry its own requirements. Having
settled D3 on HTTPS, that allowance is mostly unnecessary: `urllib.request`,
`ssl`, `xml.etree` and `json` cover SOAP, OData, SCIM and REST. A connector tier
with *no* dependencies is a stronger position than one with its own, and it keeps
`collect/` reviewable under the same standard as the rest of the codebase.

So the allowance exists but is not spent by default. Three mechanical guards:

1. `purity` extends to `collect/` as stdlib-only.
2. A test asserts `server/` and `modules/` never import `collect/`.
3. The test asserting the runtime dependency list verbatim stays **exactly** as
   it is. It is the thing that makes the charter real.

## D5 — Does ECC coverage change the product's positioning?

**Decided: both, and in that order.** *"Works where agents cannot — connects
where they can."*

The offline model was adopted because RISE customers cannot grant access, and on
that estate it remains the differentiator. ECC and on-prem customers usually
*can* grant access, so there the wedge is differentiation of **content**, not of
access — and connected mode removes the export-friction objection that would
otherwise cost the deal before the content is ever seen.

Offline leads because it is the harder property and the one competitors cannot
match. Connected mode follows because on half the addressable estate, export
friction is the actual obstacle.

## D6 — AnyDB: common core, or declined out loud?

**Decided: declined explicitly, in the export guide.**

`hana_db_security.py` is 55 KB for one engine; Oracle, Db2, SQL Server and ASE
are four more. Revisit only with a deliberately scoped common core — privileged
accounts, audit, encryption at rest, roughly six checks per engine — and cost it
as four modules, never as one.

Silence here reads as coverage that does not exist, which is the failure mode
this product exists to refuse.

## D7 — Naming the ECC-in-RISE deployment mode

**Decided: `rise_ecc`. Never `ecc_rise`.** *Verified in this repository, not
taken from the plan:*

```
modules/user_auth_audit.py:250    return self.deployment_mode().startswith("rise")
server/coverage.py:141            rise = deployment_mode.startswith("rise")
server/enrich.py:156              if not deployment_mode.startswith("rise"):
server/enrich.py:194              if not deployment_mode.startswith("rise"):
```

Four live branches. `ecc_rise` would silently disable every ECS rule for a system
contractually bound by them, **without failing a single test** — the exact
signature of the defects fixed this week.

Because the vocabulary is declared in six places across three languages, adding a
fourth value in five of them is the same class of hazard. D7 is therefore
implemented as a single source of truth plus an agreement test, not as five
string edits. See `modules/deployment_modes.py`.

## D8 — Is a SaaS tenant a system or a landscape?

**Decided: a `sap_system` row** carrying a platform and an external key. Not a
landscape.

A landscape is the customer's estate; a tenant is a thing inside it that findings
attach to. Modelling a tenant as a landscape would fork every query that already
scopes by system.

The blocking defect is real and was **reproduced** before deciding:

```
compute_fingerprint('SF-PWD-001', None, None, …)  -> 99cf1b82…0670
compute_fingerprint('SF-PWD-001', '',   '',   …)  -> 99cf1b82…0670   identical
```

`sap_system.sid` and `.client` are both `NOT NULL` with `UNIQUE (landscape_id,
sid, client)`, and `compute_fingerprint` normalises a missing SID to the empty
string. So two tenants with no SID cannot both exist as systems, and under
`UNIQUE (landscape_id, fingerprint)` (`server/schema.sql:237`) one tenant's
finding **overwrites** the other's rather than creating a row — silently, and in
the direction that loses data. Worse than losing a row: the finding lookup
(`server/ingest.py:343`) keys on `(landscape_id, fingerprint)` with no
`system_id` term, so tenant B's evidence is **attributed to tenant A's finding**.

### The first design was wrong. Here is what replaced it.

The obvious implementation — route the tenant's external key through
`compute_fingerprint`'s existing `system` parameter — **does not work**, and it
fails silently. Measured against the live module:

```
tenant key via the run-level `system` argument   faa556b8… / faa556b8…  COLLIDE
tenant key named by the OBJECT   ({"system": …}) a300405c… / c26b8cef…  distinct
tenant key named by the FINDING  ({"system": …}) 28f01c0e… / d70a1142…  distinct
```

The cause is this morning's cloud-scope fix, working exactly as intended:
`fingerprint_finding` deliberately discards the **run-level** system for
object-scoped findings whose objects are all cloud-typed — which is precisely the
shape a SaaS tenant produces. The exemption discriminates on **provenance, not
value**: it suppresses a *borrowed* ABAP SID and never suppresses a system the
finding or object states for itself (`server/identity.py:442`, evaluated before
the guard is consulted).

So the two goals are compatible, but only through one channel:

| goal | mechanism |
|---|---|
| one identity across the ABAP systems a cloud bundle is uploaded beside | drop the borrowed run default (already built) |
| two tenants must never share an identity | the tenant names its own scope |

**The tenant key must arrive as `finding["system"]` or `AffectedObject.system`.**
It must never arrive as the run default. This is already pinned by
`test_a_cloud_object_that_names_its_own_system_keeps_it_in_the_fingerprint`.

### Backward compatibility is achievable, and is a hard requirement

`finding.fingerprint` is **persisted**, never recomputed, under `UNIQUE
(landscape_id, fingerprint)`. `FINGERPRINT_SCHEMA` is the first field of the
canonical string and there is no machinery to migrate across a bump — `_rebase`
carries history across a change of *basis*, not of *schema*. So a change to the
canonical string re-identifies every stored finding, and on the next upload every
existing finding reads as `resolved` with an identical one appearing as `new`:
the whole mitigation journey resets, for every customer.

The condition for avoiding that is exact — the canonical string for an ABAP
finding must be **byte-identical**, so the tenant discriminator has to be carried
in the existing `sid` slot by a self-named scope, **not** appended as a new
component. Appending a sixth field changes every fingerprint even when it is
empty.

### Schema hazards, each reproduced against PostgreSQL 16

The migration is not the same shape as D7's, and four of these have no precedent
in the file:

1. `ADD COLUMN IF NOT EXISTS` with an **inline** `CHECK` has the same silent-no-op
   trap as `CREATE TABLE IF NOT EXISTS` — and the warning in `schema.sql` names
   only the latter. Two live instances already exist (`taint_confidence`,
   `reachability`); neither list can be widened on a deployed database. The
   `platform` CHECK must be a named DROP/ADD pair.
2. `CREATE UNIQUE INDEX IF NOT EXISTS` is idempotent **by name only** — the
   definition is never compared. The only correct idempotent form is
   unconditional `DROP INDEX IF EXISTS` then `CREATE`.
3. `UNIQUE (landscape_id, sid, client)` is constraint-backed, so `DROP INDEX`
   cannot remove it; it needs `DROP CONSTRAINT sap_system_landscape_id_sid_client_key`,
   an auto-generated name written nowhere in the repository.
4. Replacing that constraint with a partial index breaks `cmd_add_system`
   (`server/cli.py:239`) at runtime with **42P10** — `ON CONFLICT (cols)` cannot
   infer a partial index unless the statement repeats the predicate.
5. A discriminator written `sid IS NOT NULL` **does not fix the collision**: a row
   with `sid = ''` satisfies it and normalises to the same canonical string. It
   must demand `sid <> ''`. Such rows are insertable today — `add-system` takes
   `sid` positionally with no validation.
6. Partial unique indexes are `NULLS DISTINCT` by default, so they permit
   unlimited NULL-keyed duplicates. The discriminator CHECK is therefore
   load-bearing for uniqueness, not documentary.
7. `db.init_schema` runs the file in **one transaction**; the CI job runs it under
   `psql` **statement-per-transaction**. A CHECK that fails on existing data
   therefore leaves production untouched and CI half-migrated. The migration needs
   an explicit pre-step that normalises or rejects `sid = ''`.

The `schema-upgrade` CI job could not catch any of this: it inserted one row into
`landscape` and none into `sap_system`, and its only assertion was hardcoded to
`deployment_mode`.

> **Since built.** The job now seeds an ABAP system, asserts that row survives the
> upgrade byte-for-byte, checks column nullability and the tenant index
> *definition* (not merely its existence), and exercises behaviour — five row
> shapes that must be refused, two tenants that must be accepted, and the
> `ON CONFLICT` arbiter that must still resolve. Its constraint assertion is no
> longer hardcoded to one column.

### Also uncovered, and in scope for D8

`_CLOUD_SCOPED_TYPES` held 11 types. Six more were registered as case-bearing
cloud entities and were **not** exempt — `btp_destination`, `btp_service`,
`cc_backend`, `cpi_credential`, `event_queue`, `ias_application` — so each still
took its identity from whichever ABAP SID it was uploaded beside. That is the same
defect the cloud-scope fix addressed, for six more types.

> **Since built.** All six are in the set, which now holds 17, and
> `tests/test_identity.py` requires every case-bearing type to carry a deliberate
> cloud-or-system classification — so the next one cannot default into borrowing
> a SID.

`certificate` is deliberately **excluded** from that list: an ABAP STRUST
certificate genuinely is system-scoped, so the set cannot be widened
mechanically. This is why the morning's structural test — "every type in the set
is exempt on both sides" — did not catch it: it holds the set consistent, not
complete.

---

## What this does not decide

- **Whether connected mode is worth building before Phase 1.** It is not. The
  ECC fixture and the per-module split still come first, because they are the
  only cheap way to find out whether the ECC estimate holds.
- **Which SaaS products get connectors.** D1 admits SuccessFactors to the
  roadmap; it does not schedule a connector for it.
- **The RFC-only surface list.** D3 requires it to be written down. It is not
  written down yet, and until it is, connected mode is not documentable as
  complete.
