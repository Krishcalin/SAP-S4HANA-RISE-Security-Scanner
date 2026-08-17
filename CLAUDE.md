# CLAUDE.md — SAP S/4HANA RISE Security Scanner

Guidance for Claude Code (and humans) working in this repository.

## What this is

An **offline SAP S/4HANA RISE + BTP security config-review tool**, in two modes over one
scanner core:

1. **CLI** (`sap_scanner.py`) — reads exports from a `--data-dir`, runs the auditor modules,
   writes **HTML / PDF / PPTX**. Single-shot and stateless.
2. **Server** (`server/`) — the same modules behind a browser console backed by
   **PostgreSQL 16**. Uploads are scanned automatically, findings persist, and re-uploads over
   time track the **mitigation journey**.

No live system / RFC connection is needed in either mode — ideal for RISE, where the customer
contractually has no OS access and a third-party ABAP add-on is an Excluded Task.

### ⚠️ The charter changed (2026-08-05) — read this before adding a dependency

The founding rule was *zero external dependencies, stdlib only*. That rule **ended when the
product became client-server**, deliberately and one-way. It has NOT been relaxed everywhere:

- **`modules/` and `sap_scanner.py` remain standard library only.** The HTML, PDF and PPTX
  engines are hand-built. Do **not** add `reportlab` / `python-pptx` / `pandas`.
- **`server/` may use the four pinned runtime dependencies** in `requirements.txt` (FastAPI,
  uvicorn, psycopg, python-multipart) and nothing else without a decision. It was five;
  **Jinja2 left on 2026-08-09** with the server-rendered console, and nothing replaced it.
- The discipline replacing "zero deps" is a **single-digit runtime dependency count**. Also
  deliberately absent, and to stay absent: an **ORM** (SQL is hand-written and reviewed) and a
  **graph database** (recursive CTEs are ample at SAP landscape scale).
- **The client-side framework ban ended on 2026-08-08, and only it.** The console migrated
  from 13 Jinja templates to a **React + TypeScript SPA in `frontend/`**, compiled by Vite at
  **build time** into `server/spa/` and served as static files by the **same FastAPI process**
  (`SpaFiles` in `server/app.py`). React, Vite and TypeScript are **build-time** dependencies:
  the RUNTIME list in `requirements.txt` went DOWN. The frontend's own budget is equally
  tight — react, react-dom, react-router, lucide-react, vite, typescript, tailwind. No state
  library, no component library, no data-fetching library, no chart library.
- **`collect/` is new (2026-08-11) and is stdlib-only too — by choice, not by rule.**
  Decision D4 *permits* the connector tier its own requirements and it spends none:
  `urllib`, `ssl` and `xml.etree` cover SOAP, OData, SCIM and REST, so a customer running a
  connector against their own SAP system installs nothing. The `purity` CI job now covers
  `collect/` as well as `modules/`, because an allowance that is not taken is only real if
  something checks.
- The deployment is **one app container + one PostgreSQL**. A third service — a Node server, an
  nginx — is a design failure, not a feature; it forfeits the product's clearest structural
  advantage over competitors that need a console VM plus sensors. The SPA is built inside the
  `Dockerfile`'s first stage and nothing JavaScript survives into the runtime image.
- **The Jinja console is retired (2026-08-09).** It owned `/`, `/findings`, `/paths` and the
  rest while the SPA sat at `/ui`, so a half-finished migration could not strand the product.
  Every screen landed, so `server/templates/` and its 13 page routes were deleted and the SPA
  took the root: `SPA_MOUNT_PATH` and vite's `base` are both `/`, and a test asserts they agree.
  Three things that read like part of that console stayed, because none of them was one —
  `/static` (brand assets the compiled `index.html` names by absolute path), `/health`
  (operational), and `/v/{slug}`, which is now a **console** route because the SPA declares the
  same path. `/ui/*` answers **301** to the same path without the prefix, because those URLs
  are in bookmarks and tickets. See `frontend/README.md` and `tests/test_spa_mount.py`.
- **The SPA mount is registered LAST in `server/app.py`, and that is load-bearing.** A Mount at
  `/` matches every path and Starlette takes the first match, so anything declared after it is
  dead — silently, with a 200 and a page of HTML. New routes go **above** it.

Background and the full plan: [`docs/PIVOT_PLAN.md`](docs/PIVOT_PLAN.md),
[`docs/BUILD_ROADMAP.md`](docs/BUILD_ROADMAP.md).
- **~600 checks across 30 audit modules.** Measure, never estimate — and know which number you
  are quoting. `modules/` holds 50 files, of which **30 emit findings**; the other 20 are rule
  tables, loaders, importers and report writers. Those 30 are exactly `sap_scanner.py`'s
  `--modules` choices. Check IDs: **363** are written as literals, and **621** exist once the
  five runtime-generated families resolve against their shipped rulesets — `PARAM-<param>` (78),
  the SAST rule ids (133), `ARA-<risk>` (27), `IAM-<sod_rule>` (10) and `ATC-<family>` (10),
  which do not overlap the static set at all.
  ⚠️ **Counting `self.finding(` alone undercounts by 29** and silently misses every `AUTH-*`
  and `BASELINE-*` id: `abap_authorizations._emit` and `baseline_params._flag` forward
  `check_id` positionally into `finding()`. Include both wrappers or your number is wrong.
  Keep the README badge and `docs/CHECKS_REFERENCE.md` in sync when you add checks —
  `docs/CHECKS_REFERENCE.md` is GENERATED from the code by
  `tools/build_checks_reference.py`, and the `purity` CI job fails if it drifts.
  It covers all 618 ids — 363 literal plus 255 from five runtime families —
  and renders a title or severity the code computes per finding as *varies*
  rather than freezing one branch as fact. Do not hand-edit it; change the
  check and regenerate.
  **MODULES** → each emits severity-ranked findings (**CHECKS** → **RANK**) → a **REPORT** is
  written.
  ⚠️ **`docs/banner.svg` is stale and nothing checks it** — it still reads *v2.0, 19 MODULES ·
  278+ CHECKS*. It is referenced by this file only; the README's banner is
  `assets/monitorrisk-logo.png`. Refresh it or retire it; do not cite its numbers.
- **Reports** (`--format html|pdf|pptx|both|all`, `--pptx-mode full|summary`):
  `report_generator.py` (light-themed HTML dashboard, MonitorRisk + SAP branding),
  `pdf_report.py` (multi-page hand-over PDF on the stdlib `pdf_writer.py` engine), and
  `pptx_report.py` (PowerPoint deck on the stdlib `pptx_writer.py` OOXML engine — one slide
  per finding in `full` mode). **All three engines are pure standard library** — do not add
  `reportlab` / `python-pptx`. The HTML and PDF are ordered *priority queue → categories →
  compliance mapping → fix-first findings*; `risk_prioritizer.py` computes the P1–P4 order and
  `compliance_mapping.py` maps categories to **eight** frameworks — ISO/IEC 27001:2022,
  NIST CSF 2.0, **NIST SP 800-53 Rev 5**, **DORA (EU 2022/2554)**, CIS Controls v8,
  TISAX/VDA ISA, SOC 2 and EU GDPR. Each finding renders its detailed **Security Risk** narrative +
  step-by-step **Remediation** from the findings knowledge base (`finding_kb.py` loading
  `data/finding_details.json`, keyed by check-id with family-prefix fallback), falling back
  to the finding's own `description`/`remediation` when no KB entry exists. When you add
  checks, add matching KB entries so the hand-over report stays detailed. Report logos live in
  `assets/` and are embedded as base64 data URIs so reports stay self-contained/offline.

## Run it

```bash
python sap_scanner.py --data-dir ./sample_data --output report.html            # all modules
python sap_scanner.py --data-dir ./sample_data --output report.html --modules hanadb authz
python sap_scanner.py --data-dir ./exports --output report.html --severity HIGH  # min severity
python sap_scanner.py --data-dir ./sample_data --output report.pdf  --format pdf   # PDF hand-over
python sap_scanner.py --data-dir ./sample_data --output report.pptx --format pptx  # PPTX deck (full)
python sap_scanner.py --data-dir ./sample_data --output report.html --format all   # HTML + PDF + PPTX
python sap_scanner.py --data-dir ./sample_data --output report.html --format both --crq \
    --crq-revenue 2000000000 --crq-industry manufacturing --crq-org-name "Acme Mfg"   # + FAIR $ loss exposure
python sap_scanner.py --data-dir ./exports --abap-src ./abapgit_export --modules cva   # ABAP source scan
python sap_scanner.py --data-dir ./exports --cap-src ./bookshop --modules capxsuaa     # CAP project scan
python sap_scanner.py --data-dir ./exports --deployment-mode rise_pce                  # ECS rules apply
python sap_scanner.py --data-dir ./exports --gate --gate-baseline gate-baseline.json   # decide: exit 0/1/2
```

**The Windows redirection crash is fixed — do not re-introduce it, and do not delete the
guard.** `banner()` prints box-drawing characters (`╔═╗`). An interactive Windows console
negotiates UTF-8, but the moment stdout is a pipe or a file Python falls back to the ANSI code
page and those characters raised `UnicodeEncodeError` before any work started — with a
traceback naming an encodings module, so it read like a broken install. `_make_output_encoding_safe()`
now reconfigures stdout/stderr at import (`sap_scanner.py`), so `PYTHONIOENCODING=utf-8` is no
longer needed. This is load-bearing for the **release gate** specifically: CI always redirects
stdout, so on a Windows agent the scanner used to die before it reached the gate, and a control
that cannot run under redirection is not a control.
`tests/test_release_gate.py::test_the_scanner_survives_having_its_output_redirected` pins it.

### Server mode

```bash
cp .env.example .env          # then set SESSION_SECRET (>=32 chars) and POSTGRES_PASSWORD
docker compose up -d --build
docker compose exec app python -m server.cli init-db
docker compose exec app python -m server.cli create-user admin admin --generate
docker compose exec app python -m server.cli add-landscape "Acme Prod" --mode rise_pce

# scan without a browser (air-gapped path)
python -m server.cli scan "Acme Prod" ./sample_data --sid PRD --client 100
python -m server.cli runs

# the way back in when nobody can sign in
docker compose exec app python -m server.cli set-password admin --generate

# second factor: who has one, and is this deployment still recoverable
docker compose exec app python -m server.cli totp-status
docker compose exec app python -m server.cli totp-disable admin   # lost phone
```

`DB_DSN` and `SESSION_SECRET` have **no defaults** — a deployment that forgets them must fail
at startup rather than silently run on a value published in this repo.

### Two-factor authentication (TOTP)

Opt-in per user, enrolled from **Your account**. Added 2026-08-11 after an
adversarial design review that rejected the first design outright — the notes
below are the parts that review changed, and each one is a defect that was in the
plan before it was in the code.

**Zero new runtime dependencies.** `server/totp.py` (RFC 6238) and `server/qr.py`
(byte-mode QR → inline SVG) are standard library only, because `requirements.txt`
holds four packages and `tests/test_spa_mount.py` asserts that list verbatim.
`pyotp` and `qrcode` would be a fifth and sixth. Both are ports of the same
approach in the sibling OverWatch codebase, which reached the same conclusion.

**Correctness is checked against published vectors, never against itself.**
`tests/test_totp.py` asserts RFC 6238 Appendix B; `tests/test_qr.py` asserts
ISO/IEC 18004's Reed-Solomon worked example and its level-M format-information
table. A hand-rolled OTP or QR implementation can be perfectly self-consistent and
interoperate with nothing — round-tripping proves only that two halves share a
bug. Both suites are stdlib-only and therefore run in the `cli` CI job too.

⚠️ **SHA-1 is deliberate.** Microsoft and Google Authenticator ignore the
`algorithm=` parameter and assume it; advertising SHA-256 produces codes that never
match, which users experience as "the app is broken".

⚠️ **`totp.verify()` must be called from `server/auth.py` and nowhere else.** It
returns the matched COUNTER, not a bool, so the caller can persist it and refuse a
replay. A route calling it directly gets a truthy value, a working login, and a
silently skipped counter advance — leaving a code replayable for up to 90 seconds.

**Storage is `app_totp`, a separate table, never columns on `app_user`.**
`resolve_session` selects `u.*` and `api_account` does `SELECT *`, so a column
there rides into every handler's `current_user`. More importantly `secret` and
`pending_secret` are DISTINCT: with one column, `begin` must overwrite the live
secret to offer a new QR, so a stolen session could swap the factor into the
attacker's own authenticator or clear it and downgrade the account to
password-only.

**Both authorisations are conditional UPDATEs, not read-then-write.**
`UPDATE app_totp SET last_counter=%s WHERE user_id=%s AND last_counter < %s
RETURNING` and the equivalent on `recovery_code.used_at`. The returned row IS the
proof. `tests/test_totp_auth.py` fires eight simultaneous logins with one code and
asserts exactly one 200 and exactly one session row — a read-then-write
implementation passes every sequential test and fails that one.

**The attempt budget lives in `auth_attempt`** — three self-clearing counters
(`ip:` 30, `pw:` 10, `2fa:` 5, per 15 minutes), keyed on the username **as
submitted** and checked BEFORE any PBKDF2. Never a 429, never "try again in N
minutes": an over-budget refusal is byte-identical to a wrong password, or it is
an oracle. Nothing here ever sets `is_active = false` — a lockout an admin must
lift is how rate limiting gets removed rather than tuned.

**`totp_required` may only appear after the password verifies.** Before that every
branch answers `{"detail": "Invalid credentials"}`, or the login route hands out a
map of which accounts are worth phishing.

**Recovery codes are 16 characters** (~2⁷⁹) because `recovery_fingerprint` is a
single unsalted SHA-256 round — defensible only for genuinely high-entropy input.
At the original ten they were ~2⁴⁹·⁵ and a leaked table fell to a GPU in minutes.
They are accepted in the SAME field as a TOTP code on `/api/auth/login`,
`/totp/disable` and `/totp/recovery`; without that last one, somebody who signed in
with a recovery code could log in and never fix the state they were in.
`auth.set_password` deletes unused ones — they are credentials on paper, and a
password change is what somebody does when they think a credential leaked.

**`_ALLOWED_WHILE_FORCED` is an EXACT-PATH frozenset.** It was a prefix tuple
matched with `startswith`, which silently exempted every `/api/account/totp/*`
route the day it was written — letting an account still on a generated password
bind a second factor to it.

**The lost-device escape hatch is `server.cli totp-disable` / `totp-status`,** and
it is the counterpart to having no self-service reset. `set-password` now warns
when the target still has a factor, because it is the command the account screen
names and it reported success while the user still could not sign in.
`totp-status` prints `last_counter` as wall-clock: a clock that jumped forward
leaves the replay floor in the future and refuses every correct code, which is
otherwise undiagnosable.

**Out of scope, deliberately:** encrypting the seed at rest (the only key material
is `SESSION_SECRET`, so binding to it converts a free rotation into silent mass
lockout; the response to a suspected dump is `totp-disable` and re-enrol), any
mandatory or admin-enforced 2FA policy, an HTTP route for an admin to clear
someone else's factor, WebAuthn, and SMS or email codes.

### Branding

The web console is **MonitorRisk**. `tests/test_branding.py` asserts the retired names
(`SAPSec`, `SAP Security Platform`) appear nowhere in `frontend/src`, so a NEW screen that
ships with an old name fails too.

The tab-title assertion got **stronger** when the templates went, and the reason is worth
keeping. Thirteen Jinja templates each declared their own `{% block title %}`; a SPA has one
`index.html` and therefore one `<title>`, so without deliberate work the whole console renders
as thirteen identical tabs — invisible in a screenshot, and ruinous for the tab strip, the
history menu and every bookmark. The brand is appended in one place (`frontend/src/lib/title.ts`)
and the test asserts both that it brands the tab **and that every screen calls it**.

Brand assets are **derived, not drawn**. `docs/brand/monitorrisk-master.png` is the
supplied artwork; `server/static/*` **and** `assets/monitorrisk-logo.png` are generated
from it:

```bash
python tools/build_brand_assets.py            # rebuild
python tools/build_brand_assets.py --check    # fail if the committed assets drift
```

That tool needs Pillow. It is a build-time dependency and is deliberately NOT in
`requirements.txt` — the container never runs it, and the derived PNGs are committed so
a deployment needs nothing but the repo. The runtime dependency count stays at four;
`StaticFiles` ships inside Starlette, which FastAPI already pulls in.

**Both destinations are derived, since 2026-08-10.** `server/static/` is what the console
serves and `assets/` is what the CLI reports embed; they were the same bytes *by hand*,
with nothing enforcing it. `--check` covers both and ignores `assets/sap-logo.png`, which
is SAP's and is not derived.

### ⚠️ The artwork changed on 2026-08-10, and the old treatment would have destroyed it

The previous master was navy-and-blue ink on a flat **cream** field. That cream was
incidental packaging, so the build keyed it out and shipped transparent ink. **The current
master is different in kind.** Measure it before touching `tools/build_brand_assets.py`:

    "Monitor", the shield, the tagline   navy   #0b246a
    "Risk"                               WHITE  #ffffff     <- new
    field                                blue   #6cc2fb     <- NOT incidental

`key_out` un-mixes each pixel against the target inks, and every target is **darker** than
the field — so a white pixel projects to a negative coefficient, clamps to zero, and is
written fully transparent. **Run the old treatment over this master and the console renders
the product as "Monitor".** With a valid RGBA PNG, correct dimensions and a green suite:
the previous assertion only checked the PNG colour type, which a half-erased wordmark
passes. `tests/test_branding.py::test_the_word_risk_survived_the_asset_pipeline` now checks
the ink instead.

Adding white as a third target restores the glyphs and then meets the real constraint —
there is no page colour on which a keyed lockup reads:

| | navy | white |
|---|---|---|
| on its own blue field | 7.29:1 | 1.95:1 | ✅ both legible |
| on the dark console `#0f1419` | **1.30:1** | 18.51:1 | "Monitor" invisible |
| on a cream panel `#f3f2ee` | 12.71:1 | **1.12:1** | "Risk" invisible |

So the **lockup keeps its field** and is a self-contained brand panel, and every panel
behind it is painted the same value — `--brand-field` in `frontend/src/index.css`. The
build flattens the master's compression noise (82% of the image, ±13 levels in red) to
*exactly* that colour, which both fixes the old seam properly and takes the shipped asset
from 474 KB to 176 KB — this file is base64-**inlined** into every HTML report and embedded
in every PPTX, so its size is paid on every deliverable. A test asserts the asset and the
CSS still agree.

The **mark** is still keyed, because it has no white in it — shield outline and pulse only.

Three places consume the brand, and the differences are forced by contrast and by size:
- **Sign-in** (`Login.tsx`) — the full lockup on a `--brand-field` panel, at its natural size.
- **The homepage** (`Dashboard.tsx`, `.brand-band`) — the same lockup, height-capped at
  **80px**. That number is measured: the tagline occupies the bottom quarter of a 2.74:1
  lockup, so at 52px it renders at ~4px cap height and is a smudge, and past ~110px the band
  stops reading as a header and starts pushing the dashboard's three banners under the fold.
- **The header** (`Sidebar.tsx`) — the shield mark alone at 22px, in two variants swapped by
  `<picture>`. That `<picture>` is written "backwards" on purpose — it mirrors the
  stylesheet, where `:root` is dark and only `prefers-color-scheme: light` overrides. The
  dark variant lifts the navy to the page ink because navy on the console is 1.20:1.

`/static` is why the brand mount outlived `server/templates/`: the compiled `index.html` and
the sign-in screen name `/static/...` by **absolute path**, and the mount is deliberately
unauthenticated because a gated one shows a broken logo to everyone not yet signed in.
`tests/test_branding.py::test_the_console_asks_for_the_brand_assets_by_absolute_path` records
that reasoning so the mount is not "tidied away" later.

**One brand everywhere, since 2026-08-07.** The CLI's HTML/PDF/PPTX reports used to
carry a different vendor brand (`PhalanxCyber`) while the console said MonitorRisk —
customer-visible, in the deliverable the customer keeps. They embed
`assets/monitorrisk-logo.png`, the same lockup the console serves — and as of
2026-08-10 that is *enforced* rather than maintained by hand: one build writes both,
and `test_the_console_and_the_reports_carry_the_same_lockup` compares the bytes.
`.brand-logo` carries a 6px corner radius again, because the artwork carries its own
field once more and an unrounded rectangle reads as an image that failed to key. Still
no drop shadow: on the white report page a shadow under a light panel reads as a UI
control rather than a logo.

**Passwords never come from argv** — an argument is visible in `ps` and in shell history, so
`--password` does not exist and must not be added. `_read_password` takes a TTY prompt, a pipe,
or `--generate`. `--generate` also sets `must_change_password`: it printed the secret to a
terminal, so it now lives in scrollback and in `docker compose logs`, which makes it a handover
credential rather than a chosen one. `current_user` (now in `server/api_auth.py`) then raises
303 for such an account, and `app.py`'s `@app.exception_handler(303)` turns that into a **403**
carrying `{"detail": "password change required", "change_at": "/account"}` — for every caller,
not just `/api/*`, so the gate cannot be scripted around. There is no redirect branch left: in
a SPA the shell is static, so the gate is enforced on the **data**. Changing a password drops
every session for that user **except the caller's
own** (`set_password(..., keep_token=)`); an admin reset drops all of them, including the
target's current one. The audit log records the event and never the value.

## Architecture

- **`sap_scanner.py`** — CLI entry / orchestrator. Parses args, loads data via `DataLoader`,
  runs each selected auditor, severity-filters, and calls `ReportGenerator`. Each module is
  invoked in its own `if "<key>" in run_modules:` block.
- **`modules/base_auditor.py`** — `BaseAuditor`. Subclass it; implement
  `run_all_checks() -> list[findings]`. Create findings with:
  `self.finding(check_id, title, severity, category, description, affected_items=[],
  remediation="", references=[], details={}, affected_objects=[], subject=[], scope=None,
  system=None, client=None)`. Severity constants: `SEVERITY_CRITICAL/HIGH/MEDIUM/LOW/INFO`.
  `self.get_config(key, default)` reads baseline overrides (from `--config baseline.json`).

  **The identity kwargs are not optional extras — get them wrong and the mitigation journey
  breaks.** Read the `finding()` docstring and `server/identity.py` before touching a module.
  - `affected_objects=[{"type","name","system"?,"client"?,"qualifier"?}]` — the concrete SAP
    objects. Display strings alone cannot be graph nodes and cannot identify a finding.
  - `scope="object"` — the finding is ABOUT the named object(s); identity includes them. Four
    unlocked default users must be four findings, not one.
  - `scope="aggregate"` — the finding SUMMARISES a set ("23 dormant accounts"). Identity
    excludes the members; otherwise dismissing one member retires the finding and raises a new
    one, resetting its age **every run**. Still pass the objects — they become graph nodes.
  - `subject=[…]` — for a finding that is about ONE thing but names several ("role Z_ADMIN
    grants SAP_ALL to 41 users"): the role is identity, the users are members.
  - Types must be registered in `_UPPERCASE_TYPES` or `_CASE_SENSITIVE_TYPES` in
    `server/identity.py`, never both. Case-bearing things (ICF paths, URLs, BTP entities,
    schemas) are case-**sensitive**; SAP identifiers are not.
  - **A cloud object must also be registered in `_CLOUD_SCOPED_TYPES`.** `extract_nodes`
    stamps the run's SID onto anything that does not name its own system — right for ABAP
    objects, wrong for BTP ones. Unregistered, a BTP subaccount role became
    `role_collection:Subaccount_Admin@PRD`, filing a cloud entity under an on-premise SID, and
    a BTP `JSMITH` merged with an ABAP `JSMITH` into one node. That erases the very boundary
    the cloud-to-on-prem attack path exists to show, so **`btp_user` is deliberately distinct
    from `user`** even though the cross-system check matches them: the matching happens in
    Python and reports its result; the graph must still keep the two principals apart.
  - **Do not reach for `subject` just to make `fingerprint_basis` read `objects`.** A genuine
    aggregate is honestly `check_only`; the console presents `objects` as "structural, survives
    rewording", so mislabelling it is a claim the data does not support.
  - The cloud set must be kept **complete as well as consistent**. The structural test asserts
    every member is exempt on both the fingerprint and the node side; that says nothing about a
    type that should be a member and is not. Six were missing and each still borrowed whatever
    ABAP SID its bundle arrived beside. `tests/test_identity.py` now requires every case-bearing
    type to be **classified deliberately**, and `certificate` is deliberately NOT cloud — a
    STRUST certificate belongs to the system holding it.

  **Helpers on `BaseAuditor` that exist so a check can say "I could not tell":**
  - `param_lookup(params)` / `param_provenance(params)` — the **one** reader for a profile
    parameter export. Two modules once had their own and read different column spellings, which
    produced a HIGH finding against a system whose value was correct. A row is only judged when
    it actually carries a value column; where RSPARAM supplies a default column and leaves the
    user value blank, the default is the effective value and the provenance says so.
  - `release_gate(min, max, component)` / `skip_for_release(...)` — three answers, never two:
    `applies`, `not_applicable`, `unknown`. Folding `unknown` into either neighbour is the
    defect — one way invents findings on systems that cannot have the thing, the other quietly
    does not run and reads exactly like a pass.
  - `export_completeness(source)` / `absence_is_observable(source)` — whether anybody has
    **declared** a source complete. Named that way on purpose: the honest question is "has
    somebody said so", which is weaker than "is it complete" and must look weaker at the call
    site. Where declared, an absent row is an observation; otherwise it is a coverage gap.
  - Coverage findings carry `details={"degrades_coverage": True}`. That flag is what `--gate`
    reads to refuse a green build, so a module that knows it could not look **says so in a way
    the gate reads without being taught the check id**.
- **`modules/data_loader.py`** — `DataLoader.FILE_MAP` maps a logical data-source name to a
  list of candidate filenames. CSV → list of dicts with **headers normalized to
  UPPERCASE, spaces→underscores** and values stripped; JSON → the parsed object. Missing
  files load as `None`, so checks self-skip when their data is absent.
- **`modules/report_generator.py`** — light-themed HTML dashboard. Uses `html.escape`
  (XSS-safe) and a weighted risk score; renders the P1–P4 priority queue and the
  compliance-mapping panel. Consumes the standard `finding()` dict plus optional
  `priorities` (from `risk_prioritizer.py`). `pdf_report.py` / `pptx_report.py` consume the
  same inputs so all three formats stay consistent.
- **Report-side helpers (not auditors):** `risk_prioritizer.py` (P1–P4 tiering),
  `compliance_mapping.py` (category → framework controls), `pdf_writer.py` / `pptx_writer.py`
  (stdlib PDF / OOXML engines). Keep these in sync when a new **category** is introduced — add
  it to `compliance_mapping.CATEGORY_THEMES` so its findings map to controls, **and give it a
  home in `modules/domains.py`** (a domain, or `UNPLACED_CATEGORIES` with the reason).
  `tests/test_domains.py` fails on a category with neither.
- **THE FOUR STATES, AND THE ONE FUNCTION THAT DECIDES BETWEEN THEM.** Read this before
  touching any roll-up. Every view that summarises findings — domains, NIST CSF, FAIR-CAM, the
  trend pass rate, the resolution guard, the release gate — must distinguish four sentences,
  and no two of them may render alike:

  | state | means | who it belongs to |
  |---|---|---|
  | `assessed` | we looked and found something | — |
  | `clear` | we looked and found nothing | — |
  | `not_supplied` | we would have looked; the export never arrived | **the customer** — they can fix it |
  | `not_assessed` | we do not do this, on any run | **us** — a product boundary |

  The rule the whole product turns on: **"we could not look" must never render as "we looked
  and found nothing."** Nearly every defect fixed on 2026-08-13/14 was one instance of that
  sentence, in a different screen.

  `modules/coverage.look_verdict(feeders, manifest, require_complete=False)` is the ONLY place
  that decides. It returns three answers — `LOOKED`, `UNSUPPLIED`, `UNKNOWN` — because
  collapsing UNKNOWN into either proof is how five hand-written copies of `bool(feeders & ran)`
  drifted apart, one of them publishing 28 categories at 100% over an empty database.
  `tests/test_derivations_match_the_corpus.py` asserts the predicate is evaluated in exactly one
  place and that all five consumers route through it. **Do not re-derive it.**

  Two axes of caller choice, each stated at the call site rather than inherited:
  * **UNKNOWN** — the finding-facing callers treat it as *looked* (claiming an export was missing
    unchecked tells a customer they forgot something they did send); the pass rate treats it as
    *no rate* (its denominator comes from the code, so treating UNKNOWN as looked divides it by
    itself).
  * **`degraded`** — the CLAIM side (domains, CSF, FAIR-CAM) passes `require_complete=True`,
    because those three publish "we looked and found nothing"; the CONSEQUENCE side (the
    resolution guard, the release gate) does not, because a complete `sample_data` run has
    eleven degraded modules and the strict rule there would freeze the backlog and block every
    build.

  The category→module map is DERIVED from the source (`coverage.module_categories`,
  `module_check_ids`, `check_catalogue`), and `tests/test_derivations_match_the_corpus.py`
  holds it against what the auditors actually emit. It reads three spellings of a category
  declaration; a module using a fourth would vanish from it silently and every consumer would
  read the gap as *assume it ran*. **If that test fails, the derivation is wrong, not the test.**

- **`modules/domains.py`** — the twelve buyer-facing security domains, used by the console
  (`/domains`, the dashboard strip), the `?domain=` queue filter and one PPTX slide.
  ⚠️ **The HTML and PDF reports carry no domain section, by decision (2026-08-13)** — they are
  the long-form hand-over documents and stay simple. It shipped in the HTML for a day and was
  removed; `tests/test_domains_in_reports.py` records the decision, because re-adding it would
  look like filling a gap rather than reversing a call. **Two axes,
  and they must not be collapsed:** `reach` is what the product can *ever* see in a domain
  (author-time, same for every customer) and `state` is what a run produced. Merging them
  cannot express a configuration-only domain that came back clean, which is a real and
  sellable observation. One hard constraint, applied before any count is read: `reach == NONE`
  ⇒ `state == NOT_ASSESSED`, so *Exploit and 0-Day Protection* can never print a zero.
  Membership is a strict **partition** — one finding, one domain — and three categories are
  split by check-id prefix, each with a `prefix_default` so an unmatched id cannot fall out of
  the taxonomy silently (three did). The routing rules are emitted once by `match_terms()` and
  compiled to SQL by `server/queries._domain_clause`; never write them a second time in SQL.
  ⚠️ *Custom Code Security* is deliberately **not** called "Code Vulnerability Analyzer" —
  that is SAP's own name for a separately licensed product.
- **`modules/fair_adapter.py` + `data/fair_scenarios.json`** — optional FAIR cyber-risk
  quantification (`--crq`). The adapter maps findings onto **5 scoped SAP loss scenarios**,
  calibrates the FAIR factor ranges, emits the sibling CRQ engine's scenario JSON, and (if
  `crq_engine.py` is locatable) runs the Monte Carlo to embed a $ ALE + loss-exceedance curve
  in the HTML/PDF. **Invariants to preserve when you touch this** (all covered by
  `tests/test_fair_adapter.py`):
  - *A finding is not a risk.* Findings are **evidence that shifts a scenario's factors**;
    never give a finding its own ALE and sum them. The portfolio ALE is the **element-wise
    Monte-Carlo sum** of per-scenario draws — **never a sum of percentiles**.
  - *Calibration is range-selection, not arithmetic on CVSS/ordinals.* Worst open prevention
    finding → Resistance-Strength band; `exposed`/`exploited` (RiskPrioritizer's own flags) →
    Contact-Frequency / Probability-of-Action bands. Logging/monitoring findings are **not** a
    scenario — they set a **dwell-time loss multiplier** on the dwell-sensitive loss components.
  - *Report filters must not move the number.* FAIR always runs on the **complete** finding set
    (`fair_findings` captured before the `--severity` display filter, and passed to all
    three report generators as `full_findings` — the CSF, FAIR-CAM, compliance and
    domain roll-ups and the posture score all read it, because they describe the estate
    rather than the selection).
  - *No hard dependency on the sibling repo.* If the engine isn't found, still export the
    `*.crq.json` and degrade gracefully (summary = None).
  - *Routing lives in the catalog.* When you add a **new module**, add its `check_id` prefix (or
    category) to the right scenario's `routing` in `fair_scenarios.json`, else its findings fall
    to the `SAP-PRIV-03` fallback and the report discloses the `unrouted` count. Routing is
    prefix-first, then exact-category — so category strings must match the module's emitted
    `category` **byte-for-byte**.
  - **Loss ranges are modelled estimates from public benchmarks, not measurements** — cite real
    sources in the catalog's `sources[]`, and keep the report's "modelled estimate" disclaimer.
- **`modules/crq_engine.py`** — the FAIR Monte-Carlo engine, bundled. It exists because the
  sibling repo `fair_adapter` looks for is not present in a normal checkout, so `--crq` silently
  degraded to "inputs exported, not simulated" and produced no number at all. It is **last** in
  `_ENGINE_CANDIDATES`, so `--crq-engine`, `CRQ_ENGINE` and an external sibling engine all still
  take precedence.
  - ⚠️ **The vulnerability function is not a free choice.** `data/fair_scenarios.json` documents
    it — `clamp((TC - RS + 50) / 100, 0, 1)` — and its resistance-strength bands are calibrated
    to it (`hardened` ~0.3–0.4, `CRITICAL` ~0.8–0.85 against TC ~50–72). A plain `TC > RS`
    comparison is defensible FAIR theory and **wrong for this catalogue**: the hardened band is
    barely reachable, vulnerability collapses to ~0, and the model claims remediating everything
    drives residual risk to exactly $0. If the function ever changes, **re-calibrate the bands in
    the same commit** — `tests/test_crq_engine.py` fails if they drift apart.
  - Other invariants with tests: frequency is Poisson (a 0.3 expected frequency means "usually
    zero, sometimes one", not "0.3 of an incident"), secondary loss is **conditional** on
    escalation rather than applied to every event, and identical input yields an identical figure
    — a currency number that drifts between runs is indistinguishable from a real change in
    exposure and makes the trend chart worthless.

### The connector tier (`collect/`) — connected mode

Added 2026-08-11 by decisions D2/D3/D4. **The scanner still connects to nothing.** A
connector is a separate, optional program that reads from a system the operator authorises
and writes **the same export files the offline path already reads**:

```
online   SAP instance ──HTTPS──> collect/ ──writes──> extract files ─┐
                                                                     ├─> DataLoader ──> modules/
offline  the customer's own export ─────────────────────────────────┘
```

Both modes converge before the first check runs, which is what makes connected mode
affordable rather than a second product: it inherits the offline path's whole test suite and
`modules/` never learns a network exists.

| file | role |
|---|---|
| `web.py` | Shared HTTP. **GET-only by construction** — `fetch` has no `method` and no body parameter, so POSTing requires editing the file. One TLS policy for the package. |
| `soap.py` | Minimal SOAP, the single exception to GET-only because SOAP requires POST. Carries an **operation allowlist enforced before any byte reaches the network**. |
| `sapcontrol.py` | `python -m collect sapcontrol` — profile parameters via `ParameterValue`, over sapstartsrv on `5<NN>14`. |
| `icf.py` | `python -m collect icf` — probes documented ICF paths **anonymously** (that is what makes `AUTH_REQUIRED` mean anything) and reads the Gateway OData catalogue with credentials. |
| `extract.py` | Writes the export files, the run manifest, and `export_completeness.json`. |

**Four rules, and they are structural rather than aspirational** (`tests/test_collect.py`
asserts each):

1. **Nothing in `server/` or `modules/` may import `collect/`.** A connector imported into the
   product is a live API client inside the product, which is what D2 declined.
2. **Deleting the directory leaves every test passing and the image building.**
3. **Stdlib only** — see the charter note above.
4. **Read-only, enforced not intended.** sapstartsrv offers `Start`, `Stop`, `Restart` and OS
   command execution on the same endpoint and port. A typo must not be able to stop a
   production instance.

`sap_scanner.py` must never grow `--connect`, `--host` or `--live`; a test asserts that too.
**Connected mode is partial by construction** — RFC-only surfaces stay export-only (D3) — and
every run writes a manifest saying what it could not reach.

### The server tier (`server/`)

| file | role |
|---|---|
| `identity.py` | **The load-bearing module.** `AffectedObject`, normalization, `compute_fingerprint`, `extract_nodes`. Read its docstring before changing anything about finding identity. |
| `schema.sql` | 28 tables. Single-tenant (no `tenant_id`); `landscape` preserves the option. Idempotent — re-running it upgrades an existing deployment. |
| `db.py` | psycopg pool, `scope_clause` (**the one place** row scoping is expressed), `audit`. |
| `auth.py` | PBKDF2 passwords, sessions, ranked roles, per-system scope, password change/reset and the forced-change flag. |
| `api_auth.py` | The **only** sign-in surface: `APIRouter(prefix="/api")` serving `/auth/me`, `/auth/login`, `/auth/logout`, `/account`, `/account/password`, `/account/reset/{user_id}`. Also owns both auth dependencies — `current_user` and `require(role)` — and `SESSION_COOKIE`. Unlike the rest of the write API these take **JSON bodies, not forms**, as a CSRF control. |
| `sapcontent.py` | SAP's **own** Security Baseline vocabulary, adopted rather than reinvented: parses SAP-samples' `frun-csa-policies-best-practices` (Apache-2.0) into `data/sap_baseline_requirements.json`. We take the requirement IDs, titles, tiers and config stores; we do **not** execute SAP's SQL predicates — they run against Focused Run's CCDB, which we do not have, so claiming to run SAP's policies would be false. Rebuilt by `server.cli rebuild-sap-catalogue`; the `sap-content` CI job re-derives and fails on drift. ⚠️ Do not publish a percentage against the widely-quoted "214 control points" — parsing v2.4 yields 351 check items across 38 families, different units that do not reconcile. |
| `prose.py` | `steps` and `paragraphs`. Were Jinja filters; now the **reference implementation** that `frontend/src/routes/FindingDetail.tsx` ports line for line, with `tests/test_prose.py` as its executable spec. Change this and the TypeScript together. The findings KB authors remediation as a numbered list and risk as prose, both separated by a single `\n`; HTML collapses those to spaces, so a `<p>` turns a ten-step procedure into a wall. `steps` returns None unless the text is a clean 1..N run — an `<ol>` renumbers, so an excerpt starting at 3 must NOT become one — and the caller falls back to paragraphs. |
| `static/` | Brand assets, mounted at `/static` and deliberately UNAUTHENTICATED — the sign-in screen carries the logo, so a gated mount shows a broken image to everyone not yet signed in. The compiled `index.html` names `/static/favicon.ico` by absolute path, which is why this mount outlived `templates/`. Derived, not hand-made: see below. |
| `queries.py` | Every read of findings/runs/systems, plus assignment, bulk actions and saved views. The JSON API is now its only caller, so "everything the console shows is in the API" has stopped being a discipline — it is the only way anything renders. |
| `enrich.py` | Priority tier, owning team, **remediation owner** and SLA window. The team map is a prefix table; the ownership map is deployment-mode dependent. |
| `analytics.py` | The mitigation journey: MTTR, burndown, aging, backlog trajectory, team and domain scorecards. |
| `graph.py` | Attack paths: template instantiation, cuts, choke points, closure over time. |
| `crq.py` | FAIR quantification per run — portfolio ALE, the 5 scoped scenarios, the unrouted count, and system criticality as a calibration input. |
| `coverage.py` | The per-upload manifest. Module→source mapping is **derived from source at import**, never hand-maintained, so it cannot drift. |
| `ingest.py` | upload → parse → scan → enrich → store → diff → notify. Holds `store_run` (the journey), `_rebase` and `queue_notifications`. |
| `app.py` | FastAPI. The JSON API, uploads, cancellable background scans, `/health`, the `/ui` — `/` redirect, and the `SpaFiles` mount that serves the console. **The mount is registered last on purpose** — see the charter note above. |
| `totp.py` | RFC 6238 one-time passwords + recovery codes. **Stdlib only**, and the only file that computes a code. `verify()` returns the matched counter, not a bool — see the 2FA note above. |
| `qr.py` | Byte-mode QR encoder rendering an `otpauth://` URI as inline SVG. **Stdlib only**; `svg_or_empty` never raises out of a route, because the picture is a convenience and the typed key completes enrolment on its own. |
| `cli.py` | Admin + the air-gapped `scan` path. Subcommands: `init-db`, `create-user`, `set-password`, `add-landscape`, `add-system`, `scan`, `rebuild-sap-catalogue`, `runs`, **`totp-status`**, **`totp-disable`**. The last two are the lost-device escape hatch — see the second-factor note below. |
| `config.py` | Env-only settings. `DB_DSN` and `SESSION_SECRET` have **no defaults** and `validate()` runs at startup, so a deployment that forgets them fails loudly rather than running on a value published in this repo. |
| `spa/` | The compiled console. Build output, gitignored, produced by the `Dockerfile`'s first stage — never edited, never committed. |

**The console is tested, not only type-checked.** `cd frontend && npm test` runs vitest +
jsdom + testing-library; CI runs it in the `server` job. It exists because `tsc --noEmit`
proves the code COMPILES and says nothing about what the screen SAYS — two defects shipped
through that gap in one day, a CSF Category filed under "Assessed here" while showing the
"Export not supplied" chip, and `pct_passing ?? 0` turning an unscanned category into the
customer's worst-performing area. `??` is invisible to a type-checker by design.
**Assert the SENTENCES A READER SEES**, not state names: `expect(document.body)
.toMakeNoCleanClaim()` (in `src/test/setup.ts`) fails if a screen rendered from an
unassessed fixture says "no findings", "assessed, and", "fully assessed" or "100%".
⚠️ **Build fixtures from `api/types.ts` and never cast them.** `as CsfFunctionView`
suppresses the check and hides a real mismatch; a fixture that lies about the wire shape
tests a screen the product does not have. All three of the first fixtures written here were
wrong in that way.

**Invariants to preserve in the server tier:**
- *A finding row is never deleted.* "Resolved" is the **absence of an observation by a run that
  could have made one**. That is what lets a regression re-open the same row with its age and
  assignee intact.
  ⚠️ **The second half of that sentence is new and load-bearing.** It used to read "the absence of
  an observation in the latest run", full stop — and that is exactly the defect `3e0e00e` fixed:
  send fewer exports than last time and every finding from the missing ones was marked resolved,
  reason "not observed in this run", actor "scanner". A remediation that never happened, written
  into the journey the product is sold on and propagated into MTTR, the burndown and the
  attack-path closure counts. `server/ingest.store_run` now takes the coverage manifest and leaves
  a candidate OPEN when no module that could have produced it ran; the count comes back as
  `RunDiff.unexamined`. **The limit, stated:** this catches a module that was `skipped` or
  `not_run`, not one that ran `degraded` — per-finding source provenance does not exist to say
  which half of a partial input a finding came from, and treating degraded as blind would freeze
  most of the backlog open.
- *Degrade, never drop.* A module that raises is recorded with its traceback and the run
  continues. Losing 29 modules because the 30th hit a bad row is far worse than an incomplete
  run that says it is incomplete.
- *An empty explicit row scope means NOTHING, not everything.* `scope_clause([])` returns
  `FALSE`. Returning `TRUE` would hand a deliberately-restricted user the whole estate.
- *Coverage is recorded, not implied.* A missing export loads as `None` and its checks
  self-skip; without the manifest a partial upload produces a clean-looking report. This is a
  correctness defect, not a missing feature.
- *`_rebase` must refuse to guess.* Converting a module changes its findings' fingerprints;
  `_rebase` carries history across that only when exactly one candidate matches. Attaching one
  defect's history to another is worse than losing it.
- *`remediation_owner` is four-state* (`customer_fixable` / `ticket_to_sap` / `provider_owned`
  / `not_assessable`). In RISE the customer can see a bad parameter and cannot fix it, so a
  report that says "change this" is unactionable noise.
- *Never add an R&R line-item ID column.* Tagging checks to the SAP contract task they
  discharge is a good idea, but the published PDFs' ID-to-task pairings drift under text
  extraction and are **unverified**. Tag to the task description. See
  `docs/RISE_SECURITY_MODEL.md` §0.
- *The scanner owns severity and priority; a HUMAN owns the assignee.* A re-scan must never
  quietly undo somebody's assignment, and the SLA clock restarts only when the tier actually
  moves — recomputing the due date every run would mean nothing could ever be overdue.
- *Provider-bound work is a separate series in every metric.* A finding a RISE customer cannot
  fix sits open until SAP acts. Rolling `ticket_to_sap` into the customer's MTTR or overdue
  count measures the wrong organisation, which is why it also carries a longer SLA window.
- *Count resolved occurrences, never average a severity.* A mean that falls because a batch of
  LOW findings arrived reports progress where none happened. Likewise MTTR counts only findings
  actually **resolved**: including still-open ones as "time so far" makes it fall whenever new
  findings arrive, which is exactly backwards.
- *A path is a STORED ROW with a lifecycle*, never a query re-run on each page load. That is
  what makes "severed on 6 August" expressible and what lets a returning path re-open as the
  SAME path. Its identity is (template, systems) — never the findings, whose churn would retire
  and re-raise it continuously.
- *An accepted risk does not close an attack path.* Acceptance is a decision to tolerate a
  defect, not evidence it is gone; an attacker is unmoved by paperwork. A `mitigated` finding
  does close it — a compensating control genuinely interrupts the step.
- *Attack paths are templates in `data/attack_paths.json`, i.e. CONTENT.* Adding a path is a
  data change, never a code change, and every hop must cite checks that already exist. A
  required hop citing a check no module emits produces a path that silently never
  instantiates — `tests/test_graph_paths.py` fails on it.
- *Never claim a path was traversed.* We hold no connection and never will. Paths carry
  `derived_from_config` and the UI repeats it.
- *A saved view stores FILTERS, never rows*, and the filter keys are an allowlist. Opening a
  shared link re-runs the query under the caller's own row scope, so it can never widen access.

**Traps this tier has already fallen into — do not re-introduce them:**
- *`CREATE OR REPLACE VIEW` over `SELECT f.*` breaks the upgrade path.* A view's column list
  cannot change, so the first `ALTER TABLE` that adds a column makes re-running `schema.sql`
  fail. If a view is ever wanted, enumerate its columns and `DROP` before recreating.
- *A `Mount` at `/` swallows everything declared after it.* Starlette dispatches to the first
  matching route and a root mount matches every path, so a route registered below it is dead —
  silently, answering 200 with a page of HTML instead of JSON. The SPA mount is therefore the
  **last** statement in `app.py`; new routes go above it. This replaced the `TemplateResponse`
  trap, which is now historical: `TemplateResponse` takes `request` FIRST in current Starlette
  and the legacy `(name, context)` form broke every page while imports still succeeded. Nothing
  in `server/` renders a template any more, so that one cannot recur — but the shape of the bug
  (breaks everything, passes import) is worth remembering, because the mount-order trap has it.
- *Two definitions of one predicate will disagree.* `expired_acceptance` and `is_overdue` were
  computed in SQL for the finding **list** and in Python for the finding **detail**, so the queue
  could show an expiry banner the detail page denied. Both are SQL now, using the same
  expression. Any derived flag a user can see in two places belongs in one.
- *`scope_clause` is the one place row scoping is expressed — with one exception that should not
  grow.* `server/graph.py` has its own `_scoped()` for the attack-path predicate (same
  `None → TRUE` / `[] → FALSE` semantics, different join). Two implementations of the access
  boundary is one more than is safe; do not add a third.

### The 30 modules (module key → class → focus)

| key | module | focus |
|---|---|---|
| `users` | user_auth_audit | default users, SAP_ALL, dormant, service accounts, wildcard values |
| `iam` | iam_advanced | SoD, firefighter, role lifecycle, cross-system identity |
| `params` | security_params | password/login/RFC/gateway/TLS/audit profile parameters |
| `network` | network_services | RFC destinations, ICF, transports, audit config |
| `rise` | rise_btp_checks | BTP trust/IdP, comm arrangements, API exposure |
| `btpcloud` | btp_cloud_surface | Cloud Connector, service bindings, destinations, IAS, CPI, network |
| `intglayer` | integration_layer | APIM, IDoc, web services, webhooks, gateway ACLs, OAuth |
| `dataprot` | data_protection | RAL, ILM, masking, GDPR/DPDP, residency |
| `codetrans` | code_transport | ABAP SQLi, ATC, transports, client config, SAP mods |
| `logmon` | log_monitoring | Security Audit Log, SIEM, retention, table logging |
| `fiori` | fiori_ui | catalog access, OData backend auth, spaces/tiles |
| `crypto` | crypto_posture | TLS, certs, SNC, **HANA encryption-at-rest** (data/log/**backup**), **system-replication TLS**, PSE, keys |
| `hanadb` | hana_db_security | HANA DB users/privileges/roles/audit/parameters (not encryption); **log_mode/PITR, MDC cross-DB, DEBUG privileges** |
| `hotnews` | sap_hotnews | missing critical SAP Security Notes since 2020 |
| `authz` | abap_authorizations | AGR_1251 role-content: critical auth objects & transactions |
| `systrust` | system_trust | trusted RFC, SAProuter, msg server, UCON, SAP*/default passwords |
| `baseline` | baseline_params | SAP Security Baseline profile params: auth engine, SNC fallback, GUI scripting, weak hashes, sapstartsrv, gateway ACL, SSO cookies, ICM log |
| `s4authz` | s4_business_authz | S/4HANA business roles/catalogs/restrictions, CDS auth-check, OData V4, Cloud Connector principal propagation, CF platform roles, birthright role collections |
| `ara` | access_risk_analysis | offline GRC-style **permission-level SoD** from AGR_1251+AGR_USERS: 27-risk ruleset (P2P/O2C/R2R/H2R/Basis), mitigating controls, per-user risk score; iam SoD defers to it when role_auth_values present |
| `jobcmd` | basis_job_command | **host-command-execution surface**: SM69/SXPGCOSTAB external cmds (shell-wrap/ADDPAR/path/danger-verb) + TBTCO/TBTCP armed job step users (SAP*/DDIC/SAP_ALL, RSBDCOS0, external steps, deleted/dialog, identity-borrow); reuses users/profiles |
| `grcac` | grc_access_control | **GRC Access Control**: EAM/Firefighter usage+ownership, ARM access-request workflow, GRC-native SoD violations, mitigating controls, SoD ruleset governance |
| `rolegov` | role_governance | **role design**: SU24 proposal hygiene for custom tcodes, ungenerated profiles (AGR_1016), derived-role authorization-value drift vs parent |
| `atc` | atc_import | SAP's own ATC/CVA results, ingested rather than re-derived |
| `cva` | abap_sast | **our** ABAP/CDS/BDEF scanner — **133 rules dispatched by file type** (118 ABAP/CDS/RAP, 7 JS/UI5, 8 BTP descriptor), statement lexer, intra-procedural taint. `ABAP-XSS-006` is retired and `ABAP-AUTH-003` is handled in the engine, so 116 of the 118 fire from the rule table |
| `logreview` | log_review | retrospective SM20 review: what the audit log actually recorded |
| `capxsuaa` | cap_xsuaa | **CAP project as written** (`--cap-src`): `xs-security.json` exactly + CDS model lexically. Traces scope ← role-template ← role-collection ← IdP group; `CAPX-TOK-001` closes the application-override blind spot `BTP-TOK-*` declares |
| `codeinv` | code_inventory_report | custom-code estate: size by type, unreachable, dormant, unknown-kept-separate |
| `resilience` | resilience_posture | backup recency/failure posture, DR test evidence, recovery objectives (RES-*) |
| `snc` | snc_posture | **the SNC family as one model** — 18 params incl. the ECS-mandated ones |
| `ecsconfig` | ecs_config_items | the configuration half of Note 3250501 (SPWD/SPSE table groups, clients, SAL) |
| `fincontrols` | financial_controls | **SOX ITGC / FI config**: posting-period controls (T001B), tolerance groups (T043T), payment dual-control (T055F), document-change rules (TBAER), FI number-range buffering (TNRO) |

### Deployment mode decides what "compliant" means

`--deployment-mode {on_prem,rise_pce,rise_tailored}` is built once as `run_ctx` in
`sap_scanner.py`. It is not cosmetic:

    snc/accept_insecure_gui = 1        <- SAP MANDATES this in ECS
    rfc/callback_security_method = 1   <- a permitted EXCEPTION in ECS (the standard is 3)
    DDIC unlocked                      <- explicitly NOT required to be locked

All three are findings on classic on-premise ABAP and are compliant — or tolerated — in ECS.
Three checks reported HIGH on fully compliant RISE systems before this existed, because
they reasoned from what a parameter is NAMED rather than from what SAP wrote.

Note the second line precisely, and do not "simplify" it: the note records
`rfc/callback_security_method` as standard value **3** with **1** allowed as a documented
exception (NetWeaver 7.40, with a planned move to 3). Calling 1 "SAP's mandate" overstates
what the note says, which is the same class of error as inventing a note number.

**`run_ctx` does NOT reach every auditor, and the docs used to claim it did.** Six auditors
receive it — `users`, `params`, `snc`, `ecsconfig`, `crypto`, `baseline` — and five of those
six actually branch on it; `crypto_posture` takes it and never reads it. Three more
(`iam`, `atc`, `cva`) get a **modules-only** `run_context`, which is the "is my sibling
running" signal and carries no deployment mode. The remaining 21 are constructed
`Cls(data, baseline_overrides)` and cannot know the mode at all. **Before writing an
ECS-conditional check, confirm your module is actually handed `run_ctx`** — if it is not,
wiring it in `sap_scanner.py` is part of your change. A mode-blind module that assumes it is
mode-aware silently applies on-premise rules to a RISE system.

Default is `on_prem`. Guessing ECS would silently relax genuine on-premise
findings, which is the wrong direction to be wrong in.

### `modules/ecs_baseline.py` is the single oracle

`data/ecs_hardening_3250501.json` holds SAP Note 3250501 (v46, 2026-05-15) — the
MANDATORY hardening baseline for AS ABAP in SAP Enterprise Cloud Services —
recorded as **facts only**: parameter names, SAP's standard value, and the
exceptions SAP explicitly permits. SAP's prose is copyright and is not reproduced.

**Never hand-type a value from that note into Python.** Read it from the JSON. A
transcription typo tells a customer they are compliant when they are not, which is
exactly the defect this file was created to fix: we required
`login/min_password_lng >= 8` where SAP mandates `>= 15`.

`is_compliant()` returns `True` / `False` / **`None`**. `None` means *no opinion* —
the parameter is not in the note, or the deployment is not ECS. It is never
"compliant"; a caller must fall back to its own rule, not pass.

Coverage: **92 of 92 parameters** (74 in `security_params`, 18 in `snc_posture`).
The old standing instruction not to claim coverage against 3250501 until someone
with an S-user read it is **satisfied** — a customer supplied it on 2026-08-07.

### The release gate

`--gate` turns the scanner from something that reports into something that
decides. Exit 0 pass / 1 policy violated / 2 could not assess. See
`docs/RELEASE_GATE.md`. Four rules, each from a specific way gates get switched
off: judge the delta not the backlog; judge only what the transport touches; never
block on what the customer cannot fix (`remediation_owner`); and **never fail
open** — degraded coverage is exit 2, never 0.

It is **CLI-only**. `server/` never imports `release_gate` and exposes no gate route, so
`docs/RELEASE_GATE.md`'s suggestion to "run the gate against the server" describes something
that does not exist. Either build it or drop the line.

One edge worth knowing before you trust an exit code:
- **`--gate-write-baseline` runs the whole scan and writes a report first**, then writes the
  baseline and exits 0 — and it is evaluated *before* `--gate`, so passing both silently skips
  gate evaluation.

`evaluate([])` used to return pass/0 — the docstring listed "no findings were supplied" among
its exit-2 triggers and the code did not implement it. It does now, as Rule 4's third arm:
`evaluate(findings, assessed_checks=N)` takes the number of checks that actually executed, and
an empty finding list is a pass only when N is greater than zero. `sap_scanner.py` derives N
from the coverage manifest via `posture_score.assessed_check_count`; a caller that supplies
nothing gets exit 2, which is the honest reading of "we have no idea how much was looked at".

## Adding a new module (the recipe)

1. **`modules/<name>.py`** — `class <Name>Auditor(BaseAuditor)`, with a `run_all_checks()`
   that calls check methods. Each check: `rows = self.data.get("<source>")`; guard
   `if not rows: return`; iterate with **tolerant column access**
   (`row.get("A", row.get("B", ""))`); collect offenders; `self.finding(...)`. Check IDs are
   `MODULE-SUBAREA-NNN` (e.g. `HANADB-PRIV-001`, `AUTH-002`, `TRUST-005`). Always cite **real**
   references (SAP Note / CIS SAP / DSAG / SAP Security Baseline).
   **Pass `affected_objects` and `scope` on every finding** — names taken from the data, never
   invented; omit the object rather than fabricating a placeholder when a row lacks the field.
   `modules/coverage.py` derives your module's data sources by scanning for
   `self.data.get("…")`, and its finding **categories** the same way (literal
   `category="…"` plus a `CATEGORY` class attribute), so both the coverage manifest and the
   domain roll-up pick the module up automatically.
2. **`sap_scanner.py`** — add the import, add the module key to the `--modules` `choices`
   list, add it to the `"all"` expansion list, and add an `if "<key>" in run_modules:` run block.
   **Add the key to `coverage.CLI_MODULE_ALIASES` too.** The CLI's short names and the
   manifest's module names are two vocabularies; `tests/test_coverage_cli_names.py` re-derives
   the mapping from this dispatch and fails if they part. They parted once and every offline
   report stamped all thirty modules `not_run` while carrying hundreds of their findings.
   **If any check of yours is deployment-mode dependent, pass `run_ctx` in the constructor** —
   most auditors are not given it, and a module that reasons about ECS without receiving the
   mode silently applies on-premise rules to a RISE system.
3. **`modules/data_loader.py`** — add the new data source(s) to `FILE_MAP`.
   ⚠️ **A missing `FILE_MAP` key ships the module DEAD.** `self.data.get("your_source")` returns
   `None`, the guard returns early, and the module reports nothing while looking healthy —
   `table_auth_groups`, `backup_catalog` and `recovery_tests` were absent, and two modules'
   checks were unreachable in production for exactly that reason. Prove it fires before you
   claim it works.
4. **`sample_data/`** — add crafted-bad sample files so the module produces findings on the
   bundled `sample_data` run (and verify a benign row does NOT fire). Registering the loader key
   is not enough: with no fixture the module still emits nothing on the bundled run, which is
   the state `resilience` and `ecsconfig` are in today.
5. **Docs** — bump the README badge + "N checks across M modules" line, add a README module-
   table row (and a row to the module table in this file), and add a section to
   `docs/CHECKS_REFERENCE.md`.
   ⚠️ If your test file touches `server/`, add it to the `cli` job's `--ignore` list in
   `.github/workflows/tests.yml` — that job installs pytest and nothing else, so a module-level
   `import psycopg` aborts collection for the entire matrix.
6. **Reports** — add a `data/finding_details.json` KB entry per new check (detailed risk +
   step-by-step remediation) so the PDF/PPTX hand-over stays detailed, and if the module
   introduces a **new category** string, add it to `compliance_mapping.CATEGORY_THEMES` so its
   findings map to framework controls.
7. **Smoke test end-to-end** (see below), then commit.

## Conventions & gotchas (learned the hard way)

- **A textual check cannot tell code from prose about code.** Three tests in one week grepped
  source and then flagged their own explanation — the deployment-mode test tripped on a
  comment recording the old behaviour, the `--password` test on the docstring explaining why
  there is no `--password`, the Python-matrix test on its own module docstring. A test that
  forces the reasoning to be deleted in order to pass trades the documentation for the check.
  **Parse it.** `ast` distinguishes a call from a sentence about a call.
- **Do not pin a whole result list.** `assert ids(findings) == ["PARAM-MISSING"]` failed the
  moment a legitimate new finding arrived, and the temptation is then to weaken the assertion
  rather than read it. Assert the claim the test is actually making — "no accusation" — not
  the shape of everything that came back.
- **Consistency is not completeness, and the difference is where things hide.** The
  cloud-scope test asserted every member of a set behaved correctly and said nothing about
  types that should have been members; six were missing. The coverage manifest reported on
  modules it could parse and said nothing about four it could not. When a guard enumerates a
  set, ask what enumerates the set's *boundary*.
- **A shared rule belongs to neither module.** Two auditors read the same export with two
  column vocabularies, and the one that drifted accused a compliant system. A copy is not a
  fix for drift — it is the mechanism of it. Put it on `BaseAuditor`.
- **Fail towards silence, never towards accusation — but check which silence.** An
  unrecognised rule operator returned `False`, which the caller reads as *accuse*, so a typo
  fired on every system. The first fix raised instead, which was worse: the runner skips a
  raising module, so one typo would have cost the customer every finding from it. The answer
  was silent at runtime plus a test asserting every shipped rule uses a known operator — the
  programming error fails CI rather than somebody's report.
- **Order is load-bearing exactly once in `server/schema.sql`.** Anything naming a column added
  by an `ALTER` must come after it. A partial index placed beside the other indexes passes a
  fresh install and fails every upgrade — which is how it gets shipped.
- **Never fabricate SAP identifiers.** SAP Note numbers, CVEs, authorization objects/fields
  (`S_DEVELOP`/`OBJTYPE`/`ACTVT`), and profile parameter names must be **verified against SAP
  Help / SAP Security Baseline / CIS SAP / DSAG** before shipping. Past verification passes
  caught wrong SAP Note numbers (`2408073`, `1852424`) and misattributed auth logic. When
  unsure of a specific SAP Note number, prefer a generic "SAP Security Baseline" reference.
- **Run the FULL scanner, not just `run_all_checks()`.** A direct `run_all_checks()` smoke
  test does not exercise `report_generator`. A trailing comma in `description=( "…", )` makes
  the value a **tuple**, which passes the findings test but crashes `html.escape` in the HTML
  report. Always finish with a full `python sap_scanner.py --data-dir ./sample_data …` run.
  **And exercise the report OPTIONS, not just the default.** `--crq` reached
  `report_generator._svg_lec` with the engine's dict-shaped loss-exceedance points while that
  function unpacked `for t, p in points`, so every `--crq` run wrote its `.crq.json`, ran the
  Monte-Carlo, and then died before producing any HTML at all. Both sides had tests and both
  passed: the engine test checked the curve in isolation, the report test passed
  `"loss_exceedance": []` and returned before the unpacking. A contract between two components
  needs a test that spans both, or each side stays internally consistent while the seam rots.
- **String false-positive/negative traps.** Substring tests bite: `"lock" in "unlocked"` is
  `True`; `"default" in "No default"` is `True`. Use `startswith` / exact tokens and guard
  negations.
- **Fire only on present-and-risky.** Parameter checks should key on a parameter being
  *present with a risky value*, not merely absent from the export (absence ≠ secure/insecure).
- **A module may defer to a deeper sibling, but never on data presence alone, and never
  silently.** `iam` defers its transaction-level SoD to `ara`'s permission-level analysis — but
  the condition must be *"is `ara` actually running"* (`self.module_is_running("ara")`), not
  *"is `ara`'s input loaded"*. Those differ: `--modules iam` loads `role_auth_values.csv` without
  running `ara`, and the original condition made SoD analysis produce **nothing** while looking
  like a clean result. When a check does stand down it must emit an INFO finding saying so —
  same discipline as the coverage manifest: **absence is stated, never implied**. Callers pass
  `run_context={"modules": …}`; a module given no context keeps its historical behaviour rather
  than guessing.
- **CSV header normalization:** the loader upper-cases headers and replaces spaces with `_`,
  so match `row.get("USER_NAME")` etc. Values are stripped but keep their case.
- **Tests + CI exist** (`tests/`, `.github/workflows/tests.yml`, `requirements-dev.txt`). About
  **2,365** tests; no SAP system needed. ⚠️ **`requirements-dev.txt` alone is not enough to run
  the whole suite** — it is only `pytest`, and the server-tier suites import psycopg/starlette
  at module level, which aborts collection rather than skipping. Install both:
  ```bash
  python -m pip install -r requirements.txt -r requirements-dev.txt httpx
  python -m pytest -q          # DB-gated suites still skip without DB_DSN
  ```
  `httpx` is not in either file but Starlette's `TestClient` refuses to construct without it.
  To reproduce the **scanner-core** guarantee instead — that `modules/` and `sap_scanner.py`
  need nothing third-party — install *only* pytest and use the CI `cli` job's `--ignore` list.
  The suite runs every module over `sample_data`
  and validates the finding contract, cross-module id collisions, the report render, and a CLI
  end-to-end run. **When you add a module:** it is picked up automatically by the parametrized
  tests via the `MODULES` list in `tests/test_scanner.py` — add your class there, and add a set
  of key check ids to `EXPECTED_CHECKS` so a regression that stops your checks firing is caught.
  Module tests stay stdlib + `pytest`-only; type hints stay `typing`-based (`List`/`Dict`/
  `Optional`, not `list[...]`/`X | Y`) for the 3.8–3.12 matrix.
- **NINE suites need a real PostgreSQL and SKIP without `DB_DSN`** — `test_integration_ingest.py`
  (the journey), `test_integration_journey.py` (analytics, saved views, bulk actions),
  `test_http_console.py`, `test_api_auth.py`, `test_account.py`, `test_api_finding_detail.py`,
  `test_branding.py`, `test_code_finding_console.py` and `test_graph_paths.py` — together well
  over a hundred tests, and **all of the RBAC coverage**. The journey is implemented in SQL, so a
  mocked database proves the Python is self-consistent and proves nothing about whether it works.
  Run the whole DB-gated set, not the three this file used to name:
  ```bash
  docker run -d --name sapsec-test-db -e POSTGRES_USER=sapsec -e POSTGRES_PASSWORD=sapsec \
      -e POSTGRES_DB=sapsec -p 55433:5432 postgres:16
  DB_DSN=postgresql://sapsec:sapsec@localhost:55433/sapsec \
  SESSION_SECRET=$(python -c "import secrets;print(secrets.token_urlsafe(48))") \
      python -m pytest -q          # the full suite; the nine above now execute
  ```
  A few of them are **data**-dependent as well as DB-dependent and self-skip with "no findings in
  this database". Seed a scan first (as CI does) or they will quietly prove nothing.
- **The Phase-1 exit criterion is a test, and it must stay green:** scan the same bundle twice
  and get `new 0 · persisting N · resolved 0`. If it ever fails, finding identity has broken
  and every re-upload will report the whole estate as newly broken.
- **CI has FIVE jobs, and the skip guard is load-bearing.**
  `cli` (3.8–3.12, pytest only, so a third-party import into the scanner core fails the build,
  plus a full smoke run); `purity` (walks the AST of `modules/` and `sap_scanner.py` and rejects
  any non-stdlib import); `sap-content` (clones SAP's published policy repo, re-derives
  `data/sap_baseline_requirements.json` and fails on drift, because the coverage page is measured
  against that catalogue and a stale copy misreports coverage); `brand-assets` (installs Pillow —
  **only here** — and runs `tools/build_brand_assets.py --check`, on the rule that anything
  derived is re-derived by CI); and `server` (PostgreSQL 16, applies the schema **twice** because
  idempotency is the upgrade path and it has broken once).
- **The `server` job seeds a scan BEFORE pytest, and that is deliberate.** It inserts a
  landscape/system/run, ingests `sample_data`, and **asserts findings > 0**. Without it, the
  data-dependent suites self-skipped and the skip guard counted them as drift. The job
  **fails if more than one test skips** — before that guard, `pytest -q` ran the DB-backed
  suites, they skipped for want of `DB_DSN`, and the job went green having verified nothing.
  Consequence for contributors: **a new test that self-skips for want of data breaks CI.** Give
  it the data instead of widening the guard; widening it only moves the goalposts.
- **The compiled SPA is never built in CI**, so a handful of `tests/test_spa_mount.py` tests
  skip with "run `npm run build` in frontend/". That is the one class of skip the guard tolerates
  — but it also means **no CI job exercises the real bundle**. Build it locally before claiming a
  console change works.
- **`tests/test_identity.py` runs against the REAL `sample_data`, not fixtures**, and asserts
  the `check_id` collisions still exist before asserting they resolve. If the sample data ever
  stops colliding, the test fails loudly rather than silently proving less.

## Product direction

The tool is being taken from an offline assessment CLI to a commercial-grade platform. The
competitive and contractual research behind that is in `docs/`, and it is evidence-based —
claims are labelled `verified` / `asserted` / `inferred`, and two adversarial verification
passes corrected sixteen of them.

| doc | what it settles |
|---|---|
| [`PIVOT_PLAN.md`](docs/PIVOT_PLAN.md) | Architecture and the six phases, with rationale |
| [`BUILD_ROADMAP.md`](docs/BUILD_ROADMAP.md) | Execution view: status, dependencies, exit criteria, non-goals |
| [`COMPETITIVE_ANALYSIS.md`](docs/COMPETITIVE_ANALYSIS.md) | Onapsis, the market, and the attack-path design spec |
| [`COMPETITOR_SECURITYBRIDGE.md`](docs/COMPETITOR_SECURITYBRIDGE.md) | SecurityBridge dossier |
| [`RISE_SECURITY_MODEL.md`](docs/RISE_SECURITY_MODEL.md) | Where SAP's contractual line sits; what a RISE customer can actually export |

**Things that would be a mistake to build** (each is argued in the docs): real-time threat
detection, peer benchmarking (fiction without a customer base), BusinessObjects, an ABAP
agent of any kind, and check-count comparisons.

**SuccessFactors left that list** — decision D1, `docs/DECISIONS.md` — in scope qualified:
offline-first, security surface only. **A live API client inside `server/` or `modules/`
is still a mistake**; decision D2 permits connectors only as an out-of-process `collect/`
package whose sole output is a file the offline path already reads.

**"Transport gating" was on that list and has been deliberately removed** — do not add it back
by copying an older revision. What was rejected was gating *inside SAP*: an agent or exit that
intercepts a transport release, which needs the ABAP-resident footprint this product exists to
avoid. What shipped instead is `--gate`, a **pipeline** control that judges an export outside
the SAP system and returns an exit code. Same goal, opposite architecture, and only one of them
contradicts the charter. If you find the two conflated anywhere, the CLI gate is the survivor.

**Do not repeat these overclaims:** the mitigation journey is *table stakes*, not a
differentiator — both incumbents ship it. The genuinely open lane is monetary risk
quantification. And absence of a capability in a competitor's public material is stated as
"no public evidence across N named sources", never as proof of absence.

## Git / commits

- Remote: `https://github.com/Krishcalin/SAP-S4HANA-RISE-Security-Scanner`.
## Licensing

**Proprietary, all rights reserved, since 2026-08-11.** The repository was MIT until
then; it is not any more, and the badge, the README section and `LICENSE` were changed
together. Do not reintroduce an MIT badge or an OSI licence identifier for this code.

The repository is **publicly viewable and that is not a grant** — `LICENSE` says so
explicitly, because a public repo with no licence file is widely (and wrongly) read as
permissive.

⚠️ **A proprietary licence on our code does not touch third-party terms, and cannot.**
Full notices are in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md); it is part of
the release, not documentation trivia, because the `Dockerfile` redistributes some of
what it lists and an attribution obligation is not discharged by a source comment
nobody ships.

**Exactly one component here is third-party**: `data/sap_baseline_requirements.json`,
derived from SAP-samples' `frun-csa-policies-best-practices`, **Apache-2.0, Copyright
(c) 2020 SAP SE**. We take identifiers, titles, tiers and store names; SAP's prose is
not reproduced and SAP's SQL predicates are neither copied nor executed. The licence
copy lives at `licenses/Apache-2.0.txt` and the derived file carries source, licence
and copyright in its own `_meta` block, so the notice travels with the data.

⚠️ **`modules/abap_sast_rules.py` LOOKS third-party and is not.** Its upstream
`SAP-Code-Vulnerability-Analyzer` says "MIT, Copyright (c) 2026 KRISH", which reads as
another party — but both repositories are under the same GitHub organisation and share
the same two commit identities (`KRISH <krishnendu.de@hotmail.com>` and
`Krishnendu De <krishcalin@gmail.com>`). Same author, so no obligation arises here. Two
consequences, neither obvious: publishing that code under MIT elsewhere does **not**
retroactively license this repository, and relicensing here does **not** revoke the MIT
grant already made upstream — MIT is irrevocable for copies already distributed. If
that is not the intent, the thing to change is the upstream repository's licence.

⚠️ **`psycopg` is LGPL-3.0-only.** It is fine as an unmodified, separately installed
library — that is what LGPL permits for a work that merely uses it. **Never vendor,
fork or patch it into this repository**: that would make this project a derivative of
an LGPL work and pull copyleft terms onto proprietary code. The same reasoning bans
vendoring GPL/AGPL source outright.

**Before vendoring anything else, check its licence permits it and record the notice
where regeneration cannot drop it** — `tools/build_abap_rules.py` puts its header in the
generator's `_COPYRIGHT` constant precisely because a hand-added notice in the generated
file is deleted by the next rebuild, silently.

## Git / commits

- **Commit style: plain, descriptive conventional messages with NO co-author trailer** —
  match the existing history (e.g. `Adding <X> module — <summary> (N new checks)`).
- Flow: branch → commit → `git fetch` → ff-merge to `main` → push. Keep new modules additive.
