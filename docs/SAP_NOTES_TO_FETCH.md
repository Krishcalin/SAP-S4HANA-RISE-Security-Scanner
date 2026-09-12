# SAP Notes behind the Security Baseline v2.6 — what to fetch, and why

Every note below is referenced by **SAP Security Baseline Template v2.6**
(11-Jul-2025) and sits behind an S-user login, so this repository cannot read
them. This file exists so the fetching is **targeted rather than exhaustive**:
the baseline cites ~135 notes and only some of them carry information a checker
needs.

**URL form:** `https://me.sap.com/notes/<number>`
(older form `https://launchpad.support.sap.com/#/notes/<number>` still resolves).

## Already held — do NOT re-fetch

| note | what we hold | where |
|---|---|---|
| **3250501** | ECS ABAP hardening, **version 46, released 2026-05-15**, obtained by S-user 2026-08-07. 92 parameters with ECS standard values and SAP-permitted exceptions. | `data/ecs_hardening_3250501.json` |
| **2671160** | TLOGOCHECK / tp-R3trans minimum versions | `data/sap_notes_catalogue.json` |
| **3600840** | `rfc/authCheckInPlayback` | `data/sap_notes_catalogue.json` |

⚠️ **Our ECS data is NEWER than the baseline PDF's.** The PDF's §3.6.1 table
quotes note 3250501 **version 32 (05.06.2025)**; we hold **version 46**. Where
the two disagree, v46 is current and the PDF is stale — do not "correct" our
values to match the document.

The 1,732-note `sap_notes_catalogue.json` is the **security patch** catalogue
(HotNews and patch-day notes). It is a different corpus from the configuration
notes below, which carry parameter values and lists. Only two overlap.

---

## Tier 1 — a check cannot be written correctly without these

These carry a **value, a list, or a table** that we would otherwise have to
invent. Inventing one is the failure mode this project has already been bitten
by, so the checks are not written until the note is read.

| note | URL | what it unblocks |
|---|---|---|
| **2926224** | https://me.sap.com/notes/2926224 | Collection note: **all** secure-by-default settings for S/4HANA and BW/4HANA via SL Toolset and SUM. Drives the whole `--deployment-mode on_prem` expected-value set. The single highest-value note here. |
| **3346659** | https://me.sap.com/notes/3346659 | `ssl/ciphersuites` / `ssl/client_ciphersuites` cipher-suite **id numbers** for S/4HANA 2025. v2.6 quotes `1159:`, `1569:` and `1174:` — we need the id semantics, not just the strings, to judge a value we did not see verbatim. |
| **510007** | https://me.sap.com/notes/510007 | The authoritative cipher-suite id table for AS ABAP. Pairs with 3346659; without it `ssl/ciphersuites` can only be string-matched. |
| **3157268** | https://me.sap.com/notes/3157268 | **TRUST-A** — the trusting-relations migration and "latest security method". This requirement family is entirely new in v2.5/v2.6 and absent from our catalogue. Also defines `rfc/allowoldticket4tt`. |
| **2676384** + **2838480** | https://me.sap.com/notes/2676384 · https://me.sap.com/notes/2838480 | Security Audit Log **best-practice filter configuration** and SAL secure-by-default. `AUDIT-A b)` requires specific slots; we currently check that SAL is on, not that the right filters exist. |
| **3016478** | https://me.sap.com/notes/3016478 | The recommended **HANA audit policy set**. `AUDIT-H c)` requires policies "according to best practices" and the PDF's sample table is a customer's, not SAP's. |
| **2776748** | https://me.sap.com/notes/2776748 | `gw/reg_no_conn_info` **bit-vector semantics**. The PDF gives permitted values for kernel <7.40 and says "uneven" for ≥7.40; the bit meanings decide whether a value is safe. |
| **887164** | https://me.sap.com/notes/887164 | The **critical BSP/ICF service list**. v2.6 names 16 services under this note; a hard-coded list rots, and the note is the source. |
| **1484692** | https://me.sap.com/notes/1484692 | **Additional password-hash tables** beyond USR02/USH02/USRPWDHISTORY. CRITAU-A d) says "lists some more tables. You may want to include these." |
| **3480723** | https://me.sap.com/notes/3480723 | **ECS HANA** mandatory parameters. We hold the ABAP equivalent (3250501) and nothing for HANA. |
| **3381209** | https://me.sap.com/notes/3381209 | **ECS Java** mandatory parameters. Same gap. |

## Tier 2 — confirms a value or threshold we currently infer

| note | URL | what it settles |
|---|---|---|
| **3584984** | https://me.sap.com/notes/3584984 | `login/accept_sso2_ticket = 2` (accept Assertion Tickets, reject Logon Tickets). **New in v2.6.** We currently hold ECS `1` with `2` permitted — the baseline now wants 2, so the direction of the check may be inverted for on-prem. |
| **862989** | https://me.sap.com/notes/862989 | `login/password_max_idle_initial` / `_productive` semantics and the recommended 7 / 180. |
| **2140269** | https://me.sap.com/notes/2140269 | `login/password_hash_algorithm` — the iSSHA-512 / iterations / saltsize syntax we must parse rather than string-match. |
| **1023437** | https://me.sap.com/notes/1023437 | `login/password_downwards_compatibility` value semantics 0–5 (v2.6: 5 prohibited, 1–4 not recommended). |
| **3286256** | https://me.sap.com/notes/3286256 | `UNCONF_PATH_AS_EMPTY` in SFILE / FILECMCUSTP. **[Standard]**, and we do not check it. |
| **2251231** + **2395138** | https://me.sap.com/notes/2251231 · https://me.sap.com/notes/2395138 | `REJECT_EMPTY_PATH` in SFILE / FILECMCUSTP. |
| **3272585** | https://me.sap.com/notes/3272585 | KBA: `ms/server_port_<xx>` and the `ACLFILE` sub-parameter. **[Critical]** and unchecked. |
| **3224889** | https://me.sap.com/notes/3224889 | `gw/acl_mode_proxy` default change and `prxyinfo` ACL semantics. |
| **2183363** | https://me.sap.com/notes/2183363 | HANA `listeninterface` `.local` / `.internal` and `internal_hostname_resolution`. **NETCF-H is [Critical].** |
| **3064888** + **1413011** | https://me.sap.com/notes/3064888 · https://me.sap.com/notes/1413011 | `S_START` activation in SU25 for WDCA/WDYA. |
| **2958356** | https://me.sap.com/notes/2958356 | SACF scenarios set productive — and which are exempt. |
| **1922712** | https://me.sap.com/notes/1922712 | SLDW scenarios productive. |
| **3083852** | https://me.sap.com/notes/3083852 | UCON HTTP allowlist zones 01 / 02 / 03. |
| **65968** | https://me.sap.com/notes/65968 | `S_DBG` activity 02 on SAP_BASIS 7.57+ — the debug authorization changed shape and CRITAU-A c) 4. depends on it. |

## Tier 3 — customizing-table values (small, but they close four requirements)

`PRGN_CUST` is a **config store we check nothing from**, and four v2.6
requirements hang off it. These notes give the exact key/value pairs.

| note | URL | key |
|---|---|---|
| **1731549** | https://me.sap.com/notes/1731549 | `BNAME_RESTRICT = XXX` → **USRCHAR-A** |
| **513694** | https://me.sap.com/notes/513694 | `REF_USER_CHECK = E` → **USRTYP-A** |
| **1723881** | https://me.sap.com/notes/1723881 | `US_ASGM_TRANSPORT = NO` → **AUTHASSIGN-A a)** |
| **571276** | https://me.sap.com/notes/571276 | `USER_REL_IMPORT = NO` → **AUTHASSIGN-A b)** |

## Tier 4 — standard-user and secure-store detail

| note | URL | what it settles |
|---|---|---|
| **3303172** | https://me.sap.com/notes/3303172 | The **virtual SAP\*** process, which STDUSR-A a) requires a written procedure for. |
| **2293011** + **2119627** | https://me.sap.com/notes/2293011 · https://me.sap.com/notes/2119627 | SAP Solution Manager generated users with well-known passwords. v2.6 names nine; the notes are the authoritative list, and the PDF states plainly that RSUSR003 / SOS / Configuration Validation **cannot** validate them. |
| **1414256** | https://me.sap.com/notes/1414256 | TMSADM default-password change procedure. |
| **1902611** + **1902258** | https://me.sap.com/notes/1902611 · https://me.sap.com/notes/1902258 | SECSTORE individual main key — **SECSTO-A**, which we do not check at all. |
| **2159014** | https://me.sap.com/notes/2159014 | HANA data-at-rest encryption; **DISCL-H**, absent from our catalogue. |

---

## How to hand the content back

Paste the note body into the session. What is needed from each is **facts, not
prose**: parameter names, values, permitted exceptions, version tables, object
lists. Follow the precedent set by `data/ecs_hardening_3250501.json`, whose
`source` block records note number, version, release date, component, scope and
how it was obtained — and whose header says plainly that SAP's descriptive text
is not reproduced.

⚠️ **SAP's note text is SAP's.** Take identifiers, values and lists; do not paste
SAP's explanatory prose into the repository. This is the same line already drawn
for the FRUN policies in `server/sapcontent.py` and for CIS Benchmarks
throughout the project — cite the number, never reproduce the text.
