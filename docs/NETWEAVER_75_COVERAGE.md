# SAP NetWeaver Security Guide 7.5 (SPS22) — coverage review

A quality check of **MonitorRisk** against the *SAP NetWeaver Security Guide,
7.5 SPS22* (2026-09-12, revised after the OS/infra + host-platform build). The
question this answers: of what the guide requires, what does the tool check, what
is a genuine gap, and what is out of scope — with a reason for every line.

## Scope depends on deployment mode, not on the product being RISE-only

NetWeaver 7.5 is a **generic platform** guide. It covers AS ABAP, AS Java, the
Enterprise Portal, TREX, the Content Server, ALE/IDoc, the SAP GUI, five
non-HANA databases, and both UNIX and Windows host hardening. MonitorRisk is an
**offline (and optionally connected) S/4HANA + BTP** config-review tool that
covers **on-premise, RISE, and self-managed SAP on a hyperscaler** (AWS / Azure
/ GCP IaaS) — see decisions D5, D7 and D10.

The deciding axis is **who owns the host**, which the deployment mode already
carries (`is_rise()`). Chapters of this guide are therefore in or out of scope
*per mode*, not absolutely:

| Guide chapter | RISE (`rise_*`) | On-prem / self-managed hyperscaler (`on_prem`) | Why |
|---|---|---|---|
| OS security — UNIX/LINUX & Windows (SUID, NFS/NIS, `/usr/sap` perms, UMASK, `SAP_<SID>_GlobalAdmin`, `<sid>adm`) | **Out of scope** — SAP ECS owns the host; customer has no OS access | **In scope and BUILT (D10/D11)** — module `osec` (OSEC-USR/FILE/NET-*); customer owns OS root, so `customer_fixable`; `not_assessable` in RISE | The customer owns exactly this layer on any host they manage, including a self-managed hyperscaler VM. |
| Host-side message server / Web Dispatcher / SAProuter config | **Out of scope** — provider-operated | **In scope and BUILT (D10)** — SAProuter `TRUST-005`, message server `TRUST-006/010/011`, Web Dispatcher `webdisp` + `WDISP-SSL-001` | Same boundary: in RISE these are ECS's; on a customer-run host they are the customer's. |
| Cloud infrastructure *below* the OS — hypervisor, block-storage encryption, security groups, cloud IAM | **Out of scope** | **Out of scope — deferred to the customer's cloud CNAPP (D10)** | AWS/Azure/GCP posture is a CNAPP's job, not an SAP config scanner's. MonitorRisk names the boundary and does not duplicate it. |
| Non-HANA databases — Oracle (OPS$, `sqlnet.ora`), MaxDB, ASE, Db2, SQL Server | **Out of scope** | **Out of scope (D6)** — anydb explicitly declined | S/4HANA runs on HANA in every hosting mode. HANA DB security is covered in depth (below). ECC-on-anydb is D6's costed, deferred core. |
| AS Java — UME, JAAS, Web Dynpro Java `DevelopmentMode`, servlet_jsp, deploy service, secure store | **Out of scope** | **Out of scope** | S/4HANA is ABAP + HANA regardless of hosting. (BTP, the modern Java-adjacent surface, **is** covered — `btpcloud`, `intglayer`, `capxsuaa`.) |
| Enterprise Portal, KM, Collaboration, TREX, Content Server, SLD, NWDI, Universal Worklist | **Out of scope** | **Out of scope** | Legacy NetWeaver components not shipped with S/4HANA. |
| Network topology — firewalls, DMZ, network zones | **Out of scope (architecture)** | **Out of scope (architecture)** | Landscape architecture, not a fact any config export states. (The customer-run *devices* — WD, SAProuter — are the row above, and are in-scope on-prem.) |
| SAP's own services — EarlyWatch Alert, Security Optimization Service, Configuration Validation | **N/A (peer tooling)** | **N/A (peer tooling)** | The SAP services MonitorRisk sits alongside; not requirements to audit. |

Everything below is the part that is **in scope in every mode**: AS ABAP
hardening, HANA database security, the message server, the Web Dispatcher (where
customer-run), SNC/TLS, the audit log, standard users, and data protection.

---

## In-scope requirements — what the tool covers

Each row cites the module and, where I verified a specific one, the check id.

| Guide section | MonitorRisk coverage | Evidence |
|---|---|---|
| **Standard users** (SAP\*, DDIC, SAPCPIC, TMSADM, EARLYWATCH; default passwords) | Covered | `user_auth_audit` (`users`), `system_trust` (SAP\*/default-password) |
| **Authentication — SNC / TLS** (SNC-protected paths, GSS-API, TLS vs SNC per protocol) | Covered | `snc_posture` (18-param SNC model), `crypto_posture` (TLS, ciphers, certs) |
| **Authentication — SSO logon tickets** (`login/ticket_only_by_https`, `login/ticket_only_to_host`, HttpOnly ICF cookie) | Covered | `security_params` (SSO-A family) |
| **HANA authorizations** — standard privileges, critical privileges, critical *combinations* | Covered, and deeper than the guide | `hana_db_security`: `DATA ADMIN` etc. in `CRITICAL_SYSTEM_PRIVS`, resolved directly **and** through role membership (SAP's `EFFECTIVE_PRIVILEGE_GRANTEES`); named critical pairs at `HANADB-PRIV-008`. The guide's one-liner "do not assign ABAP_ADMIN with ABAP_READ" is a single niche case of what this module already does structurally. |
| **Data protection — Read Access Logging (RAL)** | Covered | `data_protection`: `DPP-RAL-001/002/003` (enabled, channel coverage, retention), `DPP-FIELD-001` (PII fields without RAL) |
| **Message Server — internal/external split, app-server ACL, monitoring, admin port** | Covered | `system_trust`: `TRUST-006` (`rdisp/msserv_internal`, `ms/monitor`, `ms/admin_port`), `TRUST-010` (`ms/acl_info` rule content — the rogue-app-server / 10KBLAZE class), `TRUST-011` (`ms/server_port_<xx>` browser-monitoring ACL) |
| **Web Dispatcher — admin-interface hardening + back-end encryption** (`icm/HTTP/admin_<n>` PORT / CLIENTHOST / ALLOWPUB, HTTPS, `wdisp/ssl_encrypt`) | Covered (for customer-run WD) | `webdisp_security` + `data/webdisp_baseline.json`; `WDISP-SSL-001` (back-end encryption, conditional/LOW) |
| **ICF service hygiene** (deactivating `/sap/bc/*` test/echo services) | Covered | `network_services` (SICF services), Baseline `NETCF-A d)` |
| **Clickjacking framing protection** (UCON allowlist zones) | Covered | `network_services` / Baseline `NETCF-A h)` |
| **Auditing and logging — Security Audit Log** | Covered | `log_monitoring`, `security_params` (`rsau/*`, `AUDIT-A`) |
| **Secure SAP code — missing Security Notes** | Covered | `sap_hotnews`, `abap_sast` (CVA) |

The two documents reconcile: everything the NetWeaver guide states as a
concrete AS-ABAP or HANA control is already checked, most of it because the
**SAP Security Baseline Template** (reviewed separately in
`SAP_NOTES_TO_FETCH.md`) restates the same requirements more crisply and the
tool is built against that.

---

## Genuine gaps — reconsidered under D10: what got built, what stays deferred

The guide surfaced four things the tool did not check. Under D10 the two on the
customer-run host surface were **reconsidered against the code and resolved in
opposite directions**; the other two remain deliberate non-checks. The discipline
is unchanged — the one that leaves `SECSTO-A` unchecked and drives the four-state
coverage model: a check that cannot be right is worse than an honest gap.

- **`wdisp/ssl_encrypt` — now built** as `WDISP-SSL-001`, but as a LOW
  *conditional* note, not a defect (§2).
- **The message-server per-port ACLs — confirmed deferred**: reconsidered against
  the message-server checks that already exist, and they add no clean signal (§1).

### 1. Message-server per-port ACL files — `ms/acl_file_{ext,int,admin,extbnd}`

The guide devotes a table to four per-port ACL-file parameters, one for each
message-server port. The tool checks none of them by name, and reconsidering
under D10 **confirmed that stays deliberate**, because:

- The message server's real exposures are already covered: `ms/acl_info` (who may
  register as an application server — the rogue-app-server attack) at `TRUST-010`
  with rule content and all, the internal/external port split and `ms/monitor` at
  `TRUST-006`, and the browser-monitoring port ACL at `TRUST-011`.
- The per-port files are **defense-in-depth over that same port**. An empty
  `ms/acl_file_int` on a system whose `ms/acl_info` is populated adds no real
  exposure; an empty one on a system whose `ms/acl_info` is *also* bad is
  already reported by `TRUST-010`. There is no clean incremental signal.
- Firing on "present but empty" would misfire on the common case: an empty
  `ms/acl_file_admin` is irrelevant when `ms/admin_port = 0` (the compliant
  state the tool already checks). Correct firing would need per-port
  reachability the export does not state.

### 2. Web Dispatcher → back-end encryption — `wdisp/ssl_encrypt` (now built)

The guide recommends HTTPS between the Web Dispatcher and the back-end systems.
**Now built as `WDISP-SSL-001`** — but deliberately not as a defect, because:

- The guide makes it **conditional** in its own words: use it *"if the network
  between SAP Web Dispatcher and the back-end systems is not sufficiently
  secured otherwise."* A tool cannot see whether that network is secured, so an
  *unconditional* finding would be a false positive. `WDISP-SSL-001` therefore
  fires only on an explicit `wdisp/ssl_encrypt = 0` (present-and-off), at **LOW**,
  and carries the condition in the finding rather than asserting it away.
- It is **not** a WEBDISP_ALL baseline rule — SAP does not assert it in the policy
  files `data/webdisp_baseline.json` transcribes — so it lives in code in
  `webdisp_security`, cited to the NetWeaver guide, kept out of the SAP-baseline
  transcription.
- In RISE the Web Dispatcher and the network behind it are **operated by SAP
  ECS**, not the customer — the same reason the WD module fires only where a
  customer runs their own WD.

### 3. HANA `ABAP_ADMIN` + `ABAP_READ` application-privilege pair

A NetWeaver-**delivered application privilege** pair (page 10), distinct from the
HANA **system** privileges `hana_db_security` already pairs. **Left as a gap**,
because it applies only where ABAP developers author native HANA artifacts in
HANA studio against the S/4 database — a scenario that essentially does not
occur in RISE S/4HANA, and whose grants the tool does not ingest.

### 4. Virus Scan Interface (VSI) — active-content upload protection

The guide's XSS-from-uploads section recommends the Virus Scan Interface to
block active content on HTTP upload. The tool checks no VSI/`VSCANPROFILE`
state. A **real but minor** gap: niche, application-scenario-dependent, and only
meaningful where an estate actually exports its virus-scan-profile
configuration. Recorded here rather than guessed at.

---

## Bottom line

Within the part that is in scope **in every mode** — AS ABAP, HANA, the message
server, SNC/TLS, the audit log, standard users, data protection — the guide
**validates** the tool's coverage: every concrete AS-ABAP and HANA control it
states is already checked, and the HANA and RAL coverage is more thorough than
the guide's own text.

The guide's host chapters were its largest remaining value, and that layer is
**now built**. Its UNIX/Windows hardening, `USRCTR-O`, `/usr/sap` permissions and
OS user/group membership are the `osec` module (`OSEC-USR/FILE/NET-*`); its
customer-run infrastructure is `TRUST-005` (SAProuter), `TRUST-006/010/011`
(message server) and `WDISP-SSL-001` (Web Dispatcher back-end encryption). That
layer is out of scope in RISE (ECS owns the host, so it reads `not_assessable`)
and in scope for `on_prem` — including self-managed SAP on AWS / Azure / GCP,
where the customer owns OS root — with the cloud infrastructure *below* the OS
deferred to the customer's CNAPP and surfaced as the `OSEC-CLOUD-001` boundary
note. Of the four residual gaps above, one (`wdisp/ssl_encrypt`) became a
conditional check, one (the per-port message-server ACLs) is a confirmed
deferral, and two (the HANA application-privilege pair, the Virus Scan Interface)
remain niche or out of scope.
