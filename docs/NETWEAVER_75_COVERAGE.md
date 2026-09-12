# SAP NetWeaver Security Guide 7.5 (SPS22) — coverage review

A quality check of **MonitorRisk** against the *SAP NetWeaver Security Guide,
7.5 SPS22* (generated 2026-09-12). The question this answers: of what the guide
requires, what does the tool check, what is a genuine gap, and what is
out of scope — with a reason for every line.

## The scope frame comes first, because most of this guide is out of scope

NetWeaver 7.5 is a **generic platform** guide. It covers AS ABAP, AS Java, the
Enterprise Portal, TREX, the Content Server, ALE/IDoc, the SAP GUI, five
non-HANA databases, and both UNIX and Windows host hardening. MonitorRisk is an
**offline S/4HANA RISE + BTP** config-review tool. The RISE contract and the
S/4HANA/HANA target scope out whole chapters of this guide **by construction**,
not by omission:

| Guide chapter | Status here | Why |
|---|---|---|
| OS security — UNIX/LINUX & Windows (SUID, NFS/NIS, `/usr/sap` perms, UMASK, SAP_<SID>_GlobalAdmin, `<sid>adm`) | **Out of scope** | In RISE the customer contractually has **no OS access**; the host is SAP ECS's. A tool premised on customer-supplied exports cannot read, and is not responsible for, `/etc/passwd` or NTFS ACLs. |
| Non-HANA databases — Oracle (OPS$, `sqlnet.ora`), MaxDB, ASE, Db2, SQL Server | **Out of scope** | RISE S/4HANA runs on **HANA**. HANA DB security is covered in depth (below); the other five engines do not occur in the target estate. |
| AS Java — UME, JAAS, Web Dynpro Java `DevelopmentMode`, servlet_jsp, deploy service, secure store | **Out of scope** | S/4HANA is ABAP + HANA. The Java stack is not part of an S/4HANA RISE system. (BTP, the modern Java-adjacent surface, **is** covered — `btpcloud`, `intglayer`, `capxsuaa`.) |
| Enterprise Portal, KM, Collaboration, TREX, Content Server, SLD, NWDI, Universal Worklist | **Out of scope** | Legacy NetWeaver components not shipped with S/4HANA RISE. |
| Network topology — firewalls, DMZ, SAProuter, network zones | **Out of scope (architecture)** | Landscape architecture, provider-operated in RISE, and not a fact any config export states. The guide itself presents these as recommendations, not checkable settings. |
| SAP's own services — EarlyWatch Alert, Security Optimization Service, Configuration Validation | **N/A (peer tooling)** | These are the SAP services MonitorRisk sits alongside; not requirements to audit. |

Everything below is the part that **is** in scope: AS ABAP hardening, HANA
database security, the message server, the Web Dispatcher (where customer-run),
SNC/TLS, the audit log, standard users, and data protection.

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
| **Web Dispatcher — admin-interface hardening** (`icm/HTTP/admin_<n>` PORT / CLIENTHOST / ALLOWPUB, HTTPS) | Covered (for customer-run WD) | `webdisp_security` + `data/webdisp_baseline.json` |
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

## Genuine gaps — and why none warrants a new firing check

The guide surfaces four things the tool does not check. Each was evaluated for a
check and **deliberately left out**, because firing on it would either misfire
or claim a fact an offline export cannot support. This is the same discipline
that leaves `SECSTO-A` unchecked and that drives the four-state coverage model:
a check that cannot be right is worse than an honest gap.

### 1. Message-server per-port ACL files — `ms/acl_file_{ext,int,admin,extbnd}`

The guide devotes a table to four per-port ACL-file parameters, one for each
message-server port. The tool checks none of them by name. **Left as a gap**,
because:

- The load-bearing ACL — `ms/acl_info`, which decides who may register as an
  application server (the rogue-app-server attack) — is already checked at
  `TRUST-010`, rule content and all.
- The per-port files are **defense-in-depth over that same port**. An empty
  `ms/acl_file_int` on a system whose `ms/acl_info` is populated adds no real
  exposure; an empty one on a system whose `ms/acl_info` is *also* bad is
  already reported by `TRUST-010`. There is no clean incremental signal.
- Firing on "present but empty" would misfire on the common case: an empty
  `ms/acl_file_admin` is irrelevant when `ms/admin_port = 0` (the compliant
  state the tool already checks). Correct firing would need per-port
  reachability the export does not state.

### 2. Web Dispatcher → back-end encryption — `wdisp/ssl_encrypt`

The guide recommends HTTPS between the Web Dispatcher and the back-end systems.
**Left as a gap**, because:

- The guide makes it **conditional** in its own words: use it *"if the network
  between SAP Web Dispatcher and the back-end systems is not sufficiently
  secured otherwise."* A tool cannot see whether that network is secured, so an
  unconditional finding would be a false positive.
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

The NetWeaver 7.5 guide is a broad platform document most of which a RISE /
S/4HANA / HANA offline scanner scopes out for structural reasons — no OS access,
no non-HANA databases, no Java stack. Within the part that **is** in scope, the
guide **validates** the tool's coverage: every concrete AS-ABAP and HANA control
it states is already checked, and the HANA and RAL coverage is more thorough
than the guide's own text. The four residual gaps are all conditional or
out-of-scope; **no new firing check is warranted**, and inventing one would
lower the tool's quality rather than raise it. The gaps are recorded above so
that a future move toward **on-premise** (non-RISE) coverage — where OS access,
customer-run Web Dispatchers, and `wdisp/ssl_encrypt` become real — has the
list ready.
