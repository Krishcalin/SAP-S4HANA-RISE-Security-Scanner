# Security Policy

## Reporting a vulnerability

**Do not open a public issue.**

MonitorRisk is a security tool that reads SAP configuration exports and, in
connected mode, talks to live SAP systems. A vulnerability report filed in a
public issue is a working attack published to everyone who runs it, before there
is a fix.

**Report privately, by one of these routes:**

1. **GitHub private vulnerability reporting** — the *Report a vulnerability*
   button under this repository's **Security** tab. Preferred: it keeps the
   report, the discussion and the eventual advisory in one place.
2. **Email** — krishnendu.de@hotmail.com, subject line beginning
   `SECURITY:`.

### What helps

- what an attacker gains, in one sentence — read a file, execute code, escalate
  privilege, read another tenant's findings
- the version or commit
- reproduction steps, or a proof of concept if you have one
- whether it is already public anywhere

### What to expect

| | |
|---|---|
| acknowledgement | within **3 working days** |
| initial assessment | within **10 working days** |
| fix or a stated position | as fast as severity warrants; you will be told which |
| credit | offered by name or handle unless you would rather not |

This is a single-maintainer project, so those are honest commitments rather than
a team's SLA. If a deadline slips you will be told, not left waiting.

### Coordinated disclosure

Please give a reasonable window before publishing — **90 days** is the usual
convention and is fine here. If a fix is going to take longer than that, that is
a conversation, not a refusal. If a vulnerability is already being exploited,
say so and the timetable becomes immediate.

You will not be pursued for reporting something you found in good faith.

---

## Scope

**In scope** — the code in this repository:

- the scanner and its modules (`sap_scanner.py`, `modules/`)
- the server, its API and its authentication (`server/`)
- the console (`frontend/`)
- the connectors (`collect/`)
- the container image and its build

Things worth looking at hardest, because they carry the most consequence:

- **the connectors.** They talk to production SAP systems. They are read-only by
  design and the read-only guarantee is enforced in the transport rather than by
  convention — if you can get one of them to perform a state-changing operation,
  that is the report I most want to receive.
- **authentication, sessions and the second factor** in `server/`.
- **tenant and system scoping.** Findings are scoped per system; a way to read
  another scope's findings is a serious defect.
- **anything that makes a scan report clean when it is not.** This product's
  central claim is that it never presents "we could not look" as "we looked and
  found nothing". A way to make a scan silently under-report is a security
  finding here, not merely a bug.

**Out of scope:**

- vulnerabilities in **SAP software itself** — report those to SAP
  ([SAP's security page](https://www.sap.com/about/trust-center/security.html)),
  not here
- findings this tool *reports about your own SAP estate*; those are your systems
  to fix
- third-party dependencies, unless this repository uses them in a way that
  creates the vulnerability. See
  [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
- results from scanning a system you are not authorised to assess. This tool is
  for **authorised assessments only** — see the disclaimer in
  [README.md](README.md)

---

## A note on this repository being public

The source is readable so it can be reviewed — including by people looking for
weaknesses in it, which is welcome and is part of why it is public.

It is **not** open source. Reading and reviewing are permitted; running, copying,
forking, modifying or redistributing it are not, without written permission. See
[LICENSE](LICENSE) and [CONTRIBUTING.md](CONTRIBUTING.md).

Security research on your **own** copy, for the purpose of reporting to me, is
permitted and encouraged — that permission is granted here explicitly so nobody
has to wonder whether the licence forbids the thing this file asks for.

**Contact:** krishnendu.de@hotmail.com
