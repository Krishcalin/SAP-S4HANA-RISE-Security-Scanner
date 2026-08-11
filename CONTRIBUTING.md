# Contributing

**This project does not accept external code contributions.**

MonitorRisk is source-available, not open source. The repository is public so the
work can be read, reviewed and evaluated; the copyright is held solely by
Krishnendu De and the licence reserves all rights (see [LICENSE](LICENSE)).

That is why pull requests are declined rather than reviewed, and it is not a
judgement on the code in them. Merging outside contributions into a proprietary
codebase makes the copyright jointly held, which quietly undermines the one thing
the licence asserts — that the software is the exclusive property of its
copyright holder. Sorting that out afterwards is far harder than declining
politely up front.

> This file used to say *"Thanks for your interest in contributing!"* and
> *"Submit a PR with a clear description."* That was written when the project was
> open source and it survived the relicensing. It is corrected here rather than
> quietly deleted, because anyone who acted on the old wording did so in good
> faith and deserves to see why the answer changed.

---

## What *is* welcome

**Bug reports.** If a check misfires, a parser mangles an export, or a finding is
wrong, that is genuinely useful and easy to act on. Open an issue with:

- the Python version and OS
- the module or check id involved (for example `PARAM-014`, `ABAP-SQLI-001`)
- a **de-identified** fragment of the input that triggers it

> ⚠️ **Never attach a real SAP export to a public issue.** They routinely contain
> user names, host names, system ids, RFC destinations and occasionally
> credentials. Reduce it to the few lines that reproduce the problem, and replace
> anything identifying. If you cannot reduce it safely, describe the shape of the
> data instead and email it if asked.

**Corrections to SAP facts.** A wrong SAP Note number, parameter name,
authorisation object or transaction code is worth reporting on its own. This
project treats an unverified SAP identifier as a defect, so a citation to SAP
Help, the SAP Security Baseline or a note number is the most valuable thing you
can attach.

**False positives and false negatives.** Both matter. A check that fires on a
correctly configured system erodes trust in every other finding; a check that
stays silent on a real misconfiguration is worse.

**Questions about whether your intended use is permitted.** Ask. See below.

## What to do instead of a pull request

| you want to | do this |
|---|---|
| fix a bug you found | open an issue describing it — a patch in the issue text is fine and welcome as a *description*, but it will be reimplemented rather than merged |
| use part of this in your own tool | email for permission first |
| use it internally at your company | email — internal evaluation licences are straightforward |
| build something similar | you are free to; ideas are not the thing being reserved here |
| report a security vulnerability | **do not open an issue** — see [SECURITY.md](SECURITY.md) |

## Security vulnerabilities

Reporting a vulnerability in a **public issue** publishes a working attack against
every deployment before there is a fix. This file previously told people to do
exactly that, with a `security` label. It should never have.

Use the process in **[SECURITY.md](SECURITY.md)** instead.

---

**Contact:** krishnendu.de@hotmail.com
