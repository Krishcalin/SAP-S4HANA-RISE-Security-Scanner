# Contributing

**Pull requests are welcome.**

MonitorRisk is open source under the [MIT licence](LICENSE). The repository is
public so the work can be read, reviewed, used, forked and built on, and code
contributions are accepted like any other MIT project. By opening a pull request
you agree that your contribution is licensed under the same terms.

> This file said the opposite between 2026-08-11 and the return to MIT: that
> pull requests were declined because merging outside work into a proprietary
> codebase would make the copyright jointly held. That reasoning was sound while
> the licence was proprietary and is simply void now. It is corrected here rather
> than quietly deleted, because anyone who read the old wording and did not send
> a patch deserves to see that the answer changed.

The most valuable contributions are corrections to **SAP facts** — a note number,
an authorization object, a parameter name, a requirement id. A wrong SAP fact in
this product is worse than a missing feature: it is a confident claim about
someone's estate that does not hold, and it is the one class of defect a reader
cannot check without leaving the tool.

---

## What *is* welcome

**Bug reports.** If a check misfires, a parser mangles an export, or a finding is
wrong, that is genuinely useful and easy to act on. Open an issue with:

- the Python version and OS
- the module or check id involved (for example `PARAM-login/min_password_lng`, `ABAP-SQLI-001`)
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
