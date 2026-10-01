"""Generate docs/LOG_USE_CASES.md — the log-based detection coverage matrix.

    python -m tools.build_log_use_cases          # write the doc
    python -m tools.build_log_use_cases --check   # exit 1 if it is stale

WHY GENERATED, NOT HAND-WRITTEN. The matrix pairs each log-based use case with a
severity, a MITRE ATT&CK technique and the SAP Baseline area it relates to. The
severity is read from the CODE (the single source of truth), and the SET of use
cases is held against the live catalogue, so neither can drift: add, remove or
re-severity a log check and this doc — and its --check gate — move with it. Only
the ATT&CK and Baseline-area columns are authored here, because the scanner maps
to CIS / NIST / SAP Baseline rather than ATT&CK and those labels live nowhere else.

WHAT COUNTS AS A LOG USE CASE. The threat PATTERNS over the audit-log window
(LREV-PAT-*, not the LREV-SRC/FLT/WIN log-health checks), the broader LogServ
log-class detectors (GWLOG/HANALOG/ICMLOG/NETLOG-*), the governance violations
(LVIO-*) and the config-vs-log correlations (CORR-*). `tests/test_log_use_cases.py`
holds the authored id set equal to exactly those catalogue ids.
"""
from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

MODULES = ROOT / "modules"
TARGET = ROOT / "docs" / "LOG_USE_CASES.md"

#: The check-id prefixes that make a check a "log use case" (threat / violation /
#: correlation), as opposed to the LREV-SRC/FLT/WIN log-HEALTH checks.
USE_CASE_PREFIXES = ("LREV-PAT-", "LVIO-", "GWLOG-", "HANALOG-", "ICMLOG-",
                     "NETLOG-", "CORR-")

#: The modules whose finding() calls carry these ids, read for the severity.
_SEVERITY_SOURCES = ("log_review", "logserv_review", "correlation")
_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# ── the authored half: MITRE ATT&CK technique + related SAP Baseline area ───────
# Severity is NOT here — it is derived from the code. Each group is (title, tag,
# kind, blurb, rows); each row is (check_id, use case, mitre id, mitre name,
# baseline area). Order is the reading order of the matrix.
GROUPS = [
    ("Security Audit Log patterns", "LREV-PAT", "threat",
     "The ABAP Security Audit Log window, read retrospectively for attacker and "
     "abuse behaviour.", [
        ("LREV-PAT-001", "Off-hours privileged dialog logon", "T1078", "Valid Accounts", "Audit log review (AUDIT-A)"),
        ("LREV-PAT-002", "Failed-logon run ending in a success", "T1110", "Brute Force", "Audit log review (AUDIT-A)"),
        ("LREV-PAT-003", "Standard / default account active", "T1078.001", "Valid Accounts: Default Accounts", "System trust & standard users (STDUSR)"),
        ("LREV-PAT-004", "Debug activity", "T1211", "Exploitation for Defense Evasion", "Audit log review (AUDIT-A)"),
        ("LREV-PAT-005", "High-volume direct table access", "T1005", "Data from Local System", "Audit log review (AUDIT-A)"),
        ("LREV-PAT-006", "Audit configuration changed", "T1562.001", "Impair Defenses: Disable or Modify Tools", "Audit log review (AUDIT-A)"),
        ("LREV-PAT-007", "Privileged logon from a rare terminal", "T1078", "Valid Accounts", "Audit log review (AUDIT-A)"),
        ("LREV-PAT-008", "External OS command (SM49 / SM69)", "T1059", "Command and Scripting Interpreter", "Audit log review (AUDIT-A)"),
        ("LREV-PAT-009", "Interactive logon by a technical user", "T1078", "Valid Accounts", "Audit log review (AUDIT-A)"),
        ("LREV-PAT-010", "Password spraying", "T1110.003", "Brute Force: Password Spraying", "Audit log review (AUDIT-A)"),
     ]),
    ("Gateway log", "GWLOG", "threat",
     "The RFC gateway log — registered external programs and secinfo / reginfo ACL "
     "decisions.", [
        ("GWLOG-001", "External program registered or started through the gateway", "T1210", "Exploitation of Remote Services", "RFC gateway (RFCGW-A)"),
        ("GWLOG-002", "Connections blocked by the secinfo / reginfo ACL", "T1046", "Network Service Discovery", "RFC gateway (RFCGW-A)"),
        ("GWLOG-003", "Permissive gateway allowed a connection the ACL would deny", "T1210", "Exploitation of Remote Services", "RFC gateway (RFCGW-A)"),
     ]),
    ("HANA audit log", "HANALOG", "threat",
     "The HANA audit trail — audit-policy changes, privileged activity and failed "
     "logons.", [
        ("HANALOG-001", "HANA audit configuration changed", "T1562.001", "Impair Defenses: Disable or Modify Tools", "HANA auditing (AUDIT-H)"),
        ("HANALOG-002", "Privileged DB activity (SYSTEM / privilege grant)", "T1098", "Account Manipulation (with T1078 Valid Accounts)", "HANA privileged access (CRITAU-H / STDUSR-H)"),
        ("HANALOG-003", "Failed HANA database logons", "T1110", "Brute Force", "HANA authentication (PWDPOL-H)"),
     ]),
    ("ICM / Web Dispatcher log", "ICMLOG", "threat",
     "The ICM / Web Dispatcher HTTP log — the paths requested over the exported "
     "window.", [
        ("ICMLOG-001", "Administrative web path reached", "T1190", "Exploit Public-Facing Application", "ICF service exposure, SICF (DISCL-A)"),
        ("ICMLOG-002", "HTTP scanning pattern", "T1595", "Active Scanning", "ICF service exposure, SICF"),
        ("ICMLOG-003", "Remote-execution HTTP endpoint used (SOAP / RFC)", "T1190", "Exploit Public-Facing Application", "ICF service exposure, SICF"),
     ]),
    ("Network / firewall log", "NETLOG", "threat",
     "The network / firewall log — connections to SAP service ports and their "
     "disposition.", [
        ("NETLOG-001", "Connection to an SAP service port", "T1021", "Remote Services", "Network filtering (NETCF-A)"),
        ("NETLOG-002", "Blocked connection attempts", "T1046", "Network Service Discovery", "Network filtering (NETCF-A)"),
        ("NETLOG-003", "SAP service port reached from a public source", "T1133", "External Remote Services", "Network filtering, message server (MSGSRV-A)"),
     ]),
    ("Governance violations", "LVIO", "violation",
     "The audit window crossed with the firefighter log and the privileged set — an "
     "access rule broken rather than a raw threat pattern.", [
        ("LVIO-FF-001", "Firefighter account used outside the logged process", "T1078", "Valid Accounts", "Emergency access / SOX ITGC"),
        ("LVIO-OFH-001", "Off-hours privileged change action", "T1078", "Valid Accounts", "Privileged access / SOX ITGC"),
     ]),
    ("Config-vs-log correlations", "CORR", "correlation",
     "A configuration weakness and a log observation of it being used, coinciding in "
     "one system — an active-exploitation indicator, not a theoretical gap.", [
        ("CORR-GW-001", "Gateway exposure is being used, not just misconfigured", "T1210", "Exploitation of Remote Services", "RFC gateway (RFCGW-A)"),
        ("CORR-HANA-001", "HANA privileged access used against weak auditing", "T1078", "Valid Accounts (with T1562 Impair Defenses)", "HANA auditing / privileged access"),
        ("CORR-ICM-001", "Exposed web service is being reached", "T1190", "Exploit Public-Facing Application", "ICF / web-tier exposure"),
        ("CORR-NET-001", "Exposed network service is being reached", "T1133", "External Remote Services (with T1210)", "Network filtering"),
     ]),
]

_KIND_LABEL = {"threat": "Threat", "violation": "Violation", "correlation": "Correlation"}


def authored_ids() -> List[str]:
    return [row[0] for _t, _tag, _k, _b, rows in GROUPS for row in rows]


def _severity_expr_best(node: ast.AST) -> Optional[str]:
    """The most severe SEVERITY_* named anywhere in a `severity=` expression.

    A plain `self.SEVERITY_HIGH` yields HIGH; a conditional
    `self.SEVERITY_HIGH if x else self.SEVERITY_MEDIUM` yields HIGH (the worst
    case the check can raise), which is how the matrix should read it."""
    names = [n.attr.replace("SEVERITY_", "") for n in ast.walk(node)
             if isinstance(n, ast.Attribute) and n.attr.startswith("SEVERITY_")]
    if not names:
        return None
    return min(names, key=lambda s: _SEV_RANK.get(s, 99))


def severities() -> Dict[str, str]:
    """{check id: severity} read from the finding() calls in the log modules."""
    out: Dict[str, str] = {}
    for stem in _SEVERITY_SOURCES:
        tree = ast.parse((MODULES / (stem + ".py")).read_text(encoding="utf-8"))
        for call in ast.walk(tree):
            if not isinstance(call, ast.Call):
                continue
            kw = {k.arg: k.value for k in call.keywords if k.arg}
            cid, sev = kw.get("check_id"), kw.get("severity")
            if (isinstance(cid, ast.Constant) and isinstance(cid.value, str)
                    and sev is not None):
                best = _severity_expr_best(sev)
                if best:
                    out[cid.value] = best
    return out


def build() -> str:
    sev = severities()
    ids = authored_ids()
    missing = [c for c in ids if c not in sev]
    if missing:
        raise SystemExit("no severity found in code for: %s" % ", ".join(missing))

    kinds = {k: 0 for k in _KIND_LABEL}
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for _t, _tag, kind, _b, rows in GROUPS:
        kinds[kind] += len(rows)
        for row in rows:
            sev_counts[sev[row[0]]] += 1
    total = len(ids)

    lines: List[str] = []
    lines.append("# Log-based detection coverage")
    lines.append("")
    lines.append("<!-- GENERATED FILE — DO NOT EDIT BY HAND.")
    lines.append("     Produced by tools/build_log_use_cases.py; severities are read")
    lines.append("     from the code, the use-case set from the catalogue. -->")
    lines.append("")
    lines.append("Every threat, violation and correlation use case MonitorRisk derives from "
                 "the SAP LogServ / Security Audit Log window, mapped to its severity, an "
                 "indicative MITRE ATT&CK technique, and the SAP Security Baseline area it "
                 "relates to. This is a **retrospective** review over an exported window — "
                 "not monitoring, not real-time; nothing here is live.")
    lines.append("")
    lines.append("- A **threat** is a pattern of attacker or abuse behaviour the log recorded.")
    lines.append("- A **violation** is an access rule broken (emergency access used outside "
                 "its process; an off-hours privileged change).")
    lines.append("- A **correlation** fires only where a configuration weakness and a log "
                 "observation of it being used coincide — an active-exploitation indicator.")
    lines.append("")
    lines.append("**%d use cases** — %d critical, %d high, %d medium "
                 "(%d threat, %d violation, %d correlation). Every one is proven to fire in "
                 "the test suite." % (total, sev_counts["CRITICAL"], sev_counts["HIGH"],
                                      sev_counts["MEDIUM"], kinds["threat"],
                                      kinds["violation"], kinds["correlation"]))
    lines.append("")
    lines.append("MITRE ATT&CK mappings are indicative, for orientation; the scanner's own "
                 "compliance engine maps to CIS / NIST / SAP Baseline. The **SAP Baseline "
                 "area** names the related configuration requirement family — the log checks "
                 "themselves are beyond-baseline.")
    lines.append("")

    for title, tag, kind, blurb, rows in GROUPS:
        lines.append("## %s" % title)
        lines.append("")
        lines.append("_%s — `%s-*`._ %s" % (_KIND_LABEL[kind], tag, blurb))
        lines.append("")
        lines.append("| Check | Use case | Severity | MITRE ATT&CK | SAP Baseline area |")
        lines.append("|---|---|---|---|---|")
        for cid, uc, mid, mname, area in rows:
            lines.append("| `%s` | %s | %s | %s %s | %s |"
                         % (cid, uc, sev[cid], mid, mname, area))
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("Delivered across PRs **#6** (SAL patterns 008–010), **#8** (violations), "
                 "**#11** (gateway + correlation), **#12** (HANA / ICM / network); SAL "
                 "patterns 001–007 pre-existing. Threat patterns and detectors live in "
                 "`modules/log_review.py` and `modules/logserv_review.py`; correlations in "
                 "`modules/correlation.py`; the OCSF adapter in `modules/logserv_ocsf.py`.")
    lines.append("")
    lines.append("_Generated by `tools/build_log_use_cases.py`._")
    lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if docs/LOG_USE_CASES.md is out of date")
    args = ap.parse_args(argv)
    generated = build()
    if args.check:
        current = TARGET.read_text(encoding="utf-8") if TARGET.exists() else ""
        if current != generated:
            print("docs/LOG_USE_CASES.md is out of date — regenerate with "
                  "`python -m tools.build_log_use_cases`")
            return 1
        print("docs/LOG_USE_CASES.md is current")
        return 0
    TARGET.write_text(generated, encoding="utf-8")
    print("Wrote %s: %d log use cases" % (TARGET.relative_to(ROOT), len(authored_ids())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
