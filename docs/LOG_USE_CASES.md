# Log-based detection coverage

<!-- GENERATED FILE — DO NOT EDIT BY HAND.
     Produced by tools/build_log_use_cases.py; severities are read
     from the code, the use-case set from the catalogue. -->

Every threat, violation and correlation use case MonitorRisk derives from the SAP LogServ / Security Audit Log window, mapped to its severity, an indicative MITRE ATT&CK technique, and the SAP Security Baseline area it relates to. This is a **retrospective** review over an exported window — not monitoring, not real-time; nothing here is live.

- A **threat** is a pattern of attacker or abuse behaviour the log recorded.
- A **violation** is an access rule broken (emergency access used outside its process; an off-hours privileged change).
- A **correlation** fires only where a configuration weakness and a log observation of it being used coincide — an active-exploitation indicator.

**28 use cases** — 6 critical, 15 high, 7 medium (22 threat, 2 violation, 4 correlation). Every one is proven to fire in the test suite.

MITRE ATT&CK mappings are indicative, for orientation; the scanner's own compliance engine maps to CIS / NIST / SAP Baseline. The **SAP Baseline area** names the related configuration requirement family — the log checks themselves are beyond-baseline.

## Security Audit Log patterns

_Threat — `LREV-PAT-*`._ The ABAP Security Audit Log window, read retrospectively for attacker and abuse behaviour.

| Check | Use case | Severity | MITRE ATT&CK | SAP Baseline area |
|---|---|---|---|---|
| `LREV-PAT-001` | Off-hours privileged dialog logon | HIGH | T1078 Valid Accounts | Audit log review (AUDIT-A) |
| `LREV-PAT-002` | Failed-logon run ending in a success | CRITICAL | T1110 Brute Force | Audit log review (AUDIT-A) |
| `LREV-PAT-003` | Standard / default account active | HIGH | T1078.001 Valid Accounts: Default Accounts | System trust & standard users (STDUSR) |
| `LREV-PAT-004` | Debug activity | HIGH | T1211 Exploitation for Defense Evasion | Audit log review (AUDIT-A) |
| `LREV-PAT-005` | High-volume direct table access | MEDIUM | T1005 Data from Local System | Audit log review (AUDIT-A) |
| `LREV-PAT-006` | Audit configuration changed | CRITICAL | T1562.001 Impair Defenses: Disable or Modify Tools | Audit log review (AUDIT-A) |
| `LREV-PAT-007` | Privileged logon from a rare terminal | MEDIUM | T1078 Valid Accounts | Audit log review (AUDIT-A) |
| `LREV-PAT-008` | External OS command (SM49 / SM69) | HIGH | T1059 Command and Scripting Interpreter | Audit log review (AUDIT-A) |
| `LREV-PAT-009` | Interactive logon by a technical user | HIGH | T1078 Valid Accounts | Audit log review (AUDIT-A) |
| `LREV-PAT-010` | Password spraying | HIGH | T1110.003 Brute Force: Password Spraying | Audit log review (AUDIT-A) |

## Gateway log

_Threat — `GWLOG-*`._ The RFC gateway log — registered external programs and secinfo / reginfo ACL decisions.

| Check | Use case | Severity | MITRE ATT&CK | SAP Baseline area |
|---|---|---|---|---|
| `GWLOG-001` | External program registered or started through the gateway | HIGH | T1210 Exploitation of Remote Services | RFC gateway (RFCGW-A) |
| `GWLOG-002` | Connections blocked by the secinfo / reginfo ACL | MEDIUM | T1046 Network Service Discovery | RFC gateway (RFCGW-A) |
| `GWLOG-003` | Permissive gateway allowed a connection the ACL would deny | HIGH | T1210 Exploitation of Remote Services | RFC gateway (RFCGW-A) |

## HANA audit log

_Threat — `HANALOG-*`._ The HANA audit trail — audit-policy changes, privileged activity and failed logons.

| Check | Use case | Severity | MITRE ATT&CK | SAP Baseline area |
|---|---|---|---|---|
| `HANALOG-001` | HANA audit configuration changed | HIGH | T1562.001 Impair Defenses: Disable or Modify Tools | HANA auditing (AUDIT-H) |
| `HANALOG-002` | Privileged DB activity (SYSTEM / privilege grant) | HIGH | T1098 Account Manipulation (with T1078 Valid Accounts) | HANA privileged access (CRITAU-H / STDUSR-H) |
| `HANALOG-003` | Failed HANA database logons | MEDIUM | T1110 Brute Force | HANA authentication (PWDPOL-H) |

## ICM / Web Dispatcher log

_Threat — `ICMLOG-*`._ The ICM / Web Dispatcher HTTP log — the paths requested over the exported window.

| Check | Use case | Severity | MITRE ATT&CK | SAP Baseline area |
|---|---|---|---|---|
| `ICMLOG-001` | Administrative web path reached | HIGH | T1190 Exploit Public-Facing Application | ICF service exposure, SICF (DISCL-A) |
| `ICMLOG-002` | HTTP scanning pattern | MEDIUM | T1595 Active Scanning | ICF service exposure, SICF |
| `ICMLOG-003` | Remote-execution HTTP endpoint used (SOAP / RFC) | HIGH | T1190 Exploit Public-Facing Application | ICF service exposure, SICF |

## Network / firewall log

_Threat — `NETLOG-*`._ The network / firewall log — connections to SAP service ports and their disposition.

| Check | Use case | Severity | MITRE ATT&CK | SAP Baseline area |
|---|---|---|---|---|
| `NETLOG-001` | Connection to an SAP service port | MEDIUM | T1021 Remote Services | Network filtering (NETCF-A) |
| `NETLOG-002` | Blocked connection attempts | MEDIUM | T1046 Network Service Discovery | Network filtering (NETCF-A) |
| `NETLOG-003` | SAP service port reached from a public source | HIGH | T1133 External Remote Services | Network filtering, message server (MSGSRV-A) |

## Governance violations

_Violation — `LVIO-*`._ The audit window crossed with the firefighter log and the privileged set — an access rule broken rather than a raw threat pattern.

| Check | Use case | Severity | MITRE ATT&CK | SAP Baseline area |
|---|---|---|---|---|
| `LVIO-FF-001` | Firefighter account used outside the logged process | HIGH | T1078 Valid Accounts | Emergency access / SOX ITGC |
| `LVIO-OFH-001` | Off-hours privileged change action | HIGH | T1078 Valid Accounts | Privileged access / SOX ITGC |

## Config-vs-log correlations

_Correlation — `CORR-*`._ A configuration weakness and a log observation of it being used, coinciding in one system — an active-exploitation indicator, not a theoretical gap.

| Check | Use case | Severity | MITRE ATT&CK | SAP Baseline area |
|---|---|---|---|---|
| `CORR-GW-001` | Gateway exposure is being used, not just misconfigured | CRITICAL | T1210 Exploitation of Remote Services | RFC gateway (RFCGW-A) |
| `CORR-HANA-001` | HANA privileged access used against weak auditing | CRITICAL | T1078 Valid Accounts (with T1562 Impair Defenses) | HANA auditing / privileged access |
| `CORR-ICM-001` | Exposed web service is being reached | CRITICAL | T1190 Exploit Public-Facing Application | ICF / web-tier exposure |
| `CORR-NET-001` | Exposed network service is being reached | CRITICAL | T1133 External Remote Services (with T1210) | Network filtering |

---

Delivered across PRs **#6** (SAL patterns 008–010), **#8** (violations), **#11** (gateway + correlation), **#12** (HANA / ICM / network); SAL patterns 001–007 pre-existing. Threat patterns and detectors live in `modules/log_review.py` and `modules/logserv_review.py`; correlations in `modules/correlation.py`; the OCSF adapter in `modules/logserv_ocsf.py`.

_Generated by `tools/build_log_use_cases.py`._
