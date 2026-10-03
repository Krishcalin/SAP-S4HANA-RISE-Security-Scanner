"""MITRE ATT&CK mapping for MonitorRisk's observed-behaviour detections.

ATT&CK describes what an ADVERSARY DOES. So this maps the retrospective
log-based threat detections — the LogServ families that record behaviour an
attacker would exhibit (anomalous logons, brute force, audit-log tampering, OS
commands, exploitation of exposed services) — to ATT&CK techniques. It does NOT
map configuration or custom-code findings: those are weaknesses that ENABLE a
technique, not a technique observed, and tagging a misconfiguration with an
ATT&CK ID would misrepresent what the finding is.

WHY TECHNIQUE-LEVEL IS WORTH DOING. Microsoft's Sentinel-for-SAP maps its SAP
rules to ATT&CK TACTICS only — it assigns no technique IDs — and there is no
official MITRE "ATT&CK for SAP" matrix. So a technique-level mapping is genuinely
ahead of the field, but it is also partly a judgement call. The discipline here:

  * assign a technique ID only where a real ATT&CK technique genuinely fits;
  * fall back to a TACTIC-only tag (technique = None) where a SAP-specific threat
    has no clean technique (e.g. debug-replace), rather than inventing precision;
  * prefer the BASE technique over an OS-specific sub-technique that does not fit
    SAP (SAP audit-log deletion is T1070, not "Clear Windows Event Logs");
  * every mapping carries a `confidence` (high/medium/low) and a `source`, and an
    unmapped finding travels with the REASON it is unmapped — a mapping whose
    provenance is not visible is indistinguishable from a guess.

Sources: attack.mitre.org (every technique id/name/tactic verified there) and
Microsoft's Sentinel-for-SAP security-content reference for the tactic framing.
No new check ids; this is a mapping over EXISTING checks, attached once in
base_auditor like the OWASP mapping.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

#: The ATT&CK Enterprise tactics this product's SAP detections touch (TA ids for
#: reference; names are what findings carry).
TACTICS: Dict[str, str] = {
    "Reconnaissance": "TA0043",
    "Initial Access": "TA0001",
    "Execution": "TA0002",
    "Persistence": "TA0003",
    "Privilege Escalation": "TA0004",
    "Defense Evasion": "TA0005",
    "Credential Access": "TA0006",
    "Discovery": "TA0007",
    "Lateral Movement": "TA0008",
    "Collection": "TA0009",
    "Exfiltration": "TA0010",
}

#: Technique id -> canonical name (as published on attack.mitre.org). Kept in one
#: place so every mapping below names its technique identically.
TECHNIQUES: Dict[str, str] = {
    "T1078": "Valid Accounts",
    "T1078.001": "Valid Accounts: Default Accounts",
    "T1110": "Brute Force",
    "T1110.003": "Brute Force: Password Spraying",
    "T1059": "Command and Scripting Interpreter",
    "T1562.001": "Impair Defenses: Disable or Modify Tools",
    "T1213": "Data from Information Repositories",
    "T1190": "Exploit Public-Facing Application",
    "T1133": "External Remote Services",
    "T1021": "Remote Services",
    "T1595.002": "Active Scanning: Vulnerability Scanning",
}

#: check_id -> (technique_id | None, tactic, confidence, source).
#: technique_id None means a deliberate TACTIC-ONLY mapping (no clean technique).
#: Keyed on the full check id; LogServ detections are enumerated individually
#: because each records a distinct behaviour.
_MAP: Dict[str, Tuple[Optional[str], str, str, str]] = {
    # ── Security Audit Log behaviour patterns (log_review) ──────────────────
    "LREV-PAT-001": ("T1078", "Initial Access", "high",
                     "Privileged valid-account logon; MITRE T1078, cf. Sentinel "
                     "'Sensitive privileged user logged in'"),
    "LREV-PAT-002": ("T1110", "Credential Access", "high",
                     "Failed run then success = brute force; MITRE T1110"),
    "LREV-PAT-003": ("T1078.001", "Initial Access", "high",
                     "SAP-delivered default accounts; MITRE T1078.001 Default Accounts"),
    "LREV-PAT-004": (None, "Execution", "low",
                     "SAP debug-replace has no clean ATT&CK technique; tactic-only "
                     "(cf. Sentinel 'Data has Changed during Debugging' -> Execution)"),
    "LREV-PAT-005": ("T1213", "Collection", "medium",
                     "High-volume direct table access; MITRE T1213 (base; the "
                     "sub-techniques are Confluence/SharePoint, not SAP)"),
    "LREV-PAT-006": ("T1562.001", "Defense Evasion", "high",
                     "Security Audit Log config change; MITRE T1562.001"),
    "LREV-PAT-007": ("T1078", "Initial Access", "high",
                     "Privileged logon from a rare terminal = anomalous valid "
                     "account; MITRE T1078"),
    "LREV-PAT-008": ("T1059", "Execution", "high",
                     "External OS command from SAP; MITRE T1059 (base)"),
    "LREV-PAT-009": ("T1078", "Defense Evasion", "medium",
                     "Technical account used interactively = valid-account misuse; "
                     "MITRE T1078"),
    "LREV-PAT-010": ("T1110.003", "Credential Access", "high",
                     "Failed logons across many accounts = password spraying; "
                     "MITRE T1110.003"),
    # ── Access violations (log_review) ──────────────────────────────────────
    "LVIO-FF-001": ("T1078", "Privilege Escalation", "medium",
                    "Firefighter/emergency elevated access use; MITRE T1078, cf. "
                    "Sentinel 'Assignment of a sensitive profile' -> Priv Esc"),
    "LVIO-OFH-001": ("T1078", "Defense Evasion", "medium",
                     "Privileged change outside business hours = valid-account "
                     "misuse; MITRE T1078"),
    # ── Gateway / RFC log review (logserv_review) ───────────────────────────
    "GWLOG-001": ("T1190", "Initial Access", "medium",
                  "External program registered/started via the RFC gateway "
                  "(10KBLAZE class); the outcome maps to MITRE T1190 + T1059 "
                  "(the registration act itself has no clean technique)"),
    "GWLOG-002": ("T1190", "Initial Access", "low",
                  "Gateway connections blocked by the ACL = attempted access the "
                  "control stopped; MITRE T1190 (attempted)"),
    "GWLOG-003": ("T1190", "Initial Access", "medium",
                  "Gateway allowed a connection its ACL would deny; MITRE T1190"),
    # ── HANA database log review (logserv_review) ───────────────────────────
    "HANALOG-001": ("T1562.001", "Defense Evasion", "high",
                    "HANA audit configuration change; MITRE T1562.001, cf. Sentinel "
                    "'HANA DB Audit Trail Policy Changes'"),
    "HANALOG-002": ("T1078", "Privilege Escalation", "medium",
                    "Privileged HANA database activity; MITRE T1078, cf. Sentinel "
                    "'HANA DB - User Admin actions' -> Priv Esc"),
    "HANALOG-003": ("T1110", "Credential Access", "high",
                    "Failed HANA logons = brute force; MITRE T1110"),
    # ── ICM / web log review (logserv_review) ───────────────────────────────
    "ICMLOG-001": ("T1190", "Initial Access", "low",
                   "Administrative web path accessed; MITRE T1190 (may be "
                   "legitimate administration)"),
    "ICMLOG-002": ("T1595.002", "Reconnaissance", "high",
                   "HTTP scanning pattern; MITRE T1595.002 Vulnerability Scanning"),
    "ICMLOG-003": ("T1190", "Initial Access", "high",
                   "Remote-execution HTTP endpoint used (ICMAD/CVE-2025-31324 "
                   "class); MITRE T1190"),
    # ── Network log review (logserv_review) ─────────────────────────────────
    "NETLOG-001": ("T1021", "Lateral Movement", "low",
                   "Connections to SAP service ports; MITRE T1021 Remote Services "
                   "(may be legitimate access)"),
    "NETLOG-002": ("T1595.002", "Reconnaissance", "medium",
                   "Blocked network connection attempts = scanning/probing; "
                   "MITRE T1595.002"),
    "NETLOG-003": ("T1133", "Initial Access", "medium",
                   "SAP service port reached from a public source; MITRE T1133 "
                   "External Remote Services"),
    # ── Config-vs-log correlation (correlation): exposure being USED ────────
    "CORR-GW-001": ("T1190", "Initial Access", "medium",
                    "Gateway exposure is being reached, not just misconfigured; "
                    "MITRE T1190"),
    "CORR-HANA-001": ("T1078", "Defense Evasion", "medium",
                      "HANA privileged access used where auditing is weak; "
                      "MITRE T1078"),
    "CORR-ICM-001": ("T1190", "Initial Access", "medium",
                     "Exposed web service is being reached; MITRE T1190"),
    "CORR-NET-001": ("T1133", "Initial Access", "medium",
                     "Exposed network service is being reached; MITRE T1133"),
}

#: Why a finding carries no ATT&CK mapping — so an unmapped one travels with the
#: reason, not a silent blank.
_UNMAPPED_REASON = (
    "Not an observed-behaviour detection: ATT&CK describes adversary actions, and "
    "this finding is a configuration, authorization, compliance or custom-code "
    "weakness that may ENABLE a technique rather than record one."
)


def map_mitre(check_id: Optional[str]) -> Dict[str, Any]:
    """ATT&CK mapping for one finding, with the basis it rests on.

    `basis` is always present: "check" when this check id has a mapping (which may
    be TACTIC-ONLY, with `technique` None), or None with an `unmapped_reason` when
    the finding is not an observed-behaviour detection. Mirrors the shape of
    owasp_mapping.map_finding.
    """
    cid = str(check_id or "")
    entry = _MAP.get(cid)
    if entry is None:
        return {"basis": None, "unmapped_reason": _UNMAPPED_REASON}
    technique, tactic, confidence, source = entry
    return {
        "basis": "check",
        "technique": technique,
        "technique_name": TECHNIQUES.get(technique) if technique else None,
        "tactic": tactic,
        "tactic_id": TACTICS.get(tactic),
        "confidence": confidence,
        "source": source,
    }


def mapped_check_ids() -> List[str]:
    """Every check id that carries an ATT&CK mapping (for coverage/tests)."""
    return sorted(_MAP)


def coverage(check_ids: Sequence[str]) -> Dict[str, Any]:
    """How many of `check_ids` carry an ATT&CK mapping, split by technique vs
    tactic-only vs unmapped. Mirrors owasp_mapping.coverage."""
    technique = tactic_only = unmapped = 0
    for cid in check_ids:
        m = map_mitre(cid)
        if m["basis"] is None:
            unmapped += 1
        elif m.get("technique"):
            technique += 1
        else:
            tactic_only += 1
    return {"total": len(check_ids), "technique": technique,
            "tactic_only": tactic_only, "unmapped": unmapped}
