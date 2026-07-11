"""
Risk-Prioritization Engine (P1-P4)
==================================
Turns a flat list of findings into a fix-first queue. Each finding is scored on

    severity  x  real-world exploitability  x  exposure

and bucketed into four action tiers (P1 Fix Now -> P4 Backlog) with an SLA window,
so an operator works the highest-actual-risk items first instead of triaging a wall
of CRITICAL/HIGH findings by hand.

Unlike a network-device scanner there is no live CISA-KEV/EPSS feed to consult
offline, so exploitability is derived from the findings themselves — the SAP
HotNews / Security-Notes auditor already identifies missing notes for **actively-
exploited** vulnerabilities (HOTNEWS-003, public exploits / CISA KEV) and HotNews
(Priority 1) notes, and other modules flag well-known privileged attack paths
(SAP*/DDIC default credentials, S_RFCACL / Debug-&-Replace, open gateway/message
server). Exposure is read from the finding's category (Network / RISE-BTP surface).

Design rules (conservative — a signal only ever RAISES priority):
  * An actively-exploited finding never drops below P2 (the KEV-analog floor).
  * The score is advisory; the tier is what an operator acts on.
  * Every boost carries a cited rationale factor so the ranking is explainable.

Pure standard library.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

# ── action tiers ──────────────────────────────────────────────────────────────
TIER_META: Dict[str, Dict[str, str]] = {
    "P1": {"label": "Fix Now", "window": "24-72 hours",
           "blurb": "Critical and actively exploited, or critical on an exposed surface — treat as an incident."},
    "P2": {"label": "Fix This Week", "window": "within 7 days",
           "blurb": "Critical weakness, a HotNews/known-exploited gap, or a high-risk exposure — schedule a change now."},
    "P3": {"label": "Planned Remediation", "window": "within 30 days",
           "blurb": "Meaningful hardening gap — fold into the next maintenance window."},
    "P4": {"label": "Backlog / Accept", "window": "next review cycle",
           "blurb": "Low residual risk — remediate opportunistically or formally accept."},
}
TIER_RANK = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}

_SEV_BASE = {"CRITICAL": 65, "HIGH": 42, "MEDIUM": 22, "LOW": 8, "INFO": 0}

# Categories that put a finding on an attacker-reachable surface.
_EXPOSURE_CATEGORIES = {
    "Network & Service Exposure", "Network & Integration Layer",
    "RISE / BTP Security", "BTP Cloud Attack Surface", "Fiori & UI Layer",
}
_EXPOSURE_KW = re.compile(
    r"\b(internet|external|publicly|public[- ](?:facing|internet)|0\.0\.0\.0|exposed|"
    r"open port|reachable|saprouter|message server|web dispatcher|webdispatcher|gateway|"
    r"anonymous|unauthenticated)\b",
    re.IGNORECASE)
# Well-known privileged attack paths (SAP-specific), which raise real exploitability.
# Only SPECIFIC signals — generic descriptive phrases like "profile parameter" are
# excluded (they appear in benign config-hardening findings and would over-escalate).
_PRIV_KW = re.compile(
    r"(\bSAP\*|\bDDIC\b|\bEARLYWATCH\b|\bdefault password\b|\bstandard user\b|\bS_RFCACL\b|"
    r"\bdebug.{0,6}replace|\bSAP_ALL\b|\bSAP_NEW\b|\bfull authoriz|\*\s*authoriz|"
    r"\btrusted rfc\b|\bgateway (?:acl|secinfo|reginfo)\b)",
    re.IGNORECASE)
_EXPLOIT_KW = re.compile(
    r"(actively.?exploit|exploited in the wild|public exploit|CISA KEV|known.?exploited)",
    re.IGNORECASE)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _text(f: Dict[str, Any]) -> str:
    parts = [str(f.get("title", "")), str(f.get("description", ""))]
    parts += [str(r) for r in (f.get("references") or [])]
    return " ".join(parts)


def _cve_cvss(f: Dict[str, Any]):
    det = f.get("details") or {}
    cve = det.get("cve")
    cvss = det.get("cvss")
    if not cve:
        m = _CVE_RE.search(_text(f))
        cve = m.group(0).upper() if m else None
    try:
        cvss = float(cvss) if cvss is not None else None
    except (TypeError, ValueError):
        cvss = None
    return cve, cvss


class PriorityResult:
    """The prioritization verdict for one finding."""
    __slots__ = ("finding", "tier", "score", "factors", "rationale",
                 "exploited", "hotnews", "exposed", "privileged", "cve", "cvss")

    def __init__(self, finding, tier, score, factors, rationale,
                 exploited, hotnews, exposed, privileged, cve, cvss):
        self.finding = finding
        self.tier = tier
        self.score = score
        self.factors = factors
        self.rationale = rationale
        self.exploited = exploited
        self.hotnews = hotnews
        self.exposed = exposed
        self.privileged = privileged
        self.cve = cve
        self.cvss = cvss

    @property
    def tier_rank(self) -> int:
        return TIER_RANK.get(self.tier, 9)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_id": self.finding.get("check_id"),
            "tier": self.tier,
            "tier_label": TIER_META[self.tier]["label"],
            "priority_score": self.score,
            "exploited": self.exploited,
            "hotnews": self.hotnews,
            "exposed": self.exposed,
            "cve": self.cve,
            "cvss": self.cvss,
            "rationale": self.rationale,
            "factors": self.factors,
        }


class RiskPrioritizer:
    """Score + tier findings. Stateless; safe to reuse across scans."""

    def assess(self, f: Dict[str, Any]) -> PriorityResult:
        sev = str(f.get("severity", "INFO")).upper()
        cid = str(f.get("check_id", ""))
        cat = str(f.get("category", ""))
        text = _text(f)
        cve, cvss = _cve_cvss(f)

        exploited = bool(cid.startswith("HOTNEWS-003") or _EXPLOIT_KW.search(text))
        hotnews = bool(cid.startswith("HOTNEWS") or "HotNews" in cat or "Security Notes" in cat)
        exposed = bool(cat in _EXPOSURE_CATEGORIES or _EXPOSURE_KW.search(text))
        privileged = bool(_PRIV_KW.search(text))

        score = _SEV_BASE.get(sev, 0)
        factors: List[Dict[str, Any]] = [
            {"label": f"Severity {sev}", "detail": "base risk from the finding severity",
             "points": _SEV_BASE.get(sev, 0)}]

        def boost(pts, label, detail):
            nonlocal score
            score += pts
            factors.append({"label": label, "detail": detail, "points": pts})

        if exploited:
            boost(25, "Actively exploited", "public exploit / CISA KEV — attackers weaponise this now")
        elif hotnews:
            boost(14, "HotNews / Security Note", "fixes a top-severity SAP vulnerability (Priority 1/High)")
        if privileged:
            boost(14, "Known privileged path", "default credentials / critical authorization / trust abuse")
        if exposed:
            boost(12, "Exposed surface", "on a network / RISE-BTP surface reachable by an attacker")
        if cvss is not None:
            if cvss >= 9.0:
                boost(10, f"CVSS {cvss:g}", "critical CVSS base score")
            elif cvss >= 7.0:
                boost(5, f"CVSS {cvss:g}", "high CVSS base score")
        score = max(0, min(100, score))

        tier = self._tier(sev, score, exploited, hotnews, exposed, privileged)
        rationale = self._rationale(sev, tier, exploited, hotnews, exposed, privileged, cve)
        return PriorityResult(f, tier, score, factors, rationale,
                              exploited, hotnews, exposed, privileged, cve, cvss)

    @staticmethod
    def _tier(sev, score, exploited, hotnews, exposed, privileged) -> str:
        crit = sev == "CRITICAL"
        high = sev == "HIGH"
        # P1 — incident-grade
        if (crit and (exploited or exposed or privileged)) or score >= 82:
            tier = "P1"
        elif crit or exploited or (hotnews and sev in ("CRITICAL", "HIGH")) or score >= 58:
            tier = "P2"
        elif high or (sev == "MEDIUM" and (exposed or privileged)) or score >= 30:
            tier = "P3"
        else:
            tier = "P4"
        # KEV-analog floor: an actively-exploited finding never sits below P2.
        if exploited and TIER_RANK[tier] > TIER_RANK["P2"]:
            tier = "P2"
        return tier

    @staticmethod
    def _rationale(sev, tier, exploited, hotnews, exposed, privileged, cve) -> str:
        bits = [f"{sev} finding"]
        if exploited:
            bits.append("actively exploited in the wild" + (f" ({cve})" if cve else ""))
        elif hotnews:
            bits.append("HotNews / high-priority SAP note")
        if privileged:
            bits.append("well-known privileged attack path")
        if exposed:
            bits.append("on an attacker-reachable surface")
        window = TIER_META[tier]["window"]
        return "; ".join(bits) + f" -> {tier} ({TIER_META[tier]['label']}, {window})"

    def prioritize(self, findings: List[Dict[str, Any]]) -> List[PriorityResult]:
        results = [self.assess(f) for f in (findings or [])]
        results.sort(key=lambda r: (r.tier_rank, -r.score))
        return results


def by_finding(results: List[PriorityResult]) -> Dict[int, PriorityResult]:
    """Map id(finding) -> PriorityResult, so a report/consumer can look up a finding's tier."""
    return {id(r.finding): r for r in results}


def prioritize(findings: List[Dict[str, Any]]) -> List[PriorityResult]:
    return RiskPrioritizer().prioritize(findings)
