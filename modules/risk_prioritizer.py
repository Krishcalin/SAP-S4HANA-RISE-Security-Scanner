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

#: Code findings take their exposure from the reachability join, never from the
#: keyword scan over their own description. See `assess()`.
_CODE_CATEGORY = "Code & Transport Security"
_REACHABLE = "reachable"
_UNREACHABLE = "unreachable"

# Categories that put a finding on an attacker-reachable surface.
_EXPOSURE_CATEGORIES = {
    "Network & Service Exposure", "Network & Integration Layer",
    "RISE / BTP Security", "BTP Cloud Attack Surface", "Fiori & UI Layer",
    "CAP & XSUAA Application Security",
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
        privileged = bool(_PRIV_KW.search(text))

        # ── Reachability ────────────────────────────────────────────────────
        # WHY A CODE FINDING DOES NOT GET `exposed` FROM ITS OWN PROSE
        # `_EXPOSURE_KW` matches internet|external|publicly|exposed|… across the
        # title, description and references. That is a fair heuristic for a
        # configuration finding, whose description describes the thing it found.
        # It is wrong for a code finding, whose description is a rule's canned
        # explanation of a vulnerability CLASS — "an attacker can reach this
        # endpoint", "data from an external source" — written once in exactly that
        # vocabulary and reused for every occurrence. Left alone it stamps
        # `exposed` on essentially every ABAP finding on the strength of an English
        # word, lifts each one a tier, and inflates the FAIR figure the board
        # reads. For a code finding, exposure comes from the reachability join or
        # it does not come at all.
        reach = str((f.get("details") or {}).get("reachability") or "").lower()
        is_code = cat == _CODE_CATEGORY or reach in (_REACHABLE, _UNREACHABLE)

        if is_code:
            exposed = reach == _REACHABLE
        else:
            exposed = bool(cat in _EXPOSURE_CATEGORIES or _EXPOSURE_KW.search(text))

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

        # ── Is anybody actually using the account this is about? ─────────────
        #
        # Every finding here is derived from configuration, so the list says
        # what COULD be abused and nothing about what is live. `logon_events` is
        # already ingested and already decides whether a graph edge is `used`;
        # `server/activity.py` applies the same evidence to findings.
        #
        # IT RAISES AND NEVER LOWERS. Boosting what is demonstrably in use is
        # safe. Damping what looks quiet is not: a 30-day window is one
        # break-glass procedure away from being wrong, and a firefighter account
        # is dormant by design. So `quiet` earns no points in either direction
        # and is carried for the reader instead — the console shows it, and
        # nothing is pushed down the queue on the strength of a short window.
        #
        # `unassessed` is likewise worth nothing, and that is the whole reason
        # the three states are kept apart: scoring it as quiet would turn a
        # missing export into a reassurance.
        activity = (f.get("details") or {}).get("account_activity") or {}
        if activity.get("state") == "active":
            boost(10, "Account in use",
                  "the account this is about logged on in the exported window — "
                  + str(activity.get("reason") or ""))

        # The object side, and a WEAKER claim stated as such. A change document
        # says the role or user was maintained on a date, by somebody, through a
        # transaction. It does not say the privilege was exercised — nothing this
        # product ingests evidences that, because `security_audit_log.csv` is the
        # SAL configuration rather than an event log. So this is worth less than
        # an account demonstrably logging on, and says "changed" rather than
        # "used" wherever a reader will see it.
        obj = (f.get("details") or {}).get("object_activity") or {}
        if obj.get("state") == "changed":
            boost(6, "Configuration actively maintained",
                  "a change document records a recent change to this object, so "
                  "it is live rather than a fossil — "
                  + str(obj.get("reason") or ""))
        if exposed and is_code:
            boost(12, "Reachable code",
                  "referenced or recently executed — an attacker can get to it: "
                  + "; ".join((f.get("details") or {}).get("reachability_reasons") or []))
        elif exposed:
            boost(12, "Exposed surface", "on a network / RISE-BTP surface reachable by an attacker")
        if cvss is not None:
            if cvss >= 9.0:
                boost(10, f"CVSS {cvss:g}", "critical CVSS base score")
            elif cvss >= 7.0:
                boost(5, f"CVSS {cvss:g}", "high CVSS base score")
        # ── The one place a signal LOWERS a tier, and why it is allowed to ──
        # Every other signal here only ever raises, so that a heuristic can never
        # hide a real problem. This one is different on purpose.
        #
        # "Nothing references this object and it has never run" is not a heuristic
        # about severity — it is direct evidence about EXPLOITABILITY, which is
        # what the tier means. A SQL injection in dead code is a real defect and a
        # fake incident, and a queue that ranks it alongside an injection in a
        # program that ran this morning is a queue nobody works top-down.
        #
        # It is fenced tightly. It needs POSITIVE evidence of disuse from the
        # inventory (not merely absent data); it never applies to an actively
        # exploited finding or a HotNews one; it never drops below P3, so the
        # finding stays on the backlog rather than disappearing; and the reason is
        # recorded in the factor list so a reviewer sees exactly why it moved.
        dampened = (is_code and reach == _UNREACHABLE
                    and not exploited and not hotnews)
        if dampened:
            reasons = "; ".join(
                (f.get("details") or {}).get("reachability_reasons") or [])
            boost(-18, "Unreachable code",
                  f"no path to it was found: {reasons}. Still a real defect — "
                  f"floored at P3, never hidden")

        score = max(0, min(100, score))

        tier = self._tier(sev, score, exploited, hotnews, exposed, privileged)
        if dampened:
            tier = self._dampen(tier)
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
    def _dampen(tier: str) -> str:
        """One tier down for proven-unreachable code, floored at P3.

        Floored rather than dropped to P4 so the finding stays on a worked list.
        Dead code gets deleted, resurrected and copied; "nobody can reach it
        today" is a statement about today.
        """
        lowered = {"P1": "P2", "P2": "P3", "P3": "P3", "P4": "P4"}
        return lowered[tier]

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
