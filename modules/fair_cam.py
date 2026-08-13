# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
FAIR-CAM v1.0 — which control function each finding is evidence against.

WHAT THIS REPLACES
------------------
The quantification already moved FAIR factors from findings, but by severity and
two boolean flags (`exposed`, `exploited`). That works and it is not wrong; what
it could not do is SAY WHY. A CFO asking "why did closing these fourteen findings
move the number, and which lever did they pull?" got a severity weight for an
answer. FAIR-CAM is the vocabulary that answers it, and this module is the seam
where a finding acquires a named control function.

THE NINE LOSS EVENT CONTROL FUNCTIONS, AND THE FACTOR EACH ONE MOVES
--------------------------------------------------------------------
From the FAIR-CAM standard, and the mapping is the standard's own (Fig. 5, A-D):

    PREVENTION
      Avoidance          -> Contact Frequency        reduce contact happening
      Deterrence         -> Probability of Action    reduce acting once in contact
      Resistance         -> Susceptibility           reduce the action succeeding
    DETECTION
      Visibility         -> Loss Magnitude           evidence exists at all
      Monitoring         -> Loss Magnitude           somebody reviews it
      Recognition        -> Loss Magnitude           normal is told from abnormal
    RESPONSE
      Event Termination  -> Loss Magnitude           the activity is stopped
      Resilience         -> Loss Magnitude           operations are restored
      Loss Reduction     -> Loss Magnitude           realised loss is smaller

Detection and Response both act on magnitude, not frequency: they do not stop the
event, they shorten it. Conflating them with Prevention is the most common way
FAIR-CAM is implemented wrongly, and it flatters detection spending enormously.

AMBIGUITY IS RECORDED, NOT RESOLVED BY FIAT
-------------------------------------------
Nine of our seventeen themes do not map to one function. `privileged-access` is
Resistance AND Loss Reduction — least privilege makes an action less likely to
succeed and shrinks the blast radius when it does. `logging-monitoring` spans all
three Detection functions, and which one a finding evidences depends on the check:
"the audit log is off" is Visibility; "nobody reviews it" is Monitoring.

Forcing a single function on these would produce a tidy table that is wrong in
ways nobody can see. So a theme carries a WEIGHTED SPLIT and a confidence, both
published, and the console renders the ambiguous ones as ambiguous. A reader who
disagrees with a split can see it and argue; a reader given a false certainty
cannot.

TWO THEMES ARE NOT LOSS EVENT CONTROLS AT ALL
---------------------------------------------
`change-management` and the SDLC half of `secure-development` are FAIR-CAM
VARIANCE MANAGEMENT controls: they govern whether other controls stay effective,
and they act on control RELIABILITY rather than on any FAIR factor directly.
Mapping them to Resistance would double-count them against the very controls they
maintain. They are classified, reported, and deliberately given no factor.
"""
from typing import Any, Dict, List, Optional, Sequence, Tuple

# ── the nine functions ───────────────────────────────────────────────────────
#: function id -> (display name, FAIR-CAM domain, the FAIR factor it moves,
#:                 the standard's definition, verbatim)
FUNCTIONS: Dict[str, Tuple[str, str, str, str]] = {
    "avoidance": (
        "Avoidance", "Prevention", "contact_frequency",
        "Reduce the frequency of contact between threat agents and the assets "
        "they could adversely affect."),
    "deterrence": (
        "Deterrence", "Prevention", "probability_of_action",
        "Reduce the probability of potentially harmful actions after a threat "
        "agent has come into contact with an asset."),
    "resistance": (
        "Resistance", "Prevention", "susceptibility",
        "Reduce the likelihood that a threat agent's action(s) will result in a "
        "loss event."),
    "visibility": (
        "Visibility", "Detection", "loss_magnitude",
        "Provide evidence of activity that may be anomalous or illicit."),
    "monitoring": (
        "Monitoring", "Detection", "loss_magnitude",
        "Review data provided by Visibility controls."),
    "recognition": (
        "Recognition", "Detection", "loss_magnitude",
        "Enable differentiation of regular activity/conditions from abnormal "
        "activity/conditions that may indicate a loss event has occurred or is "
        "in progress."),
    "event_termination": (
        "Event Termination", "Response", "loss_magnitude",
        "Enable termination of threat agent activities that could continue to be "
        "harmful."),
    "resilience": (
        "Resilience", "Response", "loss_magnitude",
        "Maintain or restore normal operations."),
    "loss_reduction": (
        "Loss Reduction", "Response", "loss_magnitude",
        "Reduce the amount of realized losses from an event."),
}

FUNCTION_ORDER: Tuple[str, ...] = (
    "avoidance", "deterrence", "resistance",
    "visibility", "monitoring", "recognition",
    "event_termination", "resilience", "loss_reduction",
)

DOMAIN_ORDER: Tuple[str, ...] = ("Prevention", "Detection", "Response")

#: A theme whose controls are Variance Management rather than Loss Event
#: controls. They act on the reliability of OTHER controls, so they move no FAIR
#: factor of their own and are excluded from the weighted split above.
VARIANCE_MANAGEMENT = "variance_management"

#: theme -> (splits, confidence, note)
#: `splits` is {function: weight}; weights sum to 1.0 within a theme.
#: `confidence` is "high" | "medium" | "ambiguous" and is PUBLISHED — the console
#: renders ambiguous rows differently, because a split we are guessing at should
#: not look like one we can defend.
THEME_FUNCTIONS: Dict[str, Tuple[Dict[str, float], str, str]] = {
    "authentication": (
        {"resistance": 1.0}, "high",
        "Password policy and SNC authentication raise the probability that a "
        "threat event fails. No competing reading."),
    "vuln-mgmt": (
        {"resistance": 1.0}, "high",
        "A missing SAP Note means the system does not resist a known exploit."),
    "network-security": (
        {"avoidance": 0.7, "resistance": 0.3}, "high",
        "Exposure findings are a CONTACT signal — the prioritiser already treats "
        "them that way. A minority (service authentication) is Resistance."),
    "backup-recovery": (
        {"resilience": 1.0}, "high",
        "Evidences whether operations can be restored, which is Resilience by "
        "definition. Note it evidences EXISTENCE of backup, not that a restore "
        "has been tested."),
    "access-control": (
        {"resistance": 0.85, "loss_reduction": 0.15}, "medium",
        "Application-layer authorisation, with the actor already in contact. A "
        "little Loss Reduction because narrower access is a smaller blast radius."),
    "secure-config": (
        {"resistance": 0.8, "avoidance": 0.2}, "medium",
        "Mostly hardening against a successful action; some members (disabling an "
        "unused service) are properly Avoidance."),
    "privileged-access": (
        {"resistance": 0.5, "loss_reduction": 0.5}, "ambiguous",
        "Least privilege both lowers the probability an action succeeds AND "
        "shrinks what it reaches. Genuinely both; split evenly rather than "
        "pretending one dominates."),
    "sod": (
        {"resistance": 0.6, "recognition": 0.4}, "ambiguous",
        "ARA/GRC risk findings are Resistance against insider fraud; the "
        "mitigating-control half is Recognition. Which one a given finding "
        "evidences depends on the check."),
    "cryptography": (
        {"resistance": 0.6, "loss_reduction": 0.4}, "ambiguous",
        "Transport encryption resists interception; encryption at rest reduces "
        "the magnitude of a breach that already happened. Different functions, "
        "one theme."),
    "data-protection": (
        {"loss_reduction": 0.7, "resistance": 0.3}, "ambiguous",
        "Masking a production copy is squarely magnitude reduction — the breach "
        "still happens, it just takes less. Access-side controls are Resistance."),
    "logging-monitoring": (
        {"visibility": 0.5, "monitoring": 0.3, "recognition": 0.2}, "ambiguous",
        "Spans all three Detection functions. 'The audit log is off' is "
        "Visibility; 'nobody reviews it' is Monitoring; 'no alert rule exists' is "
        "Recognition. The theme cannot tell them apart."),
    "incident-response": (
        {"event_termination": 0.5, "loss_reduction": 0.5}, "ambiguous",
        "Depends on the check, and the product only evidences that a capability "
        "exists — not how quickly it is used."),
    "app-runtime": (
        {"avoidance": 0.5, "resistance": 0.5}, "ambiguous",
        "An exposed running application is Avoidance (contact); authentication on "
        "that service is Resistance. The theme covers both."),
    "supplier-cloud": (
        {"resistance": 0.5, "avoidance": 0.5}, "ambiguous",
        "Shared-responsibility findings span who can reach the tenant (Avoidance) "
        "and how well it is configured (Resistance)."),
    # ── not Loss Event Controls ──────────────────────────────────────────────
    "change-management": (
        {VARIANCE_MANAGEMENT: 1.0}, "high",
        "A FAIR-CAM VARIANCE MANAGEMENT control. Transport segregation governs "
        "whether other controls stay effective; it does not itself move a FAIR "
        "factor. Mapping it to Resistance would double-count it against the "
        "controls it maintains."),
    "secure-development": (
        {"resistance": 0.5, VARIANCE_MANAGEMENT: 0.5}, "ambiguous",
        "A SQL injection in running code is a Resistance deficiency; the SDLC "
        "practice that let it ship is Variance Management. One theme, two "
        "FAIR-CAM domains."),
}

_SEVERITY_WEIGHT: Dict[str, float] = {
    "CRITICAL": 1.0, "HIGH": 0.6, "MEDIUM": 0.3, "LOW": 0.1, "INFO": 0.0,
}

#: Control functions NO theme reaches, and why. A function here can only ever
#: report 0.0 findings, and 0.0 rendered like a measured zero is the same lie the
#: CSF view exists to prevent: "we looked and found nothing" printed over "we
#: cannot look at all".
#:
#: Deterrence is the honest example. Its controls are logon banners, legal
#: warnings, visible-monitoring notices — things whose PRESENCE deters an actor
#: already in contact. An SAP configuration export does not reveal whether they
#: exist, are legible, or are believed, and none of the scanner's 16 themes
#: evidences one. Reporting it as a clean prevention layer would be flattering and
#: false.
UNREACHABLE_FUNCTIONS: Dict[str, str] = {
    "deterrence": (
        "No check this scanner runs is evidence about deterrence. Its controls — "
        "logon banners, legal warnings, visible monitoring — are not something an "
        "SAP configuration export reveals, so this is not a clean result: it is "
        "an unexamined one."),
}

ASSESSED = "assessed"
CLEAR = "clear"
NOT_ASSESSED = "not_assessed"
#: We would have looked, and the export never arrived. NOT_ASSESSED is a property
#: of the product (no theme reaches this function, on any run); this is a property
#: of THIS run. See the same note in modules/nist_csf.py — measured before it
#: existed, a `--modules users` scan reported six control functions clean,
#: including the whole Detection and Response half of the control model, having
#: read no log configuration whatsoever.
NOT_SUPPLIED = "not_supplied"


def factor_of(function_id: str) -> Optional[str]:
    """The FAIR factor a control function moves, or None for Variance Management."""
    if function_id == VARIANCE_MANAGEMENT:
        return None
    entry = FUNCTIONS.get(function_id)
    return entry[2] if entry else None


def functions_for_theme(theme: str) -> Dict[str, float]:
    entry = THEME_FUNCTIONS.get(theme)
    return dict(entry[0]) if entry else {}


def _empty_state(function_id: str, category_themes: Dict[str, List[str]],
                 ran: Optional[set], modules_for_categories) -> str:
    """CLEAR or NOT_SUPPLIED for a reachable function with no findings.

    A function is reached by THEMES and a finding reaches a theme through its own
    category, so the categories feeding a function are those whose themes reach
    it — the same two hops the CSF view walks, at the same resolution.
    """
    if ran is None:
        return CLEAR
    themes = {theme for theme, entry in THEME_FUNCTIONS.items()
              if function_id in (entry[0] or {})}
    if not themes:
        return CLEAR
    feeding = {cat for cat, cat_themes in category_themes.items()
               if themes & set(cat_themes)}
    feeders = modules_for_categories(feeding)
    # Untieable to a module means we cannot say the evidence was missing.
    return CLEAR if (not feeders or (feeders & ran)) else NOT_SUPPLIED


def classify(findings: Sequence[Dict[str, Any]],
             category_themes: Optional[Dict[str, List[str]]] = None,
             coverage: Optional[Dict[str, Any]] = None
             ) -> Dict[str, Any]:
    """Attribute findings to FAIR-CAM control functions.

    A finding is evidence against every function its themes reach, weighted by the
    theme split and by severity. Weights are FRACTIONAL and sum to at most one per
    finding, so a finding touching three functions contributes a third of itself to
    each rather than triple-counting — the same discipline the CSF roll-up needed.

    Returns per-function deficiency pressure, the domain roll-up, and the findings
    that reached no function at all.

    `coverage` is a manifest from modules/coverage.py. Supplied, a reachable
    function that nothing fed reports NOT_SUPPLIED rather than CLEAR. Omitted, no
    function ever claims its evidence was missing.
    """
    if category_themes is None:
        from .compliance_mapping import ComplianceMapper
        category_themes = ComplianceMapper.CATEGORY_THEMES
    from .coverage import modules_for_categories, ran_modules
    ran = ran_modules(coverage)

    per_function: Dict[str, Dict[str, Any]] = {
        fid: {"id": fid, "name": FUNCTIONS[fid][0], "domain": FUNCTIONS[fid][1],
              "factor": FUNCTIONS[fid][2], "definition": FUNCTIONS[fid][3],
              "findings": 0.0, "weight": 0.0, "severities": {},
              "themes": set(), "confidence": set()}
        for fid in FUNCTION_ORDER
    }
    variance: Dict[str, Any] = {"findings": 0.0, "weight": 0.0, "themes": set()}
    unattributed: List[Dict[str, Any]] = []

    for finding in findings:
        category = finding.get("category")
        severity = str(finding.get("severity", "")).upper()
        themes = category_themes.get(category, [])
        if not themes:
            unattributed.append({"category": category, "severity": severity})
            continue

        # Split the finding across its themes first, then across each theme's
        # functions, so one finding is worth one finding however many routes it has.
        share = 1.0 / len(themes)
        sev_weight = _SEVERITY_WEIGHT.get(severity, 0.0)
        reached = False
        for theme in themes:
            splits, confidence, _note = THEME_FUNCTIONS.get(theme, ({}, "", ""))
            for function_id, portion in splits.items():
                contribution = share * portion
                if function_id == VARIANCE_MANAGEMENT:
                    variance["findings"] += contribution
                    variance["weight"] += contribution * sev_weight
                    variance["themes"].add(theme)
                    reached = True
                    continue
                entry = per_function.get(function_id)
                if entry is None:
                    continue
                entry["findings"] += contribution
                entry["weight"] += contribution * sev_weight
                entry["severities"][severity] = (
                    entry["severities"].get(severity, 0.0) + contribution)
                entry["themes"].add(theme)
                entry["confidence"].add(confidence)
                reached = True
        if not reached:
            unattributed.append({"category": category, "severity": severity})

    functions: List[Dict[str, Any]] = []
    for fid in FUNCTION_ORDER:
        e = per_function[fid]
        confidences = e["confidence"]
        functions.append({
            **{k: v for k, v in e.items() if k not in ("themes", "confidence")},
            "findings": round(e["findings"], 2),
            "weight": round(e["weight"], 3),
            "severities": {k: round(v, 2) for k, v in sorted(e["severities"].items())},
            "themes": sorted(e["themes"]),
            # If ANY contributing theme was ambiguous, the function's number is
            # ambiguous. Reporting the best case would hide exactly the doubt a
            # reader needs to weigh the figure.
            "confidence": ("ambiguous" if "ambiguous" in confidences
                           else ("medium" if "medium" in confidences
                                 else ("high" if confidences else "none"))),
            # THREE STATES, NEVER TWO — the same discipline as the CSF view and
            # the release gate. A function no theme reaches can only report 0.0,
            # and 0.0 drawn like a measured zero says "clean" about something
            # nobody examined.
            "status": (NOT_ASSESSED if fid in UNREACHABLE_FUNCTIONS
                       else (ASSESSED if e["findings"] > 0
                             else _empty_state(fid, category_themes, ran,
                                               modules_for_categories))),
            "reason": UNREACHABLE_FUNCTIONS.get(fid),
        })

    domains: List[Dict[str, Any]] = []
    for domain in DOMAIN_ORDER:
        members = [f for f in functions if f["domain"] == domain]
        domains.append({
            "domain": domain,
            "findings": round(sum(f["findings"] for f in members), 2),
            "weight": round(sum(f["weight"] for f in members), 3),
            "functions": [f["id"] for f in members],
        })

    return {
        "functions": functions,
        "domains": domains,
        "variance_management": {
            "findings": round(variance["findings"], 2),
            "weight": round(variance["weight"], 3),
            "themes": sorted(variance["themes"]),
            "note": ("These findings are FAIR-CAM Variance Management controls. "
                     "They govern whether other controls stay effective and move "
                     "no FAIR factor directly, so they are counted here and "
                     "excluded from the factor attribution above."),
        },
        "unattributed": {
            "count": len(unattributed),
            "categories": sorted({u["category"] or "(no category)"
                                  for u in unattributed}),
            "note": ("Findings whose category reaches no theme, and therefore no "
                     "control function. Reported rather than dropped: a control "
                     "attribution that silently loses findings reads as a complete "
                     "picture."),
        },
        "severity_weights": dict(_SEVERITY_WEIGHT),
        "total_findings": len(findings),
    }
