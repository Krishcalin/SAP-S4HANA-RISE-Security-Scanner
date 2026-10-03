"""Security Monitor: the per-domain, per-check posture of one estate, on one screen.

A LENS, NOT A NEW ANALYTIC. It adds no checks and defines no check ids. It
regroups the findings a scan already produced into the twelve security domains
(modules/domains.py) and, within each, the individual checks that fired — so a
reviewer can read posture the way the market's "security & compliance monitors"
present it (a category strip with per-check cards) without the product inventing
a second taxonomy or a compliance percentage.

WHAT IT ADDS OVER A SETTINGS MONITOR, and why it earns its own screen:
  * the honest FOUR states per domain (assessed / clear / not_supplied /
    not_assessed), carried straight from domains.roll_up — an empty domain says
    WHICH of the four it is, never a reassuring blank. This is the one thing a
    category strip that draws every empty cell the same way cannot do.
  * a per-check OWNER badge — yours to fix vs a SAP service request under RISE
    (modules/rise_ownership) — the difference between an action and noise.
  * a severity-weighted posture BAND with its basis (modules/posture_score) and
    the annualised-loss headline (server/crq) beside it, neither of which a
    configuration monitor produces.

RECONCILES WITH /domains BY CONSTRUCTION. The per-check cards are grouped by the
SAME `domains.domain_for(check_id, category)` that `domains.roll_up` counts by
(domains.py:433), so the sum of a domain's per-check totals is its domain count —
the strip and the cards can never disagree.

CONTENT, NOT CHECKS. Lives in server/ so it is not discovered as an audit module
and does not move the module / check counts. Reads the same finding projection
the domains screen does (`queries.findings_for_domains`), so the two agree.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from modules import domains, posture_score, rise_ownership

#: Severity buckets, worst first — the same tuple the rest of the product orders by.
_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_SEV_RANK = {s: i for i, s in enumerate(_SEVERITIES)}

#: The domain states that mean "no measurement here", folded together for the
#: not-assessed tile. CLEAR is deliberately NOT among them — it is the one empty
#: state that is good news (a domain was assessed and came back without findings).
_UNMEASURED = (domains.NOT_ASSESSED, domains.NOT_SUPPLIED)


def _worst(counts: Dict[str, int]) -> Optional[str]:
    """The worst severity present in a per-check count map, or None if empty."""
    for s in _SEVERITIES:
        if counts.get(s):
            return s
    return None


def _check_rank(card: Dict[str, Any]):
    """Worst severity first, then most findings, then the id for a stable order."""
    return (_SEV_RANK.get(card["worst"], 9), -card["total"], str(card["check_id"]))


def roll_up(findings: Sequence[Dict[str, Any]],
            coverage: Optional[Dict[str, Any]] = None,
            deployment_mode: str = "on_prem",
            risk: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Compose the Security Monitor view from the finding projection.

    `findings` is the projection `queries.findings_for_domains` returns (it carries
    check_id + category, which is all the domain placement and the per-check
    grouping need). `coverage` supplies the per-domain state honesty and the
    `measured` timestamp. `deployment_mode` decides a check's owner badge — under
    RISE a customer can SEE a bad parameter and not fix it, so the badge is the
    difference between an action and noise. `risk` is the annualised-loss headline
    (server/crq.latest, projected by the endpoint); None when nothing was priced.
    """
    domain_view = domains.roll_up(findings, coverage)

    # Group every placed finding into domain -> check, counting by severity. Placed
    # by the SAME function domains.roll_up counts by, so the per-check totals sum to
    # the domain's own count.
    per_domain: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for f in findings:
        cid = f.get("check_id")
        did = domains.domain_for(cid, f.get("category"))
        if did is None:
            continue   # outside the taxonomy — surfaced as `unplaced`, never a card
        checks = per_domain.setdefault(did, {})
        card = checks.get(cid)
        if card is None:
            card = {
                "check_id": cid,
                "title": f.get("title"),
                "counts": {s: 0 for s in _SEVERITIES},
                "total": 0,
                "owner": rise_ownership.remediation_owner_for(cid, deployment_mode),
            }
            checks[cid] = card
        sev = str(f.get("severity") or "").upper()
        if sev in card["counts"]:
            card["counts"][sev] += 1
        card["total"] += 1

    # Assemble per-domain in domains.roll_up's own order (reach then label), each
    # carrying its state/reach honesty plus the firing-check cards.
    out_domains: List[Dict[str, Any]] = []
    gaps = 0
    for d in domain_view["domains"]:
        cards = list(per_domain.get(d["id"], {}).values())
        for c in cards:
            c["worst"] = _worst(c["counts"])
        cards.sort(key=_check_rank)
        gaps += len(cards)
        out_domains.append({
            "id": d["id"], "label": d["label"], "reach": d["reach"],
            "scope": d.get("scope"), "blurb": d.get("blurb"),
            "state": d["state"], "total": d["total"], "counts": d["counts"],
            "checks": cards,
        })

    states = [d["state"] for d in domain_view["domains"]]
    counts = {s: sum(d["counts"].get(s, 0) for d in domain_view["domains"])
              for s in _SEVERITIES}

    # The severity-weighted posture band, computed over the checks that actually
    # ran — a density, not a count, and None (so the screen prints counts instead)
    # when there is no manifest to divide by. Same corpus the domains use.
    posture_block: Optional[Dict[str, Any]] = None
    scored = posture_score.score_with_scope(findings, coverage)
    if scored is not None:
        score, band, assessed = scored
        posture_block = {
            "score": score, "band": band, "assessed": assessed,
            "basis": posture_score.scope_note(assessed),
            "anchor": posture_score.ANCHOR,
        }

    return {
        "measured": domain_view["measured"],
        "posture": posture_block,
        "risk": risk,
        "domains": out_domains,
        "totals": {
            "findings": sum(counts.values()),       # placed in the twelve domains
            "counts": counts,
            "gaps": gaps,                            # distinct firing checks
            "domains": len(states),
            "assessed": sum(1 for s in states if s == domains.ASSESSED),
            "clear": sum(1 for s in states if s == domains.CLEAR),
            "not_assessed": sum(1 for s in states if s in _UNMEASURED),
            "corpus": domain_view["totals"]["findings"],
            "unplaced": domain_view["unplaced"]["total"],
        },
    }
