# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
Cyber-risk quantification: findings as a currency figure.

WHY THIS IS ON THE FRONT PAGE AND NOT BEHIND A FLAG
-----------------------------------------------------
Research across both incumbents found no monetary risk output of any kind — one
carries a prose `business_impact` field, the other's only money artifact computes
the ROI of buying the tool. This is the cleanest open lane the product has, and it
already existed here as a `--crq` flag on a report generator.

FOUR DISCIPLINES THAT MUST SURVIVE CONTACT WITH THE CONSOLE
------------------------------------------------------------
These are inherited from `modules/fair_adapter.py`, are what make the number
defensible, and are exactly what a buyer with a risk function will probe:

1. **A finding is not a risk.** Findings are evidence that shifts a scenario's
   factors. No finding gets its own ALE, and ALEs are never summed per finding.

2. **The portfolio is an element-wise Monte-Carlo sum, never a sum of
   percentiles.** Adding five scenarios' P90s produces a number that is not any
   percentile of anything.

3. **A display filter must never move the figure.** FAIR runs on the COMPLETE
   finding set. If filtering the console to CRITICAL changed the dollar number,
   the number would be a rendering artifact rather than a measurement — so the
   input count is stored alongside the result and asserted in tests.

4. **Disclose what was not priced.** The `unrouted` count is carried to the UI.
   Findings that could not be attributed to a specific loss scenario are folded
   conservatively into SAP-PRIV-03 and may overstate it; hiding that would be the
   vendor hand-waving this feature exists to beat.

SYSTEM CRITICALITY
------------------
A production ledger and a sandbox must not carry the same exposure band. The
console captures per-system criticality, which CVSS structurally cannot express —
the incumbent concedes as much ("not all systems are the same"). It is applied as
a **calibration input**, i.e. by selecting a band, never by multiplying a score.
"""
from __future__ import annotations

import hashlib
import json
import logging
from typing import Any, Dict, List, Optional, Sequence

from psycopg.types.json import Jsonb

from server import db

log = logging.getLogger(__name__)

#: Criticality -> revenue-at-risk weight. Selects a band; does NOT scale a score.
#: A landscape whose scanned systems are all sandboxes should not report the same
#: loss exposure as one centred on a production ledger.
CRITICALITY_WEIGHT: Dict[str, float] = {
    "critical": 1.0,
    "high": 0.6,
    "medium": 0.3,
    "low": 0.1,
}


def landscape_exposure_weight(conn, landscape_id: int) -> float:
    """The heaviest criticality among the landscape's systems.

    MAX rather than mean: a landscape containing one production ledger is exposed
    to a production-ledger loss, and averaging it against four sandboxes would
    quietly discount the only system that matters.
    """
    row = conn.execute(
        "SELECT criticality, count(*) AS n FROM sap_system "
        "WHERE landscape_id = %s GROUP BY criticality", (landscape_id,)).fetchall()
    if not row:
        return CRITICALITY_WEIGHT["medium"]
    return max(CRITICALITY_WEIGHT.get(r["criticality"], 0.3) for r in row)


def compute_and_store(conn, run_id: int, landscape_id: int,
                      findings: List[Dict[str, Any]],
                      enrichment: Optional[Dict[int, Dict[str, Any]]] = None,
                      revenue: Optional[float] = None,
                      industry: Optional[str] = None,
                      simulations: int = 10000) -> Dict[str, Any]:
    """Run FAIR over a scan's findings and persist the result.

    `findings` MUST be the complete, unfiltered set. Passing a filtered list here
    is the one way to make this number dishonest, so the count that went in is
    stored on every row.

    Degrades rather than fails: if the adapter or the Monte-Carlo engine is
    unavailable, the run still completes and the console shows that CRQ did not
    compute — a scan is not worth losing over a chart.
    """
    try:
        from modules.fair_adapter import run as fair_run
    except Exception:                                    # noqa: BLE001
        log.exception("FAIR adapter unavailable")
        return {"computed": False, "reason": "fair adapter not importable"}

    # The prioritiser's own exposed/exploited flags are what calibrate contact
    # frequency and probability of action, so CRQ needs the same PriorityResult
    # objects the console stores — not a re-derivation.
    try:
        from modules.risk_prioritizer import prioritize
        priorities = prioritize(findings)
    except Exception:                                    # noqa: BLE001
        log.exception("prioritiser unavailable; CRQ cannot calibrate")
        return {"computed": False, "reason": "prioritiser not available"}

    weight = landscape_exposure_weight(conn, landscape_id)
    overrides: Dict[str, Any] = {}
    if revenue:
        # THE CATALOGUE KEY IS "revenue", NOT "annual_revenue".
        # This wrote a key nothing ever read, so --crq-revenue was silently inert:
        # the figure stayed calibrated to the catalogue's illustrative $1B whatever
        # the customer's real turnover. Both keys are written now — "revenue"
        # because it is what data/fair_scenarios.json and the loss model read, and
        # "annual_revenue" so any consumer that grew to depend on the old spelling
        # keeps working.
        overrides["revenue"] = float(revenue) * weight
        overrides["annual_revenue"] = float(revenue) * weight
    if industry:
        overrides["industry"] = industry

    try:
        result = fair_run(findings, priorities, org_overrides=overrides or None,
                          simulations=simulations)
    except Exception:                                    # noqa: BLE001
        log.exception("FAIR run failed")
        return {"computed": False, "reason": "FAIR run raised"}

    summary = result.get("summary")
    unrouted = int(result.get("unrouted") or 0)
    input_count = len(findings)

    if not summary:
        # No Monte-Carlo engine. Still record that CRQ was attempted and how many
        # findings went unpriced — silence would read as "nothing to report".
        conn.execute(
            "INSERT INTO crq_result (scan_run_id, scenario_id, unrouted_count, "
            "input_finding_count, detail) VALUES (%s,NULL,%s,%s,%s)",
            (run_id, unrouted, input_count,
             Jsonb({"engine_found": False,
                    "reason": "Monte-Carlo engine not locatable; scenario inputs "
                              "were built but not simulated",
                    "exposure_weight": weight})))
        return {"computed": False, "engine_found": False, "unrouted": unrouted,
                "reason": "Monte-Carlo engine not locatable"}

    portfolio = summary.get("portfolio") or {}
    conn.execute(
        """
        INSERT INTO crq_result (scan_run_id, scenario_id, ale_p10, ale_p50, ale_p90,
                                ale_mean, unrouted_count, input_finding_count, detail)
        VALUES (%s, NULL, %s, %s, %s, %s, %s, %s, %s)
        """,
        (run_id, portfolio.get("ale_p10"), portfolio.get("ale_p50"),
         portfolio.get("ale_p90"), portfolio.get("mean_ale"), unrouted, input_count,
         Jsonb({"engine_found": True,
                "simulations": summary.get("simulations"),
                "organization": summary.get("organization"),
                "exposure_weight": weight,
                "target_portfolio": summary.get("target_portfolio"),
                "reducible_ale_p90": summary.get("reducible_ale_p90"),
                "reducible_ale_mean": summary.get("reducible_ale_mean"),
                "detection": summary.get("detection")})))

    for sc in summary.get("scenarios") or []:
        conn.execute(
            """
            INSERT INTO crq_result (scan_run_id, scenario_id, ale_p10, ale_p50,
                                    ale_p90, ale_mean, unrouted_count,
                                    input_finding_count, detail)
            VALUES (%s,%s,%s,%s,%s,%s,0,%s,%s)
            """,
            (run_id, sc.get("id"), sc.get("ale_p10"), sc.get("ale_p50"),
             sc.get("ale_p90"), sc.get("mean_ale"), input_count,
             Jsonb({"name": sc.get("name"),
                    "finding_count": sc.get("finding_count"),
                    "worst_severity": sc.get("worst_severity"),
                    "exposed": sc.get("exposed"),
                    "exploited": sc.get("exploited")})))

    return {"computed": True, "engine_found": True, "unrouted": unrouted,
            "input_finding_count": input_count,
            "portfolio": portfolio,
            "reducible_ale_p90": summary.get("reducible_ale_p90"),
            "scenarios": len(summary.get("scenarios") or [])}


# --------------------------------------------------------------------------- #
#  Reads                                                                      #
# --------------------------------------------------------------------------- #

def latest(scope: Optional[Sequence[int]] = None) -> Optional[Dict[str, Any]]:
    """Portfolio CRQ from the most recent completed run in scope."""
    clause, params = db.scope_clause(scope, "r.system_id")
    return db.one(
        f"""
        SELECT c.*, r.started_at, r.id AS run_id, s.sid, s.client
        FROM crq_result c
        JOIN scan_run r ON r.id = c.scan_run_id
        LEFT JOIN sap_system s ON s.id = r.system_id
        WHERE c.scenario_id IS NULL AND r.status = 'complete' AND {clause}
        ORDER BY r.started_at DESC LIMIT 1
        """, params)


def scenarios_for_run(run_id: int) -> List[Dict[str, Any]]:
    return db.query(
        "SELECT * FROM crq_result WHERE scan_run_id = %s AND scenario_id IS NOT NULL "
        "ORDER BY ale_p90 DESC NULLS LAST", (run_id,))


def trend(scope: Optional[Sequence[int]] = None, limit: int = 12) -> List[Dict[str, Any]]:
    """Portfolio ALE per run — does the money figure move as findings are fixed?"""
    clause, params = db.scope_clause(scope, "r.system_id")
    rows = db.query(
        f"""
        SELECT c.ale_p50, c.ale_p90, c.ale_mean, c.unrouted_count,
               c.input_finding_count, c.detail,
               r.id AS run_id, r.started_at
        FROM crq_result c
        JOIN scan_run r ON r.id = c.scan_run_id
        WHERE c.scenario_id IS NULL AND r.status = 'complete'
          AND c.ale_p90 IS NOT NULL AND {clause}
        ORDER BY r.started_at DESC LIMIT %s
        """, list(params) + [limit])
    rows = list(reversed(rows))

    # THE TREND LINE MOVES FOR SEVEN REASONS AND ONLY ONE OF THEM IS REMEDIATION.
    #
    # Findings closing is the intended one. The others: the scenario catalogue is
    # edited; the simulation count changes; a different engine is resolved on
    # disk; the caller's row scope differs (two users screenshot two different
    # lines and neither image says so); the customer revises their financial
    # answers; and — worst of all — COVERAGE DROPS. A missing export makes checks
    # self-skip, so fewer checks means fewer findings means a lower ALE, and the
    # chart draws "we could not look" as an improvement in money.
    #
    # So every point carries a fingerprint of everything that is NOT remediation.
    # The console draws one polyline per fingerprint group and breaks the line
    # where it changes. A break is honest; a continuous line across a model change
    # is a claim that the two ends are comparable, which they are not.
    for row in rows:
        row["inputs_fingerprint"] = _inputs_fingerprint(row)
        row["residual_p90"] = _residual_p90(row)
    return rows


def _inputs_fingerprint(row: Dict[str, Any]) -> str:
    """A short digest of everything about a run EXCEPT which findings were open.

    Deliberately excludes ale_* and the finding count: those are the signal. It
    covers the model, the money assumptions and the coverage, because a change in
    any of them makes this point incomparable with its neighbour.
    """
    detail = row.get("detail") or {}
    if not isinstance(detail, dict):
        detail = {}
    org = detail.get("organization") or {}
    material = {
        "simulations": detail.get("simulations"),
        "revenue": org.get("revenue") or org.get("annual_revenue"),
        "industry": org.get("industry"),
        "exposure_weight": detail.get("exposure_weight"),
        "crq_parameters_id": detail.get("crq_parameters_id"),
        "model_version": detail.get("model_version"),
        "engine_found": detail.get("engine_found"),
    }
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"),
                           default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def _residual_p90(row: Dict[str, Any]) -> Optional[float]:
    """The floor: what P90 would be with every finding closed.

    It earns its place on the chart twice. It shows the line cannot reach zero,
    which removes a whole class of misreading. And because it depends on the model
    and the money assumptions but NOT on findings, if the floor moves then
    something other than the customer's security posture moved.
    """
    detail = row.get("detail") or {}
    if not isinstance(detail, dict):
        return None
    target = detail.get("target_portfolio") or {}
    value = target.get("ale_p90") if isinstance(target, dict) else None
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


# ── CFO parameters ──────────────────────────────────────────────────────────

def save_parameters(landscape_id: int, answers: Dict[str, Any],
                    currency: str = "USD", note: Optional[str] = None,
                    created_by: Optional[str] = None) -> int:
    """Record a revision of the customer's financial answers. Returns its id.

    INSERT, never UPDATE. A past quantification must stay explainable, and it
    cannot be if the answers behind it can be edited underneath it.

    Unknown keys are dropped rather than stored: they would travel into the loss
    model, match nothing, and look like an answered question in the UI.
    """
    from modules.fair_loss_model import PARAMETER_KEYS
    clean = {k: v for k, v in (answers or {}).items()
             if k in PARAMETER_KEYS and v not in (None, "")}
    row = db.one(
        "INSERT INTO crq_parameters (landscape_id, answers, currency, note, created_by) "
        "VALUES (%s, %s, %s, %s, %s) RETURNING id",
        (landscape_id, Jsonb(clean), currency or "USD", note, created_by))
    return int(row["id"])


def latest_parameters(landscape_id: int) -> Optional[Dict[str, Any]]:
    """The most recent revision for a landscape, or None if never answered."""
    return db.one(
        "SELECT id, landscape_id, answers, currency, note, created_by, created_at "
        "FROM crq_parameters WHERE landscape_id = %s "
        "ORDER BY created_at DESC, id DESC LIMIT 1", (landscape_id,))


def parameter_history(landscape_id: int, limit: int = 20) -> List[Dict[str, Any]]:
    """Every revision, newest first — the audit trail behind a moving number."""
    return db.query(
        "SELECT id, answers, currency, note, created_by, created_at "
        "FROM crq_parameters WHERE landscape_id = %s "
        "ORDER BY created_at DESC, id DESC LIMIT %s", (landscape_id, limit))


def quantify_with_parameters(findings: List[Dict[str, Any]],
                             answers: Dict[str, Any],
                             simulations: int = 10000,
                             seed: int = 42) -> Dict[str, Any]:
    """Run FAIR with the customer's own loss figures. No database, no writes.

    This is the interactive path: the input screen calls it on every recompute so
    a CFO can see what a different recovery-time assumption does without polluting
    the stored history with a draft.
    """
    from modules import fair_loss_model as loss_model
    from modules.fair_adapter import (build_inputs, load_catalog, locate_engine,
                                      _quantify)
    from modules.risk_prioritizer import prioritize

    catalogue = load_catalog()
    org = dict(catalogue.get("organization_default", {}))
    priced = loss_model.build_loss_components(answers or {})
    scale = loss_model.scale_factor(answers or {},
                                    float(org.get("revenue") or 0.0))
    if answers.get("sap_revenue"):
        org["revenue"] = float(answers["sap_revenue"])

    scenarios = [loss_model.apply_to_scenario(s, priced, scale)
                 for s in catalogue.get("scenarios", [])]
    calibrated = dict(catalogue)
    calibrated["scenarios"] = scenarios

    engine = locate_engine()
    if engine is None:
        return {"computed": False, "reason": "no FAIR engine available",
                "priced": priced}

    priorities = prioritize(findings or [])
    built = build_inputs(priorities, calibrated, org)
    asis = _quantify(built["asis"], engine, simulations, seed)
    target = _quantify(built["target"], engine, simulations, seed)

    return {
        "computed": True,
        "portfolio": asis["portfolio"],
        "target_portfolio": target["portfolio"],
        "scenarios": asis["scenarios"],
        "reducible_ale_p90": max(0.0, asis["portfolio"]["ale_p90"]
                                 - target["portfolio"]["ale_p90"]),
        "reducible_ale_mean": max(0.0, asis["portfolio"]["mean_ale"]
                                  - target["portfolio"]["mean_ale"]),
        # The loss provenance travels WITH the figure, always. A currency number
        # whose basis is one API call away is a number that will be quoted without
        # its basis.
        "priced": priced,
        "scale_factor": scale,
        "simulations": simulations,
        "seed": seed,
        "unrouted": built.get("unrouted", 0),
        "finding_count": len(findings or []),
    }
