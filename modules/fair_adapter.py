"""
FAIR Cyber-Risk-Quantification Adapter
======================================
Turns the scanner's technical findings into a FAIR (Factor Analysis of
Information Risk) analysis, expressed as dollar-denominated Annualized Loss
Expectancy (ALE) and a Loss Exceedance Curve.

Design (see data/fair_scenarios.json and docs):
  * A finding is NOT a risk. Findings are *evidence* that shifts the FAIR
    factors of a small set of scoped SAP loss scenarios (asset x threat x
    effect). We never assign a finding its own ALE and sum them.
  * Findings are routed to one scenario each (by check-id prefix, then
    category). Logging/monitoring findings are not a scenario - they set a
    loss-magnitude MULTIPLIER on every scenario (weak detection => longer
    dwell => larger loss), per FAIR-CAM.
  * Calibration = RANGE SELECTION from qualitative signals, never arithmetic
    on ordinal severities/CVSS:
       - worst-severity prevention finding  -> Resistance Strength band
       - any `exposed` finding              -> Contact Frequency band
       - any `exploited` finding            -> Probability of Action band
    (the `exposed`/`exploited` flags are exactly what RiskPrioritizer already
    derives, so this reuses the scanner's own signals.)
  * The Monte Carlo maths live in the standalone CRQ engine
    (Cyber-Risk-Quantification/crq_engine.py). This adapter EMITS that engine's
    scenario JSON and, if the engine is locatable, runs it to produce numbers
    for the scanner's own report. The scanner stays self-contained: no hard
    dependency on the sibling repo.
  * Remediation upside is shown as an as-is vs. hardened ALE delta (two engine
    runs) - so we need no fabricated control costs.

Pure standard library.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_SEV_RANK_WORST = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "NONE": 0}

_DEFAULT_CATALOG = Path(__file__).resolve().parent.parent / "data" / "fair_scenarios.json"

# Candidate locations for the sibling CRQ engine (checked in order). The env var
# CRQ_ENGINE and an explicit --crq-engine path take precedence over these.
_ENGINE_CANDIDATES = [
    Path(__file__).resolve().parent.parent.parent.parent
    / "Cyber-Risk-Quantification" / "Cyber-Risk-Quantification" / "crq_engine.py",
    Path(__file__).resolve().parent.parent.parent
    / "Cyber-Risk-Quantification" / "crq_engine.py",
    # Bundled engine, deliberately LAST. An explicit --crq-engine path, the
    # CRQ_ENGINE environment variable and an external sibling repo all still win,
    # so shipping this cannot silently change results for anyone who already had
    # an engine. It exists because none of the paths above resolve in a normal
    # checkout, which meant --crq produced no number at all.
    Path(__file__).resolve().parent / "crq_engine.py",
]


# ── catalog ────────────────────────────────────────────────────────────────

def load_catalog(path: Optional[str] = None) -> Dict[str, Any]:
    """Load the FAIR scenario catalog (data/fair_scenarios.json by default)."""
    p = Path(path) if path else _DEFAULT_CATALOG
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


# ── routing ──────────────────────────────────────────────────────────────

def _worst(sevs: List[str]) -> str:
    """Return the highest severity present (CRITICAL > ... > LOW), else NONE."""
    best = "NONE"
    for s in sevs:
        s = str(s).upper()
        if _SEV_RANK_WORST.get(s, 0) > _SEV_RANK_WORST.get(best, 0):
            best = s
    return best


def _is_detection(cid: str, cat: str, catalog: Dict[str, Any]) -> bool:
    det = catalog.get("detection", {})
    if any(cid.startswith(p) for p in det.get("check_prefixes", [])):
        return True
    if cat in det.get("categories", []):
        return True
    return False


def _route(cid: str, cat: str, scenarios: List[Dict[str, Any]]) -> Optional[str]:
    """Route a finding to a scenario id. Prefix match takes precedence over
    category match (so e.g. STDUSR-* and TRUST-* separate cleanly even though
    they share the 'System Trust & Standard Users' category)."""
    for sc in scenarios:                                   # prefix pass
        for pref in sc.get("routing", {}).get("check_prefixes", []):
            if cid.startswith(pref):
                return sc["id"]
    for sc in scenarios:                                   # category pass
        if cat in sc.get("routing", {}).get("categories", []):
            return sc["id"]
    return None


# ── calibration ────────────────────────────────────────────────────────────

def _scale_loss(loss: Dict[str, Dict[str, float]], mult: float,
                dwell_keys: Optional[set] = None) -> Dict[str, Dict[str, float]]:
    """Scale loss ranges by the detection-deficiency multiplier. When dwell_keys
    is given, only those components are scaled (FAIR-CAM: detection weakness
    drives DWELL-sensitive loss - productivity/response/fines/reputation - not
    fixed rebuild/replacement or competitive-advantage). dwell_keys=None scales
    all components (back-compatible)."""
    out = {}
    for k, v in loss.items():
        if mult != 1.0 and (dwell_keys is None or k in dwell_keys):
            out[k] = {"min": v["min"] * mult, "likely": v["likely"] * mult, "max": v["max"] * mult}
        else:
            out[k] = dict(v)
    return out


def _detection_multiplier(worst_sev: str, catalog: Dict[str, Any]) -> float:
    table = catalog.get("detection", {}).get("multiplier_by_worst_severity", {})
    return float(table.get(worst_sev, 1.0))


def build_inputs(priorities: List[Any], catalog: Dict[str, Any],
                 org: Dict[str, Any]) -> Dict[str, Any]:
    """Group findings, calibrate factor ranges, and build the as-is and target
    (fully-hardened) CRQ scenario inputs.

    `priorities` is a list of PriorityResult (each carries .finding + the
    .exposed/.exploited flags). Returns a dict with 'asis', 'target' (each a
    CRQ input dict) and 'meta' (per-scenario + detection diagnostics).
    """
    scenarios = catalog["scenarios"]
    rs_bands = catalog["resistance_strength_bands"]

    # bucket findings by scenario + collect detection findings
    buckets: Dict[str, List[Any]] = {sc["id"]: [] for sc in scenarios}
    det_sevs: List[str] = []
    unrouted = 0
    for r in priorities:
        f = r.finding
        cid = str(f.get("check_id", ""))
        cat = str(f.get("category", ""))
        sev = str(f.get("severity", "INFO")).upper()
        if _is_detection(cid, cat, catalog):
            det_sevs.append(sev)
            continue
        sid = _route(cid, cat, scenarios)
        if sid is None:
            unrouted += 1
            sid = "SAP-PRIV-03"          # conservative fallback: access-control
        if sid not in buckets:           # fallback scenario missing? skip safely
            unrouted += 1
            continue
        buckets[sid].append(r)

    det_worst = _worst(det_sevs)
    det_mult = _detection_multiplier(det_worst, catalog)
    det_cfg = catalog.get("detection", {})
    dwell_keys = set(det_cfg.get("dwell_sensitive_components") or []) or None
    exempt = set(det_cfg.get("exempt_scenarios") or [])

    asis_scenarios: List[Dict[str, Any]] = []
    target_scenarios: List[Dict[str, Any]] = []
    meta: List[Dict[str, Any]] = []

    for sc in scenarios:
        routed = buckets[sc["id"]]
        sevs = [str(r.finding.get("severity", "INFO")).upper() for r in routed]
        worst = _worst(sevs)
        exposed = any(getattr(r, "exposed", False) for r in routed)
        exploited = any(getattr(r, "exploited", False) for r in routed)

        # Resistance Strength band: worst open prevention finding selects it.
        # Only MEDIUM/HIGH/CRITICAL have distinct bands; LOW/INFO/NONE fall back
        # to 'hardened' (a minor gap barely moves control strength) - and the
        # meta label reflects the band ACTUALLY used, not the raw severity.
        band_key = worst if worst in rs_bands else "hardened"
        rs_asis = rs_bands[band_key]
        rs_target = rs_bands["hardened"]

        cf = sc["contact_frequency"]
        pa = sc["probability_of_action"]
        cf_asis = cf["exposed"] if exposed else cf["baseline"]
        pa_asis = pa["exploited"] if exploited else pa["baseline"]

        loss_primary = sc["primary_loss"]
        loss_secondary = sc["secondary_loss"]
        # detection multiplier is dwell-driven: skip scenarios whose loss already
        # assumes long undetected dwell (e.g. fraud), and only scale dwell-sensitive components.
        sc_mult = 1.0 if sc["id"] in exempt else det_mult

        base = {
            "id": sc["id"],
            "name": sc["name"],
            "description": sc.get("description", ""),
            "threat_community": sc.get("threat_community", "organized_crime"),
            "threat_capability": dict(sc["threat_capability"]),
        }
        asis_scenarios.append({
            **base,
            "contact_frequency": dict(cf_asis),
            "probability_of_action": dict(pa_asis),
            "resistance_strength": dict(rs_asis),
            "primary_loss": _scale_loss(loss_primary, sc_mult, dwell_keys),
            "secondary_loss": _scale_loss(loss_secondary, sc_mult, dwell_keys),
        })
        target_scenarios.append({
            **base,
            "contact_frequency": dict(cf["baseline"]),
            "probability_of_action": dict(pa["baseline"]),
            "resistance_strength": dict(rs_target),
            "primary_loss": _scale_loss(loss_primary, 1.0, dwell_keys),
            "secondary_loss": _scale_loss(loss_secondary, 1.0, dwell_keys),
        })
        meta.append({
            "id": sc["id"], "name": sc["name"],
            "finding_count": len(routed), "worst_severity": worst,
            "exposed": exposed, "exploited": exploited,
            "rs_band": band_key,
        })

    asis = {"organization": org, "scenarios": asis_scenarios}
    target = {"organization": org, "scenarios": target_scenarios}
    return {
        "asis": asis, "target": target, "meta": meta,
        "detection": {"worst_severity": det_worst, "multiplier": det_mult,
                      "count": len(det_sevs)},
        "unrouted": unrouted,
    }


# ── engine location + simulation ─────────────────────────────────────────

def locate_engine(explicit: Optional[str] = None):
    """Import the CRQ engine module from an explicit path, the CRQ_ENGINE env
    var, or a sibling-repo candidate. Returns the module or None if not found."""
    candidates: List[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    env = os.environ.get("CRQ_ENGINE")
    if env:
        candidates.append(Path(env))
    candidates.extend(_ENGINE_CANDIDATES)

    for cand in candidates:
        try:
            if cand and cand.is_file():
                spec = importlib.util.spec_from_file_location("crq_engine", str(cand))
                if spec and spec.loader:
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    if hasattr(mod, "FAIREngine"):
                        return mod
        except Exception:
            continue
    return None


def _percentile(sorted_vals: List[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = int(len(sorted_vals) * p / 100)
    idx = min(idx, len(sorted_vals) - 1)
    return sorted_vals[idx]


def _quantify(crq_input: Dict[str, Any], engine_module, simulations: int,
              seed: int) -> Dict[str, Any]:
    """Run the FAIR Monte Carlo for every scenario and aggregate to a portfolio.

    Portfolio = element-wise sum of per-scenario ALE draws (independent
    scenarios). We sum per-iteration draws and compute stats on the aggregate -
    never sum percentiles.
    """
    FAIREngine = engine_module.FAIREngine
    engine = FAIREngine(simulations=simulations, seed=seed)
    org = crq_input["organization"]

    per_scenario = []
    ale_matrix: List[List[float]] = []
    for sc in crq_input["scenarios"]:
        res = engine.simulate_scenario(sc, [], org)
        ale_matrix.append(res.ale_distribution)
        per_scenario.append({
            "id": res.scenario_id, "name": res.scenario_name,
            "threat_community": sc.get("threat_community", ""),
            "ale_p50": res.percentiles.get(50, 0.0),
            "ale_p90": res.percentiles.get(90, 0.0),
            "ale_p95": res.percentiles.get(95, 0.0),
            "mean_ale": res.mean_ale, "mean_lef": res.mean_lef,
            "mean_lm": res.mean_lm, "severity": res.severity,
        })

    # element-wise portfolio sum (all scenarios ran with the same iteration count)
    n = min((len(a) for a in ale_matrix), default=0)
    portfolio_dist = [sum(a[i] for a in ale_matrix) for i in range(n)] if n else []
    ps = sorted(portfolio_dist)
    mean_port = sum(ps) / len(ps) if ps else 0.0
    lec = engine_module.FAIREngine._calc_loss_exceedance(ps) if ps else []

    return {
        "scenarios": per_scenario,
        "portfolio": {
            "ale_p50": _percentile(ps, 50), "ale_p90": _percentile(ps, 90),
            "ale_p95": _percentile(ps, 95), "mean_ale": mean_port,
            "loss_exceedance": lec,
        },
    }


def run(findings: List[Dict[str, Any]], priorities: List[Any],
        catalog_path: Optional[str] = None,
        org_overrides: Optional[Dict[str, Any]] = None,
        engine_path: Optional[str] = None,
        simulations: int = 10000, seed: int = 42) -> Dict[str, Any]:
    """Full adapter run. Returns:
        {
          "crq_input": <as-is CRQ scenario JSON to export / hand to crq_engine>,
          "meta": [...per-scenario diagnostics...],
          "detection": {...}, "unrouted": int,
          "engine_found": bool,
          "summary": {...as-is + target portfolio + reducible...} | None,
        }
    If the CRQ engine can't be located, summary is None (caller still exports
    the JSON so the user can run crq_engine.py standalone).
    """
    simulations = max(1, int(simulations or 1))   # guard: 0/negative -> empty engine dists
    catalog = load_catalog(catalog_path)
    org = dict(catalog.get("organization_default", {}))
    for k, v in (org_overrides or {}).items():
        if v is not None:
            org[k] = v

    built = build_inputs(priorities, catalog, org)
    out: Dict[str, Any] = {
        "crq_input": built["asis"], "meta": built["meta"],
        "detection": built["detection"], "unrouted": built["unrouted"],
        "engine_found": False, "summary": None,
        "organization": org,
    }

    engine_module = locate_engine(engine_path)
    if engine_module is None:
        return out

    out["engine_found"] = True
    asis = _quantify(built["asis"], engine_module, simulations, seed)
    target = _quantify(built["target"], engine_module, simulations, seed)
    # enrich per-scenario results with finding diagnostics (count/flags) for the report
    meta_by_id = {mm["id"]: mm for mm in built["meta"]}
    for sc in asis["scenarios"]:
        mm = meta_by_id.get(sc["id"], {})
        sc["finding_count"] = mm.get("finding_count", 0)
        sc["worst_severity"] = mm.get("worst_severity", "NONE")
        sc["exposed"] = mm.get("exposed", False)
        sc["exploited"] = mm.get("exploited", False)
    reducible_p90 = max(0.0, asis["portfolio"]["ale_p90"] - target["portfolio"]["ale_p90"])
    reducible_mean = max(0.0, asis["portfolio"]["mean_ale"] - target["portfolio"]["mean_ale"])
    out["summary"] = {
        "organization": org, "simulations": simulations,
        "scenarios": asis["scenarios"],
        "portfolio": asis["portfolio"],
        "target_portfolio": target["portfolio"],
        "reducible_ale_p90": reducible_p90,
        "reducible_ale_mean": reducible_mean,
        "detection": built["detection"],
        # Surface the fallback-routing count so the report can disclose when
        # findings could not be attributed to a specific loss scenario (they are
        # conservatively folded into SAP-PRIV-03 and may overstate it).
        "unrouted": built["unrouted"],
    }
    return out
