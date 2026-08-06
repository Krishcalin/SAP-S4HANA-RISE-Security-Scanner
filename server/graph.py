"""
Attack paths: instantiation, cuts, chokepoints and closure over time.

WHAT THIS CLAIMS, AND WHAT IT DOES NOT
---------------------------------------
A path here is a statement that a set of conditions **co-exist in this landscape**,
each one evidenced by an open finding, arranged in an order that an attacker could
use. It is derived from exported configuration.

It is **not** a claim that anything was traversed, reached or validated. We hold no
connection to the system and never will — so every path carries
`derived_from_config` and the console repeats it. A buyer who has seen Wiz will ask
"did you actually reach it?", and the honest answer has to be prepared rather than
improvised. Wiz itself draws this distinction: graph-derived exposure is only
POTENTIAL until a dynamic scanner validates it, and we have no such scanner.

WHY TEMPLATES RATHER THAN FREE TRAVERSAL
-----------------------------------------
Free traversal over a graph this dense produces hundreds of "paths", most of them
noise, and the reviewer then has to work out which matter. Microsoft's own
documentation says the opposite is wanted — that an empty attack-path page is
correct, because paths should focus on real, exploitable threats rather than broad
scenarios. A short list is the feature.

So paths are instantiated from named templates in `data/attack_paths.json`, which is
CONTENT: adding a path is a data change, never a code change. Each hop names the
checks that evidence it, so a path can never claim more than the scanner actually
detected.

CUTS, AND WHY THEY NEED NO ALGORITHM
-------------------------------------
A hop marked `cut` appears on every variant of its path, so closing it disconnects
the path; everything else only reduces exploitability. That is the whole
mitigate-vs-additional split, and it needs no clever graph algorithm — only that
each hop knows whether removing it disconnects. The remediation knowledge base then
supplies the fix text for the cut at no extra content cost.
"""
from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from psycopg.types.json import Jsonb

from server import db

log = logging.getLogger(__name__)

TEMPLATES_PATH = Path(__file__).resolve().parents[1] / "data" / "attack_paths.json"

#: Findings in these states no longer hold a hop open. `accepted` deliberately
#: still does: a risk acceptance is a decision to tolerate the defect, not a claim
#: that it is gone, and an attacker is unmoved by paperwork. `mitigated` does not,
#: because a compensating control genuinely interrupts the step.
_CLOSED_STATES = ("resolved", "false_positive", "mitigated")


def load_templates(path: Optional[Path] = None) -> Dict[str, Any]:
    with open(path or TEMPLATES_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def ruleset_fingerprint(templates: Optional[Dict[str, Any]] = None) -> str:
    """Fingerprint of the path ruleset AS IT IS NOW.

    Stored paths go stale when the RULESET changes, not only when the data does.
    Measuring against the live fingerprint — rather than one recorded at the time —
    is what lets the console say "these derivations predate the current rules"
    instead of silently showing conclusions nobody would draw today.
    """
    tpl = templates or load_templates()
    canonical = json.dumps(tpl.get("paths", []), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


# --------------------------------------------------------------------------- #
#  Instantiation                                                              #
# --------------------------------------------------------------------------- #

def _open_findings_by_check(conn, landscape_id: int) -> Dict[str, List[Dict[str, Any]]]:
    rows = conn.execute(
        f"""
        SELECT f.id, f.check_id, f.severity, f.system_id, f.subject,
               f.priority_tier, s.sid, s.client, s.tier
        FROM finding f
        LEFT JOIN sap_system s ON s.id = f.system_id
        WHERE f.landscape_id = %s
          AND f.state NOT IN ({','.join(['%s'] * len(_CLOSED_STATES))})
        """, [landscape_id, *_CLOSED_STATES]).fetchall()
    out: Dict[str, List[Dict[str, Any]]] = {}
    for r in rows:
        out.setdefault(r["check_id"], []).append(r)
    return out


def instantiate(conn, landscape_id: int,
                templates: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Work out which templates currently hold, and with what evidence.

    Pure with respect to the database — it reads findings and returns structures.
    Persistence is `store_paths`, so the matching logic can be tested without one.
    """
    tpl = templates or load_templates()
    by_check = _open_findings_by_check(conn, landscape_id)

    instantiated: List[Dict[str, Any]] = []
    for path in tpl.get("paths", []):
        hops: List[Dict[str, Any]] = []
        satisfied_required = True

        for hop in path.get("hops", []):
            evidence = [f for cid in hop.get("checks", []) for f in by_check.get(cid, ())]
            present = bool(evidence)
            if hop.get("required") and not present:
                satisfied_required = False
            hops.append({
                "name": hop["name"],
                "required": bool(hop.get("required")),
                "is_cut": bool(hop.get("cut")),
                "why_cut": hop.get("why_cut"),
                "checks": hop.get("checks", []),
                "node_types": hop.get("node_types", []),
                "present": present,
                "findings": evidence,
            })

        if not satisfied_required:
            continue

        # A cut hop that is NOT present is already severed — but the path only
        # exists at all when every required hop holds, so this can only be an
        # optional cut. Those still count as cuts for remediation advice.
        systems = sorted({f["system_id"] for h in hops for f in h["findings"]
                          if f["system_id"] is not None})
        instantiated.append({
            "template_id": path["id"],
            "name": path["name"],
            "summary": path.get("summary", ""),
            "narrative": path.get("narrative", ""),
            "severity": path.get("severity", "HIGH"),
            "fair_scenario": path.get("fair_scenario"),
            "crosses_tier": bool(path.get("crosses_tier")),
            "hops": hops,
            "system_ids": systems,
            "finding_ids": sorted({f["id"] for h in hops for f in h["findings"]}),
            "cut_findings": sorted({f["id"] for h in hops if h["is_cut"]
                                    for f in h["findings"]}),
        })
    return instantiated


def _path_key(landscape_id: int, template_id: str, system_ids: Sequence[int]) -> str:
    """Stable identity for one instantiated path.

    Keyed on the template and the SYSTEMS it spans, never on the findings: the
    evidence for a hop changes as individual defects are fixed and re-found, and
    folding that into identity would retire and re-raise the path continuously —
    the same mistake that aggregate findings avoid.
    """
    scope = ",".join(str(s) for s in sorted(system_ids)) or "-"
    return f"{template_id}@{scope}"


def store_paths(conn, landscape_id: int, run_id: int,
                templates: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Recompute paths for a landscape and persist them with their lifecycle.

    Paths are stored entities with `first_seen`, `last_seen` and `closed_at`, not
    query results rendered on demand. That is what makes closure observable:
    "this path was severed on 12 September when the S_RFCACL wildcard was removed"
    is a sentence that requires the path to have been a row all along.
    """
    tpl = templates or load_templates()
    fingerprint = ruleset_fingerprint(tpl)
    live = instantiate(conn, landscape_id, tpl)
    live_by_key = {_path_key(landscape_id, p["template_id"], p["system_ids"]): p
                   for p in live}

    existing = {r["path_key"]: r for r in conn.execute(
        "SELECT id, path_key, closed_at FROM attack_path WHERE landscape_id = %s",
        (landscape_id,)).fetchall()}

    opened, persisting, closed, reopened = [], [], [], []

    for key, p in live_by_key.items():
        prior = existing.get(key)
        if prior is None:
            path_id = conn.execute(
                """
                INSERT INTO attack_path
                    (landscape_id, template_id, path_key, fair_scenario, severity,
                     ruleset_fingerprint)
                VALUES (%s,%s,%s,%s,%s,%s) RETURNING id
                """,
                (landscape_id, p["template_id"], key, p["fair_scenario"],
                 p["severity"], fingerprint)).fetchone()["id"]
            opened.append(path_id)
        else:
            path_id = prior["id"]
            was_closed = prior["closed_at"] is not None
            conn.execute(
                "UPDATE attack_path SET last_seen = now(), closed_at = NULL, "
                "closed_by_edge = NULL, severity = %s, ruleset_fingerprint = %s "
                "WHERE id = %s", (p["severity"], fingerprint, path_id))
            (reopened if was_closed else persisting).append(path_id)

        # Evidence is rewritten each run: it is the CURRENT state of the path, and
        # the path's own row carries the history.
        conn.execute("DELETE FROM attack_path_finding WHERE path_id = %s", (path_id,))
        for fid in p["finding_ids"]:
            conn.execute(
                "INSERT INTO attack_path_finding (path_id, finding_id) VALUES (%s,%s) "
                "ON CONFLICT DO NOTHING", (path_id, fid))
        conn.execute(
            "UPDATE attack_path SET detail = %s WHERE id = %s",
            (Jsonb(_detail(p)), path_id))
        p["_id"] = path_id

    # Anything stored and no longer instantiated is CLOSED, not deleted — the row
    # and its first_seen are what make "severed on 12 September" expressible.
    for key, row in existing.items():
        if key in live_by_key or row["closed_at"] is not None:
            continue
        conn.execute(
            "UPDATE attack_path SET closed_at = now(), closed_by_edge = NULL "
            "WHERE id = %s", (row["id"],))
        closed.append(row["id"])

    return {"open": len(live_by_key), "opened": opened, "persisting": persisting,
            "reopened": reopened, "closed": closed,
            "ruleset_fingerprint": fingerprint}


def _detail(p: Dict[str, Any]) -> Dict[str, Any]:
    """The renderable shape of a path, without the finding rows themselves."""
    return {
        "name": p["name"], "summary": p["summary"], "narrative": p["narrative"],
        "crosses_tier": p["crosses_tier"],
        "system_ids": p["system_ids"],
        "hops": [{
            "name": h["name"], "required": h["required"], "is_cut": h["is_cut"],
            "why_cut": h["why_cut"], "present": h["present"],
            "checks": h["checks"],
            "finding_ids": [f["id"] for f in h["findings"]],
            "evidence": [{"id": f["id"], "check_id": f["check_id"],
                          "severity": f["severity"], "sid": f["sid"],
                          "client": f["client"], "tier": f["tier"]}
                         for f in h["findings"][:12]],
            "evidence_total": len(h["findings"]),
        } for h in p["hops"]],
        # Confidence is stated on the path itself, not left to the UI to remember.
        "confidence": "derived_from_config",
        "confidence_note": (
            "These conditions co-exist in the exported configuration. Nothing was "
            "connected to, traversed or validated."),
    }


# --------------------------------------------------------------------------- #
#  Reads                                                                      #
# --------------------------------------------------------------------------- #

def _scoped(scope: Optional[Sequence[int]]) -> Tuple[str, List[Any]]:
    """Path-level row scoping.

    A path spans systems, so it is visible when the caller may see ANY system it
    touches. Requiring all of them would hide precisely the cross-tier paths that
    matter most from anyone with a partial scope.
    """
    if scope is None:
        return "TRUE", []
    if not scope:
        return "FALSE", []
    return ("EXISTS (SELECT 1 FROM attack_path_finding apf "
            "JOIN finding f ON f.id = apf.finding_id "
            "WHERE apf.path_id = p.id AND f.system_id = ANY(%s))", [list(scope)])


def list_paths(scope: Optional[Sequence[int]], landscape_id: Optional[int] = None,
               include_closed: bool = False) -> List[Dict[str, Any]]:
    where, params = [], []
    clause, sparams = _scoped(scope)
    where.append(clause); params.extend(sparams)
    if landscape_id is not None:
        where.append("p.landscape_id = %s"); params.append(landscape_id)
    if not include_closed:
        where.append("p.closed_at IS NULL")
    return db.query(
        f"""
        SELECT p.*, c.ale_p90 AS scenario_ale,
               (SELECT count(*) FROM attack_path_finding apf WHERE apf.path_id = p.id)
                   AS finding_count
        FROM attack_path p
        LEFT JOIN LATERAL (
            SELECT cr.ale_p90 FROM crq_result cr
            JOIN scan_run r ON r.id = cr.scan_run_id
            WHERE cr.scenario_id = p.fair_scenario AND r.landscape_id = p.landscape_id
            ORDER BY r.started_at DESC LIMIT 1
        ) c ON TRUE
        WHERE {' AND '.join(where)}
        ORDER BY CASE p.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                                 WHEN 'MEDIUM' THEN 2 ELSE 3 END,
                 c.ale_p90 DESC NULLS LAST, p.first_seen
        """, params)


def get_path(path_id: int, scope: Optional[Sequence[int]]) -> Optional[Dict[str, Any]]:
    clause, params = _scoped(scope)
    return db.one(
        f"""
        SELECT p.*, c.ale_p90 AS scenario_ale
        FROM attack_path p
        LEFT JOIN LATERAL (
            SELECT cr.ale_p90 FROM crq_result cr
            JOIN scan_run r ON r.id = cr.scan_run_id
            WHERE cr.scenario_id = p.fair_scenario AND r.landscape_id = p.landscape_id
            ORDER BY r.started_at DESC LIMIT 1
        ) c ON TRUE
        WHERE p.id = %s AND {clause}
        """, [path_id, *params])


def path_findings(path_id: int) -> List[Dict[str, Any]]:
    return db.query(
        """
        SELECT f.id, f.check_id, f.severity, f.state, f.priority_tier,
               f.remediation_owner, cd.title, cd.remediation, s.sid, s.client
        FROM attack_path_finding apf
        JOIN finding f ON f.id = apf.finding_id
        JOIN check_definition cd ON cd.check_id = f.check_id
        LEFT JOIN sap_system s ON s.id = f.system_id
        WHERE apf.path_id = %s
        ORDER BY f.severity, f.check_id
        """, (path_id,))


def chokepoints(scope: Optional[Sequence[int]], limit: int = 15,
                landscape_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """Findings that sit on a CUT hop of the most open paths.

    This is the landing metric, not the graph. It converts a 300-row report into a
    short worklist with a stated consequence per line — "close this and 4 paths
    die" — which is a far more persuasive artefact than any picture.

    Only cut hops count. A finding on a non-cut hop reduces exploitability without
    severing anything, and including it would promise a closure it cannot deliver.
    """
    clause, params = _scoped(scope)
    land = ""
    if landscape_id is not None:
        land = " AND p.landscape_id = %s"
        params = list(params) + [landscape_id]
    return db.query(
        f"""
        WITH cut_findings AS (
            SELECT p.id AS path_id, p.severity, p.fair_scenario,
                   (jsonb_array_elements(p.detail->'hops')->'finding_ids') AS ids,
                   (jsonb_array_elements(p.detail->'hops')->>'is_cut')::boolean AS is_cut
            FROM attack_path p
            WHERE p.closed_at IS NULL AND {clause}{land}
        ),
        exploded AS (
            SELECT path_id, severity, fair_scenario,
                   (jsonb_array_elements_text(ids))::bigint AS finding_id
            FROM cut_findings WHERE is_cut
        )
        SELECT e.finding_id, count(DISTINCT e.path_id) AS paths_cut,
               array_agg(DISTINCT e.fair_scenario) AS scenarios,
               f.check_id, f.severity, f.state, f.priority_tier,
               f.remediation_owner, cd.title, s.sid, s.client
        FROM exploded e
        JOIN finding f ON f.id = e.finding_id
        JOIN check_definition cd ON cd.check_id = f.check_id
        LEFT JOIN sap_system s ON s.id = f.system_id
        GROUP BY e.finding_id, f.check_id, f.severity, f.state, f.priority_tier,
                 f.remediation_owner, cd.title, s.sid, s.client
        ORDER BY paths_cut DESC,
                 CASE f.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                                 WHEN 'MEDIUM' THEN 2 ELSE 3 END
        LIMIT %s
        """, params + [limit])


def path_summary(scope: Optional[Sequence[int]]) -> Dict[str, Any]:
    clause, params = _scoped(scope)
    counts = db.one(
        f"""
        SELECT count(*) FILTER (WHERE p.closed_at IS NULL)                    AS open,
               count(*) FILTER (WHERE p.closed_at IS NULL
                                  AND p.severity = 'CRITICAL')                AS critical,
               count(*) FILTER (WHERE p.closed_at IS NOT NULL)                AS closed,
               count(*) FILTER (WHERE p.closed_at IS NULL
                                  AND p.ruleset_fingerprint IS DISTINCT FROM %s) AS stale
        FROM attack_path p WHERE {clause}
        """, [ruleset_fingerprint(), *params])
    return dict(counts or {})


def recently_closed(scope: Optional[Sequence[int]], limit: int = 10):
    """Paths severed, most recent first — the mitigation journey's strongest unit."""
    clause, params = _scoped(scope)
    return db.query(
        f"SELECT p.* FROM attack_path p WHERE p.closed_at IS NOT NULL AND {clause} "
        f"ORDER BY p.closed_at DESC LIMIT %s", params + [limit])
