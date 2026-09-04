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

from server import db, identity

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
                # Authored commentary on the hop. Usually the reason a hop is NOT a
                # cut — "withdrawing emergency access is not a remediation anyone
                # will accept" — which is the half of mitigate-vs-additional that
                # `why_cut` cannot carry, because it is about the hops that do not
                # sever anything.
                "note": hop.get("note"),
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
            "why_cut": h["why_cut"], "note": h.get("note"),
            "present": h["present"],
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
        SELECT p.*, c.ale_p90 AS scenario_ale, c.loss_model,
               (SELECT count(*) FROM attack_path_finding apf WHERE apf.path_id = p.id)
                   AS finding_count
        FROM attack_path p
        LEFT JOIN LATERAL (
            -- `loss_model` rides along with the figure it describes, from the same
            -- row. Returning `ale_p90` without it is what left the risk-path
            -- screens unable to ask lib/pricing whether the number is the
            -- customer's own or the catalogue's illustrative $1bn manufacturer.
            SELECT cr.ale_p90, cr.detail -> 'loss_model' AS loss_model
            FROM crq_result cr
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
        SELECT p.*, c.ale_p90 AS scenario_ale, c.loss_model
        FROM attack_path p
        LEFT JOIN LATERAL (
            -- `loss_model` rides along with the figure it describes, from the same
            -- row. Returning `ale_p90` without it is what left the risk-path
            -- screens unable to ask lib/pricing whether the number is the
            -- customer's own or the catalogue's illustrative $1bn manufacturer.
            SELECT cr.ale_p90, cr.detail -> 'loss_model' AS loss_model
            FROM crq_result cr
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


#: Edge kinds that put an ACCOUNT on a path. Each names a privilege a user
#: holds, so walking one backwards from an object the path depends on answers
#: "who is standing here". `grants_authorization` is deliberately absent: it runs
#: role -> auth_object and its source is not an account.
_ACTOR_EDGES = ("holds_role", "holds_profile", "can_use_destination")


def path_actors(path_id: int, scope: Optional[Sequence[int]]
                ) -> Dict[str, Any]:
    """The accounts whose configuration puts them on this path.

    THE FIRST THING THAT READS THE GRAPH. Until this existed, `graph_node` and
    `graph_edge` were written by every ingest and selected by nothing, and the
    scan said so out loud.

    A path is a chain of hops evidenced by CHECKS. "Caller can arrive as any
    user (AUTH-002)" names a check, never an account, so the templates
    structurally cannot say who is able to walk the route they describe. The
    graph can: it holds `user -holds_role-> role`, `user -holds_profile->
    profile` and `user -can_use_destination-> destination`, so taking the
    objects this path's findings name and walking one actor edge backwards
    yields the accounts the configuration places on it.

    WHAT THIS CLAIMS, in the same terms `data/graph_edges.json` sets for every
    edge: that the configuration GRANTS these accounts the privileges the path
    depends on. Not that any of them walked it, and not that the route was ever
    exercised — every edge is `derived_from_config`. `provenance` is carried
    through unchanged rather than summarised, so a `used` edge still means only
    that the account logged on in the exported window, which evidences that the
    ACCOUNT is live rather than that it invoked this role or destination.

    Absence is reported as absence. `edges_available` distinguishes "this path
    touches no object any edge reaches" from "the graph holds no edges at all",
    because a bare empty list reads as "nobody can do this" and only one of
    those two situations says anything about the estate.
    """
    path = get_path(path_id, scope)
    if path is None:
        return {"actors": [], "edges_available": None, "reachable_objects": 0}

    findings = db.query(
        """
        SELECT f.subject, s.sid
        FROM attack_path_finding apf
        JOIN finding f ON f.id = apf.finding_id
        LEFT JOIN sap_system s ON s.id = f.system_id
        WHERE apf.path_id = %s
        """, (path_id,))

    # Keyed exactly as ingest keyed them, by reusing the extractor that wrote
    # the nodes. Re-deriving the key format here is how the two halves drift.
    keys = set()
    for row in findings:
        subject = row.get("subject")
        if isinstance(subject, str):
            try:
                subject = json.loads(subject)
            except ValueError:
                continue
        if not subject:
            continue
        for node in identity.extract_nodes([{"affected_objects": subject}],
                                           default_system=row.get("sid")):
            keys.add(node["key"])

    total_edges = db.one(
        "SELECT count(*) AS n FROM graph_edge WHERE landscape_id = %s",
        (path["landscape_id"],))["n"]
    if not keys:
        return {"actors": [], "edges_available": total_edges,
                "reachable_objects": 0}

    rows = db.query(
        f"""
        SELECT src.name AS actor, src.type AS actor_type,
               dst.name AS object, dst.type AS object_type,
               e.type AS edge_type, e.provenance, e.check_id
        FROM graph_edge e
        JOIN graph_node src ON src.id = e.from_node
        JOIN graph_node dst ON dst.id = e.to_node
        WHERE e.landscape_id = %s
          AND dst.node_key = ANY(%s)
          AND e.type = ANY(%s)
        ORDER BY src.name, dst.name
        """, (path["landscape_id"], sorted(keys), list(_ACTOR_EDGES)))

    actors: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        entry = actors.setdefault(row["actor"], {
            "actor": row["actor"], "actor_type": row["actor_type"],
            "via": [], "any_used": False,
        })
        entry["via"].append({
            "object": row["object"], "object_type": row["object_type"],
            "edge_type": row["edge_type"], "provenance": row["provenance"],
            "check_id": row["check_id"],
        })
        if row["provenance"] == "used":
            entry["any_used"] = True

    return {
        "actors": sorted(actors.values(), key=lambda a: a["actor"]),
        "edges_available": total_edges,
        # How much of the path the graph could speak to at all. A path whose
        # objects no edge reaches is not a path nobody can walk; it is a path
        # this graph has nothing to say about, and the two must not render alike.
        "reachable_objects": len({r["object"] for r in rows}),
        "objects_on_path": len(keys),
    }


def chokepoints(scope: Optional[Sequence[int]], limit: int = 15,
                landscape_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """Findings that sit on a CUT hop of the most open paths, and what that is worth.

    This is the landing metric, not the graph. It converts a 300-row report into a
    short worklist with a stated consequence per line — "close this and 4 paths
    die" — which is a far more persuasive artefact than any picture.

    Only cut hops count. A finding on a non-cut hop reduces exploitability without
    severing anything, and including it would promise a closure it cannot deliver.

    WHY THERE IS MONEY ON THIS ROW NOW
    ----------------------------------
    Every path names the FAIR scenario it ends at, and every scenario carries a
    calibrated annual figure. The two lived side by side and were never joined,
    so the one screen where somebody decides what to do on Monday ranked its
    worklist by a path count while the currency figure sat on a different page.

    WHAT THE FIGURE IS ALLOWED TO MEAN, WHICH IS THE WHOLE PROBLEM
    --------------------------------------------------------------
    The tempting arithmetic is "sum the ALE of every scenario this finding's cut
    paths reach". It is wrong, and wrong in the flattering direction:

      * A scenario is reachable by SEVERAL paths. Cutting one of six leaves the
        scenario reachable, and claiming its whole ALE would promise a closure
        the graph explicitly says does not happen.
      * The FAIR figure is driven by findings routed to a scenario, not by paths.
        Severing a path does not mechanically remove a scenario's exposure.

    So money is attached ONLY where this finding cuts EVERY open path to a
    scenario — where the graph's own claim is that the scenario becomes
    unreachable by any modelled route. That makes the headline rare and strong:
    "close this one thing and the entire ransomware scenario has no path left".
    Everywhere else the row still says how many of how many paths it severs, and
    says no number, because a fraction of a scenario's ALE is a quantity this
    model does not compute and cannot defend.
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
        ,
        -- How many open paths reach each scenario AT ALL. The denominator of
        -- the only claim this function is allowed to monetise.
        scenario_paths AS (
            SELECT p.fair_scenario, count(*) AS paths_open
            FROM attack_path p
            WHERE p.closed_at IS NULL AND {clause}{land}
            GROUP BY p.fair_scenario
        ),
        -- The most recent completed run's per-scenario figure. NULL where the
        -- customer has not calibrated, which is a state this must survive: the
        -- worklist is still a worklist without money on it.
        priced AS (
            SELECT DISTINCT ON (c.scenario_id)
                   c.scenario_id, c.ale_mean, c.ale_p90,
                   -- FROM THE RUN'S PORTFOLIO ROW, not from this one.
                   --
                   -- Whether the customer priced the business is a property of
                   -- the RUN, and server/crq.py stores it once, on the row whose
                   -- scenario_id is NULL. Reading `c.detail` here instead found
                   -- nothing on every real row ever written, so the gate could
                   -- never open and no chokepoint could ever carry a figure.
                   -- It passed its tests because the fixture wrote the field
                   -- where this query looked for it.
                   --
                   -- Read rather than duplicated per scenario: two places to
                   -- record one fact is two places for it to disagree.
                   (SELECT pf.detail -> 'loss_model' FROM crq_result pf
                     WHERE pf.scan_run_id = c.scan_run_id
                       AND pf.scenario_id IS NULL) AS loss_model
            FROM crq_result c
            JOIN scan_run r ON r.id = c.scan_run_id
            WHERE c.scenario_id IS NOT NULL AND r.status = 'complete'
            ORDER BY c.scenario_id, r.started_at DESC
        ),
        per_scenario AS (
            SELECT e.finding_id, e.fair_scenario,
                   count(DISTINCT e.path_id) AS paths_cut,
                   sp.paths_open,
                   count(DISTINCT e.path_id) >= sp.paths_open AS severs_all,
                   pr.ale_mean, pr.ale_p90, pr.loss_model
            FROM exploded e
            JOIN scenario_paths sp ON sp.fair_scenario = e.fair_scenario
            LEFT JOIN priced pr ON pr.scenario_id = e.fair_scenario
            GROUP BY e.finding_id, e.fair_scenario, sp.paths_open,
                     pr.ale_mean, pr.ale_p90, pr.loss_model
        )
        SELECT e.finding_id, count(DISTINCT e.path_id) AS paths_cut,
               array_agg(DISTINCT e.fair_scenario) AS scenarios,
               f.check_id, f.severity, f.state, f.priority_tier,
               f.remediation_owner, cd.title, s.sid, s.client,
               -- Per scenario: severed how many of how many, and what it is
               -- worth if the answer is "all of them".
               (SELECT jsonb_agg(jsonb_build_object(
                           'scenario', ps.fair_scenario,
                           'paths_cut', ps.paths_cut,
                           'paths_open', ps.paths_open,
                           'severs_all', ps.severs_all,
                           'ale_mean', ps.ale_mean,
                           'ale_p90', ps.ale_p90,
                           'loss_model', ps.loss_model)
                       ORDER BY ps.severs_all DESC, ps.paths_cut DESC)
                  FROM per_scenario ps WHERE ps.finding_id = e.finding_id)
                   AS scenario_detail,
               -- THE SORT KEY, and the only number on this row that is money.
               -- Summed over the scenarios this finding leaves with no open
               -- path at all; null where it severs none of them outright.
               (SELECT sum(ps.ale_mean) FROM per_scenario ps
                 WHERE ps.finding_id = e.finding_id AND ps.severs_all
                   AND (ps.loss_model ->> 'applied')::boolean IS TRUE)
                   AS ale_severed
        FROM exploded e
        JOIN finding f ON f.id = e.finding_id
        JOIN check_definition cd ON cd.check_id = f.check_id
        LEFT JOIN sap_system s ON s.id = f.system_id
        GROUP BY e.finding_id, f.check_id, f.severity, f.state, f.priority_tier,
                 f.remediation_owner, cd.title, s.sid, s.client
        -- Money first where there is money; the old ordering underneath it, so
        -- an uncalibrated deployment sees exactly the list it saw before.
        ORDER BY ale_severed DESC NULLS LAST,
                 paths_cut DESC,
                 CASE f.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                                 WHEN 'MEDIUM' THEN 2 ELSE 3 END
        LIMIT %s
        """, params + params + [limit])


def severing_sets(scope: Optional[Sequence[int]],
                  landscape_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """Per scenario: the smallest set of open findings that disconnects it.

    WHY THIS EXISTS. `chokepoints` prices a finding only where closing it alone
    severs every route to a scenario, which is the only claim a single finding
    supports. On a real estate that almost never happens — the reference
    landscape has four to six independent routes to each scenario, so every row
    on that worklist shows no figure and the product's differentiator is
    invisible on exactly the screen built to carry it.

    A SET is the honest unit. "Close these three and the ransomware scenario has
    no route left" is a claim the graph fully supports, it is what somebody
    actually schedules, and it is the first thing in this market that prices a
    remediation plan rather than a finding.

    THE ANSWER IS EXACT, not capped. Minimum hitting set is NP-hard in general
    and trivial here, because a finding matters only through WHICH PATHS it
    cuts. Collapsing candidates to distinct coverage signatures bounds the
    search by the number of paths rather than the number of findings: six paths
    admit at most sixty-three useful signatures however many hundred findings
    sit on them. Dominated signatures — those cutting a subset of another's
    paths — are dropped, because taking one can never beat taking the other.

    A PATH WITH NO CUT HOP CANNOT BE CLOSED THIS WAY, and a scenario holding one
    is reported as unclosable rather than being handed a set that quietly
    ignores it. Filtering those paths out is the obvious implementation and it
    would produce the product's most dangerous sentence: "close these three" for
    a scenario that still has a route open.
    """
    clause, params = _scoped(scope)
    land = ""
    if landscape_id is not None:
        land = " AND p.landscape_id = %s"
        params = list(params) + [landscape_id]

    rows = db.query(
        f"""
        SELECT p.id, p.fair_scenario, p.detail -> 'hops' AS hops
        FROM attack_path p
        WHERE p.closed_at IS NULL AND {clause}{land}
        """, params)

    by_scenario: Dict[str, List[Any]] = {}
    for row in rows:
        cuts = set()
        for hop in (row["hops"] or []):
            if hop.get("is_cut"):
                cuts |= {int(i) for i in (hop.get("finding_ids") or [])}
        by_scenario.setdefault(row["fair_scenario"], []).append(cuts)

    priced = {r["scenario_id"]: r for r in db.query(
        """
        SELECT DISTINCT ON (c.scenario_id) c.scenario_id, c.ale_mean,
               (SELECT pf.detail -> 'loss_model' FROM crq_result pf
                 WHERE pf.scan_run_id = c.scan_run_id
                   AND pf.scenario_id IS NULL) AS loss_model
        FROM crq_result c JOIN scan_run r ON r.id = c.scan_run_id
        WHERE c.scenario_id IS NOT NULL AND r.status = 'complete'
        ORDER BY c.scenario_id, r.started_at DESC
        """)}

    out: List[Dict[str, Any]] = []
    for scenario, paths in sorted(by_scenario.items()):
        money = priced.get(scenario) or {}
        applied = ((money.get("loss_model") or {}).get("applied") is True)
        entry: Dict[str, Any] = {
            "scenario": scenario,
            "paths_open": len(paths),
            "ale_mean": money.get("ale_mean") if applied else None,
        }
        if any(not cuts for cuts in paths):
            entry.update(closable=False, fixes=[], reason=(
                "one of these routes has no hop that closing a finding would "
                "sever, so no set of fixes disconnects this scenario"))
            out.append(entry)
            continue

        chosen = _smallest_cover(paths)
        entry.update(closable=True, fixes=_describe(chosen), reason="")
        out.append(entry)

    # Most valuable first where there is a value, then fewest fixes: the order
    # somebody would work them in.
    out.sort(key=lambda e: (-(float(e["ale_mean"]) if e["ale_mean"] else 0.0),
                            len(e["fixes"]) or 99))
    return out


def _smallest_cover(paths: List[set]) -> List[int]:
    """The fewest findings that touch every path. Exact.

    Candidates are collapsed to their coverage signature — which paths they cut
    — so the search is bounded by the path count rather than the finding count.
    """
    import itertools

    signature: Dict[frozenset, int] = {}
    for finding in sorted(set().union(*paths)):
        hits = frozenset(i for i, cuts in enumerate(paths) if finding in cuts)
        if hits and hits not in signature:
            signature[hits] = finding

    # A signature covering a subset of another's paths can never be the better
    # choice, so it is dropped before the search rather than explored.
    useful = [h for h in signature
              if not any(h < other for other in signature)]
    wanted = frozenset(range(len(paths)))

    for size in range(1, len(paths) + 1):
        for combo in itertools.combinations(useful, size):
            if frozenset().union(*combo) == wanted:
                return [signature[h] for h in combo]
    return []                                   # unreachable: one per path covers


def _describe(finding_ids: List[int]) -> List[Dict[str, Any]]:
    """The findings themselves, so the caller shows a worklist not a set of ids."""
    if not finding_ids:
        return []
    return db.query(
        """
        SELECT f.id AS finding_id, f.check_id, f.severity, f.remediation_owner,
               cd.title, s.sid, s.client
        FROM finding f
        JOIN check_definition cd ON cd.check_id = f.check_id
        LEFT JOIN sap_system s ON s.id = f.system_id
        WHERE f.id = ANY(%s)
        ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                                 WHEN 'MEDIUM' THEN 2 ELSE 3 END, f.check_id
        """, (list(finding_ids),))


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
