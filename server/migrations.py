"""One-off data migrations that SQL cannot express.

`schema.sql` handles structure: it is idempotent DDL plus a `schema_version`
marker, and re-running it is free. That works for columns and indexes and stops
working the moment a migration has to recompute a hash, because a fingerprint is
a SHA over normalised objects and Postgres cannot reproduce it.

EACH MIGRATION RUNS ONCE, guarded by its own `schema_version` row, and each is
written to be safe if it somehow runs twice anyway. Belt and braces, because the
thing being rewritten here is finding IDENTITY, and identity is what every
finding's history hangs off: age, assignee, risk acceptance, the whole mitigation
journey. A migration that half-applies is worse than one that never ran.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

log = logging.getLogger(__name__)

#: The `parameter` -> `parameter_name` unification.
PARAMETER_TYPE_VERSION = 4


def _renamed(subject: Any) -> Any:
    """The stored subject with `parameter` retyped, or None if nothing changes."""
    if not isinstance(subject, list):
        return None
    out, touched = [], False
    for o in subject:
        if isinstance(o, dict) and o.get("type") == "parameter":
            o = {**o, "type": "parameter_name"}
            touched = True
        out.append(o)
    return out if touched else None


def migrate_parameter_type(conn) -> Dict[str, Any]:
    """Retype `parameter` objects to `parameter_name`, keeping every history.

    THE DEFECT. `webdisp_security` emitted the object type `parameter` while every
    other module emitted `parameter_name`. Identity was correct either way -- both
    took the same case rule -- but the graph keys a node on `type:name@system`, so
    five profile parameters an estate has once existed as two nodes:

        login/show_detailed_errors        is/HTTP/show_detailed_errors
        is/HTTP/show_server_header        rdisp/TRACE_HIDE_SEC_DATA
        service/protectedwebmethods

    A risk-path hop declaring `parameter_name` saw half their evidence, and
    choke-point ranking counted one estate object as two.

    WHY THIS COULD NOT BE A CODE CHANGE ALONE. Retyping the object changes the
    fingerprint of every WDISP finding, and `_rebase` in server/ingest.py cannot
    carry that history: it rebases across a change of BASIS -- display to objects,
    say -- and this keeps the basis at `objects`. Widening `_rebase` to same-basis
    moves would be worse than the defect it fixed, because under `objects` basis a
    moved fingerprint normally means a genuinely DIFFERENT object, and rebasing
    onto it would attach one defect's history to another.

    So the mapping is done here, once, where it is explicit: for each affected
    row, retype the stored subject and recompute the fingerprint the same way
    `server.ingest` will compute it on the next scan. Get that wrong and the
    migration achieves nothing -- the next run reports every WDISP finding as new
    and resolves the old ones, which is the exact churn this exists to prevent.

    A COLLISION IS REFUSED, NOT RESOLVED. If the recomputed fingerprint already
    belongs to another row in the same landscape, the two findings would have to
    merge, and merging discards one row's age, assignee and acceptance. That is
    the same judgement `_rebase` makes when several candidates match: do nothing
    and report it, because attaching one defect's history to another is worse than
    leaving a duplicate that a human can look at.
    """
    from server.identity import fingerprint_finding

    done = conn.execute(
        "SELECT 1 FROM schema_version WHERE version = %s",
        (PARAMETER_TYPE_VERSION,)).fetchone()
    if done:
        return {"status": "already applied", "migrated": 0}

    rows = conn.execute(
        """
        SELECT f.id, f.check_id, f.scope, f.client, f.subject, f.fingerprint,
               f.landscape_id, s.sid
        FROM finding f
        LEFT JOIN sap_system s ON s.id = f.system_id
        WHERE f.subject::text LIKE '%"type": "parameter"%'
           OR f.subject::text LIKE '%"type":"parameter"%'
        """).fetchall()

    migrated: List[int] = []
    collided: List[Dict[str, Any]] = []
    unchanged = 0

    for r in rows:
        subject = r["subject"]
        if isinstance(subject, str):
            subject = json.loads(subject)
        new_subject = _renamed(subject)
        if new_subject is None:
            unchanged += 1
            continue

        # Reconstructed the way ingest presents a finding to the fingerprinter, so
        # the value computed here is the value the next scan will compute.
        fp, basis = fingerprint_finding(
            {"check_id": r["check_id"], "subject": new_subject, "scope": r["scope"]},
            r["sid"], r["client"])

        if fp == r["fingerprint"]:
            unchanged += 1
            continue

        clash = conn.execute(
            "SELECT id FROM finding WHERE landscape_id = %s AND fingerprint = %s "
            "AND id <> %s",
            (r["landscape_id"], fp, r["id"])).fetchone()
        if clash:
            collided.append({"finding": r["id"], "would_merge_into": clash["id"],
                             "check_id": r["check_id"]})
            continue

        conn.execute(
            "UPDATE finding SET subject = %s, fingerprint = %s, fingerprint_basis = %s "
            "WHERE id = %s",
            (json.dumps(new_subject), fp, basis, r["id"]))
        conn.execute(
            "INSERT INTO finding_transition (finding_id, from_state, to_state, actor, "
            "reason) VALUES (%s, NULL, 'open', 'migration', %s)",
            (r["id"], "object type `parameter` unified to `parameter_name`; "
                      "identity recomputed, history preserved"))
        migrated.append(r["id"])

    # The duplicated nodes themselves. graph_node is DERIVED -- rebuilt from
    # findings on every ingest -- so the stale half is deleted rather than
    # rewritten, which also sidesteps merging two node rows that are about to be
    # regenerated as one. Anything referencing them is ON DELETE SET NULL.
    nodes = conn.execute(
        "DELETE FROM graph_node WHERE type = 'parameter' RETURNING id").fetchall()

    conn.execute("INSERT INTO schema_version (version) VALUES (%s) "
                 "ON CONFLICT DO NOTHING", (PARAMETER_TYPE_VERSION,))

    result = {"status": "applied", "migrated": len(migrated),
              "unchanged": unchanged, "stale_nodes_removed": len(nodes),
              "collisions": collided}
    log.info("parameter type migration: %s", result)
    return result


#: Lifting `internet_exposed` from observation details onto the finding row.
INTERNET_EXPOSED_VERSION = 5


def backfill_internet_exposed(conn) -> Dict[str, Any]:
    """Copy the exposure verdict from the latest observation onto the finding.

    WHY A MIGRATION AND NOT JUST THE NEXT SCAN. `ingest` writes the column from
    now on, so a re-scanned estate fills it in by itself. But an estate that is
    not re-scanned would carry the verdict in `finding_observation.details` —
    where it has been recorded since the endpoint join shipped — and NULL on the
    row, so the same fact would read two different ways depending on which the
    caller consulted. That is worse than not having the column.

    WHAT IT REFUSES TO INVENT. Only observations that actually RECORD the key are
    read. A finding scanned before the join existed has no `internet_exposed` in
    its details at all, and stays NULL — which is the honest answer, because
    nobody ever asked the question about it. `schema.sql` makes the same argument
    for `crq_result.model_version`: "backfilling them with a revision they were
    not computed from would be inventing provenance."

    ONLY `true` IS COPIED. The verdict is `True` or absent — `reachability.
    exposure` never answers "not exposed" — so there is no False to carry, and a
    row that would have received one is a row this product does not produce.
    """
    done = conn.execute(
        "SELECT 1 FROM schema_version WHERE version = %s",
        (INTERNET_EXPOSED_VERSION,)).fetchone()
    if done:
        return {"status": "already applied", "backfilled": 0}

    # The LATEST observation per finding, because the verdict is per-run: an
    # endpoint deactivated between scans changes the answer, and the most recent
    # scan is the one that describes the estate now.
    updated = conn.execute(
        """
        UPDATE finding f
           SET internet_exposed = true
          FROM (
                SELECT DISTINCT ON (o.finding_id) o.finding_id, o.details
                  FROM finding_observation o
                 ORDER BY o.finding_id, o.id DESC
               ) latest
         WHERE latest.finding_id = f.id
           AND f.internet_exposed IS NULL
           AND latest.details ->> 'internet_exposed' = 'true'
        """).rowcount

    conn.execute("INSERT INTO schema_version (version) VALUES (%s) "
                 "ON CONFLICT DO NOTHING", (INTERNET_EXPOSED_VERSION,))
    log.info("backfilled internet_exposed on %d finding(s)", updated)
    return {"status": "applied", "backfilled": int(updated or 0)}


def run_all(conn) -> List[Dict[str, Any]]:
    """Every data migration, in order. Called by `server.cli init-db`."""
    return [migrate_parameter_type(conn), backfill_internet_exposed(conn)]
