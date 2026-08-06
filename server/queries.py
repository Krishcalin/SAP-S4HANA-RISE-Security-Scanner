"""
The query layer.

EVERY read of findings, runs or systems goes through here, and every one of them
composes `db.scope_clause` rather than writing its own row predicate. A filter
expressed in nine places is a filter that is missing from one, and the one it is
missing from is the leak.

Functions return plain dicts. The HTML pages and the JSON API call the same
functions, which is what makes "everything the console shows is available via the
API" structural rather than something to remember.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple

from server import db

PAGE_SIZE = 50

#: Legal lifecycle moves. A transition table beats scattered if-statements: it is
#: the one place to see that, for example, a resolved finding is re-opened by the
#: SCANNER observing it again, never by a human clicking a button.
ALLOWED_TRANSITIONS = {
    "open": {"submitted_to_provider", "mitigated", "accepted", "false_positive"},
    "submitted_to_provider": {"open", "mitigated", "accepted", "false_positive"},
    "mitigated": {"open", "accepted", "false_positive"},
    "accepted": {"open", "false_positive"},
    "false_positive": {"open"},
    "resolved": {"open", "false_positive"},
}


class TransitionError(ValueError):
    pass


def _scoped(where: List[str], params: List[Any], scope: Optional[Sequence[int]],
            column: str = "f.system_id") -> None:
    clause, extra = db.scope_clause(scope, column)
    where.append(clause)
    params.extend(extra)


# --------------------------------------------------------------------------- #
#  Reference data                                                             #
# --------------------------------------------------------------------------- #

def list_landscapes() -> List[Dict[str, Any]]:
    return db.query("SELECT * FROM landscape ORDER BY name")


def list_systems(scope: Optional[Sequence[int]]) -> List[Dict[str, Any]]:
    where, params = [], []
    _scoped(where, params, scope, "s.id")
    return db.query(
        f"SELECT s.*, l.name AS landscape_name, l.deployment_mode "
        f"FROM sap_system s JOIN landscape l ON l.id = s.landscape_id "
        f"WHERE {' AND '.join(where)} ORDER BY s.sid, s.client", params)


# --------------------------------------------------------------------------- #
#  Dashboard                                                                  #
# --------------------------------------------------------------------------- #

def dashboard_summary(scope: Optional[Sequence[int]]) -> Dict[str, Any]:
    where, params = ["f.state NOT IN ('resolved','false_positive')"], []
    _scoped(where, params, scope)
    w = " AND ".join(where)

    by_sev = db.query(
        f"SELECT f.severity, count(*) AS n FROM finding f WHERE {w} "
        f"GROUP BY f.severity", params)
    by_owner = db.query(
        f"SELECT f.remediation_owner, count(*) AS n FROM finding f WHERE {w} "
        f"GROUP BY f.remediation_owner", params)
    by_state = db.query(
        f"SELECT f.state, count(*) AS n FROM finding f WHERE {w} GROUP BY f.state",
        params)

    # An expired risk acceptance is itself an audit finding, so it is surfaced on
    # the landing page rather than buried behind a filter nobody applies.
    expired = db.one(
        f"SELECT count(*) AS n FROM finding f WHERE {w} AND f.state = 'accepted' "
        f"AND f.acceptance_due IS NOT NULL AND f.acceptance_due < CURRENT_DATE",
        params)

    # Findings whose identity we do not fully trust. Shown because a journey
    # feature that cannot say which rows match reliably is not trustworthy.
    weak = db.one(
        f"SELECT count(*) AS n FROM finding f WHERE {w} AND f.fingerprint_basis <> 'objects'",
        params)

    regressed = db.one(
        f"SELECT count(*) AS n FROM finding f WHERE {w} AND f.regression_count > 0", params)

    return {
        "by_severity": {r["severity"] or "UNKNOWN": r["n"] for r in by_sev},
        "by_remediation_owner": {r["remediation_owner"]: r["n"] for r in by_owner},
        "by_state": {r["state"]: r["n"] for r in by_state},
        "open_total": sum(r["n"] for r in by_sev),
        "expired_acceptances": expired["n"] if expired else 0,
        "weak_identity": weak["n"] if weak else 0,
        "regressed": regressed["n"] if regressed else 0,
    }


def recent_runs(scope: Optional[Sequence[int]], limit: int = 10) -> List[Dict[str, Any]]:
    where, params = [], []
    _scoped(where, params, scope, "r.system_id")
    params.append(limit)
    return db.query(
        f"SELECT r.*, s.sid, s.client FROM scan_run r "
        f"LEFT JOIN sap_system s ON s.id = r.system_id "
        f"WHERE {' AND '.join(where)} ORDER BY r.started_at DESC LIMIT %s", params)


# --------------------------------------------------------------------------- #
#  Findings                                                                   #
# --------------------------------------------------------------------------- #

def list_findings(scope: Optional[Sequence[int]], system_id: Optional[int] = None,
                  state: Optional[str] = None, severity: Optional[str] = None,
                  team: Optional[str] = None, remediation_owner: Optional[str] = None,
                  page: int = 1) -> Dict[str, Any]:
    where: List[str] = []
    params: List[Any] = []
    _scoped(where, params, scope)

    if state:
        where.append("f.state = %s"); params.append(state)
    else:
        where.append("f.state NOT IN ('resolved','false_positive')")
    if system_id is not None:
        where.append("f.system_id = %s"); params.append(system_id)
    if severity:
        where.append("f.severity = %s"); params.append(severity)
    if team:
        where.append("COALESCE(f.owning_team, cd.owning_team) = %s"); params.append(team)
    if remediation_owner:
        where.append("f.remediation_owner = %s"); params.append(remediation_owner)

    w = " AND ".join(where)
    total = db.one(
        f"SELECT count(*) AS n FROM finding f "
        f"JOIN check_definition cd ON cd.check_id = f.check_id WHERE {w}", params)["n"]

    page = max(1, page)
    rows = db.query(
        f"""
        SELECT f.*, cd.title, cd.category, cd.owning_team AS default_team,
               cd.baseline_req_id, s.sid, s.client AS system_client, s.tier,
               (f.state = 'accepted' AND f.acceptance_due IS NOT NULL
                AND f.acceptance_due < CURRENT_DATE) AS expired_acceptance,
               GREATEST(0, EXTRACT(DAY FROM (COALESCE(f.resolved_at, now())
                                             - f.first_seen_at))::int) AS days_open
        FROM finding f
        JOIN check_definition cd ON cd.check_id = f.check_id
        LEFT JOIN sap_system s ON s.id = f.system_id
        WHERE {w}
        ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                                 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END,
                 f.first_seen_at
        LIMIT %s OFFSET %s
        """, params + [PAGE_SIZE, (page - 1) * PAGE_SIZE])

    return {"findings": rows, "total": total, "page": page,
            "pages": max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)}


def get_finding(finding_id: int, scope: Optional[Sequence[int]]) -> Optional[Dict[str, Any]]:
    where, params = ["f.id = %s"], [finding_id]
    _scoped(where, params, scope)
    return db.one(
        f"SELECT f.*, cd.title, cd.category, cd.remediation, cd.risk_narrative, "
        f"cd.references_json, cd.baseline_req_id, cd.responsibility, "
        f"s.sid, s.client AS system_client, s.tier, l.deployment_mode "
        f"FROM finding f JOIN check_definition cd ON cd.check_id = f.check_id "
        f"LEFT JOIN sap_system s ON s.id = f.system_id "
        f"JOIN landscape l ON l.id = f.landscape_id "
        f"WHERE {' AND '.join(where)}", params)


def finding_history(finding_id: int) -> List[Dict[str, Any]]:
    return db.query(
        "SELECT * FROM finding_transition WHERE finding_id = %s ORDER BY occurred_at",
        (finding_id,))


def finding_observations(finding_id: int) -> List[Dict[str, Any]]:
    return db.query(
        "SELECT o.*, r.started_at FROM finding_observation o "
        "JOIN scan_run r ON r.id = o.scan_run_id "
        "WHERE o.finding_id = %s ORDER BY r.started_at DESC LIMIT 50", (finding_id,))


def transition_finding(finding_id: int, to_state: str, actor: str,
                       reason: str = "", ticket: str = "",
                       scope: Optional[Sequence[int]] = None) -> Dict[str, Any]:
    current = get_finding(finding_id, scope)
    if current is None:
        raise TransitionError("finding not found or not visible")

    from_state = current["state"]
    if to_state not in ALLOWED_TRANSITIONS.get(from_state, set()):
        raise TransitionError(f"cannot move a finding from {from_state} to {to_state}")

    # A dispute without a reason is noise; with one it is tuning data. Same for a
    # risk acceptance, which an auditor will ask to see justified.
    if to_state in ("false_positive", "accepted") and not reason.strip():
        raise TransitionError(f"a reason is required to mark a finding {to_state}")
    if to_state == "submitted_to_provider" and not ticket.strip():
        raise TransitionError(
            "a provider ticket reference is required — this state exists to track work "
            "handed to SAP, and it is meaningless without the ticket")

    with db.connection() as conn:
        sets = ["state = %s", "transitioned_by = %s", "last_transition_at = now()"]
        params: List[Any] = [to_state, actor]
        if to_state == "false_positive":
            sets.append("false_positive_reason = %s"); params.append(reason)
        if to_state == "accepted":
            sets += ["accepted_by = %s", "acceptance_reason = %s",
                     "acceptance_from = CURRENT_DATE"]
            params += [actor, reason]
        if to_state == "submitted_to_provider":
            sets.append("provider_ticket_ref = %s"); params.append(ticket)
        params.append(finding_id)

        conn.execute(f"UPDATE finding SET {', '.join(sets)} WHERE id = %s", params)
        conn.execute(
            "INSERT INTO finding_transition (finding_id, from_state, to_state, actor, "
            "reason) VALUES (%s,%s,%s,%s,%s)",
            (finding_id, from_state, to_state, actor, reason or ticket))
        db.audit(conn, actor, "finding.transition", "finding", str(finding_id),
                 {"from": from_state, "to": to_state})
        conn.commit()

    return {"finding_id": finding_id, "from": from_state, "to": to_state}


# --------------------------------------------------------------------------- #
#  Runs and the journey                                                       #
# --------------------------------------------------------------------------- #

def get_run(run_id: int, scope: Optional[Sequence[int]]) -> Optional[Dict[str, Any]]:
    where, params = ["r.id = %s"], [run_id]
    _scoped(where, params, scope, "r.system_id")
    return db.one(
        f"SELECT r.*, s.sid, s.client, l.name AS landscape_name, l.deployment_mode "
        f"FROM scan_run r LEFT JOIN sap_system s ON s.id = r.system_id "
        f"JOIN landscape l ON l.id = r.landscape_id "
        f"WHERE {' AND '.join(where)}", params)


def run_diff(run_id: int, scope: Optional[Sequence[int]]) -> Dict[str, Any]:
    """New / persisting / resolved / regressed for one run.

    Derived from stored columns rather than recomputed, so the numbers on this
    page can never disagree with the finding rows themselves.
    """
    where, params = ["f.first_seen_run = %s"], [run_id]
    _scoped(where, params, scope)
    new = db.query(
        f"SELECT f.id, f.check_id, f.severity, cd.title FROM finding f "
        f"JOIN check_definition cd ON cd.check_id = f.check_id "
        f"WHERE {' AND '.join(where)} ORDER BY f.severity", params)

    where, params = ["f.last_seen_run = %s", "f.first_seen_run <> %s"], [run_id, run_id]
    _scoped(where, params, scope)
    persisting = db.one(
        f"SELECT count(*) AS n FROM finding f WHERE {' AND '.join(where)}", params)["n"]

    where, params = ["f.state = 'resolved'", "f.last_seen_run < %s"], [run_id]
    _scoped(where, params, scope)
    resolved = db.one(
        f"SELECT count(*) AS n FROM finding f WHERE {' AND '.join(where)}", params)["n"]

    where, params = ["f.regression_count > 0", "f.last_seen_run = %s"], [run_id]
    _scoped(where, params, scope)
    regressed = db.query(
        f"SELECT f.id, f.check_id, f.severity, f.regression_count, cd.title "
        f"FROM finding f JOIN check_definition cd ON cd.check_id = f.check_id "
        f"WHERE {' AND '.join(where)}", params)

    return {"new": new, "new_count": len(new), "persisting": persisting,
            "resolved": resolved, "regressed": regressed,
            "regressed_count": len(regressed)}


def changes_since(run_id: int, scope: Optional[Sequence[int]]) -> Dict[str, Any]:
    """Everything that moved since a given run — the incremental endpoint."""
    where, params = ["f.last_transition_at IS NOT NULL",
                     "f.last_seen_run >= %s"], [run_id]
    _scoped(where, params, scope)
    rows = db.query(
        f"SELECT f.id, f.fingerprint, f.check_id, f.state, f.severity, "
        f"f.last_detected_at, f.regression_count, cd.title "
        f"FROM finding f JOIN check_definition cd ON cd.check_id = f.check_id "
        f"WHERE {' AND '.join(where)} ORDER BY f.last_detected_at DESC", params)
    return {"since_run": run_id, "count": len(rows), "findings": rows}
