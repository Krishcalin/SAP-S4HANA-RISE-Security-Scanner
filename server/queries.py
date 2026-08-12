# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

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


#: How a system is NAMED, in one place, in SQL.
#:
#: An ABAP system is "PRD/100". A SaaS tenant (decision D8) has neither a SID nor
#: a client, and every screen used to build the name by concatenating the two.
#: That fails in two different ways and the quieter one is worse:
#:
#:   * `${s.sid}/${s.client}` renders the literal text "null/null";
#:   * `{finding.sid && <>…</>}` renders NOTHING — the system identity silently
#:     disappears from the page, and the reader has no way to know a system was
#:     ever involved.
#:
#: A tenant is named by its platform and its own external key —
#: "successfactors:acme-sf-prod". Computed here rather than in TypeScript because
#: six screens need the same answer, one of them is the text a user pastes into an
#: SAP service request, and a non-browser API consumer needs it too.
#:
#: The `s.id IS NULL` arm matters: scan_run LEFT JOINs sap_system, so an upload
#: filed against no system at all reaches this expression with every column NULL.
#: That is a real state — see the resolution guard in server/ingest.py — and it
#: must read as "no system", not as "null:?".
SYSTEM_LABEL_SQL = (
    "CASE WHEN s.id IS NULL          THEN NULL "
    "     WHEN s.sid IS NOT NULL     THEN s.sid || '/' || s.client "
    "     ELSE s.platform || ':' || coalesce(s.external_key, '?') END")


# --------------------------------------------------------------------------- #
#  Reference data                                                             #
# --------------------------------------------------------------------------- #

def list_landscapes() -> List[Dict[str, Any]]:
    return db.query("SELECT * FROM landscape ORDER BY name")


def create_system(*, landscape_id: int, platform: str,
                  sid: Optional[str], client: Optional[str],
                  external_key: Optional[str], tier: str, criticality: str,
                  exposure_zone: str, owner: Optional[str],
                  actor: str) -> Dict[str, Any]:
    """Register an ABAP system or a SaaS tenant, idempotently. Decision D8.

    TWO ON CONFLICT ARBITERS, BECAUSE THERE ARE TWO IDENTITIES. An ABAP system is
    unique on (landscape, sid, client) — a table constraint. A tenant is unique on
    (landscape, platform, external_key) — a PARTIAL index, and PostgreSQL will not
    infer a partial index as an arbiter unless the statement repeats its predicate.
    Omitting that `WHERE` is SQLSTATE 42P10 at runtime, which is why it is written
    out here rather than shared with the ABAP branch.

    Re-registering is an UPDATE of the declared attributes rather than an error:
    tier, criticality and exposure are the customer's own declarations about a
    system and they change. Identity does not.
    """
    tenant = platform != "abap"
    with db.connection() as conn:
        if tenant:
            row = conn.execute(
                """
                INSERT INTO sap_system (landscape_id, platform, external_key, tier,
                                        criticality, exposure_zone, owner)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (landscape_id, platform, external_key)
                    WHERE platform <> 'abap'
                DO UPDATE SET tier = EXCLUDED.tier,
                              criticality = EXCLUDED.criticality,
                              exposure_zone = EXCLUDED.exposure_zone,
                              owner = EXCLUDED.owner
                RETURNING *
                """,
                (landscape_id, platform, external_key, tier, criticality,
                 exposure_zone, owner)).fetchone()
        else:
            row = conn.execute(
                """
                INSERT INTO sap_system (landscape_id, platform, sid, client, tier,
                                        criticality, exposure_zone, owner)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (landscape_id, sid, client)
                DO UPDATE SET tier = EXCLUDED.tier,
                              criticality = EXCLUDED.criticality,
                              exposure_zone = EXCLUDED.exposure_zone,
                              owner = EXCLUDED.owner
                RETURNING *
                """,
                (landscape_id, platform, sid, client, tier, criticality,
                 exposure_zone, owner)).fetchone()
        label = (f"{row['sid']}/{row['client']}" if row["sid"]
                 else f"{row['platform']}:{row['external_key']}")
        db.audit(conn, actor, "system.create", "sap_system", str(row["id"]),
                 {"platform": platform, "label": label,
                  "landscape_id": landscape_id})
        conn.commit()
    return dict(row, label=label)


def list_systems(scope: Optional[Sequence[int]]) -> List[Dict[str, Any]]:
    where, params = [], []
    _scoped(where, params, scope, "s.id")
    return db.query(
        f"SELECT s.*, l.name AS landscape_name, l.deployment_mode, "
        f"{SYSTEM_LABEL_SQL} AS label "
        f"FROM sap_system s JOIN landscape l ON l.id = s.landscape_id "
        f"WHERE {' AND '.join(where)} ORDER BY {SYSTEM_LABEL_SQL}", params)


# --------------------------------------------------------------------------- #
#  Dashboard                                                                  #
# --------------------------------------------------------------------------- #

def findings_for_compliance(scope: Optional[Sequence[int]]) -> List[Dict[str, Any]]:
    """Every OPEN finding as {category, severity} — the whole corpus, unpaginated.

    Two columns because that is genuinely all ComplianceMapper reads, and a
    control-framework roll-up that silently ran on page 1 of the findings would
    understate every control in the report. `category` lives on check_definition,
    not on finding, so the join is not optional: without it every row arrives
    with no category, maps to no theme, and the whole framework reports zero
    while looking perfectly healthy.
    """
    where, params = ["f.state NOT IN ('resolved','false_positive')"], []
    _scoped(where, params, scope)
    return db.query(
        "SELECT cd.category, f.severity FROM finding f "
        "JOIN check_definition cd ON cd.check_id = f.check_id "
        f"WHERE {' AND '.join(where)}", params)


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
        f"SELECT r.*, s.sid, s.client, s.platform, s.external_key, "
        f"{SYSTEM_LABEL_SQL} AS system_label FROM scan_run r "
        f"LEFT JOIN sap_system s ON s.id = r.system_id "
        f"WHERE {' AND '.join(where)} ORDER BY r.started_at DESC LIMIT %s", params)


# --------------------------------------------------------------------------- #
#  Findings                                                                   #
# --------------------------------------------------------------------------- #

def list_findings(scope: Optional[Sequence[int]], system_id: Optional[int] = None,
                  state: Optional[str] = None, severity: Optional[str] = None,
                  team: Optional[str] = None, remediation_owner: Optional[str] = None,
                  tier: Optional[str] = None, category: Optional[str] = None,
                  assignee: Optional[str] = None, overdue: bool = False,
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
    if tier:
        where.append("f.priority_tier = %s"); params.append(tier)
    if category:
        where.append("cd.category = %s"); params.append(category)
    if assignee:
        where.append("f.assignee = %s"); params.append(assignee)
    if overdue:
        where.append("f.due_date IS NOT NULL AND f.due_date < CURRENT_DATE")

    w = " AND ".join(where)
    total = db.one(
        f"SELECT count(*) AS n FROM finding f "
        f"JOIN check_definition cd ON cd.check_id = f.check_id WHERE {w}", params)["n"]

    page = max(1, page)
    rows = db.query(
        f"""
        SELECT f.*, cd.title, cd.category, cd.owning_team AS default_team,
               cd.baseline_req_id, s.sid, s.client AS system_client,
               s.platform, s.external_key,
               {SYSTEM_LABEL_SQL} AS system_label,
               s.tier AS system_tier,
               (f.state = 'accepted' AND f.acceptance_due IS NOT NULL
                AND f.acceptance_due < CURRENT_DATE) AS expired_acceptance,
               (f.due_date IS NOT NULL AND f.due_date < CURRENT_DATE
                AND f.state IN ('open','submitted_to_provider')) AS is_overdue,
               GREATEST(0, EXTRACT(DAY FROM (COALESCE(f.resolved_at, now())
                                             - f.first_seen_at))::int) AS days_open
        FROM finding f
        JOIN check_definition cd ON cd.check_id = f.check_id
        LEFT JOIN sap_system s ON s.id = f.system_id
        WHERE {w}
        -- Priority tier first, severity second. The tier already folds in
        -- exploitability, exposure and privilege; sorting by raw severity would
        -- put an unreachable CRITICAL above an actively-exploited HIGH.
        ORDER BY CASE f.priority_tier WHEN 'P1' THEN 0 WHEN 'P2' THEN 1
                                      WHEN 'P3' THEN 2 WHEN 'P4' THEN 3 ELSE 4 END,
                 CASE f.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
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
        # expired_acceptance and is_overdue are computed HERE, in SQL, with the same
        # expressions list_findings uses — deliberately not re-derived in Python by
        # the caller. Two definitions of "this acceptance has expired" can disagree
        # about the SAME finding: the queue would show the banner and the detail page
        # would not, or worse the other way round, and whichever the reviewer saw
        # last is the one they would act on. One rule, one place, both readings.
        f"SELECT f.*, cd.title, cd.category, cd.remediation, cd.risk_narrative, "
        f"(f.state = 'accepted' AND f.acceptance_due IS NOT NULL "
        f" AND f.acceptance_due < CURRENT_DATE) AS expired_acceptance, "
        f"(f.due_date IS NOT NULL AND f.due_date < CURRENT_DATE "
        f" AND f.state IN ('open','submitted_to_provider')) AS is_overdue, "
        f"cd.references_json, cd.baseline_req_id, cd.responsibility, cd.cwe, "
        f"s.sid, s.client AS system_client, s.platform, s.external_key, "
        f"{SYSTEM_LABEL_SQL} AS system_label, s.tier, l.deployment_mode, "
        # The snippet and the source->sink trace describe what the code looked like
        # in a PARTICULAR run, so they come from the newest observation rather than
        # from `finding`. Read here so the detail page stays one round trip.
        f"(SELECT o.details FROM finding_observation o "
        f"  WHERE o.finding_id = f.id ORDER BY o.scan_run_id DESC LIMIT 1) "
        f"  AS latest_details "
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
        f"SELECT r.*, s.sid, s.client, s.platform, s.external_key, "
        f"{SYSTEM_LABEL_SQL} AS system_label, "
        f"l.name AS landscape_name, l.deployment_mode "
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


# --------------------------------------------------------------------------- #
#  Assignment and bulk actions                                                #
# --------------------------------------------------------------------------- #

def assign_finding(finding_id: int, actor: str, assignee: Optional[str] = None,
                   team: Optional[str] = None, due_date: Optional[str] = None,
                   scope: Optional[Sequence[int]] = None) -> Dict[str, Any]:
    """Set assignee / team / due date without changing state.

    Kept out of `transition_finding` because assigning work is not a lifecycle
    event: a finding can change hands three times while staying open, and folding
    that into the state machine would fill the transition history with entries
    that say nothing about the defect.
    """
    if get_finding(finding_id, scope) is None:
        raise TransitionError("finding not found or not visible")

    sets: List[str] = []
    params: List[Any] = []
    if assignee is not None:
        sets.append("assignee = %s"); params.append(assignee or None)
    if team is not None:
        sets.append("owning_team = %s"); params.append(team or None)
    if due_date is not None:
        sets.append("due_date = %s"); params.append(due_date or None)
    if not sets:
        return {"finding_id": finding_id, "changed": False}

    params.append(finding_id)
    with db.connection() as conn:
        conn.execute(f"UPDATE finding SET {', '.join(sets)} WHERE id = %s", params)
        db.audit(conn, actor, "finding.assign", "finding", str(finding_id),
                 {"assignee": assignee, "team": team, "due_date": due_date})
        conn.commit()
    return {"finding_id": finding_id, "changed": True}


def bulk_transition(finding_ids: Sequence[int], to_state: str, actor: str,
                    reason: str = "", ticket: str = "",
                    scope: Optional[Sequence[int]] = None) -> Dict[str, Any]:
    """Move several findings at once, reporting per-finding outcomes.

    Deliberately NOT all-or-nothing. Over 40 findings where 3 are in a state that
    cannot make the move, apply the 37 and say which 3 were skipped and why:
    failing the whole batch makes the feature unusable, and skipping silently
    misreports what happened.
    """
    applied: List[int] = []
    skipped: List[Dict[str, Any]] = []
    for fid in finding_ids:
        try:
            transition_finding(fid, to_state, actor, reason, ticket, scope)
            applied.append(fid)
        except TransitionError as exc:
            skipped.append({"finding_id": fid, "reason": str(exc)})
    return {"applied": applied, "applied_count": len(applied),
            "skipped": skipped, "skipped_count": len(skipped)}


# --------------------------------------------------------------------------- #
#  Saved views                                                                #
# --------------------------------------------------------------------------- #

#: Only these keys may be stored in a view. An allowlist rather than a passthrough:
#: stored filters are replayed into the query layer, so accepting arbitrary keys
#: would let a saved view smuggle in a parameter nothing validated.
VIEW_FILTER_KEYS = frozenset({
    "system_id", "state", "severity", "team", "owner", "tier", "category",
    "assignee", "overdue", "days",
})


def list_views(username: str, kind: Optional[str] = None) -> List[Dict[str, Any]]:
    where = ["(is_shared OR created_by = %s)"]
    params: List[Any] = [username]
    if kind:
        where.append("kind = %s"); params.append(kind)
    return db.query(
        f"SELECT * FROM saved_view WHERE {' AND '.join(where)} ORDER BY name", params)


def get_view(slug: str, username: str) -> Optional[Dict[str, Any]]:
    return db.one(
        "SELECT * FROM saved_view WHERE slug = %s AND (is_shared OR created_by = %s)",
        (slug, username))


def save_view(slug: str, name: str, kind: str, filters: Dict[str, Any], actor: str,
              description: str = "", is_shared: bool = True) -> Dict[str, Any]:
    """Store a view's FILTERS — never its rows.

    That is what makes a shared link safe: opening it re-runs the query under the
    caller's own row scope, so two people following the same URL each see only the
    systems they are entitled to. **A saved view can never widen access.**
    """
    from psycopg.types.json import Jsonb

    clean = {k: v for k, v in (filters or {}).items()
             if k in VIEW_FILTER_KEYS and v not in (None, "")}
    slug = "".join(c for c in (slug or "").lower().replace(" ", "-")
                   if c.isalnum() or c in "-_")[:64]
    if not slug:
        raise ValueError("a view needs a URL-safe slug")

    with db.connection() as conn:
        row = conn.execute(
            """
            INSERT INTO saved_view (slug, name, description, kind, filters,
                                    created_by, is_shared)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (slug) DO UPDATE SET
                name = EXCLUDED.name, description = EXCLUDED.description,
                kind = EXCLUDED.kind, filters = EXCLUDED.filters,
                is_shared = EXCLUDED.is_shared, updated_at = now()
            RETURNING *
            """,
            (slug, name, description, kind, Jsonb(clean), actor, is_shared)).fetchone()
        db.audit(conn, actor, "view.save", "saved_view", slug, {"kind": kind})
        conn.commit()
    return row


def delete_view(slug: str, actor: str) -> None:
    with db.connection() as conn:
        conn.execute("DELETE FROM saved_view WHERE slug = %s", (slug,))
        db.audit(conn, actor, "view.delete", "saved_view", slug)
        conn.commit()


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
