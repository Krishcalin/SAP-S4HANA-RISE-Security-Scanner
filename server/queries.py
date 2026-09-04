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

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from modules import coverage as _coverage_module
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


#: Every value `finding.state` may hold, from schema.sql's own CHECK constraint.
#:
#: WHY THIS IS NOT JUST TIDINESS. `list_findings` drops its default
#: "NOT IN ('resolved','false_positive')" guard the moment a `state` is supplied,
#: and the value went to an equality predicate unvalidated. So `?state=OPEN` —
#: the obvious guess, and what a shell script produces from an uppercase
#: constant — returned HTTP 200 with the ENTIRE corpus hidden: a queue that reads
#: as "nothing to do here" because a filter matched nothing.
FINDING_STATES = frozenset({
    "open", "submitted_to_provider", "mitigated", "accepted", "false_positive",
    "resolved",
})


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


#: A scan is only an assessment of the estate if it FINISHED. `status` also
#: holds queued, running and failed runs, and a failed run tells you nothing
#: about the system except that the scanner stopped. Every freshness figure in
#: this file filters on this for that reason, and `coverage_for_scope` below
#: already did.
ASSESSED_RUN = "r.status = 'complete'"

#: How old an export may be before its answers are called stale.
#:
#: NOT AN INVENTED NUMBER. SAP publishes Security Notes on Security Patch Day,
#: the second Tuesday of each month. An export older than one full cycle cannot
#: account for a patch day that has since passed, so the verdicts drawn from it
#: are answers about a system that no longer exists in that form. 35 days is one
#: cycle plus the slack between two second-Tuesdays (28-35 days apart).
#:
#: It governs EMPHASIS ONLY. The measured date is returned and displayed
#: whatever this is set to, so moving the threshold can never hide the age of an
#: answer — it can only change whether the console calls it out.
#:
#: IMPORTED, NOT REDEFINED. The offline report asks the same question of an
#: upload's file timestamps, and two copies of this number would drift the day
#: somebody tuned one of them — leaving the console and the PDF a customer
#: sends an auditor disagreeing about whether the same estate is current.
STALE_AFTER_DAYS = _coverage_module.STALE_AFTER_DAYS


def list_systems(scope: Optional[Sequence[int]]) -> List[Dict[str, Any]]:
    """The estate, each system carrying the date it was last actually assessed.

    IT USED TO CARRY NO DATE AT ALL, and the dashboard's systems table rendered
    the result as though every row were equally current. Measured on the live
    sample estate: seven systems, of which PRD had been assessed that morning,
    three twenty days earlier, and DEV and QAS had NEVER BEEN ASSESSED — no
    complete run, ever. All seven rendered identically, and the panel above them
    read "Open findings across 7 systems", which was a claim about two systems
    nothing had ever looked at.

    That is the same failure this codebase keeps finding: an absence rendering
    as a measurement. `null` here means never assessed and must be shown as
    that; it must never be allowed to read as zero days old.
    """
    where, params = [], []
    _scoped(where, params, scope, "s.id")
    return db.query(
        f"SELECT s.*, l.name AS landscape_name, l.deployment_mode, "
        f"{SYSTEM_LABEL_SQL} AS label, "
        f"a.last_assessed, a.assessed_runs, "
        # Computed in SQL, against the database's clock. A browser computing
        # this from a timestamp would answer with the reader's clock and time
        # zone, so two people looking at the same estate could disagree about
        # whether a system is stale.
        f"CASE WHEN a.last_assessed IS NULL THEN NULL "
        f"     ELSE (CURRENT_DATE - a.last_assessed::date) END AS days_since_assessed "
        f"FROM sap_system s JOIN landscape l ON l.id = s.landscape_id "
        f"LEFT JOIN LATERAL ("
        f"    SELECT max(r.started_at) AS last_assessed, count(*) AS assessed_runs "
        f"    FROM scan_run r WHERE r.system_id = s.id AND {ASSESSED_RUN}"
        f") a ON true "
        f"WHERE {' AND '.join(where)} ORDER BY {SYSTEM_LABEL_SQL}", params)


def estate_freshness(scope: Optional[Sequence[int]],
                     stale_after: int = STALE_AFTER_DAYS) -> Dict[str, Any]:
    """One sentence's worth of "how much of this answer is current".

    Built from `list_systems` rather than its own query, so the summary and the
    table under it can never disagree — a headline computed by a second query is
    a headline that drifts from the rows it summarises.
    """
    systems = list_systems(scope)
    never = [s for s in systems if s["last_assessed"] is None]
    dated = [s for s in systems if s["last_assessed"] is not None]

    # `is not None`, NEVER `or 0`. A never-assessed system has no age, and the
    # idiom that turns None into 0 would file it as the freshest thing in the
    # estate — which is the exact conflation this whole function exists to
    # prevent, reintroduced in the code that reports it. Written this way the
    # rule is stated rather than accidentally held by a falsy default.
    ages = [s["days_since_assessed"] for s in dated
            if s["days_since_assessed"] is not None]
    stale = [s for s in dated if s["days_since_assessed"] is not None
             and s["days_since_assessed"] > stale_after]
    oldest = max(ages) if ages else None
    return {
        "systems": len(systems),
        "current": len(dated) - len(stale),
        "stale": len(stale),
        "never_assessed": len(never),
        "stale_after_days": stale_after,
        # The worst case, named. A count of stale systems tells the reader that
        # something is old; this tells them how old, which is what decides
        # whether it matters.
        "oldest_days": oldest,
        "never_assessed_labels": [s["label"] for s in never],
        "stale_labels": [s["label"] for s in stale],
    }


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

    # HOW FAR THE SEGREGATION RESULT CAN BE BELIEVED, on the landing page.
    #
    # SODCOV-000's own text tells the reader to read it before the conflict
    # results. In the offline report it is rendered above them; in the console
    # it was one row in a findings list, which is the same failure that was
    # fixed there two commits ago and left standing here.
    #
    # The newest observation, because the verdict is a fact about a RUN: an
    # estate that supplies its Fiori exports next month should see the verdict
    # move without the finding being treated as new.
    trust = db.one(
        f"SELECT f.severity, o.details FROM finding f "
        f"JOIN finding_observation o ON o.finding_id = f.id "
        f"WHERE {w} AND f.check_id = 'SODCOV-000' "
        f"ORDER BY o.scan_run_id DESC LIMIT 1", params)

    return {
        "by_severity": {r["severity"] or "UNKNOWN": r["n"] for r in by_sev},
        "by_remediation_owner": {r["remediation_owner"]: r["n"] for r in by_owner},
        "by_state": {r["state"]: r["n"] for r in by_state},
        "open_total": sum(r["n"] for r in by_sev),
        "expired_acceptances": expired["n"] if expired else 0,
        "weak_identity": weak["n"] if weak else 0,
        "regressed": regressed["n"] if regressed else 0,
        # None when the ruleset-coverage module did not run or its finding is
        # closed. The page renders nothing rather than an encouraging default:
        # "no verdict" is not "usable", and inventing the reassuring reading is
        # the failure this whole family of checks reports on.
        "sod_trust": ({
            "verdict": (trust["details"] or {}).get("verdict"),
            "limits": (trust["details"] or {}).get("limits") or [],
            "severity": trust["severity"],
        } if trust and (trust["details"] or {}).get("verdict") else None),
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

def _domain_clause(where: List[str], params: List[Any], domain_id: str) -> None:
    """Filter the queue to one of the twelve security domains.

    THE RULES ARE NOT WRITTEN AGAIN HERE. modules/domains.py emits them from the
    same table `domain_for` reads, and this function only compiles them — so a
    prefix added to the taxonomy reaches the SQL without anyone remembering to
    come here. Writing the membership rules a second time in SQL is precisely how
    a filter and the tile above it start disagreeing about the same number.

    `starts_with()` rather than LIKE: a prefix is data, and LIKE would give the
    `%` and `_` in it a meaning nobody intended. The prefixes contain neither
    today, which is exactly the kind of thing that stops being true quietly.
    """
    from modules import domains

    terms = domains.match_terms(domain_id)
    if not terms:
        # A domain nothing can ever be in. The API refuses this before it gets
        # here; a direct caller gets an empty result rather than the whole queue,
        # because silently ignoring a filter shows more than was asked for.
        where.append("false")
        return
    clauses: List[str] = []
    for term in terms:
        parts = ["cd.category = %s"]
        params.append(term["category"])
        include = term.get("starts_with") or ()
        if include:
            parts.append("(" + " OR ".join(
                ["starts_with(f.check_id, %s)"] * len(include)) + ")")
            params.extend(include)
        exclude = term.get("not_starts_with") or ()
        if exclude:
            parts.append("NOT (" + " OR ".join(
                ["starts_with(f.check_id, %s)"] * len(exclude)) + ")")
            params.extend(exclude)
        clauses.append("(" + " AND ".join(parts) + ")")
    where.append("(" + " OR ".join(clauses) + ")")


def list_findings(scope: Optional[Sequence[int]], system_id: Optional[int] = None,
                  state: Optional[str] = None, severity: Optional[str] = None,
                  team: Optional[str] = None, remediation_owner: Optional[str] = None,
                  tier: Optional[str] = None, category: Optional[str] = None,
                  assignee: Optional[str] = None, overdue: bool = False,
                  domain: Optional[str] = None, check: Optional[str] = None,
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
    # One check id, exactly. This is what makes a check's own page able to answer
    # "and where does it bite in MY estate" without a second, differently-scoped
    # query living on that page -- row scoping is applied once, above, for every
    # filter including this one.
    if check:
        where.append("f.check_id = %s"); params.append(check)
    if assignee:
        where.append("f.assignee = %s"); params.append(assignee)
    if overdue:
        where.append("f.due_date IS NOT NULL AND f.due_date < CURRENT_DATE")
    if domain:
        _domain_clause(where, params, domain)

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
                                             - f.first_seen_at))::int) AS days_open,
               -- Whether the newest observation's data was complete. A
               -- correlated subquery rather than a join: `finding_observation`
               -- carries UNIQUE (finding_id, scan_run_id), so this is an index
               -- lookup per row, and a join would need a window function to
               -- pick the newest and would change the row count if it went
               -- wrong.
               --
               -- On the LIST as well as the detail because a reader scanning
               -- fifty rows should not have to open each one to learn which
               -- rest on partial data. That is the same "reachable in
               -- principle" that left the trust statement at card 151.
               (SELECT o.evidence FROM finding_observation o
                 WHERE o.finding_id = f.id
                 ORDER BY o.scan_run_id DESC LIMIT 1) AS latest_evidence
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
                 f.first_seen_at,
                 -- THE UNIQUE TIEBREAK, WITHOUT WHICH PAGING SILENTLY LOSES ROWS.
                 -- Every finding an ingest creates gets the same `first_seen_at`,
                 -- so the three keys above tie across most of the estate. A tied
                 -- ORDER BY leaves the row order unspecified, and Postgres is
                 -- free to answer page 2 in a different order than it answered
                 -- page 1 -- so a row served on page 1 comes back again on page
                 -- 2 and some other row is served on neither.
                 --
                 -- Measured on a 397-finding estate before this line existed:
                 -- eight pages returned 397 rows of which 27 were duplicates,
                 -- and 27 findings -- including a HIGH -- appeared on no page at
                 -- all. The total said 397 and the reader could reach 370. This
                 -- is why `total` cannot be trusted as evidence that paging
                 -- works: both numbers were right and the list was still wrong.
                 --
                 -- `rank_key` already tiebreaks on id and its comment says that
                 -- is "the same tiebreak list_findings uses". It now is.
                 f.id
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
        f"  AS latest_details, "
        # Whether the data behind the NEWEST observation was complete. From the
        # same run as the snippet above, and for the same reason: a finding
        # drawn from a partial export last month may be fully evidenced today,
        # and the page should say which run it is describing.
        f"(SELECT o.evidence FROM finding_observation o "
        f"  WHERE o.finding_id = f.id ORDER BY o.scan_run_id DESC LIMIT 1) "
        f"  AS latest_evidence "
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

    # COUNTED FROM THE TRANSITIONS, NOT INFERRED FROM THE ROW.
    #
    # This asked for `state = 'resolved' AND last_seen_run < run_id`, and the
    # resolution UPDATE never touches `last_seen_run` — so EVERY past resolution
    # satisfied it for EVERY later run. The "Resolved" tile on a run page grew
    # monotonically for the life of the landscape and had nothing to do with the
    # run being looked at: a scan that resolved nothing still reported the sum of
    # everything ever resolved before it.
    #
    # `finding_transition` records `scan_run_id` on the row it writes, so the
    # exact answer was already stored. Same root cause as the burndown fixed in
    # dc6f74b: `last_seen_run` means "last observed", it stopped implying "still
    # open" when resolution became conditional, and the queries that read it as a
    # date never noticed.
    where, params = ["ft.scan_run_id = %s", "ft.to_state = 'resolved'"], [run_id]
    _scoped(where, params, scope)
    resolved = db.one(
        f"SELECT count(DISTINCT ft.finding_id) AS n FROM finding_transition ft "
        f"JOIN finding f ON f.id = ft.finding_id "
        f"WHERE {' AND '.join(where)}", params)["n"]

    # The same correction, for the same reason: `regression_count > 0` is a
    # lifetime total, so a finding that regressed once was reported as regressing
    # in every run that observed it afterwards.
    where, params = ["ft.scan_run_id = %s", "ft.from_state = 'resolved'",
                     "ft.to_state = 'open'"], [run_id]
    _scoped(where, params, scope)
    regressed = db.query(
        f"SELECT DISTINCT f.id, f.check_id, f.severity, f.regression_count, cd.title "
        f"FROM finding_transition ft "
        f"JOIN finding f ON f.id = ft.finding_id "
        f"JOIN check_definition cd ON cd.check_id = f.check_id "
        f"WHERE {' AND '.join(where)}", params)

    # WHAT THE RUN CONCLUDED, which the finding rows cannot say.
    #
    # A finding left open because no module could observe it looks, row by row,
    # exactly like one that persisted. The difference is a property of the RUN,
    # so it is read from what the run recorded rather than re-derived.
    #
    # None, never 0, when the run recorded nothing: a scan stored before
    # scan_run.diff existed did not withhold nothing, it did not measure. The
    # console draws no tile for None rather than a reassuring zero.
    stored = db.one("SELECT diff FROM scan_run WHERE id = %s", [run_id]) or {}
    recorded = stored.get("diff") if isinstance(stored.get("diff"), dict) else {}
    return {"new": new, "new_count": len(new), "persisting": persisting,
            "resolved": resolved, "regressed": regressed,
            "regressed_count": len(regressed),
            "unexamined": recorded.get("unexamined"),
            "resolution_skipped": recorded.get("resolution_skipped")}


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
#: `domain` is here for the allowlist's OWN stated reason, not despite it. The
#: rule is that a stored filter must be one something validates, and this is the
#: most validated of the lot — server/app.py refuses an unknown domain and
#: refuses the one we do not assess, before the query layer sees it. Omitted, a
#: saved link to one domain silently replayed as the whole ~600-finding queue,
#: which is the failure the allowlist exists to prevent, arriving by the other door.
VIEW_FILTER_KEYS = frozenset({
    "system_id", "state", "severity", "team", "owner", "tier", "category",
    "assignee", "overdue", "days", "domain",
    # `check` qualifies on the allowlist's own terms: it is validated before the
    # query layer sees it -- server/app.py refuses an id the catalogue does not
    # publish -- and "every open instance of LOG-AUD-001" is exactly the kind of
    # view worth saving a link to.
    "check",
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


def findings_for_crq(scope: Optional[Sequence[int]],
                     landscape_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """Every OPEN finding in a landscape, shaped for the FAIR prioritiser.

    UNPAGINATED, DELIBERATELY. compute_and_store's docstring says the complete
    unfiltered set is the one thing that makes this number honest; quantifying a
    page of findings would understate every scenario while looking identical.
    """
    where = ["f.state NOT IN ('resolved','false_positive')"]
    params: List[Any] = []
    _scoped(where, params, scope)
    if landscape_id is not None:
        where.append("s.landscape_id = %s")
        params.append(landscape_id)
    return db.query(
        "SELECT f.id, f.check_id, f.severity, f.state, f.remediation_owner, "
        "       f.priority_score, cd.category, cd.title, s.sid, s.tier "
        "FROM finding f "
        "JOIN check_definition cd ON cd.check_id = f.check_id "
        "LEFT JOIN sap_system s ON s.id = f.system_id "
        f"WHERE {' AND '.join(where)}", params)


#: How many findings the top-risk view shows per domain.
TOP_RISKS_PER_DOMAIN = 5

#: The order the console ranks findings in, as data rather than as SQL, so the
#: top-risk view sorts identically to the findings list.
#:
#: TIER FIRST, SEVERITY SECOND, and the reason is in `list_findings`: the tier
#: already folds in exploitability, exposure and privilege, so sorting on raw
#: severity would put an unreachable CRITICAL above an actively-exploited HIGH.
#: A "top five" built on severity alone would be the wrong five.
_TIER_ORDER = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def rank_key(finding: Dict[str, Any]):
    """Sort key for "worst first". Unknown tier and severity sort last, not
    first: a finding the priority engine could not place is not evidence that
    it is urgent."""
    return (
        _TIER_ORDER.get(finding.get("priority_tier"), 4),
        _SEVERITY_ORDER.get(str(finding.get("severity", "")).upper(), 4),
        # A tie between two findings of the same tier and severity goes to the
        # one that has been open longer, which is the same tiebreak
        # `list_findings` uses. `id` stands in for age here: the rows come from
        # `findings_for_domains`, which does not carry `first_seen_at`, and
        # ids are assigned in insertion order.
        finding.get("id") or 0,
    )


def top_risks_by_domain(scope: Optional[Sequence[int]],
                        per_domain: int = TOP_RISKS_PER_DOMAIN
                        ) -> Dict[str, Any]:
    """The worst `per_domain` open findings in each of the twelve domains.

    DERIVED FROM THE ROLL-UP, NOT COMPUTED BESIDE IT. The domain tiles and this
    page must never disagree about whether a domain was assessed, so the state
    on each entry is `domains.roll_up`'s own — including the distinction that
    matters most here.

    AN EMPTY LIST IS FOUR DIFFERENT THINGS, and a page that draws them the same
    way is the failure this product exists to prevent:

      * `assessed` with rows      — we looked, and here are the worst of them
      * `clear`                   — we looked and found nothing
      * `not_supplied`            — we would have looked; the export never came
      * `not_assessed`            — this product does not cover it, in any run

    Only the second is good news. The caller gets the state so the screen can
    say which one it is looking at.
    """
    from modules import domains as domains_module

    findings = findings_for_domains(scope)
    rolled = domains_module.roll_up(findings, coverage=latest_coverage(scope))

    buckets: Dict[str, List[Dict[str, Any]]] = {}
    for finding in findings:
        domain = domains_module.domain_for(finding.get("check_id"),
                                           finding.get("category"))
        if domain:
            buckets.setdefault(domain, []).append(finding)

    out = []
    for entry in rolled["domains"]:
        rows = sorted(buckets.get(entry["id"], []), key=rank_key)
        risks = _distinct_risks(rows)
        out.append({
            "id": entry["id"],
            "label": entry["label"],
            "state": entry["state"],
            "counts": entry["counts"],
            "total": entry["total"],
            # The five shown, and how many were not. "5 of 138" is a different
            # sentence from "5", and the second one invites a reader to think
            # they have seen the domain.
            "shown": risks[:per_domain],
            "not_shown": max(0, len(risks) - per_domain),
            # Distinct risks, which is what the five are drawn from. The domain
            # total above counts FINDINGS, and the two differ whenever one
            # problem lands on several systems — so both are given rather than
            # one being quietly used as the other.
            "distinct": len(risks),
        })
    return {"domains": out, "per_domain": per_domain,
            "measured": (latest_coverage(scope) or {}).get("measured")}


def _distinct_risks(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One entry per check, worst instance first, carrying the systems it hits.

    FIVE ROWS OF THE SAME RISK ARE NOT FIVE RISKS. Measured on the live sample
    estate before this existed: the Patch domain's "top five" was three copies
    of "Missing HotNews (Priority 1) SAP Security Notes" and two of "Missing
    notes for actively-exploited SAP vulnerabilities" — the same two problems on
    five different systems, spending all five slots to say two things.

    A finding here is per-system by design, and that is right for the findings
    list, where somebody works one system at a time. It is wrong for a
    "top five", which is read as five different things to go and fix.

    The representative is the WORST-ranked instance, because the rows arrive
    sorted: the first occurrence of a check is already its highest-priority
    instance, so a domain whose check is P1 on production and P3 on a sandbox
    is represented by production.
    """
    out: List[Dict[str, Any]] = []
    seen: Dict[str, Dict[str, Any]] = {}
    ids: Dict[str, set] = {}
    for row in rows:
        check = str(row.get("check_id") or "")
        system = row.get("sid")
        # HOW MANY SYSTEMS, COUNTED ON THE SYSTEM AND NOT ON ITS NAME.
        #
        # `systems` is the DISPLAY list and is keyed by SID, which is what a
        # reader recognises. It is not a count: two systems can share a SID —
        # the same SID recorded in two landscapes — and one system carries
        # several clients, so a check firing in client 100 and 200 is two
        # findings on one SID. Counting the display list therefore understates,
        # and counting `instances` (which counts FINDINGS) overstates.
        #
        # Found on an eight-system estate, where AUTH-001 read "9 instances
        # across 8 systems" and the screen rendered "9 systems" while naming
        # eight. Both numbers were right about something and neither was right
        # about systems.
        holder = ids.setdefault(check, set())
        if row.get("system_id") is not None:
            holder.add(row["system_id"])
        if check in seen:
            entry = seen[check]
            entry["instances"] += 1
            if system and system not in entry["systems"]:
                entry["systems"].append(system)
            continue
        entry = dict(row)
        entry["instances"] = 1
        entry["systems"] = [system] if system else []
        seen[check] = entry
        out.append(entry)
    for entry in out:
        # Falls back to the display list where the rows carry no system id, so
        # a caller that does not select it is no worse off than before.
        entry["system_count"] = (len(ids.get(entry["check_id"]) or ())
                                 or len(entry["systems"]))
    return out


def latest_coverage(scope: Optional[Sequence[int]],
                    landscape_id: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """The coverage manifests behind the findings a reader can currently see.

    WHY THIS EXISTS. `findings_for_domains` answers "what is open"; a roll-up over
    it also has to answer "what did we fail to look at", and without this the
    answer defaulted to "nothing" — every unsupplied domain rendered as *assessed,
    and nothing found*, which is the one sentence modules/domains.py exists to
    stop the product saying. The manifest was being written on every upload
    (server/ingest.py) and read by nothing.

    ONE RUN PER SYSTEM — THE LATEST COMPLETE ONE — BECAUSE THAT IS WHAT THE OPEN
    FINDINGS REFLECT. A finding is resolved by the SCANNER not observing it again,
    so the open set is a statement about each system's most recent complete run;
    pairing it with an older run's coverage would describe a different scan than
    the one the numbers came from. An in-flight or failed run is excluded for the
    same reason: it has no manifest worth trusting.

    The merge across systems is a UNION, and modules/coverage.merge_manifests
    argues that choice at length. Returns None when the caller's scope contains no
    complete run at all, and `roll_up` then declines to claim anything was
    missing — an unchecked claim of absence is as false as an unchecked claim of
    cleanliness.

    `landscape_id` NARROWS THE UNION TO MATCH ITS FINDINGS, and a caller that
    narrows one side must narrow both. /api/crq/fair-cam pairs
    `findings_for_crq(scope, landscape_id)` — one landscape — with this manifest,
    and without the parameter the union spanned EVERY landscape the reader can
    see. A module that ran in landscape B then counted as having looked at
    landscape A, so a control function fed only by an export A never supplied
    reported CLEAR on the strength of a scan of a different estate. Same false
    reassurance as everywhere else in this file, arriving through a join nobody
    tightened.
    """
    where = ["r.status = 'complete'"]
    params: List[Any] = []
    _scoped(where, params, scope, "r.system_id")
    if landscape_id is not None:
        where.append("r.landscape_id = %s")
        params.append(landscape_id)
    rows = db.query(
        # `started_at` COMES BACK NOW. It was selected only to order by and then
        # dropped, so a domain reported CLEAR on the strength of an export of
        # any age and the screen could not say which. Carried on the manifest
        # rather than returned separately because every caller that renders the
        # manifest is a caller that should be able to date it.
        f"SELECT DISTINCT ON (r.system_id) r.system_id, r.coverage, r.started_at "
        f"FROM scan_run r WHERE {' AND '.join(where)} "
        f"ORDER BY r.system_id, r.started_at DESC", params)
    from modules.coverage import merge_manifests
    merged = merge_manifests(row["coverage"] for row in rows)
    if merged is None:
        return None

    # ADDITIVE. `roll_up` in modules/domains.py and modules/nist_csf.py reads
    # `coverage["modules"]` and nothing else, so a caller that does not know
    # about these keys is unaffected — which is why this is a new key rather
    # than a new return shape.
    stamps = [row["started_at"] for row in rows if row["started_at"]]
    if stamps:
        oldest, newest = min(stamps), max(stamps)
        today = datetime.now(timezone.utc)
        merged["measured"] = {
            "systems": len(stamps),
            "oldest": oldest.isoformat(),
            "newest": newest.isoformat(),
            # THE OLDEST DATES THE ROLL-UP, not the newest. This manifest is a
            # UNION across systems: a module counts as having run if it ran for
            # any of them. So the weakest evidence behind a CLEAR verdict is the
            # oldest run in the union, and quoting the newest would date the
            # answer by its best input rather than its worst — the same mistake
            # `SODCOV-000` exists to stop a summary making.
            "oldest_days": max(0, (today - oldest).days),
            "newest_days": max(0, (today - newest).days),
            "stale_after_days": STALE_AFTER_DAYS,
            "stale": (today - oldest).days > STALE_AFTER_DAYS,
        }
    return merged


def findings_for_domains(scope: Optional[Sequence[int]]) -> List[Dict[str, Any]]:
    """Open findings shaped for the domain roll-up.

    Carries check_id as well as category because three categories are SPLIT
    between domains by check-id prefix — an audit-log pattern belongs to a
    different domain than an audit-log configuration check, and the category
    alone cannot tell them apart.
    """
    where = ["f.state NOT IN ('resolved','false_positive')"]
    params: List[Any] = []
    _scoped(where, params, scope)
    return db.query(
        # priority_tier and priority_score are ADDITIVE here: `roll_up`
        # counts by severity and ignores them. They are carried so that
        # `top_risks_by_domain` can rank on the same rows the roll-up counts,
        # rather than issuing a second query that could disagree with the tile
        # above it.
        "SELECT f.id, f.check_id, f.severity, f.priority_tier, "
        "       f.priority_score, f.state, cd.category, cd.title, "
        # The system ITSELF, not only the name it goes by. `_distinct_risks`
        # counts systems on this: a SID is a display label that two systems can
        # share across landscapes, and one system carries several clients.
        "       f.system_id, "
        "       s.sid, s.client AS system_client "
        "FROM finding f "
        "JOIN check_definition cd ON cd.check_id = f.check_id "
        "LEFT JOIN sap_system s ON s.id = f.system_id "
        f"WHERE {' AND '.join(where)} "
        "ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 "
        "         WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, f.check_id",
        params)
