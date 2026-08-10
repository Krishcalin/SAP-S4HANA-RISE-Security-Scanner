# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
The mitigation journey: aging, MTTR, burndown, backlog trajectory, scorecards.

WHAT THIS HAS TO ANSWER
-----------------------
    "What changed since last month, who owns it, and is it getting better?"

...without exporting anything. The incumbent's own documented method for tracking
remediation over time is to export a PDF periodically and watch the numbers move,
so a working version of this screen is table stakes rather than a differentiator —
but it has to be *right*, and there are two ways to get it wrong that look fine on
a chart.

TWO TRAPS, BOTH AVOIDED HERE
----------------------------
1. **Averaging severity instead of counting occurrences.** Watching a mean CVSS or
   a mean severity fall toward zero says nothing about whether anything was fixed:
   discovering a batch of LOW findings moves the average down while the estate got
   worse. Everything below counts *resolved occurrences*, never an average severity.

2. **Measuring the customer against the provider's clock.** A finding a RISE
   customer cannot fix — a profile parameter SAP operates — sits open until SAP
   acts. Rolling it into the same MTTR as the customer's own work measures the
   wrong organisation, so `ticket_to_sap` findings are reported as a separate
   series everywhere they appear.

All series are computed from stored columns rather than recomputed from
observations, so these numbers can never disagree with the finding rows the team
is triaging on the next screen over.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from server import db

#: Every scorecard axis. Kept as data so the console and the API iterate the same
#: list and a new team cannot appear in one and not the other.
TEAMS = ("basis", "authorizations", "development", "integration",
         "data_protection", "identity", "unassigned")

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
TIERS = ("P1", "P2", "P3", "P4")


def _scope(scope: Optional[Sequence[int]], column: str = "f.system_id"):
    return db.scope_clause(scope, column)


def _open_where(scope: Optional[Sequence[int]], extra: Optional[List[str]] = None):
    clause, params = _scope(scope)
    where = ["f.state NOT IN ('resolved','false_positive')", clause]
    if extra:
        where.extend(extra)
    return " AND ".join(where), list(params)


# --------------------------------------------------------------------------- #
#  SLA and aging                                                              #
# --------------------------------------------------------------------------- #

def sla_status(scope: Optional[Sequence[int]]) -> Dict[str, Any]:
    """Overdue / due-soon / on-time, split by who is actually on the hook.

    `due_date` is set from the P-tier when the tier is assigned and only moves when
    the tier moves — so "overdue" means the window we told them about has passed,
    not that the finding is merely old.
    """
    where, params = _open_where(scope, ["f.due_date IS NOT NULL"])
    rows = db.query(
        f"""
        SELECT f.remediation_owner,
               count(*) FILTER (WHERE f.due_date < CURRENT_DATE)                AS overdue,
               count(*) FILTER (WHERE f.due_date BETWEEN CURRENT_DATE
                                     AND CURRENT_DATE + 7)                       AS due_soon,
               count(*) FILTER (WHERE f.due_date > CURRENT_DATE + 7)             AS on_time,
               count(*)                                                          AS total
        FROM finding f WHERE {where} GROUP BY f.remediation_owner
        """, params)

    by_owner = {r["remediation_owner"]: dict(r) for r in rows}
    # The headline number is CUSTOMER-fixable overdue work only. Including
    # provider-bound findings would report SAP's queue as the customer's breach.
    cust = by_owner.get("customer_fixable", {})
    return {
        "by_owner": by_owner,
        "overdue_customer": cust.get("overdue", 0),
        "due_soon_customer": cust.get("due_soon", 0),
        "overdue_provider": by_owner.get("ticket_to_sap", {}).get("overdue", 0),
        "total_tracked": sum(r["total"] for r in rows),
    }


def aging_buckets(scope: Optional[Sequence[int]]) -> List[Dict[str, Any]]:
    """How long open findings have been open, by severity."""
    where, params = _open_where(scope)
    return db.query(
        f"""
        SELECT f.severity,
               count(*) FILTER (WHERE now() - f.first_seen_at <  interval '7 days')  AS d0_7,
               count(*) FILTER (WHERE now() - f.first_seen_at >= interval '7 days'
                                  AND now() - f.first_seen_at <  interval '30 days') AS d7_30,
               count(*) FILTER (WHERE now() - f.first_seen_at >= interval '30 days'
                                  AND now() - f.first_seen_at <  interval '90 days') AS d30_90,
               count(*) FILTER (WHERE now() - f.first_seen_at >= interval '90 days') AS d90_plus,
               count(*) AS total,
               round(avg(EXTRACT(EPOCH FROM (now() - f.first_seen_at)) / 86400)::numeric, 1)
                                                                                   AS avg_days
        FROM finding f WHERE {where} GROUP BY f.severity
        """, params)


# --------------------------------------------------------------------------- #
#  MTTR                                                                       #
# --------------------------------------------------------------------------- #

def mttr(scope: Optional[Sequence[int]], days: int = 180) -> Dict[str, Any]:
    """Mean time to remediate, over findings actually RESOLVED in the window.

    Deliberately excludes findings still open. Including them ("time so far")
    conflates two different questions and makes MTTR fall whenever a burst of new
    findings arrives, which is precisely backwards.
    """
    clause, sparams = _scope(scope)
    base = (f"f.state = 'resolved' AND f.resolved_at IS NOT NULL "
            f"AND f.resolved_at > now() - make_interval(days => %s) AND {clause}")

    by_sev = db.query(
        f"""
        SELECT f.severity,
               count(*) AS resolved,
               round(avg(EXTRACT(EPOCH FROM (f.resolved_at - f.first_seen_at))/86400)::numeric, 1)
                   AS mean_days,
               round((percentile_cont(0.5) WITHIN GROUP (
                   ORDER BY EXTRACT(EPOCH FROM (f.resolved_at - f.first_seen_at))/86400))::numeric, 1)
                   AS median_days
        FROM finding f WHERE {base} GROUP BY f.severity
        """, [days] + list(sparams))

    by_team = db.query(
        f"""
        SELECT COALESCE(f.owning_team, cd.owning_team, 'unassigned') AS team,
               count(*) AS resolved,
               round(avg(EXTRACT(EPOCH FROM (f.resolved_at - f.first_seen_at))/86400)::numeric, 1)
                   AS mean_days
        FROM finding f JOIN check_definition cd ON cd.check_id = f.check_id
        WHERE {base} GROUP BY 1 ORDER BY 2 DESC
        """, [days] + list(sparams))

    by_owner = db.query(
        f"""
        SELECT f.remediation_owner, count(*) AS resolved,
               round(avg(EXTRACT(EPOCH FROM (f.resolved_at - f.first_seen_at))/86400)::numeric, 1)
                   AS mean_days
        FROM finding f WHERE {base} GROUP BY 1
        """, [days] + list(sparams))

    overall = db.one(
        f"""
        SELECT count(*) AS resolved,
               round(avg(EXTRACT(EPOCH FROM (f.resolved_at - f.first_seen_at))/86400)::numeric, 1)
                   AS mean_days
        FROM finding f WHERE {base}
        """, [days] + list(sparams))

    return {"window_days": days, "overall": overall,
            "by_severity": by_sev, "by_team": by_team, "by_owner": by_owner}


# --------------------------------------------------------------------------- #
#  Burndown and trajectory                                                    #
# --------------------------------------------------------------------------- #

def burndown(scope: Optional[Sequence[int]], limit: int = 24) -> List[Dict[str, Any]]:
    """Open-finding count per completed run — the actual backlog trajectory.

    Per RUN rather than per calendar day, because the backlog only changes when a
    scan observes it. A daily series over weekly scans would draw six flat days and
    one cliff, implying activity on days nothing was measured.
    """
    clause, params = _scope(scope, "r.system_id")
    return db.query(
        f"""
        WITH runs AS (
            SELECT r.id, r.started_at, r.system_id
            FROM scan_run r
            WHERE r.status = 'complete' AND {clause}
            ORDER BY r.started_at DESC LIMIT %s
        )
        SELECT r.id AS run_id, r.started_at,
               count(f.id) FILTER (WHERE f.first_seen_run = r.id)          AS new,
               count(f.id) FILTER (WHERE f.last_seen_run  = r.id)          AS open_after,
               count(f.id) FILTER (WHERE f.last_seen_run = r.id
                                     AND f.severity = 'CRITICAL')          AS critical,
               count(f.id) FILTER (WHERE f.last_seen_run = r.id
                                     AND f.priority_tier = 'P1')           AS p1,
               count(f.id) FILTER (WHERE f.last_seen_run = r.id
                                     AND f.priority_tier = 'P2')           AS p2
        FROM runs r
        LEFT JOIN finding f ON f.last_seen_run = r.id OR f.first_seen_run = r.id
        GROUP BY r.id, r.started_at
        ORDER BY r.started_at
        """, list(params) + [limit])


def backlog_by_tier(scope: Optional[Sequence[int]]) -> List[Dict[str, Any]]:
    where, params = _open_where(scope)
    return db.query(
        f"""
        SELECT COALESCE(f.priority_tier, 'untiered') AS tier,
               count(*) AS open,
               count(*) FILTER (WHERE f.due_date < CURRENT_DATE)  AS overdue,
               count(*) FILTER (WHERE f.remediation_owner = 'ticket_to_sap') AS with_sap,
               round(avg(EXTRACT(EPOCH FROM (now() - f.first_seen_at))/86400)::numeric, 1)
                   AS avg_age_days
        FROM finding f WHERE {where}
        GROUP BY 1 ORDER BY 1
        """, params)


def technical_debt(scope: Optional[Sequence[int]]) -> Dict[str, Any]:
    """Findings that have been open a long time, and ones that keep coming back.

    A regression count is the more interesting of the two: a defect that has been
    fixed and returned three times is a broken process, not a backlog item, and it
    is invisible if you only ever look at current state.
    """
    where, params = _open_where(scope)
    stale = db.one(
        f"SELECT count(*) AS n FROM finding f WHERE {where} "
        f"AND now() - f.first_seen_at > interval '90 days'", params)
    recurring = db.query(
        f"""
        SELECT f.id, f.check_id, f.severity, f.regression_count, cd.title,
               s.sid, s.client
        FROM finding f JOIN check_definition cd ON cd.check_id = f.check_id
        LEFT JOIN sap_system s ON s.id = f.system_id
        WHERE {where} AND f.regression_count > 0
        ORDER BY f.regression_count DESC, f.severity LIMIT 20
        """, params)
    accepted_expired = db.query(
        f"""
        SELECT f.id, f.check_id, cd.title, f.accepted_by, f.acceptance_due
        FROM finding f JOIN check_definition cd ON cd.check_id = f.check_id
        WHERE {' AND '.join(['f.state = %s', _scope(scope)[0]])}
          AND f.acceptance_due IS NOT NULL AND f.acceptance_due < CURRENT_DATE
        ORDER BY f.acceptance_due LIMIT 20
        """, ["accepted"] + list(_scope(scope)[1]))
    return {"stale_over_90d": stale["n"] if stale else 0,
            "recurring": recurring,
            "expired_acceptances": accepted_expired}


# --------------------------------------------------------------------------- #
#  Scorecards                                                                 #
# --------------------------------------------------------------------------- #

def team_scorecard(scope: Optional[Sequence[int]]) -> List[Dict[str, Any]]:
    """Open work per owning team, so findings route to a team rather than a person.

    This is what makes a 300-finding queue consumable: nobody owns 300 findings,
    but Basis owns 40 and Authorizations owns 60.
    """
    where, params = _open_where(scope)
    return db.query(
        f"""
        SELECT COALESCE(f.owning_team, cd.owning_team, 'unassigned') AS team,
               count(*) AS open,
               count(*) FILTER (WHERE f.severity = 'CRITICAL')       AS critical,
               count(*) FILTER (WHERE f.severity = 'HIGH')           AS high,
               count(*) FILTER (WHERE f.due_date < CURRENT_DATE)     AS overdue,
               count(*) FILTER (WHERE f.remediation_owner = 'customer_fixable')
                                                                     AS actionable,
               round(avg(EXTRACT(EPOCH FROM (now() - f.first_seen_at))/86400)::numeric, 1)
                   AS avg_age_days
        FROM finding f JOIN check_definition cd ON cd.check_id = f.check_id
        WHERE {where} GROUP BY 1 ORDER BY 3 DESC, 2 DESC
        """, params)


def domain_scorecard(scope: Optional[Sequence[int]]) -> List[Dict[str, Any]]:
    """Percentage-compliant per finding category — the number an exec repeats.

    "Compliant" is measured over CHECKS THAT ACTUALLY RAN for the systems in
    scope, not over the whole catalogue. Scoring against every check ever written
    would let a customer improve their score by supplying fewer exports, which is
    the exact opposite of the incentive we want.
    """
    clause, params = _scope(scope)
    return db.query(
        f"""
        WITH ran AS (
            SELECT DISTINCT cd.category, f.check_id
            FROM finding f JOIN check_definition cd ON cd.check_id = f.check_id
            WHERE {clause}
        ),
        failing AS (
            SELECT DISTINCT cd.category, f.check_id
            FROM finding f JOIN check_definition cd ON cd.check_id = f.check_id
            WHERE f.state NOT IN ('resolved','false_positive') AND {clause}
        )
        SELECT ran.category,
               count(DISTINCT ran.check_id)                       AS checks_run,
               count(DISTINCT failing.check_id)                   AS checks_failing,
               round(100.0 * (count(DISTINCT ran.check_id) - count(DISTINCT failing.check_id))
                     / NULLIF(count(DISTINCT ran.check_id), 0), 0) AS pct_compliant
        FROM ran LEFT JOIN failing
               ON failing.category = ran.category AND failing.check_id = ran.check_id
        GROUP BY ran.category ORDER BY pct_compliant NULLS LAST
        """, list(params) + list(params))


def journey_summary(scope: Optional[Sequence[int]], days: int = 180) -> Dict[str, Any]:
    """One call for the trend screen."""
    return {
        "sla": sla_status(scope),
        "aging": aging_buckets(scope),
        "mttr": mttr(scope, days),
        "burndown": burndown(scope),
        "backlog_by_tier": backlog_by_tier(scope),
        "technical_debt": technical_debt(scope),
        "teams": team_scorecard(scope),
        "domains": domain_scorecard(scope),
    }
