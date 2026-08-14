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


def domain_scorecard(scope: Optional[Sequence[int]],
                     coverage: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Pass rate per finding category — the number an exec repeats.

    THE DENOMINATOR USED TO BE THE FINDINGS THEMSELVES, which made this a closure
    rate wearing a pass rate's name. Both CTEs read `finding`, so `ran` meant
    "checks that have failed at some point": a category where three of forty
    checks ever produced a finding had a denominator of three, a first-time
    customer read 0%, and a category whose export was never supplied vanished
    from the table altogether rather than appearing as unassessed.

    Now the denominator comes from the CODE — `coverage.check_catalogue()` pairs
    each literal check id with its category — narrowed to the modules that
    actually ran for the systems in scope. That keeps the incentive the old
    docstring described and could not deliver: supplying fewer exports removes
    checks from the denominator AND marks the category unassessed, so it cannot
    buy a better number.

    `pct` is None, never 0, for a category nothing assessed. Zero is a measured
    result and this is the absence of one — the distinction the whole product
    turns on.

    Checks built at runtime from rule tables are not literals and are not in the
    catalogue, so the denominator is a floor. `checks_known` is returned so a
    caller can say so rather than implying completeness.
    """
    clause, params = _scope(scope)
    failing_rows = db.query(
        f"""
        SELECT cd.category, count(DISTINCT f.check_id) AS n
        FROM finding f JOIN check_definition cd ON cd.check_id = f.check_id
        WHERE f.state NOT IN ('resolved','false_positive') AND {clause}
        GROUP BY cd.category
        """, list(params))
    failing = {r["category"]: r["n"] for r in failing_rows}

    # THE DENOMINATOR IS A UNION, and the first version of this was not.
    #
    # `check_catalogue()` reads check ids written as LITERALS. Roughly 255 more
    # are built at runtime from shipped rule tables (ABAP-*, ATC-*), so a
    # code-only denominator produced "3 checks known, 18 failing" for Code &
    # Transport Security — a floor smaller than the thing it bounds, and a pass
    # rate clamped at 0% by arithmetic rather than by evidence.
    #
    # So: every check the code declares in this category, PLUS every check this
    # tenant has actually observed in it. The first half is what fixed the
    # original defect — checks that have never failed now count — and the second
    # half keeps the number coherent for checks the catalogue cannot see.
    observed_rows = db.query(
        f"""
        SELECT cd.category, count(DISTINCT f.check_id) AS n
        FROM finding f JOIN check_definition cd ON cd.check_id = f.check_id
        WHERE {clause}
        GROUP BY cd.category
        """, list(params))
    observed = {r["category"]: r["n"] for r in observed_rows}

    return _score_rows(observed=observed, failing=failing, coverage=coverage)


def _score_rows(observed: Dict[str, int], failing: Dict[str, int],
                coverage: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The scorecard arithmetic, with no database in it.

    EXTRACTED BECAUSE THE DEFECT IT NOW GUARDS COULD NOT BE REACHED BY A TEST.
    Every path into this logic ran through a PostgreSQL query, so the 191 tests
    that skip without a DSN were the only ones that could see it — and none of
    them exercised the empty-database case, which is the one that published 28
    categories at 100%.
    """
    from modules.coverage import check_catalogue, modules_for_categories, ran_modules

    catalogue = check_catalogue()
    per_category: Dict[str, int] = {}
    for category in catalogue.values():
        per_category[category] = per_category.get(category, 0) + 1
    for category, n in observed.items():
        # A category the code declares nothing in but this tenant has seen is
        # real; a runtime-built family is exactly that case.
        per_category[category] = max(per_category.get(category, 0), n)

    ran = ran_modules(coverage)
    out: List[Dict[str, Any]] = []
    for category, known in sorted(per_category.items()):
        n_observed = observed.get(category, 0)
        if ran is None:
            # NO MANIFEST MEANS NOBODY CHECKED WHAT RAN, and the first version of
            # this defaulted that to `assessed = True`. Over an empty database the
            # code-derived denominator then divided by itself: 28 categories at
            # 100% "compliant" on a fresh install or a demo — the precise
            # inversion the rest of this product exists to prevent, arriving
            # through the door that had just been opened to prevent it.
            #
            # Without a manifest, the only categories we can prove were assessed
            # are the ones this tenant has actually observed a check in.
            assessed = n_observed > 0
        else:
            feeders = modules_for_categories([category])
            assessed = not feeders or bool(feeders & ran)
        n_failing = failing.get(category, 0)
        if not assessed:
            out.append({"category": category, "checks_known": known,
                        "checks_failing": n_failing, "pct_compliant": None,
                        "assessed": False})
            continue
        passing = max(0, known - n_failing)
        out.append({"category": category, "checks_known": known,
                    "checks_failing": n_failing,
                    "pct_compliant": round(100.0 * passing / known) if known else None,
                    "assessed": True})
    # Worst first, with the unassessed after the measured ones: a category we did
    # not look at is not the worst performer, it is not a performer at all.
    out.sort(key=lambda r: (r["pct_compliant"] is None,
                            r["pct_compliant"] if r["pct_compliant"] is not None else 0))
    return out


def journey_summary(scope: Optional[Sequence[int]], days: int = 180,
                    coverage: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """One call for the trend screen.

    `coverage` reaches `domain_scorecard`, which needs it to tell a category it
    assessed and found clean from one it never looked at.
    """
    return {
        "sla": sla_status(scope),
        "aging": aging_buckets(scope),
        "mttr": mttr(scope, days),
        "burndown": burndown(scope),
        "backlog_by_tier": backlog_by_tier(scope),
        "technical_debt": technical_debt(scope),
        "teams": team_scorecard(scope),
        "domains": domain_scorecard(scope, coverage=coverage),
    }
