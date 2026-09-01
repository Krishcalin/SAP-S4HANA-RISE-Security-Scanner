"""The worst five in each domain.

WHY THIS IS A DIFFERENT SCREEN FROM THE FINDINGS LIST, and not a filter on it.
/findings answers "what is worst in the estate", sorted once — and on a real
estate its first five rows can all sit in one domain, which tells the eleven
other owners nothing. This answers "what is worst in EACH domain", which is the
shape somebody uses to hand out work.

TWO RULES IT MUST NOT BREAK.

Ranked by TIER first and severity second, the order `list_findings` already
uses. The tier folds in exploitability, exposure and privilege, so a top five
built on raw severity would put an unreachable CRITICAL above an
actively-exploited HIGH — the wrong five, presented with more confidence than
the list it came from.

An empty card is FOUR different things and only one is good news: assessed,
clear, not_supplied, not_assessed. A page that draws the last three alike turns
an absence of evidence into a clean bill of health.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server import queries                                       # noqa: E402



def _function(source: str, name: str) -> str:
    """One function's source.

    `findings_for_domains` is the LAST definition in queries.py, so slicing to
    the next `def` has to tolerate there not being one. A helper that throws on
    the last function in a module fails for a reason having nothing to do with
    the code it is meant to be checking.
    """
    start = source.index("def %s" % name)
    rest = source[start:]
    at = rest.find("\ndef ", 10)
    return rest if at == -1 else rest[:at]

# ── the ranking, which decides which five ────────────────────────────────────

def _f(**kw):
    base = {"id": 1, "priority_tier": "P3", "severity": "MEDIUM"}
    base.update(kw)
    return base


def test_tier_beats_severity():
    """THE RULE THE WHOLE SCREEN RESTS ON. `list_findings` states the reason:
    the tier already accounts for exploitability, exposure and privilege, so an
    unreachable CRITICAL must not outrank an actively-exploited HIGH."""
    exploited_high = _f(priority_tier="P1", severity="HIGH", id=2)
    unreachable_critical = _f(priority_tier="P4", severity="CRITICAL", id=1)
    ordered = sorted([unreachable_critical, exploited_high], key=queries.rank_key)
    assert ordered[0] is exploited_high


def test_severity_breaks_a_tie_within_a_tier():
    high = _f(priority_tier="P2", severity="HIGH", id=2)
    low = _f(priority_tier="P2", severity="LOW", id=1)
    assert sorted([low, high], key=queries.rank_key)[0] is high


def test_the_older_finding_wins_a_complete_tie():
    """Same tiebreak as the findings list: the one that has been open longer."""
    older = _f(id=1)
    newer = _f(id=90)
    assert sorted([newer, older], key=queries.rank_key)[0] is older


def test_an_unranked_finding_sorts_last_not_first():
    """A finding the priority engine could not place is not evidence that it is
    urgent. Sorting unknown first would promote exactly the findings we
    understand least."""
    unranked = _f(priority_tier=None, severity="CRITICAL", id=1)
    ranked = _f(priority_tier="P4", severity="LOW", id=2)
    assert sorted([unranked, ranked], key=queries.rank_key)[0] is ranked


def test_severity_case_does_not_change_the_rank():
    assert queries.rank_key(_f(severity="critical")) == \
        queries.rank_key(_f(severity="CRITICAL"))


# ── the wiring ───────────────────────────────────────────────────────────────

def test_the_roll_up_query_carries_what_the_ranking_needs():
    """`findings_for_domains` fed the tiles and carried no tier. Ranking on rows
    fetched by a second query would let this page and the tile above it disagree
    about the same estate."""
    source = (ROOT / "server" / "queries.py").read_text(encoding="utf-8")
    block = _function(source, "findings_for_domains")
    assert "f.priority_tier" in block
    assert "f.priority_score" in block


def test_the_view_is_derived_from_the_roll_up_not_computed_beside_it():
    source = (ROOT / "server" / "queries.py").read_text(encoding="utf-8")
    block = _function(source, "top_risks_by_domain")
    assert "roll_up(" in block, \
        "the state is computed here instead of taken from the roll-up"
    assert "domain_for(" in block, \
        "findings are mapped to domains by some other rule than domains.py's"


def test_the_route_has_a_nav_entry():
    """nav.ts states the rule itself: a route with no nav entry is a route
    nobody finds."""
    nav = (ROOT / "frontend" / "src" / "lib" / "nav.ts").read_text(encoding="utf-8")
    app = (ROOT / "frontend" / "src" / "App.tsx").read_text(encoding="utf-8")
    assert "'/top-risks'" in nav and "Top5Risk" in nav
    assert 'path="/top-risks"' in app


def test_the_screen_words_each_empty_state_differently():
    """Four states, four sentences. Sharing one would turn "the export never
    arrived" into "nothing found here"."""
    page = (ROOT / "frontend" / "src" / "routes" / "TopRisks.tsx"
            ).read_text(encoding="utf-8")
    for state in ("clear", "not_supplied", "not_assessed"):
        assert "'%s'" % state in page, state
    assert "not a clean result" in page, \
        "an unsupplied export no longer says it is not a clean result"
    # And the wording for the state chip is shared with the Domains screen
    # rather than reinvented.
    assert "from './Domains'" in page


# ── against a real database ──────────────────────────────────────────────────

pg = pytest.mark.skipif(not os.getenv("DB_DSN"),
                        reason="set DB_DSN to a PostgreSQL 16 instance")


@pg
def test_every_domain_appears_even_with_nothing_in_it():
    """Twelve cards, always. Dropping the empty ones would quietly shorten the
    page to the domains that happen to have findings — and the ones that do not
    are exactly where "was this even assessed?" needs answering."""
    from server import db
    db.init_schema()
    view = queries.top_risks_by_domain(None)
    from modules.domains import DOMAINS
    assert len(view["domains"]) == len(DOMAINS)
    assert {d["id"] for d in view["domains"]} == {d["id"] for d in DOMAINS}


@pg
def test_no_domain_shows_more_than_the_limit():
    from server import db
    db.init_schema()
    view = queries.top_risks_by_domain(None)
    for entry in view["domains"]:
        assert len(entry["shown"]) <= view["per_domain"], entry["id"]
        # And says how many it left out, so "5" is never mistaken for "all".
        assert entry["not_shown"] >= 0


@pg
def test_the_limit_is_honoured_when_asked_for_a_different_one():
    from server import db
    db.init_schema()
    view = queries.top_risks_by_domain(None, per_domain=2)
    assert view["per_domain"] == 2
    for entry in view["domains"]:
        assert len(entry["shown"]) <= 2, entry["id"]


@pg
def test_the_endpoint_serves_it():
    from fastapi.testclient import TestClient
    from server import app as appmod, auth, db

    db.init_schema()
    username = "toprisk_%s" % os.urandom(4).hex()
    auth.create_user(username, "top-risk-password", "viewer")
    try:
        client = TestClient(appmod.app)
        assert client.post("/api/auth/login",
                           json={"username": username,
                                 "password": "top-risk-password"}
                           ).status_code == 200
        got = client.get("/api/top-risks")
        assert got.status_code == 200, got.text
        body = got.json()
        assert body["per_domain"] == queries.TOP_RISKS_PER_DOMAIN
        assert len(body["domains"]) == 12
        for entry in body["domains"]:
            assert entry["state"] in (
                "assessed", "clear", "not_supplied", "not_assessed")
    finally:
        db.execute("DELETE FROM app_user WHERE username = %s", (username,))


@pg
def test_a_stranger_gets_nothing():
    from fastapi.testclient import TestClient
    from server import app as appmod
    assert TestClient(appmod.app).get("/api/top-risks").status_code == 401


# ── five risks, not one risk five times ──────────────────────────────────────

def test_one_problem_on_five_systems_is_one_risk():
    """MEASURED ON THE LIVE ESTATE BEFORE THIS EXISTED: the Patch domain's top
    five was three copies of "Missing HotNews (Priority 1)" and two of "Missing
    notes for actively-exploited" — the same two problems on five systems,
    spending every slot to say two things."""
    rows = [
        _f(id=1, check_id="HOTNEWS-001", priority_tier="P1", severity="CRITICAL", sid="PRD"),
        _f(id=2, check_id="HOTNEWS-001", priority_tier="P1", severity="CRITICAL", sid="D01"),
        _f(id=3, check_id="HOTNEWS-001", priority_tier="P1", severity="CRITICAL", sid="T01"),
        _f(id=4, check_id="HOTNEWS-004", priority_tier="P1", severity="CRITICAL", sid="PRD"),
    ]
    risks = queries._distinct_risks(rows)
    assert [r["check_id"] for r in risks] == ["HOTNEWS-001", "HOTNEWS-004"]
    assert risks[0]["instances"] == 3
    assert risks[0]["systems"] == ["PRD", "D01", "T01"]
    assert risks[1]["instances"] == 1


def test_the_representative_is_the_worst_instance():
    """A check that is P1 on production and P3 on a sandbox is represented by
    production. The rows arrive sorted, so the first occurrence already is the
    worst — this pins that the order is relied upon rather than assumed."""
    rows = sorted([
        _f(id=9, check_id="PARAM-X", priority_tier="P3", severity="LOW", sid="SBX"),
        _f(id=4, check_id="PARAM-X", priority_tier="P1", severity="CRITICAL", sid="PRD"),
    ], key=queries.rank_key)
    risk = queries._distinct_risks(rows)[0]
    assert risk["sid"] == "PRD" and risk["priority_tier"] == "P1"
    assert risk["instances"] == 2


def test_a_system_is_not_listed_twice():
    rows = [_f(id=1, check_id="C", sid="PRD"), _f(id=2, check_id="C", sid="PRD")]
    assert queries._distinct_risks(rows)[0]["systems"] == ["PRD"]


def test_a_finding_with_no_system_does_not_invent_one():
    rows = [_f(id=1, check_id="C", sid=None)]
    assert queries._distinct_risks(rows)[0]["systems"] == []


def test_the_page_reports_distinct_and_total_separately():
    """`total` counts FINDINGS and the five are drawn from DISTINCT risks. A
    screen that showed "5 of 143" while ranking 88 distinct risks would be
    quoting the wrong denominator."""
    page = (ROOT / "frontend" / "src" / "routes" / "TopRisks.tsx"
            ).read_text(encoding="utf-8")
    assert "distinct risk" in page
    assert "across {domain.total} findings" in page
