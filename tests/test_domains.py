"""The twelve buyer-facing domains, and the two things that make them safe.

REACH and STATE are separate axes. Reach is what the product can ever see and is
fixed at author time; state is what a run produced. Collapsing them into one enum
loses a real cell — a configuration-only domain that came back clean — and forces
the code to pick between two true statements.

The partition is strict: every finding lands in exactly one domain or in the
explicit unplaced bucket. modules/nist_csf.py records what happens otherwise, in
its own words: "the first run of this code reported Protect: 148 for a system with
92 findings in total."
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import domains as D                                   # noqa: E402
from modules.compliance_mapping import ComplianceMapper            # noqa: E402


def _f(check_id, category, severity="HIGH"):
    return {"check_id": check_id, "category": category, "severity": severity}


# ── the taxonomy itself ──────────────────────────────────────────────────────

def test_there_are_twelve_domains():
    assert len(D.DOMAINS) == 12


def test_every_domain_declares_a_reach():
    for d in D.DOMAINS:
        assert d["reach"] in (D.FULL, D.PARTIAL, D.CONFIG_ONLY, D.NONE), d["id"]


def test_a_domain_that_is_not_full_explains_its_limit():
    """The label is the buyer's word verbatim; the honesty lives in `scope`, and
    a tile that qualifies nothing is a tile that overclaims."""
    for d in D.DOMAINS:
        if d["reach"] != D.FULL:
            assert d.get("scope"), f"{d['id']} has a limit and does not state it"
            assert len(d["scope"]) > 40, d["id"]


def test_the_runtime_domains_say_they_are_not_live():
    """These four are where a buyer most likely assumes a capability from the
    name alone."""
    for domain_id in ("event_monitoring", "interface", "user_behaviour"):
        scope = D.by_id(domain_id)["scope"].lower()
        assert "not" in scope
        assert "live" in scope or "retrospectiv" in scope, domain_id


def test_the_code_domain_does_not_borrow_saps_product_name():
    """"Code Vulnerability Analyzer" is SAP's own name for a separately licensed
    entitlement. A tile carrying it implies we are CVA, or that CVA is included —
    and a customer without that licence would be misled about what they may run.
    Every other label is a competitor's marketing word, which is fair game."""
    domain = D.by_id("custom_code")
    assert domain["label"] == "Custom Code Security"
    assert "separately licensed" in domain["scope"]


# ── the partition ────────────────────────────────────────────────────────────

def test_every_category_lands_somewhere():
    """A category with no home means real findings vanish from a view that claims
    to summarise them."""
    owned = set()
    for d in D.DOMAINS:
        owned |= set(d.get("categories") or [])
        owned |= set(d.get("prefixes") or {})
    unplaced = set(D.UNPLACED_CATEGORIES)
    missing = set(ComplianceMapper.CATEGORY_THEMES) - owned - unplaced
    assert not missing, f"no domain and no stated exclusion: {sorted(missing)}"


def test_no_category_is_owned_outright_by_two_domains():
    seen = {}
    for d in D.DOMAINS:
        for cat in (d.get("categories") or []):
            assert cat not in seen, f"{cat} owned by {seen[cat]} and {d['id']}"
            seen[cat] = d["id"]


def test_no_domain_claims_a_category_that_does_not_exist():
    real = set(ComplianceMapper.CATEGORY_THEMES)
    for d in D.DOMAINS:
        for cat in list(d.get("categories") or []) + list(d.get("prefixes") or {}):
            assert cat in real, f"{d['id']} claims unknown category {cat!r}"


def test_every_split_category_has_a_default():
    """THE LEAK THIS CLOSES.

    A check id matching no prefix used to fall out of the taxonomy silently:
    PARAM-MS/ACL_INFO, PARAM-MS/MONITOR and CODE-STMT-001 all did, and the only
    reason it surfaced is that the placed and unplaced totals were checked against
    the corpus. A split with no default is a hole that widens with every new check.
    """
    split = {c for d in D.DOMAINS for c in (d.get("prefixes") or {})}
    defaults = {d.get("prefix_default") for d in D.DOMAINS if d.get("prefix_default")}
    assert split <= defaults, f"split with no default: {sorted(split - defaults)}"


def test_a_split_category_routes_an_unknown_check_to_its_default():
    assert D.domain_for("LREV-NEWTHING-001", "Security Audit Log Review") == "event_monitoring"
    assert D.domain_for("CODE-NEWTHING-001", "Code & Transport Security") == "custom_code"
    assert D.domain_for("PARAM-MS/ANYTHING", "System Trust & Standard Users") == "interface"


def test_the_prefix_splits_route_as_intended():
    assert D.domain_for("LREV-PAT-003", "Security Audit Log Review") == "user_behaviour"
    assert D.domain_for("LREV-FLT-001", "Security Audit Log Review") == "event_monitoring"
    assert D.domain_for("TRUST-001", "System Trust & Standard Users") == "interface"
    assert D.domain_for("STDUSR-002", "System Trust & Standard Users") == "identity"
    assert D.domain_for("CODE-TMS-001", "Code & Transport Security") == "transport"
    assert D.domain_for("ABAP-SQLI-001", "Code & Transport Security") == "custom_code"


# ── conservation ─────────────────────────────────────────────────────────────

def test_placed_plus_unplaced_accounts_for_every_finding():
    findings = [_f("USR-001", "User & Authorization"),
                _f("BTP-CC-001", "BTP Cloud Attack Surface"),
                _f("LREV-PAT-001", "Security Audit Log Review"),
                _f("NOPE-001", "Not A Real Category")]
    r = D.roll_up(findings)
    assert r["totals"]["placed"] + r["unplaced"]["total"] == len(findings)


def test_no_domain_total_exceeds_the_corpus():
    findings = [_f("USR-00%d" % i, "User & Authorization") for i in range(5)]
    r = D.roll_up(findings)
    for d in r["domains"]:
        assert d["total"] <= len(findings), d["id"]


def test_a_finding_is_counted_once_not_once_per_category():
    findings = [_f("TRUST-001", "System Trust & Standard Users")]
    r = D.roll_up(findings)
    assert sum(d["total"] for d in r["domains"]) == 1


# ── the constraint ───────────────────────────────────────────────────────────

def test_a_domain_the_product_does_not_do_can_never_report_a_number():
    """THE HARD CONSTRAINT. Even if a finding were somehow routed there, reach is
    consulted before any count is read."""
    r = D.roll_up([_f("USR-001", "User & Authorization")] * 20)
    exploit = next(d for d in r["domains"] if d["id"] == "exploit")
    assert exploit["state"] == D.NOT_ASSESSED
    assert exploit["total"] == 0
    assert all(v == 0 for v in exploit["counts"].values())


def test_the_not_assessed_domain_says_what_it_would_take():
    """"We do not do this" is more useful when it names the nearest thing we do."""
    scope = D.by_id("exploit")["scope"]
    assert "does not" in scope
    assert "Patch and Hotnews" in scope


def test_an_empty_scan_never_reports_a_clean_sweep():
    """With no findings at all, no domain may claim a result it did not observe.
    A fresh deployment must not render twelve green tiles."""
    r = D.roll_up([])
    states = {d["id"]: d["state"] for d in r["domains"]}
    assert states["exploit"] == D.NOT_ASSESSED
    assert all(s in (D.CLEAR, D.NOT_ASSESSED, D.NOT_SUPPLIED)
               for s in states.values())


def test_clear_and_not_assessed_are_different_states():
    assert D.CLEAR != D.NOT_ASSESSED != D.NOT_SUPPLIED


def test_a_domain_whose_export_never_arrived_is_not_clear():
    """"You did not send us the file" and "we looked and it was fine" are
    different sentences, and only one of them is reassuring."""
    manifest = {"modules": {}}          # nothing ran at all
    r = D.roll_up([], coverage=manifest)
    assessable = [d for d in r["domains"] if d["reach"] != D.NONE]
    assert all(d["state"] == D.NOT_SUPPLIED for d in assessable)


def test_without_a_manifest_no_domain_claims_the_export_was_missing():
    """Claiming an export was absent without having checked is the same class of
    error as claiming it was clean."""
    r = D.roll_up([])
    assert not any(d["state"] == D.NOT_SUPPLIED for d in r["domains"])


# ── the findings the taxonomy has no word for ────────────────────────────────

def test_categories_outside_the_taxonomy_are_named_with_a_reason():
    """They are real findings this product produces. A taxonomy that silently
    dropped them would understate the product while claiming to summarise it."""
    assert D.UNPLACED_CATEGORIES
    for name, why in D.UNPLACED_CATEGORIES.items():
        assert name in ComplianceMapper.CATEGORY_THEMES, name
        assert len(why) > 40, name


def test_the_roll_up_reports_what_it_could_not_place():
    r = D.roll_up([_f("BTP-CC-001", "BTP Cloud Attack Surface")])
    assert r["unplaced"]["total"] == 1
    assert "BTP Cloud Attack Surface" in r["unplaced"]["counts"]
    assert r["unplaced"]["reasons"]


# ── the rules a query layer compiles ─────────────────────────────────────────
#
# server/queries.py filters the triage queue by domain, and the obvious way to do
# that is to write the routing rules a second time as a WHERE clause. `match_terms`
# exists so it does not have to; these tests are what make the two readings one.

def _a_corpus():
    """Every category, and every prefix, with an id that matches no prefix too."""
    corpus = []
    for cat in ComplianceMapper.CATEGORY_THEMES:
        corpus.append(("ZZZ-000", cat))
    for d in D.DOMAINS:
        for cat, prefixes in (d.get("prefixes") or {}).items():
            for prefix in prefixes:
                corpus.append((prefix + "999", cat))
    return corpus


def test_the_terms_and_the_router_agree_on_every_prefix_in_the_taxonomy():
    """THE INVARIANT THE SQL FILTER RESTS ON. If these two readings can differ,
    a domain tile and the queue behind it report different numbers for the same
    domain — and the reader who notices is holding both."""
    for check_id, category in _a_corpus():
        expected = D.domain_for(check_id, category)
        matched = [d["id"] for d in D.DOMAINS
                   if D.matches(check_id, category, D.match_terms(d["id"]))]
        assert matched == ([expected] if expected else []), (check_id, category)


def test_a_split_category_routes_its_default_through_the_terms_too():
    assert D.matches("PARAM-MS/ACL_INFO", "System Trust & Standard Users",
                     D.match_terms("interface"))
    assert not D.matches("PARAM-MS/ACL_INFO", "System Trust & Standard Users",
                         D.match_terms("identity"))


def test_the_domain_we_do_not_assess_has_no_terms_at_all():
    """Not "terms that match nothing" — none. A filter built from them selects
    no rows by construction rather than by hoping the data is empty."""
    assert D.match_terms("exploit") == []


def test_an_unknown_domain_yields_no_terms():
    assert D.match_terms("no-such-domain") == []


# ── which modules feed a domain ──────────────────────────────────────────────

def test_a_domain_reached_only_by_prefix_is_not_fed_by_a_category_sibling():
    """THE OVER-ATTRIBUTION THAT REINSTATED THE CLAIM WE HAD JUST REMOVED.

    `ecs_config_items` emits findings in "Security Audit Log Review" — audit-log
    CONFIGURATION, which is Security Event Monitoring. By category alone it also
    counted as a feeder of Suspicious User Behaviour, which owns only the
    LREV-PAT pattern checks. So a scan with no audit-log EXPORT reported the
    behaviour domain as clean, on the strength of a different module having read
    the configuration.
    """
    by_category = {"ecs_config_items": ["Security Audit Log Review"],
                   "log_review": ["Security Audit Log Review"]}
    by_check_id = {"ecs_config_items": ["ECS-AUD-001"],
                   "log_review": ["LREV-PAT-001", "LREV-SRC-001"]}
    behaviour = D.feeders_for(D.by_id("user_behaviour"), by_category, by_check_id)
    assert behaviour == {"log_review"}
    events = D.feeders_for(D.by_id("event_monitoring"), by_category, by_check_id)
    assert events == {"ecs_config_items", "log_review"}


def test_the_behaviour_domain_is_not_clear_when_its_only_module_did_not_run():
    """End to end, with a manifest shaped like the real one."""
    manifest = {"modules": {"log_review": {"status": "skipped"},
                            "ecs_config_items": {"status": "complete"},
                            "user_auth_audit": {"status": "complete"}}}
    rolled = D.roll_up([_f("USR-001", "User & Authorization")], coverage=manifest)
    states = {d["id"]: d["state"] for d in rolled["domains"]}
    assert states["user_behaviour"] == D.NOT_SUPPLIED
    assert states["identity"] == D.ASSESSED


def test_a_domain_whose_module_ran_and_found_nothing_is_clear_not_not_supplied():
    """The other direction, and it matters just as much: telling a customer they
    failed to send an export they did send is its own false statement."""
    manifest = {"modules": {"log_review": {"status": "complete"},
                            "user_auth_audit": {"status": "complete"}}}
    rolled = D.roll_up([_f("USR-001", "User & Authorization")], coverage=manifest)
    states = {d["id"]: d["state"] for d in rolled["domains"]}
    assert states["user_behaviour"] == D.CLEAR


def test_every_assessable_domain_can_be_tied_to_at_least_one_real_module():
    """A domain with no feeder falls back to the coarse "did anything run?"
    question, which is the behaviour this machinery replaced. If a rename breaks
    the link, this fails rather than the report quietly getting vaguer."""
    from modules.coverage import module_categories, module_check_ids
    by_category, by_check_id = module_categories(), module_check_ids()
    for d in D.DOMAINS:
        if d["reach"] == D.NONE:
            continue
        assert D.feeders_for(d, by_category, by_check_id), d["id"]


# ── no score, anywhere ───────────────────────────────────────────────────────

def test_the_roll_up_publishes_no_score_or_percentage():
    """compliance_mapping.py forbids one, and a twelve-tile dashboard is exactly
    where somebody would want to add a maturity rating."""
    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                low = str(key).lower()
                assert "percent" not in low and not low.endswith("_pct"), key
                assert "score" not in low and "maturity" not in low, key
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)
    walk(D.roll_up([_f("USR-001", "User & Authorization")]))
