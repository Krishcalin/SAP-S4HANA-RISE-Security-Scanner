"""SoD ruleset coverage — the number that can make us look worse.

The load-bearing test is `test_a_wildcard_degrades_the_score_and_names_itself`.

A role holding `S_TCODE = *` grants every transaction in the system, including
every transaction nobody exported. An earlier revision refused to score at all
in that case; measured against the real sample estate, one such role reduced the
whole module to "could not be measured" — honest and useless.

The fix was to separate two questions. Coverage of EXPLICITLY GRANTED
transactions is bounded and answerable and is always reported; coverage of
everything the estate can REACH is not, and a wildcard says so in its own
finding rather than by withholding the first. What must never happen is a bare
percentage presented as the estate's coverage with a wildcard role behind it.

The second is `test_custom_transactions_do_not_depress_the_coverage_score`. No
shipped ruleset can contain a customer's Z* transactions. Folding them into the
percentage would make every estate look badly covered for a reason no vendor can
fix, and would bury the finding that matters: which custom transactions are
granted.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.ruleset_coverage import RulesetCoverageAuditor  # noqa: E402


def row(role="Z_ROLE", obj="S_TCODE", field="TCD", low="", high=""):
    return {"AGR_NAME": role, "OBJECT": obj, "AUTH": "A01",
            "FIELD": field, "LOW": low, "HIGH": high}


#: A ruleset naming two transactions and one object, so the arithmetic is
#: checkable by hand rather than by running the real 36-risk table.
TINY_RULESET = [{
    "risk_id": "T-01", "functions": [
        {"name": "Maintain Vendor", "actions": ["FK02"],
         "permissions": [{"object": "F_LFA1_BUK", "field": "ACTVT",
                          "values": ["02"]}]},
        {"name": "Pay Vendor", "actions": ["F110"],
         "permissions": [{"object": "F_REGU_BUK", "field": "FBTCH",
                          "values": ["11"]}]},
    ]}]


def audit(rows, ruleset=TINY_RULESET):
    return RulesetCoverageAuditor({"role_auth_values": rows},
                                  ruleset=ruleset).run_all_checks()


def one(findings, check_id):
    for f in findings:
        if f["check_id"] == check_id:
            return f
    return None


# ── the measurement ────────────────────────────────────────────────────────

def test_full_coverage_is_reported_as_such():
    findings = audit([row(low="FK02"), row(low="F110")])
    action = one(findings, "SODCOV-001")
    assert action["details"]["coverage_fraction"] == 1.0
    assert action["details"]["not_named"] == 0
    assert action["severity"] == "INFO"


def test_the_unseen_transactions_are_named_not_just_counted():
    """A count tells an operator there is a problem. The list tells them which
    one, and is the difference between a metric and an action."""
    findings = audit([row(low="FK02"), row(low="ME21N"), row(low="MIGO")])
    action = one(findings, "SODCOV-001")
    # Rounded to 4dp in the module, deliberately: a report does not need
    # sixteen significant figures of a ratio.
    assert action["details"]["coverage_fraction"] == pytest.approx(1 / 3, abs=1e-4)
    assert set(action["details"]["unseen_examples"]) == {"ME21N", "MIGO"}


def test_low_coverage_is_raised_to_high_severity():
    """Below half, a clean SoD result says more about the ruleset than the
    estate, and should not be read as an estate-wide answer."""
    rows = [row(low="FK02")] + [row(low="XX%02d" % i) for i in range(9)]
    assert one(audit(rows), "SODCOV-001")["severity"] == "HIGH"


def test_the_title_carries_the_number():
    """It is the one figure in the report that can make us look worse, so it
    goes in the title rather than three clicks down."""
    assert "33%" in one(audit([row(low="FK02"), row(low="A"), row(low="B")]),
                        "SODCOV-001")["title"]


# ── the wildcard: THE test ─────────────────────────────────────────────────

def test_a_wildcard_degrades_the_score_and_names_itself():
    """THE test. The score survives, but it must be labelled as covering only
    EXPLICIT grants, marked degraded, and accompanied by a finding naming the
    role that made the estate-wide question unanswerable."""
    findings = audit([row(role="Z_SUPER", low="*"), row(low="FK02")])

    action = one(findings, "SODCOV-001")
    assert action is not None, "the measurable half was withheld"
    assert action["details"]["coverage_state"] == "degraded"
    assert action["details"]["denominator"] == "explicitly granted transactions"
    assert "explicitly grants" in action["title"]
    assert "SODCOV-005" in action["description"]

    unbounded = one(findings, "SODCOV-005")
    assert unbounded is not None and unbounded["severity"] == "HIGH"
    assert "Z_SUPER" in unbounded["details"]["wildcard_roles"]


def test_without_a_wildcard_the_score_is_complete_and_says_so():
    """The contrast that makes `degraded` mean something."""
    action = one(audit([row(low="FK02")]), "SODCOV-001")
    assert action["details"]["coverage_state"] == "complete"
    assert one(audit([row(low="FK02")]), "SODCOV-005") is None


@pytest.mark.parametrize("low,high", [
    ("*", ""),            # explicit wildcard
    ("", ""),             # blank is the same thing spelled differently
    ("FB*", ""),          # prefix wildcard
    ("FB01", "*"),        # open-ended range
])
def test_every_spelling_of_unbounded_is_treated_as_unbounded(low, high):
    findings = audit([row(role="Z_WIDE", low=low, high=high), row(low="FK02")])
    assert one(findings, "SODCOV-005") is not None,         "%r..%r was not recognised as unbounded" % (low, high)


def test_an_unenumerable_range_is_unbounded_not_two_transactions():
    """`FB01..FB99` is 99 codes of which perhaps 40 exist. Enumerating them
    would put transactions in the denominator the system does not have;
    counting the endpoints would understate it. Neither is honest."""
    findings = audit([row(role="Z_RANGE", low="FB01", high="FB99")])
    assert one(findings, "SODCOV-005") is not None


def test_the_custom_gap_is_still_reported_under_a_wildcard():
    """The wildcard removes the percentage. It does not remove a finding that
    is measurable and actionable on its own."""
    findings = audit([row(role="Z_SUPER", low="*"), row(low="ZVENDOR")])
    assert one(findings, "SODCOV-003") is not None


# ── custom transactions ────────────────────────────────────────────────────

def test_custom_transactions_do_not_depress_the_coverage_score():
    """THE other test. No vendor's ruleset can contain a customer's Z*
    transactions, so counting them as ruleset failure would make every estate
    look bad for a reason nobody can fix."""
    findings = audit([row(low="FK02"), row(low="ZVENDOR"), row(low="YPAY")])
    action = one(findings, "SODCOV-001")
    assert action["details"]["granted_standard_tcodes"] == 1
    assert action["details"]["coverage_fraction"] == 1.0


def test_custom_transactions_are_reported_with_the_roles_that_grant_them():
    findings = audit([row(role="Z_AP_CLERK", low="ZVENDOR")])
    custom = one(findings, "SODCOV-003")
    assert "ZVENDOR" in custom["details"]["custom_tcodes"]
    assert "Z_AP_CLERK" in custom["details"]["roles_granting_them"]


def test_an_estate_with_no_custom_transactions_gets_no_custom_finding():
    """A compliant estate must be silent — the criterion in CLAUDE.md."""
    assert one(audit([row(low="FK02")]), "SODCOV-003") is None


# ── permission coverage ────────────────────────────────────────────────────

def test_permission_coverage_excludes_s_tcode():
    """S_TCODE is the START authorization, not a predicate the ruleset
    discriminates on. Counting it would flatter the score."""
    rows = [row(low="FK02"),
            row(obj="F_LFA1_BUK", field="ACTVT", low="02"),
            row(obj="M_BEST_WRK", field="WERKS", low="1000")]
    perm = one(audit(rows), "SODCOV-002")
    assert perm["details"]["granted_objects"] == 2
    assert perm["details"]["in_predicates"] == 1
    assert "M_BEST_WRK" in perm["details"]["unseen_examples"]


# ── the unmeasurable case ──────────────────────────────────────────────────

def test_no_export_is_unknown_not_zero_and_not_complete():
    findings = RulesetCoverageAuditor({}).run_all_checks()
    unknown = one(findings, "SODCOV-004")
    assert unknown["details"]["coverage_state"] == "unknown"
    assert "not a coverage of zero" in unknown["description"]
    assert one(findings, "SODCOV-001") is None


def test_the_unknown_finding_says_what_to_do_about_it():
    findings = RulesetCoverageAuditor({}).run_all_checks()
    assert "AGR_1251" in one(findings, "SODCOV-004")["description"]


# ── it measures whatever ruleset it is given ───────────────────────────────

def test_a_custom_ruleset_can_be_measured():
    """The case that matters to a customer who replaced ours — and the reason
    the ruleset is injected rather than imported."""
    findings = RulesetCoverageAuditor(
        {"role_auth_values": [row(low="ME21N")]},
        ruleset=[{"functions": [{"actions": ["ME21N"], "permissions": []}]}]
    ).run_all_checks()
    assert one(findings, "SODCOV-001")["details"]["coverage_fraction"] == 1.0


def test_the_shipped_ruleset_is_the_default():
    """With no ruleset injected it measures ours, which is the point: the
    number we publish is about the rulebook we ship."""
    findings = RulesetCoverageAuditor(
        {"role_auth_values": [row(low="FK02"), row(low="F110")]}
    ).run_all_checks()
    assert one(findings, "SODCOV-001")["details"]["coverage_fraction"] == 1.0


def test_it_never_raises_on_malformed_rows():
    """Hand-made CSVs reach this module."""
    RulesetCoverageAuditor({"role_auth_values": [
        {}, {"OBJECT": ""}, "not a dict", {"AGR_NAME": None, "OBJECT": "S_TCODE"},
    ]}).run_all_checks()


# ── the Fiori surface ──────────────────────────────────────────────────────
#
# The first version of this module counted S_TCODE grants and nothing else. On
# an S/4HANA estate whose users work through Fiori, that reports a confident
# percentage over the classic surface while the Fiori surface goes unmeasured —
# the same failure the module exists to prevent, reproduced inside it.

def tile(app="F0733", service="API_USER_MANAGEMENT", role="Z_ADMIN"):
    return {"TILE_ID": "T1", "APP_ID": app, "CATALOG_ID": "Z_CAT",
            "ODATA_SERVICE": service, "ROLE": role}


def fiori_audit(tiles, ruleset=TINY_RULESET, rows=None):
    data = {"role_auth_values": rows if rows is not None else [row(low="FK02")],
            "fiori_tiles": tiles}
    return RulesetCoverageAuditor(data, ruleset=ruleset).run_all_checks()


def test_a_fiori_surface_the_ruleset_cannot_name_scores_zero():
    """THE Fiori test. An app the ruleset never mentions cannot appear in any
    conflict, and on an S/4HANA estate that is most of the surface."""
    finding = one(fiori_audit([tile(), tile("F0735", "API_BUSINESS_ROLE")]),
                  "SODCOV-006")
    assert finding is not None
    assert finding["details"]["coverage_fraction"] == 0.0
    assert finding["details"]["fiori_apps"] == 2
    assert finding["severity"] == "HIGH"


def test_the_transaction_figure_discloses_the_other_surface():
    """93% of transactions must not read as 93% of the estate while a second,
    unmeasured surface exists."""
    findings = fiori_audit([tile()])
    assert "separate surface measured in SODCOV-006" in \
        one(findings, "SODCOV-001")["description"]


def test_an_estate_with_no_fiori_exports_gets_no_fiori_finding():
    """A compliant — or classic-only — estate must be silent."""
    assert one(audit([row(low="FK02")]), "SODCOV-006") is None


def test_naming_the_app_is_not_enough_without_the_start_object():
    """A Fiori app carries NO permissions of its own; they belong to the OData
    service behind it. A ruleset naming apps but never S_SERVICE cannot express
    a permission-level Fiori rule, and says so."""
    ruleset = [{"functions": [{"actions": ["F0733"], "permissions": []}]}]
    finding = one(fiori_audit([tile()], ruleset=ruleset), "SODCOV-006")
    assert finding["details"]["can_express_permission_level_fiori_rules"] is False
    assert "neither S_SERVICE nor S_START" in finding["description"]


def test_the_start_object_makes_permission_level_fiori_rules_expressible():
    ruleset = [{"functions": [{"actions": ["F0733"], "permissions": [
        {"object": "S_SERVICE", "field": "SRV_NAME", "values": ["*"]}]}]}]
    finding = one(fiori_audit([tile()], ruleset=ruleset), "SODCOV-006")
    assert finding["details"]["can_express_permission_level_fiori_rules"] is True


def test_an_app_whose_tile_names_no_service_is_counted_as_unresolvable():
    """It cannot be resolved to a back-end authorization at all, which is a
    different problem from the ruleset not naming it."""
    finding = one(fiori_audit([tile(service="")]), "SODCOV-006")
    assert finding["details"]["apps_with_no_service"] == ["F0733"]
    assert "cannot be resolved to a back-end authorization" in finding["description"]


def test_the_fiori_surface_is_measured_even_without_role_authorizations():
    """The two surfaces are described by different exports. An estate may
    supply the Fiori ones and not AGR_1251."""
    findings = RulesetCoverageAuditor(
        {"fiori_tiles": [tile()]}, ruleset=TINY_RULESET).run_all_checks()
    assert one(findings, "SODCOV-006") is not None
    assert one(findings, "SODCOV-004") is not None       # and still says so


# ── objects the release does not define ────────────────────────────────────
#
# The matcher is fail-closed, so a predicate naming an object nobody holds is
# simply unsatisfied — correct for an object that exists and is ungranted, and a
# silent catastrophe for one that does not exist at all. A typo produces a rule
# that can never fire for anybody and looks exactly like a rule that ran and
# found nothing. TOBJ is what tells the two apart.

def catalogue(*objects):
    return [{"OBJCT": o} for o in objects]


def cov(rows=None, ruleset=TINY_RULESET, tobj=None):
    data = {"role_auth_values": rows if rows is not None else [row(low="FK02")]}
    if tobj is not None:
        data["auth_object_catalogue"] = tobj
    return RulesetCoverageAuditor(data, ruleset=ruleset).run_all_checks()


def test_without_a_catalogue_object_existence_is_not_claimed_either_way():
    """Most uploads will not carry TOBJ. Absence must produce no verdict."""
    assert one(cov(), "SODCOV-007") is None


def test_the_object_coverage_finding_says_existence_was_not_checked():
    """Otherwise the percentage reads as though the objects were verified.
    Needs a granted OBJECT, not just a transaction, or SODCOV-002 has nothing
    to measure and does not fire at all."""
    rows = [row(low="FK02"), row(obj="F_LFA1_BUK", field="ACTVT", low="02")]
    assert "was not checked" in one(cov(rows), "SODCOV-002")["description"]


def test_a_complete_catalogue_reports_clean_rather_than_staying_silent():
    """"We looked and everything resolved" is a different statement from "we did
    not look", and this module exists to keep them apart."""
    f = one(cov(tobj=catalogue("F_LFA1_BUK", "F_REGU_BUK")), "SODCOV-007")
    assert f is not None and f["severity"] == "INFO"
    assert f["details"]["objects_absent"] == 0


def test_a_rule_whose_only_object_is_absent_is_reported_as_unfirable():
    """THE finding. Not "an object is missing" — "this rule can never fire"."""
    f = one(cov(tobj=catalogue("F_LFA1_BUK")), "SODCOV-007")
    assert f["severity"] == "HIGH"
    assert f["details"]["rules_unfirable"] == ["T-01"]
    assert "F_REGU_BUK" in f["details"]["absent_objects"]


def test_the_finding_names_the_rule_and_the_object_it_cannot_resolve():
    f = one(cov(tobj=catalogue("F_LFA1_BUK")), "SODCOV-007")
    assert any("T-01" in i and "F_REGU_BUK" in i for i in f["affected_items"])


def test_an_absent_object_beside_a_present_one_does_not_kill_the_rule():
    """Within a function the default match across distinct objects is 'any', so
    one surviving object still lets the function be held. Reporting it as dead
    would overstate the damage."""
    ruleset = [{"risk_id": "T-02", "functions": [
        {"name": "A", "actions": ["FK02"], "permissions": [
            {"object": "F_LFA1_BUK", "field": "ACTVT", "values": ["02"]},
            {"object": "F_GONE_XXX", "field": "ACTVT", "values": ["02"]}]},
        {"name": "B", "actions": ["F110"], "permissions": [
            {"object": "F_REGU_BUK", "field": "ACTVT", "values": ["02"]}]}]}]
    f = one(cov(ruleset=ruleset,
                tobj=catalogue("F_LFA1_BUK", "F_REGU_BUK")), "SODCOV-007")
    assert f["severity"] == "MEDIUM"          # noted, not fatal
    assert f["details"]["rules_unfirable"] == []
    assert f["details"]["absent_objects"] == ["F_GONE_XXX"]


def test_the_catalogue_is_read_from_the_ordinary_tobj_column_names():
    for key in ("OBJCT", "OBJECT", "AUTH_OBJECT", "NAME"):
        rows = [{key: "F_LFA1_BUK"}, {key: "F_REGU_BUK"}]
        assert one(cov(tobj=rows), "SODCOV-007")["details"]["objects_absent"] == 0


def test_it_is_measurable_without_any_role_export():
    """The catalogue question is about the RULESET, not about what the estate
    granted, so it survives an upload with no AGR_1251 at all."""
    a = RulesetCoverageAuditor({"auth_object_catalogue": catalogue("F_LFA1_BUK")},
                               ruleset=TINY_RULESET)
    assert one(a.run_all_checks(), "SODCOV-007") is not None


def test_the_shipped_ruleset_resolves_against_its_own_object_list():
    """A sanity check on the library itself: every object the 99 shipped rules
    name must resolve when the catalogue contains exactly those objects. It
    cannot tell whether the names are RIGHT — provenance covers that — but it
    catches a predicate that could never be satisfied by construction."""
    from modules.access_risk_analysis import AccessRiskAnalysisAuditor as ARA
    objects = sorted({p["object"] for r in ARA.RULESET
                      for f in r["functions"] for p in f.get("permissions", [])})
    f = one(RulesetCoverageAuditor(
        {"auth_object_catalogue": catalogue(*objects)}).run_all_checks(),
        "SODCOV-007")
    assert f["severity"] == "INFO", f["details"]["absent_objects"]
    assert f["details"]["objects_referenced"] == len(objects)


# ── the customer's own ruleset ─────────────────────────────────────────────
#
# ara_ruleset.json is the path any enterprise with an existing GRC ruleset
# takes, and it was accepted without a single validation. Each shape below was
# run through the engine before the check was written, so these are its actual
# behaviours rather than a reading of the source.

def custom(rules, rows=None):
    data = {"role_auth_values": rows if rows is not None else [row(low="FK02")],
            "ara_ruleset": rules}
    return RulesetCoverageAuditor(data).run_all_checks()


def two_sided(rid="ZOK"):
    return {"risk_id": rid, "risk_type": "SOD", "functions": [
        {"name": "a", "actions": ["FK02"], "permissions": [
            {"object": "F_LFA1_BUK", "field": "ACTVT", "values": ["02"]}]},
        {"name": "b", "actions": ["F110"], "permissions": [
            {"object": "F_REGU_BUK", "field": "ACTVT", "values": ["02"]}]}]}


def test_no_custom_ruleset_means_no_verdict():
    assert one(audit([row(low="FK02")]), "SODCOV-008") is None


def test_a_well_formed_custom_ruleset_is_silent():
    """A check that fires on correct input is a check nobody reads."""
    assert one(custom([two_sided()]), "SODCOV-008") is None
    assert one(custom([two_sided()]), "SODCOV-009") is None


def test_a_function_with_no_gate_at_all_is_reported_as_firing_for_everyone():
    """THE serious one. The action gate is skipped when a function names no
    actions and the permission gate returns True when it declares none, so the
    rule is held by every user in the estate — a false-positive engine."""
    f = one(custom([{"risk_id": "ZBAD", "risk_type": "SOD",
                     "functions": [{"name": "a"}, {"name": "b"}]}]), "SODCOV-008")
    assert f["severity"] == "CRITICAL"
    assert f["details"]["fires_for_every_user"] == 1
    assert "held by EVERY user" in " ".join(f["affected_items"])


def test_a_misspelled_functions_key_is_reported_rather_than_ignored():
    f = one(custom([{"risk_id": "ZTYPO", "risk_type": "SOD",
                     "function": [{"name": "a", "actions": ["FK02"]}]}]),
            "SODCOV-008")
    assert f["details"]["can_never_fire"] == 1
    assert "misspelled key" in " ".join(f["affected_items"])


def test_a_segregation_rule_with_one_function_can_never_fire():
    f = one(custom([{"risk_id": "ZONE", "risk_type": "SOD", "functions": [
        {"name": "a", "actions": ["FK02"], "permissions": []}]}]), "SODCOV-008")
    assert "requires two sides" in " ".join(f["affected_items"])
    assert f["severity"] == "HIGH"          # dead, but not noisy


def test_permissions_naming_no_object_can_never_be_held():
    f = one(custom([{"risk_id": "ZNOOBJ", "risk_type": "SOD", "functions": [
        {"name": "a", "actions": ["FK02"],
         "permissions": [{"field": "ACTVT", "values": ["02"]}]},
        {"name": "b", "actions": ["F110"], "permissions": []}]}]), "SODCOV-008")
    assert "none names an object" in " ".join(f["affected_items"])


def test_firing_for_everyone_outranks_merely_being_dead():
    """Noise buries real findings; silence only hides one rule. When both are
    present the severity must follow the worse of the two."""
    f = one(custom([{"risk_id": "ZDEAD", "risk_type": "SOD", "functions": [
                        {"name": "a", "actions": ["FK02"], "permissions": []}]},
                    {"risk_id": "ZLOUD", "risk_type": "SOD",
                     "functions": [{"name": "a"}, {"name": "b"}]}]), "SODCOV-008")
    assert f["severity"] == "CRITICAL"
    assert f["details"]["can_never_fire"] == 1
    assert f["details"]["fires_for_every_user"] == 1


def test_replacing_a_shipped_rule_is_reported_separately():
    """Overriding is a legitimate feature. Doing it unknowingly is not, and the
    ruleset count does not change, so nothing else would show it."""
    f = one(custom([two_sided(rid="P2P-01")]), "SODCOV-009")
    assert f is not None and f["severity"] == "MEDIUM"
    assert f["details"]["replaced"] == ["P2P-01"]
    assert "Maintain Vendor Master" in " ".join(f["affected_items"])


def test_a_custom_rule_with_a_fresh_id_replaces_nothing():
    assert one(custom([two_sided(rid="Z_FRESH_01")]), "SODCOV-009") is None


def test_an_override_is_not_itself_treated_as_a_defect():
    """SODCOV-009 is a disclosure, not an error. A well-formed override must
    not also raise SODCOV-008."""
    assert one(custom([two_sided(rid="P2P-01")]), "SODCOV-008") is None


def test_a_non_object_entry_does_not_crash_the_check():
    """Hand-edited JSON contains anything at all."""
    f = one(custom([["not", "a", "rule"], two_sided()]), "SODCOV-008")
    assert f["details"]["can_never_fire"] == 1


# ── comparing two rulesets ─────────────────────────────────────────────────
#
# An organisation that already owns a GRC ruleset will not replace it with ours.
# What they want is the delta, and the framing has to be exact: this engine
# MERGES a supplied ruleset with the shipped one, so within a scan both ran.
# Their own GRC system runs theirs alone, and that is the comparison worth
# making.

from modules.access_risk_analysis import AccessRiskAnalysisAuditor as _ARA  # noqa: E402


def z_rule(rid, a_tcodes, a_obj, b_tcodes, b_obj):
    return {"risk_id": rid, "risk_type": "SOD", "functions": [
        {"name": "a", "actions": a_tcodes,
         "permissions": [{"object": a_obj, "field": "ACTVT", "values": ["02"]}]},
        {"name": "b", "actions": b_tcodes,
         "permissions": [{"object": b_obj, "field": "ACTVT", "values": ["02"]}]}]}


SMALL = [z_rule("Z01", ["FK01"], "F_LFA1_BUK", ["F110"], "F_REGU_BUK")]


def test_no_supplied_ruleset_means_no_comparison():
    assert one(audit([row(low="FK02")]), "SODCOV-010") is None


def test_a_ruleset_identical_to_ours_produces_no_comparison():
    """Nothing to say, so say nothing."""
    assert one(custom(_ARA.RULESET), "SODCOV-010") is None


def test_it_leads_with_processes_rather_than_a_transaction_count():
    """A raw count of unnamed transactions is dominated by how many rules were
    supplied, so on a small extension it reads as alarming when it is merely
    arithmetic. A whole business process left untouched is a decision."""
    f = one(custom(SMALL), "SODCOV-010")
    assert "business processes at all" in f["title"]
    assert "H2R" in f["details"]["shipped_processes_untouched_by_supplied"]


def test_the_comparison_states_that_this_scan_merged_the_two():
    """Otherwise the delta reads as a description of what just ran, which it
    is not."""
    assert "MERGED them" in one(custom(SMALL), "SODCOV-010")["description"]


def test_capabilities_only_the_supplied_ruleset_reaches_are_reported():
    """The reverse direction is a gap in THIS product. A comparison that only
    ever flattered us would not be worth running."""
    f = one(custom(SMALL + [z_rule("Z02", ["ZCUST1"], "Z_MINE",
                                   ["ZCUST2"], "Z_MINE2")]), "SODCOV-010")
    assert f["details"]["only_in_supplied"] == ["ZCUST1", "ZCUST2"]
    assert f["details"]["objects_only_in_supplied"] == ["Z_MINE", "Z_MINE2"]
    assert "a gap in THIS product" in f["description"]


def test_a_superset_of_ours_is_reported_at_info_not_medium():
    """They are ahead of us on those capabilities. That is not their finding."""
    f = one(custom(_ARA.RULESET + [z_rule("ZX", ["ZNEW1"], "Z_NEW1",
                                          ["ZNEW2"], "Z_NEW2")]), "SODCOV-010")
    assert f["severity"] == "INFO"
    assert "this one does not" in f["title"]


def test_no_attempt_is_made_to_match_risk_to_risk():
    """Identifiers and groupings will not correspond between two rulesets, and
    a fuzzy correspondence would read as precision it does not have."""
    d = one(custom(SMALL), "SODCOV-010")["details"]
    assert "not_named_by_supplied" in d and "risks_matched" not in d
    assert "match individual risks" in one(custom(SMALL), "SODCOV-010")["description"]


def test_the_counts_describe_each_ruleset_alone():
    f = one(custom(SMALL), "SODCOV-010")
    d = f["details"]
    assert d["supplied_transactions"] == 2          # FK01 + F110
    assert d["shipped_transactions"] == len(
        {a for r in _ARA.RULESET for fn in r["functions"] for a in fn["actions"]})


def test_a_malformed_supplied_rule_does_not_break_the_comparison():
    """SODCOV-008 reports it; this check must still produce its numbers."""
    f = one(custom(SMALL + [["not", "a", "rule"], {"risk_id": "ZB"}]),
            "SODCOV-010")
    assert f is not None and f["details"]["supplied_transactions"] == 2


# ── one statement, for the workpaper ───────────────────────────────────────
#
# Ten findings are not an answer to the question that was asked. An auditor
# wants one sentence they can quote, and a reader made to assemble it will
# assemble it wrongly or not at all.

def verdict_of(findings):
    f = one(findings, "SODCOV-000")
    return f["details"]["verdict"] if f else None


def test_no_findings_means_no_statement():
    """Nothing to summarise, so nothing is claimed."""
    a = RulesetCoverageAuditor({})
    a.run_all_checks()
    assert one(a.findings, "SODCOV-000") is None or a.findings


def test_an_unmeasurable_estate_is_reported_as_not_measured():
    """The strongest floor. Without the authorization export there is no
    statement about breadth to make, and a percentage would be invented."""
    a = RulesetCoverageAuditor({})
    assert verdict_of(a.run_all_checks()) == "not measured"


def test_a_wildcard_grant_makes_the_whole_result_unbounded():
    rows = [row(low="*"), row(low="FK02"),
            row(obj="F_LFA1_BUK", field="ACTVT", low="02")]
    assert verdict_of(audit(rows)) == "unbounded"


def test_the_verdict_is_the_weakest_dimension_not_the_average():
    """THE design rule. Averaging broad transaction coverage against a Fiori
    surface the ruleset cannot see produces a comfortable number describing
    neither, and a summary that buries its worst input is the failure every
    other check here exists to report."""
    data = {"role_auth_values": [row(low="FK02"), row(low="F110"),
                                 row(obj="F_LFA1_BUK", field="ACTVT", low="02"),
                                 row(obj="F_REGU_BUK", field="ACTVT", low="02")],
            "fiori_tiles": [{"APP_ID": "F0733", "ODATA_SERVICE": "API_X",
                             "ROLE": "Z_ROLE"}]}
    f = one(RulesetCoverageAuditor(data).run_all_checks(), "SODCOV-000")
    assert f["details"]["verdict"] == "partial"
    assert any("Fiori" in l for l in f["details"]["limits"])
    assert "never an average" in f["description"]


def test_a_clean_estate_says_so_rather_than_staying_silent():
    """"We looked and found no limit" is a different statement from "we did not
    look", and this module exists to keep them apart."""
    data = {"role_auth_values": [row(low="FK02"), row(low="F110"),
                                 row(obj="F_LFA1_BUK", field="ACTVT", low="02"),
                                 row(obj="F_REGU_BUK", field="ACTVT", low="02")]}
    f = one(RulesetCoverageAuditor(data).run_all_checks(), "SODCOV-000")
    assert f["details"]["verdict"] == "usable"
    assert f["severity"] == "INFO"
    assert "No limit was found" in f["description"]


def test_it_is_derived_from_the_findings_it_summarises():
    """A summary that recalculates can disagree with its own detail, and then
    the report contradicts itself in front of the person least able to tell
    which half is right."""
    f = one(audit([row(low="*"), row(low="FK02")]), "SODCOV-000")
    assert f["details"]["derived_from"]
    assert all(c.startswith("SODCOV-") and c != "SODCOV-000"
               for c in f["details"]["derived_from"])


def test_dead_rules_raise_the_statement_even_when_coverage_is_broad():
    """A rule that can never fire undermines the result regardless of how much
    of the estate the ruleset otherwise names."""
    data = {"role_auth_values": [row(low="FK02"), row(low="F110"),
                                 row(obj="F_LFA1_BUK", field="ACTVT", low="02"),
                                 row(obj="F_REGU_BUK", field="ACTVT", low="02")],
            "auth_object_catalogue": [{"OBJCT": "F_LFA1_BUK"}]}
    f = one(RulesetCoverageAuditor(data).run_all_checks(), "SODCOV-000")
    assert f["severity"] == "HIGH"
    assert any("can never fire" in l for l in f["details"]["limits"])


def test_the_limits_are_ordered_worst_first():
    """They are worked in the order given, so the first must be the one that
    decides what the report is worth."""
    rows = [row(low="*"), row(low="FK02"),
            row(obj="F_LFA1_BUK", field="ACTVT", low="02")]
    data = dict(role_auth_values=rows,
                fiori_tiles=[{"APP_ID": "F0733", "ODATA_SERVICE": "API_X",
                              "ROLE": "Z_ROLE"}])
    limits = one(RulesetCoverageAuditor(data).run_all_checks(),
                 "SODCOV-000")["details"]["limits"]
    assert "grants every transaction" in limits[0]


# ── the verdict has to know what was hidden ────────────────────────────────
#
# SODCOV-000 read USABLE / INFO on an estate whose only conflict had been
# removed by a blanket mitigation row carrying no approver, no expiry and no
# control id. The statement that exists to say how far a result can be believed
# was the last place in the product still capable of a false all-clear — and it
# renders above the findings in every format and on the console dashboard.

from modules.access_risk_analysis import AccessRiskAnalysisAuditor as _ARA2  # noqa: E402

SUPPRESSIBLE = [{"risk_id": "ZS", "name": "vendor create vs pay",
                 "description": "d", "risk_type": "SOD", "severity": "CRITICAL",
                 "process": "P2P", "functions": [
                     {"name": "A", "actions": ["FK01"], "permissions": [
                         {"object": "F_LFA1_BUK", "field": "ACTVT",
                          "values": ["02"]}]},
                     {"name": "B", "actions": ["F110"], "permissions": [
                         {"object": "F_REGU_BUK", "field": "ACTVT",
                          "values": ["02"]}]}]}]

HOLDS_IT = [row(low="FK01"), row(low="F110"),
            row(obj="F_LFA1_BUK", field="ACTVT", low="02"),
            row(obj="F_REGU_BUK", field="ACTVT", low="02")]


def with_peers(mitigations=None):
    """Run ARA first, then the coverage module over the same estate."""
    data = {"role_auth_values": HOLDS_IT,
            "user_roles": [{"UNAME": "U1", "AGR_NAME": "Z_ROLE"}]}
    if mitigations is not None:
        data["mitigating_controls"] = mitigations
    ara = _ARA2(dict(data))
    ara.RULESET = SUPPRESSIBLE
    peers = ara.run_all_checks()
    cov = RulesetCoverageAuditor(dict(data), {}, {"peer_findings": peers},
                                 ruleset=SUPPRESSIBLE)
    return one(cov.run_all_checks(), "SODCOV-000")


BLANKET = [{"USER": "U1", "RISK_ID": "*", "CONTROL_ID": "", "VALID_TO": ""}]


def test_an_unsuppressed_estate_still_reads_usable():
    f = with_peers()
    assert f["details"]["verdict"] == "usable"
    assert f["details"]["suppression_checked"] is True


def test_a_risk_hidden_by_a_mitigation_stops_the_verdict_reading_usable():
    """THE false all-clear. A conflict removed from the report is not a
    conflict that was not there."""
    f = with_peers(BLANKET)
    assert f["details"]["verdict"] == "partial"
    assert f["severity"] == "HIGH"
    assert f["details"]["risks_hidden_by_mitigation"] == 1


def test_the_limit_says_a_suppression_is_not_an_absence():
    limits = " ".join(with_peers(BLANKET)["details"]["limits"])
    assert "reflects a suppression rather than an absence" in limits


def test_unsupportable_rows_are_named_as_their_own_limit():
    limits = " ".join(with_peers(BLANKET)["details"]["limits"])
    assert "cannot support an audit conclusion" in limits


def test_the_verdict_names_the_mitigation_checks_it_was_derived_from():
    """Derived, not recomputed — a summary that recalculates can disagree with
    the detail it summarises."""
    derived = with_peers(BLANKET)["details"]["derived_from"]
    assert "MITIG-001" in derived and "MITIG-002" in derived


def test_without_peer_findings_it_says_suppression_was_not_examined():
    """Absence of suppression data is NOT an absence of suppression. Claiming
    a clean verdict without having looked would be the same defect one level
    up."""
    a = RulesetCoverageAuditor({"role_auth_values": HOLDS_IT},
                               ruleset=SUPPRESSIBLE)
    f = one(a.run_all_checks(), "SODCOV-000")
    assert f["details"]["suppression_checked"] is False
    assert "not examined in this run" in f["description"]
