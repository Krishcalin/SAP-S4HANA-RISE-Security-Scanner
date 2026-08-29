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
