"""A parameter exported twice, with two different values.

FOUND IN A REAL EXPORT. While driving the console against a customer-shaped
estate, `security_params.csv` carried `login/no_automatic_user_sapstar` twice.
Both copies agreed, so nothing surfaced. They do not have to agree:

  * RSPARAM taken across application servers carries a genuinely different
    value per server, because a profile parameter CAN differ per instance and
    every one of those values is live on some server.
  * DEFAULT.PFL merged with an instance profile carries the override beside the
    default it overrides.

`param_lookup` keeps the LAST row for a name, so before this the verdict was
decided by CSV row order. Measured on the two orderings of one export:

    weak first, strong last  ->  judged 15   (compliant)
    strong first, weak last  ->  judged 6    (non-compliant)

For `login/no_automatic_user_sapstar` that is a CRITICAL -- SAP* kernel
emergency-user auto-logon -- reported or suppressed by accident. This is the
fail-open the release gate's Rule 4 exists to forbid, sitting one layer below
the gate where the gate could not see it.

THE RESOLUTION IS NOT TO PICK BETTER. It is to judge every value the export
carries, because a rule any live server fails is a rule the estate fails, and
to disclose the ambiguity separately since the file cannot say which of the two
ordinary causes produced it.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.base_auditor import BaseAuditor          # noqa: E402
from modules.security_params import SecurityParamAuditor  # noqa: E402

WEAK, STRONG = "6", "15"
LNG = "login/min_password_lng"
SAPSTAR = "login/no_automatic_user_sapstar"


def rows(name, *values):
    return [{"NAME": name, "VALUE": v} for v in values]


def run(param_rows):
    return SecurityParamAuditor({"security_params": param_rows}).run_all_checks()


def ids(findings):
    return {f["check_id"] for f in findings}


# --------------------------------------------------------------------------- #
#  The map that sees every value                                              #
# --------------------------------------------------------------------------- #

def test_param_values_keeps_both_values():
    got = BaseAuditor.param_values(rows(LNG, WEAK, STRONG))
    assert got[LNG] == [WEAK, STRONG]


def test_param_values_is_order_independent_as_a_set():
    a = BaseAuditor.param_values(rows(LNG, WEAK, STRONG))[LNG]
    b = BaseAuditor.param_values(rows(LNG, STRONG, WEAK))[LNG]
    assert sorted(a) == sorted(b)


def test_a_repeated_identical_value_is_not_a_conflict():
    """The real export's duplicate agreed with itself. That is not news."""
    assert BaseAuditor.param_conflicts(rows(LNG, WEAK, WEAK)) == {}
    assert BaseAuditor.param_values(rows(LNG, WEAK, WEAK))[LNG] == [WEAK]


def test_param_lookup_is_unchanged_for_the_ordinary_case():
    """Adding this must not disturb the map 800-odd checks already read."""
    assert BaseAuditor.param_lookup(rows(LNG, WEAK)) == {LNG: WEAK}


# --------------------------------------------------------------------------- #
#  The fail-open itself                                                       #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("order", [(WEAK, STRONG), (STRONG, WEAK)])
def test_a_weak_value_is_reported_whichever_row_it_sits_on(order):
    """THE REGRESSION. Before the fix, only one of these two orderings fired."""
    found = ids(run(rows(LNG, *order)))
    assert "PARAM-%s" % LNG in found, (
        "an export carrying %s = %s was judged compliant because the compliant "
        "copy came last" % (LNG, WEAK))


@pytest.mark.parametrize("order", [("0", "1"), ("1", "0")])
def test_sap_star_auto_logon_cannot_be_hidden_by_row_order(order):
    """The CRITICAL case, stated on its own because it is the one that matters:
    `login/no_automatic_user_sapstar = 0` leaves SAP*'s kernel emergency user
    available, and a scan must not miss it because of where a row sat."""
    assert "PARAM-%s" % SAPSTAR in ids(run(rows(SAPSTAR, *order)))


def test_the_verdict_is_identical_for_both_orderings():
    a = ids(run(rows(LNG, WEAK, STRONG)))
    b = ids(run(rows(LNG, STRONG, WEAK)))
    assert a == b, "the same export in a different row order gave a different scan"


def test_two_compliant_values_still_pass():
    """Fail-closed must not mean fail-noisy: if every value passes, nothing is
    wrong with the estate and no parameter finding belongs."""
    assert "PARAM-%s" % LNG not in ids(run(rows(LNG, STRONG, "16")))


# --------------------------------------------------------------------------- #
#  What the reader is told                                                    #
# --------------------------------------------------------------------------- #

def test_the_finding_names_the_other_value():
    """A reader who checks one server and finds 15 must not conclude the report
    is wrong; it is reporting that some other server is not 15."""
    finding = next(f for f in run(rows(LNG, WEAK, STRONG))
                   if f["check_id"] == "PARAM-%s" % LNG)
    shown = " ".join(finding.get("affected_items") or [])
    assert STRONG in shown and WEAK in shown, shown


def test_the_ambiguity_is_disclosed_as_its_own_finding():
    found = [f for f in run(rows(LNG, WEAK, STRONG))
             if f["check_id"] == "PARAM-EXPORT-CONFLICT"]
    assert found, "the export was ambiguous and nothing said so"
    assert found[0]["severity"] == BaseAuditor.SEVERITY_INFO
    assert found[0]["details"]["degrades_coverage"] is True


def test_no_conflict_finding_when_the_export_is_unambiguous():
    """A disclosure that fires on a clean export is noise, and noise is filtered
    out along with the signal."""
    assert "PARAM-EXPORT-CONFLICT" not in ids(run(rows(LNG, STRONG)))


def test_a_duplicate_that_changes_no_verdict_is_not_disclosed():
    """Measured on the export that prompted this work: it carried TWO repeated
    parameters and only one of them mattered. `rfc/allowoldticket4tt` came as
    "yes" and as "1" — two spellings the shipped rules judge identically, both
    failing — so there is nothing for a reader to resolve and saying so would be
    noise.

    The alternative was to teach the comparison that "yes" means 1. That is an
    SAP fact this repository has no source for, and inventing one to quieten a
    message is the fabrication the provenance rules forbid. Asking whether the
    verdict moves is right about "yes"/"1" without knowing what they mean.
    """
    findings = run(rows("rfc/allowoldticket4tt", "yes", "1"))
    assert "PARAM-EXPORT-CONFLICT" not in ids(findings)
    # ...and the parameter itself is still judged non-compliant, on both values.
    assert "PARAM-rfc/allowoldticket4tt" in ids(findings)


def test_a_parameter_no_rule_judges_is_not_disclosed():
    """This scan concluded nothing about it, and a duplicate cannot unsettle a
    conclusion that was never reached."""
    assert "PARAM-EXPORT-CONFLICT" not in ids(
        run(rows("some/unjudged_parameter", "a", "b")))


# --------------------------------------------------------------------------- #
#  Identity                                                                   #
# --------------------------------------------------------------------------- #

def test_an_existing_finding_keeps_its_identity_when_a_duplicate_appears():
    """A duplicate that changes nothing about the verdict must not retire the
    finding and raise a fresh one, which would reset its age and its ticket."""
    from server import identity

    before = next(f for f in run(rows(LNG, WEAK))
                  if f["check_id"] == "PARAM-%s" % LNG)
    after = next(f for f in run(rows(LNG, WEAK, STRONG))
                 if f["check_id"] == "PARAM-%s" % LNG)
    assert (identity.fingerprint_finding(before, system="PRD", client="100")
            == identity.fingerprint_finding(after, system="PRD", client="100")), (
        "the same non-compliant value produced a different finding identity "
        "once a compliant duplicate appeared beside it")
