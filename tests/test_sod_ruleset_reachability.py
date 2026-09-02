"""Every risk in the shipped SoD ruleset must be able to fire.

THE RULESET CARRIES ITS OWN TEST DATA. Each risk in `data/sod_ruleset.json`
declares the functions that conflict, and each function declares the
transactions and authorization values that constitute it. So the rule states
exactly what a user would have to hold to trigger it — and if a user holding
precisely that does not trigger it, the rule fires for nobody.

That is not hypothetical. `docs/CHECK_FIRING.md` records that five
segregation-of-duties rules were once found dead, and 36 of the 99 `ARA-*` ids
had never been observed to fire anywhere in this suite or against the bundled
corpus. A dead SoD rule is the worst kind of defect this product can ship: it
reports zero conflicts, on every estate, for ever — and zero conflicts is
exactly what a working control looks like on the page.

This test is GENERATED FROM THE RULESET rather than written against a list of
ids, so a risk added to the JSON is covered the moment it is added, and a
malformed one fails on the next run rather than at some customer.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.access_risk_analysis import AccessRiskAnalysisAuditor as ARA  # noqa: E402


def _grants_for(risk):
    """AGR_1251 rows and role assignments satisfying every function of a risk.

    One action and one permission value per function — the minimum that
    constitutes the function according to the rule's own declaration. Taking
    more would risk proving the rule through some other risk's inputs.
    """
    role_auth, user_roles = [], []
    for index, function in enumerate(risk.get("functions") or []):
        role = "Z_TEST_F%d" % index
        user_roles.append({"UNAME": "TESTER", "AGR_NAME": role})
        for action in (function.get("actions") or [])[:1]:
            role_auth.append({"AGR_NAME": role, "OBJECT": "S_TCODE",
                              "AUTH": "T%02d" % index, "FIELD": "TCD",
                              "LOW": action, "HIGH": ""})
        for permission in (function.get("permissions") or []):
            for value in (permission.get("values") or [""])[:1]:
                role_auth.append({"AGR_NAME": role,
                                  "OBJECT": permission.get("object", ""),
                                  "AUTH": "P%02d" % index,
                                  "FIELD": permission.get("field", ""),
                                  "LOW": value, "HIGH": ""})
    return {"role_auth_values": role_auth, "user_roles": user_roles}


def _fired(data):
    return {f["check_id"] for f in (ARA(data).run_all_checks() or [])}


RISKS = [(str(r.get("risk_id", "?")), r) for r in ARA.RULESET]


@pytest.mark.parametrize("risk_id, risk", RISKS, ids=[r[0] for r in RISKS])
def test_the_risk_fires_on_the_access_it_says_conflicts(risk_id, risk):
    got = _fired(_grants_for(risk))
    assert "ARA-" + risk_id in got, (
        "risk %s does not fire on a user holding exactly the transactions and "
        "authorization values it declares as its own conflicting functions. "
        "Either the rule is unreachable — it will report nothing on any estate "
        "— or its functions no longer describe the access it is looking for. "
        "Reported instead: %s" % (risk_id, sorted(got) or "nothing"))


def test_every_risk_declares_something_to_match_on():
    """A function with neither an action nor a permission matches nothing, and
    a risk built from one cannot fire however the estate is configured."""
    empty = []
    for risk_id, risk in RISKS:
        for function in (risk.get("functions") or []):
            if not (function.get("actions") or function.get("permissions")):
                empty.append("%s / %s" % (risk_id, function.get("name", "?")))
    assert not empty, "functions with nothing to match on: %s" % empty


def test_a_risk_needs_all_of_its_functions_not_just_one():
    """Segregation of duties is about a COMBINATION. A rule that fires on half
    of itself would report a conflict against every user doing their own job.
    """
    over_eager = []
    for risk_id, risk in RISKS:
        functions = risk.get("functions") or []
        if len(functions) < 2:
            continue                      # critical action/permission, not a pair
        half = dict(risk, functions=functions[:1])
        if "ARA-" + risk_id in _fired(_grants_for(half)):
            over_eager.append(risk_id)
    assert not over_eager, (
        "these risks fire on ONE of their functions alone, so they report a "
        "segregation conflict against a user who has no conflict: %s" % over_eager)
