"""Parameters SAP states as a RANGE, and the value that switches the control off.

FOUR CHECKS PASSED A DISABLED CONTROL AND CALLED IT COMPLIANT.

SAP Security Baseline v2.6 writes several parameters as "between N and M" —
PWDPOL-A c) is "login/password_expiration_time between 1 and 183". This
repository encoded those as a single `<=` comparison, which is correct at the top
end and silently wrong at the bottom, because in every one of these parameters
**0 does not mean "very strict", it means OFF**:

    login/password_expiration_time = 0   passwords never expire
    login/password_max_idle_initial = 0  initial passwords never expire
    login/fails_to_user_lock = 0         the account never locks
    login/fails_to_session_end = 0       the session is never ended

All four evaluated `0 <= n` as True and produced no finding. A customer whose
password expiry was switched off entirely read a clean report — and the
`login/fails_to_user_lock` rule's own remediation text already said "and not 0",
so the intent was right and the operator could not express it.

The same `<=` also raised findings against values SAP explicitly permits: 180 is
a normal expiry and was reported non-compliant against a hard-coded 90.

`between` exists so the requirement can be written the way SAP states it. This
file fails if any of the four regress, and — more usefully — if a NEW rule is
added to a zero-disables parameter using a one-sided operator.
"""

import pytest

from modules.security_params import SecurityParamAuditor

#: Parameters where 0 (or an absent lower bound) turns the control OFF rather
#: than making it stricter. A one-sided `<=` on any of these is the defect.
ZERO_DISABLES = {
    "login/password_expiration_time": "passwords never expire",
    "login/password_max_idle_initial": "initial passwords never expire",
    "login/password_max_idle_productive": "unused productive passwords never expire",
    "login/fails_to_user_lock": "the account never locks",
    "login/fails_to_session_end": "the session is never ended",
    "rdisp/gui_auto_logout": "no automatic logout",
}


def _rules():
    """Every rule table this module ships, flattened to (name, rule)."""
    found = {}
    for attr in dir(SecurityParamAuditor):
        value = getattr(SecurityParamAuditor, attr, None)
        if isinstance(value, dict):
            for name, rule in value.items():
                if isinstance(rule, dict) and "op" in rule:
                    found.setdefault(name, []).append(rule)
    return found


def _evaluate(actual, expected, op):
    return SecurityParamAuditor._evaluate_rule(actual, expected, op)


# ── the operator itself ─────────────────────────────────────────────────────
def test_between_is_a_known_operator():
    """An unknown operator returns True — "no finding" — by deliberate design.
    So a typo'd `between` would not error; it would silently stop checking."""
    assert "between" in SecurityParamAuditor._KNOWN_OPS


@pytest.mark.parametrize(
    "value,expected,ok",
    [
        ("0", "1-183", False),   # the defect: OFF must not pass
        ("1", "1-183", True),
        ("90", "1-183", True),
        ("180", "1-183", True),  # SAP-permitted, previously a false positive
        ("183", "1-183", True),
        ("184", "1-183", False),
        ("365", "1-183", False),
    ],
)
def test_between_checks_both_ends(value, expected, ok):
    assert _evaluate(value, expected, "between") is ok


def test_a_non_numeric_value_is_a_finding_not_a_crash():
    """A parameter that cannot satisfy the comparison is a real answer about the
    system. The evaluator's docstring makes this the one case where the wrong
    shape IS the finding."""
    assert _evaluate("ALL", "1-183", "between") is False
    assert _evaluate("", "1-183", "between") is False


# ── the four defects ────────────────────────────────────────────────────────
@pytest.mark.parametrize("param", sorted(ZERO_DISABLES))
def test_a_zero_disabling_parameter_never_uses_a_one_sided_upper_bound(param):
    """THE REGRESSION GUARD. `<=` on any of these accepts the value that turns
    the control off, and it does so silently — the report is clean."""
    for rule in _rules().get(param, []):
        op = rule.get("op")
        if op != "<=":
            continue
        expected = rule.get("expected", "")
        assert not _evaluate("0", expected, op), (
            f"{param} uses `<= {expected}`, so a value of 0 passes and "
            f"{ZERO_DISABLES[param]}. State SAP's range with `between`."
        )


@pytest.mark.parametrize(
    "param",
    [
        "login/password_expiration_time",
        "login/password_max_idle_initial",
        "login/fails_to_user_lock",
        "login/fails_to_session_end",
    ],
)
def test_the_four_corrected_rules_refuse_a_disabled_control(param):
    rules = _rules().get(param, [])
    assert rules, f"{param} is no longer checked at all"
    ranged = [r for r in rules if r.get("op") == "between"]
    assert ranged, f"{param} lost its range rule and can accept 0 again"
    for rule in ranged:
        assert not _evaluate("0", rule["expected"], "between")
        low = rule["expected"].split("-")[0]
        assert _evaluate(low, rule["expected"], "between"), (
            f"{param}'s own lower bound does not satisfy its rule"
        )


def test_password_expiry_matches_the_range_sap_states():
    """PWDPOL-A c) is "between 1 and 183". The previous hard-coded 90 reported
    a compliant 180-day expiry as a finding, which is a false positive against
    SAP's own baseline."""
    rules = [r for r in _rules()["login/password_expiration_time"] if r.get("op") == "between"]
    assert any(r["expected"] == "1-183" for r in rules)


def test_initial_password_expiry_matches_the_range_sap_states():
    """PWDPOL-A b) is "between 1 and 14", recommending 7."""
    rules = [r for r in _rules()["login/password_max_idle_initial"] if r.get("op") == "between"]
    assert any(r["expected"] == "1-14" for r in rules)
