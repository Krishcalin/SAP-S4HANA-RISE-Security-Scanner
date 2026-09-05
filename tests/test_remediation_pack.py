"""The change itself, for a finding the customer is able to make.

The product finds a problem, ranks it, explains the ranking and names the export
that would find more — then hands over prose. For a profile parameter it already
knows the name, the current value, the required value and the Note that mandates
it: everything an operator retypes by hand into RZ10 from a screen that could
have written it.

    apply    : login/min_password_lng = 15
    rollback : login/min_password_lng = 6

WHAT IT MUST NEVER DO, and what these tests are mostly about.

It must never emit a change the customer cannot apply. Under a RISE contract the
profile parameters are SAP's, and an RZ10 line is worse than nothing there —
`server/servicerequest.py` already drafts the right artefact, so this defers to
it and says so.

It must never emit a rule where a value goes. `expected_value` on a real finding
reads "15 (SAP standard) or one of: >=15"; `ecs_standard` reads "15". Pasting
the first into a profile puts a sentence where a number belongs, and this text
is meant to be APPLIED rather than read, so the bar is higher than for prose.

It must never claim anything was done. This product holds no connection to SAP.

TWO BUGS THESE TESTS EXIST BECAUSE OF, both found by running real findings
through the first draft rather than by reading it. The owner constant is
`customer_fixable` and I had guessed "customer", so every pack came back
inapplicable and looked like correct RISE behaviour. And `expected_value` is
prose, which would have produced an unusable apply line on any finding where
`ecs_standard` happened to be absent.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server import remediation  # noqa: E402


def finding(check_id="PARAM-LOGIN/MIN_PASSWORD_LNG",
            owner="customer_fixable", sid="OPD", **detail):
    base = {"parameter": "login/min_password_lng", "current_value": "6",
            "ecs_standard": "15",
            "expected_value": "15 (SAP standard) or one of: >=15",
            "baseline_source": "SAP Note 3250501"}
    base.update(detail)
    return {"check_id": check_id, "remediation_owner": owner, "sid": sid,
            "latest_details": base}


# --------------------------------------------------------------------------- #
#  The change                                                                  #
# --------------------------------------------------------------------------- #

def test_it_writes_the_line_an_operator_would_type():
    pack = remediation.pack(finding())
    assert pack["applicable"] is True
    assert pack["apply"] == ["login/min_password_lng = 15"]
    assert "RZ10" in pack["where"] and "OPD" in pack["where"]


def test_the_rollback_is_the_value_that_was_observed():
    """Not a guess at the SAP default: restoring what SAP ships is a different
    change from undoing this one."""
    pack = remediation.pack(finding(current_value="6"))
    assert pack["rollback"] == ["login/min_password_lng = 6"]


def test_an_unset_parameter_rolls_back_to_something_readable():
    """An empty value IS a value — `gw/sec_info` unset is the finding — and a
    blank in a change request reads as a broken tool."""
    pack = remediation.pack(finding(parameter="gw/sec_info", current_value="",
                                    ecs_standard="/usr/sap/PRD/secinfo"))
    assert pack["rollback"] == ["gw/sec_info = (not set)"]


def test_it_says_how_to_confirm_the_fix_worked():
    pack = remediation.pack(finding())
    assert "Re-run the scan" in pack["verify"]
    assert "PARAM-LOGIN/MIN_PASSWORD_LNG" in pack["verify"]


def test_it_never_claims_to_have_changed_anything():
    """This product holds no connection to SAP and never will."""
    pack = remediation.pack(finding())
    text = " ".join(pack["caveats"]).lower()
    assert "has changed nothing" in text
    assert "change control" in text


def test_it_carries_the_authority_for_the_value():
    pack = remediation.pack(finding())
    assert pack["source"] == "SAP Note 3250501"


# --------------------------------------------------------------------------- #
#  What it refuses                                                             #
# --------------------------------------------------------------------------- #

def test_a_parameter_sap_operates_is_deferred_not_drafted():
    """THE FIRST BUG THIS FILE EXISTS FOR, from the other direction. Under RISE
    the parameters are SAP's, and `servicerequest` already drafts the right
    artefact — an RZ10 line the customer cannot apply is worse than none."""
    pack = remediation.pack(finding(owner="ticket_to_sap"))
    assert pack["applicable"] is False
    assert pack["apply"] == [] and pack["rollback"] == []
    assert "service request" in pack["why"]


def test_the_customer_owner_value_is_the_one_the_product_actually_uses():
    """The first draft guessed "customer". The real value is `customer_fixable`,
    every pack came back inapplicable, and it looked exactly like correct RISE
    behaviour until real findings went through it."""
    assert remediation.pack(finding(owner="customer_fixable"))["applicable"]
    assert remediation._CUSTOMER_FIXABLE == "customer_fixable"


def test_a_rule_is_not_written_as_a_value():
    """`expected_value` reads "15 (SAP standard) or one of: >=15". Pasted into a
    profile that is a sentence where a number goes — and this text is meant to
    be applied, not read."""
    pack = remediation.pack(finding(ecs_standard=None))
    assert pack["applicable"] is False
    assert pack["apply"] == []
    assert "rather than a single value" in pack["why"]


def test_what_counts_as_a_value():
    assert remediation._is_a_value("15")
    assert remediation._is_a_value("/usr/sap/PRD/secinfo")
    assert remediation._is_a_value("X")
    assert not remediation._is_a_value(">=15")
    assert not remediation._is_a_value("15 (SAP standard) or one of: >=15")
    assert not remediation._is_a_value("A, B")
    assert not remediation._is_a_value("")


def test_a_finding_with_no_required_value_produces_nothing():
    """None, never a half-filled template: a change request with a blank where
    the number goes gets sent anyway."""
    assert remediation.pack(
        finding(ecs_standard=None, expected_value=None)) is None


def test_a_check_this_cannot_write_a_change_for_returns_nothing():
    """Most of the catalogue, honestly. A role change needs the authorisation
    object, field and value to be safe; a REVOKE needs the grantee-privilege
    pairing. Neither is guessed at."""
    assert remediation.pack(finding(check_id="AUTH-002")) is None
    assert remediation.pack(finding(check_id="HANADB-PRIV-002")) is None
