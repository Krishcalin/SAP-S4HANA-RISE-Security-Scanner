"""Who can WRITE a security policy — the forward half of SECPOL-001.

SECPOL-001 reports that a policy is set weaker than the instance parameter it
overrides. It says nothing about who put it that way, or who can do it again
once it is corrected. Those are the same question asked forward instead of
backward, and a policy corrected today stays corrected only until the next
holder of S_SECPOL decides otherwise.

Transaction SECPOL is guarded by two objects, and they are two different
powers: S_SECPOL is checked during maintenance of the policies themselves,
S_SECPOL_A governs the values a policy's attributes may be assigned.

THE RISE ASYMMETRY IS THE POINT. `data/rise_reachability.json` records that the
login/* parameters a policy overrides are `read_only` under RISE — SAP operates
parameter maintenance, so the customer cannot raise login/min_password_lng
without a service request. Security policies are the customer's own. A holder of
S_SECPOL can therefore lower, for the users they choose, a control they are not
permitted to raise.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.security_params import SecurityParamAuditor                # noqa: E402


def fired(auth_objects):
    return {f["check_id"]: f for f in
            SecurityParamAuditor({"auth_objects": auth_objects}).run_all_checks()}


def grant(user, obj, actvt="02"):
    return {"UNAME": user, "OBJECT": obj, "FIELD": "ACTVT", "VALUE": actvt}


# ── the two objects, and what each one is ──────────────────────────────────

@pytest.mark.parametrize("obj, phrase", [
    ("S_SECPOL", "maintain the security policies themselves"),
    ("S_SECPOL_A", "define the values a policy attribute may be assigned"),
])
def test_each_object_is_reported_with_what_it_actually_confers(obj, phrase):
    """Two objects because they are two powers: writing a policy, and deciding
    what a policy is allowed to say. A finding naming only the object leaves
    the reader to look that up."""
    finding = fired([grant("LWANG", obj)])["SECPOL-004"]
    assert finding["severity"] == "HIGH"
    item, = finding["affected_items"]
    assert obj in item and phrase in item


@pytest.mark.parametrize("actvt", ["01", "02", "06", "07", "*"])
def test_any_activity_that_writes_is_reported(actvt):
    assert "SECPOL-004" in fired([grant("LWANG", "S_SECPOL", actvt)])


def test_display_only_is_not_the_finding():
    """Reading the policy list is not the power this is about. Reporting a
    display-only auditor beside somebody who can rewrite the password rules
    would flatten the distinction the finding exists to draw."""
    assert "SECPOL-004" not in fired([grant("AUDITOR", "S_SECPOL", "03")])


def test_a_display_holder_is_left_out_of_a_finding_others_trigger():
    finding = fired([grant("LWANG", "S_SECPOL", "02"),
                     grant("AUDITOR", "S_SECPOL", "03")])["SECPOL-004"]
    assert any("LWANG" in i for i in finding["affected_items"])
    assert not any("AUDITOR" in i for i in finding["affected_items"])


def test_an_unstated_activity_is_reported_rather_than_assumed_harmless():
    """A grant of the object whose activity the export does not carry is a
    grant this scan could not narrow. Treating it as display-only would be
    inventing the reassuring half."""
    item, = fired([{"UNAME": "LWANG", "OBJECT": "S_SECPOL"}]
                  )["SECPOL-004"]["affected_items"]
    assert "not stated" in item


def test_another_authorization_object_is_not_this_finding():
    assert "SECPOL-004" not in fired([grant("LWANG", "S_TABU_DIS", "02")])


def test_no_authorization_export_stays_silent():
    assert "SECPOL-004" not in fired([])


def test_both_objects_and_several_holders_roll_into_one_finding():
    """Removing one administrator must shrink the finding, not retire it and
    restart the age of the rest."""
    finding = fired([grant("LWANG", "S_SECPOL", "02"),
                     grant("MWILSON", "S_SECPOL_A", "01"),
                     grant("JSMITH", "S_SECPOL", "*")])["SECPOL-004"]
    assert finding["scope"] == "aggregate"
    assert len(finding["affected_items"]) == 3
    assert finding["details"]["holders"] == 3


# ── the pair, and why it is a pair ─────────────────────────────────────────

def test_it_names_the_finding_it_is_the_other_half_of():
    """A reader who has just actioned SECPOL-001 needs to know this exists, or
    they will correct the policy and leave its authorship open."""
    finding = fired([grant("LWANG", "S_SECPOL")])["SECPOL-004"]
    assert "SECPOL-001" in finding["description"]


def test_it_states_the_rise_asymmetry():
    """The customer cannot raise the parameter and can lower the policy. That
    is the sentence that makes this worth reading, and it is recorded in
    rise_reachability rather than invented here."""
    finding = fired([grant("LWANG", "S_SECPOL")])["SECPOL-004"]
    assert "RISE" in finding["description"]
    assert "service request" in finding["description"]


def test_the_object_set_is_exactly_the_two_sap_names():
    """A third object added here without a source is the failure this product
    keeps guarding against."""
    assert set(SecurityParamAuditor.SECPOL_ADMIN_OBJECTS) == {
        "S_SECPOL", "S_SECPOL_A"}


def test_display_activity_is_absent_from_the_write_set():
    assert "03" not in SecurityParamAuditor.SECPOL_WRITE_ACTIVITIES
