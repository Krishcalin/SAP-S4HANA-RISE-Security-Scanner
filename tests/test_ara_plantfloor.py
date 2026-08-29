"""The plant-floor ARA rules (MFG / INV / QM / PM / PS / WM).

These rules are built from a design-specification object catalogue rather
than the object-by-object web verification the finance rules had, so the
tests carry their verification: each rule is exercised against synthesised
authorization values and must fire for the conflict, stay silent for one
side alone, and stay silent for display-only access.

The last property is the one that matters most. The matcher is fail-closed,
so an inaccurate field name makes a rule quieter — but a rule that fired on
ACTVT 03 would be loudly wrong, and that is what these tests pin.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.access_risk_analysis import AccessRiskAnalysisAuditor as ARA  # noqa: E402


def _auth(role, obj, field, low):
    return {"AGR_NAME": role, "OBJECT": obj, "AUTH": "A1", "FIELD": field,
            "LOW": low, "HIGH": ""}


def _run(rows, user_roles=None):
    data = {"role_auth_values": rows}
    if user_roles:
        data["user_roles"] = user_roles
    a = ARA(data)
    a.run_all_checks()
    return {f["check_id"] for f in a.findings}


def _side(role, tcodes, perms, activity="01"):
    """One role holding a function: its tcodes plus its objects at `activity`."""
    rows = [_auth(role, "S_TCODE", "TCD", t) for t in tcodes]
    for obj in perms:
        rows.append(_auth(role, obj, "ACTVT", activity))
    return rows


#: risk_id -> (function-A tcodes+objects, function-B tcodes+objects, B activity)
CASES = {
    "MFG-01": ((["CS01"], ["C_STUE_BER"]), (["CO01"], ["C_AFKO_AWK"]), "01"),
    "MFG-02": ((["CO11N"], ["C_AFKO_AWK"]), (["MIGO"], ["M_MSEG_BWA"]), "01"),
    "INV-01": ((["MIGO"], ["M_MSEG_BWA"]), (["MI07"], ["M_MSEG_WMB"]), "01"),
    "INV-02": ((["MIGO"], ["M_MSEG_BWA"]), (["MM02"], ["M_MATE_MAR"]), "02"),
    "QM-01": ((["QE51N"], ["Q_INSP_WRK"]), (["QA11"], ["Q_INSP_WRK"]), "02"),
    "QM-02": ((["QA11"], ["Q_INSP_WRK"]), (["QS21"], ["Q_MATERIAL"]), "02"),
    "PM-01": ((["IW31"], ["I_AUART"]), (["IW41"], ["I_IWERK"]), "02"),
    "PS-01": ((["CJ30"], ["C_PRPS_ART"]), (["CJ88"], ["K_ORDER"]), "02"),
    "WM-01": ((["LT01"], ["L_LGNUM"]), (["LT12"], ["L_LGNUM"]), "02"),
}


@pytest.mark.parametrize("rid", sorted(CASES))
def test_each_plant_floor_rule_fires_on_its_conflict(rid):
    (a_t, a_o), (b_t, b_o), b_act = CASES[rid]
    rows = _side("Z_A", a_t, a_o, "01") + _side("Z_B", b_t, b_o, b_act)
    users = [{"UNAME": "U1", "AGR_NAME": "Z_A"}, {"UNAME": "U1", "AGR_NAME": "Z_B"}]
    assert f"ARA-{rid}" in _run(rows, users)


@pytest.mark.parametrize("rid", sorted(CASES))
def test_one_side_alone_is_not_a_conflict(rid):
    (a_t, a_o), _b, _act = CASES[rid]
    rows = _side("Z_A", a_t, a_o, "01")
    users = [{"UNAME": "U1", "AGR_NAME": "Z_A"}]
    assert f"ARA-{rid}" not in _run(rows, users)


@pytest.mark.parametrize("rid", sorted(CASES))
def test_display_only_access_never_fires(rid):
    """ACTVT 03 on both sides — the false-positive class permission-level
    matching exists to suppress. WM-01 keeps its create side at 01 because
    03 would fail the action gate's intent, not the activity check."""
    (a_t, a_o), (b_t, b_o), _act = CASES[rid]
    rows = _side("Z_A", a_t, a_o, "03") + _side("Z_B", b_t, b_o, "03")
    users = [{"UNAME": "U1", "AGR_NAME": "Z_A"}, {"UNAME": "U1", "AGR_NAME": "Z_B"}]
    assert f"ARA-{rid}" not in _run(rows, users)


def test_plant_floor_rules_declare_their_provenance():
    """The finance rules were verified object by object; these were not.
    Every plant-floor entry must say so in-band, so a reader of the ruleset
    cannot mistake the two tiers."""
    plant = [r for r in ARA.RULESET
             if r["process"] in {"MFG", "INV", "QM", "PM", "PS", "WM"}]
    # Batch 2 took the operational tier from 9 rules to 25.
    assert len(plant) == 25
    for r in plant:
        assert r.get("provenance"), f"{r['risk_id']} has no provenance note"
        assert r.get("references"), r["risk_id"]
        assert r.get("rationale"), r["risk_id"]


def test_risk_ids_stay_unique_across_the_whole_library():
    ids = [r["risk_id"] for r in ARA.RULESET]
    assert len(ids) == len(set(ids))
