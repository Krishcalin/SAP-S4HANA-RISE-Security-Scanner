"""BASELINE-004 gave advice about four parameters nothing then looked at.

Its remediation has always read "if enabled, restrict via
sapgui/user_scripting_per_user and disable notification suppression" — advice
about other parameters that no check in this product read. A system that took
the advice and a system that ignored it produced the same report.

These four are here and `dynp/checkskip1screen` is not, and the difference is
provenance. Every direction below is read off the parameter's own name:
"force_notification" on is hardened, "disable_recording" on is hardened, a
scripting switch off is hardened. The required VALUE of the dynp pair is not in
this repository — see `_UNSOURCED_USER_CONTROL_PARAMS` in the module, which
records the gap rather than guessing at it.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.baseline_params import BaselineParamAuditor                # noqa: E402

CONTROLS = [row[0] for row in BaselineParamAuditor.GUI_SCRIPTING_CONTROLS]


def fired(params):
    rows = [{"PARAMETER": k, "VALUE": v} for k, v in params.items()]
    return {f["check_id"]: f
            for f in BaselineParamAuditor({"security_params": rows}).run_all_checks()}


def scripting(on=True, **controls):
    params = {"sapgui/user_scripting": "TRUE" if on else "FALSE"}
    params.update(controls)
    return params


#: Derived from the control set rather than restated, so a control added to
#: the module cannot silently drop out of the "everything hardened" case.
HARDENED = {name: ("TRUE" if hardened else "FALSE")
            for name, hardened, _item, _why
            in BaselineParamAuditor.GUI_SCRIPTING_CONTROLS}


# ── the feature switch decides whether any of this matters ─────────────────

def test_scripting_switched_off_reports_nothing_about_its_controls():
    """These parameters govern how scripting behaves. With the API disabled
    they decide nothing, and four findings on every such system would be noise
    on the majority to describe the minority."""
    got = fired(scripting(on=False))
    assert "BASELINE-004B" not in got
    assert "BASELINE-004" not in got


def test_scripting_on_with_every_control_hardened_is_silent():
    """Taking BASELINE-004's advice must be visible. Before this check, a
    system that did and one that did not looked identical."""
    got = fired(scripting(**HARDENED))
    assert "BASELINE-004B" not in got
    assert "BASELINE-004" in got, "scripting is still on; that finding stands"


def test_scripting_on_with_the_controls_weak_is_high():
    weak = {k: ("FALSE" if v == "TRUE" else "TRUE") for k, v in HARDENED.items()}
    got = fired(scripting(**weak))
    assert got["BASELINE-004B"]["severity"] == "HIGH"
    assert len(got["BASELINE-004B"]["affected_items"]) == len(CONTROLS)


# ── read versus inferred ───────────────────────────────────────────────────

def test_an_unread_control_is_not_reported_as_disabled():
    """Three of these four default to the less protective value, so "not set"
    is genuinely bad news — but it is news this scan INFERRED rather than read,
    and the finding says which it is doing."""
    got = fired(scripting())
    finding = got["BASELINE-004B"]
    assert finding["severity"] == "MEDIUM", (
        "an unread control must not carry the same weight as one read and "
        "found wrong")
    assert all("not in the export" in i for i in finding["affected_items"])


def test_a_control_read_and_wrong_outranks_one_merely_unread():
    got = fired(scripting(**{"sapgui/user_scripting_force_notification": "FALSE"}))
    finding = got["BASELINE-004B"]
    assert finding["severity"] == "HIGH"
    assert any("= FALSE" in i for i in finding["affected_items"])
    assert any("not in the export" in i for i in finding["affected_items"])


@pytest.mark.parametrize("name, hardened_truthy, _item, _why",
                         BaselineParamAuditor.GUI_SCRIPTING_CONTROLS,
                         ids=[c[0] for c in BaselineParamAuditor.GUI_SCRIPTING_CONTROLS])
def test_each_control_is_reported_on_its_own(name, hardened_truthy, _item, _why):
    """One wrong control is enough, and the finding names that one."""
    wrong = "FALSE" if hardened_truthy else "TRUE"
    params = scripting(**dict(HARDENED, **{name: wrong}))
    finding = fired(params)["BASELINE-004B"]
    assert finding["severity"] == "HIGH"
    assert [i for i in finding["affected_items"] if i.startswith(name)]
    assert len(finding["affected_items"]) == 1, (
        "the others are hardened and must not be listed")


def test_the_direction_is_not_uniform():
    """Most are hardened when TRUE and nwbc_scripting when FALSE. A check that
    applied one direction to all of them would report a correctly configured
    system, and SAP's own policy states the directions separately."""
    truthy = {r[0] for r in BaselineParamAuditor.GUI_SCRIPTING_CONTROLS if r[1]}
    falsy = {r[0] for r in BaselineParamAuditor.GUI_SCRIPTING_CONTROLS if not r[1]}
    assert truthy and falsy
    assert "sapgui/nwbc_scripting" in falsy


# ── the gap that was recorded, and then closed by sourcing it ─────────────

SOURCED = {
    "dynp/checkskip1screen": ("ALL", "USRCTR-A_a.1"),
    "dynp/confirmskip1screen": ("ALL", "USRCTR-A_a.2"),
}


@pytest.mark.parametrize("name, expected_and_item", sorted(SOURCED.items()))
def test_the_recorded_gap_was_closed_by_reading_sap_not_by_guessing(
        name, expected_and_item):
    """These two were held out of every check with the reason written down:
    SAP's baseline named them, nothing here had their required VALUE, and
    guessing is the failure this product exists to avoid.

    The value came from SAP's own policy XML in the end —
    SAP-samples/frun-csa-policies-best-practices, Apache-2.0 and public, the
    same repository `data/sap_baseline_requirements.json` is derived from.

    AND THE GUESS WOULD HAVE BEEN WRONG. Every instinct said these were
    booleans and that ON was the hardened state. SAP's compliant value is
    `ALL`. A rule written on the instinct would have reported a correctly
    configured system as non-compliant, quietly, on every estate.
    """
    from modules.security_params import SecurityParamAuditor
    expected, item = expected_and_item
    rule = SecurityParamAuditor({}).effective_rules()[name]
    assert rule["expected"] == expected
    assert rule["op"] == "=="
    assert any(item in ref for ref in rule["refs"]), (
        "the rule must cite the SAP check item its value came from, so the "
        "next reader can tell a transcription from a judgement")


def test_no_scripting_control_is_asserted_without_a_sap_check_item():
    """Same rule for the set BASELINE-004B reads. The first version derived
    each direction from the parameter's name; that was right, and "turned out
    to be right" is not a provenance."""
    for name, _hardened, item, _buys in BaselineParamAuditor.GUI_SCRIPTING_CONTROLS:
        assert item.startswith("SCRIPT-A_"), (
            "%s carries no SAP check item id" % name)
