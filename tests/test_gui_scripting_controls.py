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

CONTROLS = [name for name, _hardened, _why
            in BaselineParamAuditor.GUI_SCRIPTING_CONTROLS]


def fired(params):
    rows = [{"PARAMETER": k, "VALUE": v} for k, v in params.items()]
    return {f["check_id"]: f
            for f in BaselineParamAuditor({"security_params": rows}).run_all_checks()}


def scripting(on=True, **controls):
    params = {"sapgui/user_scripting": "TRUE" if on else "FALSE"}
    params.update(controls)
    return params


HARDENED = {"sapgui/user_scripting_force_notification": "TRUE",
            "sapgui/user_scripting_disable_recording": "TRUE",
            "sapgui/user_scripting_per_user": "TRUE",
            "sapgui/nwbc_scripting": "FALSE"}


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


@pytest.mark.parametrize("name, hardened_truthy, _why",
                         BaselineParamAuditor.GUI_SCRIPTING_CONTROLS,
                         ids=[c[0] for c in BaselineParamAuditor.GUI_SCRIPTING_CONTROLS])
def test_each_control_is_reported_on_its_own(name, hardened_truthy, _why):
    """One wrong control is enough, and the finding names that one."""
    wrong = "FALSE" if hardened_truthy else "TRUE"
    params = scripting(**dict(HARDENED, **{name: wrong}))
    finding = fired(params)["BASELINE-004B"]
    assert finding["severity"] == "HIGH"
    assert [i for i in finding["affected_items"] if i.startswith(name)]
    assert len(finding["affected_items"]) == 1, (
        "the other three are hardened and must not be listed")


def test_the_direction_is_not_uniform():
    """Three of these are hardened when TRUE and nwbc_scripting when FALSE.
    A check that applied one direction to all four would report a correctly
    configured system."""
    truthy = {n for n, h, _ in BaselineParamAuditor.GUI_SCRIPTING_CONTROLS if h}
    falsy = {n for n, h, _ in BaselineParamAuditor.GUI_SCRIPTING_CONTROLS if not h}
    assert truthy and falsy
    assert "sapgui/nwbc_scripting" in falsy


# ── the gap that was recorded rather than guessed ──────────────────────────

def test_the_unsourced_parameters_are_named_and_not_checked():
    """SAP's baseline names dynp/checkskip1screen and dynp/confirmskip1screen
    under USRCTR-A, which is good provenance for them MATTERING. It does not
    give the required value, and nothing else in this repository does — the
    predicates live in the policy XML inside SAP's baseline archive, which this
    repository pins the state of without vendoring.

    Guessing the value is the failure this product exists to avoid. The gap is
    recorded in the module so somebody can close it, rather than left looking
    like coverage.
    """
    unsourced = BaselineParamAuditor._UNSOURCED_USER_CONTROL_PARAMS
    assert "dynp/checkskip1screen" in unsourced
    assert "dynp/confirmskip1screen" in unsourced
    for name in unsourced:
        assert name not in CONTROLS, (
            "%s moved into a checked set without its predicate being sourced"
            % name)
        # And no rule anywhere silently started asserting a value for it.
        got = fired({name: "OFF", "sapgui/user_scripting": "FALSE"})
        assert not [c for c in got if name in str(got[c].get("affected_items"))], (
            "something now reports on %s; if its predicate has been sourced, "
            "move it out of _UNSOURCED_USER_CONTROL_PARAMS and delete this "
            "branch of the test" % name)
