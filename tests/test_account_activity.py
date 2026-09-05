"""Which findings are about accounts somebody is actually using.

THE PROBLEM. Eight systems produce several thousand findings and every one is
`derived_from_config`: a list of what COULD be abused with nothing saying which
of it is live. SAP_ALL held by somebody who logged on this morning and SAP_ALL
held by an account dormant for a year are the same finding today.

The evidence was already ingested. `logon_events.csv` has decided whether a
graph edge is `used` or merely `configured` since edges landed; this applies the
same evidence to findings, and lets the prioritiser rank on it.

THREE STATES, AND THE THIRD IS WHY THIS IS NOT ONE BOOLEAN:

    active       a named account logged on successfully in the window
    quiet        every named account was covered by the export, none logged on
    unassessed   no logon export, or it covers none of these accounts

`quiet` and `unassessed` render identically in a list and mean opposite things —
a measurement versus the absence of one. Collapsing them lets a missing export
read as a clean bill.

IT RAISES AND NEVER LOWERS, which is the safety property these tests exist to
hold. Boosting what is demonstrably in use is safe; damping what looks quiet is
not, because a 30-day window is one break-glass procedure away from being wrong
and a firefighter account is dormant by design.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server import activity                      # noqa: E402
from server.enrich import enrich                 # noqa: E402


def finding(check_id="USR-002", objects=None, **extra):
    f = {"check_id": check_id, "severity": "CRITICAL", "scope": "aggregate",
         "title": "t", "description": "d", "category": "User & Authorization",
         "affected_objects": objects or []}
    f.update(extra)
    return f


def user(name):
    return {"type": "user", "name": name}


# --------------------------------------------------------------------------- #
#  The three states                                                            #
# --------------------------------------------------------------------------- #

def test_an_account_that_logged_on_is_active():
    got = activity.classify(finding(objects=[user("JSMITH")]),
                            active={"JSMITH"}, observed={"JSMITH", "MWILSON"})
    assert got["state"] == activity.ACTIVE
    assert got["live"] == ["JSMITH"]


def test_an_account_covered_and_silent_is_quiet_not_unassessed():
    got = activity.classify(finding(objects=[user("MWILSON")]),
                            active={"JSMITH"}, observed={"JSMITH", "MWILSON"})
    assert got["state"] == activity.QUIET
    assert got["assessed"] == ["MWILSON"]


def test_an_account_the_export_never_mentions_is_unassessed():
    """A user missing from the logon export is not an inactive user: the export
    may cover a different window, client or population."""
    got = activity.classify(finding(objects=[user("SVC_BATCH")]),
                            active={"JSMITH"}, observed={"JSMITH"})
    assert got["state"] == activity.UNASSESSED
    assert "none of these accounts" in got["reason"]


def test_no_logon_export_at_all_is_unassessed_and_says_so():
    got = activity.classify(finding(objects=[user("JSMITH")]),
                            active=None, observed=None)
    assert got["state"] == activity.UNASSESSED
    assert "no logon export" in got["reason"]


def test_a_finding_about_no_account_gets_no_verdict():
    """A profile-parameter finding has no account for this evidence to be about,
    and stamping it "activity unassessed" would caveat a question never asked."""
    assert activity.classify(
        finding(check_id="PARAM-LOGIN/MIN_PASSWORD_LNG",
                objects=[{"type": "parameter_name", "name": "login/x"}]),
        active={"JSMITH"}, observed={"JSMITH"}) is None


def test_only_abap_accounts_are_judged_by_an_abap_export():
    """`logon_events` is an ABAP export. A HANA database user or a BTP user has
    its own logon story and this file is no evidence about either."""
    assert activity.classify(
        finding(objects=[{"type": "hana_user", "name": "J_SMITH"},
                         {"type": "btp_user", "name": "j@x.com"}]),
        active={"J_SMITH"}, observed={"J_SMITH"}) is None


def test_one_live_account_among_several_makes_the_finding_active():
    got = activity.classify(
        finding(objects=[user("A"), user("B"), user("C")]),
        active={"C"}, observed={"A", "B", "C"})
    assert got["state"] == activity.ACTIVE
    assert got["live"] == ["C"]


# --------------------------------------------------------------------------- #
#  What it does to priority                                                    #
# --------------------------------------------------------------------------- #

def logon(rows):
    return {"logon_events": rows}


def test_an_active_account_raises_the_score():
    f = finding(objects=[user("JSMITH")])
    with_data = enrich([f], "rise_pce", set(),
                       data=logon([{"USERNAME": "JSMITH", "EVENT": "SUCCESS",
                                    "COUNT": "4"}]))
    without = enrich([f], "rise_pce", set(), data=None)
    assert (with_data[id(f)]["priority_score"]
            > without[id(f)]["priority_score"])
    labels = [x["label"] for x in with_data[id(f)]["priority_factors"]]
    assert "Account in use" in labels


def test_a_quiet_account_moves_nothing():
    """THE SAFETY PROPERTY. A 30-day window is one break-glass procedure away
    from being wrong, and a firefighter account is dormant by design."""
    f = finding(objects=[user("MWILSON")])
    quiet = enrich([f], "rise_pce", set(),
                   data=logon([{"USERNAME": "MWILSON", "EVENT": "FAILED",
                                "COUNT": "2"},
                               {"USERNAME": "JSMITH", "EVENT": "SUCCESS",
                                "COUNT": "1"}]))
    none = enrich([f], "rise_pce", set(), data=None)
    assert quiet[id(f)]["priority_score"] == none[id(f)]["priority_score"]
    assert quiet[id(f)]["account_activity"]["state"] == activity.QUIET


def test_an_unassessed_account_moves_nothing():
    """Scoring absence as quiet would turn a missing export into a reassurance."""
    f = finding(objects=[user("SVC_BATCH")])
    got = enrich([f], "rise_pce", set(),
                 data=logon([{"USERNAME": "JSMITH", "EVENT": "SUCCESS",
                              "COUNT": "1"}]))
    none = enrich([f], "rise_pce", set(), data=None)
    assert got[id(f)]["priority_score"] == none[id(f)]["priority_score"]


def test_a_failed_logon_is_not_use():
    """Evidence of an attempt, never of use. Counting it would mark an account
    active on the strength of somebody failing to get in."""
    f = finding(objects=[user("JSMITH")])
    got = enrich([f], "rise_pce", set(),
                 data=logon([{"USERNAME": "JSMITH", "EVENT": "FAILED",
                              "COUNT": "9"}]))
    assert got[id(f)]["account_activity"]["state"] != activity.ACTIVE


def test_enrich_does_not_mutate_the_auditors_finding():
    """`enrich` states this contract in its own docstring — the same objects
    reach the report renderers, and adding keys there has bitten before."""
    f = finding(objects=[user("JSMITH")])
    before = dict(f)
    enrich([f], "rise_pce", set(),
           data=logon([{"USERNAME": "JSMITH", "EVENT": "SUCCESS", "COUNT": "1"}]))
    assert f == before
    assert "account_activity" not in (f.get("details") or {})


def test_the_verdict_is_returned_for_the_console_to_show():
    f = finding(objects=[user("JSMITH")])
    got = enrich([f], "rise_pce", set(),
                 data=logon([{"USERNAME": "JSMITH", "EVENT": "SUCCESS",
                              "COUNT": "1"}]))
    assert got[id(f)]["account_activity"]["state"] == activity.ACTIVE


# --------------------------------------------------------------------------- #
#  The object side: has anything been DONE to the thing                        #
# --------------------------------------------------------------------------- #

def change(cls, oid, who="LWANG", when="20250301", tcode="SU01"):
    return {"OBJECTCLAS": cls, "OBJECTID": oid, "CHANGENR": "1",
            "USERNAME": who, "UDATE": when, "TCODE": tcode}


def role(name):
    return {"type": "role", "name": name}


def test_a_changed_object_is_recognised_and_dated():
    idx = activity._change_index([change("ROLE", "Z_FI_CLERK")])
    got = activity.classify_object(finding(objects=[role("Z_FI_CLERK")]), idx)
    assert got["state"] == activity.CHANGED
    assert got["last_changed"] == "20250301"
    assert got["changed_by"] == "LWANG"
    assert "via SU01" in got["reason"]


def test_it_says_changed_and_never_used():
    """THE CLAIM THIS MUST NOT MAKE. `security_audit_log.csv` is the SAL
    CONFIGURATION — CONFIG_NAME, EVENT_CLASS, ACTIVE — and holds no events, so
    nothing this product ingests evidences that a privilege was exercised. A
    change document says the object was maintained, which is a weaker and
    different claim, and the wording has to stay weaker with it."""
    idx = activity._change_index([change("ROLE", "Z_FI_CLERK")])
    got = activity.classify_object(finding(objects=[role("Z_FI_CLERK")]), idx)
    assert "used" not in got["reason"].lower()
    assert "executed" not in got["reason"].lower()
    assert "changed" in got["reason"]


def test_an_object_with_no_change_recorded_is_quiet():
    idx = activity._change_index([change("ROLE", "Z_OTHER")])
    got = activity.classify_object(finding(objects=[role("Z_FI_CLERK")]), idx)
    assert got["state"] == activity.QUIET


def test_no_change_export_is_unassessed_not_quiet():
    got = activity.classify_object(finding(objects=[role("Z_FI_CLERK")]), None)
    assert got["state"] == activity.UNASSESSED
    assert "no change-document export" in got["reason"]


def test_a_finding_naming_no_changeable_object_gets_no_verdict():
    assert activity.classify_object(
        finding(objects=[{"type": "parameter_name", "name": "login/x"}]),
        activity._change_index([])) is None


def test_the_most_recent_change_is_the_one_reported():
    idx = activity._change_index([
        change("ROLE", "Z_FI_CLERK", who="OLDUSER", when="20240101"),
        change("ROLE", "Z_FI_CLERK", who="NEWUSER", when="20250601")])
    got = activity.classify_object(finding(objects=[role("Z_FI_CLERK")]), idx)
    assert got["changed_by"] == "NEWUSER"
    assert got["last_changed"] == "20250601"


def test_a_change_raises_the_score_by_less_than_a_live_account():
    """A maintained configuration is weaker evidence than an account somebody
    demonstrably logs on with, and the points say so."""
    f_obj = finding(objects=[role("Z_FI_CLERK")])
    f_acct = finding(objects=[user("JSMITH")])
    changed = enrich([f_obj], "rise_pce", set(),
                     data={"change_documents": [change("ROLE", "Z_FI_CLERK")]})
    live = enrich([f_acct], "rise_pce", set(),
                  data=logon([{"USERNAME": "JSMITH", "EVENT": "SUCCESS",
                               "COUNT": "1"}]))
    base = enrich([f_obj], "rise_pce", set(), data=None)
    obj_gain = changed[id(f_obj)]["priority_score"] - base[id(f_obj)]["priority_score"]
    acct_gain = (live[id(f_acct)]["priority_score"]
                 - enrich([f_acct], "rise_pce", set(),
                          data=None)[id(f_acct)]["priority_score"])
    assert 0 < obj_gain < acct_gain, (obj_gain, acct_gain)


def test_a_quiet_object_moves_nothing():
    f = finding(objects=[role("Z_FI_CLERK")])
    quiet = enrich([f], "rise_pce", set(),
                   data={"change_documents": [change("ROLE", "Z_OTHER")]})
    none = enrich([f], "rise_pce", set(), data=None)
    assert quiet[id(f)]["priority_score"] == none[id(f)]["priority_score"]


def test_the_summary_counts_every_state_including_the_absent_one():
    verdicts = [{"state": activity.ACTIVE}, {"state": activity.QUIET}, None]
    assert activity.summarise(verdicts) == {
        activity.ACTIVE: 1, activity.QUIET: 1, activity.UNASSESSED: 0,
        "no_accounts": 1}
