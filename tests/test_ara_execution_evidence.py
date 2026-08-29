"""Holding a conflict and having used it are different claims.

Change documents answer part of the second one: CDHDR records which user changed
which object under which transaction, on which date.

THE ASYMMETRY IS THE POINT, and most of this file pins it. Evidence of
performance raises severity by one level; absence of evidence lowers nothing,
because this log cannot support the negative — change documents exist only where
change logging is on, display actions leave none at all, and anything before the
window is invisible. A tool that quietly downgrades every unexercised conflict is
optimising the axis SAP's own ruleset guidance warns against, and its clean
results become indistinguishable from unasked questions.

The sharper finding came out of the sample estate rather than the design: LWANG
is recorded running SU01 and PFCG — both halves of BASIS-01 — while holding no
AGR_1251 rows at all. The log says it happened and the snapshot cannot explain
how. `ARA-DIDDO-001` reports that, and the last group of tests pins it.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.access_risk_analysis import AccessRiskAnalysisAuditor as ARA  # noqa: E402

RISK = [{
    "risk_id": "ZX-01", "name": "vendor create vs pay", "description": "d",
    "risk_type": "SOD", "severity": "MEDIUM", "process": "P2P",
    "functions": [{"name": "Create vendor", "actions": ["FK01"], "permissions": []},
                  {"name": "Pay vendor", "actions": ["F110"], "permissions": []}]}]


def auth(role, obj, field, low):
    return {"AGR_NAME": role, "OBJECT": obj, "AUTH": "A1", "FIELD": field,
            "LOW": low, "HIGH": ""}


def cd(user, tcode, date="20250301"):
    return {"OBJECTCLAS": "VENDOR", "OBJECTID": "V1", "CHANGENR": "1",
            "USERNAME": user, "UDATE": date, "TCODE": tcode}


#: One user holding both halves, via one role.
HOLDER = {"role_auth_values": [auth("Z_BOTH", "S_TCODE", "TCD", "FK01"),
                               auth("Z_BOTH", "S_TCODE", "TCD", "F110")],
          "user_roles": [{"UNAME": "MJONES", "AGR_NAME": "Z_BOTH"}]}


def run(extra=None, ruleset=RISK):
    data = dict(HOLDER)
    if extra:
        data = dict(data, **extra)
    a = ARA(data)
    a.RULESET = ruleset
    a.run_all_checks()
    return {f["check_id"]: f for f in a.findings}


# ── evidence raises ────────────────────────────────────────────────────────

def test_a_conflict_with_evidence_of_both_halves_is_raised_one_level():
    f = run({"change_documents": [cd("MJONES", "FK01"), cd("MJONES", "F110")]})
    assert f["ARA-ZX-01"]["severity"] == "HIGH"          # declared MEDIUM
    assert f["ARA-ZX-01"]["details"]["realised_by"] == ["MJONES"]
    assert f["ARA-ZX-01"]["details"]["evidence_state"] == "realised"


def test_the_description_says_it_was_exercised_not_merely_held():
    f = run({"change_documents": [cd("MJONES", "FK01"), cd("MJONES", "F110")]})
    assert "EXERCISED both sides" in f["ARA-ZX-01"]["description"]


def test_one_half_alone_is_not_a_realised_conflict():
    """Performing one side of a segregation pair is ordinary work."""
    f = run({"change_documents": [cd("MJONES", "FK01")]})
    assert f["ARA-ZX-01"]["severity"] == "MEDIUM"
    assert f["ARA-ZX-01"]["details"]["realised_by"] == []


# ── and absence lowers nothing ─────────────────────────────────────────────

def test_no_evidence_does_not_reduce_the_severity():
    """THE asymmetry. A log that records nothing about this user is not a
    statement that nothing happened."""
    f = run({"change_documents": [cd("SOMEONE_ELSE", "FK01")]})
    assert f["ARA-ZX-01"]["severity"] == "MEDIUM"


def test_no_evidence_says_so_and_says_why_the_silence_is_weak():
    f = run({"change_documents": [cd("SOMEONE_ELSE", "FK01")]})
    d = f["ARA-ZX-01"]["description"]
    assert "That is not evidence they did not" in d
    assert "display actions leave none at all" in d
    assert "unchanged, not reduced" in d


def test_the_three_states_are_distinguishable():
    """"nobody did it" and "we could not look" must never render alike."""
    assert run()["ARA-ZX-01"]["details"]["evidence_state"] == "unmeasured"
    assert run({"change_documents": [cd("SOMEONE_ELSE", "FK01")]}
               )["ARA-ZX-01"]["details"]["evidence_state"] == "no_evidence_in_window"
    assert run({"change_documents": [cd("MJONES", "FK01"), cd("MJONES", "F110")]}
               )["ARA-ZX-01"]["details"]["evidence_state"] == "realised"


def test_with_no_execution_export_nothing_is_claimed_either_way():
    f = run()
    assert "EXERCISED" not in f["ARA-ZX-01"]["description"]
    assert "not evidence they did not" not in f["ARA-ZX-01"]["description"]


def test_the_window_is_published_so_a_silence_can_be_weighed():
    f = run({"change_documents": [cd("SOMEONE_ELSE", "FK01", "20250101"),
                                  cd("SOMEONE_ELSE", "F110", "20250630")]})
    assert f["ARA-ZX-01"]["details"]["evidence_window"] == "20250101 to 20250630"


# ── the log contradicting the snapshot ─────────────────────────────────────

def test_a_user_who_exercised_both_halves_without_holding_them_is_reported():
    """THE finding the sample estate produced. The conflict is evidenced and the
    access that allowed it is not visible."""
    f = run({"change_documents": [cd("LWANG", "FK01"), cd("LWANG", "F110")],
             "user_roles": HOLDER["user_roles"] + [
                 {"UNAME": "LWANG", "AGR_NAME": "Z_EMPTY"}]})
    assert "ARA-DIDDO-001" in f
    assert f["ARA-DIDDO-001"]["details"]["users"] == ["LWANG"]
    assert f["ARA-DIDDO-001"]["severity"] == "HIGH"


def test_it_distinguishes_a_missing_export_from_withdrawn_access():
    """A user with no authorization rows at all points at an incomplete export;
    the check says which reading the data favours without asserting it."""
    f = run({"change_documents": [cd("LWANG", "FK01"), cd("LWANG", "F110")],
             "user_roles": HOLDER["user_roles"] + [
                 {"UNAME": "LWANG", "AGR_NAME": "Z_EMPTY"}]})
    assert f["ARA-DIDDO-001"]["details"]["users_with_no_authorization_rows"] == ["LWANG"]
    assert "points at the first reading" in f["ARA-DIDDO-001"]["description"]


def test_neither_reading_is_asserted_as_fact():
    """Access withdrawn after use is a GOOD outcome and fits the same evidence.
    The check must not call it an incident."""
    f = run({"change_documents": [cd("LWANG", "FK01"), cd("LWANG", "F110")],
             "user_roles": HOLDER["user_roles"] + [
                 {"UNAME": "LWANG", "AGR_NAME": "Z_EMPTY"}]})
    d = f["ARA-DIDDO-001"]["description"]
    assert "does not choose between them" in d
    assert "withdrawn after it was used" in d


def test_a_user_who_holds_the_conflict_is_not_also_reported_as_unexplained():
    """They are already reported, with the severity raised. Reporting them twice
    would double-count the same exposure."""
    f = run({"change_documents": [cd("MJONES", "FK01"), cd("MJONES", "F110")]})
    assert "ARA-DIDDO-001" not in f


def test_exercising_one_half_without_holding_it_is_not_reported():
    """Not a conflict, and the export gap it might imply is out of scope here."""
    f = run({"change_documents": [cd("LWANG", "FK01")],
             "user_roles": HOLDER["user_roles"] + [
                 {"UNAME": "LWANG", "AGR_NAME": "Z_EMPTY"}]})
    assert "ARA-DIDDO-001" not in f


def test_nothing_is_claimed_without_an_execution_export():
    assert "ARA-DIDDO-001" not in run()


def test_the_fiori_evidence_gap_is_stated_where_a_fiori_surface_exists():
    """A limit a reader has to discover is not a stated limit. The launchpad
    usage export is aggregate and carries no user column, so it can evidence
    nobody — on an estate that publishes Fiori, the finding says so."""
    f = run({"change_documents": [cd("SOMEONE_ELSE", "FK01")],
             "fiori_tiles": [{"APP_ID": "F0733", "ODATA_SERVICE": "API_X",
                              "ROLE": "Z_OTHER"}]})
    assert "would leave no trace here either" in f["ARA-ZX-01"]["description"]


def test_a_classic_estate_is_not_told_about_a_surface_it_does_not_have():
    f = run({"change_documents": [cd("SOMEONE_ELSE", "FK01")]})
    assert "leave no trace here either" not in f["ARA-ZX-01"]["description"]
