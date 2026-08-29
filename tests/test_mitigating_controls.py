"""A mitigating control is a row; a compensating control is a conclusion.

Nothing makes the former produce the latter, and this module used to behave as
though it did. A conflict every one of whose holders carried a mitigation row
returned early and emitted NOTHING — it left the report entirely on the strength
of a line in a CSV, and no other output mentioned that it had.

PCAOB AS 2201 §.68 requires a compensating control to "operate at a level of
precision that would prevent or detect a misstatement that could be material".
A row asserts nothing about precision, about whether anybody performs the
control, or about whether its evidence would survive being looked at.

Suppression is still honoured — customers rely on it. What changed is that it
can no longer be silent.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.access_risk_analysis import AccessRiskAnalysisAuditor as ARA  # noqa: E402

RISK = [{"risk_id": "ZX", "name": "vendor create vs pay", "description": "d",
         "risk_type": "SOD", "severity": "CRITICAL", "process": "P2P",
         "functions": [
             {"name": "A", "actions": ["FK01"], "permissions": [
                 {"object": "F_LFA1_BUK", "field": "ACTVT", "values": ["02"]}]},
             {"name": "B", "actions": ["F110"], "permissions": [
                 {"object": "F_REGU_BUK", "field": "ACTVT", "values": ["02"]}]}]}]


def auth(obj, field, low, role="Z"):
    return {"AGR_NAME": role, "OBJECT": obj, "AUTH": "A1", "FIELD": field,
            "LOW": low, "HIGH": ""}


HOLDER = [auth("S_TCODE", "TCD", "FK01"), auth("S_TCODE", "TCD", "F110"),
          auth("F_LFA1_BUK", "ACTVT", "02"), auth("F_REGU_BUK", "ACTVT", "02")]


def run(mitigations=None):
    data = {"role_auth_values": HOLDER,
            "user_roles": [{"UNAME": "U1", "AGR_NAME": "Z"}]}
    if mitigations is not None:
        data["mitigating_controls"] = mitigations
    a = ARA(data)
    a.RULESET = RISK
    a.run_all_checks()
    return {f["check_id"]: f for f in a.findings}


GOOD = [{"USER": "U1", "RISK_ID": "ZX", "CONTROL_ID": "C1",
         "VALID_TO": "99991231", "MITIGATED_BY": "J.CONTROLLER"}]


# ── nothing leaves the report silently ─────────────────────────────────────

def test_without_mitigations_the_conflict_reports_normally():
    assert "ARA-ZX" in run()
    assert "MITIG-001" not in run()


def test_a_suppressed_conflict_is_reported_as_suppressed():
    """THE defect. It used to return early and emit nothing at all."""
    got = run(GOOD)
    assert "ARA-ZX" not in got          # still suppressed: customers rely on it
    assert "MITIG-001" in got           # but no longer silently
    assert got["MITIG-001"]["details"]["risks_hidden_entirely"] == 1


def test_the_finding_names_the_risk_that_disappeared():
    item = " ".join(run(GOOD)["MITIG-001"]["affected_items"])
    assert "ZX" in item and "entire risk hidden" in item


def test_it_says_a_row_is_not_an_audit_conclusion():
    """Without this the finding reads as bookkeeping rather than as the point."""
    d = run(GOOD)["MITIG-001"]["description"]
    assert "a compensating control is an audit conclusion" in d
    assert "AS 2201" in d


def test_a_well_formed_row_is_reported_but_not_faulted():
    """Suppression is legitimate. MITIG-002 is for rows that cannot support a
    conclusion, not for the existence of a mitigation."""
    got = run(GOOD)
    assert "MITIG-001" in got and "MITIG-002" not in got


# ── rows that cannot support a conclusion ──────────────────────────────────

def test_a_blanket_row_suppresses_every_risk_and_is_called_out():
    """One row naming no specific risk removes EVERY conflict for that user —
    the rubber stamp SAP ships as configuration, reproduced in data."""
    got = run([{"USER": "U1", "RISK_ID": "*", "CONTROL_ID": "C1",
                "VALID_TO": "99991231", "MITIGATED_BY": "J.C"}])
    assert got["MITIG-002"]["severity"] == "HIGH"
    assert "blanket" in " ".join(got["MITIG-002"]["affected_items"])


def test_a_row_with_no_approver_records_no_decision():
    got = run([{"USER": "U1", "RISK_ID": "ZX", "CONTROL_ID": "C1",
                "VALID_TO": "99991231"}])
    assert "no approver" in " ".join(got["MITIG-002"]["affected_items"])


def test_a_row_with_no_expiry_has_never_been_revalidated():
    """A mitigation without an expiry is a permanent exemption: nothing will
    ever make it lapse, so nobody will ever revisit it."""
    got = run([{"USER": "U1", "RISK_ID": "ZX", "CONTROL_ID": "C1",
                "MITIGATED_BY": "J.C"}])
    assert "nobody has ever revalidated it" in " ".join(
        got["MITIG-002"]["affected_items"])


def test_a_row_with_no_control_id_names_no_control():
    got = run([{"USER": "U1", "RISK_ID": "ZX", "VALID_TO": "99991231",
                "MITIGATED_BY": "J.C"}])
    assert "no control id" in " ".join(got["MITIG-002"]["affected_items"])


def test_every_fault_on_one_row_is_listed_together():
    got = run([{"USER": "U1", "RISK_ID": "*", "CONTROL_ID": "", "VALID_TO": ""}])
    item = " ".join(got["MITIG-002"]["affected_items"])
    for fault in ("blanket", "no control id", "no approver", "no expiry"):
        assert fault in item


def test_an_expired_row_suppresses_nothing_so_the_conflict_returns():
    """Expiry already worked; this pins that MITIG did not change it."""
    got = run([{"USER": "U1", "RISK_ID": "ZX", "CONTROL_ID": "C1",
                "VALID_TO": "20200101", "MITIGATED_BY": "J.C"}])
    assert "ARA-ZX" in got
    assert "MITIG-001" not in got       # nothing was suppressed
