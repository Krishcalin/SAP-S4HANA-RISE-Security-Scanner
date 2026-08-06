"""
The IAM -> ARA Segregation of Duties deferral.

WHAT WAS WRONG
--------------
`iam_advanced.check_sod_conflicts` stood down whenever `role_auth_values.csv` was
LOADED, on the reasoning that the `ara` module does the same analysis at
permission level and does it better. The reasoning is right; the condition was
not. Data being present does not mean `ara` is running — `--modules iam` supplies
exactly that export and never runs `ara` — so the check deferred to a module that
was not there, the run produced no SoD findings at all, and nothing anywhere said
why. An empty SoD result read as "no SoD conflicts".

Two properties are asserted here:
  * defer only when the deeper module is GENUINELY in the run, and
  * when deferring, SAY SO, so silence is never mistaken for a clean result.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.iam_advanced import AdvancedIamAuditor  # noqa: E402

SAMPLE = ROOT / "sample_data"


def _data():
    from modules.data_loader import DataLoader
    return DataLoader(SAMPLE).load_all()


def _sod_ids(findings):
    return {f["check_id"] for f in findings if f["check_id"].startswith("IAM-SOD")}


# --------------------------------------------------------------------------- #
#  The bug                                                                    #
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_sod_runs_when_ara_is_not_in_the_run():
    """THE regression test. `--modules iam` loads role_auth_values but never runs
    `ara`; SoD analysis must not vanish."""
    data = _data()
    assert data.get("role_auth_values"), "fixture must have the export that triggered the bug"

    findings = AdvancedIamAuditor(
        data, None, run_context={"modules": {"iam"}}).run_all_checks()

    assert "IAM-SOD-DEFERRED" not in _sod_ids(findings), (
        "the module deferred to 'ara' even though 'ara' is not in this run — "
        "SoD analysis silently produced nothing")


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_sod_defers_when_ara_is_in_the_run_and_says_so():
    """Deferring is correct when the deeper module really runs — but a silent
    stand-down is indistinguishable from a clean bill of health."""
    findings = AdvancedIamAuditor(
        _data(), None, run_context={"modules": {"iam", "ara"}}).run_all_checks()

    deferred = [f for f in findings if f["check_id"] == "IAM-SOD-DEFERRED"]
    assert len(deferred) == 1, "the deferral was silent"
    note = deferred[0]
    assert note["severity"] == "INFO", "a coverage note must not read as a defect"
    assert "permission level" in note["description"]
    assert "ARA-" in note["description"], "the note should point at where the answer is"

    # And the coarse rules genuinely did not run.
    assert not [f for f in findings if f["check_id"].startswith("IAM-SOD-0")]


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_an_unknown_caller_keeps_the_historical_behaviour():
    """A caller that does not supply run_context must not have its behaviour
    changed underneath it — the module falls back to the data-presence rule
    rather than guessing."""
    findings = AdvancedIamAuditor(_data()).run_all_checks()
    assert "IAM-SOD-DEFERRED" in _sod_ids(findings)


def test_sod_runs_when_there_is_no_deeper_export_at_all():
    """With no AGR_1251 export there is nothing to defer TO, so the coarse check
    is the only SoD available and must run regardless of run_context."""
    data = {"sod_matrix": [
        {"USERNAME": "U1", "TCODE": "ME21N"},
        {"USERNAME": "U1", "TCODE": "F110"},
    ]}
    for ctx in (None, {"modules": {"iam", "ara"}}, {"modules": {"iam"}}):
        findings = AdvancedIamAuditor(data, None, run_context=ctx).run_all_checks()
        assert "IAM-SOD-DEFERRED" not in _sod_ids(findings), \
            f"deferred with no role_auth_values present (context={ctx})"


# --------------------------------------------------------------------------- #
#  The plumbing that makes the fix real                                       #
# --------------------------------------------------------------------------- #

def test_module_is_running_reports_unknown_rather_than_guessing():
    from modules.base_auditor import BaseAuditor
    assert BaseAuditor({}).module_is_running("ara") is None
    assert BaseAuditor({}, None, {"modules": {"ara"}}).module_is_running("ara") is True
    assert BaseAuditor({}, None, {"modules": {"iam"}}).module_is_running("ara") is False


def test_the_two_module_vocabularies_cannot_drift_apart():
    """`server.ingest.MODULE_KEYS` is hand-written and must match the CLI's
    `--modules` choices. A prefix/key table that drifts is exactly how eight
    checks previously ended up routed to no owning team — silently."""
    import re
    from server.ingest import MODULE_KEYS

    src = (ROOT / "sap_scanner.py").read_text(encoding="utf-8")
    cli = None
    for m in re.finditer(r"choices=\[(.*?)\]", src, re.S):
        vals = {c.strip().strip("\"'") for c in m.group(1).split(",") if c.strip()}
        if "users" in vals:              # the modules list, not the severity list
            cli = vals - {"all"}
            break

    assert cli, "could not locate the CLI's --modules choices"
    assert cli == set(MODULE_KEYS), (
        f"module vocabularies have drifted.\n"
        f"  missing from server.ingest.MODULE_KEYS: {sorted(cli - set(MODULE_KEYS))}\n"
        f"  present there but not in the CLI:       {sorted(set(MODULE_KEYS) - cli)}")


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_the_server_passes_run_context_so_the_fix_actually_applies():
    """The fix is inert unless callers supply run_context. The server runs every
    auditor, so `ara` is always present and the deferral is always correct — but
    it must be TOLD that, not left to infer it."""
    from server.ingest import RUN_CONTEXT
    assert "ara" in RUN_CONTEXT["modules"]
    assert "iam" in RUN_CONTEXT["modules"]

    findings = AdvancedIamAuditor(_data(), None, RUN_CONTEXT).run_all_checks()
    assert "IAM-SOD-DEFERRED" in _sod_ids(findings)


def test_the_deferral_note_is_routed_and_identifiable():
    """It is a finding like any other: it needs a team and a stable identity, or
    it becomes the orphaned row nobody sees."""
    from server.enrich import team_for
    from server.identity import fingerprint_finding

    assert team_for("IAM-SOD-DEFERRED") == "identity"
    fp, basis = fingerprint_finding(
        {"check_id": "IAM-SOD-DEFERRED", "scope": "aggregate"}, "PRD", "100")
    assert len(fp) == 64 and basis == "check_only"
