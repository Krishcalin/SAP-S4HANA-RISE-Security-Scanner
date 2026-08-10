# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

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


# --------------------------------------------------------------------------- #
#  The two conversion judgement calls, resolved                               #
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_btp_identities_are_typed_as_cloud_users_not_abap_users():
    """The cross-system check matches the two user masters in Python and reports the
    result; the GRAPH must still keep them apart. Typing BTP identities as `user`
    filed them under the ABAP SID and would merge a BTP JSMITH with an ABAP JSMITH."""
    from server.identity import extract_nodes

    findings = AdvancedIamAuditor(
        _data(), None, run_context={"modules": {"iam"}}).run_all_checks()
    xid = [f for f in findings if f["check_id"].startswith("IAM-XID")]
    assert xid, "the cross-system identity checks did not fire"

    types = {o["type"] for f in xid for o in (f.get("affected_objects") or [])}
    assert "btp_user" in types, "BTP identities are not typed as cloud users"

    keys = {n["key"] for n in extract_nodes(xid, "PRD")}
    assert keys, "no graph nodes were produced"
    for key in keys:
        if key.startswith(("btp_user:", "role_collection:")):
            assert "@PRD" not in key, (
                f"{key} files a BTP object under the ABAP system's SID")


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_access_reviews_name_the_campaign_and_never_the_reviewer():
    """A campaign is a real governance object with an id and belongs in the evidence.
    The reviewer is NOT the defect — naming them would put a person in the graph as
    though they were."""
    data = _data()
    findings = AdvancedIamAuditor(
        data, None, run_context={"modules": {"iam"}}).run_all_checks()
    rev = [f for f in findings if f["check_id"].startswith("IAM-REV")]
    assert rev, "the access-review checks did not fire"

    reviewers = {str(r.get("REVIEWER", "")).upper()
                 for r in data["access_reviews"] if r.get("REVIEWER")}
    campaign_ids = {str(r.get("REVIEW_ID", "")).upper()
                    for r in data["access_reviews"]}

    for f in rev:
        objs = f.get("affected_objects") or []
        assert objs, f"{f['check_id']} carries no structured evidence"
        for o in objs:
            assert o["type"] == "review_campaign", \
                f"{f['check_id']} named a {o['type']} — only campaigns belong here"
            assert o["name"].upper() in campaign_ids
            assert o["name"].upper() not in reviewers, \
                "a reviewer was named as though they were the defect"


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_completing_one_campaign_does_not_reset_the_others_age():
    """The campaigns are evidence, not identity. IAM-REV-001 stays aggregate, so
    closing one overdue review shrinks the member list without retiring the finding
    and restarting the clock on the rest."""
    from server.identity import fingerprint_finding

    def rev001(campaigns):
        return {"check_id": "IAM-REV-001", "scope": "aggregate",
                "affected_objects": [{"type": "review_campaign", "name": c}
                                     for c in campaigns]}

    before = fingerprint_finding(rev001(["REV-A", "REV-B", "REV-C"]), "PRD", "100")
    after = fingerprint_finding(rev001(["REV-A", "REV-C"]), "PRD", "100")
    assert before[0] == after[0]
    assert before[1] == "check_only"
