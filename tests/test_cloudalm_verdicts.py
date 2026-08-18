# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""SAP's CSA verdicts, and the discipline of reporting somebody else's findings.

WHY THIS MODULE EXISTS AT ALL. The roadmap gated Cloud ALM ingestion on a
question — does its API return raw store values or only compliance verdicts —
that could not be answered: SAP's setup guide carries no CSA content, its
published API examples cover projects, tasks, requirements, testing and
analytics and nothing for configuration and security analysis, and the Business
Accelerator Hub is a JavaScript application. Settling it needs a live tenant.

So the module answers it by making it stop mattering. The raw path was already
built in `cloudalm_import.py`; this is the verdict path. Whichever shape a
tenant's export takes, one of the two reads it.

WHAT THESE TESTS ARE FOR. Not that a CSV parses. They pin the properties that
make importing another vendor's assessment defensible: that it is labelled as
SAP's throughout, that its severity is SAP's tier rather than one we invented,
that "could not evaluate" never merges into "failed", and that a policy our own
catalogue cannot resolve is reported rather than quietly downgraded.
"""
from __future__ import annotations

import contextlib
import io
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.cloudalm_verdicts import CloudAlmVerdictAuditor   # noqa: E402


def _run(rows):
    data = {} if rows is None else {"csa_findings": rows}
    with contextlib.redirect_stdout(io.StringIO()):
        return {f["check_id"]: f
                for f in CloudAlmVerdictAuditor(data, {}).run_all_checks()}


#: `2AAUDIT` is SAP's audit policy and resolves to requirement AUDIT-A, tier
#: STANDARD, in the vendored baseline catalogue.
_FAIL = {"POLICY": "2AAUDIT", "SYSTEM": "PRD", "STATUS": "NON-COMPLIANT"}


# ═════════════════════════════════════════════════════════════════════════════
#  Whose finding is it
# ═════════════════════════════════════════════════════════════════════════════

def test_the_finding_says_it_is_sap_s_not_ours():
    """The plainest overclaim available here would be presenting another
    vendor's verdict as this product's own assessment."""
    finding = _run([_FAIL])["CSA-SAP-001"]
    assert finding["details"]["assessed_by"] == "SAP Cloud ALM CSA"
    assert finding["details"]["reassessed_by_this_product"] is False
    assert "THESE ARE SAP'S FINDINGS, NOT THIS PRODUCT'S" in finding["description"]


def test_nothing_here_claims_to_have_re_judged_the_result():
    """A verdict arrives without the parameter value, user or table row that
    produced it, so there is nothing to re-judge — and the description has to
    say why rather than leaving the reader to assume we checked."""
    description = " ".join(_run([_FAIL])["CSA-SAP-001"]["description"].split())
    assert "nothing here re-judged them" in description
    assert "nothing to re-judge" in description


def test_severity_is_sap_s_tier_and_says_so():
    """Ranking a result this product did not compute would be inventing
    precision. AUDIT-A is STANDARD, which maps to HIGH."""
    finding = _run([_FAIL])["CSA-SAP-001"]
    assert finding["severity"] == "HIGH"
    assert finding["details"]["severity_basis"] == "sap_baseline_tier"


def test_a_critical_tier_policy_outranks_a_standard_one():
    """The translation has to actually carry SAP's ranking across, or the
    severity_basis claim is decoration."""
    from modules.cloudalm_verdicts import TIER_SEVERITY
    assert TIER_SEVERITY["CRITICAL"] == "CRITICAL"
    assert TIER_SEVERITY["EXTENDED"] == "MEDIUM"


def test_the_policy_resolves_to_sap_s_own_requirement_and_title():
    """The payoff from vendoring SAP's baseline catalogue: a bare policy id
    becomes SAP's requirement, family and tier without anybody typing them."""
    line = _run([_FAIL])["CSA-SAP-001"]["affected_items"][0]
    assert "2AAUDIT" in line and "AUDIT-A" in line and "STANDARD" in line


# ═════════════════════════════════════════════════════════════════════════════
#  Could not evaluate is not the same as failed
# ═════════════════════════════════════════════════════════════════════════════

def test_an_unevaluated_policy_is_reported_separately():
    """"SAP could not check this" and "SAP checked it and it failed" are
    different statements, and a report that merges them is worth less than
    either — the first is a gap in the collection, the second in the system."""
    fired = _run([dict(_FAIL, STATUS="NOT ASSESSED")])
    assert "CSA-SAP-002" in fired
    assert "CSA-SAP-001" not in fired


def test_an_unevaluated_policy_degrades_coverage():
    """A system reported compliant on everything CSA could evaluate is not a
    system reported compliant, and the gate has to know the difference."""
    assert _run([dict(_FAIL, STATUS="NOT ASSESSED")])["CSA-SAP-002"][
        "details"]["degrades_coverage"] is True


def test_a_compliant_result_produces_nothing():
    assert _run([dict(_FAIL, STATUS="COMPLIANT")]) == {}


def test_an_unrecognised_status_is_not_read_as_a_failure():
    """Inventing a failure from a status word nobody recognised would put SAP's
    name on this product's mistake."""
    fired = _run([dict(_FAIL, STATUS="SOMETHING NEW")])
    assert "CSA-SAP-001" not in fired and "CSA-SAP-002" not in fired


# ═════════════════════════════════════════════════════════════════════════════
#  A policy our own catalogue cannot resolve
# ═════════════════════════════════════════════════════════════════════════════

def test_an_unknown_policy_is_still_reported_as_failing():
    """It is SAP's verdict either way. Dropping it because our catalogue is
    behind would hide a real result behind our own staleness."""
    line = _run([dict(_FAIL, POLICY="9ZZFAKE")])["CSA-SAP-001"]["affected_items"][0]
    assert "9ZZFAKE" in line
    assert "not in the vendored catalogue" in line


def test_the_unknown_policy_is_also_raised_against_this_product():
    """The reason the line above reads as it does. Without this the reader sees
    "policy not in the vendored catalogue" with nothing explaining why."""
    finding = _run([dict(_FAIL, POLICY="9ZZFAKE")])["CSA-SAP-003"]
    assert finding["details"]["self_audit"] is True
    assert finding["severity"] == "LOW"
    assert "rebuild-sap-catalogue" in finding["remediation"]


# ═════════════════════════════════════════════════════════════════════════════
#  Reading the export
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("column", ["POLICY", "POLICY_ID", "CHECK_ID", "RULE_ID"])
def test_the_policy_column_is_accepted_under_the_spellings_a_tenant_might_use(column):
    """This file comes from a tenant's own extraction, not from a documented API
    shape anybody could pin. Refusing a reasonable spelling sends somebody to
    rename columns rather than to read the finding."""
    assert "CSA-SAP-001" in _run([{column: "2AAUDIT", "STATUS": "FAILED"}])


@pytest.mark.parametrize("status", ["NON-COMPLIANT", "NONCOMPLIANT", "FAILED",
                                    "RED", "VIOLATION"])
def test_the_failure_vocabulary_covers_what_an_export_actually_says(status):
    assert "CSA-SAP-001" in _run([dict(_FAIL, STATUS=status)])


def test_no_export_produces_nothing_at_all():
    """An absent optional input is not degraded coverage — the same line
    cap_xsuaa and abap_sast draw. Arming the gate on every scan that omits an
    optional file would make the signal worth nothing."""
    assert _run(None) == {}


def test_an_export_with_no_usable_row_is_a_coverage_finding_not_silence():
    """Supplied and unreadable must not look like a tenant with no failing
    policies. The usual cause is a store export sent to the results reader."""
    fired = _run([{"SOMETHING": "else"}])
    assert fired["CSA-COV-001"]["details"]["degrades_coverage"] is True


# ═════════════════════════════════════════════════════════════════════════════
#  It is registered where a customer can reach it
# ═════════════════════════════════════════════════════════════════════════════

def test_the_source_and_the_cli_alias_exist():
    from modules.coverage import CLI_MODULE_ALIASES
    from modules.data_loader import DataLoader
    assert "csa_findings" in DataLoader.FILE_MAP
    assert CLI_MODULE_ALIASES["csa"] == "cloudalm_verdicts"


def test_the_store_importer_is_untouched_and_still_the_other_half():
    """The two paths are complementary, not alternatives to each other: store
    exports feed this product's own checks, results exports carry SAP's."""
    from modules.cloudalm_import import STORE_TARGETS
    assert STORE_TARGETS, "the raw-store path lost its targets"
    doc = (ROOT / "modules" / "cloudalm_verdicts.py").read_text(encoding="utf-8")
    assert "cannot turn" in doc and "modules/cloudalm_import.py" in doc
