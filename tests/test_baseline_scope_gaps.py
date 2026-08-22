"""The five requirements that closed the in-scope Baseline gap, and the scope
rule that keeps the denominator honest.

HOW THE GAP WAS ACTUALLY MEASURED. The figure carried into this work was "15 of
38", and it was wrong in the direction that flatters: 15 was the UNCOVERED count,
not the covered one. Recomputing it found 23 covered — and then found that one of
the 23 was false. `CHECK_TO_REQUIREMENT` mapped the prefix `BTP-` to `NETCF-P`,
and `NETCF-P` is a SINGLE check item reading one Cloud Connector parameter,
`isHaActive`, which nothing in this product read. Forty-two BTP checks were
claiming a requirement none of them tested.

That is the same class of error as the `PARAM-PWD` prefix that matched nothing for
the life of the table, inverted: one under-reported silently, this one
over-reported loudly. A wrong mapping tells an auditor we satisfy a control we do
not test, which is the one direction an error here must never go — so these tests
pin the mapping to the check that demonstrably reads the same configuration, not
to a family that shares a prefix with it.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.btp_cloud_surface import BtpCloudSurfaceAuditor    # noqa: E402
from modules.coverage import all_check_ids                      # noqa: E402
from modules.hana_db_security import HanaDbSecurityAuditor      # noqa: E402
from server import sapcontent                                   # noqa: E402

ALL_IDS = sorted({c for ids in all_check_ids().values() for c in ids})


def _hana(rows, **extra):
    data = {"hana_parameters": [
        {"FILE_NAME": f, "SECTION": s, "KEY": k, "VALUE": v} for f, s, k, v in rows]}
    data.update(extra)
    return {f["check_id"]: f for f in HanaDbSecurityAuditor(data).run_all_checks()}


def _scc(**cc):
    data = {"cloud_connector": cc}
    return {f["check_id"]: f for f in BtpCloudSurfaceAuditor(data, {}).run_all_checks()}


# ═════════════════════════════════════════════════════════════════════════════
#  NETCF-H — HANA internal communication
# ═════════════════════════════════════════════════════════════════════════════

def test_global_listeninterface_is_reported():
    found = _hana([("global.ini", "communication", "listeninterface", ".global")])
    assert "HANADB-PARAM-006" in found
    assert found["HANADB-PARAM-006"]["severity"] == "CRITICAL"


@pytest.mark.parametrize("value", [".local", ".internal", ".LOCAL"])
def test_a_bound_listeninterface_is_not_reported(value):
    assert "HANADB-PARAM-006" not in _hana(
        [("global.ini", "communication", "listeninterface", value)])


def test_an_unrecognised_listeninterface_is_left_alone():
    """Only `.global` is the defect. A spelling this check does not know must not
    be reported as one — guessing about a customer's estate is the failure mode
    this module's docstring is about."""
    assert "HANADB-PARAM-006" not in _hana(
        [("global.ini", "communication", "listeninterface", ".site")])


def test_an_absent_listeninterface_is_not_a_finding():
    """Absent is not `.global`. An export that never carried the row would
    otherwise fail every customer on a missing column."""
    assert "HANADB-PARAM-006" not in _hana([("global.ini", "persistence",
                                             "log_mode", "normal")])


def test_the_listeninterface_finding_names_the_section():
    """`listeninterface` is qualified by its section, as every generic key in this
    module is. Without it the identity would collide with any other section's."""
    obj = _hana([("global.ini", "communication",
                  "listeninterface", ".global")])["HANADB-PARAM-006"]["affected_objects"]
    assert obj == [{"type": "parameter_name", "name": "listeninterface",
                    "qualifier": "section=communication"}]


# ═════════════════════════════════════════════════════════════════════════════
#  TRACES-H — SQL trace level
# ═════════════════════════════════════════════════════════════════════════════

def test_a_trace_recording_results_is_reported():
    found = _hana([("indexserver.ini", "sqltrace", "level", "ALL_WITH_RESULTS")])
    assert "HANADB-TRACE-001" in found
    assert found["HANADB-TRACE-001"]["severity"] == "CRITICAL"


@pytest.mark.parametrize("value", ["NORMAL", "ERROR", "ALL"])
def test_a_trace_not_recording_results_is_not_reported(value):
    """ALL is not ALL_WITH_RESULTS. Statements without rows are a different — and
    much smaller — disclosure, and this check is about the rows."""
    assert "HANADB-TRACE-001" not in _hana(
        [("indexserver.ini", "sqltrace", "level", value)])


def test_a_level_in_another_section_is_not_read_as_a_trace_level():
    """Every ini section has a `level`. A strict section match is what stops an
    unrelated one being reported as a SQL trace."""
    assert "HANADB-TRACE-001" not in _hana(
        [("global.ini", "communication", "level", "ALL_WITH_RESULTS")])


def test_the_trace_finding_carries_the_surrounding_settings():
    found = _hana([("indexserver.ini", "sqltrace", "level", "ALL_WITH_RESULTS"),
                   ("indexserver.ini", "sqltrace", "trace", "on"),
                   ("indexserver.ini", "sqltrace", "user", "SAPABAP1")])
    items = found["HANADB-TRACE-001"]["affected_items"]
    assert any("trace = on" in i for i in items)
    assert any("SAPABAP1" in i for i in items)


# ═════════════════════════════════════════════════════════════════════════════
#  SECUPD-H — HANA maintenance status
# ═════════════════════════════════════════════════════════════════════════════

def _version(value):
    return _hana([("global.ini", "persistence", "log_mode", "normal")],
                 hana_version=[{"NAME": "VERSION", "VALUE": value}])


def test_a_retired_revision_line_is_reported():
    found = _version("2.00.059.06.1678")
    assert "HANADB-VER-001" in found
    assert found["HANADB-VER-001"]["severity"] == "CRITICAL"
    assert "2.00.059.06.1678" in found["HANADB-VER-001"]["title"]


@pytest.mark.parametrize("value", ["2.00.067.00.1000", "2.00.076.00.1", "2.00.079.03.9"])
def test_a_maintained_revision_line_is_not_reported(value):
    assert "HANADB-VER-001" not in _version(value)


def test_a_revision_that_cannot_be_ordered_is_not_reported():
    """A revision this cannot parse must not be reported as old. Silence is the
    correct answer, and `sap_hotnews.py` takes the same position on the same
    string."""
    assert "HANADB-VER-001" not in _version("fa/2024.11")


def test_an_absent_version_export_is_not_a_finding():
    assert "HANADB-VER-001" not in _hana([("global.ini", "persistence",
                                           "log_mode", "normal")])


def test_the_maintenance_finding_does_not_carry_the_revision_in_its_identity():
    """The revision is a property, not a subject. Carrying it into identity would
    retire the finding on an upgrade that is STILL out of maintenance, resetting
    the age of an exposure that has not moved — the same reasoning BTP-CC-008
    records for the Cloud Connector version."""
    found = _version("2.00.059.06.1678")["HANADB-VER-001"]
    assert found["scope"] == "aggregate"
    assert not found.get("affected_objects")


# ═════════════════════════════════════════════════════════════════════════════
#  NETCF-P / AUDIT-P — the Cloud Connector
# ═════════════════════════════════════════════════════════════════════════════

def test_a_connector_without_high_availability_is_reported():
    assert "BTP-CC-009" in _scc(version="2.16.2", isHaActive=False)


def test_a_connector_with_high_availability_is_not_reported():
    assert "BTP-CC-009" not in _scc(version="2.16.2", isHaActive=True)


@pytest.mark.parametrize("spelling", ["haActive", "highAvailability", "ha_active"])
def test_the_high_availability_field_is_read_under_its_other_spellings(spelling):
    assert "BTP-CC-009" in _scc(**{"version": "2.16.2", spelling: False})


def test_an_absent_high_availability_field_is_not_a_finding():
    """Absent is not false. An export that never carried the field would otherwise
    fail every customer on a missing column — the distinction BTP-AUD-001 makes
    for audit state, made here for this one."""
    assert "BTP-CC-009" not in _scc(version="2.16.2")


def test_audit_switched_off_is_reported():
    found = _scc(version="2.16.2", auditLevel="Off")
    assert "BTP-CC-010" in found
    assert found["BTP-CC-010"]["severity"] == "HIGH"


@pytest.mark.parametrize("level", ["All", "Security", "all"])
def test_a_connector_that_audits_is_not_reported(level):
    assert "BTP-CC-010" not in _scc(version="2.16.2", auditLevel=level)


def test_a_nested_audit_level_is_read():
    assert "BTP-CC-010" in _scc(version="2.16.2", audit={"level": "Off"})


def test_an_unrecognised_audit_level_is_not_reported_as_off():
    """A level this check does not know is not evidence of anything, and reporting
    it as Off would be a guess about a customer's estate."""
    assert "BTP-CC-010" not in _scc(version="2.16.2", auditLevel="Verbose")


# ═════════════════════════════════════════════════════════════════════════════
#  The mapping, and the scope rule
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("check_id,requirement", [
    ("HANADB-PARAM-006", "NETCF-H"),
    ("HANADB-TRACE-001", "TRACES-H"),
    ("HANADB-VER-001", "SECUPD-H"),
    ("BTP-CC-009", "NETCF-P"),
    ("BTP-CC-010", "AUDIT-P"),
    ("BTP-CC-008", "SECUPD-P"),
])
def test_each_new_check_maps_to_the_requirement_it_answers(check_id, requirement):
    assert sapcontent.requirement_for(check_id) == requirement


@pytest.mark.parametrize("check_id", [
    "BTP-CPI-001", "BTP-IAS-004", "BTP-DST-001", "BTP-TOK-001", "BTP-SB-001",
])
def test_the_rest_of_the_btp_family_maps_to_nothing(check_id):
    """SAP's BTP baseline is three requirements and all three read the Cloud
    Connector. CPI, IAS, destinations, tokens and service bindings have no
    Baseline equivalent at all, and saying so is more defensible than claiming
    they answer a parameter they never read."""
    assert sapcontent.requirement_for(check_id) is None


@pytest.mark.parametrize("check_id", [
    "HANADB-PARAM-002", "HANADB-PARAM-003", "HANADB-PARAM-004", "HANADB-PARAM-005",
])
def test_the_non_password_hana_parameters_no_longer_claim_pwdpol(check_id):
    """PWDPOL-H's four published titles are all password policy. Only
    HANADB-PARAM-001 reads it; error disclosure, TLS enforcement, log mode and
    cross-database access were claiming a password requirement they have nothing
    to do with."""
    assert sapcontent.requirement_for(check_id) != "PWDPOL-H"


def test_hanadb_param_001_still_maps_to_the_password_requirement():
    assert sapcontent.requirement_for("HANADB-PARAM-001") == "PWDPOL-H"


def test_every_in_scope_requirement_is_answered():
    """The state this work reached. Stated as a property rather than a number so
    that a requirement SAP ADDS in a future baseline version fails this test —
    which is the point: a new published requirement should show up as work, not
    be absorbed silently into a ratio."""
    cov = sapcontent.coverage(ALL_IDS)
    assert cov["not_covered"] == [], (
        "in-scope Baseline requirements are unanswered: %s"
        % [r["requirement"] for r in cov["not_covered"]])


def test_the_scope_rule_names_what_it_excludes_and_why():
    cov = sapcontent.coverage(ALL_IDS)
    assert cov["out_of_scope"], "nothing excluded; the Java stack should be"
    for r in cov["out_of_scope"]:
        assert r["requirement"] and r["reason"]
        assert r["technology"] in sapcontent.OUT_OF_SCOPE_TECHNOLOGY


def test_the_three_lists_partition_the_published_set():
    """The guard that a scope rule cannot quietly shrink the denominator."""
    cov = sapcontent.coverage(ALL_IDS)
    total = len(cov["covered"]) + len(cov["not_covered"]) + len(cov["out_of_scope"])
    assert total == cov["requirements_published"]


def test_a_covered_requirement_is_never_excluded_by_the_scope_rule():
    """Otherwise excluding a technology would raise the percentage by dropping a
    requirement we already answer, which is a way to flatter the ratio rather than
    to describe it."""
    cov = sapcontent.coverage(ALL_IDS)
    covered = {r["requirement"] for r in cov["covered"]}
    excluded = {r["requirement"] for r in cov["out_of_scope"]}
    assert not (covered & excluded)


def test_the_new_checks_are_documented():
    """Five checks were added while 352 in the catalogue still have no published
    narrative. Adding to that number would have been the wrong trade."""
    from server import checkdocs
    for check_id in ("HANADB-PARAM-006", "HANADB-TRACE-001", "HANADB-VER-001",
                     "BTP-CC-009", "BTP-CC-010"):
        assert checkdocs.check(check_id)["documented"], check_id
