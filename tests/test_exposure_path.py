"""From a published endpoint to the injection, as a route somebody can check.

WHAT THIS CLOSES
`reachability.verdict` answers "does anything in the system reference this
object". That separates live code from housekeeping and says nothing about the
network — so an SQL injection in a class published on an unauthenticated ICF node
and the same statement in a class only a nightly job touches were reported
identically, and scored identically.

`docs/CVA_MERGE_PLAN.md` Phase 4b specified the two columns that fix it —
`icf_services.HANDLER_CLASS` and `odata_auth.IMPL_CLASS` — and
`docs/EXPORT_GUIDE.md` carries a warning box against each saying, correctly, that
nothing reads them. They are read now, and the tree call graph supplies the rest:
the walk starts at the sink's own procedure and climbs until it arrives in a
class that serves an endpoint, so the answer holds for code several classes in
and not only for the handler itself.

    /sap/bc/z_vendor_report   ICF, active, AUTH_REQUIRED=NO
      -> ZCL_TREE_CALLER      HANDLER_CLASS
         -> drive                          zcl_tree_caller.clas.abap:20
            -> by_public_tainted           zcl_tree_worker.clas.abap:35
               -> SELECT ... WHERE (iv_where)   :36

ABSENCE IS NEVER SAFETY, and most of this file is about that. No route found is
`None`, not False: a dynamic `CALL METHOD (lv_name)` resolves to no edge, and the
entry list is only as complete as the columns the customer exported. A customer
who supplies nothing must not be told their code is unreachable, and `None` earns
no points in the prioritiser in either direction.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.abap_sast import AbapSastAuditor  # noqa: E402
from modules.reachability import EXPOSED, UNKNOWN, ReachabilityIndex  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "exposure"
TREE = ROOT / "tests" / "fixtures" / "abap_tree"


def rows(name: str):
    with open(FIXTURES / name, newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def data_with_columns():
    return {
        "icf_services": rows("icf_services.csv"),
        "odata_auth": rows("odata_auth.csv"),
        AbapSastAuditor.SOURCE_KEY: str(TREE),
    }


@pytest.fixture(scope="module")
def findings():
    return AbapSastAuditor(data_with_columns(), {}, {}).run_all_checks()


def code_findings(found):
    return [f for f in found if "internet_exposed" in (f.get("details") or {})]


def at_line(found, line):
    return [f for f in code_findings(found)
            if line in ((f.get("details") or {}).get("lines") or [])]


# --------------------------------------------------------------------------- #
#  The index                                                                   #
# --------------------------------------------------------------------------- #

def test_a_handler_class_is_joined_to_its_node():
    index = ReachabilityIndex({"icf_services": rows("icf_services.csv")})
    verdict = index.exposure("ZCL_TREE_CALLER")
    assert verdict["state"] == EXPOSED
    assert any("/sap/bc/z_vendor_report" in r for r in verdict["reasons"])
    assert any("no authentication" in r for r in verdict["reasons"])


def test_an_authenticated_node_is_still_exposed_but_says_so():
    """Published-with-authentication is not published-without. Both are exposed;
    only one of them is anybody's first job on a Monday."""
    index = ReachabilityIndex({"icf_services": rows("icf_services.csv")})
    verdict = index.exposure("ZCL_TREE_ADMIN")
    assert verdict["state"] == EXPOSED
    assert not any("no authentication" in r for r in verdict["reasons"])


def test_an_inactive_node_is_not_treated_as_published():
    """ICF_ACTIVE=NO. An explicit negative, and the only kind that counts."""
    index = ReachabilityIndex({"icf_services": rows("icf_services.csv")})
    verdict = index.exposure("ZCL_TREE_RETIRED")
    assert verdict["state"] == UNKNOWN
    assert any("inactive" in r for r in verdict["reasons"])


def test_a_blank_active_flag_is_read_as_possibly_live():
    """The direction to be wrong in, and the same rule `REFERENCED` already
    follows: an empty cell means the export did not say. Reading it as inactive
    would let a blank column silently retire a published node and take the
    finding's exposure with it."""
    index = ReachabilityIndex({"icf_services": rows("icf_services.csv")})
    verdict = index.exposure("ZCL_TREE_UNSTATED")
    assert verdict["state"] == EXPOSED


def test_an_odata_service_with_no_auth_check_is_exposed():
    index = ReachabilityIndex({"odata_auth": rows("odata_auth.csv")})
    verdict = index.exposure("ZCL_TREE_ODATA")
    assert verdict["state"] == EXPOSED
    assert any("no authentication" in r for r in verdict["reasons"])


def test_without_the_columns_every_answer_is_unknown():
    """Today's exports. The whole point of the warning boxes in EXPORT_GUIDE."""
    index = ReachabilityIndex({
        "icf_services": [{"ICF_NAME": "/sap/bc/x", "ICF_ACTIVE": "X",
                          "AUTH_REQUIRED": "NO"}]})
    assert index.has_entry_point_data is False
    verdict = index.exposure("ZCL_ANYTHING")
    assert verdict["state"] == UNKNOWN
    assert any("HANDLER_CLASS" in r for r in verdict["reasons"])


def test_a_class_no_endpoint_names_is_unknown_and_not_safe():
    """The state this module refuses to collapse. A class can be reached through
    another class, through a dynamic call, or through an endpoint whose handler
    column the customer left blank."""
    index = ReachabilityIndex({"icf_services": rows("icf_services.csv")})
    verdict = index.exposure("ZCL_SOMETHING_ELSE")
    assert verdict["state"] == UNKNOWN
    assert any("not evidence" in r for r in verdict["reasons"])


# --------------------------------------------------------------------------- #
#  The route                                                                   #
# --------------------------------------------------------------------------- #

def test_a_sink_one_call_in_is_reported_exposed_with_its_route(findings):
    rows_ = at_line(findings, 36)
    assert rows_, "the injection in by_public_tainted was not reported"
    details = rows_[0]["details"]
    assert details["internet_exposed"] is True
    path = details["exposure_path"]
    assert len(path) == 1
    assert path[0]["from"] == "zcl_tree_caller~drive"
    assert path[0]["to"] == "zcl_tree_worker~by_public_tainted"
    assert path[0]["file"] == "zcl_tree_caller.clas.abap"


def test_a_sink_two_calls_in_is_still_found(findings):
    """The reason the walk exists rather than a direct handler lookup: real code
    puts the vulnerable statement several classes in from the endpoint."""
    rows_ = at_line(findings, 52)
    assert rows_
    path = rows_[0]["details"]["exposure_path"]
    assert [h["from"] for h in path] == ["zcl_tree_caller~drive",
                                         "zcl_tree_worker~entry"]


def test_the_reason_names_the_endpoint_and_its_authentication(findings):
    reasons = at_line(findings, 36)[0]["details"]["exposure_reasons"]
    joined = " ".join(reasons)
    assert "/sap/bc/z_vendor_report" in joined
    assert "no authentication" in joined


def test_a_method_nothing_reaches_is_unknown_not_false(findings):
    """`never_called` has no route. That is the absence of evidence — a dynamic
    call resolves to no edge — and reporting False would tell a customer their
    injection is unreachable on the strength of what we could not see."""
    rows_ = at_line(findings, 44)
    assert rows_
    details = rows_[0]["details"]
    assert details["internet_exposed"] is None
    assert any("not evidence" in r for r in details["exposure_reasons"])


def test_no_route_is_claimed_when_the_columns_are_absent():
    data = {"icf_services": [{"ICF_NAME": "/sap/bc/x", "ICF_ACTIVE": "X",
                              "AUTH_REQUIRED": "NO"}],
            AbapSastAuditor.SOURCE_KEY: str(TREE)}
    found = code_findings(AbapSastAuditor(data, {}, {}).run_all_checks())
    assert found
    for f in found:
        assert f["details"]["internet_exposed"] is None
        assert any("HANDLER_CLASS" in r
                   for r in f["details"]["exposure_reasons"])


# --------------------------------------------------------------------------- #
#  What it changes                                                             #
# --------------------------------------------------------------------------- #

def _score(details):
    from modules.risk_prioritizer import RiskPrioritizer
    finding = {"check_id": "ABAP-SQLI-001", "severity": "CRITICAL",
               "title": "Dynamic WHERE clause", "category": "Custom Code",
               "details": details}
    return RiskPrioritizer().assess(finding)


def test_reaching_a_published_endpoint_outranks_merely_being_referenced():
    """The distinction that did not exist. Both findings are identical CRITICAL
    injections; one is three hops from an unauthenticated endpoint and the other
    is referenced by a batch job."""
    exposed = _score({
        "source": "abap_scan", "confidence": "confirmed",
        "reachability": "reachable", "reachability_reasons": ["referenced"],
        "internet_exposed": True,
        "exposure_reasons": ["ICF /sap/bc/z is published with no authentication"],
        "exposure_path": [{"from": "a~b", "to": "c~d", "line": 1, "file": "x", "code": ""}],
    })
    referenced = _score({
        "source": "abap_scan", "confidence": "confirmed",
        "reachability": "reachable", "reachability_reasons": ["referenced"],
        "internet_exposed": None, "exposure_reasons": ["no route found"],
    })
    assert exposed.score > referenced.score, (exposed.score, referenced.score)


def test_the_factor_is_named_and_carries_its_evidence():
    """A score a customer cannot argue with is a score they will not accept."""
    scored = _score({
        "source": "abap_scan", "confidence": "confirmed",
        "reachability": "unknown", "reachability_reasons": [],
        "internet_exposed": True,
        "exposure_reasons": ["ICF /sap/bc/z is published with no authentication"],
        "exposure_path": [{"from": "a~b", "to": "c~d", "line": 1, "file": "x", "code": ""}],
    })
    labels = {factor["label"] for factor in scored.factors}
    assert "Reachable from a published endpoint" in labels
    detail = next(f["detail"] for f in scored.factors
                  if f["label"] == "Reachable from a published endpoint")
    assert "/sap/bc/z" in detail
    assert "1 call(s) in" in detail


def test_an_unknown_exposure_earns_nothing_in_either_direction():
    """A customer who has not supplied the columns must be scored exactly as they
    were before the column existed."""
    without = _score({"source": "abap_scan", "confidence": "confirmed",
                      "reachability": "reachable",
                      "reachability_reasons": ["referenced"]})
    unknown = _score({"source": "abap_scan", "confidence": "confirmed",
                      "reachability": "reachable",
                      "reachability_reasons": ["referenced"],
                      "internet_exposed": None,
                      "exposure_reasons": ["no HANDLER_CLASS column"]})
    assert without.score == unknown.score
