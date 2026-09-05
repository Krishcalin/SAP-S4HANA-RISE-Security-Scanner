"""The bundled estate demonstrates the endpoint-to-sink join, and says what it cost.

WHY THE SAMPLE CHANGED. `sample_data/` held a custom class with three SQL
injections in it and nothing that published the class — so the join built for
exactly this case had no worked example anywhere a reader would meet it, and
`internet_exposed` came back `None` for all eight ABAP findings. A custom report
nobody can reach is also a less realistic estate than one somebody can.

`/sap/bc/z_vendor_report` is now an active, unauthenticated ICF node whose
`HANDLER_CLASS` is `ZCL_VENDOR_REPORT`. Z-namespaced so it reads as the
customer's; unauthenticated because that is the case the join exists to catch.

WHAT IT COST, MEASURED BEFORE AND AFTER over every auditor:

    findings          419 -> 419      (no new finding)
    severity mix      unchanged
    internet_exposed    0 ->   4
    P1/P2/P3/P4    38/43/229/109 -> 39/43/230/107
    total priority  17,844 -> 17,924  (+80, exactly 4 x the +20 boost)

No new finding because `NET-005` is an AGGREGATE — its item list went 3 to 4 and
now names the node, which is a true positive rather than a side effect. Exactly
one test broke, and it was the right one: `test_cloudalm_import` pairs this estate
against its Cloud ALM export and caught that only one side had gained the node.

WHAT THIS FILE IS FOR. The numbers above are now load-bearing — they are quoted
in a commit message and they are what a reader sees in the bundled demo. A silent
regression to `exposed=None` would take the worked example with it and nothing
else would fail, because every other assertion in the suite is about counts this
change did not move.
"""
from __future__ import annotations

import contextlib
import csv
import io
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.abap_sast import AbapSastAuditor  # noqa: E402
from modules.data_loader import DataLoader  # noqa: E402

NODE = "/sap/bc/z_vendor_report"
HANDLER = "ZCL_VENDOR_REPORT"


@pytest.fixture(scope="module")
def sample_findings():
    with contextlib.redirect_stdout(io.StringIO()), \
            contextlib.redirect_stderr(io.StringIO()):
        data = DataLoader(ROOT / "sample_data").load_all()
        data["abap_source_dir"] = str(ROOT / "sample_data" / "abap_src")
        return AbapSastAuditor(data, {}, {}).run_all_checks()


def exposed(findings):
    return [f for f in findings
            if (f.get("details") or {}).get("internet_exposed") is True]


# --------------------------------------------------------------------------- #
#  The export                                                                  #
# --------------------------------------------------------------------------- #

def test_the_sample_supplies_the_handler_column():
    """Optional in the guide, supplied here — a column documented and never
    demonstrated is a column nobody exports."""
    with open(ROOT / "sample_data" / "icf_services.csv",
              newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert "HANDLER_CLASS" in rows[0], "sample_data/icf_services.csv lost the column"
    node = [r for r in rows if r["ICF_NAME"] == NODE]
    assert node, "the sample no longer publishes %s" % NODE
    assert node[0]["HANDLER_CLASS"] == HANDLER
    assert node[0]["AUTH_REQUIRED"].upper() in ("NO", "N", "0", "NONE")


def test_the_class_it_names_actually_exists_in_the_sample_tree():
    """A handler naming a class nobody wrote would demonstrate the plumbing and
    prove nothing about the join."""
    src = (ROOT / "sample_data" / "abap_src").rglob("*.abap")
    defined = {line.split()[1].upper()
               for path in src
               for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
               if line.upper().startswith("CLASS ") and " DEFINITION" in line.upper()}
    assert HANDLER in defined, (
        "the sample's ICF node names %s, which the ABAP tree does not define: %s"
        % (HANDLER, sorted(defined)))


def test_the_cloud_alm_export_describes_the_same_estate():
    """The two directories are the same system seen two ways. A node in one and
    not the other silently breaks that claim — which is what caught this change,
    and the only test that did."""
    with open(ROOT / "sample_data_cloudalm" / "SICF_SERVICES.csv",
              newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    paths = {r["PATH"] for r in rows}
    assert NODE in paths, "the Cloud ALM export no longer carries %s" % NODE
    node = next(r for r in rows if r["PATH"] == NODE)
    assert node["AUTHENTICATION"].upper() == "NONE", \
        "the node must be unauthenticated on BOTH sides or the estates differ"
    # And deliberately no handler column: SAP's SICF_SERVICES store has none.
    assert "HANDLER_CLASS" not in rows[0], (
        "a HANDLER_CLASS was invented for the Cloud ALM export. SAP's store does "
        "not carry one, and cloudalm_import._t_sicf_services cannot emit it.")


# --------------------------------------------------------------------------- #
#  What it demonstrates                                                        #
# --------------------------------------------------------------------------- #

def test_four_findings_come_back_reachable_from_outside(sample_findings):
    hits = exposed(sample_findings)
    assert len(hits) == 4, (
        "the sample demonstrates %d exposed findings, not 4: %s"
        % (len(hits), sorted(f["check_id"] for f in hits)))


def test_the_injections_are_among_them(sample_findings):
    """The three SQL injections in ZCL_VENDOR_REPORT are the point of the
    example: a dynamic WHERE clause behind an unauthenticated endpoint."""
    ids = {f["check_id"] for f in exposed(sample_findings)}
    assert {"ABAP-SQLI-001", "ABAP-SQLI-010", "ABAP-SQLI-011"} <= ids, ids


def test_each_one_names_the_endpoint_and_that_it_is_unauthenticated(sample_findings):
    for finding in exposed(sample_findings):
        reasons = " ".join((finding.get("details") or {}).get("exposure_reasons") or [])
        assert NODE in reasons, (finding["check_id"], reasons)
        assert "no authentication" in reasons, (finding["check_id"], reasons)


def test_the_rest_are_unknown_and_not_false(sample_findings):
    """Only the class the endpoint names is exposed. Everything else answers
    `None` — the export did not say — and never False."""
    others = [f for f in sample_findings
              if (f.get("details") or {}).get("internet_exposed") is not True]
    assert others, "every sample finding became exposed, which would be wrong"
    for finding in others:
        assert (finding.get("details") or {})["internet_exposed"] is None, (
            "%s reports a non-None, non-True exposure — this product never "
            "answers 'not exposed'" % finding["check_id"])


def test_the_new_node_is_counted_as_an_unauthenticated_service():
    """The second-order effect, asserted rather than assumed. Adding the node
    added no FINDING because NET-005 is an aggregate; what it added was an item,
    and that item is a true positive somebody should see."""
    from modules.network_services import NetworkServiceAuditor
    with contextlib.redirect_stdout(io.StringIO()), \
            contextlib.redirect_stderr(io.StringIO()):
        data = DataLoader(ROOT / "sample_data").load_all()
        try:
            findings = NetworkServiceAuditor(data, {}, {}).run_all_checks()
        except TypeError:
            findings = NetworkServiceAuditor(data, {}).run_all_checks()
    net005 = [f for f in findings if f["check_id"] == "NET-005"]
    assert net005, "NET-005 stopped firing on the sample"
    items = " ".join(str(i) for i in (net005[0].get("affected_items") or []))
    assert NODE in items, (
        "NET-005 does not name %s. An unauthenticated node that the exposure "
        "join reports on, and the network check does not, is two modules "
        "disagreeing about the same row." % NODE)
