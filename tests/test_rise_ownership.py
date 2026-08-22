"""Who owns a finding under RISE, and the two products agreeing about it.

WHAT WAS WRONG. The ownership oracle lived entirely in `server/enrich.py`, so only
the client-server product could answer "is this mine to fix?". The offline
scanner — the primary distribution, the one a customer runs before they have
bought anything — produced reports with no ownership on any finding at all, while
`docs/RISE_SECURITY_MODEL.md` section 7.4 calls that tag "the argument that
justifies buying anything at all in a RISE tenant".

WHAT THESE TESTS ARE FOR. That there is ONE definition rather than two that drift,
that the offline path is actually wired to it, and that the heuristic half stays
labelled as a heuristic — a wrong "SAP's problem" hides a real finding, which is
worse than an extra one to dismiss.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import rise_ownership as own                # noqa: E402
from server import edges                                 # noqa: E402

RISE = "rise_pce"


def _f(check_id, *dests):
    return {"check_id": check_id,
            "affected_objects": [{"type": "destination", "name": d} for d in dests]}


# ═════════════════════════════════════════════════════════════════════════════
#  One definition, two products
# ═════════════════════════════════════════════════════════════════════════════

def test_the_oracle_lives_in_modules_so_the_offline_product_can_reach_it():
    """`modules/` is stdlib-only and `server/` may import it; the reverse would
    put psycopg and FastAPI behind an offline scan. Living in `server/` was why
    the offline path had no ownership at all."""
    assert (ROOT / "modules" / "rise_ownership.py").is_file()


def test_enrich_re_exports_rather_than_redefining():
    """Two vocabularies for one concept is how a product tells a customer two
    different things about the same finding. `server/enrich.py` is now a caller."""
    src = (ROOT / "server" / "enrich.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    defined = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
    for name in ("remediation_owner_for", "classify_destination_owner", "team_for",
                 "sla_due_date", "destination_hosts", "owner_for_finding"):
        assert name not in defined, f"{name} redefined in server/enrich.py"
    assert "from modules.rise_ownership import" in src


def test_the_offline_scanner_is_wired_to_it():
    """A shared oracle nothing calls is the state this change was made to leave
    behind. Checked structurally because `main()` needs a data directory and a
    full run to exercise."""
    src = (ROOT / "sap_scanner.py").read_text(encoding="utf-8")
    assert "rise_ownership" in src
    assert "owner_for_finding" in src
    assert '"remediation_owner"' in src


def test_the_oracle_imports_nothing_the_offline_product_lacks():
    """The dependency charter: `modules/` is stdlib-only. This file was moved out
    of a package that is exempt, so the check matters more here than usual."""
    tree = ast.parse((ROOT / "modules" / "rise_ownership.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".")[0]
            assert root in ("__future__", "datetime", "typing", "modules"), node.module
        elif isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in ("datetime", "typing"), a.name


# ═════════════════════════════════════════════════════════════════════════════
#  The verdicts
# ═════════════════════════════════════════════════════════════════════════════

def test_a_profile_parameter_is_not_the_customers_to_fix_under_rise():
    """SAP executes parameter maintenance; KBA 3460793 records the customer unable
    to save in RZ10. Reporting PARAM-* as customer-fixable sends them at work they
    are contractually barred from doing."""
    assert own.owner_for_finding({"check_id": "PARAM-001"}, RISE)[0] == "ticket_to_sap"


def test_the_same_finding_is_the_customers_on_premise():
    """Outside RISE they own every layer, so the question does not arise. This is
    the truth there, not a default."""
    assert own.owner_for_finding({"check_id": "PARAM-001"}, "on_prem")[0] \
        == "customer_fixable"


def test_an_os_sourced_check_with_no_evidence_is_not_assessable_rather_than_passing():
    """A gateway ACL check in RISE saw no file. "We could not look" must not
    render as a verdict in either direction."""
    owner, _ = own.owner_for_finding({"check_id": "INTG-GW-001"}, RISE,
                                     supplied_sources=set())
    assert owner == "not_assessable"


def test_evidence_the_customer_obtained_anyway_is_not_discarded():
    """If they got the gateway file some other way and uploaded it, the finding is
    real. Marking it unassessable by general rule would throw away work they went
    to the trouble of doing."""
    owner, _ = own.owner_for_finding({"check_id": "INTG-GW-001"}, RISE,
                                     supplied_sources={"gw_secinfo"})
    assert owner != "not_assessable"


def test_a_finding_naming_only_sap_destinations_is_downgraded():
    owner, note = own.owner_for_finding(_f("TRUST-004", "SAPOSS"), RISE,
                                        dest_hosts={"SAPOSS": ""})
    assert owner == "provider_owned"
    assert note and "heuristic" in note


def test_a_finding_spanning_both_stays_the_customers():
    """THE ALL-OR-NOTHING RULE. A finding naming one SAP destination and one of
    theirs is still actionable on theirs, and marking it provider-owned would hide
    real work behind SAP's name."""
    owner, _ = own.owner_for_finding(
        _f("TRUST-004", "SAPOSS", "Z_PAYROLL_PROD"), RISE,
        dest_hosts={"SAPOSS": "", "Z_PAYROLL_PROD": "hr.example.com"})
    assert owner == "customer_fixable"


def test_a_sap_service_host_is_sap_operated_but_a_saas_tenant_is_not():
    """`*.sap.com` is not a rule: an Ariba or SuccessFactors tenant is a customer
    integration the customer very much owns. Only the support domains count."""
    assert own.classify_destination_owner("Z_X", "abc.sapserv.com", RISE) == "sap"
    assert own.classify_destination_owner("Z_Y", "acme.ariba.com", RISE) == "customer"


def test_an_unnamed_destination_says_unknown_rather_than_guessing():
    """A wrong "SAP's problem" hides a real finding, which is worse than an extra
    one to dismiss."""
    assert own.classify_destination_owner("", "", RISE) == "unknown"


def test_provider_bound_work_gets_a_longer_clock_not_a_shorter_one():
    """The customer does not control SAP's queue, so measuring them against the
    same window would attribute the provider's latency to them."""
    assert own.SLA_DAYS_PROVIDER["P1"] > own.SLA_DAYS["P1"]


# ═════════════════════════════════════════════════════════════════════════════
#  Graph edges — the column that was always `unknown`
# ═════════════════════════════════════════════════════════════════════════════

def test_a_destination_edge_carries_who_operates_it():
    """`graph_edge.owner` held `customer|sap|unknown` since the schema landed and
    every edge was written `unknown`, while the classifier answering exactly this
    sat a few files away."""
    es, stats = edges.extract_edges(
        [{"check_id": "TRUST-004",
          "affected_objects": [{"type": "user", "name": "U"},
                               {"type": "destination", "name": "SAPOSS"}]}],
        deployment_mode=RISE, dest_hosts={"SAPOSS": ""})
    assert [e["owner"] for e in es] == ["sap"]
    assert stats["owner_sap"] == 1


def test_a_customer_destination_edge_says_customer():
    es, _ = edges.extract_edges(
        [{"check_id": "TRUST-004",
          "affected_objects": [{"type": "user", "name": "U"},
                               {"type": "destination", "name": "Z_PAYROLL"}]}],
        deployment_mode=RISE, dest_hosts={"Z_PAYROLL": "hr.example.com"})
    assert [e["owner"] for e in es] == ["customer"]


def test_a_role_edge_does_not_borrow_the_destination_heuristic():
    """A role has no operator distinct from the system it lives in. Applying a
    naming heuristic built for RFC destinations would invent an answer."""
    es, _ = edges.extract_edges(
        [{"check_id": "AUTH-002",
          "affected_objects": [{"type": "user", "name": "U"},
                               {"type": "role", "name": "Z_SUPER"}]}],
        deployment_mode=RISE, dest_hosts={})
    assert {e["owner"] for e in es} == {"unknown"}


def test_without_the_sm59_export_an_edge_says_unknown_not_customer():
    """No export is not evidence the destination is theirs. `unknown` is the
    honest answer and the ingest COALESCE keeps any better one already recorded."""
    es, _ = edges.extract_edges(
        [{"check_id": "TRUST-004",
          "affected_objects": [{"type": "user", "name": "U"},
                               {"type": "destination", "name": "SAPOSS"}]}],
        deployment_mode=RISE, dest_hosts=None)
    assert {e["owner"] for e in es} == {"unknown"}


def test_on_premise_every_destination_edge_is_the_customers():
    es, _ = edges.extract_edges(
        [{"check_id": "TRUST-004",
          "affected_objects": [{"type": "user", "name": "U"},
                               {"type": "destination", "name": "SAPOSS"}]}],
        deployment_mode="on_prem", dest_hosts={"SAPOSS": ""})
    assert {e["owner"] for e in es} == {"customer"}


# ═════════════════════════════════════════════════════════════════════════════
#  Against the real corpus
# ═════════════════════════════════════════════════════════════════════════════

def test_the_sample_landscape_splits_the_work_between_the_two_parties():
    """The point of the whole exercise: before this, an offline RISE report gave a
    customer 75 findings with no indication which of them they could act on."""
    import contextlib
    import importlib
    import io
    from collections import Counter

    from modules.data_loader import DataLoader
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(ROOT / "sample_data").load_all()
        findings = []
        for name in ("security_params", "system_trust", "abap_authorizations"):
            module = importlib.import_module("modules." + name)
            cls = next(getattr(module, n) for n in dir(module)
                       if n.endswith("Auditor") and n != "BaseAuditor")
            findings += cls(data, {}).run_all_checks()

    hosts = own.destination_hosts(data)
    supplied = {k for k, v in data.items() if v}
    counts = Counter(own.owner_for_finding(f, RISE, hosts, supplied)[0]
                     for f in findings)
    assert counts["ticket_to_sap"] > 0, "no finding routed to SAP in a RISE tenant"
    assert counts["customer_fixable"] > 0, "nothing left for the customer to do"

    on_prem = Counter(own.owner_for_finding(f, "on_prem", hosts, supplied)[0]
                      for f in findings)
    assert on_prem["customer_fixable"] == len(findings)
