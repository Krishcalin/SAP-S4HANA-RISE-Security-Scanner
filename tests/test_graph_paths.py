"""
Attack paths: instantiation, cuts, chokepoints and closure.

The load-bearing test is `test_a_path_closes_when_its_cut_is_remediated`. Closure
over time is the differentiating claim of the whole feature — neither the
commercial SAP attack-path tool nor the open-source one claims longitudinal
tracking of path closure — and it only works because a path is a stored row with a
lifecycle rather than a query re-run on each page load.

The template tests matter too, quietly: a template referencing a check the scanner
does not emit would produce a hop that can never hold, so the path would silently
never instantiate and nobody would notice a path was missing.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.graph import load_templates, ruleset_fingerprint  # noqa: E402

SAMPLE = ROOT / "sample_data"


def _all_check_ids():
    import contextlib
    import importlib
    import io
    from modules.data_loader import DataLoader
    from server.ingest import AUDITORS, RUN_CONTEXT
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(SAMPLE).load_all()
        out = set()
        for mod, cls in AUDITORS:
            for f in (getattr(importlib.import_module(f"modules.{mod}"), cls)(
                    data, None, RUN_CONTEXT).run_all_checks() or []):
                out.add(f["check_id"])
    return out


# --------------------------------------------------------------------------- #
#  The templates are content, and content can be wrong                        #
# --------------------------------------------------------------------------- #

def test_every_template_is_well_formed():
    tpl = load_templates()
    paths = tpl.get("paths") or []
    assert paths, "no path templates"

    ids = [p["id"] for p in paths]
    assert len(ids) == len(set(ids)), f"duplicate template ids: {ids}"

    for p in paths:
        assert p.get("fair_scenario"), f"{p['id']} does not end at a loss scenario"
        assert p.get("severity") in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        hops = p.get("hops") or []
        assert hops, f"{p['id']} has no hops"
        assert any(h.get("required") for h in hops), \
            f"{p['id']} has no required hop, so it would instantiate unconditionally"
        assert any(h.get("cut") for h in hops), (
            f"{p['id']} has no cut — the console could show the path but could never "
            f"tell anyone how to close it")
        for h in hops:
            assert h.get("checks"), f"{p['id']} hop '{h['name']}' cites no checks"
            if h.get("cut"):
                assert h.get("why_cut"), (
                    f"{p['id']} hop '{h['name']}' claims to be a cut without saying why")


def test_every_path_targets_a_real_loss_scenario():
    """A path ends at a currency figure. A dangling scenario id would render as a
    blank exposure column and quietly undo that."""
    scenarios = {s["id"] for s in json.loads(
        (ROOT / "data" / "fair_scenarios.json").read_text(encoding="utf-8"))["scenarios"]}
    for p in load_templates()["paths"]:
        assert p["fair_scenario"] in scenarios, (
            f"{p['id']} targets unknown scenario {p['fair_scenario']}; "
            f"known: {sorted(scenarios)}")


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_required_hops_cite_checks_the_scanner_can_actually_emit():
    """A REQUIRED hop citing only checks that no module emits can never hold, so its
    path would silently never instantiate — a missing path is invisible in a way a
    wrong one is not.

    Optional hops are allowed to cite checks absent from this fixture: they enrich a
    path without gating it, and sample_data is not obliged to trigger everything.
    """
    emitted = _all_check_ids()
    problems = []
    for p in load_templates()["paths"]:
        for h in p["hops"]:
            if not h.get("required"):
                continue
            if not (set(h["checks"]) & emitted):
                problems.append(f"{p['id']} / {h['name']}: {h['checks']}")
    assert not problems, (
        "required hops citing no emittable check — these paths can never "
        f"instantiate:\n  " + "\n  ".join(problems))


def test_the_ruleset_fingerprint_moves_only_when_the_rules_do():
    a = ruleset_fingerprint()
    assert a == ruleset_fingerprint(), "fingerprint is not stable"

    tpl = load_templates()
    tpl["paths"][0]["hops"][0]["checks"].append("ZZZ-999")
    assert ruleset_fingerprint(tpl) != a, \
        "a changed ruleset produced the same fingerprint, so stale paths would look current"

    # Metadata is not part of the rules.
    tpl2 = load_templates()
    tpl2["_meta"]["description"] = "reworded"
    assert ruleset_fingerprint(tpl2) == a, \
        "an editorial change invalidated every stored path"


# --------------------------------------------------------------------------- #
#  Destination ownership                                                      #
# --------------------------------------------------------------------------- #

def test_sap_operated_destinations_are_not_the_customers_problem():
    from server.enrich import classify_destination_owner as owner

    assert owner("SAPOSS", "", "rise_pce") == "sap"
    assert owner("SM_PRDCLNT100", "", "rise_pce") == "sap"
    assert owner("SAPNET_RFC", "", "rise_pce") == "sap"
    # Customer integrations are the customer's, including SAP-branded SaaS.
    assert owner("ARIBA_CLOUD", "ariba.cloud.sap.com", "rise_pce") == "customer"
    assert owner("SF_EC_CONNECT", "api.successfactors.com", "rise_pce") == "customer"
    assert owner("VENDOR_PORTAL", "203.0.113.55", "rise_pce") == "customer"


def test_on_premise_everything_is_the_customers():
    from server.enrich import classify_destination_owner as owner
    assert owner("SAPOSS", "", "on_prem") == "customer"


def test_a_finding_spanning_both_owners_stays_actionable():
    """Only downgrade when EVERY destination named is SAP's. A finding covering both
    is still real work on the customer's own destinations, and marking it
    provider-owned would hide it."""
    from server.enrich import enrich

    mixed = {"check_id": "NET-001", "severity": "HIGH", "title": "t", "description": "d",
             "affected_objects": [{"type": "destination", "name": "SAPOSS"},
                                  {"type": "destination", "name": "VENDOR_PORTAL"}]}
    only_sap = {"check_id": "NET-001", "severity": "HIGH", "title": "t", "description": "d",
                "affected_objects": [{"type": "destination", "name": "SAPOSS"}]}

    out = enrich([mixed, only_sap], "rise_pce", set(), {"SAPOSS": "", "VENDOR_PORTAL": ""})
    assert out[id(mixed)]["remediation_owner"] == "customer_fixable"
    assert out[id(only_sap)]["remediation_owner"] == "provider_owned"


# --------------------------------------------------------------------------- #
#  Instantiation and closure — against a real database                        #
# --------------------------------------------------------------------------- #

pytestmark_db = pytest.mark.skipif(
    not __import__("os").getenv("DB_DSN"), reason="set DB_DSN for the DB-backed tests")


@pytest.fixture()
def landscape():
    from server import db
    import os
    db.init_schema()
    row = db.one("INSERT INTO landscape (name, deployment_mode) "
                 "VALUES (%s,'rise_pce') RETURNING id", (f"g-{os.urandom(5).hex()}",))
    yield row["id"]
    db.execute("DELETE FROM landscape WHERE id = %s", (row["id"],))


def _seed(conn, landscape_id, check_ids, system_id=None):
    """Open one finding per check id, so a hop can be made to hold or not."""
    for cid in check_ids:
        conn.execute("INSERT INTO check_definition (check_id, title) VALUES (%s,%s) "
                     "ON CONFLICT (check_id) DO NOTHING", (cid, cid))
        conn.execute(
            "INSERT INTO finding (landscape_id, system_id, fingerprint, check_id, "
            "severity, state) VALUES (%s,%s,%s,%s,'HIGH','open')",
            (landscape_id, system_id, __import__("os").urandom(16).hex(), cid))


@pytestmark_db
def test_a_path_needs_every_required_hop(landscape):
    from server import db, graph

    tpl = {"paths": [{
        "id": "T-1", "name": "Test", "fair_scenario": "SAP-RCE-01", "severity": "HIGH",
        "hops": [
            {"name": "entry", "required": True, "cut": False, "checks": ["G-ENTRY"]},
            {"name": "pivot", "required": True, "cut": True, "checks": ["G-CUT"],
             "why_cut": "test"},
        ]}]}

    with db.connection() as conn:
        _seed(conn, landscape, ["G-ENTRY"])
        conn.commit()
        assert graph.instantiate(conn, landscape, tpl) == [], \
            "a path instantiated with a required hop missing"

        _seed(conn, landscape, ["G-CUT"])
        conn.commit()
        live = graph.instantiate(conn, landscape, tpl)
        assert len(live) == 1
        assert live[0]["template_id"] == "T-1"


@pytestmark_db
def test_a_path_closes_when_its_cut_is_remediated(landscape):
    """THE test. Closure over time is the differentiating claim, and it only works
    because a path is a stored row: closing it must keep the row, its first_seen and
    its identity so the closure can be shown and a return can re-open the same path.
    """
    from server import db, graph

    tpl = {"paths": [{
        "id": "T-2", "name": "Closable", "fair_scenario": "SAP-RCE-01",
        "severity": "CRITICAL",
        "hops": [
            {"name": "entry", "required": True, "cut": False, "checks": ["G2-ENTRY"]},
            {"name": "the cut", "required": True, "cut": True, "checks": ["G2-CUT"],
             "why_cut": "test"},
        ]}]}

    with db.connection() as conn:
        _seed(conn, landscape, ["G2-ENTRY", "G2-CUT"])
        conn.commit()
        run = db.one("INSERT INTO scan_run (landscape_id, status) VALUES (%s,'complete') "
                     "RETURNING id", (landscape,))["id"]

        first = graph.store_paths(conn, landscape, run, tpl)
        conn.commit()
        assert first["open"] == 1 and len(first["opened"]) == 1
        path_id = first["opened"][0]
        before = db.one("SELECT first_seen, closed_at FROM attack_path WHERE id=%s",
                        (path_id,))
        assert before["closed_at"] is None

        # Remediate the CUT only. The entry condition still holds.
        conn.execute("UPDATE finding SET state='resolved' WHERE landscape_id=%s "
                     "AND check_id='G2-CUT'", (landscape,))
        conn.commit()

        second = graph.store_paths(conn, landscape, run, tpl)
        conn.commit()
        assert second["open"] == 0
        assert path_id in second["closed"]

        after = db.one("SELECT first_seen, closed_at FROM attack_path WHERE id=%s",
                       (path_id,))
        assert after is not None, "the path row was DELETED; closure is unshowable"
        assert after["closed_at"] is not None, "the path did not record its closure"
        assert after["first_seen"] == before["first_seen"], \
            "closing the path reset its history"

        # And it returns as the SAME path, not a new one.
        conn.execute("UPDATE finding SET state='open' WHERE landscape_id=%s "
                     "AND check_id='G2-CUT'", (landscape,))
        conn.commit()
        third = graph.store_paths(conn, landscape, run, tpl)
        conn.commit()
        assert path_id in third["reopened"]
        assert not third["opened"], "the returning path was raised as a NEW path"
        reopened = db.one("SELECT first_seen, closed_at FROM attack_path WHERE id=%s",
                          (path_id,))
        assert reopened["closed_at"] is None
        assert reopened["first_seen"] == before["first_seen"]


@pytestmark_db
def test_an_accepted_risk_does_not_close_a_path(landscape):
    """A risk acceptance is a decision to tolerate a defect, not evidence it is gone.
    An attacker is unmoved by paperwork, so the route stays open."""
    from server import db, graph

    tpl = {"paths": [{
        "id": "T-3", "name": "Accepted", "fair_scenario": "SAP-RCE-01", "severity": "HIGH",
        "hops": [{"name": "only", "required": True, "cut": True, "checks": ["G3-X"],
                  "why_cut": "test"}]}]}
    with db.connection() as conn:
        _seed(conn, landscape, ["G3-X"])
        conn.execute("UPDATE finding SET state='accepted' WHERE landscape_id=%s",
                     (landscape,))
        conn.commit()
        assert len(graph.instantiate(conn, landscape, tpl)) == 1, \
            "accepting the risk made the attack path disappear"

        conn.execute("UPDATE finding SET state='mitigated' WHERE landscape_id=%s",
                     (landscape,))
        conn.commit()
        assert graph.instantiate(conn, landscape, tpl) == [], \
            "a compensating control did not interrupt the path"


@pytestmark_db
def test_chokepoints_rank_only_cuts(landscape):
    """A finding on a non-cut hop reduces exploitability without severing anything.
    Listing it as a choke point would promise a closure it cannot deliver."""
    from server import db, graph

    tpl = {"paths": [{
        "id": "T-4", "name": "Ranked", "fair_scenario": "SAP-RCE-01", "severity": "HIGH",
        "hops": [
            {"name": "noise", "required": True, "cut": False, "checks": ["G4-NOISE"]},
            {"name": "cut", "required": True, "cut": True, "checks": ["G4-CUT"],
             "why_cut": "test"},
        ]}]}
    with db.connection() as conn:
        _seed(conn, landscape, ["G4-NOISE", "G4-CUT"])
        conn.commit()
        run = db.one("INSERT INTO scan_run (landscape_id, status) VALUES (%s,'complete') "
                     "RETURNING id", (landscape,))["id"]
        graph.store_paths(conn, landscape, run, tpl)
        conn.commit()

    checks = {c["check_id"] for c in graph.chokepoints(None, landscape_id=landscape)}
    assert "G4-CUT" in checks
    assert "G4-NOISE" not in checks, "a non-cut finding was offered as a choke point"


@pytestmark_db
def test_every_stored_path_states_it_was_not_validated(landscape):
    """We hold no connection and never will. A path that does not say so invites the
    reader to believe something was reached."""
    from server import db, graph

    tpl = {"paths": [{
        "id": "T-5", "name": "Conf", "fair_scenario": "SAP-RCE-01", "severity": "HIGH",
        "hops": [{"name": "only", "required": True, "cut": True, "checks": ["G5-X"],
                  "why_cut": "test"}]}]}
    with db.connection() as conn:
        _seed(conn, landscape, ["G5-X"])
        conn.commit()
        run = db.one("INSERT INTO scan_run (landscape_id, status) VALUES (%s,'complete') "
                     "RETURNING id", (landscape,))["id"]
        graph.store_paths(conn, landscape, run, tpl)
        conn.commit()

    row = db.one("SELECT detail FROM attack_path WHERE landscape_id=%s", (landscape,))
    assert row["detail"]["confidence"] == "derived_from_config"
    assert "traversed" in row["detail"]["confidence_note"]


@pytestmark_db
def test_row_scoping_applies_to_paths(landscape):
    from server import db, graph
    tpl = {"paths": [{
        "id": "T-6", "name": "Scoped", "fair_scenario": "SAP-RCE-01", "severity": "HIGH",
        "hops": [{"name": "only", "required": True, "cut": True, "checks": ["G6-X"],
                  "why_cut": "test"}]}]}
    sysid = db.one("INSERT INTO sap_system (landscape_id, sid, client) "
                   "VALUES (%s,'PRD','100') RETURNING id", (landscape,))["id"]
    with db.connection() as conn:
        _seed(conn, landscape, ["G6-X"], system_id=sysid)
        conn.commit()
        run = db.one("INSERT INTO scan_run (landscape_id, status) VALUES (%s,'complete') "
                     "RETURNING id", (landscape,))["id"]
        graph.store_paths(conn, landscape, run, tpl)
        conn.commit()

    assert graph.list_paths([sysid], landscape), "a scoped user could not see their path"
    assert not graph.list_paths([], landscape), \
        "an empty scope returned paths; it must mean nothing, not everything"
