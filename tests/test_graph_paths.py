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


def test_every_hop_node_type_is_a_registered_object_type():
    """`node_types` is carried into `attack_path.detail` and rendered, and was
    validated nowhere. A hop naming a type no object ever has renders a filter that
    matches nothing, and nothing fails — the same shape as a test that cannot fail.

    Checked against the case registries rather than against the types the sample
    fixture happens to emit. Those are different questions: an optional hop may cite
    a check no export in this repository triggers, and its type is still correct.
    Asserting against the fixture would make coverage of the sample data look like
    correctness of the content, which is the confusion the `used`-edge counts exist
    to avoid elsewhere.
    """
    from server.identity import _CASE_SENSITIVE_TYPES, _UPPERCASE_TYPES

    registered = _UPPERCASE_TYPES | _CASE_SENSITIVE_TYPES
    unknown = []
    for p in load_templates()["paths"]:
        for h in p["hops"]:
            for t in h.get("node_types") or []:
                if t not in registered:
                    unknown.append(f"{p['id']} / {h['name']}: {t}")
    assert not unknown, (
        "hops declare object types that no registry knows, so they can never "
        "match a node: " + "; ".join(unknown))


def test_every_loss_scenario_is_reachable_by_some_path():
    """The orphan this was written for: SAP-DATA-04 — HANA data exfiltration to a
    GDPR-regulated breach — was priced by the FAIR model and targeted by none of the
    seven templates. The product put a currency figure on data exfiltration and the
    graph never showed a route to it.

    The reverse test (every path targets a real scenario) already existed and passes
    happily on that state, because a dangling scenario id is visible and a missing
    path is not. A reader seeing paths that end only in privilege, fraud, RCE and
    interface compromise would reasonably conclude exfiltration is not modelled.

    Deliberately strict. If a scenario is genuinely unreachable by configuration
    alone, the honest response is to say so in data/fair_scenarios.json and retire
    the scenario — not to leave it priced and unreachable.
    """
    scenarios = {s["id"]: s.get("name", "") for s in json.loads(
        (ROOT / "data" / "fair_scenarios.json").read_text(encoding="utf-8"))["scenarios"]}
    targeted = {p["fair_scenario"] for p in load_templates()["paths"]}
    orphaned = sorted(set(scenarios) - targeted)
    assert not orphaned, (
        "these loss scenarios are priced but no path reaches them: "
        + ", ".join(f"{s} ({scenarios[s]})" for s in orphaned)
        + " — the report would quantify a loss it never shows a route to.")


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


# ── what a choke point is worth ──────────────────────────────────────────────
#
# Every path names the FAIR scenario it ends at and every scenario carries an
# annual figure. Joining them is what turns "close this and 4 paths die" into
# "close this and $X of annual exposure has no route left" — and it is also the
# easiest place in this product to overclaim, because the flattering arithmetic
# is one SQL sum away.


def _price(conn, landscape_id, scenario, ale_mean, applied=True):
    """A completed run carrying one scenario's annual figure.

    `applied` is the customer's own loss figures having been supplied. It is a
    parameter rather than a constant because the interesting case is the false
    one: a stored figure the customer never priced must not reach the worklist
    as their money.
    """
    import json
    run = db_one(conn, "INSERT INTO scan_run (landscape_id, status) "
                       "VALUES (%s,'complete') RETURNING id", (landscape_id,))

    # THE SHAPE server/crq.py ACTUALLY WRITES, which is two rows.
    #
    # `loss_model` is a property of the RUN and is stored once, on the portfolio
    # row whose scenario_id is NULL. An earlier version of this helper put it on
    # the per-scenario row because that is where the query looked for it — so the
    # test asserted the query against a shape nothing produces, and the gate
    # could never open on a real deployment while every test passed. Found by
    # loading a real estate, not by reading the code.
    conn.execute(
        "INSERT INTO crq_result (scan_run_id, scenario_id, ale_mean, ale_p90, "
        "detail) VALUES (%s, NULL, %s, %s, %s)",
        (run, ale_mean, ale_mean * 2,
         json.dumps({"loss_model": {"applied": applied}})))
    conn.execute(
        "INSERT INTO crq_result (scan_run_id, scenario_id, ale_mean, ale_p90) "
        "VALUES (%s,%s,%s,%s)", (run, scenario, ale_mean, ale_mean * 2))
    return run


def db_one(conn, sql, params):
    return conn.execute(sql, params).fetchone()["id"]


def _one_path(pid, scenario, cut_check):
    return {"id": pid, "name": pid, "fair_scenario": scenario, "severity": "HIGH",
            "hops": [{"name": "cut", "required": True, "cut": True,
                      "checks": [cut_check], "why_cut": "test"}]}


@pytestmark_db
def test_severing_every_path_to_a_scenario_names_the_money(landscape):
    """The one claim the graph actually supports: no route left at all."""
    from server import db, graph

    with db.connection() as conn:
        _seed(conn, landscape, ["M-ONLY"])
        conn.commit()
        _price(conn, landscape, "SAP-RCE-01", 4_000_000)
        run = db_one(conn, "INSERT INTO scan_run (landscape_id, status) "
                           "VALUES (%s,'complete') RETURNING id", (landscape,))
        graph.store_paths(conn, landscape, run,
                          {"paths": [_one_path("M-1", "SAP-RCE-01", "M-ONLY")]})
        conn.commit()

    row = [c for c in graph.chokepoints(None, landscape_id=landscape)
           if c["check_id"] == "M-ONLY"][0]
    assert float(row["ale_severed"]) == 4_000_000
    detail = row["scenario_detail"][0]
    assert detail["severs_all"] is True
    assert detail["paths_cut"] == detail["paths_open"] == 1


@pytestmark_db
def test_severing_some_paths_names_no_money(landscape):
    """THE OVERCLAIM THIS EXISTS TO PREVENT.

    A scenario reachable by two paths is not closed by cutting one of them, so
    none of its annual figure has been removed. The row still says one of two —
    that is true and useful — but a fraction of a scenario's ALE is a quantity
    this model does not compute, and inventing one here would be the single
    most quotable wrong number the product could produce.
    """
    from server import db, graph

    with db.connection() as conn:
        _seed(conn, landscape, ["M-HALF", "M-OTHER"])
        conn.commit()
        _price(conn, landscape, "SAP-RCE-01", 4_000_000)
        run = db_one(conn, "INSERT INTO scan_run (landscape_id, status) "
                           "VALUES (%s,'complete') RETURNING id", (landscape,))
        graph.store_paths(conn, landscape, run, {"paths": [
            _one_path("M-2", "SAP-RCE-01", "M-HALF"),
            _one_path("M-3", "SAP-RCE-01", "M-OTHER"),
        ]})
        conn.commit()

    row = [c for c in graph.chokepoints(None, landscape_id=landscape)
           if c["check_id"] == "M-HALF"][0]
    assert row["ale_severed"] is None, "a partial cut was priced"
    detail = row["scenario_detail"][0]
    assert detail["severs_all"] is False
    assert (detail["paths_cut"], detail["paths_open"]) == (1, 2)


@pytestmark_db
def test_the_money_outranks_a_bigger_path_count(landscape):
    """The behaviour change, stated as an ordering.

    A finding that cuts three paths and closes nothing is a smaller decision
    than one that cuts a single path and leaves a four-million-dollar scenario
    with no route at all. The old list put the three first.
    """
    from server import db, graph

    with db.connection() as conn:
        _seed(conn, landscape, ["M-BUSY", "M-WORTH"])
        conn.commit()
        _price(conn, landscape, "SAP-RCE-01", 4_000_000)
        run = db_one(conn, "INSERT INTO scan_run (landscape_id, status) "
                           "VALUES (%s,'complete') RETURNING id", (landscape,))
        graph.store_paths(conn, landscape, run, {"paths": [
            # three paths to an UNPRICED scenario, all cut by one finding
            _one_path("M-4", "SAP-INTF-05", "M-BUSY"),
            _one_path("M-5", "SAP-INTF-05", "M-BUSY"),
            _one_path("M-6", "SAP-INTF-05", "M-BUSY"),
            # one path to the priced one
            _one_path("M-7", "SAP-RCE-01", "M-WORTH"),
        ]})
        conn.commit()

    listed = [c["check_id"] for c in graph.chokepoints(None, landscape_id=landscape)]
    assert listed.index("M-WORTH") < listed.index("M-BUSY")


@pytestmark_db
def test_a_figure_the_customer_never_priced_is_not_their_money(landscape):
    """The catalogue's illustrative $1bn manufacturer must not arrive here.

    `crq_result.ale_mean` is populated whether or not the customer supplied
    their own loss figures, and every row written before the loss model existed
    carries the illustrative company's number. A null check would put that on
    the worklist as this customer's exposure, which is the defect
    frontend/src/lib/pricing.ts was written to stop happening on five other
    screens.
    """
    from server import db, graph

    with db.connection() as conn:
        _seed(conn, landscape, ["M-FAKE"])
        conn.commit()
        _price(conn, landscape, "SAP-RCE-01", 9_000_000, applied=False)
        run = db_one(conn, "INSERT INTO scan_run (landscape_id, status) "
                           "VALUES (%s,'complete') RETURNING id", (landscape,))
        graph.store_paths(conn, landscape, run,
                          {"paths": [_one_path("M-13", "SAP-RCE-01", "M-FAKE")]})
        conn.commit()

    row = [c for c in graph.chokepoints(None, landscape_id=landscape)
           if c["check_id"] == "M-FAKE"][0]
    assert row["ale_severed"] is None
    # The severing itself is still true and still reported: the graph's claim
    # does not depend on anybody having priced anything.
    assert row["scenario_detail"][0]["severs_all"] is True


@pytestmark_db
def test_an_uncalibrated_deployment_sees_the_list_it_always_saw(landscape):
    """Nobody loses a worklist for not having answered the money questions.

    With no priced scenario there is no `ale_severed` on any row, and the order
    falls back to paths cut then severity — which is what this screen did
    before there was any money on it.
    """
    from server import db, graph

    with db.connection() as conn:
        _seed(conn, landscape, ["M-A", "M-B"])
        conn.commit()
        run = db_one(conn, "INSERT INTO scan_run (landscape_id, status) "
                           "VALUES (%s,'complete') RETURNING id", (landscape,))
        graph.store_paths(conn, landscape, run, {"paths": [
            _one_path("M-8", "SAP-RCE-01", "M-A"),
            _one_path("M-9", "SAP-RCE-01", "M-A"),
            _one_path("M-10", "SAP-DATA-04", "M-B"),
        ]})
        conn.commit()

    rows = graph.chokepoints(None, landscape_id=landscape)
    assert all(r["ale_severed"] is None for r in rows)
    assert [r["check_id"] for r in rows][0] == "M-A"      # cuts two, not one


@pytestmark_db
def test_a_closed_path_is_not_counted_in_the_denominator(landscape):
    """Otherwise closing paths makes the remaining ones look un-severable.

    `paths_open` counts only open paths, so a scenario whose other route has
    already been shut becomes severable by the finding on the route that is
    left — which is exactly the progress the journey exists to show.
    """
    from server import db, graph

    with db.connection() as conn:
        _seed(conn, landscape, ["M-LAST", "M-GONE"])
        conn.commit()
        _price(conn, landscape, "SAP-RCE-01", 4_000_000)
        run = db_one(conn, "INSERT INTO scan_run (landscape_id, status) "
                           "VALUES (%s,'complete') RETURNING id", (landscape,))
        graph.store_paths(conn, landscape, run, {"paths": [
            _one_path("M-11", "SAP-RCE-01", "M-LAST"),
            _one_path("M-12", "SAP-RCE-01", "M-GONE"),
        ]})
        conn.commit()
        conn.execute("UPDATE attack_path SET closed_at = now() "
                     "WHERE template_id = %s AND landscape_id = %s",
                     ("M-12", landscape))
        conn.commit()

    row = [c for c in graph.chokepoints(None, landscape_id=landscape)
           if c["check_id"] == "M-LAST"][0]
    assert float(row["ale_severed"]) == 4_000_000


# ── the smallest set of fixes that closes a scenario ─────────────────────────
#
# A single finding almost never severs a scenario on a real estate — the
# reference landscape has four to six independent routes to each — so the
# chokepoint worklist shows no figure on any row. A SET is the unit that
# actually closes something and the unit somebody schedules.


def _cut_path(pid, scenario, checks):
    """A path whose single hop is cut by every check named."""
    return {"id": pid, "name": pid, "fair_scenario": scenario, "severity": "HIGH",
            "hops": [{"name": "cut", "required": True, "cut": True,
                      "checks": list(checks), "why_cut": "test"}]}


@pytestmark_db
def test_two_fixes_close_two_routes_that_share_nothing(landscape):
    from server import db, graph

    with db.connection() as conn:
        _seed(conn, landscape, ["S-A", "S-B"])
        conn.commit()
        _price(conn, landscape, "SAP-RCE-01", 4_000_000)
        run = db_one(conn, "INSERT INTO scan_run (landscape_id, status) "
                           "VALUES (%s,'complete') RETURNING id", (landscape,))
        graph.store_paths(conn, landscape, run, {"paths": [
            _cut_path("S-1", "SAP-RCE-01", ["S-A"]),
            _cut_path("S-2", "SAP-RCE-01", ["S-B"]),
        ]})
        conn.commit()

    entry = [e for e in graph.severing_sets(None, landscape_id=landscape)
             if e["scenario"] == "SAP-RCE-01"][0]
    assert entry["closable"] is True
    assert entry["paths_open"] == 2
    assert {f["check_id"] for f in entry["fixes"]} == {"S-A", "S-B"}
    assert float(entry["ale_mean"]) == 4_000_000


@pytestmark_db
def test_it_finds_the_one_fix_that_does_the_work_of_two(landscape):
    """The smallest set, not merely A set. One finding on both routes beats
    one from each, and a greedy pass that took the first hit would miss it."""
    from server import db, graph

    with db.connection() as conn:
        _seed(conn, landscape, ["S-BOTH", "S-ONE", "S-TWO"])
        conn.commit()
        run = db_one(conn, "INSERT INTO scan_run (landscape_id, status) "
                           "VALUES (%s,'complete') RETURNING id", (landscape,))
        graph.store_paths(conn, landscape, run, {"paths": [
            _cut_path("S-3", "SAP-DATA-04", ["S-BOTH", "S-ONE"]),
            _cut_path("S-4", "SAP-DATA-04", ["S-BOTH", "S-TWO"]),
        ]})
        conn.commit()

    entry = [e for e in graph.severing_sets(None, landscape_id=landscape)
             if e["scenario"] == "SAP-DATA-04"][0]
    assert [f["check_id"] for f in entry["fixes"]] == ["S-BOTH"]


@pytestmark_db
def test_a_route_nothing_can_sever_makes_the_scenario_unclosable(landscape):
    """THE MOST DANGEROUS SENTENCE THIS COULD PRODUCE.

    A path with no cut hop cannot be closed by fixing findings at all. Dropping
    such paths before the search is the obvious implementation and it would tell
    somebody "close these two and the scenario is gone" while a route stayed
    wide open — a false all-clear, which is worse than no answer.
    """
    from server import db, graph

    with db.connection() as conn:
        _seed(conn, landscape, ["S-CUT", "S-SOFT"])
        conn.commit()
        run = db_one(conn, "INSERT INTO scan_run (landscape_id, status) "
                           "VALUES (%s,'complete') RETURNING id", (landscape,))
        graph.store_paths(conn, landscape, run, {"paths": [
            _cut_path("S-5", "SAP-INTF-05", ["S-CUT"]),
            # required, holds, and severs nothing when closed
            {"id": "S-6", "name": "S-6", "fair_scenario": "SAP-INTF-05",
             "severity": "HIGH",
             "hops": [{"name": "soft", "required": True, "cut": False,
                       "checks": ["S-SOFT"]}]},
        ]})
        conn.commit()

    entry = [e for e in graph.severing_sets(None, landscape_id=landscape)
             if e["scenario"] == "SAP-INTF-05"][0]
    assert entry["closable"] is False
    assert entry["fixes"] == []
    assert "no hop" in entry["reason"]


@pytestmark_db
def test_an_unpriced_scenario_still_gets_its_plan(landscape):
    """The set is a fact about the graph. Only the money needs the answers."""
    from server import db, graph

    with db.connection() as conn:
        _seed(conn, landscape, ["S-P"])
        conn.commit()
        _price(conn, landscape, "SAP-PRIV-03", 7_000_000, applied=False)
        run = db_one(conn, "INSERT INTO scan_run (landscape_id, status) "
                           "VALUES (%s,'complete') RETURNING id", (landscape,))
        graph.store_paths(conn, landscape, run,
                          {"paths": [_cut_path("S-7", "SAP-PRIV-03", ["S-P"])]})
        conn.commit()

    entry = [e for e in graph.severing_sets(None, landscape_id=landscape)
             if e["scenario"] == "SAP-PRIV-03"][0]
    assert entry["closable"] is True
    assert [f["check_id"] for f in entry["fixes"]] == ["S-P"]
    assert entry["ale_mean"] is None, "an unpriced figure reached the plan"


@pytestmark_db
def test_a_closed_route_is_not_one_that_needs_fixing(landscape):
    """Otherwise the plan keeps asking for work that has already been done."""
    from server import db, graph

    with db.connection() as conn:
        _seed(conn, landscape, ["S-LIVE", "S-DEAD"])
        conn.commit()
        run = db_one(conn, "INSERT INTO scan_run (landscape_id, status) "
                           "VALUES (%s,'complete') RETURNING id", (landscape,))
        graph.store_paths(conn, landscape, run, {"paths": [
            _cut_path("S-8", "SAP-FRAUD-02", ["S-LIVE"]),
            _cut_path("S-9", "SAP-FRAUD-02", ["S-DEAD"]),
        ]})
        conn.commit()
        conn.execute("UPDATE attack_path SET closed_at = now() "
                     "WHERE template_id = %s AND landscape_id = %s",
                     ("S-9", landscape))
        conn.commit()

    entry = [e for e in graph.severing_sets(None, landscape_id=landscape)
             if e["scenario"] == "SAP-FRAUD-02"][0]
    assert entry["paths_open"] == 1
    assert [f["check_id"] for f in entry["fixes"]] == ["S-LIVE"]


def test_the_cover_is_exact_not_greedy():
    """Pure arithmetic, no database.

    The classic case where greedy loses: the finding on the most routes is not
    in any smallest set. Greedy takes {A} then needs two more; the answer is two.
    """
    from server.graph import _smallest_cover

    # The textbook instance where taking the biggest set first costs you a fix.
    # Eight routes:
    #   A cuts routes 0-5   (six — greedy grabs it, and is then stuck with
    #                        two singletons for routes 6 and 7)
    #   B cuts routes 0,1,2 and 6
    #   C cuts routes 3,4,5 and 7
    # B and C between them cut all eight. Greedy answers three; the answer is two.
    paths = [{"A", "B"}, {"A", "B"}, {"A", "B"},
             {"A", "C"}, {"A", "C"}, {"A", "C"},
             {"B"}, {"C"}]
    chosen = _smallest_cover(paths)
    assert len(chosen) == 2, "greedy would have answered 3 here"
    assert set(chosen) == {"B", "C"}
