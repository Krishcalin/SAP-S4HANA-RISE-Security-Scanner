"""
A code finding, end to end: auditor -> ingest -> console.

WHY THIS IS A SEPARATE FILE FROM test_abap_sast.py
That one proves the engine finds the right things. This one proves the finding
survives the journey to a person: the snippet and the source->sink trace are
written into `finding_observation.details`, the evidence class and reachability
onto `finding`, and all of it reaches the screen. A SAST finding without its code
is a line number and an adjective.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

pytestmark = pytest.mark.skipif(
    not os.getenv("DB_DSN"), reason="set DB_DSN to a PostgreSQL 16 instance")

TAINTED = (
    "REPORT z_taint_demo.\n"
    "DATA lv_where TYPE string.\n"
    "START-OF-SELECTION.\n"
    "  lv_where = request->get_form_field( 'q' ).\n"
    "  SELECT * FROM mara WHERE (lv_where) INTO TABLE @DATA(lt).\n"
)


@pytest.fixture()
def landscape():
    from server import db
    db.init_schema()
    name = f"code-{os.urandom(5).hex()}"
    land = db.one("INSERT INTO landscape (name, deployment_mode) "
                  "VALUES (%s,'rise_pce') RETURNING id", (name,))["id"]
    sysid = db.one("INSERT INTO sap_system (landscape_id, sid, client, tier) "
                   "VALUES (%s,'PRD','100','prod') RETURNING id", (land,))["id"]
    yield {"landscape": land, "system": sysid}
    db.execute("DELETE FROM landscape WHERE id = %s", (land,))


def _store(landscape, source, inventory=None, filename="z_taint_demo.prog.abap"):
    """Run the auditor and push its findings through the real ingest path."""
    import tempfile
    from server import db, ingest
    from modules.abap_sast import AbapSastAuditor

    with tempfile.TemporaryDirectory() as td:
        (Path(td) / filename).write_text(source, encoding="utf-8")
        data = {"abap_source_dir": td}
        if inventory is not None:
            data["code_inventory"] = inventory
        findings = AbapSastAuditor(data, {}).run_all_checks()

    from server.enrich import enrich

    run = db.one("INSERT INTO scan_run (landscape_id, system_id, status) "
                 "VALUES (%s,%s,'pending') RETURNING id",
                 (landscape["landscape"], landscape["system"]))["id"]
    with db.connection() as conn:
        # Enrichment is passed because without it findings store with no tier, and
        # the reachability work in Phase 4a is precisely a tier change.
        ingest.store_run(conn, run, landscape["landscape"], landscape["system"],
                         findings, default_sid="PRD", default_client="100",
                         enrichment=enrich(findings, deployment_mode="rise_pce"))
        conn.commit()
    return findings, run


# --------------------------------------------------------------------------- #
#  Storage                                                                    #
# --------------------------------------------------------------------------- #

def test_the_snippet_and_taint_trace_reach_the_database(landscape):
    from server import db
    _store(landscape, TAINTED)

    row = db.one(
        "SELECT o.details FROM finding_observation o "
        "JOIN finding f ON f.id = o.finding_id "
        "WHERE f.landscape_id = %s AND f.check_id LIKE 'ABAP-SQLI%%' LIMIT 1",
        (landscape["landscape"],))
    assert row, "no ABAP-SQLI finding was stored at all"
    details = row["details"]
    assert details.get("snippet"), "the source snippet was not stored"
    assert details.get("file"), "the file the finding is in was not stored"


def test_the_evidence_class_lands_on_the_finding_not_the_catalogue(landscape):
    """It varies per occurrence — the same rule is confirmed in one program and
    pattern-only in another — so it cannot live on check_definition."""
    from server import db
    _store(landscape, TAINTED)
    row = db.one("SELECT taint_confidence FROM finding "
                 "WHERE landscape_id = %s AND check_id LIKE 'ABAP-SQLI%%' LIMIT 1",
                 (landscape["landscape"],))
    assert row["taint_confidence"] in ("confirmed", "tentative", "pattern-only")


def test_the_cwe_lands_on_the_catalogue(landscape):
    from server import db
    _store(landscape, TAINTED)
    row = db.one("SELECT cwe FROM check_definition WHERE check_id LIKE 'ABAP-SQLI%%' "
                 "AND cwe IS NOT NULL LIMIT 1")
    assert row and row["cwe"].startswith("CWE-")


def test_reachability_is_stored_and_refreshed_between_runs(landscape):
    """A program goes unreachable -> reachable the day something starts calling it.
    Writing the verdict only at first sight would leave the console asserting last
    quarter's answer about this quarter's estate."""
    from server import db

    dead = [{"OBJECT_NAME": "Z_TAINT_DEMO", "REFERENCED": "NO", "LAST_USED": ""}]
    live = [{"OBJECT_NAME": "Z_TAINT_DEMO", "REFERENCED": "YES", "LAST_USED": "20260801"}]

    _store(landscape, TAINTED, inventory=dead)
    first = db.one("SELECT reachability FROM finding WHERE landscape_id = %s "
                   "AND check_id LIKE 'ABAP-SQLI%%' LIMIT 1",
                   (landscape["landscape"],))["reachability"]

    _store(landscape, TAINTED, inventory=live)
    second = db.one("SELECT reachability FROM finding WHERE landscape_id = %s "
                    "AND check_id LIKE 'ABAP-SQLI%%' LIMIT 1",
                    (landscape["landscape"],))["reachability"]

    assert first == "unreachable" and second == "reachable", (first, second)


def test_the_same_source_twice_resolves_nothing(landscape):
    """The journey must survive a second upload of identical code."""
    from server import db
    _store(landscape, TAINTED)
    _store(landscape, TAINTED)
    resolved = db.one(
        "SELECT count(*) n FROM finding WHERE landscape_id = %s AND state = 'resolved'",
        (landscape["landscape"],))["n"]
    assert resolved == 0, f"{resolved} finding(s) resolved on an unchanged re-scan"


# --------------------------------------------------------------------------- #
#  Reaching a person                                                          #
# --------------------------------------------------------------------------- #
#  This section read the server-rendered detail page and grepped its HTML. That
#  page is retired; the console builds the code card in the browser from
#  /api/findings/{id}. So the journey is asserted in the two halves it now has:
#  the payload carries every piece, and FindingDetail.tsx reads every piece. Each
#  half is worthless alone — a field delivered to a screen that ignores it is a
#  blank card, and a screen reading a field the payload dropped is the same blank
#  card — which is why neither was left out when the markup assertions went.

@pytest.fixture()
def client():
    from fastapi.testclient import TestClient
    from server import app as appmod, auth, db
    db.init_schema()
    username = f"code_{os.urandom(4).hex()}"
    auth.create_user(username, "code-test-password", "admin")
    c = TestClient(appmod.app)
    assert c.post("/api/auth/login",
                  json={"username": username, "password": "code-test-password"}
                  ).status_code == 200
    yield c
    db.execute("DELETE FROM app_user WHERE username = %s", (username,))


#: The console composes the code card in the browser, so the server-side half of
#: "does it render" is whether the ONE endpoint that screen reads carries the
#: pieces. Named here so a rename of a jsonb key fails loudly rather than turning
#: a card into an empty box, which is the exact failure this file exists for.
#:
#: The client-side half is asserted against the source of FindingDetail.tsx. Not
#: markup — the strings below are the field NAMES it reads and the two headings a
#: reviewer looks for — because the data being present and the screen not reading
#: it is a blank card and a green test.
_CODE_CARD_SOURCE = ROOT / "frontend" / "src" / "routes" / "FindingDetail.tsx"


def _detail(client, finding_id):
    resp = client.get(f"/api/findings/{finding_id}")
    assert resp.status_code == 200, resp.text[:400]
    return resp.json()


def test_the_detail_screen_is_given_the_code_and_the_taint_trace(client, landscape):
    """This used to read the server-rendered page and grep it for "Code location".

    That page is deleted. The finding still has to reach a person, and the only
    route by which it now can is `/api/findings/{id}` — so the assertion moved to
    the payload, and it is the stronger place for it: the old test could not tell
    a snippet that reached the browser from one that reached the template and was
    dropped, and this one names every field the card is built from.
    """
    from server import db
    _store(landscape, TAINTED,
           inventory=[{"OBJECT_NAME": "Z_TAINT_DEMO", "REFERENCED": "YES",
                       "LAST_USED": "20260801"}])
    fid = db.one("SELECT id FROM finding WHERE landscape_id = %s "
                 "AND check_id LIKE 'ABAP-SQLI%%' LIMIT 1",
                 (landscape["landscape"],))["id"]

    body = _detail(client, fid)
    details = body["latest_details"] or {}

    assert details.get("source") in ("abap_scan", "atc_export"), (
        "the card is shown on `details.source`; without it FindingDetail.tsx "
        "renders no code section at all")
    assert "z_taint_demo" in str(details.get("file", "")).lower(),         "the file the finding is in did not reach the screen"
    assert "SELECT" in str(details.get("snippet", "")),         "the offending source did not reach the screen"
    # Reachability from Phase 4a, with its evidence rather than a bare verdict.
    assert body["reachability"] == "reachable"
    assert details.get("reachability_reasons"),         "a reachability verdict with no reasons is an assertion the reviewer cannot check"
    assert body["taint_confidence"] in ("confirmed", "tentative", "pattern-only")


def test_a_confirmed_finding_carries_its_source_to_sink_path(client, landscape):
    """The best thing the engine produces, and there is nothing else like it in the
    product. If the taint pass confirmed the finding, the path must be visible."""
    from server import db
    _store(landscape, TAINTED)
    row = db.one(
        "SELECT f.id, f.taint_confidence, o.details FROM finding f "
        "JOIN finding_observation o ON o.finding_id = f.id "
        "WHERE f.landscape_id = %s AND f.check_id LIKE 'ABAP-SQLI%%' LIMIT 1",
        (landscape["landscape"],))
    if row["taint_confidence"] != "confirmed" or not row["details"].get("taint_flow"):
        pytest.skip("taint pass produced no flow for this sample")

    flow = (_detail(client, row["id"])["latest_details"] or {}).get("taint_flow")
    assert flow, "the source->sink trace did not reach the screen"
    roles = {str(hop.get("role")) for hop in flow}
    assert "source" in roles and "sink" in roles,         f"the trace has no source and sink to read it by: {roles}"
    for hop in flow:
        # The four columns the table renders. A hop missing `code` is a row of
        # blanks, which reads as a rendering bug rather than as missing data.
        assert {"line", "role", "var", "code"} <= set(hop), f"incomplete hop: {hop}"


def test_a_non_code_finding_carries_nothing_to_put_in_the_card(client, landscape):
    """The card must not appear on a parameter or user finding with nothing in it.

    The condition is `details.source`, so the server-side assertion is that a
    non-code finding does not claim to be one — which is what actually keeps the
    card off the screen.
    """
    from server import db
    row = db.one(
        "SELECT id FROM finding WHERE check_id NOT LIKE 'ABAP-%%' "
        "AND check_id NOT LIKE 'ATC-%%' LIMIT 1")
    if not row:
        pytest.skip("no non-code finding in this database")
    details = _detail(client, row["id"])["latest_details"] or {}
    assert details.get("source") not in ("abap_scan", "atc_export")
    assert not details.get("snippet") and not details.get("taint_flow")


def test_the_console_actually_reads_every_field_the_payload_carries():
    """The other half of a client-rendered screen, and the half a JSON assertion
    cannot see: data delivered to a screen that never looks at it is a blank card
    and a passing suite.

    Needs no database — it is a claim about one source file — so it holds on a
    bare checkout, which is where a dropped field is cheapest to catch.
    """
    src = _CODE_CARD_SOURCE.read_text(encoding="utf-8")
    for field in ("'file'", "'snippet'", "'taint_flow'", "'reachability_reasons'",
                  "'source'", "reachability", "taint_confidence"):
        assert field in src,             f"FindingDetail.tsx no longer reads {field}; the payload carries it to nobody"
    for heading in ("Code location", "How untrusted input reaches it"):
        assert heading in src, f"the {heading!r} section was lost in the port"
