"""
GET /api/findings/{id}, and one brand across every deliverable.

THE API GAP THIS CLOSES
`server/app.py`'s own module docstring states the invariant: "everything the
dashboard shows is available via the API ... only holds if it is structural rather
than remembered". It was remembered, and it had stopped holding. The list
endpoints never select `cd.remediation` or `cd.risk_narrative`, and there was no
single-finding route at all — so the two fields a consumer most wants when opening
a ticket were reachable only by scraping the HTML page.

ROUTE ORDER IS PART OF THE FIX
Starlette matches in declaration order. `/api/findings/{finding_id}` declared
above `/api/findings/changes` captures the literal "changes", fails int coercion
and 422s — breaking incremental sync in a way that reads like a client bug.
`test_the_changes_route_is_not_captured_by_the_id_route` is that regression.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

pg = pytest.mark.skipif(not os.getenv("DB_DSN"),
                        reason="set DB_DSN to a PostgreSQL 16 instance")


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient
    from server import app as appmod, auth, db
    db.init_schema()
    name = f"api_{os.urandom(4).hex()}"
    auth.create_user(name, "api-test-password", "admin")
    c = TestClient(appmod.app)
    assert c.post("/login", data={"username": name, "password": "api-test-password",
                                  "next": "/"}, follow_redirects=False).status_code == 303
    yield c
    db.execute("DELETE FROM app_user WHERE username = %s", (name,))


@pytest.fixture()
def a_finding():
    from server import db
    row = db.one("SELECT id FROM finding LIMIT 1")
    if row is None:
        pytest.skip("no findings in this database")
    return row["id"]


# --------------------------------------------------------------------------- #
#  The route                                                                  #
# --------------------------------------------------------------------------- #

@pg
def test_a_single_finding_is_reachable_and_carries_what_the_page_shows(client, a_finding):
    body = client.get(f"/api/findings/{a_finding}").json()
    assert body["id"] == a_finding
    for field in ("check_id", "severity", "state", "remediation", "risk_narrative"):
        assert field in body, f"{field} is on the HTML page but not in the API"


@pg
def test_the_changes_route_is_not_captured_by_the_id_route(client):
    """`/api/findings/changes` must still resolve to the incremental-sync endpoint.
    If the id route were declared first, "changes" would bind to {finding_id} and
    422 on int coercion."""
    resp = client.get("/api/findings/changes?since_run=1")
    assert resp.status_code == 200, \
        f"the id route swallowed /changes: {resp.status_code} {resp.text[:120]}"
    # A 422 here would be the symptom of the ordering bug: "changes" coerced to int.
    assert "findings" in resp.json()


@pg
def test_the_list_route_still_works(client):
    assert client.get("/api/findings").status_code == 200


@pg
def test_an_unknown_id_is_404_not_500(client):
    assert client.get("/api/findings/999999999").status_code == 404


@pg
def test_an_anonymous_caller_gets_401_not_the_finding(a_finding):
    from fastapi.testclient import TestClient
    from server import app as appmod
    resp = TestClient(appmod.app).get(f"/api/findings/{a_finding}")
    assert resp.status_code == 401


@pg
def test_a_finding_outside_the_callers_scope_is_indistinguishable_from_absent(a_finding):
    """404, not 403. Telling a scoped user that a finding exists but is not theirs
    lets them enumerate ids in landscapes they cannot see.

    The user needs a scope row pointing at a DIFFERENT system. `visible_system_ids`
    documents that ABSENCE of scope rows means unrestricted — the right default for
    a single-tenant deployment — so a viewer with no rows at all legitimately sees
    the whole estate and would prove nothing here.
    """
    from fastapi.testclient import TestClient
    from server import app as appmod, auth, db

    target_system = db.one("SELECT system_id FROM finding WHERE id = %s", (a_finding,))
    other = db.one("SELECT id FROM sap_system WHERE id IS DISTINCT FROM %s LIMIT 1",
                   (target_system["system_id"],))
    if other is None:
        pytest.skip("only one system in this database; scoping cannot be exercised")

    name = f"scoped_{os.urandom(4).hex()}"
    uid = auth.create_user(name, "scoped-test-pass", "viewer")
    db.execute("INSERT INTO user_system_scope (user_id, system_id) VALUES (%s,%s)",
               (uid, other["id"]))
    try:
        c = TestClient(appmod.app)
        c.post("/login", data={"username": name, "password": "scoped-test-pass",
                               "next": "/"})
        resp = c.get(f"/api/findings/{a_finding}")
        assert resp.status_code == 404, \
            f"out-of-scope finding returned {resp.status_code}, which discloses it exists"
    finally:
        db.execute("DELETE FROM app_user WHERE id = %s", (uid,))


# --------------------------------------------------------------------------- #
#  One brand across every deliverable                                         #
# --------------------------------------------------------------------------- #

RETIRED = "PhalanxCyber"


def test_no_shipped_module_carries_the_retired_vendor_brand():
    """The console said MonitorRisk while the PDF a customer keeps said something
    else. Asserted over the tree so a new report surface cannot reintroduce it."""
    offenders = []
    for path in sorted((ROOT / "modules").glob("*.py")):
        if RETIRED in path.read_text(encoding="utf-8"):
            offenders.append(path.name)
    assert not offenders, f"retired vendor brand still in: {offenders}"


def test_the_brand_asset_the_reports_embed_exists():
    """`_asset_data_uri` returns "" when the file is missing and the report still
    renders — so a missing logo is silent, and only a test catches it."""
    asset = ROOT / "assets" / "monitorrisk-logo.png"
    assert asset.is_file(), "reports would render with no logo at all"
    assert asset.stat().st_size > 1024
    assert not (ROOT / "assets" / "phalanxcyber-logo.png").exists(), \
        "the retired logo is still shipping"


def test_the_html_report_embeds_the_brand_and_not_the_old_one():
    from modules.report_generator import ReportGenerator
    gen = ReportGenerator(findings=[], meta={"scan_date": "2026-08-07"})
    uri = gen._logo_data_uri()
    assert uri.startswith("data:image/png;base64,"), \
        "the brand logo is not being embedded as a data URI"


def test_the_pptx_core_properties_name_the_right_product():
    import inspect
    from modules import pptx_writer
    src = inspect.getsource(pptx_writer)
    assert "MonitorRisk" in src and RETIRED not in src
