"""Registering a system, and registering a tenant. Decision D8.

WHY THIS FILE EXISTS AT ALL
`/api/systems` was GET-only. The sole creator of a `sap_system` row in the whole
product was `server/cli.py`, so once the schema learned to hold a SaaS tenant,
a tenant was something the database could store and nobody using the console
could create. A filter vocabulary you cannot add to is a half-built feature, and
the gap was invisible because every test seeded its systems with a raw INSERT.

The tests here go through HTTP for that reason: a hand-written INSERT in a
fixture proves the table accepts a row, not that a person can put one there.
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


@pytest.fixture(scope="module")
def admin():
    from fastapi.testclient import TestClient
    from server import app as appmod, auth, db

    db.init_schema()
    username = f"sysapi_{os.urandom(4).hex()}"
    auth.create_user(username, "systems-api-password", "admin")
    c = TestClient(appmod.app)
    r = c.post("/api/auth/login",
               json={"username": username, "password": "systems-api-password"})
    assert r.status_code == 200, r.text[:200]
    yield c
    db.execute("DELETE FROM app_user WHERE username = %s", (username,))


@pytest.fixture(scope="module")
def analyst():
    """A non-admin, for the authorisation test. Registering a system defines what
    the estate IS, and scoping is per-system — an analyst creating a system would
    create something they then could not see."""
    from fastapi.testclient import TestClient
    from server import app as appmod, auth, db

    db.init_schema()
    username = f"sysanalyst_{os.urandom(4).hex()}"
    auth.create_user(username, "systems-api-password", "analyst")
    c = TestClient(appmod.app)
    r = c.post("/api/auth/login",
               json={"username": username, "password": "systems-api-password"})
    assert r.status_code == 200, r.text[:200]
    yield c
    db.execute("DELETE FROM app_user WHERE username = %s", (username,))


@pytest.fixture()
def landscape():
    from server import db
    lid = db.one("INSERT INTO landscape (name, deployment_mode) "
                 "VALUES (%s,'on_prem') RETURNING id",
                 (f"sysapi-{os.urandom(5).hex()}",))["id"]
    yield lid
    db.execute("DELETE FROM landscape WHERE id = %s", (lid,))


# --------------------------------------------------------------------------- #
#  The two shapes                                                             #
# --------------------------------------------------------------------------- #

def test_an_abap_system_can_be_registered(admin, landscape):
    r = admin.post("/api/systems", data={
        "landscape_id": landscape, "platform": "abap",
        "sid": "prd", "client": "100", "tier": "prod"})
    assert r.status_code == 200, r.text[:300]
    s = r.json()["system"]
    assert s["sid"] == "PRD", "a SID is upper-cased on the way in, as it is in the CLI"
    assert s["client"] == "100"
    assert s["platform"] == "abap"
    assert s["external_key"] is None
    assert s["label"] == "PRD/100"


def test_a_saas_tenant_can_be_registered(admin, landscape):
    r = admin.post("/api/systems", data={
        "landscape_id": landscape, "platform": "successfactors",
        "external_key": "acme-sf-prod", "tier": "prod"})
    assert r.status_code == 200, r.text[:300]
    s = r.json()["system"]
    assert s["sid"] is None and s["client"] is None
    assert s["external_key"] == "acme-sf-prod"
    assert s["label"] == "successfactors:acme-sf-prod"


def test_two_tenants_of_the_same_platform_are_two_systems(admin, landscape):
    """The whole point of D8. Before it, both would have needed a SID, and with an
    empty one their findings hashed to the same fingerprint — so one tenant's
    finding overwrote the other's."""
    a = admin.post("/api/systems", data={
        "landscape_id": landscape, "platform": "successfactors",
        "external_key": "acme-sf-prod"}).json()["system"]
    b = admin.post("/api/systems", data={
        "landscape_id": landscape, "platform": "successfactors",
        "external_key": "acme-sf-test"}).json()["system"]
    assert a["id"] != b["id"]
    assert a["label"] != b["label"]


def test_registering_the_same_tenant_twice_updates_rather_than_duplicates(
        admin, landscape):
    """Idempotent, and through the PARTIAL index — which PostgreSQL will only
    accept as an ON CONFLICT arbiter because the statement repeats its predicate.
    Without that `WHERE platform <> 'abap'` this is SQLSTATE 42P10 at runtime."""
    first = admin.post("/api/systems", data={
        "landscape_id": landscape, "platform": "concur",
        "external_key": "acme-concur", "tier": "dev"}).json()["system"]
    again = admin.post("/api/systems", data={
        "landscape_id": landscape, "platform": "concur",
        "external_key": "acme-concur", "tier": "prod"})
    assert again.status_code == 200, again.text[:300]
    s = again.json()["system"]
    assert s["id"] == first["id"], "re-registering created a second row"
    assert s["tier"] == "prod", "a re-declared tier must be recorded"


def test_registering_the_same_abap_system_twice_updates_rather_than_duplicates(
        admin, landscape):
    """The other arbiter — the table constraint, which add-system also depends on.
    Kept non-partial precisely so this keeps working."""
    first = admin.post("/api/systems", data={
        "landscape_id": landscape, "platform": "abap",
        "sid": "QAS", "client": "200", "tier": "dev"}).json()["system"]
    again = admin.post("/api/systems", data={
        "landscape_id": landscape, "platform": "abap",
        "sid": "QAS", "client": "200", "tier": "qa"})
    assert again.status_code == 200, again.text[:300]
    assert again.json()["system"]["id"] == first["id"]
    assert again.json()["system"]["tier"] == "qa"


# --------------------------------------------------------------------------- #
#  What it refuses, and whether it explains itself                            #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("payload,expect", [
    ({"platform": "successfactors"}, "external key"),
    ({"platform": "successfactors", "external_key": "   "}, "external key"),
    ({"platform": "successfactors", "external_key": "k", "sid": "PRD"}, "no SID"),
    ({"platform": "abap"}, "SID and a client"),
    ({"platform": "abap", "sid": "PRD"}, "SID and a client"),
    ({"platform": "abap", "sid": "", "client": ""}, "SID and a client"),
    ({"platform": "abap", "sid": "PRD", "client": "100",
      "external_key": "nope"}, "not by an external key"),
    ({"platform": "myspace", "external_key": "k"}, "unknown platform"),
])
def test_a_malformed_system_is_refused_with_a_reason(admin, landscape, payload, expect):
    """400 with prose, not a 500 carrying a constraint name.

    `sap_system_shape_check` refuses every one of these too, which is the
    guarantee that matters — but 'violates check constraint
    sap_system_shape_check' is a poor way to learn you left a field blank.
    """
    r = admin.post("/api/systems", data={"landscape_id": landscape, **payload})
    assert r.status_code == 400, f"accepted {payload}: {r.text[:200]}"
    assert expect in r.json()["detail"], \
        f"unhelpful message for {payload}: {r.json()['detail']}"


def test_an_empty_sid_cannot_be_registered(admin, landscape):
    """The exact row D8 exists to make impossible. It is insertable through the
    CLI's add-system today, and an empty SID normalises to the same canonical
    fingerprint as every other empty SID — so two such systems' findings collide."""
    r = admin.post("/api/systems", data={
        "landscape_id": landscape, "platform": "abap", "sid": "", "client": "100"})
    assert r.status_code == 400


def test_an_unknown_landscape_is_a_404_not_a_500(admin):
    r = admin.post("/api/systems", data={
        "landscape_id": 99999999, "platform": "abap", "sid": "PRD", "client": "100"})
    assert r.status_code == 404


def test_creating_a_system_requires_admin(analyst, landscape):
    """An analyst's visible set is a list of system ids, so an analyst who created
    a system would create something they could not then see."""
    r = analyst.post("/api/systems", data={
        "landscape_id": landscape, "platform": "abap", "sid": "PRD", "client": "100"})
    assert r.status_code == 403, r.text[:200]


def test_creating_a_system_requires_a_session(landscape):
    from fastapi.testclient import TestClient
    from server import app as appmod
    anon = TestClient(appmod.app)
    r = anon.post("/api/systems", data={
        "landscape_id": landscape, "platform": "abap", "sid": "PRD", "client": "100"})
    assert r.status_code in (401, 403), r.text[:200]


# --------------------------------------------------------------------------- #
#  It reaches the screens                                                     #
# --------------------------------------------------------------------------- #

def test_a_registered_tenant_appears_in_the_system_list_with_a_label(
        admin, landscape):
    """`/api/systems` is described in app.py as "the filter vocabulary for every
    screen", and every screen now renders `label` rather than concatenating sid
    and client — which for a tenant produced the literal text "null/null" or, on
    the screens that gated on `sid &&`, nothing at all."""
    admin.post("/api/systems", data={
        "landscape_id": landscape, "platform": "ias",
        "external_key": "acme-ias"})
    rows = admin.get("/api/systems").json()["systems"]
    mine = [s for s in rows if s.get("external_key") == "acme-ias"]
    assert mine, "a registered tenant is missing from the system list"
    s = mine[0]
    assert s["label"] == "ias:acme-ias"
    assert s["platform"] == "ias"
    # The fields the TypeScript SapSystem interface declares must all be present,
    # or the console renders `undefined` for them.
    for key in ("id", "landscape_id", "platform", "external_key", "label",
                "sid", "client", "tier", "criticality", "exposure_zone",
                "landscape_name", "deployment_mode"):
        assert key in s, f"/api/systems omits {key}, which types.ts declares"


def test_the_audit_log_records_who_registered_it(admin, landscape):
    """A system appearing in an estate is a configuration change, and the audit
    entry commits in the same transaction as the row it describes."""
    from server import db
    r = admin.post("/api/systems", data={
        "landscape_id": landscape, "platform": "btp",
        "external_key": "acme-subaccount"})
    sid = r.json()["system"]["id"]
    entry = db.one("SELECT * FROM audit_log WHERE action = 'system.create' "
                   "AND object_id = %s", (str(sid),))
    assert entry is not None, "registering a system left no audit entry"
    assert entry["detail"]["label"] == "btp:acme-subaccount"


# --------------------------------------------------------------------------- #
#  The CLI half — the air-gapped path, where there is no browser              #
# --------------------------------------------------------------------------- #

def _cli(*argv) -> int:
    """Run a server.cli subcommand in-process and return its exit code."""
    from server import cli
    return cli.main(list(argv))


def test_the_cli_can_register_a_tenant(landscape):
    """add-tenant exists because add-system cannot express one: its sid and client
    are POSITIONAL, so making them optional would leave `add-system acme-sf-prod`
    ambiguous — a SID or an external key? — with argparse accepting it either way.
    """
    from server import db
    name = db.one("SELECT name FROM landscape WHERE id = %s", (landscape,))["name"]

    assert _cli("add-tenant", name, "successfactors", "cli-tenant-a") == 0
    row = db.one("SELECT * FROM sap_system WHERE landscape_id = %s "
                 "AND external_key = %s", (landscape, "cli-tenant-a"))
    assert row is not None
    assert row["sid"] is None and row["client"] is None
    assert row["platform"] == "successfactors"


def test_the_cli_refuses_an_empty_external_key(landscape):
    from server import db
    name = db.one("SELECT name FROM landscape WHERE id = %s", (landscape,))["name"]
    assert _cli("add-tenant", name, "concur", "   ") == 1, \
        "an empty external key was accepted; two such tenants would collide"


def test_the_cli_re_registers_a_tenant_idempotently(landscape):
    """Through the partial index, which needs its predicate repeated in the
    statement or PostgreSQL raises 42P10."""
    from server import db
    name = db.one("SELECT name FROM landscape WHERE id = %s", (landscape,))["name"]
    assert _cli("add-tenant", name, "btp", "cli-sub", "--tier", "dev") == 0
    first = db.one("SELECT id, tier FROM sap_system WHERE landscape_id = %s "
                   "AND external_key = %s", (landscape, "cli-sub"))
    assert _cli("add-tenant", name, "btp", "cli-sub", "--tier", "prod") == 0
    again = db.one("SELECT id, tier FROM sap_system WHERE landscape_id = %s "
                   "AND external_key = %s", (landscape, "cli-sub"))
    assert again["id"] == first["id"], "re-registering created a second row"
    assert again["tier"] == "prod"


def test_add_tenant_will_not_accept_abap(landscape):
    """`abap` is excluded from the choices by construction (TENANT_PLATFORMS is
    derived), so this command cannot be used to create a SID-less ABAP row — which
    the schema would refuse anyway, but with a constraint name rather than a
    sentence."""
    from modules.platforms import TENANT_PLATFORMS
    assert "abap" not in TENANT_PLATFORMS
    with pytest.raises(SystemExit):        # argparse rejects an invalid choice
        _cli("add-tenant", "whatever", "abap", "k")
