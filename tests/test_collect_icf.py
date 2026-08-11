# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""The ICF connector, against a fake ABAP web surface.

THE CORRECTION THIS FILE EXISTS TO HOLD IN PLACE
This connector was scoped out loud as "the one that gets users and roles". IT
DOES NOT. There is no standard, pre-built OData service on ECC exposing USR02 or
AGR_USERS; SAP Gateway exposes only the services an administrator has activated,
and on a typical ECC estate that set does not include user master data. Users,
roles, profiles and authorisations stay export-only.

What it does reach is a different logical source and a genuinely valuable one:
which ICF endpoints are active, and which answer with no authentication at all.
An unauthenticated /sap/bc/soap/rfc is not a configuration detail — it is a
remote function call interface open to anyone who can route to the host.
"""
from __future__ import annotations

import inspect
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from collect import extract, icf, web                                 # noqa: E402

CATALOG_JSON = json.dumps({"d": {"results": [
    {"TechnicalServiceName": "API_BUSINESS_PARTNER_SRV",
     "ServiceUrl": "/sap/opu/odata/sap/API_BUSINESS_PARTNER_SRV",
     "TechnicalServiceVersion": "1"},
    {"TechnicalServiceName": "ZCUSTOM_SRV",
     "ServiceUrl": "/sap/opu/odata/sap/ZCUSTOM_SRV",
     "TechnicalServiceVersion": "1"},
]}}).encode()


class FakeAbapWeb(BaseHTTPRequestHandler):
    """Answers like an ABAP ICM: some paths open, some 401, some absent."""

    routes: dict = {}
    seen: list = []
    methods: list = []
    auth_seen: list = []

    def log_message(self, *a):
        pass

    def _handle(self):
        type(self).methods.append(self.command)
        type(self).auth_seen.append(self.headers.get("Authorization"))
        path = self.path.split("?")[0]
        type(self).seen.append(path)
        status, body = type(self).routes.get(path, (404, b"not found"))
        if status in (301, 302):
            self.send_response(status)
            self.send_header("Location", "/sap/bc/gui/sap/its/webgui/logon")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(status)
        self.send_header("Content-Type",
                         "application/json" if body[:1] == b"{" else "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _handle
    do_POST = _handle


DEFAULT_ROUTES = {
    "/sap/public/info": (200, b"<systeminfo/>"),
    "/sap/public/icman/ping": (200, b"ok"),
    "/sap/bc/ping": (401, b"unauthorized"),
    "/sap/bc/soap/rfc": (200, b"<soap/>"),
    "/sap/bc/gui/sap/its/webgui": (302, b""),
    "/sap/opu/odata/IWFND/CATALOGSERVICE;v=2/ServiceCollection":
        (200, CATALOG_JSON),
}


@pytest.fixture()
def abap():
    FakeAbapWeb.routes = dict(DEFAULT_ROUTES)
    FakeAbapWeb.seen = []
    FakeAbapWeb.methods = []
    FakeAbapWeb.auth_seen = []
    httpd = HTTPServer(("127.0.0.1", 0), FakeAbapWeb)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd
    httpd.shutdown()
    httpd.server_close()


def icf_for(httpd, **kw):
    host, port = httpd.server_address
    return icf.IcfCollector(host, https=False, port=port, verify_tls=False, **kw)


# --------------------------------------------------------------------------- #
#  What it does not claim                                                     #
# --------------------------------------------------------------------------- #

def test_it_does_not_claim_to_reach_users_and_roles():
    """A future edit that quietly starts claiming otherwise fails here."""
    for source in ("users", "roles", "profiles", "auth_objects",
                   "role_auth_values"):
        assert source in extract.ICF_CANNOT_REACH, (
            f"{source} was dropped from ICF_CANNOT_REACH. If it really is "
            f"reachable now, show how; if not, this list is the only place a "
            f"reader learns it is missing.")


def test_the_probed_list_is_a_reviewed_set_and_not_a_wordlist():
    """An audit of documented endpoints, not a scan. A customer authorising a
    configuration review has not authorised a web crawl of their production
    application server, and a tool that quietly did one would deserve the
    incident report."""
    assert len(icf.WELL_KNOWN) <= 40, \
        "this has grown into a wordlist; that is a different activity"
    for path, why in icf.WELL_KNOWN:
        assert path.startswith("/sap/"), path
        assert len(why) > 15, f"{path} has no stated reason for being probed"


def test_the_web_helper_cannot_be_asked_to_write():
    """Everything this package does to a production system is a read, and the way
    to keep that true is to make writing impossible rather than unusual."""
    sig = inspect.signature(web.fetch)
    assert "method" not in sig.parameters
    assert "data" not in sig.parameters and "body" not in sig.parameters


# --------------------------------------------------------------------------- #
#  The observation                                                            #
# --------------------------------------------------------------------------- #

def test_the_probe_is_anonymous_and_that_is_the_whole_point(abap):
    """AUTH_REQUIRED means nothing if the probe carries a credential: a 401 would
    become a 200, and a protected service would be recorded as open."""
    src = inspect.getsource(icf.IcfCollector.probe_services)
    assert "username" not in src, \
        "probe_services has grown a credential; AUTH_REQUIRED would then be " \
        "measuring the credential rather than the service"

    icf_for(abap).probe_services()
    assert FakeAbapWeb.methods and set(FakeAbapWeb.methods) == {"GET"}
    assert all(a is None for a in FakeAbapWeb.auth_seen), \
        "a probe sent an Authorization header"


def test_an_open_service_is_distinguished_from_a_protected_one(abap):
    rows = {r["ICF_NAME"]: r for r in icf_for(abap).probe_services()}

    # 200 with no credentials — the finding this connector exists to produce.
    assert rows["/sap/public/info"]["ICF_ACTIVE"] == "X"
    assert rows["/sap/public/info"]["AUTH_REQUIRED"] == "NO"
    assert rows["/sap/bc/soap/rfc"]["AUTH_REQUIRED"] == "NO"

    # 401 — active, and protected.
    assert rows["/sap/bc/ping"]["ICF_ACTIVE"] == "X"
    assert rows["/sap/bc/ping"]["AUTH_REQUIRED"] == "YES"

    # 404 — not active here.
    assert rows["/sap/bc/webrfc"]["ICF_ACTIVE"] == ""


def test_a_redirect_to_a_logon_page_is_protected_not_open(abap):
    """Following it would land on a logon page, return 200, and record an
    authentication-protected service as needing none — inverting the finding. It
    also stops a probe being walked onto a host nobody authorised."""
    rows = {r["ICF_NAME"]: r for r in icf_for(abap).probe_services()}
    assert rows["/sap/bc/gui/sap/its/webgui"]["ICF_ACTIVE"] == "X"
    assert rows["/sap/bc/gui/sap/its/webgui"]["AUTH_REQUIRED"] == "YES"
    assert "/sap/bc/gui/sap/its/webgui/logon" not in FakeAbapWeb.seen, \
        "the probe followed a redirect"


def test_every_probed_path_is_recorded_including_the_absent_ones(abap):
    """"We looked and it was not there" and "we did not look" are different
    facts. A collector reporting only its hits would make a fully-probed system
    indistinguishable from a barely-probed one."""
    rows = icf_for(abap).probe_services()
    assert len(rows) == len(icf.WELL_KNOWN)
    assert {r["ICF_NAME"] for r in rows} == {p for p, _ in icf.WELL_KNOWN}


def test_an_unreachable_host_is_not_a_system_with_no_services():
    """A firewall must never be reported as a clean estate."""
    # A short timeout on purpose: this asserts how an unreachable host is
    # RECORDED, not how long the collector is willing to wait, and the whole list
    # is probed — so a generous timeout here costs one second per path for
    # nothing.
    c = icf.IcfCollector("127.0.0.1", https=False, port=1, timeout=0.25,
                         verify_tls=False)
    rows = c.probe_services()
    assert all(r["ICF_ACTIVE"] == "" and r["OBSERVED_STATUS"] == "" for r in rows)
    assert all(not a["ok"] for a in c.attempts)


def test_a_server_error_is_unknown_rather_than_open_or_absent(abap):
    """500 means something is listening and what it wants is unknown. Guessing
    either way would be inventing a fact."""
    FakeAbapWeb.routes["/sap/bc/webrfc"] = (500, b"boom")
    rows = {r["ICF_NAME"]: r for r in icf_for(abap).probe_services()}
    assert rows["/sap/bc/webrfc"]["ICF_ACTIVE"] == "X"
    assert rows["/sap/bc/webrfc"]["AUTH_REQUIRED"] == "UNKNOWN"


# --------------------------------------------------------------------------- #
#  The Gateway catalogue                                                      #
# --------------------------------------------------------------------------- #

def test_the_catalogue_is_read_with_credentials(abap):
    """Unlike the probe. The catalogue is ordinary authenticated data rather than
    an exposure test, so reading it anonymously would just yield a 401."""
    endpoints = icf_for(abap).read_catalog(username="u", password="p")
    assert endpoints is not None
    names = {e["name"] for e in endpoints}
    assert {"API_BUSINESS_PARTNER_SRV", "ZCUSTOM_SRV"} <= names
    assert all(e["authentication"] == "unknown" for e in endpoints), \
        "an authentication method was invented; the catalogue does not state one"


def test_no_catalogue_is_a_gap_not_an_empty_api_surface(abap, tmp_path):
    """A system with no Gateway must not be recorded as one exposing no APIs."""
    FakeAbapWeb.routes = {}
    assert icf_for(abap).read_catalog(username="u", password="p") is None
    assert extract.write_api_endpoints(tmp_path, []) == 0
    assert not (tmp_path / "api_endpoints.json").exists()


def test_the_v4_limitation_is_recorded(tmp_path):
    """The Gateway catalogue does not list OData V4 services. Carrying that into
    the manifest stops a reader mistaking the collected list for the whole API
    surface."""
    assert "V4" in icf.CATALOG_OMITS
    path = extract.write_manifest(
        tmp_path, source="icf", endpoint="e", collected_at="t",
        wrote={"api_endpoints.json": 2}, attempts=[],
        cannot_reach=extract.ICF_CANNOT_REACH, caveats=[icf.CATALOG_OMITS])
    assert "V4" in extract.summarise(path)


# --------------------------------------------------------------------------- #
#  What it writes                                                             #
# --------------------------------------------------------------------------- #

def test_it_writes_icf_services_the_real_loader_reads(abap, tmp_path):
    from modules.data_loader import DataLoader

    c = icf_for(abap)
    assert extract.write_icf_services(tmp_path, c.probe_services()) == \
        len(icf.WELL_KNOWN)

    rows = DataLoader(tmp_path).load_all().get("icf_services")
    assert rows, "the loader did not read the ICF file the collector wrote"
    by_name = {r["ICF_NAME"]: r for r in rows}
    assert by_name["/sap/public/info"]["AUTH_REQUIRED"] == "NO"
    assert by_name["/sap/bc/ping"]["AUTH_REQUIRED"] == "YES"


def test_the_extra_evidence_columns_do_not_disturb_the_loader(abap, tmp_path):
    """OBSERVED_STATUS and WHY_IT_MATTERS are for a human opening the file.
    DictReader ignores columns nobody asked for — asserted, not assumed."""
    from modules.data_loader import DataLoader
    extract.write_icf_services(tmp_path, icf_for(abap).probe_services())
    rows = DataLoader(tmp_path).load_all()["icf_services"]
    assert "OBSERVED_STATUS" in rows[0]
    assert {"ICF_NAME", "ICF_ACTIVE", "AUTH_REQUIRED"} <= set(rows[0])


def test_the_written_export_produces_findings(abap, tmp_path):
    """A file the loader accepts but no check can use would still be broken."""
    from modules.data_loader import DataLoader
    from modules.network_services import NetworkServiceAuditor

    extract.write_icf_services(tmp_path, icf_for(abap).probe_services())
    data = DataLoader(tmp_path).load_all()
    findings = NetworkServiceAuditor(data, {}).run_all_checks()
    assert findings, "no check produced a finding from a collected ICF export"


# --------------------------------------------------------------------------- #
#  Two collectors, one directory                                              #
# --------------------------------------------------------------------------- #

def test_both_collections_stay_in_the_manifest(tmp_path):
    """The intended workflow — sapcontrol and icf reach different things — and a
    manifest that overwrote its predecessor would leave a directory whose data
    came from two collections and whose record described one."""
    extract.write_manifest(tmp_path, source="sapcontrol", endpoint="a",
                           collected_at="t1",
                           wrote={"security_params.csv": 900}, attempts=[])
    path = extract.write_manifest(tmp_path, source="icf", endpoint="b",
                                  collected_at="t2",
                                  wrote={"icf_services.csv": 10}, attempts=[],
                                  cannot_reach=extract.ICF_CANNOT_REACH)
    m = json.loads(path.read_text(encoding="utf-8"))
    assert [c["source"] for c in m["collections"]] == ["sapcontrol", "icf"]
    assert m["partial"] is True
    assert "2 collections recorded" in extract.summarise(path)


def test_a_corrupt_previous_manifest_is_flagged_not_silently_replaced(tmp_path):
    """Losing the record of an earlier collection without saying so would leave a
    directory that looks like it came from one run when it came from two."""
    (tmp_path / "collection_manifest.json").write_text("{not json",
                                                       encoding="utf-8")
    path = extract.write_manifest(tmp_path, source="icf", endpoint="b",
                                  collected_at="t", wrote={}, attempts=[])
    m = json.loads(path.read_text(encoding="utf-8"))
    assert m.get("unreadable_previous_manifest") is True
