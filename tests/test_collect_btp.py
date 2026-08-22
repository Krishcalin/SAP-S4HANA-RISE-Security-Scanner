"""The BTP collector, exercised against a real socket.

A real ``http.server`` on a real port, speaking the real protocol — no mocked
``urlopen``. Asserting that the code calls the function the test expects is not
the same claim as speaking OAuth to something that answers.

This is the first token-handling code in the repository, and a BTP OAuth
scanner was removed from this codebase once already. So the tests that matter
most here are not the happy path: they are that a path outside the allowlist
never reaches the network, that the secret stays out of argv and out of the
manifest, and that a collection which got nothing exits non-zero instead of
writing a file that reads as "this landscape has no configuration".
"""
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from collect import btp, extract                                  # noqa: E402


# --------------------------------------------------------------------------- #
#  A fake BTP: one token endpoint, three resources                            #
# --------------------------------------------------------------------------- #

class _Handler(BaseHTTPRequestHandler):
    """Records every path it was asked for — ON THE SERVER, not on the class.

    It was a class attribute first, and the file was flaky: three runs of the
    same tests gave 15, 14 and 13 passes. Two servers from two tests share one
    class, so a request still in flight when a test ended appended to the next
    test's list. A test that is wrong occasionally is worse than no test,
    because the failure gets re-run rather than read.
    """

    def log_message(self, *a):                                     # noqa: D102
        pass

    @property
    def reached(self):
        return self.server.reached

    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):                                             # noqa: N802
        # DRAIN THE BODY BEFORE ANSWERING. Skipping this made the whole file
        # flaky on Windows — roughly one run in eight died with WinError 10053,
        # a different test each time. Responding and closing while the form
        # body is still unread leaves bytes in the socket, the close becomes a
        # reset, and the client sees an aborted connection on a later request.
        # A real server reads the request; a fake that does not is testing a
        # protocol nobody speaks.
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self.reached.append(("POST", self.path))
        if self.path != btp.TOKEN_PATH:
            self._send(404, {"error": "not found"})
            return
        if not self.headers.get("Authorization", "").startswith("Basic "):
            self._send(401, {"error": "no client credentials"})
            return
        self._send(200, {"access_token": "tok-123", "expires_in": 3600})

    def do_GET(self):                                              # noqa: N802
        self.reached.append(("GET", self.path))
        if self.headers.get("Authorization") != "Bearer tok-123":
            self._send(401, {"error": "bad token"})
            return
        if self.path.endswith("subaccountDestinations"):
            self._send(200, [{"Name": "S4", "Authentication": "BasicAuthentication",
                              "User": "RFCUSER", "URL": "http://10.1.2.3/sap"}])
        elif self.path.endswith("/subaccounts"):
            self._send(200, {"value": [{"guid": "g1", "displayName": "prod"}]})
        elif self.path.endswith("/auditlogrecords"):
            self._send(200, [{"uuid": "u1", "time": "2026-08-16T00:00:00Z"}])
        else:
            self._send(404, {"error": "not found"})


class _Server(HTTPServer):
    """One server per test, carrying its own record of what it was asked."""

    def __init__(self, *a, **kw):
        HTTPServer.__init__(self, *a, **kw)
        self.reached = []


@pytest.fixture()
def server():
    srv = _Server(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()          # release the port, or the next test may inherit it
    thread.join(timeout=5)


def _base(srv):
    return "http://127.0.0.1:%d" % srv.server_port


def _key(base):
    return btp.ServiceKey({"url": base,
                           "uaa": {"clientid": "cid", "clientsecret": "sec",
                                   "url": base}})


#: The one path the fake server serves successfully. Module-level so the
#: allowlist in a test and the endpoint it asks for cannot drift apart.
ENDPOINT_OK = "/destination-configuration/v1/subaccountDestinations"


# ── the transport refuses before the network ─────────────────────────────────

def test_a_path_outside_the_allowlist_never_reaches_the_server(server):
    c = btp.BtpCollector(_key(_base(server)), allowed=frozenset(["/only/this"]))
    with pytest.raises(btp.RefusedRequest):
        c.get("/destination-configuration/v1/subaccountDestinations")
    assert server.reached == [], "a refused path still hit the network"


def test_the_allowlist_is_passed_in_not_defaulted_inside_the_transport():
    """The permitted set must be visible at the call site — the same rule
    collect/soap.py follows."""
    import inspect
    sig = inspect.signature(btp.BtpCollector.__init__)
    assert "allowed" in sig.parameters


# ── the credential ───────────────────────────────────────────────────────────

def test_the_secret_is_not_in_the_repr():
    """A traceback or a debug print must not leak the client secret."""
    k = _key("https://x.example")
    assert "sec" not in repr(k)


def test_a_service_key_missing_fields_is_refused_with_a_useful_message():
    with pytest.raises(btp.ServiceKeyError) as exc:
        btp.ServiceKey({"url": "https://x", "uaa": {"clientid": "c"}})
    assert "clientsecret" in str(exc.value)


def test_the_wrapped_service_key_shape_is_accepted():
    """The CLI emits credentials wrapped; the cockpit emits them bare."""
    k = btp.ServiceKey({"credentials": {
        "url": "https://svc", "uaa": {"clientid": "c", "clientsecret": "s",
                                      "url": "https://uaa"}}})
    assert k.service_url == "https://svc" and k.token_url == "https://uaa"


def test_no_credential_can_be_supplied_on_the_btp_command_line():
    """The standing rule, re-checked for the flags this subcommand added."""
    import ast
    tree = ast.parse((ROOT / "collect" / "__main__.py").read_text(encoding="utf-8"))
    flags = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_argument"):
            flags += [a.value for a in node.args
                      if isinstance(a, ast.Constant) and isinstance(a.value, str)]
    bad = [f for f in flags if "pass" in f.lower() or "secret" in f.lower()]
    assert not bad, f"a credential can be supplied on the command line: {bad}"


# ── the happy path, end to end ───────────────────────────────────────────────

def test_it_authenticates_once_and_collects(server):
    c = btp.BtpCollector(_key(_base(server)))
    got = c.collect()
    assert set(got) == {"btp_destinations", "btp_subaccounts",
                        "btp_audit_log_records"}
    posts = [p for m, p in server.reached if m == "POST"]
    assert posts == [btp.TOKEN_PATH], "the token was fetched more than once"
    assert all(a["ok"] for a in c.attempts)


def test_a_failing_endpoint_is_recorded_not_fatal(server):
    c = btp.BtpCollector(_key(_base(server)),
                         allowed=frozenset(["/nope", ENDPOINT_OK]))
    got = c.collect([{"source": "btp_destinations", "file": "btp_destinations.json",
                      "path": ENDPOINT_OK},
                     {"source": "btp_subaccounts", "file": "btp_subaccounts.json",
                      "path": "/nope"}])
    assert "btp_destinations" in got and "btp_subaccounts" not in got, c.attempts
    assert [a["ok"] for a in c.attempts] == [True, False], c.attempts


# ── what it writes is what the offline scanner reads ─────────────────────────

def test_it_writes_files_the_offline_loader_reads(server, tmp_path):
    from modules.data_loader import DataLoader
    c = btp.BtpCollector(_key(_base(server)))
    for source, payload in c.collect().items():
        fname = {e["source"]: e["file"] for e in btp.ENDPOINTS}[source]
        extract.write_btp_payload(tmp_path, fname, payload)
    import contextlib, io
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(tmp_path).load_all()
    assert data["btp_destinations"], "the loader did not read the destinations"


def test_the_written_export_actually_produces_findings(server, tmp_path):
    """The strongest claim available: a real check module reaches a verdict on
    what the collector wrote."""
    from modules.data_loader import DataLoader
    from modules.btp_cloud_surface import BtpCloudSurfaceAuditor
    c = btp.BtpCollector(_key(_base(server)))
    for source, payload in c.collect().items():
        fname = {e["source"]: e["file"] for e in btp.ENDPOINTS}[source]
        extract.write_btp_payload(tmp_path, fname, payload)
    import contextlib, io
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(tmp_path).load_all()
        findings = BtpCloudSurfaceAuditor(data, {}, {}).run_all_checks()
    ids = {f["check_id"] for f in findings}
    # The fixture destination uses Basic auth with a stored user, over http.
    assert "BTP-DST-001" in ids, sorted(ids)


# ── empty is absent ──────────────────────────────────────────────────────────

def test_an_empty_payload_writes_no_file(tmp_path):
    """`[]` would read as "this subaccount has no destinations" — a claim a
    collection that returned nothing has not earned."""
    assert extract.write_btp_payload(tmp_path, "btp_destinations.json", []) == 0
    assert not (tmp_path / "btp_destinations.json").exists()


def test_the_record_count_looks_through_the_usual_wrappers(tmp_path):
    n = extract.write_btp_payload(tmp_path, "btp_subaccounts.json",
                                  {"value": [{"a": 1}, {"b": 2}]})
    assert n == 2


# ── declared gaps ────────────────────────────────────────────────────────────

def test_every_gap_is_declared_with_a_reason():
    produced = {e["source"] for e in btp.ENDPOINTS} | {"cloud_connector"}
    assert not (produced & set(btp.BTP_CANNOT_REACH)), \
        "a source is both produced and declared unreachable"
    for source, why in btp.BTP_CANNOT_REACH.items():
        assert len(why) > 20, f"{source} has no real reason"


def test_every_file_it_writes_is_one_the_loader_knows():
    from modules.data_loader import DataLoader
    known = {f for names in DataLoader.FILE_MAP.values() for f in names}
    for e in btp.ENDPOINTS:
        assert e["file"] in known, e["file"]
    assert "cloud_connector.json" in known


def test_every_endpoint_declares_how_well_it_is_attested():
    """A path this product supplies is either documented by SAP or corroborated
    inside this repository, and it says which."""
    for e in btp.ENDPOINTS:
        assert e["attested"] in ("documented", "in-repo"), e["source"]
        assert e["note"]
