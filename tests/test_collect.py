# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""Connected mode, exercised against a fake sapstartsrv.

WHY A FAKE SERVER AND NOT MOCKS
The original objection to a live client, written into this repository, was that
"one we cannot exercise" is a capability claim nobody can stand behind. A mock of
`urlopen` would reproduce that objection exactly: it asserts that the code calls
the function the test expects it to call, which is not the same claim as the code
speaking a protocol correctly. So the tests here stand up a real HTTP server on a
real socket, speak real SOAP to it, and assert on files that end up on disk.

WHAT IS DELIBERATELY NOT CLAIMED
No test here proves this works against a genuine SAP instance — nothing short of
a genuine SAP instance can. What they prove is that the client forms valid SOAP,
parses both response shapes seen in the field, refuses to send anything outside
its allowlist, and writes files the offline loader accepts. The remaining risk is
that a method name or response shape differs on some kernel release, and
`Endpoint.probe` exists so that surfaces as a stated coverage gap rather than as
a silent empty result.
"""
from __future__ import annotations

import json
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from collect import extract, sapcontrol, soap                        # noqa: E402

WSDL = """<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/" name="SAPControl">
  <portType name="SAPControl">
    <operation name="ParameterValue"/>
    <operation name="GetProcessList"/>
    <operation name="GetSystemInstanceList"/>
    <operation name="GetVersionInfo"/>
    <operation name="GetInstanceProperties"/>
    <operation name="Start"/>
    <operation name="Stop"/>
  </portType>
</definitions>"""


def _envelope(inner: str) -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<SOAP-ENV:Envelope '
        'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
        f"<SOAP-ENV:Body>{inner}</SOAP-ENV:Body></SOAP-ENV:Envelope>"
    ).encode("utf-8")


#: Two real response shapes. `item` arrays are the common one; a single `value`
#: blob of `name = value` lines is the other, and a reader that handled only the
#: first would return {} for the second — which reads as "this system has no
#: parameters configured", which is never true.
PARAM_ITEMS = _envelope(
    "<ParameterValueResponse>"
    "<item><name>login/min_password_lng</name><value>8</value></item>"
    "<item><name>rfc/reject_expired_passwd</name><value>1</value></item>"
    "<item><name>gw/reg_no_conn_info</name><value>255</value></item>"
    "</ParameterValueResponse>")

PARAM_BLOB = _envelope(
    "<ParameterValueResponse><value>login/min_password_lng = 8\n"
    "rfc/reject_expired_passwd = 1\n"
    "gw/reg_no_conn_info = 255\n</value></ParameterValueResponse>")

PROCESSES = _envelope(
    "<GetProcessListResponse>"
    "<item><name>disp+work</name><dispstatus>SAPControl-GREEN</dispstatus></item>"
    "<item><name>igswd_mt</name><dispstatus>SAPControl-GREEN</dispstatus></item>"
    "</GetProcessListResponse>")

INSTANCES = _envelope(
    "<GetSystemInstanceListResponse>"
    "<item><hostname>ecc-app1</hostname><instanceNr>0</instanceNr></item>"
    "</GetSystemInstanceListResponse>")

VERSION = _envelope(
    "<GetVersionInfoResponse>"
    "<item><Filename>disp+work</Filename><VersionInfo>753</VersionInfo></item>"
    "</GetVersionInfoResponse>")

FAULT = _envelope(
    "<SOAP-ENV:Fault xmlns:SOAP-ENV='http://schemas.xmlsoap.org/soap/envelope/'>"
    "<faultcode>SOAP-ENV:Server</faultcode>"
    "<faultstring>Invalid function</faultstring></SOAP-ENV:Fault>")


class FakeSapStartSrv(BaseHTTPRequestHandler):
    """Answers the handful of things a real one would. Configured per test."""

    #: set by the fixture
    param_body = PARAM_ITEMS
    require_auth = False
    seen: list = []

    def log_message(self, *a):        # silence the test run
        pass

    def _send(self, body: bytes, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "text/xml; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/?wsdl"):
            self._send(WSDL.encode("utf-8"))
        else:
            self._send(b"not found", 404)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode("utf-8")
        m = re.search(r"<ns1:(\w+)", body)
        op = m.group(1) if m else "?"
        type(self).seen.append(op)

        if type(self).require_auth and not self.headers.get("Authorization"):
            self._send(b"unauthorized", 401)
            return

        table = {
            "ParameterValue": type(self).param_body,
            "GetProcessList": PROCESSES,
            "GetSystemInstanceList": INSTANCES,
            "GetVersionInfo": VERSION,
        }
        self._send(table.get(op, FAULT))


@pytest.fixture()
def server():
    FakeSapStartSrv.param_body = PARAM_ITEMS
    FakeSapStartSrv.require_auth = False
    FakeSapStartSrv.seen = []
    httpd = HTTPServer(("127.0.0.1", 0), FakeSapStartSrv)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield httpd
    httpd.shutdown()
    httpd.server_close()


def collector_for(httpd, **kw):
    host, port = httpd.server_address
    return sapcontrol.SapControlCollector(
        host, 0, https=False, port=port, verify_tls=False, **kw)


# --------------------------------------------------------------------------- #
#  The safety property                                                        #
# --------------------------------------------------------------------------- #

def test_a_state_changing_operation_is_refused_before_it_reaches_the_network(server):
    """THE ONE THAT MATTERS MOST.

    sapstartsrv offers Start, Stop, Restart and OS command execution on the SAME
    endpoint and port as the read methods this collector wants. The allowlist is
    enforced in the transport, before any byte is sent, so a typo or a future
    caller cannot stop a production instance.

    Asserted by watching the fake server: it must never even SEE the request.
    """
    c = collector_for(server)
    for dangerous in ("Start", "Stop", "Restart", "ExecuteOSCommand"):
        with pytest.raises(soap.RefusedOperation):
            c.endpoint.call(dangerous)
    assert FakeSapStartSrv.seen == [], \
        "a refused operation still reached the server; the allowlist is being " \
        "applied after the request rather than before it"


def test_the_allowlist_and_the_denylist_do_not_overlap():
    """A structural guard. Adding any state-changing operation to READ_OPERATIONS
    fails here, loudly, rather than quietly becoming callable."""
    overlap = sapcontrol.READ_OPERATIONS & sapcontrol.STATE_CHANGING
    assert not overlap, f"these are both allowed and forbidden: {sorted(overlap)}"
    assert sapcontrol.READ_OPERATIONS, "the allowlist is empty"


def test_every_allowlisted_operation_reads_rather_than_writes():
    """Names alone are weak evidence, so this asserts the shape of the name too:
    a read operation is a Get*/query, never an imperative verb."""
    imperatives = ("Start", "Stop", "Restart", "Shutdown", "Execute", "Send",
                   "Set", "Delete", "Remove", "Kill", "Abort", "Bootstrap")
    for op in sorted(sapcontrol.READ_OPERATIONS):
        assert not any(op.startswith(v) for v in imperatives), \
            f"{op} reads like an imperative; if it changes state it must not be " \
            f"in READ_OPERATIONS"


def test_an_operation_the_instance_does_not_advertise_is_a_gap_not_a_call(server):
    """After probing, a method absent from the WSDL is reported as a coverage gap.
    A wrong method name for some kernel release therefore surfaces as 'we could
    not look' rather than as an empty result that reads as 'nothing there'."""
    c = collector_for(server)
    c.probe()
    c.endpoint.allowed = frozenset(c.endpoint.allowed | {"NotOnThisKernel"})
    with pytest.raises(soap.SoapError, match="not advertised"):
        c.endpoint.call("NotOnThisKernel")


# --------------------------------------------------------------------------- #
#  Collecting                                                                 #
# --------------------------------------------------------------------------- #

def test_profile_parameters_are_collected_from_item_arrays(server):
    c = collector_for(server)
    params = c.profile_parameters()
    assert params["login/min_password_lng"] == "8"
    assert params["rfc/reject_expired_passwd"] == "1"
    assert params["gw/reg_no_conn_info"] == "255"


def test_profile_parameters_are_collected_from_a_name_equals_value_blob(server):
    """The second shape seen in the field. A reader that handled only <item>
    arrays would return {} here — and an empty parameter set reads as 'this
    system has none configured', which is never true of an ABAP instance."""
    FakeSapStartSrv.param_body = PARAM_BLOB
    c = collector_for(server)
    params = c.profile_parameters()
    assert params["login/min_password_lng"] == "8"
    assert len(params) == 3


def test_a_soap_fault_is_recorded_as_a_failed_attempt_not_swallowed(server):
    """An operation the endpoint faults on must leave a trace. Returning {} and
    saying nothing is how a failed collection becomes a clean report."""
    c = collector_for(server)
    c.endpoint.allowed = frozenset(c.endpoint.allowed | {"GetInstanceProperties"})
    c.probe()
    assert c._attempt("GetInstanceProperties") is None
    failed = [a for a in c.attempts if not a["ok"]]
    assert failed and "faulted" in failed[0]["error"]


def test_missing_credentials_produce_an_explanatory_error(server):
    """401 is the single most likely first-run outcome, and 'HTTP Error 401' does
    not tell an operator that service/protectedwebmethods is the thing to look
    at."""
    FakeSapStartSrv.require_auth = True
    c = collector_for(server)
    with pytest.raises(soap.SoapError, match="protectedwebmethods"):
        c.endpoint.call("ParameterValue")


def test_an_endpoint_that_answers_without_credentials_is_reported(server):
    """A security observation collected deliberately. An instance answering an
    unauthenticated caller is exposing an interface that can also stop it."""
    c = collector_for(server)
    posture = c.probe_posture()
    assert posture["unauthenticated_read"] is True
    assert "service/protectedwebmethods" in posture["detail"]


# --------------------------------------------------------------------------- #
#  What it writes                                                             #
# --------------------------------------------------------------------------- #

def test_it_writes_a_file_the_offline_loader_reads(server, tmp_path):
    """THE WHOLE CONTRACT. What the collector writes must be indistinguishable
    from a customer's own export, so it is fed to the REAL DataLoader here rather
    than parsed by the test."""
    from modules.data_loader import DataLoader

    c = collector_for(server)
    n = extract.write_profile_parameters(tmp_path, c.profile_parameters())
    assert n == 3

    data = DataLoader(tmp_path).load_all()
    params = data.get("security_params")
    assert params, "the loader did not read the file the collector wrote"
    names = {r.get("NAME") or r.get("name") for r in params}
    assert "login/min_password_lng" in names


def test_the_written_export_actually_produces_findings(server, tmp_path):
    """One step further: the real check module must run on it. A file the loader
    accepts but no check can use would still be a broken collector."""
    from modules.data_loader import DataLoader
    from modules.security_params import SecurityParamAuditor

    c = collector_for(server)
    extract.write_profile_parameters(tmp_path, c.profile_parameters())
    data = DataLoader(tmp_path).load_all()
    findings = SecurityParamAuditor(data, {}).run_all_checks()
    assert findings, "no check produced a finding from a collected export"
    assert not any(f["check_id"] == "PARAM-000" for f in findings), \
        "the parameter module reported NO parameter export, so the collected " \
        "file did not reach it"


def test_no_parameters_means_no_file_rather_than_an_empty_one(tmp_path):
    """An empty security_params.csv would be read as 'this system reports no
    parameters' — a collection failure presenting as a clean result. Absent, the
    loader reports the source missing and PARAM-000 fires, which is honest."""
    assert extract.write_profile_parameters(tmp_path, {}) == 0
    assert not (tmp_path / "security_params.csv").exists()


# --------------------------------------------------------------------------- #
#  The manifest — why a partial collection cannot read as a complete one      #
# --------------------------------------------------------------------------- #

def test_the_manifest_states_what_was_not_collected(tmp_path):
    path = extract.write_manifest(
        tmp_path, source="sapcontrol", endpoint="https://x:50014",
        collected_at="2026-08-11T00:00:00+00:00",
        wrote={"security_params.csv": 3}, attempts=[{"operation": "ParameterValue",
                                                     "ok": True}])
    m = json.loads(path.read_text(encoding="utf-8"))
    assert m["partial"] is True
    c = m["collections"][-1]
    assert "users" in c["not_reachable"]
    assert "roles" in c["not_reachable"]
    assert "UNKNOWN, never as clean" in m["read_this"]


def test_a_connected_collection_is_always_partial(tmp_path):
    """`partial` is not a field a caller can turn off, because a connected
    collection is partial by construction: RFC-only surfaces are declined by
    decision D3, so they are never in the directory however well the run went."""
    path = extract.write_manifest(
        tmp_path, source="sapcontrol", endpoint="e", collected_at="t",
        wrote={"security_params.csv": 900}, attempts=[], cannot_reach=())
    assert json.loads(path.read_text(encoding="utf-8"))["partial"] is True


def test_disabled_tls_verification_is_recorded_not_merely_printed(tmp_path):
    """An unverified connection is a caveat on the evidence. Printing it to a
    terminal nobody kept is not recording it."""
    path = extract.write_manifest(
        tmp_path, source="sapcontrol", endpoint="e", collected_at="t",
        wrote={}, attempts=[], tls_verified=False)
    m = json.loads(path.read_text(encoding="utf-8"))
    assert m["collections"][-1]["tls_verified"] is False
    assert "TLS certificate verification was DISABLED" in extract.summarise(path)


def test_the_summary_says_so_when_nothing_was_collected(tmp_path):
    path = extract.write_manifest(
        tmp_path, source="sapcontrol", endpoint="e", collected_at="t",
        wrote={}, attempts=[{"operation": "ParameterValue", "ok": False,
                             "error": "boom"}])
    text = extract.summarise(path)
    assert "wrote NOTHING" in text
    assert "FAILED ParameterValue" in text


# --------------------------------------------------------------------------- #
#  The structural rules from the package docstring                            #
# --------------------------------------------------------------------------- #

def test_nothing_in_server_or_modules_imports_collect():
    """Decision D2 permits a connector OUT of process. A connector imported into
    the product is a live API client inside the product, which is the thing that
    was declined — and it would be declined for the same reason as before, not
    for a new one."""
    import ast
    offenders = []
    for path in (list((ROOT / "server").glob("*.py"))
                 + list((ROOT / "modules").glob("*.py"))
                 + [ROOT / "sap_scanner.py"]):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.name.split(".")[0] == "collect":
                        offenders.append(f"{path.name}:{node.lineno}")
            elif isinstance(node, ast.ImportFrom):
                if (node.module or "").split(".")[0] == "collect":
                    offenders.append(f"{path.name}:{node.lineno}")
    assert not offenders, (
        "these import the connector tier into the product: " + ", ".join(offenders))


@pytest.mark.skipif(not hasattr(sys, "stdlib_module_names"),
                    reason="sys.stdlib_module_names is 3.10+; the purity CI job "
                           "enforces this repository-wide on 3.12")
def test_collect_is_stdlib_only():
    """Decision D4 allows this package its own requirements and it spends none.
    A connector tier with NO dependencies is a stronger position than one with
    different ones — the customer running it installs nothing.

    ⚠️ THE SKIPIF IS NOT OPTIONAL, AND THIS FILE SHIPPED WITHOUT IT.
    `sys.stdlib_module_names` did not exist before Python 3.10 and the `cli` job
    runs a 3.8-3.12 matrix, so the first version of this test turned that job red
    on 3.8 and 3.9 while passing on the three newer interpreters. That is the
    identical failure `tests/test_resilience_posture.py` documents having caused
    for months, reintroduced in a new file by not looking for the established
    pattern first.

    Skipping below 3.10 is honest rather than a workaround: the `purity` job walks
    the same AST over all of collect/ on 3.12, so the guarantee holds either way
    and this is only the fast local copy of it.
    """
    import ast
    allowed = set(sys.stdlib_module_names) | {"collect"}
    for path in sorted((ROOT / "collect").glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                for a in node.names:
                    assert a.name.split(".")[0] in allowed, f"{path.name}: {a.name}"
            elif isinstance(node, ast.ImportFrom):
                mod = (node.module or "").split(".")[0]
                assert mod in allowed, f"{path.name}: {node.module}"


def test_there_is_no_password_argument():
    """Standing rule: a credential in argv is visible in `ps` and in shell
    history on a shared administrative host.

    Parsed rather than grepped: the module docstring explains WHY there is no
    --password, and a textual search cannot tell that explanation from an actual
    option. A test that forced the reasoning to be deleted in order to pass would
    be trading the documentation for the check.
    """
    import ast
    tree = ast.parse((ROOT / "collect" / "__main__.py").read_text(encoding="utf-8"))
    flags = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_argument"):
            flags += [a.value for a in node.args
                      if isinstance(a, ast.Constant) and isinstance(a.value, str)]
    assert flags, "no arguments were found; this test has stopped checking"
    bad = [f for f in flags if "pass" in f.lower() or "secret" in f.lower()]
    assert not bad, f"a credential can be supplied on the command line: {bad}"


def test_the_scanner_does_not_grow_a_connect_flag():
    """A `--connect` option on sap_scanner.py would make the scanner a program
    that sometimes opens connections to production SAP systems, which is exactly
    the property keeping connectors out of process preserves."""
    src = (ROOT / "sap_scanner.py").read_text(encoding="utf-8")
    for flag in ("--connect", "--host", "--sapcontrol", "--live"):
        assert flag not in src, f"sap_scanner.py has grown {flag}"


def test_port_numbering_matches_the_documented_convention():
    """5<NN>13 for HTTP, 5<NN>14 for HTTPS. Getting it wrong presents as
    'connection refused', which reads like a firewall rather than arithmetic."""
    assert sapcontrol.default_port(0, https=True) == 50014
    assert sapcontrol.default_port(0, https=False) == 50013
    assert sapcontrol.default_port(42, https=True) == 54214
    with pytest.raises(ValueError):
        sapcontrol.default_port(100)
