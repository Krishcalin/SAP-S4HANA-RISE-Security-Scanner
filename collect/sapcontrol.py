"""Collect from a live SAP ABAP instance over the sapstartsrv SOAP interface.

WHY THIS INTERFACE AND NOT RFC
Decision D3 declines RFC: the NetWeaver RFC SDK cannot be redistributed inside
the image, so every user — including the majority who only ever scan offline —
would need an S-user and a mounted SDK before the container starts. sapstartsrv
speaks SOAP over HTTP/HTTPS on a port every ABAP instance already has, needs no
SDK, and is reachable with the standard library alone.

WHAT IT ACTUALLY GETS, AND WHAT IT DOES NOT
`ParameterValue` returns the instance's profile parameters, which is the input
`modules/security_params.py` and `modules/baseline_params.py` audit — two of the
largest check modules in the product. That is a real slice of an ECC review
obtained with no export at all.

It is NOT a whole review. Users, roles, authorisations, change documents and
table-level settings live inside the ABAP stack and are reachable over RFC or by
export, not over this interface. So a connected collection is PARTIAL BY
CONSTRUCTION, `write_manifest` says so in writing, and the scanner reads that as
degraded coverage. Connected mode that quietly implied completeness would be the
same failure the release gate exists to refuse.

THE ENDPOINT IS DANGEROUS AND THAT SHAPES THIS MODULE
The same port and the same service also offer Start, Stop, Restart and OS command
execution. Which of them require authentication is governed by the profile
parameter `service/protectedwebmethods`, whose factory default has historically
left some methods callable with no credentials at all. Two consequences:

  * READ_OPERATIONS below is an allowlist enforced by the transport before any
    byte reaches the network, and STATE_CHANGING is an explicit denylist asserted
    against it by tests. Neither is decoration.
  * The posture of that parameter is itself worth reporting, so `probe_posture`
    records what the endpoint let us do WITHOUT credentials. An instance that
    answers an unauthenticated caller is a finding, not a convenience.

References for the reader: SAP Note 927637 (how service/protectedwebmethods
works) and SAP Note 1439348 (extended security settings for sapstartsrv). Both
are cited as pointers, not quoted, and the check text in `modules/` remains the
place where any claim about a parameter's meaning must be verified.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from collect import soap

#: The ONLY operations this collector may invoke. Each is a read.
#:
#: Corroborated across SAP's own documentation and administration references
#: before being written down; `Endpoint.probe` additionally checks each against
#: the WSDL the target instance publishes, so a name that is wrong for a given
#: kernel release becomes a stated coverage gap rather than a silent failure.
READ_OPERATIONS = frozenset({
    "ParameterValue",        # profile parameters — the payload that matters
    "GetProcessList",        # instance processes and their status
    "GetSystemInstanceList",  # the other instances of this system
    "GetVersionInfo",        # kernel release and patch level
    "GetInstanceProperties",  # instance number, host, port assignments
})

#: Operations this collector must NEVER perform. Not consulted at runtime — the
#: allowlist above is what the transport enforces — but asserted against it by
#: tests, so that adding any of these to READ_OPERATIONS fails CI loudly.
#:
#: They are written down because the danger is not obvious from the outside: a
#: reader would not assume that the service answering "what are your profile
#: parameters" is the same service that can stop the instance.
STATE_CHANGING = frozenset({
    "Start", "Stop", "Restart", "StartSystem", "StopSystem", "StartService",
    "StopService", "InstanceStart", "InstanceStop", "Bootstrap", "Shutdown",
    "RestartService", "RestartInstance", "ExecuteOSCommand", "OSExecute",
    "SendSignal", "ABAPAcknowledgeAlerts", "SetProcessParameter",
})


def default_port(instance_number: int, *, https: bool = True) -> int:
    """sapstartsrv listens on 5<NN>13 for HTTP and 5<NN>14 for HTTPS.

    Instance 00 is therefore 50013/50014. Computed rather than asked for, because
    getting it wrong presents as "connection refused", which reads like a firewall
    problem rather than an arithmetic one.
    """
    if not 0 <= instance_number <= 99:
        raise ValueError(f"instance number must be 00-99, got {instance_number}")
    # 50000, not 5000. The first draft dropped a zero and produced 5014 for
    # instance 00 — a port nothing listens on, which is exactly the "connection
    # refused, so it must be the firewall" wild goose chase this docstring warns
    # about. Caught by test_port_numbering_matches_the_documented_convention.
    return 50000 + instance_number * 100 + (14 if https else 13)


def endpoint_url(host: str, instance_number: int, *, https: bool = True,
                 port: Optional[int] = None) -> str:
    scheme = "https" if https else "http"
    return f"{scheme}://{host}:{port or default_port(instance_number, https=https)}"


class SapControlCollector:
    """One instance, collected read-only."""

    def __init__(self, host: str, instance_number: int, *,
                 https: bool = True, port: Optional[int] = None,
                 username: Optional[str] = None, password: Optional[str] = None,
                 verify_tls: bool = True, ca_file: Optional[str] = None,
                 timeout: float = 30.0):
        self.host = host
        self.instance_number = instance_number
        self.https = https
        self.verify_tls = verify_tls
        self.url = endpoint_url(host, instance_number, https=https, port=port)
        self.endpoint = soap.Endpoint(
            self.url, allowed=READ_OPERATIONS, username=username,
            password=password, verify_tls=verify_tls, ca_file=ca_file,
            timeout=timeout)
        #: Every operation attempted, and what came of it. This is the raw material
        #: for the manifest: an operation that failed must be visible as a gap, and
        #: the only way to guarantee that is to record attempts rather than results.
        self.attempts: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #

    def _attempt(self, operation: str,
                 params: Optional[Dict[str, str]] = None):
        try:
            result = self.endpoint.call(operation, params)
        except (soap.SoapError, soap.TransportError) as exc:
            self.attempts.append({"operation": operation, "ok": False,
                                  "error": str(exc)})
            return None
        self.attempts.append({"operation": operation, "ok": True})
        return result

    def probe(self) -> Dict[str, Any]:
        """Discover what the instance advertises before asking it for anything."""
        advertised = self.endpoint.probe()
        missing = sorted(READ_OPERATIONS - advertised)
        return {"advertised": len(advertised), "unavailable": missing}

    def probe_posture(self) -> Dict[str, Any]:
        """What this endpoint answers to a caller with NO credentials.

        A security observation, collected deliberately rather than as a
        side-effect. `service/protectedwebmethods` governs which methods require
        authentication, and an instance that answers an unauthenticated request is
        exposing an interface that can also stop it and run commands on its host.

        Reported as evidence for a check to judge — this module states what
        happened, and does not decide what it means.
        """
        anon = soap.Endpoint(self.url, allowed=frozenset({"GetVersionInfo"}),
                             username=None, password=None,
                             verify_tls=self.verify_tls,
                             ca_file=self.endpoint.ca_file,
                             timeout=self.endpoint.timeout)
        try:
            anon.call("GetVersionInfo")
        except soap.SoapError as exc:
            return {"unauthenticated_read": False, "detail": str(exc)[:300]}
        except soap.TransportError as exc:
            return {"unauthenticated_read": None, "detail": str(exc)[:300]}
        return {
            "unauthenticated_read": True,
            "detail": ("the endpoint answered GetVersionInfo with no credentials, "
                       "so at least one web method is unprotected. The same service "
                       "and port also offer instance control and OS command "
                       "execution; which of them are protected is governed by the "
                       "profile parameter service/protectedwebmethods."),
        }

    # ------------------------------------------------------------------ #

    def profile_parameters(self) -> Dict[str, str]:
        """Every profile parameter the instance will report, as NAME -> VALUE.

        Called with no argument, `ParameterValue` returns all known parameter
        value pairs; called with a name it returns one. The no-argument form is
        used because a fixed list of names would silently miss any parameter the
        list did not anticipate — including the ones a future check will want.
        """
        response = self._attempt("ParameterValue")
        if response is None:
            return {}

        out: Dict[str, str] = {}
        # Two shapes are seen in the wild: <item><name/><value/></item> arrays,
        # and a single text blob of `name = value` lines. Both are handled because
        # returning {} for the second would read as "this system has no parameters
        # configured", which is never true and never harmless.
        for row in soap.rows(response):
            name = row.get("name") or row.get("parameter")
            if name:
                out[name.strip()] = (row.get("value") or "").strip()
        if not out:
            blob = soap.text_of(response, "value") or ""
            for line in blob.splitlines():
                if "=" in line:
                    name, _, value = line.partition("=")
                    if name.strip():
                        out[name.strip()] = value.strip()
        return out

    def instances(self) -> List[Dict[str, Any]]:
        response = self._attempt("GetSystemInstanceList")
        return soap.rows(response) if response is not None else []

    def processes(self) -> List[Dict[str, Any]]:
        response = self._attempt("GetProcessList")
        return soap.rows(response) if response is not None else []

    def version(self) -> List[Dict[str, Any]]:
        response = self._attempt("GetVersionInfo")
        return soap.rows(response) if response is not None else []
