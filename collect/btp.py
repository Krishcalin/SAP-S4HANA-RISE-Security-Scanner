# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""Collect SAP BTP configuration over the platform's own REST APIs.

    python -m collect btp --service-key ./destination-key.json --out ./extract
    python -m collect btp --cloud-connector scc.example.com:8443 \\
                          --user Administrator --out ./extract

Then scan what it wrote, exactly as if the customer had exported it by hand:

    python sap_scanner.py --data-dir ./extract

WHY THIS EXISTS, AND WHY IT IS HERE RATHER THAN IN modules/.
A live BTP OAuth scanner was REMOVED from this codebase once, on three grounds
recorded in docs/CVA_MERGE_PLAN.md: it was a network client inside `modules/`,
it duplicated checks that already existed, and its `import requests` was the
only non-stdlib import in the product. Decision D2 reversed exactly one of
those three and no more — connectors are permitted, out of process, under
`collect/`, writing a file the offline path already reads. So this module may
open sockets and may not be imported by `server/` or `modules/`; deleting the
directory must leave every test passing.

THE BASE URL IS THE CUSTOMER'S, NEVER OURS.
A BTP service is reached at a per-region, per-service hostname that no tool can
correctly guess, and guessing one would produce a connection error that reads
like a permissions problem. So this collector takes the SERVICE KEY the customer
downloads from the BTP cockpit — the file that already carries `uaa.clientid`,
`uaa.clientsecret`, `uaa.url` and the service `url` — and reads the endpoint out
of it. We supply only the resource path, and each one is declared in `ENDPOINTS`
below with how well it is attested. Two of them are corroborated inside this
repository: `modules/btp_import.py` names `/api/v1/configuration` and
`/auditlog/v2/auditlogrecords` in its own docstring, because it was written to
parse those exact payloads.

WHAT IT WRITES IS RAW, ON PURPOSE.
`modules/btp_import.py` already translates the BTP CLI's JSON, the Cloud
Connector configuration API and the audit-log API into the shapes the checks
read — including the parts that must NOT be inferred, such as refusing to
synthesise Cloud Connector host ACLs the API has no concept of. Re-implementing
any of that here would create a second normaliser to disagree with the first, so
this collector writes the payload through unchanged and lets the importer do
what it already does correctly.

THE SECRET IS IN THE KEY FILE, NOT IN argv.
`--service-key` is a path, like `--ca-file`. The client secret lives inside the
file the customer already downloaded, so it never reaches the command line, `ps`
output or shell history. The Cloud Connector's administration API uses Basic
authentication rather than OAuth, so it goes through the same password path
every other collector uses.

READ-ONLY IS ENFORCED BY THE TRANSPORT.
`ALLOWED_PATHS` is checked before a request is built, not promised by the
caller, and the single POST this module makes is to the token endpoint named in
the customer's own service key — there is no other POST and no request builder
that could make one.
"""
from __future__ import annotations

import json
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from collect import web

#: One TLS policy for the whole package, in collect/web.py — imported, never
#: re-implemented. Two copies would drift, and the copy that drifted would be
#: the one that stopped verifying.
_tls_context = web.tls_context

#: The OAuth 2.0 client-credentials path on an XSUAA/IAS authorisation server.
#: Appended to the `uaa.url` the customer's own service key supplies.
TOKEN_PATH = "/oauth/token"


#: What this collector fetches. Declarative for the same reason
#: `collect/rfc_tables.py` is: the paths are reviewable in one place, and
#: `--list-sources` falls out of it without a second list to keep in step.
#:
#: `attested` records how well the path is established, in this repository's
#: usual three tiers. A path marked `in-repo` is one `modules/btp_import.py`
#: names in its own docstring because it parses that payload. `documented` is
#: SAP's published API surface. Nothing here is invented, and an operator can
#: check every one with `--list-sources` before a single request is made.
ENDPOINTS: Sequence[Dict[str, Any]] = (
    {
        "source": "btp_destinations",
        "file": "btp_destinations.json",
        "path": "/destination-configuration/v1/subaccountDestinations",
        "attested": "documented",
        "note": "Subaccount destinations. Feeds BTP-DST-001..004. Needs a "
                "service key for the Destination service.",
    },
    {
        "source": "btp_subaccounts",
        "file": "btp_subaccounts.json",
        "path": "/accounts/v1/subaccounts",
        "attested": "documented",
        "note": "Subaccount inventory from the Cloud Management service. Feeds "
                "BTP-GOV-001/002 once audit and IdP evidence is merged onto it.",
    },
    {
        "source": "btp_audit_log_records",
        "file": "btp_audit_log_records.json",
        "path": "/auditlog/v2/auditlogrecords",
        "attested": "in-repo",
        "note": "Audit log records. modules/btp_import.py names this path and "
                "reduces the payload to a per-tenant SUMMARY — records are "
                "personal data and never reach a report.",
    },
)

#: The Cloud Connector's own administration API. Not OAuth: it is a
#: customer-hosted appliance with Basic authentication, so it is fetched
#: separately from the service-key path above.
CLOUD_CONNECTOR_PATH = "/api/v1/configuration"

#: Every path this collector may request. Checked before a request is built.
ALLOWED_PATHS = frozenset(
    [e["path"] for e in ENDPOINTS] + [CLOUD_CONNECTOR_PATH])

#: Logical sources a BTP collector cannot produce, with the reason. Passed to
#: the manifest rather than derived, so that adding a source to the loader
#: cannot silently turn a new gap into a documented limitation.
BTP_CANNOT_REACH: Mapping[str, str] = {
    "ias_config": "The Identity Authentication tenant is a separate product "
                  "with its own administration API and its own credentials; it "
                  "is not reachable with a BTP subaccount service key.",
    "btp_users": "User lists are personal data. Collecting them needs a "
                 "decision by the customer about scope and retention, not a "
                 "default in a scanner.",
    "btp_trust": "Trust configuration is exposed per subaccount through a "
                 "different service; no path for it is attested here, and "
                 "guessing one would report a connection error as a finding.",
    "cf_roles": "Cloud Foundry org and space roles come from the CF API with a "
                "CF login, which is a separate authentication flow.",
    "btp_service_bindings": "Service bindings are enumerated per service "
                            "instance; the collector would need to walk every "
                            "instance in every subaccount, which is a scope "
                            "decision rather than a default.",
    "event_mesh": "Event Mesh and CPI expose their own management APIs, each "
                  "with its own service key.",
    "cpi_artifacts": "Cloud Integration's OData management API needs its own "
                     "service key and tenant URL.",
}


class ServiceKeyError(ValueError):
    """The supplied service key is not one this collector can use."""


class RefusedRequest(RuntimeError):
    """A path outside the allowlist was requested. Raised before any network."""


class ServiceKey:
    """The parts of a downloaded BTP service key this collector needs.

    Accepts the two shapes the cockpit and the CLI produce: the credentials at
    the top level, or wrapped under `credentials` as `btp` and `cf` emit them.
    """

    def __init__(self, payload: Mapping[str, Any]):
        creds = payload.get("credentials")
        if isinstance(creds, Mapping):
            payload = creds
        uaa = payload.get("uaa")
        if not isinstance(uaa, Mapping):
            uaa = payload
        self.client_id = str(uaa.get("clientid") or uaa.get("client_id") or "")
        self.client_secret = str(
            uaa.get("clientsecret") or uaa.get("client_secret") or "")
        self.token_url = str(uaa.get("url") or "").rstrip("/")
        self.service_url = str(payload.get("url") or "").rstrip("/")
        missing = [n for n, v in (("clientid", self.client_id),
                                  ("clientsecret", self.client_secret),
                                  ("uaa.url", self.token_url),
                                  ("url", self.service_url)) if not v]
        if missing:
            raise ServiceKeyError(
                "service key is missing " + ", ".join(missing)
                + ". Download the key from the BTP cockpit for the service "
                  "instance you want to read, and pass the file unchanged.")

    @classmethod
    def from_file(cls, path: str) -> "ServiceKey":
        with open(path, "r", encoding="utf-8") as fh:
            return cls(json.load(fh))

    def __repr__(self) -> str:                              # pragma: no cover
        # The secret must not be reachable through a debug print or a traceback.
        return "ServiceKey(service_url=%r, client_id=%r)" % (
            self.service_url, self.client_id)


class BtpCollector:
    """One BTP service endpoint, with a path allowlist it cannot exceed."""

    def __init__(self, key: ServiceKey, *, allowed: frozenset = ALLOWED_PATHS,
                 verify_tls: bool = True, ca_file: Optional[str] = None,
                 timeout: float = 30.0):
        self.key = key
        #: The ONLY paths this collector may request. Passed in rather than
        #: defaulted inside the transport, so the permitted set is visible at
        #: the call site — the same rule collect/soap.py follows.
        self.allowed = allowed
        self.verify_tls = verify_tls
        self.ca_file = ca_file
        self.timeout = timeout
        self._token: Optional[str] = None
        self.attempts: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #

    def token(self) -> str:
        """Acquire a client-credentials access token. The only POST here.

        Credentials go in the Authorization header rather than the form body:
        both are permitted by RFC 6749, and a secret in a body is a secret in
        any proxy log that records request bodies.
        """
        if self._token is not None:
            return self._token
        url = self.key.token_url + TOKEN_PATH
        body = urllib.parse.urlencode({"grant_type": "client_credentials"})
        req = urllib.request.Request(
            url, data=body.encode("utf-8"), method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.add_header("Accept", "application/json")
        req.add_header("User-Agent",
                       "MonitorRisk-collect/1.0 (+authorised assessment)")
        for k, v in web.basic_auth_header(self.key.client_id,
                                          self.key.client_secret).items():
            req.add_header(k, v)
        ctx = _tls_context(verify=self.verify_tls, ca_file=self.ca_file)
        with urllib.request.urlopen(req, timeout=self.timeout,
                                    context=ctx) as resp:
            payload = json.loads(resp.read(1_000_000).decode("utf-8", "replace"))
        token = payload.get("access_token")
        if not token:
            raise ServiceKeyError(
                "the authorisation server answered without an access_token")
        self._token = str(token)
        return self._token

    def get(self, path: str) -> web.Result:
        """One GET against the service, with a bearer token.

        The allowlist is checked BEFORE the request is built, so a path outside
        it cannot reach the network even by mistake.
        """
        if path not in self.allowed:
            raise RefusedRequest(
                "%s is not in this collector's allowlist" % path)
        return _bearer_get(self.key.service_url + path, self.token(),
                           verify_tls=self.verify_tls, ca_file=self.ca_file,
                           timeout=self.timeout)

    def collect(self, endpoints: Sequence[Mapping[str, Any]] = ENDPOINTS
                ) -> Dict[str, Any]:
        """Fetch every endpoint, recording each attempt as evidence.

        A failure is an entry in `attempts`, never an exception that abandons
        the run: one service key rarely reaches every service, and the honest
        outcome is a partial collection whose manifest says which parts are
        missing.
        """
        out: Dict[str, Any] = {}
        for spec in endpoints:
            path = spec["path"]
            try:
                res = self.get(path)
            except Exception as exc:                         # noqa: BLE001
                self.attempts.append({"operation": path, "ok": False,
                                      "error": "%s: %s" % (type(exc).__name__, exc)})
                continue
            if res.status != 200 or not res.body:
                self.attempts.append({
                    "operation": path, "ok": False,
                    "error": "HTTP %s %s" % (res.status, res.reason)})
                continue
            try:
                payload = json.loads(res.body.decode("utf-8", "replace"))
            except ValueError as exc:
                self.attempts.append({"operation": path, "ok": False,
                                      "error": "not JSON: %s" % exc})
                continue
            self.attempts.append({"operation": path, "ok": True, "error": ""})
            out[spec["source"]] = payload
        return out


def _bearer_get(url: str, token: str, *, verify_tls: bool = True,
                ca_file: Optional[str] = None,
                timeout: float = 30.0) -> web.Result:
    """A GET carrying a bearer token.

    `web.fetch` cannot do this — it has no header parameter, and giving it one
    would make the shared helper able to carry a credential for every caller.
    The status is returned rather than raised, exactly as `web.fetch` does,
    because the status IS the observation.
    """
    req = urllib.request.Request(url, method="GET")
    req.add_header("Authorization", "Bearer " + token)
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent",
                   "MonitorRisk-collect/1.0 (+authorised assessment)")
    opener = urllib.request.build_opener(
        web._NoRedirects(),
        urllib.request.HTTPSHandler(
            context=_tls_context(verify=verify_tls, ca_file=ca_file)))
    try:
        with opener.open(req, timeout=timeout) as resp:
            return web.Result(url, resp.status, resp.reason or "",
                              resp.read(4_000_000),
                              resp.headers.get("Content-Type", ""))
    except urllib.error.HTTPError as exc:
        body = b""
        try:
            body = exc.read(1_000_000)
        except Exception:                                    # noqa: BLE001
            pass
        return web.Result(url, exc.code, exc.reason or "", body,
                          exc.headers.get("Content-Type", "") if exc.headers else "")
    except Exception as exc:                                 # noqa: BLE001
        return web.Result(url, None, "%s: %s" % (type(exc).__name__, exc), b"", "")


def fetch_cloud_connector(host: str, *, username: str, password: str,
                          verify_tls: bool = True, ca_file: Optional[str] = None,
                          timeout: float = 30.0
                          ) -> Tuple[Optional[Any], Dict[str, Any]]:
    """Read a Cloud Connector's configuration through its administration API.

    Basic authentication, not OAuth: the Cloud Connector is a customer-hosted
    appliance with its own local administrator. `modules/btp_import.py` names
    this path in its docstring and parses this exact payload.

    Returns `(payload_or_None, attempt_record)`.
    """
    if CLOUD_CONNECTOR_PATH not in ALLOWED_PATHS:            # pragma: no cover
        raise RefusedRequest(CLOUD_CONNECTOR_PATH)
    base = host if "://" in host else "https://" + host
    url = base.rstrip("/") + CLOUD_CONNECTOR_PATH
    res = web.fetch(url, username=username, password=password,
                    verify_tls=verify_tls, ca_file=ca_file, timeout=timeout)
    if res.status != 200 or not res.body:
        return None, {"operation": CLOUD_CONNECTOR_PATH, "ok": False,
                      "error": "HTTP %s %s" % (res.status, res.reason)}
    try:
        payload = json.loads(res.body.decode("utf-8", "replace"))
    except ValueError as exc:
        return None, {"operation": CLOUD_CONNECTOR_PATH, "ok": False,
                      "error": "not JSON: %s" % exc}
    return payload, {"operation": CLOUD_CONNECTOR_PATH, "ok": True, "error": ""}


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def describe_sources() -> List[str]:
    """What `--list-sources` prints. No connection is made."""
    lines = ["Sources this collector can produce (service key required):"]
    for e in ENDPOINTS:
        lines.append("  %-24s %-12s %s" % (e["source"], "[" + e["attested"] + "]",
                                           e["path"]))
        lines.append("        %s" % e["note"])
    lines.append("  %-24s %-12s %s" % ("cloud_connector", "[in-repo]",
                                       CLOUD_CONNECTOR_PATH))
    lines.append("        Cloud Connector administration API "
                 "(--cloud-connector, Basic auth).")
    lines.append("")
    lines.append("Cannot be reached by this collector:")
    for src in sorted(BTP_CANNOT_REACH):
        lines.append("  %-24s %s" % (src, BTP_CANNOT_REACH[src]))
    return lines
