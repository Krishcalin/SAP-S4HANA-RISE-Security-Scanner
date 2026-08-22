"""Shared HTTP for the connectors. Stdlib only, GET only.

WHY `GET ONLY` IS IN THE MODULE DOCSTRING AND IN THE CODE
Everything this package does to a customer's production system is a read, and the
only way to keep that true is to make writing impossible rather than unusual.
`fetch` has no `method` parameter and no body parameter — a caller that wanted to
POST would have to edit this file, which is a code review rather than a typo.

The SOAP client in `collect/soap.py` is the single exception: SOAP requires POST
by protocol. It carries its own operation allowlist for that reason, enforced
before any byte reaches the network.
"""
from __future__ import annotations

import base64
import http.client
import socket
import ssl
import urllib.error
import urllib.request
from typing import Dict, NamedTuple, Optional


def tls_context(*, verify: bool, ca_file: Optional[str] = None) -> ssl.SSLContext:
    """A TLS context that verifies by default.

    `verify=False` exists because a great many SAP instances present a self-signed
    certificate, and refusing outright would mean the collector could not be used
    on them at all. It is opt-in, never the default, and every run that uses it
    records the fact in its manifest — an unverified connection is a caveat on the
    evidence, not a detail of the plumbing.
    """
    if not verify:
        return ssl._create_unverified_context()      # noqa: S323 — see docstring
    ctx = ssl.create_default_context(cafile=ca_file)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def basic_auth_header(username: Optional[str],
                      password: Optional[str]) -> Dict[str, str]:
    if username is None:
        return {}
    token = base64.b64encode(
        f"{username}:{password or ''}".encode("utf-8")).decode()
    return {"Authorization": f"Basic {token}"}


class Result(NamedTuple):
    """What happened, including when nothing did.

    `status is None` means the request never got an HTTP answer — DNS, TCP, TLS or
    a timeout. That is deliberately DIFFERENT from a 404: "the host refused the
    connection" and "the service is not there" are different facts, and collapsing
    them would report a firewall as an absent service.
    """
    url: str
    status: Optional[int]
    reason: str
    body: bytes
    content_type: str


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Do not follow redirects.

    A redirect is INFORMATION here, not an inconvenience: an ICF path answering
    302 to a logon page is an active, authentication-protected service, and
    following it would turn that into a 200 and record the service as needing no
    authentication — inverting the finding. It also stops a probe being walked
    onto a host the operator never authorised.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch(url: str, *, username: Optional[str] = None,
          password: Optional[str] = None, verify_tls: bool = True,
          ca_file: Optional[str] = None, timeout: float = 15.0,
          max_bytes: int = 1_000_000) -> Result:
    """One GET. Never raises for an HTTP status — the status IS the observation."""
    opener = urllib.request.build_opener(
        _NoRedirects(),
        urllib.request.HTTPSHandler(context=tls_context(verify=verify_tls,
                                                        ca_file=ca_file)))
    req = urllib.request.Request(url, method="GET")
    for k, v in basic_auth_header(username, password).items():
        req.add_header(k, v)
    # A plain, honest User-Agent. Not disguised: this is an authorised assessment
    # of the operator's own system, and an unattributable request in a customer's
    # web dispatcher log is a support ticket waiting to happen.
    req.add_header("User-Agent", "MonitorRisk-collect/1.0 (+authorised assessment)")

    try:
        with opener.open(req, timeout=timeout) as resp:
            return Result(url, resp.status, resp.reason or "",
                          resp.read(max_bytes),
                          resp.headers.get("Content-Type", ""))
    except urllib.error.HTTPError as exc:
        # 401, 403, 404, 500 — all real answers, all evidence.
        body = b""
        try:
            body = exc.read(max_bytes)
        except Exception:                                   # noqa: BLE001
            pass
        return Result(url, exc.code, exc.reason or "", body,
                      exc.headers.get("Content-Type", "") if exc.headers else "")
    except (urllib.error.URLError, socket.timeout, ssl.SSLError,
            http.client.HTTPException, OSError) as exc:
        return Result(url, None, f"{type(exc).__name__}: {exc}", b"", "")
