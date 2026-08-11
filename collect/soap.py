# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""A very small SOAP client, stdlib only.

NOT A GENERAL SOAP LIBRARY, AND DELIBERATELY NOT. It speaks exactly the shape
sapstartsrv answers to and refuses everything else. A general client would accept
any operation the endpoint offers, and the endpoint in question offers Start,
Stop, Restart and OS-command execution alongside the read methods this product
wants — so "general" would mean one typo away from stopping a production
instance.

WHY urllib AND NOT requests
Decision D4 allows `collect/` its own dependencies and this package spends none.
urllib.request plus ssl covers everything needed here; the cost is a little more
code in `post`, and the benefit is that a customer running the collector installs
nothing.
"""
from __future__ import annotations

import base64
import http.client
import socket
import ssl
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional
from xml.etree import ElementTree as ET

#: sapstartsrv answers SOAP 1.1 in this namespace. Confirmed against the WSDL the
#: instance itself publishes at /?wsdl rather than assumed — see `Endpoint.probe`,
#: which reads the live WSDL and refuses to call anything it does not advertise.
SAPCONTROL_NS = "urn:SAPControl"

_ENVELOPE_NS = "http://schemas.xmlsoap.org/soap/envelope/"


class SoapError(RuntimeError):
    """The endpoint answered, and the answer was a fault or was unusable."""


class TransportError(RuntimeError):
    """The endpoint could not be reached, or refused the connection."""


class RefusedOperation(RuntimeError):
    """A caller asked for an operation this client is not permitted to perform.

    Raised BEFORE any bytes reach the network. This is the read-only guarantee:
    it is enforced by the transport rather than promised by the caller, because a
    caller that could be trusted to only ask for safe things would not need the
    guarantee in the first place.
    """


def _tls_context(*, verify: bool, ca_file: Optional[str]) -> ssl.SSLContext:
    """A TLS context that verifies by default.

    `verify=False` exists because a great many SAP instances present a
    self-signed certificate and refusing outright would mean the collector simply
    could not be used on them. It is opt-in, it is never the default, and every
    run that uses it records the fact in its manifest — an unverified connection
    is a caveat on the evidence, not a detail of the plumbing.
    """
    if not verify:
        ctx = ssl._create_unverified_context()      # noqa: S323 — see docstring
        return ctx
    ctx = ssl.create_default_context(cafile=ca_file)
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


class Endpoint:
    """One sapstartsrv endpoint, with an operation allowlist it cannot exceed."""

    def __init__(self, url: str, *, allowed: frozenset,
                 username: Optional[str] = None, password: Optional[str] = None,
                 verify_tls: bool = True, ca_file: Optional[str] = None,
                 timeout: float = 30.0):
        self.url = url.rstrip("/")
        #: The ONLY operations this endpoint may be asked for. Frozen, and passed
        #: in by the connector rather than defaulted here, so the permitted set is
        #: visible at the call site instead of buried in a transport.
        self.allowed = allowed
        self.username = username
        self.password = password
        self.verify_tls = verify_tls
        self.ca_file = ca_file
        self.timeout = timeout
        #: Operations the live endpoint actually advertises. Empty until `probe`
        #: runs. Empty is NOT "everything" — see `call`.
        self.advertised: Optional[frozenset] = None

    # ------------------------------------------------------------------ #

    def _request(self, body: bytes, headers: Dict[str, str]) -> bytes:
        req = urllib.request.Request(self.url, data=body, headers=headers,
                                     method="POST")
        if self.username is not None:
            token = base64.b64encode(
                f"{self.username}:{self.password or ''}".encode("utf-8")).decode()
            req.add_header("Authorization", f"Basic {token}")
        ctx = _tls_context(verify=self.verify_tls, ca_file=self.ca_file)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout,
                                        context=ctx) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read()[:2000].decode("utf-8", "replace")
            if exc.code in (401, 403):
                raise SoapError(
                    f"{self.url} refused the request with HTTP {exc.code}. The "
                    f"method is protected by service/protectedwebmethods and the "
                    f"supplied credentials were not accepted."
                ) from exc
            raise SoapError(f"HTTP {exc.code} from {self.url}: {detail}") from exc
        except (urllib.error.URLError, socket.timeout, ssl.SSLError,
                http.client.HTTPException, OSError) as exc:
            raise TransportError(f"cannot reach {self.url}: {exc}") from exc

    def probe(self) -> frozenset:
        """Read the endpoint's own WSDL and record what it advertises.

        WHY THIS EXISTS. A method name that is wrong — a typo, a rename between
        kernel releases, a method this instance simply does not offer — would
        otherwise surface as a SOAP fault mid-collection, or worse as an empty
        result that reads like "there is nothing there". Asking the instance what
        it offers turns that into a stated coverage gap before anything is
        collected, which is the difference between "we did not look" and "we
        looked and found nothing".
        """
        url = f"{self.url}/?wsdl"
        req = urllib.request.Request(url, method="GET")
        if self.username is not None:
            token = base64.b64encode(
                f"{self.username}:{self.password or ''}".encode("utf-8")).decode()
            req.add_header("Authorization", f"Basic {token}")
        ctx = _tls_context(verify=self.verify_tls, ca_file=self.ca_file)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout,
                                        context=ctx) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            raise SoapError(f"cannot read the WSDL at {url}: HTTP {exc.code}") from exc
        except (urllib.error.URLError, socket.timeout, ssl.SSLError,
                http.client.HTTPException, OSError) as exc:
            raise TransportError(f"cannot reach {url}: {exc}") from exc

        try:
            root = ET.fromstring(raw)
        except ET.ParseError as exc:
            raise SoapError(f"the WSDL at {url} is not parseable XML: {exc}") from exc

        names = {el.get("name") for el in root.iter()
                 if el.tag.endswith("}operation") and el.get("name")}
        self.advertised = frozenset(n for n in names if n)
        return self.advertised

    def call(self, operation: str,
             params: Optional[Dict[str, str]] = None) -> ET.Element:
        """Invoke one allowlisted read operation and return its response element.

        THE ORDER OF THESE TWO CHECKS IS THE SAFETY PROPERTY. The allowlist is
        consulted first and without any network access, so an operation this
        client may not perform cannot be sent even to an endpoint that would
        happily perform it.
        """
        if operation not in self.allowed:
            raise RefusedOperation(
                f"{operation!r} is not in this collector's read-only allowlist "
                f"({', '.join(sorted(self.allowed))}). sapstartsrv offers "
                f"state-changing operations — Start, Stop, Restart, and OS command "
                f"execution — on this same endpoint and port, so the allowlist is "
                f"enforced here rather than trusted to callers.")
        if self.advertised is not None and operation not in self.advertised:
            raise SoapError(
                f"{operation!r} is not advertised by {self.url}. This instance's "
                f"WSDL lists {len(self.advertised)} operation(s) and this is not "
                f"one of them — it is a coverage gap, not a failure.")

        args = "".join(f"<{k}>{_escape(v)}</{k}>" for k, v in (params or {}).items())
        envelope = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f'<SOAP-ENV:Envelope xmlns:SOAP-ENV="{_ENVELOPE_NS}" '
            f'xmlns:ns1="{SAPCONTROL_NS}">'
            "<SOAP-ENV:Body>"
            f"<ns1:{operation}>{args}</ns1:{operation}>"
            "</SOAP-ENV:Body></SOAP-ENV:Envelope>"
        ).encode("utf-8")

        raw = self._request(envelope, {
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": f'"{SAPCONTROL_NS}:{operation}"',
            "Content-Length": str(len(envelope)),
        })

        try:
            root = ET.fromstring(raw)
        except ET.ParseError as exc:
            raise SoapError(
                f"{operation} returned a body that is not XML: {raw[:200]!r}") from exc

        fault = root.find(f".//{{{_ENVELOPE_NS}}}Fault")
        if fault is not None:
            msg = (fault.findtext("faultstring")
                   or fault.findtext(f"{{{_ENVELOPE_NS}}}faultstring") or "")
            raise SoapError(f"{operation} faulted: {msg.strip() or 'no detail'}")

        body = root.find(f"{{{_ENVELOPE_NS}}}Body")
        if body is None or len(body) == 0:
            raise SoapError(f"{operation} returned an empty SOAP body")
        return body[0]


def _escape(value: str) -> str:
    return (str(value).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def rows(response: ET.Element, item_tag: str = "item") -> List[Dict[str, Any]]:
    """Flatten a SAPControl array response into dicts.

    sapstartsrv wraps arrays as <item> children carrying flat elements. Kept
    tolerant of namespaces because the responses are not consistently prefixed
    across kernel releases, and a namespace-strict reader would return an empty
    list — which is the failure mode that reads as "nothing configured".
    """
    out: List[Dict[str, Any]] = []
    for item in response.iter():
        tag = item.tag.rsplit("}", 1)[-1]
        if tag != item_tag:
            continue
        row = {child.tag.rsplit("}", 1)[-1]: (child.text or "").strip()
               for child in item}
        if row:
            out.append(row)
    return out


def text_of(response: ET.Element, name: str) -> Optional[str]:
    """The first descendant with this local name, ignoring namespaces."""
    for el in response.iter():
        if el.tag.rsplit("}", 1)[-1] == name:
            return (el.text or "").strip()
    return None
