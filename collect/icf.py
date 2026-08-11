# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""Collect the ICF surface of an ABAP system over HTTP(S).

WHAT THIS IS FOR, AND WHAT IT IS HONESTLY NOT
---------------------------------------------
It was scoped as "the connector that gets users and roles". IT DOES NOT, and the
correction belongs at the top of the file rather than in a footnote: there is no
standard, pre-built OData service on ECC that exposes USR02 or AGR_USERS. Gateway
exposes whatever services an administrator has activated, and on a typical ECC
estate that set does not include user master data. Users, roles, profiles and
authorisations therefore remain export-only, exactly as `docs/DECISIONS.md` D3
says.

What IS reachable is a different logical source and a genuinely valuable one: the
ICF service tree itself — which endpoints are active, and which answer WITHOUT
authentication. That is `icf_services`, which `modules/network_services.py`,
`modules/ecs_config_items.py` and `modules/reachability.py` already consume. An
unauthenticated `/sap/bc/soap/rfc` is not a configuration detail; it is a remote
function call interface open to anyone who can route to the host.

HOW `AUTH_REQUIRED` IS DETERMINED, AND WHY IT IS PROBED ANONYMOUSLY
------------------------------------------------------------------
Every probe is sent with NO credentials, deliberately. Sending a credential would
turn a 401 into a 200 and record an authentication-protected service as one
needing no authentication — inverting the finding this collector exists to
produce. The status code is the whole observation:

    404 / 503        the service is not active here
    401 / 403        active, and authentication is required
    302 to a logon   active, and authentication is required
    200              ACTIVE AND UNAUTHENTICATED  <- the finding
    no answer at all  recorded as unknown, never as absent

THIS IS AN AUDIT OF KNOWN ENDPOINTS, NOT A SCAN
-----------------------------------------------
`WELL_KNOWN` is a short, fixed, reviewed list of documented SAP ICF paths. It is
not a wordlist and this module does not enumerate, guess, fuzz or walk links.
That distinction is deliberate: a customer authorising a configuration review has
not thereby authorised a web crawl of their production application server, and a
tool that quietly did one would deserve the incident report it got. Requests are
sequential and a delay is available for estates behind rate-limited dispatchers.

Every path is recorded WITH ITS RESULT, including the ones that answered 404.
"We looked and it was not there" and "we did not look" are different facts, and
only the first is evidence.
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlencode

from collect import web

#: Documented SAP ICF paths worth knowing the state of, each with why it matters.
#:
#: Drawn from this repository's own curated sample export and from SAP's public
#: documentation. NOT a discovery wordlist — see the module docstring. Adding an
#: entry is a deliberate act with a stated reason, which is what keeps this an
#: audit rather than a scan.
WELL_KNOWN: Tuple[Tuple[str, str], ...] = (
    ("/sap/public/info",
     "returns system information (SID, database, kernel) and is frequently left "
     "open to unauthenticated callers"),
    ("/sap/public/icman/ping",
     "ICM ping; unauthenticated by design, useful only to confirm reachability"),
    ("/sap/bc/ping",
     "ICF ping; confirms the ICF tree is reachable at all, which separates "
     "'no services active' from 'nothing answered'"),
    ("/sap/bc/soap/rfc",
     "SOAP-to-RFC gateway: a remote function call interface over HTTP"),
    ("/sap/bc/srt/rfc/sap",
     "SOAP runtime RFC endpoint"),
    ("/sap/bc/webrfc",
     "WebRFC: executes ABAP reports over HTTP"),
    ("/sap/bc/gui/sap/its/webgui",
     "full SAP GUI in a browser"),
    ("/sap/bc/bsp/sap/it00",
     "BSP test application, an example of a shipped service left active"),
    ("/sap/bc/bsp/sap/system",
     "BSP system application"),
    ("/sap/opu/odata/IWFND/CATALOGSERVICE",
     "SAP Gateway OData catalogue; if reachable, it enumerates the activated "
     "OData services"),
)

#: The Gateway service catalogue, verified against SAP Help.
#:
#: IT DOES NOT LIST OData V4 SERVICES. That is a documented limitation of the
#: catalogue, not of this collector, and it is carried into the manifest so a
#: reader does not mistake the resulting list for the complete API surface.
CATALOG_PATH = "/sap/opu/odata/IWFND/CATALOGSERVICE;v=2/ServiceCollection"

CATALOG_OMITS = ("OData V4 services are not listed by the SAP Gateway service "
                 "catalogue, so the collected endpoint list covers V2 only.")


def base_url(host: str, *, https: bool = True, port: Optional[int] = None) -> str:
    scheme = "https" if https else "http"
    if port is None:
        port = 443 if https else 80
    return f"{scheme}://{host}:{port}"


def classify(result: web.Result) -> Tuple[str, str]:
    """(ICF_ACTIVE, AUTH_REQUIRED) in the loader's own vocabulary.

    Returns ``("", "")`` when there was no HTTP answer at all. An unreachable host
    must not be recorded as a system with no active services — that would report a
    firewall as a clean estate.
    """
    if result.status is None:
        return "", ""
    if result.status in (404, 503):
        return "", ""
    if result.status in (401, 403):
        return "X", "YES"
    if result.status in (301, 302, 303, 307, 308):
        # A redirect to a logon page. Recorded as protected rather than followed —
        # following it would produce a 200 and invert the finding.
        return "X", "YES"
    if 200 <= result.status < 300:
        return "X", "NO"
    # 5xx and anything else: it answered, so something is listening, but what it
    # wants is unknown. Stated rather than guessed.
    return "X", "UNKNOWN"


class IcfCollector:
    """Probe a bounded list of documented ICF paths, anonymously."""

    def __init__(self, host: str, *, https: bool = True, port: Optional[int] = None,
                 sap_client: Optional[str] = None, verify_tls: bool = True,
                 ca_file: Optional[str] = None, timeout: float = 15.0,
                 delay: float = 0.0,
                 paths: Sequence[Tuple[str, str]] = WELL_KNOWN):
        self.base = base_url(host, https=https, port=port)
        self.sap_client = sap_client
        self.verify_tls = verify_tls
        self.ca_file = ca_file
        self.timeout = timeout
        self.delay = delay
        self.paths = tuple(paths)
        self.attempts: List[Dict[str, Any]] = []

    def _get(self, path: str, *, username: Optional[str] = None,
             password: Optional[str] = None) -> web.Result:
        url = self.base + path
        if self.sap_client:
            url += ("&" if "?" in url else "?") + urlencode(
                {"sap-client": self.sap_client})
        return web.fetch(url, username=username, password=password,
                         verify_tls=self.verify_tls, ca_file=self.ca_file,
                         timeout=self.timeout)

    def probe_services(self) -> List[Dict[str, str]]:
        """Every path in the list, with what it answered.

        ALWAYS returns one row per path, including the ones that were absent. A
        collector that returned only the hits would make a fully-probed system
        indistinguishable from a barely-probed one.
        """
        rows: List[Dict[str, str]] = []
        for i, (path, why) in enumerate(self.paths):
            if i and self.delay:
                time.sleep(self.delay)
            result = self._get(path)
            active, auth = classify(result)
            rows.append({
                "ICF_NAME": path,
                "ICF_ACTIVE": active,
                "AUTH_REQUIRED": auth,
                "OBSERVED_STATUS": ("" if result.status is None
                                    else str(result.status)),
                "WHY_IT_MATTERS": why,
            })
            self.attempts.append({
                "operation": f"GET {path}", "ok": result.status is not None,
                **({} if result.status is not None
                   else {"error": result.reason}),
            })
        return rows

    def read_catalog(self, *, username: Optional[str] = None,
                     password: Optional[str] = None) -> Optional[List[Dict[str, Any]]]:
        """The Gateway OData catalogue, if this system has one and lets us read it.

        WITH credentials, unlike the probe. The catalogue is ordinary
        authenticated data rather than an exposure test, and reading it
        anonymously would usually just yield a 401 and no list.

        Returns None when there is no catalogue to read — which is a coverage gap
        (this estate has no Gateway, or it is not activated, or the credential
        cannot see it), NOT an empty API surface.
        """
        url_path = CATALOG_PATH + "?" + urlencode({"$format": "json"})
        result = self._get(url_path, username=username, password=password)
        self.attempts.append({
            "operation": f"GET {CATALOG_PATH}",
            "ok": bool(result.status and 200 <= result.status < 300),
            **({} if result.status and 200 <= result.status < 300
               else {"error": f"HTTP {result.status}: {result.reason}"[:200]}),
        })
        if not result.status or not (200 <= result.status < 300):
            return None
        try:
            payload = json.loads(result.body.decode("utf-8", "replace"))
        except (ValueError, UnicodeDecodeError):
            return None

        # OData v2 JSON nests the rows under d/results. Tolerated in several
        # shapes because a strict reader that found none would return [] — and an
        # empty endpoint list reads as "this system exposes no APIs", which is a
        # much stronger claim than "we could not parse the answer".
        items = payload.get("d", payload)
        if isinstance(items, dict):
            items = items.get("results", [])
        if not isinstance(items, list):
            return None

        out: List[Dict[str, Any]] = []
        for row in items:
            if not isinstance(row, dict):
                continue
            name = (row.get("TechnicalServiceName") or row.get("Title")
                    or row.get("ID") or "")
            if not name:
                continue
            out.append({
                "name": name,
                "url": row.get("ServiceUrl") or row.get("MetadataUrl") or "",
                "status": "ACTIVE",
                # NOT guessed. The catalogue does not state an authentication
                # method, and inventing one would put a fabricated fact in front
                # of a check that reads it.
                "authentication": "unknown",
                "version": str(row.get("TechnicalServiceVersion") or ""),
            })
        return out
