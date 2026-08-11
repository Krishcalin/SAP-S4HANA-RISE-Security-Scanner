# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""The collector's command line.

    python -m collect sapcontrol --host ecc-prod.example.com --instance 00 \
                                 --user SAPADM --out ./extract
    python -m collect sapcontrol --host ecc.example.com --instance 00 \
                                 --out ./extract --probe-only

Then scan what it wrote, exactly as if the customer had exported it by hand:

    python sap_scanner.py --data-dir ./extract

SEPARATE ENTRY POINT ON PURPOSE. This is not a flag on `sap_scanner.py`. A
`--connect` option would make the scanner a program that sometimes opens network
connections to production SAP systems, which is precisely the property decision
D2 preserved by keeping connectors out of process. Two commands, one artefact
between them, and the scanner unchanged.

PASSWORDS NEVER COME FROM argv. There is no `--password` and there must not be:
an argument is visible in `ps` output and in shell history on a shared
administrative host, which is the worst possible place for a credential that can
read a production instance's configuration. A TTY is prompted, a pipe is read,
and `SAPCONTROL_PASSWORD` is honoured for unattended runs.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from collect import extract, icf, sapcontrol, soap


def _read_password(user: Optional[str]) -> Optional[str]:
    """Obtain a password without ever putting it on the command line."""
    if user is None:
        return None
    env = os.environ.get("SAPCONTROL_PASSWORD")
    if env:
        return env
    if sys.stdin.isatty():
        return getpass.getpass(f"password for {user}: ")
    line = sys.stdin.readline().rstrip("\n")
    if not line:
        print("no password supplied. Run interactively, pipe one in, or set "
              "SAPCONTROL_PASSWORD.", file=sys.stderr)
        return None
    return line


def cmd_sapcontrol(args: argparse.Namespace) -> int:
    if args.user is not None:
        password = _read_password(args.user)
        if password is None:
            return 2
    else:
        password = None

    collector = sapcontrol.SapControlCollector(
        args.host, args.instance, https=not args.http, port=args.port,
        username=args.user, password=password,
        verify_tls=not args.insecure, ca_file=args.ca_file,
        timeout=args.timeout)

    print(f"[*] {collector.url}")
    if args.insecure:
        # Loudly, every time. An unverified connection is a caveat on the
        # evidence, and it is recorded in the manifest as well as printed here.
        print("[!] TLS certificate verification is DISABLED for this collection.")

    try:
        probe = collector.probe()
    except (soap.SoapError, soap.TransportError) as exc:
        print(f"[!] cannot read the instance's WSDL: {exc}", file=sys.stderr)
        print("    Nothing was collected. This is a connection or credential "
              "problem, NOT an empty system.", file=sys.stderr)
        return 1
    print(f"[*] the instance advertises {probe['advertised']} operation(s)")
    if probe["unavailable"]:
        print(f"[!] not offered here: {', '.join(probe['unavailable'])}")

    posture = collector.probe_posture()
    if posture.get("unauthenticated_read") is True:
        print("[!] this endpoint answered a read with NO credentials — recorded")

    if args.probe_only:
        print("[*] --probe-only: nothing was collected and nothing was written")
        return 0

    out = Path(args.out)
    params = collector.profile_parameters()
    wrote = {
        "security_params.csv": extract.write_profile_parameters(out, params),
        "sapcontrol_instances.csv": extract.write_instances(out, collector.instances()),
        "sapcontrol_processes.csv": extract.write_processes(out, collector.processes()),
    }

    collected_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    # ONLY when the parameter read actually succeeded. Declaring completeness on
    # the strength of a call that returned nothing would assert that a system has
    # no parameters — which is never true of an ABAP instance, and would turn
    # every rule into a confident "not set".
    if params:
        decl = extract.declare_complete(
            out, ["security_params"], declared_by=f"collect/sapcontrol {collector.url}",
            method="SAPControl ParameterValue with no argument, which returns "
                   "every parameter the instance reports",
            when=collected_at)
        print(f"[*] declared security_params complete: {decl.name}")
        print("    (absent parameters will now be judged as NOT SET rather than "
              "listed as gaps — remove that file if the read was partial)")

    manifest = extract.write_manifest(
        out, source="sapcontrol", endpoint=collector.url,
        collected_at=collected_at,
        wrote=wrote, attempts=collector.attempts,
        unavailable=probe["unavailable"], tls_verified=not args.insecure,
        posture=posture)

    print(extract.summarise(manifest))
    print(f"[*] manifest: {manifest}")
    print(f"[*] now scan it: python sap_scanner.py --data-dir {out}")

    # A collection that obtained NOTHING must not exit 0. A pipeline that treats
    # exit 0 as "we have data" would otherwise proceed to scan an empty directory
    # and report a clean estate.
    if not any(wrote.values()):
        print("[!] no data was collected", file=sys.stderr)
        return 1
    return 0


def cmd_icf(args: argparse.Namespace) -> int:
    """Probe the ICF surface, and read the Gateway catalogue if there is one."""
    collector = icf.IcfCollector(
        args.host, https=not args.http, port=args.port,
        sap_client=args.sap_client, verify_tls=not args.insecure,
        ca_file=args.ca_file, timeout=args.timeout, delay=args.delay)

    print(f"[*] {collector.base}")
    print(f"[*] probing {len(collector.paths)} documented ICF path(s), "
          f"WITHOUT credentials")
    print("    (anonymously on purpose: sending a credential would turn a 401 "
          "into a 200\n     and record a protected service as needing no "
          "authentication)")
    if args.insecure:
        print("[!] TLS certificate verification is DISABLED for this collection.")

    rows = collector.probe_services()
    reachable = [r for r in rows if r["ICF_ACTIVE"] == "X"]
    if not reachable and all(not r["OBSERVED_STATUS"] for r in rows):
        print(f"[!] nothing answered at {collector.base}. That is a connection "
              f"problem, NOT a system with no active services.", file=sys.stderr)
        return 1

    open_now = [r for r in rows if r["AUTH_REQUIRED"] == "NO"]
    for r in open_now:
        print(f"[!] UNAUTHENTICATED: {r['ICF_NAME']}  ({r['WHY_IT_MATTERS']})")

    catalog = None
    if args.user is not None:
        password = _read_password(args.user)
        if password is None:
            return 2
        catalog = collector.read_catalog(username=args.user, password=password)
        if catalog is None:
            print("[*] no readable OData catalogue (no Gateway, not activated, "
                  "or not visible to this user) — recorded as a gap")

    out = Path(args.out)
    wrote = {
        "icf_services.csv": extract.write_icf_services(out, rows),
        "api_endpoints.json": extract.write_api_endpoints(out, catalog or []),
    }

    caveats = [icf.CATALOG_OMITS] if catalog else []
    manifest = extract.write_manifest(
        out, source="icf", endpoint=collector.base,
        collected_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        wrote=wrote, attempts=collector.attempts,
        cannot_reach=extract.ICF_CANNOT_REACH,
        tls_verified=not args.insecure, caveats=caveats,
        posture={"unauthenticated_read": bool(open_now),
                 "detail": ", ".join(r["ICF_NAME"] for r in open_now)})

    print(extract.summarise(manifest))
    print(f"[*] manifest: {manifest}")
    print(f"[*] now scan it: python sap_scanner.py --data-dir {out}")
    if not any(wrote.values()):
        print("[!] no data was collected", file=sys.stderr)
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m collect",
        description="Collect an SAP configuration export from a live system. "
                    "Read-only, out of process, writes the same files an offline "
                    "export would.")
    sub = p.add_subparsers(dest="command", required=True)

    sc = sub.add_parser(
        "sapcontrol",
        help="collect profile parameters and topology from an ABAP instance's "
             "sapstartsrv SOAP interface")
    sc.add_argument("--host", required=True)
    sc.add_argument("--instance", type=int, default=0,
                    help="instance number 00-99 (default 00); the port is derived "
                         "as 5<NN>14 for HTTPS and 5<NN>13 for HTTP")
    sc.add_argument("--port", type=int, default=None,
                    help="override the derived port")
    sc.add_argument("--http", action="store_true",
                    help="use HTTP instead of HTTPS. The credential and every "
                         "parameter value then cross the network in clear text")
    sc.add_argument("--user", default=None,
                    help="user for protected web methods. The password is NEVER "
                         "an argument: it is prompted, piped, or taken from "
                         "SAPCONTROL_PASSWORD")
    sc.add_argument("--insecure", action="store_true",
                    help="do not verify the TLS certificate. Recorded in the "
                         "manifest, because an unverified connection is a caveat "
                         "on the evidence")
    sc.add_argument("--ca-file", default=None,
                    help="a CA bundle to verify the instance's certificate "
                         "against — the right answer for a self-signed estate")
    sc.add_argument("--timeout", type=float, default=30.0)
    sc.add_argument("--out", default="./extract",
                    help="directory to write the export into (default ./extract)")
    sc.add_argument("--probe-only", action="store_true",
                    help="report what the endpoint offers and exposes, collect "
                         "nothing, write nothing")
    sc.set_defaults(fn=cmd_sapcontrol)

    ic = sub.add_parser(
        "icf",
        help="probe the ICF service surface over HTTP(S) and, with credentials, "
             "read the SAP Gateway OData catalogue")
    ic.add_argument("--host", required=True)
    ic.add_argument("--port", type=int, default=None,
                    help="default 443 for HTTPS, 80 for HTTP")
    ic.add_argument("--http", action="store_true",
                    help="use HTTP instead of HTTPS")
    ic.add_argument("--sap-client", default=None,
                    help="sap-client to append to each request")
    ic.add_argument("--user", default=None,
                    help="only used to read the Gateway OData catalogue. The ICF "
                         "probe is ALWAYS anonymous — that is what makes its "
                         "AUTH_REQUIRED column mean anything")
    ic.add_argument("--insecure", action="store_true",
                    help="do not verify the TLS certificate; recorded in the "
                         "manifest")
    ic.add_argument("--ca-file", default=None)
    ic.add_argument("--timeout", type=float, default=15.0)
    ic.add_argument("--delay", type=float, default=0.0,
                    help="seconds between requests, for an estate behind a "
                         "rate-limited dispatcher")
    ic.add_argument("--out", default="./extract")
    ic.set_defaults(fn=cmd_icf)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
