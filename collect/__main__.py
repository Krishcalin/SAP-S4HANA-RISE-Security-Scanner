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


def cmd_btp(args: argparse.Namespace) -> int:
    # Imported here rather than at module scope for the reason `cmd_rfc` is:
    # a subcommand nobody ran should cost nothing.
    from collect import btp

    if args.list_sources:
        for line in btp.describe_sources():
            print(line)
        return 0

    if not args.service_key and not args.cloud_connector:
        print("nothing to collect: pass --service-key, --cloud-connector, or "
              "both. --list-sources shows what each reaches.", file=sys.stderr)
        return 2

    out = Path(args.out)
    wrote: dict = {}
    attempts: list = []
    endpoints: list = []
    verify = not args.insecure
    if not verify:
        print("[!] TLS certificate verification is DISABLED for this collection.")

    if args.service_key:
        try:
            key = btp.ServiceKey.from_file(args.service_key)
        except (OSError, ValueError) as exc:
            print("[!] %s" % exc, file=sys.stderr)
            return 2
        endpoints.append(key.service_url)
        collector = btp.BtpCollector(key, verify_tls=verify,
                                     ca_file=args.ca_file, timeout=args.timeout)
        try:
            payloads = collector.collect()
        except Exception as exc:                             # noqa: BLE001
            # A token that cannot be obtained is a connection/credential
            # failure, not an estate with no configuration.
            print("[!] could not authenticate to %s: %s"
                  % (key.token_url, exc), file=sys.stderr)
            return 1
        attempts += collector.attempts
        by_source = {e["source"]: e for e in btp.ENDPOINTS}
        for source, payload in payloads.items():
            fname = by_source[source]["file"]
            wrote[fname] = extract.write_btp_payload(out, fname, payload)
        for a in collector.attempts:
            if not a["ok"]:
                print("    %-52s FAILED: %s" % (a["operation"], a["error"]))

    if args.cloud_connector:
        if args.user is None:
            print("--cloud-connector needs --user (its administration API uses "
                  "Basic authentication).", file=sys.stderr)
            return 2
        password = _read_password(args.user)
        if password is None:
            return 2
        endpoints.append(args.cloud_connector)
        payload, attempt = btp.fetch_cloud_connector(
            args.cloud_connector, username=args.user, password=password,
            verify_tls=verify, ca_file=args.ca_file, timeout=args.timeout)
        attempts.append(attempt)
        if payload is None:
            print("    %-52s FAILED: %s" % (attempt["operation"], attempt["error"]))
        else:
            wrote["cloud_connector.json"] = extract.write_btp_payload(
                out, "cloud_connector.json", payload)

    for name, n in sorted(wrote.items()):
        if n:
            print("    %-32s %d record(s)" % (name, n))

    if not any(wrote.values()):
        print("[!] nothing was collected. Every request failed or returned "
              "nothing — that is a connection or authorisation problem, not a "
              "landscape with no configuration.", file=sys.stderr)
        return 1

    manifest = extract.write_manifest(
        out, source="btp", endpoint=", ".join(endpoints),
        collected_at=btp.now_utc(), wrote=wrote, attempts=attempts,
        cannot_reach=sorted(btp.BTP_CANNOT_REACH),
        tls_verified=verify,
        caveats=["Payloads are written through unchanged; modules/btp_import.py "
                 "normalises them at scan time."])
    print(extract.summarise(manifest))
    print("[*] now scan it:  python sap_scanner.py --data-dir %s" % out)
    return 0


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


def cmd_rfc(args) -> int:
    """Collect the RFC-only sources, if the customer has installed the SDK.

    THIS IS THE ONLY COLLECTOR THAT CAN FAIL BEFORE IT STARTS, and it says so in
    one line. The SAP NetWeaver RFC SDK is S-user gated and cannot be shipped, so
    the first thing reported is whether one is present and where it was looked
    for — a customer who has not installed it should learn that from a sentence,
    not from a stack trace inside ctypes.
    """
    from collect import rfc, rfc_tables

    ok, detail = rfc.available(args.sdk_home)
    if not ok:
        print("[!] RFC SDK unavailable: %s" % detail, file=sys.stderr)
        print("    This collector is optional. sapcontrol and icf need no SDK "
              "and reach everything else.", file=sys.stderr)
        return 2
    print("[*] RFC SDK: %s" % detail)

    if args.check_sdk:
        try:
            report = rfc.check_sdk(args.sdk_home)
        except rfc.RfcUnavailable as exc:
            print("[!] %s" % exc, file=sys.stderr)
            return 2
        print("    loaded            %s" % report["path"])
        print("    symbols declared  %d" % len(rfc.REQUIRED_SYMBOLS))
        if report["missing"]:
            print("    MISSING           %s" % ", ".join(report["missing"]),
                  file=sys.stderr)
            print("    This SDK version does not export everything this binding "
                  "declares. Report the list above.", file=sys.stderr)
            return 1
        print("    all symbols bound ok")
        print("    strings encoded as SAP_UC (%d bytes/char), explicitly, on "
              "every platform" % report["sap_uc_bytes"])
        print("    NOTE: this proves the library loads and the entry points "
              "exist. It does NOT prove a call's argument order or struct "
              "layout — only a live system does that.")
        return 0

    if args.list_sources:
        print("    produces:")
        for e in rfc_tables.EXTRACTS:
            print("      %-18s <- %-10s -> %s" % (e["source"], e["table"], e["file"]))
        print("    still cannot reach:")
        for name, why in sorted(rfc_tables.RFC_CANNOT_REACH.items()):
            print("      %-18s %s" % (name, why))
        return 0

    password = _read_password(args.user)
    if password is None:
        return 2

    params = {"ashost": args.host, "sysnr": "%02d" % args.instance,
              "client": args.client, "user": args.user, "passwd": password,
              "lang": args.lang}
    if args.saprouter:
        params["saprouter"] = args.saprouter

    out = Path(args.out)
    endpoint = "%s/%02d client %s" % (args.host, args.instance, args.client)

    try:
        conn = rfc.Connection(params, home=args.sdk_home).open()
    except (rfc.RfcUnavailable, rfc.RfcCallFailed) as exc:
        print("[!] %s" % exc, file=sys.stderr)
        return 1

    wrote = {}
    attempts = []
    try:
        if args.probe_only:
            print("[*] RFCPING ...", end=" ")
            print("ok" if conn.ping() else "no response")
            print("    --probe-only: nothing collected, nothing written.")
            return 0

        wanted = set(args.only.split(",")) if args.only else None
        for e in rfc_tables.EXTRACTS:
            if wanted and e["source"] not in wanted:
                continue
            fields = rfc_tables.fields_for(e)
            try:
                rows = conn.read_table(e["table"], fields,
                                       where=args.where or "",
                                       row_limit=args.row_limit)
            except rfc.RfcCallFailed as exc:
                # ONE TABLE FAILING MUST NOT LOSE THE OTHERS. A field absent on an
                # older release, or an authorisation this RFC user lacks, is a
                # per-source outcome and is recorded as one rather than aborting
                # a collection that has already succeeded elsewhere.
                print("    %-18s FAILED: %s" % (e["source"], exc))
                attempts.append({"source": e["source"], "table": e["table"],
                                 "ok": False, "error": str(exc)})
                continue
            records = rfc_tables.rows_to_csv(e, rows)
            header = list(e["columns"])
            n = extract._write_csv(out / e["file"], header,
                                   [[r.get(h, "") for h in header] for r in records])
            print("    %-18s %7d row(s) -> %s" % (e["source"], n, e["file"]))
            wrote[e["file"]] = n
            attempts.append({"source": e["source"], "table": e["table"],
                             "ok": True, "rows": n,
                             "derived": bool(e.get("derive"))})
    finally:
        conn.close()

    extract.write_manifest(
        out, source="rfc", endpoint=endpoint,
        collected_at=datetime.now(timezone.utc).isoformat(timespec="seconds"), wrote=wrote, attempts=attempts,
        cannot_reach=tuple(sorted(rfc_tables.RFC_CANNOT_REACH)),
        # WHAT THIS CONNECTION ACTUALLY WAS, stated rather than defaulted.
        #
        # `tls_verified` defaults to True and this collector never passed it, so
        # the manifest asserted a verified TLS connection for a protocol that is
        # not TLS. None is the honest third answer.
        #
        # SNC is SAP's transport encryption for RFC and this binding does not
        # request it — no snc_mode, snc_partnername, snc_qop or snc_lib is set on
        # the connection. Whether the conversation was encrypted therefore
        # depends entirely on what the server enforces, which the collector
        # cannot observe from its side. Recording "not requested" is a fact about
        # us; claiming it was unencrypted would be a claim about them.
        #
        # This product audits exactly this question on a CUSTOMER's connections
        # in modules/snc_posture.py. Asking it of every estate we scan and not of
        # ourselves is the asymmetry this record removes.
        tls_verified=None,
        transport={
            "protocol": "SAP RFC",
            "encryption_requested": False,
            "mechanism": "SNC (Secure Network Communications)",
            "note": "This collector does not set snc_mode/snc_partnername/"
                    "snc_qop/snc_lib, so it neither requests nor negotiates SNC. "
                    "If the target enforces SNC the conversation is protected by "
                    "the server's policy rather than by anything asked for here; "
                    "if it does not, the credentials and the authorisation model "
                    "below crossed the network unprotected. Prefer a host where "
                    "SAP enforces SNC, or treat the extract as sensitive in "
                    "transit.",
            "sources_affected": "every file this collection wrote",
        },
        caveats=("RFC_READ_TABLE returns a 512-byte row, so every extract names "
                 "its columns rather than taking the table.",
                 "rfc_destinations host and user are PARSED out of the RFCOPTIONS "
                 "blob rather than read as columns; SNC and auth type are left "
                 "blank because their encoding varies by release and a wrong "
                 "value would mislabel a destination as secured."))
    print("[*] wrote %s" % out)
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

    bt = sub.add_parser(
        "btp",
        help="collect SAP BTP configuration over the platform's own REST APIs, "
             "using a service key you download from the cockpit")
    bt.add_argument("--service-key", default=None, metavar="FILE",
                    help="path to a downloaded BTP service key (JSON). The "
                         "endpoint and the credential both come from this file, "
                         "so neither is ever on the command line")
    bt.add_argument("--cloud-connector", default=None, metavar="HOST[:PORT]",
                    help="Cloud Connector administration host. Uses Basic "
                         "authentication with --user, not the service key")
    bt.add_argument("--user", default=None,
                    help="Cloud Connector administrator, for --cloud-connector")
    bt.add_argument("--insecure", action="store_true",
                    help="do not verify the TLS certificate; recorded in the "
                         "manifest")
    bt.add_argument("--ca-file", default=None)
    bt.add_argument("--timeout", type=float, default=30.0)
    bt.add_argument("--out", default="./extract")
    bt.add_argument("--list-sources", action="store_true",
                    help="print what this collector can and cannot produce, "
                         "with the path used for each. Makes no connection")
    bt.set_defaults(fn=cmd_btp)

    rf = sub.add_parser(
        "rfc",
        help="collect the users, roles, authorisations and RFC destinations that "
             "HTTPS cannot reach. Needs the SAP NetWeaver RFC SDK, which you "
             "supply under your own licence")
    rf.add_argument("--host", required=True, help="application server host")
    rf.add_argument("--instance", type=int, default=0,
                    help="instance number 00-99 (default 00)")
    rf.add_argument("--client", required=True, help="SAP client, e.g. 100")
    rf.add_argument("--user", required=True,
                    help="RFC user. The password is NEVER an argument: it is "
                         "prompted, piped, or taken from SAPCONTROL_PASSWORD")
    rf.add_argument("--lang", default="EN")
    rf.add_argument("--saprouter", default=None,
                    help="SAProuter string, if the system is behind one")
    rf.add_argument("--sdk-home", default=None,
                    help="the unpacked nwrfcsdk directory. Defaults to the "
                         "SAPNWRFC_HOME environment variable")
    rf.add_argument("--only", default=None,
                    help="comma-separated source names to collect (see "
                         "--list-sources)")
    rf.add_argument("--where", default=None,
                    help="a WHERE clause applied to every table read. AGR_1251 "
                         "and CDHDR are unbounded on a production system and "
                         "should always have one")
    rf.add_argument("--row-limit", type=int, default=0,
                    help="maximum rows per table (0 = no limit)")
    rf.add_argument("--check-sdk", action="store_true",
                    help="load the SDK and bind every symbol this collector "
                         "declares, then exit. No host, no credential, no "
                         "network — run this first")
    rf.add_argument("--list-sources", action="store_true",
                    help="print what this collector produces and what it still "
                         "cannot reach, then exit. Needs the SDK present but no "
                         "connection and no password")
    rf.add_argument("--probe-only", action="store_true",
                    help="RFCPING only: prove the credential works, collect "
                         "nothing, write nothing")
    rf.add_argument("--out", default="./extract")
    rf.set_defaults(fn=cmd_rfc)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
