"""
Server administration CLI.

    python -m server.cli init-db
    python -m server.cli create-user  <username> <role>
    python -m server.cli add-landscape <name> [--mode rise_pce]
    python -m server.cli add-system    <landscape> <SID> <client> [--tier prod] ...
    python -m server.cli scan          <landscape> <data-dir> [--sid PRD --client 100]
    python -m server.cli runs

Passwords are read interactively and never taken from argv — an argument is
visible in `ps` output and in shell history.
"""
from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from server import auth, db, ingest


def cmd_init_db(args: argparse.Namespace) -> int:
    db.init_schema()
    print("schema applied")
    return 0


def cmd_create_user(args: argparse.Namespace) -> int:
    pw = getpass.getpass("password: ")
    if pw != getpass.getpass("confirm: "):
        print("passwords do not match", file=sys.stderr)
        return 1
    try:
        uid = auth.create_user(args.username, pw, args.role)
    except auth.AuthError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"created user {args.username} (id={uid}, role={args.role})")
    return 0


def cmd_add_landscape(args: argparse.Namespace) -> int:
    row = db.one(
        "INSERT INTO landscape (name, deployment_mode, rr_version) VALUES (%s,%s,%s) "
        "ON CONFLICT (name) DO UPDATE SET deployment_mode = EXCLUDED.deployment_mode "
        "RETURNING id", (args.name, args.mode, args.rr_version))
    print(f"landscape {args.name} (id={row['id']}, mode={args.mode})")
    return 0


def cmd_add_system(args: argparse.Namespace) -> int:
    land = db.one("SELECT id FROM landscape WHERE name = %s", (args.landscape,))
    if land is None:
        print(f"no such landscape: {args.landscape}", file=sys.stderr)
        return 1
    row = db.one(
        """
        INSERT INTO sap_system (landscape_id, sid, client, tier, criticality,
                                exposure_zone, owner)
        VALUES (%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (landscape_id, sid, client) DO UPDATE SET
            tier = EXCLUDED.tier, criticality = EXCLUDED.criticality,
            exposure_zone = EXCLUDED.exposure_zone, owner = EXCLUDED.owner
        RETURNING id
        """,
        (land["id"], args.sid.upper(), args.client, args.tier, args.criticality,
         args.exposure, args.owner))
    print(f"system {args.sid}/{args.client} (id={row['id']}, tier={args.tier})")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Scan a directory directly — the air-gapped path, no upload, no browser."""
    land = db.one("SELECT * FROM landscape WHERE name = %s", (args.landscape,))
    if land is None:
        print(f"no such landscape: {args.landscape}", file=sys.stderr)
        return 1

    system_id = None
    if args.sid and args.client:
        sysrow = db.one(
            "SELECT id FROM sap_system WHERE landscape_id = %s AND sid = %s AND client = %s",
            (land["id"], args.sid.upper(), args.client))
        if sysrow is None:
            sysrow = db.one(
                "INSERT INTO sap_system (landscape_id, sid, client) VALUES (%s,%s,%s) "
                "RETURNING id", (land["id"], args.sid.upper(), args.client))
            print(f"registered system {args.sid}/{args.client}")
        system_id = sysrow["id"]

    data_dir = Path(args.data_dir)
    if not data_dir.is_dir():
        print(f"not a directory: {data_dir}", file=sys.stderr)
        return 1

    sha = ingest.bundle_sha(data_dir)
    prior = db.one("SELECT id FROM scan_run WHERE landscape_id = %s AND content_sha = %s "
                   "ORDER BY started_at DESC LIMIT 1", (land["id"], sha))
    if prior:
        print(f"note: byte-identical to run #{prior['id']}; scanning anyway")

    run = db.one(
        "INSERT INTO scan_run (landscape_id, system_id, content_sha, uploaded_by, "
        "upload_name, status) VALUES (%s,%s,%s,%s,%s,'pending') RETURNING id",
        (land["id"], system_id, sha, "cli", str(data_dir)))

    result = ingest.scan_directory(data_dir, land["id"], system_id, run["id"],
                                   deployment_mode=land["deployment_mode"],
                                   default_sid=args.sid, default_client=args.client)

    cov = result.get("coverage", {})
    diff = result.get("diff", {})
    print(f"\nrun #{result['run_id']}: {result['findings']} findings, "
          f"{result['nodes']} graph nodes")
    print(f"  new {diff.get('new',0)} · persisting {diff.get('persisting',0)} · "
          f"resolved {diff.get('resolved',0)} · regressed {diff.get('regressed',0)}")
    if cov.get("summary"):
        print(f"  coverage: {cov['summary']}")
    failed = [n for n, m in result.get("module_status", {}).items()
              if m.get("status") == "failed"]
    if failed:
        print(f"  MODULES FAILED: {', '.join(failed)}")
    return 0


def cmd_runs(args: argparse.Namespace) -> int:
    rows = db.query(
        "SELECT r.id, r.status, r.started_at, r.content_sha, s.sid, s.client "
        "FROM scan_run r LEFT JOIN sap_system s ON s.id = r.system_id "
        "ORDER BY r.started_at DESC LIMIT 25")
    for r in rows:
        sysname = f"{r['sid']}/{r['client']}" if r["sid"] else "-"
        print(f"#{r['id']:<5} {r['status']:<10} {sysname:<12} "
              f"{r['started_at']:%Y-%m-%d %H:%M}  {(r['content_sha'] or '')[:12]}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="server.cli")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init-db").set_defaults(fn=cmd_init_db)

    cu = sub.add_parser("create-user")
    cu.add_argument("username")
    cu.add_argument("role", choices=sorted(auth.ROLE_RANK), nargs="?", default="viewer")
    cu.set_defaults(fn=cmd_create_user)

    al = sub.add_parser("add-landscape")
    al.add_argument("name")
    al.add_argument("--mode", default="on_prem",
                    choices=["on_prem", "rise_pce", "rise_tailored"])
    al.add_argument("--rr-version", default=None,
                    help="SAP Roles & Responsibilities version this mapping is read against")
    al.set_defaults(fn=cmd_add_landscape)

    asys = sub.add_parser("add-system")
    asys.add_argument("landscape")
    asys.add_argument("sid")
    asys.add_argument("client")
    asys.add_argument("--tier", default="unknown",
                      choices=["prod", "qa", "dev", "sandbox", "unknown"])
    asys.add_argument("--criticality", default="medium",
                      choices=["critical", "high", "medium", "low"])
    asys.add_argument("--exposure", default="unknown",
                      choices=["internet", "dmz", "internal", "isolated", "unknown"])
    asys.add_argument("--owner", default=None)
    asys.set_defaults(fn=cmd_add_system)

    sc = sub.add_parser("scan")
    sc.add_argument("landscape")
    sc.add_argument("data_dir")
    sc.add_argument("--sid", default=None)
    sc.add_argument("--client", default=None)
    sc.set_defaults(fn=cmd_scan)

    sub.add_parser("runs").set_defaults(fn=cmd_runs)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
