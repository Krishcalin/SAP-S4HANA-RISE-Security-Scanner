"""
Server administration CLI.

    python -m server.cli init-db
    python -m server.cli create-user  <username> <role>
    python -m server.cli add-landscape <name> [--mode rise_pce]
    python -m server.cli add-system    <landscape> <SID> <client> [--tier prod] ...
    python -m server.cli scan          <landscape> <data-dir> [--sid PRD --client 100]
    python -m server.cli runs

Passwords are never taken from argv — an argument is visible in `ps` output and
in shell history. They come from a TTY prompt, from stdin when piped, or from
`--generate`. The container has no TTY, so `--generate` is the documented way to
bootstrap the first admin.
"""
from __future__ import annotations

import argparse
import getpass
import secrets
import sys
from pathlib import Path
from typing import Optional

from server import auth, db, ingest


def cmd_init_db(args: argparse.Namespace) -> int:
    db.init_schema()
    print("schema applied")
    return 0


def _read_password(generate: bool) -> Optional[str]:
    """Obtain a password without ever putting it on the command line.

    THREE WAYS IN, AND WHY THERE ARE THREE
    A password passed as an argument is visible in `ps` output and in shell
    history, so `--password` does not exist and must not be added.

    But interactive-only was wrong in a different way: the documented Docker setup
    step — `docker compose exec app python -m server.cli create-user admin admin` —
    has no TTY in most contexts and died with an EOFError out of getpass. It is the
    first command a new user runs, and it could not work.

    So a TTY gets a prompt, a pipe gets read, and `--generate` mints a strong one
    and prints it to stderr — which is the right default for bootstrapping a first
    admin, and keeps the secret out of stdout if the caller is capturing it.
    """
    if generate:
        pw = secrets.token_urlsafe(18)
        print(f"generated password: {pw}", file=sys.stderr)
        print("store it now — it is not recoverable.", file=sys.stderr)
        return pw

    if sys.stdin.isatty():
        pw = getpass.getpass("password: ")
        if pw != getpass.getpass("confirm: "):
            print("passwords do not match", file=sys.stderr)
            return None
        return pw

    # Piped: echo 'secret' | docker compose exec -T app ... create-user admin admin
    pw = sys.stdin.readline().rstrip("\n")
    if not pw:
        print("no password supplied. Run interactively, pipe one in, or pass "
              "--generate.", file=sys.stderr)
        return None
    return pw


def cmd_create_user(args: argparse.Namespace) -> int:
    pw = _read_password(args.generate)
    if pw is None:
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


def cmd_rebuild_sap_catalogue(args: argparse.Namespace) -> int:
    """Re-derive data/sap_baseline_requirements.json from a checkout of SAP's
    Apache-2.0 policy repository.

    Vendored so the tool works offline and air-gapped — the product premise — but a
    vendored copy of someone else's content goes stale silently, so CI re-derives it
    and fails on drift. This is the command CI tells you to run.

        git clone --depth 1 https://github.com/SAP-samples/frun-csa-policies-best-practices.git
        python -m server.cli rebuild-sap-catalogue ./frun-csa-policies-best-practices
    """
    from server.sapcontent import build_catalogue, write_catalogue
    try:
        cat = build_catalogue(Path(args.repo_dir), args.version)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    write_catalogue(cat)
    counts = cat["_meta"]["counts"]
    print(f"catalogue written: {counts['requirements']} requirements from "
          f"{counts['policies']} policies ({counts['check_items']} check items, "
          f"{counts['by_tier']})")
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
    cu.add_argument("--generate", action="store_true",
                    help="mint a strong password and print it to stderr, instead of "
                         "prompting. Use this for the first admin in a container, "
                         "where there is no TTY.")
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

    rb = sub.add_parser("rebuild-sap-catalogue")
    rb.add_argument("repo_dir", help="checkout of SAP-samples/frun-csa-policies-best-practices")
    rb.add_argument("--version", default="v2.4", help="baseline policy version folder")
    rb.set_defaults(fn=cmd_rebuild_sap_catalogue)

    sub.add_parser("runs").set_defaults(fn=cmd_runs)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
