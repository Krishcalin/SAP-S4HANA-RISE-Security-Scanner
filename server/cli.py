"""
Server administration CLI.

    python -m server.cli init-db
    python -m server.cli create-user  <username> <role>
    python -m server.cli add-landscape <name> [--mode rise_pce]
    python -m server.cli add-system    <landscape> <SID> <client> [--tier prod] ...
    python -m server.cli add-tenant    <landscape> <platform> <external-key> ...
    python -m server.cli scan          <landscape> <data-dir> [--sid PRD --client 100]
    python -m server.cli mcp <username>
    python -m server.cli notify
    python -m server.cli runs
    python -m server.cli totp-status  [username]
    python -m server.cli totp-disable <username>

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
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from server import auth, db, graph, ingest, mcp, totp, webhook
from modules.deployment_modes import DEPLOYMENT_MODES, DEFAULT_DEPLOYMENT_MODE
from modules.platforms import PLATFORMS, TENANT_PLATFORMS, status_note


def cmd_rederive_paths(args: argparse.Namespace) -> int:
    """Recompute risk paths from findings already stored, with no rescan.

    WHY THIS CAN EXIST AT ALL. `graph.instantiate` reads OPEN FINDINGS, not the
    export bundle. Paths are therefore derivable from what the database already
    holds, and a ruleset change does not need the customer to still have their
    exports -- which they usually do not, because an upload is consumed and
    removed once its scan completes.

    WHY IT IS NEEDED. A path row carries the fingerprint of the ruleset that
    derived it, and the console shows a staleness banner when that no longer
    matches the current one. Before this, the only way to clear it was a full
    rescan, because paths were recomputed only as a side effect of ingest. A
    landscape whose exports were gone had no route at all and would have carried
    "these derivations predate the current rules" indefinitely.

    Path IDENTITY is (template, systems) and never the findings, so re-deriving
    keeps `first_seen` and re-opens a returning path as the same path. A path the
    new ruleset no longer supports closes with its history intact, exactly as it
    would have on a scan.
    """
    with db.pool().connection() as conn:
        land = conn.execute("SELECT id, name FROM landscape WHERE name = %s",
                            (args.landscape,)).fetchone()
        if land is None:
            print(f"no such landscape: {args.landscape}")
            return 2
        run = conn.execute(
            "SELECT id FROM scan_run WHERE landscape_id = %s AND status = 'complete' "
            "ORDER BY started_at DESC LIMIT 1", (land["id"],)).fetchone()
        if run is None:
            print(f"{land['name']}: no completed run to attribute the derivation to")
            return 2

        before = conn.execute(
            "SELECT count(*) AS n FROM attack_path WHERE landscape_id = %s "
            "AND closed_at IS NULL", (land["id"],)).fetchone()["n"]
        result = graph.store_paths(conn, land["id"], run["id"])
        after = conn.execute(
            "SELECT count(*) AS n FROM attack_path WHERE landscape_id = %s "
            "AND closed_at IS NULL", (land["id"],)).fetchone()["n"]

    print(f"{land['name']}: open paths {before} -> {after}  {result}")
    return 0


def cmd_init_db(args: argparse.Namespace) -> int:
    db.init_schema()
    print("schema applied")

    # Data migrations run in the same command, because a deployment that applied
    # the schema and skipped these would be structurally correct and holding
    # findings whose identity no longer matches what the scanner computes -- which
    # presents as every affected finding churning new+resolved on the next scan,
    # with its age and assignee gone. See server/migrations.py.
    from server import migrations
    with db.pool().connection() as conn:
        for result in migrations.run_all(conn):
            if result.get("status") == "already applied":
                continue
            print(f"migration: {result['migrated']} finding(s) re-identified, "
                  f"{result.get('stale_nodes_removed', 0)} stale graph node(s) removed")
            for c in result.get("collisions", []):
                print(f"  NOT migrated: finding {c['finding']} ({c['check_id']}) would "
                      f"merge into {c['would_merge_into']}; left alone so neither "
                      f"loses its history")
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
        # A generated password is a handover credential, not a chosen
        # one: it was printed to a terminal and lives in scrollback.
        uid = auth.create_user(args.username, pw, args.role,
                               must_change=args.generate)
    except auth.AuthError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"created user {args.username} (id={uid}, role={args.role})")
    return 0


def cmd_set_password(args: argparse.Namespace) -> int:
    """Reset a password from the host — the way back in when nobody can sign in.

    Not a backdoor: whoever can run this already has the container and the
    database, so it grants nothing they did not have. It exists so a locked-out
    deployment has a documented recovery path instead of an undocumented one.
    """
    user = db.one("SELECT id, username FROM app_user WHERE username = %s",
                  (args.username,))
    if user is None:
        print(f"no such user: {args.username}", file=sys.stderr)
        return 1
    pw = _read_password(args.generate)
    if pw is None:
        return 1
    try:
        auth.set_password(user["id"], pw, "cli")
    except auth.AuthError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.generate:
        db.execute("UPDATE app_user SET must_change_password = true WHERE id = %s",
                   (user["id"],))
        print("the user must replace it at next sign-in")
    print(f"password set for {args.username}; all their sessions were signed out")
    # A NEW PASSWORD IS NOT A NEW PHONE, and this command is the one people reach
    # for when somebody cannot sign in. Without this line it reports success and
    # the user still cannot get in, because the second factor is untouched — and
    # this is the command the account screen tells them to run.
    if auth.totp_active(user["id"]):
        print(f"NOTE: {args.username} still has a second factor enabled. If the "
              f"authenticator is what was lost, also run:\n"
              f"      python -m server.cli totp-disable {args.username}")
    return 0


def cmd_totp_disable(args: argparse.Namespace) -> int:
    """Clear somebody's second factor from the host — the lost-phone escape hatch.

    THE COUNTERPART TO HAVING NO SELF-SERVICE RESET. This product refuses an
    unauthenticated reset because it is a way in; that decision is only survivable
    because a documented path exists on the other side of it. Without this command
    a lost authenticator is a permanently dead account, and for a single-admin
    install a dead deployment recoverable only by hand-editing PostgreSQL — the
    exact undocumented path `set-password` exists to prevent.

    Not a backdoor, for the same reason as `set-password`: whoever runs this
    already holds the database. It grants nothing new, it just writes down how.

    Sessions go too. A lost phone may be holding a live one, and the person
    reaching for this command is usually saying "that device is gone".
    """
    user = db.one("SELECT id, username FROM app_user WHERE username = %s",
                  (args.username,))
    if user is None:
        print(f"no such user: {args.username}", file=sys.stderr)
        return 1
    was = auth.disable_totp(user["id"], "cli", reason="cli:lost-device")
    db.execute("DELETE FROM session WHERE user_id = %s", (user["id"],))
    if was:
        print(f"second factor cleared for {args.username}; recovery codes "
              f"invalidated and all their sessions signed out")
        print("they can enrol a new authenticator from Your account after signing in")
    else:
        print(f"{args.username} had no second factor; nothing to clear")
    return 0


def cmd_totp_status(args: argparse.Namespace) -> int:
    """Who has a second factor, and is this deployment still recoverable.

    THE QUESTION THIS ANSWERS IS "what happens if that person leaves". An estate
    where every administrator is enrolled and nobody has recovery codes left is one
    lost phone away from needing a DBA, and nothing else in the product will say so
    before it happens.

    `last_counter` is printed with its wall-clock equivalent because it is the only
    diagnostic for the confusing failure: a server or phone clock that jumped
    forward leaves the replay floor in the future, and every subsequent code is
    refused as a replay while looking, to the user, like "the app stopped working".
    """
    rows = db.query(
        "SELECT u.username, u.role, t.confirmed_at, t.pending_at, t.last_counter, "
        "  (SELECT count(*) FROM recovery_code r "
        "   WHERE r.user_id = u.id AND r.used_at IS NULL) AS codes_left "
        "FROM app_user u LEFT JOIN app_totp t ON t.user_id = u.id "
        + ("WHERE u.username = %s " if args.username else "")
        + "ORDER BY u.username",
        (args.username,) if args.username else ())
    if not rows:
        print("no matching users", file=sys.stderr)
        return 1

    print(f"{'user':22} {'role':8} {'second factor':28} {'codes':5} drift")
    exposed = 0
    for r in rows:
        if r["confirmed_at"]:
            state = f"enabled {r['confirmed_at']:%Y-%m-%d}"
            if r["codes_left"] == 0:
                exposed += 1
        elif r["pending_at"]:
            state = f"pending since {r['pending_at']:%Y-%m-%d}"
        else:
            state = "none"
        drift = ""
        if r["last_counter"] is not None and r["last_counter"] >= 0:
            seen = datetime.fromtimestamp(r["last_counter"] * totp.PERIOD,
                                          tz=timezone.utc)
            ahead = (seen - datetime.now(timezone.utc)).total_seconds()
            drift = f"{seen:%Y-%m-%d %H:%M}Z"
            if ahead > totp.PERIOD:
                drift += f"  AHEAD by {ahead / 60:.0f} min — codes will be refused"
        codes = "-" if not r["confirmed_at"] else str(r["codes_left"])
        print(f"{r['username']:22} {r['role']:8} {state:28} {codes:5} {drift}")

    if exposed:
        print(f"\nWARNING: {exposed} account(s) have a second factor and NO recovery "
              f"codes left.\n         A lost device there needs "
              f"`python -m server.cli totp-disable <user>`.")
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


def cmd_add_tenant(args: argparse.Namespace) -> int:
    """Register a SaaS tenant — a system row with no SID. Decision D8.

    SEPARATE FROM add-system RATHER THAN OPTIONAL FLAGS ON IT. `add-system PRD 100`
    takes its sid and client positionally, so making them optional to accommodate a
    tenant would make `add-system acme-sf-prod` ambiguous — is that a SID or an
    external key? — and argparse would accept it either way. Two commands cannot be
    confused with each other, and each refuses the other's arguments outright.
    """
    land = db.one("SELECT id FROM landscape WHERE name = %s", (args.landscape,))
    if land is None:
        print(f"no such landscape: {args.landscape}", file=sys.stderr)
        return 1
    # WHAT THIS PLATFORM WILL ACTUALLY GET, said before the row exists.
    #
    # `PLATFORMS` says which platforms a row may DECLARE; it never said whether
    # any check would look at one. So `add-tenant ... ariba acme-prod` created a
    # system that no module can produce a finding for, silently — and a registered
    # tenant that can never be assessed reads as coverage. Printed rather than
    # refused: the row is legitimate, it is the expectation that needed correcting.
    note = status_note(args.platform)
    if note:
        print("note: " + note)

    if not args.external_key.strip():
        # The schema refuses this too (sap_system_shape_check demands
        # external_key <> ''), but a constraint violation is a poor way to learn
        # you typed an empty argument.
        print("external key cannot be empty: it is what tells two tenants apart, "
              "and without it their findings collide", file=sys.stderr)
        return 1

    # THE `WHERE` IS NOT OPTIONAL. sap_system_tenant_key is a PARTIAL unique index,
    # and PostgreSQL will not infer a partial index as an ON CONFLICT arbiter
    # unless the statement repeats its predicate — without this, SQLSTATE 42P10.
    row = db.one(
        """
        INSERT INTO sap_system (landscape_id, platform, external_key, tier,
                                criticality, exposure_zone, owner)
        VALUES (%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (landscape_id, platform, external_key) WHERE platform <> 'abap'
        DO UPDATE SET
            tier = EXCLUDED.tier, criticality = EXCLUDED.criticality,
            exposure_zone = EXCLUDED.exposure_zone, owner = EXCLUDED.owner
        RETURNING id
        """,
        (land["id"], args.platform, args.external_key.strip(), args.tier,
         args.criticality, args.exposure, args.owner))
    print(f"tenant {args.platform}:{args.external_key} "
          f"(id={row['id']}, tier={args.tier})")
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
    edges = result.get("edges") or {}
    if edges.get("stored"):
        print(f"  graph: {edges['stored']} edge(s) — {edges.get('used', 0)} used, "
              f"{edges.get('configured', 0)} configured")
        # WHICH OF THE THREE CAUSES OF A LOW `used` COUNT THIS ONE IS. No export
        # at all; an export that covers nobody holding an edge here; or an export
        # that covers them and finds them quiet. Only the third says anything
        # about the landscape, and a bare "0 used" would be read as the third
        # every time — the strongest available claim from the weakest available
        # evidence.
        if not edges.get("provenance_evidence"):
            print("         no logon export supplied: activity was not assessed, "
                  "so every edge is configured by default rather than by finding.")
        elif edges.get("users_in_logon_export") == 0 and edges.get("users_on_edges"):
            # THE CASE THE SAMPLE CORPUS ACTUALLY HITS. Both exports were present
            # and read, and they describe different populations — so `0 used` is a
            # verdict on the evidence, not on the landscape. Printing the count
            # without this line would report a fully dormant estate.
            print(f"         the logon export names none of the "
                  f"{edges['users_on_edges']} user(s) holding edges here, so "
                  f"activity could not be settled for any of them.")
        else:
            print("         used = the holding account logged on in the exported "
                  "window; it does not mean this role or destination was invoked.")
            if edges.get("users_absent_from_logon_export"):
                print(f"         {edges['users_absent_from_logon_export']} of "
                      f"{edges['users_on_edges']} user(s) on edges are absent from "
                      f"the logon export: unassessed, not quiet.")
    if edges.get("declined_ambiguous"):
        print(f"  {edges['declined_ambiguous']} relationship(s) left out of the "
              f"graph: the finding named several objects on both sides and does "
              f"not say which relate.")
    if edges.get("missing_node"):
        print(f"  {edges['missing_node']} edge(s) skipped: an endpoint was not a "
              f"known node.")
    # WHAT THE GRAPH IS FOR, STATED BECAUSE THE COUNTS ALONE IMPLY MORE.
    #
    # Every line above describes the graph with real care — how an edge was
    # evidenced, why `used` may be low, which relationships were declined — and
    # a reader finishing them concludes the product reasons over an attack
    # graph. For a long time it did not: `graph_node` and `graph_edge` were
    # written here and selected nowhere, and the earlier version of this line
    # said so.
    #
    # `graph.path_actors` now reads it, so the line says what it feeds instead.
    # The boundary matters and is stated rather than blurred: the paths and
    # chokepoints THEMSELVES are still the shipped templates matched against
    # findings, and would be identical if the graph were empty. What the graph
    # adds is the half a template cannot express — a hop names the checks that
    # evidence it, never the accounts, so only the edges can say who holds the
    # privileges the route depends on.
    #
    # `tests/test_graph_is_not_consumed.py` keeps this sentence tied to the
    # code: it fails if the claim and the readers ever disagree, in either
    # direction.
    if result.get("nodes") or edges.get("stored"):
        print("         read by the path pages, to name the accounts whose "
              "privileges put them on a path. The paths and chokepoints "
              "themselves still come from the templates matched against "
              "findings rather than from traversing this graph.")
    print(f"  new {diff.get('new',0)} · persisting {diff.get('persisting',0)} · "
          f"resolved {diff.get('resolved',0)} · regressed {diff.get('regressed',0)}")
    # WHAT THIS RUN DECLINED TO SAY, on the same line of sight as what it said.
    # A finding left open because its module never executed is neither resolved
    # nor persisting; reporting only the four states above would present it as
    # persisting, which is a claim this run cannot make.
    if diff.get("unexamined"):
        print(f"  {diff['unexamined']} finding(s) left open: no module that "
              f"could have observed them ran in this scan.")
    if diff.get("resolution_skipped"):
        print(f"  {diff['resolution_skipped']}")
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


def cmd_notify(args: argparse.Namespace) -> int:
    """Drain the notification queue to the configured ITSM endpoint.

    A COMMAND RATHER THAN A BACKGROUND WORKER, because this product has one
    process and adding a scheduler to it would be a new failure mode for a job
    that a cron line already runs. `queue_notifications` fills the queue during
    ingest; this empties it, and how often is the operator's decision.
    """
    with db.connection() as conn:
        result = webhook.deliver(conn, limit=args.limit)
        conn.commit()
    print(result["note"])
    if not result["configured"]:
        # Not an error. A deployment without an ITSM keeps queueing, and the rows
        # are readable in the console either way.
        return 0
    return 1 if result["failed"] else 0


def cmd_mcp(args: argparse.Namespace) -> int:
    """Serve the read-only MCP surface on stdio, as a named console account.

    RUNS AS SOMEBODY, DELIBERATELY. There is no ambient MCP identity and no
    default of "everything": the surface sees exactly what that account's
    `auth.scope_for` allows, which is the same function the console uses. An
    assistant reading a landscape it should not see is the same breach as a user
    doing it.
    """
    return mcp.serve(args.username)


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

    sub.add_parser("init-db", help="Create or migrate the database schema.").set_defaults(fn=cmd_init_db)

    rp = sub.add_parser(
        "rederive-paths",
        help="Recompute risk paths from stored findings, without a rescan.")
    rp.add_argument("landscape")
    rp.set_defaults(fn=cmd_rederive_paths)

    cu = sub.add_parser("create-user", help="Create a console account with a role.")
    cu.add_argument("username")
    cu.add_argument("role", choices=sorted(auth.ROLE_RANK), nargs="?", default="viewer")
    cu.add_argument("--generate", action="store_true",
                    help="mint a strong password and print it to stderr, instead of "
                         "prompting. Use this for the first admin in a container, "
                         "where there is no TTY.")
    cu.set_defaults(fn=cmd_create_user)

    sp = sub.add_parser("set-password", help="Set an account's password, signing out its other sessions.")
    sp.add_argument("username")
    sp.add_argument("--generate", action="store_true",
                    help="mint one and print it; the user must then replace it")
    sp.set_defaults(fn=cmd_set_password)

    al = sub.add_parser("add-landscape", help="Register a customer estate.")
    al.add_argument("name")
    al.add_argument("--mode", default=DEFAULT_DEPLOYMENT_MODE,
                    choices=list(DEPLOYMENT_MODES))
    al.add_argument("--rr-version", default=None,
                    help="SAP Roles & Responsibilities version this mapping is read against")
    al.set_defaults(fn=cmd_add_landscape)

    asys = sub.add_parser("add-system", help="Register an ABAP system (SID and client) in a landscape.")
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

    aten = sub.add_parser(
        "add-tenant",
        help="register a SaaS tenant (SuccessFactors, Concur, IAS, a BTP "
             "subaccount) — a system with an external key instead of a SID")
    aten.add_argument("landscape")
    # PLATFORMS come from the schema's own CHECK list rather than being repeated
    # here. A choices= list that drifts from the constraint rejects a platform the
    # database would accept, while naming every other one as valid — which reads
    # as the feature not existing rather than as a stale list.
    aten.add_argument("platform", choices=list(TENANT_PLATFORMS))
    aten.add_argument("external_key",
                      help="the tenant's own identifier: a SuccessFactors company "
                           "id, a Concur entity id, a BTP subaccount id")
    aten.add_argument("--tier", default="unknown",
                      choices=["prod", "qa", "dev", "sandbox", "unknown"])
    aten.add_argument("--criticality", default="medium",
                      choices=["critical", "high", "medium", "low"])
    aten.add_argument("--exposure", default="unknown",
                      choices=["internet", "dmz", "internal", "isolated", "unknown"])
    aten.add_argument("--owner", default=None)
    aten.set_defaults(fn=cmd_add_tenant)

    sc = sub.add_parser("scan", help="Scan an export directory and store the run.")
    sc.add_argument("landscape")
    sc.add_argument("data_dir")
    sc.add_argument("--sid", default=None)
    sc.add_argument("--client", default=None)
    sc.set_defaults(fn=cmd_scan)

    rb = sub.add_parser("rebuild-sap-catalogue", help="Rebuild the SAP security-note catalogue from its source data.")
    rb.add_argument("repo_dir", help="checkout of SAP-samples/frun-csa-policies-best-practices")
    rb.add_argument("--version", default="v2.4", help="baseline policy version folder")
    rb.set_defaults(fn=cmd_rebuild_sap_catalogue)

    nt = sub.add_parser(
        "notify",
        help="Send queued notifications to the ITSM endpoint and mark them "
             "delivered. Configure with ITSM_WEBHOOK_URL and "
             "ITSM_WEBHOOK_TOKEN in the environment — never on the command "
             "line, where an argument is visible in ps and shell history.")
    nt.add_argument("--limit", type=int, default=webhook.DEFAULT_LIMIT,
                    help="How many to attempt in one drain (default %(default)s). "
                         "The rest stay queued for the next run.")
    nt.set_defaults(fn=cmd_notify)

    mc = sub.add_parser(
        "mcp",
        help="Serve a READ-ONLY MCP surface on stdio, scoped to one console "
             "account. Nothing it exposes changes anything: transitions and "
             "assignment record an actor and a tool call carries none.")
    mc.add_argument("username",
                    help="The console account to run as. Its scope is the "
                         "surface's scope — there is no unscoped mode.")
    mc.set_defaults(fn=cmd_mcp)

    sub.add_parser("runs", help="List stored scan runs, newest first.").set_defaults(fn=cmd_runs)

    td = sub.add_parser("totp-disable", help="Turn off two-factor authentication for an account.")
    td.add_argument("username")
    td.set_defaults(fn=cmd_totp_disable)

    ts = sub.add_parser("totp-status", help="Show which accounts have two-factor authentication enabled.")
    ts.add_argument("username", nargs="?", default=None)
    ts.set_defaults(fn=cmd_totp_status)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
