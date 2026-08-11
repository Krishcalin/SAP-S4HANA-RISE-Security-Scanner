# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""Write what a collector obtained, in the shape the offline loader already reads.

THE ONE RULE OF THIS MODULE. Everything written here must be a file
`modules/data_loader.py` would have accepted from a customer's own export. No new
format, no marker that says "this came from a connector", nothing the scanner has
to know about. `security_params.csv` from this module and `security_params.csv`
exported by hand from RSPARAM are the same artefact, and the scanner cannot tell
them apart — which is what keeps connected mode from becoming a second ingestion
path with its own bugs.

THE MANIFEST IS THE EXCEPTION, AND IT IS NOT AN INPUT
`collection_manifest.json` is not read by any check. It records what a connected
run obtained, what it could not, and under what conditions — and it exists
because a connected collection is PARTIAL by construction (decision D3: some
surfaces are RFC-only, and RFC is declined). A directory holding four files and
no statement about the fortieth is indistinguishable from a complete export, and
that ambiguity is exactly the failure the release gate refuses.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

#: What a connected collection over sapstartsrv CANNOT obtain, stated so that no
#: reader has to infer it from silence.
#:
#: Each entry is a logical source `modules/data_loader.py` knows by name. They are
#: not missing because the collector is unfinished; they are not reachable over
#: this interface at all — they live inside the ABAP stack, behind RFC or an
#: interactive export. Decision D3 declines RFC, so on ECC these stay export-only.
SAPCONTROL_CANNOT_REACH: Sequence[str] = (
    "users", "profiles", "roles", "role_profiles", "auth_objects",
    "change_documents", "table_auth_groups", "rfc_destinations",
    "audit_log_config", "standard_users", "gateway_acl", "icf_services",
    "transport_routes", "background_jobs",
)


def _write_csv(path: Path, header: Sequence[str],
               rows: Iterable[Sequence[Any]]) -> int:
    """Write a CSV the loader reads, and report how many rows it holds.

    `newline=""` is not cosmetic: without it csv writes \\r\\r\\n on Windows and
    the file gains a blank line between every record. The loader tolerates that,
    a customer opening the file in Excel does not, and "the export looks corrupt"
    is a support conversation nobody needs.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        for row in rows:
            writer.writerow(row)
            count += 1
    return count


def write_profile_parameters(out_dir: Path, params: Mapping[str, str]) -> int:
    """`security_params.csv`, in the NAME,VALUE shape the loader expects.

    THE FILE IS NOT WRITTEN WHEN THERE ARE NO PARAMETERS. An empty
    security_params.csv would be read as "this system reports no parameters",
    which is never true — every ABAP instance has hundreds — so it would present a
    collection failure as a clean result. Absent, the loader reports the source as
    missing and `modules/security_params.py` raises PARAM-000 instead, which is
    the honest outcome.
    """
    if not params:
        return 0
    return _write_csv(out_dir / "security_params.csv", ("NAME", "VALUE"),
                      sorted(params.items()))


def write_instances(out_dir: Path, instances: Sequence[Mapping[str, Any]]) -> int:
    """Instance topology, as reference data rather than as a check input.

    Deliberately NOT named after a logical source the loader knows: nothing in
    `modules/` consumes it today, and inventing a source name the loader would
    then half-read is worse than writing a plainly-named side file a human can
    open.
    """
    if not instances:
        return 0
    keys = sorted({k for row in instances for k in row})
    return _write_csv(out_dir / "sapcontrol_instances.csv", keys,
                      [[row.get(k, "") for k in keys] for row in instances])


def write_processes(out_dir: Path, processes: Sequence[Mapping[str, Any]]) -> int:
    if not processes:
        return 0
    keys = sorted({k for row in processes for k in row})
    return _write_csv(out_dir / "sapcontrol_processes.csv", keys,
                      [[row.get(k, "") for k in keys] for row in processes])


READ_THIS = (
    "This directory was produced by connected collection and is NOT a complete "
    "export. The sources listed under 'not_reachable' live inside the ABAP stack "
    "and are reachable over RFC or by an interactive export only; this product "
    "declines RFC (decision D3), so on this estate they remain export-only. "
    "Treat every check that depends on an uncollected source as UNKNOWN, never "
    "as clean.")


#: What an ICF probe CANNOT obtain. Longer than the sapcontrol list because this
#: interface reaches a narrower thing: it observes which endpoints answer, and
#: nothing about what lives behind them.
#:
#: `users`, `roles`, `profiles` and `auth_objects` are first in the list on
#: purpose. This connector was scoped as "the one that gets users and roles" and
#: it does not — there is no standard pre-built OData service on ECC exposing
#: USR02 or AGR_USERS, and Gateway exposes only what an administrator activated.
#: Recording that where a reader will actually meet it is worth more than a note
#: in a design document.
ICF_CANNOT_REACH: Sequence[str] = (
    "users", "profiles", "roles", "role_profiles", "auth_objects",
    "role_auth_values", "change_documents", "table_auth_groups",
    "rfc_destinations", "audit_log_config", "standard_users", "gateway_acl",
    "security_params", "background_jobs", "transport_routes", "client_settings",
)


def write_icf_services(out_dir: Path, rows: Sequence[Mapping[str, Any]]) -> int:
    """`icf_services.csv` — ICF_NAME, ICF_ACTIVE, AUTH_REQUIRED.

    The loader's own column names, so the file is indistinguishable from an SICF
    export. The two extra columns this connector can supply — the HTTP status it
    actually observed, and why the path is on the list — are written AFTER them:
    csv.DictReader ignores columns it was not asked for, so they cost the loader
    nothing and give a human opening the file the evidence behind each row.
    """
    if not rows:
        return 0
    header = ("ICF_NAME", "ICF_ACTIVE", "AUTH_REQUIRED", "OBSERVED_STATUS",
              "WHY_IT_MATTERS")
    return _write_csv(out_dir / "icf_services.csv", header,
                      [[r.get(k, "") for k in header] for r in rows])


def write_api_endpoints(out_dir: Path,
                        endpoints: Sequence[Mapping[str, Any]]) -> int:
    """`api_endpoints.json`, in the shape the loader reads.

    Not written when the catalogue could not be read. An empty endpoint list
    would be read as "this system exposes no APIs", which is a far stronger claim
    than "we could not reach the catalogue" — and the wrong one to make about a
    system that may simply have no Gateway.
    """
    if not endpoints:
        return 0
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "api_endpoints.json").write_text(
        json.dumps({"endpoints": list(endpoints)}, indent=2) + "\n",
        encoding="utf-8")
    return len(endpoints)


def write_manifest(out_dir: Path, *, source: str, endpoint: str,
                   collected_at: str, wrote: Mapping[str, int],
                   attempts: Sequence[Mapping[str, Any]],
                   unavailable: Sequence[str] = (),
                   cannot_reach: Sequence[str] = SAPCONTROL_CANNOT_REACH,
                   tls_verified: bool = True,
                   caveats: Sequence[str] = (),
                   posture: Optional[Mapping[str, Any]] = None) -> Path:
    """Record what one collector got, what it did not, and under what conditions.

    IT ACCUMULATES RATHER THAN OVERWRITES. Two collectors run into one directory —
    that is the intended workflow, since `sapcontrol` and `icf` reach different
    things — and a manifest that replaced its predecessor would leave a directory
    whose data came from two collections and whose record described one. The
    reader would have no way to know that, which is precisely the ambiguity this
    file exists to remove.

    WHY `cannot_reach` IS PASSED IN AND NOT COMPUTED. Deriving it as "everything
    the loader knows, minus what we wrote" would silently absorb a future logical
    source into the not-reachable list the moment somebody added one — turning a
    new coverage gap into a documented limitation without anyone deciding that.
    Each collector states its own, so widening it is a choice.

    `partial` is always true and is not a field a caller can set. A connected
    collection is partial by construction, not by circumstance.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "collection_manifest.json"

    existing: Dict[str, Any] = {}
    if path.is_file():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            # A corrupt manifest must not take the collection down, but it must
            # not be silently discarded either.
            existing = {"unreadable_previous_manifest": True}
    collections: List[Dict[str, Any]] = list(existing.get("collections") or [])

    collections.append({
        "source": source,
        "endpoint": endpoint,
        "collected_at": collected_at,
        "tls_verified": tls_verified,
        "files_written": {name: n for name, n in sorted(wrote.items()) if n},
        "operations_attempted": list(attempts),
        "operations_failed": [a for a in attempts if not a.get("ok")],
        "advertised_but_unavailable": list(unavailable),
        "not_reachable": list(cannot_reach),
        "caveats": list(caveats),
        "endpoint_posture": dict(posture or {}),
    })

    manifest = {
        "schema": 2,
        # ALWAYS TRUE — a statement about the interfaces, not about how a
        # particular run went.
        "partial": True,
        "read_this": READ_THIS,
        "collections": collections,
    }
    if existing.get("unreadable_previous_manifest"):
        manifest["unreadable_previous_manifest"] = True
    path.write_text(json.dumps(manifest, indent=2, sort_keys=False) + "\n",
                    encoding="utf-8")
    return path


def summarise(manifest_path: Path) -> str:
    """A human-readable summary of the LAST collection recorded."""
    m = json.loads(manifest_path.read_text(encoding="utf-8"))
    collections = m.get("collections") or []
    if not collections:
        return "  nothing was recorded"
    c = collections[-1]

    lines: List[str] = []
    files = c.get("files_written") or {}
    if files:
        for name, n in files.items():
            lines.append(f"  wrote {name} ({n} row(s))")
    else:
        lines.append("  wrote NOTHING — no operation returned usable data")
    for a in c.get("operations_failed") or []:
        lines.append(f"  FAILED {a['operation']}: {a.get('error', '')[:140]}")
    if c.get("advertised_but_unavailable"):
        lines.append("  not offered by this instance: "
                     + ", ".join(c["advertised_but_unavailable"]))
    for caveat in c.get("caveats") or []:
        lines.append(f"  NOTE: {caveat}")
    posture = c.get("endpoint_posture") or {}
    if posture.get("unauthenticated_read") is True:
        lines.append("  ATTENTION: this endpoint answered a read with NO "
                     "credentials — see service/protectedwebmethods")
    if not c.get("tls_verified", True):
        lines.append("  ATTENTION: TLS certificate verification was DISABLED for "
                     "this collection")
    lines.append(f"  {len(c.get('not_reachable') or [])} logical source(s) are "
                 f"NOT reachable over this interface and remain export-only")
    if len(collections) > 1:
        lines.append(f"  ({len(collections)} collections recorded in this "
                     f"directory: "
                     f"{', '.join(x.get('source', '?') for x in collections)})")
    return "\n".join(lines)
