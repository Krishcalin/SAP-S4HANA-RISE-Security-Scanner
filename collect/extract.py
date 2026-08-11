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


def write_manifest(out_dir: Path, *, source: str, endpoint: str,
                   collected_at: str, wrote: Mapping[str, int],
                   attempts: Sequence[Mapping[str, Any]],
                   unavailable: Sequence[str] = (),
                   cannot_reach: Sequence[str] = SAPCONTROL_CANNOT_REACH,
                   tls_verified: bool = True,
                   posture: Optional[Mapping[str, Any]] = None) -> Path:
    """State what this run got, what it did not, and under what conditions.

    WHY `cannot_reach` IS A CONSTANT AND NOT A COMPUTED DIFFERENCE. Computing it
    as "everything the loader knows, minus what we wrote" would silently absorb a
    future logical source into the not-reachable list the moment somebody added
    one — turning a new coverage gap into a documented limitation without anyone
    deciding that. It is written down, so widening it is a choice.

    `partial` is always true for a connected collection, and it is not a field
    anybody should be able to set. A connected run is partial by construction.
    """
    failed = [a for a in attempts if not a.get("ok")]
    manifest = {
        "schema": 1,
        "source": source,
        "endpoint": endpoint,
        "collected_at": collected_at,
        "tls_verified": tls_verified,
        # ALWAYS TRUE. See the docstring — this is a statement about the interface,
        # not about how this particular run went.
        "partial": True,
        "files_written": {name: n for name, n in sorted(wrote.items()) if n},
        "operations_attempted": list(attempts),
        "operations_failed": failed,
        "advertised_but_unavailable": list(unavailable),
        "not_reachable_over_this_interface": list(cannot_reach),
        "endpoint_posture": dict(posture or {}),
        "read_this": (
            "This directory was produced by a connected collection and is NOT a "
            "complete export. The sources listed under "
            "'not_reachable_over_this_interface' live inside the ABAP stack and "
            "are reachable over RFC or by an interactive export only; this "
            "product declines RFC (decision D3), so on this estate they remain "
            "export-only. Scan results from this directory alone describe the "
            "instance's profile parameters and nothing else. Treat every check "
            "that depends on an unlisted source as UNKNOWN, never as clean."),
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "collection_manifest.json"
    path.write_text(json.dumps(manifest, indent=2, sort_keys=False) + "\n",
                    encoding="utf-8")
    return path


def summarise(manifest_path: Path) -> str:
    """A human-readable summary, for the console the operator is looking at."""
    m = json.loads(manifest_path.read_text(encoding="utf-8"))
    lines: List[str] = []
    files = m.get("files_written") or {}
    if files:
        for name, n in files.items():
            lines.append(f"  wrote {name} ({n} row(s))")
    else:
        lines.append("  wrote NOTHING — no operation returned usable data")
    for a in m.get("operations_failed") or []:
        lines.append(f"  FAILED {a['operation']}: {a.get('error', '')[:140]}")
    if m.get("advertised_but_unavailable"):
        lines.append("  not offered by this instance: "
                     + ", ".join(m["advertised_but_unavailable"]))
    posture = m.get("endpoint_posture") or {}
    if posture.get("unauthenticated_read") is True:
        lines.append("  ATTENTION: this endpoint answered a read with NO "
                     "credentials — see service/protectedwebmethods")
    if not m.get("tls_verified", True):
        lines.append("  ATTENTION: TLS certificate verification was DISABLED for "
                     "this collection")
    lines.append(f"  {len(m.get('not_reachable_over_this_interface') or [])} "
                 f"logical source(s) are NOT reachable over this interface and "
                 f"remain export-only — see collection_manifest.json")
    return "\n".join(lines)
