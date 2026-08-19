# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""Has SAP's Security Baseline Template moved since we last looked?

WHAT THIS COMPLETES. The `sap-content` CI job already clones SAP's Apache-2.0
policy repository on every run and re-derives both catalogues, failing on any
drift. That covers the POLICIES. It does not cover the Baseline Template ZIP,
which is a different artefact on a different release cadence — and the gap
between them is not hypothetical: the policy set this product derives from is
**v2.4**, and the ZIP currently ships **V2.6**.

WHY THE CHANGE MARKERS ARE THE POINT. Each version in the ZIP carries a
`..._change_marker.pdf`. They are what makes "the REQUIREMENT changed"
distinguishable from "the SYSTEM changed" across two scans of the same estate —
a distinction nothing else in this market appears to draw, and one a customer
cannot make for themselves once a finding's text has silently moved underneath
them. This tool does not read the PDFs. It records that a new one exists, which
is the trigger for a person to read it.

WHY IT DOES NOT DOWNLOAD 99 MB. The archive is 99,336,484 bytes and CI runs on
every push. The server answers `HEAD` with `Content-Length` and `Last-Modified`,
and honours a `Range` request — so the ZIP's own central directory, which lists
all 545 entries, is readable from the last 300 KB. Size, timestamp and the entry
list together detect every change worth detecting at 0.3% of the transfer.

NO LOGIN WALL, WHICH IS WHY THIS IS POSSIBLE AT ALL. The URL returns 200 to an
unauthenticated request. Most SAP content of this value sits behind SAP for Me;
this does not, and that is worth writing down because it is the reason this
check can run in CI rather than on somebody's laptop with an S-user.

FAILING IS THE POINT, NOT THE PROBLEM. A drift here does not mean the product is
wrong. It means SAP moved and somebody has to read the change marker and decide
whether anything follows. A check that warned instead of failing would be read
once and then ignored.
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import sys
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

RECORD_PATH = Path(__file__).resolve().parents[1] / "data" / "sap_baseline_zip.json"

#: How much of the archive's tail to read. The central directory for 545 entries
#: is well under this; the margin is for growth rather than precision.
TAIL_BYTES = 300_000

#: Central-directory file-header signature. The archive is scanned for these
#: rather than parsed from the end-of-central-directory record, because a ranged
#: read may land mid-structure and a signature scan tolerates that.
_CDFH = b"PK\x01\x02"

_VERSION = re.compile(r"V\d+(?:\.\d+)+")


def entry_names(tail: bytes) -> List[str]:
    """Every filename in the archive's central directory, from a ranged read."""
    names: List[str] = []
    i = 0
    while True:
        i = tail.find(_CDFH, i)
        if i < 0:
            return names
        try:
            n_len, m_len, k_len = struct.unpack("<HHH", tail[i + 28:i + 34])
            name = tail[i + 46:i + 46 + n_len].decode("utf-8", "replace")
            if name:
                names.append(name)
        except (struct.error, IndexError):
            pass                      # a truncated trailing record; keep scanning
        i += 4


def versions_of(names: List[str]) -> List[str]:
    return sorted({m.group(0) for name in names
                   for m in [_VERSION.search(name)] if m})


def change_markers(names: List[str]) -> List[str]:
    return sorted(n for n in names if "change_marker" in n.lower())


def fetch(url: str, timeout: int = 120) -> Dict[str, Any]:
    """Size, timestamp and entry list, without downloading the archive."""
    head = urllib.request.Request(url, method="HEAD")
    with urllib.request.urlopen(head, timeout=timeout) as response:
        length = int(response.headers.get("Content-Length") or 0)
        modified = response.headers.get("Last-Modified") or ""
    if not length:
        raise RuntimeError("no Content-Length; cannot range-read the directory")

    start = max(0, length - TAIL_BYTES)
    ranged = urllib.request.Request(url, headers={"Range": f"bytes={start}-{length - 1}"})
    with urllib.request.urlopen(ranged, timeout=timeout) as response:
        tail = response.read()

    names = entry_names(tail)
    return {"content_length": length, "last_modified": modified,
            "entries": len(names), "versions": versions_of(names),
            "change_markers": change_markers(names)}


def compare(live: Dict[str, Any], pinned: Dict[str, Any]) -> List[str]:
    """What moved, in the words a reader needs rather than a diff.

    Each difference names what to DO about it. "content_length differs" tells
    nobody anything; "SAP published V2.7, read its change marker" is the whole
    reason this runs.
    """
    problems: List[str] = []
    if live["content_length"] != pinned.get("content_length"):
        problems.append(
            "The archive's size changed (%s -> %s). SAP republished it; compare "
            "the version list below before assuming what moved."
            % (pinned.get("content_length"), live["content_length"]))
    if live["last_modified"] != pinned.get("last_modified"):
        problems.append(
            "Last-Modified moved (%s -> %s)."
            % (pinned.get("last_modified"), live["last_modified"]))

    new = [v for v in live["versions"] if v not in (pinned.get("versions") or [])]
    if new:
        problems.append(
            "SAP published %s. READ THE CHANGE MARKER for it — it is what makes "
            "'the requirement changed' distinguishable from 'the system changed' "
            "in a repeat scan, and a finding whose text moved underneath a "
            "customer is the failure this check exists to catch."
            % ", ".join(new))

    gone = [v for v in (pinned.get("versions") or []) if v not in live["versions"]]
    if gone:
        problems.append(
            "%s is no longer in the archive. A version SAP withdrew is worth "
            "knowing about before citing it." % ", ".join(gone))
    return problems


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--update", action="store_true",
                        help="rewrite the pinned record from what is live. Use "
                             "AFTER reading the change marker, never to make a "
                             "failing build pass.")
    parser.add_argument("--offline", action="store_true",
                        help="validate the pinned record without reaching SAP")
    args = parser.parse_args(argv)

    pinned = json.loads(RECORD_PATH.read_text(encoding="utf-8"))
    if args.offline:
        print(f"pinned: {pinned['current']} of {len(pinned['versions'])} versions, "
              f"{pinned['entries']} entries, {pinned['content_length']} bytes")
        return 0

    live = fetch(pinned["url"])
    problems = compare(live, pinned)

    if args.update:
        pinned.update(live)
        pinned["current"] = live["versions"][-1] if live["versions"] else None
        RECORD_PATH.write_text(json.dumps(pinned, indent=2, ensure_ascii=False) + "\n",
                               encoding="utf-8")
        print(f"pinned record updated: {pinned['current']}, "
              f"{live['entries']} entries")
        return 0

    if problems:
        print("SAP's Security Baseline Template has moved:\n", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}\n", file=sys.stderr)
        print("After reading what changed, re-pin with:\n"
              "    python -m tools.check_baseline_zip --update\n", file=sys.stderr)
        return 1

    print(f"unchanged: {live['versions'][-1]}, {live['entries']} entries, "
          f"{live['content_length']} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
