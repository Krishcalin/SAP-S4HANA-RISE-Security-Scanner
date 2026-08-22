"""
What produced this figure — the catalogue, the engine, and the model version.

THE HOLE THIS CLOSES
--------------------
The trend line already breaks when the customer's financial answers change, and
that guard works. It could not see one layer down.

`data/fair_scenarios.json` carries a `_meta.version` and nothing recorded it per
run. Edit a loss band, a resistance-strength band or a detection multiplier and
EVERY customer's number moves, on unchanged findings, with nothing anywhere saying
why — the chart simply redraws its own past. A catalogue edit is the single
cheapest way to move this product's headline figure and it was the least visible.

The engine is worse, because it can change without anybody editing anything.
`locate_engine` searches an explicit path, then `CRQ_ENGINE`, then the bundled
module. Drop a file at one of those and different mathematics runs, silently. The
old loop swallowed every failure with a bare `except Exception: continue`, so a
BROKEN external engine also substituted quietly: no log line, no record, and a
figure computed by something nobody knew was there.

So a run records what actually ran: the catalogue's declared version and the
SHA-256 of its bytes, the engine's origin and digest, and the model version. Bytes
rather than the declared version alone, because `_meta.version` is a string a
human remembers to bump and a hash is not.

STDLIB ONLY. `hashlib`, `json`, `pathlib` — `modules/` is stdlib-only by charter
and CI enforces it.
"""
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

#: Bumped when a change to the model would move a figure for unchanged findings.
#: Mirrors server.crq.MODEL_VERSION; the test asserts they agree, because two
#: version numbers that can disagree are worse than one.
MODEL_VERSION = 3


def file_digest(path: Any) -> Optional[str]:
    """SHA-256 of a file's bytes, or None if it cannot be read.

    None rather than a raised exception or an empty string: provenance is a
    best-effort record ALONGSIDE the figure, and a scan must not fail because a
    digest could not be taken. But it must not report a digest it does not have
    either — hence None, which the consumer renders as "unknown".
    """
    try:
        p = Path(path)
        h = hashlib.sha256()
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:                                    # noqa: BLE001
        return None


def catalogue_provenance(path: Any,
                         catalogue: Optional[Dict[str, Any]] = None
                         ) -> Dict[str, Any]:
    """What the scenario catalogue is, and what it says it is.

    Both are recorded because they answer different questions. `version` is what
    the author claims; `sha256` is what the file actually contains. They disagree
    exactly when somebody edited the catalogue without bumping the version, which
    is the case the version alone cannot catch and the one most likely to happen.
    """
    meta: Dict[str, Any] = {}
    if catalogue is None:
        try:
            with open(Path(path), "r", encoding="utf-8") as fh:
                catalogue = json.load(fh)
        except Exception:                                # noqa: BLE001
            catalogue = {}
    if isinstance(catalogue, dict):
        raw = catalogue.get("_meta")
        if isinstance(raw, dict):
            meta = raw
    scenarios = catalogue.get("scenarios") if isinstance(catalogue, dict) else None
    return {
        "path": str(path),
        "version": meta.get("version"),
        "currency": meta.get("currency"),
        "sha256": file_digest(path),
        "scenario_count": len(scenarios) if isinstance(scenarios, list) else None,
    }


def engine_provenance(kind: str, path: Any = None,
                      skipped: Optional[List[Dict[str, str]]] = None
                      ) -> Dict[str, Any]:
    """Which engine ran, and which candidates were passed over.

    `skipped` matters as much as the winner. A candidate that failed to import is
    a deployment problem somebody needs to see, and the previous bare `continue`
    made it invisible — the run produced a number from a different engine and
    reported nothing unusual.
    """
    return {
        "kind": kind,                       # bundled | env | explicit | none
        "path": str(path) if path else None,
        "sha256": file_digest(path) if path else None,
        "skipped": list(skipped or []),
    }


def fingerprint(material: Dict[str, Any]) -> str:
    """A stable digest over the things that are NOT remediation.

    Canonical JSON — sorted keys, no whitespace — so the same inputs give the same
    fingerprint in any process and any Python version. `default=str` because a
    Decimal from psycopg would otherwise raise here and take a scan down over a
    provenance record, which is the wrong trade.
    """
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"),
                           default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
