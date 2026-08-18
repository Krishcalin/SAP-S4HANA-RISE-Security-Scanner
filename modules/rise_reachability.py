# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""Can a RISE customer actually produce this source? Five answers, not two.

WHAT THIS REPLACES
------------------
`modules/coverage.py` held one set — five OS-level sources — and everything else
absent was reported as `missing`, which in a coverage manifest means "you did not
send this". `docs/RISE_SECURITY_MODEL.md` section 3 had already classified the
whole upload surface in FIVE states, and eleven of the sources it calls SAP-
operated were landing in the customer's column: the HANA configuration views, the
ICM/SNC parameters, the crypto library. Telling a RISE customer they failed to
export what SAP contractually operates is the same defect the original set existed
to prevent, stopped halfway.

THE MIDDLE STATE IS THE POINT
-----------------------------
`ticket` — obtainable, but only by raising a service request with SAP — is neither
"you forgot" nor "impossible", and with two buckets it had to be filed as one or
the other. Both readings are wrong in a way that costs something real: filed as
missing it blames the customer for SAP's queue, and filed as unreachable it tells
them to stop asking for data they could actually get.

WHAT THIS FILE DOES NOT DECIDE
------------------------------
Who fixes a finding. That is `server/enrich.py` — `remediation_owner_for`,
`RISE_PROVIDER_PREFIXES`, `classify_destination_owner` — and it answers a different
question about the same estate: this file is "who can EXPORT it", that one is "who
can CHANGE it". They agree where they overlap (`security_params` is `read_only`
here and `ticket_to_sap` there) and neither derives from the other, because a
source can be freely exportable and unfixable, or vice versa.

The content lives in `data/rise_reachability.json` for the same reason the edge
rules and attack paths do: adding a source's classification is a data change, and
the evidence for each row belongs next to the row.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from modules.deployment_modes import is_rise

_PATH = Path(__file__).resolve().parents[1] / "data" / "rise_reachability.json"
_CACHE: Optional[Dict[str, Dict[str, Any]]] = None

#: The five states, ordered from most to least the customer's own to obtain.
STATES = ("yes", "read_only", "partial", "ticket", "no")

#: Which absence bucket each state produces. The three that the customer CAN
#: obtain collapse to `missing` — a partial export is still an export they did not
#: send — while the two they cannot self-serve get their own buckets.
_BUCKET = {
    "yes": "missing",
    "read_only": "missing",
    "partial": "missing",
    "ticket": "needs_sap_action",
    "no": "unreachable",
}

#: What an unlisted source is treated as. `missing` is the behaviour that was
#: there before this file existed, and it is the conservative direction: most of
#: the logical sources are application-layer and customer-owned, so the default
#: asks for data rather than excusing its absence. `unclassified()` exists so the
#: number of sources riding on that default stays countable.
DEFAULT_STATE = "yes"


def load(path: Optional[Path] = None) -> Dict[str, Dict[str, Any]]:
    """The classification table, or empty if the content file cannot be read.

    Empty degrades to exactly the pre-existing behaviour with one exception, and
    the exception is the reason `coverage.py` keeps its own fallback: with no
    table, nothing is unreachable and every absent source reads as missing. That
    is worse than what was there before, so the caller substitutes the original
    five-source set rather than accepting it.
    """
    global _CACHE
    if _CACHE is None:
        try:
            payload = json.loads((path or _PATH).read_text(encoding="utf-8"))
            raw = payload.get("sources") or {}
            _CACHE = {k: v for k, v in raw.items()
                      if isinstance(v, dict) and v.get("state") in STATES}
        except (OSError, ValueError):
            _CACHE = {}
    return _CACHE


def state_of(source: str, deployment_mode: str = "on_prem") -> str:
    """The state for one logical source.

    Outside RISE every layer is the customer's, so the question does not arise and
    the answer is always `yes`. Consulting the table there would import RISE's
    constraints into an on-premise estate that does not have them.
    """
    if not is_rise(deployment_mode):
        return "yes"
    entry = load().get(source) or {}
    return entry.get("state", DEFAULT_STATE)


def bucket_of(source: str, deployment_mode: str = "on_prem") -> str:
    """Which absence bucket this source falls into: missing / needs_sap_action /
    unreachable."""
    return _BUCKET[state_of(source, deployment_mode)]


def detail(source: str) -> Dict[str, Any]:
    """The row as recorded — how to produce it, what blocks it, its provenance.

    Returned verbatim so a report can show the customer the actual procedure
    rather than a bare status. An unlisted source returns `{}`, which a caller
    must not render as "nothing blocks this".
    """
    return dict(load().get(source) or {})


def sources_in_state(state: str) -> Set[str]:
    return {k for k, v in load().items() if v.get("state") == state}


def unclassified(known: Any) -> List[str]:
    """Known logical sources with no row here, riding on `DEFAULT_STATE`.

    Reported rather than absorbed. A table that silently defaults is a table
    nobody ever finishes, and the count is the only thing that makes the
    unfinished part visible.
    """
    return sorted(set(known) - set(load()))


def unverified() -> List[str]:
    """Sources whose classification is recorded but not confirmed on a tenant.

    `docs/RISE_SECURITY_MODEL.md` section 8 gates the HANA rows on a design-partner
    test. Marking them and moving on is honest; forgetting they were guesses is
    not.
    """
    return sorted(k for k, v in load().items() if v.get("verified") is False)
