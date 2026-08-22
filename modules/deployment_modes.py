"""The deployment-mode vocabulary, declared once.

WHY THIS FILE EXISTS
--------------------
The vocabulary was declared in six places across three languages — twice in
`server/schema.sql` (the CREATE TABLE constraint and the migration block),
`frontend/src/api/types.ts`, `sap_scanner.py`, `server/cli.py` — plus three
`or "on_prem"` defaults scattered through `modules/`. Adding a fourth value meant
editing five of them and hoping.

That is not a hypothetical hazard here. Four live branches decide whether a
system is governed by SAP's ECS rules by asking whether its mode name *starts
with* "rise":

    modules/user_auth_audit.py:250    self.deployment_mode().startswith("rise")
    server/coverage.py:141            deployment_mode.startswith("rise")
    server/enrich.py:156, :194        deployment_mode.startswith("rise")

So the ECC-in-RISE mode had to be named `rise_ecc` and not `ecc_rise`. The wrong
order disables every ECS rule for a system contractually bound by them — and
disables them SILENTLY, without failing a single test, because no test asserts
that a given mode is RISE-governed. Decision D7 in docs/DECISIONS.md.

WHY IT LIVES IN modules/
------------------------
`modules/` is the dependency-free layer, so `server/` depending on it is the safe
direction; the reverse would drag FastAPI behind the stdlib-only boundary. This
is the first `server/` -> `modules/` import, and it is deliberately a module with
no behaviour beyond a tuple and two predicates. The one existing rule about this
direction — CLAUDE.md's "`server/` never imports `release_gate`" — is about the
gate being CLI-only and is untouched.

SQL AND TYPESCRIPT CANNOT IMPORT THIS.
`server/schema.sql` and `frontend/src/api/types.ts` still declare the vocabulary
themselves, because neither can read a Python tuple. `tests/test_deployment_modes.py`
asserts all four declarations agree with this one, which is the same three-way
technique the `schema-upgrade` CI job uses on the CHECK constraint: a source of
truth for what can import it, and an agreement test for what cannot.
"""
from __future__ import annotations

from typing import Tuple

#: Every deployment mode the product understands.
#:
#: ORDER IS NOT ARBITRARY: `rise_*` modes must sort together and must begin with
#: the prefix `is_rise` tests. A mode that is RISE-governed but not named `rise_*`
#: would be treated as on-premise by four separate call sites.
DEPLOYMENT_MODES: Tuple[str, ...] = (
    "on_prem",
    "rise_pce",
    "rise_tailored",
    "rise_ecc",
)

#: What an unset mode means. A customer who never declared one is far more likely
#: to be on-premise than in RISE, and the RISE rules are the stricter set — so
#: defaulting the other way would invent contractual obligations a customer does
#: not have and report them as findings.
DEFAULT_DEPLOYMENT_MODE = "on_prem"

#: The prefix that means "SAP operates this system under ECS".
RISE_PREFIX = "rise"


def normalise(mode: object) -> str:
    """Coerce anything the callers actually hold into a known mode.

    Callers had three copies of `str(mode).strip().lower() or "on_prem"`
    (baseline_params, security_params, user_auth_audit). An unrecognised value
    falls back to the default rather than raising: this runs inside a scan, and a
    typo in one config field must not take the whole run down.
    """
    text = str(mode or "").strip().lower()
    return text if text in DEPLOYMENT_MODES else DEFAULT_DEPLOYMENT_MODE


def is_rise(mode: object) -> bool:
    """Is this system operated by SAP under ECS?

    The four call sites listed above each spelled this as a `startswith` on a raw
    string. Spelled once, it can be tested once — and `test_deployment_modes.py`
    asserts the answer for EVERY mode in the tuple, so a mode added later cannot
    quietly land on the wrong side of it.
    """
    return normalise(mode).startswith(RISE_PREFIX)
