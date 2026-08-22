"""Compatibility shim. The coverage manifest now lives in `modules/coverage.py`.

WHY IT MOVED
The manifest is computed from DataLoader output and describes what the SCANNER
could and could not look at. It had no dependency on the server tier — its only
non-stdlib import was `modules.deployment_modes` — but living under `server/` put
it out of reach of the offline CLI and the three report generators, because
`modules/` may not import `server/`.

That is why a customer's PDF never carried a word of it: the code existed, was
correct, was wired to ingest, and was structurally unreachable from the artefact
that most needed it. A half-supplied estate rendered as a clean one.

This module re-exports so `server/ingest.py` and the existing tests keep working.
New code should import from `modules.coverage`.
"""
# EVERY public name, not a hand-picked few. The first version of this shim
# re-exported two functions and broke two tests that used `module_sources` — a
# shim that exports a subset is a rename pretending to be a move.
from modules import coverage as _coverage
from modules.coverage import *                                    # noqa: F401,F403

__all__ = [name for name in dir(_coverage) if not name.startswith("_")]

# Module-level attribute access (`coverage.module_sources`) goes through here too,
# so anything reached by attribute rather than by import keeps working.
def __getattr__(name):
    return getattr(_coverage, name)
