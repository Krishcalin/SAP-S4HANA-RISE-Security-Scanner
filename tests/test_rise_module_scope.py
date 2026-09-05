"""Every auditor has a RISE verdict, or is named here as deliberately outside it.

THIS TEST WAS ASSERTED IN PROSE BEFORE IT EXISTED. `docs/RISE_SECURITY_MODEL.md`
§4 said the live verdict for every module is `RISE_MODULE_SCOPE` "which a test
holds to cover all 33 auditors with no gaps". There was no such test, the module
count had reached 38, and the map had 36 entries — so two auditors were rendering
`unknown` in the RISE scope column of the customer-facing coverage table while
the document promised the opposite.

WHY IT MATTERS THAT THE MAP IS COMPLETE. `coverage.py` reads it to decide what a
RISE tenant is even claimed to be assessed on. A module with no verdict is not a
crash and not a wrong answer — `.get(mod, "unknown")` degrades honestly — but
`unknown` here means "nobody decided", and it is indistinguishable on the page
from "we could not determine". Those are different states and this product does
not merge them anywhere else.

THE TWO EXCLUSIONS ARE NOT AN OVERSIGHT. `export_integrity` and
`ruleset_coverage` do not audit the SAP estate at all: the first asks whether the
customer's own export files could be read, the second asks how much of the estate
our own SoD ruleset can see. Neither has a contractual owner, because neither
names anything in the contract. They are listed rather than given a verdict,
because inventing "in_scope" for them would put a made-up responsibility split in
a document customers read.

The point of the list is that it cannot grow silently. A 39th auditor either gets
a verdict derived from §2 and §3 of the research, or somebody has to come here and
argue in writing that it audits something other than the SAP estate.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import coverage  # noqa: E402

#: Auditors that answer a question about our own evidence or our own ruleset
#: rather than about the customer's SAP system. See the module docstring.
NOT_ABOUT_THE_ESTATE = {"export_integrity", "ruleset_coverage"}


def test_every_auditor_has_a_rise_verdict_or_is_a_named_exclusion():
    modules = set(coverage.module_sources())
    scoped = set(coverage.RISE_MODULE_SCOPE)
    missing = modules - scoped - NOT_ABOUT_THE_ESTATE
    assert not missing, (
        f"{len(missing)} auditor(s) have no RISE scope verdict: {sorted(missing)}. "
        f"Derive one from docs/RISE_SECURITY_MODEL.md sections 2 and 3 and record "
        f"it in RISE_MODULE_SCOPE, or add it to NOT_ABOUT_THE_ESTATE with the "
        f"argument for why it audits something other than the SAP estate.")


def test_the_map_holds_no_verdict_for_a_module_that_is_gone():
    """A verdict for a deleted module is dead weight that reads as coverage."""
    stale = set(coverage.RISE_MODULE_SCOPE) - set(coverage.module_sources())
    assert not stale, f"RISE_MODULE_SCOPE names modules that no longer exist: {sorted(stale)}"


def test_the_exclusions_are_really_excluded():
    """A module cannot be both excluded and given a verdict.

    Two entries saying different things is how the list stops meaning anything —
    the map would win at runtime and the list would go on justifying an
    exclusion that is not in force."""
    both = NOT_ABOUT_THE_ESTATE & set(coverage.RISE_MODULE_SCOPE)
    assert not both, (
        f"{sorted(both)} is named as outside the RISE responsibility question AND "
        f"given a verdict in RISE_MODULE_SCOPE. Delete one.")


def test_the_exclusions_still_exist():
    """A stale exclusion silently re-opens the gap it was written to close."""
    gone = NOT_ABOUT_THE_ESTATE - set(coverage.module_sources())
    assert not gone, f"excluded module(s) no longer exist: {sorted(gone)}"


def test_every_verdict_uses_the_published_vocabulary():
    """The value is rendered in the customer-facing coverage table.

    A typo does not fail anywhere — it renders as itself, in a column a customer
    reads as a statement about their contract."""
    allowed = {"in_scope", "read_only", "split", "partial", "mostly_out",
               "conditional"}
    unknown = {m: v for m, v in coverage.RISE_MODULE_SCOPE.items()
               if v not in allowed}
    assert not unknown, (
        f"unrecognised RISE scope value(s): {unknown}. Adding a value changes "
        f"what a customer reads in the coverage table — widen `allowed` here "
        f"deliberately, and say what the new word means.")
