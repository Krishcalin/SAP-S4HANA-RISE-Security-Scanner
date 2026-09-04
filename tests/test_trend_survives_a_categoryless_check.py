"""A check with no category must not 500 the whole trend screen.

`check_definition.category` is nullable with no default, so a module that emits
a finding without a category produces a NULL row. `pass_rate_by_category` then
sorted a dict whose keys were mostly strings and occasionally None, and Python
cannot compare the two: TypeError, 500, and the screen is gone for the entire
landscape — not for the one odd check, for all of it.

FOUND BY ACCIDENT, which is worth recording. A shared test database had
accumulated 50 category-less `check_definition` rows left by DB-gated fixtures
(RBAC-PROBE, G-ENTRY, G-CUT and friends), and a full run happened to leave them
visible to `/api/trend`. The rows were test litter; the crash was not. One
shipped module emitting a finding without a category reaches the same place.

The uncategorised group sorts LAST and is KEPT. Dropping it would silently
remove those checks from a pass-rate denominator, which is the exact failure the
surrounding code already argues against at length.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server import analytics  # noqa: E402


def rates(observed, failing=None, coverage=None):
    return analytics._score_rows(observed=observed, failing=failing or {},
                                 coverage=coverage)


def test_a_categoryless_check_does_not_raise():
    """The regression. Before the fix this was a TypeError, and the caller is an
    HTTP route with no handler for it."""
    out = rates({None: 3, "Password Policy": 2})
    assert isinstance(out, list) and out


def test_the_uncategorised_group_is_kept_rather_than_dropped():
    out = rates({None: 3})
    assert [row for row in out if row["category"] is None], (
        "the category-less checks vanished from the screen instead of being "
        "shown as uncategorised")


def test_the_final_order_is_by_pass_rate_not_by_name():
    """A correction to my own first draft. The loop's sort key does not decide
    where anything appears: `_score_rows` re-sorts by pass rate at the end,
    worst first, with the unassessed after the measured ones. The key exists
    only so the loop can run at all, and a test asserting alphabetical order
    would have been asserting something the function overrides two lines later.
    """
    out = rates({None: 3, "Password Policy": 2}, failing={"Password Policy": 1})
    rated = [r["pct_passing"] for r in out if r["pct_passing"] is not None]
    assert rated == sorted(rated), "measured categories are not worst-first"
    unassessed_start = next((i for i, r in enumerate(out)
                             if r["pct_passing"] is None), len(out))
    assert all(r["pct_passing"] is None for r in out[unassessed_start:]), (
        "an unassessed category is interleaved with the measured ones")


def test_nothing_observed_at_all_still_works():
    assert isinstance(rates({}), list)
