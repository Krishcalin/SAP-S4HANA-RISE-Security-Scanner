# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""A per-category denominator that counts only failures is not a denominator.

THE DEFECT
`check_catalogue()` maps check id -> finding category by pairing the two inside
one call, and it can only do that when the id is written as a literal. Every
runtime family composes its id — `f"ARA-{rid}"`, `lead["rule_id"]` — so 287 of
620 checks had no category at all.

server/analytics.py backfills a category the catalogue does not know with
`max(0, observed)`, and a check is only observed when it FAILS. So for the six
categories built entirely from profile parameters the denominator equalled the
failure count, and the compliance figure was 0% by construction, on every estate,
for ever:

    Password Policy        0%  ->  44%   (9 failing of 16, not of 9)
    Login Security         0%  ->  62%
    RFC Security           0%  ->  43%
    Gateway Security       0%  ->  50%
    Transport Security     0%  ->  86%
    Development Controls   0%  ->  80%
    Code & Transport       0%  ->  84%   (28 failing of 177, not of 28)

WHAT THESE TESTS PIN
That every check the product can raise carries a category; that the category is
the one the auditor actually emits, checked against a real scan rather than
asserted; and that the derivation refuses to guess when a module is ambiguous.
"""
from __future__ import annotations

import contextlib
import importlib
import io
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.coverage import (all_check_ids, check_catalogue,          # noqa: E402
                              runtime_check_families, runtime_emit_categories)


@pytest.fixture(scope="module")
def emitted():
    """(check id, category) as the real auditors produce them over sample_data."""
    from modules.data_loader import DataLoader
    from server import ingest

    with contextlib.redirect_stdout(io.StringIO()), \
         contextlib.redirect_stderr(io.StringIO()):
        data = DataLoader(ROOT / "sample_data").load_all()
        pairs = {}
        for name, cls_name in ingest.AUDITORS:
            cls = getattr(importlib.import_module("modules." + name), cls_name)
            try:
                auditor = cls(data, {}, {"deployment_mode": "on_prem",
                                         "modules": set()})
            except TypeError:
                auditor = cls(data, {})
            for f in auditor.run_all_checks():
                if f.get("check_id") and f.get("category"):
                    pairs.setdefault(f["check_id"], set()).add(f["category"])
    return pairs


def test_every_check_the_product_can_raise_has_a_category():
    """The whole point. A check with no category cannot be counted in one, and
    an uncounted check makes its category's denominator smaller than the truth."""
    catalogue = check_catalogue()
    every = {cid for ids in all_check_ids().values() for cid in ids}
    missing = sorted(every - set(catalogue))
    assert not missing, (
        "%d checks carry no category, so their categories are measured against "
        "fewer checks than ran: %s" % (len(missing), missing[:12]))


def test_the_category_is_the_one_the_auditor_actually_emits(emitted):
    """Measured, not asserted. A category derived from the wrong place is worse
    than a missing one — it moves a finding into a denominator it does not
    belong to, and nothing looks broken."""
    catalogue = check_catalogue()
    wrong = []
    for cid, cats in emitted.items():
        if cid in catalogue and catalogue[cid] not in cats:
            wrong.append("%s: catalogue=%r emitted=%r"
                         % (cid, catalogue[cid], sorted(cats)))
    assert emitted, "no findings produced — this test would prove nothing"
    assert not wrong, "\n".join(["catalogue disagrees with the auditors:"] + wrong)


def test_the_abap_rule_tables_own_category_field_is_not_used():
    """THE TRAP THIS DERIVATION HAD TO AVOID.

    `ALL_ABAP_SAST_RULES` rows carry a `category`, which looks exactly like the
    field to use. It is a different taxonomy — "SQL Injection", "Cross-Site
    Scripting", "Directory Traversal" — classifying the weakness rather than the
    finding. Taking it would have added twelve categories that no finding carries
    and no domain maps. The emit site says "Code & Transport Security", and the
    emit site is what the finding will actually carry.
    """
    from modules.abap_sast import ALL_ABAP_SAST_RULES

    catalogue = check_catalogue()
    rule_taxonomy = {r.get("category") for r in ALL_ABAP_SAST_RULES
                     if isinstance(r, dict) and r.get("category")}
    assert len(rule_taxonomy) > 5, "the rule table stopped carrying a category"

    # ASKED PER ID, NOT AS A SET INTERSECTION. The first version of this test
    # intersected the two taxonomies and failed on a correct implementation:
    # "RFC Security" is a name they share, a genuine finding category from
    # security_params AND a weakness class in the ABAP table. Overlap is not
    # leakage. What matters is which category each ABAP id actually carries.
    family = next(f for f in runtime_check_families() if f["module"] == "abap_sast")
    assert set(family["categories"].values()) == {"Code & Transport Security"}

    leaked = sorted(cid for cid in family["ids"]
                    if catalogue.get(cid) != "Code & Transport Security")
    assert not leaked, (
        "these ABAP checks took a category from somewhere other than the emit "
        "site: %s" % [(c, catalogue.get(c)) for c in leaked[:6]])


def test_every_runtime_family_carries_a_category_for_every_id():
    for family in runtime_check_families():
        cats = family.get("categories") or {}
        missing = sorted(set(family["ids"]) - set(cats))
        assert not missing, "%s has ids with no category: %s" % (family["pattern"],
                                                                 missing[:6])
        assert all(cats.values()), "%s maps an id to an empty category" % family["pattern"]


def test_a_family_whose_module_is_ambiguous_is_refused_not_guessed():
    """A module emitting two categories for composed ids cannot be attributed,
    and the derivation says so rather than picking the more common one."""
    import inspect

    from modules import coverage

    src = inspect.getsource(coverage.runtime_check_families)
    assert "raise RuntimeError" in src
    assert "len(cats) != 1" in src, \
        "the ambiguity guard is gone; a category is being guessed"


def test_the_derivation_reads_the_emit_site_rather_than_a_table_here():
    """Declared categories would be a second copy of a decision the emit site
    already makes, and a category is a string somebody renames."""
    derived = runtime_emit_categories()
    assert derived, "no emit categories derived at all"
    for module in ("abap_sast", "access_risk_analysis", "atc_import",
                   "iam_advanced"):
        assert module in derived, module
        assert len(derived[module]) == 1, (
            "%s emits composed ids with %s" % (module, sorted(derived[module])))
    # The one the data settled: iam_advanced spans two module categories, and
    # its SoD findings carry this one.
    assert derived["iam_advanced"] == {"Identity & Access Management"}


def test_the_six_parameter_categories_are_no_longer_measured_against_failures():
    """Each of these is built entirely from profile parameters, so the literals-
    only map knew none of them and the denominator collapsed to the failures."""
    catalogue = check_catalogue()
    counts = {}
    for category in catalogue.values():
        counts[category] = counts.get(category, 0) + 1
    for category, floor in [("Password Policy", 10), ("Login Security", 8),
                            ("RFC Security", 5), ("Gateway Security", 5),
                            ("Transport Security", 4), ("Development Controls", 3),
                            ("Code & Transport Security", 100)]:
        assert counts.get(category, 0) >= floor, (
            "%s is known for only %d checks; it was 0 before this derivation "
            "and its compliance figure was 0%% by arithmetic"
            % (category, counts.get(category, 0)))
