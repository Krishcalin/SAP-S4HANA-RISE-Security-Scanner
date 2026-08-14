# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""What the derivations CLAIM, against what a real run EMITS.

WHY THIS FILE IS THE MOST IMPORTANT TEST IN THE SUITE

Five separate consumers now ask modules/coverage.py the same question — "could
anything that produces this category have looked?" — and act on the answer:

    modules/domains.py        CLEAR vs NOT_SUPPLIED on twelve buyer-facing tiles
    modules/nist_csf.py       the same, on 22 CSF Categories
    modules/fair_cam.py       the same, on 9 control functions
    server/ingest.py          whether a finding may be marked RESOLVED
    server/analytics.py       whether a category has a pass rate at all

Every one of them treats "I cannot tie this category to a module" as *assume it
ran*. That default is deliberate — over-reporting NOT_SUPPLIED tells a customer
they forgot an export they did send — but it means a HOLE IN THE DERIVATION IS
SILENT AND FAILS OPEN. The answer is not wrong; it is confidently absent.

The derivations are AST heuristics over source text, so a module that declares
its categories in a spelling they do not anticipate simply vanishes from them.
`modules/security_params.py` did exactly that: it carries category names as
values inside a parameter table (`{"gw/acl_mode": {"category": "Gateway
Security", ...}}`) rather than as `category=` keyword arguments, so ten of its
categories were unclaimed and five were tied to NOTHING AT ALL. Twenty-four
findings — 7% of a sample_data run — passed the resolution guard unconditionally
and were written `state='resolved'` by a run that had never looked at them.

Nothing in the suite compared the two sides, so all of it was invisible. That is
what this file exists to make impossible: it runs the real auditors over the real
sample data and holds the derivations to what actually came out.

IF THIS TEST FAILS, THE DERIVATION IS WRONG, NOT THE TEST. The corpus is ground
truth. Do not add a module to an exclusion list to make it pass.
"""
from __future__ import annotations

import collections
import contextlib
import importlib
import io
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SAMPLE = ROOT / "sample_data"

pytestmark = pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")


@pytest.fixture(scope="module")
def corpus():
    """{module name: {category: count}} from actually running the auditors.

    The auditor registry is server/ingest.AUDITORS rather than a list here, so a
    module added to the product joins this test automatically — the same
    reasoning modules/coverage.py gives for deriving rather than declaring.
    """
    from modules.data_loader import DataLoader
    from server import ingest

    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(SAMPLE).load_all()

    emitted: dict = collections.defaultdict(collections.Counter)
    for module_name, class_name in ingest.AUDITORS:
        module = importlib.import_module(f"modules.{module_name}")
        auditor_class = getattr(module, class_name)
        with contextlib.redirect_stdout(io.StringIO()):
            try:
                auditor = auditor_class(data, {}, {"deployment_mode": "on_prem",
                                                   "modules": set()})
            except TypeError:
                auditor = auditor_class(data, {})
            for finding in auditor.run_all_checks():
                if finding.get("category"):
                    emitted[module_name][finding["category"]] += 1
    return dict(emitted)


def test_the_run_produced_enough_to_be_worth_checking(corpus):
    """A guard on the guard. If the fixture silently produced nothing, every
    assertion below would pass while testing air."""
    assert len(corpus) >= 20, f"only {len(corpus)} modules emitted findings"
    assert sum(sum(c.values()) for c in corpus.values()) > 200


def test_every_category_a_module_emits_is_claimed_by_that_module(corpus):
    """THE INVARIANT. `module_categories()` says what a module can produce; a
    real run says what it did. The first must cover the second."""
    from modules.coverage import module_categories

    claimed = module_categories()
    missing = [
        (module, category, count)
        for module, categories in sorted(corpus.items())
        for category, count in sorted(categories.items())
        if category not in (claimed.get(module) or [])
    ]
    assert not missing, (
        "the derivation does not claim categories these modules actually emit — "
        "every consumer will read the gap as 'assume it ran':\n"
        + "\n".join(f"  {m} -> {c!r} ({n} finding(s))" for m, c, n in missing))


def test_every_category_a_run_emits_can_be_tied_to_some_module(corpus):
    """The consumers' actual question, asked the way they ask it.

    A category `modules_for_categories` cannot resolve returns an empty set, and
    every caller then falls through to "assume it ran" — so a finding in it can
    never be NOT_SUPPLIED and can always be resolved. Five categories were in
    that state, including Password Policy and Gateway Security.
    """
    from modules.coverage import modules_for_categories

    orphans = sorted({
        category
        for categories in corpus.values()
        for category in categories
        if not modules_for_categories([category])
    })
    assert not orphans, (
        "no module can be tied to these categories, so every honesty check "
        f"fails open for them: {orphans}")


def test_the_check_catalogue_agrees_with_the_run_about_categories(corpus):
    """Where the catalogue knows a check id, it must place it in the same
    category the run did. A disagreement silently moves a check between
    denominators on the trend screen."""
    from modules.coverage import check_catalogue
    from modules.data_loader import DataLoader
    from server import ingest

    catalogue = check_catalogue()
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(SAMPLE).load_all()

    disagreements = []
    for module_name, class_name in ingest.AUDITORS:
        module = importlib.import_module(f"modules.{module_name}")
        with contextlib.redirect_stdout(io.StringIO()):
            try:
                auditor = getattr(module, class_name)(
                    data, {}, {"deployment_mode": "on_prem", "modules": set()})
            except TypeError:
                auditor = getattr(module, class_name)(data, {})
            for finding in auditor.run_all_checks():
                cid, cat = finding.get("check_id"), finding.get("category")
                if cid in catalogue and cat and catalogue[cid] != cat:
                    disagreements.append((cid, catalogue[cid], cat))
    assert not disagreements, (
        "the catalogue and the run disagree about a check's category:\n"
        + "\n".join(f"  {c}: catalogue says {a!r}, the run emitted {b!r}"
                    for c, a, b in disagreements[:10]))


def test_a_scan_that_ran_nothing_leaves_no_domain_looking_clean(corpus):
    """The end-to-end form of the same rule, over the real category vocabulary.

    With a manifest in which every module skipped, no domain, CSF Category or
    control function may report CLEAR — whatever the derivations do or do not
    know. This is the assertion that would have caught the hole above by its
    consequence rather than by its cause.
    """
    from modules import domains, fair_cam, nist_csf
    from server import ingest

    nothing_ran = {"modules": {name: {"status": "skipped"}
                               for name, _cls in ingest.AUDITORS}}

    rolled = domains.roll_up([], coverage=nothing_ran)
    clean = [d["id"] for d in rolled["domains"] if d["state"] == domains.CLEAR]
    assert not clean, f"domains reported clean on a scan that ran nothing: {clean}"

    csf = nist_csf.roll_up([], coverage=nothing_ran)
    clear = [c["id"] for f in csf["functions"] for c in f["categories"]
             if c["status"] == nist_csf.CLEAR]
    assert not clear, f"CSF Categories reported clear on a scan that ran nothing: {clear}"

    cam = fair_cam.classify([], coverage=nothing_ran)
    clear_fns = [f["id"] for f in cam["functions"] if f["status"] == fair_cam.CLEAR]
    assert not clear_fns, (
        f"control functions reported clear on a scan that ran nothing: {clear_fns}")


# ── the honesty predicate is one site, not five ──────────────────────────────

def test_only_one_place_decides_whether_something_was_looked_at():
    """`bool(feeders & ran)` was written out five times and the five had already
    drifted: one defaulted the no-manifest case to "assessed" and published 28
    categories at 100% over an empty database.

    A convention five files agree to follow is not a rule. This asserts the
    intersection appears in exactly one function — the rest call it.
    """
    import ast

    # READ THE AST, NOT THE TEXT. The first version of this grepped for the
    # expression and stripped `#` comments — and then flagged the DOCSTRING in
    # look_verdict that explains why the function exists. That is the fifth time
    # in this codebase a textual check has matched prose written to prevent the
    # very thing it was looking for. A rule about what the CODE does has to be
    # asked of the code.
    hits = []
    for path in sorted((ROOT / "modules").glob("*.py")) + \
            sorted((ROOT / "server").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
        for node in ast.walk(tree):
            if (isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitAnd)
                    and {getattr(node.left, "id", None),
                         getattr(node.right, "id", None)} == {"feeders", "ran"}):
                hits.append(f"{path.name}:{node.lineno}")
    assert len(hits) == 1, (
        f"the honesty predicate is evaluated in more than one place: {hits}")
    assert hits[0].startswith("coverage.py"), hits


@pytest.mark.parametrize("module_name", [
    "modules/domains.py", "modules/nist_csf.py", "modules/fair_cam.py",
    "server/ingest.py", "server/analytics.py",
])
def test_every_consumer_goes_through_the_resolver(module_name):
    """And each states what it does with UNKNOWN at the call site, because the
    four finding-facing callers and the one rate-facing caller answer that
    question differently and both are right."""
    source = (ROOT / module_name).read_text(encoding="utf-8")
    assert "look_verdict" in source, f"{module_name} decides this itself"
    assert "UNKNOWN" in source or "UNSUPPLIED" in source


def test_the_resolver_returns_three_answers_not_two():
    """UNKNOWN is not a synonym for either proof. Collapsing it to a bool is how
    the five copies drifted in the first place."""
    from modules import coverage

    assert coverage.look_verdict({"a"}, None) == coverage.UNKNOWN
    assert coverage.look_verdict(set(), {"modules": {"a": {"status": "complete"}}}) \
        == coverage.UNKNOWN
    assert coverage.look_verdict({"a"}, {"modules": {"a": {"status": "complete"}}}) \
        == coverage.LOOKED
    assert coverage.look_verdict({"a"}, {"modules": {"a": {"status": "skipped"}}}) \
        == coverage.UNSUPPLIED
    assert len({coverage.LOOKED, coverage.UNSUPPLIED, coverage.UNKNOWN}) == 3


# ── a module that ran on half its input ──────────────────────────────────────
#
# `degraded` means the module executed and one of several exports was missing.
# Whether that counts as "looked" depends on what the caller does with the
# answer, and the two answers are deliberately different — see
# modules/coverage.look_verdict. These tests hold BOTH directions, because the
# split is only defensible while each half stays where it was put.

DEGRADED = {"modules": {
    "log_review": {"status": "degraded", "sources_missing": ["security_audit_log"]},
    "user_auth_audit": {"status": "complete", "sources_missing": []},
}}


def test_a_half_fed_module_cannot_support_a_clean_claim():
    """THE WORKED EXAMPLE THE FILE ITSELF USES, which stayed broken until now.

    Drop security_audit_log.csv from an otherwise full upload. `log_review` runs
    degraded; it is the sole feeder of Suspicious User Behaviour, and that domain
    rendered CLEAR — "we looked and found nothing" — about a log nobody supplied.
    """
    from modules import domains

    states = {d["id"]: d["state"]
              for d in domains.roll_up([], coverage=DEGRADED)["domains"]}
    assert states["user_behaviour"] == domains.NOT_SUPPLIED
    # And a domain whose feeder ran COMPLETE is still allowed to be clean.
    assert states["identity"] == domains.CLEAR


def test_the_resolution_guard_still_resolves_for_a_half_fed_module():
    """THE OTHER DIRECTION, AND IT MATTERS AS MUCH. A complete sample_data run
    has eleven degraded modules. Applying the strict rule here would freeze most
    of the backlog open and quietly delete the mitigation journey — a worse
    defect than the one the strict rule fixes, and a much quieter one."""
    from modules.coverage import UNSUPPLIED, look_verdict

    assert look_verdict({"log_review"}, DEGRADED) != UNSUPPLIED
    assert look_verdict({"log_review"}, DEGRADED, require_complete=True) == UNSUPPLIED


def test_the_release_gate_does_not_block_on_a_degraded_module():
    """Same reasoning, sharper consequence: a gate that returns cannot_assess on
    every realistic upload gets switched off wholesale, taking the real signal
    with it."""
    from modules import release_gate

    assert release_gate.coverage_reasons(DEGRADED) == []


def test_a_module_with_no_inputs_at_all_is_not_treated_as_starved():
    """`no_file_inputs` has nothing missing because it needs nothing. It must
    satisfy the strict rule too, or a module that legitimately reads no export
    would permanently report its domain as unsupplied."""
    from modules.coverage import LOOKED, look_verdict

    manifest = {"modules": {"abap_sast": {"status": "no_file_inputs",
                                          "sources_missing": []}}}
    assert look_verdict({"abap_sast"}, manifest, require_complete=True) == LOOKED
