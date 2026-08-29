"""The ECC coverage measurement, locked so the published number cannot drift.

`docs/ECC_COVERAGE.md` publishes a claim — fourteen of thirty auditors produce
identical findings on an ECC export — and a published number that nothing checks
is a number that quietly stops being true. These tests re-run the measurement and
fail if the answer moves, which is the point: if a change genuinely improves ECC
coverage the number SHOULD move, and somebody should have to update the document
that states it in the same commit.

They also guard the two things that make the measurement mean anything: that the
fixture's tiers were fixed independently of the result, and that every auditor is
visible to the coverage manifest.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server import coverage                                          # noqa: E402
from tests import measure_ecc_coverage as measure                    # noqa: E402
from tests.ecc_fixture_tiers import (                                # noqa: E402
    CANNOT_EXIST_ON_ECC, OPTIONAL_TOOLING)

FIXTURE = ROOT / "sample_data_ecc"
pytestmark = pytest.mark.skipif(not FIXTURE.is_dir(),
                                reason="sample_data_ecc/ is not present")


@pytest.fixture(scope="module")
def measured():
    _, ecc = measure.run("sample_data_ecc")
    _, full = measure.run("sample_data")
    return {r["module"]: r for r in ecc}, {r["module"]: r for r in full}


# --------------------------------------------------------------------------- #
#  The published claim                                                        #
# --------------------------------------------------------------------------- #

def test_fourteen_auditors_are_identical_on_ecc(measured):
    """THE NUMBER docs/ECC_COVERAGE.md PUBLISHES.

    "Identical to the full sample" is the operational meaning of the plan's
    estimate that fourteen modules "run on an ECC export with no code change".
    Measured against the full-data control rather than asserted: without the
    control, "this module produced 6 findings" says nothing about whether 6 is
    all of them.

    IT MOVED 15 -> 14, AND DOWNWARD WAS THE IMPROVEMENT. `sap_hotnews` left the
    identical set when its exposure checks began reading the installed component
    release: the ECC fixture is SAP_BASIS 750 with no S4CORE, the full sample is
    755 with S4CORE 105, so the two systems now get different — correct — answers.
    A module that returns the same findings whatever release it is pointed at is
    identical for the least interesting reason there is.

    IT MOVED 15 -> 14 AGAIN, FOR THE SAME SHAPE OF REASON. `ruleset_coverage`
    was ECC-identical by construction while it read AGR_1251 and nothing else.
    It now also measures the Fiori surface, and the ECC fixture has no Fiori or
    OData export because ECC has no launchpad to publish one — so the S/4 sample
    gets a Fiori coverage finding and the ECC fixture correctly gets none. The
    module became LESS parity-clean by becoming more honest, which is the trade
    this file exists to make visible rather than to prevent.
    """
    ecc, full = measured
    identical = [m for m, r in ecc.items()
                 if r["findings"] > 0 and r["findings"] == full[m]["findings"]]
    assert len(identical) == 14, (
        f"ECC parity moved to {len(identical)} of {len(ecc)}. If that is an "
        f"improvement, "
        f"say so and update docs/ECC_COVERAGE.md in this commit — a published "
        f"number nothing checks stops being true quietly.\n"
        f"identical: {sorted(identical)}")


def test_twentyfive_auditors_produce_something_on_ecc(measured):
    """The other honest number. Seven modules run degraded and are still worth
    running, which the parity count alone hides."""
    ecc, _ = measured
    producing = [m for m, r in ecc.items() if r["findings"] > 0]
    assert len(producing) == 25, \
        f"moved to {len(producing)} of 32: {sorted(producing)}"


def test_no_auditor_errors_on_the_ecc_fixture(measured):
    """A module that RAISES on a legitimate ECC export is a defect, not a
    coverage gap — and the runner catches and skips it, so the customer's report
    would simply be missing that module's findings with nothing saying why."""
    ecc, _ = measured
    broken = {m: r["error"] for m, r in ecc.items() if r["error"]}
    assert not broken, f"auditors raised on the ECC fixture: {broken}"


# --------------------------------------------------------------------------- #
#  What makes the measurement trustworthy                                     #
# --------------------------------------------------------------------------- #

def test_every_auditor_is_visible_to_the_coverage_manifest():
    """FOUR WERE NOT, AND THAT IS WHY THIS TEST EXISTS.

    `user_auth_audit`, `ecs_config_items`, `code_inventory_report` and
    `abap_sast` read their data through an accessor, a class constant or
    `(self.data or {}).get(...)`, so the extractor — which only recognised a
    literal `self.data.get("name")` — produced no entry for them at all. The
    manifest whose job is to state what was covered said nothing about the module
    that audits users, profiles and roles.
    """
    import ast
    auditors = set()
    for path in (ROOT / "modules").glob("*.py"):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and any(
                    getattr(b, "id", getattr(b, "attr", "")) == "BaseAuditor"
                    for b in node.bases):
                auditors.add(path.stem)

    mapped = set(coverage.module_sources())
    invisible = sorted(auditors - mapped)
    assert not invisible, (
        f"these auditors have no coverage entry, so the manifest says nothing "
        f"about them: {invisible}")
    # 34 since `cloudalm_verdicts` — the Cloud ALM CSA verdict path — was added
    # beside the existing store importer. The number is asserted rather than
    # derived on purpose: a new auditor should be a deliberate act, and this is
    # the line that makes somebody say so.
    assert len(auditors) == 37, f"auditor count moved to {len(auditors)}"


def test_a_required_source_is_always_one_the_loader_knows():
    """The accessor analysis collects literals passed to data-reading helpers,
    and `user_auth_audit` passes "DDIC" — a standard SAP user name — to one. Left
    unfiltered it became a required source no customer could supply, so the
    module read as permanently degraded. Over-reporting requirements is the more
    dangerous direction: it manufactures coverage gaps that are not real."""
    known = set(coverage.all_logical_sources())
    # ...OR A DECLARED NON-FILE INPUT. `abap_sast` reads a DIRECTORY named by
    # --abap-src (`SOURCE_KEY = "abap_source_dir"`), which is a real input and
    # deliberately not one of the loader's file sources — putting it in
    # all_logical_sources() would move the "N of 123 sources supplied" figure a
    # customer is measured against, for a directory nobody asked them to send.
    #
    # The guard this test exists for is unchanged: a literal that is NEITHER a
    # loader source NOR a declared SOURCE_KEY — "DDIC", the case that started it
    # — still fails here.
    import ast

    declared = set()
    for path in sorted((ROOT / "modules").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
        declared |= coverage._source_key_attributes(tree)
    allowed = known | declared
    for module, needs in coverage.module_sources().items():
        unknown = sorted(set(needs) - allowed)
        assert not unknown, f"{module} requires sources nothing can supply: {unknown}"


def test_a_module_with_no_file_inputs_is_not_reported_as_skipped():
    """`abap_sast` reads an abapGit directory given with --abap-src, which is not
    one of the loader's logical sources. Calling that "skipped" tells a customer
    they forgot an export that does not exist.

    THE STATUS MOVED, THE RULE DID NOT. It used to be `no_file_inputs` — which
    also meant "counts as having looked", so Custom Code Security could never
    report NOT_SUPPLIED and the resolution guard could never withhold one of its
    findings. It is now `not_requested`: still not "skipped", still not arming
    the release gate, but outside RAN_STATUSES so the claim-side roll-ups can
    tell the truth about 133 rules nobody was asked to run.
    """
    from modules.data_loader import DataLoader
    import contextlib, io
    from modules import release_gate
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(FIXTURE).load_all()
    manifest = coverage.build_manifest(data)
    status = manifest["modules"]["abap_sast"]["status"]
    assert status == "not_requested"
    assert status != "skipped", "a customer would be told they forgot an export"
    assert release_gate.coverage_reasons(
        {"modules": {"abap_sast": {"status": status}}}) == [],         "not being asked to scan code must not block a build"


# --------------------------------------------------------------------------- #
#  The fixture itself                                                         #
# --------------------------------------------------------------------------- #

def test_the_fixture_holds_no_source_that_cannot_exist_on_ecc():
    """The deliberate absences the plan asks for. A HANA or BTP file appearing in
    here would inflate ECC coverage with sources no ECC estate has."""
    from modules.data_loader import DataLoader
    present = {p.name for p in FIXTURE.iterdir() if p.is_file()}
    for logical in CANNOT_EXIST_ON_ECC:
        for filename in DataLoader.FILE_MAP.get(logical, []):
            assert filename not in present, (
                f"{filename} is in the ECC fixture, but {logical} cannot exist "
                f"on ECC — see tests/ecc_fixture_tiers.py")


def test_the_tiers_are_disjoint_and_cover_only_known_sources():
    """A source in both tiers, or in neither list but assumed absent, would make
    the published Tier A/B/C counts wrong."""
    from modules.data_loader import DataLoader
    known = set(DataLoader.FILE_MAP)
    overlap = CANNOT_EXIST_ON_ECC & OPTIONAL_TOOLING
    assert not overlap, f"a source is in both tiers: {sorted(overlap)}"
    for name, tier in (("CANNOT_EXIST_ON_ECC", CANNOT_EXIST_ON_ECC),
                       ("OPTIONAL_TOOLING", OPTIONAL_TOOLING)):
        stray = sorted(tier - known)
        assert not stray, f"{name} names sources the loader does not know: {stray}"


def test_the_published_document_states_the_number_it_measured():
    """The document and the test must agree. If one is edited without the other,
    the repository publishes a claim its own suite contradicts."""
    doc = (ROOT / "docs" / "ECC_COVERAGE.md").read_text(encoding="utf-8")
    assert "| **14** |" in doc, \
        "docs/ECC_COVERAGE.md no longer states 14; update it and the test together"
    assert "**25**" in doc
