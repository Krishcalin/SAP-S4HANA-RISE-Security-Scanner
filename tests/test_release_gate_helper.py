"""Release gating, and the three answers it must keep apart.

WHAT THIS MECHANISM IS FOR
Seven of the thirty modules need to branch on a system's release before a check
can be trusted — a parameter introduced in SAP_BASIS 7.40 cannot be missing from
a 7.31 system, it can only be absent because it does not exist there. Without
gating, such a check either fires wrongly on the old system or is dropped
entirely from the product.

THE FAILURE THIS FILE EXISTS TO PREVENT is not "the gate compares wrongly". It is
the gate collapsing three answers into two. `applies` and `not_applicable` are
easy; `unknown` is the one that gets folded into whichever neighbour the author
found convenient, and both foldings are wrong in a way nothing visible reports:

    unknown read as applies         false findings on systems that are correct
    unknown read as not_applicable  the check silently does not run, and a report
                                    over an unmeasured system reads exactly like
                                    a report over a compliant one

So `unknown` is its own verdict, and `skip_for_release` emits a coverage finding
rather than returning silence.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.base_auditor import BaseAuditor                          # noqa: E402
from modules.compliance_mapping import ComplianceMapper              # noqa: E402

#: A REAL, MAPPED category. The helper takes the calling check's own category
#: rather than inventing "Coverage": an unmapped category is silently absent
#: from every compliance panel while the panel still looks complete, which
#: tests/test_compliance_breadth.py exists to prevent — and it caught exactly
#: that in the first draft of this helper.
CATEGORY = "Security Baseline Parameters"


def auditor(components=None):
    data = {}
    if components is not None:
        data["system_component"] = [
            {"COMPONENT": c, "RELEASE": r} for c, r in components.items()]
    return BaseAuditor(data, {})


# --------------------------------------------------------------------------- #
#  Comparison — where a silent bug would live                                 #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("a,b", [
    ("700", "750"), ("740", "750"), ("750", "755"), ("731", "740"),
    ("7.31", "7.40"), ("46C", "700"),
    # S/4HANA year-style releases. A two-character minor slice collapsed these
    # to the same key, so 2021 did not sort above 2020.
    ("1909", "2020"), ("2020", "2021"),
])
def test_releases_order_the_way_sap_means_them(a, b):
    """AS STRINGS THIS IS WRONG AND QUIETLY SO. "750" < "8" lexically, and
    "7.31" > "7.4" — so a gate comparing raw strings would decide a 7.31 system
    is newer than a 7.40 one and run checks that cannot apply to it. Nothing
    would raise; the report would just be wrong."""
    assert BaseAuditor._release_key(a) < BaseAuditor._release_key(b), \
        f"{a} did not order before {b}"


@pytest.mark.parametrize("written", ["750", "7.50", "0750", "7.5"])
def test_the_same_release_written_three_ways_compares_equal(written):
    """SAP writes it all three ways and they are one release. A gate that treated
    them as different would apply on one export of a system and not on another
    export of the SAME system."""
    assert BaseAuditor._release_key(written) == BaseAuditor._release_key("750")


def test_an_unparseable_release_is_not_silently_zero():
    """Returning (0, 0) would make every minimum satisfied — the most permissive
    possible reading of a value we could not understand."""
    assert BaseAuditor._release_key("") is None
    assert BaseAuditor._release_key("unknown") is None


# --------------------------------------------------------------------------- #
#  The three verdicts                                                         #
# --------------------------------------------------------------------------- #

def test_a_new_enough_system_applies():
    a = auditor({"SAP_BASIS": "750"})
    assert a.release_gate(min_release="740") == BaseAuditor.RELEASE_APPLIES


def test_an_older_system_is_not_applicable_rather_than_a_finding():
    """The thing genuinely cannot exist there. Reporting it would be a false
    positive about a system that is correctly configured for what it is."""
    a = auditor({"SAP_BASIS": "731"})
    assert a.release_gate(min_release="740") == BaseAuditor.RELEASE_NOT_APPLICABLE


def test_no_component_export_is_unknown_not_either_of_the_others():
    """THE ONE THAT MATTERS. Neither 'run it anyway' nor 'quietly skip'."""
    assert auditor().release_gate(min_release="740") == BaseAuditor.RELEASE_UNKNOWN
    assert auditor({}).release_gate(min_release="740") == BaseAuditor.RELEASE_UNKNOWN


def test_a_missing_component_is_unknown_not_not_applicable():
    """S4CORE absent from an ECC export does not mean 'this is not S/4HANA and
    therefore the check does not apply' — the export may simply be partial. The
    difference matters: one is a fact about the system, the other about the
    export."""
    a = auditor({"SAP_BASIS": "750"})
    assert a.release_gate(min_release="105", component="S4CORE") == \
        BaseAuditor.RELEASE_UNKNOWN


def test_the_upper_bound_is_exclusive():
    """A check for something removed in 7.54 is release_gate("740", "754"), which
    reads the way SAP documentation does. An inclusive upper bound invites an
    off-by-one that shows up as a check running on exactly the release that
    removed the thing it looks for."""
    a = auditor({"SAP_BASIS": "754"})
    assert a.release_gate("740", "754") == BaseAuditor.RELEASE_NOT_APPLICABLE
    b = auditor({"SAP_BASIS": "753"})
    assert b.release_gate("740", "754") == BaseAuditor.RELEASE_APPLIES


# --------------------------------------------------------------------------- #
#  What the caller does with it                                               #
# --------------------------------------------------------------------------- #

def test_skip_for_release_is_silent_when_the_check_cannot_apply():
    """Nothing to report, so nothing is reported. Noise here would train people
    to ignore the coverage findings that DO matter."""
    a = auditor({"SAP_BASIS": "731"})
    assert a.skip_for_release("PARAM-X", "the X parameter", CATEGORY, "740") is True
    assert a.findings == []


def test_skip_for_release_reports_when_it_could_not_decide():
    """An INFO finding carrying degrades_coverage — the flag --gate reads to
    refuse a green build. A check that could not determine whether it applied did
    not examine this system, and the report must not imply that it did."""
    a = auditor()
    assert a.skip_for_release("PARAM-X", "the X parameter", CATEGORY, "740") is True
    assert len(a.findings) == 1
    f = a.findings[0]
    assert f["check_id"] == "PARAM-X-COVERAGE"
    assert f["details"]["degrades_coverage"] is True
    assert "did NOT run" in f["description"]
    assert "not evidence" in f["description"]
    # It must say how to fix the gap, in the customer's vocabulary.
    assert "CVERS" in f["remediation"] and "system_component.csv" in f["remediation"]


def test_skip_for_release_lets_an_applicable_check_run():
    a = auditor({"SAP_BASIS": "750"})
    assert a.skip_for_release("PARAM-X", "the X parameter", CATEGORY, "740") is False
    assert a.findings == []


def test_the_coverage_finding_arms_the_release_gate():
    """End to end with the real gate: an undecidable check must stop --gate
    returning green, by the same mechanism the ABAP coverage findings use."""
    from modules import release_gate

    a = auditor()
    a.skip_for_release("PARAM-X", "the X parameter", CATEGORY, "740")
    degraded = [f for f in a.findings
                if (f.get("details") or {}).get("degrades_coverage")]
    result = release_gate.evaluate(a.findings, degraded=bool(degraded))
    assert result.exit_code == release_gate.EXIT_CANNOT_ASSESS


# --------------------------------------------------------------------------- #
#  The fixtures                                                               #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("fixture,component,release", [
    ("sample_data", "S4CORE", "105"),
    ("sample_data_ecc", "SAP_APPL", "618"),
])
def test_the_fixtures_carry_a_component_list(fixture, component, release):
    """The ECC fixture is an ECC stack and the full sample an S/4HANA one. If
    they were identical the gate could not be exercised in both directions."""
    import contextlib, io
    from modules.data_loader import DataLoader
    d = ROOT / fixture
    if not d.is_dir():
        pytest.skip(f"{fixture} not present")
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(d).load_all()
    rows = data.get("system_component")
    assert rows, f"{fixture} has no component list"
    assert {r["COMPONENT"]: r["RELEASE"] for r in rows}.get(component) == release


def test_the_ecc_fixture_is_not_s4hana():
    """S4CORE in the ECC fixture would make it not an ECC fixture, and every
    release-gated check measured against it would be measuring the wrong estate."""
    import contextlib, io
    from modules.data_loader import DataLoader
    d = ROOT / "sample_data_ecc"
    if not d.is_dir():
        pytest.skip("sample_data_ecc not present")
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(d).load_all()
    names = {r["COMPONENT"] for r in data.get("system_component") or []}
    assert "S4CORE" not in names
    assert "SAP_BASIS" in names


# --------------------------------------------------------------------------- #
#  Scope note                                                                 #
# --------------------------------------------------------------------------- #

def test_no_module_yet_asserts_a_release_applicability_fact():
    """DELIBERATE, AND THE BOUNDARY OF THIS PHASE.

    Phase 2 ships the MECHANISM. Saying "this check applies from SAP_BASIS 7.40"
    is a claim about SAP that has to be verified against SAP Help or the Security
    Baseline before it ships — this repository treats an unverified SAP
    identifier as a defect, and a wrong release boundary silently disables a real
    check on every system below it.

    So no caller uses `skip_for_release` yet. When Phase 3 adds them, this test
    should be replaced by ones asserting each boundary against its source.
    """
    import ast
    callers = []
    for path in (ROOT / "modules").glob("*.py"):
        if path.stem == "base_auditor":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("skip_for_release", "release_gate")):
                callers.append(f"{path.stem}:{node.lineno}")
    assert not callers, (
        "a module now gates on release: " + ", ".join(callers) + ". That is the "
        "intended next step — replace this test with ones that verify each "
        "release boundary against SAP Help or the SAP Security Baseline.")


def test_the_coverage_finding_lands_in_a_mapped_category():
    """An unmapped category does not raise and does not warn — the finding is
    reported normally and is simply absent from every compliance panel, while the
    panel still looks complete. The first draft of this helper used a category
    called "Coverage" and did exactly that."""
    a = auditor()
    a.skip_for_release("PARAM-X", "the X parameter", CATEGORY, "740")
    assert a.findings[0]["category"] == CATEGORY
    assert CATEGORY in ComplianceMapper.CATEGORY_THEMES, \
        "the coverage finding would vanish from every compliance panel"
