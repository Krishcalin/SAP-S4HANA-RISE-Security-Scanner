"""The fourth state, in the two roll-ups that still had three.

WHAT WAS WRONG
`nist_csf.roll_up` and `fair_cam.classify` took no coverage input at all, so an
assessable CSF Category or a reachable FAIR-CAM control function with no findings
became CLEAR — "we looked and found nothing" — whether or not anything that feeds
it had run. Measured on a `--modules users` scan: **11 of the 22 CSF Categories
and 6 of the 9 control functions rendered the green chip**, including the entire
Detect and Respond half of the control model, on a run that read no log
configuration whatsoever.

`modules/domains.py` had already solved this; these two were the last roll-ups
speaking in three states. The derivation is shared rather than copied a third
time — `coverage.modules_for_categories` — because three copies of "did anything
that could have found something here actually run?" is three chances for one of
them to keep saying CLEAR.

THE FOUR STATES ARE FOUR DIFFERENT SENTENCES
  assessed      we looked and found something
  clear         we looked and found nothing
  not_supplied  we would have looked; the export never arrived   <- THIS RUN
  not_assessed  we do not do this, on any run                    <- THE PRODUCT

The last two are both "no measurement", and they are still not the same: one is
the customer's to act on and one is ours. Collapsing either into `clear` is the
failure the whole three-state discipline exists to prevent.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import fair_cam, nist_csf                            # noqa: E402
from modules.compliance_mapping import ComplianceMapper           # noqa: E402
from modules.coverage import (                                    # noqa: E402
    modules_for_categories, ran_modules,
)

#: One module ran; the other twenty-nine did not. The shape `--modules users`
#: produces, and the shape a customer who uploads one export produces.
USERS_ONLY = {"modules": {"user_auth_audit": {"status": "complete"},
                          "log_review": {"status": "skipped"},
                          "log_monitoring": {"status": "not_run"},
                          "data_protection": {"status": "not_run"}}}

EVERYTHING_RAN = {"modules": {"user_auth_audit": {"status": "complete"},
                              "log_review": {"status": "complete"},
                              "log_monitoring": {"status": "degraded"},
                              "data_protection": {"status": "no_file_inputs"}}}


def _csf_states(findings, coverage=None):
    rolled = nist_csf.roll_up(findings, coverage=coverage)
    return {c["id"]: c["status"] for fn in rolled["functions"] for c in fn["categories"]}


def _cam_states(findings, coverage=None):
    return {f["id"]: f["status"] for f in fair_cam.classify(findings, coverage=coverage)["functions"]}


# ── the shared derivation ────────────────────────────────────────────────────

def test_ran_modules_distinguishes_nothing_ran_from_nobody_checked():
    """None is not an empty set. A caller given None must not report anything as
    unsupplied, because nobody looked at whether it was."""
    assert ran_modules(None) is None
    assert ran_modules({}) is None
    assert ran_modules({"modules": {}}) == set()
    assert ran_modules(EVERYTHING_RAN) == {"user_auth_audit", "log_review",
                                           "log_monitoring", "data_protection"}


def test_a_skipped_or_not_run_module_does_not_count_as_having_run():
    assert ran_modules(USERS_ONLY) == {"user_auth_audit"}


def test_the_category_to_module_map_is_derived_not_declared():
    """A declared table is a second place for the same fact to be true."""
    assert "log_review" in modules_for_categories(["Security Audit Log Review"])
    assert modules_for_categories([]) == set()
    assert modules_for_categories(["Not A Real Category"]) == set()


# ── NIST CSF ─────────────────────────────────────────────────────────────────

def test_without_a_manifest_the_csf_view_behaves_exactly_as_before():
    """No manifest means nobody checked, so no Category may claim its export was
    missing. Passing no coverage must not become a silent new claim either."""
    states = _csf_states([])
    assert "not_supplied" not in set(states.values())
    assert set(states.values()) <= {"clear", "not_assessed"}


def test_a_category_nothing_fed_is_not_clear():
    """THE DEFECT, in one assertion."""
    states = _csf_states([], coverage=USERS_ONLY)
    assert "not_supplied" in set(states.values())
    unsupplied = [cid for cid, s in states.items() if s == "not_supplied"]
    assert len(unsupplied) >= 10, unsupplied


def test_a_category_whose_module_ran_and_found_nothing_is_still_clear():
    """The other direction matters as much: telling a customer they failed to
    send an export they did send is its own false statement."""
    states = _csf_states([], coverage=EVERYTHING_RAN)
    assert "clear" in set(states.values())


def test_the_states_a_product_boundary_produces_are_untouched():
    """Ten Categories describe governance and training outcomes no SAP export can
    answer. That is true on every run and a manifest must not change it."""
    without = _csf_states([])
    with_manifest = _csf_states([], coverage=USERS_ONLY)
    for cid, status in without.items():
        if status == "not_assessed":
            assert with_manifest[cid] == "not_assessed", cid


def test_a_category_with_findings_is_never_downgraded():
    """Evidence beats the manifest. If a finding landed here, we plainly looked —
    whatever the manifest says about the module that produced it."""
    finding = {"check_id": "USR-001", "severity": "HIGH",
               "category": "User & Authorization"}
    states = _csf_states([finding], coverage={"modules": {"x": {"status": "not_run"}}})
    assert "assessed" in set(states.values())


def test_the_function_page_agrees_with_the_function_tile():
    """/csf and /csf/<fn> are the same roll-up. A tile saying "export not
    supplied" over a page saying "no findings" is worse than either alone."""
    rolled = nist_csf.roll_up([], coverage=USERS_ONLY)
    for fn in rolled["functions"]:
        detail = nist_csf.function_detail([], fn["id"], coverage=USERS_ONLY)
        assert detail is not None, fn["id"]
        assert ([c["status"] for c in detail["categories"]]
                == [c["status"] for c in fn["categories"]]), fn["id"]


# ── FAIR-CAM ─────────────────────────────────────────────────────────────────

def test_a_control_function_nothing_fed_is_not_clear():
    states = _cam_states([], coverage=USERS_ONLY)
    assert "not_supplied" in set(states.values())


def test_without_a_manifest_the_control_map_behaves_as_before():
    assert "not_supplied" not in set(_cam_states([]).values())


def test_a_function_no_theme_reaches_stays_not_assessed():
    """A product boundary, not a run outcome."""
    assert fair_cam.UNREACHABLE_FUNCTIONS
    states = _cam_states([], coverage=USERS_ONLY)
    for fid in fair_cam.UNREACHABLE_FUNCTIONS:
        assert states[fid] == "not_assessed", fid


def test_the_unmeasured_function_reports_no_number():
    """0.0 is what an unfed function computes, and 0.0 drawn like a measurement
    says "healthy" about something nothing looked at."""
    result = fair_cam.classify([], coverage=USERS_ONLY)
    for fn in result["functions"]:
        if fn["status"] == "not_supplied":
            assert fn["findings"] == 0.0        # the number exists...
    # ...and the renderers are asserted separately not to print it.


# ── the wiring, at every call site ───────────────────────────────────────────

@pytest.mark.parametrize("needle", [
    "nist_csf.roll_up(findings, coverage=queries.latest_coverage(scope))",
    "coverage=queries.latest_coverage(scope))",
    # Narrowed by landscape as well as by scope: /api/crq/controls pairs this
    # with findings_for_crq(scope, landscape_id), and a manifest spanning every
    # landscape let a module that ran elsewhere vouch for this one.
    "coverage=queries.latest_coverage(scope, landscape_id))",
])
def test_the_server_routes_pass_the_manifest(needle):
    """A roll-up that ACCEPTS a manifest and a route that never passes one is
    exactly the shape of the defect this replaces — /api/domains shipped that way
    for a day."""
    assert needle in (ROOT / "server" / "app.py").read_text(encoding="utf-8")


def test_the_offline_report_passes_the_manifest_it_already_holds():
    source = (ROOT / "modules" / "report_generator.py").read_text(encoding="utf-8")
    assert "nist_csf.roll_up(self.full_findings, coverage=self.coverage)" in source
    assert "fair_cam.classify(self.full_findings, coverage=self.coverage)" in source


def test_neither_printed_table_can_draw_the_unexamined_as_clean():
    """The print side, where a reader cannot hover or click through."""
    source = (ROOT / "modules" / "report_generator.py").read_text(encoding="utf-8")
    assert source.count('"not_supplied"') >= 2
    assert source.count("export not supplied") >= 2


# ── the console must not contradict itself about a Category ──────────────────

# The textual placeholder that stood here has been deleted, as its own docstring
# instructed: frontend/src/routes/CsfFunction.test.tsx renders the four states
# and asserts the sentences a reader actually sees. Keeping both would leave a
# proxy for a behaviour beside the behaviour.


def test_the_console_and_the_report_agree_about_an_unsupplied_category():
    """They disagreed for one run: the page said "Assessed, and this run produced
    no findings", the HTML report said "No module feeding this Category ran".
    Both are generated from the same roll-up."""
    page = (ROOT / "frontend" / "src" / "routes" / "CsfFunction.tsx").read_text(
        encoding="utf-8")
    report = (ROOT / "modules" / "report_generator.py").read_text(encoding="utf-8")
    for artefact in (page, report):
        assert "No module feeding this Category ran" in artefact
