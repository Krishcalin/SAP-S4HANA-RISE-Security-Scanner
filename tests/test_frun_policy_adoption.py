"""Insights adopted from SAP's FRUN CSA policy repository (Apache-2.0).

Four repo-derived changes are held here:

  #1  HOTNEWS-SPAGE-001 — the SAP_BASIS support-package-age check, grounded in
      SAP's own age_of_sap_basis.xml (data/abap_sp_stack_dates.json).
  #3  the range-deferral MEASUREMENT — notes_blocked_only_by_a_range makes the
      cost of not interpreting `between` ranges explicit and small.
  #4  the CI freshness guards exist and cannot be removed silently.
  #5  the baseline-version pin guard — a newer SOS/vX upstream must not age in
      silence behind the pinned version.
"""
from __future__ import annotations

import datetime
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# ═══════════════════════════════════════════════════════════════════════════
#  #1 — SAP_BASIS support-package-age check
# ═══════════════════════════════════════════════════════════════════════════

from modules.sap_hotnews import SapHotNewsAuditor           # noqa: E402


def _age(rel, sp):
    data = {"system_component": [{"COMPONENT": "SAP_BASIS",
                                  "RELEASE": rel, "SP_LEVEL": sp}]}
    a = SapHotNewsAuditor(data, {}, {"deployment_mode": "on_prem", "modules": set()})
    a.check_sp_stack_age()
    return [f["check_id"] for f in a.findings], a.findings


@pytest.mark.parametrize("rel,sp", [("754", "0002"), ("750", "0018"),
                                    ("740", "0011"), ("700", "0037")])
def test_a_legacy_sap_basis_stack_is_flagged_out_of_date(rel, sp):
    """Every SP in SAP's 2015-2020 table is well past the 730-day window in 2026,
    so a system still on 700-754 is a real 'years out of date' finding."""
    ids, findings = _age(rel, sp)
    assert "HOTNEWS-SPAGE-001" in ids
    f = findings[0]
    assert f["severity"] == "MEDIUM"
    assert f["scope"] == "aggregate"


def test_current_s4hana_is_not_assessable_for_age_not_reported_current():
    """SAP's table stops at 754 (June 2020). A 755+ stack cannot be aged from it
    and must be skipped, never reported as current — the coverage manifest carries
    the absence."""
    assert _age("755", "0004")[0] == []
    assert _age("757", "0000")[0] == []


def test_the_check_self_skips_without_a_component_export():
    a = SapHotNewsAuditor({}, {}, {"deployment_mode": "on_prem", "modules": set()})
    a.check_sp_stack_age()
    assert a.findings == []


def test_an_sp_above_the_highest_listed_uses_the_fallback_date():
    """754 lists SP0-2 plus a 'SP > 2' fallback; SP9 must resolve via the fallback,
    not fall through to not-assessable."""
    assert "HOTNEWS-SPAGE-001" in _age("754", "0009")[0]


def test_the_sp_date_table_is_sap_grounded_and_bounded():
    table = json.loads((ROOT / "data" / "abap_sp_stack_dates.json")
                       .read_text(encoding="utf-8"))
    assert table["_meta"]["source"] == "SAP-samples/frun-csa-policies-best-practices"
    assert table["threshold_days"] == 730
    covered = table["_meta"]["releases_covered"]
    assert "754" in covered and "700" in covered
    assert "755" not in covered, "SAP's June-2020 table cannot cover 755+"


def test_the_generator_parses_saps_case_table():
    """A unit test of the extraction on an inline fragment, so the parser is held
    even where a live checkout is not."""
    from tools.build_abap_sp_stack_dates import parse
    xml = (
        "<!-- older than 730 days. Version: 003 -->\n"
        "((COMPONENT = 'SAP_BASIS' and VERSION = '754' and 1 = (CASE WHEN SP &gt; "
        "'0002' THEN ( CASE WHEN DAYS_BETWEEN(TO_DATE('2020-06-30','YYYY-MM-DD'),"
        "CURRENT_DATE) &lt;= 730 THEN 1 ELSE 0 END) ELSE 0 END ) )\n"
        " OR (COMPONENT = 'SAP_BASIS' and VERSION = '754' and 1 = (CASE WHEN SP = "
        "'0000' THEN ( CASE WHEN DAYS_BETWEEN(TO_DATE('2019-09-20','YYYY-MM-DD'),"
        "CURRENT_DATE) &lt;= 730 THEN 1 ELSE 0 END) ELSE 0 END ) )\n")
    parsed = parse(xml)
    assert parsed["threshold_days"] == 730
    assert parsed["policy_version"] == "003"
    rel = parsed["releases"]["754"]
    assert rel["exact"]["0"] == "2019-09-20"
    assert rel["above_sp"] == 2 and rel["above_date"] == "2020-06-30"


# ═══════════════════════════════════════════════════════════════════════════
#  #3 — the range deferral is measured, and #2's UI stores are a recorded decision
# ═══════════════════════════════════════════════════════════════════════════

def test_the_range_deferral_cost_is_measured_and_small():
    """The 1,220 uninterpreted range check-items are mostly the same notes counted
    once per affected release; the distinct-note figure is what actually costs
    coverage, and it must be published so the deferral is honest rather than
    implicit."""
    counts = json.loads((ROOT / "data" / "sap_notes_catalogue.json")
                        .read_text(encoding="utf-8"))["_meta"]["counts"]
    blocked = counts["notes_blocked_only_by_a_range"]
    assert 0 < blocked < counts["check_items_using_an_uninterpreted_range"]
    assert blocked < 100, "distinct notes blocked by a range should be a small set"


def test_the_ui_version_stores_are_a_recorded_deferral_not_an_oversight():
    from tools.build_sap_notes_catalogue import CONFIGSTORE_UNMAPPED
    for store in ("SAPUI5_VERSION", "ABAP_UR_VERSION"):
        assert "deferred" in CONFIGSTORE_UNMAPPED[store].lower(), store


# ═══════════════════════════════════════════════════════════════════════════
#  #5 — the baseline-version pin guard
# ═══════════════════════════════════════════════════════════════════════════

from server import sapcontent                                # noqa: E402


def test_a_newer_upstream_baseline_version_is_detected(tmp_path):
    sos = tmp_path / "BaselinePolicies" / "SOS"
    for v in ("v1.9.3", "v2.2", "v2.4", "v2.6"):
        (sos / v).mkdir(parents=True)
    assert sapcontent.newer_baseline_versions(tmp_path, "v2.4") == ["v2.6"]


def test_no_newer_version_is_the_healthy_state(tmp_path):
    sos = tmp_path / "BaselinePolicies" / "SOS"
    for v in ("v1.9.3", "v2.2", "v2.4"):
        (sos / v).mkdir(parents=True)
    assert sapcontent.newer_baseline_versions(tmp_path, "v2.4") == []


def test_version_ordering_is_numeric_not_lexical():
    # 'v2.10' must sort after 'v2.4', which a string compare gets wrong.
    assert sapcontent._version_key("v2.10") > sapcontent._version_key("v2.4")
    assert sapcontent._version_key("main") is None


def test_the_pin_is_recorded_so_a_bump_is_a_conscious_act():
    assert sapcontent.BASELINE_VERSION == "v2.4"
    # The catalogue that ships was built from the pinned version.
    cat = sapcontent.load_catalogue()
    assert cat["_meta"]["baseline_version"] == sapcontent.BASELINE_VERSION


# ═══════════════════════════════════════════════════════════════════════════
#  #4 — the CI freshness/version guards exist and cannot vanish silently
# ═══════════════════════════════════════════════════════════════════════════

def _workflow() -> str:
    return (ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")


def test_ci_re_derives_both_catalogues_from_the_upstream_repo():
    """Freshness is already guarded: CI clones the repo and fails on drift. These
    are the load-bearing lines; deleting them would let the shipped catalogues age
    silently against SAP's published policies."""
    wf = _workflow()
    assert "frun-csa-policies-best-practices" in wf
    assert "build_catalogue" in wf                      # baseline compare
    assert "tools.build_sap_notes_catalogue --source" in wf and "--check" in wf


def test_ci_guards_the_pinned_baseline_version():
    assert "newer_baseline_versions" in _workflow()


def test_ci_regenerates_and_checks_the_sp_date_table():
    assert "tools.build_abap_sp_stack_dates" in _workflow()
