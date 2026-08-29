"""The shipped ruleset now lives in data/, and must survive the move intact.

WHY IT MOVED

It was a 1534-line literal inside modules/access_risk_analysis.py, which was
about 60% of that module. The argument for extracting it is the one that moved
the finding guidance into data/finding_details.json: correcting a rule should be
an edit to a content file the person who knows SAP best can make, not a change
to a Python module.

That matters more here than it did there. Most of these rules were written from
general SAP knowledge rather than object-by-object verification, and each says
so in `provenance`. The fix for unverified provenance is review by somebody who
knows the objects — and requiring that person to edit Python is what stops it
happening.

WHAT THESE TESTS GUARD

  the content   99 risks, unique ids, and every one passing the same structural
                validator that guards a CUSTOMER's ruleset. A shipped rule that
                could never fire would be the exact defect SODCOV-008 reports in
                somebody else's file.
  the failure   a missing or malformed file must RAISE. An empty ruleset does
                not fail — it reports zero conflicts on every estate for ever,
                and zero conflicts is what a working control looks like.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.access_risk_analysis import (                     # noqa: E402
    AccessRiskAnalysisAuditor as ARA, _load_shipped_ruleset)
from modules.ruleset_coverage import RulesetCoverageAuditor    # noqa: E402

DATA = ROOT / "data" / "sod_ruleset.json"


# ── the content survived the move ──────────────────────────────────────────

def test_the_shipped_file_is_the_ruleset_the_class_exposes():
    assert ARA.RULESET == json.loads(DATA.read_text(encoding="utf-8"))["risks"]


def test_the_library_still_holds_ninetynine_risks():
    assert len(ARA.RULESET) == 99


def test_risk_ids_are_unique():
    ids = [r["risk_id"] for r in ARA.RULESET]
    assert len(ids) == len(set(ids))


def test_the_declared_count_matches_the_rules_present():
    """The _meta block is read by people, so it must not drift from the file."""
    payload = json.loads(DATA.read_text(encoding="utf-8"))
    assert payload["_meta"]["risk_count"] == len(payload["risks"])


def test_every_shipped_rule_passes_the_validator_we_apply_to_customers():
    """SODCOV-008 reports a customer's rule that can never fire, or that fires
    for everybody. Ours must not do either — holding our own ruleset to a lower
    standard than the one we report on would be indefensible."""
    bad = [(r["risk_id"], RulesetCoverageAuditor._rule_defect(r))
           for r in ARA.RULESET if RulesetCoverageAuditor._rule_defect(r)]
    assert not bad, bad


def test_every_rule_carries_its_reasoning_and_provenance():
    for r in ARA.RULESET:
        assert r.get("rationale"), r["risk_id"]
        assert r.get("references"), r["risk_id"]


# ── the failure mode ───────────────────────────────────────────────────────

def test_a_missing_ruleset_file_raises_rather_than_loading_empty(tmp_path):
    """THE test. An empty ruleset does not error, it reports zero conflicts on
    every estate — indistinguishable from a clean one. Refusing to start is the
    only honest response to a packaging mistake."""
    with pytest.raises(RuntimeError) as e:
        _load_shipped_ruleset(tmp_path / "absent.json")
    assert "zero conflicts" in str(e.value)


def test_a_ruleset_file_with_no_risks_raises(tmp_path):
    p = tmp_path / "empty.json"
    p.write_text(json.dumps({"_meta": {}, "risks": []}), encoding="utf-8")
    with pytest.raises(RuntimeError) as e:
        _load_shipped_ruleset(p)
    assert "no 'risks' list" in str(e.value)


def test_malformed_json_raises(tmp_path):
    p = tmp_path / "broken.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(RuntimeError):
        _load_shipped_ruleset(p)


def test_a_bare_list_is_accepted_as_well_as_the_wrapped_form(tmp_path):
    """So a hand-edited file that drops the _meta wrapper still works rather
    than silently producing nothing."""
    p = tmp_path / "bare.json"
    p.write_text(json.dumps(ARA.RULESET[:2]), encoding="utf-8")
    assert len(_load_shipped_ruleset(p)) == 2
