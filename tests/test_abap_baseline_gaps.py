"""The two ABAP Baseline requirements publishing the catalogue exposed.

HOW THEY WERE FOUND. Neither was discovered by review. `docs/CHECKS_REFERENCE.md`
started listing the SAP Security Baseline requirements this catalogue does NOT
address, split by technology, and two of the seventeen turned out to be ABAP —
inside the stack this product is about, rather than Java or HANA which are scope
decisions. That is the whole argument for publishing a catalogue: a gap nobody
can see is a gap nobody closes.

THE INVERSION THIS NEARLY SHIPPED. SAP's `2AOBSCNT.xml` writes its compliant and
noncompliant predicates IDENTICALLY — both `MANDT = '066'` — and puts the entire
semantics in `operator="NOT_EXIST"`. Transcribing the compliant clause at face
value, which is what every other policy in this repository invites, would have
reported every estate that HAS removed client 066 as failing and every estate
that kept it as passing. Exactly backwards, on a check that looks right.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.coverage import all_check_ids                     # noqa: E402
from modules.security_params import SecurityParamAuditor       # noqa: E402
from modules.system_trust import SystemTrustAuditor            # noqa: E402
from server import sapcontent                                  # noqa: E402

ALL_IDS = sorted({c for ids in all_check_ids().values() for c in ids})


def _clients(*numbers):
    return {"client_settings": [{"CLIENT": n} for n in numbers]}


def _run(data):
    return [f for f in SystemTrustAuditor(data, {}, {}).run_all_checks()
            if f["check_id"].startswith("OBSCNT")]


# ═════════════════════════════════════════════════════════════════════════════
#  FILE-A — abap/path_normalization
# ═════════════════════════════════════════════════════════════════════════════

def test_the_parameter_is_now_judged():
    assert "PARAM-abap/path_normalization" in ALL_IDS


def test_the_rule_is_saps_and_is_not_tightened():
    """SAP's predicate is `VALUE != 'off'` — anything but off is compliant.
    Writing `== on` would be stricter than SAP's own baseline and would report a
    compliant system as failing, which is worse than not checking."""
    rule = SecurityParamAuditor.BASELINE["abap/path_normalization"]
    assert rule["op"] == "!="
    assert rule["expected"] == "off"


def test_the_rule_cites_the_policy_it_came_from():
    rule = SecurityParamAuditor.BASELINE["abap/path_normalization"]
    assert any("2AFILE" in r for r in rule["refs"])
    assert any("FILE-A" in r for r in rule["refs"])


def test_it_did_not_go_into_the_ecs_table():
    """SAP Note 3250501 does not mandate this parameter. Putting it in the ECS
    rules would claim a mandate the note does not make."""
    from modules import ecs_baseline
    assert "abap/path_normalization" not in ecs_baseline.parameters()


def test_it_reaches_the_requirement_it_answers():
    assert sapcontent.requirement_for("PARAM-abap/path_normalization") == "FILE-A"


# ═════════════════════════════════════════════════════════════════════════════
#  OBSCNT-A — obsolete clients, and the operator that carries the meaning
# ═════════════════════════════════════════════════════════════════════════════

def test_a_present_obsolete_client_is_the_finding_not_an_absent_one():
    """THE INVERSION. SAP's compliant and noncompliant predicates are identical;
    `operator="NOT_EXIST"` is the whole semantics. Reading the compliant clause
    at face value would flag every estate that has done the right thing."""
    assert [f["check_id"] for f in _run(_clients("066"))] == ["OBSCNT-001"]
    assert _run(_clients("000", "100")) == []


def test_client_001_is_a_question_rather_than_a_defect():
    """SAP's wording differs between the two: 066 "must not exist", 001 "must be
    deleted IF NOT USED". A template client somebody genuinely uses is not a
    finding, and the severity says so."""
    found = _run(_clients("001"))
    assert [f["check_id"] for f in found] == ["OBSCNT-002"]
    assert found[0]["severity"] == "LOW"
    assert "IF IT IS NOT USED" in found[0]["description"]


def test_client_066_outranks_it():
    assert _run(_clients("066"))[0]["severity"] == "MEDIUM"


def test_both_are_raised_when_both_are_present():
    assert {f["check_id"] for f in _run(_clients("066", "001", "100"))} == {
        "OBSCNT-001", "OBSCNT-002"}


def test_an_unpadded_client_number_still_matches():
    """T000 and other exports do not always agree about leading zeros, and a
    set-membership test would miss `1`."""
    assert [f["check_id"] for f in _run(_clients("1"))] == ["OBSCNT-002"]
    assert [f["check_id"] for f in _run(_clients("66"))] == ["OBSCNT-001"]


def test_no_client_export_raises_nothing():
    """Absence is the coverage manifest's to report. Two findings for one absence
    is one too many."""
    assert _run({}) == []
    assert _run({"client_settings": []}) == []


def test_the_findings_carry_saps_operator_so_the_semantics_travel():
    """The next person to read this check should not have to re-derive why the
    predicate looks inverted."""
    found = _run(_clients("066"))[0]
    assert found["details"]["sap_operator"] == "NOT_EXIST"
    assert found["details"]["sap_check_id"] == "OBSCNT-A.1"


def test_they_reach_the_requirement_they_answer():
    for cid in ("OBSCNT-001", "OBSCNT-002"):
        assert sapcontent.requirement_for(cid) == "OBSCNT-A"


def test_the_client_becomes_a_typed_object():
    found = _run(_clients("066"))[0]
    assert found["affected_objects"] == [{"type": "client", "name": "066"}]


# ═════════════════════════════════════════════════════════════════════════════
#  What closing them achieved
# ═════════════════════════════════════════════════════════════════════════════

def test_no_abap_baseline_requirement_is_left_unaddressed():
    """The point of the exercise. What remains unaddressed is Java, HANA and BTP
    — stacks this product does not audit, which is a scope decision rather than
    a gap inside the stack it is about."""
    cov = sapcontent.coverage(ALL_IDS)
    abap = [r["requirement"] for r in cov["not_covered"]
            if r["technology"] == "ABAP"]
    assert abap == [], f"ABAP requirements still unaddressed: {abap}"


def test_the_covered_count_went_up():
    cov = sapcontent.coverage(ALL_IDS)
    assert cov["requirements_covered"] >= 23


def test_the_published_catalogue_reflects_it():
    doc = (ROOT / "docs" / "CHECKS_REFERENCE.md").read_text(encoding="utf-8")
    assert "`FILE-A`" in doc and "`OBSCNT-A`" in doc
    unaddressed = doc.split("does not address", 1)[1].split("## Checks by module", 1)[0]
    assert "| `FILE-A` |" not in unaddressed
    assert "| `OBSCNT-A` |" not in unaddressed


def test_the_operator_trap_is_recorded_where_the_next_transcription_will_look():
    """The Web Dispatcher rules were transcribed before this was understood. None
    of them carries an operator — verified rather than assumed — and the content
    file now says to check the attribute first."""
    import json
    meta = json.loads((ROOT / "data" / "webdisp_baseline.json")
                      .read_text(encoding="utf-8"))["_meta"]
    assert "NOT_EXIST" in meta["the_operator_attribute"]
    assert "verified rather than assumed" in meta["the_operator_attribute"]
