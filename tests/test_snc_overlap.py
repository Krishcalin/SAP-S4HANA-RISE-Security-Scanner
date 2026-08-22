"""One SNC defect, one finding — across three modules.

WHAT WAS WRONG
--------------
Three modules could each report the same SNC problem, and on one export with
``snc/enable = 0`` all three did:

    snc_posture      CRYPTO-SNCECS-001   HIGH   SNC is not enabled
    crypto_posture   CRYPTO-SNC-001      HIGH   SNC is disabled
    baseline_params  BASELINE-003        HIGH   SNC accepts insecure connections

One defect, three findings — priced three times by `modules/fair_adapter.py`, worked
three times in the remediation queue and read three times by whoever gets the
report.

`modules/snc_posture.py` owns the family: it is the only one of the three that
models all eighteen ``snc/*`` parameters together, takes each compliant value from
SAP Note 3250501 instead of from the parameter's name, and knows that with the
master switch off every dependent setting is moot.

THE THREE PROPERTIES ASSERTED HERE
----------------------------------
  * the duplicate is gone when all three modules run;
  * the shallower checks still fire when the owner is NOT in the run — losing the
    coverage would be a worse defect than the duplicate, and deferring on the
    PRESENCE of the owner's input data instead of on the owner RUNNING is exactly
    how `--modules iam` once produced no SoD findings at all;
  * the stand-down is stated. A silent one is indistinguishable from a clean bill
    of health.

The negative control runs through the whole file: a correctly-configured system
must produce ZERO findings from all three modules, deferral notes included.
"""
from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import snc_posture                                     # noqa: E402
from modules.baseline_params import BaselineParamAuditor            # noqa: E402
from modules.crypto_posture import CryptoPostureAuditor             # noqa: E402
from modules.snc_posture import (                                   # noqa: E402
    SncPostureAuditor,
    _template_fragments,
    load_ecs_baseline,
    snc_family,
)
from server.enrich import team_for                                  # noqa: E402

BASELINE = load_ecs_baseline()
SPEC = snc_family(BASELINE)

#: The two notes this change introduces, and the module each belongs to.
DEFERRAL_IDS = {"CRYPTO-SNC-DEFERRED": "crypto_posture.py",
                "BASELINE-SNC-DEFERRED": "baseline_params.py"}


# --------------------------------------------------------------------------- #
#  Fixtures built from the note extract, not typed                            #
# --------------------------------------------------------------------------- #

def _substituted(template: str) -> str:
    """A realistic running value for one of the note's templated parameters."""
    if "<" in template and ">" in template:
        concrete = re.sub(r"<SID>", "PRD", template)
        concrete = re.sub(r"<CID>", "100", concrete)
        concrete = re.sub(r"<[^>]+>", "X", concrete)
        return concrete.replace(".FQDN", ".prd.customer.example.com")
    return ("/usr/sap/PRD/SYS/exe/uc/linuxx86_64/lib"
            + "".join(_template_fragments(template)) + ".so")


def compliant(**overrides: str) -> dict:
    """Every snc parameter at the ECS standard the note states."""
    values = {}
    for name, spec in SPEC.items():
        mandated = str(spec.get("ecs", ""))
        templated = "$(" in mandated or ("<" in mandated and ">" in mandated)
        values[name] = _substituted(mandated) if templated else mandated
    values.update(overrides)
    return values


def export(values: dict) -> dict:
    return {"security_params": [{"NAME": name, "VALUE": value}
                                for name, value in values.items()]}


def ctx(*modules: str, mode: str = "on_prem") -> dict:
    return {"modules": set(modules), "deployment_mode": mode}


def run_all(data: dict, run_context, overrides=None) -> list:
    """Every finding the three modules produce over one export."""
    out = []
    for cls in (SncPostureAuditor, CryptoPostureAuditor, BaselineParamAuditor):
        out += cls(dict(data), overrides or {}, run_context).run_all_checks() or []
    return out


def run_one(cls, data: dict, run_context, overrides=None) -> list:
    return cls(dict(data), overrides or {}, run_context).run_all_checks() or []


def ids(findings) -> set:
    return {f["check_id"] for f in findings}


def defects(findings) -> set:
    """The findings that assert a defect. A coverage note is not one."""
    return {f["check_id"] for f in findings if f["severity"] != "INFO"}


#: The export the problem was measured on.
SNC_OFF = export(compliant(**{"snc/enable": "0"}))

ALL_THREE = ctx("snc", "crypto", "baseline")


def test_the_note_extract_is_actually_present():
    """Everything here would pass vacuously against an empty baseline."""
    assert len(SPEC) >= 17, f"only {len(SPEC)} snc parameters loaded from the extract"


# --------------------------------------------------------------------------- #
#  THE REGRESSION                                                             #
# --------------------------------------------------------------------------- #

def test_snc_switched_off_is_reported_exactly_once():
    """THE measured defect: one problem, three findings.

    The owner's finding is the one that survives, because it is the only one that
    also says the rest of the family is moot rather than raising it separately.
    """
    found = run_all(SNC_OFF, ALL_THREE)
    assert defects(found) == {"CRYPTO-SNCECS-001"}, \
        sorted((f["check_id"], f["severity"], f["title"]) for f in found)


def test_the_duplicate_is_gone_in_the_estate_the_product_specialises_in():
    """The same export read as a RISE tenant. `BASELINE-003` was already silent
    there through the ECS oracle; this asserts the deferral did not undo that and
    that crypto_posture no longer speaks over the owner either."""
    found = run_all(SNC_OFF, ctx("snc", "crypto", "baseline", mode="rise_pce"))
    assert defects(found) == {"CRYPTO-SNCECS-001"}, sorted(ids(found))


def test_the_server_run_context_actually_triggers_the_deferral():
    """The fix is inert unless callers pass run_context. The server runs every
    auditor, so the owner is always present — but it must be TOLD, not left to
    infer it."""
    from server.ingest import RUN_CONTEXT
    assert "snc" in RUN_CONTEXT["modules"]
    assert defects(run_all(SNC_OFF, RUN_CONTEXT)) == {"CRYPTO-SNCECS-001"}


# --------------------------------------------------------------------------- #
#  COVERAGE MUST SURVIVE THE FIX                                              #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("cls,expected", [
    (CryptoPostureAuditor, "CRYPTO-SNC-001"),
    (BaselineParamAuditor, "BASELINE-003"),
])
def test_the_shallow_check_still_fires_when_the_owner_is_not_in_the_run(cls, expected):
    """THE regression test for the fix itself. `--modules crypto` does not run the
    SNC posture module, and the SNC problem must not vanish with it."""
    key = "crypto" if cls is CryptoPostureAuditor else "baseline"
    found = run_one(cls, SNC_OFF, ctx(key))
    assert expected in ids(found), sorted(ids(found))
    assert not (ids(found) & set(DEFERRAL_IDS)), "stood down with nobody to stand down to"


@pytest.mark.parametrize("cls,expected", [
    (CryptoPostureAuditor, "CRYPTO-SNC-001"),
    (BaselineParamAuditor, "BASELINE-003"),
])
def test_deferring_on_data_presence_alone_is_the_bug_not_the_fix(cls, expected):
    """The trap `BaseAuditor.run_context` documents, applied here.

    This export carries every parameter the owner needs — its input data is fully
    present — and the owner is still not in the run. Standing down on the data
    would silently drop the whole SNC reading, which is precisely what
    `--modules iam` did to SoD analysis.
    """
    assert expected in ids(run_one(cls, SNC_OFF, ctx("crypto", "baseline")))


@pytest.mark.parametrize("cls,expected", [
    (CryptoPostureAuditor, "CRYPTO-SNC-001"),
    (BaselineParamAuditor, "BASELINE-003"),
])
def test_a_caller_that_does_not_say_keeps_the_historical_behaviour(cls, expected):
    """No run_context means the caller did not tell us. Guessing that the owner is
    running would change behaviour underneath every caller that predates this."""
    assert expected in ids(run_one(cls, SNC_OFF, None))


@pytest.mark.parametrize("cls,expected", [
    (CryptoPostureAuditor, "CRYPTO-SNC-001"),
    (BaselineParamAuditor, "BASELINE-003"),
])
def test_no_baseline_extract_means_the_owner_is_silent_so_nobody_defers(cls, expected):
    """The owner is in the run and can say nothing: with no note extract it has no
    mandated values and returns nothing at all. Running is not the same as able to
    answer, and standing down here would lose the family entirely."""
    empty = {"ecs_baseline": {}}
    assert run_one(SncPostureAuditor, SNC_OFF, ALL_THREE, empty) == []
    assert expected in ids(run_one(cls, SNC_OFF, ALL_THREE, empty))


def test_an_on_premise_verdict_the_owner_calls_compliant_is_not_deferred():
    """THE direction this must not over-reach in.

    ``snc/accept_insecure_gui = 1`` is the ECS STANDARD, so the owner is silent
    about it — correctly. On classic on-premise ABAP the stricter reading is the
    right one, and deferring a parameter the owner judged compliant would delete a
    genuine finding rather than a duplicate.
    """
    data = export(compliant())          # switch on, everything at the ECS standard
    found = run_all(data, ALL_THREE)    # deployment defaults to on_prem
    assert defects(found) == {"BASELINE-003"}, sorted(ids(found))
    assert not (ids(found) & set(DEFERRAL_IDS)), \
        "a parameter the owner never reports was recorded as deferred"


def test_the_owner_does_not_defer_the_family_it_cannot_see():
    """`snc_config.csv` is a different export, and the owner reads only
    `security_params`. Standing down over evidence it never looked at would be the
    same lost coverage in a subtler place."""
    data = {"snc_config": [{"PARAMETER": "snc/enable", "VALUE": "0"}]}
    found = run_one(CryptoPostureAuditor, data, ALL_THREE)
    assert "CRYPTO-SNC-001" in ids(found)


def test_the_dedicated_export_defers_only_where_the_owner_reports_the_same_parameter():
    """With both exports present the owner IS reporting snc/enable, so repeating it
    from `snc_config` is the duplicate again."""
    data = dict(SNC_OFF)
    data["snc_config"] = [{"PARAMETER": "snc/enable", "VALUE": "0"}]
    found = run_one(CryptoPostureAuditor, data, ALL_THREE)
    assert "CRYPTO-SNC-001" not in ids(found)
    assert "CRYPTO-SNC-DEFERRED" in ids(found)


# --------------------------------------------------------------------------- #
#  THE STAND-DOWN IS STATED                                                   #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("check_id", sorted(DEFERRAL_IDS))
def test_the_deferral_says_so_and_points_at_the_answer(check_id):
    """A silent stand-down reads exactly like a clean result. Each note has to say
    that it withheld something and where the verdict actually is."""
    note = [f for f in run_all(SNC_OFF, ALL_THREE) if f["check_id"] == check_id]
    assert len(note) == 1, "the stand-down was silent"
    note = note[0]
    assert note["severity"] == "INFO", "a coverage note must not read as a defect"
    assert "CRYPTO-SNCECS-" in note["description"], \
        "the note does not say where the answer is"
    assert note["affected_items"], "the note does not say what was withheld"
    assert not note.get("affected_objects"), \
        "a note that asserts no defect must not put objects in the graph"


def test_the_baseline_note_explains_that_the_family_is_moot_not_merely_moved():
    """With the switch off these settings cannot take effect at all. That is the
    reason they are not raised, and it is a different reason from 'somebody else is
    reporting them', so the note has to distinguish the two."""
    note = [f for f in run_one(BaselineParamAuditor, SNC_OFF, ALL_THREE)
            if f["check_id"] == "BASELINE-SNC-DEFERRED"][0]
    assert "cannot take effect" in note["description"]


def test_a_partial_deferral_still_raises_the_parameters_nobody_took():
    """The mixed case. ``snc/accept_insecure_cpic = u`` deviates from the note, so
    the owner reports it; ``snc/accept_insecure_gui = 1`` is the ECS standard, so
    the owner is silent and the on-premise reading of it is still ours."""
    data = export(compliant(**{"snc/accept_insecure_cpic": "u"}))
    found = run_one(BaselineParamAuditor, data, ALL_THREE)
    assert {"BASELINE-003", "BASELINE-SNC-DEFERRED"} <= ids(found)
    raised = [f for f in found if f["check_id"] == "BASELINE-003"][0]
    assert not any("cpic" in item for item in raised["affected_items"]), \
        "a parameter handed to the owner was reported here as well"
    withheld = [f for f in found if f["check_id"] == "BASELINE-SNC-DEFERRED"][0]
    assert any("cpic" in item for item in withheld["affected_items"])
    # And the owner really is reporting it, so nothing fell between the two.
    assert "CRYPTO-SNCECS-002" in ids(run_one(SncPostureAuditor, data, ALL_THREE))


# --------------------------------------------------------------------------- #
#  THE NEGATIVE CONTROL                                                       #
# --------------------------------------------------------------------------- #

def test_a_compliant_ecs_system_produces_nothing_from_any_of_the_three():
    """THE EXIT CRITERION. A rule that also fires on correct configuration is worse
    than no rule, and a coverage note on a clean system is the same mistake wearing
    an INFO badge."""
    found = run_all(export(compliant()), ctx("snc", "crypto", "baseline",
                                             mode="rise_pce"))
    assert found == [], [(f["check_id"], f["title"]) for f in found]


def test_no_deferral_note_when_the_shallow_check_had_nothing_to_say():
    """The owner is running and the export is clean. Nothing was withheld, so
    announcing a stand-down would be noise in every clean report."""
    found = run_all(export(compliant()), ctx("snc", "crypto", "baseline",
                                             mode="rise_pce"))
    assert not (ids(found) & set(DEFERRAL_IDS))


#: Spellings of an ENABLED switch that `crypto_posture` reads as disabled — its
#: comparison is case-sensitive against ("1", "TRUE", "YES") — and that the owner
#: folds to the mandated 1 through `snc_posture._BOOLEAN_SPELLINGS`. That table
#: exists because real exports produce these, so these are loadable exports and not
#: hypotheticals.
SWITCH_ON_SPELLED_OTHERWISE = ["TRUE", "true", "True", "YES", "yes", "on", "X", "x"]


@pytest.mark.parametrize("spelling", SWITCH_ON_SPELLED_OTHERWISE)
def test_no_deferral_note_when_only_this_modules_own_reading_was_wrong(spelling):
    """A stand-down announced on a system the owner judges CORRECT.

    ``snc/enable = true`` is enabled. `crypto_posture` compares case-sensitively and
    reads it as disabled, so "would this module have fired?" is the wrong question to
    hang the note on: it produced an INFO coverage note claiming a withheld verdict,
    and pointed the reader at CRYPTO-SNCECS-* findings that do not exist, on a report
    with nothing wrong in it. A coverage note on correct, present data is a false
    positive like any other.
    """
    data = export(compliant(**{"snc/enable": spelling}))
    found = run_all(data, ctx("snc", "crypto", "baseline", mode="rise_pce"))
    assert found == [], [(f["check_id"], f["title"]) for f in found]


@pytest.mark.parametrize("spelling", SWITCH_ON_SPELLED_OTHERWISE)
def test_the_owner_still_reads_those_spellings_as_the_mandated_value(spelling):
    """The other half of the pair: the silence above is the owner agreeing the
    system is right, not the owner having been skipped."""
    data = export(compliant(**{"snc/enable": spelling}))
    assert run_one(SncPostureAuditor, data, ALL_THREE) == []


def test_a_stand_down_is_only_announced_where_the_owner_actually_speaks():
    """The invariant behind the note, stated directly.

    Whenever a shallow module says it withheld a reading, the owner has to be
    producing a CRYPTO-SNCECS-* finding in the same run — including the coverage one.
    A note that points at an answer nobody gave is worse than no note.
    """
    for enable in ["0", "", "2", "1", *SWITCH_ON_SPELLED_OTHERWISE]:
        for qop in ["1", "3", "AUTHENTICATION_ONLY"]:
            data = export(compliant(**{"snc/enable": enable,
                                       "snc/data_protection/min": qop}))
            shallow = (run_one(CryptoPostureAuditor, data, ALL_THREE)
                       + run_one(BaselineParamAuditor, data, ALL_THREE))
            if not (ids(shallow) & set(DEFERRAL_IDS)):
                continue
            owner = ids(run_one(SncPostureAuditor, data, ALL_THREE))
            assert any(c.startswith("CRYPTO-SNCECS-") for c in owner), \
                (enable, qop, sorted(ids(shallow)), sorted(owner))


# --------------------------------------------------------------------------- #
#  Thin, absent and malformed input                                           #
# --------------------------------------------------------------------------- #

#: Inputs carrying no SNC evidence at all — nothing to find, nothing to defer.
NOTHING_TO_SAY = [
    {},
    {"security_params": []},
    {"security_params": None},
    {"security_params": [{}]},
    {"security_params": [{"VALUE": "0"}]},
    {"security_params": [{"NAME": "login/min_password_lng", "VALUE": "15"}]},
    {"snc_config": []},
    {"snc_config": [{}]},
]

#: Rows a hand-edited CSV really produces. These crashed `crypto_posture` with an
#: AttributeError before this change; a malformed export is a normal input here.
MALFORMED = [
    {"security_params": ["not a row", 7, None]},
    {"security_params": [{"NAME": None, "VALUE": "0"}]},
    {"snc_config": ["not a row", None]},
    {"snc_config": [{"PARAMETER": None, "VALUE": "0"}]},
]


@pytest.mark.parametrize("data", NOTHING_TO_SAY + MALFORMED)
@pytest.mark.parametrize("run_context", [None, ALL_THREE, ctx("crypto", "baseline")])
def test_thin_and_malformed_input_never_raises(data, run_context):
    """Absent or broken evidence returns a list cleanly from every one of the
    three, whatever the run context is."""
    for cls in (SncPostureAuditor, CryptoPostureAuditor, BaselineParamAuditor):
        assert isinstance(cls(dict(data), {}, run_context).run_all_checks(), list)


@pytest.mark.parametrize("data", NOTHING_TO_SAY + MALFORMED)
@pytest.mark.parametrize("run_context", [None, ALL_THREE, ctx("crypto", "baseline")])
def test_a_stand_down_is_never_recorded_over_evidence_nobody_had(data, run_context):
    """A deferral note asserts that a reading was withheld. With no SNC evidence in
    the export there was no reading, and inventing the note would put a coverage
    statement in the report that nothing supports."""
    for cls in (CryptoPostureAuditor, BaselineParamAuditor):
        found = cls(dict(data), {}, run_context).run_all_checks()
        assert not (ids(found) & set(DEFERRAL_IDS)), (cls.__name__, data)


def test_an_absent_snc_enable_is_neither_a_finding_nor_a_stand_down():
    """`crypto_posture` used to read an ABSENT snc/enable as "0" and report SNC as
    disabled — absence of evidence turned into a HIGH finding, which is the one
    thing this codebase refuses to do. That is now fixed at source.

    The stand-down note follows: with nothing to say about snc/enable, there is
    nothing to withhold, so announcing a stand-down would be a second invention on
    top of the first. Saying "I declined to tell you X" about an X that was never
    going to be said is noise dressed as diligence.

    The gap IS reported — by the owner, which models the family and can say
    precisely what it could not establish. This test previously asserted the
    opposite and was correct for the code as it then stood.
    """
    data = export({"snc/accept_insecure_rfc": "1", "login/min_password_lng": "15"})
    said = run_one(CryptoPostureAuditor, data, ALL_THREE)
    assert not any(f["check_id"] == "CRYPTO-SNC-001" for f in said),         "an absent snc/enable was reported as SNC being disabled"
    for f in said:
        assert not any("snc/enable = 0" in item for item in f.get("affected_items", [])),             f"a value nobody exported was printed back to the customer: {f['affected_items']}"

    # The owner does say what it could not establish, rather than nothing.
    owner_said = run_one(SncPostureAuditor, data, ALL_THREE)
    assert ids(owner_said) == {"CRYPTO-SNCECS-000"}
    assert "snc/enable is not in the profile-parameter export" in         owner_said[0]["description"]


def test_a_parameter_exported_with_no_value_is_the_owners_to_report():
    """Present-but-empty is neither on nor off. The owner says so — "neither the
    mandated value nor one this module recognises as disabled" — and this is
    exactly the state crypto_posture reads as a flat "SNC is disabled", so the
    stand-down here is the point rather than an accident."""
    data = {"security_params": [{"NAME": "snc/enable", "VALUE": ""}]}
    assert "CRYPTO-SNCECS-001" in ids(run_one(SncPostureAuditor, data, ALL_THREE))
    assert ids(run_one(CryptoPostureAuditor, data, ALL_THREE)) == {"CRYPTO-SNC-DEFERRED"}
    assert ids(run_one(CryptoPostureAuditor, data, ctx("crypto"))) == {"CRYPTO-SNC-001"}


def test_the_coverage_object_declines_to_answer_rather_than_guessing():
    """The primitive the whole deferral rests on: only a genuine YES stands anybody
    down."""
    auditor = CryptoPostureAuditor(SNC_OFF, {}, None)
    assert snc_posture.coverage_in_this_run(auditor) is None      # caller did not say
    auditor = CryptoPostureAuditor(SNC_OFF, {}, ctx("crypto"))
    assert snc_posture.coverage_in_this_run(auditor) is None      # owner excluded
    auditor = CryptoPostureAuditor(SNC_OFF, {}, ALL_THREE)
    assert snc_posture.coverage_in_this_run(auditor) is not None


def test_the_owner_reports_a_coverage_gap_rather_than_being_deferred_to():
    """An export with no snc parameter at all: the owner says it could not assess
    the family, which is not a verdict anybody can stand down to."""
    data = export({"login/min_password_lng": "15"})
    auditor = CryptoPostureAuditor(data, {}, ALL_THREE)
    assert snc_posture.coverage_in_this_run(auditor) is None
    assert "CRYPTO-SNCECS-000" in ids(run_one(SncPostureAuditor, data, ALL_THREE))


# --------------------------------------------------------------------------- #
#  What the deferral is allowed to assume about the note                      #
# --------------------------------------------------------------------------- #

def test_the_note_is_at_least_as_strict_as_the_checks_that_stand_down_for_it():
    """THE SAFETY CONDITION behind crypto_posture's wholesale stand-down.

    It hands the owner both of its parameters outright, which is only lossless
    while the ECS baseline objects to everything those checks object to: the note
    mandates snc/enable at the value CRYPTO-SNC-001 wants, and a protection level
    other than the one CRYPTO-SNC-002 objects to. If a revision ever changed
    either, the deferral would start swallowing a finding and this test is the
    thing that says so.
    """
    assert str(SPEC["snc/enable"]["ecs"]).strip() == "1", \
        "the note no longer mandates SNC on — crypto_posture must stop deferring"
    assert not SPEC["snc/enable"].get("allowed"), \
        "the note now permits SNC to be off; the deferral would hide CRYPTO-SNC-001"
    qop = SPEC["snc/data_protection/min"]
    assert str(qop["ecs"]).strip() != "1", \
        "the note now mandates authentication-only; CRYPTO-SNC-002 would be lost"
    assert "1" not in [str(a).strip() for a in (qop.get("allowed") or [])], \
        "the note now permits authentication-only; CRYPTO-SNC-002 would be lost"


def test_the_moot_rule_mirrors_the_owners_own_branch():
    """`OwnedSncFamily.family_is_moot` has to mean exactly what the owner does with
    the switch: the states in which it folds the whole family into one finding."""
    for state, moot in (("off", True), ("unreadable", True),
                        ("on", False), ("not_exported", False)):
        assert snc_posture.OwnedSncFamily({}, state).family_is_moot is moot

    # And the owner really does fold it: one finding on an export where four other
    # parameters also deviate.
    broken = export(compliant(**{"snc/enable": "0",
                                 "snc/data_protection/use": "1",
                                 "snc/only_encrypted_gui": "7",
                                 "snc/identity/as": "",
                                 "snc/accept_insecure_cpic": "u"}))
    assert ids(run_one(SncPostureAuditor, broken, ALL_THREE)) == {"CRYPTO-SNCECS-001"}
    assert defects(run_all(broken, ALL_THREE)) == {"CRYPTO-SNCECS-001"}


# --------------------------------------------------------------------------- #
#  Routing and identity                                                       #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("check_id", sorted(DEFERRAL_IDS))
def test_the_deferral_notes_are_routed_and_identifiable(check_id):
    """A note is a finding like any other: without a team it reaches nobody's queue,
    and without a stable identity it churns every run."""
    from server.identity import fingerprint_finding

    assert team_for(check_id) != "unassigned"
    fingerprint, basis = fingerprint_finding(
        {"check_id": check_id, "scope": "aggregate"}, "PRD", "100")
    assert len(fingerprint) == 64 and basis == "check_only"


@pytest.mark.parametrize("check_id,owner_file", sorted(DEFERRAL_IDS.items()))
def test_each_note_is_emitted_by_exactly_one_module(check_id, owner_file):
    """A shared id shares a remediation, a control mapping and an identity."""
    for path in sorted((ROOT / "modules").glob("*.py")):
        if path.name == owner_file:
            continue
        assert check_id not in path.read_text(encoding="utf-8", errors="replace"), \
            f"{path.name} also uses {check_id}"


@pytest.mark.parametrize("check_id", sorted(DEFERRAL_IDS))
def test_the_note_ids_follow_the_house_format(check_id):
    assert re.fullmatch(r"[A-Z][A-Z0-9]*(-[A-Z0-9]+)+", check_id)


def test_the_two_shallow_modules_import_nothing_outside_the_standard_library():
    """modules/ is stdlib-only, and the deferral must not have smuggled anything in
    with it."""
    for name in ("crypto_posture.py", "baseline_params.py", "snc_posture.py"):
        tree = ast.parse((ROOT / "modules" / name).read_text(encoding="utf-8"))
        roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots |= {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                roots.add(node.module.split(".")[0])
        assert roots <= {"__future__", "ast", "datetime", "json", "re", "pathlib",
                         "typing", "modules"}, (name, sorted(roots))


def test_no_unverified_sap_note_number_entered_the_three_modules():
    """NON-NEGOTIABLE. This repository has shipped invented SAP Note numbers before.

    The numbers already cited by these modules are the baseline; this asserts the
    change introduced none of its own.
    """
    permitted = {"3250501"} | {str(n) for n in BASELINE.get("referenced_notes", [])}
    # Numbers these two modules already cited before this change. Recorded as the
    # baseline so a NEW one fails here — this list vouches for nothing.
    permitted |= {"93254", "1023437", "1439348", "1408081", "1690662",   # baseline_params
                  "480149", "692245",                                    # baseline_params
                  "510007", "2300507", "1848999"}                        # crypto_posture
    cited = set()
    for name in ("crypto_posture.py", "baseline_params.py", "snc_posture.py"):
        cited |= set(re.findall(r"[Nn]ote\s+(\d{3,8})",
                                (ROOT / "modules" / name).read_text(encoding="utf-8")))
    assert cited <= permitted, f"unverified note numbers cited: {sorted(cited - permitted)}"

    in_notes = set()
    for finding in run_all(SNC_OFF, ALL_THREE):
        for text in [finding["description"], finding["remediation"],
                     *finding["references"]]:
            in_notes |= set(re.findall(r"[Nn]ote\s+(\d{3,8})", text))
    assert in_notes <= permitted, sorted(in_notes - permitted)


def test_the_ecs_awareness_of_baseline_003_was_not_undone():
    """`BASELINE-003` consults `modules/ecs_baseline.py` and is silent on a
    compliant RISE system. The deferral must not have become the only thing keeping
    it quiet there — it stays quiet with the owner out of the run entirely."""
    found = run_one(BaselineParamAuditor, export(compliant()),
                    ctx("baseline", mode="rise_pce"))
    assert "BASELINE-003" not in ids(found)
    assert not (ids(found) & set(DEFERRAL_IDS))


def test_the_original_three_way_duplicate_cannot_come_back():
    """The measurement from the report, kept as an assertion: no two of the three
    modules may raise a defect about the same SNC state."""
    found = run_all(SNC_OFF, ALL_THREE)
    snc_defects = [f for f in found
                   if f["severity"] != "INFO"
                   and ("SNC" in f["title"] or "snc/" in json.dumps(f["affected_items"]))]
    assert len(snc_defects) == 1, [(f["check_id"], f["title"]) for f in snc_defects]
