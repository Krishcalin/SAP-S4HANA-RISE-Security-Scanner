# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
The SNC family, against SAP Note 3250501's ECS baseline.

THE EXIT CRITERION IS THE NEGATIVE CONTROL
A system sitting exactly on the ECS standard, and a system sitting on any of the
exceptions the note permits, must both produce ZERO findings. Both fixtures are
built FROM the note extract rather than typed here, so if SAP revises a value the
control follows it instead of quietly asserting last year's baseline.

The trap these tests exist to hold shut: several values SAP mandates read as
insecure — ``snc/accept_insecure_gui = 1``, ``snc/only_encrypted_rfc = 0`` — and a
check that reasons from the parameter name flags every compliant ECS system on
earth. That is the false-positive class the CVA engine's Tier 2 was spent
eliminating, and `test_the_mandated_but_insecure_sounding_values_are_not_findings`
is the guard against reintroducing it here.
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

from modules.snc_posture import (  # noqa: E402
    GROUPS,
    PARAM_META,
    STATUS_DEVIATION,
    STATUS_ECS,
    STATUS_EXCEPTION,
    STATUS_INDETERMINATE,
    SncPostureAuditor,
    _template_fragments,
    load_ecs_baseline,
    snc_family,
)
from server.enrich import team_for  # noqa: E402

MODULE_SRC = ROOT / "modules" / "snc_posture.py"
BASELINE = load_ecs_baseline()
SPEC = snc_family(BASELINE)


# --------------------------------------------------------------------------- #
#  Fixtures built from the note, not typed                                    #
# --------------------------------------------------------------------------- #

def _substituted(template: str) -> str:
    """A realistic running value for one of the note's four templated parameters.

    The note gives the identity as ``p:<SID>_<CID>_SNCS.FQDN`` and the library as a
    macro expression. A live system reports the substituted or macro-expanded form,
    so the compliant fixture has to as well — otherwise the negative control would
    only prove that a system echoing the template back is clean, which no system
    does.
    """
    if "<" in template and ">" in template:
        concrete = re.sub(r"<SID>", "PRD", template)
        concrete = re.sub(r"<CID>", "100", concrete)
        concrete = re.sub(r"<[^>]+>", "X", concrete)
        return concrete.replace(".FQDN", ".prd.customer.example.com")
    fragments = _template_fragments(template)
    return "/usr/sap/PRD/SYS/exe/uc/linuxx86_64/lib" + "".join(fragments) + ".so"


def _is_templated_value(value: str) -> bool:
    return "$(" in value or ("<" in value and ">" in value)


def compliant(**overrides: str) -> dict:
    """Every snc parameter at the ECS standard the note states."""
    values = {}
    for name, spec in SPEC.items():
        mandated = str(spec.get("ecs", ""))
        values[name] = (_substituted(mandated) if _is_templated_value(mandated)
                        else mandated)
    values.update(overrides)
    return values


def on_permitted_exceptions(index: int) -> dict:
    """Every parameter that HAS a permitted exception, sitting on one of them."""
    values = compliant()
    for name, spec in SPEC.items():
        allowed = [str(a) for a in (spec.get("allowed") or [])]
        if allowed:
            values[name] = allowed[index]
    return values


def export(values: dict) -> dict:
    return {"security_params": [{"NAME": name, "VALUE": value}
                                for name, value in values.items()]}


def run(values: dict, **kwargs) -> list:
    return SncPostureAuditor(export(values), **kwargs).run_all_checks()


def ids(findings) -> set:
    return {f["check_id"] for f in findings}


# --------------------------------------------------------------------------- #
#  The join: our wording and the note's facts must cover the same parameters  #
# --------------------------------------------------------------------------- #

def test_our_wording_and_the_note_cover_exactly_the_same_parameters():
    """THE JOIN GUARD, required by the task.

    The note supplies the values; this module supplies severity, category,
    description and remediation, joined by parameter name. If the note gains a
    parameter we have no wording for, it would be silently unchecked; if we describe
    one the note does not list, we would be scoring a system against a value nobody
    mandated. Either direction fails here.
    """
    assert set(PARAM_META) == set(SPEC), {
        "described but not in the note": sorted(set(PARAM_META) - set(SPEC)),
        "in the note but not described": sorted(set(SPEC) - set(PARAM_META)),
    }


def test_every_parameter_is_routed_to_a_verdict_group():
    unknown = {name: meta.get("group") for name, meta in PARAM_META.items()
               if meta.get("group") not in GROUPS}
    assert not unknown, f"parameters with no verdict group: {unknown}"
    assert all(meta.get("role") for meta in PARAM_META.values()), \
        "a parameter with no description would produce an empty finding"


def test_the_note_extract_is_actually_present():
    """Everything else here would pass vacuously against an empty baseline."""
    assert len(SPEC) >= 17, f"only {len(SPEC)} snc parameters loaded from the extract"
    assert BASELINE.get("source", {}).get("version"), "the extract carries no version"


# --------------------------------------------------------------------------- #
#  THE NEGATIVE CONTROLS                                                      #
# --------------------------------------------------------------------------- #

def test_a_compliant_ecs_system_produces_nothing():
    """THE EXIT CRITERION.

    Every value is the ECS standard, read from the note. A tool that reports on the
    baseline SAP itself mandates is worse than useless on an ECS tenant: every
    system it ever scans is "non-compliant" and the report is discarded whole.
    """
    found = run(compliant())
    assert not found, [(f["check_id"], f["title"]) for f in found]


@pytest.mark.parametrize("index", [0, -1])
def test_a_system_on_the_permitted_exceptions_produces_nothing(index):
    """The `allowed` list matters as much as the standard value. A system sitting on
    an exception SAP explicitly permits is COMPLIANT, and reporting it would send the
    customer to argue with SAP about a configuration SAP sanctioned.

    The fixture is derived from the extract, so it has to prove it actually MOVED
    something first: if `allowed` ever came back empty — a renamed key, a schema
    change — this fixture would quietly collapse into `compliant()` and the test
    would keep passing while exercising nothing at all.
    """
    values = on_permitted_exceptions(index)
    moved = {name for name, value in values.items() if value != compliant()[name]}
    assert len(moved) >= 5, f"the exception fixture exercised nothing: {moved}"
    found = run(values)
    assert not found, [(f["check_id"], f["affected_items"]) for f in found]


@pytest.mark.parametrize("name,exception", [
    (name, str(entry))
    for name, spec in sorted(SPEC.items())
    for entry in (spec.get("allowed") or [])
])
def test_each_permitted_exception_on_its_own_is_silent(name, exception):
    """One system per exception the note lists, rather than all of them at once: a
    combination can be silent while an individual value is not, and the note permits
    each of these on its own."""
    found = run(compliant(**{name: exception}))
    assert not found, (name, exception,
                       [(f["check_id"], f["affected_items"]) for f in found])


@pytest.mark.parametrize("name,value", [
    ("snc/accept_insecure_gui", "1"),
    ("snc/accept_insecure_rfc", "1"),
    ("snc/accept_insecure_r3int_rfc", "1"),
    ("snc/only_encrypted_rfc", "0"),
    ("snc/only_encrypted_gui", "0"),
])
def test_the_mandated_but_insecure_sounding_values_are_not_findings(name, value):
    """THE TRAP, named explicitly so nobody "fixes" it later.

    These read as insecure and are the ECS STANDARD. The parameter name is not
    evidence; the note is. Each is also asserted against the extract so this test
    cannot drift away from the document it claims to encode.
    """
    assert str(SPEC[name]["ecs"]) == value, \
        f"the note no longer mandates {value} for {name} — this test is now wrong"
    assert not run(compliant(**{name: value}))


def test_enforcing_snc_for_rfc_is_treated_as_a_permitted_exception_not_the_target():
    """The note records that enforcing SNC for RFC is not generally available in
    ECS. So the hardened values are exceptions the note permits, and a system on one
    of them is compliant — the tool must not steer every ECS customer towards a
    configuration SAP cannot support there."""
    hardened = compliant(**{"snc/only_encrypted_rfc": "3",
                            "snc/accept_insecure_rfc": "0"})
    assert not run(hardened)


# --------------------------------------------------------------------------- #
#  The switch decides how much of the family means anything                   #
# --------------------------------------------------------------------------- #

def test_snc_switched_off_is_one_finding_not_ten():
    """Reporting ten SNC findings on a system with SNC switched off is ten findings
    where the truth is one, and the nine burying the one that can be acted on."""
    broken = compliant(**{
        "snc/enable": "0",
        "snc/data_protection/min": "1",
        "snc/data_protection/use": "1",
        "snc/only_encrypted_gui": "7",
        "snc/identity/as": "",
        "igs/snc/name": "p:CN=somethingelse",
        "snc/gssapi_lib": "/usr/lib/libnotthecryptolib.so",
    })
    found = run(broken)
    assert len(found) == 1, [(f["check_id"], f["title"]) for f in found]
    assert found[0]["check_id"] == "CRYPTO-SNCECS-001"
    assert found[0]["affected_objects"] == [{"type": "parameter_name",
                                             "name": "snc/enable"}]


def test_the_suppressed_deviations_are_still_recorded_not_discarded():
    """Suppressing them from the finding list must not mean losing them: the reader
    needs to know what else will need attention once the switch is on."""
    found = run(compliant(**{"snc/enable": "0", "snc/data_protection/use": "1"}))
    suppressed = found[0]["details"]["suppressed_because_snc_is_off"]
    assert any("snc/data_protection/use" in item for item in suppressed), suppressed


def test_a_switch_value_we_cannot_interpret_is_not_reported_as_disabled():
    """"snc/enable = 2" is not evidence that SNC is off. The finding says what was
    read rather than asserting a state we cannot establish."""
    found = run(compliant(**{"snc/enable": "2"}))
    assert ids(found) == {"CRYPTO-SNCECS-001"}
    assert "2" in found[0]["description"]
    assert "cannot be assumed to be in force" in found[0]["description"]
    assert "With the switch off" not in found[0]["description"]


def test_a_boolean_spelling_of_the_switch_is_not_a_deviation():
    """An export that writes TRUE instead of 1 is a reporting artefact, not a
    misconfiguration, and must not raise a HIGH finding about SNC being off."""
    assert not run(compliant(**{"snc/enable": "TRUE"}))


def test_the_switch_verdict_comes_from_the_note_and_not_from_the_parameter_name():
    """If a future revision ever mandated the switch off, "SNC is off" would BE the
    baseline and reporting it would be the trap this module exists to avoid. The
    verdict is the note's, never the name's."""
    inverted = json.loads(json.dumps(BASELINE))
    inverted["parameters"]["snc/enable"] = {"ecs": "0", "allowed": []}
    assert not run(compliant(**{"snc/enable": "0"}),
                   baseline_overrides={"ecs_baseline": inverted})


def test_deviations_are_still_assessed_when_the_switch_is_not_in_the_export():
    """Absent is not off. The family is still scored, and the finding says the
    switch could not be read rather than assuming either state."""
    values = compliant(**{"snc/data_protection/use": "1"})
    values.pop("snc/enable")
    found = run(values)
    assert ids(found) == {"CRYPTO-SNCECS-003"}
    assert "snc/enable is not in this export" in found[0]["description"]
    # Not HIGH: we cannot claim traffic is affected by a level we cannot confirm is
    # in force.
    assert found[0]["severity"] == "MEDIUM"


# --------------------------------------------------------------------------- #
#  The posture verdicts                                                       #
# --------------------------------------------------------------------------- #

def test_the_acceptance_family_is_one_finding_however_many_members_deviate():
    found = run(compliant(**{"snc/accept_insecure_cpic": "9",
                             "snc/only_encrypted_gui": "7",
                             "snc/force_login_screen": "4"}))
    assert ids(found) == {"CRYPTO-SNCECS-002"}
    assert found[0]["affected_count"] == 3
    assert found[0]["scope"] == "aggregate"
    assert {o["name"] for o in found[0]["affected_objects"]} == {
        "snc/accept_insecure_cpic", "snc/only_encrypted_gui", "snc/force_login_screen"}


def test_the_acceptance_finding_states_that_a_deviation_may_be_the_harder_value():
    """A value outside the permitted set is not automatically the weaker one, and
    telling a customer to loosen or to tighten without saying which is a guess."""
    found = run(compliant(**{"snc/accept_insecure_cpic": "9"}))
    text = found[0]["description"]
    assert "ECS standard" in text and "not generally available in ECS" in text


def test_a_protection_level_below_the_mandate_is_reported_as_an_exposure():
    found = run(compliant(**{"snc/data_protection/use": "1"}))
    assert ids(found) == {"CRYPTO-SNCECS-003"}
    assert found[0]["severity"] == "HIGH"
    assert found[0]["details"]["below_mandated_level"] == ["snc/data_protection/use = 1"]


def test_a_protection_level_deviation_that_is_not_below_the_mandate_is_medium():
    """Severity matches the risk. A value above the mandate is a deviation we report
    without claiming the payload is unencrypted, because it is not."""
    found = run(compliant(**{"snc/data_protection/max": "9"}))
    assert ids(found) == {"CRYPTO-SNCECS-003"}
    assert found[0]["severity"] == "MEDIUM"
    assert found[0]["details"]["below_mandated_level"] == []


def test_min_above_max_is_incoherent_whatever_either_value_is():
    """Neither value can be judged alone: 3 is the mandated minimum and 2 is a
    plausible-looking maximum, and together they contradict each other. The
    contradiction is reported — but as part of the one finding about the protection
    level, because one wrong value must not become two findings."""
    found = run(compliant(**{"snc/data_protection/min": "3",
                             "snc/data_protection/max": "2"}))
    assert ids(found) == {"CRYPTO-SNCECS-003"}
    assert "contradict each other" in found[0]["description"]
    assert found[0]["details"]["contradictions"], "the relation defect was lost"


def test_a_use_level_outside_the_declared_window_is_reported():
    found = run(compliant(**{"snc/data_protection/min": "2",
                             "snc/data_protection/max": "2",
                             "snc/data_protection/use": "3"}))
    assert ids(found) == {"CRYPTO-SNCECS-003"}
    assert any("outside" in problem
               for problem in found[0]["details"]["contradictions"])


def test_a_contradiction_between_individually_permitted_values_stands_alone():
    """The case the folded reporting must not swallow: if a revision of the note
    permits a range, two values can each be permitted and still disagree — and then
    the contradiction IS the whole finding. Today's note mandates one level for all
    three, so this is reachable only with an injected baseline."""
    ranged = json.loads(json.dumps(BASELINE))
    ranged["parameters"]["snc/data_protection/max"] = {"ecs": "3", "allowed": ["2"]}
    found = run(compliant(**{"snc/data_protection/min": "3",
                             "snc/data_protection/max": "2"}),
                baseline_overrides={"ecs_baseline": ranged})
    assert ids(found) == {"CRYPTO-SNCECS-004"}
    assert "min" in found[0]["description"] and "max" in found[0]["description"]


def test_a_coherent_protection_level_triple_raises_no_coherence_finding():
    assert "CRYPTO-SNCECS-004" not in ids(run(compliant()))


# --------------------------------------------------------------------------- #
#  The templated values — where a literal comparison would flag every system  #
# --------------------------------------------------------------------------- #

def test_a_macro_expanded_library_path_is_not_a_deviation():
    """The note states the library as a macro expression. A running system reports
    the resolved path, and comparing the two literally would raise this finding on
    every ECS system in existence."""
    assert not run(compliant(**{
        "snc/gssapi_lib": "/usr/sap/PRD/SYS/exe/uc/linuxx86_64/libsapcrypto.so",
        "igs/snc/library": "/usr/sap/PRD/SYS/exe/uc/linuxx86_64/libsapcrypto.so"}))


def test_the_unexpanded_macro_form_is_also_accepted():
    """RZ11 may show the profile's own macro form. Both spellings name the same
    library and neither is a defect."""
    macro = str(SPEC["snc/gssapi_lib"]["ecs"])
    assert not run(compliant(**{"snc/gssapi_lib": macro, "igs/snc/library": macro}))


def test_a_different_library_is_a_finding():
    found = run(compliant(**{
        "snc/gssapi_lib": "/usr/lib/libcustomgss.so",
        "igs/snc/library": "/usr/lib/libcustomgss.so"}))
    assert ids(found) == {"CRYPTO-SNCECS-006"}


def test_the_igs_library_must_match_the_application_server_library():
    found = run(compliant(**{
        "snc/gssapi_lib": "/usr/sap/PRD/SYS/exe/uc/linuxx86_64/libsapcrypto.so",
        "igs/snc/library": "/opt/other/libsapcrypto.so"}))
    assert ids(found) == {"CRYPTO-SNCECS-006"}
    assert "igs/snc/library" in found[0]["description"]


def test_a_macro_form_on_one_side_and_a_path_on_the_other_is_not_a_mismatch():
    """Two spellings of the same library are not a disagreement, and calling them one
    would be a false positive on a perfectly consistent system."""
    assert not run(compliant(**{
        "snc/gssapi_lib": str(SPEC["snc/gssapi_lib"]["ecs"]),
        "igs/snc/library": "/usr/sap/PRD/SYS/exe/uc/linuxx86_64/libsapcrypto.so"}))


def test_a_substituted_identity_is_not_a_deviation():
    """The note's identity value is a template with placeholders. Every real system
    reports the substituted form."""
    assert not run(compliant(**{
        "snc/identity/as": "p:PRD_100_SNCS.prd.customer.example.com",
        "igs/snc/name": "p:PRD_100_SNCS.prd.customer.example.com"}))


def test_an_identity_still_carrying_the_template_placeholder_is_a_finding():
    found = run(compliant(**{"snc/identity/as": "p:<SID>_<CID>_SNCS.FQDN"}))
    assert ids(found) == {"CRYPTO-SNCECS-005"}
    assert "placeholder" in found[0]["description"]


def test_an_identity_in_the_wrong_form_is_a_finding():
    found = run(compliant(**{"snc/identity/as": "CN=PRD, O=Example",
                             "igs/snc/name": "CN=PRD, O=Example"}))
    assert ids(found) == {"CRYPTO-SNCECS-005"}


def test_an_empty_identity_while_snc_is_enabled_is_a_finding():
    found = run(compliant(**{"snc/identity/as": ""}))
    assert ids(found) == {"CRYPTO-SNCECS-005"}


def test_the_igs_name_must_match_the_application_server_identity():
    found = run(compliant(**{
        "snc/identity/as": "p:PRD_100_SNCS.prd.customer.example.com",
        "igs/snc/name": "p:DEV_100_SNCS.dev.customer.example.com"}))
    assert ids(found) == {"CRYPTO-SNCECS-005"}
    assert "igs/snc/name" in found[0]["description"]


def test_what_cannot_be_seen_is_said_rather_than_guessed():
    """The identity has to match the SNC certificate's subject and the export does
    not contain the certificate. Every finding carries that caveat, and no finding
    ever asserts anything about the certificate's contents."""
    found = run(compliant(**{"snc/identity/as": ""}))
    assert "STRUST" in found[0]["description"]
    for finding in run(compliant(**{"snc/data_protection/use": "1"})):
        assert "certificate" in finding["details"]["unverifiable_from_export"]


# --------------------------------------------------------------------------- #
#  Thin, absent and malformed input                                           #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("data", [
    {},
    {"security_params": []},
    {"security_params": None},
    {"security_params": "not a list"},
    {"security_params": [{}]},
    {"security_params": [{"NAME": "snc/enable"}]},
    {"security_params": [{"VALUE": "1"}]},
    {"security_params": ["not a row", 7, None]},
    {"security_params": [{"PARAMETER": "snc/enable", "PARAM_VALUE": "1"}]},
])
def test_thin_input_never_raises(data):
    """A hand-edited CSV is a normal input here, not an exceptional one."""
    assert isinstance(SncPostureAuditor(data, {}).run_all_checks(), list)


@pytest.mark.parametrize("data", [{}, {"security_params": []}])
def test_an_absent_export_says_nothing_at_all(data):
    """Absent evidence is not a clean bill of health, but it is also not a finding
    about SNC: security_params.py already reports the missing export once, and a
    second voice saying it adds noise without adding information."""
    assert SncPostureAuditor(data, {}).run_all_checks() == []


def test_an_export_with_no_snc_parameters_says_so_at_info():
    """"No SNC findings" otherwise reads as "SNC is fine", which is the
    misunderstanding that costs the customer."""
    found = SncPostureAuditor(
        export({"login/min_password_lng": "15"}), {}).run_all_checks()
    assert ids(found) == {"CRYPTO-SNCECS-000"}
    assert found[0]["severity"] == "INFO"


def test_a_partial_export_without_the_switch_does_not_pass_as_clean():
    """The shape `sample_data` actually has: one snc parameter, at its ECS standard,
    and no snc/enable. Nothing deviates, but nothing is established either — and
    silence there would be read as "SNC is fine"."""
    found = SncPostureAuditor(
        export({"snc/accept_insecure_rfc": str(SPEC["snc/accept_insecure_rfc"]["ecs"]),
                "login/min_password_lng": "15"}), {}).run_all_checks()
    assert ids(found) == {"CRYPTO-SNCECS-000"}
    assert found[0]["severity"] == "INFO"
    assert "snc/enable is not in the profile-parameter export" in found[0]["description"]


def test_a_complete_compliant_export_is_silent_and_not_merely_unassessed():
    """The other side of the same coin: when the switch IS exported and everything is
    at a permitted value, there is nothing to say and the not-assessable finding must
    not appear as a consolation prize."""
    assert run(compliant()) == []


def test_an_alternative_column_naming_is_read_the_same_way():
    data = {"security_params": [{"PARAMETER": name, "PARAM_VALUE": value}
                                for name, value in compliant().items()]}
    assert SncPostureAuditor(data, {}).run_all_checks() == []


@pytest.mark.parametrize("source", ["v46", 46, None, [], {"version": 46}])
def test_a_malformed_provenance_block_degrades_instead_of_crashing(source):
    """The orchestrator may hand us the extract, so a `source` that is a bare version
    string rather than a block must not take the scan down. It reached `.get` and
    raised AttributeError before this was fixed."""
    odd = json.loads(json.dumps(BASELINE))
    odd["source"] = source
    found = run(compliant(**{"snc/enable": "0"}),
                baseline_overrides={"ecs_baseline": odd})
    assert ids(found) == {"CRYPTO-SNCECS-001"}
    assert found[0]["references"], "a finding with no reference cannot be re-checked"


def test_no_finding_claims_snc_is_enabled_when_the_switch_was_never_exported():
    """The module's own rule, applied to itself: absent is not on. A finding that
    opens "SNC is enabled" on an export that never contained snc/enable asserts the
    one thing this module is careful never to assume."""
    values = compliant(**{"snc/identity/as": "",
                          "snc/gssapi_lib": "/usr/lib/libother.so",
                          "igs/snc/library": "/usr/lib/libother.so",
                          "snc/only_encrypted_gui": "7",
                          "snc/data_protection/use": "1"})
    values.pop("snc/enable")
    found = run(values)
    assert ids(found) == {"CRYPTO-SNCECS-002", "CRYPTO-SNCECS-003",
                          "CRYPTO-SNCECS-005", "CRYPTO-SNCECS-006"}
    for finding in found:
        assert "SNC is enabled" not in finding["description"], finding["check_id"]
        assert "snc/enable is not in this export" in finding["description"], \
            finding["check_id"]


def test_the_enabled_claim_is_still_made_when_the_switch_says_so():
    """The other direction: dropping the caveat must not mean dropping the fact."""
    found = run(compliant(**{"snc/identity/as": ""}))
    assert "SNC is enabled" in found[0]["description"]
    assert "snc/enable is not in this export" not in found[0]["description"]


def test_a_missing_baseline_file_reports_nothing_rather_than_guessing():
    """With no extract there are no mandated values, and remembering them is exactly
    the failure this module was built to prevent."""
    assert run(compliant(**{"snc/enable": "0"}),
               baseline_overrides={"ecs_baseline": {}}) == []


def test_a_permitted_range_we_cannot_evaluate_is_not_reported_as_a_deviation():
    """No snc entry uses a range today ("<=7 not 0" and ">=15" appear elsewhere in
    the note). If a revision introduces one, a value we cannot evaluate must not be
    called a deviation against a set SAP may well permit."""
    ranged = json.loads(json.dumps(BASELINE))
    ranged["parameters"]["snc/only_encrypted_gui"] = {"ecs": "0", "allowed": [">=1"]}
    auditor = SncPostureAuditor(export(compliant(**{"snc/only_encrypted_gui": "5"})),
                                {"ecs_baseline": ranged})
    assert auditor.run_all_checks() == []
    assert auditor._verdicts["snc/only_encrypted_gui"]["status"] == \
        STATUS_INDETERMINATE


def test_every_parameter_in_the_family_gets_a_verdict():
    auditor = SncPostureAuditor(export(compliant()), {})
    auditor.run_all_checks()
    assert set(auditor._verdicts) == set(SPEC)
    assert {v["status"] for v in auditor._verdicts.values()} <= {STATUS_ECS,
                                                                 STATUS_EXCEPTION}


# --------------------------------------------------------------------------- #
#  Anti-fabrication and routing                                               #
# --------------------------------------------------------------------------- #

def _every_finding_this_module_can_emit() -> list:
    #: The one contradiction that stands alone needs a baseline in which both values
    #: are individually permitted; see
    #: `test_a_contradiction_between_individually_permitted_values_stands_alone`.
    ranged = json.loads(json.dumps(BASELINE))
    ranged["parameters"]["snc/data_protection/max"] = {"ecs": "3", "allowed": ["2"]}

    scenarios = [
        ({"login/min_password_lng": "15"}, {}),                       # 000
        (compliant(**{"snc/enable": "0"}), {}),                       # 001
        (compliant(**{"snc/accept_insecure_cpic": "9"}), {}),         # 002
        (compliant(**{"snc/data_protection/use": "1"}), {}),          # 003
        (compliant(**{"snc/data_protection/max": "2"}),               # 004
         {"baseline_overrides": {"ecs_baseline": ranged}}),
        (compliant(**{"snc/identity/as": ""}), {}),                   # 005
        (compliant(**{"snc/gssapi_lib": "/usr/lib/libx.so",
                      "igs/snc/library": "/usr/lib/libx.so"}), {}),   # 006
    ]
    emitted = [f for values, kwargs in scenarios for f in run(values, **kwargs)]
    # The corpus guards itself. Four tests below iterate this list and assert a
    # property of each member; every one of them would pass forever against an empty
    # list, so the emptiness is caught here once rather than missed four times.
    assert ids(emitted) >= {f"CRYPTO-SNCECS-00{n}" for n in range(7)}, \
        f"the scenarios no longer reach every check: {sorted(ids(emitted))}"
    return emitted


def test_every_check_this_module_emits_routes_to_a_team():
    """An unrouted check_id reaches nobody's queue and is worked by no one."""
    emitted = _every_finding_this_module_can_emit()
    assert ids(emitted) == {f"CRYPTO-SNCECS-00{n}" for n in range(7)}
    unrouted = sorted({f["check_id"] for f in emitted
                       if team_for(f["check_id"]) == "unassigned"})
    assert not unrouted, unrouted


def test_no_check_id_from_this_module_exists_anywhere_else():
    """A shared id shares a remediation, a control mapping and an identity."""
    mine = ids(_every_finding_this_module_can_emit())
    for path in sorted((ROOT / "modules").glob("*.py")):
        if path.name == "snc_posture.py":
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        clashes = sorted(cid for cid in mine if cid in text)
        assert not clashes, f"{path.name} also uses {clashes}"


def test_only_the_note_numbers_the_extract_itself_references_are_cited():
    """NON-NEGOTIABLE. This repository has shipped invented SAP Note numbers before.
    The only safe numbers are 3250501 and the notes it references, and this test
    reads that list from the extract rather than trusting the author."""
    permitted = {"3250501"} | {str(n) for n in BASELINE.get("referenced_notes", [])}
    cited = set(re.findall(r"[Nn]ote\s+(\d{3,8})",
                           MODULE_SRC.read_text(encoding="utf-8")))
    assert cited <= permitted, f"unverified note numbers cited: {sorted(cited - permitted)}"

    in_findings = set()
    for finding in _every_finding_this_module_can_emit():
        for text in [finding["description"], finding["remediation"],
                     *finding["references"]]:
            in_findings |= set(re.findall(r"[Nn]ote\s+(\d{3,8})", text))
    assert in_findings <= permitted, sorted(in_findings - permitted)


def test_the_mandated_values_are_read_and_not_transcribed():
    """The whole point of the exercise. A hand-typed baseline value is a typo waiting
    to tell a customer they are compliant when they are not, so no distinctive value
    from the note may appear as a literal in this module's CODE. Docstrings and
    comments are exempt — they explain, they do not decide.
    """
    tree = ast.parse(MODULE_SRC.read_text(encoding="utf-8"))
    docstrings = {id(node.value) for node in ast.walk(tree)
                  if isinstance(node, ast.Expr)
                  and isinstance(node.value, ast.Constant)
                  and isinstance(node.value.value, str)}
    code_literals = [node.value for node in ast.walk(tree)
                     if isinstance(node, ast.Constant)
                     and isinstance(node.value, str)
                     and id(node) not in docstrings]

    distinctive = {str(spec["ecs"]) for spec in SPEC.values()
                   if len(str(spec["ecs"])) >= 4}
    distinctive |= {f for value in distinctive for f in _template_fragments(value)
                    if len(f) >= 4}
    assert distinctive, "no distinctive mandated values found to check against"

    transcribed = sorted({value for value in distinctive
                          for literal in code_literals if value in literal})
    assert not transcribed, \
        f"mandated values typed into the module instead of read from the note: {transcribed}"


def test_the_module_imports_nothing_outside_the_standard_library():
    """modules/ is stdlib-only; a third-party import here would break every install
    that does not happen to have it."""
    tree = ast.parse(MODULE_SRC.read_text(encoding="utf-8"))
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".")[0])
    assert roots <= {"__future__", "json", "re", "pathlib", "typing", "modules"}, \
        sorted(roots)


def test_findings_carry_the_note_version_they_were_judged_against():
    """A baseline verdict without the revision it came from cannot be re-checked when
    the note moves."""
    for finding in _every_finding_this_module_can_emit():
        assert finding["details"]["baseline_note"] == "3250501"
        assert finding["details"]["baseline_version"] == BASELINE["source"]["version"]
        assert finding["references"], finding["check_id"]


def test_deviation_findings_name_the_parameters_they_are_about():
    """Without the structured object the finding has no stable identity across runs
    and no node in the attack-path graph."""
    for finding in _every_finding_this_module_can_emit():
        if finding["check_id"] == "CRYPTO-SNCECS-000":
            continue                       # a coverage gap names no defective object
        named = {o["name"] for o in finding.get("affected_objects", [])}
        assert named, finding["check_id"]
        assert named <= set(SPEC), sorted(named - set(SPEC))
        assert all(o["type"] == "parameter_name"
                   for o in finding["affected_objects"])
