# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
SAP Note 3250501 — the mandatory ECS parameter baseline.

WHAT THIS FILE IS DEFENDING
---------------------------
The product's core claim is "we tell you whether this system meets the hardening
SAP mandates for ECS". Two ways to break that claim, in order of severity:

  1. A FALSE CLEAN. We required `login/min_password_lng >= 8` where SAP mandates
     >= 15, so a system SAP considers non-compliant was told it passed. Nobody
     files a bug against a green tick. Every value therefore comes from
     `data/ecs_hardening_3250501.json` and never from a Python literal, and
     `test_the_json_is_what_decides` proves the JSON — not this module — is what
     the check obeys.

  2. A FALSE FINDING ON SAP'S OWN BASELINE. Several mandated values read as
     insecure if you reason from the parameter name (`icf/set_HTTPonly_flag_on_
     cookies = 0`), and several parameters carry exceptions SAP explicitly
     permits. A check that reasons "insecure-sounding = finding" reports SAP's own
     note as a defect on every ECS system in existence.

THE EXIT CRITERION is `test_a_compliant_ecs_system_produces_nothing`: a system
sitting exactly on the note produces ZERO findings. Everything above it is the
detail that makes that result mean something, because zero findings is also what
a check that never fires produces — so each negative control is paired with the
positive control proving the same check still detects the real thing.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.security_params import (                                # noqa: E402
    ECS_META,
    ECS_NOTE_PATH,
    ECS_RULES,
    SNC_PREFIXES,
    UNPARSED_SPECS,
    SecurityParamAuditor,
    build_ecs_rules,
    load_ecs_note,
)

NOTE = load_ecs_note()
PARAMS = NOTE["parameters"]

#: The parameters this module owns: everything the note mandates except SNC,
#: which belongs to the cryptographic-posture module.
OWNED = {name: entry for name, entry in PARAMS.items()
         if not name.startswith(SNC_PREFIXES)}

#: Legacy checks note 3250501 does not mention, at values that satisfy them.
#: Hand-written because they are OUR thresholds, not the note's — and pinned by
#: `test_the_legacy_only_set_is_exactly_what_this_fixture_covers`, so a change to
#: the legacy table cannot silently drop out of the compliant fixture and leave
#: the exit criterion passing for the wrong reason.
LEGACY_ONLY_COMPLIANT = {
    "login/disable_multi_gui_login": "1",
    "rfc/reject_insecure_logon": "1",
    "rfc/reject_insecure_logon_data": "1",
    "rdisp/wpdbug_max_no": "0",
}


def rows(values: dict) -> list:
    return [{"NAME": name, "VALUE": value} for name, value in values.items()]


def compliant_export() -> dict:
    """A full profile export of a system sitting exactly on the note.

    Built FROM the note, so it cannot drift away from what the checks expect: if
    a future revision changes a mandated value, this fixture changes with it.
    """
    values = {name: entry["ecs"] for name, entry in PARAMS.items()}
    values.update(LEGACY_ONLY_COMPLIANT)
    return values


def audit(values: dict, overrides: dict = None) -> list:
    return SecurityParamAuditor({"security_params": rows(values)},
                                overrides or {}).run_all_checks()


def ids(findings: list) -> list:
    return [f["check_id"] for f in findings]


def fires_on(param: str, value: str) -> list:
    """Findings produced when one parameter of an otherwise compliant system moves."""
    values = compliant_export()
    values[param] = value
    return audit(values)


# --------------------------------------------------------------------------- #
#  THE EXIT CRITERION                                                          #
# --------------------------------------------------------------------------- #

def test_a_compliant_ecs_system_produces_nothing():
    """THE EXIT CRITERION FOR THIS WHOLE TASK.

    Every parameter set to the value SAP's own note mandates. A single finding
    here is a false accusation against SAP's baseline, which lands on every ECS
    tenant simultaneously and is the fastest way to lose the room.
    """
    found = audit(compliant_export())
    assert not found, ("a compliant ECS system produced "
                       f"{[(f['check_id'], f['description'][:90]) for f in found]}")


def test_the_exit_criterion_is_not_passing_because_nothing_runs():
    """Zero findings is also what a dead check produces. This is the control."""
    assert len(ECS_RULES) == len(OWNED) == 74, len(ECS_RULES)
    broken = fires_on("login/min_password_lng", "4")
    assert ids(broken) == ["PARAM-login/min_password_lng"]


# --------------------------------------------------------------------------- #
#  The join: OUR judgement against THEIR values                               #
# --------------------------------------------------------------------------- #

def test_neither_side_of_the_join_has_a_parameter_the_other_lacks():
    """The parity guard the task asked for, in both directions.

    A note parameter with no metadata is silently UNCHECKED — the compliance
    claim covers it and the code does not. Metadata for a parameter the note does
    not mandate is a rule with no authority behind it.
    """
    note_side = set(OWNED)
    meta_side = set(ECS_META)
    assert note_side - meta_side == set(), \
        f"mandated by the note, unchecked here: {sorted(note_side - meta_side)}"
    assert meta_side - note_side == set(), \
        f"checked here, not in the note: {sorted(meta_side - note_side)}"


def test_the_metadata_table_cannot_carry_an_expected_value():
    """STRUCTURAL, not stylistic.

    The defect being prevented is a hand-transcribed value drifting from the
    note. Restricting `ECS_META` to judgement-only keys means there is nowhere in
    Python for a mandated value to be typed in the first place — the join has to
    go through the JSON.
    """
    allowed_keys = {"severity", "category", "desc", "fix"}
    for name, entry in ECS_META.items():
        assert set(entry) == allowed_keys, f"{name} carries {set(entry) - allowed_keys}"


def test_every_rule_carries_the_notes_values_verbatim():
    for name, rule in ECS_RULES.items():
        assert rule["ecs"] == OWNED[name]["ecs"]
        assert rule["allowed"] == [str(a) for a in OWNED[name]["allowed"]]


def test_the_json_is_what_decides_not_a_python_constant():
    """Move the mandate in the DATA and the verdict must move with it.

    A system at 15 characters is compliant today. Told the note demands 20, the
    same system must fail — which it can only do if the check reads the file.
    """
    note = json.loads(Path(ECS_NOTE_PATH).read_text(encoding="utf-8"))
    note["parameters"]["login/min_password_lng"] = {"ecs": "20", "allowed": [">=20"]}

    class Stricter(SecurityParamAuditor):
        ECS_RULES = build_ecs_rules(note=note, unparsed=[])

    values = compliant_export()
    found = Stricter({"security_params": rows(values)}, {}).run_all_checks()
    assert ids(found) == ["PARAM-login/min_password_lng"]


def test_no_allowed_spec_grammar_is_silently_unsupported():
    """An `allowed` form the compiler does not understand SKIPS the parameter.

    That is the right runtime behaviour — silence beats guessing in either
    direction — but it is only safe because this test turns the skip into a build
    failure. Without it, a fifth grammar in a future note revision would disable
    a mandatory check with nothing anywhere saying so.
    """
    assert UNPARSED_SPECS == [], UNPARSED_SPECS


@pytest.mark.parametrize("spec", ["<=8 or 0", "between 30 and 90", "8-16",
                                  ">8", "not 0", "30 to 90 not 0"])
def test_a_novel_grammar_is_refused_and_recorded(spec):
    """THE TEST ABOVE IS ONLY WORTH ANYTHING IF THE REFUSAL CAN HAPPEN.

    It could not. Every unrecognised spec fell through to the literal branch and
    compiled to "the permitted value is the string '<=8 or 0'", which no real
    value equals — so SAP's exception silently disappeared, compliant systems
    sitting on it were accused, and `UNPARSED_SPECS` stayed empty while the guard
    above went on passing. A dead safety net is worse than none, because it is
    believed.
    """
    note = json.loads(Path(ECS_NOTE_PATH).read_text(encoding="utf-8"))
    note["parameters"]["login/min_password_lng"] = {"ecs": "15", "allowed": [spec]}
    sink = []
    rules = build_ecs_rules(note=note, unparsed=sink)

    assert sink == [("login/min_password_lng", spec)], sink
    assert "login/min_password_lng" not in rules, "guessed at a grammar it cannot parse"
    # And the build fails rather than shipping 73 of 74 mandatory checks:
    # `test_the_exit_criterion_is_not_passing_because_nothing_runs` pins the count.
    assert len(rules) == len(OWNED) - 1


@pytest.mark.parametrize("literal", ["U", "expansion", "TRUE", "0", "DISABLED",
                                     "1568:PFS:HIGH::EC_X25519:EC_P256:EC_HIGH"])
def test_refusing_novel_grammars_does_not_refuse_a_plain_permitted_value(literal):
    """The other half. Most of the note's exceptions ARE literals, and refusing
    one would drop a real parameter out of the rule set — the failure the test
    above is designed to cause, arriving for no reason."""
    note = json.loads(Path(ECS_NOTE_PATH).read_text(encoding="utf-8"))
    note["parameters"]["sapgui/user_scripting"] = {"ecs": "FALSE", "allowed": [literal]}
    sink = []
    rules = build_ecs_rules(note=note, unparsed=sink)
    assert sink == []
    assert rules["sapgui/user_scripting"]["check"](literal)


# --------------------------------------------------------------------------- #
#  THE TRAP: the compliant value is whatever the note says                    #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("param", [
    "icf/set_HTTPonly_flag_on_cookies",     # mandated 0
    "ms/monitor",                           # mandated 0
    "login/failed_user_auto_unlock",        # mandated 0
    "login/create_virtual_user_sapstar",    # mandated 0
    "gw/accept_remote_trace_level",         # mandated 0
])
def test_a_mandated_value_that_reads_as_insecure_is_still_compliant(param):
    """The false-positive class this file exists to prevent.

    Reasoning from the parameter name — "HTTPonly = 0, so HttpOnly is off, so
    that is a finding" — flags SAP's own baseline on every ECS system. The note
    is the authority, not the name.
    """
    assert not fires_on(param, PARAMS[param]["ecs"])


def test_the_same_parameter_still_fires_when_it_actually_deviates():
    """The control. Reading the value from the note must not mean never firing."""
    assert ids(fires_on("icf/set_HTTPonly_flag_on_cookies", "1")) == \
        ["PARAM-icf/set_HTTPonly_flag_on_cookies"]


def test_the_description_warns_the_reader_off_the_parameter_name():
    """A reader who "fixes" this to 1 has broken their ECS compliance. The finding
    has to say that the mandated value is the mandated value."""
    finding = fires_on("icf/set_HTTPonly_flag_on_cookies", "1")[0]
    assert "READ THE MANDATED VALUE, NOT THE PARAMETER NAME" in finding["description"]


# --------------------------------------------------------------------------- #
#  THE TRAP: a permitted exception is compliance                              #
# --------------------------------------------------------------------------- #

def _sample_values(spec: str) -> list:
    """Representative values for one `allowed` spec, including its boundaries."""
    text = spec.strip()
    if " to " in text:
        low, high = (int(part) for part in text.split(" to "))
        return [str(low), str(high), str((low + high) // 2)]
    if text.startswith("<="):
        high = int("".join(c for c in text.split("not")[0] if c.isdigit()))
        return ["1", str(high)]
    if text.startswith(">="):
        low = int("".join(c for c in text if c.isdigit()))
        return [str(low), str(low + 5)]
    return [text]


EXCEPTION_CASES = [(name, spec, value)
                   for name, entry in sorted(OWNED.items())
                   for spec in entry["allowed"]
                   for value in _sample_values(spec)]


@pytest.mark.parametrize("param,spec,value", EXCEPTION_CASES,
                         ids=[f"{n}={v}" for n, _s, v in EXCEPTION_CASES])
def test_a_system_on_a_permitted_exception_is_compliant(param, spec, value):
    """Every exception the note grants, every parameter, driven from the JSON.

    `allowed` is not decoration: `login/password_change_for_SSO` permits 2 and 3
    besides the standard 1, and demanding the standard alone manufactures a
    finding against a system SAP considers correct.
    """
    assert not fires_on(param, value), f"{param}={value} is permitted by '{spec}'"


def test_there_are_actually_exceptions_being_exercised():
    """Guards the parametrisation itself: an empty list would make the block above
    vacuously green."""
    assert len(EXCEPTION_CASES) >= 25, len(EXCEPTION_CASES)


# --------------------------------------------------------------------------- #
#  The grammars the old operator set could not express                        #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("param", ["login/password_expiration_time",
                                   "login/password_max_idle_productive"])
def test_a_range_is_enforced_at_both_ends(param):
    """THE MEASURED GAP. The note says "30 to 90" and we checked `<= 90`, so a
    system set to 10 days passed us and failed SAP. Too short is a real defect:
    it drives incremental passwords and written-down credentials."""
    assert ids(fires_on(param, "10")) == [f"PARAM-{param}"], "below the range"
    assert ids(fires_on(param, "180")) == [f"PARAM-{param}"], "above the range"
    assert not fires_on(param, "30"), "the lower bound is inclusive"
    assert not fires_on(param, "90"), "the upper bound is inclusive"


@pytest.mark.parametrize("param", ["login/fails_to_session_end",
                                   "login/fails_to_user_lock",
                                   "login/password_max_idle_initial",
                                   "rdisp/gui_auto_logout"])
def test_zero_does_not_pass_a_not_zero_bound(param):
    """THE SECOND MEASURED GAP. "<= 3 (not 0)" — and 0 sails through a naive `<=`
    while being the single most dangerous value the parameter can hold, because it
    switches the control off rather than tightening it."""
    assert ids(fires_on(param, "0")) == [f"PARAM-{param}"]
    assert not fires_on(param, "1"), "the smallest non-zero value is permitted"


def test_an_open_lower_bound_accepts_anything_above_it():
    """">= 1" must not be read as "== 1": a system demanding three digits is more
    compliant, not less."""
    assert not fires_on("login/min_password_digits", "3")
    assert ids(fires_on("login/min_password_digits", "0")) == \
        ["PARAM-login/min_password_digits"]


def test_a_value_that_is_not_a_number_at_all_is_a_finding_not_a_crash():
    assert ids(fires_on("login/min_password_lng", "unset")) == \
        ["PARAM-login/min_password_lng"]


@pytest.mark.parametrize("value", ["ALL", "all", " ALL ", "AlL"])
def test_string_values_are_compared_without_punishing_the_exports_spelling(value):
    """A finding raised because a CSV used lowercase is a finding nobody trusts."""
    assert not fires_on("rec/client", value)


def test_but_a_genuinely_different_string_still_fires():
    assert ids(fires_on("rec/client", "100")) == ["PARAM-rec/client"]


# --------------------------------------------------------------------------- #
#  Structural checks — placeholders and compound values                       #
# --------------------------------------------------------------------------- #

def test_a_placeholder_path_is_not_demanded_verbatim():
    """`$(DIR_GLOBAL)$(DIR_SEP)secinfo$(FT_DAT)` resolves differently on every
    host. Demanding the literal string fires on every real system — the exact
    over-precision this module is meant to avoid."""
    assert not fires_on("gw/sec_info", "/usr/sap/PRD/SYS/global/secinfo")
    assert not fires_on("gw/sec_info", "$(DIR_GLOBAL)$(DIR_SEP)secinfo$(FT_DAT)")


def test_but_an_unconfigured_acl_path_still_fires():
    """The half that matters: no ACL file named at all."""
    assert ids(fires_on("gw/sec_info", "")) == ["PARAM-gw/sec_info"]
    assert ids(fires_on("ms/acl_info", "   ")) == ["PARAM-ms/acl_info"]


def test_gateway_logging_accepts_extra_actions_and_a_host_specific_log_file():
    assert not fires_on("gw/logging",
                        "ACTION=SsPXMZ LOGFILE=gw_log-%y-%m-%d SWITCHTF=day")


def test_gateway_logging_fires_when_a_mandated_action_is_missing():
    assert ids(fires_on("gw/logging", "ACTION=Ss LOGFILE=gw_log")) == ["PARAM-gw/logging"]


def test_gateway_log_actions_are_compared_case_sensitively():
    """`S` and `s` are DIFFERENT gateway actions, so casefolding the comparison
    would accept a set that is missing one of them."""
    assert ids(fires_on("gw/logging", "ACTION=SPXM")) == ["PARAM-gw/logging"]


def test_the_icm_security_log_accepts_a_higher_level_and_a_host_specific_file():
    """`>=`, not `==`: a system logging MORE than SAP requires is not deviating."""
    assert not fires_on("icm/security_log",
                        "LOGFILE=dev_icm_sec LEVEL=3 MAXSIZEKB=10000")
    assert not fires_on("icm/security_log", "LEVEL=5")


def test_the_icm_security_log_fires_below_the_mandated_level():
    assert ids(fires_on("icm/security_log", "LOGFILE=dev_icm_sec LEVEL=1")) == \
        ["PARAM-icm/security_log"]


def test_http_access_logging_only_requires_that_something_is_logged():
    assert not fires_on("icm/HTTP/logging_0",
                        "PREFIX=/, LOGFILE=http-%y-%m-%d.log, LOGFORMAT=SAPSMD")
    assert ids(fires_on("icm/HTTP/logging_0", "")) == ["PARAM-icm/HTTP/logging_0"]


def test_the_password_hash_accepts_a_higher_work_factor_but_not_a_weaker_one():
    """Raising iterations is a hardening and must not read as a deviation; a
    different algorithm or a lower work factor is the defect."""
    assert not fires_on(
        "login/password_hash_algorithm",
        "encoding=RFC2307, algorithm=iSSHA-512, iterations=30000, saltsize=512")
    assert ids(fires_on(
        "login/password_hash_algorithm",
        "encoding=RFC2307, algorithm=iSSHA-1, iterations=1024, saltsize=96")) == \
        ["PARAM-login/password_hash_algorithm"]
    assert ids(fires_on(
        "login/password_hash_algorithm",
        "encoding=RFC2307, algorithm=iSSHA-512, iterations=1000, saltsize=256")) == \
        ["PARAM-login/password_hash_algorithm"]


def test_the_admin_user_list_is_checked_for_shape_not_for_the_exact_accounts():
    """Which operator accounts a landscape carries varies; an empty or wildcarded
    list does not."""
    assert not fires_on("service/admin_users", "daaadm sapadm dacadm prdadm")
    assert ids(fires_on("service/admin_users", "*")) == ["PARAM-service/admin_users"]
    assert ids(fires_on("service/admin_users", "")) == ["PARAM-service/admin_users"]


@pytest.mark.parametrize("param", sorted(
    name for name, rule in ECS_RULES.items() if rule["caveat"]))
def test_every_structural_check_says_what_it_did_not_verify(param):
    """An approximate check presented as an exact one is worse than no check: the
    reader closes the finding believing something was proved that was not."""
    finding = fires_on(param, "")
    assert finding, f"{param} produced nothing on an empty value"
    assert "Not verified" in finding[0]["description"] or \
           "Verified" in finding[0]["description"]


# --------------------------------------------------------------------------- #
#  Regression: the checks that already existed                                #
# --------------------------------------------------------------------------- #

def test_the_legacy_only_set_is_exactly_what_this_fixture_covers():
    """Pins the boundary between the note's rules and ours. A legacy parameter
    dropping out of `LEGACY_ONLY_COMPLIANT` would leave it unset in the compliant
    fixture, where it is skipped rather than checked — and the exit criterion
    would go on passing for the wrong reason."""
    legacy_only = set(SecurityParamAuditor.BASELINE) - set(ECS_RULES)
    assert legacy_only == set(LEGACY_ONLY_COMPLIANT), legacy_only


@pytest.mark.parametrize("param,value", [
    ("login/disable_multi_gui_login", "0"),
    ("rfc/reject_insecure_logon", "0"),
    ("rfc/reject_insecure_logon_data", "0"),
    ("rdisp/wpdbug_max_no", "2"),
])
def test_a_legacy_check_the_note_does_not_cover_still_fires(param, value):
    """These four are not in note 3250501. Extending the module to the note must
    not quietly drop the checks that were already shipping."""
    assert ids(fires_on(param, value)) == [f"PARAM-{param}"]


def test_one_parameter_produces_one_finding_not_two():
    """The ECS rule REPLACES the legacy rule for a shared parameter rather than
    layering on it. Two findings for one wrong value, carrying two different
    thresholds (`<= 90` and "30 to 90" disagree about 10 days), leaves the reader
    unable to tell which is authoritative."""
    for param in ("login/min_password_lng", "login/password_expiration_time",
                  "login/fails_to_user_lock", "rsau/enable", "rec/client"):
        found = fires_on(param, "0")
        assert len(found) == 1, f"{param} produced {ids(found)}"


def test_where_the_two_baselines_disagree_the_note_wins():
    """`login/password_expiration_time` = 10 passes the legacy `<= 90` and fails
    the note's "30 to 90". The note is the mandatory one."""
    effective = SecurityParamAuditor({}, {}).effective_rules()
    rule = effective["login/password_expiration_time"]
    assert rule["allowed"] == ["30 to 90"], "the legacy '<= 90' rule is still in force"
    assert rule["source"] == "ecs_note_3250501"
    assert ids(fires_on("login/password_expiration_time", "10")) == \
        ["PARAM-login/password_expiration_time"]


def test_the_no_export_finding_is_unchanged():
    findings = SecurityParamAuditor({}, {}).run_all_checks()
    assert ids(findings) == ["PARAM-000"]
    assert findings[0]["scope"] == "aggregate"


def test_missing_high_severity_parameters_are_rolled_up_once():
    findings = audit({"login/min_password_lng": "15"})
    rollup = [f for f in findings if f["check_id"] == "PARAM-MISSING"]
    assert len(rollup) == 1
    assert rollup[0]["scope"] == "aggregate"
    # Mandatory ECS parameters absent from the export cannot be verified, and the
    # roll-up is where that is said.
    assert any("rsau/enable" in item for item in rollup[0]["affected_items"])


def test_a_baseline_override_still_wins_over_the_note():
    """An operator with a documented, accepted deviation must be able to say so.
    The override supplies an operator, and the operator is consulted first — a
    silently ignored override is worse than no override mechanism."""
    values = compliant_export()
    values["login/min_password_lng"] = "10"
    assert ids(audit(values)) == ["PARAM-login/min_password_lng"]
    assert not audit(values, {"param.login/min_password_lng":
                              {"expected": "10", "op": ">="}})


# --------------------------------------------------------------------------- #
#  Scope: SNC belongs to another module                                       #
# --------------------------------------------------------------------------- #

def test_no_snc_parameter_is_checked_here():
    """`snc/accept_insecure_gui = 1` IS the ECS standard. Two modules disagreeing
    about that in one report is worse than one of them being silent, so the split
    is absolute."""
    assert not [name for name in ECS_RULES if name.startswith(SNC_PREFIXES)]
    assert not [name for name in ECS_META if name.startswith(SNC_PREFIXES)]


def test_an_snc_parameter_in_the_export_produces_nothing_here():
    values = compliant_export()
    values["snc/accept_insecure_gui"] = "0"      # a permitted exception, and not ours
    values["snc/enable"] = "0"
    assert not audit(values)


# --------------------------------------------------------------------------- #
#  Degrading rather than raising                                              #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("payload", [
    {},
    {"security_params": None},
    {"security_params": []},
    {"security_params": [{}]},
    {"security_params": [{"NAME": "login/min_password_lng"}]},        # no VALUE
    {"security_params": [{"VALUE": "15"}]},                           # no NAME
    {"security_params": [{"NAME": None, "VALUE": None}]},
    {"security_params": ["login/min_password_lng=15"]},               # not a dict
    {"security_params": [{"PARAMETER": "rsau/enable", "PARAM_VALUE": "1"}]},
    {"security_params": 12345},                     # not iterable at all
    {"security_params": "login/min_password_lng=15"},
    {"security_params": {"NAME": "rsau/enable"}},   # a dict where a list belongs
    {"security_params": [None, 7, {"NAME": "rsau/enable", "VALUE": "0"}]},
    {"security_params": [{"NAME": "login/min_password_lng", "VALUE": ["15"]}]},
])
def test_a_missing_or_malformed_export_never_raises(payload):
    findings = SecurityParamAuditor(payload, {}).run_all_checks()
    assert isinstance(findings, list)


def test_a_row_with_no_value_column_is_not_read_as_an_empty_value():
    """A row that carries no value column tells us NOTHING about the parameter.

    Defaulting it to "" reads that silence as "the parameter is empty" — and empty
    IS the finding for `gw/sec_info`, `ms/acl_info` and `service/admin_users`. An
    export whose value column we do not recognise would therefore produce a page
    of confident accusations built entirely from a parsing gap, which is the same
    false-accusation class as flagging SAP's own baseline.
    """
    unreadable = [{"NAME": "gw/sec_info", "PVALUE": "/usr/sap/PRD/global/secinfo"},
                  {"NAME": "rsau/enable", "PVALUE": "1"},
                  {"NAME": "service/admin_users", "PVALUE": "daaadm"}]
    findings = SecurityParamAuditor({"security_params": unreadable}, {}).run_all_checks()
    assert ids(findings) == ["PARAM-MISSING"], \
        "accused a parameter of being empty on the strength of a column we cannot read"


def test_but_a_value_column_that_is_present_and_empty_is_still_an_answer():
    """The other direction, and the one that must not be lost: `gw/sec_info` with
    nothing after the comma is an unset gateway ACL, not a parsing gap."""
    assert ids(fires_on("gw/sec_info", "")) == ["PARAM-gw/sec_info"]


def test_the_alternate_column_spellings_still_reach_the_checks():
    """RSPARAM, RZ11 and the Cloud ALM extract disagree about column names; a
    parameter read under one spelling and not another is a check that silently
    stops running for half the customers."""
    for name_col, value_col in (("NAME", "VALUE"), ("PARAMETER", "PARAM_VALUE"),
                                ("PARAM_NAME", "CURRENT_VALUE")):
        findings = SecurityParamAuditor(
            {"security_params": [{name_col: "rsau/enable", value_col: "0"}]},
            {}).run_all_checks()
        assert "PARAM-rsau/enable" in ids(findings), (name_col, value_col)


def test_an_unreadable_note_degrades_to_the_legacy_checks_instead_of_exploding():
    """A corrupt or absent data file must not take down every scan that touches
    profile parameters."""
    assert load_ecs_note(str(ROOT / "data" / "no_such_file.json"))["parameters"] == {}
    assert build_ecs_rules(note=load_ecs_note("/nonexistent"), unparsed=[]) == {}

    class NoNote(SecurityParamAuditor):
        ECS_RULES = {}

    findings = NoNote({"security_params": rows({"login/min_password_lng": "4"})},
                      {}).run_all_checks()
    assert "PARAM-login/min_password_lng" in ids(findings)


def test_a_note_whose_shape_is_wrong_is_treated_as_absent(tmp_path):
    for content in ("[]", "not json at all", '{"parameters": "nonsense"}'):
        path = tmp_path / "bad.json"
        path.write_text(content, encoding="utf-8")
        assert load_ecs_note(str(path))["parameters"] == {}


# --------------------------------------------------------------------------- #
#  Finding hygiene                                                            #
# --------------------------------------------------------------------------- #

def _every_possible_finding() -> list:
    """One finding per rule, by moving each parameter to a value nothing permits.

    The assertions matter as much as the return value. Five tests below iterate
    this list and assert a property of each member — and a loop over an empty list
    asserts nothing at all, forever. Mutating the module to emit no findings left
    every one of those five green. So the shape of the list is checked HERE, once,
    and the hygiene tests inherit a non-empty list they can rely on.

    Not `>= 1`: one finding PER RULE. A regression that silenced 73 of the 74
    checks would still satisfy a non-emptiness assertion.
    """
    out = []
    silent = []
    for name in ECS_RULES:
        found = fires_on(name, "§not-a-permitted-value§")
        out.extend(found)
        if not found:
            silent.append(name)
    assert set(silent) == _STRUCTURALLY_PERMISSIVE, (
        "a check went silent on a value nothing permits, and the hygiene tests "
        f"below would then pass vacuously: {sorted(set(silent) ^ _STRUCTURALLY_PERMISSIVE)}")
    return out


#: Rules that accept an arbitrary string because what they verify is the SHAPE of
#: a value, not the value: "a path is configured", "the admin list has no
#: wildcard". They cannot contribute a finding to `_every_possible_finding`, and
#: that is by design — `test_a_placeholder_path_is_not_demanded_verbatim` is the
#: reason. Pinned as a set so a rule that becomes permissive by ACCIDENT shows up
#: as a failure here rather than as one fewer finding nobody counted.
_STRUCTURALLY_PERMISSIVE = {
    "gw/prxy_info", "gw/reg_info", "gw/sec_info", "ms/acl_info",
    "service/admin_users",
}


def test_the_permissive_rules_are_exactly_the_ones_we_know_about():
    """A rule that stops firing on junk has stopped checking anything. The five
    below are deliberate (they verify a path is set, not what it is); a sixth
    joining them silently would be a check that quietly died."""
    junk = {name for name in ECS_RULES
            if not fires_on(name, "wholly-bogus-value-42")}
    assert junk == _STRUCTURALLY_PERMISSIVE, junk ^ _STRUCTURALLY_PERMISSIVE


def test_every_check_id_routes_to_a_team():
    """An unrouted finding reaches no queue and is worked by nobody."""
    from server.enrich import team_for
    unrouted = sorted({f["check_id"] for f in _every_possible_finding()
                       if team_for(f["check_id"]) == "unassigned"})
    assert not unrouted, unrouted


def test_no_check_id_collides_with_another_modules():
    """`PARAM-<parameter>` is a foreign key into the remediation knowledge base and
    into every stored finding's identity."""
    import ast
    emitted = {f["check_id"] for f in _every_possible_finding()}
    others = set()
    for path in sorted((ROOT / "modules").glob("*.py")):
        if path.name == "security_params.py":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8", errors="replace"))):
            if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "finding":
                for kw in node.keywords:
                    if kw.arg == "check_id" and isinstance(kw.value, ast.Constant):
                        others.add(kw.value.value)
    assert not emitted & others, emitted & others


def test_every_category_reaches_a_compliance_framework():
    """A category absent from `CATEGORY_THEMES` still reports its findings and
    then vanishes from every compliance panel, which is the worst shape a gap can
    take because the panel still looks complete."""
    from modules.compliance_mapping import ComplianceMapper
    used = {entry["category"] for entry in ECS_META.values()}
    assert used <= set(ComplianceMapper.CATEGORY_THEMES), \
        sorted(used - set(ComplianceMapper.CATEGORY_THEMES))


def test_severities_are_valid_and_not_uniformly_inflated():
    valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    severities = [entry["severity"] for entry in ECS_META.values()]
    assert set(severities) <= valid, set(severities) - valid
    critical = sum(1 for s in severities if s == "CRITICAL")
    assert critical <= 5, f"{critical} CRITICALs out of {len(severities)} parameters"


def test_the_only_sap_note_cited_is_the_one_this_module_read():
    """FABRICATED NOTE NUMBERS HAVE SHIPPED FROM THIS REPOSITORY BEFORE.

    Note 3250501 references nine other notes, but which one governs which
    parameter is not in the extract — so attaching one to a specific check would
    be inventing a citation that a customer's auditor will pull on.
    """
    import re
    cited = set()
    for finding in _every_possible_finding():
        for reference in finding["references"]:
            cited.update(re.findall(r"\b(\d{6,7})\b", reference))
    assert cited <= {"3250501"}, cited


def test_every_finding_names_the_parameter_as_a_structured_object():
    """What gives the finding a stable identity across runs and supplies the
    attack-path graph its node."""
    for finding in _every_possible_finding():
        objects = finding.get("affected_objects") or []
        assert len(objects) == 1 and objects[0]["type"] == "parameter_name"
        assert finding["scope"] == "object"


def test_no_ecs_finding_pins_the_observed_value_into_its_identity():
    """The failing condition is "anything outside the permitted set", which is
    always more than one value. Pinning it would retire the finding and raise a
    fresh one — resetting its age — on a change from one wrong value to another."""
    for finding in _every_possible_finding():
        if finding["details"].get("baseline_source") == "SAP Note 3250501":
            assert "qualifier" not in finding["affected_objects"][0]


def test_the_finding_carries_the_notes_values_for_the_reader():
    finding = fires_on("login/password_expiration_time", "180")[0]
    assert finding["details"]["ecs_standard"] == "90"
    assert finding["details"]["ecs_allowed"] == ["30 to 90"]
    assert "30 to 90" in finding["description"], \
        "a reader told 'expected 90' next to a permitted range cannot act on it"
    assert "3250501" in " ".join(finding["references"])
