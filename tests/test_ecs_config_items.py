# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
The configuration half of SAP Note 3250501.

THE EXIT CRITERION IS THE NEGATIVE CONTROL
A compliant ECS system must produce ZERO findings. Everything else in this file
is subordinate to that: an insecure-SOUNDING setting that the note mandates is
COMPLIANT, and a check that reasons from the name of a thing rather than from the
note flags SAP's own baseline on every ECS system in existence. So every true
positive here is paired with the compliant case it must stay silent on.

THE OTHER LOAD-BEARING TEST
`test_the_module_and_the_note_agree_on_the_item_list` fails if the note gains or
loses a configuration item that `CONFIG_ITEM_DISPOSITION` does not know about, in
either direction. Note 3250501 is at v46; a v47 that adds an item must break the
build rather than quietly widen a gap nobody is looking at.
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

from modules.compliance_mapping import ComplianceMapper                # noqa: E402
from modules.ecs_config_items import (                                 # noqa: E402
    CONFIG_ITEM_DISPOSITION,
    EcsConfigAuditor,
    OBSOLETE_CLIENTS,
    PASSWORD_HASH_AUTH_GROUP,
    PASSWORD_HASH_TABLES,
    PSE_AUTH_GROUP,
    PSE_TABLE,
)
from server.enrich import team_for                                     # noqa: E402

NOTE_JSON = ROOT / "data" / "ecs_hardening_3250501.json"
MODULE_SRC = ROOT / "modules" / "ecs_config_items.py"


def run(data):
    return EcsConfigAuditor(data).run_all_checks()


def ids(findings):
    return sorted(f["check_id"] for f in findings)


def compliant():
    """An ECS system that meets every item this module checks.

    Built fresh per call so a test that mutates it cannot leak into another.
    """
    return {
        "table_auth_groups": (
            [{"TABNAME": t, "CCLASS": PASSWORD_HASH_AUTH_GROUP}
             for t in PASSWORD_HASH_TABLES]
            + [{"TABNAME": PSE_TABLE, "CCLASS": PSE_AUTH_GROUP},
               {"TABNAME": "T000", "CCLASS": "SS"}]
        ),
        "client_settings": [{"CLIENT": "000", "CCCATEGORY": "S"},
                            {"CLIENT": "100", "CCCATEGORY": "P"}],
        "security_audit_log": [
            {"FILTER_NAME": "SAL01", "PROFILE_TYPE": "STATIC", "ACTIVE": "X",
             "CLIENT": "*", "USER": "*", "EVENT_CLASS": "ALL"},
        ],
    }


# --------------------------------------------------------------------------- #
#  THE NEGATIVE CONTROL                                                        #
# --------------------------------------------------------------------------- #

def test_a_compliant_ecs_system_produces_no_findings():
    assert run(compliant()) == []


def test_a_compliant_system_stays_silent_even_with_extra_narrow_audit_filters():
    """The configuration that a name-based check would flag: one filter covering
    everybody, plus a second that records one account in more detail. That is a
    GOOD configuration and the note is satisfied by the first filter."""
    data = compliant()
    data["security_audit_log"].append(
        {"FILTER_NAME": "SAL02", "PROFILE_TYPE": "DYNAMIC", "ACTIVE": "X",
         "CLIENT": "100", "USER": "DDIC", "EVENT_CLASS": "ALL"})
    assert run(data) == []


def test_client_000_alone_is_not_a_finding():
    """000 is the SAP reference client and stays. Only 001 and 066 are listed."""
    data = compliant()
    data["client_settings"] = [{"CLIENT": "000"}, {"CLIENT": "200"}]
    assert run(data) == []


def test_a_table_in_another_authorization_group_is_not_our_business():
    """Only the objects the note names are checked. T000 in group SS is normal."""
    data = compliant()
    data["table_auth_groups"].append({"TABNAME": "ZCUSTOM", "CCLASS": ""})
    assert run(data) == []


# --------------------------------------------------------------------------- #
#  Absent / malformed input — return [] cleanly, never raise                   #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("data", [
    {},
    {"table_auth_groups": [], "client_settings": [], "security_audit_log": []},
    {"table_auth_groups": None, "client_settings": None, "security_audit_log": None},
    # A dict where a row list is expected: the loader can hand back a JSON object.
    {"table_auth_groups": {"TABNAME": "USR02"}, "client_settings": {},
     "security_audit_log": {}},
    # Rows that are not dicts at all.
    {"table_auth_groups": ["USR02", 7, None], "client_settings": [[]],
     "security_audit_log": [None]},
])
def test_absent_or_unusable_input_yields_nothing(data):
    assert run(data) == []


@pytest.mark.parametrize("data", [
    # Every row present but the columns we need are missing.
    {"table_auth_groups": [{"SOMETHING": "x"}, {"OTHER": ""}]},
    {"client_settings": [{"CCCATEGORY": "P"}, {"DESCRIPTION": "prod"}]},
    {"security_audit_log": [{"EVENT_CLASS": "ALL", "ACTIVE": "X"}]},
])
def test_rows_missing_the_columns_we_need_yield_nothing(data):
    """Absence of a column is absence of evidence, and must never be read as a
    verdict in either direction."""
    assert run(data) == []


def test_a_table_extract_with_no_table_column_is_not_read_as_unassigned():
    """The dangerous direction: if a missing TABNAME column made every required
    table 'absent', a malformed extract would report the estate's password hashes
    as unprotected on a system that is fine."""
    assert run({"table_auth_groups": [{"CCLASS": "SPWD"}, {"CCLASS": "SPSE"}]}) == []


# --------------------------------------------------------------------------- #
#  AUTH-ECS-001 — password-hash tables behind SPWD                             #
# --------------------------------------------------------------------------- #

def test_a_password_hash_table_in_the_wrong_group_fires():
    data = compliant()
    data["table_auth_groups"][0] = {"TABNAME": PASSWORD_HASH_TABLES[0], "CCLASS": "SS"}
    findings = run(data)
    assert ids(findings) == ["AUTH-ECS-001"]
    assert findings[0]["details"]["wrong_group"] == {PASSWORD_HASH_TABLES[0]: "SS"}


def test_a_password_hash_table_with_a_blank_group_fires():
    data = compliant()
    data["table_auth_groups"][1] = {"TABNAME": PASSWORD_HASH_TABLES[1], "CCLASS": ""}
    findings = run(data)
    assert ids(findings) == ["AUTH-ECS-001"]
    assert findings[0]["details"]["no_group"] == [PASSWORD_HASH_TABLES[1]]


def test_the_no_class_marker_counts_as_no_group():
    """`&NC&` is the marker for a table with no authorization class; treating it
    as a group name would read it as 'assigned to something' and pass."""
    data = compliant()
    data["table_auth_groups"][2] = {"TABNAME": PASSWORD_HASH_TABLES[2], "CCLASS": "&NC&"}
    findings = run(data)
    assert ids(findings) == ["AUTH-ECS-001"]
    assert findings[0]["details"]["no_group"] == [PASSWORD_HASH_TABLES[2]]


def test_a_table_missing_from_the_extract_is_reported_separately_from_a_wrong_group():
    """Both are the same defect and take the same fix, so they are one finding —
    but a reviewer holding a namespace-filtered extract has to be able to see at a
    glance which tables the extract simply never mentioned."""
    data = compliant()
    data["table_auth_groups"] = [r for r in data["table_auth_groups"]
                                 if r["TABNAME"] != PASSWORD_HASH_TABLES[3]]
    findings = run(data)
    assert ids(findings) == ["AUTH-ECS-001"]
    details = findings[0]["details"]
    assert details["not_in_extract"] == [PASSWORD_HASH_TABLES[3]]
    assert details["no_group"] == [] and details["wrong_group"] == {}
    assert details["extract_rows"] == len(data["table_auth_groups"])


def test_every_named_table_is_actually_checked():
    """Protecting USR02 alone leaves the same hashes readable through the views and
    the archiving copy, which is why the note names all six."""
    for table in PASSWORD_HASH_TABLES:
        data = compliant()
        data["table_auth_groups"] = [
            r for r in data["table_auth_groups"] if r["TABNAME"] != table]
        assert ids(run(data)) == ["AUTH-ECS-001"], table


def test_all_six_wrong_is_one_aggregate_finding_not_six():
    data = compliant()
    data["table_auth_groups"] = [{"TABNAME": t, "CCLASS": "SS"}
                                 for t in PASSWORD_HASH_TABLES] + \
                                [{"TABNAME": PSE_TABLE, "CCLASS": PSE_AUTH_GROUP}]
    findings = run(data)
    assert ids(findings) == ["AUTH-ECS-001"]
    assert findings[0]["scope"] == "aggregate"
    assert len(findings[0]["affected_objects"]) == len(PASSWORD_HASH_TABLES)


def test_the_group_name_is_matched_case_insensitively():
    """An SE16 download may lower-case the column contents; 'spwd' is SPWD."""
    data = compliant()
    data["table_auth_groups"] = [{"tabname": t.lower(), "cclass": "spwd"}
                                 for t in PASSWORD_HASH_TABLES] + \
                                [{"tabname": PSE_TABLE.lower(), "cclass": "spse"}]
    assert run(data) == []


@pytest.mark.parametrize("header", ["TABNAME", "TABLE", "TABLE_NAME", "OBJECT",
                                    "OBJECT_NAME", "VIEWNAME"])
def test_every_documented_table_header_alias_is_honoured(header):
    data = {"table_auth_groups": [{header: t, "AUTH_GROUP": "SS"}
                                  for t in PASSWORD_HASH_TABLES]}
    assert "AUTH-ECS-001" in ids(run(data))


@pytest.mark.parametrize("header", ["CCLASS", "AUTH_GROUP", "AUTHGROUP",
                                    "AUTHORIZATION_GROUP", "AUTH_GRP",
                                    "DICBERCLS", "BRGRU"])
def test_every_documented_group_header_alias_is_honoured(header):
    """The control for the alias list: if an alias were NOT read, the group would
    look blank and a compliant system would be reported as unprotected."""
    rows = [{"TABNAME": t, header: PASSWORD_HASH_AUTH_GROUP}
            for t in PASSWORD_HASH_TABLES]
    rows.append({"TABNAME": PSE_TABLE, header: PSE_AUTH_GROUP})
    assert run({"table_auth_groups": rows}) == []


# --------------------------------------------------------------------------- #
#  CRYPTO-ECS-001 — SSF_PSE_D behind SPSE                                      #
# --------------------------------------------------------------------------- #

def test_the_pse_table_in_the_wrong_group_fires():
    data = compliant()
    data["table_auth_groups"][-2] = {"TABNAME": PSE_TABLE, "CCLASS": "SS"}
    findings = run(data)
    assert ids(findings) == ["CRYPTO-ECS-001"]
    assert findings[0]["details"]["observed_group"] == "SS"
    assert findings[0]["details"]["in_extract"] is True


def test_the_pse_table_missing_from_the_extract_fires():
    data = compliant()
    data["table_auth_groups"] = [r for r in data["table_auth_groups"]
                                 if r["TABNAME"] != PSE_TABLE]
    findings = run(data)
    assert ids(findings) == ["CRYPTO-ECS-001"]
    assert findings[0]["details"]["in_extract"] is False


def test_the_pse_table_names_itself_as_the_finding_subject():
    """One table IS the defect, so it must sit in identity — otherwise the finding
    cannot be matched against itself after the next upload."""
    data = compliant()
    data["table_auth_groups"][-2] = {"TABNAME": PSE_TABLE, "CCLASS": ""}
    finding = run(data)[0]
    assert finding["scope"] == "object"
    assert finding["affected_objects"] == [{"type": "table", "name": PSE_TABLE}]


def test_the_two_table_checks_are_independent():
    """A system can fail one and pass the other; neither may mask the other."""
    data = compliant()
    data["table_auth_groups"] = [{"TABNAME": t, "CCLASS": "SS"}
                                 for t in PASSWORD_HASH_TABLES] + \
                                [{"TABNAME": PSE_TABLE, "CCLASS": "SS"}]
    assert ids(run(data)) == ["AUTH-ECS-001", "CRYPTO-ECS-001"]


# --------------------------------------------------------------------------- #
#  STDUSR-ECS-001 — clients 001 / 066                                          #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("client", OBSOLETE_CLIENTS)
def test_an_obsolete_client_that_still_exists_fires(client):
    data = compliant()
    data["client_settings"].append({"CLIENT": client})
    findings = run(data)
    assert ids(findings) == ["STDUSR-ECS-001"]
    assert findings[0]["details"]["obsolete_clients_present"] == [client]


def test_both_obsolete_clients_are_one_finding():
    data = compliant()
    data["client_settings"] += [{"CLIENT": c} for c in OBSOLETE_CLIENTS]
    findings = run(data)
    assert ids(findings) == ["STDUSR-ECS-001"]
    assert findings[0]["scope"] == "aggregate"
    assert len(findings[0]["affected_objects"]) == len(OBSOLETE_CLIENTS)


def test_an_unpadded_client_number_is_the_same_client():
    """An SE16 download gives '1' where T000 holds '001'. Missing that would report
    the system as clean."""
    data = compliant()
    data["client_settings"].append({"MANDT": "1"})
    assert ids(run(data)) == ["STDUSR-ECS-001"]


def test_the_finding_says_usage_was_not_measured():
    """The note asks for these clients to be deleted when UNUSED, and no export we
    take carries usage. The finding must name that limit rather than implying we
    checked — a customer who deletes a live client on our say-so is our fault."""
    data = compliant()
    data["client_settings"].append({"CLIENT": "066"})
    finding = run(data)[0]
    assert finding["details"]["usage_evidence"] == \
        "not available from a configuration export"
    assert "not been measured" in finding["description"].lower()


# --------------------------------------------------------------------------- #
#  LREV-ECS-001 — audit filters bound to named users                           #
# --------------------------------------------------------------------------- #

def test_filters_bound_only_to_named_users_fire():
    data = compliant()
    data["security_audit_log"] = [
        {"FILTER_NAME": "SAL01", "ACTIVE": "X", "CLIENT": "*", "USER": "DDIC"},
        {"FILTER_NAME": "SAL02", "ACTIVE": "X", "CLIENT": "*", "USER": "SAP*"},
    ]
    findings = run(data)
    assert ids(findings) == ["LREV-ECS-001"]
    assert findings[0]["details"]["filters_restricted_to_users"] == ["DDIC", "SAP*"]


def test_a_wildcard_filter_anywhere_in_the_set_clears_the_check():
    """Order must not matter: the narrow filter is seen first here."""
    data = compliant()
    data["security_audit_log"] = [
        {"FILTER_NAME": "SAL02", "ACTIVE": "X", "USER": "DDIC"},
        {"FILTER_NAME": "SAL01", "ACTIVE": "X", "USER": "*"},
    ]
    assert run(data) == []


def test_an_inactive_narrow_filter_is_not_evidence():
    """A filter that is switched off records nothing and restricts nothing. It is
    LREV-FLT-001's business, not this check's."""
    data = compliant()
    data["security_audit_log"] = [
        {"FILTER_NAME": "SAL02", "ACTIVE": "", "USER": "DDIC"},
    ]
    assert run(data) == []


def test_a_filter_extract_with_no_active_column_is_still_read():
    """The control for the rule above. "The ACTIVE cell is blank" and "there is no
    ACTIVE column" are different answers, and treating the second as the first
    would silently disable this check on every hand-made extract — which is most
    of them."""
    data = compliant()
    data["security_audit_log"] = [{"FILTER_NAME": "SAL01", "USER": "DDIC"}]
    assert ids(run(data)) == ["LREV-ECS-001"]


def test_an_event_extract_does_not_fire_the_filter_check():
    """THE TRAP. Every logged event names a user, so reading event rows as filter
    rows would fire this check on every system that supplied an event extract. A
    row carrying a date or timestamp is an event."""
    data = compliant()
    data["security_audit_log"] = [
        {"DATE": "20260701", "TIME": "081500", "USER": "DDIC", "TEXT": "Logon successful"},
        {"DATE": "20260701", "TIME": "081600", "USER": "MMUELLER", "TEXT": "Logon successful"},
    ]
    assert run(data) == []


def test_a_blank_user_field_is_not_read_as_a_wildcard():
    """An ALV download renders an unset field and a '*' field the same way often
    enough that reading blank as 'covers everyone' would suppress the finding on
    exactly the systems that have it. Blank is no evidence, so nothing fires and
    nothing is cleared."""
    data = compliant()
    data["security_audit_log"] = [{"FILTER_NAME": "SAL01", "ACTIVE": "X", "USER": ""}]
    assert run(data) == []


def test_the_fallback_audit_config_export_is_read():
    data = compliant()
    del data["security_audit_log"]
    data["audit_config"] = [{"FILTER_NAME": "SAL01", "ACTIVE": "X", "USER": "DDIC"}]
    assert ids(run(data)) == ["LREV-ECS-001"]


@pytest.mark.parametrize("datecol", ["SLGDATE", "AUDIT_TIME", "EVENT_TIME", "ZEIT",
                                     "LOGDATE", "CREATED_ON", "WHEN"])
def test_an_event_extract_whose_date_header_we_do_not_recognise_is_still_not_a_filter(datecol):
    """THE FALSE POSITIVE THIS CHECK ONCE HAD, in its exact shape.

    The system below is COMPLIANT: its one filter records all users. It also sent
    an event extract whose date column is spelled something other than the nine
    names we recognise. When a filter row was defined as "a row with no date
    column", every one of those events became a filter, every event names a user,
    and a compliant system was told its audit log was blind — with a list of its
    own end users presented as filter definitions.

    A verdict must not turn on the spelling of a column header, so a filter row
    now needs positive evidence that it IS one.
    """
    data = compliant()
    data["security_audit_log"] = [
        {datecol: "20260701", "USER": "MMUELLER", "TEXT": "Logon successful"},
        {datecol: "20260701", "USER": "JSCHMIDT", "TEXT": "Logon successful"},
    ]
    data["audit_config"] = [{"FILTER_NAME": "SAL01", "ACTIVE": "X", "USER": "*"}]
    assert run(data) == []


def test_a_row_that_is_both_event_shaped_and_filter_shaped_is_not_evidence():
    """The other half of the rule. A row we cannot classify decides nothing."""
    data = compliant()
    data["security_audit_log"] = [
        {"FILTER_NAME": "SAL01", "ACTIVE": "X", "DATE": "20260701", "USER": "DDIC"}]
    assert run(data) == []


def test_an_event_shaped_audit_log_falls_back_to_the_filter_export():
    """The false NEGATIVE that came with the same rule.

    This system is genuinely non-compliant — its only filter is bound to DDIC — and
    it supplied an event extract as well. Falling back to `audit_config` only when
    `security_audit_log` was entirely EMPTY meant the event rows were consumed, the
    filter list was never opened, and the check reported nothing. modules/log_review.py
    falls back on event-shaped content, and this module cites that rule as its own.
    """
    data = compliant()
    data["security_audit_log"] = [{"DATE": "20260701", "USER": "MMUELLER"}]
    data["audit_config"] = [{"FILTER_NAME": "SAL01", "ACTIVE": "X", "USER": "DDIC"}]
    assert ids(run(data)) == ["LREV-ECS-001"]


def test_the_fallback_does_not_fire_on_a_compliant_filter_export():
    """The control for the test above: the same shape, compliant filter."""
    data = compliant()
    data["security_audit_log"] = [{"DATE": "20260701", "USER": "MMUELLER"}]
    data["audit_config"] = [{"FILTER_NAME": "SAL01", "ACTIVE": "X", "USER": "*"}]
    assert run(data) == []


def test_the_shipped_sample_exports_are_read_without_a_verdict():
    """The repository's own sample filter exports carry no user column at all, so
    the honest answer on them is silence — not a pass and not a finding."""
    for rows in ([{"CONFIG_NAME": "Dialog_Logon_Filter", "EVENT_CLASS": "dialog_logon_failure",
                   "ACTIVE": "ACTIVE", "PROFILE_TYPE": "STATIC", "CLIENT": "100"}],
                 [{"FILTER_NAME": "DEFAULT_FILTER", "ACTIVE": "NO",
                   "EVENT_CLASS": "ALL", "CLIENT": "*"}]):
        data = compliant()
        data["security_audit_log"] = rows
        assert run(data) == [], rows


def test_the_password_hash_table_list_comes_from_the_note_not_from_memory():
    """These six table names drive a HIGH customer finding, so every one has to be
    pointable-at in the note extract.

    They were once typed into the module from recollection, because the first
    extract recorded only the item slug and not the member list — and three of the
    six could then be sourced from nowhere at all. Shipping an invented identifier
    as fact is the incident this repository has already had once.

    The earlier version of this test asserted the OPPOSITE — that the names carried
    an UNVERIFIED marker — and was right for that state. It failed the moment the
    extract gained the list, which is exactly when the module should have stopped
    keeping its own copy. That is the test doing its job, not breaking.
    """
    note = json.loads(NOTE_JSON.read_text(encoding="utf-8"))
    detail = note.get("configuration_detail", {}).get(
        "password_hash_tables_authgroup_SPWD", {})
    assert detail.get("tables"), "the extract no longer enumerates the tables"
    assert tuple(detail["tables"]) == tuple(PASSWORD_HASH_TABLES), (
        "the module's table list has drifted from the note extract — it must be "
        "read from it, never re-typed")
    src = MODULE_SRC.read_text(encoding="utf-8")
    for table in PASSWORD_HASH_TABLES:
        assert f'"{table}"' not in src, (
            f"{table} is hard-coded in the module again; read it from the extract")


def test_losing_the_extract_self_skips_rather_than_inventing_a_member_list():
    """The fallback is empty, not a guess. A check asserting six table names with
    no source behind them would be the same defect wearing a default value."""
    src = MODULE_SRC.read_text(encoding="utf-8")
    assert '_SPWD.get("tables", ())' in src, \
        "the fallback must be empty so the check self-skips rather than guessing"


def test_the_client_half_of_the_item_is_left_to_log_review():
    """Two findings for one misconfiguration are counted twice in the FAIR figure.
    A filter covering all users but only one client is LREV-FLT-002's finding and
    must produce nothing here."""
    data = compliant()
    data["security_audit_log"] = [
        {"FILTER_NAME": "SAL01", "ACTIVE": "X", "CLIENT": "100", "USER": "*"}]
    assert run(data) == []


# --------------------------------------------------------------------------- #
#  The module <-> note contract                                                #
# --------------------------------------------------------------------------- #

def note_items():
    return json.loads(NOTE_JSON.read_text(encoding="utf-8"))["configuration_items"]


def test_the_module_and_the_note_agree_on_the_item_list():
    """Fails in BOTH directions.

    A note version that adds an item leaves it undispositioned and unnoticed; a
    disposition for an item the note no longer has is a claim about a document
    that does not say it any more. Neither may pass.
    """
    in_note = set(note_items())
    in_module = set(CONFIG_ITEM_DISPOSITION)
    assert in_note == in_module, (
        "the note and CONFIG_ITEM_DISPOSITION disagree.\n"
        f"  in the note, not dispositioned: {sorted(in_note - in_module)}\n"
        f"  dispositioned, not in the note: {sorted(in_module - in_note)}")


def test_the_note_item_list_has_no_duplicates():
    """A duplicated key would let the set comparison above pass while one item is
    silently represented twice."""
    items = note_items()
    assert len(items) == len(set(items))


@pytest.mark.parametrize("item,entry", sorted(CONFIG_ITEM_DISPOSITION.items()))
def test_every_disposition_is_one_of_the_three_kinds_and_explains_itself(item, entry):
    kind, why = entry
    assert kind in ("checked", "covered", "not_evidenceable"), item
    assert len(why) > 30, f"{item}: a disposition without a reason is not a decision"


def test_every_check_this_module_emits_is_dispositioned_as_checked():
    """The other direction of the same contract: a check id in the code that no
    disposition claims means the table has stopped describing the module."""
    claimed = set()
    for kind, why in CONFIG_ITEM_DISPOSITION.values():
        if kind == "checked":
            claimed.update(re.findall(r"\b[A-Z]+-ECS-\d{3}\b", why))
    emitted = set(re.findall(r'check_id="([^"]+)"',
                             MODULE_SRC.read_text(encoding="utf-8")))
    assert emitted == claimed, (
        f"emitted but not claimed: {sorted(emitted - claimed)}; "
        f"claimed but not emitted: {sorted(claimed - emitted)}")


def test_the_covered_dispositions_name_the_check_that_already_fires():
    """A 'covered' entry is a decision NOT to check something. It is only
    reviewable if it says what covers it."""
    for item, (kind, why) in CONFIG_ITEM_DISPOSITION.items():
        if kind == "covered":
            assert re.search(r"\b[A-Z][A-Z0-9]*(?:-[A-Z0-9*]+)+\b", why), item


# --------------------------------------------------------------------------- #
#  Finding plumbing: routing, category, id format, no invented identifiers     #
# --------------------------------------------------------------------------- #

def all_findings():
    """Every finding the module can emit, from a maximally non-compliant system."""
    return run({
        "table_auth_groups": [{"TABNAME": "T000", "CCLASS": "SS"}],
        "client_settings": [{"CLIENT": c} for c in ("000",) + OBSOLETE_CLIENTS],
        "security_audit_log": [{"FILTER_NAME": "SAL01", "ACTIVE": "X", "USER": "DDIC"}],
    })


def test_the_worst_case_system_fires_every_check():
    assert ids(all_findings()) == ["AUTH-ECS-001", "CRYPTO-ECS-001",
                                   "LREV-ECS-001", "STDUSR-ECS-001"]


@pytest.mark.parametrize("finding", all_findings(), ids=lambda f: f["check_id"])
def test_every_check_id_routes_to_a_team(finding):
    """An unrouted finding lands in nobody's queue and is worked by nobody."""
    assert team_for(finding["check_id"]) != "unassigned"


@pytest.mark.parametrize("finding", all_findings(), ids=lambda f: f["check_id"])
def test_every_category_reaches_the_compliance_frameworks(finding):
    """An unmapped category does not raise and does not warn — the findings are
    simply absent from every compliance panel, which still looks complete."""
    assert finding["category"] in ComplianceMapper.CATEGORY_THEMES


@pytest.mark.parametrize("finding", all_findings(), ids=lambda f: f["check_id"])
def test_every_check_id_follows_the_house_format(finding):
    assert re.fullmatch(r"[A-Z][A-Z0-9]*(-[A-Z0-9]+)+", finding["check_id"])


@pytest.mark.parametrize("finding", all_findings(), ids=lambda f: f["check_id"])
def test_every_finding_carries_the_contract(finding):
    assert finding["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
    assert finding["scope"] in ("object", "aggregate")
    assert finding["remediation"].strip()
    assert finding["references"], "a baseline finding must cite the baseline"
    assert finding["description"].strip()


@pytest.mark.parametrize("finding", all_findings(), ids=lambda f: f["check_id"])
def test_every_finding_cites_the_source_note(finding):
    assert any("3250501" in r for r in finding["references"])


def test_no_check_id_collides_with_another_module():
    """tests/test_check_id_uniqueness.py guards this repo-wide; this is the local
    copy so a collision fails the module's own suite too."""
    import ast as _ast
    mine = {f["check_id"] for f in all_findings()}
    for path in sorted((ROOT / "modules").glob("*.py")):
        if path.name == MODULE_SRC.name:
            continue
        tree = _ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        for node in _ast.walk(tree):
            if not (isinstance(node, _ast.Call)
                    and getattr(node.func, "attr", "") == "finding"):
                continue
            for kw in node.keywords:
                if (kw.arg == "check_id" and isinstance(kw.value, _ast.Constant)
                        and kw.value.value in mine):
                    pytest.fail(f"{kw.value.value} is already emitted by {path.name}")


def test_the_module_cites_no_note_number_but_the_source_note():
    """This repository has shipped invented SAP Note numbers before. The only note
    3250501's own reference list makes safe to cite here is 3250501 itself, and a
    number that creeps in later must fail rather than be believed."""
    src = MODULE_SRC.read_text(encoding="utf-8")
    cited = set(re.findall(r"Note\s+(\d{4,})", src))
    assert cited <= {"3250501"}, f"unverified SAP Note number(s) cited: {sorted(cited)}"


def test_the_fair_prefix_does_not_price_a_leftover_client_as_remote_code_execution():
    """Records the reason STDUSR-ECS-001 is not TRUST-ECS-001.

    `data/fair_scenarios.json` routes by check-id prefix BEFORE category, and
    TRUST- is routed to the remote-code-execution scenario. An undeleted client is
    a foothold, not an RCE, and the prefix alone would have set the loss magnitude
    with nothing anywhere saying so.
    """
    catalog = json.loads((ROOT / "data" / "fair_scenarios.json").read_text(encoding="utf-8"))
    rce = next(s for s in catalog["scenarios"] if s["id"] == "SAP-RCE-01")
    prefixes = tuple(rce.get("routing", {}).get("check_prefixes", []))
    assert not "STDUSR-ECS-001".startswith(prefixes)
