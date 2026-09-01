"""The HANA checks SAP's own security checklist asked for.

Every test here pairs a firing case with the mutation that must silence it.
A check that fires on the right export but also on the wrong one has not been
tested; it has been observed.

Source: SAP HANA Security Checklists and Recommendations (SAP HANA Platform
2.0 SPS 05, document version 1.1, PUBLIC).
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.hana_db_security import HanaDbSecurityAuditor          # noqa: E402


def fired(data):
    """{check_id: finding} for one export."""
    return {f["check_id"]: f for f in HanaDbSecurityAuditor(data).run_all_checks()}


def priv(grantee, gtype, privilege, obj="", grantable="FALSE"):
    return {"GRANTEE": grantee, "GRANTEE_TYPE": gtype, "PRIVILEGE": privilege,
            "OBJECT_NAME": obj, "IS_GRANTABLE": grantable}


def param(fname, section, key, value):
    return {"FILE_NAME": fname, "SECTION": section, "KEY": key, "VALUE": value}


# ── HANADB-PRIV-007 — privileges that arrive through role membership ────────
#
# The defect this closes: `check_system_privileges` carried the line
#
#     if gtype and gtype not in ("USER", ""):   # role grants handled elsewhere
#
# and they were not handled elsewhere. `check_powerful_roles` reads
# hana_granted_roles, which is who holds which ROLE, never which PRIVILEGES a
# role holds. SAP tells customers to grant through roles, so the estates
# following the advice put their critical privileges in the one place this
# module refused to read.

ROLE_CHAIN = {
    "hana_granted_privileges": [priv("Z_BASE", "ROLE", "DATA ADMIN")],
    "hana_granted_roles": [
        {"GRANTEE": "Z_DBA", "ROLE_NAME": "Z_BASE"},
        {"GRANTEE": "ALICE", "ROLE_NAME": "Z_DBA"},
    ],
}


def test_a_privilege_two_roles_away_from_a_user_is_found():
    f = fired(ROLE_CHAIN)["HANADB-PRIV-007"]
    assert f["affected_items"] == ["ALICE ← role Z_DBA ← role Z_BASE ← DATA ADMIN"], (
        "the whole path must be printed: a reviewer needs to know WHICH link to "
        "break, and the user is rarely the right one")
    assert f["severity"] == "HIGH"


def test_the_direct_grant_check_stays_quiet_on_a_role_held_privilege():
    """Otherwise the two checks would report the same grant twice."""
    assert "HANADB-PRIV-002" not in fired(ROLE_CHAIN)


@pytest.mark.parametrize("mutation, why", [
    ({"hana_granted_privileges": [priv("Z_BASE", "ROLE", "MONITOR ADMIN")]},
     "MONITOR ADMIN is not a critical system privilege"),
    ({"hana_granted_roles": []},
     "the role is granted to nobody, so nothing reaches a user"),
    ({"hana_granted_privileges": [priv("Z_BASE", "USER", "DATA ADMIN")]},
     "a USER grantee is HANADB-PRIV-002's finding, not this one"),
])
def test_role_held_privileges_stay_quiet_when_they_should(mutation, why):
    assert "HANADB-PRIV-007" not in fired({**ROLE_CHAIN, **mutation}), why


def test_a_role_granted_back_to_its_own_member_does_not_hang():
    """Role membership is a graph. A cycle in it must terminate."""
    cyclic = {**ROLE_CHAIN, "hana_granted_roles": ROLE_CHAIN["hana_granted_roles"]
              + [{"GRANTEE": "Z_BASE", "ROLE_NAME": "Z_DBA"}]}
    assert "HANADB-PRIV-007" in fired(cyclic)


def test_an_unsupplied_membership_export_is_said_not_assumed():
    """ABSENT IS NOT EMPTY, and this check must not report "nobody holds it".

    A role carrying DATA ADMIN whose membership was never collected is an open
    question. Rendering it as no holders is the false clean the whole module
    exists to avoid.
    """
    items = fired({"hana_granted_privileges": ROLE_CHAIN["hana_granted_privileges"]}
                  )["HANADB-PRIV-007"]["affected_items"]
    assert items == ["role Z_BASE ← DATA ADMIN (holders unknown: "
                     "hana_granted_roles not supplied)"]


def test_an_empty_membership_export_is_an_answer_not_a_question():
    """Supplied-and-empty means no role is granted to anyone. That is a result."""
    assert "HANADB-PRIV-007" not in fired(
        {**ROLE_CHAIN, "hana_granted_roles": []})


def test_public_is_left_to_the_check_that_owns_it():
    """PUBLIC is a role every user holds; PRIV-001 reports it at CRITICAL.

    Resolving it here would name the entire user list one severity band lower.
    """
    got = fired({"hana_granted_privileges": [priv("PUBLIC", "ROLE", "DATA ADMIN")]})
    assert "HANADB-PRIV-001" in got
    assert "HANADB-PRIV-007" not in got


# ── HANADB-PRIV-008 — combinations SAP names as critical ────────────────────
#
# A pair is not visible one privilege at a time, which is why no amount of
# tuning CRITICAL_SYSTEM_PRIVS finds one.

SPLIT_PAIR = {
    "hana_granted_privileges": [priv("Z_USERS", "ROLE", "USER ADMIN"),
                                priv("BOB", "USER", "ROLE ADMIN")],
    "hana_granted_roles": [{"GRANTEE": "BOB", "ROLE_NAME": "Z_USERS"}],
}


def test_a_pair_split_between_a_role_and_a_direct_grant_is_found():
    """The likelier shape by far — nobody granting the second role is looking
    at what the first one already carries."""
    f = fired(SPLIT_PAIR)["HANADB-PRIV-008"]
    assert f["severity"] == "CRITICAL"
    item, = f["affected_items"]
    assert "BOB holds USER ADMIN (via role Z_USERS) + ROLE ADMIN (direct)" in item
    assert "grant it to itself" in item, (
        "the consequence belongs in the finding: 'USER ADMIN + ROLE ADMIN' "
        "means nothing to a reader who has not memorised the checklist")


def test_the_two_halves_on_two_people_is_not_the_finding():
    """Segregation of duties is the control. Two people holding one half each
    is what it looks like when it works."""
    assert "HANADB-PRIV-008" not in fired({"hana_granted_privileges": [
        priv("CAROL", "USER", "USER ADMIN"), priv("BOB", "USER", "ROLE ADMIN")]})


def test_one_half_alone_is_not_the_finding():
    assert "HANADB-PRIV-008" not in fired(
        {**SPLIT_PAIR, "hana_granted_privileges": [priv("Z_USERS", "ROLE", "USER ADMIN")]})


@pytest.mark.parametrize("first, second", [
    ("AUDIT ADMIN", "AUDIT OPERATOR"),
    ("CREATE SCENARIO", "SCENARIO ADMIN"),
    ("CREATE STRUCTURED PRIVILEGE", "STRUCTUREDPRIVILEGE ADMIN"),
])
def test_every_pair_the_checklist_names_is_detected(first, second):
    got = fired({"hana_granted_privileges": [priv("DAVE", "USER", first),
                                             priv("DAVE", "USER", second)]})
    assert "HANADB-PRIV-008" in got, "%s + %s went unreported" % (first, second)


# ── HANADB-PRIV-009 — the full system info dump ─────────────────────────────

def test_execute_on_the_system_info_dump_is_reported():
    """An EXECUTE on an object, so no system-privilege check can see it — and
    the archive it produces carries configuration, traces and statement text."""
    f = fired({"hana_granted_privileges": [
        priv("DAVE", "USER", "EXECUTE", "FULL_SYSTEM_INFO_DUMP_CREATE")]})
    assert f["HANADB-PRIV-009"]["affected_items"] == [
        "DAVE ← EXECUTE ON FULL_SYSTEM_INFO_DUMP_CREATE"]


def test_a_role_holding_the_dump_right_is_labelled_as_a_role():
    item, = fired({"hana_granted_privileges": [
        priv("Z_SUPPORT", "ROLE", "EXECUTE", "FULL_SYSTEM_INFO_DUMP_RETRIEVE")]}
    )["HANADB-PRIV-009"]["affected_items"]
    assert item.startswith("Z_SUPPORT (role) ←")


def test_another_sys_procedure_is_not_this_finding():
    assert "HANADB-PRIV-009" not in fired({"hana_granted_privileges": [
        priv("DAVE", "USER", "EXECUTE", "GET_INSUFFICIENT_PRIVILEGE_ERROR_DETAILS")]})


# ── HANADB-USER-004 — an installation account left live ─────────────────────

def test_an_active_xsa_admin_is_reported_with_its_last_use():
    """"Never used since setup" and "used last week" are the same defect with
    very different urgency, and the export can tell them apart."""
    item, = fired({"hana_db_users": [{"USER_NAME": "XSA_ADMIN",
                                      "USER_DEACTIVATED": "FALSE",
                                      "LAST_SUCCESSFUL_CONNECT": "2026-08-14 09:12:00"}]}
                  )["HANADB-USER-004"]["affected_items"]
    assert "last successful connect 2026-08-14 09:12:00" in item


def test_an_unused_setup_account_says_so_rather_than_going_silent():
    item, = fired({"hana_db_users": [{"USER_NAME": "XSA_ADMIN",
                                      "USER_DEACTIVATED": "FALSE",
                                      "LAST_SUCCESSFUL_CONNECT": ""}]}
                  )["HANADB-USER-004"]["affected_items"]
    assert "no successful connect recorded" in item


def test_a_deactivated_setup_account_is_the_target_state():
    assert "HANADB-USER-004" not in fired({"hana_db_users": [
        {"USER_NAME": "XSA_ADMIN", "USER_DEACTIVATED": "TRUE"}]})


def test_the_setup_account_is_not_folded_into_the_superuser_finding():
    """HANADB-USER-001's advice is to KEEP the account for break-glass.

    XSA_ADMIN has no break-glass role — there is nothing it recovers that a
    named XS administrator cannot — so its correct end state is deactivated,
    not reserved, and the two must not share a remediation.
    """
    got = fired({"hana_db_users": [{"USER_NAME": "XSA_ADMIN",
                                    "USER_DEACTIVATED": "FALSE"}]})
    assert "HANADB-USER-004" in got
    assert "HANADB-USER-001" not in got
    assert "DEACTIVATE USER NOW" in got["HANADB-USER-004"]["remediation"]


# ── HANADB-PARAM-007 — the system replication channel ───────────────────────

REPLICATING = [param("global.ini", "system_replication", "operation_mode", "logreplay"),
               param("global.ini", "system_replication_hostname_resolution",
                     "10.0.0.7", "hana02")]


def test_replication_without_an_allowlist_is_reported():
    items = fired({"hana_parameters": REPLICATING})["HANADB-PARAM-007"]["affected_items"]
    assert any("allowed_sender: not set" in i for i in items)
    assert any("replication is configured" in i for i in items), (
        "the finding must show WHY it concluded this system replicates")


def test_an_empty_allowlist_is_no_allowlist():
    assert "HANADB-PARAM-007" in fired({"hana_parameters": REPLICATING + [
        param("global.ini", "system_replication_communication", "allowed_sender", "")]})


def test_replication_ssl_switched_off_is_reported_alongside_the_allowlist():
    """One control surface: who may take a copy, and whether the copy is
    readable in transit."""
    items = fired({"hana_parameters": REPLICATING + [
        param("global.ini", "system_replication_communication", "allowed_sender", "hana02"),
        param("global.ini", "system_replication_communication", "enable_ssl", "false")]}
    )["HANADB-PARAM-007"]["affected_items"]
    assert any("enable_ssl = false" in i for i in items)
    assert not any("allowed_sender" in i for i in items), (
        "the allowlist is set; reporting it would be wrong")


def test_an_unread_ssl_setting_alone_is_not_a_finding():
    """A parameter that is not in the export is not a parameter set to false."""
    assert "HANADB-PARAM-007" not in fired({"hana_parameters": REPLICATING + [
        param("global.ini", "system_replication_communication",
              "allowed_sender", "hana02")]})


def test_a_system_that_does_not_replicate_is_left_alone():
    """Most systems have no replication. Firing on all of them to catch the
    few that do is how a real finding gets skimmed past."""
    assert "HANADB-PARAM-007" not in fired({"hana_parameters": [
        param("global.ini", "communication", "sslenforce", "true")]})


# ── HANADB-PARAM-008 — IMPORT/EXPORT file access ────────────────────────────

def test_relaxed_import_export_file_security_names_who_can_use_it():
    """The parameter is only exploitable by a holder of IMPORT or EXPORT, and
    the two facts are otherwise assessed by different people."""
    items = fired({
        "hana_parameters": [param("indexserver.ini", "import_export",
                                  "file_security", "low")],
        "hana_granted_privileges": [priv("EVE", "USER", "EXPORT")],
    })["HANADB-PARAM-008"]["affected_items"]
    assert "indexserver.ini [import_export] file_security = low" in items
    assert any("EVE" in i for i in items)


def test_no_privilege_export_says_not_found_rather_than_none():
    items = fired({"hana_parameters": [param("indexserver.ini", "import_export",
                                             "file_security", "medium")]}
                  )["HANADB-PARAM-008"]["affected_items"]
    assert any("none found in the supplied privilege export" in i for i in items)


def test_the_strict_setting_passes_whatever_its_case():
    assert "HANADB-PARAM-008" not in fired({"hana_parameters": [
        param("indexserver.ini", "import_export", "file_security", "HIGH")]})


def test_an_absent_parameter_is_not_reported_as_relaxed():
    assert "HANADB-PARAM-008" not in fired({"hana_parameters": [
        param("global.ini", "communication", "sslenforce", "true")]})


# ── HANADB-TRACE-002 — components left at DEBUG ─────────────────────────────

def test_every_file_carrying_a_debug_component_is_named():
    """`_param_index` keeps ONE value per key name across every file, so a
    lookup by key would report one component and hide the rest — [trace] lives
    in indexserver.ini, nameserver.ini and xsengine.ini at the same time."""
    items = fired({"hana_parameters": [
        param("indexserver.ini", "trace", "sql", "DEBUG"),
        param("nameserver.ini", "trace", "sql", "INFO"),
        param("xsengine.ini", "trace", "authentication", "debug"),
    ]})["HANADB-TRACE-002"]["affected_items"]
    assert items == ["indexserver.ini [trace] sql = DEBUG",
                     "xsengine.ini [trace] authentication = debug"]


def test_default_trace_levels_are_not_reported():
    assert "HANADB-TRACE-002" not in fired({"hana_parameters": [
        param("indexserver.ini", "trace", "sql", "INFO")]})


def test_reverting_the_setting_is_not_the_whole_remediation():
    """The trace files outlive the parameter, and they hold the data."""
    f = fired({"hana_parameters": [param("indexserver.ini", "trace", "sql", "DEBUG")]}
              )["HANADB-TRACE-002"]
    assert "Delete trace files" in f["remediation"]


# ── HANADB-PARAM-009 — the tenant configuration blocklist ───────────────────

MULTIDB = [param("multidb.ini", "readonly_parameters",
                 "global.ini/auditing configuration/global_auditing_state", ""),
           param("global.ini", "communication", "sslenforce", "true")]


def test_a_control_this_scan_asserts_but_a_tenant_can_change_is_reported():
    items = fired({"hana_parameters": MULTIDB})["HANADB-PARAM-009"]["affected_items"]
    assert any("sslenforce" in i and "HANADB-PARAM-003" in i for i in items), (
        "each entry must name the check whose verdict the tenant can reverse — "
        "that is what makes this a meta-control rather than another parameter")
    assert not any("global_auditing_state" in i for i in items), (
        "that one IS blocklisted")


def test_a_full_blocklist_produces_no_finding():
    rows = [param("multidb.ini", "readonly_parameters", p, "")
            for p, _cid in HanaDbSecurityAuditor.TENANT_PROTECTED_PARAMS]
    assert "HANADB-PARAM-009" not in fired({"hana_parameters": rows})


def test_an_export_with_no_multidb_rows_is_silent():
    """Single-container system, or a collector that did not read the file —
    and a FILE_NAME/SECTION/KEY/VALUE export cannot tell the two apart. Firing
    on every system to catch the second would put a finding on the majority to
    describe a minority."""
    assert "HANADB-PARAM-009" not in fired({"hana_parameters": [
        param("global.ini", "communication", "sslenforce", "true")]})


# ── HANADB-AUDIT-005 — the auditing state that was never read ───────────────

def test_a_missing_auditing_state_is_reported_as_coverage_not_as_a_verdict():
    """SAP ships auditing DISABLED, so silence here used to render the check
    that reports "no forensic trail at all" as a clean result.

    It is INFO, not HIGH: `degrades_coverage` is this codebase's UNKNOWN
    mechanism, and raising an unread value to HIGH would assert the verdict the
    finding has just said it could not read.
    """
    f = fired({"hana_parameters": [param("global.ini", "communication",
                                         "sslenforce", "true")]})["HANADB-AUDIT-005"]
    assert f["severity"] == "INFO"
    assert f["details"]["degrades_coverage"] is True


def test_a_present_auditing_state_is_measured_not_flagged():
    got = fired({"hana_parameters": [param("global.ini", "auditing configuration",
                                           "global_auditing_state", "true")]})
    assert "HANADB-AUDIT-005" not in got
    assert "HANADB-AUDIT-001" not in got


def test_a_disabled_auditing_state_is_still_the_critical_finding():
    got = fired({"hana_parameters": [param("global.ini", "auditing configuration",
                                           "global_auditing_state", "false")]})
    assert got["HANADB-AUDIT-001"]["severity"] == "CRITICAL"
    assert "HANADB-AUDIT-005" not in got


# ── HANADB-PARAM-006 — a section is not a key ───────────────────────────────

def test_a_defined_internal_network_is_no_longer_denied():
    """`internal_hostname_resolution` is a SECTION whose keys are adapter IP
    addresses. Looking it up as a KEY returned None on every real export, so
    the finding asserted "no internal network is defined" on landscapes that
    define one.
    """
    listening = [param("global.ini", "communication", "listeninterface", ".global")]
    without = fired({"hana_parameters": listening})["HANADB-PARAM-006"]
    with_net = fired({"hana_parameters": listening + [
        param("global.ini", "internal_hostname_resolution", "192.168.1.11", "hana01")]}
    )["HANADB-PARAM-006"]
    assert any("is not set" in i for i in without["affected_items"])
    assert not any("is not set" in i for i in with_net["affected_items"])
    assert with_net["severity"] == "CRITICAL", (
        "the binding is still wrong; only the supplementary claim was")


# ── the privilege names the sets did not carry ──────────────────────────────

@pytest.mark.parametrize("privilege", [
    "BACKUP OPERATOR",        # no "ADMIN" substring — every fallback missed it
    "CREATE REMOTE SOURCE",   # likewise; defines an outbound database connection
    "LDAP ADMIN", "SSL ADMIN", "WORKLOAD ADMIN", "CLIENT PARAMETER ADMIN",
])
def test_privileges_the_checklist_names_are_now_reported(privilege):
    got = fired({"hana_granted_privileges": [priv("FRANK", "USER", privilege)]})
    assert "HANADB-PRIV-003" in got, "%s went unreported" % privilege
    assert any(privilege in i for i in got["HANADB-PRIV-003"]["affected_items"])
