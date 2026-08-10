# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
SAP Cloud ALM CSA store import.

Two things are under test, and the second is the point of the exercise.

1. The translation itself — mostly COLUMN NAMES. SAP's published policies name the
   stores and a few of their fields; the header a customer actually gets depends on
   the export route, so every field is resolved through an alias list. A field that
   silently fails to resolve does not raise, it produces an empty column, and an
   empty column reads to a check as "compliant". Those are the failures worth a test.

2. That the SAME CHECKS FIRE from CSA-shaped input as from our native shape. The
   importer's whole claim is that existing checks run unchanged against Cloud ALM
   data; a translation that loads cleanly and then produces a different finding set
   has not delivered that, it has quietly forked the product's behaviour by input
   format.
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import cloudalm_import as calm            # noqa: E402
from modules.data_loader import DataLoader             # noqa: E402
from server.identity import fingerprint_finding        # noqa: E402

CLOUDALM_DIR = ROOT / "sample_data_cloudalm"

#: The logical sources a CSA export can supply. The equivalence test restricts
#: BOTH inputs to these so it compares like with like.
MAPPED_KEYS = sorted({key for keys in calm.STORE_TARGETS.values() for key in keys})


def _load(directory):
    """Load a directory with the loader's console chatter suppressed."""
    loader = DataLoader(Path(directory))
    with contextlib.redirect_stdout(io.StringIO()):
        data = loader.load_all()
    return loader, data


def _t(store, rows):
    """Translate rows for one store, returning the sources only."""
    translated, _notes = calm.translate_store(store, rows)
    return translated


def _notes(store, rows):
    _translated, notes = calm.translate_store(store, rows)
    return notes


# --------------------------------------------------------------------------- #
#  Catalogue integrity                                                        #
# --------------------------------------------------------------------------- #

def test_every_translatable_store_has_a_translator():
    """A store advertised as translatable with no translator claims coverage we
    do not have — the import report would say 'unknown_store' for a store our own
    documentation lists as supported."""
    assert set(calm.STORE_TARGETS) == set(calm.TRANSLATORS)


def test_translated_and_refused_stores_are_disjoint():
    """A store in both lists resolves by dict ordering, which is not a decision."""
    assert not (set(calm.STORE_TARGETS) & set(calm.UNMAPPED_STORES))


def test_every_refusal_states_a_reason():
    for store, reason in calm.UNMAPPED_STORES.items():
        assert reason and len(reason) > 20, store


def test_every_target_is_a_real_loader_source():
    """A typo in a target key would route rows to a source no check reads —
    a translation that loads cleanly and feeds nothing."""
    for store, keys in calm.STORE_TARGETS.items():
        for key in keys:
            assert key in DataLoader.FILE_MAP, "{0} -> unknown source {1}".format(
                store, key)


# --------------------------------------------------------------------------- #
#  Filename recognition                                                       #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("filename,expected", [
    ("ABAP_INSTANCE_PAHI.csv", "ABAP_INSTANCE_PAHI"),
    ("abap_instance_pahi.csv", "ABAP_INSTANCE_PAHI"),
    ("CSA_STANDARD_USERS.json", "STANDARD_USERS"),
    ("CALM_SICF_SERVICES.csv", "SICF_SERVICES"),
    # An export that appends the SID / instance / collection date.
    ("ABAP_INSTANCE_PAHI_PRD_00.csv", "ABAP_INSTANCE_PAHI"),
    ("CLIENTS-20260806.csv", "CLIENTS"),
    ("Parameters.csv", "PARAMETERS"),
    # Not stores.
    ("users.csv", None),
    ("report.html", None),
    ("ABAP_INSTANCE_PAHI.pdf", None),
    ("", None),
])
def test_store_for_filename(filename, expected):
    assert calm.store_for_filename(filename) == expected


def test_slot_store_is_not_swallowed_by_its_own_prefix():
    """`AUDIT_CONFIGURATION_SLOT` starts with `AUDIT_CONFIGURATION`, which we
    deliberately refuse to translate. A shortest-first prefix match would file the
    audit filter slots under the refusal and silently drop them."""
    assert calm.store_for_filename("AUDIT_CONFIGURATION_SLOT.csv") == \
        "AUDIT_CONFIGURATION_SLOT"
    assert calm.store_for_filename("AUDIT_CONFIGURATION.csv") == \
        "AUDIT_CONFIGURATION"


# --------------------------------------------------------------------------- #
#  ABAP_INSTANCE_PAHI -> security_params                                      #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("row", [
    {"PARAMETER": "login/min_password_lng", "VALUE": "6"},
    {"NAME": "login/min_password_lng", "VALUE": "6"},
    {"PARAM": "login/min_password_lng", "PARAM_VALUE": "6"},
    {"Parameter Name": "login/min_password_lng", "Current Value": "6"},
    {"parameter": "login/min_password_lng", "value": "6"},
])
def test_pahi_column_aliases_all_resolve(row):
    out = _t("ABAP_INSTANCE_PAHI", [row])["security_params"]
    assert out == [{"NAME": "login/min_password_lng", "VALUE": "6",
                    "SOURCE_STORE": "ABAP_INSTANCE_PAHI"}]


def test_pahi_keeps_an_empty_value_rather_than_dropping_the_parameter():
    """`gw/sec_info` with no value IS the finding. Dropping the row because the
    value is empty would turn an unset gateway ACL into a parameter we never saw."""
    out = _t("ABAP_INSTANCE_PAHI", [{"PARAMETER": "gw/sec_info", "VALUE": ""}])
    assert out["security_params"][0]["VALUE"] == ""


def test_pahi_row_without_a_parameter_name_is_counted_not_silently_dropped():
    notes = _notes("ABAP_INSTANCE_PAHI", [{"VALUE": "6"}])
    assert notes["skipped_rows"] == 1


def test_pahi_carries_the_instance_when_present():
    out = _t("ABAP_INSTANCE_PAHI",
             [{"PARAMETER": "rsau/enable", "VALUE": "0", "INSTANCE": "PRD_00"}])
    assert out["security_params"][0]["INSTANCE"] == "PRD_00"


# --------------------------------------------------------------------------- #
#  STANDARD_USERS -> standard_users                                           #
# --------------------------------------------------------------------------- #

def test_uflag_is_translated_to_a_lock_flag():
    """USR02-UFLAG is numeric: 0 unlocked, any set bit locked. The consumer's
    truthiness test reads "64" as FALSE, so an untranslated UFLAG would report
    every locked standard user as unlocked — a silent pass on a CRITICAL check."""
    rows = [{"USERNAME": "DDIC", "CLIENT": "000", "UFLAG": "64"},
            {"USERNAME": "SAP*", "CLIENT": "000", "UFLAG": "0"}]
    out = _t("STANDARD_USERS", rows)["standard_users"]
    assert out[0]["LOCKED"] == "X"
    assert out[1]["LOCKED"] == ""


def test_textual_lock_and_password_columns_pass_through():
    out = _t("STANDARD_USERS", [{"USER": "SAP*", "CLIENT": "000",
                                 "DEFAULT_PASSWORD": "YES", "LOCKED": "NO"}])
    assert out["standard_users"][0]["DEFAULT_PASSWORD"] == "X"
    assert out["standard_users"][0]["LOCKED"] == ""


def test_a_single_status_column_is_decomposed():
    """SAP's 1ASTDUSR policy describes this store as standard-user *status*; an
    export may collapse both facts into one column."""
    out = _t("STANDARD_USERS", [
        {"USERNAME": "SAP*", "CLIENT": "000", "STATUS": "Default password, unlocked"},
        {"USERNAME": "TMSADM", "CLIENT": "000", "STATUS": "Locked"},
    ])["standard_users"]
    assert (out[0]["DEFAULT_PASSWORD"], out[0]["LOCKED"]) == ("X", "")
    assert out[1]["LOCKED"] == "X"


def test_status_column_never_overrides_dedicated_columns():
    out = _t("STANDARD_USERS", [{"USERNAME": "DDIC", "CLIENT": "000",
                                 "LOCKED": "X", "STATUS": "unlocked"}])
    assert out["standard_users"][0]["LOCKED"] == "X"


def test_clients_seen_are_recorded_for_the_partial_scope_problem():
    """Standard-user hygiene is cross-client and a RISE customer may only be able
    to evidence some clients. The clients we actually saw have to be reportable, or
    'compliant in the clients we saw' renders as 'compliant' (RISE model §3.1)."""
    notes = _notes("STANDARD_USERS", [
        {"USERNAME": "SAP*", "CLIENT": "000"},
        {"USERNAME": "SAP*", "CLIENT": "100"},
    ])
    assert notes["clients_seen"] == ["000", "100"]


# --------------------------------------------------------------------------- #
#  AUTH_PROFILE_USER -> profiles (and never users)                            #
# --------------------------------------------------------------------------- #

def test_auth_profile_user_maps_to_usr04_shape():
    out = _t("AUTH_PROFILE_USER", [{"PROFILE": "SAP_ALL", "USERNAME": "jsmith",
                                    "USER_TYPE": "A", "STATUS": "ASSIGNED"}])
    row = out["profiles"][0]
    assert (row["BNAME"], row["PROFILE"]) == ("JSMITH", "SAP_ALL")


def test_auth_profile_user_never_populates_the_user_master():
    """The store holds only users who hold a profile. Feeding that partial
    population to checks that compute rates over the user master — dormancy,
    password age, never-logged-on — makes every one of them understate."""
    out = _t("AUTH_PROFILE_USER", [{"PROFILE": "SAP_ALL", "USERNAME": "JSMITH"}])
    assert "users" not in out
    assert "users" not in calm.STORE_TARGETS["AUTH_PROFILE_USER"]
    assert not any("users" in targets for targets in calm.STORE_TARGETS.values())


def test_auth_profile_user_row_missing_either_half_is_skipped():
    notes = _notes("AUTH_PROFILE_USER", [{"PROFILE": "SAP_ALL"},
                                         {"USERNAME": "JSMITH"}])
    assert notes["skipped_rows"] == 2


# --------------------------------------------------------------------------- #
#  SICF_SERVICES -> icf_services                                              #
# --------------------------------------------------------------------------- #

def test_sicf_prefers_the_full_path_over_the_leaf_name():
    """The high-risk-service check substring-matches on the path, so picking the
    leaf ("webrfc") over "/sap/bc/webrfc" would make every match miss."""
    out = _t("SICF_SERVICES", [{"NAME": "webrfc", "PATH": "/sap/bc/webrfc",
                                "ACTIVE": "X", "AUTH_REQUIRED": "NO"}])
    assert out["icf_services"][0]["ICF_NAME"] == "/sap/bc/webrfc"


def test_sicf_active_tokens_are_normalised():
    rows = [{"PATH": "/a", "ACTIVE": "ACTIVE"}, {"PATH": "/b", "ACTIVE": "INACTIVE"}]
    out = _t("SICF_SERVICES", rows)["icf_services"]
    assert [r["ICF_ACTIVE"] for r in out] == ["X", ""]


def test_an_unrecognised_active_token_is_passed_through_and_recorded():
    """Guessing that some single letter means 'inactive' would clear an exposed
    service with nothing anywhere saying so. Unknown tokens survive and surface."""
    translated, notes = calm.translate_store(
        "SICF_SERVICES", [{"PATH": "/sap/bc/webrfc", "ACTIVE": "Z"}])
    assert translated["icf_services"][0]["ICF_ACTIVE"] == "Z"
    assert "ICF_ACTIVE=Z" in notes["unrecognised_values"]


def test_sicf_auth_mechanism_is_not_flattened_to_a_boolean():
    out = _t("SICF_SERVICES", [{"PATH": "/a", "ACTIVE": "X",
                                "AUTHENTICATION": "BASIC"}])
    assert out["icf_services"][0]["AUTH_REQUIRED"] == "BASIC"


# --------------------------------------------------------------------------- #
#  Gateway + message-server ACLs                                              #
# --------------------------------------------------------------------------- #

def test_structured_secinfo_columns_are_composed_into_a_rule():
    out = _t("GW_SECINFO", [{"ACCESS": "PERMIT", "TP": "sapxpg",
                             "HOST": "*", "USER": "*"}])
    assert out["gw_secinfo"][0]["RULE"] == "P TP=sapxpg HOST=* USER=*"


def test_structured_acl_columns_are_not_also_forwarded_separately():
    """Forwarding them as well changes WHICH FINDINGS FIRE. The permit-all check
    matches the literal word "PERMIT" in the rule text but takes a structured
    ACTION of "P" as a permit, so the same ACL yields three extra CRITICAL
    findings purely because it arrived as a store export. An importer that changes
    finding outcomes is not a translator, and the ACL notation loses nothing:
    every field is stated verbatim in the rule text."""
    row = _t("GW_SECINFO", [{"ACCESS": "PERMIT", "TP": "sapxpg",
                             "HOST": "*", "USER": "*"}])["gw_secinfo"][0]
    assert set(row) == {"RULE", "SOURCE_STORE"}


def test_a_raw_acl_line_is_never_rewritten():
    out = _t("GW_REGINFO", [{"RULE": "P TP=BW_RFC HOST=10.0.1.60"}])
    assert out["gw_reginfo"][0]["RULE"] == "P TP=BW_RFC HOST=10.0.1.60"


def test_deny_rules_keep_their_verdict():
    out = _t("GW_SECINFO", [{"ACCESS": "DENY", "TP": "*", "HOST": "external.*",
                             "USER": "*"}])
    assert out["gw_secinfo"][0]["RULE"].startswith("D ")


def test_ms_secinfo_composes_an_acl_line():
    out = _t("MS_SECINFO", [{"HOST": "*", "SERVICE": "*"}])
    row = out["ms_acl"][0]
    assert (row["HOST"], row["LINE"]) == ("*", "HOST=* SERVICE=*")


# --------------------------------------------------------------------------- #
#  Audit slots + clients                                                      #
# --------------------------------------------------------------------------- #

def test_audit_slot_without_a_name_is_named_after_its_slot():
    """SAP's 2AAUDIT policy counts filter SLOTS. A nameless slot must still be a
    countable row, or a system with ten unnamed slots reads as having none."""
    out = _t("AUDIT_CONFIGURATION_SLOT",
             [{"SLOT": "3", "ACTIVE": "X", "EVENT_CLASS": "rfc_logon"}])
    assert out["audit_config"][0]["FILTER_NAME"] == "SLOT_3"


def test_audit_profile_type_is_not_invented_when_absent():
    """Defaulting an absent value to STATIC would make a dynamic-only
    configuration look permanent."""
    out = _t("AUDIT_CONFIGURATION_SLOT", [{"SLOT": "1", "ACTIVE": "X"}])
    assert "PROFILE_TYPE" not in out["audit_config"][0]


def test_client_textual_change_options_become_canonical_fields():
    out = _t("CLIENTS", [{"MANDT": "100", "CCCATEGORY": "P",
                          "CCCORACTIV": "MODIFIABLE", "CCNOCLIIND": "YES",
                          "CCCOPYLOCK": "YES"}])
    row = out["client_settings"][0]
    assert (row["CLIENT"], row["ROLE"]) == ("100", "P")
    assert row["CHANGES_ALLOWED"] == "MODIFIABLE"
    assert row["CROSS_CLIENT_CHANGES"] == "YES"


def test_raw_t000_change_codes_are_quarantined_and_reported():
    """T000 stores the change options as single-character codes whose meanings are
    in no source we hold. Decoding by guess would either invent a CRITICAL
    'production client is modifiable' finding or clear a real one, so a code goes
    somewhere the check cannot see it AND into the import report."""
    translated, notes = calm.translate_store(
        "CLIENTS", [{"MANDT": "100", "CCCATEGORY": "P", "CCCORACTIV": "2"}])
    row = translated["client_settings"][0]
    assert "CHANGES_ALLOWED" not in row
    assert row["RAW_CHANGES_ALLOWED"] == "2"
    assert notes["undecoded_client_codes"] == ["client 100: CHANGES_ALLOWED=2"]


# --------------------------------------------------------------------------- #
#  Refusals                                                                   #
# --------------------------------------------------------------------------- #

def test_java_parameters_store_never_becomes_abap_security_params():
    """SAP's Java stack has a store literally named `Parameters`. Translating it
    would score Java AS settings against ABAP profile-parameter thresholds."""
    translated, notes = calm.translate_store(
        "PARAMETERS", [{"NAME": "ume.logon.security_policy.password_min_length",
                        "VALUE": "6"}])
    assert translated == {}
    assert notes["status"] == "recognised_not_translated"
    assert notes["technology"] == "JAVA"


def test_java_role_assignment_store_is_not_mistaken_for_abap():
    translated, notes = calm.translate_store("AUTH_ROLE_USER", [{"USER": "X"}])
    assert translated == {} and notes["technology"] == "JAVA"


def test_global_audit_settings_do_not_inflate_the_filter_count():
    """AUDIT_CONFIGURATION holds global settings, not filter slots. Mixing them
    into audit_config would turn 'no audit filters configured' into a pass."""
    translated, notes = calm.translate_store(
        "AUDIT_CONFIGURATION", [{"SETTING": "RECORDING_TARGET", "VALUE": "DATABASE"}])
    assert translated == {}
    assert notes["status"] == "recognised_not_translated"


def test_an_unknown_store_is_reported_not_raised():
    translated, notes = calm.translate_store("SOME_FUTURE_STORE", [{"A": "1"}])
    assert translated == {} and notes["status"] == "unknown_store"


# --------------------------------------------------------------------------- #
#  File / directory handling                                                  #
# --------------------------------------------------------------------------- #

def test_json_odata_envelope_is_unwrapped(tmp_path):
    payload = {"value": [{"PARAMETER": "rsau/enable", "VALUE": "0"}]}
    (tmp_path / "ABAP_INSTANCE_PAHI.json").write_text(json.dumps(payload),
                                                      encoding="utf-8")
    translated, report = calm.load_cloudalm(tmp_path)
    assert translated["security_params"] == [
        {"NAME": "rsau/enable", "VALUE": "0", "SOURCE_STORE": "ABAP_INSTANCE_PAHI"}]
    assert report[0]["status"] == "translated"


def test_a_bare_json_list_is_accepted(tmp_path):
    (tmp_path / "GW_REGINFO.json").write_text(
        json.dumps([{"RULE": "P TP=* HOST=*"}]), encoding="utf-8")
    translated, _report = calm.load_cloudalm(tmp_path)
    assert translated["gw_reginfo"][0]["RULE"] == "P TP=* HOST=*"


def test_an_unreadable_store_is_reported_and_the_others_still_load(tmp_path):
    (tmp_path / "ABAP_INSTANCE_PAHI.json").write_text("{not json", encoding="utf-8")
    (tmp_path / "GW_REGINFO.csv").write_text("RULE\nP TP=* HOST=*\n", encoding="utf-8")
    translated, report = calm.load_cloudalm(tmp_path)
    statuses = {e["store"]: e["status"] for e in report}
    assert statuses["ABAP_INSTANCE_PAHI"] == "unreadable"
    assert "gw_reginfo" in translated


def test_an_empty_directory_yields_no_report(tmp_path):
    translated, report = calm.load_cloudalm(tmp_path)
    assert translated == {} and report == []


def test_a_missing_directory_is_not_an_error(tmp_path):
    assert calm.discover_stores(tmp_path / "nope") == {}


def test_there_is_no_one_argument_is_this_a_cloudalm_export_helper():
    """`STANDARD_USERS`, `GW_SECINFO` and `GW_REGINFO` are both store names and our
    own filenames, so such a predicate answers "yes, Cloud ALM" for an ordinary
    native export directory unless the caller also passes the already-claimed
    files. A convenience function whose one-argument form is wrong is worse than no
    function — this asserts nobody adds one back."""
    assert not hasattr(calm, "looks_like_cloudalm_export")
    # The trap it would have fallen into, demonstrated:
    assert "STANDARD_USERS" in calm.discover_stores(ROOT / "sample_data")
    assert "STANDARD_USERS" not in calm.discover_stores(
        ROOT / "sample_data", skip_files={"standard_users.csv"})


# --------------------------------------------------------------------------- #
#  DataLoader wiring                                                          #
# --------------------------------------------------------------------------- #

def test_native_export_directory_reports_no_cloudalm_import():
    """`standard_users.csv`, `gw_secinfo.csv` and `gw_reginfo.csv` are ALSO CSA
    store names. Without the skip-list the bundled native sample_data would report
    a Cloud ALM import it never performed."""
    loader, _data = _load(ROOT / "sample_data")
    assert loader.cloudalm_report == []


def test_native_loading_is_unchanged_by_the_new_pass():
    _loader, data = _load(ROOT / "sample_data")
    for key in MAPPED_KEYS:
        assert data.get(key), "native source {0} disappeared".format(key)
    assert data["standard_users"][0]["USER"] == "SAP*"


def test_cloudalm_directory_populates_every_mapped_source():
    loader, data = _load(CLOUDALM_DIR)
    for key in MAPPED_KEYS:
        assert data.get(key), "{0} not populated from the CSA export".format(key)
    stores = {e["store"]: e for e in loader.cloudalm_report}
    assert stores["ABAP_INSTANCE_PAHI"]["status"] == "translated"
    assert stores["PARAMETERS"]["status"] == "recognised_not_translated"


def test_a_named_file_beats_a_store_export(tmp_path):
    """The existing convention must not change meaning because a store file
    happens to be in the same directory."""
    (tmp_path / "security_params.csv").write_text(
        "NAME,VALUE\nlogin/min_password_lng,12\n", encoding="utf-8")
    (tmp_path / "ABAP_INSTANCE_PAHI.csv").write_text(
        "PARAMETER,VALUE\nlogin/min_password_lng,4\n", encoding="utf-8")
    _loader, data = _load(tmp_path)
    assert data["security_params"] == [{"NAME": "login/min_password_lng",
                                        "VALUE": "12"}]


def test_a_colliding_store_name_is_decided_by_case_not_by_the_host_os(tmp_path):
    """`STANDARD_USERS` is both a CSA store and our own filename. On Windows the
    filesystem cannot tell the two apart, so a bare `(dir / "standard_users.csv")
    .exists()` matched the store file and the FILE_MAP pass ate it RAW — untranslated,
    with UFLAG=64 reading as unlocked. The same directory went to the importer on
    Linux. One export, two products, decided by the host OS."""
    (tmp_path / "STANDARD_USERS.csv").write_text(
        "USERNAME,CLIENT,UFLAG\nDDIC,000,64\n", encoding="utf-8")
    loader, data = _load(tmp_path)
    assert [e["status"] for e in loader.cloudalm_report] == ["translated"]
    assert data["standard_users"][0]["LOCKED"] == "X"


def test_our_own_filename_still_takes_the_native_path(tmp_path):
    """The exact lower-case name is the native convention and must not be diverted
    into the importer by the collision rule above."""
    (tmp_path / "standard_users.csv").write_text(
        "USER,CLIENT,LOCKED\nDDIC,000,X\n", encoding="utf-8")
    loader, data = _load(tmp_path)
    assert loader.cloudalm_report == []
    assert data["standard_users"] == [{"USER": "DDIC", "CLIENT": "000",
                                       "LOCKED": "X"}]


def test_a_store_export_fills_only_what_is_missing(tmp_path):
    (tmp_path / "security_params.csv").write_text(
        "NAME,VALUE\nrsau/enable,0\n", encoding="utf-8")
    (tmp_path / "CLIENTS.csv").write_text(
        "MANDT,CCCATEGORY\n100,P\n", encoding="utf-8")
    _loader, data = _load(tmp_path)
    assert data["security_params"][0]["VALUE"] == "0"
    assert data["client_settings"][0]["CLIENT"] == "100"


def test_the_java_parameters_file_does_not_reach_security_params():
    """End to end, from the fixture directory: the ABAP parameters come from
    ABAP_INSTANCE_PAHI and nothing from Parameters.csv is in there."""
    _loader, data = _load(CLOUDALM_DIR)
    names = {row["NAME"] for row in data["security_params"]}
    assert "login/min_password_lng" in names
    assert not any(name.startswith("ume.") for name in names)


def test_the_user_master_is_not_faked_from_csa_data():
    """No CSA store in SAP's baseline policies carries a full USR02 user master,
    so `users` must stay absent rather than be reconstructed from a partial one."""
    _loader, data = _load(CLOUDALM_DIR)
    assert data.get("users") is None


# --------------------------------------------------------------------------- #
#  THE POINT: the same checks fire from CSA-shaped input                      #
# --------------------------------------------------------------------------- #

def _findings_from(data):
    """Run every auditor that consumes a CSA-translatable source."""
    from modules.security_params import SecurityParamAuditor
    from modules.baseline_params import BaselineParamAuditor
    from modules.network_services import NetworkServiceAuditor
    from modules.integration_layer import IntegrationLayerAuditor
    from modules.system_trust import SystemTrustAuditor
    from modules.code_transport import CodeTransportAuditor
    from modules.user_auth_audit import UserAuthAuditor
    from modules.log_monitoring import LogMonitoringAuditor

    findings = []
    for auditor in (SecurityParamAuditor, BaselineParamAuditor,
                    NetworkServiceAuditor, IntegrationLayerAuditor,
                    SystemTrustAuditor, CodeTransportAuditor,
                    UserAuthAuditor, LogMonitoringAuditor):
        findings.extend(auditor(dict(data)).run_all_checks())
    return findings


@pytest.fixture(scope="module")
def paired_findings():
    _l1, native = _load(ROOT / "sample_data")
    _l2, csa = _load(CLOUDALM_DIR)
    # Restrict both sides to the sources a CSA export can supply, so the
    # comparison is about the translation and not about which extra files
    # happen to sit in one directory.
    native_subset = {key: native.get(key) for key in MAPPED_KEYS}
    csa_subset = {key: csa.get(key) for key in MAPPED_KEYS}
    return _findings_from(native_subset), _findings_from(csa_subset)


def test_the_same_checks_fire_from_csa_shaped_input(paired_findings):
    native, csa = paired_findings
    assert {f["check_id"] for f in native} == {f["check_id"] for f in csa}
    assert len(native) > 20, "the fixture stopped exercising the checks"


def test_findings_keep_their_identity_across_the_translation(paired_findings):
    """Stronger than matching check ids: the fingerprint is what makes a finding
    the SAME finding across runs. If re-uploading the same system as a Cloud ALM
    export minted new fingerprints, every finding's age would reset and the
    mitigation journey would be wrong for a whole scan."""
    native, csa = paired_findings
    native_fp = {fingerprint_finding(f, "PRD", "100")[0] for f in native}
    csa_fp = {fingerprint_finding(f, "PRD", "100")[0] for f in csa}
    assert native_fp == csa_fp


def test_severity_and_affected_counts_match(paired_findings):
    native, csa = paired_findings

    def index(findings):
        out = {}
        for f in findings:
            out.setdefault(f["check_id"], []).append(
                (f["severity"], f["affected_count"]))
        return {k: sorted(v) for k, v in out.items()}

    assert index(native) == index(csa)
