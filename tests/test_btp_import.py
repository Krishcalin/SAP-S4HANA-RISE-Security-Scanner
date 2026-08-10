# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
BTP administrative export importers.

The point of these tests is NOT that the translators produce some shape — it is
that the EXISTING btpcloud / s4authz checks fire, unchanged, when the only thing
in the data directory is the raw output of SAP's own BTP tooling. So the
assertions are on check ids and on the objects those checks name, not on the
intermediate dicts.

The second half is the other half of the contract, and the reason the importers
are written the way they are: a fact no export carries must not become a finding.
A subaccount list does not say whether audit logging is on, so "you have no audit
logging" must not appear; a settings payload that names no subaccount must not be
attributed to an arbitrary one; and a hand-made export in our own shape must come
out of the loader byte-for-byte as it went in.
"""
import contextlib
import copy
import io
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import btp_import                              # noqa: E402
from modules.btp_cloud_surface import BtpCloudSurfaceAuditor  # noqa: E402
from modules.data_loader import DataLoader                  # noqa: E402
from modules.s4_business_authz import S4BusinessAuthzAuditor  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "btp_cli"
SAMPLE = ROOT / "sample_data"

PROD = "a1b2c3d4-1111-4aaa-8bbb-000000000001"
QA = "a1b2c3d4-1111-4aaa-8bbb-000000000002"
SANDBOX = "a1b2c3d4-1111-4aaa-8bbb-000000000003"


@pytest.fixture(scope="module")
def cli_data():
    """The fixture directory loaded exactly as a customer's upload would be."""
    with contextlib.redirect_stdout(io.StringIO()):
        return DataLoader(FIXTURES).load_all()


def _findings(data):
    out = []
    for cls in (BtpCloudSurfaceAuditor, S4BusinessAuthzAuditor):
        out.extend(cls(dict(data), {}).run_all_checks())
    return out


def _by_id(data):
    result = {}
    for finding in _findings(data):
        result.setdefault(finding["check_id"], []).append(finding)
    return result


# ── the headline claim: existing checks fire on CLI-shaped JSON ──────────────

def test_existing_btp_checks_fire_from_cli_shaped_json(cli_data):
    """No file in tests/fixtures/btp_cli is in our own shape — every one is raw
    tooling output. These checks must fire anyway."""
    fired = set(_by_id(cli_data))
    expected = {
        "BTP-CC-001",   # wildcard "/" resource mapping
        "BTP-CC-002",   # WebGUI + OData exposed through the tunnel
        "BTP-CC-005",   # subaccount certificate expired
        "BTP-CC-008",   # connector 2.15.2 -> CVE-2024-25642
        "BTP-GOV-002",  # a subaccount left on the default SAP IdP
        "S4AUTHZ-006",  # system mapping without principal propagation
        "S4AUTHZ-008",  # birthright role collection
    }
    assert expected <= fired, "missing: %s" % sorted(expected - fired)


def test_cloud_connector_backend_is_one_object_across_both_modules(cli_data):
    """BTP-CC-* reads `name`, S4AUTHZ-006 reads `virtualHost`. If the translation
    wrote different strings into the two, one backend would become two graph
    nodes and the cloud-to-on-prem path would break at the join."""
    by_id = _by_id(cli_data)
    cc_names = {o["name"] for o in by_id["BTP-CC-001"][0]["affected_objects"]
                if o["type"] == "cc_backend"}
    s4_names = {o["name"] for o in by_id["S4AUTHZ-006"][0]["affected_objects"]
                if o["type"] == "cc_backend"}
    assert cc_names == {"s4h-prod.internal:443"}
    assert s4_names >= cc_names, (
        "the same backend is named differently by the two modules: %s vs %s"
        % (sorted(cc_names), sorted(s4_names)))


def test_resource_id_is_translated_to_path(cli_data):
    """The configuration API calls a resource's path `id`; our checks read `path`.
    That rename is the whole reason a raw dump does not work as-is."""
    backends = cli_data["cloud_connector"]["backends"]
    prod = [b for b in backends if b["name"].startswith("s4h-prod")][0]
    assert [r["path"] for r in prod["resources"]] == [
        "/", "/sap/bc/gui/sap/its/webgui", "/sap/opu/odata/sap"]
    assert prod["internalHost"] == "10.0.1.50:44300"
    assert prod["principalType"] == "None"          # authenticationMode NONE


def test_birthright_finding_names_the_default_mapped_collection(cli_data):
    """`attributeReferences: Groups=Default` is BTP's birthright mapping. The
    collection mapped to a NAMED IdP group must not be dragged in with it."""
    finding = _by_id(cli_data)["S4AUTHZ-008"][0]
    names = {o["name"] for o in finding["affected_objects"]}
    assert names == {"Z_Analytics_Viewer"}
    assert finding["scope"] == "aggregate"


def test_default_idp_finding_names_only_the_evidenced_subaccount(cli_data):
    """Three subaccounts, security settings for two, one of those on sap.default.
    Exactly one subaccount may be named — the other two are not evidence."""
    finding = _by_id(cli_data)["BTP-GOV-002"][0]
    assert {o["name"] for o in finding["affected_objects"]} == {QA}


# ── the other half: what must NOT be claimed ─────────────────────────────────

def test_no_audit_logging_claim_without_evidence(cli_data):
    """`btp list accounts/subaccount` does not carry audit-log enablement, and the
    audit-record export covers one subaccount only. BTP-GOV-001 reads a MISSING
    flag as "off", so a naive translation would report two subaccounts as having
    no audit logging on the strength of a field that was never in the export."""
    assert "BTP-GOV-001" not in _by_id(cli_data)

    subaccounts = {s["id"]: s for s in cli_data["btp_subaccounts"]["subaccounts"]}
    assert subaccounts[PROD]["auditLogEnabled"] is True      # records were retrieved
    assert subaccounts[QA]["auditLogEnabled"] == btp_import.UNKNOWN
    assert subaccounts[SANDBOX]["auditLogEnabled"] == btp_import.UNKNOWN


def test_subaccount_without_settings_makes_no_idp_claim(cli_data):
    subaccounts = {s["id"]: s for s in cli_data["btp_subaccounts"]["subaccounts"]}
    assert subaccounts[PROD]["customIdp"] == "corp-azuread"
    assert subaccounts[QA]["customIdp"] == "sap.default"
    assert subaccounts[SANDBOX]["customIdp"] == btp_import.UNKNOWN


def test_no_access_control_lists_are_synthesised(cli_data):
    """The Cloud Connector configuration API exposes no per-subaccount allowed-host
    list — its access control IS the system mappings. An empty ACL entry would make
    BTP-CC-004 report "unrestricted" from data that has no such concept."""
    assert "accessControlLists" not in cli_data["cloud_connector"]
    assert "BTP-CC-004" not in _by_id(cli_data)


def test_creation_date_does_not_become_last_used(cli_data):
    """A mapping's creationDate is not evidence of when it was last used; mapping
    one onto the other would make BTP-CC-007 call a busy backend stale."""
    for backend in cli_data["cloud_connector"]["backends"]:
        assert "lastUsed" not in backend
    assert "BTP-CC-007" not in _by_id(cli_data)


def test_certificate_is_named_the_way_every_other_certificate_is(cli_data):
    """The Cloud Connector reports a DN; crypto_posture names certificates by their
    STRUST alias. One convention, or the same certificate is two graph nodes
    depending on which export revealed it."""
    finding = _by_id(cli_data)["BTP-CC-005"][0]
    assert {o["name"] for o in finding["affected_objects"]} == {PROD}
    assert btp_import.import_cloud_connector({
        "systemMappings": [{"virtualHost": "a", "localHost": "b", "protocol": "HTTPS"}],
        "certificates": [{"alias": "SCC_System_Cert", "notAfter": "2025-02-01"}],
    })["certificates"][0]["name"] == "SCC_System_Cert"


def test_certificate_weakness_is_not_invented(cli_data):
    """The dump carries no key size and no signature algorithm, so BTP-CC-006 has
    nothing to say. Defaulting either field would manufacture a crypto finding."""
    certificates = cli_data["cloud_connector"]["certificates"]
    assert certificates and all("keySize" not in c for c in certificates)
    assert "BTP-CC-006" not in _by_id(cli_data)


def test_audit_records_do_not_become_a_retention_measurement():
    """The window covered by an export is chosen by whoever ran the query. Turning
    it into "you retain N days" would be a fabricated measurement."""
    raw = json.loads((FIXTURES / "btp_audit_log_records.json").read_text("utf-8"))
    summary = btp_import.import_audit_log_records(raw)
    assert summary["record_count"] == 3
    assert [t["tenant"] for t in summary["tenants"]] == [PROD]
    assert summary["tenants"][0]["earliest"] == "2026-07-30"
    assert summary["tenants"][0]["latest"] == "2026-08-01"
    assert not any("retention" in key for key in summary)


def test_audit_records_do_not_carry_message_bodies_into_the_scan():
    """Audit records are personal data. What the scanner needs from them is that
    the tenant produces records at all, so only the summary crosses the boundary."""
    raw = json.loads((FIXTURES / "btp_audit_log_records.json").read_text("utf-8"))
    text = json.dumps(btp_import.import_audit_log_records(raw))
    assert "basis.admin@acme.example" not in text
    assert "failed logon" not in text


def test_settings_are_not_attributed_when_the_payload_names_none():
    """The settings output describes the CURRENTLY TARGETED subaccount. With
    several subaccounts known and no id in the payload, attributing it would put
    one subaccount's identity provider onto another's finding."""
    data = {
        "btp_subaccounts": {"subaccounts": [
            {"id": PROD, "name": "Production", "customIdp": btp_import.UNKNOWN},
            {"id": QA, "name": "Quality", "customIdp": btp_import.UNKNOWN},
        ]},
        "btp_security_settings": [{"defaultIdentityProvider": "sap.default"}],
    }
    notes = btp_import.apply(data)
    for subaccount in data["btp_subaccounts"]["subaccounts"]:
        assert subaccount["customIdp"] == btp_import.UNKNOWN
    assert any("not attributed" in n for n in notes)


def test_settings_are_attributed_when_only_one_subaccount_is_known():
    data = {
        "btp_subaccounts": {"subaccounts": [
            {"id": PROD, "name": "Production", "customIdp": btp_import.UNKNOWN}]},
        "btp_security_settings": [{"defaultIdentityProvider": "sap.default"}],
    }
    btp_import.apply(data)
    assert data["btp_subaccounts"]["subaccounts"][0]["customIdp"] == "sap.default"


def test_a_customer_value_is_never_overwritten():
    """Positive evidence fills a gap; it does not overrule what the customer said."""
    data = {
        "btp_subaccounts": {"subaccounts": [
            {"id": PROD, "name": "Production", "customIdp": "corp-okta",
             "auditLogEnabled": False}]},
        "btp_security_settings": [{"subaccount": PROD,
                                   "defaultIdentityProvider": "sap.default"}],
        "btp_audit_log_records": [{"uuid": "x", "time": "2026-01-01T00:00:00Z",
                                   "tenant": PROD, "category": "audit.configuration"}],
    }
    btp_import.apply(data)
    subaccount = data["btp_subaccounts"]["subaccounts"][0]
    assert subaccount["customIdp"] == "corp-okta"
    assert subaccount["auditLogEnabled"] is False


# ── hand-made exports must pass through untouched ────────────────────────────

def test_hand_made_exports_are_not_recognised_as_tooling_output():
    """The translators sit directly on the canonical sources, so the ONLY thing
    protecting a working hand-made export is that it is not recognised. Assert
    that, on the shipped sample_data, rather than trusting it."""
    for name in ("cloud_connector.json", "btp_subaccounts.json"):
        raw = json.loads((SAMPLE / name).read_text("utf-8"))
        assert btp_import.import_cloud_connector(raw) is None
        assert btp_import.import_subaccounts(raw) is None

    rows = [{"ROLE_COLLECTION": "Z_X", "IDP_GROUP": "Default"}]
    assert btp_import.import_role_collections(rows) is None


def test_sample_data_is_byte_for_byte_unchanged_by_apply():
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(SAMPLE).load_all()
    before = copy.deepcopy({k: data.get(k) for k in
                            ("cloud_connector", "btp_subaccounts",
                             "btp_role_collection_mappings")})
    with contextlib.redirect_stdout(io.StringIO()):
        notes = btp_import.apply(data)
    after = {k: data.get(k) for k in before}
    assert after == before
    assert notes == []


# ── tolerance: several shapes in, nothing guessed ────────────────────────────

@pytest.mark.parametrize("payload", [
    [{"guid": PROD, "displayName": "Production", "region": "eu10"}],
    {"value": [{"guid": PROD, "displayName": "Production", "region": "eu10"}]},
    {"subaccounts": [{"guid": PROD, "displayName": "Production", "region": "eu10"}]},
    {"items": [{"guid": PROD, "displayName": "Production", "region": "eu10"}]},
    {"payload": {"value": [{"guid": PROD, "displayName": "Production",
                            "region": "eu10"}]}},
])
def test_subaccount_containers_are_all_accepted(payload):
    out = btp_import.import_subaccounts(payload)
    assert out["subaccounts"][0]["id"] == PROD
    assert out["subaccounts"][0]["name"] == "Production"


@pytest.mark.parametrize("payload", [
    None, [], {}, "", 0, [1, 2, 3], {"unrelated": {"nested": "thing"}},
    [{"some": "row", "with": "no recognised key"}],
])
def test_unrecognised_payloads_translate_to_nothing(payload):
    """"I do not recognise this" must be the answer, not a half-built record."""
    assert btp_import.import_subaccounts(payload) is None
    assert btp_import.import_security_settings(payload) is None
    assert btp_import.import_role_collections(payload) is None
    assert btp_import.import_cloud_connector(payload) is None
    assert btp_import.import_audit_log_records(payload) is None


def test_cloud_connector_accepts_a_bare_system_mapping_array():
    out = btp_import.import_cloud_connector([
        {"virtualHost": "s4h.internal", "virtualPort": "443", "localHost": "10.0.0.9",
         "localPort": "44300", "protocol": "HTTPS", "authenticationMode": "KERBEROS",
         "resources": [{"id": "/sap/opu/odata", "exactMatchOnly": True}]}])
    assert out["backends"][0]["name"] == "s4h.internal:443"
    assert out["backends"][0]["principalType"] == "Kerberos"
    assert out["backends"][0]["resources"] == [
        {"path": "/sap/opu/odata", "exactMatchOnly": True}]


def test_unknown_authentication_mode_leaves_principal_type_absent():
    """S4AUTHZ-006 treats an absent principalType as "unknown, do not flag". A
    mode we do not recognise must land there rather than default to None."""
    out = btp_import.import_cloud_connector([
        {"virtualHost": "s4h.internal", "localHost": "10.0.0.9", "protocol": "HTTPS",
         "authenticationMode": "SOME_FUTURE_MODE"}])
    assert "principalType" not in out["backends"][0]
    findings = S4BusinessAuthzAuditor({"cloud_connector": out}, {}).run_all_checks()
    assert "S4AUTHZ-006" not in {f["check_id"] for f in findings}


def test_separately_curled_resources_are_dropped_when_ambiguous():
    """Resources curled on their own carry no backend. With two mappings they
    cannot be attributed, and attaching a wildcard to the wrong system would be a
    finding against an innocent backend."""
    payload = {
        "systemMappings": [
            {"virtualHost": "a.internal", "localHost": "10.0.0.1", "protocol": "HTTPS"},
            {"virtualHost": "b.internal", "localHost": "10.0.0.2", "protocol": "HTTPS"},
        ],
        "resources": [{"id": "/", "exactMatchOnly": False, "enabled": True}],
    }
    out = btp_import.import_cloud_connector(payload)
    assert all("resources" not in b for b in out["backends"])

    payload["systemMappings"] = payload["systemMappings"][:1]
    out = btp_import.import_cloud_connector(payload)
    assert out["backends"][0]["resources"] == [
        {"path": "/", "exactMatchOnly": False, "enabled": True}]


def test_unreadable_resources_do_not_leak_through_as_a_phantom_wildcard():
    """BTP-CC-001 treats an EMPTY path as a wildcard. A raw resource entry we
    could not read a path out of must therefore not survive into the backend, or
    every unreadable row would raise a CRITICAL wildcard finding."""
    out = btp_import.import_cloud_connector([
        {"virtualHost": "a.internal", "localHost": "10.0.0.1", "protocol": "HTTPS",
         "resources": [{"unexpected": "shape"}]}])
    assert "resources" not in out["backends"][0]
    findings = BtpCloudSurfaceAuditor({"cloud_connector": out}, {}).run_all_checks()
    assert "BTP-CC-001" not in {f["check_id"] for f in findings}


def test_certificate_timestamps_in_any_documented_form():
    for expiry in (1738368000000, 1738368000, "1738368000000",
                   "2025-02-01T00:00:00.000Z", "2025-02-01"):
        out = btp_import.import_cloud_connector({
            "systemMappings": [{"virtualHost": "a.internal", "localHost": "10.0.0.1",
                                "protocol": "HTTPS"}],
            "certificates": [{"subjectDN": "CN=scc", "notAfterTimeStamp": expiry}],
        })
        assert out["certificates"][0]["expiryDate"] == "2025-02-01", expiry


def test_role_collection_without_references_asserts_nothing():
    """The list verb may not return references at all. An empty mapping is not a
    birthright mapping, and it is not a claim that the collection is unmapped."""
    rows = btp_import.import_role_collections(
        [{"name": "Z_Thing", "isReadOnly": False, "roleReferences": []}])
    assert rows == [{"ROLE_COLLECTION": "Z_Thing", "DESCRIPTION": "",
                     "READ_ONLY": "false", "ROLE_COUNT": "0", "USER_COUNT": "0",
                     "IDP_GROUP": "", "ORIGIN": "", "MAPPING_TYPE": ""}]
    findings = S4BusinessAuthzAuditor({"btp_role_collection_mappings": rows},
                                      {}).run_all_checks()
    assert "S4AUTHZ-008" not in {f["check_id"] for f in findings}


def test_a_malformed_payload_degrades_one_source_and_says_so():
    """A broken export must not abort the scan — and must not pass silently
    either, because a silent skip looks exactly like a file nobody sent."""
    class Exploding(dict):
        def values(self):
            raise RuntimeError("truncated export")

    data = {"btp_subaccounts": Exploding(x=1)}
    notes = btp_import.apply(data)
    assert any("could not translate btp_subaccounts" in n for n in notes)
    assert isinstance(data["btp_subaccounts"], Exploding)


def test_translation_is_idempotent(cli_data):
    """Re-running apply() over already-translated data must not degrade a fact to
    UNKNOWN or duplicate a row."""
    data = copy.deepcopy(dict(cli_data))
    btp_import.apply(data)
    assert data["btp_subaccounts"] == cli_data["btp_subaccounts"]
    assert data["cloud_connector"] == cli_data["cloud_connector"]
    assert data["btp_role_collection_mappings"] == cli_data["btp_role_collection_mappings"]


# ── finding identity contract ────────────────────────────────────────────────

def test_findings_from_translated_data_have_stable_identity(cli_data):
    """Every finding raised off translated data must carry the identity contract:
    a declared scope, structured objects of REGISTERED types, and a fingerprint
    that does not move when the same export is scanned twice."""
    from server.identity import (AffectedObject, _CASE_SENSITIVE_TYPES,
                                 _UPPERCASE_TYPES, fingerprint_finding)

    first = _findings(cli_data)
    assert first, "no findings to check"
    second = _findings(copy.deepcopy(dict(cli_data)))

    for finding in first:
        assert finding.get("scope") in ("object", "aggregate"), finding["check_id"]
        for raw in finding.get("affected_objects", []):
            obj = AffectedObject.coerce(raw)
            assert (obj.type in _UPPERCASE_TYPES) != (obj.type in _CASE_SENSITIVE_TYPES), (
                "%s: object type %r must be registered in exactly one case registry"
                % (finding["check_id"], obj.type))

    fingerprints_a = sorted(fingerprint_finding(f, "PRD", "100")[0] for f in first)
    fingerprints_b = sorted(fingerprint_finding(f, "PRD", "100")[0] for f in second)
    assert fingerprints_a == fingerprints_b


def test_no_volatile_value_becomes_a_qualifier(cli_data):
    """A count, an age or a timestamp in a qualifier churns the object's identity
    every run. The certificate finding is the one at risk here — it knows the
    expiry date and the days remaining."""
    for finding in _findings(cli_data):
        for obj in finding.get("affected_objects", []):
            qualifier = str(obj.get("qualifier", ""))
            assert "d ago" not in qualifier and "expires" not in qualifier
            assert not any(part.isdigit() and len(part) == 4
                           for part in qualifier.replace("-", " ").split())
