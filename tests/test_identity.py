"""
Tests for finding identity — the pivot's load-bearing contract.

The exit criterion for Phase 1 is stated in docs/PIVOT_PLAN.md: upload the same export
bundle twice and every finding must match itself. These tests prove the pieces of that,
and — critically — they run against the REAL bundled sample_data rather than fixtures,
because the collisions being fixed were measured there:

    USR-001 x4, CODE-STMT-001 x4, RISE-002 x2

A fixture that hand-builds four USR-001 findings would prove the hash function works.
It would not prove the scanner actually produces distinguishable findings, which is the
thing in doubt.
"""
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.identity import (  # noqa: E402
    FINGERPRINT_SCHEMA,
    AffectedObject,
    IdentityError,
    _CASE_SENSITIVE_TYPES,
    _UPPERCASE_TYPES,
    compute_fingerprint,
    extract_nodes,
    fingerprint_finding,
    norm_client,
    norm_sid,
)

SAMPLE = ROOT / "sample_data"


# --------------------------------------------------------------------------- #
#  Normalization                                                              #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("raw,expected", [
    ("0", "000"), ("00", "000"), ("000", "000"),
    ("100", "100"), (100, "100"), (" 100 ", "100"),
    ("1", "001"),
])
def test_client_padding_makes_one_client_one_identity(raw, expected):
    """A CSV opened in Excel turns client 000 into 0. Without padding that is three
    different clients and therefore three different finding identities."""
    assert norm_client(raw) == expected


def test_non_numeric_client_is_not_mangled():
    """SAP permits alphanumeric clients. Zero-padding one would corrupt it."""
    assert norm_client("A01") == "A01"


def test_sid_is_upper_cased():
    assert norm_sid(" prd ") == "PRD"
    assert norm_sid("") is None
    assert norm_sid(None) is None


def test_sap_identifiers_are_case_insensitive():
    a = AffectedObject("user", "mm_clerk_01")
    b = AffectedObject("user", "MM_CLERK_01")
    assert a == b, "an export that lost its casing must not create a second identity"


def test_case_bearing_types_are_never_upper_cased():
    """An ICF path is case-sensitive. Upper-casing it would merge genuinely different
    endpoints into one node and one finding."""
    obj = AffectedObject("icf_path", "/sap/bc/webRFC")
    assert obj.name == "/sap/bc/webRFC"
    assert AffectedObject("icf_path", "/sap/bc/webrfc") != obj


def test_internal_whitespace_is_collapsed_not_stripped():
    """"Z FIN CLERK" and "ZFINCLERK" are different roles; equating them merges two
    findings. But a double space is just a dirty export."""
    assert AffectedObject("role", "Z  FIN  CLERK").name == "Z FIN CLERK"
    assert AffectedObject("role", "Z FIN CLERK") != AffectedObject("role", "ZFINCLERK")


def test_the_two_case_registries_are_disjoint():
    """A type in both registries would make normalization order-dependent."""
    overlap = _UPPERCASE_TYPES & _CASE_SENSITIVE_TYPES
    assert not overlap, f"types registered in both case registries: {sorted(overlap)}"


def test_an_object_without_a_name_or_type_is_refused():
    with pytest.raises(IdentityError):
        AffectedObject("user", "")
    with pytest.raises(IdentityError):
        AffectedObject("", "SAP*")


# --------------------------------------------------------------------------- #
#  Fingerprint semantics                                                      #
# --------------------------------------------------------------------------- #

def test_qualifier_participates_in_identity():
    """S_TABU_DIS with DICBERCLS=* and the same object with a narrow class are
    different defects and must not share a history."""
    wide = compute_fingerprint("AUTH-009", "PRD", "100",
                               subject=[{"type": "auth_object", "name": "S_TABU_DIS",
                                         "qualifier": "DICBERCLS=*"}])[0]
    narrow = compute_fingerprint("AUTH-009", "PRD", "100",
                                 subject=[{"type": "auth_object", "name": "S_TABU_DIS",
                                           "qualifier": "DICBERCLS=FI"}])[0]
    assert wide != narrow


def test_subject_order_does_not_affect_identity():
    """The order a module happens to append objects in is not part of the defect."""
    a = compute_fingerprint("X-1", "PRD", "100", subject=[
        {"type": "user", "name": "A"}, {"type": "profile", "name": "SAP_ALL"}])[0]
    b = compute_fingerprint("X-1", "PRD", "100", subject=[
        {"type": "profile", "name": "SAP_ALL"}, {"type": "user", "name": "A"}])[0]
    assert a == b


def test_the_same_defect_in_two_systems_is_two_findings():
    prd = compute_fingerprint("USR-001", "PRD", "100",
                              subject=[{"type": "user", "name": "SAP*"}])[0]
    dev = compute_fingerprint("USR-001", "DEV", "100",
                              subject=[{"type": "user", "name": "SAP*"}])[0]
    assert prd != dev, "a landscape view is impossible if systems share identities"


def test_the_same_defect_in_two_clients_is_two_findings():
    c100 = compute_fingerprint("USR-001", "PRD", "100",
                               subject=[{"type": "user", "name": "SAP*"}])[0]
    c200 = compute_fingerprint("USR-001", "PRD", "200",
                               subject=[{"type": "user", "name": "SAP*"}])[0]
    assert c100 != c200


def test_aggregate_identity_survives_membership_change():
    """THE regression this design exists to prevent. If an aggregate finding's identity
    included its members, dismissing one dormant account would retire the finding and
    raise a new one — the age would reset to zero every single run and MTTR would be
    permanently, silently wrong."""
    before = fingerprint_finding({
        "check_id": "USR-003", "scope": "aggregate",
        "affected_items": ["U1", "U2", "U3"],
        "affected_objects": [{"type": "user", "name": u} for u in ("U1", "U2", "U3")],
    }, system="PRD", client="100")
    after = fingerprint_finding({
        "check_id": "USR-003", "scope": "aggregate",
        "affected_items": ["U1", "U3"],
        "affected_objects": [{"type": "user", "name": u} for u in ("U1", "U3")],
    }, system="PRD", client="100")
    assert before[0] == after[0]
    assert before[1] == "check_only"


def test_object_findings_do_not_collapse_into_one():
    """The mirror-image failure: if per-object findings shared an identity, three of
    the four unlocked default users would simply vanish from the report."""
    prints = {
        fingerprint_finding({"check_id": "USR-001",
                             "affected_objects": [{"type": "user", "name": u}]},
                            system="PRD", client="100")[0]
        for u in ("SAP*", "DDIC", "SAPCPIC", "EARLYWATCH")
    }
    assert len(prints) == 4


def test_editorial_changes_do_not_orphan_history():
    """Retuning a severity or rewording a title must not reset a finding's age."""
    base = {"check_id": "USR-001", "affected_objects": [{"type": "user", "name": "SAP*"}]}
    a = fingerprint_finding({**base, "severity": "HIGH", "title": "Old wording",
                             "description": "x"}, system="PRD", client="100")[0]
    b = fingerprint_finding({**base, "severity": "CRITICAL", "title": "New wording",
                             "description": "y"}, system="PRD", client="100")[0]
    assert a == b


def test_a_finding_naming_its_own_system_overrides_the_run_default():
    """A cross-system trust finding belongs to the system it is ABOUT, not to whichever
    export happened to reveal it — otherwise the same trust defect is reported twice
    under two owners."""
    fp, _ = fingerprint_finding(
        {"check_id": "TRUST-001",
         "affected_objects": [{"type": "trusted_system", "name": "DEV", "system": "PRD"}]},
        system="QAS", client="100")
    direct, _ = compute_fingerprint(
        "TRUST-001", "PRD", "100",
        subject=[{"type": "trusted_system", "name": "DEV", "system": "PRD"}])
    assert fp == direct


def test_subject_separates_what_a_finding_is_about_from_what_it_names():
    """"Role Z_ADMIN grants SAP_ALL to 41 users" is ABOUT the role. The users are
    context that changes as people join and leave, and must not sit in identity —
    otherwise a team transfer re-raises a finding nobody has fixed."""
    def f(users):
        return {"check_id": "AUTH-X",
                "subject": [{"type": "role", "name": "Z_ADMIN"}],
                "affected_objects": [{"type": "role", "name": "Z_ADMIN"}]
                                    + [{"type": "user", "name": u} for u in users],
                "scope": "object"}

    a = fingerprint_finding(f(["U1", "U2", "U3"]), "PRD", "100")
    b = fingerprint_finding(f(["U1", "U9"]), "PRD", "100")
    assert a[0] == b[0], "the member list leaked into identity"
    assert a[1] == "objects", "a subject-identified finding must not degrade to a coarser basis"

    # ...but a different role is a different defect.
    other = fingerprint_finding(
        {"check_id": "AUTH-X", "subject": [{"type": "role", "name": "Z_OTHER"}],
         "scope": "object"}, "PRD", "100")
    assert other[0] != a[0]


def test_members_still_become_graph_nodes_when_a_subject_is_set():
    """Excluding members from IDENTITY must not exclude them from the graph — the
    role-to-user edges are the point of that check."""
    nodes = extract_nodes([{
        "check_id": "AUTH-X",
        "subject": [{"type": "role", "name": "Z_ADMIN"}],
        "affected_objects": [{"type": "role", "name": "Z_ADMIN"},
                             {"type": "user", "name": "U1"},
                             {"type": "user", "name": "U2"}],
        "scope": "object"}], default_system="PRD")
    assert {n["key"] for n in nodes} == {
        "role:Z_ADMIN@PRD", "user:U1@PRD", "user:U2@PRD"}


def test_a_genuine_aggregate_keeps_the_honest_coarse_label():
    """A check that rolls every offending role into ONE finding is correctly
    identified by check and system. Naming a constant as its subject would change
    the label to 'objects' without changing the guarantee — and the console
    presents 'objects' as structural, so that would be a claim the data cannot
    support. check_only is the honest answer here, not a shortfall."""
    fp, basis = fingerprint_finding({
        "check_id": "AUTH-001", "scope": "aggregate",
        "affected_objects": [{"type": "role", "name": r} for r in ("Z_A", "Z_B")],
    }, "PRD", "100")
    assert basis == "check_only"
    same, _ = fingerprint_finding({
        "check_id": "AUTH-001", "scope": "aggregate",
        "affected_objects": [{"type": "role", "name": "Z_A"}],
    }, "PRD", "100")
    assert fp == same, "remediating one role re-raised the finding"


def test_basis_is_reported_honestly():
    structured = fingerprint_finding(
        {"check_id": "A-1", "affected_objects": [{"type": "user", "name": "X"}]})[1]
    legacy = fingerprint_finding(
        {"check_id": "A-1", "affected_items": ["X -> SAP_ALL"]})[1]
    bare = fingerprint_finding({"check_id": "A-1"})[1]
    assert (structured, legacy, bare) == ("objects", "display", "check_only")


def test_unconverted_modules_still_get_a_stable_identity():
    """Incremental conversion is only safe if a module that has not been touched yet
    still matches itself across runs."""
    f = {"check_id": "CODE-STMT-001", "affected_items": ["ZPROG_A -> EXEC SQL"]}
    assert fingerprint_finding(f, "PRD", "100")[0] == fingerprint_finding(f, "PRD", "100")[0]


def test_schema_version_is_in_the_hash():
    """Guards against a future normalization change silently resetting every stored
    history instead of announcing itself."""
    import server.identity as ident
    fp1 = compute_fingerprint("A-1", "PRD", "100",
                              subject=[{"type": "user", "name": "X"}])[0]
    original = ident.FINGERPRINT_SCHEMA
    try:
        ident.FINGERPRINT_SCHEMA = "v2"
        fp2 = compute_fingerprint("A-1", "PRD", "100",
                                  subject=[{"type": "user", "name": "X"}])[0]
    finally:
        ident.FINGERPRINT_SCHEMA = original
    assert fp1 != fp2
    assert FINGERPRINT_SCHEMA == "v1"


def test_a_finding_without_a_check_id_is_refused():
    with pytest.raises(IdentityError):
        compute_fingerprint("")


# --------------------------------------------------------------------------- #
#  Against the real scanner, on the real sample data                          #
# --------------------------------------------------------------------------- #

def _run_real_scan():
    """Run the actual auditors over the bundled sample_data."""
    from modules.data_loader import DataLoader
    loader = DataLoader(SAMPLE)
    data = loader.load_all()

    from modules.user_auth_audit import UserAuthAuditor
    from modules.code_transport import CodeTransportAuditor
    findings = []
    for cls in (UserAuthAuditor, CodeTransportAuditor):
        findings.extend(cls(data).run_all_checks())
    return findings


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_the_measured_collisions_resolve_on_real_sample_data():
    """THE Phase-1 exit test.

    The pivot was blocked on a measured fact: `check_id` collides within a single run.
    This asserts (a) that the collisions are real and still present — so the test fails
    loudly if the sample data changes and stops exercising the problem — and (b) that
    every colliding finding now receives a distinct fingerprint.
    """
    findings = _run_real_scan()
    assert findings, "sample_data produced no findings; the test proves nothing"

    by_check = Counter(f["check_id"] for f in findings)
    colliding = {cid: n for cid, n in by_check.items() if n > 1}
    assert colliding, (
        "no check_id collides in sample_data any more — this test no longer exercises "
        "the defect it was written for. Re-measure before deleting it."
    )

    for cid, count in sorted(colliding.items()):
        prints = {fingerprint_finding(f, "PRD", "100")[0]
                  for f in findings if f["check_id"] == cid}
        assert len(prints) == count, (
            f"{cid} fires {count} times but yields {len(prints)} distinct "
            f"fingerprint(s) — findings would be silently merged and the mitigation "
            f"journey would under-report."
        )


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_rescanning_identical_data_reports_nothing_new():
    """The exit criterion in one assertion: same bundle twice, zero new findings."""
    first = {fingerprint_finding(f, "PRD", "100")[0] for f in _run_real_scan()}
    second = {fingerprint_finding(f, "PRD", "100")[0] for f in _run_real_scan()}
    assert first == second
    assert not (second - first), "a re-upload of identical data invented new findings"


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_every_finding_gets_a_fingerprint_without_raising():
    """No finding may be un-storable. A module that emits something un-fingerprintable
    would silently drop out of the console."""
    for f in _run_real_scan():
        fp, basis = fingerprint_finding(f, "PRD", "100")
        assert len(fp) == 64
        assert basis in ("objects", "display", "check_only")


# --------------------------------------------------------------------------- #
#  Graph node extraction                                                      #
# --------------------------------------------------------------------------- #

def test_nodes_are_deduplicated_and_counted_across_findings():
    nodes = extract_nodes([
        {"check_id": "USR-002", "affected_objects": [
            {"type": "user", "name": "MM_CLERK_01"},
            {"type": "profile", "name": "SAP_ALL"}]},
        {"check_id": "AUTH-001", "affected_objects": [
            {"type": "user", "name": "mm_clerk_01"}]},
    ], default_system="PRD")
    by_key = {n["key"]: n for n in nodes}
    assert set(by_key) == {"user:MM_CLERK_01@PRD", "profile:SAP_ALL@PRD"}
    user = by_key["user:MM_CLERK_01@PRD"]
    assert user["finding_count"] == 2
    assert user["check_ids"] == ["AUTH-001", "USR-002"]


# --------------------------------------------------------------------------- #
#  Cloud objects do not live in the ABAP system                               #
# --------------------------------------------------------------------------- #

def test_cloud_objects_are_not_stamped_with_the_abap_sid():
    """A BTP subaccount entity has nothing to do with whichever ABAP system was
    scanned. Before this rule the extractor produced
    `role_collection:Subaccount_Admin@PRD`, filing a cloud role under an on-premise
    SID."""
    nodes = extract_nodes([{
        "check_id": "IAM-XID-003",
        "affected_objects": [
            {"type": "btp_user", "name": "jsmith@company.com"},
            {"type": "role_collection", "name": "Subaccount_Admin"},
            {"type": "user", "name": "JSMITH"},          # ABAP — SHOULD be stamped
        ]}], default_system="PRD")
    keys = {n["key"] for n in nodes}
    assert "btp_user:JSMITH@COMPANY.COM" in keys
    assert "role_collection:Subaccount_Admin" in keys
    assert "user:JSMITH@PRD" in keys, "an ABAP object must still carry its system"
    assert not any(k.startswith(("btp_user:", "role_collection:")) and "@PRD" in k
                   for k in keys), "a cloud object was filed under the ABAP SID"


# --------------------------------------------------------------------------- #
#  The fingerprint-side twin of the rule above.                               #
#                                                                             #
#  THE ONE ABOVE EXISTED ALONE FOR MONTHS, AND THAT IS WHY THE BUG SURVIVED.  #
#  The cloud-scope exemption was applied to `extract_nodes` and not to        #
#  `fingerprint_finding`, so the graph gave a BTP user ONE node key across     #
#  every system while identity gave the same user a DIFFERENT fingerprint per  #
#  SID. One bundle uploaded against two ABAP systems churned its whole BTP     #
#  finding set — new on one, resolved on the other. A conversion pass looking  #
#  for exactly this class of defect missed it, because only half of the        #
#  contract was ever asserted. Both halves are asserted now; if you add a rule #
#  to one side, add its twin here.                                            #
# --------------------------------------------------------------------------- #

def test_a_cloud_finding_has_one_identity_across_abap_systems():
    """The defect, stated as the property it broke.

    The same BTP bundle uploaded against PRD and against QAS must describe the
    SAME finding. Anything else and the mitigation journey reports a resolution
    and a regression that never happened.
    """
    finding = {
        "check_id": "BTP-DST-001",
        "scope": "object",
        "affected_objects": [{"type": "btp_user", "name": "jsmith@company.com"}],
    }
    prd, _basis = fingerprint_finding(finding, system="PRD", client="100")
    qas, _basis2 = fingerprint_finding(finding, system="QAS", client="100")
    assert prd == qas, "a cloud finding took its identity from the ABAP SID"

    # ...and it agrees with the node side, which is the whole point of the twin.
    keys_prd = {n["key"] for n in extract_nodes([finding], default_system="PRD")}
    keys_qas = {n["key"] for n in extract_nodes([finding], default_system="QAS")}
    assert keys_prd == keys_qas


def test_an_abap_finding_still_takes_its_identity_from_the_system():
    """The exemption must not leak. Two systems with the same defect are two
    findings, and collapsing them would hide one of them entirely."""
    finding = {
        "check_id": "USR-001",
        "scope": "object",
        "affected_objects": [{"type": "user", "name": "DDIC"}],
    }
    prd, _ = fingerprint_finding(finding, system="PRD", client="100")
    qas, _ = fingerprint_finding(finding, system="QAS", client="100")
    assert prd != qas


def test_a_mixed_finding_keeps_the_system_it_is_about():
    """A finding naming both a BTP user and an ABAP user genuinely concerns that
    ABAP system — the cross-system identity checks are exactly this shape."""
    finding = {
        "check_id": "IAM-XID-003",
        "scope": "object",
        "affected_objects": [{"type": "btp_user", "name": "a@b.com"},
                             {"type": "user", "name": "JSMITH"}],
    }
    prd, _ = fingerprint_finding(finding, system="PRD", client="100")
    qas, _ = fingerprint_finding(finding, system="QAS", client="100")
    assert prd != qas


def test_a_cloud_AGGREGATE_stays_system_scoped():
    """The qualifier that stops the fix going too far.

    An aggregate deliberately excludes its members from the fingerprint, so the
    system is the ONLY thing separating one system's summary from another's.
    Exempting aggregates too would merge "N dormant BTP users" across every
    system in the landscape into one finding, and dismissing it once would
    dismiss it everywhere.
    """
    finding = {
        "check_id": "BTP-USR-009",
        "scope": "aggregate",
        "affected_objects": [{"type": "btp_user", "name": "a@b.com"},
                             {"type": "btp_user", "name": "c@d.com"}],
    }
    prd, _ = fingerprint_finding(finding, system="PRD", client="100")
    qas, _ = fingerprint_finding(finding, system="QAS", client="100")
    assert prd != qas


def test_a_cloud_object_that_names_its_own_system_keeps_it_in_the_fingerprint():
    """Mirrors test_a_cloud_object_keeps_a_system_it_names_itself on the node side:
    the exemption is about not BORROWING the ABAP SID, never about discarding a
    system the object states for itself."""
    finding = {
        "check_id": "BTP-DST-002",
        "scope": "object",
        "affected_objects": [{"type": "subaccount", "name": "acme", "system": "TEN1"}],
    }
    prd, _ = fingerprint_finding(finding, system="PRD", client="100")
    qas, _ = fingerprint_finding(finding, system="QAS", client="100")
    assert prd == qas, "the object's own system should decide, not the run's"


def test_every_cloud_scoped_type_is_exempt_on_BOTH_sides():
    """The structural guard against this ever splitting again.

    Enumerates _CLOUD_SCOPED_TYPES and asserts, per type, that the node key and the
    fingerprint are both independent of the run's SID. A type added to the set but
    handled on only one side fails here rather than in a customer's journey.
    """
    from server.identity import _CLOUD_SCOPED_TYPES

    for ctype in sorted(_CLOUD_SCOPED_TYPES):
        finding = {"check_id": "X-001", "scope": "object",
                   "affected_objects": [{"type": ctype, "name": "thing"}]}
        prd, _ = fingerprint_finding(finding, system="PRD", client="100")
        qas, _ = fingerprint_finding(finding, system="QAS", client="100")
        assert prd == qas, f"{ctype} takes its fingerprint from the ABAP SID"

        kp = {n["key"] for n in extract_nodes([finding], default_system="PRD")}
        kq = {n["key"] for n in extract_nodes([finding], default_system="QAS")}
        assert kp == kq, f"{ctype} takes its node key from the ABAP SID"


#: Every case-bearing type, classified. True = belongs to a cloud tenant and must
#: never borrow the ABAP SID; False = genuinely lives inside the scanned system.
#:
#: WHY THIS MAP EXISTS. The test above holds _CLOUD_SCOPED_TYPES CONSISTENT — every
#: member exempt on both sides — and that is not the same as holding it COMPLETE.
#: Six types (btp_destination, btp_service, cc_backend, cpi_credential,
#: event_queue, ias_application) sat in _CASE_SENSITIVE_TYPES as cloud entities and
#: NOT in _CLOUD_SCOPED_TYPES, so each borrowed the SID of whatever ABAP system its
#: bundle arrived beside. The consistency test passed throughout. They were found
#: by reading the two sets against each other, which is not a thing CI does.
#:
#: Written out by hand rather than derived, for the same reason EXPECTED_RISE in
#: test_deployment_modes.py is: a classification derived from the set under test
#: agrees with it by construction, including when both are wrong.
CLOUD_SCOPED_BY_TYPE = {
    # --- cloud: a tenant owns these, not an ABAP system ---------------------
    "btp_user": True, "subaccount": True, "role_collection": True,
    "service_binding": True, "iflow": True, "destination_url": True,
    "cpi_datastore": True, "cpi_variable": True, "oauth_client": True,
    "idp_trust": True, "comm_arrangement": True, "btp_destination": True,
    "btp_service": True, "cc_backend": True, "cpi_credential": True,
    "event_queue": True, "ias_application": True,
    # --- system-scoped, despite being case-bearing --------------------------
    # A STRUST certificate belongs to the system holding it. Exempting it would
    # merge every system's certificates into one identity — the mirror image of
    # the bug the cloud set exists to fix, and equally silent.
    "certificate": False,
    "icf_path": False, "url": False, "path": False, "file": False,
    "endpoint": False, "schema": False,
    # Fiori launchpad content is delivered into, and lives in, the ABAP system.
    "fiori_catalog": False, "fiori_app": False, "fiori_tile": False,
    "fiori_space": False,
    # Data-protection configuration, all ABAP-resident: Read Access Logging
    # (SRALMANAGER), ILM retention policies (IRMPOL), purpose-of-processing and
    # cross-border transfer entries, and DSAR requests. Two systems each holding a
    # policy named RETENTION_HR hold two different policies.
    "ral_config": False, "ral_channel": False, "ilm_policy": False,
    "processing_purpose": False, "data_transfer": False, "dsar_request": False,
    "audit_filter": False,
    # CAP / XSUAA. Both run on BTP and belong to a subaccount, never to an ABAP
    # SID — the same project scanned beside two ABAP systems is one project.
    # These reached this table only once `cap_xsuaa` could be reached at all: it
    # reads a project DIRECTORY that no upload ever supplied, so neither type had
    # been emitted through ingest and neither had ever been classified.
    "xsuaa_application": True, "cap_service": True,
}


def test_every_case_bearing_type_is_deliberately_classified():
    """Completeness, not just consistency — the half that was missing.

    A type registered as case-bearing but never classified here fails this test, so
    the next cloud entity added cannot quietly default to borrowing the ABAP SID.
    That default is the dangerous direction: it produces a plausible report in which
    two tenants' objects have silently become one.
    """
    from server.identity import _CASE_SENSITIVE_TYPES, _CLOUD_SCOPED_TYPES

    unclassified = sorted(set(_CASE_SENSITIVE_TYPES) - set(CLOUD_SCOPED_BY_TYPE))
    assert not unclassified, (
        "these case-bearing types have no cloud/system decision recorded: "
        f"{unclassified}. Decide deliberately — a type that is really a tenant's "
        "will otherwise take the SID of whichever ABAP system it was uploaded "
        "beside, and nothing will report it.")

    # And the map must agree with the live set, in both directions.
    expected = {t for t, cloud in CLOUD_SCOPED_BY_TYPE.items() if cloud}
    missing = sorted(expected - set(_CLOUD_SCOPED_TYPES))
    extra = sorted(set(_CLOUD_SCOPED_TYPES) - expected)
    assert not missing, f"classified cloud but not exempt: {missing}"
    assert not extra, f"exempt but not classified cloud: {extra}"


def test_a_system_scoped_type_still_takes_the_system(monkeypatch):
    """The other direction, and the reason the set cannot just absorb every
    case-bearing type. A certificate in PRD and a certificate of the same name in
    QAS are two objects, and must keep two identities."""
    finding = {"check_id": "CRYPTO-001", "scope": "object",
               "affected_objects": [{"type": "certificate", "name": "CN=acme"}]}
    prd, _ = fingerprint_finding(finding, system="PRD", client="100")
    qas, _ = fingerprint_finding(finding, system="QAS", client="100")
    assert prd != qas, \
        "a STRUST certificate is being shared across systems; every system's " \
        "certificates have merged into one identity"


def test_a_btp_identity_and_an_abap_user_of_the_same_name_are_different_nodes():
    """Different principals reached by different means. Merging them would hide the
    on-prem/BTP crossing that the cloud-to-on-prem attack path exists to show — the
    boundary IS the path."""
    nodes = extract_nodes([{
        "check_id": "X",
        "affected_objects": [{"type": "user", "name": "JSMITH"},
                             {"type": "btp_user", "name": "JSMITH"}],
    }], default_system="PRD")
    assert len(nodes) == 2, "a cloud identity was merged with an ABAP user"


def test_a_btp_user_folds_case_so_one_person_is_one_node():
    """BTP user names are email addresses. RFC 5321 makes the local part
    case-sensitive in theory and no identity provider treats it so in practice, and
    the module upper-cases them to compare. Splitting on case would make one person
    two nodes the moment two exports disagreed."""
    nodes = extract_nodes([{
        "check_id": "X",
        "affected_objects": [{"type": "btp_user", "name": "jsmith@company.com"},
                             {"type": "btp_user", "name": "JSmith@Company.com"}],
    }])
    assert len(nodes) == 1


def test_a_cloud_object_keeps_a_system_it_names_itself():
    """The rule suppresses a BORROWED default, not a real scope: when something can
    name the subaccount, that must survive."""
    nodes = extract_nodes([{
        "check_id": "X",
        "affected_objects": [{"type": "btp_user", "name": "a@b.com", "system": "SUB1"}],
    }], default_system="PRD")
    assert nodes[0]["key"] == "btp_user:A@B.COM@SUB1"


def test_every_cloud_scoped_type_has_a_case_rule():
    """A type registered cloud-scoped but in neither case registry would fall to the
    unknown-type default and be silently upper-cased."""
    from server.identity import _CLOUD_SCOPED_TYPES
    unregistered = _CLOUD_SCOPED_TYPES - _UPPERCASE_TYPES - _CASE_SENSITIVE_TYPES
    assert not unregistered, f"cloud types with no case rule: {sorted(unregistered)}"


def test_a_malformed_object_does_not_abort_node_extraction():
    """One bad row in one export must not empty the graph."""
    nodes = extract_nodes([{"check_id": "X", "affected_objects": [
        {"type": "user", "name": ""},          # malformed
        {"type": "user", "name": "GOOD"},
    ]}], default_system="PRD")
    assert [n["key"] for n in nodes] == ["user:GOOD@PRD"]


@pytest.mark.skipif(not SAMPLE.is_dir(), reason="sample_data not present")
def test_every_emitted_object_type_is_registered():
    """Completeness in the direction nothing was checking: from the MODULES inward.

    `norm_name` has always said that "a new case-bearing type must be registered in
    _CASE_SENSITIVE_TYPES — see test_identity.py, which asserts ... that every type
    used by a shipped module is registered." No such test existed. The two
    completeness tests above start from the REGISTRIES and ask whether each entry is
    classified; neither starts from the modules and asks whether each type they emit
    arrived deliberately.

    Two had not. `business_partner` (master_data_changes, vendor_master) took the
    unknown-type fallback for its whole life — harmlessly, because the fallback
    upper-cases and a partner id is upper-case, which is exactly why nobody noticed.
    `parameter` (webdisp_security) is worse: it duplicates `parameter_name`, so five
    profile parameters an estate has once exist in the graph twice, and a path hop
    declaring `parameter_name` sees half their evidence. See the comment on
    `parameter` in server/identity.py for why it is registered rather than renamed.

    A type reaching the fallback is not automatically wrong. Reaching it WITHOUT
    anyone deciding is, because the dangerous direction is silent: the next
    case-bearing type added would be upper-cased, merging two objects into one, and
    no report would say so.
    """
    import contextlib
    import importlib
    import io

    from modules.data_loader import DataLoader
    from server.ingest import AUDITORS, RUN_CONTEXT

    emitted: dict[str, set[str]] = {}
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(SAMPLE).load_all()
        for mod, cls in AUDITORS:
            auditor = getattr(importlib.import_module(f"modules.{mod}"), cls)
            for f in (auditor(data, None, RUN_CONTEXT).run_all_checks() or []):
                for obj in (f.get("affected_objects") or []):
                    t = obj.get("type") if isinstance(obj, dict) else getattr(obj, "type", None)
                    if t:
                        emitted.setdefault(str(t).strip().lower(), set()).add(f["check_id"])

    assert emitted, "no module emitted a single structured object — the scan did not run"

    registered = _UPPERCASE_TYPES | _CASE_SENSITIVE_TYPES
    unregistered = {t: sorted(c)[:4] for t, c in emitted.items() if t not in registered}
    assert not unregistered, (
        "these object types are emitted by shipped modules but registered in neither "
        f"case registry, so they take the unknown-type fallback undecided: {unregistered}. "
        "Add each to _UPPERCASE_TYPES or _CASE_SENSITIVE_TYPES — the fallback may well "
        "be the right rule, but it has to be chosen.")
