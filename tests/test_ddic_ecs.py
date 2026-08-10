# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
DDIC in SAP Enterprise Cloud Services — the false positive, and its replacement.

WHY THIS FILE EXISTS
`modules/user_auth_audit.py` raised a CRITICAL when DDIC was unlocked. SAP Note
3250501 — the MANDATORY hardening baseline for AS ABAP in ECS, which is the exact
estate this product audits — grants DDIC an explicit exception: locking it is not
required there. So on every RISE tenant we scanned we produced a CRITICAL for a
compliant system, with a remediation that can collide with the provider's own
operations. Reasoning from what a control sounds like instead of from what the
governing baseline says is the same defect class the CVA engine's Tier 2 was spent
eliminating.

EVERY SUPPRESSION HERE IS PAIRED WITH A CONTROL
Deleting a check is not a fix. Non-ECS AS ABAP still wants DDIC locked, so each
"this must no longer fire" test below is followed by the case that must STILL fire —
either the unchanged on-premise finding, or the sharper ECS finding that replaces
it. A check that stops detecting the real thing is not an improvement on one that
over-reports; it is the same failure wearing a quieter coat.

THE EXIT CRITERION is `test_a_compliant_ecs_system_produces_no_findings_at_all`.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import user_auth_audit                                   # noqa: E402
from modules.user_auth_audit import UserAuthAuditor                   # noqa: E402
from server.enrich import team_for                                    # noqa: E402

NOTE_FILE = ROOT / "data" / "ecs_hardening_3250501.json"

#: The deployment modes server/enrich.py already defines. Using its vocabulary is
#: the point — a second one invented in the module would route findings to nobody.
ECS_MODES = ["rise_pce", "rise_tailored"]
NON_ECS_MODES = ["on_prem", ""]


# --------------------------------------------------------------------------- #
#  Harness                                                                    #
# --------------------------------------------------------------------------- #

def audit(users, mode=None, **data):
    """Run the whole user auditor over `users` in deployment mode `mode`.

    The WHOLE auditor, not just the method under test: the defect being fixed is
    what the customer's report says, and a check suppressed in one method while a
    sibling still emits it would pass a method-level test and ship the bug.
    """
    run_context = {"modules": {"users"}}
    if mode is not None:
        run_context["deployment_mode"] = mode
    payload = {"users": users}
    payload.update(data)
    return UserAuthAuditor(payload, None, run_context).run_all_checks()


def ids(findings):
    return sorted(f["check_id"] for f in findings)


def one(findings, check_id):
    """The single finding with this id — asserting there is exactly one."""
    got = [f for f in findings if f["check_id"] == check_id]
    assert len(got) == 1, f"expected exactly one {check_id}, got {len(got)}"
    return got[0]


#: Today, in SAP's date format. The rows below carry a fresh logon and password
#: date so that the dormancy, never-logged-in and password-age checks stay SILENT
#: and an `== []` assertion means what it says. Computed rather than hard-coded:
#: a literal date would quietly turn every negative control into a dormancy finding
#: ninety days after this file was written.
TODAY = datetime.now().strftime("%Y%m%d")


def user(name, ustyp="B", uflag="0", **extra):
    row = {"BNAME": name, "USTYP": ustyp, "UFLAG": uflag,
           "TRDAT": TODAY, "PWDCHGDATE": TODAY, "ERDAT": TODAY}
    row.update(extra)
    return row


@pytest.fixture
def note(monkeypatch):
    """Replace the bundled note facts for one test.

    The module caches the file, so a test that mutated it would leak into the next
    one. `None` restores the real file.
    """
    def _set(value):
        monkeypatch.setattr(user_auth_audit, "_ECS_NOTE_CACHE", value)
    yield _set


# --------------------------------------------------------------------------- #
#  The source of truth is the file, not this test                             #
# --------------------------------------------------------------------------- #

def test_the_note_file_carries_the_configuration_items_we_key_on():
    """Both ECS behaviours are gated on items in the note. If the data file is
    regenerated without them, the gate silently opens (DDIC) or silently closes
    (EARLYWATCH) and nothing else in the suite would notice."""
    items = set(json.loads(NOTE_FILE.read_text(encoding="utf-8"))["configuration_items"])
    missing = sorted(set(UserAuthAuditor.ECS_STANDARD_USER_ITEMS.values()) - items)
    assert not missing, (
        f"modules/user_auth_audit.py keys on configuration items the note no longer "
        f"lists: {missing}. Either the note changed and the checks must follow, or "
        f"the extraction dropped them.")


def test_parameter_values_are_read_from_the_note_and_not_transcribed():
    """The SAP* remediation prints ECS parameter values. Every one of them must be
    the file's value — a baseline value typed from memory is how this product told a
    customer they were compliant when they were not (min_password_lng >= 8 vs 15)."""
    params = json.loads(NOTE_FILE.read_text(encoding="utf-8"))["parameters"]
    for name in ("login/no_automatic_user_sapstar", "login/create_virtual_user_sapstar"):
        assert user_auth_audit._ecs_parameter(name) == params[name]["ecs"]

    text = one(audit([user("SAP*", ustyp="A", uflag="0")], mode="rise_pce"),
               "USR-001")["remediation"]
    for name in ("login/no_automatic_user_sapstar", "login/create_virtual_user_sapstar"):
        assert f"{name} = {params[name]['ecs']}" in text


def test_no_sap_note_is_cited_that_3250501_does_not_reference():
    """The repo has shipped invented note numbers before. The two new checks may
    cite 3250501 itself and the notes it references — nothing else."""
    note_json = json.loads(NOTE_FILE.read_text(encoding="utf-8"))
    allowed = set(note_json["referenced_notes"]) | {"3250501"}

    findings = audit([user("DDIC", ustyp="A"), user("EARLYWATCH", uflag="64")],
                     mode="rise_pce")
    for f in findings:
        if f["check_id"] not in ("USR-009", "USR-010"):
            continue
        blob = " ".join([f["description"], f["remediation"], *f["references"]])
        cited = set(re.findall(r"SAP Note\s+(\d{4,})", blob))
        assert cited <= allowed, f"{f['check_id']} cites unverified note(s): {cited - allowed}"
        assert "3250501" in cited, (
            f"{f['check_id']} must show the reader which baseline it applied")


# --------------------------------------------------------------------------- #
#  The false positive                                                         #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("mode", ECS_MODES)
@pytest.mark.parametrize("ustyp", ["B", "S"])
def test_an_unlocked_ddic_is_not_a_finding_in_ecs(mode, ustyp):
    """THE BUG. SAP does not require DDIC to be locked in ECS, so an unlocked DDIC
    of type System (as delivered) or Service (as produced by a CAM request) is a
    compliant system and must produce nothing at all."""
    assert audit([user("DDIC", ustyp=ustyp, uflag="0")], mode=mode) == []


@pytest.mark.parametrize("mode", NON_ECS_MODES)
def test_but_an_unlocked_ddic_is_still_a_finding_outside_ecs(mode):
    """THE CONTROL. The exception is SAP's, for SAP's estate. On premise the old
    check is still right and losing it would be a regression, not a fix."""
    f = one(audit([user("DDIC", ustyp="A", uflag="0")], mode=mode), "USR-001")
    assert f["severity"] == "CRITICAL"
    assert f["affected_objects"] == [{"type": "user", "name": "DDIC"}]


def test_a_caller_that_says_nothing_gets_the_historical_behaviour():
    """`BaseAuditor.run_context` is explicit that an unset context means the caller
    did not tell us. Guessing ECS would silently drop the check on real on-premise
    systems, which is a worse trade than an extra finding on a RISE one."""
    assert ids(audit([user("DDIC", ustyp="A")])) == ["USR-001"]
    assert ids(audit([user("DDIC", ustyp="A")], mode=None)) == ["USR-001"]


# --------------------------------------------------------------------------- #
#  The replacement: what SAP's exception actually rests on                     #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("mode", ECS_MODES)
def test_a_dialog_ddic_in_ecs_is_the_real_finding(mode):
    """SAP's stated protection is the user TYPE: System cannot open an ordinary GUI
    dialog session, and Service is reached through a tracked request. Type Dialog has
    neither property, so the premise of the exception is void — and that is a sharper
    statement than 'DDIC is unlocked'."""
    f = one(audit([user("DDIC", ustyp="A", uflag="0")], mode=mode), "USR-009")
    assert f["severity"] == "HIGH"
    assert f["scope"] == "object"
    assert f["affected_objects"] == [{"type": "user", "name": "DDIC"}]
    assert "USR-001" not in ids([f]), "the replaced check must not fire as well"


@pytest.mark.parametrize("mode", ECS_MODES)
def test_the_finding_shows_the_reader_we_read_the_note(mode):
    """A reviewer holding 3250501 has to be able to see that we hold it too —
    otherwise 'we did not flag your unlocked DDIC' reads as an oversight."""
    f = one(audit([user("DDIC", ustyp="A")], mode=mode), "USR-009")
    text = f["description"]
    assert "3250501" in text
    assert "secure_ddic_ecs_exception" in text
    assert "CAM" in text, "the request path SAP's exception depends on"
    assert f["details"]["ecs_configuration_item"] == "secure_ddic_ecs_exception"


@pytest.mark.parametrize("mode", ECS_MODES)
def test_a_locked_dialog_ddic_is_reported_lower(mode):
    """Locked means no live logon path today, only one waiting for the next
    maintenance unlock. Reporting that at the same severity as a usable account is
    the inflation that makes a queue unworkable."""
    f = one(audit([user("DDIC", ustyp="A", uflag="64")], mode=mode), "USR-009")
    assert f["severity"] == "MEDIUM"
    assert f["details"]["locked"] is True


@pytest.mark.parametrize("mode", ECS_MODES)
@pytest.mark.parametrize("ustyp", ["", "   "])
def test_a_blank_user_type_is_not_a_dialog_user(mode, ustyp):
    """An empty USTYP column is an export that did not say. Turning silence into a
    HIGH against DDIC would rebuild the exact false positive this work removed."""
    assert audit([user("DDIC", ustyp=ustyp)], mode=mode) == []


@pytest.mark.parametrize("mode", NON_ECS_MODES)
def test_the_type_check_does_not_change_on_premise_behaviour(mode):
    """Outside ECS the instruction was 'behaviour unchanged'. USR-009 is scoped to
    the estate whose baseline motivates it."""
    assert ids(audit([user("DDIC", ustyp="A")], mode=mode)) == ["USR-001"]


@pytest.mark.parametrize("mode", ECS_MODES)
def test_one_ddic_across_several_clients_is_one_finding(mode):
    """The export carries a row per client. Three rows for one misconfigured account
    is one defect and one graph node, not three."""
    rows = [user("DDIC", ustyp="A", CLIENT=c) for c in ("000", "100", "200")]
    f = one(audit(rows, mode=mode), "USR-009")
    assert f["affected_objects"] == [{"type": "user", "name": "DDIC"}]
    assert f["details"]["observed_clients"] == ["000", "100", "200"]
    assert len(f["affected_items"]) == 3, "the reader still needs to see which clients"


# --------------------------------------------------------------------------- #
#  Revision awareness: the gate is the note file, not a constant here          #
# --------------------------------------------------------------------------- #

def test_if_a_future_revision_drops_the_exception_ddic_falls_back(note):
    """The carve-out is keyed on the note's own configuration item. A v47 that
    withdrew it must restore the lock check without anyone editing the module."""
    note({"configuration_items": ["secure_sap_star"], "source": {}})
    assert ids(audit([user("DDIC", ustyp="A")], mode="rise_pce")) == ["USR-001"]


def test_an_unreadable_note_keeps_the_ddic_carve_out(note):
    """Deliberate asymmetry. Withdrawing the suppression on a missing file would
    reinstate a KNOWN false positive on every ECS tenant, and it costs nothing to
    keep: the sharper type check still runs in its place."""
    note({})
    assert ids(audit([user("DDIC", ustyp="B")], mode="rise_pce")) == []
    assert ids(audit([user("DDIC", ustyp="A")], mode="rise_pce")) == ["USR-009"]


def test_an_unreadable_note_leaves_earlywatch_audited_by_something(note):
    """The other half of the asymmetry. USR-010 ASSERTS a requirement, so it must not
    run on a file we could not read — but suppressing the generic check as well would
    leave the account checked by nothing, which is worse than generic text."""
    note({})
    findings = audit([user("EARLYWATCH", ustyp="S", uflag="0")], mode="rise_pce")
    assert ids(findings) == ["USR-001"]


def test_an_unreadable_note_is_not_quoted_as_if_we_had_read_it(note):
    """The fallback above must not carry a claim about a document we could not open.
    A citation is a promise the reader can check it; making one from a missing file is
    how a report's numbers stop being trustworthy."""
    note({})
    f = one(audit([user("EARLYWATCH", ustyp="S", uflag="0")], mode="rise_pce"), "USR-001")
    blob = f["description"] + " ".join(f["references"])
    assert "3250501" not in blob


def test_the_replacement_check_is_held_to_the_same_rule(note):
    """Found in review. USR-009 runs on the unreadable-file path (DDIC is in
    `ECS_ITEM_ASSUMED_WHEN_NOTE_UNREADABLE`), and it used to describe and cite
    3250501 there — asserting the note's content from a file we had just failed to
    open, which is exactly what the test above forbids one check above it. The
    finding itself must still fire: the type is wrong whether or not we can read the
    baseline that explains why it matters."""
    note({})
    f = one(audit([user("DDIC", ustyp="A")], mode="rise_pce"), "USR-009")
    blob = f["description"] + " " + " ".join(f["references"])
    assert "3250501" not in blob
    assert "secure_ddic_ecs_exception" not in f["description"]
    assert "Dialog" in f["description"], "the observation itself is still reported"


def test_the_citation_names_the_revision_it_judged_against(note):
    """The module reads version and release date out of the note file rather than
    hard-coding them. Nothing asserted that, so a citation that silently dropped back
    to the bare note number — the same string the unreadable-file path produces —
    would have looked identical to a passing suite."""
    src = json.loads(NOTE_FILE.read_text(encoding="utf-8"))["source"]
    f = one(audit([user("DDIC", ustyp="A")], mode="rise_pce"), "USR-009")
    assert f"v{src['version']}" in f["description"]
    assert str(src["released"]) in f["description"]


# --------------------------------------------------------------------------- #
#  EARLYWATCH: our generic text under-states the ECS rule                      #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("mode", ECS_MODES)
def test_a_locked_earlywatch_is_still_a_deviation_in_ecs(mode):
    """We said 'lock if not actively used'. The note's item is
    `delete_earlywatch_all_clients`, so locked-but-present is not compliant and a
    report calling it clean is wrong — just wrong in the opposite direction to DDIC."""
    f = one(audit([user("EARLYWATCH", ustyp="S", uflag="64")], mode=mode), "USR-010")
    assert f["severity"] == "LOW", "no logon path; a baseline deviation, not exposure"
    assert "delete_earlywatch_all_clients" in f["description"]
    assert "3250501" in f["description"]


@pytest.mark.parametrize("mode", ECS_MODES)
def test_an_unlocked_earlywatch_keeps_its_severity(mode):
    """USR-010 REPLACES USR-001 for this account in ECS, so it must not quietly
    downgrade a live, unlocked account on the way through."""
    findings = audit([user("EARLYWATCH", ustyp="S", uflag="0")], mode=mode)
    assert ids(findings) == ["USR-010"]
    assert findings[0]["severity"] == "HIGH", "the generic check's severity, kept"


@pytest.mark.parametrize("mode", ECS_MODES)
def test_an_absent_earlywatch_is_the_compliant_state(mode):
    """Deleted in every client is what the note asks for. It must produce silence,
    not a 'could not verify' finding."""
    assert audit([user("SAP*", ustyp="A", uflag="64")], mode=mode) == []


@pytest.mark.parametrize("mode", NON_ECS_MODES)
def test_earlywatch_is_unchanged_outside_ecs(mode):
    """No basis to demand deletion on an estate the ECS baseline does not govern."""
    assert ids(audit([user("EARLYWATCH", ustyp="S", uflag="0")], mode=mode)) == ["USR-001"]


# --------------------------------------------------------------------------- #
#  The standard users the note does NOT carve out                             #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("mode", ECS_MODES + NON_ECS_MODES)
@pytest.mark.parametrize("name", ["SAP*", "SAPCPIC", "TMSADM"])
def test_the_other_standard_users_are_unchanged_in_every_mode(name, mode):
    """The note's items for these three call for the accounts to be SECURED, which is
    what the generic check already asserts. Diverging where the note does not diverge
    would be inventing a rule."""
    f = one(audit([user(name, ustyp="A", uflag="0")], mode=mode), "USR-001")
    assert f["affected_objects"] == [{"type": "user", "name": name}]


@pytest.mark.parametrize("name", ["SAP*", "SAPCPIC", "TMSADM"])
def test_their_ecs_finding_says_the_baseline_agrees_with_us(name):
    """In ECS the customer can check our claim against SAP's own document; saying
    which document turns 'the scanner says so' into 'your provider says so'."""
    f = one(audit([user(name, ustyp="A", uflag="0")], mode="rise_pce"), "USR-001")
    assert "3250501" in f["description"]


# --------------------------------------------------------------------------- #
#  Negative controls and degradation                                          #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("mode", ECS_MODES)
def test_a_compliant_ecs_system_produces_no_findings_at_all(mode):
    """THE EXIT CRITERION for this task, run through the whole auditor rather than
    the two methods: DDIC delivered as type System and unlocked (which ECS permits),
    EARLYWATCH deleted, every other standard user locked. Zero findings."""
    users = [
        user("DDIC", ustyp="B", uflag="0", TRDAT="20260801"),
        user("SAP*", ustyp="A", uflag="64"),
        user("SAPCPIC", ustyp="C", uflag="64"),
        user("TMSADM", ustyp="B", uflag="64"),
    ]
    assert audit(users, mode=mode) == []


@pytest.mark.parametrize("mode", ECS_MODES + NON_ECS_MODES)
@pytest.mark.parametrize("payload", [
    {},                                        # no export at all
    {"users": []},                             # export present, empty
    {"users": [{}]},                           # a row with no columns
    {"users": [{"BNAME": "DDIC"}]},            # no USTYP, no UFLAG
    {"users": [{"BNAME": None, "USTYP": None, "UFLAG": None}]},
    {"users": [{"USERNAME": "DDIC", "USER_TYPE": "A", "LOCK_STATUS": "0"}]},
    {"users": "not-a-list"},                   # a loader that returned nonsense
    {"users": ["DDIC"]},                       # rows that are not dicts
])
def test_a_missing_or_malformed_export_never_raises(payload, mode):
    """Absent evidence returns cleanly. `row.get("BNAME", row.get("USERNAME"))`
    returns None when BNAME is present but empty, and the `.upper()` after it used to
    take the whole user audit down on one malformed row."""
    findings = UserAuthAuditor(dict(payload), None,
                               {"deployment_mode": mode}).run_all_checks()
    assert isinstance(findings, list)


def test_the_alternate_column_names_still_reach_the_ecs_checks():
    """The control for the malformed-input test above: USERNAME/USER_TYPE/LOCK_STATUS
    is a real export shape, and tolerating junk must not mean ignoring valid data."""
    findings = UserAuthAuditor(
        {"users": [{"USERNAME": "DDIC", "USER_TYPE": "A", "LOCK_STATUS": "0",
                    "LAST_LOGON": TODAY, "PASSWORD_CHANGE_DATE": TODAY}]},
        None, {"deployment_mode": "rise_pce"}).run_all_checks()
    assert ids(findings) == ["USR-009"]


@pytest.mark.parametrize("mode", ECS_MODES + NON_ECS_MODES)
def test_every_check_id_this_module_emits_routes_to_a_team(mode):
    """An unrouted id is a finding that appears in no team's queue. The new ids are
    covered here because the static uniqueness guard cannot see routing."""
    users = [user("DDIC", ustyp="A"), user("EARLYWATCH", uflag="0"),
             user("SAP*", ustyp="A"), user("SVC_RFC", ustyp="A")]
    unrouted = sorted({f["check_id"] for f in audit(users, mode=mode)
                       if team_for(f["check_id"]) == "unassigned"})
    assert not unrouted, unrouted


def test_the_new_ids_do_not_reuse_an_existing_one():
    """USR-001..008 are foreign keys into the remediation KB, the compliance mapping
    and the attack-path templates. A replacement check must not inherit another
    check's remediation text."""
    findings = audit([user("DDIC", ustyp="A"), user("EARLYWATCH", uflag="0")],
                     mode="rise_pce")
    assert set(ids(findings)) == {"USR-009", "USR-010"}
    assert one(findings, "USR-009")["title"] != one(findings, "USR-010")["title"]
