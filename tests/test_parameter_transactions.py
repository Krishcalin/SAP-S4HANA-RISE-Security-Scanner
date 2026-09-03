"""A Z transaction that is SE16 wearing a different name.

A parameter transaction runs an existing transaction with screen fields
pre-filled. SAP writes the mode into the PARAM string in table TSTCP:

    /*SE16 DATABROWSE-TABLENAME=USR02;   first screen SKIPPED
    /NSE16 DATABROWSE-TABLENAME=USR02;   first screen NOT skipped

The difference is the whole check. With `/*` the entry screen never appears and
the pre-filled table is the only one reachable — a deliberate, narrow grant.
With `/N` the entry screen appears WITH the value filled in, and the user types
over it.

What that defeats is the transaction-level control. `check_sensitive_tcodes` in
this module reports a role granting SE16 by name; it cannot see a role granting
Z_VENDOR_LIST. The role looks unremarkable in PFCG, in SUIM, and in this
product's own role review.

It is NOT unrestricted table access, and the finding says so: S_TABU_DIS and
S_TABU_NAM still apply to whatever the user substitutes. Overstating that would
be the kind of claim a reviewer checks once and then stops trusting the report.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.abap_authorizations import AbapAuthorizationAuditor        # noqa: E402


def fired(data):
    return {f["check_id"]: f
            for f in AbapAuthorizationAuditor(data).run_all_checks()}


def param(tcode, param_string):
    return {"TCODE": tcode, "PARAM": param_string}


def s_tcode(role, tcd):
    return {"AGR_NAME": role, "OBJECT": "S_TCODE", "AUTH": role + "01",
            "FIELD": "TCD", "LOW": tcd, "HIGH": ""}


OPEN_SE16 = [param("Z_VEND_LIST", "/NSE16 DATABROWSE-TABLENAME=LFA1;")]


# ── the mode is the whole check ────────────────────────────────────────────

def test_an_open_entry_screen_over_a_critical_transaction_is_reported():
    finding = fired({"parameter_transactions": OPEN_SE16})["AUTH-017"]
    assert finding["severity"] == "HIGH"
    item, = finding["affected_items"]
    assert "Z_VEND_LIST" in item and "/NSE16" in item


def test_a_skipped_entry_screen_is_a_narrow_grant_not_a_finding():
    """`/*` means the entry screen never appears, so the pre-filled table is
    the only one reachable — which is the transaction doing exactly what its
    author intended."""
    assert "AUTH-017" not in fired({"parameter_transactions": [
        param("Z_VEND_LIST", "/*SE16 DATABROWSE-TABLENAME=LFA1;")]})


def test_the_pre_filled_value_is_shown():
    """A reviewer needs to know which table it was built for before deciding
    whether the open screen matters."""
    item, = fired({"parameter_transactions": OPEN_SE16})["AUTH-017"]["affected_items"]
    assert "DATABROWSE-TABLENAME=LFA1" in item


@pytest.mark.parametrize("target", ["SE16", "SE16N", "SE17", "SM30", "SM31",
                                    "SE38", "SA38", "SM49"])
def test_every_critical_target_is_recognised(target):
    assert "AUTH-017" in fired({"parameter_transactions": [
        param("Z_WRAP", "/N%s X=Y;" % target)]}), target


def test_a_harmless_target_is_not_reported():
    """The concern is reaching a CRITICAL transaction by another name, not
    parameter transactions as a category — they are an ordinary SAP feature."""
    assert "AUTH-017" not in fired({"parameter_transactions": [
        param("Z_HELLO", "/NSU53 X=Y;")]})


def test_a_param_that_is_not_a_parameter_transaction_is_skipped():
    for junk in ("", "SE16", "X=Y;", "   "):
        assert "AUTH-017" not in fired({"parameter_transactions": [
            param("Z_ODD", junk)]}), junk


def test_lower_case_n_is_the_same_mode():
    assert "AUTH-017" in fired({"parameter_transactions": [
        param("Z_VEND_LIST", "/nse16 DATABROWSE-TABLENAME=LFA1;")]})


# ── it runs without the role export, and says more with it ────────────────

def test_it_runs_without_agr_1251():
    """THE MODULE SELF-SKIPS WITHOUT role_auth_values, and this check must not.
    A parameter transaction is a property of the transaction definition; TSTCP
    settles it, and gating it behind an export it does not read would make the
    finding disappear for every customer who supplies only TSTCP."""
    assert "AUTH-017" in fired({"parameter_transactions": OPEN_SE16})


def test_role_data_names_who_reaches_the_transaction_only_through_this_one():
    """The detail that makes it actionable. A role granting both Z_VEND_LIST
    and SE16 gains nothing from the indirection; a role granting only
    Z_VEND_LIST is reaching SE16 by a route no role review shows."""
    item, = fired({
        "parameter_transactions": OPEN_SE16,
        "role_auth_values": [s_tcode("Z_AP_CLERK", "Z_VEND_LIST"),
                             s_tcode("Z_BASIS", "Z_VEND_LIST"),
                             s_tcode("Z_BASIS", "SE16")],
        "user_roles": [{"UNAME": "AGARCIA", "AGR_NAME": "Z_AP_CLERK"},
                       {"UNAME": "LWANG", "AGR_NAME": "Z_BASIS"}],
    })["AUTH-017"]["affected_items"]
    assert "2 role(s)" in item
    assert "1 of which do not grant SE16 directly" in item
    assert "2 user(s)" in item


def test_the_roles_become_graph_objects():
    finding = fired({
        "parameter_transactions": OPEN_SE16,
        "role_auth_values": [s_tcode("Z_AP_CLERK", "Z_VEND_LIST")],
    })["AUTH-017"]
    types = {(o["type"], o["name"]) for o in finding["affected_objects"]}
    assert ("tcode", "Z_VEND_LIST") in types
    assert ("tcode", "SE16") in types, (
        "the transaction actually reached belongs in the graph too, or the "
        "path from role to SE16 has a missing link")
    assert ("role", "Z_AP_CLERK") in types


# ── what it does not claim ────────────────────────────────────────────────

def test_it_does_not_claim_unrestricted_table_access():
    """S_TABU_DIS and S_TABU_NAM still apply to whatever the user substitutes.
    A finding that said otherwise would be checked once and then disbelieved."""
    finding = fired({"parameter_transactions": OPEN_SE16})["AUTH-017"]
    text = finding["description"].lower()
    assert "not unrestricted table access" in text
    assert "s_tabu_dis" in text


def test_it_names_the_check_it_is_invisible_to():
    finding = fired({"parameter_transactions": OPEN_SE16})["AUTH-017"]
    assert "SE16" in finding["description"]
    assert "role review" in finding["description"].lower()


def test_no_export_is_silent():
    assert "AUTH-017" not in fired({})


# ── the mistake this check was nearly shipped with ────────────────────────

def test_no_two_checks_in_this_module_share_an_id():
    """AUTH-017 WAS FIRST WRITTEN AS AUTH-016, WHICH WAS ALREADY TAKEN.

    `check_icf_destination` has emitted AUTH-016 all along, and the collision
    was not caught by grepping for `check_id="AUTH-..."` because this module
    passes the id POSITIONALLY to `_emit` — that grep returns one hit for
    sixteen ids. Two checks sharing an id merge unrelated findings under one
    identity in the database and one page in the catalogue, and the second one
    silently overwrites the first's published guidance.

    This reads the ids the way the module actually writes them.
    """
    import re
    source = (ROOT / "modules" / "abap_authorizations.py").read_text(
        encoding="utf-8")
    ids = re.findall(r'"(AUTH-\d+)"', source)
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    assert not duplicates, "check ids emitted more than once: %s" % duplicates
    assert "AUTH-017" in ids and "AUTH-016" in ids


def test_every_emitted_id_has_its_own_published_page():
    """The overwrite half of the same mistake: AUTH-016's guidance was replaced
    by AUTH-017's before the collision was noticed."""
    import json
    import re
    source = (ROOT / "modules" / "abap_authorizations.py").read_text(
        encoding="utf-8")
    pages = json.loads((ROOT / "data" / "finding_details.json").read_text(
        encoding="utf-8"))
    for check_id in sorted(set(re.findall(r'"(AUTH-\d+)"', source))):
        page = pages.get(check_id)
        assert page, "%s emits no published page" % check_id
        assert len(page.get("risk", "")) > 200, "%s has a stub page" % check_id
    assert "S_ICF" in pages["AUTH-016"]["risk"], (
        "AUTH-016's page is not the ICF destination one it belongs to")
    assert "parameter transaction" in pages["AUTH-017"]["risk"]
