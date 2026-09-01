"""The text sent to SAP for a setting the customer may not change.

The finding page told people for months that "the pre-drafted text is below"
and there was none. What was below was the check's generic remediation, which
for a profile parameter opens "Set login/min_password_lng to at least the
mandated minimum" — an instruction to perform the change the sentence above it
has just said the customer cannot perform.

That is the defect these tests exist for, and the first one asserts the thing
that was wrong rather than the thing that is now right.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

needs_db = pytest.mark.skipif(
    not os.environ.get("DB_DSN"),
    reason="set DB_DSN to a PostgreSQL 16 instance")


@pytest.fixture
def estate():
    """A RISE landscape with one SAP-owned parameter finding on one system."""
    from server import db
    db.init_schema()
    land = db.one("INSERT INTO landscape (name, deployment_mode) "
                  "VALUES (%s,'rise_pce') RETURNING id",
                  ("sr-%s" % os.urandom(4).hex(),))["id"]
    system = db.one("INSERT INTO sap_system (landscape_id, sid, client, tier) "
                    "VALUES (%s,'PRD','100','prod') RETURNING id", (land,))["id"]
    run = db.one("INSERT INTO scan_run (landscape_id, system_id, status) "
                 "VALUES (%s,%s,'complete') RETURNING id", (land, system))["id"]
    yield {"landscape": land, "system": system, "run": run}
    db.execute("DELETE FROM landscape WHERE id = %s", (land,))


def _finding(estate, check_id, details, owner="ticket_to_sap"):
    from server import db
    from psycopg.types.json import Jsonb
    db.execute("INSERT INTO check_definition (check_id, title, references_json) "
               "VALUES (%s,%s,%s) ON CONFLICT (check_id) DO UPDATE "
               "SET references_json = EXCLUDED.references_json",
               (check_id, check_id,
                Jsonb(["SAP Note 3250501 — mandatory hardening for AS ABAP in "
                       "SAP ECS (v46, 2026-05-15)"])))
    fid = db.one(
        "INSERT INTO finding (landscape_id, system_id, fingerprint, check_id, "
        "client, severity, state, remediation_owner) "
        "VALUES (%s,%s,%s,%s,'100','HIGH','open',%s) RETURNING id",
        (estate["landscape"], estate["system"], os.urandom(16).hex(),
         check_id, owner))["id"]
    db.execute(
        "INSERT INTO finding_observation (finding_id, scan_run_id, severity, "
        "title, description, details) VALUES (%s,%s,'HIGH',%s,'',%s)",
        (fid, estate["run"], check_id, Jsonb(details)))
    return fid


PARAM = {"parameter": "login/min_password_lng", "current_value": "6",
         "ecs_standard": "15", "ecs_allowed": [">=15"],
         "baseline_source": "SAP Note 3250501"}


# --------------------------------------------------------------------------
# The defect
# --------------------------------------------------------------------------

@needs_db
def test_it_never_tells_the_customer_to_make_the_change(estate):
    """THE ORIGINAL DEFECT, asserted directly.

    Under RISE the customer cannot set a profile parameter, and the product's
    own model says a finding must ask SAP rather than instruct the customer.
    The page said both things at once.
    """
    from server import servicerequest

    text = servicerequest.draft(_finding(estate, "PARAM-A", PARAM))["text"]
    lowered = text.lower()
    assert "please set" in lowered, "it does not ask SAP for anything"
    assert not lowered.startswith("set "), "it opens with an instruction"
    assert "not able to make this change ourselves" in lowered


@needs_db
def test_it_carries_what_sap_needs_to_act_without_asking(estate):
    from server import servicerequest

    text = servicerequest.draft(_finding(estate, "PARAM-B", PARAM))["text"]
    for needed in ("PRD", "client 100", "login/min_password_lng", "6", "15",
                   "SAP Note 3250501", "Private Cloud Edition"):
        assert needed in text, "the request omits %r" % needed


@needs_db
def test_the_note_version_travels_with_the_request(estate):
    """ECS answers against the note as it stands, so a request quoting a
    superseded revision comes back."""
    from server import servicerequest

    text = servicerequest.draft(_finding(estate, "PARAM-C", PARAM))["text"]
    assert "v46, 2026-05-15" in text


# --------------------------------------------------------------------------
# What it refuses to write
# --------------------------------------------------------------------------

@needs_db
def test_no_values_means_a_question_not_a_template_with_a_blank(estate):
    """A request with a hole where the number goes is the one that gets sent,
    bounced, and blamed on the tool."""
    from server import servicerequest

    drafted = servicerequest.draft(
        _finding(estate, "PARAM-D", {"parameter": "login/other"}))
    assert drafted["has_values"] is False
    assert "Please confirm the current value" in drafted["text"]
    assert "Please set" not in drafted["text"]
    assert "not readable from the export supplied" in drafted["text"]


@needs_db
def test_an_unset_parameter_says_so_rather_than_leaving_a_blank(estate):
    """`gw/sec_info` with an empty value means NOT SET, which is the finding.
    A blank cell reads as a tool that failed rather than a system that is."""
    from server import servicerequest

    drafted = servicerequest.draft(_finding(estate, "PARAM-E", {
        "parameter": "gw/sec_info", "current_value": "",
        "ecs_standard": "$(DIR_GLOBAL)$(DIR_SEP)secinfo$(FT_DAT)"}))
    assert "(not set)" in drafted["text"]
    assert drafted["has_values"] is True          # unset IS a current value


@needs_db
def test_a_finding_the_customer_can_fix_has_no_request_to_raise(estate):
    from server import servicerequest

    fid = _finding(estate, "PARAM-F", PARAM, owner="customer_fixable")
    assert servicerequest.draft(fid) is None


# --------------------------------------------------------------------------
# One request, not forty-seven
# --------------------------------------------------------------------------

@needs_db
def test_every_setting_on_a_system_goes_in_one_request(estate):
    """Forty-seven tickets is not a remediation plan, it is a way to be
    ignored. SAP ECS works per system and per change window."""
    from server import servicerequest

    _finding(estate, "PARAM-G", PARAM)
    _finding(estate, "PARAM-H", {"parameter": "login/fails_to_user_lock",
                                 "current_value": "10", "ecs_standard": "6"})
    batch = servicerequest.draft_for_system(estate["system"])
    assert batch["settings"] == 2 and batch["with_values"] == 2
    assert "login/min_password_lng" in batch["text"]
    assert "login/fails_to_user_lock" in batch["text"]
    assert batch["text"].count("Subject:") == 1


@needs_db
def test_the_ones_it_could_not_read_are_listed_separately(estate):
    """Mixed in with the table they look like settings SAP can act on."""
    from server import servicerequest

    _finding(estate, "PARAM-I", PARAM)
    _finding(estate, "PARAM-J", {"parameter": "login/unknown"})
    batch = servicerequest.draft_for_system(estate["system"])
    assert (batch["with_values"], batch["to_confirm"]) == (1, 1)
    assert "confirm their current values" in batch["text"]


@needs_db
def test_the_table_stays_narrow_enough_to_survive_a_mail_client(estate):
    """One sixty-four-character value must not widen every row: a table that
    wraps is one SAP retypes."""
    from server import servicerequest

    _finding(estate, "PARAM-K", PARAM)
    _finding(estate, "PARAM-L", {
        "parameter": "login/password_hash_algorithm",
        "current_value": "encoding=RFC2307, algorithm=iSSHA-1, iterations=1024, saltsize=96",
        "ecs_standard": "encoding=RFC2307, algorithm=iSSHA-512, iterations=15000, saltsize=256"})
    text = servicerequest.draft_for_system(estate["system"])["text"]
    assert max(len(line) for line in text.splitlines()) <= 100
    # and the long one is still fully present, on its own lines
    assert "iSSHA-512" in text


@needs_db
def test_a_system_with_nothing_for_sap_produces_no_request(estate):
    from server import servicerequest

    _finding(estate, "PARAM-M", PARAM, owner="customer_fixable")
    assert servicerequest.draft_for_system(estate["system"]) is None


@needs_db
def test_the_contract_named_is_the_one_the_landscape_runs(estate):
    """A request citing the wrong contract is rejected before the parameter
    name is read."""
    from server import db, servicerequest

    fid = _finding(estate, "PARAM-N", PARAM)
    assert "Private Cloud Edition" in servicerequest.draft(fid)["text"]

    db.execute("UPDATE landscape SET deployment_mode = 'rise_ecc' WHERE id = %s",
               (estate["landscape"],))
    assert "Enterprise Cloud Services" in servicerequest.draft(fid)["text"]
