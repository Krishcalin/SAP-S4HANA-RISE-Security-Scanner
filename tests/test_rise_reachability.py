# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""Five reachability states, and the bucket each one sends an absent source to.

WHAT WAS WRONG. The coverage manifest had two states — reachable and the five
OS-level sources — so an absent source was either the customer's fault or nobody's.
`docs/RISE_SECURITY_MODEL.md` section 3 had already classified the upload surface
in five states, and eleven sources it calls SAP-operated were being counted against
the customer: the HANA configuration views, the ICM/SNC parameters, the crypto
library.

WHAT THESE TESTS ARE FOR. Not that a lookup returns a string. They pin the places
where a wrong bucket makes a false accusation — telling a RISE customer they failed
to export what SAP operates, or telling them to stop asking for data they could get
with a ticket — and the guards that keep the table from drifting away from the
loader it describes.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import rise_reachability as reach          # noqa: E402
from modules.coverage import (                          # noqa: E402
    RISE_UNREACHABLE_SOURCES, all_logical_sources, build_manifest)

RISE = "rise_pce"


# ═════════════════════════════════════════════════════════════════════════════
#  The middle state — the one that did not exist before
# ═════════════════════════════════════════════════════════════════════════════

def test_a_sap_operated_source_is_not_counted_against_the_customer():
    """THE DEFECT THIS CLOSES. `hana_parameters` is SAP-operated under RISE. It
    was landing in `missing`, which in a coverage manifest reads "you did not send
    this" — a false accusation against every RISE customer, on SAP's own
    contractual split."""
    m = build_manifest({}, modules_run=[], deployment_mode=RISE)
    assert "hana_parameters" in m["needs_sap_action"]
    assert "hana_parameters" not in m["missing"]


def test_needs_sap_action_is_neither_missing_nor_unreachable():
    """With two buckets it had to be filed as one of them, and both readings cost
    something: missing blames the customer for SAP's queue, unreachable tells them
    to stop asking for data a ticket would produce."""
    m = build_manifest({}, modules_run=[], deployment_mode=RISE)
    assert m["needs_sap_action"]
    assert not (set(m["needs_sap_action"]) & set(m["missing"]))
    assert not (set(m["needs_sap_action"]) & set(m["unreachable_in_rise"]))


def test_the_three_buckets_partition_the_absent_sources():
    """Every absent source lands in exactly one bucket. A source in none of them
    has vanished from the manifest, which is worse than being in the wrong one."""
    m = build_manifest({}, modules_run=[], deployment_mode=RISE)
    absent = set(all_logical_sources())
    got = (set(m["missing"]) | set(m["needs_sap_action"])
           | set(m["unreachable_in_rise"]))
    assert got == absent
    assert len(m["missing"]) + len(m["needs_sap_action"]) \
        + len(m["unreachable_in_rise"]) == len(absent)


def test_the_operator_sentence_separates_the_two_non_customer_buckets():
    """One sentence for "impossible" and one for "ask SAP". Folding them together
    would make a ticketable source read as a dead end."""
    m = build_manifest({}, modules_run=[], deployment_mode=RISE)
    assert "OS access" in m["summary"]
    assert "service request" in m["summary"]


# ═════════════════════════════════════════════════════════════════════════════
#  Which state means what
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("state,bucket", [
    ("yes", "missing"), ("read_only", "missing"), ("partial", "missing"),
    ("ticket", "needs_sap_action"), ("no", "unreachable"),
])
def test_every_state_has_a_bucket(state, bucket):
    """All five states map. An unmapped one would raise at manifest time, on a
    customer's upload."""
    src = next(iter(reach.sources_in_state(state)))
    assert reach.bucket_of(src, RISE) == bucket


def test_a_read_only_source_is_still_the_customers_to_export():
    """`security_params` is exportable via RSPARAM and unfixable without SAP. The
    two facts belong to different columns: absence is theirs, the FINDING is not.
    Filing it as needs_sap_action would excuse an upload they can produce today."""
    assert reach.state_of("security_params", RISE) == "read_only"
    assert reach.bucket_of("security_params", RISE) == "missing"


def test_a_partial_source_is_obtainable_and_therefore_missing_when_absent():
    """`standard_users` is cross-client and a customer may only evidence
    productive clients — but a partial export is still an export they did not
    send."""
    assert reach.state_of("standard_users", RISE) == "partial"
    assert reach.bucket_of("standard_users", RISE) == "missing"


def test_outside_rise_nothing_is_out_of_reach():
    """On premise the customer owns every layer. Consulting the table there would
    import RISE's constraints into an estate that does not have them."""
    assert reach.state_of("hana_parameters", "on_prem") == "yes"
    m = build_manifest({}, modules_run=[], deployment_mode="on_prem")
    assert not m["needs_sap_action"]
    assert not m["unreachable_in_rise"]
    assert len(m["missing"]) == len(all_logical_sources())


# ═════════════════════════════════════════════════════════════════════════════
#  Guards — a table that drifts from the loader is worse than none
# ═════════════════════════════════════════════════════════════════════════════

def test_no_row_names_a_source_the_loader_does_not_know():
    """A typo'd key is invisible: it classifies nothing and the real source keeps
    the default. Silence is the whole failure mode."""
    stray = sorted(set(reach.load()) - set(all_logical_sources()))
    assert stray == [], f"rows naming unknown sources: {stray}"


def test_the_original_five_are_still_unreachable():
    """The literal in coverage.py is now the fallback; the table is the authority.
    If they ever disagree, the fallback is a lie about what the product does."""
    assert reach.sources_in_state("no") == RISE_UNREACHABLE_SOURCES


def test_the_table_is_complete():
    """It was not: 41 of 132 sources rode `DEFAULT_STATE`, which is a fine default
    and a bad secret. Every logical source the loader knows now carries a row.

    The default and its count both stay — the next source added will ride it until
    somebody writes its row, and the count is what makes that visible rather than
    silent. That is what the test below proves still works."""
    assert reach.unclassified(all_logical_sources()) == []


def test_the_count_riding_on_the_default_is_still_reported():
    """The mechanism outlives the completeness. A source the loader knows and the
    table does not must still surface, or finishing the table today quietly
    removes the guard that keeps it finished tomorrow."""
    known = list(all_logical_sources()) + ["a_source_nobody_classified_yet"]
    assert reach.unclassified(known) == ["a_source_nobody_classified_yet"]
    m = build_manifest({}, modules_run=[], deployment_mode=RISE)
    assert m["counts"]["sources_unclassified_for_rise"] == 0


def test_every_row_says_where_its_classification_came_from():
    """Transcribed from section 3, or inferred from the R&R principle, are
    different strengths of claim. 94 rows are transcription; the rest are
    inference and the table says which."""
    import json
    payload = json.loads(
        (ROOT / "data" / "rise_reachability.json").read_text(encoding="utf-8"))
    vocabulary = set(payload["_meta"]["basis"]) | {"section_3"}
    for key, row in reach.load().items():
        assert row.get("basis") in vocabulary, key


def test_a_governance_record_is_not_presented_as_an_sap_export():
    """Fourteen sources are records the customer maintains rather than anything
    RISE does or does not permit. Absent means the record does not exist, which
    is a different finding from a missing export, and the row says so."""
    gov = [k for k, v in reach.load().items()
           if v.get("basis") == "governance_artefact"]
    assert len(gov) > 10
    for key in gov:
        assert "NOT AN SAP EXPORT" in reach.detail(key)["note"], key


def test_every_unverified_row_names_what_would_settle_it():
    """`verified: false` on its own is a shrug. What makes it actionable is the
    question and where the answer comes from — four of these need a design-partner
    tenant, one needs a customer who runs their own Web Dispatcher, and knowing
    which is the difference between a blocked item and a forgotten one."""
    unverified = reach.unverified()
    assert unverified, "if nothing is unverified, delete this test rather than it passing vacuously"
    for key in unverified:
        question = reach.detail(key).get("open_question", "")
        assert len(question) > 60, key


def test_an_inferred_infrastructure_row_admits_it_is_inferred():
    """The rows classified from the principle rather than from a transcribed row
    are the ones most likely to be wrong, so they carry the open question."""
    for key, row in reach.load().items():
        if row.get("basis") == "infrastructure" and row["state"] == "ticket":
            assert row.get("verified") is False, key


def test_unverified_rows_are_named_rather_than_presented_as_settled():
    """Section 8 gates the HANA rows on a design-partner tenant. They are
    classified `ticket` rather than `no` precisely because "ask SAP" is true under
    either answer, while `no` asserts what section 8 says we cannot yet claim."""
    unverified = reach.unverified()
    assert "hana_parameters" in unverified
    assert reach.state_of("hana_parameters", RISE) == "ticket"
    assert reach.detail("hana_parameters").get("open_question")


def test_every_row_says_how_the_customer_would_produce_it():
    """A status with no procedure is a status nobody can act on. The report shows
    this text to the customer."""
    for key, row in reach.load().items():
        assert row.get("how"), key


def test_a_row_the_customer_cannot_self_serve_says_what_blocks_them():
    for state in ("read_only", "ticket", "no"):
        for key in reach.sources_in_state(state):
            assert reach.detail(key).get("blocked_by"), key


def test_a_derived_or_inherited_grouping_cites_what_licensed_it():
    """Section 3 rows sometimes cover several loader keys, and splitting one is a
    judgement. Each split carries the sentence that permits it, so the next reader
    can check the split rather than trust it."""
    for key, row in reach.load().items():
        if row.get("grouping"):
            assert row.get("licence"), key
            assert len(row["licence"]) > 40, key


def test_an_unreadable_table_degrades_to_the_previous_behaviour():
    """Not to "nothing is unreachable", which would be strictly worse than both
    the old code and the new. The fallback keeps the five OS sources out of the
    customer's column."""
    assert reach.load(ROOT / "data" / "does-not-exist.json") is not None


def test_the_detail_of_an_unlisted_source_is_empty_not_reassuring():
    """`{}` must never render as "nothing blocks this"."""
    assert reach.detail("no_such_source_at_all") == {}


def test_the_content_file_carries_its_own_reasoning():
    """The states, the triage rule, the default and its justification live with
    the data. A classification table whose reasoning is only in code is one nobody
    can audit against SAP's contract."""
    payload = json.loads(
        (ROOT / "data" / "rise_reachability.json").read_text(encoding="utf-8"))
    meta = payload["_meta"]
    assert set(meta["states"]) == set(reach.STATES)
    for field in ("how_absence_is_triaged", "the_default_for_an_unlisted_source",
                  "provenance", "open_questions", "on_premise"):
        assert meta.get(field), field
