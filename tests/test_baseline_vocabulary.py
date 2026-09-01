"""Findings speak SAP's control vocabulary, not only the check page.

THE DEFECT. `check_definition.baseline_req_id` carries the SAP Security Baseline
requirement a check answers — `PWDPOL-A`, `RFCGW-A`, `CRITAU-A`. The schema
argues for it: "mapping to SAP's own vocabulary is far more defensible in an
audit than a house-brand control name". It has an index. `/api/requirements/{id}`
reads it. `FindingDetail.tsx` renders "SAP Security Baseline …" from it.

Nothing ever wrote it. Measured on the live estate: **0 of 458** catalogue rows
carried one, so that line never rendered — while the same fact was already
correct on the check page, because `server/checkdocs.py` derives it live from
`sapcontent.requirement_for`. One fact, two paths, and the stored path was
empty.

`_upsert_check_definitions` had documented the column as a human judgement a
scan "must never silently overwrite", and nobody had curated it. The fix keeps
that rule intact from the other side: the derivation FILLS A BLANK and never
overwrites, so a curated value survives every future scan.

WHY THE DERIVED MAP IS NOT AN INVENTION. `sapcontent.requirement_for` resolves
in three steps — an exact recorded mapping, then the parameter name for a
`PARAM-<name>` check, then a family prefix — and every one of them is grounded
in SAP's own published policies (`SAP-samples/frun-csa-policies-best-practices`,
Apache-2.0). Nobody types a requirement id.

A NUMBER THIS FILE DELIBERATELY DOES NOT COMPUTE. `server/sapcontent.py` warns
at length that the widely-quoted "214 control points (69/92/53)" is a different
unit from the 351 check items in SAP's CSA policies, that the two do not
reconcile, and that publishing a percentage of one against the other would cost
more than the claim is worth. No test here quotes such a percentage, and one
below asserts the warning is still in the file.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server import sapcontent                                    # noqa: E402


# ── the derivation, which is SAP's and not ours ──────────────────────────────

def test_a_parameter_check_resolves_to_the_requirement_sap_names_it_in():
    """SAP's own baseline titles name profile parameters — "sapgui/user_scripting
    (Profile Parameter…)" — so the mapping for a PARAM- check is read out of
    SAP's text rather than decided here."""
    assert sapcontent.requirement_for("PARAM-sapgui/user_scripting") == "SCRIPT-A"
    assert sapcontent.requirement_for("PARAM-rec/client") == "CHANGE-A"


def test_the_parameter_lookup_is_case_insensitive_on_our_side():
    """Our check ids are upper-cased in the catalogue; SAP writes parameters in
    lower case. A mapping that worked in only one direction would silently drop
    every stored check id."""
    assert (sapcontent.requirement_for("PARAM-REC/CLIENT")
            == sapcontent.requirement_for("PARAM-rec/client"))


def test_a_check_sap_names_nothing_for_maps_to_nothing():
    """None, not a guess. A wrong requirement id in front of an auditor is
    worse than no requirement id."""
    assert sapcontent.requirement_for("PARAM-not/a/real/parameter") is None
    assert sapcontent.requirement_for("") is None


def test_the_unit_warning_is_still_in_the_file():
    """The 214-control-point figure and the 351 check items are different units
    that do not reconcile. This product must never publish a percentage of one
    against the other, and the reasoning has to stay where the next person
    tempted to compute it will read it."""
    source = (ROOT / "server" / "sapcontent.py").read_text(encoding="utf-8")
    assert "do not reconcile" in source
    assert "214" in source


# ── the wiring, which is what was missing ────────────────────────────────────

def test_the_catalogue_upsert_stores_the_requirement():
    source = (ROOT / "server" / "ingest.py").read_text(encoding="utf-8")
    block = source[source.index("def _upsert_check_definitions"):]
    block = block[:block.index("\ndef ", 10)]
    assert "sapcontent.requirement_for(cid)" in block, \
        "the derivation is not applied at ingest, so the column stays empty"
    assert "baseline_req_id  = COALESCE(check_definition.baseline_req_id," in block, \
        "a curated requirement would be overwritten by the derivation"


def test_the_derivation_covers_a_meaningful_slice_of_the_catalogue():
    """Not a percentage against SAP's document — a count of OUR checks that can
    speak SAP's vocabulary. If a refactor drops the mapping this fails loudly
    rather than quietly returning to zero."""
    reference = (ROOT / "docs" / "CHECKS_REFERENCE.md").read_text(encoding="utf-8")
    ids = set()
    for line in reference.splitlines():
        if line.startswith("| `") and "`" in line[3:]:
            ids.add(line[3:].split("`")[0])
    mapped = [c for c in ids if sapcontent.requirement_for(c)]
    assert len(mapped) >= 100, (
        "only %d of %d checks map to an SAP requirement; the derivation has "
        "regressed" % (len(mapped), len(ids)))


# ── against a real database ──────────────────────────────────────────────────

pg = pytest.mark.skipif(not os.getenv("DB_DSN"),
                        reason="set DB_DSN to a PostgreSQL 16 instance")


@pg
def test_a_scan_fills_the_column_and_a_curated_value_survives():
    """Both halves of the rule, in one test: the derivation speaks where there
    is silence, and never over a human."""
    from server import db, ingest

    db.init_schema()
    curated = "ZZTEST-CURATED-%s" % os.urandom(3).hex()
    findings = [
        {"check_id": "PARAM-rec/client", "title": "t", "category": "c",
         "severity": "HIGH", "description": "d", "remediation": "r"},
        # Upper-cased here because `_upsert_check_definitions` upper-cases every
        # check id on the way in; a mixed-case id in the test would query a row
        # that exists under another name.
        {"check_id": ("ZZTEST-HUMAN-%s" % os.urandom(3).hex()).upper(),
         "title": "t", "category": "c", "severity": "HIGH", "description": "d",
         "remediation": "r"},
    ]
    human = findings[1]["check_id"]
    try:
        with db.connection() as conn:
            ingest._upsert_check_definitions(conn, findings)
            # A human curates the second one.
            conn.execute("UPDATE check_definition SET baseline_req_id = %s "
                         "WHERE check_id = %s", (curated, human))
            conn.commit()

        derived = db.one("SELECT baseline_req_id FROM check_definition "
                         "WHERE check_id = %s", ("PARAM-REC/CLIENT",))
        assert derived and derived["baseline_req_id"] == "CHANGE-A", \
            "the derivation did not reach the column"

        # Scan again. The curated value must not move.
        with db.connection() as conn:
            ingest._upsert_check_definitions(conn, findings)
            conn.commit()
        after = db.one("SELECT baseline_req_id FROM check_definition "
                       "WHERE check_id = %s", (human,))
        assert after["baseline_req_id"] == curated, \
            "a scan overwrote a curated requirement id"
    finally:
        db.execute("DELETE FROM check_definition WHERE check_id = %s", (human,))


@pg
def test_the_finding_page_has_something_to_render():
    """The line reads `finding.baseline_req_id`, and it never rendered because
    the column was empty for every row in the catalogue."""
    from server import db, ingest
    db.init_schema()
    with db.connection() as conn:
        ingest._upsert_check_definitions(conn, [
            {"check_id": "PARAM-sapgui/user_scripting", "title": "t",
             "category": "c", "severity": "HIGH", "description": "d",
             "remediation": "r"}])
        conn.commit()
    row = db.one("SELECT baseline_req_id FROM check_definition "
                 "WHERE check_id = %s", ("PARAM-SAPGUI/USER_SCRIPTING",))
    assert row["baseline_req_id"] == "SCRIPT-A"
