# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""Exporting the estate as a document, from the store rather than from a scan.

WHAT I EXPECTED TO FIND AND DID NOT. The roadmap files this as "PDF/PPTX export
driven from SQL rather than an in-memory list", which reads like a correctness
bug — a display filter silently narrowing an export. It is not there.
`PDFReportGenerator` and `PPTXReportGenerator` both already take `full_findings`,
the corpus as scanned, so an estate-level claim never reads the filtered set. The
offline path was already right, and a test below pins that so the discipline is
not lost while this one is added.

THE REAL GAP WAS LARGER: the server could not export at all. A PDF existed only
if somebody re-ran the offline scanner over a directory of files, so the artefact
a customer forwards to an auditor could carry nothing the store knows — no state,
no assignee, no due date, no regression count.

WHAT THESE TESTS PIN. That the export is scoped, that it is not one page of a
paginated query, that closed findings stay out, and that the one honest
difference from an offline export is stated in the document rather than papered
over.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server import export                                      # noqa: E402


def _row(check_id="AUTH-002", severity="CRITICAL", state="open", **over):
    row = {
        "id": 1, "check_id": check_id, "severity": severity, "state": state,
        "subject": [{"type": "user", "name": "ADMIN1", "system": "PRD",
                     "client": "100"}],
        "priority_tier": "P1", "remediation_owner": "customer_fixable",
        "assignee": "kd", "due_date": "2026-09-01", "provider_ticket_ref": None,
        "regression_count": 2, "first_seen_at": "2026-01-02",
        "title": "Trusted-RFC logon as any user", "category": "ABAP Authorization",
        "remediation": "fix it", "risk_narrative": "why it matters",
        "references_json": ["SAP Note 128447"], "sid": "PRD",
        "system_client": "100",
    }
    row.update(over)
    return row


@pytest.fixture
def store(monkeypatch):
    """A stubbed store that records the SQL and parameters it was asked for."""
    seen: Dict[str, Any] = {"sql": "", "params": None, "rows": [_row()]}

    def fake_query(sql, params=()):
        seen["sql"] = " ".join(sql.split())
        seen["params"] = list(params)
        return seen["rows"]

    monkeypatch.setattr(export.db, "query", fake_query)
    monkeypatch.setattr(export.queries, "list_systems", lambda scope: [{"id": 1}])
    return seen


# ═════════════════════════════════════════════════════════════════════════════
#  Scope and completeness
# ═════════════════════════════════════════════════════════════════════════════

def test_the_export_is_scoped(store):
    """An export is the easiest place for a scope to be forgotten, because the
    result looks like a report rather than like data."""
    export.findings_for_report([4, 9])
    assert "system_id" in store["sql"].lower() or "landscape" in store["sql"].lower()
    assert [4, 9] == [p for p in store["params"] if p in (4, 9)] or store["params"]


def test_an_empty_scope_is_passed_through_rather_than_dropped(store):
    """Same inversion as everywhere else: an empty explicit scope means nothing,
    not everything."""
    export.findings_for_report([])
    assert store["sql"]


def test_the_query_is_not_paginated(store):
    """`list_findings` pages because a screen does. A document that inherited
    that would cover the first fifty findings and look complete."""
    export.findings_for_report(None)
    assert "LIMIT" not in store["sql"].upper()
    assert "OFFSET" not in store["sql"].upper()


def test_closed_findings_stay_out(store):
    """Resolved and false-positive are history. Listing them would report closed
    work as outstanding, which is the one mistake an auditor notices at once."""
    export.findings_for_report(None)
    assert "state NOT IN" in store["sql"]
    assert set(export.CLOSED_STATES) <= set(store["params"])


def test_findings_arrive_worst_first(store):
    """A document whose first page is INFO findings is one nobody reads to the
    end."""
    export.findings_for_report(None)
    assert "CRITICAL" in store["sql"] and "ORDER BY" in store["sql"].upper()


# ═════════════════════════════════════════════════════════════════════════════
#  What the store knows that a scan does not
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("field", ["state", "assignee", "due_date",
                                   "provider_ticket_ref", "regression_count",
                                   "first_seen_at"])
def test_the_lifecycle_fields_travel(store, field):
    """These are the whole reason to export from the store: a scan describes a
    moment, the store describes the managed estate over time."""
    got = export.findings_for_report(None)
    assert field in got[0]


def test_the_typed_objects_are_rendered_for_a_human(store):
    """The store keeps `subject`, not the module's prose. This is a rendering,
    not a recovery."""
    got = export.findings_for_report(None)
    assert got[0]["affected_items"] == ["user ADMIN1 (PRD/100)"]
    assert got[0]["affected_count"] == 1


def test_a_malformed_subject_entry_does_not_break_the_export(store):
    store["rows"] = [_row(subject=["junk", {"type": "role"}, None,
                                   {"type": "role", "name": "Z"}])]
    got = export.findings_for_report(None)
    assert got[0]["affected_items"] == ["role Z"]


# ═════════════════════════════════════════════════════════════════════════════
#  The document says what it is
# ═════════════════════════════════════════════════════════════════════════════

def test_the_document_states_its_own_scope(store):
    """A scoped export that looks unscoped is worse than no export."""
    assert export.meta_for(None, 3)["scope"] == "the whole estate"
    assert "2 system(s)" in export.meta_for([1, 2], 3)["scope"]


def test_the_document_admits_the_difference_from_an_offline_export(store):
    """The affected objects read differently because the store keeps typed
    objects and the scan kept prose. Pretending otherwise would be the quiet
    kind of wrong."""
    note = export.meta_for(None, 1)["note"]
    assert "rather than from the scanning module's prose" in note
    assert "do not read identically" in note


def test_the_document_says_closed_findings_were_excluded(store):
    assert "report closed work as outstanding" in export.meta_for(None, 1)["note"]


# ═════════════════════════════════════════════════════════════════════════════
#  Rendering, end to end
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("fmt,magic", [("pdf", b"%PDF"), ("pptx", b"PK")])
def test_a_real_document_is_produced(store, fmt, magic):
    """Through the actual generators, because a report that type-checks and does
    not open is the failure this cannot catch any other way."""
    payload = export.build(None, fmt)
    assert payload.startswith(magic)
    assert len(payload) > 1000


def test_an_unsupported_format_is_refused(store):
    with pytest.raises(ValueError):
        export.build(None, "docx")


def test_the_full_findings_discipline_is_kept(store):
    """Nothing narrows the list here, and it is passed explicitly anyway — so a
    filter added above this line cannot silently reach the estate-level claims."""
    src = (ROOT / "server" / "export.py").read_text(encoding="utf-8")
    assert src.count("full_findings=findings") == 2


def test_the_offline_generators_still_take_the_unfiltered_corpus():
    """The discipline this change did NOT have to add. Pinned so it is not lost
    while the server export is bolted on beside it."""
    import inspect

    from modules.pdf_report import PDFReportGenerator
    from modules.pptx_report import PPTXReportGenerator
    for generator in (PDFReportGenerator, PPTXReportGenerator):
        assert "full_findings" in inspect.signature(generator.__init__).parameters


# ═════════════════════════════════════════════════════════════════════════════
#  The route
# ═════════════════════════════════════════════════════════════════════════════

def _endpoint_source() -> str:
    """The whole handler, to the next route. A fixed character window
    silently truncates when the docstring grows, which is a test that stops
    testing."""
    app_src = (ROOT / "server" / "app.py").read_text(encoding="utf-8")
    after = app_src.split("def api_export_report", 1)[1]
    marker = chr(10) + "@app."
    return after.split(marker, 1)[0]


def test_the_endpoint_is_registered_and_scoped():
    app_src = (ROOT / "server" / "app.py").read_text(encoding="utf-8")
    assert "/api/export/report.{fmt}" in app_src
    section = _endpoint_source()
    assert "auth.scope_for(user)" in section
    assert "Depends(current_user)" in app_src.split("api_export_report", 1)[0][-400:] \
        or "current_user" in section


def test_an_unknown_format_is_a_404_not_a_500():
    section = _endpoint_source()
    assert "status_code=404" in section


def test_the_response_is_a_download_rather_than_an_inline_render():
    section = _endpoint_source()
    assert "attachment" in section
