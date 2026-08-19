# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""PDF and PPTX built from the store, not from one scan's in-memory list.

WHAT THIS ADDS, AND WHAT IT DOES NOT FIX. The roadmap files this as "PDF/PPTX
export driven from SQL rather than an in-memory list", and I expected to find a
correctness bug — a display filter silently narrowing an export. It is not there:
`PDFReportGenerator` and `PPTXReportGenerator` both already take `full_findings`,
the corpus as scanned, precisely so an estate-level claim never reads the
filtered set. The offline path was already right.

The real gap was simpler and larger: THE SERVER COULD NOT EXPORT AT ALL. A PDF
existed only if somebody re-ran the offline scanner over a directory of files, so
the artefact a customer forwards to an auditor could not include anything the
store knows.

WHAT THE STORE KNOWS THAT A SCAN DOES NOT. State, assignee, due date, the
provider ticket a finding was raised under, how many times it regressed, and when
it was first seen. A scan describes a moment; the store describes the managed
estate over time, and that is the whole reason to export from it.

THE ONE HONEST DIFFERENCE, WHICH IS RECORDED RATHER THAN PAPERED OVER. A scan's
findings carry `affected_items` — prose strings composed by the module that found
them. The store does not keep those: it keeps `subject`, the TYPED objects, which
is the identity basis this product deliberately moved to when prose proved unable
to tell two findings apart. So an export from SQL lists the objects, rendered from
their type and name, where the offline export lists the module's sentence. They
describe the same finding and they do not read identically, and pretending
otherwise would be the quiet kind of wrong.

SCOPE IS NOT OPTIONAL AND PAGINATION IS NOT APPLIED. `list_findings` returns one
page because a console screen shows one page; a report that exported page 1 would
be an auditable-looking document covering the first fifty findings. This reads the
whole scoped corpus in one query and says so.
"""
from __future__ import annotations

import datetime as _dt
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from server import db, queries
from server.queries import _scoped

#: Formats and the generator each one uses. Adding a third means adding a
#: generator, not a branch here.
FORMATS = ("pdf", "pptx")

MEDIA_TYPES = {
    "pdf": "application/pdf",
    "pptx": ("application/vnd.openxmlformats-officedocument."
             "presentationml.presentation"),
}

#: States that are not part of the current picture. `resolved` and
#: `false_positive` are history — an export that listed them would report closed
#: work as outstanding, which is the one mistake an auditor notices immediately.
CLOSED_STATES = ("resolved", "false_positive")


def _items_from_subject(subject: Any) -> List[str]:
    """The typed objects, rendered for a human.

    `user:ADMIN1@PRD` reads as "user ADMIN1 (PRD)". The store keeps the objects
    rather than the module's prose, so this is a rendering rather than a
    recovery — see the module docstring.
    """
    out: List[str] = []
    for obj in (subject or ()):
        if not isinstance(obj, dict):
            continue
        name = str(obj.get("name") or "").strip()
        if not name:
            continue
        kind = str(obj.get("type") or "object").replace("_", " ")
        system = str(obj.get("system") or "").strip()
        client = str(obj.get("client") or "").strip()
        where = "/".join(p for p in (system, client) if p)
        out.append(f"{kind} {name}" + (f" ({where})" if where else ""))
    return out


def findings_for_report(scope: Optional[Sequence[int]]) -> List[Dict[str, Any]]:
    """Every finding in scope that is still part of the picture, unpaginated.

    ONE QUERY, NO PAGE. `queries.list_findings` pages because a screen does; an
    export that inherited that would produce an auditable-looking document
    covering the first fifty findings and nothing would say so.
    """
    where: List[str] = ["f.state NOT IN (%s, %s)"]
    params: List[Any] = list(CLOSED_STATES)
    _scoped(where, params, scope)
    rows = db.query(
        "SELECT f.id, f.check_id, f.severity, f.state, f.subject, "
        "       f.priority_tier, f.remediation_owner, f.assignee, f.due_date, "
        "       f.provider_ticket_ref, f.regression_count, f.first_seen_at, "
        "       cd.title, cd.category, cd.remediation, cd.risk_narrative, "
        "       cd.references_json, s.sid, s.client AS system_client "
        "FROM finding f "
        "JOIN check_definition cd ON cd.check_id = f.check_id "
        "LEFT JOIN sap_system s ON s.id = f.system_id "
        f"WHERE {' AND '.join(where)} "
        "ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 "
        "         WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, f.check_id",
        params)

    findings: List[Dict[str, Any]] = []
    for row in rows:
        record = dict(row)
        items = _items_from_subject(record.get("subject"))
        findings.append({
            "check_id": record.get("check_id"),
            "title": record.get("title") or record.get("check_id"),
            "severity": record.get("severity"),
            "category": record.get("category"),
            "description": record.get("risk_narrative") or "",
            "remediation": record.get("remediation") or "",
            "references": record.get("references_json") or [],
            "affected_items": items,
            "affected_count": len(items),
            # WHAT THE STORE KNOWS AND A SCAN DOES NOT. These travel so the
            # export can be about the managed estate rather than a moment.
            "state": record.get("state"),
            "assignee": record.get("assignee"),
            "due_date": record.get("due_date"),
            "provider_ticket_ref": record.get("provider_ticket_ref"),
            "regression_count": record.get("regression_count"),
            "first_seen_at": record.get("first_seen_at"),
            "remediation_owner": record.get("remediation_owner"),
            "priority_tier": record.get("priority_tier"),
        })
    return findings


def meta_for(scope: Optional[Sequence[int]], count: int) -> Dict[str, Any]:
    """What the document says about itself.

    A report that does not state its own scope invites the reader to assume it
    covers everything, and a scoped export that looks unscoped is worse than no
    export.
    """
    systems = queries.list_systems(scope)
    return {
        "scan_time": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "data_directory": "the finding store",
        "modules_run": [],
        "severity_filter": "ALL",
        "source": "store",
        "systems": len(systems),
        "scope": "the whole estate" if scope is None else f"{len(scope)} system(s)",
        "note": (
            "Built from the finding store rather than from one scan, so it "
            "carries state, assignment, due dates and regression counts that a "
            "single scan does not have. Affected objects are rendered from the "
            "stored typed objects rather than from the scanning module's prose; "
            "they describe the same finding and do not read identically. "
            "Resolved and false-positive findings are excluded — they are "
            "history, and listing them would report closed work as outstanding."),
    }


def build(scope: Optional[Sequence[int]], fmt: str) -> bytes:
    """Render the report and return its bytes.

    Generators write to a path rather than returning bytes — they are the offline
    product's and that is the right shape there — so this writes to a temporary
    file and reads it back rather than changing a contract the CLI depends on.
    """
    if fmt not in FORMATS:
        raise ValueError(f"unsupported format: {fmt}")

    from modules.finding_kb import FindingKB

    findings = findings_for_report(scope)
    meta = meta_for(scope, len(findings))
    kb = FindingKB()

    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / f"report.{fmt}"
        if fmt == "pdf":
            from modules.pdf_report import PDFReportGenerator
            # `full_findings` is the same list: nothing narrowed it, and passing
            # it explicitly keeps the estate-level claims reading the corpus even
            # if a filter is ever added above.
            PDFReportGenerator(findings, meta, kb,
                               full_findings=findings).generate(str(out))
        else:
            from modules.pptx_report import PPTXReportGenerator
            PPTXReportGenerator(findings, meta, kb,
                                full_findings=findings).generate(str(out))
        return out.read_bytes()
