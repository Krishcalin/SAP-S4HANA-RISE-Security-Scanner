"""The per-control evidence pack: the ComplianceEvidence screen as a document.

modules/evidence_pack.py renders control_status.assess_framework + drift into one
self-contained HTML file an auditor keeps. What must hold: it renders the real
shape those functions return (not a drifted copy), it makes the SAME honest
promises the screen does (clear is not a certification, not-tested stays distinct,
NO percentage), it escapes finding text, it is self-contained (no external fetch),
and build_evidence_pack reuses the scoped store reads and refuses an unknown
framework with None so the route can answer 404.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import control_status as cs      # noqa: E402
from modules import evidence_pack              # noqa: E402
from server import export                      # noqa: E402

# An AUTH finding maps (via the access-control themes) onto SOX/ITGC's "Access to
# Programs and Data" (APD) control — the same fixture control_status is tested with.
_AUTH_GAP = {"id": 1, "check_id": "AUTH-015",
             "category": "ABAP Authorization & Critical Access", "severity": "HIGH",
             "title": "SAP_ALL assigned to a dialog user", "sid": "PRD",
             "state": "open", "priority_tier": "P2",
             "affected_items": ["user ADMIN1 (PRD/100)"]}

_META = {"generated": "2026-10-03T00:00:00+00:00", "scope": "the whole estate"}


def _pack(findings, now_cov, before_findings=None, before_cov=None, framework="soxitgc"):
    """assess + drift + render, the way build_evidence_pack wires them."""
    assessed = cs.assess_framework(framework, findings, coverage=now_cov)
    drift = cs.drift(framework, findings, now_cov, before_findings, before_cov)
    return evidence_pack.render(assessed, drift, _META)


# ═════════════════════════════════════════════════════════════════════════════
#  It is a document, and it renders the real data shape
# ═════════════════════════════════════════════════════════════════════════════

def test_it_is_a_self_contained_html_document():
    doc = _pack([_AUTH_GAP], {"modules": {}})
    assert doc.startswith("<!DOCTYPE html>") and "</html>" in doc
    # Self-contained: no external stylesheet, script or font fetch — the pack must
    # open identically offline / air-gapped, the whole point of this product.
    low = doc.lower()
    assert "<script" not in low
    assert "googleapis" not in low and "cdnjs" not in low
    assert "http://" not in low and "https://" not in low


def test_a_gap_control_shows_the_finding_that_proves_it():
    doc = _pack([_AUTH_GAP], {"modules": {}})
    assert "APD" in doc                       # the control id
    assert "AUTH-015" in doc                  # the check that fired
    assert "SAP_ALL assigned to a dialog user" in doc
    assert "user ADMIN1 (PRD/100)" in doc     # the affected object
    assert "Gap" in doc


def test_the_framework_name_titles_the_document():
    assessed = cs.assess_framework("soxitgc", [_AUTH_GAP], coverage={"modules": {}})
    doc = evidence_pack.render(assessed, None, _META)
    assert assessed["name"] in doc


# ═════════════════════════════════════════════════════════════════════════════
#  The same honest promises the screen makes
# ═════════════════════════════════════════════════════════════════════════════

def test_clear_is_not_a_certification_and_not_tested_is_distinct():
    # coverage says nothing ran, so the quiet controls are NOT_TESTED, not clear.
    doc = _pack([_AUTH_GAP], {"modules": {}})
    assert "Clear is not a certification" in doc
    assert "Not tested" in doc
    assert "not run" in doc            # the not-tested explanation


def test_no_percentage_value_is_ever_rendered():
    # The honesty banner SAYS "No percentage is computed" (the promise); what must
    # never appear is an actual percentage VALUE — an NN% figure that a reader
    # takes for a compliance score. So the percent SIGN is what is forbidden.
    doc = _pack([_AUTH_GAP], {"modules": {}})
    assert "%" not in doc
    # Collapsed the way a browser renders it — the promise wraps across a newline
    # in the source.
    assert "No percentage is computed" in " ".join(doc.split())


def test_finding_text_is_escaped():
    evil = dict(_AUTH_GAP, title="<b>pwn</b>", affected_items=["<i>PRD</i>"])
    doc = _pack([evil], {"modules": {}})
    assert "<b>pwn</b>" not in doc and "&lt;b&gt;pwn&lt;/b&gt;" in doc
    assert "<i>PRD</i>" not in doc and "&lt;i&gt;PRD&lt;/i&gt;" in doc


# ═════════════════════════════════════════════════════════════════════════════
#  Drift, rendered honestly
# ═════════════════════════════════════════════════════════════════════════════

def test_drift_summary_names_the_change_since_the_previous_scan():
    # before: no gap; now: APD gains the gap -> newly failing.
    doc = _pack([_AUTH_GAP], {"modules": {}}, before_findings=[], before_cov={"modules": {}})
    assert "Since the previous scan:" in doc
    assert "newly failing" in doc


def test_with_no_previous_scan_the_document_says_no_baseline():
    doc = _pack([_AUTH_GAP], {"modules": {}}, before_findings=None)
    assert "No previous complete scan to compare against yet" in doc
    assert "Since the previous scan:" not in doc


def test_render_tolerates_missing_drift():
    assessed = cs.assess_framework("soxitgc", [_AUTH_GAP], coverage={"modules": {}})
    doc = evidence_pack.render(assessed, None, _META)
    assert doc.startswith("<!DOCTYPE html>")
    assert "Since the previous scan:" not in doc


# ═════════════════════════════════════════════════════════════════════════════
#  build_evidence_pack — the scoped store read behind the route
# ═════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def stub(monkeypatch):
    """The three store reads build_evidence_pack makes, stubbed and recorded."""
    seen: Dict[str, Any] = {"scope": "unset"}

    def fake_findings(scope):
        seen["scope"] = scope
        return [dict(_AUTH_GAP)]

    monkeypatch.setattr(export, "findings_for_report", fake_findings)
    monkeypatch.setattr(export.queries, "latest_coverage", lambda scope: {"modules": {}})
    monkeypatch.setattr(export.queries, "previous_scan", lambda scope: (None, None))
    monkeypatch.setattr(export.queries, "list_systems", lambda scope: [{"id": 1}])
    return seen


def test_build_evidence_pack_returns_html_bytes(stub):
    payload = export.build_evidence_pack(None, "soxitgc")
    assert isinstance(payload, bytes)
    assert payload.startswith(b"<!DOCTYPE html>")
    assert b"AUTH-015" in payload              # the evidence rode through


def test_build_evidence_pack_is_scoped(stub):
    export.build_evidence_pack([4, 9], "soxitgc")
    assert stub["scope"] == [4, 9]


def test_build_evidence_pack_refuses_an_unknown_framework(stub):
    # None, so the route answers 404 rather than shipping an empty document.
    assert export.build_evidence_pack(None, "not-a-framework") is None


# ═════════════════════════════════════════════════════════════════════════════
#  The route
# ═════════════════════════════════════════════════════════════════════════════

def _endpoint_source() -> str:
    app_src = (ROOT / "server" / "app.py").read_text(encoding="utf-8")
    after = app_src.split("def api_compliance_evidence_pack", 1)[1]
    return after.split(chr(10) + "@app.", 1)[0]


def test_the_endpoint_is_registered_scoped_and_a_download():
    app_src = (ROOT / "server" / "app.py").read_text(encoding="utf-8")
    assert "/api/compliance/{framework}/evidence-pack.html" in app_src
    section = _endpoint_source()
    assert "auth.scope_for(user)" in section
    assert "attachment" in section
    assert "text/html" in section or "EVIDENCE_PACK_MEDIA_TYPE" in section


def test_an_unknown_framework_is_a_404_not_an_empty_document():
    section = _endpoint_source()
    assert "status_code=404" in section
