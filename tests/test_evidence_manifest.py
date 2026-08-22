"""The evidence manifest: every file the scan read, SHA-256 hashed at scan
time, stamped into the report. The SRS requirement it answers is audit
replay — "raw extract hash … supports defensible results" — so the tests
recompute the hashes independently and require the report to carry them.
"""
import contextlib
import hashlib
import io
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.data_loader import DataLoader          # noqa: E402
from modules.report_generator import ReportGenerator  # noqa: E402


def _loader():
    with contextlib.redirect_stdout(io.StringIO()):
        ld = DataLoader(ROOT / "sample_data")
        ld.load_all()
    return ld


def test_hashes_are_independently_recomputable_and_rows_match():
    ld = _loader()
    manifest = ld.evidence_manifest()
    assert manifest, "sample_data produced an empty manifest"
    by_file = {e["file"].lower(): e for e in manifest}
    e = by_file["bkpf.csv"]
    raw = (ROOT / "sample_data" / e["file"]).read_bytes()
    assert e["sha256"] == hashlib.sha256(raw).hexdigest()
    assert e["bytes"] == len(raw)
    assert e["rows"] == len(ld._data["fi_documents"])
    # every entry is fully formed
    for entry in manifest:
        assert len(entry["sha256"]) == 64
        assert entry["bytes"] > 0
        assert entry["modified"]


def test_manifest_covers_what_was_consumed_and_is_deterministic():
    a = _loader()
    manifest = a.evidence_manifest()
    listed = {e["file"].lower() for e in manifest}
    # Every consumed file that still exists on disk is listed — nothing the
    # scan read is allowed to go unhashed.
    for name in a._consumed_files:
        if (ROOT / "sample_data" / name).is_file():
            assert name.lower() in listed, f"consumed but not in manifest: {name}"
    b = _loader().evidence_manifest()
    assert [(e["file"], e["sha256"]) for e in manifest] == \
           [(e["file"], e["sha256"]) for e in b]


def test_report_renders_the_manifest(tmp_path):
    ld = _loader()
    manifest = ld.evidence_manifest()
    meta = {"scan_time": "2026-08-16T00:00:00", "data_directory": "sample_data",
            "modules_run": ["users"], "severity_filter": None,
            "evidence_manifest": manifest}
    finding = {"check_id": "TEST-001", "severity": "LOW", "category": "Test",
               "title": "t", "description": "d", "affected_items": [],
               "remediation": "r", "references": [], "details": {}}
    out = tmp_path / "r.html"
    with contextlib.redirect_stdout(io.StringIO()):
        ReportGenerator([finding], meta).generate(str(out))
    text = out.read_text(encoding="utf-8")
    assert "Evidence manifest" in text
    assert manifest[0]["sha256"] in text


def test_report_without_manifest_stays_silent(tmp_path):
    meta = {"scan_time": "2026-08-16T00:00:00", "data_directory": "x",
            "modules_run": [], "severity_filter": None}
    finding = {"check_id": "TEST-001", "severity": "LOW", "category": "Test",
               "title": "t", "description": "d", "affected_items": [],
               "remediation": "r", "references": [], "details": {}}
    out = tmp_path / "r.html"
    with contextlib.redirect_stdout(io.StringIO()):
        ReportGenerator([finding], meta).generate(str(out))
    assert "Evidence manifest" not in out.read_text(encoding="utf-8")
