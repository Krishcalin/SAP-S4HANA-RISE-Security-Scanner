# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""Every report must say what the scan could not look at.

THE DEFECT
A missing export file loads as None and every check that needs it self-skips
SILENTLY, so a customer who supplied a fraction of the sources received a
clean-looking report with nothing anywhere saying so. modules/coverage.py has said
exactly that in its own docstring since it was written — and the manifest was
wired to the server's ingest path only.

The reason it never reached a report is architectural rather than an oversight:
the code lived under server/, and modules/ may not import server/, so the three
generators could not reach it even in principle. Moving it is most of the fix.
"""
import contextlib
import io
import re
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.coverage import build_manifest                    # noqa: E402
from modules.data_loader import DataLoader                     # noqa: E402
from modules.pdf_report import PDFReportGenerator              # noqa: E402
from modules.pptx_report import PPTXReportGenerator            # noqa: E402
from modules.report_generator import ReportGenerator           # noqa: E402


@pytest.fixture(scope="module")
def partial_manifest():
    """A deliberately partial export — one system's worth out of 123 sources."""
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(ROOT / "sample_data_landscape" / "D01").load_all()
    return build_manifest(data)


def _finding():
    return {"check_id": "USR-001", "title": "t", "severity": "HIGH",
            "category": "User & Authorization", "description": "d",
            "affected_items": []}


# ── the manifest is reachable from the scanner core ──────────────────────────

def test_the_manifest_lives_where_the_reports_can_reach_it():
    """It was under server/, and modules/ may not import server/ — so the three
    generators could not reach it even in principle. That, not forgetfulness, is
    why no PDF ever carried a word of it."""
    assert (ROOT / "modules" / "coverage.py").exists()


def test_the_move_is_covered_by_the_purity_job_not_by_a_copy_of_it():
    """NOT a second AST walk. The `purity` CI job already walks every file in
    modules/ on 3.12, and this file's first version duplicated it with
    sys.stdlib_module_names — a 3.10+ API that turned the 3.8 and 3.9 matrix jobs
    red. That is the FIFTH time that API has done this here; the previous four are
    recorded in tests/test_collect.py and tests/test_collect_rfc.py.

    The lesson is not "remember the skipif". It is that the coverage already
    exists, so the duplicate was the defect both times.
    """
    assert (ROOT / "modules" / "coverage.py").exists()
    workflow = (ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")
    assert 'Path("modules")' in workflow, "the purity job no longer walks modules/"


def test_the_old_import_path_still_works():
    """server/ingest.py and four test files import from server.coverage."""
    from server.coverage import build_manifest as shim
    assert shim is build_manifest


def test_the_shim_exports_everything_not_a_hand_picked_few():
    """The first version re-exported two functions and broke two tests that used
    `module_sources`. A shim that exports a subset is a rename pretending to be a
    move."""
    from server import coverage as shim
    from modules import coverage as real
    for name in dir(real):
        if not name.startswith("_"):
            assert hasattr(shim, name), name


# ── the manifest describes the auditors and only the auditors ────────────────

def test_the_module_list_matches_the_registry_exactly(partial_manifest):
    """PINNED TO THE REGISTRY, NOT TO A COUNT.

    Moving coverage.py into modules/ made it discover ITSELF as an auditor — 31
    where there are 30. A count would have been updated to 31 by the next person
    and the error would have become the baseline.
    """
    pytest.importorskip("psycopg")     # server.ingest needs it; the cli job has none
    from server.ingest import AUDITORS
    registry = set(AUDITORS) if isinstance(AUDITORS, dict) else {k for k, _ in AUDITORS}
    assert set(partial_manifest["modules"]) == registry


def test_the_manifest_does_not_list_itself(partial_manifest):
    assert "coverage" not in partial_manifest["modules"]


def test_the_library_tier_is_not_listed_as_auditors(partial_manifest):
    """nist_csf, fair_cam and the rest are libraries the auditors call. None
    declares a data input today, so none was appearing — naming them means a
    future one that reads data for its own purposes cannot quietly appear in a
    customer's coverage table."""
    for name in ("nist_csf", "fair_cam", "fair_loss_model", "fair_provenance",
                 "crq_engine"):
        assert name not in partial_manifest["modules"], name


# ── every format renders it ──────────────────────────────────────────────────

def test_the_html_report_says_what_was_not_looked_at(partial_manifest):
    html = ReportGenerator([_finding()], {"target": "T"},
                           coverage=partial_manifest)._render_coverage()
    assert "What this scan could not look at" in html
    assert "logical sources supplied" in html
    assert "not a clean result" in html


def test_the_html_report_says_so_when_the_manifest_is_missing():
    """A report that cannot determine its coverage must say that, not fall
    silent — silence is what the whole change exists to remove."""
    html = ReportGenerator([_finding()], {"target": "T"},
                           coverage=None)._render_coverage()
    assert "could not be determined" in html.lower()


def test_the_html_coverage_precedes_the_findings(partial_manifest):
    """A reader who meets the finding count before the coverage anchors on the
    wrong number."""
    gen = ReportGenerator([_finding()], {"target": "T"}, coverage=partial_manifest)
    source = (ROOT / "modules" / "report_generator.py").read_text(encoding="utf-8")
    assert source.index("{coverage_html}") < source.index("{csf_html}")


@pytest.mark.parametrize("generator", [ReportGenerator, PDFReportGenerator,
                                       PPTXReportGenerator])
def test_every_generator_accepts_the_manifest(generator, partial_manifest):
    """A generator that silently ignores it would render the old clean-looking
    report while the CLI printed the coverage line."""
    instance = generator([_finding()], {"target": "T"}, coverage=partial_manifest)
    assert instance.coverage is partial_manifest


def test_the_pdf_renders_a_coverage_page(tmp_path, partial_manifest):
    out = tmp_path / "r.pdf"
    PDFReportGenerator([_finding()], {"target": "T"},
                       coverage=partial_manifest).generate(str(out))
    text = out.read_bytes().decode("latin-1", "replace")
    assert "Could Not Look At" in text
    assert "unexamined one" in text


def test_the_deck_renders_a_coverage_slide(tmp_path, partial_manifest):
    out = tmp_path / "r.pptx"
    PPTXReportGenerator([_finding()], {"target": "T"},
                        coverage=partial_manifest).generate(str(out))
    z = zipfile.ZipFile(out)
    names = sorted((n for n in z.namelist() if re.match(r"ppt/slides/slide\d+\.xml$", n)),
                   key=lambda n: int(re.search(r"\d+", n.split("/")[-1]).group()))
    # SORTED NUMERICALLY. Lexically, slide10 precedes slide2, and the first
    # version of this assertion read the wrong slide and reported a false failure.
    assert len(names) >= 2
    slide2 = z.read(names[1]).decode("utf-8", "replace")
    assert "Could Not Look At" in slide2, "the coverage slide must be second"
    assert "unexamined one" in slide2


# ── the CLI computes and passes it ───────────────────────────────────────────

def test_the_cli_computes_the_manifest_and_passes_it_to_every_generator():
    source = (ROOT / "sap_scanner.py").read_text(encoding="utf-8")
    assert "build_manifest(" in source
    assert source.count("coverage=coverage_manifest") == 3


def test_a_manifest_failure_does_not_lose_the_scan():
    """The reports then say the coverage is unknown, which is worse than knowing
    and much better than implying completeness."""
    source = (ROOT / "sap_scanner.py").read_text(encoding="utf-8")
    idx = source.find("coverage_manifest = build_manifest(")
    assert idx > 0
    assert "except Exception" in source[idx:idx + 900]
    assert "coverage_manifest = None" in source[idx:idx + 900]


# ── an empty file is not an absent one ───────────────────────────────────────

def test_an_empty_export_is_reported_separately(partial_manifest):
    """Conflating them hides a broken export behind "you didn't send it"."""
    assert "empty" in partial_manifest
    if partial_manifest["empty"]:
        html = ReportGenerator([_finding()], {"target": "T"},
                               coverage=partial_manifest)._render_coverage()
        assert "present but contained no rows" in html
