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
    and much better than implying completeness.

    ASKED OF THE SYNTAX TREE, NOT OF A CHARACTER WINDOW. This used to search the
    900 characters following the call for `except Exception` and
    `coverage_manifest = None`. Adding one argument to the call pushed the
    handler past the window and the test failed on unchanged behaviour — a test
    measuring the distance between two lines rather than the relationship
    between them. The relationship is what matters: the call is inside a `try`,
    and the handler sets the manifest to None.
    """
    import ast

    tree = ast.parse((ROOT / "sap_scanner.py").read_text(encoding="utf-8"))

    def calls_build_manifest(node):
        return any(isinstance(n, ast.Call) and getattr(n.func, "id", "") == "build_manifest"
                   for n in ast.walk(node))

    guarded = [t for t in ast.walk(tree)
               if isinstance(t, ast.Try) and any(calls_build_manifest(s) for s in t.body)]
    assert guarded, "the manifest is built outside any try — one bad export loses the scan"

    for attempt in guarded:
        for handler in attempt.handlers:
            assigns_none = any(
                isinstance(n, ast.Assign)
                and any(getattr(t, "id", "") == "coverage_manifest" for t in n.targets)
                and isinstance(n.value, ast.Constant) and n.value.value is None
                for n in ast.walk(handler))
            assert assigns_none, (
                "a handler around build_manifest does not set coverage_manifest "
                "to None, so the reports would carry a half-built manifest")


# ── an empty file is not an absent one ───────────────────────────────────────

def test_an_empty_export_is_reported_separately(partial_manifest):
    """Conflating them hides a broken export behind "you didn't send it"."""
    assert "empty" in partial_manifest
    if partial_manifest["empty"]:
        html = ReportGenerator([_finding()], {"target": "T"},
                               coverage=partial_manifest)._render_coverage()
        assert "present but contained no rows" in html


# ── "did not run" is not one state, it is two ────────────────────────────────
#
# `skipped`  the customer supplied none of the module's input.
# `not_run`  the scan did not execute the module — filtered out, or it failed.
#
# They have different owners and different remedies. `modules_not_run` was
# computed on every single run and read by nobody: no summary clause, no card in
# any of the three report formats, and no entry in either label map, so the raw
# enum leaked into the customer's table and sorted BELOW "complete". A scan of
# six modules out of thirty printed three reassuring zeroes.

@pytest.fixture(scope="module")
def filtered_manifest():
    """One module asked for out of thirty — the shape `--modules users` produces."""
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(ROOT / "sample_data").load_all()
    return build_manifest(data, modules_run=["users"])


def test_a_filtered_run_actually_reports_modules_that_were_not_executed(filtered_manifest):
    assert filtered_manifest["counts"]["modules_not_run"] > 20


def test_the_summary_sentence_says_so(filtered_manifest):
    """The sentence an operator reads without a legend. It counted degraded and
    skipped and stopped there, so the one number that mattered most on a
    filtered run was the one it left out."""
    summary = filtered_manifest["summary"]
    assert "were not executed" in summary
    assert str(filtered_manifest["counts"]["modules_not_run"]) in summary


def test_a_filtered_run_is_never_described_as_complete(filtered_manifest):
    """"Coverage is complete." was gated on the SOURCES alone. Every source can be
    present while most modules were never asked to look at them, which is the
    most reassuring sentence this file can emit about the least complete thing it
    describes."""
    assert "Coverage is complete." not in filtered_manifest["summary"]


def test_a_genuinely_complete_run_still_says_so():
    """The gate must not have become unsatisfiable — a rule that never passes is
    indistinguishable from a broken one."""
    from modules.coverage import summarize
    complete = {"sources_supplied": 123, "sources_known": 123, "sources_empty": 0,
                "modules_degraded": 0, "modules_skipped": 0, "modules_not_run": 0}
    assert "Coverage is complete." in summarize(complete)


@pytest.mark.parametrize("generator", [ReportGenerator, PDFReportGenerator,
                                       PPTXReportGenerator])
def test_every_format_shows_the_not_executed_count(generator, filtered_manifest,
                                                   tmp_path):
    """All three, because all three read `modules_skipped` and none read this."""
    suffix = {"ReportGenerator": ".html", "PDFReportGenerator": ".pdf",
              "PPTXReportGenerator": ".pptx"}[generator.__name__]
    out = tmp_path / f"report{suffix}"
    with contextlib.redirect_stdout(io.StringIO()):
        generator([_finding()], {"scan_time": "2026-01-01"},
                  coverage=filtered_manifest).generate(str(out))
    if suffix == ".pptx":
        # OOXML is a zip; the words are in the slide parts, not in the file bytes.
        import re, zipfile
        with zipfile.ZipFile(out) as z:
            text = " ".join(
                " ".join(re.findall(r"<a:t>(.*?)</a:t>", z.read(n).decode("utf-8")))
                for n in z.namelist() if re.match(r"ppt/slides/slide\d+\.xml$", n))
    else:
        text = out.read_text(encoding="utf-8", errors="replace")
    assert "not executed" in text


def test_the_html_table_labels_the_state_instead_of_leaking_the_enum(filtered_manifest):
    """`not_run` was in neither label map, so the fallback printed the raw
    identifier into a customer-facing table."""
    html_out = ReportGenerator([_finding()], {"target": "T"},
                               coverage=filtered_manifest)._render_coverage()
    assert ">not_run<" not in html_out
    assert "not executed" in html_out


def test_the_state_that_means_we_did_not_look_sorts_to_the_top(filtered_manifest):
    """Absent from the order map it defaulted to 9 and sorted below `complete`,
    putting the one state a reader needs at the bottom of a table read
    top-down."""
    html_out = ReportGenerator([_finding()], {"target": "T"},
                               coverage=filtered_manifest)._render_coverage()
    body = html_out[html_out.index("<tbody>"):]
    # Compared against whatever "we did look" labels this manifest actually
    # produced — pinning it to one of them makes the test depend on the fixture
    # happening to contain that state.
    ran_labels = [lbl for lbl in ("complete", "partial input", "needs no export")
                  if ">" + lbl + "<" in body]
    assert ran_labels, "fixture produced no module that ran, so there is no order to check"
    assert all(body.index("not executed") < body.index(">" + lbl + "<")
               for lbl in ran_labels)


def test_the_coverage_section_precedes_every_number_the_report_produces(tmp_path):
    """Its docstring has said "rendered FIRST" since it was written, and it sat
    below the risk ring, the severity cards, the priority queue and the category
    bars — which is every number a reader anchors on."""
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(ROOT / "sample_data").load_all()
    out = tmp_path / "report.html"
    with contextlib.redirect_stdout(io.StringIO()):
        ReportGenerator([_finding()], {"scan_time": "2026-01-01"},
                        coverage=build_manifest(data)).generate(str(out))
    page = out.read_text(encoding="utf-8")
    first = page.index("What this scan could not look at")
    for later in ('class="summary-grid"', "Risk-Prioritized Remediation Queue",
                  "Findings by Category"):
        assert first < page.index(later), later
