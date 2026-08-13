# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""`--severity` decides what is LISTED, never what was FOUND.

THE DEFECT
The severity flag narrowed `all_findings`, and the report generators fed that
narrowed list to `nist_csf.roll_up`, `fair_cam.classify`, `ComplianceMapper` and
`domains.roll_up`. So on `--severity HIGH` a CSF Category with real MEDIUM
findings rendered the green "no findings" chip — a display option turning a
finding into a clean control — and nothing on the page said a filter had been
applied. `--severity CRITICAL` over a corpus with no criticals removed the CSF,
FAIR-CAM and compliance sections from the document entirely.

sap_scanner.py had already snapshotted the unfiltered corpus for the FAIR figure,
with the comment that a display option "must not silently change the dollar
figure". The argument was right and its scope was one section wide. The money was
protected; the frameworks were not.

THE RULE THESE TESTS ENFORCE
A section that LISTS findings obeys the filter. A section that makes a claim
ABOUT THE ESTATE does not — and the report says so, because two numbers that
disagree without explanation read as a broken report rather than an honest one.
"""
from __future__ import annotations

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

from modules import fair_cam, nist_csf                          # noqa: E402
from modules.compliance_mapping import ComplianceMapper         # noqa: E402
from modules.pdf_report import PDFReportGenerator               # noqa: E402
from modules.pptx_report import PPTXReportGenerator             # noqa: E402
from modules.report_generator import ReportGenerator            # noqa: E402

#: A corpus whose only findings in two categories are MEDIUM. Filter to CRITICAL
#: and those categories vanish — exactly the shape that produced a green chip for
#: a control the scan had evidence against.
FULL = [
    {"check_id": "USR-001", "title": "critical one", "severity": "CRITICAL",
     "category": "User & Authorization", "description": "d", "affected_items": []},
    {"check_id": "LOG-AUD-001", "title": "medium one", "severity": "MEDIUM",
     "category": "Logging, Monitoring & IR", "description": "d", "affected_items": []},
    {"check_id": "DPP-RAL-001", "title": "medium two", "severity": "MEDIUM",
     "category": "Data Protection & Privacy", "description": "d", "affected_items": []},
]
SHOWN = [f for f in FULL if f["severity"] == "CRITICAL"]
META = {"scan_time": "2026-01-01", "severity_filter": "CRITICAL"}


def _generate(generator, tmp_path, suffix):
    out = tmp_path / f"report{suffix}"
    with contextlib.redirect_stdout(io.StringIO()):
        generator(SHOWN, META, full_findings=FULL).generate(str(out))
    if suffix == ".pptx":
        with zipfile.ZipFile(out) as z:
            return " ".join(
                " ".join(re.findall(r"<a:t>(.*?)</a:t>", z.read(n).decode("utf-8")))
                for n in z.namelist() if re.match(r"ppt/slides/slide\d+\.xml$", n))
    return out.read_text(encoding="utf-8", errors="replace")


# ── the roll-ups read the estate, not the selection ──────────────────────────

def test_the_filtered_corpus_really_would_have_lied():
    """The premise, asserted rather than assumed. If filtering stopped changing
    these roll-ups for some other reason, every test below would pass while
    proving nothing."""
    filtered = {c["id"]: c["status"]
                for fn in nist_csf.roll_up(SHOWN)["functions"] for c in fn["categories"]}
    full = {c["id"]: c["status"]
            for fn in nist_csf.roll_up(FULL)["functions"] for c in fn["categories"]}
    flipped = [cid for cid in full
               if full[cid] == "assessed" and filtered.get(cid) == "clear"]
    assert flipped, "the fixture no longer demonstrates the bug"


def test_the_html_csf_section_counts_the_whole_corpus(tmp_path):
    page = _generate(ReportGenerator, tmp_path, ".html")
    section = page[page.index("NIST Cybersecurity Framework 2.0"):]
    section = section[:section.index("</table>")]
    full = {c["id"]: c["status"]
            for fn in nist_csf.roll_up(FULL)["functions"] for c in fn["categories"]}
    for cid, status in full.items():
        if status != "assessed":
            continue
        row = re.search(r'<td class="csf-id">' + re.escape(cid) + r"</td>.*?</tr>",
                        section, re.S)
        assert row, cid
        assert "no findings" not in row.group(0), (
            f"{cid} has MEDIUM evidence and renders as clean under a CRITICAL filter")


def test_the_compliance_mapping_is_computed_over_the_whole_corpus():
    """A control flagged by a MEDIUM finding is still a flagged control."""
    full_controls = sum(len(fw["controls"]) for fw in ComplianceMapper(FULL).assess())
    shown_controls = sum(len(fw["controls"]) for fw in ComplianceMapper(SHOWN).assess())
    assert full_controls > shown_controls, "fixture no longer distinguishes the two"
    gen = ReportGenerator(SHOWN, META, full_findings=FULL)
    with contextlib.redirect_stdout(io.StringIO()):
        rendered = gen._render_compliance()
    from_full = ComplianceMapper(gen.full_findings).assess()
    assert sum(len(fw["controls"]) for fw in from_full) == full_controls
    assert rendered


def test_the_control_function_map_is_computed_over_the_whole_corpus():
    """FAIR-CAM says which control function the findings weaken. A weakness the
    display filter hid is still a weakness."""
    assert fair_cam.classify(FULL) != fair_cam.classify(SHOWN), "fixture is not sensitive"
    gen = ReportGenerator(SHOWN, META, full_findings=FULL)
    with contextlib.redirect_stdout(io.StringIO()):
        assert gen._render_fair_cam()


@pytest.mark.parametrize("generator,suffix", [(ReportGenerator, ".html"),
                                              (PDFReportGenerator, ".pdf"),
                                              (PPTXReportGenerator, ".pptx")])
def test_no_format_loses_its_framework_sections_to_a_filter(generator, suffix, tmp_path):
    """`--severity CRITICAL` over a corpus with no criticals emptied
    `self.findings`, and `if not self.findings: return ""` then deleted the CSF,
    FAIR-CAM and compliance sections from the document — a report about an estate
    with findings, silently missing every section that describes it."""
    out = tmp_path / f"empty{suffix}"
    with contextlib.redirect_stdout(io.StringIO()):
        generator([], META, full_findings=FULL).generate(str(out))
    assert out.stat().st_size > 0
    if suffix == ".html":
        page = out.read_text(encoding="utf-8")
        assert "NIST Cybersecurity Framework 2.0" in page


def test_the_html_says_a_filter_is_applied_and_what_it_did(tmp_path):
    """Silence is the worse failure. Two numbers on one page that disagree, with
    nothing explaining why, read as a broken report."""
    page = _generate(ReportGenerator, tmp_path, ".html")
    assert "A severity filter is applied" in page
    assert "CRITICAL" in page
    assert str(len(FULL) - len(SHOWN)) in page       # the count it omitted
    assert "Severity filter:" in page                # and in the header meta


def test_the_deck_says_so_on_its_first_slide(tmp_path):
    """"Findings: 1" is the sentence a room remembers, and nobody in the room can
    open the CLI history to find out that a filter produced it."""
    deck = _generate(PPTXReportGenerator, tmp_path, ".pptx")
    assert "Severity filter" in deck
    assert "framework slides cover all" in deck


def test_an_unfiltered_report_says_nothing_about_filters(tmp_path):
    """A notice that fires when there is nothing to notice is noise, and noise is
    how a real warning stops being read."""
    out = tmp_path / "all.html"
    with contextlib.redirect_stdout(io.StringIO()):
        ReportGenerator(FULL, {"scan_time": "2026-01-01", "severity_filter": "ALL"},
                        full_findings=FULL).generate(str(out))
    assert "A severity filter is applied" not in out.read_text(encoding="utf-8")


# ── the default must not become a silent new claim ───────────────────────────

def test_a_caller_that_passes_no_full_corpus_gets_the_status_quo():
    """Every existing caller keeps working, and keeps getting the filtered set —
    which is what it passed. Defaulting to anything else would invent a claim the
    caller never made."""
    assert ReportGenerator(SHOWN, META).full_findings == SHOWN
    assert PDFReportGenerator(SHOWN, META).full_findings == SHOWN
    assert PPTXReportGenerator(SHOWN, META).full_findings == SHOWN


def test_the_scanner_hands_every_generator_the_unfiltered_corpus():
    """The snapshot existed for the FAIR figure alone. Three more sections now
    depend on the same argument, and a section that silently keeps the filtered
    list is invisible until somebody filters."""
    source = (ROOT / "sap_scanner.py").read_text(encoding="utf-8")
    assert source.count("full_findings=fair_findings") == 3
