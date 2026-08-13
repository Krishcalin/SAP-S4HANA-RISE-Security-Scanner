# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""The twelve domains in the deck — and deliberately not in the HTML or PDF.

WHERE THIS VIEW LIVES, AND WHY IT IS NOT EVERYWHERE
The twelve-domain view is the CONSOLE's (`/domains`, the dashboard strip, the
`?domain=` queue filter) plus one slide in the executive deck. The HTML and PDF
reports carry no domain section, by decision on 2026-08-13: those two are the
long-form hand-over documents and are to stay simple. The section existed in the
HTML for a day and was removed.

That decision is recorded as a test rather than a comment because the opposite is
so plausible — the module is stdlib-only and every other framework view (CSF,
compliance, coverage) does render in the HTML, so re-adding it would look like
filling a gap rather than reversing a call. If the decision changes, delete this
test in the same commit that adds the section back; do not work around it.

WHY THE DECK KEEPS ITS SLIDE
A deck is read further from its author than anything else we produce — in a room,
months later, by somebody who was not there and cannot hover over a tile. So the
one place the domains do appear in print is also the place where the qualifier
matters most, and the assertions below are about exactly that: that the count and
the reach word are never separated, and that the domain we do not do prints a
dash rather than a zero.
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

from modules import domains                                    # noqa: E402
from modules.pdf_report import PDFReportGenerator              # noqa: E402
from modules.pptx_report import PPTXReportGenerator            # noqa: E402
from modules.report_generator import ReportGenerator           # noqa: E402


def _findings():
    return [
        {"check_id": "USR-001", "title": "t", "severity": "CRITICAL",
         "category": "User & Authorization", "description": "d", "affected_items": []},
        {"check_id": "LREV-PAT-001", "title": "t", "severity": "HIGH",
         "category": "Security Audit Log Review", "description": "d", "affected_items": []},
        {"check_id": "BTP-CC-001", "title": "t", "severity": "MEDIUM",
         "category": "BTP Cloud Attack Surface", "description": "d", "affected_items": []},
    ]


# ── the long-form reports stay simple ────────────────────────────────────────

@pytest.mark.parametrize("generator", [ReportGenerator, PDFReportGenerator])
def test_the_hand_over_reports_carry_no_domain_section(generator, tmp_path):
    """A DECISION, NOT AN OVERSIGHT — see this module's docstring.

    Both generators are asserted together because the reason is the same for
    both, and testing only the one that briefly had the section would leave the
    other's absence looking accidental.
    """
    out = tmp_path / ("report.pdf" if generator is PDFReportGenerator else "report.html")
    with contextlib.redirect_stdout(io.StringIO()):
        generator(_findings(), {"scan_time": "2026-01-01"}).generate(str(out))
    blob = out.read_bytes()
    assert b"twelve security domains" not in blob.lower()
    assert not hasattr(generator, "_render_domains")


def test_the_taxonomy_is_still_reachable_from_the_scanner_core():
    """modules/domains.py is stdlib-only and imports nothing from server/ — that
    is what lets the DECK use it, and what would let the reports use it again if
    the decision above were reversed. Dropping the section must not quietly turn
    this back into server-only code."""
    assert (ROOT / "modules" / "domains.py").exists()
    source = (ROOT / "modules" / "domains.py").read_text(encoding="utf-8")
    assert "from server" not in source and "import server" not in source


# ── the deck ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def slide():
    """The domain slide's text, as a reader of the deck would meet it."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "deck.pptx"
        with contextlib.redirect_stdout(io.StringIO()):
            PPTXReportGenerator(_findings(), {"scan_time": "2026-01-01"}).generate(
                str(out), full=False)
        # Closed before the directory is removed: on Windows an open handle makes
        # the cleanup raise PermissionError and every test using this fixture
        # errors on teardown rather than on anything it asserted.
        with zipfile.ZipFile(out) as z:
            pages = [" ".join(re.findall(r"<a:t>(.*?)</a:t>", z.read(n).decode("utf-8")))
                     for n in z.namelist()
                     if re.match(r"ppt/slides/slide\d+\.xml$", n)]
    found = [p for p in pages if "Twelve Security Domains" in p]
    assert found, "no domain slide in the deck"
    return found[0]


def test_the_deck_names_every_domain(slide):
    for d in domains.DOMAINS:
        assert d["label"].replace("&", "&amp;") in slide, d["id"]


def test_every_domain_carries_its_reach_word_on_the_slide(slide):
    """The count and the qualifier are one claim. A slide is exactly where a
    caveat gets dropped for space, and twelve bare numbers on a projector assert
    twelve capabilities — four of which this product does not have."""
    for word in ("fully assessed", "partly assessed", "configuration only",
                 "not covered"):
        assert word in slide, word


def test_the_domain_we_do_not_do_prints_a_dash_and_never_a_zero(slide):
    head, _, tail = slide.partition("Exploit and 0-Day Protection")
    assert tail.lstrip().startswith("—"), tail[:40]


def test_the_slide_publishes_no_score_or_percentage(slide):
    """It looks for a FIGURE, not for a word: an earlier version of this test
    failed on prose written to say there is no score — the fourth time in this
    codebase a textual check has flagged the sentence that denies the thing it
    matched."""
    assert not re.search(r"\d\s*%", slide)
    assert not re.search(r"(score|rating|maturity)\s*(is|of|:|=)?\s*\d", slide, re.I)


def test_the_slide_reads_the_state_axis_it_computes(tmp_path):
    """IT COMPUTED BOTH AXES AND PRINTED ONE. `roll_up` is handed the coverage
    manifest and returns reach AND state; the tile loop read only reach, so a
    domain whose export never arrived printed "0" beside "fully assessed" — the
    reach word reading as a verdict, which is the single thing the two-axis
    design exists to prevent."""
    manifest = {"modules": {"user_auth_audit": {"status": "complete"},
                            "log_review": {"status": "skipped"},
                            "access_risk_analysis": {"status": "not_run"}}}
    out = tmp_path / "deck.pptx"
    with contextlib.redirect_stdout(io.StringIO()):
        PPTXReportGenerator(_findings(), {"scan_time": "2026-01-01"},
                            coverage=manifest).generate(str(out), full=False)
    with zipfile.ZipFile(out) as z:
        pages = [" ".join(re.findall(r"<a:t>(.*?)</a:t>", z.read(n).decode("utf-8")))
                 for n in z.namelist() if re.match(r"ppt/slides/slide\d+\.xml$", n)]
    page = next(p for p in pages if "Twelve Security Domains" in p)
    assert "export not supplied" in page

    rolled = domains.roll_up(_findings(), coverage=manifest)
    for d in rolled["domains"]:
        if d["state"] == domains.NOT_SUPPLIED:
            # Its count must not be printed at all: a zero drawn beside a reach
            # word reads as a measurement of the customer's estate.
            head, _, tail = page.partition(d["label"].replace("&", "&amp;"))
            assert tail.lstrip().startswith("—"), (d["label"], tail[:40])


def test_the_findings_outside_the_taxonomy_are_counted_on_the_slide(slide):
    """They are real findings this product produced. A summary that silently
    dropped them would understate the product while claiming to summarise it."""
    assert "outside this vocabulary" in slide
