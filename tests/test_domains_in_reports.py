# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""The twelve domains, in the artefacts that leave the building.

WHY THE PRINTED VERSION NEEDS ITS OWN TESTS
On screen a qualifier can live one click away; a reader who mistakes a
configuration-only domain for a monitoring result can hover, click through, or
ask. A report is read further from its author than anything else we produce — in
a meeting, months later, by somebody who was not there — so every claim has to
carry its own limit on the same page as the number.

The assertions below are about exactly that: that the count and the qualifier are
never separated, that the domain we do not do prints a dash and not a zero, and
that no percentage or maturity score has crept in beside them.
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


@pytest.fixture(scope="module")
def html():
    with contextlib.redirect_stdout(io.StringIO()):
        return ReportGenerator(_findings(), {"scan_time": "2026-01-01"})._render_domains()


# ── the HTML report ──────────────────────────────────────────────────────────

def test_the_html_report_carries_the_twelve_domains(html):
    assert "The twelve security domains" in html
    for d in domains.DOMAINS:
        assert d["label"].replace("&", "&amp;") in html, d["id"]


def test_every_domain_prints_its_reach_beside_its_count(html):
    """The count and the qualifier are one claim. A layout change that separated
    them would leave twelve bare numbers asserting twelve capabilities."""
    cards = html.split('<div class="dom-card dom-')[1:]
    assert len(cards) == len(domains.DOMAINS)
    for card in cards:
        assert 'class="dom-big"' in card
        assert 'class="dom-reach"' in card


def test_the_domain_we_do_not_do_prints_a_dash_and_never_a_zero(html):
    card = next(c for c in html.split('<div class="dom-card dom-')[1:]
                if "Exploit and 0-Day Protection" in c)
    big = re.search(r'dom-big">(.*?)</div>', card, re.S).group(1)
    assert "&mdash;" in big
    assert "0" not in re.sub(r"<[^>]*>", "", big)


def test_the_scope_sentence_travels_with_the_domain_in_print(html):
    """A limit stated only on the website is a limit the printed page does not
    have. Every qualified domain's own words appear in the table."""
    import html as htmlmod
    plain = htmlmod.unescape(re.sub(r"<[^>]*>", " ", html))
    for d in domains.DOMAINS:
        if not d.get("scope"):
            continue
        opening = " ".join(d["scope"].split())[:60]
        assert opening in " ".join(plain.split()), d["id"]


def test_the_findings_outside_the_taxonomy_are_named_in_print(html):
    """They are real findings this product produced. A printed summary that
    silently dropped them would understate the product while claiming to
    summarise it."""
    assert "no word for" in html
    assert "BTP Cloud Attack Surface" in html


def test_the_printed_section_publishes_no_score_or_percentage(html):
    """compliance_mapping.py forbids one, and a twelve-tile page is exactly where
    somebody would add a maturity rating for the executive summary.

    IT LOOKS FOR A FIGURE, NOT FOR A WORD. The first version of this test failed
    on the section's own honest sentence — "there is no compliance score here and
    there will not be one" — which is the fourth time in this codebase a textual
    check has flagged prose written to say the opposite of what it matched. A
    rule about what the product may CLAIM has to be written against the claim.
    """
    plain = re.sub(r"<style>.*?</style>", "", html, flags=re.S)
    text = re.sub(r"<[^>]*>", " ", plain)
    assert not re.search(r"\d\s*%", text), "a percentage figure"
    assert not re.search(r"(score|rating|maturity)\s*(is|of|:|=)?\s*\d", text, re.I)


def test_an_empty_scan_renders_no_domain_section():
    """Twelve tiles over an empty corpus would print twelve results about a scan
    that produced none."""
    with contextlib.redirect_stdout(io.StringIO()):
        assert ReportGenerator([], {})._render_domains() == ""


def test_the_section_is_in_the_document_not_merely_available(tmp_path):
    """A renderer nobody calls is the failure modules/coverage.py shipped with:
    the code existed, and no report carried a word of it for the product's whole
    life. Rendering the section is not the same as placing it in the page."""
    out = tmp_path / "report.html"
    with contextlib.redirect_stdout(io.StringIO()):
        ReportGenerator(_findings(), {"scan_time": "2026-01-01"}).generate(str(out))
    page = out.read_text(encoding="utf-8")
    assert "The twelve security domains" in page
    # After the raw category breakdown it re-expresses, and before coverage.
    assert page.index("Findings by Category") < page.index("The twelve security domains")


# ── the deck ─────────────────────────────────────────────────────────────────

def test_the_deck_renders_a_domain_slide(tmp_path):
    out = tmp_path / "deck.pptx"
    with contextlib.redirect_stdout(io.StringIO()):
        PPTXReportGenerator(_findings(), {"scan_time": "2026-01-01"}).generate(
            str(out), full=False)
    z = zipfile.ZipFile(out)
    slides = [z.read(n).decode("utf-8") for n in z.namelist()
              if re.match(r"ppt/slides/slide\d+\.xml$", n)]
    text = [" ".join(re.findall(r"<a:t>(.*?)</a:t>", s)) for s in slides]
    found = [t for t in text if "Twelve Security Domains" in t]
    assert found, "no domain slide in the deck"
    slide = found[0]
    # The qualifier is the first thing dropped when a slide runs short of room.
    assert "configuration" in slide
    assert "not covered" in slide
    assert "—" in slide          # the em dash where a zero would mislead
