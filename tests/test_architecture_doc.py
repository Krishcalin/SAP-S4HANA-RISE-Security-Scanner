"""The architecture guide has to stay true, and its diagrams have to stay legible.

WHY THIS FILE EXISTS. `docs/ARCHITECTURE.html` is the document a reader meets
before they meet the code — it is linked first from the README contents, and it
is what somebody evaluating the product reads to decide whether to trust it. A
stale architecture guide is worse than no architecture guide, because it carries
the authority of a document while being wrong, and nobody re-derives a figure
they have just been told.

TWO KINDS OF DRIFT, BOTH CAUGHT HERE.

  The COUNTS it quotes. It states 365 literal check ids, 255 built at runtime,
  620 in total, 30 modules and 133 custom-code rules. Every one of those is
  derivable from the code, so every one of them is held against the code. This
  is the same discipline docs/CHECKS_REFERENCE.md already has, and it exists
  because those numbers moved twice in a single day: the reference went 364 -> 365
  the moment a stray `f` prefix stopped hiding a check id, and the total went
  from "about 619" to an exact 620 once the runtime families were enumerated.

  The DIAGRAM GEOMETRY. Eleven SVG figures, hand-authored, with connectors routed
  as buses. The previous version of this document had seven defects that are
  invisible when reading the markup and obvious on screen: a dashed line running
  straight through the CHECKS box while lying exactly on top of the arrow beside
  it, four connectors superimposed on one spine, an arrowhead terminating in
  empty space, and a path that simply stopped. `tools/svg_geometry_check` finds
  all seven; this test runs it so the eighth cannot ship.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DOC = ROOT / "docs" / "ARCHITECTURE.html"
MD = ROOT / "docs" / "ARCHITECTURE.md"
FIGS = ROOT / "docs" / "architecture"


@pytest.fixture(scope="module")
def page():
    assert DOC.exists(), "the architecture guide is missing: %s" % DOC
    return DOC.read_text(encoding="utf-8")


# ─────────────────────────────── geometry ───────────────────────────────────

def test_every_diagram_is_geometrically_clean(page):
    """No connector through a box, no two lines superimposed, no arrowhead or
    path end in empty space."""
    from tools.svg_geometry_check import check, parse_svgs, rects

    failures = []
    figures = 0
    for i, svg in enumerate(parse_svgs(page)):
        if len(rects(svg)) < 2:
            continue                       # the shared <defs>, not a figure
        figures += 1
        for kind, message in check(svg, i):
            failures.append("FIG %02d  %-8s %s" % (i, kind, message))

    assert figures >= 10, "only %d figures found; the guide has eleven" % figures
    assert not failures, "\n".join(["diagram defects:"] + sorted(set(failures)))


def test_the_checker_still_detects_the_defects_it_was_written_for():
    """A verifier that passes everything proves nothing.

    Synthesises each defect class and requires the checker to report it, so a
    refactor cannot quietly turn the test above into a no-op.
    """
    from tools.svg_geometry_check import check

    through_a_box = '''
      <rect class="box" x="100" y="100" width="200" height="100"/>
      <rect class="box" x="400" y="100" width="200" height="100"/>
      <path class="ln" d="M50 150 L700 150"/>'''
    kinds = {k for k, _ in check(through_a_box, 0)}
    assert "CROSS" in kinds, kinds

    superimposed = '''
      <rect class="box" x="100" y="100" width="100" height="60"/>
      <rect class="box" x="400" y="100" width="100" height="60"/>
      <path class="ln" d="M200 130 L400 130"/>
      <path class="ln" d="M200 130 L400 130"/>'''
    assert "OVERLAP" in {k for k, _ in check(superimposed, 0)}

    into_nothing = '''
      <rect class="box" x="100" y="100" width="100" height="60"/>
      <rect class="box" x="400" y="300" width="100" height="60"/>
      <path class="ln" d="M200 130 L330 130" marker-end="url(#ar)"/>'''
    assert "DANGLE" in {k for k, _ in check(into_nothing, 0)}

    stops_dead = '''
      <rect class="box" x="100" y="100" width="100" height="60"/>
      <rect class="box" x="400" y="300" width="100" height="60"/>
      <path class="ln" d="M200 130 L330 130"/>'''
    assert "DEADEND" in {k for k, _ in check(stops_dead, 0)}

    floating = '''
      <rect class="box" x="100" y="100" width="100" height="60"/>
      <rect class="box" x="400" y="100" width="100" height="60"/>
      <path class="ln" d="M250 400 L400 130" marker-end="url(#ar)"/>'''
    assert "ORPHAN" in {k for k, _ in check(floating, 0)}


# ──────────────────────────────── counts ────────────────────────────────────

def _derived():
    from modules.coverage import (all_check_ids, module_check_ids,
                                  positional_check_ids, runtime_check_families)

    literal = ({c for ids in module_check_ids().values() for c in ids}
               | {c for ids in positional_check_ids().values() for c in ids})
    families = runtime_check_families()
    runtime = {c for f in families for c in f["ids"]}
    return {
        "literal check ids": len(literal),
        "runtime check ids": len(runtime),
        "total check ids": len({c for ids in all_check_ids().values() for c in ids}),
        "audit modules": len(module_check_ids()),
        "runtime families": len(families),
        "custom-code rules": len(next(f for f in families
                                      if f["module"] == "abap_sast")["ids"]),
        "logical sources": _known_sources(),
    }


def _known_sources():
    """How many logical sources the coverage manifest knows about.

    Built from the real loader rather than a constant, because the guide's "123
    logical sources" is the number a reader uses to judge how much of an estate
    an export covers.
    """
    import contextlib
    import io

    from modules.coverage import CLI_MODULE_ALIASES, build_manifest
    from modules.data_loader import DataLoader

    with contextlib.redirect_stdout(io.StringIO()),             contextlib.redirect_stderr(io.StringIO()):
        data = DataLoader(ROOT / "sample_data").load_all()
        manifest = build_manifest(data, modules_run=sorted(CLI_MODULE_ALIASES))
    return manifest["counts"]["sources_known"]


@pytest.mark.parametrize("what", sorted(_derived()))
def test_a_figure_the_guide_quotes_is_still_the_figure_the_code_produces(page, what):
    """Each count appears as a bare number in the prose, so the assertion is that
    the number is PRESENT — a changed count leaves the old one orphaned and this
    fails, which is the moment to go and update the sentence around it."""
    value = _derived()[what]
    assert re.search(r"\b%d\b" % value, page), (
        "the guide never states %d, the current %s. It has drifted from the code "
        "— find the stale figure and update the sentence it sits in." % (value, what))


def test_the_summary_sentence_attaches_each_figure_to_its_own_label(page):
    """PRESENCE IS NOT ENOUGH, and this is the hole that proved it. The guide's
    closing sentence read "139 custom-code rules … and 135 logical sources" when
    the truth is 135 rules and 139 sources. Both numbers were in the document, so
    the test above passed for a year while the sentence had them the wrong way
    round — every figure correct, every label wrong.

    This pins the two that are easy to transpose because they are adjacent in one
    sentence and close in value.
    """
    derived = _derived()
    for label, key in (("custom-code rules", "custom-code rules"),
                       ("logical sources", "logical sources")):
        value = derived[key]
        assert re.search(r"\b%d\s+%s\b" % (value, re.escape(label)), page), (
            "the guide does not say %r. Some other number is sitting next to "
            "that label — check whether two figures have been swapped."
            % ("%d %s" % (value, label)))


def _source_totals_stated_in(text):
    """Every number that qualifies the word "sources", as a total.

    `41 of 139 sources` yields 139 — the partial is free, the denominator is
    not."""
    return [(m.group(0), int(m.group(2) or m.group(1)))
            for m in re.finditer(
                r"(\d+)(?:\s+of\s+(\d+))?\s+(?:logical\s+)?sources\b", text)]


@pytest.mark.parametrize("edition", ["html", "markdown"])
def test_no_stale_denominator_survives_anywhere_in_the_prose(edition):
    """PRESENCE IS NOT ENOUGH, part two — the same hole, one paragraph over.

    The test above pins the closing summary and the one above that only asks
    whether each figure appears SOMEWHERE. Between them, two sentences in the
    body went on saying "nobody ever supplies all 135 sources" and "you supplied
    41 of 135 sources" for as long as 139 appeared once, correctly, elsewhere on
    the page. Both passed. A reader meets the wrong denominator in the chapter
    that teaches them how to judge coverage, which is the worst place on the page
    for it to be wrong — the number is the one they use to decide whether an
    export is thorough enough to trust.

    So every number that qualifies the word "sources" is checked, not just the
    one in the summary. `41 of 139` is fine: the partial is free, the total is
    not.

    BOTH EDITIONS, SEPARATELY. Almost every test in this file takes the `page`
    fixture, which is the HTML. Written that way, this one passed with the
    Markdown edition mutated — the same false pass that let the figure drift in
    the first place, reproduced in the test written to stop it. The two files are
    maintained by hand side by side; either can rot alone.
    """
    text = (DOC if edition == "html" else MD).read_text(encoding="utf-8")
    total = _derived()["logical sources"]
    bad = [phrase for phrase, stated in _source_totals_stated_in(text)
           if stated != total]
    assert not bad, (
        "the %s edition states a source total that is not %d: %s. A partial "
        "(\"41 of %d\") is fine; the denominator is not."
        % (edition, total, bad, total))


def test_the_guide_does_not_hedge_a_count_it_can_state_exactly(page):
    """"~620 checks" was true only while the runtime families were unenumerated.
    They are enumerable now, so the tilde would be false modesty — and a hedged
    number is one nobody can hold against anything."""
    hedged = re.findall(r"[~≈]\s?\d{2,}", page)
    assert not hedged, "approximate counts that are now exact: %s" % hedged


def test_the_load_bearing_invariants_are_all_present(page):
    """The guide's value is the reasoning, not the boxes. If a section is dropped
    in an edit, the diagrams still render and nothing else notices."""
    for phrase in ("connects to nothing",
                   "may never change a verdict",
                   "not a silence",
                   "Never fail open",
                   "who can fix it",
                   "strict partition"):
        assert phrase in page, "the guide no longer states: %r" % phrase


def test_it_opens_without_a_network(page):
    """The product is offline-first and air-gap capable; a guide that fetches a
    font or a script from a CDN fails closed in exactly the review room it was
    written for."""
    remote = re.findall(r'(?:href|src)="(https?://[^"]+)"', page)
    allowed = ("https://github.com/",)
    offenders = [u for u in remote if not u.startswith(allowed)]
    assert not offenders, "the guide loads remote assets: %s" % offenders


def test_it_is_a_whole_document_not_a_fragment(page):
    """It is published as a hosted page too, where the host supplies the
    skeleton. The copy in the repository has to carry its own."""
    for tag in ("<!DOCTYPE html>", "<html", "</head>", "<body>", "</body>", "</html>"):
        assert tag in page, "missing %s — this is the fragment, not the file" % tag


# ─────────────────────── the edition GitHub can render ──────────────────────
#
# GitHub shows an HTML blob as SOURCE, and the guide is classified Confidential
# so Pages — which publishes to the open internet — is not available to render
# it. Markdown is the one format GitHub renders natively in any repository,
# public or private. It is therefore the canonical edition, and the HTML is the
# print copy. Both are generated from the same source chunks so they cannot
# disagree; these tests hold that.

@pytest.fixture(scope="module")
def markdown():
    assert MD.exists(), "the Markdown edition is missing: %s" % MD
    return MD.read_text(encoding="utf-8")


def test_the_markdown_edition_is_the_same_document(markdown, page):
    """Same chapters, same figures, same counts — a second edition that says
    something different is worse than no second edition."""
    import re

    chapters = re.findall(r"^## Chapter (\d+)", markdown, re.M)
    assert len(chapters) == 35, "expected 35 chapters, found %d" % len(chapters)
    for part in ("Part one", "Part seven", "Appendices"):
        assert part in markdown, part
    for phrase in ("connects to nothing", "may never change a verdict",
                   "not a silence", "Never fail open", "who can fix it",
                   "strict partition"):
        assert phrase in markdown, "the Markdown edition no longer states: %r" % phrase


@pytest.mark.parametrize("what", sorted(_derived()))
def test_the_markdown_states_the_same_figures(markdown, what):
    import re

    value = _derived()[what]
    assert re.search(r"\b%d\b" % value, markdown), (
        "the Markdown edition never states %d, the current %s" % (value, what))


def test_every_figure_the_markdown_references_exists(markdown):
    """A broken image is the most visible way a document can rot."""
    import re

    refs = re.findall(r"!\[[^\]]*\]\((architecture/[^)]+)\)", markdown)
    assert len(refs) >= 12, "only %d figures referenced" % len(refs)
    for ref in refs:
        assert (ROOT / "docs" / ref).exists(), "missing figure: %s" % ref


def test_the_exported_figures_are_self_contained_and_clean():
    """A figure exported out of the page carries no :root to inherit from, so
    every colour must be baked in — and the geometry must still hold."""
    from tools.svg_geometry_check import check, parse_svgs

    files = sorted(FIGS.glob("*.svg"))
    assert len(files) >= 12, "only %d figures exported" % len(files)
    problems = []
    for f in files:
        text = f.read_text(encoding="utf-8")
        assert "var(--" not in text, "%s references a token it cannot resolve" % f.name
        assert "<style>" in text, "%s carries no styling of its own" % f.name
        for kind, message in check(parse_svgs(text)[0], 0):
            problems.append("%s  %s  %s" % (f.name, kind, message))
    assert not problems, "\n".join(["exported figures:"] + problems)


def test_the_markdown_has_no_leftover_html():
    """A half-converted document is worse than either format on its own."""
    import re

    text = MD.read_text(encoding="utf-8")
    stray = re.findall(r"<(?!br\b|/br\b)[a-zA-Z][^>\n]*>", text)
    assert not stray, "unconverted HTML in the Markdown edition: %s" % stray[:8]
