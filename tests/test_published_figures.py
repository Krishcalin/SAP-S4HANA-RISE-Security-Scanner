"""One figure, published in six documents, wrong in four of them.

WHAT HAPPENED. The catalogue's source count is quoted in README.md,
EXPORT_SOURCES.md, ARCHITECTURE (both editions), COMPETITIVE_ANALYSIS.md,
EXPORT_GUIDE.md, BUILD_ROADMAP.md and PIVOT_PLAN.md. It moved to 139, and:

    EXPORT_GUIDE.md      said 128 — twice, including "EXPORT_SOURCES.md lists
                         all 128", where that file is GENERATED and says 139
    BUILD_ROADMAP.md     said 135, in the header that corrects the rest of itself
    PIVOT_PLAN.md        said 135, the same line
    ARCHITECTURE (both)  said 135 in chapter 12, and 139 in its own summary

Every one of these was found by grepping, not by reading, and the ARCHITECTURE
pair had survived a commit whose entire subject was fixing that figure. A number
carried in eight places is not maintained by care.

`tests/test_architecture_doc.py` now guards the two ARCHITECTURE editions. This
guards everything else, because the drift was never architecture-specific: it is
what happens to any figure a human has to remember to update.

WHY AN ALLOWLIST RATHER THAN A CLEVERER RULE. Three occurrences are legitimate
SUBSETS — what one collector reaches, what connected mode documents — and no
regex distinguishes "14 logical sources (from sapcontrol)" from "14 logical
sources (in total)" without reading the sentence. So each is named here with its
reason, and a fourth appearing is somebody's deliberate act rather than a
silent drift.

WHAT IS DELIBERATELY NOT GUARDED. `docs/BUILD_ROADMAP.md` records numbers inside
phase entries — "518 of our 714 checks", a captured console snapshot — and its
own header says to read those as dated measurements taken when the phase closed.
They are history and correcting them would be rewriting it. Only text presenting
a CURRENT total is in scope, which in practice is what this regex finds outside
those blocks.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

#: Every markdown file that is not generated. The generated ones are rebuilt from
#: the code and cannot drift; `EXPORT_SOURCES.md` is the one this drift was
#: measured against.
_GENERATED = {"CHECKS_REFERENCE.md", "CHECK_FIRING.md", "EXPORT_SOURCES.md",
              "RELEASE_GATE.md"}

#: `N sources`, `N logical sources`, and `N of M sources` where M is the total.
#:
#: MARKDOWN BOLD IS ALLOWED AT EVERY JOIN. A first version required a bare space
#: between the number and the noun, and `The scanner reads **128** logical
#: sources` sailed straight through it — the exact sentence this file exists to
#: catch, in the document it was found in, while a mutation said the guard was
#: working because the other four documents failed.
#:
#: `logical` is optional for the same reason: the catalogue total is written both
#: ways — "139 logical sources" in ARCHITECTURE's summary, "41 of 139 sources" in
#: its chapter 12, "119 of 139 sources" in the README.
_TOTAL = re.compile(
    r"(\d+)\*{0,2}(?:\s+of\s+\*{0,2}(\d+))?\*{0,2}\s+(?:logical\s+)?sources\b")

#: Occurrences that are NOT the catalogue total — either a genuine subset (one
#: collector, one tier) or a dated measurement whose numerator would have to be
#: re-measured alongside. Keyed by the exact phrase, so a changed sentence has to
#: be re-approved rather than inheriting the exemption, and each carries why.
_SUBSETS = {
    # server/cli.py's connected mode reaches a fraction of the catalogue.
    "14 logical sources, listed in": "what connected mode documents",
    # docs/EXPORT_GUIDE.md's per-collector table.
    "| 14 logical sources |": "what the sapcontrol collector alone reaches",
    "| 16 logical sources |": "what the icf collector alone reaches",
    # docs/ECC_COVERAGE.md partitions the catalogue into three tiers by whether
    # an ECC estate can produce the source at all. Subsets by construction.
    "in the fixture (39 sources)": "ECC fixture tier A",
    "cannot exist (37 sources)": "ECC fixture tier B",
    "optional tooling (38 sources)": "ECC fixture tier C",
    # An ILLUSTRATIVE message quoted inside two design proposals, written when
    # the catalogue held 117. Left as the historical text it is, for the reason
    # BUILD_ROADMAP's phase numbers are left alone: correcting a quotation inside
    # a proposal rewrites what was proposed.
    "41 of 117 sources": "an example message quoted in a design proposal",
    # A DATED MEASUREMENT, printed under a block of test output when that phase
    # closed. `106` is how many of `123` were supplied at the time; moving the
    # denominator without re-measuring the numerator would invent a figure, which
    # is the failure the rest of this file is about.
    "106 of 123 logical": "a dated sample_data measurement, numerator included",
}


def _documents():
    for path in sorted(ROOT.rglob("*.md")):
        if "node_modules" in path.parts or path.name in _GENERATED:
            continue
        yield path


def _true_total() -> int:
    sys.path.insert(0, str(ROOT / "tests"))
    from test_architecture_doc import _derived
    return _derived()["logical sources"]


def test_the_documents_agree_on_how_many_sources_there_are():
    """Any number qualifying "logical sources" is the catalogue total, unless it
    is named above as a subset."""
    total = _true_total()
    wrong = []
    for path in _documents():
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in _TOTAL.finditer(text):
            stated = int(match.group(2) or match.group(1))
            if stated == total:
                continue
            context = text[max(0, match.start() - 30):match.end() + 20]
            if any(phrase in context for phrase in _SUBSETS):
                continue
            wrong.append("%s: %r" % (path.relative_to(ROOT), match.group(0)))
    assert not wrong, (
        "these state a source total that is not %d:\n  %s\n"
        "Either correct them, or — if the number is a subset rather than the "
        "catalogue — add the phrase to _SUBSETS with the reason."
        % (total, "\n  ".join(wrong)))


def test_every_named_subset_still_exists():
    """A stale exemption silently re-opens the hole it was written to close."""
    everything = "\n".join(p.read_text(encoding="utf-8", errors="replace")
                           for p in _documents())
    missing = [phrase for phrase in _SUBSETS if phrase not in everything]
    assert not missing, (
        "these subset exemptions match nothing any more and should be deleted: %s"
        % missing)


def test_the_guide_does_not_contradict_the_generated_catalogue():
    """`EXPORT_GUIDE.md` told the reader that `EXPORT_SOURCES.md` "lists all
    128". That file is generated from the loader and said 139. A hand-written
    document citing a generated one is the cheapest possible place to be caught
    out, and it went unnoticed until somebody grepped."""
    guide = (ROOT / "docs" / "EXPORT_GUIDE.md").read_text(encoding="utf-8")
    generated = (ROOT / "docs" / "EXPORT_SOURCES.md").read_text(encoding="utf-8")
    total = _true_total()
    assert "%d logical sources" % total in generated, (
        "the generated catalogue no longer states %d; regenerate it" % total)
    cited = re.search(r"lists all (\d+)", guide)
    assert cited and int(cited.group(1)) == total, (
        "docs/EXPORT_GUIDE.md cites a different count than the file it points at")


@pytest.mark.parametrize("path,figure", [
    ("docs/BUILD_ROADMAP.md", "audit modules"),
    ("docs/PIVOT_PLAN.md", "audit modules"),
])
def test_the_headers_that_correct_the_rest_of_a_document_are_themselves_current(
        path, figure):
    """Both files open with a note saying the body has drifted and giving the
    real figures. That header was itself two releases stale — 36 modules and 714
    checks against 38 and 819 — so the correction needed correcting, which is the
    least useful state for a document to be in."""
    text = (ROOT / path).read_text(encoding="utf-8")
    header = text[:text.index("---")] if "---" in text else text[:4000]
    sys.path.insert(0, str(ROOT / "tests"))
    from test_architecture_doc import _derived
    derived = _derived()
    assert "%d %s" % (derived["audit modules"], figure) in header, (
        "%s's header does not state the current %s (%d)"
        % (path, figure, derived["audit modules"]))
    assert "%d check ids" % derived["total check ids"] in header, (
        "%s's header does not state the current check count (%d)"
        % (path, derived["total check ids"]))
