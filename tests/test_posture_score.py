"""The headline number has to move when the estate improves, and must not move
when the customer simply sends us less.

THE DEFECT
    min(100, crit * 25 + high * 10 + med * 4 + low * 1)

On sample_data the raw total is 3693, so the printed score was 100 — and stayed
100 while sixty findings were closed, because four criticals also reach the cap.
The first number a customer sees was frozen at the worst possible value for the
entire life of a remediation programme.

The second half is worse. Fewer exports meant fewer modules ran, which meant
fewer findings, which meant a LOWER score. Uploading less improved the customer's
posture. That is the same incentive server/analytics.py names in its own
docstring about the pass rate, and the same failure this codebase has been
removing all week: an absence of evidence rendering as evidence of absence.

WHAT THESE TESTS PIN
Properties, not the arithmetic. They assert the score falls when findings close,
does not fall when coverage shrinks, is unavailable when nothing says what ran,
and that the printed bands are the severity weights rather than round numbers
somebody liked — so a future change to the weights cannot silently leave the
bands describing the old scale.
"""
from __future__ import annotations

import collections
import contextlib
import io
import re
import sys
import zipfile
import zlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import posture_score                               # noqa: E402
from modules.pdf_report import PDFReportGenerator               # noqa: E402
from modules.pptx_report import PPTXReportGenerator             # noqa: E402
from modules.report_generator import ReportGenerator            # noqa: E402

META = {"scan_time": "2026-01-01", "system_id": "PRD"}


def _f(cid, sev, cat="User & Authorization"):
    return {"check_id": cid, "title": cid, "severity": sev, "category": cat,
            "description": "d", "affected_items": []}


#: Two modules ran.
#:
#: THE NAMES ARE THE MANIFEST'S VOCABULARY, NOT THE CLI'S. `build_manifest`
#: normalises `users` to `user_auth_audit` before writing the manifest, so a
#: fixture keyed by the short names describes modules that do not exist: every
#: lookup misses, the declared set is empty, and the denominator collapses to
#: "checks that produced findings" — under which every check found something and
#: the score is 100 by construction. Two vocabularies, one dict, no error.
MODULES = ("user_auth_audit", "btp_cloud_surface")
BOTH = {"modules": {m: {"status": "complete"} for m in MODULES}}
ONE = {"modules": {MODULES[0]: {"status": "complete"}}}


# ─────────────────────────── the two properties ─────────────────────────────

def test_the_score_falls_as_findings_are_closed():
    """The whole point. The old score reached its cap on any real estate and
    then could not report progress at all."""
    before = [_f("USR-%03d" % i, "CRITICAL") for i in range(40)]
    after = before[:10]
    hi, lo = posture_score.score(before, BOTH), posture_score.score(after, BOTH)
    assert hi and lo
    assert lo[0] < hi[0], (
        "closing thirty criticals did not move the number: %s -> %s" % (hi, lo))


def test_it_does_not_improve_when_a_whole_module_is_dropped():
    """Same findings, one fewer module: the denominator shrinks with the
    numerator, so the estate cannot look better for having been measured less."""
    findings = [_f("USR-001", "CRITICAL"), _f("USR-002", "HIGH")]
    wide = posture_score.score(findings, BOTH)
    narrow = posture_score.score(findings, ONE)
    assert wide and narrow
    assert narrow[0] >= wide[0], (
        "supplying less improved the score: %s -> %s" % (wide, narrow))


def test_it_does_not_improve_when_a_MODULE_IS_DEGRADED():
    """THE CASE THE TEST ABOVE CANNOT REACH, AND THE ONE THAT ACTUALLY HAPPENS.

    Withholding an export does not remove a module from the manifest. The module
    still runs on what is left, so it is still in `ran_modules`, and it used to
    contribute its FULL declared check list to the denominator — while the
    individual checks whose sources were missing self-skipped and produced
    nothing. Numerator down, denominator flat, score DOWN.

    The test above holds a hand-written all-`complete` manifest and drops a whole
    module, which is the single shape where the denominator does shrink. It
    passed throughout. Measured against the real scanner at the time, dropping
    four HANA exports moved sample_data from 36 to 34 with the denominator pinned
    at 402, and a 20-of-108-file upload scored 9 instead of 36.

    So this fixture is the production shape: `degraded`, with `sources_missing`.
    """
    from modules.coverage import module_check_ids

    whole = "user_auth_audit"
    partial = "btp_cloud_surface"
    checks = {m: sorted(module_check_ids()[m]) for m in (whole, partial)}

    intact = {"modules": {m: {"status": "complete", "sources_missing": []}
                          for m in (whole, partial)}}
    # Same run, one module's sources half missing: it still ran, so it is still
    # `complete`-status-adjacent — `degraded` — but half its checks never fired.
    starved = {"modules": {
        whole: {"status": "complete", "sources_missing": []},
        partial: {"status": "degraded", "sources_missing": ["a", "b", "c"]}}}

    everything = [_f(c, "HIGH") for m in (whole, partial) for c in checks[m]]
    # The starved run finds nothing from the checks it could not run.
    survived = [_f(c, "HIGH") for c in checks[whole]] + \
               [_f(c, "HIGH") for c in checks[partial][:2]]

    full = posture_score.score(everything, intact)
    held_back = posture_score.score(survived, starved)
    assert full and held_back
    assert held_back[0] >= full[0], (
        "withholding sources improved the score: %s -> %s" % (full, held_back))


def test_a_degraded_module_is_not_credited_with_checks_it_never_ran():
    """The mechanism behind the test above, pinned directly.

    A check whose source was not supplied did not run, and counting it as
    assessed capacity is the four-state discipline inverted: "we could not look"
    becomes clean headroom that improves the number.
    """
    from modules.coverage import module_check_ids

    name = "btp_cloud_surface"
    declared = len(module_check_ids()[name])
    assert declared > 5, "fixture module has too few checks to be meaningful"

    intact = posture_score.assessed_check_count(
        {"modules": {name: {"status": "complete", "sources_missing": []}}})
    starved = posture_score.assessed_check_count(
        {"modules": {name: {"status": "degraded", "sources_missing": ["x"]}}})
    assert intact == declared, (
        "a module that ran on complete input should contribute every check it "
        "declares: %s vs %s" % (intact, declared))
    assert starved is None or starved < intact, (
        "a degraded module was credited with checks it could not run: %s" % starved)


def test_there_is_no_score_when_nothing_says_what_ran():
    """No denominator, no number. Consistent with the four-state discipline: we
    could not look is not the same as we looked and found nothing."""
    assert posture_score.score([_f("USR-001", "CRITICAL")], None) is None
    # A module that did not run contributes no checks to the denominator.
    assert posture_score.score(
        [], {"modules": {MODULES[0]: {"status": "not_run"}}}) is None
    # AND AN EMPTY MANIFEST IS NOT A DENOMINATOR OF ONE. This returned
    # (100, "Critical"): nothing ran, so the only checks known were the ones that
    # had produced findings, so by definition every check had found a critical.
    assert posture_score.score([_f("USR-001", "CRITICAL")], {"modules": {}}) is None


def test_one_check_contributes_once_however_many_objects_it_fires_on():
    """The numerator and the denominator must count the same unit.

    Summing per FINDING while dividing per CHECK let a check that fires on 500
    users add 500 findings' worth against one check of denominator. That made the
    printed ANCHOR false — "100 would mean every check found a critical" is only
    true if a check can contribute at most one critical — and it concentrated the
    withholding incentive in a few high-multiplicity checks.
    """
    from modules.coverage import module_check_ids

    cid = sorted(module_check_ids()[MODULES[0]])[0]
    once = posture_score.score([_f(cid, "CRITICAL")], BOTH)
    many = posture_score.score([_f(cid, "CRITICAL") for _ in range(50)], BOTH)
    assert once == many, (
        "the same check firing 50 times moved the score: %s -> %s" % (once, many))
    # ...and the worst result is the one that counts, not the first or the last.
    mixed = posture_score.score(
        [_f(cid, "LOW"), _f(cid, "CRITICAL"), _f(cid, "LOW")], BOTH)
    assert mixed == once, "a check did not score at its worst severity: %s" % (mixed,)


def test_the_scope_the_report_prints_is_the_denominator_it_used():
    """The number is a claim about the assessed portion, so the report states how
    much that was. A stale or invented count would make it decorative."""
    findings = [_f("USR-001", "CRITICAL")]
    scoped = posture_score.score_with_scope(findings, BOTH)
    assert scoped is not None
    value, band, assessed = scoped
    assert (value, band) == posture_score.score(findings, BOTH)
    assert assessed == posture_score.assessed_check_count(
        BOTH, (f["check_id"] for f in findings))
    assert str(assessed) in posture_score.scope_note(assessed)
    assert posture_score.score_with_scope(findings, None) is None


def test_a_clean_estate_scores_zero():
    assert posture_score.score([], BOTH) == (0, "Low")


# ─────────────────────────── the bands are the weights ──────────────────────

def test_every_band_floor_is_derived_from_a_severity_weight():
    """The bands must stay anchored to the arithmetic, because the report prints
    the anchor as a sentence. If somebody changes a weight and the floors do not
    follow, the page states a falsehood in plain English."""
    # THE CONCRETE VALUES FIRST. Deriving `expected` with the same expression the
    # source uses makes the comparison a tautology - it holds for any weights at
    # all, including a typo. These three numbers are what the reports print.
    assert [floor for floor, _ in posture_score.BANDS] == [40, 16, 4, 0], \
        "the published band floors changed: %s" % (posture_score.BANDS,)
    assert [label for _, label in posture_score.BANDS] == \
        ["Critical", "High", "Medium", "Low"]
    # ...and then that they are still the weights, so the two cannot drift.
    floors = {floor for floor, _ in posture_score.BANDS if floor}
    expected = {round(100 * w / posture_score.WORST_WEIGHT)
                for sev, w in posture_score.WEIGHTS.items()
                if w and sev != "CRITICAL"}
    assert floors == expected, (
        "band floors and severity weights disagree: %s vs %s" % (floors, expected))


@pytest.mark.parametrize("severity,expected", [
    ("CRITICAL", 100), ("HIGH", 40), ("MEDIUM", 16), ("LOW", 4)])
def test_the_anchor_the_report_prints_is_true(severity, expected):
    """"100 would mean every check that ran found a critical; 40, a high" — so
    construct exactly that estate and check the number comes out."""
    from modules.coverage import module_check_ids

    checks = sorted({cid for module in MODULES
                     for cid in module_check_ids().get(module, ())})
    assert checks, "no checks derived; the fixture is not exercising anything"
    findings = [_f(cid, severity) for cid in checks]
    scored = posture_score.score(findings, BOTH)
    assert scored and scored[0] == expected, (
        "one %s per check should score %d, got %s" % (severity, expected, scored))


def test_the_anchor_sentence_names_the_real_floors():
    """The prose and the table, held together. A sentence quoting stale numbers
    is exactly as misleading as a wrong number."""
    # PAIRS, NOT A BAG OF INTEGERS. Collapsing ANCHOR to a set of numbers threw
    # away the attachment between each number and its severity, so swapping "40,
    # a high" for "40, a low" left this passing. The sentence's whole job is that
    # attachment.
    pairs = {}
    for clause in posture_score.ANCHOR.split(";"):
        num = re.search(r"\b(\d+)\b", clause)
        sev = re.search(r"\b(critical|high|medium|low)\b", clause, re.I)
        if num and sev:
            pairs[sev.group(1).upper()] = int(num.group(1))
    assert len(pairs) == 4, "could not parse four number->severity pairs: %r" % pairs
    for severity, weight in posture_score.WEIGHTS.items():
        if not weight:
            continue
        expected = round(100 * weight / posture_score.WORST_WEIGHT)
        assert pairs.get(severity) == expected, (
            "ANCHOR pairs %s with %s, but its weight gives %d"
            % (severity, pairs.get(severity), expected))


# ─────────────────────────── and it reaches the page ────────────────────────

#: What a rendered page looks like to these tests: every run of visible text,
#: and the headline figure as the reader sees it.
Page = collections.namedtuple("Page", "text score")

#: Only text-showing operands. THE FIRST VERSION OF THIS SEARCHED THE RAW
#: DECOMPRESSED STREAM for a number near "OVERALL RISK" and found 9 for every
#: input — a glyph size out of a `Tm` matrix. A content stream is mostly
#: coordinates, so grepping one for "\d+" reads the typography, not the report.
_SHOWN = re.compile(r"\((?:[^()\\]|\\.)*\)")


def _html(findings, coverage, tmp_path):
    out = tmp_path / "r.html"
    with contextlib.redirect_stdout(io.StringIO()):
        ReportGenerator(findings, META, coverage=coverage).generate(str(out))
    page = out.read_text(encoding="utf-8")
    m = re.search(r'class="score-number"[^>]*>([^<]*)<', page)
    return Page(page, m.group(1).strip() if m else None)


def _pdf(findings, coverage, tmp_path):
    out = tmp_path / "r.pdf"
    with contextlib.redirect_stdout(io.StringIO()):
        PDFReportGenerator(findings, META, coverage=coverage).generate(str(out))
    parts = []
    for m in re.finditer(r"stream\r?\n(.*?)endstream",
                         out.read_bytes().decode("latin-1"), re.S):
        chunk = m.group(1).encode("latin-1")
        try:
            parts.append(zlib.decompress(chunk).decode("latin-1"))
        except Exception:                                        # noqa: BLE001
            parts.append(chunk.decode("latin-1"))
    runs = [w[1:-1] for w in _SHOWN.findall(" ".join(parts))]
    return Page(" ".join(runs), _after(runs, "OVERALL RISK"))


def _pptx(findings, coverage, tmp_path):
    out = tmp_path / "r.pptx"
    with contextlib.redirect_stdout(io.StringIO()):
        PPTXReportGenerator(findings, META, coverage=coverage).generate(str(out))
    with zipfile.ZipFile(out) as z:
        xml = " ".join(z.read(n).decode("utf-8") for n in z.namelist()
                       if "slide" in n and n.endswith(".xml"))
    runs = re.findall(r"<a:t>([^<]*)</a:t>", xml)
    return Page(" ".join(runs), _after(runs, "OVERALL RISK SCORE"))


def _after(runs, label):
    """The run immediately following the card's label."""
    for i, run in enumerate(runs):
        if label in run and i + 1 < len(runs):
            return runs[i + 1].strip()
    return None


RENDERERS = [_html, _pdf, _pptx]


@pytest.mark.parametrize("render", RENDERERS)
def test_the_rendered_number_moves_when_findings_close(render, tmp_path):
    """Rendered, not computed. Every one of these formats held its own copy of
    the formula, and a fix applied to two of three is the shape of bug this
    codebase keeps finding."""
    def number(findings):
        score = render(findings, BOTH, tmp_path).score
        assert score and score.isdigit(), \
            "no posture score found in the rendered output: %r" % score
        return int(score)

    # INPUTS THE OLD FORMULA CANNOT TELL APART. 40 criticals against 1 gives
    # 100 vs 25 under `min(100, crit*25 + ...)`, so `few < many` held even for a
    # renderer that had kept the old code — this test named the exact regression
    # it could not detect. 40 against 10 both saturate the old clamp at 100, so a
    # format left un-rebased now fails here.
    many = number([_f("USR-%03d" % i, "CRITICAL") for i in range(40)])
    few = number([_f("USR-%03d" % i, "CRITICAL") for i in range(10)])
    assert few < many, "the rendered score did not move: %d -> %d" % (many, few)
    assert many < 100, "saturated at the clamp; this cannot discriminate"


@pytest.mark.parametrize("render", RENDERERS)
def test_no_manifest_prints_no_number_in_any_format(render, tmp_path):
    """A report that cannot know its denominator says so. Printing 0, or 100, or
    a silently different scale would each be a claim we have no basis for."""
    page = render([_f("USR-001", "CRITICAL")], None, tmp_path)
    assert re.search(r"[Nn]ot scored|n/a", page.text), \
        "no manifest, but the page does not say the score is unavailable"
    assert "coverage manifest" in page.text, "nothing explains why there is no score"
    # A FAILED EXTRACTION ALSO SATISFIES "no digits", so require that something
    # was extracted before concluding it was not a number.
    assert page.score is not None, \
        "nothing extracted from the score position, so this proves nothing"
    assert not page.score.strip("\u2014 -").isdigit(), \
        "a number was printed anyway: %r" % page.score


@pytest.mark.parametrize("render", RENDERERS)
def test_every_format_explains_what_the_number_means(render, tmp_path):
    """A score nobody can interpret is decoration, and this one is a density
    rather than a percentage — the reading a slide invites by default."""
    page = render([_f("USR-001", "CRITICAL")], BOTH, tmp_path).text
    assert "every check that ran" in page, \
        "the number is printed with nothing to interpret it against"


def test_the_score_is_not_a_compliance_percentage(tmp_path):
    """modules/compliance_mapping.py forbids a percentage-secure figure. This is
    findings-per-check, and the page must not relabel it into the other thing."""
    page = _html([_f("USR-001", "CRITICAL")], BOTH, tmp_path).text
    # THE MARKUP, NOT THE STYLESHEET. `.risk-card` and `.severity-grid` are first
    # declared in the inlined <style> block ~265,000 characters before the markup
    # that uses them, so slicing on the first occurrence of each inspected two CSS
    # rules and never looked at the card at all.
    body = page[page.index("<body"):]
    region = body[body.index('class="risk-card"'):body.index('class="severity-grid"')]
    assert "score-number" in region, "the slice missed the posture card"
    for banned in ("% secure", "compliance score", "maturity"):
        assert banned.lower() not in region.lower(), \
            "the posture card is drifting into a compliance percentage: %r" % banned
