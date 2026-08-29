"""Every finding says whether the data behind it was complete.

WHY

The report already states, in aggregate, that some modules ran with incomplete
input — on the sample estate, 11 of 38. An individual finding said nothing, so a
conclusion drawn from a fraction of a module's evidence was indistinguishable
from one drawn from all of it. That is the same "confident answer over an
unasked question" this product reports on elsewhere, turning up in its own
output.

The marker is attached in BaseAuditor.finding(), beside the standards mapping
and for the same reason: one place, every check, no module having to remember.
It is always present rather than conditional — a finding that silently lacked
the field would be back to being unqualified.
"""
import io
import contextlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.base_auditor import BaseAuditor            # noqa: E402
from modules import coverage                            # noqa: E402
from modules.data_loader import DataLoader              # noqa: E402


class _Probe(BaseAuditor):
    """Stands in for a real auditor; `coverage` sees no sources for it."""

    def run_all_checks(self):
        return []


def make(data, optional=frozenset()):
    a = _Probe(data, {}, {})
    a.OPTIONAL_SOURCES = optional
    return a


def a_finding(auditor):
    return auditor.finding(check_id="X-1", title="t", severity="LOW",
                           category="c", description="d")


def test_every_finding_carries_the_marker():
    """Always present, never conditional."""
    f = a_finding(make({}))
    assert "evidence" in f and set(f["evidence"]) == {
        "complete", "declared_sources", "missing_sources"}


def test_the_marker_is_derived_from_the_same_map_the_manifest_uses():
    """A hand-maintained second list would drift the first time somebody added
    an input, and then the finding and the manifest would disagree."""
    assert coverage.module_sources.__wrapped__ is not None   # it is the cached map


def test_a_declared_source_that_is_absent_marks_the_finding_incomplete():
    a = make({})
    a.__class__.__module__ = "modules.vendor_master"          # borrow its sources
    a._evidence_cache = None
    f = a_finding(a)
    assert f["evidence"]["complete"] is False
    assert "vendor_master" in f["evidence"]["missing_sources"]


def test_supplied_but_empty_is_not_missing():
    """THE distinction. An export that was supplied and held no rows is a real
    answer; calling it missing would understate the evidence exactly as badly
    as the reverse understates the gap."""
    a = make({"vendor_master": [], "vendor_bank": []})
    a.__class__.__module__ = "modules.vendor_master"
    a._evidence_cache = None
    assert a_finding(a)["evidence"]["complete"] is True


def test_an_optional_source_does_not_mark_a_finding_incomplete():
    """Otherwise every ARA finding on an ordinary scan would be flagged because
    the customer did not supply a ruleset of their own — crying wolf."""
    a = make({}, optional=frozenset({"vendor_master", "vendor_bank"}))
    a.__class__.__module__ = "modules.vendor_master"
    a._evidence_cache = None
    assert a_finding(a)["evidence"]["complete"] is True


def test_the_default_is_required_not_optional():
    """A source wrongly marked optional makes the marker lie by staying quiet;
    one wrongly left required makes it noisy. Noise gets fixed."""
    assert BaseAuditor.OPTIONAL_SOURCES == frozenset()


def test_the_two_annotated_modules_only_exempt_self_reporting_inputs():
    """The bar for OPTIONAL_SOURCES is that the module already tells the reader
    in its own findings that the input was absent."""
    from modules.access_risk_analysis import AccessRiskAnalysisAuditor as ARA
    from modules.ruleset_coverage import RulesetCoverageAuditor as RC
    assert ARA.OPTIONAL_SOURCES == frozenset({"ara_ruleset"})
    assert "auth_object_catalogue" in RC.OPTIONAL_SOURCES
    assert "fiori_tiles" in RC.OPTIONAL_SOURCES
    assert "role_auth_values" not in RC.OPTIONAL_SOURCES   # the one it needs


def test_the_real_scan_marks_degraded_modules_and_not_the_rest():
    """End to end on the shipped fixture.

    THIS TEST USED TO ASSERT THE BUG. It required code_transport's findings to
    be badged incomplete, which was true only because the marker used the
    MODULE's declared sources: those findings are about custom code and the
    absent exports were auth_objects and dev_access_prod. Per-check
    attribution made them complete, and the test correctly failed.
    """
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(ROOT / 'sample_data').load_all()
    from modules.sap_hotnews import SapHotNewsAuditor as HN
    from modules.access_risk_analysis import AccessRiskAnalysisAuditor as ARA
    with contextlib.redirect_stdout(io.StringIO()):
        degraded = HN(data, {}, {}).run_all_checks()
        clean = ARA(data, {}, {}).run_all_checks()
    lost = [f for f in degraded if not f['evidence']['complete']]
    assert lost, 'expected the note checks to lose their catalogue'
    assert all('sap_security_notes' in f['evidence']['missing_sources']
               for f in lost)
    # ARA's only absent input is the optional custom ruleset
    assert clean and clean[0]['evidence']['complete'] is True

# ── and it has to reach the page ───────────────────────────────────────────
#
# The marker was attached to the finding dict and no renderer read it, so 150 of
# 408 findings carried complete:false and the deliverable said nothing. A
# qualification that never reaches the reader is the same failure it was built
# to fix, one layer up.

def _report_html(findings, tmp=[None]):
    """Render a report and read it back. `generate` writes to a path."""
    import tempfile, os
    from modules.report_generator import ReportGenerator
    meta = {"scan_date": "2026-08-29", "system": "SED", "client": "100"}
    d = tempfile.mkdtemp()
    out = os.path.join(d, "r.html")
    ReportGenerator(findings, meta).generate(out)
    with io.open(out, encoding="utf-8") as fh:
        return fh.read()


def _finding(complete=True, missing=None, check_id="X-1"):
    return {"check_id": check_id, "title": "t", "severity": "HIGH",
            "category": "c", "description": "d", "affected_items": [],
            "affected_count": 0, "remediation": "", "references": [],
            "details": {}, "timestamp": "2026-08-29T00:00:00",
            "evidence": {"complete": complete, "declared_sources": 3,
                         "missing_sources": missing or []}}


def test_an_incomplete_finding_is_badged_in_the_html():
    html = _report_html([_finding(False, ["vendor_master"])])
    assert 'class="ev-badge"' in html
    assert "partial data" in html


def test_the_badge_names_the_missing_exports():
    html = _report_html([_finding(False, ["vendor_master", "vendor_bank"])])
    assert "vendor_master, vendor_bank" in html


def test_a_complete_finding_is_not_badged():
    """Badging all 408 findings 'complete' would be noise, and the absence of
    the badge already carries that meaning once the coverage section explains
    it."""
    assert 'class="ev-badge"' not in _report_html([_finding(True)])


def test_the_body_says_what_the_gap_means_rather_than_only_naming_it():
    html = _report_html([_finding(False, ["vendor_master"])])
    assert "Evidence behind this finding" in html
    assert "the question was not asked" in html


def test_a_finding_with_no_marker_at_all_is_not_badged():
    """Findings can reach a renderer from a database round-trip that predates
    the field. They must not be reported as incomplete on that account."""
    f = _finding(True)
    del f["evidence"]
    assert 'class="ev-badge"' not in _report_html([f])


def test_the_coverage_section_counts_the_findings_not_just_the_modules():
    """The manifest counts MODULES that ran degraded. That cannot tell a reader
    which conclusions to weigh differently; this number can.

    Needs a manifest: the whole section is correctly omitted without one."""
    import os
    import tempfile
    from modules.report_generator import ReportGenerator
    findings = [_finding(False, ['a']), _finding(False, ['b']), _finding(True)]
    manifest = {'counts': {'sources_supplied': 10, 'sources_known': 12,
                           'modules_degraded': 1, 'modules_skipped': 0,
                           'modules_not_run': 0, 'sources_empty': 0},
                'modules': {}}
    out = os.path.join(tempfile.mkdtemp(), 'r.html')
    ReportGenerator(findings, {'scan_date': '2026-08-29'},
                    coverage=manifest).generate(out)
    with io.open(out, encoding='utf-8') as fh:
        html = fh.read()
    assert 'findings resting on partial data' in html
    assert '>2<' in html          # the finding count, not the module figure of 1


# ── per CHECK, not per module ──────────────────────────────────────────────
#
# The first version used the MODULE's declared sources and over-marked badly.
# code_transport declares auth_objects and dev_access_prod, so all 22 of its
# findings were badged "partial data" when those were absent -- including "SQL
# injection patterns detected in custom code", which reads custom_code_scan and
# could not care less about either.
#
# That is the failure mode that makes a warning worthless: a badge appearing
# where it plainly does not apply teaches a reader to ignore it, including on
# the findings where it does. On the sample estate it fell from 150 of 408
# findings to 18, and every survivor names a source that visibly bears on it.

def test_a_check_is_qualified_by_what_its_own_code_path_reads():
    from modules import coverage
    assert coverage.check_sources()["CODE-INJ-001"] == ["custom_code_scan"]


def test_reads_through_an_accessor_are_attributed_too():
    """Four modules read every input through a helper rather than a literal
    self.data.get(...). Without following those, they resolve to nothing and
    fall back to the whole module, which is the over-marking again."""
    from modules import coverage
    assert coverage.check_sources()["USR-001"] == ["users"]
    assert "auth_objects" not in coverage.check_sources()["USR-001"]


def test_an_unresolvable_check_keeps_the_module_wide_warning():
    """Ids built at run time cannot be attributed statically. Dropping the
    warning for them would hide a real gap, so unknown attribution keeps it."""
    from modules import coverage
    a = _Probe({}, {}, {})
    a.__class__.__module__ = "modules.vendor_master"
    a._evidence_cache = None
    assert "ARA-P2P-01" not in coverage.check_sources()      # runtime-built id
    ev = a._evidence_state("ARA-P2P-01")
    assert ev["complete"] is False                            # module fallback


def test_an_empty_resolution_is_not_treated_as_reading_nothing():
    """THE hole in the first attempt. A check whose inputs are read in
    run_all_checks and passed down resolves to [] because the walk follows a
    method into its helpers, not back out to its caller. Treating [] as 'reads
    nothing' would mark it complete on an estate that supplied none of its
    data — a silent all-clear."""
    from modules import coverage
    a = _Probe({}, {}, {})
    a.__class__.__module__ = "modules.vendor_master"
    a._evidence_cache = None
    empty = [cid for cid, srcs in coverage.check_sources().items() if not srcs]
    assert empty, "expected some checks to resolve empty"
    assert a._evidence_state(empty[0])["complete"] is False   # fell back


def test_the_real_scan_marks_only_the_checks_that_lost_an_input():
    """End to end: code_transport's findings are about custom code and must not
    be badged for a missing dev_access_prod export."""
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(ROOT / "sample_data").load_all()
    from modules.code_transport import CodeTransportAuditor as CT
    from modules.sap_hotnews import SapHotNewsAuditor as HN
    with contextlib.redirect_stdout(io.StringIO()):
        code = CT(data, {}, {}).run_all_checks()
        notes = HN(data, {}, {}).run_all_checks()
    assert code and all(f["evidence"]["complete"] for f in code)
    # ...while a check that genuinely lost its input stays badged
    lost = [f for f in notes if not f["evidence"]["complete"]]
    assert lost and all("sap_security_notes" in f["evidence"]["missing_sources"]
                        for f in lost)


# ── the trust statement has to be where it says to read it ─────────────────
#
# SODCOV-000's own description tells the reader to read it before the conflict
# results. It rendered as card 151 of 419, sorted in among them by severity —
# the same mistake the coverage block above it was moved to fix. A
# qualification nobody reaches is not a qualification.

def _trust_finding(verdict="unbounded", limits=("a role grants every tcode",)):
    return {"check_id": "SODCOV-000", "title": "This result is %s" % verdict.upper(),
            "severity": "HIGH", "category": "SoD Ruleset Coverage",
            "description": "Read this before the conflict results.",
            "affected_items": [], "affected_count": 0, "remediation": "",
            "references": [], "timestamp": "2026-08-29T00:00:00",
            "evidence": {"complete": True, "declared_sources": 1,
                         "missing_sources": []},
            "details": {"verdict": verdict, "limits": list(limits)}}


def test_the_trust_statement_renders_above_the_findings():
    html = _report_html([_finding(True, check_id="ZZZ-1"), _trust_finding()])
    assert 'class="trust-block' in html
    assert html.index('class="trust-block') < html.index('class="finding-card')


def test_it_is_not_also_shown_as_a_finding_card():
    """Rendering it twice puts the copy a reader reaches second 150 cards below
    the one that matters. Checked against the CARDS specifically: the block
    above carries the same id badge, which is not a duplicate."""
    import re
    html = _report_html([_finding(True, check_id="ZZZ-1"), _trust_finding()])
    cards = re.findall(r'class="finding-card".*?class="finding-id">([^<]+)<',
                       html, re.S)
    assert "ZZZ-1" in cards and "SODCOV-000" not in cards


def test_the_verdict_and_its_limits_are_both_shown():
    html = _report_html([_trust_finding(
        "partial", ("names 0% of the Fiori surface", "2 rules cannot fire"))])
    assert "PARTIAL" in html
    assert "names 0% of the Fiori surface" in html
    assert "2 rules cannot fire" in html


def test_a_report_without_the_statement_renders_normally():
    """Every other module runs without ruleset coverage, and the page must not
    depend on a finding that may not exist."""
    html = _report_html([_finding(True, check_id="ZZZ-1")])
    assert 'class="trust-block' not in html
    assert 'class="finding-card' in html


def test_the_other_formats_read_the_same_finding():
    """Recomputing the verdict per format is how three documents come to
    disagree about one estate."""
    import inspect
    from modules import pdf_report, pptx_report
    for mod in (pdf_report, pptx_report):
        src = inspect.getsource(mod)
        assert "_trust_statement" in src
        assert 'TRUST_CHECK_ID = "SODCOV-000"' in src
