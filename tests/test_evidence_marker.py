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
    """End to end on the shipped fixture."""
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(ROOT / "sample_data").load_all()
    from modules.code_transport import CodeTransportAuditor as CT
    from modules.access_risk_analysis import AccessRiskAnalysisAuditor as ARA
    with contextlib.redirect_stdout(io.StringIO()):
        degraded = CT(data, {}, {}).run_all_checks()
        clean = ARA(data, {}, {}).run_all_checks()
    assert degraded and degraded[0]["evidence"]["complete"] is False
    assert degraded[0]["evidence"]["missing_sources"]
    # ARA's only absent input is the optional custom ruleset
    assert clean and clean[0]["evidence"]["complete"] is True
