# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""Three things the product used to assert and could not do.

Each was found the same way — by checking whether a claim in the code matched the
code — and each had survived because nobody had looked. They are grouped here
because they share a failure mode, not a subsystem: a sentence that outruns the
implementation is a defect even when every test passes.
"""
import contextlib
import io
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import fair_adapter as fa                       # noqa: E402
from modules.data_loader import DataLoader                   # noqa: E402
from modules.sap_hotnews import SapHotNewsAuditor            # noqa: E402


# ── 1. the industry multiplier that never existed ────────────────────────────

def test_industry_does_not_change_the_figure():
    """It never has. --crq-industry sets a LABEL on the report.

    Measured before the fix: financial_services and education produced the
    identical P90, while the PDF told the auditor the loss was "scaled to the
    stated revenue/industry".
    """
    a = fa.run([], [], org_overrides={"industry": "financial_services"},
               simulations=400)["summary"]["portfolio"]["ale_p90"]
    b = fa.run([], [], org_overrides={"industry": "education"},
               simulations=400)["summary"]["portfolio"]["ale_p90"]
    assert a == b


def test_nothing_shipped_claims_an_industry_multiplier():
    """THE ACTUAL DEFECT WAS THE SENTENCE, NOT THE FLAG.

    Four places asserted a scaling step the engine does not perform: the
    catalogue's own _meta, the HTML report, the PDF, and the CLI help. A reader
    has no way to check, which is exactly why it survived.
    """
    banned = re.compile(r"industry multiplier|revenue/industry|"
                        r"for the (FAIR )?loss multiplier", re.I)
    allowed = re.compile(r"no industry multiplier|scales nothing|"
                         r"never has been|does not exist", re.I)
    offenders = []
    for path in [ROOT / "README.md", ROOT / "sap_scanner.py",
                 ROOT / "data" / "fair_scenarios.json",
                 ROOT / "modules" / "report_generator.py",
                 ROOT / "modules" / "pdf_report.py",
                 ROOT / "modules" / "crq_engine.py"]:
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if banned.search(line) and not allowed.search(line):
                offenders.append(f"{path.name}:{n}")
    assert not offenders, f"these claim an industry multiplier: {offenders}"


def test_the_engines_unused_parameter_is_named_as_unused():
    """It was `organization` for months, which read as though the engine scaled by
    revenue or industry. The underscore is the only in-code evidence a reader
    gets, since the parameter is still accepted for signature compatibility."""
    import inspect
    from modules.crq_engine import FAIREngine
    params = inspect.signature(FAIREngine.simulate_scenario).parameters
    assert "_organization" in params
    assert "organization" not in params


def test_the_detection_multiplier_is_real_and_is_not_the_same_claim():
    """The dwell-time multiplier DOES exist and is cited. Retracting the phantom
    must not sweep away a real one."""
    catalogue = fa.load_catalog()
    detection = catalogue.get("detection") or {}
    assert detection.get("multiplier_by_worst_severity")
    assert detection.get("sources"), "a real multiplier carries its sources"


# ── 2. the pass rate that was drawn as a compliance score ────────────────────

TREND = ROOT / "frontend" / "src" / "routes" / "Trend.tsx"


def test_the_console_does_not_head_a_column_compliant():
    """"78% Compliant" claims conformance with something external. It is the pass
    rate over the checks that actually ran — a statement about our own checks."""
    assert ">Compliant<" not in TREND.read_text(encoding="utf-8")


def test_the_pass_rate_has_no_severity_blind_traffic_light():
    """THE COLOUR WAS WORSE THAN THE WORD.

    green >= 80 / amber >= 60 / red asserts that eighty per cent passing is good,
    and it ignores severity entirely: sixteen passes and four CRITICAL failures
    is eighty per cent and rendered green.
    """
    source = TREND.read_text(encoding="utf-8")
    assert "pct >= 80" not in source
    assert not re.search(r"pct\s*>=\s*\d+\s*\?\s*'var\(--ok\)'", source)


def test_the_pass_rate_is_still_measured_over_checks_that_ran():
    """The number is defensible and was NOT deleted. Scoring against the whole
    catalogue would let a customer improve their score by supplying fewer
    exports, which is the trap the server-side comment already names."""
    source = (ROOT / "server" / "analytics.py").read_text(encoding="utf-8")
    assert "pct_compliant" in source
    assert "DISTINCT ran.check_id" in source


# ── 3. the note catalogue that stopped in April 2025 ─────────────────────────

@pytest.fixture(scope="module")
def hotnews_findings():
    with contextlib.redirect_stdout(io.StringIO()):
        data = DataLoader(ROOT / "sample_data").load_all()
        return SapHotNewsAuditor(data, {}).run_all_checks()


def test_the_note_check_always_discloses_what_it_compared_against(hotnews_findings):
    """A clean HotNews section is the most reassuring thing this product prints,
    and it was printed off a curated subset whose newest entry predates the report
    by more than a year, with nothing saying so.

    "No missing notes from a list that stops in April 2025" and "you are patched"
    are different statements. Only the first is ours to make.
    """
    scope = [f for f in hotnews_findings if f["check_id"] == "HOTNEWS-COVERAGE"]
    assert len(scope) == 1, "the scope disclosure must be emitted on every run"


def test_the_disclosure_fires_even_when_nothing_is_missing(hotnews_findings):
    """Unconditional is the whole point: the reassuring case is the dangerous one."""
    missing = [f for f in hotnews_findings if f["check_id"] in ("HOTNEWS-001", "HOTNEWS-002")]
    scope = [f for f in hotnews_findings if f["check_id"] == "HOTNEWS-COVERAGE"]
    assert scope, f"no disclosure, with {len(missing)} missing-note finding(s)"


def test_the_disclosure_names_the_cut_off_and_the_size(hotnews_findings):
    scope = next(f for f in hotnews_findings if f["check_id"] == "HOTNEWS-COVERAGE")
    details = scope["details"]
    assert details["curated_through"] == SapHotNewsAuditor.CATALOG_META["curated_through"]
    assert details["catalogue_size"] == len(SapHotNewsAuditor.HOTNEWS_CATALOG)
    assert str(details["catalogue_size"]) in scope["description"]
    assert details["curated_through"] in scope["description"]


def test_the_disclosure_degrades_coverage(hotnews_findings):
    """So the release gate treats a stale catalogue as a coverage problem rather
    than a clean bill — the mechanism that already exists for ABAP-COV-*."""
    scope = next(f for f in hotnews_findings if f["check_id"] == "HOTNEWS-COVERAGE")
    assert scope["details"]["degrades_coverage"] is True


def test_the_catalogue_declares_its_own_cut_off():
    """data/ecs_hardening_3250501.json already carried version/released/obtained.
    The discipline existed in the repository and had simply not been applied."""
    meta = SapHotNewsAuditor.CATALOG_META
    assert meta.get("curated_through")
    assert "CURATED SUBSET" in meta.get("note", "")


def test_the_declared_cut_off_matches_the_newest_note():
    """A hand-maintained date drifts the moment somebody adds a note and forgets.
    This fails the moment they disagree."""
    newest = max(e.get("released", "") for e in SapHotNewsAuditor.HOTNEWS_CATALOG)
    assert SapHotNewsAuditor.CATALOG_META["curated_through"] == newest
