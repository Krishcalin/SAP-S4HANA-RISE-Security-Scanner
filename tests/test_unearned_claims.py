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


def test_no_percentage_anywhere_is_named_for_compliance():
    """THE COLUMN WAS RENAMED AND THE FIELD BEHIND IT WAS NOT.

    The architecture guide states twice, without qualification, that there is
    deliberately no compliance percentage anywhere in the product. That was true
    of every label a customer could see and false of the JSON underneath it:
    `domain_scorecard` returned `pct_compliant`, the console's `DomainScore`
    carried it, and any integrator reading the API got a number called compliance
    from a product whose written position is that it does not produce one.

    The note in `types.ts` argued a rename was a breaking change not worth making
    for one word. The word was the entire claim, and the console — in this
    repository — was the only consumer.

    Derived rather than listed: any key or field pairing a proportion with
    conformance is the defect, whatever it ends up called.
    """
    suspect = re.compile(
        r"\b\w*(?:pct|percent|rate|score)\w*compl\w*\b"
        r"|\b\w*compl(?:iant|iance)\w*(?:pct|percent|rate|score)\w*\b", re.I)

    offenders = []
    surfaces = sorted((ROOT / "server").glob("*.py"))
    surfaces.append(ROOT / "frontend" / "src" / "api" / "types.ts")
    for path in surfaces:
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            # Prose about the rename is the record of it; the identifier is not.
            stripped = line.strip()
            if stripped.startswith(("#", "*", "//", "/*")):
                continue
            if suspect.search(line):
                offenders.append(f"{path.name}:{n}: {stripped[:80]}")
    assert not offenders, (
        "a percentage is named for compliance, which the guide says the product "
        "does not produce: %s" % offenders)


def test_the_promise_this_enforces_is_still_written_down():
    """An enforcement with no claim behind it is a rule nobody can argue with.
    If the guide ever stops promising this, the test above should be revisited
    rather than silently outliving its reason."""
    guide = (ROOT / "docs" / "ARCHITECTURE.md").read_text(encoding="utf-8")
    assert "no compliance percentage" in guide


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
    exports, which is the trap the server-side comment already names.

    THIS TEST USED TO ASSERT A SQL FRAGMENT — `"DISTINCT ran.check_id" in
    source` — which pinned the implementation rather than the property, and went
    red the moment the denominator was fixed to something better. It now asserts
    what it was always protecting: that supplying less cannot score more.
    """
    source = (ROOT / "server" / "analytics.py").read_text(encoding="utf-8")
    assert "pct_passing" in source

    # ASSERTED BY RUNNING IT, not by grepping for the helper of the day. This
    # test has now been rewritten twice because it named an implementation: first
    # a SQL fragment, then the two functions the scorecard imported before
    # `look_verdict` took the question over. The property has not changed once.
    from server.analytics import _score_rows

    nothing_scanned = _score_rows(observed={}, failing={}, coverage=None)
    assert nothing_scanned, "no rows produced"
    assert all(r["pct_passing"] is None for r in nothing_scanned), \
        "a category nobody scanned was given a pass rate"

    starved = {"modules": {"user_auth_audit": {"status": "complete"}}}
    partial = _score_rows(observed={}, failing={}, coverage=starved)
    unassessed = [r for r in partial if not r["assessed"]]
    assert unassessed, "supplying one module out of thirty scored every category"
    assert all(r["pct_passing"] is None for r in unassessed)


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


def test_adjacent_system_notes_are_disclosed_not_alarmed():
    """RECON is an AS Java note. An S/4HANA ABAP export carries no evidence
    about the Java system, so rendering RECON as "missing" here was a false
    alarm — but silently dropping an exploited-in-the-wild note would be worse.
    It must move to the HOTNEWS-005 disclosure, exploited flag intact."""
    with contextlib.redirect_stdout(io.StringIO()):
        findings = SapHotNewsAuditor({"applied_notes": []}, {}).run_all_checks()
    by_id = {f["check_id"]: f for f in findings}
    for cid, key in (("HOTNEWS-001", "missing_notes"), ("HOTNEWS-003", "exploited_notes")):
        listed = by_id.get(cid, {}).get("details", {}).get(key, [])
        assert "2934135" not in listed, f"RECON alarmed as missing in {cid}"
    scope = by_id["HOTNEWS-005"]
    assert "2934135" in scope["details"]["unassessable_notes"]
    assert any("2934135" in i and "EXPLOITED" in i for i in scope["affected_items"])


def test_high_priority_missing_still_fires_via_the_merge_path():
    """After applies_to scoping, the only built-in High entry (3123427) is an
    AS Java note, so an ABAP sample can no longer exercise HOTNEWS-002. The
    merge path can: an operator-supplied ABAP High entry that is not
    implemented must still raise it."""
    data = {"applied_notes": [],
            "sap_security_notes": [{"note": "9990001", "priority": "High",
                                    "cvss": 8.0, "applies_to": "abap",
                                    "title": "synthetic High note"}]}
    with contextlib.redirect_stdout(io.StringIO()):
        findings = SapHotNewsAuditor(data, {}).run_all_checks()
    high = next(f for f in findings if f["check_id"] == "HOTNEWS-002")
    assert "9990001" in high["details"]["missing_notes"]


def test_component_prereq_needs_positive_evidence_of_absence():
    """The SLT note (3633838) requires the DMIS add-on. With a component export
    that lacks DMIS it moves to the disclosure bucket; with NO component export
    the add-on is unknown and the entry stays counted — the fail-safe direction
    is a false alarm, never a silent pass."""
    with contextlib.redirect_stdout(io.StringIO()):
        unknown = SapHotNewsAuditor({"applied_notes": []}, {}).run_all_checks()
        absent = SapHotNewsAuditor({"applied_notes": [],
                                    "system_component": [{"COMPONENT": "SAP_BASIS"}]},
                                   {}).run_all_checks()
    missing_unknown = next(f for f in unknown if f["check_id"] == "HOTNEWS-001")
    assert "3633838" in missing_unknown["details"]["missing_notes"]
    missing_absent = next(f for f in absent if f["check_id"] == "HOTNEWS-001")
    assert "3633838" not in missing_absent["details"]["missing_notes"]
    scope = next(f for f in absent if f["check_id"] == "HOTNEWS-005")
    assert "3633838" in scope["details"]["unassessable_notes"]
