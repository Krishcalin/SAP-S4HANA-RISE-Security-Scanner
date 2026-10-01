"""The generated log-based coverage matrix (docs/LOG_USE_CASES.md).

The CI gate (`--check`) catches a stale file. These catch the ways the GENERATOR
could produce a wrong document: a use case the catalogue has and the matrix does
not (or the reverse), a severity that no longer matches the code, or a mapping
pointing at an id that does not exist.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools import build_log_use_cases as gen            # noqa: E402

TARGET = ROOT / "docs" / "LOG_USE_CASES.md"


# ── the document is current ──────────────────────────────────────────────────
def test_the_committed_document_matches_the_code():
    assert TARGET.exists(), "docs/LOG_USE_CASES.md has not been generated"
    current = TARGET.read_text(encoding="utf-8").replace("\r\n", "\n")
    assert current == gen.build(), (
        "docs/LOG_USE_CASES.md is stale. Run: python -m tools.build_log_use_cases")


def test_the_document_says_it_is_generated():
    head = TARGET.read_text(encoding="utf-8")[:400]
    assert "GENERATED FILE" in head and "build_log_use_cases" in head


# ── the matrix is exactly the live set of log use cases ──────────────────────
def test_every_live_log_use_case_is_documented_and_no_phantoms():
    """THE DRIFT GUARD. The matrix must list exactly the catalogue's threat /
    violation / correlation log checks — add one (say GWLOG-004) without a row and
    this fails; delete one and leave the row and this fails too."""
    from modules.coverage import check_catalogue
    live = {c for c in check_catalogue() if c.startswith(gen.USE_CASE_PREFIXES)}
    authored = set(gen.authored_ids())
    assert authored == live, (
        "coverage matrix out of step with the catalogue: "
        "missing %s; phantom %s" % (sorted(live - authored), sorted(authored - live)))


def test_the_log_health_checks_are_not_in_the_matrix():
    """LREV-SRC/FLT/WIN are log-HEALTH checks, not threat use cases; they belong in
    the audit-log-configuration coverage, not here."""
    authored = set(gen.authored_ids())
    assert not any(c.startswith(("LREV-SRC", "LREV-FLT", "LREV-WIN")) for c in authored)


# ── severities come from the code, not the author ────────────────────────────
def test_severities_are_read_from_the_code():
    sev = gen.severities()
    assert sev["CORR-GW-001"] == "CRITICAL"
    assert sev["LREV-PAT-002"] == "CRITICAL"
    assert sev["GWLOG-002"] == "MEDIUM"
    assert sev["NETLOG-003"] == "HIGH"


def test_a_conditional_severity_reports_its_worst_branch():
    """LVIO-FF-001 is HIGH-if-outside else MEDIUM; the matrix reads the worst case."""
    assert gen.severities()["LVIO-FF-001"] == "HIGH"


def test_every_documented_severity_matches_the_rendered_row():
    sev = gen.severities()
    body = TARGET.read_text(encoding="utf-8")
    for cid in gen.authored_ids():
        line = next(l for l in body.splitlines() if l.startswith("| `%s`" % cid))
        assert (" %s " % sev[cid]) in line, cid


# ── the --check gate ─────────────────────────────────────────────────────────
def test_the_gate_passes_on_a_current_document():
    assert gen.main(["--check"]) == 0


def test_the_gate_fails_on_a_stale_document(monkeypatch, tmp_path):
    stale = tmp_path / "LOG_USE_CASES.md"
    stale.write_text("# something else\n", encoding="utf-8")
    monkeypatch.setattr(gen, "TARGET", stale)
    assert gen.main(["--check"]) == 1


def test_building_twice_produces_the_same_text():
    assert gen.build() == gen.build()
