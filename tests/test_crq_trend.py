# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""The trend's series-break guard.

SEPARATE FROM tests/test_fair_cam.py FOR ONE REASON: these import server.crq,
which imports psycopg, and the `cli` CI job installs pytest AND NOTHING ELSE
across Python 3.8-3.12. Keeping them together cost the FAIR-CAM tests their run
on that matrix — which is exactly where a stdlib-only module most needs testing.
So the pure ones stay pure and these live here, in the server job's scope.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


# ── the trend's series break ─────────────────────────────────────────────────

def test_the_fingerprint_ignores_the_findings_and_the_answer():
    """It must cover everything that is NOT remediation, and nothing that is.

    If the finding count or the ALE fed the fingerprint, the line would break on
    every scan and the guard would be useless.
    """
    from server import crq
    base = {"detail": {"simulations": 10000, "organization": {"revenue": 1e9},
                       "exposure_weight": 1.0}}
    same_model_new_findings = {"detail": dict(base["detail"]),
                               "ale_p90": 999, "input_finding_count": 42}
    assert crq._inputs_fingerprint(base) == crq._inputs_fingerprint(same_model_new_findings)


def test_the_fingerprint_changes_when_the_money_assumptions_change():
    from server import crq
    a = {"detail": {"simulations": 10000, "organization": {"revenue": 1e9}}}
    b = {"detail": {"simulations": 10000, "organization": {"revenue": 4.2e8}}}
    assert crq._inputs_fingerprint(a) != crq._inputs_fingerprint(b)


def test_the_fingerprint_changes_when_the_simulation_count_changes():
    from server import crq
    a = {"detail": {"simulations": 10000, "organization": {}}}
    b = {"detail": {"simulations": 50000, "organization": {}}}
    assert crq._inputs_fingerprint(a) != crq._inputs_fingerprint(b)


def test_the_fingerprint_survives_a_missing_or_malformed_detail():
    """crq_result.detail is jsonb and older rows predate these keys."""
    from server import crq
    for row in ({}, {"detail": None}, {"detail": "not a dict"}, {"detail": {}}):
        assert isinstance(crq._inputs_fingerprint(row), str)


def test_the_residual_floor_is_none_rather_than_zero_when_absent():
    """Zero would draw a floor at the axis and claim risk can be eliminated."""
    from server import crq
    assert crq._residual_p90({}) is None
    assert crq._residual_p90({"detail": {}}) is None
    assert crq._residual_p90({"detail": {"target_portfolio": {"ale_p90": 12.5}}}) == 12.5
