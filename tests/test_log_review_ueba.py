"""UEBA-lite — peer-relative behaviour outliers in the Security Audit Log review.

modules/log_review.py profiles every account in the exported window and flags the
ones that stand out from their peers on one axis: volume (LREV-UEBA-001), distinct
transactions (LREV-UEBA-002) and distinct terminals (LREV-UEBA-003). What must
hold: it is a WITHIN-WINDOW, PEER-RELATIVE measure (the findings say so, never a
learned baseline); it needs a population (too few accounts -> LREV-UEBA-000, the
outlier checks stay silent); an absolute floor stops a tiny/quiet estate from
flagging noise; a uniform population flags nobody; and a blank-user event never
forms a phantom peer.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.log_review import LogReviewAuditor   # noqa: E402


def _ev(user, tcode="T0", terminal="WS", date="20260101"):
    return {"DATE": date, "USER": user, "TCODE": tcode, "TERMINAL": terminal}


def _run(rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    findings = LogReviewAuditor({"security_audit_log": rows}).run_all_checks()
    return {f["check_id"]: f for f in findings if f["check_id"].startswith("LREV-UEBA")}


def _population(n_users=8, events_each=5):
    """n quiet, uniform accounts — a comparison population with no outlier."""
    rows: List[Dict[str, Any]] = []
    for u in range(n_users):
        for i in range(events_each):
            rows.append(_ev(f"U{u}", tcode=f"T{i % 2}", terminal=f"WS{u}"))
    return rows


# ═════════════════════════════════════════════════════════════════════════════
#  Needs a population: too few accounts -> disclosure, not an invented comparison
# ═════════════════════════════════════════════════════════════════════════════

def test_too_few_accounts_discloses_and_runs_no_outlier_check():
    f = _run(_population(n_users=3))
    assert "LREV-UEBA-000" in f and f["LREV-UEBA-000"]["severity"] == "INFO"
    assert not any(c in f for c in ("LREV-UEBA-001", "LREV-UEBA-002", "LREV-UEBA-003"))


def test_no_disclosure_when_the_population_is_large_enough():
    f = _run(_population(n_users=8))
    assert "LREV-UEBA-000" not in f


def test_no_events_is_silent():
    assert _run([]) == {}


# ═════════════════════════════════════════════════════════════════════════════
#  The three outliers fire against a population
# ═════════════════════════════════════════════════════════════════════════════

def test_volume_outlier_fires_and_names_the_account():
    rows = _population(8) + [_ev("BATCH", tcode="T0", terminal="WS") for _ in range(200)]
    f = _run(rows)
    assert "LREV-UEBA-001" in f and f["LREV-UEBA-001"]["severity"] == "MEDIUM"
    assert any("BATCH" in it for it in f["LREV-UEBA-001"]["affected_items"])
    # within-window, peer-relative framing — never a learned baseline
    assert "not a learned baseline" in f["LREV-UEBA-001"]["description"]


def test_transaction_breadth_outlier_fires():
    rows = _population(8) + [_ev("ADM", tcode=f"TX{i}", terminal="WS") for i in range(40)]
    f = _run(rows)
    assert "LREV-UEBA-002" in f
    assert any("ADM" in it for it in f["LREV-UEBA-002"]["affected_items"])


def test_terminal_breadth_outlier_fires():
    rows = _population(8) + [_ev("ROAM", tcode="T0", terminal=f"HOST{i}") for i in range(12)]
    f = _run(rows)
    assert "LREV-UEBA-003" in f
    assert any("ROAM" in it for it in f["LREV-UEBA-003"]["affected_items"])


# ═════════════════════════════════════════════════════════════════════════════
#  Honesty: uniform population, the absolute floor, and blank users
# ═════════════════════════════════════════════════════════════════════════════

def test_a_uniform_population_flags_nobody():
    f = _run(_population(n_users=10, events_each=5))
    assert not any(c in f for c in ("LREV-UEBA-001", "LREV-UEBA-002", "LREV-UEBA-003"))


def test_the_floor_stops_a_small_estate_from_flagging_noise():
    # 8 users at 5 events; one user at 40 — 8x the median, but below the volume
    # floor (100), so it is NOT a volume outlier. The floor is what keeps a quiet
    # estate from calling its busiest-but-ordinary account an anomaly.
    rows = _population(8) + [_ev("A", terminal="WS") for _ in range(40)]
    f = _run(rows)
    assert "LREV-UEBA-001" not in f


def test_blank_user_events_do_not_form_a_phantom_peer():
    # Events with no user must not count as an account in the population. This test
    # includes a REAL named outlier (BATCH) so LREV-UEBA-001 actually FIRES — the
    # assertion body runs — and 200 blank-user events, ABOVE the volume floor (100):
    # if the blank-user exclusion in _user_profiles were removed, "" would itself be
    # a volume outlier and produce an affected_item beginning ":", which the final
    # assert would catch. (The earlier version used 50 blank events, below the floor,
    # so no check ever fired and the assertion never ran — a false green.)
    rows = (_population(8)
            + [_ev("BATCH", tcode="T0", terminal="WS") for _ in range(200)]
            + [_ev("", tcode="T0", terminal="WS") for _ in range(200)])
    f = _run(rows)
    assert "LREV-UEBA-001" in f                           # the outlier check fired
    items = f["LREV-UEBA-001"]["affected_items"]
    assert any("BATCH" in it for it in items)             # names the real account
    assert all(not it.startswith(":") for it in items)    # never the blank user
