"""Cross-procedure evidence depth: the honest caller sub-chain.

The engine already decides a parameter is tainted when a visible caller passes it
a non-literal (call-graph seeding). What it did NOT do was SHOW the reader where
that value came from: the trace stopped at the immediate PERFORM. This adds a
nested `caller_flow` on the call hop that chases the value back, same artefact,
bounded, through every real statement on the way.

THE RULE. The top-level flow shape is UNCHANGED (so every pinned trace test still
holds); `caller_flow` is an additive, nested extension; and it never invents a
step — a procedure with no visible caller gets no hop, and every step names a
statement that exists.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.abap_sast import AbapSourceScanner  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "abap" / "interproc_vulnerable.prog.abap"


def _scan():
    return AbapSourceScanner(data_flow=True).scan_text(
        FIXTURE.read_text(encoding="utf-8"), FIXTURE)


def _at(found, line):
    hits = [f for f in found if f.get("line") == line and f.get("flow")]
    assert hits, f"no flow-bearing finding at line {line}"
    return hits[0]


def _all_steps(flow):
    for s in flow or []:
        yield s
        yield from _all_steps(s.get("caller_flow"))


def test_two_hop_chain_reaches_the_ultimate_source():
    """inner()'s sink is two PERFORMs from the selection screen. The nested
    caller_flow must walk call(L33) -> call(L21) -> source p_tab(L12)."""
    inner = _at(_scan(), 38)
    flow = inner["flow"]
    # top-level shape unchanged: call, source, sink
    assert [s["role"] for s in flow] == ["call", "source", "sink"]
    steps = list(_all_steps(flow))
    assert any(s["role"] == "call" and s["line"] == 21 for s in steps), \
        "intermediate FORM outer (L21) not shown"
    assert any(s["role"] == "source" and s["line"] == 12 for s in steps), \
        "selection-screen source p_tab (L12) not reached"


def test_every_step_names_a_real_statement():
    for cid_line in (38, 29, 71):
        f = _at(_scan(), cid_line)
        for s in _all_steps(f["flow"]):
            assert s.get("line"), s
            assert str(s.get("code") or "").strip(), s


def test_one_hop_chain_shows_its_source():
    rq = _at(_scan(), 29)                     # FORM run_query, WHERE (iv_carrid)
    hop = rq["flow"][0]
    assert hop["role"] == "call" and hop["line"] == 17
    assert any(s["line"] == 12 for s in hop.get("caller_flow") or []), \
        "p_carr source not shown under the call hop"


def test_a_procedure_with_no_visible_caller_gets_no_invented_hop():
    orphan = _at(_scan(), 55)                 # FORM orphan: nobody calls it here
    assert orphan["flow"][0]["role"] != "call"
    assert all("caller_flow" not in s for s in _all_steps(orphan["flow"])), \
        "a caller_flow was fabricated where there is no caller"


def test_top_level_steps_keep_their_shape():
    """caller_flow is a nested addition; the existing top-level step keys and the
    confidence are untouched (so aggregation / FAIR / the pinned tests are too)."""
    rq = _at(_scan(), 29)
    assert [s["role"] for s in rq["flow"]] == ["call", "source", "sink"]
    assert set(rq["flow"][0]) >= {"line", "role", "var", "code"}
    assert rq.get("confidence") == "confirmed"
