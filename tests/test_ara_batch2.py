"""Every batch-2 rule must fire on its conflict, and only on its conflict.

WHAT THIS PINS, AND WHAT IT DOES NOT

The fixtures are derived from each rule's OWN predicates rather than
hand-transcribed. That deliberately does not test whether `C_ARPL_WRK` is really
the work-centre object — no test in this repository can, and `provenance` on each
rule says which tier its objects came from. What it does test is everything that
can go wrong between a rule being written and a rule being usable:

  satisfiable   a rule whose predicates cannot all be met by any grant fires for
                nobody, ever, and nothing else would notice. The matcher is
                fail-closed, so this is the silent failure mode for a new rule:
                it does not error, it just never speaks.
  conjunctive   one side alone is ordinary work. A rule that fires on half a
                conflict is a false positive on every user who does their job.
  not display   ACTVT 03 on both sides must stay silent. This is the loudly-wrong
                direction, and the one permission-level matching exists to
                prevent — a display user reported as a segregation conflict
                discredits every other finding in the report.

The plant-floor file hand-transcribes its nine cases and keeps doing so; this
file covers the forty added in batch 2, where transcription at that volume would
introduce more errors than it caught.
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.access_risk_analysis import AccessRiskAnalysisAuditor as ARA  # noqa: E402

#: The ids added in batch 2. Listed rather than computed so that removing a rule
#: makes a test disappear loudly instead of silently shrinking the suite.
BATCH2 = [
    "P2P-12", "P2P-13", "P2P-14", "P2P-15", "P2P-16",
    "O2C-10", "O2C-11", "O2C-12", "O2C-13", "O2C-14",
    "R2R-09", "R2R-10", "R2R-11", "R2R-12", "R2R-13",
    "H2R-05", "H2R-06", "H2R-07", "H2R-08", "H2R-09",
    "MFG-03", "MFG-04", "MFG-05",
    "INV-03", "INV-04", "INV-05",
    "QM-03", "QM-04",
    "PM-02", "PM-03", "PM-04",
    "PS-02", "PS-03",
    "WM-02", "WM-03", "WM-04",
    "BASIS-07", "BASIS-08",
    "CA-08", "CA-09",
]

BY_ID = {r["risk_id"]: r for r in ARA.RULESET}
SOD = [r for r in BATCH2 if BY_ID[r].get("risk_type", "SOD") == "SOD"]
CRITICAL = [r for r in BATCH2 if BY_ID[r].get("risk_type", "SOD") != "SOD"]


def rows_for(role, func, activity=None):
    """Grant exactly what one function asks for, to one role.

    `activity` overrides the rule's own activities — that is how the display-only
    case is built without assuming which activity each rule chose.
    """
    out = [{"AGR_NAME": role, "OBJECT": "S_TCODE", "AUTH": "T",
            "FIELD": "TCD", "LOW": t, "HIGH": ""}
           for t in func.get("actions", [])]
    for i, perm in enumerate(func.get("permissions", [])):
        for act in ([activity] if activity else perm.get("values", [])):
            out.append({"AGR_NAME": role, "OBJECT": perm["object"],
                        "AUTH": "A%d" % i, "FIELD": perm.get("field", "ACTVT"),
                        "LOW": act, "HIGH": ""})
    return out


def fired(rows, roles):
    a = ARA({"role_auth_values": rows,
             "user_roles": [{"UNAME": "U1", "AGR_NAME": r} for r in roles]})
    a.run_all_checks()
    return {f["check_id"] for f in a.findings}


@pytest.mark.parametrize("rid", SOD)
def test_each_rule_fires_on_its_own_conflict(rid):
    """Satisfiable. A rule whose predicates no grant can meet never speaks, and
    the fail-closed matcher makes that indistinguishable from a clean estate."""
    fa, fb = BY_ID[rid]["functions"]
    rows = rows_for("Z_A", fa) + rows_for("Z_B", fb)
    assert "ARA-%s" % rid in fired(rows, ["Z_A", "Z_B"])


@pytest.mark.parametrize("rid", SOD)
def test_one_side_alone_is_not_a_conflict(rid):
    fa, _fb = BY_ID[rid]["functions"]
    assert "ARA-%s" % rid not in fired(rows_for("Z_A", fa), ["Z_A"])


@pytest.mark.parametrize("rid", SOD)
def test_display_only_access_never_fires(rid):
    """The loudly-wrong direction. A display user named as a segregation
    conflict discredits every other finding on the report."""
    fa, fb = BY_ID[rid]["functions"]
    rows = rows_for("Z_A", fa, "03") + rows_for("Z_B", fb, "03")
    assert "ARA-%s" % rid not in fired(rows, ["Z_A", "Z_B"])


@pytest.mark.parametrize("rid", CRITICAL)
def test_each_critical_rule_fires_on_the_access_it_names(rid):
    func = BY_ID[rid]["functions"][0]
    assert "ARA-%s" % rid in fired(rows_for("Z_A", func), ["Z_A"])


@pytest.mark.parametrize("rid", CRITICAL)
def test_a_critical_rule_stays_silent_on_display_only(rid):
    func = BY_ID[rid]["functions"][0]
    assert "ARA-%s" % rid not in fired(rows_for("Z_A", func, "03"), ["Z_A"])


# ── properties of the batch as a whole ─────────────────────────────────────

def test_every_batch2_rule_is_present():
    missing = [r for r in BATCH2 if r not in BY_ID]
    assert not missing, "declared in this file but not in the ruleset: %s" % missing


def test_the_library_reached_ninetynine_risks():
    """The published count. Batch 1 took it 36 -> 59; batch 2 takes it to 99.
    Recorded here so a later change to the ruleset cannot move it quietly."""
    assert len(ARA.RULESET) == 99


def test_no_rule_discriminates_on_display_activity():
    """ACTVT 03 in a predicate is how a rule becomes a false-positive engine.
    Nothing in the library may carry one."""
    offenders = [r["risk_id"] for r in ARA.RULESET
                 for f in r.get("functions", [])
                 for p in f.get("permissions", [])
                 if "03" in p.get("values", [])]
    assert not offenders


def test_every_batch2_rule_declares_provenance_and_reasoning():
    """These were written from general SAP knowledge, not the object-by-object
    verification the original finance rules had. A reader of the ruleset must be
    able to tell the tiers apart without leaving the file."""
    for rid in BATCH2:
        r = BY_ID[rid]
        assert r.get("provenance"), "%s has no provenance note" % rid
        assert r.get("rationale"), rid
        assert r.get("references"), rid
        assert len(r["rationale"]) > 120, "%s rationale is too thin" % rid


def test_every_rule_has_at_least_one_permission_predicate():
    """A rule gated on transaction codes alone cannot separate display from
    change, which is the distinction most of these risks turn on."""
    bare = [r["risk_id"] for r in ARA.RULESET
            for f in r.get("functions", []) if not f.get("permissions")]
    assert not bare


def test_sod_rules_have_two_sides_and_critical_rules_have_one():
    for r in ARA.RULESET:
        n = len(r.get("functions", []))
        if str(r.get("risk_type", "SOD")).upper() == "SOD":
            assert n >= 2, "%s is a SOD rule with %d function(s)" % (r["risk_id"], n)
        else:
            assert n == 1, "%s is a critical rule with %d functions" % (r["risk_id"], n)


# ── the guard that generalises the two defects batch 2 shipped ─────────────
#
# Two batch-2 rules put the same transaction on both sides with permissions that
# overlapped, so ONE ordinary capability satisfied the whole conflict and the
# rule fired on every user who did half the job. Sharing a transaction is not
# itself wrong — BASIS-08 separates "define a job" from "assign its step user",
# both done in SM36, purely at permission level. What must never happen is a
# rule that one side alone can satisfy, so that is what is asserted, across the
# WHOLE library rather than just the rules added here.

ALL_SOD = [r["risk_id"] for r in ARA.RULESET
           if str(r.get("risk_type", "SOD")).upper() == "SOD"]


@pytest.mark.parametrize("rid", ALL_SOD)
def test_no_sod_rule_anywhere_fires_on_one_side_alone(rid):
    risk = BY_ID[rid]
    for i, func in enumerate(risk["functions"][:2]):
        rows = rows_for("Z_ONE", func)
        assert "ARA-%s" % rid not in fired(rows, ["Z_ONE"]), (
            "%s fires with only function %d (%s) granted — one side of a "
            "segregation pair is ordinary work"
            % (rid, i + 1, func.get("name", "?")))
