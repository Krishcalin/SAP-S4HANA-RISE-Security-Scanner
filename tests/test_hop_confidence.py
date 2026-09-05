"""A hop can ask how strong its evidence has to be.

THE LIMIT THIS CLOSES, in `docs/CVA_MERGE_PLAN.md`'s own words:

    Named limit: path hops match on `check_id` alone, so a `tentative` finding
    instantiates a path exactly like a `confirmed` one. Either add an optional
    hop-level `min_confidence` predicate — which changes `graph.instantiate()`
    and `_open_findings_by_check`, and therefore alters `ruleset_fingerprint`, so
    it is *not* a pure content change — or accept coarse matching for code hops.

It was deferred for a good reason: the grade did not discriminate. Every code
finding came back `confirmed`, so a predicate over it would have been a no-op
dressed as rigour. The call graph changed that, and on the drive database the
grade now reads 30 `confirmed` against 50 `pattern-only`.

WHY IT MATTERS THAT HOPS ARE WHERE THIS BITES. A hop's evidence is not just
displayed — `cut_findings` drives severing sets and choke-point ranking, so a
`pattern-only` match was making the console say "fix this and the path is cut"
about a statement pattern with no data-flow evidence behind it.

MEASURED, on the drive landscape, applying `min_confidence: tentative` to
SAPPATH-04's cut hop:

    paths instantiated   23 -> 23      (no path lost)
    total cut findings  171 -> 170
    SAPPATH-04 cuts      21 ->  20     dropped ABAP-CMDI-002, pattern-only, HIGH

A FINDING WITH NO CONFIDENCE PASSES, and that is the whole safety of it. Only
`ABAP-*` carries one; every configuration check and every `ATC-*` import has NULL.
SAPPATH-04's hop lists six ABAP checks beside eight configuration ones, so
treating NULL as "below the threshold" would drop the configuration evidence and
turn a tightening into a fail-closed regression across most of the hop.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server import graph  # noqa: E402


def finding(fid, check_id, confidence=None):
    return {"id": fid, "check_id": check_id, "severity": "HIGH", "system_id": 1,
            "subject": [], "priority_tier": "P2", "taint_confidence": confidence,
            "sid": "PRD", "client": "100", "tier": "prod"}


class _Conn:
    """Stands in for the connection `_open_findings_by_check` reads through."""

    def __init__(self, rows):
        self._rows = rows

    def execute(self, _sql, _params):
        return self

    def fetchall(self):
        return self._rows


def instantiate(rows, hop):
    template = {"paths": [{
        "id": "T-1", "name": "test", "severity": "HIGH",
        "hops": [dict({"name": "the hop", "required": True, "cut": True}, **hop)],
    }]}
    return graph.instantiate(_Conn(rows), 1, template)


# --------------------------------------------------------------------------- #
#  The predicate                                                               #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("confidence,expected", [
    ("confirmed", True),
    ("tentative", True),
    ("pattern-only", False),
])
def test_min_confidence_tentative_admits_all_but_pattern_only(confidence, expected):
    rows = [finding(1, "ABAP-CMDI-001", confidence)]
    paths = instantiate(rows, {"checks": ["ABAP-CMDI-001"],
                               "min_confidence": "tentative"})
    got = bool(paths and paths[0]["hops"][0]["findings"])
    assert got is expected


def test_min_confidence_confirmed_admits_only_confirmed():
    rows = [finding(1, "ABAP-CMDI-001", "confirmed"),
            finding(2, "ABAP-CMDI-001", "tentative")]
    paths = instantiate(rows, {"checks": ["ABAP-CMDI-001"],
                               "min_confidence": "confirmed"})
    assert [f["id"] for f in paths[0]["hops"][0]["findings"]] == [1]


def test_a_hop_without_the_key_behaves_exactly_as_before():
    """Every hop but one carries no `min_confidence`, and none of them may change."""
    rows = [finding(1, "ABAP-CMDI-001", "pattern-only")]
    paths = instantiate(rows, {"checks": ["ABAP-CMDI-001"]})
    assert len(paths[0]["hops"][0]["findings"]) == 1
    assert paths[0]["hops"][0]["min_confidence"] is None


# --------------------------------------------------------------------------- #
#  What must not be dropped                                                    #
# --------------------------------------------------------------------------- #

def test_a_finding_with_no_confidence_is_not_weak_evidence():
    """Only ABAP-* carries a confidence. A configuration check has NULL, and NULL
    means "this is not a SAST finding" — never "we could not tell". Reading it as
    below-threshold would silently drop the configuration half of a mixed hop."""
    rows = [finding(1, "AUTH-003", None), finding(2, "JOBCMD-CMD-001", None)]
    paths = instantiate(rows, {"checks": ["AUTH-003", "JOBCMD-CMD-001"],
                               "min_confidence": "confirmed"})
    assert len(paths[0]["hops"][0]["findings"]) == 2


def test_a_mixed_hop_keeps_its_configuration_evidence():
    """SAPPATH-04's real shape: six ABAP checks beside eight configuration ones.
    Raising the bar on the code evidence must not touch the rest."""
    rows = [finding(1, "ABAP-CMDI-002", "pattern-only"),
            finding(2, "AUTH-003", None),
            finding(3, "UCON-001", None)]
    paths = instantiate(rows, {"checks": ["ABAP-CMDI-002", "AUTH-003", "UCON-001"],
                               "min_confidence": "tentative"})
    kept = {f["id"] for f in paths[0]["hops"][0]["findings"]}
    assert kept == {2, 3}
    assert paths[0]["hops"][0]["excluded_as_weaker"] == 1


def test_the_hop_still_holds_when_only_weak_code_evidence_is_dropped():
    """The path must not disappear because one pattern match was excluded while
    real configuration evidence remains."""
    rows = [finding(1, "ABAP-CMDI-002", "pattern-only"), finding(2, "AUTH-003", None)]
    paths = instantiate(rows, {"checks": ["ABAP-CMDI-002", "AUTH-003"],
                               "min_confidence": "tentative"})
    assert paths, "the path stopped instantiating"
    assert paths[0]["hops"][0]["present"] is True


def test_a_required_hop_with_only_weak_evidence_stops_the_path():
    """The other direction, stated so it is a decision rather than an accident:
    if the ONLY evidence for a required hop is below the bar, the path does not
    hold. That is the predicate doing its job."""
    rows = [finding(1, "ABAP-CMDI-002", "pattern-only")]
    paths = instantiate(rows, {"checks": ["ABAP-CMDI-002"],
                               "min_confidence": "tentative"})
    assert paths == []


# --------------------------------------------------------------------------- #
#  Nothing is dropped silently                                                 #
# --------------------------------------------------------------------------- #

def test_what_was_excluded_is_counted():
    """A hop that drops evidence and says nothing is the fail-open shape: a
    shorter list, no reason for it, and a finding that would have been a cut
    simply absent."""
    rows = [finding(1, "ABAP-CMDI-001", "pattern-only"),
            finding(2, "ABAP-CMDI-001", "pattern-only"),
            finding(3, "ABAP-CMDI-001", "confirmed")]
    hop = instantiate(rows, {"checks": ["ABAP-CMDI-001"],
                             "min_confidence": "tentative"})[0]["hops"][0]
    assert hop["excluded_as_weaker"] == 2
    assert hop["min_confidence"] == "tentative"


def test_nothing_is_reported_excluded_when_nothing_was():
    rows = [finding(1, "ABAP-CMDI-001", "confirmed")]
    hop = instantiate(rows, {"checks": ["ABAP-CMDI-001"],
                             "min_confidence": "tentative"})[0]["hops"][0]
    assert hop["excluded_as_weaker"] == 0


def test_a_weak_finding_leaves_the_cut_set():
    """`cut_findings` is what drives severing sets and choke-point ranking, and
    it is the reason this predicate exists at all."""
    rows = [finding(1, "ABAP-CMDI-002", "pattern-only"), finding(2, "AUTH-003", None)]
    path = instantiate(rows, {"checks": ["ABAP-CMDI-002", "AUTH-003"],
                              "min_confidence": "tentative"})[0]
    assert 1 not in path["cut_findings"]
    assert 2 in path["cut_findings"]


# --------------------------------------------------------------------------- #
#  The shipped template, and the migration it implies                          #
# --------------------------------------------------------------------------- #

def test_the_rce_hop_asks_for_more_than_a_pattern_match():
    templates = graph.load_templates()
    hop = next(h for p in templates["paths"] for h in p.get("hops", [])
               if h["name"] == "OS command execution reachable")
    assert hop.get("min_confidence") == "tentative", (
        "SAPPATH-04's cut hop no longer raises the bar on code evidence")
    assert hop.get("cut") is True, (
        "this predicate was applied because the hop drives severing advice; if it "
        "has stopped being a cut, revisit whether it still earns the predicate")


def test_the_required_injectable_defect_hop_does_NOT_carry_it():
    """Measured, and the reason it is absent is the interesting half.

    SAPPATH-15's "Custom code carries an injectable defect" hop is `required`,
    and on the drive landscape the predicate excludes NOTHING from it — its
    evidence is ATC imports (no confidence at all) and confirmed ABAP findings.
    So it buys no precision, and being required it is the one hop where a weaker
    estate could lose the whole path rather than have its cut set trimmed.

    "Downgrade, never hide" is the contract `_refine` already runs on. Trimming a
    cut set downgrades a claim; removing a path hides one."""
    templates = graph.load_templates()
    hop = next(h for p in templates["paths"] if p["id"] == "SAPPATH-15"
               for h in p.get("hops", [])
               if h["name"] == "Custom code carries an injectable defect")
    assert hop.get("required") is True
    assert "min_confidence" not in hop, (
        "the required hop gained the predicate. Measured on the drive landscape "
        "it excluded nothing, and a landscape whose only evidence there is "
        "pattern-only would lose SAPPATH-15 entirely rather than lose two cuts.")


def test_the_optional_authority_hop_does_carry_it():
    """The same path's OPTIONAL cut hop, where the predicate excluded 2 findings
    and cannot remove a path however weak the evidence gets."""
    templates = graph.load_templates()
    hop = next(h for p in templates["paths"] if p["id"] == "SAPPATH-15"
               for h in p.get("hops", [])
               if h["name"] == "Nothing checks the caller's authority")
    assert hop.get("required") is False
    assert hop.get("cut") is True
    assert hop.get("min_confidence") == "tentative"


def test_every_hop_carrying_the_predicate_is_optional_or_has_other_evidence():
    """The rule the two decisions above amount to, stated once so a third
    application has to satisfy it: a REQUIRED hop whose checks are all code may
    not carry the predicate, because there is then nothing left to hold the path
    up when the code evidence is excluded."""
    templates = graph.load_templates()
    for path in templates["paths"]:
        for hop in path.get("hops", []):
            if not hop.get("min_confidence"):
                continue
            checks = hop.get("checks", [])
            all_code = checks and all(
                c.startswith(("ABAP-", "ATC-")) for c in checks)
            assert not (hop.get("required") and all_code), (
                "%s / %s is required and its evidence is entirely code checks, so "
                "raising the bar there can remove the path rather than trim it"
                % (path["id"], hop["name"]))


def test_the_predicate_is_part_of_the_fingerprint():
    """Not a pure content change, and the product already says so: stored paths
    carry the fingerprint they were derived under, and `path_summary` counts
    those that differ from the live one as `stale`. Adding this key moves the
    hash, every stored path reads stale until the next scan re-derives it, and
    the console shows that rather than quietly serving old conclusions."""
    import copy
    live = graph.load_templates()
    without = copy.deepcopy(live)
    for path in without["paths"]:
        for hop in path.get("hops", []):
            hop.pop("min_confidence", None)
    assert graph.ruleset_fingerprint(live) != graph.ruleset_fingerprint(without), (
        "the predicate does not move the fingerprint, so stored paths derived "
        "under the old rules would never be reported as stale")


@pytest.mark.parametrize("bad", ["", None, "nonsense"])
def test_an_unusable_threshold_admits_everything(bad):
    """A typo in the template must not silently empty a hop. An unknown word
    ranks at zero, which every real confidence meets."""
    rows = [finding(1, "ABAP-CMDI-001", "pattern-only")]
    paths = instantiate(rows, {"checks": ["ABAP-CMDI-001"], "min_confidence": bad})
    assert paths and len(paths[0]["hops"][0]["findings"]) == 1
