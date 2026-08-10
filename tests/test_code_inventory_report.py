# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
The custom-code inventory as a deliverable.

This module reports numbers a consultant puts in front of a customer, so the tests
here protect two things that are easy to get wrong and expensive to get wrong:

1. IT MUST NOT INVENT AN ESTATE. No export, an empty export, or rows with no
   object name must produce nothing at all. "0 custom objects" is an assertion
   about the customer's system; silence is the truth when we measured nothing.

2. `unknown` MUST NEVER BECOME `unreachable`. The whole value of the unreachable
   count is that somebody can act on it — delete the code. An object we simply
   know nothing about, swept into that list to make the number bigger, is how a
   security report gets someone to delete a program that runs the year-end close.

Everything else is severity discipline: an inventory statistic that shouts is a
report people stop reading, and these tests hold the ceiling at LOW.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import reachability                                    # noqa: E402
from modules.code_inventory_report import CodeInventoryAuditor      # noqa: E402
from modules.reachability import UNREACHABLE                        # noqa: E402

#: Fixed "today" so a fixture date cannot silently cross the staleness horizon as
#: the calendar moves and flip a test's meaning without anyone editing it.
TODAY = 20260807
RECENT = "20260801"
OLD = "20180101"

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def row(name, obj_type="PROG", referenced="", last_used=""):
    return {"OBJECT_NAME": name, "OBJECT_TYPE": obj_type,
            "REFERENCED": referenced, "LAST_USED": last_used}


def run(rows, today=TODAY):
    return CodeInventoryAuditor({"code_inventory": rows}, {}, today=today).run_all_checks()


def by_id(findings):
    return {f["check_id"]: f for f in findings}


#: An estate in perfect order: every object referenced and recently executed.
HEALTHY = [row("Z_LIVE_RPT", "PROG", "YES", RECENT),
           row("Z_LIVE_FUGR", "FUGR", "YES", RECENT),
           row("Z_LIVE_CLAS", "CLAS", "YES", RECENT)]


# --------------------------------------------------------------------------- #
#  Nothing in, nothing out                                                    #
# --------------------------------------------------------------------------- #

def test_no_inventory_export_produces_nothing():
    """The export is optional. A scan of a customer who did not send it must not
    report an empty custom-code estate — and must not crash the run, which would
    cost every other module in the same scan its findings too."""
    assert CodeInventoryAuditor({}, {}).run_all_checks() == []


def test_an_empty_inventory_list_produces_nothing():
    assert run([]) == []


def test_rows_that_carry_no_object_name_produce_nothing():
    """A malformed export must not become "2 custom objects" of estate."""
    assert run([{"OBJECT_TYPE": "PROG"}, {"FOO": "BAR"}]) == []


def test_non_dict_rows_do_not_crash_it():
    """Loader output is normally rows of dicts; a hand-edited JSON export is not
    guaranteed to be. A malformed row must be skipped, not raise."""
    assert by_id(run(["not a row", None, row("Z_A", "PROG", "YES", RECENT)]))


# --------------------------------------------------------------------------- #
#  The negative control                                                       #
# --------------------------------------------------------------------------- #

def test_a_healthy_estate_reports_only_the_inventory_statistic():
    """THE NEGATIVE CONTROL. Every object referenced and recently run: there is
    nothing wrong here, so the only thing that may come out is the INFO count of
    what exists. If a well-kept estate also produces a dead-code, dormancy or
    unknown finding, the module is manufacturing work and its numbers stop being
    believed — including the ones that are real."""
    findings = run(HEALTHY)
    assert [f["check_id"] for f in findings] == ["CODE-INV-001"]
    assert findings[0]["severity"] == "INFO"


def test_nothing_this_module_emits_ever_exceeds_low():
    """Severity discipline, measured against the worst estate we can build: dead
    code, dormant code, unknown code, all at once. An inventory statistic reported
    as MEDIUM competes with real defects for the same remediation window."""
    hostile = [row("Z_DEAD", "PROG", "NO", ""),
               row("Z_DORMANT", "PROG", "YES", OLD),
               row("Z_UNKNOWN", "PROG", "", ""),
               row("Z_LIVE", "PROG", "YES", RECENT)]
    findings = run(hostile)
    # Guard the loop. "for f in []: assert ..." passes forever, so a module that
    # stopped emitting anything would leave this test green while proving nothing.
    assert findings
    for f in findings:
        assert f["severity"] in ("INFO", "LOW"), \
            f"{f['check_id']} came out at {f['severity']}"


# --------------------------------------------------------------------------- #
#  Estate size                                                                #
# --------------------------------------------------------------------------- #

def test_the_estate_is_counted_by_object_type():
    f = by_id(run([row("Z_A", "PROG", "YES", RECENT),
                   row("Z_B", "PROG", "YES", RECENT),
                   row("Z_C", "CLAS", "YES", RECENT)]))["CODE-INV-001"]
    assert f["details"]["total_objects"] == 3
    assert f["details"]["by_type"] == {"PROG": 2, "CLAS": 1}


def test_an_object_listed_twice_is_one_object():
    """A duplicated export row must not make the estate look bigger here than in
    the reachability index it is being described against — the index dedupes by
    name, and two documents disagreeing about the estate size is the kind of detail
    that costs a report its credibility in the room."""
    f = by_id(run([row("Z_A", "PROG", "YES", RECENT),
                   row("Z_A", "PROG", "YES", RECENT)]))["CODE-INV-001"]
    assert f["details"]["total_objects"] == 1


def test_a_missing_object_type_is_labelled_rather_than_guessed():
    """`ReachabilityIndex` defaults a blank type to PROG, which costs it nothing
    because it never reads the field. Inheriting that default here would print a
    count of programs that nobody measured."""
    f = by_id(run([row("Z_A", "", "YES", RECENT)]))["CODE-INV-001"]
    assert list(f["details"]["by_type"]) == ["(type not stated)"]


def test_the_three_reachability_states_partition_the_estate():
    """Every object is reachable, unreachable or unknown — never two of them, never
    none. If these three stop summing to the total, one population is being
    double-counted or silently dropped and every percentage in the deliverable is
    wrong."""
    d = by_id(run([row("Z_LIVE", "PROG", "YES", RECENT),
                   row("Z_DEAD", "PROG", "NO", ""),
                   row("Z_UNK", "PROG", "", "")]))["CODE-INV-001"]["details"]
    assert (d["reachable_objects"] + d["unreachable_objects"]
            + d["unknown_reachability_objects"]) == d["total_objects"] == 3


def test_the_estate_statistic_does_not_claim_a_reachability_verdict_of_its_own():
    """`risk_prioritizer` reads `details["reachability"]` to decide whether a CODE
    finding sits on a reachable surface. An estate roll-up has no single verdict to
    give it, and setting that key would make a summary line score as if it were one
    exposed object."""
    findings = run([row("Z_LIVE", "PROG", "YES", RECENT), row("Z_DEAD", "PROG", "NO", "")])
    assert findings                      # an unguarded loop over [] proves nothing
    for f in findings:
        assert "reachability" not in f["details"]


# --------------------------------------------------------------------------- #
#  Unreachable code — the finding that is genuinely security work             #
# --------------------------------------------------------------------------- #

def test_code_nothing_reaches_is_reported():
    f = by_id(run([row("Z_LIVE", "PROG", "YES", RECENT),
                   row("Z_DEAD", "PROG", "NO", "")]))["CODE-INV-002"]
    assert f["details"]["count"] == 1
    assert any("Z_DEAD" in i for i in f["affected_items"])
    assert not any("Z_LIVE" in i for i in f["affected_items"])


def test_unreachable_code_is_low_and_no_higher():
    """LOW because it names a real, provable attack-surface reduction; no higher
    because nothing is known to be wrong inside these objects and nothing calls
    them. Inflating it would put dead code in the same queue as a live injection."""
    assert by_id(run([row("Z_DEAD", "PROG", "NO", "")]))["CODE-INV-002"]["severity"] == "LOW"


def test_a_dormant_but_referenced_object_is_not_called_dead():
    """The dangerous direction to be wrong in. Something references it, so it is
    reachable however long it has been since it last ran — and a decommissioning
    list built from this finding would otherwise delete live code."""
    findings = by_id(run([row("Z_OLD_BUT_USED", "PROG", "YES", OLD)]))
    assert "CODE-INV-002" not in findings
    assert findings["CODE-INV-003"]["details"]["dormant_but_still_referenced"] == 1


def test_a_recently_executed_object_is_not_called_dead_even_if_unreferenced():
    """Something ran it — a job, a tile, an RFC caller the export cannot see."""
    findings = by_id(run([row("Z_A", "PROG", "NO", RECENT)]))
    # The positive half: the module DID look at this estate. Without it the
    # absence assertion below would also hold for a module that emitted nothing.
    assert "CODE-INV-001" in findings
    assert "CODE-INV-002" not in findings


def test_when_no_usage_data_exists_the_dead_code_finding_says_so():
    """With LAST_USED empty across the whole export, the "and it has never run"
    half of the unreachability evidence is an absence of data, not a measurement. A
    deletion campaign resting on an unfilled column has to be told that."""
    f = by_id(run([row("Z_DEAD", "PROG", "NO", "")]))["CODE-INV-002"]
    assert f["details"]["usage_data_supplied"] is False
    assert "absence of data" in f["description"]


def test_when_usage_data_exists_the_dead_code_finding_does_not_hedge():
    """The control for the caveat above: where the column IS populated the evidence
    is real, and a hedge that is always printed teaches the reader to skip it."""
    f = by_id(run([row("Z_LIVE", "PROG", "YES", RECENT),
                   row("Z_DEAD", "PROG", "NO", "")]))["CODE-INV-002"]
    assert f["details"]["usage_data_supplied"] is True
    assert "absence of data" not in f["description"]


# --------------------------------------------------------------------------- #
#  Dormancy                                                                   #
# --------------------------------------------------------------------------- #

def test_dormant_code_is_reported_with_the_never_run_half_counted_separately():
    findings = by_id(run([row("Z_STALE", "PROG", "YES", OLD),
                          row("Z_NEVER", "PROG", "YES", ""),
                          row("Z_LIVE", "PROG", "YES", RECENT)]))
    d = findings["CODE-INV-003"]["details"]
    assert d["count"] == 2 and d["no_execution_date"] == 1


def test_a_fully_active_estate_reports_no_dormancy():
    """NEGATIVE CONTROL for dormancy."""
    findings = by_id(run(HEALTHY))
    assert "CODE-INV-001" in findings      # the module ran and saw this estate
    assert "CODE-INV-003" not in findings


def test_the_staleness_horizon_is_reachabilitys_and_is_not_a_second_copy():
    """Two definitions of "old" is the specific failure this module was told to
    avoid: this report would print "dormant" beside a finding the prioritiser had
    already ranked as reachable, and no test anywhere would fail. The number is
    quoted into `details` so a reader can see which horizon produced the count, and
    the horizon literal must not appear in this module's source at all."""
    d = by_id(run([row("Z_STALE", "PROG", "YES", OLD)]))["CODE-INV-003"]["details"]
    assert d["staleness_horizon_days"] == reachability._STALE_DAYS

    src = (ROOT / "modules" / "code_inventory_report.py").read_text(encoding="utf-8")
    assert re.search(rf"\b{reachability._STALE_DAYS}\b", src) is None, \
        "the staleness horizon is hard-coded here as well as in reachability.py"


def test_a_date_on_the_wrong_side_of_the_horizon_flips_the_answer():
    """Pins that the horizon is actually being applied to the date rather than the
    date merely being present. Same object, two dates, two answers."""
    assert "CODE-INV-003" not in by_id(run([row("Z_A", "PROG", "YES", RECENT)]))
    assert "CODE-INV-003" in by_id(run([row("Z_A", "PROG", "YES", OLD)]))


def test_an_unreadable_execution_date_counts_as_no_recent_execution():
    """Garbage in the date column must not read as "ran today". The conservative
    answer is the honest one: we have no readable evidence of use — and it is
    counted with the objects that have no date rather than echoed back to the
    customer as though "not-a-date" were a measurement."""
    findings = by_id(run([row("Z_LIVE", "PROG", "YES", RECENT),
                          row("Z_A", "PROG", "YES", "not-a-date")]))
    d = findings["CODE-INV-003"]["details"]
    assert d["count"] == 1
    assert d["no_execution_date"] == 1 and d["unreadable_execution_date"] == 1
    assert any("Z_A" in i and "not readable" in i
               for i in findings["CODE-INV-003"]["affected_items"])


def test_the_dats_empty_date_00000000_is_not_a_recorded_execution():
    """The failure this module would meet on its first real export. An SAP DATS
    column exports its EMPTY value as 00000000, so "the cell is non-empty" is not
    the same test as "we have a date". Reading it as data prints "0 objects carry
    no usable execution date" over an export where not one date was usable, and
    suppresses the caveat on the dead-code list that exists precisely to stop a
    deletion campaign resting on an unfilled column."""
    findings = by_id(run([row("Z_A", "PROG", "YES", "00000000"),
                          row("Z_B", "PROG", "NO", "00000000")]))
    assert "CODE-INV-003" not in findings, "00000000 was read as a real execution date"
    assert findings["CODE-INV-005"]["details"]["unreadable_values"] == 2
    assert "00000000" in findings["CODE-INV-005"]["description"]
    dead = findings["CODE-INV-002"]
    assert dead["details"]["usage_data_supplied"] is False
    assert "absence of data" in dead["description"]


def test_one_usable_date_among_unreadable_ones_still_reports_dormancy():
    """The control for the rule above: usable data DOES exist here, so the dormancy
    statistic is real — and the unreadable rows are counted as unreadable inside it
    rather than being silently promoted to measured executions."""
    findings = by_id(run([row("Z_LIVE", "PROG", "YES", RECENT),
                          row("Z_NULLDATE", "PROG", "YES", "00000000"),
                          row("Z_BLANK", "PROG", "YES", "")]))
    assert "CODE-INV-005" not in findings
    d = findings["CODE-INV-003"]["details"]
    assert d["count"] == 2
    assert d["no_execution_date"] == 2 and d["unreadable_execution_date"] == 1


def test_an_export_with_no_usage_column_reports_the_gap_instead_of_dormancy():
    """With the column empty everywhere, "never executed" and "never measured"
    cannot be told apart. Reporting the first would turn a gap in our own input into
    a claim about the customer's system, so the dormancy statistic is withheld
    entirely rather than published wrong."""
    findings = by_id(run([row("Z_A", "PROG", "YES", ""), row("Z_B", "PROG", "YES", "")]))
    assert "CODE-INV-005" in findings
    assert "CODE-INV-003" not in findings


def test_a_single_populated_date_is_enough_to_report_dormancy_properly():
    """The control for the withholding rule: usage data IS present here, so the
    dormancy statistic is real and the data-gap finding must not fire."""
    findings = by_id(run([row("Z_A", "PROG", "YES", RECENT), row("Z_B", "PROG", "YES", "")]))
    assert "CODE-INV-003" in findings
    assert "CODE-INV-005" not in findings


# --------------------------------------------------------------------------- #
#  Unknown is not unreachable                                                 #
# --------------------------------------------------------------------------- #

def test_an_object_with_no_evidence_either_way_is_reported_as_unknown():
    findings = by_id(run([row("Z_UNK", "PROG", "", OLD)]))
    assert findings["CODE-INV-004"]["details"]["count"] == 1
    assert "CODE-INV-002" not in findings, "absence of evidence became a deletion candidate"


def test_unknown_objects_never_appear_in_the_dead_code_list():
    """The whole value of the unreachable count is that somebody can act on it.
    Padding it with objects we know nothing about is how a security report gets a
    program that runs the year-end close deleted."""
    findings = by_id(run([row("Z_UNK", "PROG", "", ""), row("Z_DEAD", "PROG", "NO", "")]))
    dead_items = " ".join(findings["CODE-INV-002"]["affected_items"])
    assert "Z_DEAD" in dead_items and "Z_UNK" not in dead_items


def test_the_unknown_finding_says_in_words_that_it_is_not_a_deletion_list():
    """A reader who takes only the numbers must still be stopped: the prose has to
    carry the distinction, because the count alone looks exactly like the dead-code
    count next to it."""
    f = by_id(run([row("Z_UNK", "PROG", "", "")]))["CODE-INV-004"]
    assert "UNKNOWN IS NOT UNREACHABLE" in f["description"]
    assert f["details"]["is_not"] == UNREACHABLE


def test_a_fully_evidenced_estate_reports_no_unknowns():
    """NEGATIVE CONTROL for the unknown bucket."""
    findings = by_id(run(HEALTHY))
    assert "CODE-INV-001" in findings      # the module ran and saw this estate
    assert "CODE-INV-004" not in findings


# --------------------------------------------------------------------------- #
#  Shape of the output                                                        #
# --------------------------------------------------------------------------- #

def test_a_large_estate_produces_a_handful_of_findings_and_not_thousands():
    """1,000 dead objects is one decommissioning campaign, not 1,000 tracked
    findings. Per-object findings here would swamp every real defect in the queue,
    and deleting one program would retire a finding and raise a fresh one whose age
    restarts at zero."""
    rows = [row(f"Z_DEAD_{i:04d}", "PROG", "NO", "") for i in range(1000)]
    findings = run(rows)
    assert len(findings) <= 4, [f["check_id"] for f in findings]
    dead = by_id(findings)["CODE-INV-002"]
    assert dead["details"]["count"] == 1000
    assert len(dead["affected_items"]) <= 50, "the display list is unbounded"


def test_every_finding_is_aggregate_scoped():
    """These are estate-level statistics. Object scope would put the member list
    into the finding's identity, so one deletion would retire the finding and raise
    a new one every single run."""
    hostile = [row("Z_DEAD", "PROG", "NO", ""), row("Z_DORMANT", "PROG", "YES", OLD),
               row("Z_UNKNOWN", "PROG", "", ""), row("Z_LIVE", "PROG", "YES", RECENT)]
    findings = run(hostile)
    assert findings                      # an unguarded loop over [] proves nothing
    for f in findings:
        assert f.get("scope") == "aggregate", f["check_id"]


def test_no_finding_hangs_the_estate_off_the_attack_path_graph():
    """`affected_objects` become graph nodes. Attaching a 200k-object estate to an
    INFO statistic buries the graph in nodes that have no edges; the objects that
    belong there arrive with the per-object ATC/ABAP findings instead."""
    hostile = [row("Z_DEAD", "PROG", "NO", ""), row("Z_UNKNOWN", "PROG", "", "")]
    findings = run(hostile)
    assert findings                      # an unguarded loop over [] proves nothing
    for f in findings:
        assert not f.get("affected_objects"), f["check_id"]


def test_findings_honour_the_finding_contract():
    """The bug class this catches is a stray trailing comma turning a description
    into a tuple — every report renderer downstream assumes these types."""
    hostile = [row("Z_DEAD", "PROG", "NO", ""), row("Z_DORMANT", "PROG", "YES", OLD),
               row("Z_UNKNOWN", "PROG", "", ""), row("Z_LIVE", "PROG", "YES", RECENT)]
    findings = run(hostile)
    assert findings
    for f in findings:
        for key in ("check_id", "title", "severity", "category", "description",
                    "remediation"):
            assert isinstance(f[key], str) and f[key], f"{f['check_id']}.{key}"
        assert f["severity"] in VALID_SEVERITIES
        assert isinstance(f["affected_items"], list)
        assert all(isinstance(x, str) for x in f["affected_items"])
        assert isinstance(f["references"], list)
        assert all(isinstance(x, str) for x in f["references"])
        assert isinstance(f["details"], dict)
        assert f["affected_count"] == len(f["affected_items"])


def test_every_check_id_routes_to_a_team():
    """An unrouted finding lands in nobody's queue and is never worked."""
    from server.enrich import team_for
    hostile = [row("Z_DEAD", "PROG", "NO", ""), row("Z_DORMANT", "PROG", "YES", OLD),
               row("Z_UNKNOWN", "PROG", "", ""), row("Z_LIVE", "PROG", "YES", RECENT)]
    ids = {f["check_id"] for f in run(hostile)}
    ids |= {f["check_id"] for f in run([row("Z_A", "PROG", "YES", "")])}
    assert len(ids) == 5, f"expected all five checks to be exercised, got {sorted(ids)}"
    for cid in ids:
        assert team_for(cid) != "unassigned", cid


def test_each_check_id_is_emitted_at_most_once_per_run():
    """One finding per statistic. A repeat means a statistic is being computed per
    object somewhere, which is exactly the flooding this module exists to avoid."""
    hostile = [row("Z_DEAD", "PROG", "NO", ""), row("Z_DORMANT", "PROG", "YES", OLD),
               row("Z_UNKNOWN", "PROG", "", ""), row("Z_LIVE", "PROG", "YES", RECENT)]
    ids = [f["check_id"] for f in run(hostile)]
    # `len([]) == len(set([]))` is true, so the count is pinned as well: this
    # fixture triggers estate size, dead code, dormancy and unknown.
    assert sorted(ids) == ["CODE-INV-001", "CODE-INV-002", "CODE-INV-003",
                           "CODE-INV-004"], ids
    assert len(ids) == len(set(ids)), ids


def test_it_does_not_collide_with_the_dead_code_check_it_sits_beside():
    """`code_transport.py` already emits CODE-DEAD-001 over a looser population and
    only past a volume threshold. Both numbers are legitimate; sharing an id would
    make one silently overwrite the other's catalogue entry, remediation and
    control mapping."""
    ids = {f["check_id"] for f in run([row("Z_DEAD", "PROG", "NO", "")])}
    assert ids, "an empty id set intersects nothing and would pass regardless"
    assert not (ids & {"CODE-DEAD-001", "CODE-DEAD-002"})


# --------------------------------------------------------------------------- #
#  Against the shipped sample                                                 #
# --------------------------------------------------------------------------- #

def test_it_runs_on_the_bundled_sample_data(data):
    """The crafted sample carries a real inventory shape — mixed types, blank
    owners, unreferenced objects. Running against it is what catches a column-alias
    assumption that only holds for the test fixtures above."""
    findings = CodeInventoryAuditor(dict(data), {}).run_all_checks()
    ids = by_id(findings)
    assert ids["CODE-INV-001"]["details"]["total_objects"] == 15
    assert ids["CODE-INV-002"]["details"]["count"] >= 1
    for f in findings:
        assert f["severity"] in ("INFO", "LOW")
