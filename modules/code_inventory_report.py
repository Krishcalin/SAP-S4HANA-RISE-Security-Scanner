# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
The custom-code estate, reported as a picture rather than as a queue
====================================================================
We already load `code_inventory` and use it to decide whether an individual ABAP
finding is worth working (`modules/reachability.py`). We never reported the
inventory ITSELF, and the estate-level picture is the deliverable a customer
actually asks a consultant for: how much custom code is there, how much of it can
nothing reach, and how much of it has not run in years.

It costs nothing — the export is already parsed — and it answers the "document
your systems and your custom applications" line that every platform-hardening
checklist opens with. Custom code is contractually 100% the customer's under RISE
(`docs/RISE_SECURITY_MODEL.md`), so it is also the part of the estate nobody else
is counting for them.

WHY THIS IS A SECURITY MODULE AND NOT HOUSEKEEPING
--------------------------------------------------
Dead code is installed code. A program that nothing references is still on the
system, still compiled, and still executable by anyone who can name it (SA38, an
RFC-enabled function module, a background job step). Deleting it removes whatever
it contains — a hard-coded credential, an authority-check that was never written,
a dynamic SELECT — from the reachable surface permanently, which is a stronger
outcome than any parameter change. That is why the unreachable count is a real
finding here and not a line in an appendix.

SEVERITY DISCIPLINE
-------------------
An inventory statistic is INFO. The value is the picture, not the alarm, and a
module that reports "you have 4,812 custom objects" at MEDIUM teaches the reader
to stop reading. Exactly one check here rises to LOW — CODE-INV-002, and only
because it names a concrete, provable attack-surface reduction rather than a
measurement. Nothing here is ever higher.

WHAT IS DELIBERATELY NOT REIMPLEMENTED
--------------------------------------
Every reachability judgement is `ReachabilityIndex.verdict()`'s, quoted verbatim.
This module owns the counting and none of the deciding. If it re-derived
"referenced" or "recently used" from the same columns, the two would drift and the
report would eventually contradict the tier the prioritiser assigned to a finding
about the very same object — with nothing failing anywhere to say so.

`unknown` IS NOT `unreachable`
------------------------------
`reachability.py` is careful about this and so is this module. Most objects in a
real export are `unknown`, because REFERENCED and LAST_USED are optional columns.
"We have no evidence anything reaches it" and "we have evidence nothing does" are
different statements, and only the second one supports a deletion decision.
CODE-INV-004 exists so the unknown population is visible as its own number, and is
never quietly folded into the dead-code count to make that number look better.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set, Tuple

from modules.base_auditor import BaseAuditor
from modules.reachability import (
    REACHABLE,
    UNKNOWN,
    UNREACHABLE,
    ReachabilityIndex,
    _STALE_DAYS,
    _cell,
    _parse_date,
)

#: All three imported names are private to `reachability` and all three are
#: imported on purpose, because a local copy of any of them is a
#: silent-divergence bug:
#:
#:  * `_cell` carries the column-alias list (OBJECT_NAME/OBJECT/PROGRAM/REPORT).
#:    An object we read under a name the index did not use comes back `unknown`
#:    from `verdict()`, so this report would list an object and simultaneously say
#:    it knows nothing about it — from the same row.
#:  * `_STALE_DAYS` is THE staleness horizon. The task of this module is to quote
#:    it, not to hold a second opinion about how old "old" is.
#:  * `_parse_date` decides whether a LAST_USED cell is a date the reachability
#:    verdict could actually use. "Populated" and "usable" are not the same test:
#:    an SAP DATS column exports its empty value as `00000000`, and a date in
#:    `DD.MM.YYYY` order does not parse either. Asking "is the cell non-empty?"
#:    instead would report those rows as measured executions the verdict never
#:    read — printing "0 objects carry no usable execution date" over an export
#:    in which not one date was usable.
#:
#: If any of them is ever renamed, this import fails loudly at collection time. That is
#: the intended outcome — far better than a duplicated constant that survives the
#: rename and starts answering a different question.

#: Display lists are sampled at the size the rest of the modules use. The true
#: count always travels in `details`, so a truncated display can never be mistaken
#: for the whole population.
_SAMPLE = 50

#: Synthetic object names used only to ask the reachability module a question
#: about a date. They live in their own throwaway index and never touch real data.
_PROBE = "__HORIZON_PROBE_"

_TYPE_UNSTATED = "(type not stated)"


class CodeInventoryAuditor(BaseAuditor):
    """Estate-level statistics over `code_inventory`, one finding per statistic."""

    CATEGORY = "Code & Transport Security"

    def __init__(self, data: Dict[str, Any], baseline_overrides: Dict = None,
                 run_context: Dict[str, Any] = None, *, today: Optional[int] = None):
        super().__init__(data, baseline_overrides, run_context)
        #: YYYYMMDD, passed straight through to `ReachabilityIndex`. Only tests set
        #: it; a scan uses the real date. Without it every dormancy test would flip
        #: its own answer as the fixture dates aged past the horizon.
        self._today = today

    # ------------------------------------------------------------------ #

    def run_all_checks(self) -> List[Dict[str, Any]]:
        self.findings = []
        objects = self._inventory()
        if not objects:
            # No export, an empty one, or rows carrying no recognisable object
            # name. All three mean the same thing: we were not given an estate to
            # describe. Reporting "0 custom objects" would be an assertion about
            # the system, and we have not measured anything.
            return self.findings

        index = ReachabilityIndex(self.data, today=self._today)
        states = {name: index.verdict(name)["state"] for name, _t, _d in objects}
        recent = self._dates_inside_the_horizon({d for _n, _t, d in objects})
        # "Did the export give us usage data?" is a question about USABLE dates,
        # not about non-empty cells — see the note on the `_parse_date` import.
        usage_data_present = any(_parse_date(d) is not None
                                 for _n, _t, d in objects)

        self.check_estate_size(objects, states)
        self.check_unreachable_code(objects, states, usage_data_present)
        if usage_data_present:
            self.check_dormant_code(objects, states, recent)
        else:
            self.check_usage_data_absent(objects)
        self.check_unknown_reachability(objects, states)
        return self.findings

    # ------------------------------------------------------------------ #
    #  CODE-INV-001: how much custom code is there                        #
    # ------------------------------------------------------------------ #

    def check_estate_size(self, objects: List[Tuple[str, str, str]],
                          states: Dict[str, str]) -> None:
        by_type: Dict[str, int] = {}
        for _name, obj_type, _last_used in objects:
            by_type[obj_type] = by_type.get(obj_type, 0) + 1

        counts = {state: sum(1 for s in states.values() if s == state)
                  for state in (REACHABLE, UNREACHABLE, UNKNOWN)}
        total = len(objects)
        # Largest type first: the reader wants to know what the estate is MADE of,
        # and alphabetical order buries that under whatever starts with a C.
        items = [f"{t} — {n} object(s)"
                 for t, n in sorted(by_type.items(), key=lambda kv: (-kv[1], kv[0]))]

        self.finding(
            check_id="CODE-INV-001",
            title="Custom-code estate inventory",
            severity=self.SEVERITY_INFO,
            category=self.CATEGORY,
            description=(
                f"The custom-code inventory lists {total} object(s) across "
                f"{len(by_type)} object type(s). Of these, {counts[REACHABLE]} have "
                f"positive evidence that something reaches them, {counts[UNREACHABLE]} "
                f"have positive evidence that nothing does, and {counts[UNKNOWN]} carry "
                "no evidence either way. This is a measurement, not a defect: it is the "
                "denominator every other custom-code number in this report is a fraction "
                "of, and it is the custom-application register that platform hardening "
                "starts from — under RISE the entire custom estate is the customer's "
                "responsibility, and nobody else is counting it."
            ),
            affected_items=items[:_SAMPLE],
            remediation=(
                "Nothing to fix. Publish this inventory as part of the system "
                "documentation and re-take it each release, so growth in the custom "
                "estate is a number somebody owns rather than something discovered "
                "during an upgrade. Objects counted here are the population the ATC / "
                "code-scanning checks in this report should be covering."
            ),
            references=["SAP Security Baseline",
                        "SAP — Custom Code Lifecycle Management"],
            details={
                "total_objects": total,
                "object_types": len(by_type),
                "by_type": dict(sorted(by_type.items(),
                                       key=lambda kv: (-kv[1], kv[0]))),
                # NOT keyed "reachability": `risk_prioritizer` reads that key on a
                # finding's details to decide exposure for a single object, and an
                # estate-level roll-up has no single verdict to give it.
                "reachable_objects": counts[REACHABLE],
                "unreachable_objects": counts[UNREACHABLE],
                "unknown_reachability_objects": counts[UNKNOWN],
            },
            # No affected_objects, on purpose. They become attack-path graph nodes,
            # and hanging an entire 200k-object estate off an INFO statistic would
            # bury the graph in nodes that have no edges. The objects that genuinely
            # belong in the graph are already carried there by the per-object ATC /
            # ABAP findings, each of which stamps its own reachability verdict.
            scope="aggregate",
        )

    # ------------------------------------------------------------------ #
    #  CODE-INV-002: code nothing reaches                                 #
    # ------------------------------------------------------------------ #

    def check_unreachable_code(self, objects: List[Tuple[str, str, str]],
                               states: Dict[str, str],
                               usage_data_present: bool) -> None:
        dead = [(name, obj_type) for name, obj_type, _d in objects
                if states.get(name) == UNREACHABLE]
        if not dead:
            return

        by_type: Dict[str, int] = {}
        for _name, obj_type in dead:
            by_type[obj_type] = by_type.get(obj_type, 0) + 1

        # When the export never carried a usage column, half of reachability's
        # evidence ("and it has never run") is an absence rather than a
        # measurement. The verdict is still the module's to make and we still quote
        # it — but we say so, because a deletion campaign run off this list would
        # otherwise be resting on a column nobody filled in.
        caveat = ("" if usage_data_present else
                  " The inventory export carried no execution dates at all, so the "
                  "'has never run' half of that evidence is an absence of data rather "
                  "than a measurement — treat these as objects to confirm, not as "
                  "confirmed dead code.")

        self.finding(
            check_id="CODE-INV-002",
            title="Custom code that nothing reaches is still installed",
            severity=self.SEVERITY_LOW,
            category=self.CATEGORY,
            description=(
                f"{len(dead)} of {len(objects)} custom object(s) have positive evidence "
                "that nothing reaches them: the inventory says nothing references them "
                f"AND records no execution inside the last {_STALE_DAYS} days. Dead code "
                "is still installed code — it remains compiled and remains executable by "
                "anyone able to name it (SA38, an RFC-enabled function module, a job "
                "step), so whatever it contains stays on the attack surface. Removing it "
                "removes that content permanently, which is a stronger and cheaper "
                "outcome than hardening it in place. Reported at LOW rather than INFO "
                "because this is an actionable reduction of attack surface with a named "
                "object list, not a statistic; it is no higher than LOW because nothing "
                "is known to be wrong inside these objects and nothing currently calls "
                "them." + caveat
            ),
            affected_items=[f"{name} ({obj_type})"
                            for name, obj_type in sorted(dead)][:_SAMPLE],
            remediation=(
                "Run this as a decommissioning campaign, not as individual tickets. "
                "Confirm disuse over a full business cycle first — year-end, statutory "
                "and disaster-recovery code can be genuinely dormant for months and "
                "still be needed — using ABAP Call Monitor (SCMON) usage data and the "
                "SAP custom-code migration/decommissioning tooling. Then delete the "
                "confirmed objects through the normal transport path so the removal is "
                "auditable and reversible."
            ),
            references=["SAP Security Baseline",
                        "SAP — Custom Code Lifecycle Management",
                        "SAP — ABAP Call Monitor (SCMON) usage data"],
            details={
                "count": len(dead),
                "shown": min(len(dead), _SAMPLE),
                "total_objects": len(objects),
                "by_type": dict(sorted(by_type.items(),
                                       key=lambda kv: (-kv[1], kv[0]))),
                "usage_data_supplied": usage_data_present,
                # The conservative count. `CODE-DEAD-001` in code_transport.py counts
                # a looser population (it treats a blank LAST_USED as dead even when
                # something references the object) and only fires past a volume
                # threshold. Both numbers are legitimate; recording the relationship
                # here stops a reader treating the difference as a contradiction.
                "narrower_than": "CODE-DEAD-001",
            },
            # One decommissioning campaign, not one finding per dead program. A
            # 200k-object estate would otherwise produce a five-figure queue that
            # nobody works, and deleting one program would retire a finding and
            # raise a fresh one whose age restarts at zero.
            scope="aggregate",
        )

    # ------------------------------------------------------------------ #
    #  CODE-INV-003: code that has not run                                #
    # ------------------------------------------------------------------ #

    def check_dormant_code(self, objects: List[Tuple[str, str, str]],
                           states: Dict[str, str], recent: Set[str]) -> None:
        dormant: List[Tuple[str, str, str]] = []
        never_recorded = 0
        unreadable = 0
        for name, obj_type, last_used in objects:
            if last_used in recent:
                continue
            dormant.append((name, obj_type, last_used))
            # No usable date at all. Counted together because the customer-facing
            # statement — "we cannot say when this last ran" — is the same for a
            # blank cell and for `00000000`; the split below is what tells them
            # whether to switch collection on or to fix the export format.
            if _parse_date(last_used) is None:
                never_recorded += 1
                if last_used:
                    unreadable += 1
        if not dormant:
            return

        # Dormant AND still reachable. Because dormancy already means "not recently
        # used", the only way `verdict()` can still say reachable is the reference
        # evidence — so this is exactly the population that dormancy must not be
        # confused with: live, callable code that simply is not being called.
        reachable_dormant = sum(1 for name, _t, _d in dormant
                                if states.get(name) == REACHABLE)

        self.finding(
            check_id="CODE-INV-003",
            title="Custom code with no recent recorded execution",
            severity=self.SEVERITY_INFO,
            category=self.CATEGORY,
            description=(
                f"{len(dormant)} of {len(objects)} custom object(s) have no execution "
                f"recorded within the last {_STALE_DAYS} days; {never_recorded} of them "
                "carry no usable execution date at all. Dormancy is NOT unreachability: "
                f"{reachable_dormant} of these are still referenced by other objects and "
                "are therefore reachable — code that can run and simply is not running. "
                "The horizon is the same one this report's reachability verdicts use, so "
                "this count and the priority given to a code finding about the same "
                "object cannot disagree. Treat the number as scoping information for a "
                "custom-code review: it is where the review should start, not a list of "
                "defects."
            ),
            affected_items=[
                f"{name} ({obj_type}) — " + self._usage_note(last_used)
                for name, obj_type, last_used in sorted(dormant)][:_SAMPLE],
            remediation=(
                "Read this against how usage data was collected. If ABAP Call Monitor "
                "(SCMON) collection was switched on recently, or the export was taken "
                "over a short window, 'dormant' here means 'not observed' rather than "
                "'not used' — widen the collection window before acting. Where dormancy "
                "is confirmed over a full business cycle, fold the objects into the "
                "custom-code decommissioning backlog."
            ),
            references=["SAP Security Baseline",
                        "SAP — ABAP Call Monitor (SCMON) usage data"],
            details={
                "count": len(dormant),
                "shown": min(len(dormant), _SAMPLE),
                "total_objects": len(objects),
                "no_execution_date": never_recorded,
                # The subset of the above whose cell was not empty but did not
                # parse — `00000000`, a locale date order, a free-text note. Kept
                # separate because it is the one that is fixed by re-exporting
                # rather than by switching collection on.
                "unreadable_execution_date": unreadable,
                "dormant_but_still_referenced": reachable_dormant,
                # Quoted from reachability so a reader can see WHICH horizon produced
                # this number, and so a test can pin that it is not a second one.
                "staleness_horizon_days": _STALE_DAYS,
            },
            scope="aggregate",
        )

    # ------------------------------------------------------------------ #
    #  CODE-INV-005: the export could not answer the usage question       #
    # ------------------------------------------------------------------ #

    def check_usage_data_absent(self, objects: List[Tuple[str, str, str]]) -> None:
        """Fires INSTEAD of CODE-INV-003 when no row carries a USABLE execution date.

        With no usable date anywhere, "nothing has run" and "nothing was measured"
        are indistinguishable, and reporting the first would turn a gap in our own
        inputs into a claim about the customer's system. So we report the gap as the
        gap, and the dormancy statistic is not produced at all rather than produced
        wrong.

        The two ways of having no usable date need different actions and are
        therefore counted apart: an empty column means the collection was never
        switched on, whereas a column full of `00000000` or of locale-ordered dates
        means the collection ran and the export threw the answer away. Telling the
        customer to enable SCMON when the real fault is the export format sends them
        after the wrong thing.
        """
        unreadable = sum(1 for _n, _t, d in objects if d)
        if unreadable:
            gap = (f"{unreadable} row(s) do carry a value in that column, but none of "
                   "it parses as a date — an SAP DATS column exports its empty value "
                   "as 00000000, and a locale-ordered date does not read either, so "
                   "this may be an export-format fault rather than uncollected data.")
            item = ("code_inventory export carries no READABLE LAST_USED / execution "
                    f"dates ({unreadable} unparseable value(s))")
        else:
            gap = "The column is empty on every row."
            item = "code_inventory export has no LAST_USED / execution dates"

        self.finding(
            check_id="CODE-INV-005",
            # "no USABLE execution data" rather than "no execution data": the column
            # can be present and full and still tell us nothing, and a title that
            # says otherwise sends the customer to look for a missing column.
            title="Custom-code inventory carries no usable execution data",
            severity=self.SEVERITY_INFO,
            category=self.CATEGORY,
            description=(
                f"None of the {len(objects)} object(s) in the custom-code inventory "
                "carries a usable LAST_USED value, so this report cannot say which "
                f"custom code is actually running. {gap} Dormancy is therefore not "
                "reported at all — with no usable date anywhere, 'never executed' and "
                "'never measured' cannot be told apart, and reporting the first would "
                "turn a gap in the export into a claim about the system. It also weakens "
                "the reachability evidence behind every custom-code finding in this "
                "report, because one of its two inputs is missing."
            ),
            affected_items=[item],
            remediation=(
                "Re-take the custom-code inventory with the execution-date column "
                "populated from ABAP Call Monitor (SCMON) usage data, in SAP's YYYYMMDD "
                "date form (separators are tolerated), and include the REFERENCED "
                "column. See docs/EXPORT_GUIDE.md for the expected columns. "
                "Those two columns are what separates live custom code from dead custom "
                "code in this report, and without them every code finding is ranked as "
                "if the question had never been asked."
            ),
            references=["SAP — ABAP Call Monitor (SCMON) usage data",
                        "docs/EXPORT_GUIDE.md — code_inventory.csv REFERENCED / LAST_USED"],
            details={"total_objects": len(objects), "column": "LAST_USED",
                     "unreadable_values": unreadable},
            scope="aggregate",
        )

    # ------------------------------------------------------------------ #
    #  CODE-INV-004: the honest bucket                                    #
    # ------------------------------------------------------------------ #

    def check_unknown_reachability(self, objects: List[Tuple[str, str, str]],
                                   states: Dict[str, str]) -> None:
        unknown = [(name, obj_type) for name, obj_type, _d in objects
                   if states.get(name) == UNKNOWN]
        if not unknown:
            return

        self.finding(
            check_id="CODE-INV-004",
            title="Custom code whose reachability could not be determined",
            severity=self.SEVERITY_INFO,
            category=self.CATEGORY,
            description=(
                f"{len(unknown)} of {len(objects)} custom object(s) are listed in the "
                "inventory but carry no reference flag and no usable execution date, so "
                "there is no evidence in either direction about who can reach them. "
                "UNKNOWN IS NOT UNREACHABLE. These objects must not be added to a "
                "dead-code deletion list, and they must not be presented as a smaller "
                "attack surface than they are: absence of evidence that something calls "
                "an object is not evidence that nothing does. Findings about these "
                "objects elsewhere in this report are ranked as though the reachability "
                "signal did not exist, which is the only safe reading — and it means a "
                "large unknown population is quietly costing the whole report its "
                "sharpest prioritisation signal."
            ),
            affected_items=[f"{name} ({obj_type})"
                            for name, obj_type in sorted(unknown)][:_SAMPLE],
            remediation=(
                "Populate the REFERENCED and LAST_USED columns in the code_inventory "
                "export (see docs/EXPORT_GUIDE.md) — where-used information from the "
                "cross-reference utilities and execution data from ABAP Call Monitor "
                "(SCMON). Until then, treat these objects as reachable, which is the "
                "conservative assumption this report already applies to them."
            ),
            references=["SAP Security Baseline",
                        "docs/EXPORT_GUIDE.md — code_inventory.csv REFERENCED / LAST_USED"],
            details={
                "count": len(unknown),
                "shown": min(len(unknown), _SAMPLE),
                "total_objects": len(objects),
                "is_not": UNREACHABLE,
            },
            scope="aggregate",
        )

    # ------------------------------------------------------------------ #
    #  Reading the export                                                 #
    # ------------------------------------------------------------------ #

    def _inventory(self) -> List[Tuple[str, str, str]]:
        """(object name, object type, raw LAST_USED) per DISTINCT object.

        Deduplicated by name, last row winning, because that is exactly what
        `ReachabilityIndex._build` does when it fills its dict — an export that
        lists an object twice must not make the estate look bigger here than the
        index it is being described against.

        The type is NOT defaulted to "PROG" the way the index defaults it. The
        index never reads that field, so a default costs it nothing; a report that
        prints "412 PROG" when forty of them never stated a type is publishing a
        number nobody measured.
        """
        rows = (self.data or {}).get("code_inventory") or []
        seen: Dict[str, Tuple[str, str, str]] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            name = _cell(row, "OBJECT_NAME", "OBJECT", "PROGRAM", "REPORT").upper()
            if not name:
                continue
            obj_type = _cell(row, "OBJECT_TYPE", "TYPE").upper() or _TYPE_UNSTATED
            last_used = _cell(row, "LAST_USED", "LAST_EXECUTED", "LASTUSED")
            seen[name] = (name, obj_type, last_used)
        return list(seen.values())

    def _usage_note(self, last_used: str) -> str:
        """How to say "when did this last run?" for one object, honestly.

        Echoing the raw cell back — "last recorded execution 00000000" — puts a
        non-date in front of a customer as though it were a measurement, and hides
        the fact that the row is in the dormant list precisely BECAUSE we could not
        read it. The three states are genuinely different pieces of news, so they
        get three different sentences.
        """
        if not last_used:
            return "no execution recorded"
        if _parse_date(last_used) is None:
            return f"execution date not readable ({last_used})"
        return f"last recorded execution {last_used}"

    def _dates_inside_the_horizon(self, raw_dates: Set[str]) -> Set[str]:
        """Which raw LAST_USED strings still count as "recently used".

        WHY THIS ASKS INSTEAD OF CALCULATING
        The horizon test lives in `ReachabilityIndex`, on a private method, over a
        date format that module parses itself. Recomputing it here would be a second
        copy of both the arithmetic and the parsing, and the day the two disagree
        this report would print "dormant" next to a finding the prioritiser had
        ranked as reachable — with no test anywhere failing.

        So we ask the module. A synthetic object that nothing references is the one
        input whose verdict depends on the date ALONE: reachable means the date is
        inside the horizon, unreachable means it is not. One probe per DISTINCT date
        string, so the cost is bounded by the number of distinct days in the export
        rather than by the size of the estate.

        Unparseable and blank dates both come back "not recent", which is the honest
        answer — we have no readable evidence of use — and the caller reports the
        blank ones separately so the two are never conflated in the prose.
        """
        dates = sorted(d for d in raw_dates if d)
        if not dates:
            return set()
        probe = ReachabilityIndex(
            {"code_inventory": [
                {"OBJECT_NAME": f"{_PROBE}{i}", "REFERENCED": "NO", "LAST_USED": d}
                for i, d in enumerate(dates)]},
            today=self._today)
        return {d for i, d in enumerate(dates)
                if probe.verdict(f"{_PROBE}{i}")["state"] == REACHABLE}
