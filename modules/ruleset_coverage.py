"""How much of this estate the SoD ruleset can actually see.

WHY THIS EXISTS
---------------
Every SoD tool publishes a rule count. None publishes a coverage number, and the
count is the less useful of the two: a conflict report is only as trustworthy as
the fraction of the estate its ruleset can see, and a ruleset of 207 risks that
is blind to a third of the granted transactions produces a confident, clean, and
wrong answer.

SAP concedes the gap by shipping three reports for it — *List Actions in Roles
But Not in Rules*, *List Permissions in Roles But Not in Rules*, and *Embedded
Action Calls in Programs of SAP Systems*. This module is their offline
equivalent, computed from exports we already parse.

It is deliberately a measurement of OUR OWN ruleset, published in our own
report. That is unusual and it is the point: `docs/CHECKS_REFERENCE.md` already
argues that a catalogue with an itemised list is a claim somebody can check,
where a bare count is only a claim. This extends the same argument to SoD, and
it is the one number in the report that can make us look worse.

WHAT IT DOES NOT MEASURE
------------------------
Coverage is not correctness. A ruleset can name a transaction and still model it
wrongly. This answers only "could the ruleset have seen it", which is the
question that has to be answered FIRST — a precision argument over an unmeasured
denominator is worthless.

THE WILDCARD, AND THE TWO QUESTIONS IT SEPARATES
------------------------------------------------
A role holding `S_TCODE = *` grants every transaction in the system, including
every transaction nobody has exported. That does NOT make the module silent, and
an earlier revision of it that went silent was wrong — measured against the
sample estate, one wildcard role reduced the whole output to "could not be
measured", which is honest and useless.

The mistake was collapsing two different questions:

  (a) Of the transactions this estate EXPLICITLY GRANTS, how many can the
      ruleset name?  ->  bounded, answerable, and the actionable one, because
      every miss is a transaction somebody can decide about.

  (b) Of everything this estate can REACH, how many can the ruleset name?
      ->  unanswerable under a wildcard, because the reachable set is unbounded.

So (a) is always computed and always labelled as (a). A wildcard degrades it —
`coverage_state` becomes `degraded`, the finding says the true denominator is
larger and unknown, and the offending roles are named. It never silently reads
as an estate-wide answer.

That is the same three-state discipline used everywhere else here: `complete`
when nothing is unbounded, `degraded` when something is, `unknown` only when
there was no data to measure at all. What must never happen is a bare
percentage presented as the estate's coverage while a wildcard role sits behind
it — which is the failure the earlier revision over-corrected for.

TEN FINDINGS ARE NOT AN ANSWER TO THE QUESTION THAT WAS ASKED
─────────────────────────────────────────────────────────────
This module now emits up to ten separate findings about how far a segregation
result can be believed - coverage on two surfaces, whether a wildcard makes it
unbounded, rules that cannot fire, a supplied ruleset that is broken or silently
overriding ours. An auditor does not want ten. They want one sentence they can
put in a workpaper, and a reader who has to assemble that sentence themselves
will assemble it wrongly or not at all.

SODCOV-000 is that sentence. Two rules govern it, and the first is the reason
the check is worth having rather than dangerous:

  IT LEADS WITH THE WEAKEST DIMENSION, NEVER AN AVERAGE. Averaging 93% of
  transactions against 0% of Fiori produces a comfortable 47% that describes
  nothing, and a summary that buries its worst input is the exact failure the
  rest of this module exists to report. The verdict is the floor, not the mean.

  IT IS DERIVED FROM THE FINDINGS ALREADY EMITTED, not recomputed. A summary
  that recalculates can disagree with the detail it summarises, and then the
  report contradicts itself in front of the person least able to tell which
  half is right.

TWO RULESETS, AND THE COMPARISON NOBODY MAKES
─────────────────────────────────────────────
An organisation that already owns a GRC ruleset is not going to replace it with
ours, and should not be asked to. What they want is the delta, and nothing
produced it: SODCOV-009 notices when a custom rule collides with a shipped id,
which is a very small part of the question.

The framing has to be exact or the number is misleading. This engine MERGES a
supplied ruleset with the shipped one, so within this scan both ran. Their own
GRC system runs theirs ALONE, and that is the comparison worth making: run by
itself, which transactions and authorization objects would the supplied ruleset
never name?

It is reported in BOTH directions on purpose. The forward direction is the one a
buyer cares about and is therefore the one to be most careful with; the reverse
direction — capabilities their ruleset names and ours does not — is a gap in
THIS product, and a comparison that only ever flattered us would not be worth
running. No attempt is made to match risk to risk: their ids and groupings will
not correspond to ours, and a fuzzy correspondence would produce confident
nonsense. Transactions and objects are compared exactly, because "your ruleset
never mentions F110" is a fact and needs no interpretation.

THE CUSTOMER'S OWN RULESET IS THE ONE NOBODY CHECKS
───────────────────────────────────────────────────
`ara_ruleset.json` lets a customer extend or replace what we ship, and it is the
path any enterprise with an existing GRC ruleset will take. It was accepted
without a single validation, and the failure modes are not theoretical - each of
these was run against the engine:

  two functions declaring neither actions nor permissions
      FIRES FOR EVERY USER IN THE ESTATE. The action gate is skipped when a
      function names no actions and the permission gate returns True when it
      declares none, so the rule is held by everybody. A false-positive engine
      that reports the whole user base as conflicted.

  "function" written instead of "functions"
  a segregation rule carrying only one function
  permissions that name a field and value but no object
      SILENTLY DEAD. Fail-closed means each of these never fires for anybody,
      and never firing is indistinguishable from finding nothing.

  a custom risk_id matching one of ours
      SILENTLY REPLACES the shipped rule. Overriding is a legitimate feature -
      doing it without knowing is not, and nothing reported it.

SODCOV-008 reports rules that cannot work as written; SODCOV-009 reports which
shipped rules a custom file displaced. They are separate because the remediation
is: one is a defect in the customer's file, the other may be exactly what they
intended and only needs to be visible.

A RULE CAN NAME AN OBJECT THAT DOES NOT EXIST, AND NOTHING WOULD SAY SO
──────────────────────────────────────────────────────────────────────
The matcher is fail-closed: a permission predicate naming an authorization
object nobody holds simply is not satisfied. That is the correct behaviour for
an object that exists and is ungranted, and it is a silent catastrophe for an
object that does not exist at all. A typo, or an object from a different
release, produces a rule that can never fire for anybody, ever - and it looks
exactly like a rule that fires correctly and found nothing.

Our own ruleset carries that risk explicitly. Most of it was written from
general SAP knowledge rather than object-by-object verification, and every such
rule says so in `provenance`. That is honest, and it is prose. TOBJ turns it
into a measurement: an object absent from the catalogue this system publishes is
not merely unverified, it is wrong here.

The consequence worth reporting is not the object, it is the RULE. A function
whose permissions are ALL missing can never be held, so a segregation rule with
such a function can never fire - the risk is in the library, is counted in the
ruleset size, and is dead. That is what SODCOV-007 names.

THERE ARE TWO SURFACES, AND THE FIRST VERSION MEASURED ONE
────────────────────────────────────────────────────────────
An S/4HANA user reaches a capability through a transaction code OR through a
Fiori app, and the two are governed differently. A transaction is gated by
S_TCODE; a Fiori app is gated by its OData service's start authorization
(S_SERVICE), and — this is the part that breaks rulesets — **a Fiori app carries
no permissions of its own.** The permissions belong to the service behind it.
SAP's own scope table says as much, and its guidance for building a
permission-level Fiori rule is to copy the service's authorizations across by
hand, per function.

The first version of this module counted S_TCODE grants and nothing else. On an
estate whose users work through Fiori that reports a confident percentage over
the classic surface while the Fiori surface is not measured at all — which is
the same "confident number over an unasked question" this module was written to
prevent, reproduced inside it.

So the surfaces are measured and reported SEPARATELY, never averaged. Averaging
would let 93% of transactions hide 0% of Fiori apps behind one number, and the
0% is the finding. When a Fiori surface exists and the ruleset names none of it,
the transaction figure says so on its own face.

CUSTOM TRANSACTIONS ARE COUNTED APART
-------------------------------------
No shipped ruleset — ours, SAP's, or a competitor's — can contain a customer's
`Z*` transactions. Folding them into the coverage percentage would make every
estate look badly covered for a reason no vendor can fix, and would bury the
finding that actually matters: WHICH custom transactions are granted, so somebody
can decide whether they belong in a rule. They are reported as their own number.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from modules.base_auditor import BaseAuditor

#: The object that carries a transaction-code grant.
TCODE_OBJECT = "S_TCODE"
TCODE_FIELD = "TCD"

#: Customer namespaces. A shipped ruleset cannot know these, so they are
#: measured separately rather than counted as ruleset failure.
CUSTOM_PREFIXES = ("Z", "Y")

#: Values that mean "every transaction". `*` is the SAP wildcard; a range with a
#: blank or `*` LOW is the same thing spelled differently.
WILDCARDS = ("*", "")

#: The customer's own rules, extending or overriding what we ship.
CUSTOM_RULESET_EXPORT = "ara_ruleset"

#: TOBJ - the authorization objects this release defines. Optional: object
#: definitions are static SAP content rather than a customer setting, so most
#: uploads will not carry it and the check reports itself unmeasured instead of
#: guessing.
OBJECT_CATALOGUE_EXPORT = "auth_object_catalogue"

#: Exports that describe the Fiori surface. An app reaches a back-end
#: capability through the OData service behind its tile, so the tile export is
#: what carries the app -> service half of the chain.
FIORI_TILE_EXPORT = "fiori_tiles"
FIORI_CATALOG_EXPORT = "fiori_catalogs"
ODATA_EXPORT = "odata_auth"

#: Start authorization for an OData service (SAP Help). A ruleset that never
#: mentions it cannot express a permission-level Fiori rule at all.
ODATA_START_OBJECT = "S_SERVICE"
#: …and for a Web Dynpro application.
WEBDYNPRO_START_OBJECT = "S_START"

#: Below this share of the granted estate, a SoD result should not be read as an
#: estate-wide answer. Chosen as a reporting threshold, not a quality bar: it is
#: the point at which more of the estate is invisible than visible.
LOW_COVERAGE_THRESHOLD = 0.50


def _is_custom(tcode: str) -> bool:
    return bool(tcode) and tcode[0].upper() in CUSTOM_PREFIXES


def _expand_range(low: str, high: str) -> Optional[Set[str]]:
    """A LOW..HIGH transaction range, when it is small enough to enumerate.

    Returns None when the range cannot be enumerated — which is most of them.
    An unenumerable range is treated exactly like a wildcard, because that is
    what it is: an unknown number of transactions, none of which we can name.
    """
    if not high or high == low:
        return {low} if low else None
    # Deliberately not enumerated. `FB01`..`FB99` is 99 transactions of which
    # perhaps 40 exist, and inventing the other 59 would put transactions in the
    # denominator that the system does not have.
    return None


class RulesetCoverageAuditor(BaseAuditor):
    #: Optional inputs (see BaseAuditor.OPTIONAL_SOURCES): every one of these has a check that reports its own absence in words -
    #: SODCOV-006 for the Fiori exports, SODCOV-007 and the note on SODCOV-002
    #: for the object catalogue, SODCOV-008/009/010 for a supplied ruleset.
    OPTIONAL_SOURCES = frozenset({"ara_ruleset", "auth_object_catalogue", "fiori_tiles",
                                   "fiori_catalogs", "odata_auth"})

    """Measures what fraction of the granted estate the SoD ruleset can see."""

    CATEGORY = "SoD Ruleset Coverage"

    #: The ruleset under measurement. Injected rather than imported at module
    #: scope so a caller can measure a CUSTOM ruleset — which is the case that
    #: matters to a customer who has replaced ours.
    def __init__(self, data: Dict[str, Any], baseline_overrides: Dict = None,
                 run_context: Dict[str, Any] = None,
                 ruleset: Optional[List[Dict[str, Any]]] = None):
        super().__init__(data, baseline_overrides, run_context)
        self._ruleset = ruleset

    # ------------------------------------------------------------------ #
    def run_all_checks(self) -> List[Dict[str, Any]]:
        rows = self.data.get("role_auth_values")
        if not rows:
            self._emit_unknown(
                "no role authorization export was supplied, so the ruleset's "
                "coverage of this estate could not be measured at all. This is "
                "not a coverage of zero and it is not a coverage of 100% — it "
                "is an unasked question. Supply AGR_1251 (role_auth_values) to "
                "answer it.")
            # The Fiori surface is described by different exports and may be
            # present when AGR_1251 is not.
            known_actions, known_objects = self._ruleset_vocabulary()
            self._emit_fiori_coverage(known_actions, known_objects)
            # The catalogue is about the RULESET, not the estate's grants, so it
            # is measurable with no AGR_1251 at all.
            self._emit_unknown_objects()
            self._emit_custom_ruleset_defects()
            self._emit_ruleset_comparison()
            self._emit_trust_statement()
            return self.findings

        granted = self._granted(rows)
        known_actions, known_objects = self._ruleset_vocabulary()
        if granted.wildcard_roles:
            # The score still gets computed — over EXPLICIT grants, labelled as
            # such. What the wildcard removes is the right to call it an
            # estate-wide number, and that is said in the finding rather than
            # by withholding it.
            self._emit_unbounded(granted)
        self._emit_action_coverage(granted, known_actions)
        self._emit_permission_coverage(granted, known_objects)
        self._emit_custom_gap(granted)
        self._emit_fiori_coverage(known_actions, known_objects)
        self._emit_unknown_objects()
        self._emit_custom_ruleset_defects()
        self._emit_ruleset_comparison()
        self._emit_trust_statement()
        return self.findings

    # ------------------------------------------------------------------ #
    class _Granted:
        """What the estate actually grants, as opposed to what it could."""

        def __init__(self) -> None:
            self.standard: Set[str] = set()
            self.custom: Set[str] = set()
            self.objects: Set[str] = set()
            self.wildcard_roles: Set[str] = set()
            self.custom_by_role: Dict[str, Set[str]] = {}

    def _granted(self, rows: List[Dict[str, Any]]) -> "_Granted":
        out = self._Granted()
        for row in rows:
            if not isinstance(row, dict):
                continue
            role = str(row.get("AGR_NAME", row.get("ROLE", ""))).strip()
            obj = str(row.get("OBJECT", row.get("AUTH_OBJECT", ""))).strip().upper()
            field = str(row.get("FIELD", row.get("FIELD_NAME", ""))).strip().upper()
            low = str(row.get("LOW", row.get("VALUE", ""))).strip().upper()
            high = str(row.get("HIGH", row.get("BIS", ""))).strip().upper()
            if not obj:
                continue
            out.objects.add(obj)
            if obj != TCODE_OBJECT or field != TCODE_FIELD:
                continue
            if low in WILDCARDS or low.endswith("*") or high in ("*",):
                out.wildcard_roles.add(role or "<unnamed role>")
                continue
            values = _expand_range(low, high)
            if values is None:
                out.wildcard_roles.add(role or "<unnamed role>")
                continue
            for tcode in values:
                if _is_custom(tcode):
                    out.custom.add(tcode)
                    out.custom_by_role.setdefault(role, set()).add(tcode)
                else:
                    out.standard.add(tcode)
        return out

    def _risks(self) -> List[Dict[str, Any]]:
        """The ruleset under measurement, injected or shipped.

        Split out of `_ruleset_vocabulary` because SODCOV-007 needs the risks
        themselves, not the vocabulary derived from them: its finding is about
        which RULES are dead, and that cannot be recovered from a flat set of
        object names.
        """
        if self._ruleset is not None:
            return self._ruleset
        # Imported here, not at module scope, for the reason given below.
        from modules.access_risk_analysis import AccessRiskAnalysisAuditor
        return AccessRiskAnalysisAuditor.RULESET or []

    def _ruleset_vocabulary(self) -> Tuple[Set[str], Set[str]]:
        """Every action and authorization object the ruleset can name."""
        ruleset = self._ruleset
        if ruleset is None:
            # Imported here, not at module scope: importing the SoD module for
            # its constant at load time would couple two modules that are
            # otherwise independent, and `--modules` may run either alone.
            from modules.access_risk_analysis import AccessRiskAnalysisAuditor
            ruleset = AccessRiskAnalysisAuditor.RULESET
        actions: Set[str] = set()
        objects: Set[str] = set()
        for risk in ruleset or []:
            for function in risk.get("functions", []) or []:
                for action in function.get("actions", []) or []:
                    actions.add(str(action).strip().upper())
                for perm in function.get("permissions", []) or []:
                    obj = str(perm.get("object", "")).strip().upper()
                    if obj:
                        objects.add(obj)
        return actions, objects

    # ------------------------------------------------------------------ #
    def _emit_unbounded(self, granted) -> None:
        """A wildcard means the true denominator is larger and unknown."""
        roles = sorted(granted.wildcard_roles)
        self.finding(
            check_id="SODCOV-005",
            title=(
            "%d role(s) grant every transaction, so estate-wide coverage is "
                "unbounded" % len(roles)),
            severity=self.SEVERITY_HIGH,
            category=self.CATEGORY,
            description=(
            "%s grant S_TCODE = * (or an unenumerable range), so their holders "
            "can reach every transaction in the system - including transactions "
            "absent from this export. The coverage figure reported alongside is "
            "therefore measured over EXPLICITLY GRANTED transactions only. The "
            "estate's true reachable set is larger by an unknown amount, and no "
                "percentage over it would be honest." % ", ".join(roles[:5])),
            affected_items=roles,
            remediation=(
                "A wildcard transaction grant is a finding in its own right, "
                "independent of segregation of duties. Until it is removed, "
                "read the coverage figure as a floor rather than a "
                "measurement."),
            references=["SAP Access Control 12.0 - List Actions in Roles But Not in Rules",
                        "SAP Access Control 12.0 - List Permissions in Roles But Not in Rules",
                        "SAP Access Control 12.0 - Embedded Action Calls in Programs"],
            details={
                "wildcard_roles": roles,
                "explicit_standard_tcodes": len(granted.standard),
                "explicit_custom_tcodes": len(granted.custom),
                "coverage_state": "degraded",
            },
        )

    def _emit_action_coverage(self, granted, known: Set[str]) -> None:
        total = len(granted.standard)
        if not total:
            self._emit_unknown(
                "no standard transaction grants were found in the role export, "
                "so there was nothing to measure coverage against.")
            return
        seen = granted.standard & known
        missing = sorted(granted.standard - known)
        fraction = len(seen) / total
        bounded = not granted.wildcard_roles

        self.finding(
            check_id="SODCOV-001",
            title="SoD ruleset sees %.0f%% of the transactions this estate %s"
            % (fraction * 100, "grants" if bounded else "explicitly grants"),
            severity=(self.SEVERITY_HIGH if fraction < LOW_COVERAGE_THRESHOLD
                      else self.SEVERITY_MEDIUM if missing else self.SEVERITY_INFO),
            category=self.CATEGORY,
            description="Of %d distinct standard transaction codes %s across the roles in "
            "this estate, the SoD ruleset names %d. The remaining %d cannot "
            "appear in any conflict, because no rule mentions them - so a clean "
            "SoD result is a statement about %.0f%% of what was measured, not "
            "all of it.%s"
            % (total, "granted" if bounded else "EXPLICITLY granted",
               len(seen), len(missing), fraction * 100,
               "" if bounded else
               " A wildcard grant means the estate reaches more transactions "
               "than were measured here - see SODCOV-005.")
            + self._other_surface_note(),
            affected_items=missing[:40],
            remediation=(
                "Review the unseen transactions. Each is either irrelevant to "
                "segregation of duties, or a gap in the ruleset. Both are "
                "answers; neither is the silence you get by not measuring."
                if missing else
                "Every granted standard transaction is named by the ruleset."),
            references=["SAP Access Control 12.0 - List Actions in Roles But Not in Rules",
                        "SAP Access Control 12.0 - List Permissions in Roles But Not in Rules",
                        "SAP Access Control 12.0 - Embedded Action Calls in Programs"],
            details={
                "granted_standard_tcodes": total,
                "named_by_ruleset": len(seen),
                "not_named": len(missing),
                "coverage_fraction": round(fraction, 4),
                "coverage_state": "complete" if bounded else "degraded",
                "denominator": ("granted transactions" if bounded
                                else "explicitly granted transactions"),
                # Capped: a 400-entry list in a finding is a wall, not evidence.
                "unseen_examples": missing[:40],
                "unseen_truncated": max(0, len(missing) - 40),
            },
        )

    def _emit_permission_coverage(self, granted, known: Set[str]) -> None:
        # S_TCODE is excluded: it is the START authorization, not a predicate
        # the ruleset discriminates on, and counting it would flatter the score.
        granted_objects = {o for o in granted.objects if o != TCODE_OBJECT}
        if not granted_objects:
            return
        seen = granted_objects & known
        missing = sorted(granted_objects - known)
        fraction = len(seen) / len(granted_objects)
        self.finding(
            check_id="SODCOV-002",
            title="SoD ruleset discriminates on %.0f%% of the authorization objects "
            "this estate grants" % (fraction * 100),
            severity=self.SEVERITY_MEDIUM if missing else self.SEVERITY_INFO,
            category=self.CATEGORY,
            description="Of %d distinct authorization objects granted in the roles, %d "
            "appear in a ruleset permission predicate. Conflicts involving the "
            "other %d can only ever be judged at transaction level, which is "
            "where false positives and false negatives both come from.%s"
            % (len(granted_objects), len(seen), len(missing),
               self._unverified_objects_note()),
            affected_items=missing[:40],
            remediation=(
                "An object absent from every predicate is not necessarily a "
                "gap - most authorization objects have no bearing on "
                "segregation of duties. It is a gap when it governs one half "
                "of a modelled conflict."),
            references=["SAP Access Control 12.0 - List Actions in Roles But Not in Rules",
                        "SAP Access Control 12.0 - List Permissions in Roles But Not in Rules",
                        "SAP Access Control 12.0 - Embedded Action Calls in Programs"],
            details={
                "granted_objects": len(granted_objects),
                "in_predicates": len(seen),
                "not_in_predicates": len(missing),
                "coverage_fraction": round(fraction, 4),
                "unseen_examples": missing[:40],
                "unseen_truncated": max(0, len(missing) - 40),
            },
        )

    def _emit_custom_gap(self, granted) -> None:
        if not granted.custom:
            return
        custom = sorted(granted.custom)
        self.finding(
            check_id="SODCOV-003",
            title="%d custom transaction(s) are granted and no shipped ruleset can "
            "see them" % len(custom),
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description="These transactions are in the customer namespace, so no vendor's "
            "ruleset - ours or anyone else's - can contain them. A custom "
            "transaction that wraps a standard one carries the standard one's "
            "risk while being invisible to every rule keyed on the standard "
            "code.",
            affected_items=custom[:40],
            remediation=(
                "For each, determine what it calls. A custom transaction over "
                "vendor master maintenance or payment execution belongs in the "
                "ruleset under a customer-namespace risk id; one over a display "
                "report does not."),
            references=["SAP Access Control 12.0 - List Actions in Roles But Not in Rules",
                        "SAP Access Control 12.0 - List Permissions in Roles But Not in Rules",
                        "SAP Access Control 12.0 - Embedded Action Calls in Programs"],
            details={
                "custom_tcodes": custom[:40],
                "custom_truncated": max(0, len(custom) - 40),
                "roles_granting_them": sorted(granted.custom_by_role)[:20],
            },
        )

    @staticmethod
    def _rule_defect(risk: Dict[str, Any]) -> Optional[str]:
        """Why this rule cannot work as written, or None if it can.

        The verdicts are the engine's actual behaviour, confirmed by running
        each shape through it rather than read off the source.
        """
        if not isinstance(risk, dict):
            return "not an object"
        funcs = risk.get("functions")
        rtype = str(risk.get("risk_type", "SOD")).upper()
        if not isinstance(funcs, list) or not funcs:
            return ("declares no 'functions' list, so it can never fire "
                    "(a misspelled key such as 'function' lands here)")
        for func in funcs:
            if not isinstance(func, dict):
                return "a function is not an object"
            acts = [a for a in (func.get("actions") or []) if str(a).strip()]
            perms = func.get("permissions") or []
            if not acts and not perms:
                return ("function %r declares neither actions nor permissions, "
                        "so it is held by EVERY user and this rule fires for the "
                        "whole estate" % func.get("name", "?"))
            if perms and not any(str(p.get("object", "")).strip()
                                 for p in perms if isinstance(p, dict)):
                return ("function %r declares permissions but none names an "
                        "object, so the function can never be held and the rule "
                        "can never fire" % func.get("name", "?"))
        if rtype == "SOD" and len(funcs) < 2:
            return ("a segregation rule with %d function(s): the engine requires "
                    "two sides, so it can never fire" % len(funcs))
        if rtype != "SOD" and len(funcs) != 1:
            return ("a critical-access rule with %d functions: only the first is "
                    "evaluated, so the rest are ignored" % len(funcs))
        return None

    def _emit_trust_statement(self) -> None:
        """One sentence for the workpaper, built from what was already found."""
        seen = {f["check_id"]: f for f in self.findings}
        if not seen:
            return

        def detail(cid, key, default=None):
            return ((seen.get(cid) or {}).get("details") or {}).get(key, default)

        limits, verdict, severity = [], "usable", self.SEVERITY_INFO

        # WHAT WAS HIDDEN BEFORE THE READER GOT HERE.
        #
        # This verdict read USABLE / INFO on an estate whose only conflict had
        # been removed by a blanket mitigation row carrying no approver, no
        # expiry and no control id. The statement that exists to say how far a
        # result can be believed was the last place in the product still capable
        # of a false all-clear, and it was rendered above the findings in every
        # format and on the console dashboard.
        #
        # Read from the peer findings rather than recomputed from the mitigation
        # rows: MITIG-001 already decided what was suppressed, and a summary
        # that recalculates can disagree with the detail it summarises.
        peers = {f.get("check_id"): f
                 for f in ((self.run_context or {}).get("peer_findings") or [])
                 if isinstance(f, dict)}
        suppression_checked = bool(peers)
        hidden = ((peers.get("MITIG-001", {}).get("details") or {})
                  .get("risks_hidden_entirely") or 0)
        unsupportable = ((peers.get("MITIG-002", {}).get("details") or {})
                         .get("unsupportable") or 0)

        # The floor, in order of how badly each one undermines the result.
        if "SODCOV-004" in seen:
            verdict = "not measured"
            severity = self.SEVERITY_HIGH
            limits.append(
                "the authorization export needed to measure coverage was not "
                "supplied, so no statement about breadth is possible at all")
        else:
            tx = detail("SODCOV-001", "coverage_fraction")
            fiori = detail("SODCOV-006", "coverage_fraction")
            if "SODCOV-005" in seen:
                verdict = "unbounded"
                severity = self.SEVERITY_HIGH
                limits.append(
                    "at least one role grants every transaction, so the estate "
                    "reaches more than was measured and the percentages below "
                    "are a floor rather than a figure")
            if fiori is not None and fiori < 0.5:
                verdict = "partial" if verdict == "usable" else verdict
                severity = max(severity, self.SEVERITY_HIGH, key=self._rank)
                limits.append(
                    "the ruleset names %.0f%% of this estate's Fiori surface, so "
                    "a conflict reachable only through an app is outside what "
                    "any result here can find" % (fiori * 100))
            if tx is not None and tx < 0.8:
                verdict = "partial" if verdict == "usable" else verdict
                severity = max(severity, self.SEVERITY_MEDIUM, key=self._rank)
                limits.append(
                    "the ruleset names %.0f%% of the transactions this estate "
                    "grants" % (tx * 100))

        if hidden:
            # A conflict removed from the report is not a conflict that was not
            # there, and a verdict that cannot see the difference is worthless.
            verdict = "partial" if verdict == "usable" else verdict
            severity = max(severity, self.SEVERITY_HIGH, key=self._rank)
            limits.append(
                "%d risk(s) were removed from this report entirely by a "
                "mitigating control (MITIG-001), so a clean result in those "
                "areas reflects a suppression rather than an absence" % hidden)
        if unsupportable:
            severity = max(severity, self.SEVERITY_HIGH, key=self._rank)
            limits.append(
                "%d mitigating control row(s) cannot support an audit "
                "conclusion (MITIG-002) - a blanket entry, a missing approver "
                "or a missing expiry - yet still suppress conflicts"
                % unsupportable)

        dead = detail("SODCOV-007", "rules_unfirable") or []
        if dead:
            severity = max(severity, self.SEVERITY_HIGH, key=self._rank)
            limits.append(
                "%d rule(s) name authorization objects this release does not "
                "define and can never fire" % len(dead))
        broken = ((detail("SODCOV-008", "fires_for_every_user") or 0)
                  + (detail("SODCOV-008", "can_never_fire") or 0))
        if broken:
            severity = max(severity, self.SEVERITY_HIGH, key=self._rank)
            limits.append(
                "%d rule(s) in the supplied ruleset cannot work as written"
                % broken)
        if "SODCOV-009" in seen:
            limits.append(
                "%d shipped rule(s) were replaced by the supplied ruleset"
                % len(detail("SODCOV-009", "replaced") or []))

        headline = {
            "not measured": "This segregation-of-duties result is NOT MEASURED",
            "unbounded": "This segregation-of-duties result is UNBOUNDED",
            "partial": "This segregation-of-duties result is PARTIAL",
            "usable": "This segregation-of-duties result is USABLE as scoped",
        }[verdict]

        self.finding(
            check_id="SODCOV-000",
            title="%s%s" % (headline,
                            "" if not limits else " - %d stated limit(s)"
                            % len(limits)),
            severity=severity,
            category=self.CATEGORY,
            description=(
                "%s. Read this before the conflict results, because it says "
                "what those results can and cannot mean.%s%s The verdict is the "
                "WEAKEST of the measures below, never an average: averaging "
                "broad transaction coverage against narrow Fiori coverage "
                "produces a comfortable number describing neither, and a "
                "summary that buries its worst input is the failure the checks "
                "below exist to report. Every figure here is taken from those "
                "checks rather than recalculated, so this statement and the "
                "detail cannot disagree."
                % (headline,
                   "" if not limits else " Stated limits: " + "; ".join(limits) + ".",
                   "" if limits else
                   " No limit was found that would qualify it: coverage was "
                   "measurable, bounded, and broad on every surface examined."
                   + ("" if suppression_checked else
                      " NOTE: whether any conflict was suppressed by a "
                      "mitigating control was not examined in this run, so "
                      "this statement covers ruleset coverage only."))),
            affected_items=["limit: " + l for l in limits],
            remediation=(
                "1. Quote the verdict, not the conflict count, when recording "
                "what this analysis covered. A conflict count without it "
                "describes the ruleset rather than the estate.\n"
                "2. Work the stated limits in the order given. They are ordered "
                "by how much each one undermines the result, and the first is "
                "the one that decides what the report is worth.\n"
                "3. Where a limit cannot be closed before the deadline, record "
                "it as scope rather than treating the clean areas as assessed. "
                "An unasked question and a good answer look identical on a "
                "page that does not distinguish them.\n"
                "4. Re-run after closing any limit; the verdict is derived, so "
                "it moves on its own once the underlying check does."),
            references=["docs/SOD_REFERENCE.md section 1.2 — coverage beats count",
                        "PCAOB AS 2201 .68 — the scope of testing performed"],
            details={
                "verdict": verdict,
                "limits": limits,
                "derived_from": sorted(
                    [c for c in seen
                     if c.startswith("SODCOV-") and c != "SODCOV-000"]
                    + [c for c in peers if c.startswith("MITIG-")]),
                # Absence of suppression data is NOT an absence of suppression.
                "suppression_checked": suppression_checked,
                "risks_hidden_by_mitigation": hidden,
                "coverage_state": "complete",
            },
            scope="aggregate",
        )

    @staticmethod
    def _rank(severity: str) -> int:
        """Order severities so the weakest dimension can win."""
        return {"INFO": 0, "LOW": 1, "MEDIUM": 2,
                "HIGH": 3, "CRITICAL": 4}.get(str(severity).upper(), 0)

    @staticmethod
    def _vocabulary_of(ruleset) -> Tuple[Set[str], Set[str]]:
        """(actions, objects) a ruleset can name. Exact, never fuzzy."""
        actions, objects = set(), set()
        for risk in ruleset or []:
            if not isinstance(risk, dict):
                continue
            for func in (risk.get("functions") or []):
                if not isinstance(func, dict):
                    continue
                for act in (func.get("actions") or []):
                    if str(act).strip():
                        actions.add(str(act).strip().upper())
                for perm in (func.get("permissions") or []):
                    if isinstance(perm, dict) and str(perm.get("object", "")).strip():
                        objects.add(str(perm["object"]).strip().upper())
        return actions, objects

    def _emit_ruleset_comparison(self) -> None:
        """What each of the two rulesets reaches that the other does not.

        Only meaningful when a ruleset was actually supplied; silent otherwise.
        """
        supplied = self._custom_rules()
        if not supplied:
            return
        shipped = self._shipped_ruleset()
        s_act, s_obj = self._vocabulary_of(supplied)
        p_act, p_obj = self._vocabulary_of(shipped)

        missing_act, missing_obj = sorted(p_act - s_act), sorted(p_obj - s_obj)
        extra_act, extra_obj = sorted(s_act - p_act), sorted(s_obj - p_obj)
        processes = sorted({str(r.get("process", "")).strip()
                            for r in shipped if isinstance(r, dict)} - {""})
        untouched = sorted(pr for pr in processes
                           if not (self._vocabulary_of(
                               [r for r in shipped
                                if isinstance(r, dict) and r.get("process") == pr]
                           )[0] & s_act))

        if not missing_act and not missing_obj and not extra_act and not extra_obj:
            return

        self.finding(
            check_id="SODCOV-010",
            # Lead with PROCESSES where whole ones are untouched. A raw count
            # of unnamed transactions is dominated by how many rules were
            # supplied, so on a small extension it reads as alarming when it is
            # merely arithmetic. "This ruleset does not touch payroll" is a
            # decision somebody owns; "366 transactions" is not.
            title=("Run alone, the supplied ruleset would not cover %d of this "
                   "ruleset's %d business processes at all"
                   % (len(untouched), len(processes)))
            if untouched else
            ("Run alone, the supplied ruleset would not name %d "
             "transaction(s) and %d authorization object(s) this one covers"
             % (len(missing_act), len(missing_obj)))
            if (missing_act or missing_obj) else
            ("The supplied ruleset reaches %d transaction(s) this one does not"
             % len(extra_act)),
            severity=(self.SEVERITY_MEDIUM if missing_act or missing_obj
                      else self.SEVERITY_INFO),
            category=self.CATEGORY,
            description=(
                "A ruleset was supplied alongside the shipped one, and this scan "
                "MERGED them — so the conflict results above were produced by "
                "both together. The comparison below is a different question, "
                "and the one that matters if the supplied ruleset is the one "
                "your GRC system runs on its own: by itself it names %d "
                "transactions and %d authorization objects, against %d and %d "
                "here.%s%s No attempt is made to match individual risks: "
                "identifiers and groupings will not correspond between two "
                "rulesets, and a fuzzy correspondence would read as precision it "
                "does not have. Transactions and objects are compared exactly."
                % (len(s_act), len(s_obj), len(p_act), len(p_obj),
                   "" if not (missing_act or missing_obj) else
                   " Running alone it would never name %d of the transactions "
                   "and %d of the objects covered here, so any conflict "
                   "reachable only through those is outside what it can find."
                   % (len(missing_act), len(missing_obj)),
                   "" if not (extra_act or extra_obj) else
                   " It also reaches %d transaction(s) and %d object(s) that the "
                   "shipped ruleset does not — a gap in THIS product rather than "
                   "in yours, and worth reporting for that reason."
                   % (len(extra_act), len(extra_obj)))),
            affected_items=(
                ["not named by the supplied ruleset: %s" % t
                 for t in missing_act[:30]]
                + ["object not discriminated by the supplied ruleset: %s" % o
                   for o in missing_obj[:20]]
                + ["reached only by the supplied ruleset: %s" % t
                   for t in extra_act[:20]]),
            remediation=(
                "1. Decide first whether the supplied file EXTENDS this ruleset "
                "or REPLACES it. If it was meant as an extension, a large gap "
                "below is expected and says nothing about your file; the figures "
                "still describe what your own GRC system reports, because that "
                "runs your ruleset alone.\n"
                "2. Work through the unnamed transactions by process rather than "
                "individually. A whole business process absent from a ruleset is "
                "a decision somebody should own; a handful of transactions "
                "usually is not.\n"
                "3. For each gap you decide matters, add the transaction to the "
                "function it belongs to rather than creating a new risk — the "
                "conflict is usually already described, just not with that "
                "entry point.\n"
                "4. Send us the capabilities your ruleset covers and ours does "
                "not. Those are gaps in this product, and the list above names "
                "them precisely."),
            references=["docs/SOD_REFERENCE.md section 1.2 — coverage beats count",
                        "data/sod_ruleset.json — the shipped rules"],
            details={
                "supplied_transactions": len(s_act),
                "supplied_objects": len(s_obj),
                "shipped_transactions": len(p_act),
                "shipped_objects": len(p_obj),
                "not_named_by_supplied": missing_act[:80],
                "objects_not_in_supplied": missing_obj[:60],
                "only_in_supplied": extra_act[:60],
                "objects_only_in_supplied": extra_obj[:40],
                "shipped_processes_untouched_by_supplied": untouched,
                "coverage_state": "complete",
            },
        )

    def _custom_rules(self) -> List[Dict[str, Any]]:
        custom = self.data.get(CUSTOM_RULESET_EXPORT)
        return custom if isinstance(custom, list) else []

    def _emit_custom_ruleset_defects(self) -> None:
        """Custom rules that cannot work, and shipped rules they displaced."""
        custom = self._custom_rules()
        if not custom:
            return

        fires_for_everyone, never_fires = [], []
        for i, risk in enumerate(custom):
            defect = self._rule_defect(risk)
            if not defect:
                continue
            rid = (str(risk.get("risk_id", "")).strip()
                   if isinstance(risk, dict) else "") or "entry %d" % (i + 1)
            (fires_for_everyone if "whole estate" in defect
             else never_fires).append("%s — %s" % (rid, defect))

        if fires_for_everyone or never_fires:
            self.finding(
                check_id="SODCOV-008",
                title=("%d rule(s) in the supplied ruleset cannot work as written"
                       % (len(fires_for_everyone) + len(never_fires))),
                severity=(self.SEVERITY_CRITICAL if fires_for_everyone
                          else self.SEVERITY_HIGH),
                category=self.CATEGORY,
                description=(
                    "This scan used a customer-supplied ruleset "
                    "(ara_ruleset), and %d of its %d rules are broken in a way "
                    "the engine does not report on its own.%s%s Neither failure "
                    "announces itself: the matcher is fail-closed, so a rule "
                    "that can never fire looks exactly like a rule that ran and "
                    "found nothing, and a rule with no gate at all looks like a "
                    "genuine estate-wide conflict."
                    % (len(fires_for_everyone) + len(never_fires), len(custom),
                       "" if not fires_for_everyone else
                       " %d of them FIRE FOR EVERY USER: a function that "
                       "declares neither actions nor permissions is held by "
                       "everybody, so the rule reports the entire user base as "
                       "conflicted."
                       % len(fires_for_everyone),
                       "" if not never_fires else
                       " %d can never fire for anybody, so whatever they were "
                       "written to catch is not being checked and the report is "
                       "silent about it." % len(never_fires))),
                affected_items=(fires_for_everyone + never_fires)[:40],
                remediation=(
                    "1. Fix the rules that fire for every user first. They are "
                    "not a coverage gap, they are noise that will bury the real "
                    "findings, and a report naming the whole user base as "
                    "conflicted destroys trust in the rest of it.\n"
                    "2. For each rule that can never fire, check the JSON keys "
                    "against a shipped rule: 'functions' (not 'function'), each "
                    "with 'actions' and 'permissions', and every permission "
                    "carrying an 'object'.\n"
                    "3. A segregation rule needs two functions. One function "
                    "describes a capability, not a conflict - if that is what "
                    "was meant, set risk_type to CRITICAL_ACTION or "
                    "CRITICAL_PERMISSION instead.\n"
                    "4. Re-run and confirm each corrected rule now appears in "
                    "the results, or is deliberately silent because the estate "
                    "does not hold it.\n"
                    "5. Treat previous clean results for these rules as "
                    "unmeasured rather than passed."),
                references=["docs/SOD_REFERENCE.md section 2 — the rule model",
                            "ara_ruleset.json — custom rule format"],
                details={
                    "custom_rules": len(custom),
                    "fires_for_every_user": len(fires_for_everyone),
                    "can_never_fire": len(never_fires),
                    "defects": (fires_for_everyone + never_fires)[:60],
                    "coverage_state": "complete",
                },
            )

        shipped = {str(r.get("risk_id", "")).upper(): r.get("name", "")
                   for r in self._shipped_ruleset()}
        replaced = [(rid, shipped[rid]) for rid in
                    (str(r.get("risk_id", "")).strip().upper()
                     for r in custom if isinstance(r, dict))
                    if rid and rid in shipped]
        if not replaced:
            return
        self.finding(
            check_id="SODCOV-009",
            title="%d shipped rule(s) were replaced by the supplied ruleset"
                  % len(replaced),
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=(
                "A custom rule whose risk_id matches a shipped one REPLACES it "
                "rather than being added alongside. That is a legitimate way to "
                "retune a rule for an estate, and it is reported because doing "
                "it unknowingly is not: an id chosen for a new rule that happens "
                "to collide with ours silently removes the shipped rule and its "
                "reasoning, and the ruleset count stays the same, so nothing "
                "looks different. Check that each replacement below was "
                "intended, and that the replacement covers at least what the "
                "shipped rule did."),
            affected_items=["%s — replaced shipped rule: %s" % (rid, name or "?")
                            for rid, name in sorted(replaced)][:40],
            remediation=(
                "1. Confirm each id below was meant to override the shipped "
                "rule of the same name, rather than colliding with it by "
                "accident.\n"
                "2. Where the collision was accidental, renumber the custom "
                "rule - a Z prefix keeps customer rules clear of ours.\n"
                "3. Where the override was intended, compare the two: the "
                "shipped rule's actions and permissions are the floor the "
                "replacement should meet or exceed, or coverage has been "
                "narrowed without anyone deciding to."),
            references=["ara_ruleset.json — custom rules override by risk_id"],
            details={"replaced": [rid for rid, _ in sorted(replaced)],
                     "coverage_state": "complete"},
        )

    def _shipped_ruleset(self) -> List[Dict[str, Any]]:
        """What we ship, regardless of what was injected or supplied."""
        from modules.access_risk_analysis import AccessRiskAnalysisAuditor
        return AccessRiskAnalysisAuditor.RULESET or []

    def _unverified_objects_note(self) -> str:
        """Say when object EXISTENCE was not checked.

        Without TOBJ this module can say which objects the estate grants and
        which the ruleset names, and cannot say whether a named object exists at
        all. A rule naming a mistyped object is silent, and silence here reads
        as coverage.
        """
        if self._object_catalogue():
            return ""
        return (" No authorization-object catalogue (TOBJ) was supplied, so "
                "whether every object the ruleset names actually EXISTS in this "
                "release was not checked. A rule naming an object that does not "
                "exist can never fire, and is indistinguishable here from a rule "
                "that ran and found nothing — supply auth_object_catalogue to "
                "measure it (SODCOV-007).")

    def _object_catalogue(self) -> Set[str]:
        """Authorization objects this system defines, from TOBJ."""
        out = set()
        for row in (self.data.get(OBJECT_CATALOGUE_EXPORT) or []):
            if not isinstance(row, dict):
                continue
            for key in ("OBJCT", "OBJECT", "AUTH_OBJECT", "NAME"):
                value = str(row.get(key, "")).strip().upper()
                if value:
                    out.add(value)
                    break
        return out

    def _emit_unknown_objects(self) -> None:
        """Rules naming authorization objects this release does not define.

        Reported as dead RULES rather than as unknown objects, because that is
        the consequence: a function whose permissions are all missing can never
        be held, and a segregation rule containing one can never fire. It sits
        in the library, is counted in the ruleset size, and answers nothing.
        """
        catalogue = self._object_catalogue()
        if not catalogue:
            return              # not supplied; disclosed on SODCOV-002 instead

        referenced, absent = set(), set()
        dead: List[str] = []
        for risk in self._risks():
            rid = str(risk.get("risk_id", "?"))
            for func in (risk.get("functions") or []):
                objs = {str(perm.get("object", "")).strip().upper()
                        for perm in (func.get("permissions") or [])}
                objs.discard("")
                if not objs:
                    continue
                referenced |= objs
                missing = objs - catalogue
                absent |= missing
                # ALL of them missing means this function is unholdable, which
                # kills the whole rule. Some missing is survivable: the default
                # match across a function's objects is "any".
                if missing == objs and rid not in dead:
                    dead.append(rid)

        if not absent:
            self.finding(
                check_id="SODCOV-007",
                title="Every authorization object the SoD ruleset names exists "
                      "in this system",
                severity=self.SEVERITY_INFO,
                category=self.CATEGORY,
                description=(
                    "All %d authorization objects referenced by the ruleset "
                    "appear in this system's object catalogue, so no rule is "
                    "dead because of a name that does not resolve. This does "
                    "not mean each object is the RIGHT one for the duty it "
                    "guards - only that a rule naming it can fire at all."
                    % len(referenced)),
                affected_items=[],
                remediation=(
                    "1. No action. Re-run this check after any ruleset change "
                    "or system upgrade, since both can invalidate an object "
                    "name that resolves today."),
                references=["TOBJ - authorization object definitions"],
                details={"objects_referenced": len(referenced),
                         "objects_absent": 0, "rules_unfirable": [],
                         "coverage_state": "complete"},
            )
            return

        self.finding(
            check_id="SODCOV-007",
            title=("%d SoD rule(s) can never fire: they require authorization "
                   "objects this system does not define" % len(dead))
            if dead else
            ("%d authorization object(s) named by the ruleset do not exist in "
             "this system" % len(absent)),
            severity=(self.SEVERITY_HIGH if dead else self.SEVERITY_MEDIUM),
            category=self.CATEGORY,
            description=(
                "The ruleset references %d authorization objects and %d of them "
                "are absent from this system's catalogue. An absent object is "
                "not the same as an ungranted one: the matcher is fail-closed, "
                "so a predicate naming an object nobody holds is simply not "
                "satisfied - correct behaviour - while a predicate naming an "
                "object that does not EXIST can never be satisfied by anyone, "
                "and is indistinguishable in the output from a rule that ran "
                "and found nothing.%s The usual causes are a transcription "
                "error in the ruleset, an object from a different SAP release "
                "or component than this system runs, or a rule written against "
                "an add-on that is not installed here."
                % (len(referenced), len(absent),
                   "" if not dead else
                   " %d rule(s) are dead as a result: every object on one of "
                   "their functions is missing, so that function can never be "
                   "held and the rule can never fire for anybody. Those rules "
                   "are counted in the ruleset size and answer nothing."
                   % len(dead))),
            affected_items=(
                ["%s — requires %s, absent here" % (rid, ", ".join(sorted(
                    {str(perm.get("object", "")).strip().upper()
                     for risk in self._risks() if risk.get("risk_id") == rid
                     for func in (risk.get("functions") or [])
                     for perm in (func.get("permissions") or [])} - catalogue)))
                 for rid in dead[:30]]
                + ["object not in catalogue: %s" % o
                   for o in sorted(absent)[:30]]),
            remediation=(
                "1. Check each absent object against SU21 in this system. A "
                "name that is simply mistyped is the cheapest case and the "
                "commonest.\n"
                "2. Where the object is real but belongs to a component this "
                "system does not run, remove or gate the rule rather than "
                "leaving it: a rule that cannot fire here inflates the ruleset "
                "size without adding coverage.\n"
                "3. Where the object is right but the FIELD is wrong, this "
                "check will not see it - it matches on object name only. "
                "Confirm the field against SU21 at the same time.\n"
                "4. Re-run after correcting. Rules listed as unfirable should "
                "disappear from this finding and begin appearing in the "
                "conflict results if the estate holds them.\n"
                "5. Treat any previous clean result for the rules named here as "
                "unmeasured rather than passed - they were not evaluated."),
            references=["TOBJ - authorization object definitions",
                        "SU21 - authorization object maintenance",
                        "docs/SOD_REFERENCE.md section 2"],
            details={
                "objects_referenced": len(referenced),
                "objects_absent": len(absent),
                "absent_objects": sorted(absent)[:60],
                "rules_unfirable": dead[:60],
                "coverage_state": "complete",
            },
        )

    def _other_surface_note(self) -> str:
        """A transaction-coverage figure must not read as an estate figure
        while a second, unmeasured surface exists."""
        apps, services, _ = self._fiori_surface()
        if not apps and not services:
            return ""
        return (" This estate ALSO publishes %d Fiori app(s) and %d OData "
                "service(s), which are a separate surface measured in "
                "SODCOV-006 — the figure above is about transaction codes "
                "only." % (len(apps), len(services)))

    def _fiori_surface(self):
        """(apps, services) this estate publishes through roles.

        Read from the tile and catalog exports rather than from role
        authorizations, because that is where the app -> service association
        lives. An app with no tile is not reachable from a launchpad, and an
        app whose tile names no service cannot be resolved to a back-end
        authorization at all — which is itself worth counting.
        """
        apps, services, unresolvable = set(), set(), set()
        for row in (self.data.get(FIORI_TILE_EXPORT) or []):
            if not isinstance(row, dict):
                continue
            app = str(row.get("APP_ID", row.get("APP", ""))).strip().upper()
            service = str(row.get("ODATA_SERVICE",
                                  row.get("SERVICE", ""))).strip().upper()
            if app:
                apps.add(app)
                if not service:
                    unresolvable.add(app)
            if service:
                services.add(service)
        for row in (self.data.get(ODATA_EXPORT) or []):
            if isinstance(row, dict):
                name = str(row.get("SERVICE_NAME",
                                   row.get("SERVICE", ""))).strip().upper()
                if name:
                    services.add(name)
        return apps, services, unresolvable

    def _emit_fiori_coverage(self, known_actions: Set[str],
                             known_objects: Set[str]) -> None:
        """What share of the Fiori surface the ruleset can name.

        Reported apart from the transaction figure on purpose: averaging the
        two would let a high transaction score conceal a Fiori score of zero,
        and on an S/4HANA estate the zero is the finding.
        """
        apps, services, unresolvable = self._fiori_surface()
        if not apps and not services:
            # No Fiori exports. NOT a Fiori-free estate — an unmeasured one.
            if self.data.get(FIORI_CATALOG_EXPORT):
                self._emit_unknown(
                    "catalogs were supplied but no tile or OData export, so the "
                    "apps behind them could not be resolved and the Fiori half "
                    "of this estate's SoD coverage is unmeasured.")
            return

        named_apps = apps & known_actions
        named_services = services & known_actions
        covered = len(named_apps) + len(named_services)
        total = len(apps) + len(services)
        fraction = covered / total if total else 0.0
        can_express = bool({ODATA_START_OBJECT,
                            WEBDYNPRO_START_OBJECT} & known_objects)

        self.finding(
            check_id="SODCOV-006",
            title="SoD ruleset sees %.0f%% of this estate's Fiori surface"
                  % (fraction * 100),
            severity=(self.SEVERITY_HIGH if fraction < LOW_COVERAGE_THRESHOLD
                      else self.SEVERITY_MEDIUM if covered < total
                      else self.SEVERITY_INFO),
            category=self.CATEGORY,
            description=(
                "This estate publishes %d Fiori app(s) and %d OData service(s) "
                "through roles, and the SoD ruleset names %d of them. An "
                "S/4HANA user reaches a capability through a Fiori app just as "
                "readily as through a transaction code, but the two are "
                "governed separately — so a conflict available only through "
                "Fiori cannot appear in any result derived from transaction "
                "codes.%s%s"
                % (len(apps), len(services), covered,
                   "" if can_express else
                   " The ruleset also names neither S_SERVICE nor S_START in "
                   "any predicate, so it currently cannot express a "
                   "permission-level Fiori rule even where an app is listed: a "
                   "Fiori app carries no permissions of its own, they belong to "
                   "the service behind it.",
                   "" if not unresolvable else
                   " %d app(s) have a tile naming no OData service, so they "
                   "cannot be resolved to a back-end authorization at all."
                   % len(unresolvable))),
            affected_items=sorted((apps | services) - known_actions)[:40],
            remediation=(
                "1. Treat this figure as separate from the transaction "
                "coverage figure. They measure different surfaces and "
                "averaging them conceals the weaker one.\n"
                "2. Where a business capability is reachable through both a "
                "transaction and a Fiori app, the risk needs both named, or it "
                "fires for one population of users and not the other.\n"
                "3. Resolve each app through its OData service to the back-end "
                "authorization objects, and put those objects in the "
                "function's permissions — that is what makes a Fiori rule "
                "permission-level rather than app-level.\n"
                "4. Where the ruleset cannot yet express Fiori rules at all, "
                "record that any clean SoD result covers the classic surface "
                "only."),
            references=["SAP Help: Scope of Risk Analysis — Fiori Catalog [FCAT] "
                        "has no standard ruleset",
                        "SAP Help: OData services have start authorization "
                        "object S_SERVICE; Web Dynpro apps have S_START",
                        "docs/SOD_REFERENCE.md section 4.1"],
            details={
                "fiori_apps": len(apps),
                "odata_services": len(services),
                "named_by_ruleset": covered,
                "coverage_fraction": round(fraction, 4),
                "can_express_permission_level_fiori_rules": can_express,
                "apps_with_no_service": sorted(unresolvable)[:20],
                "unseen_examples": sorted((apps | services) - known_actions)[:40],
                "coverage_state": "complete",
                "surface": "fiori",
            },
        )

    def _emit_unknown(self, why: str, evidence: Dict[str, Any] = None) -> None:
        self.finding(
            check_id="SODCOV-004",
            title="SoD ruleset coverage could not be measured",
            severity=self.SEVERITY_MEDIUM,
            category=self.CATEGORY,
            description=why,
            remediation=(
                "Treat any SoD result in this report as scoped to whatever the "
                "ruleset happens to cover, which is unmeasured here. This is a "
                "different statement from a clean estate."),
            references=["SAP Access Control 12.0 - List Actions in Roles But Not in Rules",
                        "SAP Access Control 12.0 - List Permissions in Roles But Not in Rules",
                        "SAP Access Control 12.0 - Embedded Action Calls in Programs"],
            details=dict(evidence or {}, coverage_state="unknown"),
        )
