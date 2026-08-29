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
            "where false positives and false negatives both come from."
            % (len(granted_objects), len(seen), len(missing)),
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
