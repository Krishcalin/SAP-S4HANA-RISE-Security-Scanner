"""Access control that is MISSING rather than switched off.

Every CDS and RAP rule in this scanner before this file matched something a
developer WROTE: `#NOT_ALLOWED`, `authorization master ( none )`. Those are
explicit, deliberate, and comparatively rare — somebody typed them and probably
thought about it. The common failure is the opposite one, and no per-file rule
can see it: a view is exposed, nobody ever wrote a DCL role for it, and there is
nothing in the view's own source to match on. The absence is the defect.

`modules/abap_sast_extra.py:CDS_RULES` claimed to cover this. Its comment read
"A CDS view without a DCL role is readable by anyone who can read the view, and
the omission is invisible in the view's own source — which is why this is a check
on what is ABSENT", above a rule whose pattern is
`@AccessControl.authorizationCheck: #NOT_REQUIRED|#NOT_ALLOWED`. That is a check
on what is PRESENT. A view with no annotation and no role produced no finding at
all, which was confirmed by running the scanner over exactly that pair.

WHY THE ABSENCE IS A REAL DEFECT, from SAP rather than from inference
  * ABAP Keyword Documentation, "ABAP CDS - Access Control": "**If a CDS role is
    defined for a CDS entity**, the access conditions are evaluated implicitly
    each time an object is accessed using Open SQL or using an SADL query". No
    role, no evaluation.
  * SAP's own `abap-cheat-sheets`, "Authorization Checks", on the four annotation
    values: `#NOT_REQUIRED` — "No access control is needed, granting full access
    to all users"; `#CHECK` — "A **warning** is issued if no access control
    object is present"; `#MANDATORY` — "An access control object **must** be
    present"; `#NOT_ALLOWED` — "An access control object must not be present. If
    one exists, it is disregarded."

`#CHECK` is the default when the annotation is omitted, and it warns. It does not
enforce. So an exposed view carrying no annotation and no role is readable in
full by anyone who can reach it, and the only two artefacts that would show it
are in different files.

WHY THIS DOES NOT REPORT EVERY VIEW WITHOUT A ROLE
It would be trivial — and useless — to flag every roleless view in an estate.
Most of them are correct. The same SAP page says why: "Implicit access control
only takes place when a CDS view is accessed directly using Open SQL or using an
SADL query. When CDS views used as data sources in different CDS entities are
accessed indirectly, no implicit access control takes place", and recommends that
"accesses made on CDS entities without associated CDS role can be wrapped in CDS
views with associated roles". A basic view consumed only by another view is
supposed to have no role.

So this reports only views with POSITIVE EVIDENCE OF EXPOSURE found in the same
tree — published as OData, named by a service definition, or given a RAP
behaviour. A view whose exposure cannot be established is not reported, and the
count of those is disclosed rather than dropped.

AND THE FAILURE MODE THAT WOULD MAKE IT WORTHLESS
An export that omits DCL entirely — an abapGit checkout of one package, a
partial pull — would make every view in it look roleless, and this check would
report the whole estate at HIGH. That is not a finding, it is a missing input.
When a tree contains exposed views and NO access-control artefact at all, this
emits a coverage finding instead and reports nothing else.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

# ── CDS view entity, both spellings ─────────────────────────────────────────
# `define view Z_X` (classic) and `define view entity Z_X` (view entity). Also
# `define transient view entity`, `define custom entity`, `define abstract entity`.
_VIEW_DECL = re.compile(
    r"\bdefine\s+(?:root\s+)?(?:transient\s+|abstract\s+|custom\s+)?"
    r"(?:view\s+entity|view|entity)\s+([A-Za-z_]\w*)",
    re.IGNORECASE)

_AUTH_ANNOTATION = re.compile(
    r"@AccessControl\s*\.\s*authorizationCheck\s*:\s*#(\w+)", re.IGNORECASE)

# ── DCL: which entities a role grants on ────────────────────────────────────
# `grant select on Z_View where ...`, and the `grant select on Z_View` of an
# inheriting role. The entity is what binds the role to the view.
_GRANT_ON = re.compile(r"\bgrant\s+select\s+on\s+([A-Za-z_]\w*)", re.IGNORECASE)

# ── exposure evidence ───────────────────────────────────────────────────────
_ODATA_PUBLISH = re.compile(r"@OData\s*\.\s*publish\s*:\s*true", re.IGNORECASE)
_SERVICE_EXPOSE = re.compile(r"\bexpose\s+([A-Za-z_]\w*)", re.IGNORECASE)
_BEHAVIOR_FOR = re.compile(r"\bdefine\s+behavior\s+for\s+([A-Za-z_]\w*)",
                           re.IGNORECASE)

#: A behaviour definition that says anything at all about authorization. Any of
#: these means the developer engaged with the question; ABAP-RAP-001/002 judge
#: whether the answer was a good one. Only their TOTAL absence is this file's
#: business.
_BEHAVIOR_AUTH = re.compile(
    r"\bauthorization\s+(?:master|dependent)\b|\bauthorization\s*:", re.IGNORECASE)

#: `authorization master ( global )`, `( instance )` or `( global, instance )`.
#: SAP's BDL syntax is `authorization master {( global ) |( instance ) |
#: ( global, instance )}`, and the two are not interchangeable — see
#: `global_only_behaviors` for what the difference costs.
_AUTH_MASTER = re.compile(
    r"\bauthorization\s+master\s*\(([^)]*)\)", re.IGNORECASE)

#: Annotation values that make a role irrelevant, so a missing role is not the
#: story. `#NOT_ALLOWED` and `#NOT_REQUIRED` are already ABAP-CDS-001's subject
#: and must not be reported twice under a different id; `#MANDATORY` cannot
#: activate without a role, so a tree showing one is an incomplete export rather
#: than an unprotected view.
_ANNOTATION_SETTLES_IT = frozenset(
    {"NOT_ALLOWED", "NOT_REQUIRED", "MANDATORY", "PRIVILEGED_ONLY"})


class CdsAuthorizationIndex(object):
    """What every CDS artefact in one tree says about access control.

    Built file by file during the scan walk, then asked questions afterwards.
    Nothing here matches a pattern against a single file and calls it a finding —
    the whole point is the join.
    """

    def __init__(self) -> None:
        #: view name (upper) -> {"file", "line", "annotation": str|None}
        self.views: Dict[str, Dict[str, Any]] = {}
        #: entity names (upper) any DCL role grants on
        self.granted: Set[str] = set()
        #: how many access-control artefacts were seen at all
        self.dcl_files = 0
        #: view names (upper) with positive evidence of being exposed,
        #: -> the evidence string, for the finding to quote
        self.exposed: Dict[str, str] = {}
        #: behaviour definitions: entity (upper) -> {"file", "line", "has_auth"}
        self.behaviors: Dict[str, Dict[str, Any]] = {}

    # ── ingestion ───────────────────────────────────────────────────────────

    def add_file(self, text: str, label: str, suffix: str) -> None:
        """Index one CDS-family artefact. `suffix` decides what it can contribute."""
        lowered = suffix.lower()
        if lowered.endswith(("dcls", "dcls.abap")):
            self.dcl_files += 1
            for match in _GRANT_ON.finditer(text):
                self.granted.add(match.group(1).upper())
            return

        if lowered.endswith(("bdef", "asbdef")):
            self._add_behavior(text, label)
            return

        self._add_view(text, label)

    def _add_behavior(self, text: str, label: str) -> None:
        for match in _BEHAVIOR_FOR.finditer(text):
            entity = match.group(1).upper()
            # A behaviour definition exposes its entity through OData, which is
            # the strongest exposure evidence available in a source tree.
            self.exposed.setdefault(entity, "a RAP behaviour is defined for it")
            # The authorization clause belongs to this behaviour block. Scoped to
            # the text from this `define behavior` to the next one, so a second
            # behaviour's clause is not credited to a first that lacks one.
            nxt = _BEHAVIOR_FOR.search(text, match.end())
            block = text[match.start():nxt.start() if nxt else len(text)]
            self.behaviors[entity] = {
                "file": label,
                "line": text.count("\n", 0, match.start()) + 1,
                "has_auth": bool(_BEHAVIOR_AUTH.search(block)),
                "auth_master": self._auth_master_kinds(block),
            }

    def _add_view(self, text: str, label: str) -> None:
        # A service definition exposes the entities it names.
        for match in _SERVICE_EXPOSE.finditer(text):
            self.exposed.setdefault(match.group(1).upper(),
                                    "a service definition exposes it")

        for match in _VIEW_DECL.finditer(text):
            name = match.group(1).upper()
            line = text.count("\n", 0, match.start()) + 1
            # The annotation belongs to the view it precedes. Taken from the end
            # of the previous declaration so a second view in one file cannot
            # inherit the first one's annotation — the same statement-boundary
            # discipline `cap_xsuaa._annotation_span_before` needed.
            start = self._previous_end(text, match.start())
            annotation = _AUTH_ANNOTATION.search(text, start, match.start())
            self.views[name] = {
                "file": label,
                "line": line,
                "annotation": annotation.group(1).upper() if annotation else None,
            }
            if _ODATA_PUBLISH.search(text, start, match.start()):
                self.exposed.setdefault(name, "@OData.publish: true")

    @staticmethod
    def _auth_master_kinds(block):
        """Which authorization kinds a behaviour block declares, or None.

        None means the block declares no `authorization master ( ... )` at all,
        which is ABAP-RAP-005's subject and not this one's. An empty set means it
        declared one whose contents could not be read, and is treated the same
        way — unreadable is not evidence.
        """
        match = _AUTH_MASTER.search(block)
        if not match:
            return None
        kinds = {k.strip().lower() for k in match.group(1).split(",")}
        return {k for k in kinds if k in ("global", "instance")}

    @staticmethod
    def _previous_end(text: str, position: int) -> int:
        previous = None
        for earlier in _VIEW_DECL.finditer(text, 0, position):
            previous = earlier
        return previous.end() if previous else 0

    # ── questions ───────────────────────────────────────────────────────────

    def unprotected_views(self) -> List[Dict[str, Any]]:
        """Exposed views that no DCL role in this tree grants on."""
        out = []
        for name, view in sorted(self.views.items()):
            if name in self.granted:
                continue
            if (view["annotation"] or "") in _ANNOTATION_SETTLES_IT:
                continue
            evidence = self.exposed.get(name)
            if not evidence:
                continue
            out.append(dict(view, name=name, exposure=evidence))
        return out

    def unexposed_roleless_views(self) -> int:
        """Roleless views whose exposure could NOT be established.

        Not a finding and not silence: reported as a number beside the findings,
        because SAP's own guidance is that a basic view consumed only through
        another view is SUPPOSED to have no role, and a reader needs to know how
        many were set aside on that reasoning rather than examined.
        """
        return sum(1 for name, view in self.views.items()
                   if name not in self.granted
                   and (view["annotation"] or "") not in _ANNOTATION_SETTLES_IT
                   and name not in self.exposed)

    def global_only_behaviors(self) -> List[Dict[str, Any]]:
        """Behaviours whose authorization is global and never per-instance.

        SAP draws the distinction explicitly: global authorization "restricts
        data access or the ability to perform certain operations for an ENTIRE
        RAP BO, regardless of individual instances", while instance
        authorization "applies checks based on the STATE of an entity instance",
        and "both global and instance authorization checks can be implemented
        simultaneously".

        So a behaviour declaring only `( global )` answers one question — may
        this user perform this operation at all — and never the second, may they
        perform it on THIS record. Correct for an entity whose rules genuinely do
        not depend on the record; the whole vulnerability for one whose rules do.
        """
        return [dict(info, entity=entity)
                for entity, info in sorted(self.behaviors.items())
                if info.get("auth_master") == {"global"}]

    def behaviors_without_authorization(self) -> List[Dict[str, Any]]:
        return [dict(info, entity=entity)
                for entity, info in sorted(self.behaviors.items())
                if not info["has_auth"]]

    def dcl_is_missing_entirely(self) -> bool:
        """True when the tree exposes views and carries no access control at all.

        The difference between "nobody wrote roles" and "roles were not
        exported". Reporting every view at HIGH on a checkout that simply did not
        include DCL would be the single most damaging false positive this
        scanner could produce, so that case becomes a coverage finding instead.
        """
        return self.dcl_files == 0 and bool(self.exposed)


# ── the rule table ─────────────────────────────────────────────────────────
#
# A TABLE RATHER THAN TWO LITERALS IN A FUNCTION, for one reason that is not
# style: `modules/coverage.py:module_check_ids` skips any file without
# `BaseAuditor` in it, so an id written only inside this helper is invisible to
# every denominator until the day it first fails — the precise defect
# `runtime_check_families` exists to end, reproduced. Registered there alongside
# the other three `ABAP-` tables, these are counted like every other rule.
#
# Unlike those tables these rows carry no `pattern`: there is nothing to match.
# The finding IS the absence, and the analysis lives in the index above.
CROSS_ARTIFACT_RULES: List[Dict[str, Any]] = [
    {
        "id": "ABAP-CDS-003",
        "category": "Missing Authorization",
        "name": "Exposed CDS view has no access-control role",
        "severity": "HIGH",
        "cwe": "CWE-862",
    },
    {
        "id": "ABAP-RAP-006",
        "category": "Missing Authorization",
        "name": "RAP behaviour authorises the operation but never the instance",
        "severity": "MEDIUM",
        "cwe": "CWE-863",
    },
    {
        "id": "ABAP-RAP-005",
        "category": "Missing Authorization",
        "name": "RAP behaviour definition states no authorization at all",
        "severity": "HIGH",
        "cwe": "CWE-862",
    },
]

_BY_ID = {r["id"]: r for r in CROSS_ARTIFACT_RULES}


# ── findings, in the shape scan_text produces ───────────────────────────────

def _finding(check_id: str, name: str, severity: str, category: str, file: str,
             obj: str, line: int, statement: str, description: str,
             recommendation: str) -> Dict[str, Any]:
    """One raw finding, in the shape `AbapSourceScanner.scan_text` produces.

    `check_id` and `category` are KEYWORD arguments at every call site, and that
    is not a style choice. `modules/coverage.py` reads check ids by walking the
    AST for a `check_id=` keyword and pairs it with the `category=` in the same
    call; an id passed positionally to a helper is invisible to it, so the check
    would be missing from every denominator until the day it first failed — which
    is the defect that file was written to prevent, reproduced here.
    """
    return {
        "rule_id": check_id,
        "name": name,
        "category": category,
        "severity": severity,
        "literal_operand": False,
        "cwe": "CWE-862",
        "file": file,
        "object": obj,
        "line": line,
        "statement": statement,
        "snippet": statement,
        "description": description,
        "recommendation": recommendation,
        # These are STRUCTURAL, not textual. `pattern-only` is the evidence class
        # for a regex that matched a line and might be describing correct code;
        # this is the absence of an artefact across a whole tree, established by
        # reading every file in it. It is at least as well evidenced as a taint
        # path, and grading it `pattern-only` would let --gate ignore it.
        "confidence": "confirmed",
        "flow": None,
        "suppressed_by_nosec": False,
        "lex_degraded": False,
    }


def cross_artifact_findings(index: CdsAuthorizationIndex) -> List[Dict[str, Any]]:
    """Everything that can only be seen by reading more than one file."""
    if index.dcl_is_missing_entirely():
        return []                      # the caller reports this as coverage

    out: List[Dict[str, Any]] = []

    for view in index.unprotected_views():
        stated = ("no @AccessControl.authorizationCheck annotation, so the "
                  "default #CHECK applies"
                  if view["annotation"] is None
                  else "@AccessControl.authorizationCheck: #%s" % view["annotation"])
        out.append(_finding(
            check_id="ABAP-CDS-003",
            name=_BY_ID["ABAP-CDS-003"]["name"],
            severity=_BY_ID["ABAP-CDS-003"]["severity"],
            category=_BY_ID["ABAP-CDS-003"]["category"],
            file=view["file"], obj=view["name"], line=view["line"],
            statement="define view %s — %s" % (view["name"], stated),
            description=("This view is exposed (%s) and no DCL role in this source tree "
             "grants select on it. SAP's rule is that access conditions are "
             "evaluated only IF a CDS role is defined for the entity, so with no "
             "role there is no row-level restriction: every user who can reach "
             "the view reads all of it, whatever authorizations protect the "
             "underlying tables. The annotation does not save it — #CHECK, the "
             "default when none is written, only issues a WARNING when no access "
             "control object is present, and a warning does not stop an "
             "activation or a transport. Nothing in this view's own source shows "
             "the problem, which is why it survives code review: the defect is "
             "the file that was never written." % view["exposure"]),
            recommendation=("1. Decide whether this view's rows need restricting. If the data is "
             "genuinely public within the system, set "
             "@AccessControl.authorizationCheck: #NOT_REQUIRED and record why "
             "beside it — an explicit decision a reviewer can check.\n"
             "2. Otherwise write a DCL access control: DEFINE ROLE with GRANT "
             "SELECT ON %s WHERE ( <field> ) = ASPECT PFCG_AUTH ( <object>, "
             "<field>, ACTVT = '03' ).\n"
             "3. Set the annotation to #MANDATORY once the role exists, so a "
             "future edit that deletes the role fails activation instead of "
             "silently unprotecting the view.\n"
             "4. Check what else consumes this view: access control is applied "
             "only on DIRECT access, so a consumer reading it through another "
             "view is not covered by the new role either.\n"
             "5. Re-run the scan to confirm the view resolves to a role."
             % view["name"]),
        ))

    for behavior in index.global_only_behaviors():
        out.append(_finding(
            check_id="ABAP-RAP-006",
            name=_BY_ID["ABAP-RAP-006"]["name"],
            severity=_BY_ID["ABAP-RAP-006"]["severity"],
            category=_BY_ID["ABAP-RAP-006"]["category"],
            file=behavior["file"], obj=behavior["entity"], line=behavior["line"],
            statement="define behavior for %s — authorization master ( global )"
                      % behavior["entity"],
            description=(
                "This behaviour declares `authorization master ( global )` and "
                "nothing else, so its authorization handler is asked one question "
                "- may this user perform this operation at all - and never the "
                "second one, may they perform it on THIS record. SAP draws the "
                "line explicitly: global authorization restricts operations for "
                "an entire RAP business object 'regardless of individual "
                "instances', while instance authorization 'applies checks based "
                "on the state of an entity instance', and the two can be declared "
                "together as ( global, instance ). Global-only is correct where "
                "the rule genuinely does not depend on the record, and is the "
                "entire vulnerability where it does: a user cleared to update any "
                "instance is thereby cleared to update every instance - every "
                "company code, every plant, every other department's documents. "
                "Reported at MEDIUM rather than HIGH because only the data model "
                "settles which case this is, and this check cannot read that."),
            recommendation=(
                "1. Decide whether access to this entity depends on the record: "
                "if any user should be able to act on some instances and not "
                "others, global-only authorization cannot express that.\n"
                "2. Where it does, declare `authorization master ( global, "
                "instance )` and implement GET_INSTANCE_AUTHORIZATIONS in the "
                "behaviour pool alongside the global handler.\n"
                "3. Base the instance check on the record's own fields - company "
                "code, plant, owner - against the user's authorization object, "
                "not on the operation alone.\n"
                "4. Where global-only IS correct, record that in a comment beside "
                "the declaration so the next reviewer need not re-derive it from "
                "the data model.\n"
                "5. Consider a RAP precheck as well, which rejects unwanted "
                "incoming VALUES before they reach the transactional buffer - a "
                "different question again from who may act and on what.\n"
                "6. Re-run the scan."),
        ))

    for behavior in index.behaviors_without_authorization():
        out.append(_finding(
            check_id="ABAP-RAP-005",
            name=_BY_ID["ABAP-RAP-005"]["name"],
            severity=_BY_ID["ABAP-RAP-005"]["severity"],
            category=_BY_ID["ABAP-RAP-005"]["category"],
            file=behavior["file"], obj=behavior["entity"], line=behavior["line"],
            statement="define behavior for %s — no authorization clause"
                      % behavior["entity"],
            description=("This behaviour definition contains no `authorization master`, no "
             "`authorization dependent` and no `authorization` clause of any "
             "kind, so nothing declares who may create, update or delete through "
             "it. This is distinct from ABAP-RAP-001 and ABAP-RAP-002, which "
             "report a behaviour that declares authorization and then disables "
             "it: those were a decision, and this is a decision nobody made. A "
             "behaviour is reachable over OData, so the modifying operations it "
             "exposes are the ones an external caller reaches first."),
            recommendation=("1. Add `authorization master ( global )` to the root entity of the "
             "behaviour and implement the corresponding authorization handler in "
             "the behaviour implementation class.\n"
             "2. Use `authorization dependent` on child entities so they inherit "
             "the root's decision rather than each answering separately.\n"
             "3. Implement instance authorization where the permitted operations "
             "depend on the state of the record, not only on the user's role.\n"
             "4. Remember that DCL restricts READ; it does not restrict create, "
             "update or delete. A behaviour with a well-written DCL role and no "
             "authorization clause is still unrestricted for modification.\n"
             "5. Re-run the scan to confirm the behaviour declares its "
             "authorization."),
        ))

    return out
