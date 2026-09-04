"""Graph edges, derived from findings that name both ends of a relationship.

WHAT THIS COMPLETES
-------------------
`graph_node` has been populated since the schema landed — `extract_nodes` turns a
finding's typed `affected_objects` into nodes, and their `first_seen` is truthful
because it was recorded when they were first seen. `graph_edge` was defined at the
same time, with a `provenance` column, a `confidence` column and a comment about
never validating reachability, and nothing has ever written a row into it. This is
the missing half: the nodes had no relationships between them.

WHAT AN EDGE CLAIMS
-------------------
That two objects named by ONE finding stand in the stated relationship, because
the check that produced the finding is about that relationship. Every edge is
written `confidence='derived_from_config'`, which is not a hedge but the literal
truth: this product holds no connection to the system and never will, so nothing
here was traversed, reached or validated. The schema says so, the console repeats
it, and a buyer who has seen a dynamic scanner will ask — the answer has to be
prepared rather than improvised.

PROVENANCE, AND THE NARROW THING `used` MEANS
--------------------------------------------
A configuration finding alone evidences only `configured`: the export says the
relationship exists. `used` needs evidence that something was exercised, and the
one such source this product can read offline is the logon export — so an edge
FROM a user becomes `used` when that user has a successful logon in the exported
window, and `active_users` explains how the two shapes of that export are read.

The claim is deliberately weaker than it looks. A logon proves the ACCOUNT is
live, never that the user invoked this particular role or destination; nothing in
a configuration export could prove that. `used` therefore reads "this relationship
belongs to an account that is actually in use". That is worth having — a dormant
account holding SAP_ALL and a live one holding it are different risks — and it is
worth not overstating, because the moment it reads as "this role was exercised" a
reviewer will act on a traversal that was never observed.

Where no logon export was supplied, every edge stays `configured` and
`stats["provenance_evidence"]` is None. That is not a finding that nothing is
used; it is the record that nobody looked.

THE PAIRING RULE, WHICH IS THE WHOLE DESIGN
-------------------------------------------
A finding lists its objects FLAT. `AUTH-002` names one role, one authorization
object and two users, and which user holds which role is visible only in the
display string `"Role Z_BASIS_SUPER — 2 user(s) [ADMIN1, CONTRACTOR7]"`.

Two wrong answers were available. Cross-producting every user against every role
would fabricate relationships — three roles and five users would yield fifteen
edges where five exist. Parsing the display string would resurrect the `display`
identification basis this product deliberately retired, where a finding was
identified by prose rather than by the objects it names.

So an edge is emitted only where the pairing is UNAMBIGUOUS: one side of the rule
names exactly one object in that finding, and the singleton is joined to each
object on the other side. Where both sides are plural the finding evidences the
relationship without evidencing WHICH, and it is declined — and counted, so the
gap is visible rather than silent. That count is the honest measure of what a
flat object list costs.

WHY THE RULES ARE CONTENT
-------------------------
`data/graph_edges.json`, for the same reason `data/attack_paths.json` is content:
adding an edge kind is a data change, never a code change. Each rule names the
check family it derives from and why that check is about that relationship, so an
edge can never claim more than the scanner actually detected.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from modules.rise_ownership import classify_destination_owner
from server.identity import AffectedObject, IdentityError, _CLOUD_SCOPED_TYPES

RULES_PATH = Path(__file__).resolve().parents[1] / "data" / "graph_edges.json"


def load_rules(path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """The edge rules, or an empty list if the content file cannot be read.

    An empty list disables edge extraction and nothing else. That is the right
    failure: nodes, paths, chokepoints and every check continue to work, and the
    graph simply has no relationships in it — which is exactly the state this
    module was written to leave behind, so degrading back to it is safe.
    """
    try:
        payload = json.loads((path or RULES_PATH).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return list(payload.get("rules") or [])


def _matches(check_id: str, prefix: str) -> bool:
    return str(check_id or "").upper().startswith(str(prefix or "").upper())


def _objects_by_type(finding: Dict[str, Any],
                     default_system: Optional[str]) -> Dict[str, List[str]]:
    """`{type: [node_key, ...]}` for one finding, using the node keying.

    Keyed exactly as `extract_nodes` keys them, because an edge that named a node
    the node table does not hold would be an edge to nothing. The cloud-scope
    rule is mirrored for the same reason it exists there: borrowing the ABAP SID
    for a BTP object would place it in the wrong namespace, and an edge would
    then join two systems that never met.
    """
    out: Dict[str, List[str]] = defaultdict(list)
    for raw in (finding.get("affected_objects") or finding.get("subject") or ()):
        try:
            obj = AffectedObject.coerce(raw)
        except IdentityError:
            continue          # a malformed object must not abort edge extraction
        if (obj.system is None and default_system
                and obj.type not in _CLOUD_SCOPED_TYPES):
            obj = AffectedObject(obj.type, obj.name, default_system,
                                 obj.client, obj.qualifier)
        key = obj.key()
        if key not in out[obj.type]:
            out[obj.type].append(key)
    return out


#: Column names for the three things a logon export has to yield, taken from
#: `modules/log_monitoring.py:check_logon_anomalies`, which has been reading this
#: same file since long before edges existed. Mirrored rather than reinvented: two
#: readers of one export disagreeing about which column holds the user name is a
#: bug that only shows up on a customer's data, where neither author can see it.
_LOGON_USER_KEYS = ("USERNAME", "BNAME", "USER")
_LOGON_EVENT_KEYS = ("EVENT", "TYPE", "LOGON_TYPE")
_LOGON_COUNT_KEYS = ("COUNT", "OCCURRENCES")


def _is_success(event: str) -> bool:
    """Success exactly as `log_monitoring` judges it, and nothing wider."""
    return "SUCCESS" in event or event in ("S", "1")


def active_users(data: Optional[Dict[str, Any]]) -> Optional[Set[str]]:
    """Users with a successful logon in the exported window, or None.

    NONE AND EMPTY ARE DIFFERENT, AND THE DIFFERENCE IS THE POINT. None means no
    logon export was supplied, so nothing is known about activity and no edge may
    be marked either way. An empty set means the export was supplied and named
    nobody active, which is a real, if unusual, answer. Collapsing the two would
    turn "we could not look" into "we looked and found nobody" — the failure this
    codebase spends most of its comments avoiding.

    TWO EXPORT SHAPES, AND WHY BOTH ARE HANDLED. `logon_events.csv` is usually
    AGGREGATED — `USERNAME,EVENT,COUNT`, one row per user per outcome — and the
    sample corpus contains `UNKNOWN_USER1,SUCCESS,0`, a success row meaning zero
    successful logons. Reading that row as activity would mark the one account in
    the file that never got in as the active one, so a count of zero is not
    evidence. The other shape is one row per logon with no outcome column at all;
    there, a row IS a logon, so every named user counts. The shape is decided from
    the columns present across the export rather than per row, because a single
    row missing its outcome in an otherwise-typed export is a hole, not a shape.

    A failed logon is evidence of an ATTEMPT and never of use. Counting it would
    mark an account active on the strength of somebody failing to get in.
    """
    if not data or data.get("logon_events") is None:
        return None
    rows = [r for r in (data.get("logon_events") or []) if isinstance(r, dict)]
    upper_rows = [{str(k).strip().upper(): v for k, v in r.items()} for r in rows]
    # Shape decided across the export, not per row — see the docstring.
    typed = any(any(str(r.get(k, "")).strip() for k in _LOGON_EVENT_KEYS)
                for r in upper_rows)

    out: Set[str] = set()
    for row in upper_rows:
        name = ""
        for key in _LOGON_USER_KEYS:
            if str(row.get(key, "") or "").strip():
                name = str(row[key]).strip().upper()
                break
        if not name:
            continue
        if typed:
            event = ""
            for key in _LOGON_EVENT_KEYS:
                if str(row.get(key, "") or "").strip():
                    event = str(row[key]).strip().upper()
                    break
            if not _is_success(event):
                continue
        count = "1"
        for key in _LOGON_COUNT_KEYS:
            if row.get(key) is not None and str(row[key]).strip():
                count = str(row[key]).strip()
                break
        try:
            if int(float(count)) <= 0:
                continue       # a success row counting zero successes
        except ValueError:
            pass               # unparseable count, same as log_monitoring: one
        out.add(name)
    return out


def observed_users(data: Optional[Dict[str, Any]]) -> Optional[Set[str]]:
    """Every user the logon export names, whatever the outcome, or None.

    THE COMPANION `active_users` NEEDS TO STAY HONEST. A user missing from the
    logon export is not an inactive user — the export may cover a different
    window, a different client, or a population that simply does not overlap the
    one holding roles. The sample corpus is exactly that case: its logon export
    and its role assignments name disjoint sets of users, so nothing can be
    settled either way and `used` comes out zero for a reason that has nothing to
    do with activity.

    Set difference against this tells a caller which users were ASSESSED and
    found quiet, and which were never in scope of the evidence at all. Reporting
    only the first as "configured" would present the second as a finding.
    """
    if not data or data.get("logon_events") is None:
        return None
    out: Set[str] = set()
    for raw in (data.get("logon_events") or []):
        if not isinstance(raw, dict):
            continue
        row = {str(k).strip().upper(): v for k, v in raw.items()}
        for key in _LOGON_USER_KEYS:
            if str(row.get(key, "") or "").strip():
                out.add(str(row[key]).strip().upper())
                break
    return out


def _user_name(node_key: str) -> str:
    """`user:ADMIN1@PRD` -> `ADMIN1`. Keying is `type:name@system#qualifier`."""
    if ":" not in node_key:
        return ""
    name = node_key.split(":", 1)[1]
    for sep in ("@", "#"):
        name = name.split(sep, 1)[0]
    return name.strip().upper()


def _provenance(rule: Dict[str, Any], from_key: str,
                active: Optional[Set[str]]) -> str:
    """`used` where the relationship's holder was demonstrably active.

    WHAT THIS CLAIMS, EXACTLY. The schema defines `used` as "it was actually
    exercised... a role whose holders logged on recently", and that is the reading
    implemented here: an edge FROM a user becomes `used` when that user has a
    successful logon in the exported window.

    WHAT IT DOES NOT CLAIM, and the distinction is easy to lose in a UI. A logon
    proves the ACCOUNT is live. It does not prove the user invoked this particular
    role or destination — nothing in a configuration export could prove that. So
    the honest reading of a `used` edge is "this relationship belongs to an account
    that is actually in use", not "this relationship was exercised". A dormant
    account's dangerous role and a live account's are different risks, and that
    difference is the entire value of the column; claiming the stronger thing
    would spend it for nothing.

    Only edges whose SOURCE is a user can be settled, because only a user carries
    logon evidence. A role-to-authorization edge has no holder of its own and
    stays `configured` whatever the logon export says.
    """
    if active is None:
        return "configured"
    if rule.get("from_type") != "user":
        return "configured"
    name = _user_name(from_key)
    return "used" if name and name in active else "configured"


def _edge_owner(rule: Dict[str, Any], to_key: str, deployment_mode: str,
                dest_hosts: Optional[Dict[str, str]]) -> str:
    """Who operates the thing at the far end of this edge.

    `graph_edge.owner` has held `customer|sap|unknown` since the schema landed and
    every edge was written `unknown`, while `rise_ownership.classify_destination_owner`
    answered exactly this question for findings a few files away. An RFC
    destination SAP operates in a RISE tenant is a real trust relationship and
    belongs in the graph — it is simply not the customer's to sever, and a
    chokepoint that recommends closing it is recommending a ticket they cannot
    raise against a connection they do not control.

    Only destination edges can be settled. A role or an authorization object has
    no operator distinct from the system it lives in, so those stay `unknown`
    rather than borrowing the destination heuristic.
    """
    if rule.get("to_type") != "destination" or dest_hosts is None:
        return "unknown"
    name = to_key.split(":", 1)[1].split("@", 1)[0].split("#", 1)[0] if ":" in to_key else ""
    if not name:
        return "unknown"
    return classify_destination_owner(
        name, dest_hosts.get(name.upper(), ""), deployment_mode)


def _add_edge(edges: Dict[Tuple[str, str, str], Dict[str, Any]],
              source: str, target: str, rule: Dict[str, Any],
              check_id: str, active: Optional[Set[str]],
              deployment_mode: str,
              dest_hosts: Optional[Dict[str, str]]) -> None:
    """Record one edge, merging with an identical edge from another check.

    Extracted so the declared-pairing path and the inferred path build edges
    identically. Two ways of constructing an edge would eventually disagree
    about provenance or owner, and the disagreement would be invisible: both
    produce a row.
    """
    if source == target:
        return                # a self-edge is never a relationship
    key = (source, target, rule["edge_type"])
    edge = edges.get(key)
    if edge is None:
        edge = {
            "from_key": source,
            "to_key": target,
            "type": rule["edge_type"],
            "check_id": check_id,
            "provenance": _provenance(rule, source, active),
            "confidence": "derived_from_config",
            "owner": _edge_owner(rule, target, deployment_mode, dest_hosts),
            "check_ids": [],
        }
        edges[key] = edge
    if check_id and check_id not in edge["check_ids"]:
        edge["check_ids"].append(check_id)


def _declared_pairs(finding: Dict[str, Any], default_system: Optional[str]
                    ) -> Dict[Tuple[str, str], List[Tuple[str, str]]]:
    """`{(from_type, to_type): [(from_key, to_key), ...]}` a finding DECLARED.

    From the finding's optional `relations` — see `BaseAuditor.finding`. Keyed
    through the same `AffectedObject` coercion the flat path uses, because an
    edge whose end is keyed differently from the node table is an edge to
    nothing, and a declared pair is no more exempt from that than an inferred
    one.

    A malformed entry is skipped rather than raising: a module getting one pair
    wrong must not cost the run every other edge.
    """
    out: Dict[Tuple[str, str], List[Tuple[str, str]]] = defaultdict(list)
    for raw in (finding.get("relations") or ()):
        if not isinstance(raw, dict):
            continue
        try:
            src = AffectedObject.coerce(raw.get("from"))
            dst = AffectedObject.coerce(raw.get("to"))
        except (IdentityError, AttributeError, TypeError):
            continue
        pair = []
        for obj in (src, dst):
            if (obj.system is None and default_system
                    and obj.type not in _CLOUD_SCOPED_TYPES):
                obj = AffectedObject(obj.type, obj.name, default_system,
                                     obj.client, obj.qualifier)
            pair.append(obj)
        key = (pair[0].type, pair[1].type)
        entry = (pair[0].key(), pair[1].key())
        if entry not in out[key]:
            out[key].append(entry)
    return out


def extract_edges(findings: Iterable[Dict[str, Any]],
                  default_system: Optional[str] = None,
                  rules: Optional[List[Dict[str, Any]]] = None,
                  active: Optional[Set[str]] = None,
                  observed: Optional[Set[str]] = None,
                  deployment_mode: str = "on_prem",
                  dest_hosts: Optional[Dict[str, str]] = None
                  ) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """`(edges, stats)` for a set of findings.

    `stats` carries `declined_ambiguous` — findings where a rule matched, both
    sides were present, and both were plural. A caller that reports the edges
    without that number is reporting a graph as complete when it is not.

    `active` is the set of users with a successful logon in the exported window,
    from `active_users()`. Where it is None no logon export was supplied and every
    edge stays `configured` — which is not a claim that nothing is used, only the
    base fact that the export says the relationship exists.
    `stats["provenance_evidence"]` names which of those two situations produced
    the result, so a reader can tell a landscape with no dormant accounts from a
    landscape nobody checked.

    `observed` is every user the logon export NAMES, from `observed_users()`, and
    it exists so that a third situation is distinguishable from the first two: the
    export was supplied, was read, and covers none of the users holding edges. The
    counts it produces — `users_on_edges`, `users_in_logon_export`,
    `users_absent_from_logon_export` — are what stop a `used` of zero from being
    read as a verdict on the landscape when it is a verdict on the export.
    """
    rules = load_rules() if rules is None else rules
    edges: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    stats = {"declined_ambiguous": 0, "rules_applied": 0, "findings_seen": 0,
             "used": 0, "configured": 0, "owner_sap": 0, "owner_customer": 0,
             "provenance_evidence": "logon_events" if active is not None else None}

    for finding in findings:
        check_id = str(finding.get("check_id") or "")
        applicable = [r for r in rules if _matches(check_id, r.get("check_prefix"))]
        if not applicable:
            continue
        stats["findings_seen"] += 1
        by_type = _objects_by_type(finding, default_system)
        declared = _declared_pairs(finding, default_system)
        for rule in applicable:
            # WHAT THE FINDING SAID, BEFORE WHAT CAN BE INFERRED FROM IT.
            #
            # A module that knows which user holds which profile can now say so
            # (see `relations` on BaseAuditor.finding). Where it has, the pairing
            # is evidence rather than inference, so it is used as-is and the
            # ambiguity question below never arises — three declared pairs among
            # three users and three profiles are three edges, not nine and not
            # zero.
            pairs = declared.get((rule.get("from_type"), rule.get("to_type")))
            if pairs:
                stats["rules_applied"] += 1
                stats["from_declared"] = stats.get("from_declared", 0) + len(pairs)
                for source, target in pairs:
                    _add_edge(edges, source, target, rule, check_id, active,
                              deployment_mode, dest_hosts)
                continue

            sources = by_type.get(rule.get("from_type"), [])
            targets = by_type.get(rule.get("to_type"), [])
            if not sources or not targets:
                continue
            if len(sources) > 1 and len(targets) > 1:
                # The finding evidences the relationship without evidencing
                # WHICH. Counted rather than guessed — see the module docstring.
                # A module can lift its own findings out of this branch by
                # declaring `relations`.
                stats["declined_ambiguous"] += 1
                continue
            stats["rules_applied"] += 1
            for source in sources:
                for target in targets:
                    _add_edge(edges, source, target, rule, check_id, active,
                              deployment_mode, dest_hosts)

    out = []
    edge_users: Set[str] = set()
    for edge in edges.values():
        stats["used" if edge["provenance"] == "used" else "configured"] += 1
        if edge["owner"] in ("sap", "customer"):
            stats["owner_" + edge["owner"]] += 1
        if edge["from_key"].startswith("user:"):
            name = _user_name(edge["from_key"])
            if name:
                edge_users.add(name)
        edge["check_ids"].sort()
        edge["attributes"] = {"check_ids": edge.pop("check_ids")}
        out.append(edge)
    out.sort(key=lambda e: (e["from_key"], e["to_key"], e["type"]))

    # DID THE EVIDENCE EVEN COVER THESE USERS. None where the caller supplied no
    # population to compare against — an unanswered question rather than a zero.
    stats["users_on_edges"] = len(edge_users)
    if observed is None:
        stats["users_in_logon_export"] = None
        stats["users_absent_from_logon_export"] = None
    else:
        covered = {u for u in edge_users if u in observed}
        stats["users_in_logon_export"] = len(covered)
        stats["users_absent_from_logon_export"] = len(edge_users) - len(covered)
    return out, stats
