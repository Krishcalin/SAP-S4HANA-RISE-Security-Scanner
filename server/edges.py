# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

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

Provenance is `configured` on every edge this module writes. `used` means the
relationship was actually exercised — a destination appearing in a gateway log, a
role whose holders logged on recently — and no configuration finding evidences
that. The column exists and stays honest by being left alone until something that
observes use fills it.

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
from typing import Any, Dict, Iterable, List, Optional, Tuple

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


def extract_edges(findings: Iterable[Dict[str, Any]],
                  default_system: Optional[str] = None,
                  rules: Optional[List[Dict[str, Any]]] = None
                  ) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """`(edges, stats)` for a set of findings.

    `stats` carries `declined_ambiguous` — findings where a rule matched, both
    sides were present, and both were plural. A caller that reports the edges
    without that number is reporting a graph as complete when it is not.
    """
    rules = load_rules() if rules is None else rules
    edges: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    stats = {"declined_ambiguous": 0, "rules_applied": 0, "findings_seen": 0}

    for finding in findings:
        check_id = str(finding.get("check_id") or "")
        applicable = [r for r in rules if _matches(check_id, r.get("check_prefix"))]
        if not applicable:
            continue
        stats["findings_seen"] += 1
        by_type = _objects_by_type(finding, default_system)
        for rule in applicable:
            sources = by_type.get(rule.get("from_type"), [])
            targets = by_type.get(rule.get("to_type"), [])
            if not sources or not targets:
                continue
            if len(sources) > 1 and len(targets) > 1:
                # The finding evidences the relationship without evidencing
                # WHICH. Counted rather than guessed — see the module docstring.
                stats["declined_ambiguous"] += 1
                continue
            stats["rules_applied"] += 1
            for source in sources:
                for target in targets:
                    if source == target:
                        continue      # a self-edge is never a relationship
                    key = (source, target, rule["edge_type"])
                    edge = edges.get(key)
                    if edge is None:
                        edge = {
                            "from_key": source,
                            "to_key": target,
                            "type": rule["edge_type"],
                            "check_id": check_id,
                            # Never anything else from a configuration finding.
                            "provenance": "configured",
                            "confidence": "derived_from_config",
                            "owner": "unknown",
                            "check_ids": [],
                        }
                        edges[key] = edge
                    if check_id and check_id not in edge["check_ids"]:
                        edge["check_ids"].append(check_id)

    out = []
    for edge in edges.values():
        edge["check_ids"].sort()
        edge["attributes"] = {"check_ids": edge.pop("check_ids")}
        out.append(edge)
    out.sort(key=lambda e: (e["from_key"], e["to_key"], e["type"]))
    return out, stats
