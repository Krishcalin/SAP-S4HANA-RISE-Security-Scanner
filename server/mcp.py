"""A read-only MCP surface over the query layer.

WHY THERE IS NO SDK HERE. `requirements.txt` states the discipline that replaced
this project's stdlib-only charter — a single-digit runtime dependency count —
and `tests/test_spa_mount.py` asserts the list verbatim, so an MCP SDK would
break a guarded invariant to save a hundred lines. MCP is JSON-RPC 2.0 over
stdio; the standard library speaks both.

READ-ONLY IS ENFORCED BY CONSTRUCTION, NOT BY INTENT. `TOOLS` names the query
functions this surface exposes, and every one of them is a reader.
`queries.transition_finding`, `assign_finding`, `bulk_transition`, `save_view`
and `create_system` exist a few lines away in the same module and are absent
here. A test asserts that absence by NAME, because "we only added read tools" is
the kind of claim that survives exactly until somebody adds a convenient sixth.

SCOPE IS THE SAME FUNCTION THE API USES. `auth.scope_for` decides which systems
an identity may see, and this surface runs AS a named console account rather than
as itself — there is no ambient MCP identity, and no default of "everything". An
assistant reading a landscape it should not see is the same breach as a user
doing it, and it must not become easier because the caller is a model.

THE EMPTY SCOPE MEANS NOTHING, NOT EVERYTHING. That rule is written into
`server/db.py` and it is repeated here because this is exactly the boundary where
inverting it would be invisible: a user with no systems assigned would otherwise
get the whole estate through a channel nobody is watching.

WHAT IT DELIBERATELY DOES NOT EXPOSE. Audit-log records are personal data and
never leave the modules that read them; `btp_users` is not collected at all; the
XSUAA graph terminates at IdP group and holder count rather than named users.
None of that changes because the reader is an assistant. This surface returns
what the console API returns and nothing further.
"""
from __future__ import annotations

import json
import logging
import sys
from typing import Any, Callable, Dict, List, Optional, TextIO

from server import auth, db, graph, queries, sapcontent

log = logging.getLogger(__name__)

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "monitorrisk"

#: The read-only surface. Name -> (description, handler, JSON-schema properties).
#:
#: Each handler takes `(scope, arguments)` and returns something JSON-serialisable.
#: Adding a WRITER here would not merely be a bug, it would be a privilege
#: escalation dressed as a feature: the console requires a signed-in session and
#: records an actor on every transition, and a tool call carries neither.
TOOLS: Dict[str, Dict[str, Any]] = {
    "list_systems": {
        "description": "The SAP systems and SaaS tenants in scope, with their "
                       "deployment mode, tier, and when each was last assessed. "
                       "last_assessed is null for a system no completed scan has "
                       "ever covered — that is not the same as recently clean, "
                       "and nothing else in this estate is a statement about it.",
        "properties": {},
        "handler": lambda scope, args: queries.list_systems(scope),
    },
    "dashboard_summary": {
        "description": "Finding counts by severity and state across the estate "
                       "in scope, plus the most recent run.",
        "properties": {},
        "handler": lambda scope, args: queries.dashboard_summary(scope),
    },
    "list_findings": {
        "description": "Findings in scope, filtered. Returns the same page the "
                       "console shows, including its coverage caveats.",
        "properties": {
            "state": {"type": "string",
                      "description": "open, submitted_to_provider, mitigated, ..."},
            "severity": {"type": "string",
                         "description": "CRITICAL, HIGH, MEDIUM, LOW, INFO"},
            "system_id": {"type": "integer"},
            "page": {"type": "integer", "description": "1-based"},
        },
        "handler": lambda scope, args: queries.list_findings(
            scope,
            state=args.get("state"),
            severity=args.get("severity"),
            system_id=args.get("system_id"),
            page=int(args.get("page") or 1)),
    },
    "get_finding": {
        "description": "One finding with its remediation, risk narrative, "
                       "ownership and history.",
        "properties": {"finding_id": {"type": "integer"}},
        "required": ["finding_id"],
        "handler": lambda scope, args: queries.get_finding(
            int(args["finding_id"]), scope),
    },
    "recent_runs": {
        "description": "Recent scan runs in scope, newest first, with their "
                       "coverage summary.",
        "properties": {"limit": {"type": "integer"}},
        "handler": lambda scope, args: queries.recent_runs(
            scope, limit=min(int(args.get("limit") or 10), 50)),
    },
    "attack_paths": {
        "description": "Open risk paths and the choke points that sever them. "
                       "Derived from configuration, never traversed.",
        "properties": {},
        "handler": lambda scope, args: {
            "summary": graph.path_summary(scope),
            "chokepoints": graph.chokepoints(scope),
        },
    },
    "baseline_coverage": {
        "description": "How the published check catalogue lines up against SAP's "
                       "Security Baseline: requirements covered, requirements "
                       "not addressed, and checks that answer none of them.",
        "properties": {},
        "handler": lambda scope, args: sapcontent.coverage(
            [c for ids in _all_check_ids().values() for c in ids]),
    },
}


def _all_check_ids() -> Dict[str, List[str]]:
    from modules.coverage import all_check_ids
    return all_check_ids()


def _identity(username: str) -> Dict[str, Any]:
    """The console account this surface runs as.

    NO AMBIENT IDENTITY. An MCP server that authenticated as itself would be a
    second access path with its own permissions, which is how a read-only channel
    becomes the one nobody audits. It runs as somebody, and that somebody's scope
    is the one `auth.scope_for` already computes for the console.
    """
    user = db.one("SELECT id, username, role FROM app_user WHERE username = %s",
                  (username,))
    if user is None:
        raise SystemExit(f"no such user: {username}")
    return dict(user)


def _tool_list() -> List[Dict[str, Any]]:
    out = []
    for name, spec in sorted(TOOLS.items()):
        schema: Dict[str, Any] = {"type": "object",
                                  "properties": spec.get("properties", {})}
        if spec.get("required"):
            schema["required"] = list(spec["required"])
        out.append({"name": name, "description": spec["description"],
                    "inputSchema": schema})
    return out


def call_tool(name: str, arguments: Dict[str, Any],
              scope: Optional[List[int]]) -> Any:
    """Run one read-only tool under the caller's scope."""
    spec = TOOLS.get(name)
    if spec is None:
        raise KeyError(name)
    return spec["handler"](scope, arguments or {})


def handle(request: Dict[str, Any], scope: Optional[List[int]],
           user: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """One JSON-RPC request to one response, or None for a notification.

    A notification — a request with no `id` — gets no reply. Answering one is a
    protocol error that some clients tolerate and others hang on.
    """
    method = request.get("method")
    request_id = request.get("id")

    if method == "initialize":
        result: Any = {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": "1"},
            # The client shows this before the first call. It is the right place
            # to say what the surface is, because a model that believes it can
            # change a finding will try.
            "instructions": (
                "Read-only view of a MonitorRisk estate, running as console "
                "account '%s' and limited to what that account may see. No tool "
                "here changes anything: transitions, assignment and saved views "
                "are console actions that record an actor, and a tool call "
                "carries none. Findings are derived from configuration exports; "
                "nothing was traversed or reached on a live system."
                % user.get("username")),
        }
    elif method in ("tools/list", "list_tools"):
        result = {"tools": _tool_list()}
    elif method in ("tools/call", "call_tool"):
        params = request.get("params") or {}
        name = params.get("name") or ""
        try:
            payload = call_tool(name, params.get("arguments") or {}, scope)
        except KeyError:
            return _error(request_id, -32601,
                          "no such tool: %s. This surface is read-only; "
                          "transitions and assignment are console actions." % name)
        except Exception as exc:                       # noqa: BLE001
            log.exception("tool %s failed", name)
            return _error(request_id, -32603, f"{name} failed: {exc}")
        result = {"content": [{"type": "text",
                               "text": json.dumps(payload, default=str, indent=2)}]}
    elif method in ("notifications/initialized", "initialized"):
        return None
    elif method == "ping":
        result = {}
    else:
        if request_id is None:
            return None
        return _error(request_id, -32601, f"unsupported method: {method}")

    if request_id is None:
        return None
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id,
            "error": {"code": code, "message": message}}


def serve(username: str, stdin: Optional[TextIO] = None,
          stdout: Optional[TextIO] = None) -> int:
    """Read newline-delimited JSON-RPC from stdin until it closes."""
    user = _identity(username)
    scope = auth.scope_for(user)
    # THE EMPTY SCOPE MEANS NOTHING. `scope_for` returns None for an admin, which
    # the query layer reads as unrestricted, and a list otherwise — an empty list
    # is a user with no systems, and it must stay empty rather than becoming None
    # on the way through.
    source = stdin or sys.stdin
    sink = stdout or sys.stdout

    for line in source:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except ValueError:
            sink.write(json.dumps(_error(None, -32700, "invalid JSON")) + "\n")
            sink.flush()
            continue
        response = handle(request, scope, user)
        if response is not None:
            sink.write(json.dumps(response, default=str) + "\n")
            sink.flush()
    return 0
