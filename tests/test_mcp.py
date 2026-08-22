"""The MCP surface, and the three ways a read-only channel stops being one.

WHAT THESE TESTS PIN, none of which a review would reliably catch later:

  1. A WRITER APPEARING IN THE TOOL TABLE. "We only added read tools" survives
     exactly until somebody adds a convenient sixth. The absent functions are
     asserted BY NAME, because they live a few lines from the readers in the
     same module.
  2. THE SCOPE INVERTING. `server/db.py` records that an empty explicit scope
     means NOTHING, not everything. This is precisely the boundary where getting
     it backwards is invisible — a user with no systems would receive the whole
     estate through a channel nobody watches.
  3. A DEPENDENCY ARRIVING. requirements.txt states a single-digit runtime
     dependency count and test_spa_mount.py asserts the list verbatim; an MCP SDK
     would break a guarded invariant to save a hundred lines of JSON-RPC.
"""
from __future__ import annotations

import inspect
import io
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server import mcp, queries                                # noqa: E402

USER = {"id": 1, "username": "auditor", "role": "viewer"}


def _rpc(method: str, params: Dict[str, Any] | None = None, rid: Any = 1):
    req = {"jsonrpc": "2.0", "method": method}
    if rid is not None:
        req["id"] = rid
    if params is not None:
        req["params"] = params
    return req


# ═════════════════════════════════════════════════════════════════════════════
#  Read-only, enforced by construction
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("writer", [
    "transition_finding", "assign_finding", "bulk_transition",
    "save_view", "create_system",
])
def test_no_mutating_query_function_is_exposed(writer):
    """Asserted BY NAME. Each of these exists in `server/queries.py` a few lines
    from the readers this surface does expose, and a tool call carries no actor —
    so a transition made through here would be an unattributable state change."""
    assert hasattr(queries, writer), f"{writer} vanished; update this test"
    source = (ROOT / "server" / "mcp.py").read_text(encoding="utf-8")
    body = source.split("TOOLS: Dict", 1)[1].split("\ndef ", 1)[0]
    assert writer not in body


def test_every_exposed_handler_is_a_reader():
    """The other direction: whatever the table names must not be a writer, even
    one added under a read-sounding tool name."""
    banned = ("INSERT", "UPDATE", "DELETE", "transition", "assign", "save_view")
    source = (ROOT / "server" / "mcp.py").read_text(encoding="utf-8")
    table = source.split("TOOLS: Dict", 1)[1].split("\ndef _all_check_ids", 1)[0]
    for word in banned:
        assert word not in table, word


def test_an_unknown_tool_is_refused_and_says_the_surface_is_read_only():
    """The likeliest wrong call is a model trying to close a finding. The refusal
    should teach rather than just fail."""
    got = mcp.handle(_rpc("tools/call", {"name": "close_finding"}), [], USER)
    assert got["error"]["code"] == -32601
    assert "read-only" in got["error"]["message"]


def test_the_instructions_tell_the_model_what_it_cannot_do():
    """A model that believes it can change a finding will try. Saying so once, up
    front, is cheaper than refusing repeatedly."""
    text = mcp.handle(_rpc("initialize"), [], USER)["result"]["instructions"]
    assert "No tool here changes anything" in text
    assert "nothing was traversed" in text.lower()


# ═════════════════════════════════════════════════════════════════════════════
#  Scope
# ═════════════════════════════════════════════════════════════════════════════

def test_the_scope_is_passed_through_to_every_handler(monkeypatch):
    """Not re-derived, not defaulted. Whatever `auth.scope_for` returned is what
    the query layer receives."""
    seen: List[Any] = []
    monkeypatch.setattr(queries, "list_systems", lambda scope: seen.append(scope) or [])
    mcp.call_tool("list_systems", {}, [4, 9])
    assert seen == [[4, 9]]


def test_an_empty_scope_stays_empty_rather_than_becoming_everything(monkeypatch):
    """THE INVERSION THAT WOULD BE INVISIBLE. `server/db.py` records that an
    empty explicit scope means NOTHING. A user with no systems assigned must not
    receive the estate because a falsy list was read as "unset"."""
    seen: List[Any] = []
    monkeypatch.setattr(queries, "list_systems", lambda scope: seen.append(scope) or [])
    mcp.call_tool("list_systems", {}, [])
    assert seen == [[]]
    assert seen[0] is not None


def test_the_surface_runs_as_a_named_account_with_no_unscoped_mode():
    """An MCP server authenticating as itself would be a second access path with
    its own permissions — which is how a read-only channel becomes the one nobody
    audits."""
    cli = (ROOT / "server" / "cli.py").read_text(encoding="utf-8")
    section = cli.split('sub.add_parser(\n        "mcp"', 1)[1][:700]
    assert "there is no unscoped mode" in section
    assert "username" in inspect.signature(mcp.serve).parameters


def test_serving_an_unknown_account_refuses_rather_than_running_unscoped(monkeypatch):
    from server import db
    monkeypatch.setattr(db, "one", lambda *a, **k: None)
    with pytest.raises(SystemExit):
        mcp.serve("nobody", io.StringIO(""), io.StringIO())


# ═════════════════════════════════════════════════════════════════════════════
#  The protocol
# ═════════════════════════════════════════════════════════════════════════════

def test_initialize_answers_with_a_protocol_version_and_tool_capability():
    result = mcp.handle(_rpc("initialize"), [], USER)["result"]
    assert result["protocolVersion"] == mcp.PROTOCOL_VERSION
    assert "tools" in result["capabilities"]


def test_every_tool_publishes_a_schema_and_a_description():
    for tool in mcp._tool_list():
        assert tool["description"] and len(tool["description"]) > 30, tool["name"]
        assert tool["inputSchema"]["type"] == "object"


def test_a_required_argument_is_declared_as_required():
    spec = next(t for t in mcp._tool_list() if t["name"] == "get_finding")
    assert spec["inputSchema"]["required"] == ["finding_id"]


def test_a_notification_gets_no_reply():
    """A request with no id is a notification. Answering one is a protocol error
    that some clients tolerate and others hang on."""
    assert mcp.handle(_rpc("notifications/initialized", rid=None), [], USER) is None
    assert mcp.handle({"jsonrpc": "2.0", "method": "ping"}, [], USER) is None


def test_malformed_json_does_not_end_the_session():
    """A client that sends one bad line should not have to reconnect."""
    out = io.StringIO()
    mcp.serve.__wrapped__ if hasattr(mcp.serve, "__wrapped__") else None
    # Drive `handle` through the loop body via serve with a stubbed identity.
    from server import auth, db
    original_one, original_scope = db.one, auth.scope_for
    db.one = lambda *a, **k: {"id": 1, "username": "u", "role": "admin"}
    auth.scope_for = lambda user: None
    try:
        mcp.serve("u", io.StringIO('not json\n{"jsonrpc":"2.0","id":2,"method":"ping"}\n'), out)
    finally:
        db.one, auth.scope_for = original_one, original_scope
    lines = [json.loads(l) for l in out.getvalue().splitlines() if l.strip()]
    assert lines[0]["error"]["code"] == -32700
    assert lines[1]["id"] == 2


def test_a_failing_tool_returns_an_error_rather_than_killing_the_server(monkeypatch):
    monkeypatch.setattr(queries, "list_systems",
                        lambda scope: (_ for _ in ()).throw(RuntimeError("db down")))
    got = mcp.handle(_rpc("tools/call", {"name": "list_systems"}), [], USER)
    assert got["error"]["code"] == -32603
    assert "db down" in got["error"]["message"]


def test_an_unsupported_method_is_refused_not_ignored():
    got = mcp.handle(_rpc("resources/list"), [], USER)
    assert got["error"]["code"] == -32601


# ═════════════════════════════════════════════════════════════════════════════
#  The dependency budget
# ═════════════════════════════════════════════════════════════════════════════

def test_no_mcp_sdk_was_added():
    """requirements.txt states the discipline that replaced the stdlib-only
    charter, and test_spa_mount.py asserts the list verbatim. JSON-RPC over
    stdio is stdlib work."""
    reqs = (ROOT / "requirements.txt").read_text(encoding="utf-8").lower()
    assert "mcp" not in reqs
    assert len([l for l in reqs.splitlines()
                if l.strip() and not l.startswith("#")]) < 10


def test_the_module_imports_nothing_outside_stdlib_and_this_project():
    tree = __import__("ast").parse(
        (ROOT / "server" / "mcp.py").read_text(encoding="utf-8"))
    allowed = {"__future__", "json", "logging", "sys", "typing", "server", "modules"}
    for node in __import__("ast").walk(tree):
        if isinstance(node, __import__("ast").ImportFrom) and node.module:
            assert node.module.split(".")[0] in allowed, node.module
        elif isinstance(node, __import__("ast").Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
