"""The scan prints graph statistics. It must also say what they are for.

MEASURED, NOT ASSUMED. On a 404-finding estate the ingest reports 939 graph
nodes and 15 edges, and the console then serves 23 attack paths and 151
chokepoints. Those numbers look like a graph being traversed and are not:
`graph_node` and `graph_edge` are written by `server/ingest.py` and SELECTed
nowhere else, and `attack_path.closed_by_edge` -- the column whose name says an
edge can close a path -- is only ever set to NULL. The paths come from
`data/attack_paths.json` matched against FINDINGS, and would be identical if the
graph were empty.

WHY THAT NEEDED SAYING OUT LOUD. The CLI describes the graph with real care --
how each edge was evidenced, why `used` may be low, which relationships were
declined as ambiguous. A reader finishing those lines concludes the product is
reasoning over an attack graph. A confident number standing where a capability
is not is the exact failure this product exists to report in other people's
tools, and it was in our own output.

THIS TEST IS THE PART THAT KEEPS IT HONEST IN BOTH DIRECTIONS. It does not
merely assert the sentence is present. It checks the sentence against the code:
while nothing reads the graph, the disclaimer must be there; the day something
starts reading it, this fails and the disclaimer must go. A note like that,
left behind after it stops being true, is worse than never having written it.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SERVER = ROOT / "server"

#: Files allowed to touch the graph tables without counting as "consuming" it.
#: `ingest` writes them; `migrations` maintains the schema; `edges` derives the
#: rows before they are stored.
WRITERS = {"ingest.py", "migrations.py", "edges.py"}

#: The claim the CLI makes while the graph is unread.
DISCLAIMER = "nothing reads this graph yet"

READ = re.compile(r"\b(FROM|JOIN)\s+graph_(node|edge)\b", re.IGNORECASE)


def graph_readers() -> dict:
    """Files that SELECT from the graph tables, and the lines that do."""
    found = {}
    for path in sorted(SERVER.glob("*.py")):
        if path.name in WRITERS:
            continue
        hits = [line.strip()
                for line in path.read_text(encoding="utf-8").splitlines()
                if READ.search(line)]
        if hits:
            found[path.name] = hits
    return found


def test_the_cli_says_the_graph_is_unread_while_it_is_unread():
    readers = graph_readers()
    cli = (SERVER / "cli.py").read_text(encoding="utf-8")
    if readers:
        assert DISCLAIMER not in cli, (
            "Something now reads the graph (%s), so the scan output must stop "
            "saying nothing does. Remove the line and describe what it feeds."
            % ", ".join(readers))
    else:
        assert DISCLAIMER in cli, (
            "The scan prints graph node and edge counts, and nothing in server/ "
            "reads those tables. Without a line saying so, the counts read as a "
            "capability the product does not have.")


def test_the_writers_list_is_not_quietly_covering_a_reader():
    """`ingest.py` is exempt because it WRITES the graph. If it ever grows a
    read that feeds a verdict, the exemption hides exactly what this test is
    for -- so the one read it is allowed to have is pinned here."""
    ingest = (SERVER / "ingest.py").read_text(encoding="utf-8")
    reads = [line.strip() for line in ingest.splitlines() if READ.search(line)]
    assert len(reads) <= 1, (
        "ingest.py now reads the graph in %d places; it used to be the single "
        "node-key lookup it needs in order to write edges. Check whether one of "
        "them is a consumer: %s" % (len(reads), reads))
    if reads:
        assert "node_key" in reads[0], (
            "ingest.py's read of the graph is no longer the node-key lookup: %s"
            % reads[0])


def test_closed_by_edge_is_still_never_populated():
    """The column names the design that was intended -- an edge closing an
    attack path -- and is only ever written as NULL. If that changes, edges are
    feeding a verdict and the disclaimer above is wrong."""
    graph = (SERVER / "graph.py").read_text(encoding="utf-8")
    assignments = re.findall(r"closed_by_edge\s*=\s*([^\s,\"']+)", graph)
    assert assignments, "closed_by_edge is no longer written at all"
    assert set(assignments) == {"NULL"}, (
        "closed_by_edge is now set to something other than NULL (%s), so edges "
        "close paths and the graph IS consumed." % sorted(set(assignments)))
