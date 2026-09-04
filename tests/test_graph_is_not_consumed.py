"""The scan prints graph statistics. What it says about them must stay true.

THIS FILE HAS ALREADY DONE ITS JOB ONCE. It was written when nothing read the
graph: `graph_node` and `graph_edge` were written by `server/ingest.py` and
selected nowhere, while the scan described each edge's provenance in careful
detail — so a reader concluded the product reasoned over an attack graph that it
only stored. The scan was made to say "nothing reads this graph yet", and this
test tied that sentence to the code rather than merely asserting its presence.

Then `graph.path_actors` landed and the test FAILED, which is exactly what it
was for: a disclaimer left behind after it stops being true is worse than never
having written one. The sentence now describes what the graph feeds, and the
same assertions hold it to the new reality.

THE BOUNDARY IS THE PART WORTH PROTECTING. Attack paths and chokepoints are
still the shipped templates matched against FINDINGS, and would be identical if
the graph were empty. What the graph adds is the half a template cannot express:
a hop names the checks that evidence it, never the accounts, so only the edges
can say who holds the privileges the route depends on. Claiming more than that
would be the original failure in a new costume.
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

#: The claim the CLI made while the graph was unread. It must not survive a
#: reader existing.
STALE_CLAIM = "nothing reads this graph yet"

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


def test_the_scan_does_not_claim_the_graph_is_unread_once_it_is_read():
    readers = graph_readers()
    cli = (SERVER / "cli.py").read_text(encoding="utf-8")
    if readers:
        assert STALE_CLAIM not in cli, (
            "%s now reads the graph, so the scan must stop saying nothing does."
            % ", ".join(readers))
    else:
        assert STALE_CLAIM in cli, (
            "The scan prints graph node and edge counts and nothing in server/ "
            "reads those tables. Without a line saying so, the counts read as a "
            "capability the product does not have.")


def test_the_scan_says_what_the_graph_feeds():
    """A count with no stated purpose is what started this. Whatever the state,
    the graph block has to end in a sentence about what the numbers are for."""
    cli = (SERVER / "cli.py").read_text(encoding="utf-8")
    assert re.search(r"read by the path pages|nothing reads this graph yet", cli), (
        "the scan prints graph statistics and no longer says what they are for")


def test_the_claim_names_the_boundary_it_must_not_cross():
    """Paths and chokepoints are template-matched against findings. If the scan
    ever implies the graph produces THEM, it is overclaiming again — which is
    the failure this whole file exists to prevent."""
    cli = (SERVER / "cli.py").read_text(encoding="utf-8")
    if STALE_CLAIM in cli:
        return                     # nothing is read; the other tests cover it
    assert "templates matched against" in cli, (
        "the scan says the graph is read but no longer says where its "
        "contribution stops; paths and chokepoints still come from templates")


def test_the_writers_list_is_not_quietly_covering_a_reader():
    """`ingest.py` is exempt because it WRITES the graph. If it ever grows a
    read that feeds a verdict, the exemption hides exactly what this file is
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
    """The column names a design that was intended and never built -- an edge
    closing an attack path. `path_actors` does not populate it, and while it
    stays NULL no path's OPEN/CLOSED state depends on the graph. If that
    changes, the boundary described above has moved and the scan's wording has
    to move with it."""
    graph = (SERVER / "graph.py").read_text(encoding="utf-8")
    assignments = re.findall(r"closed_by_edge\s*=\s*([^\s,\"']+)", graph)
    assert assignments, "closed_by_edge is no longer written at all"
    assert set(assignments) == {"NULL"}, (
        "closed_by_edge is now set to something other than NULL (%s), so the "
        "graph decides whether a path is open." % sorted(set(assignments)))
