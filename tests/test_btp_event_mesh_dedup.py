"""
BTP-EM-003 (Event Mesh cross-namespace subscriptions) must count each
(queue, foreign namespace) pair once.

The display line and the graph object for this check are keyed on the foreign
NAMESPACE, not on the topic. A queue that subscribes to two topics under the
same foreign namespace (``sap/foo`` and ``sap/bar`` while it owns ``sap/s4``)
is one cross-namespace fact, not two — but the check builds the line inside the
per-topic loop, so before the fix it emitted the identical line, and an
identical affected object, once per topic. That inflated ``affected_count`` and
the "N queue(s)" total for a difference no reader could see, and it put a
duplicate node on the finding's ``affected_objects``.

This is the one duplicate-``affected_items`` observation the accuracy audit left
open. These tests hold it shut, and — just as importantly — prove the de-dup is
keyed on (queue, namespace) so it does NOT collapse two genuinely different
foreign namespaces, or the same namespace reached from two different queues.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.btp_cloud_surface import BtpCloudSurfaceAuditor  # noqa: E402

EM = "—"  # the em dash the check builds its line with


def _line(name: str, foreign: str, own: str) -> str:
    return (f"Queue: {name} {EM} subscribes to foreign namespace: "
            f"{foreign} (own: {own})")


def _run(event_mesh: dict):
    auditor = BtpCloudSurfaceAuditor({"event_mesh": event_mesh}, {})
    auditor.check_event_mesh_topics()
    for f in auditor.findings:
        if f.get("check_id") == "BTP-EM-003":
            return f
    return None


# An estate that exercises all three cases at once:
#   app/orders   — two topics, SAME foreign namespace  -> one line (was two)
#   app/orders2  — same foreign namespace, DIFFERENT queue -> its own line
#   app/multi    — two topics in TWO foreign namespaces -> two lines
DATA = {
    "queues": [
        {"name": "app/orders", "namespace": "own/x", "accessPolicy": "restricted",
         "topics": ["foreign/created", "foreign/changed"]},
        {"name": "app/orders2", "namespace": "own/x", "accessPolicy": "restricted",
         "topics": ["foreign/created"]},
        {"name": "app/multi", "namespace": "own/x", "accessPolicy": "restricted",
         "topics": ["red/a", "blue/b"]},
    ]
}


def test_a_queue_touching_one_foreign_namespace_twice_is_listed_once():
    f = _run(DATA)
    assert f is not None, "BTP-EM-003 did not fire on cross-namespace data"
    items = f["affected_items"]

    # No duplicate lines, and the stored count agrees with the list.
    assert len(items) == len(set(items)), f"duplicate affected_items: {items}"
    assert f["affected_count"] == len(items)

    # The two-topics-one-namespace queue contributes exactly one line.
    assert items.count(_line("app/orders", "foreign", "own/x")) == 1


def test_dedup_is_per_queue_and_per_namespace_not_over_collapsed():
    f = _run(DATA)
    items = set(f["affected_items"])

    # Same foreign namespace from a different queue is still its own fact.
    assert _line("app/orders2", "foreign", "own/x") in items
    # Two genuinely different foreign namespaces stay two lines.
    assert _line("app/multi", "red", "own/x") in items
    assert _line("app/multi", "blue", "own/x") in items

    # Exactly the four distinct (queue, namespace) facts, nothing more.
    assert items == {
        _line("app/orders", "foreign", "own/x"),
        _line("app/orders2", "foreign", "own/x"),
        _line("app/multi", "red", "own/x"),
        _line("app/multi", "blue", "own/x"),
    }


def test_the_structured_objects_carry_no_duplicate_node():
    f = _run(DATA)
    objs = f.get("affected_objects", [])
    keys = [(o.get("type"), o.get("name"), o.get("qualifier")) for o in objs]
    assert len(keys) == len(set(keys)), f"duplicate affected_objects: {keys}"
    # The de-duped display list and the object list describe the same estate.
    assert len(objs) == len(f["affected_items"])
