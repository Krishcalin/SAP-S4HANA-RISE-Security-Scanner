"""The claim every `scope=` decision in this repository rests on.

Dozens of comments across the modules justify their scope with a version of the
same sentence: "remediating one of five roles must shrink this finding, not
retire it and raise a fresh one, resetting its age every run." The finding AGE
and the MTTR built on it are numbers this product puts in front of an auditor,
so the sentence is load-bearing — and it was asserted in prose everywhere and
verified nowhere.

    aggregate  identity must EXCLUDE the member list, so fixing one member
               shrinks the finding and leaves its history intact
    object     identity must INCLUDE the thing named, so four unlocked default
               users stay four findings that can be closed one at a time

These tests check the property over every finding the bundled corpus produces —
309 aggregate and 89 object-scoped at the time of writing — and then do the
round trip a customer actually does: scan, remediate one member, scan again,
and compare fingerprints.

ONE TRAP, RECORDED BECAUSE IT COST A FALSE ALARM. `subject` is the identity
basis when a finding sets it; `affected_objects` is used only when it does not.
A first version of the object test renamed `affected_objects[0]` and left
`subject` untouched, then reported 14 findings as having object-independent
identity. They were correct and the test was wrong. `_identity_field` below
picks whichever field actually carries identity.
"""
import copy
import importlib
import io
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server import identity                                            # noqa: E402


def _scan(directory):
    from modules import data_loader
    from server.ingest import AUDITORS
    buf, sys.stdout = sys.stdout, io.StringIO()
    try:
        data = data_loader.DataLoader(Path(directory)).load_all()
    finally:
        sys.stdout = buf
    out = []
    for name, cls in AUDITORS:
        auditor_cls = getattr(importlib.import_module("modules." + name), cls)
        auditor = None
        for args in ((data,), (data, None), (data, None, {})):
            try:
                auditor = auditor_cls(*args)
                break
            except TypeError:
                continue
        if auditor is None:
            continue
        try:
            out.extend(auditor.run_all_checks() or [])
        except Exception:                                   # noqa: BLE001
            pass
    return out


def _fp(finding):
    return identity.fingerprint_finding(finding, system="PRD", client="100")


def _identity_field(finding):
    """Which field this finding's identity is actually built from."""
    return "subject" if finding.get("subject") else "affected_objects"


@pytest.fixture(scope="module")
def corpus():
    return _scan(ROOT / "sample_data")


# ── aggregate: identity must survive losing members ───────────────────────

def test_no_aggregate_finding_loses_its_identity_when_members_are_fixed(corpus):
    """The whole justification for scope="aggregate".

    Every member but the first is removed — the shape of an estate where
    somebody worked through the list. The fingerprint must not move.
    """
    unstable = []
    aggregates = [f for f in corpus if f.get("scope") == "aggregate"]
    assert aggregates, "the corpus produced no aggregate findings to check"
    for finding in aggregates:
        shrunk = copy.deepcopy(finding)
        for field in ("affected_items", "affected_objects"):
            if shrunk.get(field):
                shrunk[field] = shrunk[field][:1]
        if _fp(shrunk) != _fp(finding):
            unstable.append("%s (%s)" % (finding["check_id"], finding["title"][:50]))
    assert not unstable, (
        "these aggregate findings change identity when a member is remediated, "
        "so their age resets every time somebody fixes one of several: %s"
        % unstable[:10])


def test_an_aggregate_finding_keeps_its_identity_with_no_members_at_all(corpus):
    """The last member is a boundary worth naming: a finding on its way to
    being closed must still be the same finding while it empties."""
    for finding in corpus:
        if finding.get("scope") != "aggregate":
            continue
        emptied = copy.deepcopy(finding)
        emptied["affected_items"] = []
        emptied["affected_objects"] = []
        assert _fp(emptied) == _fp(finding), finding["check_id"]


# ── object: identity must follow the thing named ──────────────────────────

def test_every_object_scoped_finding_is_tied_to_the_object_it_names(corpus):
    """The other half. If identity ignored the object, four unlocked default
    users would collapse into one finding that cannot be closed per user."""
    detached = []
    scoped = [f for f in corpus
              if f.get("scope") == "object" and (f.get("subject")
                                                 or f.get("affected_objects"))]
    assert scoped, "the corpus produced no object-scoped findings to check"
    for finding in scoped:
        field = _identity_field(finding)
        renamed = copy.deepcopy(finding)
        renamed[field] = [dict(o) for o in finding[field]]
        renamed[field][0]["name"] = str(renamed[field][0].get("name", "")) + "_OTHER"
        if _fp(renamed) == _fp(finding):
            detached.append("%s (%s)" % (finding["check_id"], finding["title"][:50]))
    assert not detached, (
        "these object-scoped findings keep their identity when the object they "
        "name changes, so two different defects would share one history: %s"
        % detached[:10])


def test_object_scoped_findings_of_one_check_do_not_collide(corpus):
    """Four unlocked users must be four rows, not one overwritten four times."""
    seen = {}
    for finding in corpus:
        if finding.get("scope") != "object":
            continue
        seen.setdefault(_fp(finding), []).append(finding["check_id"])
    collisions = {fp: ids for fp, ids in seen.items() if len(ids) > 1}
    assert not collisions, (
        "distinct object-scoped findings share a fingerprint: %s"
        % list(collisions.values())[:5])


# ── the round trip a customer actually does ───────────────────────────────

REMEDIATIONS = [
    ("IAM-EXP-003", "role_expiry.csv", "UNAME", "CONTRACTOR2",
     "a contractor's over-long role assignment is ended"),
    ("IAM-FF-001", "firefighter_log.csv", "LOGIN_TIME", "2025-02-01",
     "one over-long firefighter session ages out of the log"),
]


@pytest.mark.parametrize("check_id, fixture, column, value, story", REMEDIATIONS,
                         ids=[r[0] for r in REMEDIATIONS])
def test_the_finding_shrinks_and_keeps_its_history(
        tmp_path, corpus, check_id, fixture, column, value, story):
    """Scan, remediate ONE member in the export, scan again.

    Not a property check on a dict this time — the actual round trip, through
    the loader and every auditor, because that is what a customer does between
    two uploads and it is where a regression would really show.
    """
    import csv
    import shutil

    before = [f for f in corpus if f["check_id"] == check_id]
    assert before, "%s no longer fires on the corpus" % check_id
    original = before[0]
    assert len(original.get("affected_items") or []) >= 2, (
        "%s has fewer than two members, so nothing can be remediated from it "
        "without retiring it — pick another case" % check_id)

    estate = tmp_path / "after"
    shutil.copytree(ROOT / "sample_data", estate)
    path = estate / fixture
    with io.open(path, encoding="utf-8-sig", newline="") as fh:
        reader = csv.DictReader(fh)
        header, rows = reader.fieldnames, list(reader)
    kept = [r for r in rows if not str(r.get(column, "")).startswith(value)]
    assert len(kept) < len(rows), "the remediation removed nothing"
    with io.open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=header, lineterminator="\n")
        writer.writeheader()
        writer.writerows(kept)

    after = {_fp(f): f for f in _scan(estate)}
    assert _fp(original) in after, (
        "%s lost its identity when one member was remediated (%s), so its age "
        "resets and the MTTR reported for it is wrong" % (check_id, story))
    assert (len(after[_fp(original)].get("affected_items") or [])
            < len(original.get("affected_items") or [])), (
        "the finding kept its identity but did not shrink — the remediation "
        "was not reflected at all")
