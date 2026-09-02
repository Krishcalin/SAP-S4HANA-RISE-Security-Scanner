"""The published firing figure has to be internally honest.

`docs/CHECK_FIRING.md` says how many of the product's checks are proven to
produce a finding somewhere in this suite. It cannot be regenerated inside a
test — it needs a full run to exist — so what is guarded here is everything
else: that the numbers add up, that the families named are real, and that no
family is excluded without a stated reason.

The failure this protects against is specific. A "proven by construction"
exclusion with no reason attached is indistinguishable from a family quietly
dropped to make the number look better, and a total that does not reconcile
means the document is describing a catalogue it did not measure.
"""
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import coverage                                   # noqa: E402
from tools import build_firing_reference as B                  # noqa: E402

DOC = ROOT / "docs" / "CHECK_FIRING.md"
pytestmark = pytest.mark.skipif(
    not DOC.exists(),
    reason="docs/CHECK_FIRING.md not generated yet (needs a full suite run)")


def numbers():
    text = DOC.read_text(encoding="utf-8")
    m = re.search(r"\*\*(\d+) of (\d+)\*\* literal check ids are proven", text)
    n = re.search(r"further \*\*(\d+)\*\* are proven by construction", text)
    u = re.search(r"\*\*(\d+)\*\* are unproven", text)
    assert m and n and u, "the document's headline figures could not be parsed"
    return (int(m.group(1)), int(m.group(2)), int(n.group(1)), int(u.group(1)))


def test_the_three_figures_reconcile_against_the_catalogue():
    """proven + by construction + unproven must equal the catalogue. A total
    that does not add up means the document describes something it did not
    measure."""
    proven, total, construction, unproven = numbers()
    assert proven + construction + unproven == total
    assert total == len(coverage.check_catalogue())


def test_the_document_does_not_claim_more_than_the_catalogue_holds():
    proven, total, _c, _u = numbers()
    assert 0 < proven <= total


def test_every_construction_exclusion_states_its_reason():
    """A family excluded without a reason is indistinguishable from one quietly
    dropped to improve the number."""
    assert B.PROVEN_BY_CONSTRUCTION
    for family, reason in B.PROVEN_BY_CONSTRUCTION.items():
        assert len(reason) > 40, family
        assert family in DOC.read_text(encoding="utf-8")


def test_every_family_named_in_the_table_exists_in_the_catalogue():
    """The unproven-by-family table must name only real families.

    AN EMPTY TABLE IS NOW A LEGITIMATE STATE and was not when this was written:
    everything in the catalogue is proven, so there is no row to write. The
    assertion used to be a bare `assert named`, which turned reaching that state
    into a failure — the same shape as a test that forbids the vocabulary of its
    own rule.

    Emptiness is still not accepted blindly, because a broken regex here would
    look identical. It is accepted only when the document's own headline says
    nothing is unproven, which is the fact the table is derived from.
    """
    text = DOC.read_text(encoding="utf-8")
    catalogue = set(coverage.check_catalogue())
    families = {c.rsplit("-", 1)[0] for c in catalogue}
    named = re.findall(r"^\| `([A-Z0-9-]+)` \| \d+ \| \d+ \|$", text, re.M)
    if not named:
        proven, total = re.search(r"\*\*(\d+) of (\d+)\*\*", text).groups()
        assert proven == total, (
            "the family table is empty but %s of %s are proven — so rows are "
            "missing rather than unnecessary, and the regex above or the "
            "builder has broken" % (proven, total))
        return
    assert not [f for f in named if f not in families]


def test_the_document_says_what_unproven_does_not_mean():
    """Left unqualified, the number reads as 'N broken checks', which is false
    and would be the same overstatement this repository keeps finding."""
    text = DOC.read_text(encoding="utf-8")
    assert "does **not** mean the check is broken" in text
    assert "correctly stay silent" in text


def test_the_builder_refuses_without_a_recording(tmp_path, monkeypatch):
    """A stale or absent recording must stop the build rather than publish a
    figure measured from nothing."""
    monkeypatch.setattr(B, "RECORDING", tmp_path / "absent.json")
    with pytest.raises(SystemExit) as e:
        B.load_recording()
    assert "Run the full suite" in str(e.value)


# ── the ratchet ────────────────────────────────────────────────────────────
#
# `--check` catches the document going stale, but only when somebody runs it.
# These read the COMMITTED document, so they run in any session and fail if the
# published figure moves the wrong way.

#: The floor, at the time it was set. Raise it when the number rises; never
#: lower it to make a build pass. A check that stops being proven is either a
#: test that stopped running or a check that stopped working, and both want
#: looking at rather than accommodating.
PROVEN_FLOOR = 700


def test_the_proven_figure_has_not_fallen():
    proven, total, _c, _u = numbers()
    assert proven >= PROVEN_FLOOR, (
        "%d checks are proven, below the floor of %d. Something stopped being "
        "exercised - find out what before lowering this." % (proven, PROVEN_FLOOR))


def test_the_floor_is_not_set_above_the_published_figure():
    """A floor above the real number would pass vacuously the day the document
    is regenerated lower, which is the moment it most needs to fail."""
    proven, _t, _c, _u = numbers()
    assert PROVEN_FLOOR <= proven


def test_the_builder_has_a_check_mode_ci_can_call():
    """CI gates this document the way it gates the others. Without --check the
    step in .github/workflows/tests.yml would be silently unenforceable."""
    import inspect
    assert "--check" in inspect.getsource(B.main)


def test_ci_actually_calls_it():
    """A --check mode nothing runs is not a guard."""
    wf = (ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")
    assert "tools.build_firing_reference --check" in wf
