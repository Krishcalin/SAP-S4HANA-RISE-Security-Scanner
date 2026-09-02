"""The kernel half of the note determination, which nothing read.

`docs/EXPORT_GUIDE.md` has a full section telling Basis teams how to produce
`sap_kernel.csv`. `modules/data_loader.py` registers it. No module read it.

Asking a customer for a file and then ignoring it is worse than not asking, and
the cost was measured rather than guessed: 74 notes in SAP's catalogue carry a
`kernel_fix`, 60 of them can be answered from no other export, and the highest
scores CVSS 10.0. On the bundled corpus, supplying the file moves HOTNEWS-013
from 162 determined notes to 218.

The module's own docstring had already named the gap and the fix — "this module
reads no kernel source, so there is no installed level to compare against;
supplying one is the way to widen this check" — and the export guide records
that it was once left unbuilt on a measurement taken against a 43-note
catalogue, when the denominator was wrong.

This mirrors `_installed_hana` / `_hana_verdict` deliberately, including the
discipline that matters most: a kernel line SAP's list does not mention returns
UNKNOWN, never "fixed".
"""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.sap_hotnews import SapHotNewsAuditor                       # noqa: E402


def kernel(release="753_REL", patch="0221"):
    return [{"NAME": "KERN_REL", "VALUE": release},
            {"NAME": "KERN_PATCHLEVEL", "VALUE": patch}]


def auditor(data=None):
    return SapHotNewsAuditor(data or {})


NOTE = {"kernel_fix": [{"release": "753_REL", "min_patch": 500},
                       {"release": "722%", "min_patch": 1010}]}


# ── reading the export ─────────────────────────────────────────────────────

def test_the_config_store_shape_is_read():
    assert auditor({"sap_kernel": kernel()})._installed_kernel() == ("753_REL", 221)


def test_a_patch_level_is_read_for_its_digits():
    """SAP writes it zero-padded; a Basis team transcribing by hand rarely
    does, and `0221` and `221` are the same patch level."""
    assert auditor({"sap_kernel": kernel(patch="221")})._installed_kernel() \
        == ("753_REL", 221)


@pytest.mark.parametrize("rows", [
    [],
    [{"NAME": "KERN_REL", "VALUE": "753_REL"}],           # no patch level
    [{"NAME": "KERN_PATCHLEVEL", "VALUE": "0221"}],       # no release
    [{"NAME": "KERN_REL", "VALUE": ""}],
])
def test_a_half_supplied_export_yields_nothing(rows):
    """Half an answer is not an answer. A release with no patch level cannot be
    compared against a fix, and guessing the missing half is how a system gets
    reported as patched because nobody said otherwise."""
    assert auditor({"sap_kernel": rows})._installed_kernel() is None


def test_no_export_at_all_yields_nothing():
    assert auditor()._installed_kernel() is None


# ── the verdict ────────────────────────────────────────────────────────────

def test_a_kernel_below_the_fix_is_reported_with_both_numbers():
    state, evidence = auditor()._kernel_verdict(NOTE, ("753_REL", 221))
    assert state == "below"
    assert evidence == ["kernel 753_REL is at patch 221; the fix is in patch 500"]


def test_a_kernel_at_the_fix_is_fixed():
    state, _ = auditor()._kernel_verdict(NOTE, ("753_REL", 500))
    assert state == "fixed"


def test_a_kernel_above_the_fix_is_fixed():
    state, _ = auditor()._kernel_verdict(NOTE, ("753_REL", 900))
    assert state == "fixed"


def test_a_release_sap_does_not_mention_is_unknown_not_safe():
    """THE DISCIPLINE THAT MATTERS. A kernel line SAP never published a fix for
    is not a line the fix is absent from — it is a question this product cannot
    answer, and collapsing the two into the reassuring one is how a scanner
    reports an exposed system as clean."""
    assert auditor()._kernel_verdict(NOTE, ("999_REL", 1)) == (None, [])


def test_a_note_with_no_kernel_fix_is_not_decided_here():
    assert auditor()._kernel_verdict({"kernel_fix": []}, ("753_REL", 1)) == (None, [])


# ── SAP's wildcard release form ────────────────────────────────────────────

def test_the_wildcard_release_covers_its_variants():
    """SAP publishes some fixes against `722%`, which covers the EXT variants of
    that line. Comparing it literally would silently drop every note published
    that way."""
    state, _ = auditor()._kernel_verdict(NOTE, ("722_EXT", 5))
    assert state == "below"


def test_the_wildcard_does_not_reach_another_line():
    assert auditor()._kernel_verdict(
        {"kernel_fix": [{"release": "722%", "min_patch": 1010}]},
        ("753_REL", 5)) == (None, [])


@pytest.mark.parametrize("published, installed, expected", [
    ("753_REL", "753_REL", True),
    ("753_REL", "754_REL", False),
    ("722%", "722_REL", True),
    ("722%", "722_EXT", True),
    ("722%", "753_REL", False),
    ("", "753_REL", False),
    ("753_REL", "", False),
])
def test_release_matching(published, installed, expected):
    assert SapHotNewsAuditor._kernel_release_matches(published, installed) is expected


# ── what it changes on a real estate ───────────────────────────────────────

def _determined(data):
    got = {f["check_id"]: f for f in SapHotNewsAuditor(data).run_all_checks()}
    finding = got.get("HOTNEWS-013")
    return len(finding.get("affected_objects") or []) if finding else 0


def test_the_kernel_settles_notes_nothing_else_could(corpus_data):
    """60 of the 74 kernel-fixed notes are answerable from no other export."""
    without = dict(corpus_data)
    without.pop("sap_kernel", None)
    assert _determined(corpus_data) > _determined(without), (
        "supplying the kernel export determined no additional note, so either "
        "the corpus no longer carries it or the verdict is not wired in")


def test_the_evidence_names_the_kernel_not_a_component(corpus_data):
    """A reader has to know which thing to patch. 'kernel 753_REL is at patch
    221' sends somebody to the kernel; a component support-package line sends
    them to SNOTE, and only one of those fixes it."""
    got = {f["check_id"]: f for f in SapHotNewsAuditor(corpus_data).run_all_checks()}
    items = got["HOTNEWS-013"]["affected_items"]
    assert any("kernel" in i and "is at patch" in i for i in items)


@pytest.fixture(scope="module")
def corpus_data():
    import io
    from modules import data_loader
    buf, sys.stdout = sys.stdout, io.StringIO()
    try:
        return data_loader.DataLoader(ROOT / "sample_data").load_all()
    finally:
        sys.stdout = buf


def test_both_corpora_carry_a_kernel(corpus_data):
    for fixture in ("sample_data", "sample_data_ecc"):
        text = (ROOT / fixture / "sap_kernel.csv").read_text(encoding="utf-8-sig")
        assert "KERN_REL" in text and "KERN_PATCHLEVEL" in text, fixture
