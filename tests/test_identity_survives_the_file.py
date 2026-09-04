"""Re-saving an export must not re-identify its findings.

WHAT IS AT STAKE. A finding's fingerprint decides whether this scan's result is
the SAME defect as last scan's. If it moves, the old finding is retired and a new
one raised: the age resets, the MTTR is wrong, the acceptance and the ticket
reference are orphaned, and the mitigation journey restarts — silently, because
both scans look perfectly healthy and the counts barely change.

WHY THESE VARIANTS. Row order was one dimension of "the answer must not depend
on something incidental", and it found four fail-opens in one day. These are the
other dimensions of the same question, all of them things that happen to a CSV
between the system and the upload without a single SAP fact changing:

    bom          Excel adds a UTF-8 byte-order mark on save
    crlf         Windows line endings
    trailing     a trailing space after every value
    lower_header column names lower-cased (BNAME -> bname)
    quoted       every field quoted, as some exporters do
    cp1252       saved in the codepage the loader already falls back to

Not hypothetical: a scan of the bundled corpus reports files "decoded only via a
fallback encoding (cp1252)" today.

THE RESULT WHEN THIS WAS WRITTEN was that the product is already right — 418 of
419 fingerprints identical across every variant. That is worth a test anyway: it
is a property nothing currently enforces, one careless `strip()` removed from
`norm_name` would break it, and the failure is invisible in every number a
reader looks at.

THE ONE DIFFERENCE, and why it is excluded rather than asserted away. The
Export Integrity checks report on the FILE — "these were not valid UTF-8" — so
re-saving an export as UTF-8 genuinely fixes what EXPORT-002 reports and it
correctly stops firing. That is a fact this rewrite really does change, unlike
every other fact in the corpus. It is the same distinction the domain taxonomy
draws when it keeps Export Integrity outside the twelve domains: a statement
about the evidence rather than about SAP. The last test here proves that
exclusion is not covering a broken check.

WHICH LINE ACTUALLY DEFENDS THIS, established by mutation rather than by
reading. `DataLoader` normalises every row with

    k.strip().upper().replace(" ", "_"): (v or "").strip()

and that one line carries two of these variants: drop the value `.strip()` and
`trailing` fails; drop the key `.upper()` and `lower_header` fails. Each
mutation fails exactly its own variant and nothing else.

`norm_name` in server/identity.py also strips, and removing ITS strip changes
nothing end-to-end — the loader has already done it. That is belt and braces
rather than a defect, but it is worth knowing which of the two is load-bearing
before trusting the other. The remaining variants (bom, crlf, quoted, cp1252)
guard the decode-and-parse path rather than a single line, and are not claimed
here to have an equivalent one-line mutation.
"""
from __future__ import annotations

import contextlib
import csv
import importlib
import io
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import data_loader          # noqa: E402
from server import identity              # noqa: E402
from server.ingest import AUDITORS       # noqa: E402

#: Checks that report on the export FILE rather than on the SAP system. Their
#: subject is the thing these variants deliberately change, so they are the one
#: family whose behaviour is expected to differ.
FILE_CHECKS = ("EXPORT-",)

VARIANTS = ("bom", "crlf", "trailing", "lower_header", "quoted", "cp1252")


def _scan(directory: Path):
    with contextlib.redirect_stdout(io.StringIO()):
        data = data_loader.DataLoader(Path(directory)).load_all()
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
        except Exception:                                     # noqa: BLE001
            # A module that raises is out of scope here; the row-order
            # invariant is where a module raising in one arrangement and not
            # another is caught.
            pass
    return out


def fingerprints(directory: Path) -> set:
    got = set()
    for f in _scan(directory):
        check = str(f.get("check_id") or "")
        if check.startswith(FILE_CHECKS):
            continue
        fingerprint, basis = identity.fingerprint_finding(
            f, system="PRD", client="100")
        got.add((check, basis, fingerprint))
    return got


def _rewrite(path: Path, how: str) -> None:
    """Re-save one CSV the `how` way, preserving every fact in it."""
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("cp1252", errors="replace")
    rows = list(csv.reader(io.StringIO(text)))
    if not rows:
        return
    if how == "lower_header":
        rows[0] = [c.lower() for c in rows[0]]
    elif how == "trailing":
        rows = [rows[0]] + [[c + " " for c in r] for r in rows[1:]]
    buf = io.StringIO()
    csv.writer(buf,
               lineterminator="\r\n" if how == "crlf" else "\n",
               quoting=csv.QUOTE_ALL if how == "quoted"
               else csv.QUOTE_MINIMAL).writerows(rows)
    body = buf.getvalue()
    if how == "cp1252":
        path.write_bytes(body.encode("cp1252", errors="replace"))
    elif how == "bom":
        path.write_bytes(b"\xef\xbb\xbf" + body.encode("utf-8"))
    else:
        path.write_bytes(body.encode("utf-8"))


@pytest.fixture(scope="module")
def baseline():
    return fingerprints(ROOT / "sample_data")


def test_the_baseline_is_not_empty(baseline):
    """Every assertion below passes vacuously against an empty set."""
    assert len(baseline) > 200, len(baseline)


@pytest.mark.parametrize("how", VARIANTS)
def test_re_saving_the_export_does_not_re_identify_anything(how, baseline, tmp_path):
    estate = tmp_path / how
    shutil.copytree(ROOT / "sample_data", estate)
    for path in estate.rglob("*.csv"):
        _rewrite(path, how)

    got = fingerprints(estate)
    lost, gained = baseline - got, got - baseline
    assert not lost and not gained, (
        "Saving the same facts as %r changed finding identity.\n"
        "  retired (age and MTTR reset): %s\n"
        "  raised as new:                %s\n"
        "Nothing about the SAP system differs between these two exports."
        % (how, sorted(x[0] for x in lost)[:8],
           sorted(x[0] for x in gained)[:8]))


def test_a_file_check_is_allowed_to_notice_the_re_save(tmp_path):
    """The exclusion above must not be hiding a broken check.

    EXPORT-002 reports files that were not valid UTF-8. Re-saving the corpus as
    UTF-8 really does fix that, so it must STOP firing — and re-saving as
    cp1252 must keep it firing. If neither happened, the exclusion would be
    covering a check that had simply stopped working.
    """
    def export_checks(estate):
        return {str(f.get("check_id")) for f in _scan(estate)
                if str(f.get("check_id") or "").startswith(FILE_CHECKS)}

    before = export_checks(ROOT / "sample_data")
    if "EXPORT-002" not in before:
        pytest.skip("the bundled corpus no longer needs a fallback encoding")

    as_utf8 = tmp_path / "utf8"
    shutil.copytree(ROOT / "sample_data", as_utf8)
    for path in as_utf8.rglob("*.csv"):
        _rewrite(path, "bom")
    assert "EXPORT-002" not in export_checks(as_utf8), (
        "the corpus was re-saved as valid UTF-8 and the fallback-encoding "
        "finding still fires")

    as_cp1252 = tmp_path / "cp1252"
    shutil.copytree(ROOT / "sample_data", as_cp1252)
    for path in as_cp1252.rglob("*.csv"):
        _rewrite(path, "cp1252")
    assert "EXPORT-002" in export_checks(as_cp1252), (
        "the corpus was re-saved in cp1252 and the fallback-encoding finding "
        "did not fire")
