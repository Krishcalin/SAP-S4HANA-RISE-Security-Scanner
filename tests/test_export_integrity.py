"""The front door: what the loader can read, and what it says when it cannot.

THE DEFECT THIS FILE EXISTS FOR

Every export was opened as UTF-8. Two of the most ordinary files a customer
produces are not UTF-8 — SAP GUI writes list and spreadsheet downloads as UTF-16
on Windows, and a German-language system writes latin-1 the moment a value
carries an umlaut. Both raised, both were caught, and both became an EMPTY LIST.

An empty list is indistinguishable from an export that genuinely held nothing,
so the scan continued over whatever remained. Measured: re-encoding one file of
the sample estate as UTF-16 took the scan from 407 findings to 383, the
segregation-of-duties conflicts vanished, and the customer-facing report said
nothing about it. The only signal was one WARN among 130 loaded sources.

`test_a_utf16_estate_loads_identically_to_a_utf8_one` is that measurement, kept.
"""
import contextlib
import io
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules.data_loader import DataLoader             # noqa: E402
from modules.export_integrity import ExportIntegrityAuditor  # noqa: E402

CSV = ("AGR_NAME,OBJECT,AUTH,FIELD,LOW,HIGH\n"
       "Z_R,S_TCODE,A1,TCD,FK01,\n"
       "Z_R,S_TCODE,A1,TCD,F110,\n")


@contextlib.contextmanager
def estate(**files):
    """A throwaway export directory. Values are bytes, written verbatim."""
    d = tempfile.mkdtemp()
    try:
        for name, blob in files.items():
            with open(os.path.join(d, name.replace("__", ".")), "wb") as fh:
                fh.write(blob)
        yield Path(d)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def load(path):
    loader = DataLoader(path)
    with contextlib.redirect_stdout(io.StringIO()):
        return loader.load_all(), loader


def findings(data):
    return {f["check_id"]: f for f in
            ExportIntegrityAuditor(data, {}, {}).run_all_checks()}


# ── what must decode ───────────────────────────────────────────────────────

@pytest.mark.parametrize("label,blob", [
    ("utf-8", CSV.encode("utf-8")),
    ("utf-8 with BOM", CSV.encode("utf-8-sig")),
    ("utf-16le with BOM (SAP GUI on Windows)", CSV.encode("utf-16")),
    ("utf-16be with BOM", b"\xfe\xff" + CSV.encode("utf-16-be")),
    ("latin-1 with an umlaut", CSV.replace("Z_R", "Z_R\xdc").encode("latin-1")),
    ("cp1252 with a curly quote", CSV.replace("Z_R", "Z’R").encode("cp1252")),
    ("tab delimited", CSV.replace(",", "\t").encode("utf-8")),
    ("semicolon delimited", CSV.replace(",", ";").encode("utf-8")),
    ("CRLF line endings", CSV.replace("\n", "\r\n").encode("utf-8")),
    ("blank-padded values (SAP CHAR fields)",
     CSV.replace("FK01", "FK01   ").encode("utf-8")),
])
def test_the_shapes_sap_actually_emits_all_load(label, blob):
    with estate(role_auth_values__csv=blob) as d:
        data, _ = load(d)
    rows = data.get("role_auth_values")
    assert rows is not None, "%s did not load at all" % label
    assert len(rows) == 2, "%s loaded %d rows" % (label, len(rows))
    assert rows[0]["LOW"] == "FK01", "%s decoded the values wrongly" % label


def test_a_utf16_estate_loads_identically_to_a_utf8_one():
    """THE regression. This is the measured defect: one file re-encoded took the
    sample scan from 407 findings to 383, and nothing in the report said so."""
    with estate(role_auth_values__csv=CSV.encode("utf-8")) as a:
        utf8, _ = load(a)
    with estate(role_auth_values__csv=CSV.encode("utf-16")) as b:
        utf16, _ = load(b)
    assert utf16["role_auth_values"] == utf8["role_auth_values"]


# ── and what must be said when something still cannot ──────────────────────

TRUNCATED_UTF32 = b"\xff\xfe\x00\x00\x00\xff"


def test_an_unreadable_export_is_recorded_as_absent_not_empty():
    """The whole defect in one assertion. `[]` means "supplied, and it held
    nothing" — a real answer. None means "not supplied". Only the second is
    honest about a file we could not decode."""
    with estate(role_auth_values__csv=TRUNCATED_UTF32) as d:
        data, _ = load(d)
    assert data["role_auth_values"] is None


def test_an_unreadable_export_is_named_in_a_finding():
    """Being counted among the sources they did not send does not tell a
    customer that the file they DID send failed to arrive."""
    with estate(role_auth_values__csv=TRUNCATED_UTF32) as d:
        data, _ = load(d)
    f = findings(data)["EXPORT-001"]
    assert f["severity"] == "HIGH"
    assert "role_auth_values.csv" in " ".join(f["affected_items"])
    assert "role_auth_values" in f["details"]["logical_sources_lost"]


def test_the_finding_says_a_clean_result_here_is_unmeasured():
    with estate(role_auth_values__csv=TRUNCATED_UTF32) as d:
        data, _ = load(d)
    assert "the question was not asked" in findings(data)["EXPORT-001"]["description"]


def test_a_fallback_decode_is_reported_separately_and_lower():
    """cp1252 never raises, so reaching it means the file was READ but may be
    mojibake. A different failure from one that would not open."""
    with estate(users__csv=CSV.replace("Z_R", "Z_R\xdc").encode("latin-1")) as d:
        data, _ = load(d)
    got = findings(data)
    assert "EXPORT-001" not in got
    assert got["EXPORT-002"]["severity"] == "LOW"
    assert "users.csv" in " ".join(got["EXPORT-002"]["affected_items"])


def test_the_fallback_finding_explains_why_a_read_file_still_matters():
    with estate(users__csv=CSV.replace("Z_R", "Z_R\xdc").encode("latin-1")) as d:
        data, _ = load(d)
    assert "matched across exports by exact string" in \
        findings(data)["EXPORT-002"]["description"]


def test_a_clean_estate_produces_no_export_findings():
    """This module must be silent on the ordinary case. A finding on every scan
    is a finding nobody reads."""
    with estate(role_auth_values__csv=CSV.encode("utf-8")) as d:
        data, _ = load(d)
    assert findings(data) == {}


def test_nothing_is_claimed_when_the_loader_recorded_nothing():
    """An auditor handed a bare dict — as the database path does — must not
    invent an integrity problem out of a missing key."""
    assert ExportIntegrityAuditor({}, {}, {}).run_all_checks() == []


def test_both_findings_appear_together_when_both_apply():
    with estate(role_auth_values__csv=TRUNCATED_UTF32,
                users__csv=CSV.replace("Z_R", "Z_R\xdc").encode("latin-1")) as d:
        data, _ = load(d)
    # SUPERSET, NOT EQUALITY. This test is about the two ENCODING findings
    # co-occurring. EXPORT-003 also fires here, and correctly: the fixture
    # writes an AGR_1251-shaped file (AGR_NAME,OBJECT,AUTH,...) into users.csv,
    # so that export genuinely carries no user-name column. Asserting equality
    # made an unrelated third finding read as a regression in these two.
    assert {"EXPORT-001", "EXPORT-002"} <= set(findings(data))
