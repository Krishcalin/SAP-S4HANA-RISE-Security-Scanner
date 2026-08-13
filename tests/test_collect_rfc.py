# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""The RFC collector, tested on machines that have no SAP RFC SDK — i.e. all of CI.

The SDK is S-user gated and cannot be redistributed, so nothing here opens a
connection. What CAN be tested without it is everything that matters most: that
the allowlist refuses before any handle exists, that strings are encoded the way
the SDK expects rather than the way the platform prefers, and that every extract
writes a file the offline loader already reads.
"""
import ctypes
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from collect import rfc, rfc_tables                  # noqa: E402
from modules.data_loader import DataLoader           # noqa: E402


# ── the encoding contract ────────────────────────────────────────────────────

def test_sap_uc_is_two_bytes_per_character():
    """SAP_UC is UTF-16LE on every platform."""
    assert rfc.to_sap_uc("USR02") == b"U\x00S\x00R\x000\x002\x00\x00\x00"
    assert rfc.to_sap_uc("A") == b"A\x00\x00\x00"


def test_sap_uc_round_trips():
    for text in ("USR02", "RFC_READ_TABLE", "SAP*", "ÄÖÜ", ""):
        assert rfc.from_sap_uc(rfc.to_sap_uc(text)) == text


def test_the_module_never_uses_the_platform_wide_character_type():
    """THE BUG THIS FILE EXISTS FOR, AND IT IS INVISIBLE ON WINDOWS.

    `wchar_t` is 2 bytes on Windows and 4 on Linux; SAP_UC is 2 everywhere. Every
    community example of this technique is Windows-only and uses c_wchar_p, which
    on Linux hands the SDK buffers twice the width it expects — SAP's own guidance
    says that produces segmentation faults because the buffer is "only half as
    long as the RFC APIs expect".

    The container is Linux. A developer on Windows would never see this, so it is
    asserted structurally rather than left to be noticed.
    """
    source = (ROOT / "collect" / "rfc.py").read_text(encoding="utf-8")
    import ast
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Attribute) and node.attr in (
                "c_wchar_p", "c_wchar", "create_unicode_buffer"):
            raise AssertionError(
                f"collect/rfc.py uses ctypes.{node.attr}, which is the platform "
                f"wchar_t and is 4 bytes on Linux where SAP_UC is 2")


def test_a_sap_uc_buffer_is_sized_in_two_byte_characters():
    assert len(rfc.uc_buffer(10)) == 20 + 1 or len(rfc.uc_buffer(10).raw) == 20


# ── the allowlist ────────────────────────────────────────────────────────────

class _FakeLib:
    """Stands in for the SDK so the refusal path can be reached without one.

    Every method raises: if the allowlist ever stops refusing first, the test
    fails with a clear "the SDK was touched" rather than passing quietly.
    """

    def __getattr__(self, name):
        def _boom(*_a, **_k):
            raise AssertionError(f"the SDK was called ({name}) despite the allowlist")
        return _boom


def _connection():
    conn = rfc.Connection({"ashost": "h"}, lib=_FakeLib())
    conn._handle = 1                      # pretend it is open
    return conn


@pytest.mark.parametrize("dangerous", [
    "BAPI_USER_CHANGE",
    "RFC_ABAP_INSTALL_AND_RUN",
    "BAPI_USER_CREATE1",
    "SXPG_COMMAND_EXECUTE",
    "rfc_read_table",                     # case matters; the allowlist is exact
])
def test_a_function_outside_the_allowlist_is_refused(dangerous):
    """RFC exposes every remote-enabled function module in the system. The
    allowlist is the entire safety story, and it is checked BEFORE any handle is
    created — the fake library asserts if it is reached."""
    with pytest.raises(rfc.RefusedFunction) as exc:
        _connection()._function(dangerous)
    assert "read-only allowlist" in str(exc.value)


def test_the_allowlist_holds_only_read_only_functions():
    assert rfc.READ_ONLY_FUNCTIONS == frozenset(
        {"RFC_READ_TABLE", "RFC_SYSTEM_INFO", "RFCPING"})


def test_the_refusal_names_what_is_permitted():
    """An error that does not say what WOULD work sends the reader to the source."""
    with pytest.raises(rfc.RefusedFunction) as exc:
        _connection()._function("BAPI_USER_CHANGE")
    for allowed in rfc.READ_ONLY_FUNCTIONS:
        assert allowed in str(exc.value)


def test_the_allowlist_is_passed_in_not_defaulted_inside_the_transport():
    """Same rule as collect/soap.py: the permitted set is visible where the
    connection is made, not buried in a transport."""
    narrow = rfc.Connection({"ashost": "h"}, allowed=frozenset({"RFCPING"}),
                            lib=_FakeLib())
    narrow._handle = 1
    with pytest.raises(rfc.RefusedFunction):
        narrow._function("RFC_READ_TABLE")


# ── no SDK present ───────────────────────────────────────────────────────────

def test_availability_is_reported_rather_than_raised(monkeypatch):
    monkeypatch.delenv(rfc.SDK_HOME_ENV, raising=False)
    ok, why = rfc.available()
    assert ok is False
    assert rfc.SDK_HOME_ENV in why


def test_the_missing_sdk_message_explains_the_licence_rather_than_the_errno(monkeypatch):
    monkeypatch.delenv(rfc.SDK_HOME_ENV, raising=False)
    with pytest.raises(rfc.RfcUnavailable) as exc:
        rfc.sdk_library_path()
    text = str(exc.value)
    assert "S-user" in text and "cannot be redistributed" in text


def test_a_wrong_sdk_home_names_the_file_it_looked_for(tmp_path):
    ok, why = rfc.available(str(tmp_path))
    assert ok is False
    assert "lib" in why and str(tmp_path) in why


# ── the extract mapping ──────────────────────────────────────────────────────

def test_every_extract_writes_a_file_the_loader_reads():
    """An extract writing a filename nothing reads is work that vanishes."""
    known = {f for names in DataLoader.FILE_MAP.values() for f in names}
    for e in rfc_tables.EXTRACTS:
        assert e["file"] in known, e["source"]


def test_every_extract_header_matches_the_shipped_fixture():
    """The connected export and a hand-made one must be the same shape — that is
    the property connected mode rests on."""
    import csv
    for e in rfc_tables.EXTRACTS:
        fixture = ROOT / "sample_data" / e["file"]
        if not fixture.exists():
            continue
        with fixture.open(encoding="utf-8") as fh:
            expected = next(csv.reader(fh))
        assert list(e["columns"]) == expected, e["file"]


def test_every_extract_names_its_columns():
    """RFC_READ_TABLE returns a 512-byte row; SELECT * on USR02 exceeds it and
    fails with DATA_BUFFER_EXCEEDED, which reads like a connection fault."""
    for e in rfc_tables.EXTRACTS:
        assert rfc_tables.fields_for(e), e["source"]


def test_a_derived_column_is_declared_as_derived():
    """rfc_destinations parses host and user out of an RFCOPTIONS blob rather
    than reading columns, which is a weaker claim and is marked as one."""
    dest = rfc_tables.by_source("rfc_destinations")
    assert dest["derive"] == "rfcoptions"
    assert dest["columns"]["RFCHOST"] is None
    assert "RFCOPTIONS" in dest["extra_fields"]


def test_rfcoptions_yields_only_keys_it_is_confident_of():
    parsed = rfc_tables.parse_rfcoptions(
        "H=p01.acme.internal,S=00,U=RFC_D01_IN,C=100,L=EN")
    assert parsed == {"RFCHOST": "p01.acme.internal", "RFCUSER": "RFC_D01_IN"}


def test_snc_and_auth_type_are_left_blank_rather_than_guessed():
    """Their encoding varies by release and destination type, and a wrong value
    would mislabel a destination as secured — in the data that feeds cross-system
    attack paths."""
    rows = rfc_tables.rows_to_csv(
        rfc_tables.by_source("rfc_destinations"),
        [{"RFCDEST": "P01_TRANSPORT", "RFCTYPE": "3",
          "RFCOPTIONS": "H=p01,U=RFC_D01_IN"}])
    assert rows[0]["RFCSNC"] == ""
    assert rows[0]["RFCAUTH"] == ""
    assert rows[0]["RFCHOST"] == "p01"


def test_rows_to_csv_emits_every_header_even_when_a_field_is_absent():
    e = rfc_tables.by_source("users")
    rows = rfc_tables.rows_to_csv(e, [{"BNAME": "SAP*"}])
    assert set(rows[0]) == set(e["columns"])
    assert rows[0]["BNAME"] == "SAP*"
    assert rows[0]["CLASS"] == ""


def test_what_rfc_still_cannot_reach_is_declared_and_disjoint():
    """An RFC connection is not a complete export either, and saying which gaps
    remain is the difference between a connector and a claim."""
    produced = {e["source"] for e in rfc_tables.EXTRACTS}
    assert produced & set(rfc_tables.RFC_CANNOT_REACH) == set()
    for name, why in rfc_tables.RFC_CANNOT_REACH.items():
        assert why and len(why) > 20, name


# ── the WHERE splitter ───────────────────────────────────────────────────────

def test_a_where_clause_is_split_on_whitespace_never_mid_token():
    """OPTIONS rows are concatenated by the function module. A break inside a
    literal produces a clause that is valid ABAP and means something else."""
    clause = "UDATE GE '20260101' AND USERNAME NE 'BATCH_FI' AND TCODE EQ 'SU01'"
    lines = rfc._split_where(clause, width=30)
    assert all(len(l) <= 30 for l in lines)
    assert " ".join(lines) == clause
    for line in lines:
        assert line.count("'") % 2 == 0, f"a quote was split: {line!r}"


def test_a_short_where_clause_is_one_line():
    assert rfc._split_where("MANDT EQ '100'") == ["MANDT EQ '100'"]


def test_an_empty_where_clause_yields_no_rows():
    assert rfc._split_where("") == []


# ── the charter ──────────────────────────────────────────────────────────────

def test_the_rfc_collector_is_covered_by_the_existing_purity_test():
    """Deliberately NOT a second AST walk over collect/.

    tests/test_collect.py::test_collect_is_stdlib_only already walks every file in
    this package, and the `purity` CI job walks it again on 3.12. My first version
    of this test duplicated that walk using `sys.stdlib_module_names` — a 3.10+ API
    — and turned the 3.8 and 3.9 matrix jobs red.

    That test's own docstring records the identical mistake being made twice
    before, in tests/test_resilience_posture.py and then in tests/test_collect.py.
    This is the third time, in a new file, by not looking for the established
    pattern first. The lesson the third time is not "add another skipif" but that
    the coverage already existed and the duplicate was the defect.
    """
    from tests import test_collect
    assert hasattr(test_collect, "test_collect_is_stdlib_only")
    assert (ROOT / "collect" / "rfc.py").exists()


def test_pyrfc_is_not_imported_anywhere():
    """The decision was to depend on no binding at all."""
    for path in (ROOT / "collect").glob("*.py"):
        assert "import pyrfc" not in path.read_text(encoding="utf-8"), path.name


# ── the SDK check ────────────────────────────────────────────────────────────

def test_check_sdk_declares_every_symbol_the_binding_uses():
    """A symbol declared in _declare but absent from REQUIRED_SYMBOLS would not be
    checked, and would fail mid-collection instead of at --check-sdk."""
    import ast
    source = (ROOT / "collect" / "rfc.py").read_text(encoding="utf-8")
    declared = set()
    for node in ast.walk(ast.parse(source)):
        if (isinstance(node, ast.Attribute) and node.attr.startswith("Rfc")
                and isinstance(node.value, ast.Name) and node.value.id == "lib"):
            declared.add(node.attr)
    missing = declared - set(rfc.REQUIRED_SYMBOLS)
    assert not missing, f"used but not checked by --check-sdk: {sorted(missing)}"


def test_check_sdk_refuses_clearly_without_an_sdk(monkeypatch):
    monkeypatch.delenv(rfc.SDK_HOME_ENV, raising=False)
    with pytest.raises(rfc.RfcUnavailable):
        rfc.check_sdk()


def test_available_does_not_claim_the_library_loads():
    """available() only stats a path. It was described in conversation as proving
    the library loads and the bindings resolve; it does neither, which is why
    check_sdk exists."""
    import inspect
    source = inspect.getsource(rfc.available)
    assert "isfile" in source
    assert "load_sdk" not in source
    assert "CDLL" not in source
