"""The ABAP lexer crashed on the way nearly every ABAP file begins.

    *&---------------------------------------------------------------------*
    *& Report Z_SOMETHING
    *&---------------------------------------------------------------------*
    REPORT z_something.

A `*` in column 1 is a full-line comment, and `_scan_line` returned early on it
— before the line that recorded whether the line had left a literal open. The
splitter read that record on the very next statement. So:

  * The FIRST file scanned in a process whose first line is a comment raised
    AttributeError. `scan_tree` does not catch it, so one ordinary banner failed
    the whole `abap_sast` module and the run reported no custom-code findings at
    all. Every abapGit export and every SE38 program starts this way.

  * Once any non-comment line had set it, the value PERSISTED on the function
    across comment lines and across FILES. A file that ended inside an open
    literal left it True, and the next file to begin with a comment had its first
    statement marked `degraded` — a lexer fault attributed to an innocent file,
    which also inflates the `lex_degraded` count that raises a coverage finding.

Both came from carrying the fact on the function object rather than returning it,
and the comment that explained the choice cited "four call sites" that would have
to change. There were two. `_scan_line` now returns it and the attribute is gone,
so a path that forgets to set it cannot compile rather than reading a stale one.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from modules import abap_sast as sast  # noqa: E402

#: What abapGit writes above `REPORT`. The literal cause of the crash.
BANNER = (
    "*&---------------------------------------------------------------------*\n"
    "*& Report Z_DEMO\n"
    "*&---------------------------------------------------------------------*\n"
)
CLEAN = BANNER + "REPORT z_demo.\nWRITE 'hello'.\n"

#: A file whose last line leaves a text literal open. Genuinely degraded, and the
#: source of the state that used to leak into the next file.
UNTERMINATED = "REPORT z_a.\nDATA(x) = 'never closed\n"


def test_a_file_that_opens_with_a_comment_does_not_raise():
    """The crash, reproduced at its simplest.

    Called first in this module so it runs against the same cold state a real
    scan starts from — the defect was invisible to any test that had already
    lexed a line of code."""
    assert sast.split_statements(CLEAN), "the banner-first file produced nothing"


def test_the_fact_is_returned_and_not_parked_on_the_function():
    """Structural, because the behavioural tests below pass either way once the
    attribute happens to be set. An attribute is reachable from anywhere and
    survives the call that wrote it; a return value cannot be stale."""
    assert not hasattr(sast._scan_line, "unterminated_at_eol"), (
        "the lexer is carrying its per-line state on the function object again. "
        "Return it instead — that is what made a comment line inherit the "
        "previous line's verdict.")
    _code, _mask, _term, _stack, unterminated = sast._scan_line("REPORT z.", [])
    assert unterminated is False


def test_a_comment_line_reports_nothing_unterminated():
    """It opens nothing and closes nothing. Whatever the line above left open was
    reported when that line was scanned."""
    _c, _m, _t, _s, unterminated = sast._scan_line("* just a comment", [])
    assert unterminated is False


def test_an_unterminated_literal_is_still_degraded():
    """The fix must not have bought its correctness by never flagging anything."""
    flagged = [st for st in sast.split_statements(UNTERMINATED) if st.degraded]
    assert flagged, "a line leaving a literal open is no longer marked degraded"
    assert "never closed" in flagged[0].text


def test_one_files_open_literal_does_not_degrade_the_next_file():
    """The contamination, stated as the customer would meet it: file B is clean
    ABAP and gets a lexer fault on its first statement because file A, scanned
    earlier in the same run, ended mid-literal."""
    sast.split_statements(UNTERMINATED)
    after = sast.split_statements(CLEAN)
    assert not any(st.degraded for st in after), (
        "a clean file was marked degraded by the previous file's open literal: "
        + repr([st.text for st in after if st.degraded]))


def test_the_banner_is_not_counted_as_a_statement():
    """Three comment lines and two statements. A banner that lexed as a statement
    would give every rule three lines of prose to match against."""
    texts = [st.text for st in sast.split_statements(CLEAN)]
    assert texts == ["REPORT z_demo", "WRITE 'hello'"], texts


@pytest.mark.parametrize("first", [
    "*&---------------------------------------------------------------------*",
    "* plain comment",
    "*",
    "*\"! ABAP Doc comment",
])
def test_every_column_one_comment_shape_opens_a_file_safely(first):
    """`*` in column 1 is the comment marker whatever follows it, including the
    ABAP Doc form, whose `"` would otherwise open a literal."""
    assert sast.split_statements(first + "\nREPORT z.\nWRITE 'x'.\n")


def test_the_scanner_reads_a_banner_first_file_end_to_end():
    """Above the lexer: the module-level failure the crash actually produced was
    `abap_sast` returning nothing for the whole tree."""
    scanner = sast.AbapSourceScanner(data_flow=True)
    findings = scanner.scan_text(
        BANNER + "REPORT z_demo.\n"
        "PARAMETERS p_t TYPE string.\n"
        "SELECT * FROM (p_t) INTO TABLE @DATA(lt).\n",
        Path("z_demo.prog.abap"))
    assert any(f["rule_id"].startswith("ABAP-SQLI") for f in findings), (
        "the dynamic FROM clause under a banner produced no injection finding: "
        + repr(sorted({f["rule_id"] for f in findings})))
