"""
The QR encoder, checked against ISO/IEC 18004 rather than against itself.

WHY A ROUND TRIP IS NOT ENOUGH, WHICH IS THE WHOLE PROBLEM WITH HAND-ROLLING THIS.
A subtly wrong encoder produces a symbol that looks perfectly QR-ish and scans as
nonsense. `encode` and `decode` in the same file agree on any mistake they share,
so a round trip can pass while every phone in the world rejects the image. Three
of the four layers below therefore compare against numbers published in the
standard, which this file did not produce:

  1. Reed-Solomon, against the standard's own worked example for "01234567" at
     version 1-M — the stage most likely to be silently wrong.
  2. The format-information bits, against the published table for level M, all
     eight masks. A scanner reads these before anything else.
  3. The terminator-and-padding rule, against the worked example's data sequence.
  4. Then, and only then, a round trip and a golden fingerprint.

────────────────────────────────────────────────────────────────────────────────
WHAT AN INDEPENDENT ENCODER SAID, AND WHY THE DIFFERENCE IS NOT A BUG HERE
────────────────────────────────────────────────────────────────────────────────
This encoder was diffed against `segno` 1.6.6 (installed temporarily for the
comparison and then removed — it is not a dependency of this project and must not
become one). Findings, recorded because the next person will run the same
experiment and reach the same confusing halfway point:

  * Version selection, symbol size, mask choice, every function pattern and all
    fifteen format bits are IDENTICAL. Zero differing modules in the function and
    reserved areas, and this file's `_read_format_mask` recovers segno's mask
    correctly for all eight masks — an external check on the format stage.
  * The DATA area differs, always by exactly one codeword's worth of shift in the
    padding region. Segno emits an extra 0x00 codeword after the 4-bit terminator
    before the alternating 0xEC/0x11 pad bytes begin.
  * ISO/IEC 18004 settles it. Its published data sequence for the worked example
    is `10 20 0C 56 61 80 EC 11 …`: the terminator byte `80` is followed
    IMMEDIATELY by the first pad byte. The rule is "terminator of up to four 0
    bits, then extend to the next codeword boundary" — so when the stream already
    lands on a boundary, nothing is added. This encoder implements that; the extra
    zero codeword is segno's deviation.
  * It is invisible to any reader either way, because a decoder reads the length
    field and stops — which is why both symbols decode correctly, and why byte
    equality against another encoder would be the WRONG assertion to enshrine.

So this file asserts the standard, not agreement with a particular library.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server import qr, totp                                       # noqa: E402


# --------------------------------------------------------------------------- #
#  1. Reed-Solomon, against the standard's worked example                     #
# --------------------------------------------------------------------------- #
#: ISO/IEC 18004, "01234567" at version 1, error-correction level M.
ISO_DATA = [0x10, 0x20, 0x0C, 0x56, 0x61, 0x80, 0xEC, 0x11,
            0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11]
ISO_EC = [0xA5, 0x24, 0xD4, 0xC1, 0xED, 0x36, 0xC7, 0x87, 0x2C, 0x55]


def test_reed_solomon_matches_the_standards_worked_example():
    assert qr.rs_encode(ISO_DATA, 10) == ISO_EC


def test_reed_solomon_is_sensitive_to_every_input_byte():
    """Guards against a generator that happens to produce the right answer for one
    vector — flip each input byte and require the parity to move."""
    for i in range(len(ISO_DATA)):
        mutated = list(ISO_DATA)
        mutated[i] ^= 0x01
        assert qr.rs_encode(mutated, 10) != ISO_EC, f"byte {i} does not affect the EC"


# --------------------------------------------------------------------------- #
#  2. Format information, against the published table                         #
# --------------------------------------------------------------------------- #
#: ISO/IEC 18004 Table C.1, error-correction level M, masks 0..7.
ISO_FORMAT_M = {
    0: "101010000010010",
    1: "101000100100101",
    2: "101111001111100",
    3: "101101101001011",
    4: "100010111111001",
    5: "100000011001110",
    6: "100111110010111",
    7: "100101010100000",
}


@pytest.mark.parametrize("mask,expected", sorted(ISO_FORMAT_M.items()))
def test_format_bits_match_the_published_table(mask, expected):
    assert "".join(str(b) for b in qr._format_bits(mask)) == expected


def test_the_format_bits_round_trip_through_the_matrix():
    """Placement as well as computation: the bits must land where a scanner reads
    them, in both copies of the format area."""
    for mask in range(8):
        m = qr.encode("x" * 20)
        # Rebuild with a known mask rather than trusting the chosen one.
        payload = qr._encode_data(b"x" * 20, 2)
        bits = []
        for cw in qr._interleave(payload, 2):
            bits.extend((cw >> i) & 1 for i in range(7, -1, -1))
        base, fixed = qr._blank(2)
        qr._place_function_patterns(base, fixed, 2)
        qr._place_data(base, fixed, bits, 2)
        cand = qr._apply_mask(base, fixed, mask, 2)
        qr._place_format(cand, mask, 2)
        assert qr._read_format_mask(cand) == mask
        del m


# --------------------------------------------------------------------------- #
#  3. Terminator and padding, against the worked example's shape               #
# --------------------------------------------------------------------------- #

def test_padding_starts_immediately_when_the_stream_is_byte_aligned():
    """The rule an independent encoder gets differently — see the module docstring.

    20 bytes at version 2 is 4 + 8 + 160 = 172 bits; the 4-bit terminator brings it
    to 176, which is exactly 22 codewords, so the pad bytes must begin at codeword
    23 with no intervening zero codeword.
    """
    cw = qr._encode_data(b"x" * 20, 2)
    assert len(cw) == qr._data_capacity(2) == 28
    assert cw[21] == 0x80, "the terminator byte is not where the bit arithmetic puts it"
    assert cw[22:] == [0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11], \
        "padding must follow the terminator immediately when already byte-aligned"


# A NOTE FOR WHOEVER MUTATION-TESTS THIS FILE. Deleting the 4-bit terminator from
# `_encode_data` does NOT fail anything here, and that is correct rather than a
# gap: in byte mode the header is 4 mode bits + an 8-bit count, so mode+count+data
# is always exactly 4 bits short of a codeword boundary, and the terminator and the
# byte padding that follows it are literally the same four zero bits. The mutant is
# equivalent by construction. (Same for the first `m[n-8][8] = 1` in
# `_place_function_patterns` — `_place_format` writes the dark module again
# afterwards, so only the second assignment is load-bearing.)

def test_the_pad_bytes_are_the_specified_alternating_pair():
    cw = qr._encode_data(b"a", 1)
    tail = cw[len(cw) - 12:]
    assert set(tail) <= {0xEC, 0x11}
    assert tail[0] != tail[1], "the pad bytes must alternate, not repeat"


# --------------------------------------------------------------------------- #
#  4. Structure, at the coordinates the standard specifies                    #
# --------------------------------------------------------------------------- #

def test_the_three_finder_patterns_are_where_a_scanner_looks():
    m = qr.encode("hello world")
    n = len(m)
    for top, left in ((0, 0), (0, n - 7), (n - 7, 0)):
        assert m[top][left] == 1 and m[top + 6][left + 6] == 1
        # The 3x3 solid core.
        for r in range(2, 5):
            for c in range(2, 5):
                assert m[top + r][left + c] == 1
        # The light ring separating core from border.
        assert m[top + 1][left + 1] == 0 and m[top + 5][left + 5] == 0


def test_the_timing_patterns_alternate():
    m = qr.encode("hello world")
    n = len(m)
    for i in range(8, n - 8):
        assert m[6][i] == (1 if i % 2 == 0 else 0)
        assert m[i][6] == (1 if i % 2 == 0 else 0)


def test_the_dark_module_is_set():
    """One module the standard fixes to dark, at (4*version+9, 8). Its absence is a
    classic hand-rolled-encoder bug that some scanners tolerate and others do not."""
    m = qr.encode("hello world")
    version = (len(m) - 17) // 4
    assert m[4 * version + 9][8] == 1


def test_the_quiet_zone_is_present_in_the_svg():
    """Four modules of light border. Scanners genuinely fail without it, and it is
    the first thing removed by someone trying to make the image smaller."""
    svg = qr.to_svg("hello", module=4, quiet=4)
    matrix = qr.encode("hello")
    side = (len(matrix) + 8) * 4
    assert f'width="{side}"' in svg and f'height="{side}"' in svg


# --------------------------------------------------------------------------- #
#  5. Round trip — the weakest check, never the only one                      #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("text", [
    "a",
    "hello world",
    "x" * 20,
    "x" * 100,
    totp.provisioning_uri(totp.new_secret(), "someone@example.com"),
    "unicode: éèê",
])
def test_encode_decode_round_trip(text):
    assert qr.decode(qr.encode(text)).decode("utf-8") == text


# --------------------------------------------------------------------------- #
#  6. Golden fingerprint — a regression detector, honestly labelled           #
# --------------------------------------------------------------------------- #
#: A real enrolment URI at 127 bytes, which lands on version 8. This is a
#: CHANGE DETECTOR, not an oracle: it proves the output has not moved, not that it
#: was ever right. The ISO checks above are what make it right.
GOLDEN_URI = totp.provisioning_uri("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", "alice")
GOLDEN_SHA = "e6a29faa00a0ecef1e1c523869bb7270e5fe792fd9e55b39aebb94b5fb611e09"


def test_a_real_enrolment_uri_encodes_to_the_expected_symbol():
    m = qr.encode(GOLDEN_URI)
    assert len(m) == 49, "version 8 is a 49x49 symbol"
    assert qr._read_format_mask(m) == 2
    assert sum(sum(row) for row in m) == 1234, "dark-module count moved"
    ser = "".join("".join(str(v) for v in row) for row in m)
    assert hashlib.sha256(ser.encode()).hexdigest() == GOLDEN_SHA


# --------------------------------------------------------------------------- #
#  7. Scope and failure behaviour                                             #
# --------------------------------------------------------------------------- #

def test_a_payload_past_version_ten_raises_rather_than_truncating():
    """Silently truncating would produce a scannable symbol carrying half a
    secret — enrolment that appears to work and never verifies."""
    with pytest.raises(qr.QREncodeError):
        qr.encode("x" * 400)


def test_version_is_the_smallest_that_fits():
    assert len(qr.encode("x" * 10)) == 21          # version 1
    assert len(qr.encode("x" * 20)) == 25          # version 2
    assert len(qr.encode("x" * 30)) == 29          # version 3


def test_svg_or_empty_never_raises_out_of_the_route():
    """The QR is a convenience; the secret and the otpauth link complete enrolment
    on their own. A bug in the encoder must degrade to "no picture", not 500 the
    account screen."""
    assert qr.svg_or_empty("x" * 400) == ""
    assert qr.svg_or_empty("hello").startswith("<svg")


def test_the_svg_is_self_contained_and_has_no_external_reference():
    """It is inlined into an authenticated page, so it must fetch nothing and run
    nothing. The `xmlns` declaration is a NAME, not a URL the browser resolves, so
    it is excluded before looking for real references — asserting "no http" without
    that exclusion fails on a correct document, which is a test bug rather than a
    finding."""
    svg = qr.to_svg("hello")
    assert svg.startswith("<svg") and svg.endswith("</svg>")
    body = svg.replace('xmlns="http://www.w3.org/2000/svg"', "")
    for forbidden in ("http://", "https://", "<script", "<image", "href", "url("):
        assert forbidden not in body, f"{forbidden!r} would make the QR fetch or execute"
