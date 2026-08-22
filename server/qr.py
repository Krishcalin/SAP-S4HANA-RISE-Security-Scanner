"""
QR Code encoder — pure standard library, byte mode, rendered as inline SVG.

Written rather than depended on because requirements.txt holds four runtime
dependencies and tests/test_spa_mount.py asserts that list verbatim. A QR library
is not what that budget is for. Ported from the sibling OverWatch codebase
(`aws_qr.py`), which reached the same conclusion under the same constraint.

It exists for exactly one job: showing an `otpauth://` URI that Microsoft
Authenticator, Google Authenticator, Authy and 1Password can scan.

────────────────────────────────────────────────────────────────────────────────
HOW THIS IS VERIFIED, WHICH IS THE WHOLE PROBLEM WITH HAND-ROLLING A QR ENCODER
────────────────────────────────────────────────────────────────────────────────
A subtly wrong encoder produces a symbol that looks perfectly QR-ish and scans as
nonsense, and the user experiences that as "enrolment is broken". Self-consistency
proves nothing here — an encoder and its own decoder agree on any mistake they
share — so tests/test_qr.py checks against oracles OUTSIDE this file:

 1. **The Reed-Solomon stage against ISO/IEC 18004's own worked example.** The
    standard publishes the data and error-correction codewords for "01234567" at
    version 1-M. That is an external oracle for the stage most likely to be wrong.
 2. **The format-information bits against the standard's published table** for
    error-correction level M, all eight masks. These are BCH(15,5) values a
    scanner reads before anything else; wrong bits mean an unreadable symbol
    however good the data area is.
 3. **A committed reference matrix** produced by an independent encoder, so
    placement, masking and interleaving are compared against something that did
    not come from this file.
 4. **A round trip**, which catches the rest — but is explicitly the weakest of
    the four and is never the only check.

Plus the acceptance test that actually matters: a phone scans it.

SCOPE. Byte mode, error-correction level M, versions 1-10 (up to 213 bytes). An
`otpauth://` URI is around 130 bytes, so this is roughly double what is needed and
stops well short of the version 27+ alignment rules, which would double the size
of this file for no benefit here. Anything longer raises rather than silently
truncating a secret into an unscannable symbol.
"""
from __future__ import annotations

from typing import List, Optional

# --------------------------------------------------------------------------- #
#  GF(256), the field QR's Reed-Solomon works in (primitive polynomial 0x11D)  #
# --------------------------------------------------------------------------- #
_EXP: List[int] = [0] * 512
_LOG: List[int] = [0] * 256


def _init_tables() -> None:
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        x <<= 1
        if x & 0x100:
            x ^= 0x11D
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


_init_tables()


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _poly_mul(a: List[int], b: List[int]) -> List[int]:
    out = [0] * (len(a) + len(b) - 1)
    for i, av in enumerate(a):
        for j, bv in enumerate(b):
            out[i + j] ^= _gf_mul(av, bv)
    return out


def _rs_generator(degree: int) -> List[int]:
    """The generator polynomial for `degree` error-correction codewords."""
    poly = [1]
    for i in range(degree):
        poly = _poly_mul(poly, [1, _EXP[i]])
    return poly


def rs_encode(data: List[int], ec_count: int) -> List[int]:
    """The error-correction codewords for one block (polynomial long division)."""
    gen = _rs_generator(ec_count)
    rem = list(data) + [0] * ec_count
    for i in range(len(data)):
        coef = rem[i]
        if coef:
            for j, g in enumerate(gen):
                rem[i + j] ^= _gf_mul(g, coef)
    return rem[len(data):]


# --------------------------------------------------------------------------- #
#  Capacity tables, error-correction level M, versions 1..10                   #
# --------------------------------------------------------------------------- #
#: version -> (ec codewords per block, [(block count, data codewords per block), ...])
_EC_M = {
    1:  (10, [(1, 16)]),
    2:  (16, [(1, 28)]),
    3:  (26, [(1, 44)]),
    4:  (18, [(2, 32)]),
    5:  (24, [(2, 43)]),
    6:  (16, [(4, 27)]),
    7:  (18, [(4, 31)]),
    8:  (22, [(2, 38), (2, 39)]),
    9:  (22, [(3, 36), (2, 37)]),
    10: (26, [(4, 43), (1, 44)]),
}

#: Alignment-pattern centre coordinates per version (none for version 1).
_ALIGN = {
    1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34],
    7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50],
}

_EC_LEVEL_BITS = 0b00           # level M
_MODE_BYTE = 0b0100

#: BCH(15,5) constants from ISO/IEC 18004.
_FORMAT_POLY = 0b101_0011_0111
_FORMAT_MASK = 0b101_0100_0001_0010
_VERSION_POLY = 0b1111100100101


class QREncodeError(ValueError):
    """The payload cannot be encoded within this encoder's scope."""


def _data_capacity(version: int) -> int:
    _ec, blocks = _EC_M[version]
    return sum(n * k for n, k in blocks)


def _choose_version(length: int) -> int:
    """Smallest version that holds `length` bytes at level M, with its header."""
    for version in sorted(_EC_M):
        # 4 mode bits + 8 or 16 count bits, rounded up to whole codewords.
        count_bits = 8 if version <= 9 else 16
        if (4 + count_bits + length * 8) <= _data_capacity(version) * 8:
            return version
    raise QREncodeError(
        f"{length} bytes exceeds this encoder's version-10 limit "
        f"({_data_capacity(10)} codewords at level M). Raising the ceiling means "
        f"the version 27+ alignment rules, which nothing here needs.")


def _cycle(seq):
    while True:
        for item in seq:
            yield item


def _encode_data(payload: bytes, version: int) -> List[int]:
    """Mode + length + bytes + terminator + padding, as data codewords."""
    count_bits = 8 if version <= 9 else 16
    bits: List[int] = []

    def push(value: int, width: int) -> None:
        for i in range(width - 1, -1, -1):
            bits.append((value >> i) & 1)

    push(_MODE_BYTE, 4)
    push(len(payload), count_bits)
    for byte in payload:
        push(byte, 8)

    capacity_bits = _data_capacity(version) * 8
    push(0, min(4, capacity_bits - len(bits)))          # terminator
    while len(bits) % 8:                                # pad to a codeword boundary
        bits.append(0)
    codewords = [int("".join(str(b) for b in bits[i:i + 8]), 2)
                 for i in range(0, len(bits), 8)]
    # The specified alternating pad bytes, until the version is full.
    for pad in _cycle([0xEC, 0x11]):
        if len(codewords) >= _data_capacity(version):
            break
        codewords.append(pad)
    return codewords


def _interleave(codewords: List[int], version: int) -> List[int]:
    """Split into blocks, add EC per block, then interleave — which is how QR
    survives a smudge: consecutive damaged modules land in different blocks."""
    ec_count, layout = _EC_M[version]
    blocks: List[List[int]] = []
    pos = 0
    for count, size in layout:
        for _ in range(count):
            blocks.append(codewords[pos:pos + size])
            pos += size
    ec_blocks = [rs_encode(b, ec_count) for b in blocks]

    out: List[int] = []
    for i in range(max(len(b) for b in blocks)):
        for b in blocks:
            if i < len(b):
                out.append(b[i])
    for i in range(ec_count):
        for b in ec_blocks:
            out.append(b[i])
    return out


# --------------------------------------------------------------------------- #
#  Matrix                                                                     #
# --------------------------------------------------------------------------- #

def _size(version: int) -> int:
    return version * 4 + 17


def _blank(version: int):
    n = _size(version)
    return [[None] * n for _ in range(n)], [[False] * n for _ in range(n)]


def _place_function_patterns(m, fixed, version: int) -> None:
    n = _size(version)

    def finder(top: int, left: int) -> None:
        for r in range(-1, 8):
            for c in range(-1, 8):
                y, x = top + r, left + c
                if not (0 <= y < n and 0 <= x < n):
                    continue
                on = ((0 <= r <= 6 and c in (0, 6))
                      or (0 <= c <= 6 and r in (0, 6))
                      or (2 <= r <= 4 and 2 <= c <= 4))
                m[y][x] = 1 if on else 0
                fixed[y][x] = True

    finder(0, 0)
    finder(0, n - 7)
    finder(n - 7, 0)

    for i in range(8, n - 8):                            # timing patterns
        bit = 1 if i % 2 == 0 else 0
        m[6][i] = bit
        fixed[6][i] = True
        m[i][6] = bit
        fixed[i][6] = True

    centres = _ALIGN[version]
    for r in centres:
        for c in centres:
            if (r < 8 and c < 8) or (r < 8 and c > n - 9) or (r > n - 9 and c < 8):
                continue                                  # would collide with a finder
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    on = max(abs(dr), abs(dc)) != 1
                    m[r + dr][c + dc] = 1 if on else 0
                    fixed[r + dr][c + dc] = True

    m[n - 8][8] = 1                                       # the dark module
    fixed[n - 8][8] = True

    for i in range(9):                                    # reserve format areas
        for y, x in ((8, i), (i, 8)):
            if m[y][x] is None:
                m[y][x] = 0
                fixed[y][x] = True
    for i in range(8):
        for y, x in ((8, n - 1 - i), (n - 1 - i, 8)):
            if m[y][x] is None:
                m[y][x] = 0
                fixed[y][x] = True

    if version >= 7:                                      # reserve version areas
        for i in range(6):
            for j in range(3):
                for y, x in ((i, n - 11 + j), (n - 11 + j, i)):
                    m[y][x] = 0
                    fixed[y][x] = True


def _place_data(m, fixed, bits: List[int], version: int) -> None:
    n = _size(version)
    idx, upward, col = 0, True, n - 1
    while col > 0:
        if col == 6:
            col -= 1                                      # column 6 is the timing line
        rows = range(n - 1, -1, -1) if upward else range(n)
        for row in rows:
            for c in (col, col - 1):
                if not fixed[row][c]:
                    m[row][c] = bits[idx] if idx < len(bits) else 0
                    idx += 1
        upward = not upward
        col -= 2


_MASKS = [
    lambda i, j: (i + j) % 2 == 0,
    lambda i, j: i % 2 == 0,
    lambda i, j: j % 3 == 0,
    lambda i, j: (i + j) % 3 == 0,
    lambda i, j: (i // 2 + j // 3) % 2 == 0,
    lambda i, j: (i * j) % 2 + (i * j) % 3 == 0,
    lambda i, j: ((i * j) % 2 + (i * j) % 3) % 2 == 0,
    lambda i, j: ((i + j) % 2 + (i * j) % 3) % 2 == 0,
]


def _apply_mask(m, fixed, mask: int, version: int):
    n = _size(version)
    out = [row[:] for row in m]
    rule = _MASKS[mask]
    for r in range(n):
        for c in range(n):
            if not fixed[r][c] and rule(r, c):
                out[r][c] ^= 1
    return out


def _penalty(m, version: int) -> int:
    """The four ISO scoring rules. Lower is better; picking the lowest is what
    stops a symbol having large blank runs a scanner mistakes for a finder."""
    n = _size(version)
    score = 0
    for line in list(m) + [list(col) for col in zip(*m)]:      # rule 1: runs of 5+
        run, prev = 1, line[0]
        for v in line[1:]:
            run = run + 1 if v == prev else 1
            if run == 5:
                score += 3
            elif run > 5:
                score += 1
            prev = v
    for r in range(n - 1):                                      # rule 2: 2x2 blocks
        for c in range(n - 1):
            if m[r][c] == m[r][c + 1] == m[r + 1][c] == m[r + 1][c + 1]:
                score += 3
    pat1 = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0]
    pat2 = [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1]
    for line in list(m) + [list(col) for col in zip(*m)]:      # rule 3: finder-alike
        for i in range(n - 10):
            if line[i:i + 11] in (pat1, pat2):
                score += 40
    dark = sum(sum(row) for row in m)                           # rule 4: dark balance
    score += 10 * (abs(dark * 100 // (n * n) - 50) // 5)
    return score


def _bch(value: int, poly: int, width: int) -> int:
    """Remainder of `value << width` under `poly` — the BCH check bits."""
    rem = value << width
    poly_len = poly.bit_length()
    while rem.bit_length() >= poly_len:
        rem ^= poly << (rem.bit_length() - poly_len)
    return rem


def _format_bits(mask: int) -> List[int]:
    """BCH(15,5) over the 5-bit (level, mask) field, XORed with the fixed mask.

    Checked against ISO/IEC 18004's published table for level M in
    tests/test_qr.py: a scanner reads these before anything else, so wrong bits
    mean an unreadable symbol no matter how correct the data area is.
    """
    value = (_EC_LEVEL_BITS << 3) | mask
    combined = ((value << 10) | _bch(value, _FORMAT_POLY, 10)) ^ _FORMAT_MASK
    return [(combined >> i) & 1 for i in range(14, -1, -1)]


def _version_bits(version: int) -> List[int]:
    """BCH(18,6). Only present from version 7 up."""
    combined = (version << 12) | _bch(version, _VERSION_POLY, 12)
    return [(combined >> i) & 1 for i in range(17, -1, -1)]


def _place_format(m, mask: int, version: int) -> None:
    n = _size(version)
    bits = _format_bits(mask)
    for i in range(6):
        m[8][i] = bits[i]
    m[8][7] = bits[6]
    m[8][8] = bits[7]
    m[7][8] = bits[8]
    for i in range(9, 15):
        m[14 - i][8] = bits[i]
    for i in range(8):
        m[n - 1 - i][8] = bits[i]
    for i in range(8, 15):
        m[8][n - 15 + i] = bits[i]
    m[n - 8][8] = 1                                        # dark module, always


def _place_version(m, version: int) -> None:
    if version < 7:
        return
    n = _size(version)
    bits = _version_bits(version)
    for i in range(18):
        bit = bits[17 - i]
        m[i // 3][n - 11 + i % 3] = bit
        m[n - 11 + i % 3][i // 3] = bit


def encode(text: str) -> List[List[int]]:
    """`text` -> a square matrix of 0/1 modules (1 = dark)."""
    payload = text.encode("utf-8")
    version = _choose_version(len(payload))
    codewords = _interleave(_encode_data(payload, version), version)
    bits: List[int] = []
    for cw in codewords:
        bits.extend((cw >> i) & 1 for i in range(7, -1, -1))

    base, fixed = _blank(version)
    _place_function_patterns(base, fixed, version)
    _place_data(base, fixed, bits, version)

    best, best_score = None, None
    for mask in range(8):
        candidate = _apply_mask(base, fixed, mask, version)
        _place_format(candidate, mask, version)
        _place_version(candidate, version)
        score = _penalty(candidate, version)
        if best_score is None or score < best_score:
            best, best_score = candidate, score
    return best


# --------------------------------------------------------------------------- #
#  Rendering                                                                  #
# --------------------------------------------------------------------------- #
#: Near-black on white. NOT the brand navy: a QR is read by a camera under
#: whatever light the room has, and contrast is the only thing that matters. The
#: light modules stay pure white for the same reason — a tinted "light" module is
#: the classic way a prettified QR stops scanning on older phones.
_DARK = "#0f1419"
_LIGHT = "#ffffff"


def to_svg(text: str, *, module: int = 4, quiet: int = 4,
           dark: str = _DARK, light: str = _LIGHT) -> str:
    """An `<svg>` string. One `<rect>` per dark module — a path would be smaller,
    but this is a few KB inline and stays readable when something looks wrong.

    The quiet zone is NOT decoration: the specification requires four modules of
    light border and scanners genuinely fail without it.
    """
    matrix = encode(text)
    n = len(matrix)
    side = (n + quiet * 2) * module
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{side}" height="{side}" '
        f'viewBox="0 0 {side} {side}" shape-rendering="crispEdges" '
        f'role="img" aria-label="Enrolment QR code">',
        f'<rect width="{side}" height="{side}" fill="{light}"/>',
    ]
    for r, row in enumerate(matrix):
        for c, value in enumerate(row):
            if value:
                x, y = (c + quiet) * module, (r + quiet) * module
                parts.append(f'<rect x="{x}" y="{y}" width="{module}" '
                             f'height="{module}" fill="{dark}"/>')
    parts.append("</svg>")
    return "".join(parts)


def svg_or_empty(text: str, **kwargs) -> str:
    """`to_svg`, but a failure here can never take enrolment down.

    THE QR IS A CONVENIENCE, NOT THE MECHANISM. Enrolment also shows the secret
    and the `otpauth://` link, either of which completes the job on its own, so a
    bug in ~400 lines of Reed-Solomon must degrade to "no picture" rather than
    500 the account screen. The route sends "" and the console renders the manual
    fallback it already has.

    Deliberately broad: this is the boundary between a self-contained pure
    computation and an HTTP handler, and there is no failure of the former worth
    breaking the latter for.
    """
    try:
        return to_svg(text, **kwargs)
    except Exception:                                       # noqa: BLE001
        return ""


# --------------------------------------------------------------------------- #
#  Read-back, for the round-trip test                                         #
# --------------------------------------------------------------------------- #

def _read_format_mask(matrix) -> Optional[int]:
    """Recover the mask index from the format area, so a decoder need not be told."""
    bits = [matrix[8][i] for i in range(6)] + [matrix[8][7], matrix[8][8], matrix[7][8]]
    bits += [matrix[14 - i][8] for i in range(9, 15)]
    value = 0
    for b in bits:
        value = (value << 1) | b
    value ^= _FORMAT_MASK
    return (value >> 10) & 0b111


def decode(matrix) -> bytes:
    """Read a matrix produced by `encode` back to its payload.

    Proves placement, masking and interleaving are mutually consistent — errors
    the ISO codeword vector cannot see. Assumes an undamaged symbol: it runs the
    layout in reverse and does NOT perform Reed-Solomon correction.

    This is the WEAKEST of the four checks in tests/test_qr.py and must never be
    the only one: an encoder and its own decoder agree on any mistake they share.
    """
    n = len(matrix)
    version = (n - 17) // 4
    mask = _read_format_mask(matrix)
    _base, fixed = _blank(version)
    _place_function_patterns(_base, fixed, version)

    rule = _MASKS[mask]
    bits: List[int] = []
    upward, col = True, n - 1
    while col > 0:
        if col == 6:
            col -= 1
        rows = range(n - 1, -1, -1) if upward else range(n)
        for row in rows:
            for c in (col, col - 1):
                if not fixed[row][c]:
                    value = matrix[row][c]
                    if rule(row, c):
                        value ^= 1
                    bits.append(value)
        upward = not upward
        col -= 2

    codewords = [int("".join(str(b) for b in bits[i:i + 8]), 2)
                 for i in range(0, len(bits) // 8 * 8, 8)]

    _ec_count, layout = _EC_M[version]
    sizes: List[int] = []
    for count, size in layout:
        sizes.extend([size] * count)
    blocks: List[List[int]] = [[] for _ in sizes]
    pos = 0
    for i in range(max(sizes)):
        for b, size in enumerate(sizes):
            if i < size:
                blocks[b].append(codewords[pos])
                pos += 1
    data = [cw for block in blocks for cw in block]

    count_bits = 8 if version <= 9 else 16
    stream = 0
    for cw in data:
        stream = (stream << 8) | cw
    total = len(data) * 8
    mode = (stream >> (total - 4)) & 0b1111
    if mode != _MODE_BYTE:
        raise ValueError(f"not byte mode: {mode:04b}")
    length = (stream >> (total - 4 - count_bits)) & ((1 << count_bits) - 1)
    out = bytearray()
    offset = total - 4 - count_bits
    for _ in range(length):
        offset -= 8
        out.append((stream >> offset) & 0xFF)
    return bytes(out)
