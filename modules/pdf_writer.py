"""
Minimal, dependency-free PDF writer
===================================
A small PDF 1.4 generator built on the Python standard library only — no
reportlab / fpdf / weasyprint. It supports multiple pages with the 14 standard
(non-embedded) fonts, colored text, filled/stroked rectangles and lines, and —
using the built-in Helvetica AFM width metrics — accurate string measurement and
word wrapping. That is enough to lay out a professional multi-page report
(cover page, tables, badges, wrapped narrative text) while keeping the scanner's
zero-external-dependency guarantee.

Coordinate system is PDF-native: origin bottom-left, Y grows upward. The report
layer (`pdf_report.py`) works top-down and converts.
"""

from typing import Dict, List, Optional, Tuple

# ── Standard-14 font width metrics (units per 1000 em, WinAnsi/ASCII range) ──
# Source: Adobe Core-14 AFM files (Helvetica, Helvetica-Bold). Used for text
# measurement and wrapping; Courier is fixed-width 600.
_HELV = {
    ' ': 278, '!': 278, '"': 355, '#': 556, '$': 556, '%': 889, '&': 667, "'": 191,
    '(': 333, ')': 333, '*': 389, '+': 584, ',': 278, '-': 333, '.': 278, '/': 278,
    '0': 556, '1': 556, '2': 556, '3': 556, '4': 556, '5': 556, '6': 556, '7': 556,
    '8': 556, '9': 556, ':': 278, ';': 278, '<': 584, '=': 584, '>': 584, '?': 556,
    '@': 1015, 'A': 667, 'B': 667, 'C': 722, 'D': 722, 'E': 667, 'F': 611, 'G': 778,
    'H': 722, 'I': 278, 'J': 500, 'K': 667, 'L': 556, 'M': 833, 'N': 722, 'O': 778,
    'P': 667, 'Q': 778, 'R': 722, 'S': 667, 'T': 611, 'U': 722, 'V': 667, 'W': 944,
    'X': 667, 'Y': 667, 'Z': 611, '[': 278, '\\': 278, ']': 278, '^': 469, '_': 556,
    '`': 333, 'a': 556, 'b': 556, 'c': 500, 'd': 556, 'e': 556, 'f': 278, 'g': 556,
    'h': 556, 'i': 222, 'j': 222, 'k': 500, 'l': 222, 'm': 833, 'n': 556, 'o': 556,
    'p': 556, 'q': 556, 'r': 333, 's': 500, 't': 278, 'u': 556, 'v': 500, 'w': 722,
    'x': 500, 'y': 500, 'z': 500, '{': 334, '|': 260, '}': 334, '~': 584,
}
_HELVB = {
    ' ': 278, '!': 333, '"': 474, '#': 556, '$': 556, '%': 889, '&': 722, "'": 238,
    '(': 333, ')': 333, '*': 389, '+': 584, ',': 278, '-': 333, '.': 278, '/': 278,
    '0': 556, '1': 556, '2': 556, '3': 556, '4': 556, '5': 556, '6': 556, '7': 556,
    '8': 556, '9': 556, ':': 333, ';': 333, '<': 584, '=': 584, '>': 584, '?': 611,
    '@': 975, 'A': 722, 'B': 722, 'C': 722, 'D': 722, 'E': 667, 'F': 611, 'G': 778,
    'H': 722, 'I': 278, 'J': 556, 'K': 722, 'L': 611, 'M': 833, 'N': 722, 'O': 778,
    'P': 667, 'Q': 778, 'R': 722, 'S': 667, 'T': 611, 'U': 722, 'V': 667, 'W': 944,
    'X': 667, 'Y': 667, 'Z': 611, '[': 333, '\\': 278, ']': 333, '^': 584, '_': 556,
    '`': 333, 'a': 556, 'b': 611, 'c': 556, 'd': 611, 'e': 556, 'f': 333, 'g': 611,
    'h': 611, 'i': 278, 'j': 278, 'k': 556, 'l': 278, 'm': 889, 'n': 611, 'o': 611,
    'p': 611, 'q': 611, 'r': 389, 's': 556, 't': 333, 'u': 611, 'v': 556, 'w': 778,
    'x': 556, 'y': 556, 'z': 500, '{': 389, '|': 280, '}': 389, '~': 584,
}

# Font aliases → (PDF BaseFont, metric table)
_FONTS = {
    "H":  ("Helvetica", _HELV),
    "HB": ("Helvetica-Bold", _HELVB),
    "HO": ("Helvetica-Oblique", _HELV),
    "C":  ("Courier", None),   # fixed-width 600
}
_RES_NAME = {"H": "F1", "HB": "F2", "HO": "F3", "C": "F4"}

# Transliterate common Unicode punctuation the scanner emits into Latin-1 the
# standard fonts can render; anything else falls back to '?'.
_TRANSLIT = {
    "–": "-", "—": "-", "‘": "'", "’": "'", "“": '"',
    "”": '"', "→": "->", "←": "<-", "↔": "<->", "·": "-",
    "•": "*", "≥": ">=", "≤": "<=", "≠": "!=", "…": "...",
    " ": " ", "‑": "-", "ˆ": "^", "€": "EUR", "×": "x",
}


def _sanitize(s: str) -> str:
    for k, v in _TRANSLIT.items():
        if k in s:
            s = s.replace(k, v)
    return s.encode("latin-1", "replace").decode("latin-1")


class PDFWriter:
    """A4 portrait PDF builder. Add pages, draw text/rects/lines, then save()."""

    A4 = (595.28, 841.89)

    def __init__(self, page_size: Tuple[float, float] = A4):
        self.pw, self.ph = page_size
        self._pages: List[List[str]] = []   # each page = list of content operators
        self._cur: Optional[List[str]] = None

    # ── page ──
    def add_page(self):
        self._cur = []
        self._pages.append(self._cur)

    @property
    def page_count(self) -> int:
        return len(self._pages)

    # ── measurement ──
    @staticmethod
    def char_width(ch: str, font: str, size: float) -> float:
        _base, metrics = _FONTS.get(font, _FONTS["H"])
        if metrics is None:      # Courier
            w = 600
        else:
            w = metrics.get(ch, 556)
        return w * size / 1000.0

    def string_width(self, s: str, font: str, size: float) -> float:
        return sum(self.char_width(c, font, size) for c in _sanitize(s))

    def wrap(self, text: str, font: str, size: float, max_width: float) -> List[str]:
        """Word-wrap `text` (honouring existing newlines) to `max_width` points."""
        out: List[str] = []
        for raw_line in text.split("\n"):
            words = raw_line.split(" ")
            line = ""
            for word in words:
                candidate = word if not line else line + " " + word
                if self.string_width(candidate, font, size) <= max_width or not line:
                    # hard-split a single word longer than the column
                    if not line and self.string_width(word, font, size) > max_width:
                        chunk = ""
                        for ch in word:
                            if self.string_width(chunk + ch, font, size) > max_width and chunk:
                                out.append(chunk)
                                chunk = ch
                            else:
                                chunk += ch
                        line = chunk
                    else:
                        line = candidate
                else:
                    out.append(line)
                    line = word
            out.append(line)
        return out

    # ── drawing (Y is bottom-up, PDF native) ──
    def text(self, x: float, y: float, s: str, font: str = "H", size: float = 10,
             color: Tuple[float, float, float] = (0, 0, 0)):
        if self._cur is None:
            self.add_page()
        r, g, b = color
        res = _RES_NAME.get(font, "F1")
        self._cur.append(
            f"BT {r:.3f} {g:.3f} {b:.3f} rg /{res} {size:.2f} Tf "
            f"{x:.2f} {y:.2f} Td ({_escape(s)}) Tj ET"
        )

    def rect(self, x: float, y: float, w: float, h: float,
             fill: Optional[Tuple[float, float, float]] = None,
             stroke: Optional[Tuple[float, float, float]] = None, line_width: float = 1.0):
        if self._cur is None:
            self.add_page()
        ops = []
        if fill:
            ops.append(f"{fill[0]:.3f} {fill[1]:.3f} {fill[2]:.3f} rg")
        if stroke:
            ops.append(f"{stroke[0]:.3f} {stroke[1]:.3f} {stroke[2]:.3f} RG {line_width:.2f} w")
        ops.append(f"{x:.2f} {y:.2f} {w:.2f} {h:.2f} re")
        if fill and stroke:
            ops.append("B")
        elif fill:
            ops.append("f")
        else:
            ops.append("S")
        self._cur.append(" ".join(ops))

    def line(self, x1: float, y1: float, x2: float, y2: float,
             color: Tuple[float, float, float] = (0, 0, 0), width: float = 1.0):
        if self._cur is None:
            self.add_page()
        self._cur.append(
            f"{color[0]:.3f} {color[1]:.3f} {color[2]:.3f} RG {width:.2f} w "
            f"{x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S"
        )

    # ── serialize ──
    def build(self) -> bytes:
        objects: List[bytes] = []

        def add_obj(body: bytes) -> int:
            objects.append(body)
            return len(objects)  # 1-based object number

        # Font objects (Core-14, WinAnsi encoding)
        font_objs = {}
        for alias, (base, _m) in _FONTS.items():
            num = add_obj(
                b"<< /Type /Font /Subtype /Type1 /BaseFont /" + base.encode("latin-1") +
                b" /Encoding /WinAnsiEncoding >>"
            )
            font_objs[alias] = num
        font_res = " ".join(f"/{_RES_NAME[a]} {n} 0 R" for a, n in font_objs.items())
        resources = ("<< /Font << " + font_res + " >> >>").encode("latin-1")

        # Reserve Pages object number
        pages_num = len(objects) + 1
        add_obj(b"")  # placeholder, filled after we know kids

        # Page + content objects
        page_nums = []
        for ops in self._pages:
            stream = ("\n".join(ops)).encode("latin-1", "replace")
            content_num = add_obj(
                b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream"
            )
            page_num = add_obj(
                ("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %.2f %.2f] /Resources %s /Contents %d 0 R >>"
                 % (pages_num, self.pw, self.ph, resources.decode("latin-1"), content_num)).encode("latin-1")
            )
            page_nums.append(page_num)

        kids = " ".join(f"{n} 0 R" for n in page_nums)
        objects[pages_num - 1] = (
            "<< /Type /Pages /Count %d /Kids [%s] >>" % (len(page_nums), kids)
        ).encode("latin-1")

        catalog_num = add_obj(("<< /Type /Catalog /Pages %d 0 R >>" % pages_num).encode("latin-1"))

        # Assemble file with xref
        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = [0] * (len(objects) + 1)
        for i, body in enumerate(objects, start=1):
            offsets[i] = len(out)
            out += str(i).encode() + b" 0 obj\n" + body + b"\nendobj\n"
        xref_pos = len(out)
        out += b"xref\n0 " + str(len(objects) + 1).encode() + b"\n"
        out += b"0000000000 65535 f \n"
        for i in range(1, len(objects) + 1):
            out += ("%010d 00000 n \n" % offsets[i]).encode()
        out += (b"trailer\n<< /Size " + str(len(objects) + 1).encode() +
                b" /Root " + str(catalog_num).encode() + b" 0 R >>\n")
        out += b"startxref\n" + str(xref_pos).encode() + b"\n%%EOF\n"
        return bytes(out)

    def save(self, path: str):
        with open(path, "wb") as fh:
            fh.write(self.build())


def _escape(s: str) -> str:
    s = _sanitize(s)
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
