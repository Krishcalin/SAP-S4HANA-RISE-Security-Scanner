# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""
Derive server/static/* and assets/monitorrisk-logo.png from the brand master.

    python tools/build_brand_assets.py            # rebuild
    python tools/build_brand_assets.py --check    # fail if the committed assets drift

Requires Pillow. That is a BUILD-time tool, not a runtime dependency — it is
deliberately absent from requirements.txt, and the container never runs this. The
derived files are committed so a deployment (and CI) needs nothing but the repo.

BOTH DESTINATIONS ARE DERIVED HERE, AND THAT IS THE POINT.
`server/static/` is what the console serves; `assets/monitorrisk-logo.png` is what
the CLI's HTML/PDF/PPTX reports embed as a base64 data URI. Those two were the
same bytes by hand, with nothing enforcing it — one brand in the console and a
different one in the deliverable the customer keeps is precisely the defect that
was fixed on 2026-08-07, and a hand-copy is how it comes back. `--check` covers
both, and ignores assets/sap-logo.png, which is not ours and is not derived.

────────────────────────────────────────────────────────────────────────────────
WHY THE LOCKUP KEEPS ITS FIELD AND THE MARK DOES NOT
────────────────────────────────────────────────────────────────────────────────
The previous master was navy-and-blue ink on a flat cream field. The cream was
incidental packaging — a presentation render — so it was keyed out, leaving
transparent ink that could sit on any page colour.

The current master is different in kind, and copying the old treatment forward
silently destroys it. Measure it and the reason is unarguable:

    "Monitor", the shield and the tagline   navy   #0b246a
    "Risk"                                  WHITE  #ffffff      <- new
    field                                   blue   #6cc2fb      <- not incidental

`key_out` un-mixes each pixel against the target ink colours. Both targets are
DARKER than the field, so a white pixel projects to a negative coefficient, clamps
to zero, and is written fully transparent: run unchanged, the console renders the
product as **"Monitor"**. Adding white as a third target restores the glyphs and
then runs into the real constraint — there is no page colour on which the keyed
lockup reads:

    on its own blue field   navy  7.29:1   white  1.95:1     both legible
    on the dark console     navy  1.30:1   white 18.51:1     "Monitor" invisible
    on a cream panel        navy 12.71:1   white  1.12:1     "Risk" invisible

The field is doing design work — it is the one ground both inks were chosen
against. So the lockup ships as a self-contained brand panel WITH its field, and
the sign-in/dashboard panels behind it are set to the same measured colour, which
is also what finally removes the seam the old cream could only approximate.

The MARK is still keyed, because it has no white in it: shield outline (navy) and
pulse (brand blue) only. It is composited onto the page at 22px, where navy on the
dark console is 1.30:1 — hence the `-dark` variant that lifts navy to the page ink
and keeps the blue pulse, which is what carries the identity at that size anyway.

Nothing here is hand-tuned to this particular export. The field colour, the ink
bounding box, the clear-space padding and the gutter between the mark and the
wordmark are all MEASURED, so a re-exported master with different spacing still
derives correctly — or fails loudly instead of producing a plausible wrong crop.
"""
from __future__ import annotations

import argparse
import hashlib
import statistics
import sys
from pathlib import Path

try:
    from PIL import Image
except ImportError:                                     # pragma: no cover
    sys.exit("this tool needs Pillow:  pip install Pillow")

ROOT = Path(__file__).resolve().parents[1]
MASTER = ROOT / "docs" / "brand" / "monitorrisk-master.png"
STATIC = ROOT / "server" / "static"
ASSETS = ROOT / "assets"

#: The ink colours, sampled from the master. NAVY is "Monitor", the shield outline
#: and the tagline; BLUE is the pulse trace. WHITE is "Risk" and is deliberately
#: NOT a key target — see the module docstring.
NAVY = (0x0b, 0x24, 0x6a)
BLUE = (0x10, 0x9a, 0xf5)
#: The dark console panel is #161c24; a navy shield on it is 1.20:1 and all but
#: invisible, so the dark-theme mark lifts the navy to the page ink colour.
INK = (0xe6, 0xed, 0xf3)

#: The files this tool owns. Anything else in those directories is not derived and
#: is not compared — assets/sap-logo.png is SAP's, not ours.
DERIVED_STATIC = ("monitorrisk-logo.png", "monitorrisk-mark.png",
                  "monitorrisk-mark-dark.png", "favicon.ico")
DERIVED_ASSETS = ("monitorrisk-logo.png",)

#: Anything further than this (sum of per-channel deltas) from the field is ink.
#: The master carries compression noise — a supposedly flat block measures a
#: standard deviation of 4.2 in red and a 26-value spread — so the threshold has
#: to clear the noise without eating anti-aliased glyph edges.
INK_TOLERANCE = 60
#: Below this, a pixel is the field wearing noise, and is snapped to the exact
#: field colour. Measured against that same block: the noise reaches ~32 summed
#: across channels, and nothing real lives between there and INK_TOLERANCE.
FIELD_TOLERANCE = 34
#: Alpha below this is not ink. Safe at this value only BECAUSE the field is
#: flattened first — against the raw master a field pixel 20 levels dark of the
#: median keys to 0.054, so anything under ~0.14 admitted a navy haze over the
#: whole crop. Flattening makes a field pixel key to exactly zero, which buys
#: back the soft edges a floor that high was eating.
ALPHA_FLOOR = 0.06


def field_colour(im):
    """The background, measured from the four margins rather than assumed.

    The median (not the mean) so that ink intruding into a margin on a future
    re-export shifts nothing.
    """
    w, h = im.size
    px = im.convert("RGB").load()
    edge = ([px[x, y] for y in (20, h - 21) for x in range(0, w, 5)]
            + [px[x, y] for x in (20, w - 21) for y in range(0, h, 5)])
    return tuple(int(statistics.median(p[i] for p in edge)) for i in range(3))


def ink_bbox(im, field):
    """(x0, y0, x1, y1) of everything that is not field, plus the column mask.

    Returned inclusive, and the mask is reused to find the gutter so the image is
    only scanned once.
    """
    w, h = im.size
    px = im.convert("RGB").load()

    def ink(p):
        return (abs(p[0] - field[0]) + abs(p[1] - field[1])
                + abs(p[2] - field[2])) > INK_TOLERANCE

    cols = [any(ink(px[x, y]) for y in range(0, h, 2)) for x in range(w)]
    rows = [any(ink(px[x, y]) for x in range(0, w, 2)) for y in range(h)]
    if not any(cols):
        raise SystemExit("the master is a blank field — nothing to derive")
    x0, x1 = cols.index(True), w - 1 - cols[::-1].index(True)
    y0, y1 = rows.index(True), h - 1 - rows[::-1].index(True)
    return (x0, y0, x1, y1), cols


def gutter_x(cols, x0, x1):
    """Where the shield ends and the wordmark begins.

    The WIDEST empty column run inside the ink — measured, not a fixed fraction,
    so a re-export that respaces the lockup still splits correctly. Letter gaps in
    "MonitorRisk" are a few pixels; the mark/wordmark gutter is two orders of
    magnitude wider, so the widest run is unambiguous. If it ever is not, that is
    a changed lockup and should stop the build rather than crop through a glyph.
    """
    runs, run, start = [], 0, x0
    for x in range(x0, x1 + 2):
        if x <= x1 and not cols[x]:
            if run == 0:
                start = x
            run += 1
        elif run:
            runs.append((run, start))
            run = 0
    if not runs:
        raise SystemExit("no gap between the mark and the wordmark")
    widest, start = max(runs)
    runner_up = max((r for r, _ in runs if (r, start) != (widest, start)), default=0)
    if widest < 24 or widest < runner_up * 3:
        raise SystemExit(
            f"the mark/wordmark gutter is not distinguishable from letter spacing "
            f"(widest {widest}px, next {runner_up}px) — the lockup has changed shape")
    return start


def flatten_field(im, field):
    """Snap every field-with-noise pixel to the exact field colour.

    The master is a render carrying compression artefacts: 82% of it is nominally
    one flat blue, and every one of those pixels is a slightly different blue. Two
    things follow, and both matter.

    SIZE. Lossless PNG cannot compress noise, so the shipped lockup weighed 474 KB
    against the old 131 KB — and this asset is not merely served, it is base64
    INLINED into every HTML report and embedded in every PPTX, where it inflates a
    further third. Flattening returns it to 176 KB with nothing visible lost: only
    pixels already within FIELD_TOLERANCE move, so the ink and its anti-aliased
    edges are untouched.

    THE SEAM. The old cream "never quite matched a CSS colour, so a rectangle is
    always visible at the seam" — which was true, because a noisy field cannot
    match a flat one. After this the field IS flat and IS exactly `field`, so the
    panels behind it (`.auth-brand`, `.brand-band`) can be set to that same value
    and the edge genuinely disappears.
    """
    out = im.copy()
    px = out.load()
    for y in range(out.height):
        for x in range(out.width):
            p = px[x, y]
            if (abs(p[0] - field[0]) + abs(p[1] - field[1])
                    + abs(p[2] - field[2])) <= FIELD_TOLERANCE:
                px[x, y] = field
    return out


def key_out(im, bg, targets, floor=ALPHA_FLOOR):
    """Background -> alpha, recovering the true colour of every anti-aliased pixel.

    Not a luminance threshold: the brand blue sits roughly halfway between the
    field and the navy in luma, so a luma key renders half the mark semi-
    transparent. Instead each pixel is un-mixed against the known ink colours — a
    pixel on an anti-aliased edge is a blend a*L + (1-a)*B of one ink and the
    background, so projecting (p - B) onto (L - B) recovers both the coverage and
    the true colour. Whichever ink leaves the smaller residual wins, which is what
    keeps navy edges navy and blue edges blue.
    """
    w, h = im.size
    src = im.convert("RGB").load()
    out = Image.new("RGBA", (w, h))
    dst = out.load()

    axes = []
    for L in targets:
        d = (L[0] - bg[0], L[1] - bg[1], L[2] - bg[2])
        axes.append((L, d, float(d[0] * d[0] + d[1] * d[1] + d[2] * d[2])))

    for y in range(h):
        for x in range(w):
            r, g, b = src[x, y]
            p = (r - bg[0], g - bg[1], b - bg[2])
            best_a, best_L, best_res = 0.0, targets[0], 1e18
            for L, d, dd in axes:
                a = (p[0] * d[0] + p[1] * d[1] + p[2] * d[2]) / dd
                a = 0.0 if a < 0.0 else (1.0 if a > 1.0 else a)
                res = ((p[0] - a * d[0]) ** 2 + (p[1] - a * d[1]) ** 2
                       + (p[2] - a * d[2]) ** 2)
                if res < best_res:
                    best_a, best_L, best_res = a, L, res
            dst[x, y] = ((0, 0, 0, 0) if best_a <= floor        # field noise, not ink
                         else (*best_L, int(best_a * 255 + 0.5)))
    return out


def trim(im):
    box = im.getbbox()
    return im if box is None else im.crop(box)


def build(static_dir: Path, assets_dir: Path) -> None:
    static_dir.mkdir(parents=True, exist_ok=True)
    assets_dir.mkdir(parents=True, exist_ok=True)

    raw = Image.open(MASTER).convert("RGB")
    w, h = raw.size
    field = field_colour(raw)
    # Measured on the RAW master: flattening cannot move the ink, but reading the
    # geometry before it is touched keeps the two steps independent.
    (x0, y0, x1, y1), cols = ink_bbox(raw, field)
    master = flatten_field(raw, field)

    # ── The lockup: the artwork, on its own field, with balanced clear space ──
    # The pad is the master's own TIGHTEST margin, applied on all four sides. That
    # keeps the designer's horizontal clear space and crops away the vertical
    # letterboxing of a 16:9 presentation render, without inventing a number.
    pad = min(x0, w - 1 - x1, y0, h - 1 - y1)
    lockup = master.crop((max(0, x0 - pad), max(0, y0 - pad),
                          min(w, x1 + 1 + pad), min(h, y1 + 1 + pad)))
    # RGBA with no transparency: the console and the reports both size this by its
    # intrinsic dimensions, and a colour-type change is a diff nobody reads.
    lockup = lockup.convert("RGBA")
    lockup = lockup.resize((1100, round(lockup.height * 1100 / lockup.width)),
                           Image.LANCZOS)
    lockup.save(static_dir / "monitorrisk-logo.png", optimize=True)
    lockup.save(assets_dir / "monitorrisk-logo.png", optimize=True)

    # ── The mark: the shield alone, keyed, for the 22px console header ──
    cut = gutter_x(cols, x0, x1)
    mark = trim(key_out(master.crop((x0, y0, cut, y1 + 1)), field, (NAVY, BLUE)))
    square = Image.new("RGBA", (max(mark.size),) * 2, (0, 0, 0, 0))
    square.paste(mark, ((square.width - mark.width) // 2,
                        (square.height - mark.height) // 2))
    square.resize((160, 160), Image.LANCZOS).save(
        static_dir / "monitorrisk-mark.png", optimize=True)

    dark = square.copy()
    px = dark.load()
    for y in range(dark.height):
        for x in range(dark.width):
            r, g, b, a = px[x, y]
            if a and abs(r - BLUE[0]) + abs(g - BLUE[1]) + abs(b - BLUE[2]) > 90:
                px[x, y] = (*INK, a)
    dark.resize((160, 160), Image.LANCZOS).save(
        static_dir / "monitorrisk-mark-dark.png", optimize=True)

    square.resize((64, 64), Image.LANCZOS).save(
        static_dir / "favicon.ico", sizes=[(16, 16), (32, 32), (48, 48), (64, 64)])


def digest(directory: Path, names):
    """SHA-256 of the DERIVED files only, so a co-located asset we do not own
    (assets/sap-logo.png) can never fail the drift check."""
    out = {}
    for name in names:
        path = directory / name
        out[name] = (hashlib.sha256(path.read_bytes()).hexdigest()
                     if path.is_file() else None)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="rebuild into a temp dir and compare; do not write")
    args = ap.parse_args(argv)

    if not MASTER.is_file():
        print(f"brand master missing: {MASTER}", file=sys.stderr)
        return 1

    if not args.check:
        build(STATIC, ASSETS)
        for label, directory, names in (("server/static", STATIC, DERIVED_STATIC),
                                        ("assets", ASSETS, DERIVED_ASSETS)):
            for name, sha in digest(directory, names).items():
                print(f"  {label}/{name:<24} {sha[:12]}")
        return 0

    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        fresh_static, fresh_assets = Path(tmp) / "static", Path(tmp) / "assets"
        build(fresh_static, fresh_assets)
        pairs = ((("server/static", STATIC, fresh_static, DERIVED_STATIC)),
                 (("assets", ASSETS, fresh_assets, DERIVED_ASSETS)))
        drift = [f"{label}/{name}"
                 for label, live_dir, fresh_dir, names in pairs
                 for name, sha in digest(fresh_dir, names).items()
                 if digest(live_dir, names)[name] != sha]

    if not drift:
        print("brand assets match the master")
        return 0
    for name in drift:
        print(f"DRIFT: {name}", file=sys.stderr)
    print("run: python tools/build_brand_assets.py", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
