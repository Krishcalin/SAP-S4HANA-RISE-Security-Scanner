"""
Derive server/static/* from the brand master in docs/brand/.

    python tools/build_brand_assets.py            # rebuild
    python tools/build_brand_assets.py --check    # fail if the committed assets drift

Requires Pillow. That is a BUILD-time tool, not a runtime dependency — it is
deliberately absent from requirements.txt, and the container never runs this. The
derived PNGs are committed so a deployment (and CI) needs nothing but the repo.

WHY THE MASTER IS NOT SERVED DIRECTLY
The supplied artwork is a presentation render: the logo sits on a textured cream
field with a wide margin. Dropped onto the console as-is it is a bright slab on a
dark page, and its cream never matches a CSS colour exactly, so a rectangle is
always visible at the seam. So the cream is keyed out to transparency.

Not with a luminance threshold. The brand blue (#109af5) sits roughly halfway
between the cream and the navy in luminance, so a luma key renders half the
wordmark semi-transparent. Instead each pixel is un-mixed against the two known
brand colours: a pixel on an anti-aliased edge is a blend a*L + (1-a)*B of one
brand colour and the background, so projecting (p - B) onto (L - B) recovers both
the coverage and the true colour. Whichever brand colour leaves the smaller
residual wins, which is what keeps navy edges navy and blue edges blue.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

try:
    from PIL import Image
except ImportError:                                     # pragma: no cover
    sys.exit("this tool needs Pillow:  pip install Pillow")

ROOT = Path(__file__).resolve().parents[1]
MASTER = ROOT / "docs" / "brand" / "monitorrisk-master.png"
STATIC = ROOT / "server" / "static"

#: Sampled from the master. NAVY is the wordmark "Monitor", the shield outline and
#: the tagline; BLUE is "Risk" and the pulse trace.
NAVY = (0x0b, 0x24, 0x6a)
BLUE = (0x10, 0x9a, 0xf5)
CREAM = (0xf3, 0xf2, 0xee)
#: The dark console panel is #161c24; a navy shield on it is all but invisible, so
#: the dark-theme mark lifts the navy to the page ink colour. The pulse keeps the
#: brand blue, which is what carries the identity at 22px anyway.
INK = (0xe6, 0xed, 0xf3)


def key_out(im, bg, targets, floor=0.06):
    """Background -> alpha, recovering the true colour of every anti-aliased pixel."""
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
            dst[x, y] = ((0, 0, 0, 0) if best_a <= floor        # paper texture, not ink
                         else (*best_L, int(best_a * 255 + 0.5)))
    return out


def trim(im):
    box = im.getbbox()
    return im if box is None else im.crop(box)


def split_mark(keyed):
    """Crop the shield off the front of the lockup.

    The gutter between the mark and the "M" is MEASURED — the first sustained run
    of fully transparent columns — rather than assumed at a fixed fraction, so a
    re-exported master with different spacing still splits correctly.
    """
    alpha = keyed.getchannel("A").load()
    gutter = max(8, keyed.width // 90)
    run = 0
    for x in range(keyed.width):
        if any(alpha[x, y] for y in range(keyed.height)):
            run = 0
            continue
        run += 1
        if run >= gutter and x > keyed.width * 0.08:
            return trim(keyed.crop((0, 0, x - run + 1, keyed.height)))
    raise SystemExit("could not find the gutter between the mark and the wordmark")


def build(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    keyed = trim(key_out(Image.open(MASTER), CREAM, (NAVY, BLUE)))

    # Full lockup — the sign-in brand panel. 1100px covers a ~550px slot at 2x.
    lockup = keyed.resize((1100, round(keyed.height * 1100 / keyed.width)), Image.LANCZOS)
    lockup.save(out_dir / "monitorrisk-logo.png", optimize=True)

    mark = split_mark(keyed)
    square = Image.new("RGBA", (max(mark.size),) * 2, (0, 0, 0, 0))
    square.paste(mark, ((square.width - mark.width) // 2,
                        (square.height - mark.height) // 2))
    square.resize((160, 160), Image.LANCZOS).save(
        out_dir / "monitorrisk-mark.png", optimize=True)

    dark = square.copy()
    px = dark.load()
    for y in range(dark.height):
        for x in range(dark.width):
            r, g, b, a = px[x, y]
            if a and abs(r - BLUE[0]) + abs(g - BLUE[1]) + abs(b - BLUE[2]) > 90:
                px[x, y] = (*INK, a)
    dark.resize((160, 160), Image.LANCZOS).save(
        out_dir / "monitorrisk-mark-dark.png", optimize=True)

    square.resize((64, 64), Image.LANCZOS).save(
        out_dir / "favicon.ico", sizes=[(16, 16), (32, 32), (48, 48), (64, 64)])


def digest(d: Path):
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(d.iterdir()) if p.is_file()}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--check", action="store_true",
                    help="rebuild into a temp dir and compare; do not write")
    args = ap.parse_args(argv)

    if not MASTER.is_file():
        print(f"brand master missing: {MASTER}", file=sys.stderr)
        return 1

    if not args.check:
        build(STATIC)
        for name, sha in digest(STATIC).items():
            print(f"  {name:<28} {sha[:12]}")
        return 0

    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        build(Path(tmp))
        fresh, live = digest(Path(tmp)), digest(STATIC)
    if fresh == live:
        print("brand assets match the master")
        return 0
    for name in sorted(set(fresh) | set(live)):
        if fresh.get(name) != live.get(name):
            print(f"DRIFT: {name}", file=sys.stderr)
    print("run: python tools/build_brand_assets.py", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
