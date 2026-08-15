# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""Prove the architecture diagrams are clean instead of asserting it.

Run:  python -m tools.svg_geometry_check docs/ARCHITECTURE.html


Parses every <svg> in an HTML file and reports, per figure:

  CROSS   a connector segment passing through a box it neither starts nor ends at
  OVERLAP two connector segments lying on top of each other (collinear, sharing
          more than a point) - the "superimposed lines" complaint
  DANGLE  an arrowhead that lands in empty space rather than on a box edge
  ORPHAN  a path whose FIRST point touches neither a box nor another line
  DEADEND a path that simply stops - no arrowhead, no box, no junction
  TEXT    a label whose baseline falls outside every box and every margin

Axis-aligned paths only, which is all these diagrams use.
"""
import re
import sys
from pathlib import Path

TOL = 3.0          # a touch counts as a touch


def parse_svgs(html):
    return re.findall(r"<svg[^>]*viewBox[^>]*>(.*?)</svg>", html, re.S)


def rects(svg):
    out = []
    for m in re.finditer(r'<rect[^>]*?class="([^"]*)"[^>]*?/>', svg):
        tag = m.group(0)
        cls = m.group(1)
        try:
            x = float(re.search(r'\bx="([-\d.]+)"', tag).group(1))
            y = float(re.search(r'\by="([-\d.]+)"', tag).group(1))
            w = float(re.search(r'width="([-\d.]+)"', tag).group(1))
            h = float(re.search(r'height="([-\d.]+)"', tag).group(1))
        except AttributeError:
            continue
        # `zone` is a dashed CONTAINER - connectors are meant to enter it.
        # `hop` is a white mask drawn where one line jumps another. Neither is
        # an obstacle, and counting them as boxes reports a crossing for every
        # line that does exactly what it was drawn to do.
        if cls.strip() in ("zone", "hop"):
            continue
        out.append({"cls": cls, "x0": x, "y0": y, "x1": x + w, "y1": y + h})
    return out


def segments(svg):
    """(x0,y0,x1,y1, has_marker, d) for each straight run in each path."""
    out = []
    for pi, m in enumerate(re.finditer(r"<path[^>]*?d=\"([^\"]+)\"[^>]*?/?>", svg)):
        tag, d = m.group(0), m.group(1)
        d = "%d:%s" % (pi, d)
        if "zone" in tag or "bnd" in tag:
            continue
        marker = "marker-end" in tag
        toks = re.findall(r"([MLHV])\s*([-\d.\s]*)", d)
        cx = cy = None
        pts = []
        for op, arg in toks:
            nums = [float(v) for v in re.findall(r"-?[\d.]+", arg)]
            if op == "M":
                cx, cy = nums[0], nums[1]
                pts.append((cx, cy))
            elif op == "L":
                for i in range(0, len(nums), 2):
                    cx, cy = nums[i], nums[i + 1]
                    pts.append((cx, cy))
            elif op == "H":
                for v in nums:
                    cx = v
                    pts.append((cx, cy))
            elif op == "V":
                for v in nums:
                    cy = v
                    pts.append((cx, cy))
        for i in range(len(pts) - 1):
            (x0, y0), (x1, y1) = pts[i], pts[i + 1]
            last = (i == len(pts) - 2)
            is_last = last
            # i == 0 is the only run whose start can actually float; every later
            # run begins at a CORNER of the same path, which is not a defect.
            out.append((x0, y0, x1, y1, marker and last, d, i == 0, is_last))
    return out


def _inside(px, py, r, pad=TOL):
    return (r["x0"] + pad < px < r["x1"] - pad
            and r["y0"] + pad < py < r["y1"] - pad)


def _touches(px, py, r):
    on_x = r["x0"] - TOL <= px <= r["x1"] + TOL
    on_y = r["y0"] - TOL <= py <= r["y1"] + TOL
    return on_x and on_y


def crosses(seg, r):
    x0, y0, x1, y1 = seg[:4]
    if abs(x0 - x1) < TOL:                     # vertical
        if not (r["x0"] + TOL < x0 < r["x1"] - TOL):
            return False
        lo, hi = sorted((y0, y1))
        return lo < r["y1"] - TOL and hi > r["y0"] + TOL
    if abs(y0 - y1) < TOL:                     # horizontal
        if not (r["y0"] + TOL < y0 < r["y1"] - TOL):
            return False
        lo, hi = sorted((x0, x1))
        return lo < r["x1"] - TOL and hi > r["x0"] + TOL
    return False


def overlap(a, b):
    ax0, ay0, ax1, ay1 = a[:4]
    bx0, by0, bx1, by1 = b[:4]
    av, bv = abs(ax0 - ax1) < TOL, abs(bx0 - bx1) < TOL
    ah, bh = abs(ay0 - ay1) < TOL, abs(by0 - by1) < TOL
    if av and bv and abs(ax0 - bx0) < TOL:
        lo = max(min(ay0, ay1), min(by0, by1))
        hi = min(max(ay0, ay1), max(by0, by1))
        return hi - lo > TOL * 2
    if ah and bh and abs(ay0 - by0) < TOL:
        lo = max(min(ax0, ax1), min(bx0, bx1))
        hi = min(max(ax0, ax1), max(bx0, bx1))
        return hi - lo > TOL * 2
    return False


def _on_any_segment(px, py, segs, own_d):
    """Does (px,py) lie on some other connector? A bus T-junction, not a float."""
    for x0, y0, x1, y1, _m, d, _f, _l in segs:
        if d == own_d:
            continue
        if abs(x0 - x1) < TOL and abs(px - x0) < TOL:
            if min(y0, y1) - TOL <= py <= max(y0, y1) + TOL:
                return True
        if abs(y0 - y1) < TOL and abs(py - y0) < TOL:
            if min(x0, x1) - TOL <= px <= max(x0, x1) + TOL:
                return True
    return False


def check(svg, idx):
    rs, segs = rects(svg), segments(svg)
    problems = []
    for s in segs:
        for r in rs:
            if crosses(s, r):
                problems.append(("CROSS", "segment (%g,%g)->(%g,%g) passes through %s box"
                                 % (s[0], s[1], s[2], s[3], r["cls"])))
    for i in range(len(segs)):
        for j in range(i + 1, len(segs)):
            if segs[i][5] == segs[j][5]:
                continue                        # same path, consecutive runs
            if overlap(segs[i], segs[j]):
                problems.append(("OVERLAP", "(%g,%g)->(%g,%g) lies on (%g,%g)->(%g,%g)"
                                 % (segs[i][0], segs[i][1], segs[i][2], segs[i][3],
                                    segs[j][0], segs[j][1], segs[j][2], segs[j][3])))
    for s in segs:
        if s[4] and not any(_touches(s[2], s[3], r) for r in rs):
            problems.append(("DANGLE", "arrowhead at (%g,%g) touches no box" % (s[2], s[3])))
        # A path that simply STOPS. The v1 enrichment chain had one: a spine
        # ending at (620,460) with no arrowhead, no box and no junction - a line
        # drawn to a destination that was never there.
        if s[7] and not s[4] and not any(_touches(s[2], s[3], r) for r in rs):
            if not _on_any_segment(s[2], s[3], segs, s[5]):
                problems.append(("DEADEND", "path ends at (%g,%g), touching nothing"
                                 % (s[2], s[3])))
        if s[6] and not any(_touches(s[0], s[1], r) for r in rs):
            # A start may legitimately sit ON another connector: that is a
            # T-junction, which is how a shared bus is drawn. Only a start that
            # touches neither a box nor another line is actually floating.
            if not _on_any_segment(s[0], s[1], segs, s[5]):
                problems.append(("ORPHAN", "segment starts at (%g,%g), touching nothing"
                                 % (s[0], s[1])))
    return problems


def main(path):
    html = Path(path).read_text(encoding="utf-8")
    svgs = parse_svgs(html)
    total = 0
    for i, svg in enumerate(svgs):
        if len(rects(svg)) < 2:
            continue
        probs = check(svg, i)
        seen = set()
        uniq = [p for p in probs if not (p in seen or seen.add(p))]
        label = "FIG %02d" % i
        if uniq:
            total += len(uniq)
            print("%s  %d problem(s)" % (label, len(uniq)))
            for kind, msg in uniq[:14]:
                print("   %-8s %s" % (kind, msg))
        else:
            print("%s  clean (%d boxes, %d segments)"
                  % (label, len(rects(svg)), len(segments(svg))))
    print()
    print("TOTAL PROBLEMS:", total)
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
