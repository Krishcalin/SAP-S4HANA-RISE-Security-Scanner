# Copyright (c) 2026 Krishnendu De. All Rights Reserved.
#
# Author : Krishnendu De
# Coding Assistance : Claude Code
# Code Security Assistance : Code QL

"""Text has to stay readable when someone picks a nicer grey.

The console's colours are six tokens in one media query, and changing them is a
two-minute edit that looks purely cosmetic. It is not: `--panel` and `--ink-faint`
are two ends of a contrast ratio, and moving either without the other is how a
palette drifts under the floor.

IT ALREADY HAD. Before the light card was softened off pure white, `--ink-faint`
was #8c959f -- 2.85:1 on the page and 3.04:1 on a card, under the 3:1 floor for
incidental text, with nothing anywhere saying so. That was not introduced by a
redesign; it shipped, and it was found by doing the arithmetic while making an
unrelated change someone asked for on the grounds that the white "looked stark".

So this file computes WCAG relative luminance from index.css itself rather than
asserting the hex values. Pinning hexes would forbid a redesign; this permits any
palette that stays legible, which is the actual requirement.

THE 4.5 FLOOR IS NOT APPLIED TO `--ink-faint`, deliberately and with the reason
recorded. It is the de-emphasis token: labels, monospace hints, the quiet half of
a two-tone row. Forcing it to 4.5:1 would put it within touching distance of
`--ink-dim` at 6.1:1 and leave the palette with no quiet tone at all. It is held
to 3:1, the threshold for incidental and large text, and to being visibly lighter
than `--ink-dim` so the hierarchy it exists to express survives.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CSS = ROOT / "frontend" / "src" / "index.css"


def _linear(channel: int) -> float:
    c = channel / 255
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def luminance(hex_colour: str) -> float:
    h = hex_colour.lstrip("#")
    if len(h) == 3:
        h = "".join(ch * 2 for ch in h)
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    return 0.2126 * _linear(r) + 0.7152 * _linear(g) + 0.0722 * _linear(b)


def contrast(a: str, b: str) -> float:
    la, lb = luminance(a), luminance(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def _tokens(block: str) -> dict[str, str]:
    return {m.group(1): m.group(2).lower()
            for m in re.finditer(r"--([a-z0-9-]+)\s*:\s*(#[0-9a-fA-F]{3,6})\b", block)}


def _palettes() -> dict[str, dict[str, str]]:
    """The dark defaults on :root, and the light overrides in the media query.

    Light is read as dark-updated-by-light because the media query only restates
    the tokens it changes -- `--accent` and the severity colours are declared
    once and serve both themes.
    """
    css = CSS.read_text(encoding="utf-8")
    root = re.search(r":root\s*\{(.*?)\}", css, re.S)
    assert root, "no :root block in index.css"
    dark = _tokens(root.group(1))

    light_block = re.search(
        r"@media \(prefers-color-scheme: light\)\s*\{.*?:root\s*\{(.*?)\}", css, re.S)
    assert light_block, "no light-scheme override in index.css"
    light = {**dark, **_tokens(light_block.group(1))}
    return {"dark": dark, "light": light}


SURFACES = ("bg", "panel", "panel-2")


@pytest.mark.parametrize("theme", ["dark", "light"])
@pytest.mark.parametrize("surface", SURFACES)
def test_primary_text_is_readable_on_every_surface(theme, surface):
    """`--ink` is body copy. 4.5:1 is the floor and it clears it comfortably in
    both themes; a change that broke this would be visible immediately, which is
    exactly why nobody checks it."""
    p = _palettes()[theme]
    r = contrast(p["ink"], p[surface])
    assert r >= 4.5, f"{theme}: --ink on --{surface} is {r:.2f}:1, below 4.5"


@pytest.mark.parametrize("theme", ["dark", "light"])
@pytest.mark.parametrize("surface", SURFACES)
def test_secondary_text_is_readable_on_every_surface(theme, surface):
    """`--ink-dim` carries real sentences — narrative, descriptions, the prose
    under a heading. It is body copy in every sense that matters and is held to
    the same floor."""
    p = _palettes()[theme]
    r = contrast(p["ink-dim"], p[surface])
    assert r >= 4.5, f"{theme}: --ink-dim on --{surface} is {r:.2f}:1, below 4.5"


@pytest.mark.parametrize("theme", ["dark", "light"])
@pytest.mark.parametrize("surface", SURFACES)
def test_de_emphasised_text_clears_the_incidental_floor(theme, surface):
    """3:1, not 4.5:1, and the docstring at the top of this file says why.

    The light theme FAILED this before the palette was softened: #8c959f gave
    2.85:1 on the page and 2.73:1 on a nested surface. The floor is here so that
    stays fixed."""
    p = _palettes()[theme]
    r = contrast(p["ink-faint"], p[surface])
    assert r >= 3.0, f"{theme}: --ink-faint on --{surface} is {r:.2f}:1, below 3.0"


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_the_three_ink_tones_stay_in_order(theme):
    """A hierarchy that inverts is worse than no hierarchy: the eye would read
    the quiet text as the loud one. Ordering is asserted by CONTRAST against the
    card rather than by luminance, because the dark theme runs light-on-dark and
    a raw luminance comparison would be backwards there."""
    p = _palettes()[theme]
    ink = contrast(p["ink"], p["panel"])
    dim = contrast(p["ink-dim"], p["panel"])
    faint = contrast(p["ink-faint"], p["panel"])
    assert ink > dim > faint, (
        f"{theme}: ink {ink:.2f} / dim {dim:.2f} / faint {faint:.2f} — "
        "the tones are out of order")


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_a_card_is_distinguishable_from_the_page_behind_it(theme):
    """The change that prompted this file. A card at 1.06:1 against the page is a
    card you locate by its border alone; the border is one pixel of --line and
    disappears on a cheap panel or in a screenshot rescaled for a deck."""
    p = _palettes()[theme]
    r = contrast(p["panel"], p["bg"])
    assert r >= 1.10, (
        f"{theme}: --panel against --bg is {r:.3f}:1 — the card does not lift off "
        "the page")


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_a_hovered_row_is_distinguishable_from_the_card(theme):
    """`--panel-2` is hover feedback and nested surfaces. Too close to `--panel`
    and hovering a row does nothing visible, which reads as an unresponsive
    table rather than as a subtle one."""
    p = _palettes()[theme]
    r = contrast(p["panel"], p["panel-2"])
    assert r >= 1.06, (
        f"{theme}: --panel-2 against --panel is {r:.3f}:1 — hover is invisible")


def test_the_light_card_is_not_pure_white():
    """The actual request, kept as a fact rather than a memory.

    Not a hex assertion — any softened neutral passes. It fails only on a return
    to #fff or #ffffff, which is the specific thing that was asked to change.
    """
    light = _palettes()["light"]
    assert light["panel"] not in ("#fff", "#ffffff"), \
        "the light card is pure white again"
