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


# ── the card edge ────────────────────────────────────────────────────────────

ROUTES = ROOT / "frontend" / "src"

#: A rounded box with a panel background. Anchored on the whole pattern so that
#: table rules (`border-b border-line`) and form controls cannot match it.
CARD_PATTERN = re.compile(r"rounded-(?:lg|md) border border-(\w+) bg-panel")


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_the_card_border_is_visible_against_the_card(theme):
    """A border nobody can see is not a border.

    The old edge was `--line` at 1.34:1 in light and 1.30:1 in dark -- present in
    the DOM and absent to the eye, which is why a card was located by its
    background rather than its outline.
    """
    p = _palettes()[theme]
    assert "card-line" in p, f"{theme}: --card-line is not declared"
    r = contrast(p["card-line"], p["panel"])
    assert r >= 1.8, (
        f"{theme}: --card-line against --panel is {r:.2f}:1 — too faint to read "
        "as an edge")


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_the_card_border_is_a_blue(theme):
    """The request was specifically a blue edge, and a later 'tidy the palette'
    pass that greyed it would be reverting a decision rather than tidying.

    Blue in the ordinary sense: more blue than red, and more blue than green."""
    h = _palettes()[theme]["card-line"].lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    assert b > r and b > g, f"{theme}: --card-line #{h} is not a blue"


def test_the_card_border_does_not_rule_the_tables():
    """`--card-line` and `--line` must stay separate tokens.

    89 uses of `--line` are row separators, cell edges and banner outlines. If the
    two ever collapse into one value, a change to how a CARD is outlined draws a
    saturated grid over every table in the product -- which is the reason this is
    a second token rather than a new value for the first.
    """
    for theme, p in _palettes().items():
        assert p["card-line"] != p["line"], (
            f"{theme}: --card-line and --line are the same value; the card edge "
            "and the table rules have collapsed into one")


def test_every_card_uses_the_card_border_token():
    """Structural, because the card class string is copy-pasted rather than
    shared: 36 occurrences across 17 route files, each written out in full.

    A new screen built by copying an existing one is the normal way this drifts,
    and it drifts silently -- the card still has a border, just the invisible one.
    """
    offenders = []
    for f in sorted(ROUTES.rglob("*.tsx")):
        if f.name.endswith(".test.tsx"):
            continue
        for m in CARD_PATTERN.finditer(f.read_text(encoding="utf-8")):
            if m.group(1) != "cardline":
                offenders.append(f"{f.relative_to(ROUTES)}: border-{m.group(1)}")
    assert not offenders, (
        "these card containers still use the table-rule border: " + "; ".join(offenders))


def test_there_are_still_cards_to_check():
    """The guard above passes trivially if the pattern stops matching anything --
    a class-name refactor would make it green and blind on the same day."""
    found = sum(len(CARD_PATTERN.findall(f.read_text(encoding="utf-8")))
                for f in ROUTES.rglob("*.tsx") if not f.name.endswith(".test.tsx"))
    assert found >= 30, f"only {found} card containers matched; the pattern has drifted"


# ── the stat tile ────────────────────────────────────────────────────────────

UI = ROOT / "frontend" / "src" / "lib" / "ui.ts"

#: A local re-declaration of a shared tile class. This is exactly how the drift
#: happened: twelve files each spelling out their own, none of them wrong on its
#: own page, four different tiles across the console.
LOCAL_TILE = re.compile(r"^const (CARD_H3|CARD_TITLE|KPI|KPI_NOTE)\s*=", re.M)


def test_the_stat_tile_lives_in_one_place():
    assert UI.exists(), "frontend/src/lib/ui.ts is gone"
    src = UI.read_text(encoding="utf-8")
    for name in ("CARD_TITLE", "KPI", "KPI_NOTE"):
        assert f"export const {name}" in src, f"lib/ui no longer exports {name}"


def test_the_headline_number_is_extrabold():
    """The point of the whole exercise.

    Eleven of twelve screens rendered the figure at `font-semibold`, where it
    read as a large paragraph rather than as the number the card exists to
    deliver. One screen used `font-extrabold`, and that is the one someone
    pointed at and said the numbers looked right.
    """
    kpi = [l for l in UI.read_text(encoding="utf-8").splitlines()
           if l.startswith("export const KPI =")]
    assert kpi, "KPI is no longer a single-line declaration"
    assert "font-extrabold" in kpi[0], f"the headline number is not extrabold: {kpi[0]}"


def test_no_screen_declares_its_own_stat_tile():
    """Structural. A screen that re-declares one of these gets a tile that is
    correct in isolation and different from every other page, which is invisible
    until two screens are open side by side."""
    offenders = []
    for f in sorted((ROOT / "frontend" / "src" / "routes").glob("*.tsx")):
        if f.name.endswith(".test.tsx"):
            continue
        for m in LOCAL_TILE.finditer(f.read_text(encoding="utf-8")):
            offenders.append(f"{f.name}: {m.group(1)}")
    assert not offenders, (
        "these screens re-declare a shared stat-tile class instead of importing "
        "it from lib/ui: " + "; ".join(offenders))


def test_the_screens_actually_use_it():
    """The guard above is satisfied by a console with no stat tiles at all. This
    is the half that notices."""
    routes = ROOT / "frontend" / "src" / "routes"
    users = [f.name for f in routes.glob("*.tsx")
             if not f.name.endswith(".test.tsx")
             and "from '../lib/ui'" in f.read_text(encoding="utf-8")]
    assert len(users) >= 12, f"only {len(users)} screens import the stat tile"


def test_the_note_under_a_number_uses_the_readable_ink():
    """`--ink-faint` is held to 3:1 and is for labels and hints. The note under a
    KPI is a sentence explaining what the figure counts, so it gets `--ink-dim`,
    which the tests above hold to 4.5:1. One screen had it on the faint token."""
    note = [l for l in UI.read_text(encoding="utf-8").splitlines()
            if l.startswith("export const KPI_NOTE =")]
    assert note and "text-ink2" in note[0], f"KPI_NOTE is not on --ink-dim: {note}"
