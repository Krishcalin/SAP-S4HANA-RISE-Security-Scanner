"""A colour class that names no token is not a colour, and nothing says so.

THE DEFECT, TWICE. `frontend/src/index.css` defines the console's palette as
fifteen tokens in one `@theme inline` block, and Tailwind turns each into
utilities — `--color-med` becomes `text-med`. Write `text-medium` and Tailwind
emits NOTHING: no error, no warning, no build failure. The element renders in
whatever colour it inherited, which is usually legible, so the page looks fine
and the emphasis the author wrote is simply absent.

Found in `Findings.tsx`, on the marker that flags a finding resting on
incomplete evidence:

    <span className="pill st text-medium ml-1.5">partial data</span>

`text-medium` is not a token. That marker exists to say a check ran without some
of its exports and a clean result in those areas means the question was not
asked — the one label on the row a reader most needs to notice — and it was
rendering in body text. It shipped that way, and was found while writing an
unrelated colour into the dashboard and checking whether the class existed.

The palette itself is already guarded: `tests/test_palette_contrast.py` computes
WCAG ratios from index.css so nobody can pick a nicer grey that falls under the
floor. That test proves the tokens are readable. This one proves the console is
actually asking for them.

WHY A WHITELIST OF NON-COLOUR VALUES rather than a colour regex: `text-` and
`bg-` are also size, alignment and background utilities (`text-left`, `text-xs`,
`bg-cover`). They are enumerated below because the alternative — matching only
things that look like colour names — is the assumption that produced the bug.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSS = ROOT / "frontend" / "src" / "index.css"
TSX = sorted((ROOT / "frontend" / "src").rglob("*.tsx"))

#: Tailwind utilities that share the `text-`/`bg-` prefix and name no colour.
NOT_COLOURS = {
    # text-*: size
    "xs", "sm", "base", "lg", "xl", "2xl", "3xl", "4xl", "5xl", "6xl", "7xl",
    # text-*: alignment, wrapping, overflow, decoration, transform
    "left", "center", "right", "justify", "start", "end",
    "wrap", "nowrap", "balance", "pretty", "clip", "ellipsis",
    # bg-*: attachment, repeat, size, position, origin, clip
    "fixed", "local", "scroll", "repeat", "cover", "contain", "auto", "none",
    "top", "bottom", "middle", "inherit", "transparent", "current",
}

#: Tailwind's built-in palette. Using one is a style choice, not a defect — the
#: console's own tokens are preferred but `text-white` resolves and renders.
BUILTIN = {
    "white", "black", "slate", "gray", "grey", "zinc", "neutral", "stone",
    "red", "orange", "amber", "yellow", "lime", "green", "emerald", "teal",
    "cyan", "sky", "blue", "indigo", "violet", "purple", "fuchsia", "pink",
    "rose",
}

CLASS_RE = re.compile(r"\b(text|bg)-([a-z][a-z0-9]*)\b")


def theme_tokens() -> set[str]:
    css = CSS.read_text(encoding="utf-8")
    block = css.split("@theme inline {", 1)[1].split("}", 1)[0]
    return set(re.findall(r"--color-([a-z0-9]+)\s*:", block))


def test_the_palette_block_is_where_this_test_thinks_it_is():
    """If the theme block moves or is renamed, every assertion below passes
    vacuously by finding no tokens and no violations. Fail loudly instead."""
    tokens = theme_tokens()
    assert len(tokens) >= 10, f"only found {sorted(tokens)} — has @theme moved?"
    assert {"ink", "crit", "accent"} <= tokens


def test_every_colour_class_in_the_console_names_a_token_that_exists():
    tokens = theme_tokens() | BUILTIN
    offences: list[str] = []
    for path in TSX:
        for lineno, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), 1):
            for prefix, name in CLASS_RE.findall(line):
                if name in tokens or name in NOT_COLOURS:
                    continue
                offences.append(
                    f"{path.relative_to(ROOT).as_posix()}:{lineno} "
                    f"{prefix}-{name}")
    assert not offences, (
        "these classes name no colour token, so Tailwind emits nothing and the "
        "element renders in whatever it inherited:\n  "
        + "\n  ".join(offences)
        + f"\n\ndefined tokens: {', '.join(sorted(theme_tokens()))}")
