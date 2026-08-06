"""
Turning authored text into structure the browser will honour.

The findings knowledge base stores remediation as a numbered list, one step per
line, and risk narratives as prose, one paragraph per line — both separated by a
single "\\n" and never by a blank line. HTML collapses newlines to spaces, so
dropping either into a <p> hands the reader one run-on paragraph and loses the
authored structure entirely. A ten-step remediation procedure rendered as a wall
of text is not a procedure; nobody can work down it, and it is impossible to say
"I'm on step 4".

WHY THIS IS NOT `white-space: pre-line`
That one CSS property would put the breaks back, and it is what the CLI's HTML
report does. It is not enough here. A wrapped step continues at the left margin,
directly under its own number, so at a glance the numbers stop being a column and
the steps stop being separable. A real <ol> gives hanging indentation, and it also
tells a screen reader "list, 10 items" — a run of lines announces nothing.

WHY THE ENUMERATION IS VALIDATED RATHER THAN ASSUMED
An <ol> renumbers from 1 whatever the source said. That is fine when the source is
already 1..N and actively wrong otherwise: text numbered 3,4,5 (an excerpt) or
1,2,2,3 (an authoring slip) would be silently RENUMBERED, and the rendered step
numbers would no longer match anything the text refers to or a reviewer is reading
alongside. So `steps()` returns None unless the run is exactly 1..N, and the
caller falls back to paragraphs, which preserve the text as written.
"""
from __future__ import annotations

import re
from typing import List, Optional

#: "1. ", "2) ", " 10.  " — a leading ordinal and its delimiter.
_ORDINAL = re.compile(r"^\s*(\d{1,3})[.)]\s+(.+)$", re.DOTALL)


def paragraphs(text: Optional[str]) -> List[str]:
    """Split authored text into paragraphs — one per non-empty line.

    The corpus separates paragraphs with a single newline and never uses blank
    lines, so a blank-line split would return the whole thing as one paragraph
    and change nothing.
    """
    if not text:
        return []
    return [line.strip() for line in str(text).splitlines() if line.strip()]


def steps(text: Optional[str]) -> Optional[List[str]]:
    """Return the numbered steps with their ordinals stripped, or None.

    None means "this is not a clean 1..N enumeration" — render it as prose
    instead. Callers must handle it; roughly a third of the knowledge base's
    risk narratives are single paragraphs with no numbering at all.

    An UNNUMBERED line is treated as a continuation of the step before it, so a
    step hard-wrapped across two lines survives instead of collapsing the whole
    list to None.

    A line that carries the WRONG ordinal aborts instead. Absorbing it would be
    the worst of the three outcomes: "2. Two.\\n2. Two again." would render as a
    single step reading "Two. 2. Two again.", which is neither the authored text
    nor a correct list — it silently corrupts a procedure someone is following.
    Refusing gives them the text as written.
    """
    lines = paragraphs(text)
    if len(lines) < 2:
        return None

    out: List[str] = []
    expected = 1
    for line in lines:
        match = _ORDINAL.match(line)
        if match:
            if int(match.group(1)) != expected:
                return None                      # 1,2,2 or 1,2,4 — not a clean run
            out.append(match.group(2).strip())
            expected += 1
        elif out:
            out[-1] = f"{out[-1]} {line}"        # hard-wrapped continuation
        else:
            return None                          # does not begin at step 1
    return out if len(out) >= 2 else None
