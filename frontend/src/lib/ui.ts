/**
 * The stat tile, in one place.
 *
 * These three strings were copy-pasted into twelve route files and had drifted
 * into four different tiles. Eleven files rendered the headline number at
 * `font-semibold`; one rendered it at `font-extrabold`, and that one is the
 * screen someone pointed at and said the numbers looked right. The note under
 * the number existed in three spellings — `text-ink2` in nine files, `text-ink3`
 * in one, and a hand-rolled `mt-[5px]` on the dashboard — and the label above it
 * in two, differing only in the order of the classes.
 *
 * None of that is visible while writing a screen. It is only visible with two
 * screens side by side, which is how a console comes to look slightly
 * home-made without any single page being wrong.
 *
 * SHARED CONSTANTS RATHER THAN A COMPONENT, deliberately. Every call site
 * already spells out its own card markup, and the tiles differ in what they
 * contain — a link, a coloured number, a second line, a donut. A <Stat>
 * component would have to grow a prop for each of those, and the first tile that
 * did not fit would quietly go back to hand-rolled classes. Strings compose with
 * anything.
 */

/** The small uppercase label above a stat. */
export const CARD_TITLE =
  'text-[12px] font-semibold uppercase tracking-[.06em] text-ink3 mb-3'

/** The number itself. EXTRABOLD, which is the whole point of this file: it is
 *  the figure the screen exists to deliver, and at `font-semibold` it read as a
 *  large paragraph rather than as a headline. */
export const KPI = 'text-[30px] font-extrabold tracking-[-.02em] leading-[1.1]'

/** The line under the number that says what it means.
 *
 *  `text-ink2`, not `text-ink3`. This is a real sentence and gets the token held
 *  to 4.5:1 by tests/test_palette_contrast.py; `--ink-faint` is held only to 3:1
 *  and is for labels and hints, not for the clause explaining what a figure
 *  counts. */
export const KPI_NOTE = 'text-[12px] text-ink2 mt-1.5'
