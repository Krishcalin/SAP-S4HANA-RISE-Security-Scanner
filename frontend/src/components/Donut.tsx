/**
 * Part-to-whole, at a glance.
 *
 * A DONUT AND NOT A PIE, and the hole is the reason. It carries the total, so
 * one mark answers both questions a reader brings to a distribution — "how many
 * altogether" and "how is it split" — where a pie answers only the second and
 * sends them elsewhere for the first.
 *
 * WHERE THIS FORM IS CORRECT, and it is a narrow window:
 *
 *   - the segments are parts of a meaningful whole
 *   - there are SIX OR FEWER of them
 *   - the reader wants the shape of the split, not a comparison of close values
 *
 * Outside that window it is the wrong mark and this component should not be
 * reached for. Two slices is a stat tile — the number is the chart. A ratio
 * against a limit (15 of 38 requirements) is a meter, because the limit is the
 * point and a donut hides it. More than about seven classes blurs at the
 * adjacent boundaries and wants a table. Close values want a bar, because arc
 * length is the hardest encoding to compare by eye and the one people
 * consistently misread.
 *
 * IDENTITY IS NEVER CARRIED BY COLOUR ALONE. Every segment appears in the legend
 * with its label, its count and its share; the arc carries emphasis, the text
 * carries the fact. That also makes the whole thing legible in monochrome, under
 * forced-colors, and to a reader with any form of colour blindness, without a
 * second encoding having to be invented for those cases.
 *
 * A 2px gap of the surface colour separates adjacent arcs, so two segments of
 * similar hue read as two marks rather than one long one.
 */

export interface DonutSlice {
  key: string
  label: string
  value: number
  /** A CSS colour — a token, not a literal, so it follows the theme. */
  color: string
}

const R = 54
const STROKE = 22
const BOX = 140
const C = 2 * Math.PI * R

export function Donut({ slices, total, caption, ariaLabel, format }: {
  slices: DonutSlice[]
  /** How to render a value. Counts read fine as plain integers, which is the
   *  default; MONEY DOES NOT. `toLocaleString()` on 114380643 produces an
   *  eleven-character grouped integer in whatever grouping the reader's locale
   *  uses -- and the exposure donut rendered exactly that, overflowing the hole
   *  and printing dollars with the grouping of another currency. Callers holding
   *  money pass `money`. */
  format?: (n: number) => string
  /** The denominator. Passed rather than summed: on some screens the whole is a
   *  known figure that the slices do not add up to, and quietly re-basing to the
   *  sum would misstate every share on the card. */
  total?: number
  caption?: string
  ariaLabel: string
}) {
  const shown = slices.filter((s) => s.value > 0)
  const sum = shown.reduce((n, s) => n + s.value, 0)
  const whole = total ?? sum

  if (whole <= 0 || shown.length === 0) {
    // An empty ring is a claim that the whole is zero AND that it is divided.
    // Say the first and drop the mark.
    return (
      <p className="text-[13px] text-ink3">
        Nothing to show here yet — the total is zero.
      </p>
    )
  }

  // A single segment is a full ring, which is a circle with a hole: no split to
  // read. The number and its one label say strictly more.
  const single = shown.length === 1

  let offset = 0
  const arcs = shown.map((s) => {
    const frac = s.value / whole
    const len = Math.max(frac * C - (single ? 0 : 2), 0)
    const arc = { ...s, frac, len, gap: C - len, offset: -offset }
    offset += frac * C
    return arc
  })

  const fmt = format ?? ((n: number) => n.toLocaleString())

  // The hole is 86 units across. Long strings step the type down rather than
  // running past the ring: the centre figure is the one thing on this mark that
  // cannot be allowed to collide with the mark itself, and a caller cannot know
  // how wide its own formatted value will be.
  // Shrink to fit, then TRUNCATE to fit, because shrinking alone has a floor:
  // below about 11 units the figure is unreadable, so past that point the string
  // has to give instead of the type. Every real value clears this comfortably --
  // a grouped seven-digit count is 9 characters, `money` gives 8 -- so truncation
  // is the pathological case degrading visibly rather than crossing the ring.
  const HOLE = 2 * (R - STROKE / 2)      // 86 units of usable width
  const MIN_SIZE = 11
  const raw = fmt(whole)
  const maxChars = Math.floor(HOLE / (MIN_SIZE * 0.58))
  const centre = raw.length > maxChars ? `${raw.slice(0, maxChars - 1)}…` : raw
  const centreSize = Math.max(
    MIN_SIZE, Math.min(26, Math.floor(HOLE / (centre.length * 0.58))))

  const pct = (v: number) => {
    const p = (100 * v) / whole
    // Never round a present slice to "0%" — it reads as absent. Nor to 100%
    // while something else is still on the card.
    if (p > 0 && p < 1) return '<1%'
    if (p > 99 && p < 100) return '>99%'
    return `${Math.round(p)}%`
  }

  return (
    <div className="flex items-center gap-5 flex-wrap">
      <svg viewBox={`0 0 ${BOX} ${BOX}`} width={BOX} height={BOX} role="img"
           aria-label={ariaLabel} className="shrink-0">
        {/* The track. Without it a nearly-empty ring floats with no shape to sit
            in, and the eye cannot judge how much of the whole is missing. */}
        <circle cx={BOX / 2} cy={BOX / 2} r={R} fill="none"
                stroke="var(--panel-2)" strokeWidth={STROKE} />
        <g transform={`rotate(-90 ${BOX / 2} ${BOX / 2})`}>
          {arcs.map((a) => (
            <circle key={a.key} cx={BOX / 2} cy={BOX / 2} r={R} fill="none"
                    stroke={a.color} strokeWidth={STROKE}
                    strokeDasharray={`${a.len.toFixed(2)} ${a.gap.toFixed(2)}`}
                    strokeDashoffset={a.offset.toFixed(2)}>
              <title>{`${a.label}: ${fmt(a.value)} (${pct(a.value)})`}</title>
            </circle>
          ))}
        </g>
        {/* The hole earns its place: this is the stat tile as well as the split. */}
        <text x={BOX / 2} y={BOX / 2 - 2} textAnchor="middle" fontSize={centreSize}
              fontWeight="700" fill="var(--ink)">
          {centre}
        </text>
        {caption && (
          <text x={BOX / 2} y={BOX / 2 + 16} textAnchor="middle" fontSize="11"
                fill="var(--ink-faint)">{caption}</text>
        )}
      </svg>

      {/* Label, count and share for every segment. The arc is emphasis; this is
          the fact, and it is what makes the card readable without colour. */}
      <ul className="text-[13px] space-y-1.5 min-w-[190px] flex-1">
        {arcs.map((a) => (
          <li key={a.key} className="flex items-center gap-2">
            <i className="inline-block w-2.5 h-2.5 rounded-[3px] shrink-0"
               style={{ background: a.color }} aria-hidden="true" />
            <span className="text-ink2 flex-1 truncate">{a.label}</span>
            <span className="font-mono text-ink tabular-nums">
              {fmt(a.value)}
            </span>
            <span className="font-mono text-ink3 tabular-nums w-[46px] text-right">
              {pct(a.value)}
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}
