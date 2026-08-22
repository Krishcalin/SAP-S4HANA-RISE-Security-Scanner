/**
 * A ratio against a stated limit.
 *
 * WHY THIS EXISTS RATHER THAN A THIRD DONUT. "15 of 38 requirements" is not a
 * part-to-whole split with two categories — it is one value measured against a
 * ceiling, and the ceiling is the point. A donut of covered-vs-uncovered turns
 * the limit into a second slice, which reads as though "not covered" were a
 * thing the product produced rather than the room left in the denominator.
 *
 * A two-slice pie is the most common way a dashboard says less than the number
 * it replaced. The number here IS the chart; the track just gives it somewhere
 * to sit so the reader can see how much of the bar is still empty.
 *
 * NEUTRAL BY DEFAULT, and deliberately not a traffic light. 15 of 38 is not a
 * failing grade: the SAP Baseline covers a narrow, specific set and most of what
 * this product checks lies outside it, so colouring the empty part red would be
 * a claim about the product that the number does not support. Callers pass a
 * `tone` when the ratio genuinely is good or bad.
 */

export function Meter({ value, limit, label, note, tone = 'neutral' }: {
  value: number
  limit: number
  /** What the value counts. Rendered beside the figure, never inferred. */
  label?: string
  note?: string
  tone?: 'neutral' | 'good' | 'warn'
}) {
  const safeLimit = Math.max(limit, 0)
  const pct = safeLimit > 0 ? Math.min(100, (100 * value) / safeLimit) : 0
  const fill = tone === 'good' ? 'var(--ok)'
    : tone === 'warn' ? 'var(--high)'
      : 'var(--accent)'

  return (
    <div>
      <div className="flex items-baseline gap-2 flex-wrap">
        <span className="text-[30px] font-extrabold tracking-[-.02em] leading-[1.1]">
          {value.toLocaleString()}
        </span>
        {/* The limit stays attached to the figure. A meter whose ceiling is only
            in the bar is a meter you have to measure with your eye. */}
        <span className="text-ink2 text-[16px] font-semibold">
          / {safeLimit.toLocaleString()}
        </span>
        {label && <span className="text-ink3 text-[12px]">{label}</span>}
      </div>

      <div className="mt-2 h-2 rounded-full bg-panel2 overflow-hidden"
           role="meter" aria-valuenow={value} aria-valuemin={0}
           aria-valuemax={safeLimit}
           aria-label={label ?? `${value} of ${safeLimit}`}>
        <i className="block h-full rounded-full transition-[width] duration-500"
           style={{ width: `${pct}%`, background: fill }} />
      </div>

      {note && <div className="text-[12px] text-ink2 mt-1.5">{note}</div>}
    </div>
  )
}
