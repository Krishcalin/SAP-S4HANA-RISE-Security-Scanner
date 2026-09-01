/**
 * When the answer on this screen was measured.
 *
 * THE DEFECT. `queries.latest_coverage` selected the newest complete run per
 * system, ordered by `started_at`, and then threw the timestamp away. So a
 * domain reported CLEAR on the strength of an export of any age and the screen
 * could not say which — a control fed by a scan from March read exactly like
 * one fed this morning. That is the same failure the estate-freshness work
 * fixed for the systems table, one layer up.
 *
 * `oldest_days` IS THE FIGURE, NOT `newest_days`. The manifest is a union
 * across systems: a module counts as having run if it ran for any of them. So
 * the weakest evidence behind a CLEAR verdict is the oldest run in the union,
 * and quoting the newest would date the answer by its best input rather than
 * its worst — which is the mistake `SODCOV-000` exists to stop a summary
 * making.
 *
 * One component rather than three copies, so the three screens cannot end up
 * disagreeing about the same estate.
 */
import type { Measured } from '../api/types'

export function MeasuredWhen({ measured, subject }: {
  measured: Measured | null
  /** What was measured, for the sentence: "posture", "coverage", "trend". */
  subject: string
}) {
  // Null is not "today". An answer nobody dated must not be stamped with now,
  // so the line is absent rather than reassuring.
  if (!measured) return null

  const { oldest_days: days, stale, stale_after_days: threshold } = measured
  const when = days === 0 ? 'today'
    : days === 1 ? 'yesterday'
    : `${days} days ago`

  return (
    <p className={`text-[12px] mt-1 ${stale ? 'text-high' : 'text-ink3'}`}>
      {measured.systems === 1
        ? `This ${subject} was last measured ${when}`
        : `Oldest of ${measured.systems} systems: last measured ${when}`}
      {stale && (
        <>
          {' '}— more than the {threshold}-day SAP Security Patch Day cycle, so
          a patch day has passed since. It describes the estate as it was then.
        </>
      )}
      .
    </p>
  )
}
