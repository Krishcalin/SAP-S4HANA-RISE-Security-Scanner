/*
 * The two charts the FAIR model exists to produce, hand-written SVG.
 *
 * No chart library, for the reason PathDetail.tsx already gives about the one
 * diagram in this product: a charting dependency would be the largest thing in
 * the bundle by an order of magnitude, and these are two plots.
 *
 * WHAT THE LOSS EXCEEDANCE CURVE MUST NOT DO
 * The annual loss distribution is heavily zero-inflated — in this product's own
 * reference data 37% of simulated years produce no loss event at all, and on a
 * fully remediated estate it is over three quarters. Three consequences, and each
 * one breaks a naive implementation:
 *   1. log(0) is undefined. A $0 point clamped to the axis minimum renders "no
 *      loss whatsoever" as "a loss of a few hundred thousand". Zero points are
 *      dropped, never clamped.
 *   2. The curve must NOT be drawn up to 100%. It terminates on the left at
 *      P(at least one loss event), and that endpoint is labelled — for a
 *      remediated estate "23% chance of any loss at all" is the most persuasive
 *      number the model produces and it appeared nowhere before.
 *   3. Fewer than two non-zero points is not a curve. It is not drawn, and the
 *      reason is stated, exactly as Burndown and ExposureSeries already do.
 *
 * WHAT THE TREND MUST NOT DO
 * It must not draw one continuous line. Risk moves for reasons that are not
 * remediation — a revised revenue figure, a different simulation count, a dropped
 * export that made checks self-skip and quietly lowered the finding count. A
 * polyline through such a change asserts the two ends are comparable. So the
 * series BREAKS wherever inputs_fingerprint changes, and the break is drawn and
 * labelled rather than smoothed over.
 */
import type { CrqPortfolioStats, CrqTrendPoint } from '../api/types'

const AXIS = 'var(--ink-faint)'
const GRID = 'var(--line)'

function fmtMoney(v: number): string {
  if (v >= 1_000_000_000) return `${(v / 1_000_000_000).toFixed(1)}bn`
  if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(1)}m`
  if (v >= 1_000) return `${Math.round(v / 1_000)}k`
  return String(Math.round(v))
}

// ── Loss exceedance ─────────────────────────────────────────────────────────

interface Pt { loss: number; probability: number }

export function LossExceedance({ current, target, height = 230 }: {
  current: CrqPortfolioStats
  target?: CrqPortfolioStats
  height?: number
}) {
  const cur = (current.loss_exceedance ?? []).filter((p) => p.loss > 0)
  const tgt = (target?.loss_exceedance ?? []).filter((p) => p.loss > 0)

  if (cur.length < 2) {
    return (
      <p className="text-[12px] text-ink3">
        Not enough non-zero points to draw a curve. In this model almost every
        simulated year produces no loss event at all, which is a result, not a
        rendering problem.
      </p>
    )
  }

  const W = 560
  const H = height
  const PAD = { l: 46, r: 14, t: 12, b: 30 }
  const all = [...cur, ...tgt]
  const minLoss = Math.min(...all.map((p) => p.loss))
  const maxLoss = Math.max(...all.map((p) => p.loss))
  const lo = Math.log10(Math.max(minLoss, 1))
  const hi = Math.log10(Math.max(maxLoss, 10))
  const span = Math.max(hi - lo, 0.0001)

  const x = (loss: number) =>
    PAD.l + ((Math.log10(Math.max(loss, 1)) - lo) / span) * (W - PAD.l - PAD.r)
  // y is probability, linear, 0 at the bottom.
  const maxP = Math.max(...all.map((p) => p.probability), 0.01)
  const y = (p: number) => PAD.t + (1 - p / maxP) * (H - PAD.t - PAD.b)

  const path = (pts: Pt[]) =>
    pts.slice().sort((a, b) => a.loss - b.loss)
      .map((p, i) => `${i === 0 ? 'M' : 'L'}${x(p.loss).toFixed(1)},${y(p.probability).toFixed(1)}`)
      .join(' ')

  const decades: number[] = []
  for (let d = Math.floor(lo); d <= Math.ceil(hi); d += 1) decades.push(d)

  const head = cur.slice().sort((a, b) => a.loss - b.loss)[0]
  const tgtHead = tgt.length >= 2 ? tgt.slice().sort((a, b) => a.loss - b.loss)[0] : null

  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 ${W} ${H}`} width="100%"
           style={{ height: 'auto', display: 'block' }}
           role="img"
           aria-label="Loss exceedance curve: the probability of losing at least a given amount in a year">
        {decades.map((d) => {
          const px = x(Math.pow(10, d))
          return (
            <g key={d}>
              <line x1={px} y1={PAD.t} x2={px} y2={H - PAD.b} stroke={GRID} strokeWidth="1" />
              <text x={px} y={H - PAD.b + 14} fill={AXIS} fontSize="12" textAnchor="middle">
                {fmtMoney(Math.pow(10, d))}
              </text>
            </g>
          )
        })}
        {[0, 0.25, 0.5, 0.75, 1].map((f) => {
          const p = maxP * f
          return (
            <g key={f}>
              <line x1={PAD.l} y1={y(p)} x2={W - PAD.r} y2={y(p)} stroke={GRID} strokeWidth="1" />
              <text x={PAD.l - 6} y={y(p) + 4} fill={AXIS} fontSize="12" textAnchor="end">
                {(p * 100).toFixed(0)}%
              </text>
            </g>
          )
        })}

        {tgt.length >= 2 && (
          <path d={path(tgt)} fill="none" stroke="var(--ok)" strokeWidth="1.5"
                strokeDasharray="4 3" />
        )}
        <path d={path(cur)} fill="none" stroke="var(--accent)" strokeWidth="2" />

        {/* The left endpoint is HOLLOW and labelled: the curve stops at the
            probability of any loss at all, and does not run up to 100%. */}
        <circle cx={x(head.loss)} cy={y(head.probability)} r="4"
                fill="var(--panel)" stroke="var(--accent)" strokeWidth="2" />
        <text x={x(head.loss) + 8} y={y(head.probability) - 6}
              fill="var(--ink-dim)" fontSize="12">
          {(head.probability * 100).toFixed(0)}% chance of any loss
        </text>
        {tgtHead && (
          <>
            <circle cx={x(tgtHead.loss)} cy={y(tgtHead.probability)} r="4"
                    fill="var(--panel)" stroke="var(--ok)" strokeWidth="2" />
            <text x={x(tgtHead.loss) + 8} y={y(tgtHead.probability) + 13}
                  fill="var(--ink-dim)" fontSize="12">
              {(tgtHead.probability * 100).toFixed(0)}% fully hardened
            </text>
          </>
        )}

        <line x1={PAD.l} y1={H - PAD.b} x2={W - PAD.r} y2={H - PAD.b}
              stroke={AXIS} strokeWidth="1" />
        <line x1={PAD.l} y1={PAD.t} x2={PAD.l} y2={H - PAD.b}
              stroke={AXIS} strokeWidth="1" />
      </svg>
      <p className="text-[12px] text-ink3 mt-1.5">
        Read it as: there is a <strong>y%</strong> chance of losing{' '}
        <strong>at least x</strong> in a year. The loss axis is logarithmic
        because the tail spans orders of magnitude. Years with no loss event
        cannot be plotted on a log axis and are <strong>omitted, not moved to the
        left edge</strong> — the curve stops at the probability of any loss at all.
      </p>
    </div>
  )
}

// ── Risk reduction trend ────────────────────────────────────────────────────

export function RiskTrend({ points, height = 210 }: {
  points: CrqTrendPoint[]
  height?: number
}) {
  if (points.length <= 1) {
    return (
      <p className="text-[12px] text-ink3">
        A trend needs at least two completed scans. One point is a reading, not a
        direction.
      </p>
    )
  }

  const W = 760
  const H = height
  // Top padding carries three rows of break labels now, not one line of 9px text.
  const PAD = { l: 64, r: 16, t: 58, b: 30 }
  const values = points.flatMap((p) => [
    Number(p.ale_p90) || 0, Number(p.ale_mean) || 0, Number(p.residual_p90) || 0,
  ])
  // Y ANCHORED AT ZERO, ALWAYS, AND LINEAR. The reader is judging "how many
  // dollars did it fall". A truncated axis exaggerates the slope and a log axis
  // makes a $50m drop from $100m look identical to a $500k drop from $1m.
  const maxV = Math.max(...values, 1)
  const x = (i: number) =>
    PAD.l + (points.length === 1 ? 0 : (i / (points.length - 1)) * (W - PAD.l - PAD.r))
  const y = (v: number) => PAD.t + (1 - v / maxV) * (H - PAD.t - PAD.b)

  // One polyline per fingerprint group. A change in the model, the money
  // assumptions or the coverage makes two adjacent points incomparable, and a
  // line through that change would claim otherwise.
  const groups: number[][] = []
  points.forEach((p, i) => {
    if (i === 0 || p.inputs_fingerprint !== points[i - 1].inputs_fingerprint) {
      groups.push([])
    }
    groups[groups.length - 1].push(i)
  })

  // Break-label placement. Measured in viewBox units against an average glyph
  // width for the font size, which is close enough for a fixed string and needs
  // no DOM measurement — this is the same estimate wrapWords makes on the risk
  // path diagram, and for the same reason.
  const LABEL_FS = 12
  const LABEL_W = 'inputs changed'.length * LABEL_FS * 0.53
  const ROW_Y = [16, 32, 48]
  const rowEnds = ROW_Y.map(() => -Infinity)
  const breaks = groups.slice(1).map((idx, gi) => {
    const prev = groups[gi][groups[gi].length - 1]
    const mid = (x(prev) + x(idx[0])) / 2
    const row = rowEnds.findIndex((end) => mid > end)
    if (row >= 0) rowEnds[row] = mid + LABEL_W + 6
    return { gi, mid, row: row >= 0 ? row : null, y: row >= 0 ? ROW_Y[row] : 0 }
  })
  const unlabelled = breaks.filter((b) => b.row === null).length

  const line = (idx: number[], key: 'ale_p90' | 'ale_mean' | 'residual_p90') =>
    idx.map((i, n) => {
      const v = Number(points[i][key]) || 0
      return `${n === 0 ? 'M' : 'L'}${x(i).toFixed(1)},${y(v).toFixed(1)}`
    }).join(' ')

  return (
    <div className="overflow-x-auto">
      {/* No `height` attribute, deliberately. With one, preserveAspectRatio fits
          the viewBox to the shorter side — the height — so the chart drew at 1:1
          and centred itself in a card twice its width, wasting the room the
          labels needed and rendering every one of them at its raw viewBox size.
          Letting the aspect ratio size it fills the card and scales the type up
          with it. */}
      <svg viewBox={`0 0 ${W} ${H}`} width="100%"
           style={{ height: 'auto', display: 'block' }} role="img"
           aria-label="Annual loss exposure per scan, with the line broken wherever the model inputs changed">
        {[0, 0.5, 1].map((f) => (
          <g key={f}>
            <line x1={PAD.l} y1={y(maxV * f)} x2={W - PAD.r} y2={y(maxV * f)}
                  stroke={GRID} strokeWidth="1" />
            <text x={PAD.l - 6} y={y(maxV * f) + 4} fill={AXIS} fontSize="12"
                  textAnchor="end">{fmtMoney(maxV * f)}</text>
          </g>
        ))}

        {groups.map((idx, gi) => (
          <g key={gi}>
            {idx.length > 1 && (
              <>
                <path d={line(idx, 'residual_p90')} fill="none" stroke="var(--ok)"
                      strokeWidth="1.5" strokeDasharray="4 3" />
                <path d={line(idx, 'ale_mean')} fill="none" stroke="var(--ink-dim)"
                      strokeWidth="1.5" />
                <path d={line(idx, 'ale_p90')} fill="none" stroke="var(--accent)"
                      strokeWidth="2" />
              </>
            )}
            {idx.map((i) => (
              <circle key={i} cx={x(i)} cy={y(Number(points[i].ale_p90) || 0)} r="4"
                      fill="var(--accent)" />
            ))}
          </g>
        ))}

        {/* The break itself, drawn. A gap nobody explains looks like missing data.

            THE LABELS USED TO OVERLAP, and on a screen whose entire job is
            "has the exposure actually fallen?" an unreadable annotation is worse
            than none: it is the thing that tells you two segments are NOT
            comparable. Every break was labelled at the same y, so a run of
            single-point groups printed "inputs changed" four times in the space
            of one.

            Placement is a stack of rows, filled left to right: a label takes the
            highest row whose last label ends before this one starts. Rows rather
            than rotation because horizontal text at 12px is read at a glance and
            rotated text is not, and this label is read while scanning a line for
            a step change.

            A label that fits in NO row is dropped and counted rather than drawn
            over its neighbour. The divider still appears — the break is the fact,
            the words are the explanation — and the caption below says how many
            went unlabelled, because silently dropping annotations is how a chart
            comes to under-report the very thing it exists to flag. */}
        {breaks.map((b) => (
          <g key={`b${b.gi}`}>
            <line x1={b.mid} y1={PAD.t} x2={b.mid} y2={H - PAD.b}
                  stroke={AXIS} strokeWidth="1" strokeDasharray="2 3" />
            {b.row !== null && (
              <>
                <line x1={b.mid} y1={b.y + 3} x2={b.mid} y2={PAD.t}
                      stroke={AXIS} strokeWidth="1" strokeDasharray="2 3" />
                <text x={b.mid + 4} y={b.y} fill={AXIS} fontSize="12">
                  inputs changed
                </text>
              </>
            )}
          </g>
        ))}

        <line x1={PAD.l} y1={H - PAD.b} x2={W - PAD.r} y2={H - PAD.b}
              stroke={AXIS} strokeWidth="1" />
      </svg>

      <div className="flex flex-wrap gap-4 text-[13px] text-ink2 mt-2">
        <span><i className="inline-block w-4 h-0.5 align-middle mr-1"
                 style={{ background: 'var(--accent)' }} /> Annual loss, P90</span>
        <span><i className="inline-block w-4 h-0.5 align-middle mr-1"
                 style={{ background: 'var(--ink-dim)' }} /> Average year</span>
        <span><i className="inline-block w-4 h-0.5 align-middle mr-1"
                 style={{ background: 'var(--ok)' }} /> Fully hardened floor</span>
      </div>
      <p className="text-[13.5px] text-ink3 mt-2 leading-relaxed">
        The line <strong>breaks wherever the model inputs changed</strong> — a
        revised revenue figure, a different simulation count, or an export that
        went missing and made checks skip. Those move the number without anything
        about your security posture changing, and a continuous line across such a
        change would claim the two sides are comparable. The residual floor is
        the second guard: it does not depend on your findings, so if it moves,
        something other than remediation did.
        {/* Said out loud rather than silently dropped. A chart that quietly
            omits annotations under-reports the exact thing it exists to flag. */}
        {unlabelled > 0 && (
          <>
            {' '}
            <strong>
              {unlabelled} more break{unlabelled === 1 ? ' is' : 's are'} drawn
              without a label
            </strong>{' '}
            — they fall too close together to print the words legibly. Every
            dashed divider is a break, labelled or not.
          </>
        )}
      </p>
    </div>
  )
}
