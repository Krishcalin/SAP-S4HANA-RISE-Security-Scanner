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

export function LossExceedance({ current, target, height = 260 }: {
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

  // WIDTH IS THE HEIGHT CONTROL HERE. The svg has no height attribute -- it
  // sizes from the viewBox ratio -- so rendered height is (card width x H / W).
  // At 560x230 in a ~970px card that is 398px of chart, which is why these came
  // back as "very big". Widening the box shortens the render without shrinking
  // anything drawn in it.
  const W = 880
  const H = height
  // l and b carry the axis titles; t carries the endpoint callout, which used to
  // be drawn at y-6 from a point that can sit exactly on PAD.t and was clipped by
  // the top of the viewBox whenever the first probability was the highest.
  const PAD = { l: 74, r: 20, t: 28, b: 54 }
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
        {/* Clamped into the plot. The head is the HIGHEST point by definition, so
            "6 above it" is off the top of the box exactly when the curve starts
            at its maximum -- which is the common case, not the edge case. */}
        <text x={x(head.loss) + 8} y={Math.max(y(head.probability) - 8, PAD.t - 8)}
              fill="var(--ink-dim)" fontSize="12">
          {(head.probability * 100).toFixed(0)}% chance of any loss
        </text>
        {tgtHead && (
          <>
            <circle cx={x(tgtHead.loss)} cy={y(tgtHead.probability)} r="4"
                    fill="var(--panel)" stroke="var(--ok)" strokeWidth="2" />
            <text x={x(tgtHead.loss) + 8}
                  y={Math.min(y(tgtHead.probability) + 15, H - PAD.b - 6)}
                  fill="var(--ink-dim)" fontSize="12">
              {(tgtHead.probability * 100).toFixed(0)}% fully hardened
            </text>
          </>
        )}

        <line x1={PAD.l} y1={H - PAD.b} x2={W - PAD.r} y2={H - PAD.b}
              stroke={AXIS} strokeWidth="1" />
        <line x1={PAD.l} y1={PAD.t} x2={PAD.l} y2={H - PAD.b}
              stroke={AXIS} strokeWidth="1" />

        {/* AXIS TITLES. The tick labels said "1.0m" and "45%" and nothing said
            what either was measuring -- readable numbers on unnamed axes. */}
        <text x={(PAD.l + W - PAD.r) / 2} y={H - 14} textAnchor="middle"
              fill={AXIS} fontSize="13" fontWeight="600">
          Annual loss, at least &mdash; log scale
        </text>
        <text transform={`rotate(-90 20 ${(PAD.t + H - PAD.b) / 2})`}
              x={20} y={(PAD.t + H - PAD.b) / 2} textAnchor="middle"
              fill={AXIS} fontSize="13" fontWeight="600">
          Chance in a year
        </text>
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

export function RiskTrend({ points, height = 270 }: {
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

  // See the note in LossExceedance: rendered height is (card width x H / W), so
  // the box is widened rather than the drawing shrunk. 760x330 rendered 421px
  // tall in a ~970px card; 900x270 renders 291px and gains horizontal room for
  // the run labels at the same time.
  const W = 900
  const H = height
  // t is 20 rather than 58 because the top band used to hold three rows of
  // "inputs changed" and now holds nothing. b carries the run labels and the
  // axis title.
  const PAD = { l: 78, r: 20, t: 20, b: 58 }
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

  // A break is the GAP between two incomparable groups, so it is drawn as the
  // gap rather than as a line at the middle of one. Shading the interval from the
  // last comparable point to the first point of the next series says "the series
  // stops here and starts again there", which is the actual claim; a hairline at
  // the midpoint said it more quietly and needed a word beside it to be read at
  // all.
  const breaks = groups.slice(1).map((idx, gi) => ({
    gi,
    from: x(groups[gi][groups[gi].length - 1]),
    to: x(idx[0]),
  }))

  // Up to four evenly spaced runs, always including the first and the last --
  // the two a reader looks for. Fewer points than ticks means every point is
  // labelled, which is correct rather than a special case.
  const TICKS = 4
  const ticks = points.length <= TICKS
    ? points.map((_, i) => i)
    : Array.from({ length: TICKS }, (_, k) =>
        Math.round((k / (TICKS - 1)) * (points.length - 1)))

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
        <defs>
          {/* The fill is the headline series and nothing else. An area under every
              line would be three translucent sheets stacked on each other, which
              is the "busy" complaint made worse; under one line it reads as
              magnitude, which is what the reader is judging. */}
          <linearGradient id="rt-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.30" />
            <stop offset="100%" stopColor="var(--accent)" stopOpacity="0.02" />
          </linearGradient>
        </defs>

        {/* The incomparable intervals, drawn as intervals. Behind the grid so the
            gridlines stay readable across them. */}
        {breaks.map((b) => (
          <rect key={`bk${b.gi}`} x={b.from} y={PAD.t} width={Math.max(b.to - b.from, 2)}
                height={H - PAD.t - PAD.b} fill="var(--ink-faint)" fillOpacity="0.07" />
        ))}
        {breaks.map((b) => (
          <g key={`bl${b.gi}`}>
            <line x1={b.from} y1={PAD.t} x2={b.from} y2={H - PAD.b}
                  stroke={AXIS} strokeWidth="1" strokeDasharray="2 3" />
            <line x1={b.to} y1={PAD.t} x2={b.to} y2={H - PAD.b}
                  stroke={AXIS} strokeWidth="1" strokeDasharray="2 3" />
          </g>
        ))}

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
                <path d={`${line(idx, 'ale_p90')} L${x(idx[idx.length - 1]).toFixed(1)},`
                         + `${y(0).toFixed(1)} L${x(idx[0]).toFixed(1)},${y(0).toFixed(1)} Z`}
                      fill="url(#rt-fill)" stroke="none" />
                <path d={line(idx, 'residual_p90')} fill="none" stroke="var(--ok)"
                      strokeWidth="2" strokeDasharray="5 4" strokeLinecap="round" />
                <path d={line(idx, 'ale_mean')} fill="none" stroke="var(--ink-dim)"
                      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                <path d={line(idx, 'ale_p90')} fill="none" stroke="var(--accent)"
                      strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
              </>
            )}
            {/* A 2px surface ring, so a marker landing on the line or on another
                marker still reads as one mark rather than as a blob. */}
            {idx.map((i) => (
              <circle key={i} cx={x(i)} cy={y(Number(points[i].ale_p90) || 0)} r="5"
                      fill="var(--accent)" stroke="var(--panel)" strokeWidth="2">
                <title>
                  {`${new Date(points[i].started_at).toLocaleDateString('en-GB', {
                    day: '2-digit', month: 'short', year: 'numeric',
                  })} — ${fmtMoney(Number(points[i].ale_p90) || 0)} annual loss, P90`}
                </title>
              </circle>
            ))}
          </g>
        ))}

        {/* REMOVED: a per-break "inputs changed" label.

            It was printed once per break -- six times on the reported estate --
            and that repetition WAS the "busy" complaint. Staggering it across
            three rows stopped it colliding and did nothing about there being six
            copies of one sentence sitting over the plot.

            The rule it broke is the ordinary one for direct labels: label
            selectively, and put anything true of EVERY mark in the legend.
            "These dashed intervals are where the inputs changed" is true of every
            break, so it is said once, beside a swatch that looks like the thing
            it describes.

            The FACT is still drawn -- shaded interval, dashed edges -- and the
            caption still explains the consequence. What went is the repetition.
            The original argument for the label was that a gap nobody explains
            looks like missing data; that still holds, and the legend answers it. */}

        <line x1={PAD.l} y1={H - PAD.b} x2={W - PAD.r} y2={H - PAD.b}
              stroke={AXIS} strokeWidth="1" />

        {/* X HAD NO LABELS AT ALL -- a bare rule, so the horizontal axis was
            unreadable in the strict sense: nothing said it was time, or which end
            was recent. At most four dated ticks, evenly spaced: enough to orient,
            few enough that they cannot collide at this width and cannot become
            the next "busy" complaint. */}
        {ticks.map((i) => (
          <text key={`t${i}`} x={x(i)} y={H - PAD.b + 18} textAnchor="middle"
                fill={AXIS} fontSize="12">
            {new Date(points[i].started_at).toLocaleDateString('en-GB', {
              day: '2-digit', month: 'short',
            })}
          </text>
        ))}
        <text x={(PAD.l + W - PAD.r) / 2} y={H - 12} textAnchor="middle"
              fill={AXIS} fontSize="13" fontWeight="600">
          Scan run, oldest first
        </text>
        <text transform={`rotate(-90 22 ${(PAD.t + H - PAD.b) / 2})`}
              x={22} y={(PAD.t + H - PAD.b) / 2} textAnchor="middle"
              fill={AXIS} fontSize="13" fontWeight="600">
          Annual loss
        </text>
      </svg>

      <div className="flex flex-wrap gap-4 text-[13px] text-ink2 mt-2">
        <span><i className="inline-block w-4 h-0.5 align-middle mr-1"
                 style={{ background: 'var(--accent)' }} /> Annual loss, P90</span>
        <span><i className="inline-block w-4 h-0.5 align-middle mr-1"
                 style={{ background: 'var(--ink-dim)' }} /> Average year</span>
        <span><i className="inline-block w-4 h-0.5 align-middle mr-1"
                 style={{ background: 'var(--ok)' }} /> Fully hardened floor</span>
        {/* The swatch looks like the mark: a shaded interval with dashed edges.
            Identity is never carried by a colour alone, and here it is not
            carried by a colour at all — it is a texture. */}
        {breaks.length > 0 && (
          <span className="inline-flex items-center">
            <i className="inline-block w-4 h-3 align-middle mr-1.5 border-x border-dashed"
               style={{ background: 'color-mix(in srgb, var(--ink-faint) 12%, transparent)',
                        borderColor: 'var(--ink-faint)' }} />
            inputs changed &mdash; the series breaks here
          </span>
        )}
      </div>
      <p className="text-[13.5px] text-ink3 mt-2 leading-relaxed">
        The line <strong>breaks wherever the model inputs changed</strong> — a
        revised revenue figure, a different simulation count, or an export that
        went missing and made checks skip. Those move the number without anything
        about your security posture changing, and a continuous line across such a
        change would claim the two sides are comparable. The residual floor is
        the second guard: it does not depend on your findings, so if it moves,
        something other than remediation did.
      </p>
    </div>
  )
}
