import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { LossExceedance, RiskTrend } from './CrqCharts'
import type { CrqPortfolioStats, CrqTrendPoint } from '../api/types'

/**
 * The exposure trend, and the two complaints that produced it.
 *
 * FIRST: the break annotations overlapped. Every break printed "inputs changed"
 * at the same y, so a run of single-point groups stacked four copies inside the
 * width of one. That was fixed by staggering them across three rows.
 *
 * SECOND, on the staggered version: "clumsy and busy". Correct, and the stagger
 * was the wrong fix. It stopped six copies of one sentence colliding and did
 * nothing about there being six copies of one sentence. The rule is the ordinary
 * one for direct labels -- label selectively, put anything true of EVERY mark in
 * the legend -- so the annotation is now stated once and the plot carries the
 * fact as a shaded interval.
 *
 * These tests guard the second fix without losing the first: the thing that can
 * never come back is per-break TEXT, and the thing that must never be lost is the
 * break itself. Geometry, on rendered SVG attributes in jsdom, because it is
 * plain SVG -- one of the quieter arguments for not reaching for a chart library.
 */

function pt(run: number, fp: string, p90: number): CrqTrendPoint {
  return {
    ale_p50: p90 * 0.4,
    ale_p90: p90,
    ale_mean: p90 * 0.5,
    unrouted_count: 0,
    run_id: run,
    started_at: `2026-0${(run % 9) + 1}-01T00:00:00Z`,
    input_finding_count: 100,
    inputs_fingerprint: fp,
  }
}

/** The reported estate: several single-point groups in a row, so their break
 *  intervals land within a label's width of each other. */
function crowded(): CrqTrendPoint[] {
  return [
    pt(1, 'a', 79_800_000), pt(2, 'a', 79_800_000),
    pt(3, 'b', 39_000_000), pt(4, 'b', 41_000_000), pt(5, 'b', 47_000_000),
    pt(6, 'c', 8_000_000),
    pt(7, 'd', 8_000_000),
    pt(8, 'e', 8_000_000),
    pt(9, 'f', 12_000_000), pt(10, 'f', 12_000_000), pt(11, 'f', 12_000_000),
    pt(12, 'g', 6_000_000),
  ]
}

const BREAKS = 6

function chart() {
  return screen.getByRole('img', { name: /Annual loss exposure per scan/ })
}

describe('RiskTrend', () => {
  it('never repeats an annotation once per break', () => {
    // THE REGRESSION GUARD. Six copies of one sentence over the plot is the
    // "busy" complaint in its original form; a stagger that spread them over
    // three rows was still six copies. Zero, not "few" — the legend carries it.
    render(<RiskTrend points={crowded()} />)
    const inPlot = Array.from(chart().querySelectorAll('text'))
      .filter((t) => (t.textContent || '').includes('inputs changed'))
    expect(inPlot).toHaveLength(0)
  })

  it('states it once, in the legend, with a swatch', () => {
    // Removing the labels without saying it anywhere would turn six shaded
    // intervals into unexplained grey bands, which is the failure the original
    // per-break label was added to prevent.
    render(<RiskTrend points={crowded()} />)
    expect(screen.getByText(/inputs changed — the series breaks here/)).toBeTruthy()
  })

  it('draws every break as an interval, not a hairline at its middle', () => {
    // A break is the GAP between two incomparable groups. Shading the interval
    // says "the series stops here and starts again there"; a line at the midpoint
    // said it more quietly and needed words beside it to be read at all.
    render(<RiskTrend points={crowded()} />)
    const bands = Array.from(chart().querySelectorAll('rect'))
      .filter((r) => r.getAttribute('fill-opacity') === '0.07')
    expect(bands).toHaveLength(BREAKS)
    for (const b of bands) {
      expect(Number(b.getAttribute('width'))).toBeGreaterThan(0)
    }
  })

  it('keeps a dashed edge on both sides of every break', () => {
    render(<RiskTrend points={crowded()} />)
    const dashed = Array.from(chart().querySelectorAll('line'))
      .filter((l) => l.getAttribute('stroke-dasharray') === '2 3')
    expect(dashed).toHaveLength(BREAKS * 2)
  })

  it('has no legend entry for breaks when the series never breaks', () => {
    // The absence case. A legend that always claims a mark the plot does not
    // contain is a legend nobody trusts.
    render(<RiskTrend points={[pt(1, 'a', 1e7), pt(2, 'a', 9e6), pt(3, 'a', 8e6)]} />)
    expect(screen.queryByText(/the series breaks here/)).toBeNull()
  })

  it('fills under the headline series only', () => {
    // One area, not three. Three translucent sheets stacked on each other is the
    // "busy" complaint made worse; under one line it reads as magnitude.
    render(<RiskTrend points={crowded()} />)
    const filled = Array.from(chart().querySelectorAll('path'))
      .filter((p) => (p.getAttribute('fill') || '').includes('rt-fill'))
    const groupsWithLines = 3   // 'a', 'b' and 'f' have more than one point
    expect(filled).toHaveLength(groupsWithLines)
  })

  it('gives every point a readable value on hover', () => {
    render(<RiskTrend points={crowded()} />)
    const titles = Array.from(chart().querySelectorAll('title'))
    expect(titles).toHaveLength(12)
    expect(titles[0].textContent).toMatch(/annual loss, P90/)
    expect(titles[0].textContent).toMatch(/\d{4}/)
  })

  it('does not letterbox itself into a fraction of the card', () => {
    // With a `height` attribute alongside width="100%", preserveAspectRatio fits
    // the viewBox to the shorter side and the chart draws at 1:1, centred, in a
    // card twice its width — which is what left the labels no room originally.
    render(<RiskTrend points={crowded()} />)
    expect(chart().getAttribute('width')).toBe('100%')
    expect(chart().getAttribute('height')).toBeNull()
  })

  it('still refuses to draw a trend from a single point', () => {
    render(<RiskTrend points={[pt(1, 'a', 1e7)]} />)
    expect(screen.getByText(/One point is a reading, not a direction/)).toBeTruthy()
  })
})


/**
 * Axis titles, and the callout that fell off the top of the box.
 *
 * BOTH CHARTS HAD READABLE NUMBERS ON UNNAMED AXES. The exceedance curve's ticks
 * said "1.0m" and "45%"; the trend's x axis was a bare rule with no labels at
 * all, so nothing on it said the dimension was time or which end was recent.
 * Tick VALUES without an axis NAME is the specific gap here — the chart looked
 * complete and could not be read literally.
 */

function stats(over: Partial<CrqPortfolioStats> = {}): CrqPortfolioStats {
  return {
    loss_exceedance: [
      { loss: 500_000, probability: 0.6 },
      { loss: 2_000_000, probability: 0.4 },
      { loss: 12_000_000, probability: 0.15 },
      { loss: 40_000_000, probability: 0.02 },
    ],
    ...over,
  } as CrqPortfolioStats
}

describe('chart axes', () => {
  it('names both axes on the exposure trend', () => {
    render(<RiskTrend points={crowded()} />)
    const svg = chart()
    const text = Array.from(svg.querySelectorAll('text')).map((t) => t.textContent)
    expect(text).toContain('Annual loss')
    expect(text).toContain('Scan run, oldest first')
  })

  it('dates the run axis without crowding it', () => {
    // At most four, always including the first and last — the two a reader looks
    // for. More would be the next "busy" complaint.
    render(<RiskTrend points={crowded()} />)
    const dated = Array.from(chart().querySelectorAll('text'))
      .filter((t) => /^\d{2} \w{3}$/.test((t.textContent || '').trim()))
    expect(dated.length).toBeGreaterThan(0)
    expect(dated.length).toBeLessThanOrEqual(4)
  })

  it('labels every run when there are fewer runs than ticks', () => {
    render(<RiskTrend points={[pt(1, 'a', 1e7), pt(2, 'a', 9e6), pt(3, 'a', 8e6)]} />)
    const dated = Array.from(chart().querySelectorAll('text'))
      .filter((t) => /^\d{2} \w{3}$/.test((t.textContent || '').trim()))
    expect(dated).toHaveLength(3)
  })

  it('names both axes on the exceedance curve', () => {
    render(<LossExceedance current={stats()} />)
    const svg = screen.getByRole('img', { name: /Loss exceedance curve/ })
    const text = Array.from(svg.querySelectorAll('text')).map((t) => t.textContent)
    expect(text.some((t) => (t || '').includes('Annual loss, at least'))).toBe(true)
    expect(text).toContain('Chance in a year')
  })

  it('keeps the endpoint callout inside the box', () => {
    // The head of the curve is its HIGHEST point by definition, so "6 above it"
    // is off the top of the viewBox exactly when the curve starts at its maximum
    // — the common case. It was clipped on the reported screenshot.
    render(<LossExceedance current={stats()} />)
    const svg = screen.getByRole('img', { name: /Loss exceedance curve/ })
    const callout = Array.from(svg.querySelectorAll('text'))
      .find((t) => (t.textContent || '').includes('chance of any loss'))
    expect(callout).toBeTruthy()
    expect(Number(callout!.getAttribute('y'))).toBeGreaterThan(0)
  })

  it('is shorter than it was, at the same drawn size', () => {
    // Rendered height is (card width x H / W) because there is no height
    // attribute. Widening the viewBox shortens the render without shrinking
    // anything in it; this pins the ratio so a later tweak cannot quietly
    // restore a 400px-tall chart.
    render(<RiskTrend points={crowded()} />)
    const [, , w, h] = (chart().getAttribute('viewBox') || '').split(/\s+/).map(Number)
    expect(h / w).toBeLessThan(0.34)
  })
})
